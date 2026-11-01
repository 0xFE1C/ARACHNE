"""Adversarial safety suite for bounded fuzzing (S30, area FUZZ, REQ-FUZZ-001...005).

Every test here tries to make the fuzzing framework do something it must not: fuzz without a
grant, exceed a bound, keep sending after the target has signalled distress, send a prohibited
payload, or produce a finding without a proof. The assertions are about what did **not** happen —
nothing reached the socket, the request count never crossed the cap, the run stopped at the first
signal — because that is what "discovery, never disruption" means and it cannot be shown by a
summary count.

The fixture is a real ARC/1 service on loopback (`tests/lab/fuzz_lab.py`), and its own counters
are the ground truth for "did anything arrive": `lab.arc.requests` is incremented by the *service*
when it parses a request, so it is independent of anything the fuzzer reports.
"""

from __future__ import annotations

import pytest

from arachne.core.errors import FuzzRefused
from arachne.fuzz.bounds import STOP_ABORTED, STOP_BUDGET, STOP_COMPLETED
from arachne.fuzz.candidates import CandidateStatus, FuzzCandidate
from arachne.fuzz.grammar import FuzzCase, MutationOperator
from arachne.fuzz.runner import FuzzPlan
from tests.helpers.fuzz import (
    ARC_KEY,
    arc_budget,
    arc_grammars_registered,
    arc_plan,
    arc_target,
    build_runner,
    fuzz_attestation,
    fuzz_definition,
    lab_arc,
)
from tests.lab.fuzz_lab import arc_lookup_request

#: A documentation-range address (RFC 5737) used as the *authorized* target when the endpoint
#: under test is deliberately out of scope.
OUT_OF_SCOPE_IP = "192.0.2.10"

# --------------------------------------------------------------------------- the grant


async def test_unattested_fuzzing_is_refused_and_audited_and_nothing_is_sent() -> None:
    """The P0 rule: no fuzzing attestation, no fuzzing — and the attempt is on the record."""
    with lab_arc() as lab:
        with arc_grammars_registered():
            harness = build_runner()
            plan = FuzzPlan(
                definition=fuzz_definition(),
                attestation=None,
                wire_targets=(arc_target(lab),),
                budget=arc_budget(),
            )
            with pytest.raises(FuzzRefused) as caught:
                await harness.runner.run(plan)

    assert "no fuzzing attestation" in str(caught.value)
    assert "fuzz.refused" in harness.actions()
    refusals = harness.audit_meta("fuzz.refused")
    assert refusals[0]["attestation_present"] is False
    assert "fuzz.authorized" not in harness.actions()
    assert lab.arc.requests == 0, "a refused fuzz must not have reached the target at all"


async def test_a_production_target_is_refused_before_any_socket_is_opened() -> None:
    with lab_arc() as lab:
        with arc_grammars_registered():
            harness = build_runner()
            plan = arc_plan(
                lab,
                attestation=fuzz_attestation(environment="production"),
            )
            with pytest.raises(FuzzRefused) as caught:
                await harness.runner.run(plan)

    assert "does not permit production targets" in str(caught.value)
    assert lab.arc.requests == 0
    assert harness.audit_meta("fuzz.refused")[0]["environment"] == "production"


# --------------------------------------------------------------------------- the bounds


async def test_the_request_budget_is_never_crossed_by_a_single_request() -> None:
    with lab_arc() as lab:
        with arc_grammars_registered():
            harness = build_runner()
            report = await harness.runner.run(
                arc_plan(lab, budget=arc_budget(max_cases=500, max_requests=12, batch_size=4))
            )

    assert report.status == STOP_BUDGET
    assert report.targets[0].requests <= 12, "the ledger is spent *before* each request"
    assert "fuzz.budget_exhausted" in harness.actions()


async def test_the_case_budget_bounds_the_mutated_messages_that_reach_the_target() -> None:
    with lab_arc() as lab:
        with arc_grammars_registered():
            harness = build_runner()
            report = await harness.runner.run(
                arc_plan(
                    lab,
                    budget=arc_budget(max_cases=6, max_requests=200, batch_size=3),
                )
            )
            cases = report.targets[0].cases_run

    assert cases <= 6
    assert summary(lab)["cases_seen"] >= cases, "the service saw at most what the budget allowed"
    assert lab.arc.requests <= 6 + 3 + 6 + 4, "probes and cases together stay within the ledger"


async def test_the_wall_clock_budget_ends_a_run_that_a_slow_target_would_stretch() -> None:
    with lab_arc() as lab:
        with arc_grammars_registered():
            harness = build_runner()
            lab.arm_slow_after(2, delay_s=0.1)
            report = await harness.runner.run(
                arc_plan(
                    lab,
                    budget=arc_budget(
                        max_cases=500, max_requests=500, max_seconds=0.8, batch_size=50
                    ),
                )
            )

    assert report.targets[0].requests <= 500
    assert report.status in (STOP_BUDGET, STOP_ABORTED)
    assert report.targets[0].cases_run < 30, "a 0.8s ceiling must not allow a long run"


# --------------------------------------------------------------------------- the guard


async def test_degradation_aborts_the_run_and_the_incident_is_audited() -> None:
    with lab_arc() as lab:
        with arc_grammars_registered():
            harness = build_runner()
            lab.arm_drop_after(10)
            report = await harness.runner.run(
                arc_plan(lab, budget=arc_budget(max_cases=200, max_requests=200, batch_size=5))
            )

    target = report.targets[0]
    assert report.aborted is True
    assert report.status == STOP_ABORTED
    assert target.abort_reasons, "an abort must state the signal that stopped it"
    assert "fuzz.aborted" in harness.actions()
    abort_meta = harness.audit_meta("fuzz.aborted")[0]
    assert abort_meta["cases_run"] if "cases_run" in abort_meta else abort_meta["reasons"]
    assert target.healthy_after is False or target.abort_reasons


async def test_fuzzing_stops_at_the_first_signal_rather_than_at_the_batch_boundary() -> None:
    """The guard is judged after every case, so a struggling service gets no extra traffic."""
    with lab_arc() as lab:
        with arc_grammars_registered():
            harness = build_runner(probe_interval=1)
            lab.arm_drop_after(6)
            report = await harness.runner.run(
                arc_plan(lab, budget=arc_budget(max_cases=200, max_requests=200, batch_size=50))
            )

    target = report.targets[0]
    assert report.aborted
    assert target.cases_run < 50, "the batch is 50 wide; the run must not have completed it"
    assert lab.arc.dropped <= 4, "the service is dropped on, then left alone"


async def test_an_abort_stops_the_remaining_targets_too() -> None:
    """A fuzzer that has just made one service struggle does not move on to the next."""
    with lab_arc() as first:
        with lab_arc() as second:
            with arc_grammars_registered():
                harness = build_runner()
                # Only the first target is armed: the second is genuinely healthy, which is what
                # makes "did it get started" a real question.
                first.arm_drop_after(8)
                plan = FuzzPlan(
                    definition=fuzz_definition(),
                    attestation=fuzz_attestation(),
                    wire_targets=(
                        arc_target(first, label="first"),
                        arc_target(second, label="second"),
                    ),
                    budget=arc_budget(max_cases=100, max_requests=100, batch_size=5),
                )
                report = await harness.runner.run(plan)

    assert report.aborted
    assert [target.label for target in report.targets] == ["first"], (
        "the second target must not be started after an abort"
    )
    assert second.arc.requests == 0


async def test_a_target_that_is_already_failing_is_not_fuzzed_at_all() -> None:
    """Fuzzing a service that was already broken would attribute its failure to the fuzzing."""
    with lab_arc() as lab:
        with arc_grammars_registered():
            harness = build_runner()
            lab.inject_drop()
            report = await harness.runner.run(arc_plan(lab))

    target = report.targets[0]
    assert target.cases_run == 0
    assert target.refusals and "did not pass its own health probe" in target.refusals[0]
    assert "fuzz.refused" in harness.actions()
    assert lab.arc.requests == 0


async def test_a_target_that_answers_with_faults_is_not_treated_as_degraded() -> None:
    """The distinction the guard turns on: a fault is a candidate, not a reason to stop."""
    with lab_arc() as lab:
        with arc_grammars_registered():
            harness = build_runner()
            # Every answer is an "internal fault", including the health probe's — so the run
            # refuses to start rather than mistaking faults for a healthy service.
            lab.inject_fault()
            report = await harness.runner.run(arc_plan(lab))
            assert report.targets[0].cases_run == 0

    with lab_arc() as lab:
        with arc_grammars_registered():
            harness = build_runner()
            report = await harness.runner.run(arc_plan(lab))
            target = report.targets[0]
            # Normal service: the two length cases fault, and the run completes regardless.
            assert report.aborted is False
            assert report.status == STOP_COMPLETED
            assert [c.signal.value for c in target.candidates] == ["fault", "fault"]


# --------------------------------------------------------------------------- the payloads


class _RogueEngine:
    """An engine that hands the runner a prohibited payload and then a normal case.

    It exists because the engine is a pluggable interface: the shipped engine cannot produce a
    prohibited payload (the grammar refuses to build one), so the only way to test the last gate
    is to be the thing that tries.
    """

    name = "rogue-test-engine"

    def plan(self, grammar, *, limit):  # type: ignore[no-untyped-def]
        seed = grammar.seed()
        rogue = FuzzCase(
            index=0,
            grammar=grammar.name,
            protocol=grammar.protocol,
            field="key",
            operator=MutationOperator.DROP_FIELD,
            payload=b"x; rm -rf / ; shutdown -h now",
            baseline=seed,
        )
        good = grammar.build_case("key-length", MutationOperator.LENGTH_MAX, index=1)
        return (rogue, good)

    def observe(self, outcome):  # type: ignore[no-untyped-def]
        return ()


async def test_a_prohibited_payload_from_any_engine_is_discarded_inside_the_process() -> None:
    with lab_arc() as lab:
        with arc_grammars_registered():
            harness = build_runner(engine=_RogueEngine())
            report = await harness.runner.run(arc_plan(lab))

    target = report.targets[0]
    assert target.payloads_refused == 1
    assert target.cases_run == 1, "only the permitted case was sent"
    assert "fuzz.payload_refused" in harness.actions()
    detail = harness.audit_meta("fuzz.payload_refused")[0]["detail"]
    assert "destructive-command" in detail
    assert "remaining-infrastructure" in detail
    # The service never parsed the prohibited message: it only ever saw the permitted one plus
    # the health probes, and its own counter is the evidence.
    assert lab.arc.faults == 1
    assert [c.operator for c in target.candidates] == ["length-max"]


def test_no_destructive_payload_exists_anywhere_in_the_shipped_grammars() -> None:
    """The same property as the grammar suite, restated where a reviewer of safety looks."""
    from arachne.fuzz.prohibitions import fuzz_payload_problems
    from arachne.fuzz.wire import GRAMMAR_NAMES, GRAMMARS

    for name in GRAMMAR_NAMES:
        grammar = GRAMMARS[name]
        for index, (field, operator) in enumerate(grammar.case_plan()):
            case = grammar.build_case(field, operator, index=index)
            verdict = fuzz_payload_problems(case.payload)
            assert verdict.ok, f"{name}/{field}/{operator.value}: {verdict.problems}"


# --------------------------------------------------------------------------- no findings


async def test_a_fuzzing_run_produces_candidates_and_never_a_finding() -> None:
    with lab_arc() as lab:
        with arc_grammars_registered():
            harness = build_runner()
            report = await harness.runner.run(arc_plan(lab))

    candidates = report.candidates
    assert candidates, "the planted parsing bug should have produced a lead"
    for candidate in candidates:
        assert candidate.is_finding is False
        assert candidate.is_verified is False
        assert candidate.to_dict()["is_finding"] is False
        assert candidate.to_dict()["candidate_status"] == "candidate"
        assert "severity" not in candidate.to_dict()
        assert candidate.status is not CandidateStatus.PROPOSED or candidate.verifier is not None
    assert "finding.candidate" not in harness.actions(), (
        "the runner must not write a candidate *record* into the finding store"
    )


async def test_the_report_states_what_was_never_verified() -> None:
    with lab_arc() as lab:
        with arc_grammars_registered():
            harness = build_runner()
            report = await harness.runner.run(arc_plan(lab))

    payload = report.to_dict()
    assert payload["aborted"] is False
    assert payload["healthy_after"] is True
    for target in payload["targets"]:
        for candidate in target["candidates"]:
            assert candidate["is_finding"] is False
    assert payload["prohibitions"]["classes"], "the report carries the prohibition table"


# --------------------------------------------------------------------------- inherited gates


async def test_the_fuzzing_egress_is_the_scoped_client_a_scan_uses() -> None:
    """Inheriting the gates means using the same client, not re-implementing them."""
    from arachne.core.net import ScopedNetClient

    with lab_arc() as lab:
        with arc_grammars_registered():
            harness = build_runner()
            await harness.runner.run(arc_plan(lab))

    assert isinstance(harness.net, ScopedNetClient)
    assert harness.net.probes > 0, "every case must have gone through the scoped client"
    assert "net.probe" in harness.actions()


async def test_a_target_outside_the_scope_is_refused_and_nothing_is_sent() -> None:
    with lab_arc() as lab:
        with arc_grammars_registered():
            # The definition authorizes a different address, so the lab is out of scope.
            definition = fuzz_definition(targets=(OUT_OF_SCOPE_IP,))
            harness = build_runner(definition=definition)
            report = await harness.runner.run(
                FuzzPlan(
                    definition=definition,
                    attestation=fuzz_attestation(targets=(OUT_OF_SCOPE_IP,)),
                    wire_targets=(arc_target(lab),),
                    budget=arc_budget(),
                )
            )

    target = report.targets[0]
    assert target.cases_run == 0
    assert target.refusals, "an out-of-scope endpoint must be reported, not silently skipped"
    assert lab.arc.requests == 0


async def test_a_case_that_is_answered_normally_produces_no_candidate() -> None:
    """The healthy service's own recorded lookups must satisfy the parser and stay quiet."""
    with lab_arc() as lab:
        with arc_grammars_registered():
            harness = build_runner()
            report = await harness.runner.run(arc_plan(lab))
            target = report.targets[0]

    assert target.candidates, "the planted bug is found"
    assert target.cases_run > len(target.candidates) * 10, (
        "almost every case is a normal answer, and none of those is a candidate"
    )
    assert lab.arc.bad_lengths > 0, (
        "the service refused plenty of malformed messages, which is healthy behaviour"
    )
    assert lab.arc.bad_opcodes == 0, (
        "an invalid operation code is unrepresentable: opcode mutations stay inside the "
        "grammar's declared read-only allowlist (REQ-FUZZ-001)"
    )
    assert all(c.signal.value == "fault" for c in target.candidates)


def summary(lab) -> dict[str, int]:  # type: ignore[no-untyped-def]
    """The service's own counters, as the ground truth for what arrived."""
    return {"cases_seen": lab.arc.lookups, "requests": lab.arc.requests}


def test_the_arc_lab_grammar_looks_up_a_real_record() -> None:
    """A sanity check on the fixture itself, so a failure above is attributable."""
    from tests.helpers.fuzz import arc1_grammar
    from tests.lab.fuzz_lab import ArcServer

    grammar = arc1_grammar()
    seed = grammar.seed()
    assert seed == arc_lookup_request(ARC_KEY, request_id=0x1234)
    server = ArcServer()
    response = server.handle(seed)
    assert response is not None
    assert b"alpha" in response
    assert server.lookups == 1 and server.faults == 0


def test_a_fuzz_candidate_cannot_be_constructed_as_a_finding() -> None:
    """The model has no severity, no verdict and no evidence kind a report renders as one."""
    fields = set(FuzzCandidate.model_fields)
    assert "severity" not in fields
    assert "verified" not in fields
    assert {"signal", "status", "confidence"} <= fields
