"""Acceptance for area FUZZ on the protocol lab (S30, REQ-FUZZ-002/005).

REQ-FUZZ-002's acceptance is not "a fuzzer ran": it is "fuzz run on ``tests/lab/`` protocol
fixtures; planted parsing bug found; health proven". All three are asserted here, against a real
ARC/1 service on loopback whose parser has one defect (``tests/lab/fuzz_lab.py``) and whose own
counters are the ground truth for what arrived.

The bug is reachable only by a *well-framed* message whose declared key length the body does not
deliver — the classic unvalidated-length defect — and the fixture's health probe (a STATS
request) is unaffected by it, which is what makes "the service was healthy before and after"
mean something.
"""

from __future__ import annotations

import pytest
from tests.helpers.fuzz import (
    ARC_KEY,
    arc1_grammar,
    arc_budget,
    arc_grammars_registered,
    arc_plan,
    build_runner,
    lab_arc,
)
from tests.lab.fuzz_lab import STATUS_INTERNAL_FAULT, ArcServer, arc_lookup_request

from arachne.fuzz.bounds import STOP_COMPLETED
from arachne.fuzz.candidates import CandidateSignal, CandidateStatus
from arachne.fuzz.grammar import MutationOperator

pytestmark = pytest.mark.lab


async def test_a_bounded_fuzz_run_finds_the_planted_parsing_bug() -> None:
    with lab_arc() as lab:
        with arc_grammars_registered():
            harness = build_runner()
            report = await harness.runner.run(arc_plan(lab, budget=arc_budget(max_cases=200)))

    target = report.targets[0]
    assert report.status == STOP_COMPLETED
    assert target.cases_run == target.cases_planned == 32, "every declared case ran"

    faults = [c for c in target.candidates if c.signal is CandidateSignal.FAULT]
    assert faults, "the planted parsing bug must be reported"
    triggers = {(candidate.field, candidate.operator) for candidate in faults}
    assert ("key-length", MutationOperator.LENGTH_MAX.value) in triggers, (
        "the all-ones key length is the mutation that indexes off the end of the record table"
    )
    for candidate in faults:
        assert "IndexError" in candidate.observation
        assert candidate.payload_sha256
        assert candidate.payload_bytes > 0
        assert candidate.status is CandidateStatus.NEEDS_MANUAL_TRIAGE, (
            "no shipped check can prove an ARC/1 fault, and the candidate says so rather than "
            "naming an unrelated verifier"
        )
        assert candidate.verifier is None
    assert lab.arc.faults >= len(faults), "the fixture's own counter agrees the parser raised"


async def test_the_health_of_the_target_is_proven_before_and_after_every_batch() -> None:
    with lab_arc() as lab:
        with arc_grammars_registered():
            harness = build_runner()
            report = await harness.runner.run(arc_plan(lab, budget=arc_budget(max_cases=200)))

    target = report.targets[0]
    assert target.baseline.ok, "the run would have refused to start against an unwell target"
    assert len(target.baseline.samples) == 3
    assert target.batches >= 2, "the case plan must have been split into batches"
    assert target.healthy_after is True
    assert target.health_after, "each batch is followed by a confirming probe"
    assert all(sample.ok for sample in target.health_after)
    assert report.healthy_after is True

    # The audit trail carries the same claim, so "healthy before and after" is evidence and not
    # only a field in a report.
    health = harness.audit_meta("fuzz.health")
    assert health, "every probe is audited"
    assert {entry["phase"] for entry in health} >= {"before", "after"}


async def test_the_bug_was_found_without_the_service_losing_its_health() -> None:
    """The point of the whole area: a real defect, and a service still answering afterwards."""
    with lab_arc() as lab:
        with arc_grammars_registered():
            harness = build_runner()
            report = await harness.runner.run(arc_plan(lab, budget=arc_budget(max_cases=200)))
            assert report.targets[0].candidates
            assert report.aborted is False

            # A fresh, well-formed lookup still answers correctly *after* the run.
            before = lab.arc.lookups
            response = lab.arc.handle(arc_lookup_request(ARC_KEY))
            assert response is not None
            assert response[4] == 0, "status OK"
            assert b"alpha" in response
            assert lab.arc.lookups == before + 1
        assert lab.arc.dropped == 0 and lab.arc.slow == 0


async def test_an_abort_leaves_the_service_alone_and_the_incident_on_the_record() -> None:
    with lab_arc() as lab:
        with arc_grammars_registered():
            harness = build_runner()
            lab.arm_drop_after(10)
            report = await harness.runner.run(
                arc_plan(lab, budget=arc_budget(max_cases=200, max_requests=200, batch_size=4))
            )

    assert report.aborted is True
    assert report.targets[0].abort_reasons
    assert "fuzz.aborted" in harness.actions()
    assert lab.arc.dropped < 5, "the abort happens at the first signal, not after a full batch"

    # The service recovers once the induced degradation is cleared, which is what lets the run
    # claim it stopped *in time*.
    lab.clear_degradation()
    response = lab.arc.handle(arc_lookup_request(ARC_KEY))
    assert response is not None and response[4] == 0


async def test_a_fingerprint_run_still_finds_the_bug_and_still_stays_healthy() -> None:
    """The second engine changes the order of the work, not the safety of the run."""
    with lab_arc() as lab:
        with arc_grammars_registered():
            harness = build_runner(engine=None)
            report = await harness.runner.run(
                arc_plan(lab, budget=arc_budget(max_cases=200), engine="fingerprint")
            )

    target = report.targets[0]
    assert report.engine == "fingerprint"
    assert "NOT instrumented code coverage" in report.engine_description
    assert any(c.signal is CandidateSignal.FAULT for c in target.candidates)
    assert report.aborted is False
    assert target.healthy_after is True


async def test_the_report_reads_out_what_the_run_did_and_what_it_refused() -> None:
    with lab_arc() as lab:
        with arc_grammars_registered():
            harness = build_runner()
            report = await harness.runner.run(arc_plan(lab))
            payload = report.to_dict()

    assert payload["definition"] == "fuzz-lab"
    assert payload["engine"] == "grammar"
    assert payload["authorization"]["environment_class"] == "non-production"
    assert payload["cases_run"] == payload["targets"][0]["cases_run"]
    assert payload["candidate_count"] == len(payload["targets"][0]["candidates"])
    assert payload["targets"][0]["protocol"] == "arc1"
    assert payload["prohibitions"]["protocols"]
    assert set(payload) >= {"run_id", "status", "aborted", "healthy_after", "budget"}


def test_the_planted_bug_is_the_one_the_grammar_targets() -> None:
    """A direct statement of the fixture's defect, so a failure above is attributable."""
    server = ArcServer()
    seed = arc_lookup_request(ARC_KEY)
    assert server.handle(seed) is not None
    assert server.faults == 0, "well-formed traffic must never reach the defect"

    # The same message with the key length the body does not deliver.
    broken = seed[:8] + b"\xff\xff" + seed[10:]
    response = server.handle(broken)
    assert response is not None
    assert response[4] == STATUS_INTERNAL_FAULT
    assert server.faults == 1
    assert b"IndexError" in response


def test_the_grammars_length_operator_builds_exactly_that_message() -> None:
    grammar = arc1_grammar()
    case = grammar.build_case("key-length", MutationOperator.LENGTH_MAX, index=0)
    assert case.payload[8:10] == b"\xff\xff"
    assert grammar.field("body-length").read(case.payload) == len(case.payload) - 8, (
        "the frame still describes the message: the *content* is what is wrong"
    )
    assert case.payload[4] == 2, "the operation code is untouched and still read-only"


async def test_a_correctly_parsing_service_produces_no_candidate_at_all() -> None:
    """The same run against the same grammar, with the one missing check put back."""
    with lab_arc() as lab:
        lab.arc.strict = True
        with arc_grammars_registered():
            harness = build_runner()
            report = await harness.runner.run(arc_plan(lab, budget=arc_budget(max_cases=200)))

    target = report.targets[0]
    assert target.cases_run > 0, "the same cases ran"
    assert target.healthy_after is True
    assert lab.arc.faults == 0, "a parser that validates its length field raises nothing"
    assert lab.arc.bad_lengths > 0, "it refused the malformed lengths instead"
    assert target.candidates == (), (
        "no candidates: a candidate means the target misbehaved, and this one did not"
    )
