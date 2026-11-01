"""What-if simulation: inject a hypothetical state, recompose the paths (S28, REQ-SIM-002).

The lab model has a known three-hop chain on the application (exposure → credentials →
execution), a database host with an access-stage finding, and a legacy host with nothing but
an access-stage finding. Each test states a hypothetical and asserts the *exact* paths that
follow — including the ones that do not, which is the half of "correct paths" a check that
only counted paths would miss.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from tests.helpers.estate import APP_HOST, DB_HOST, LEGACY_HOST, lab_estate

from arachne.core.audit import AuditAction, Auditor, MemoryAuditSink
from arachne.core.errors import SimulationError
from arachne.sim.hypotheses import (
    ChangeSet,
    Hypothesis,
    HypothesisKind,
    load_change_set,
    load_hypotheses,
    parse_hypotheses,
)
from arachne.sim.whatif import (
    ORIGIN_HYPOTHETICAL,
    ORIGIN_OBSERVED,
    apply_hypotheses,
    exposure_score,
    simulate,
)


def test_the_baseline_is_the_estate_as_scanned() -> None:
    graph = lab_estate()

    run = simulate(graph, ())

    assert [path.id for path in run.baseline] == [path.id for path in graph.attack_paths()]
    assert run.hypotheses == ()
    assert run.introduced == ()
    assert run.exposure_before == run.exposure_after
    assert run.provenance == "simulated"


def test_a_new_exposure_opens_a_chain_the_scan_could_not_see() -> None:
    """The hypothetical hop is cited by its hypothesis, and the observed hop is not."""
    graph = lab_estate()
    hypothesis = Hypothesis.new_exposure("hyp-1", LEGACY_HOST, port=8443, service="https")

    run = simulate(graph, (hypothesis,))

    legacy = [path for path in run.result if path.path.asset == LEGACY_HOST]
    assert len(legacy) == 1
    path = legacy[0]
    assert [hop.hop.stage.value for hop in path.hops] == ["exposure", "access"]
    assert path.introduced_by == ("hyp-1",)
    assert path.hypothetical
    assert [hop.origin for hop in path.hops] == [ORIGIN_HYPOTHETICAL, ORIGIN_OBSERVED]
    assert path.hops[0].hypothesis_id == "hyp-1"
    assert path.hops[1].hypothesis_id is None


def test_the_injected_service_node_lands_in_the_model_not_only_in_the_paths() -> None:
    graph = lab_estate()
    injected, refusals = apply_hypotheses(
        graph, (Hypothesis.new_exposure("hyp-1", LEGACY_HOST, port=8443, service="https"),)
    )

    assert refusals == ()
    services = [(item.host, item.port, item.protocol) for item in injected.services_of(LEGACY_HOST)]
    assert services == [(LEGACY_HOST, 23, "tcp"), (LEGACY_HOST, 8443, "tcp")]
    assert injected.summary()["weaknesses_hypothetical"] == 1
    assert graph.summary()["weaknesses_hypothetical"] == 0


def test_a_compromised_credential_turns_an_exposed_service_into_a_chain() -> None:
    graph = lab_estate()
    hypothesis = Hypothesis.compromised_credential("hyp-2", DB_HOST, identity="portal")

    run = simulate(graph, (hypothesis,))

    database = [path for path in run.result if path.path.asset == DB_HOST]
    assert len(database) == 1
    assert [hop.hop.stage.value for hop in database[0].hops] == ["credentials", "access"]
    assert database[0].path.severity == "high"
    assert list(run.introduced) == database


def test_a_new_vulnerability_stages_by_its_weakness_class_like_an_observed_one() -> None:
    """A hypothetical CWE-89 hop reaches ``execution``; the staging rules do not fork."""
    graph = lab_estate()
    hypotheses = (
        Hypothesis.new_exposure("hyp-1", LEGACY_HOST, port=8443),
        Hypothesis.new_vulnerability(
            "hyp-3", LEGACY_HOST, title="Newly published RCE", severity="critical", cwe="CWE-89"
        ),
    )

    run = simulate(graph, hypotheses)

    legacy = next(path for path in run.result if path.path.asset == LEGACY_HOST)
    assert [hop.hop.stage.value for hop in legacy.hops] == ["exposure", "access", "execution"]
    assert legacy.path.severity == "critical"
    assert legacy.introduced_by == ("hyp-1", "hyp-3")


def test_a_hypothesis_that_does_not_fit_is_refused_with_a_reason_not_dropped() -> None:
    graph = lab_estate()
    unknown = Hypothesis.new_vulnerability(
        "hyp-9", "not-in-the-model.example", title="Ghost host", severity="high"
    )

    run = simulate(graph, (unknown,))

    assert len(run.refusals) == 1
    assert run.refusals[0].hypothesis.id == "hyp-9"
    assert "no host" in run.refusals[0].reason
    # The rest of the result is still produced: one bad hypothesis is not a failed run.
    assert [path.path.id for path in run.result] == [path.id for path in run.baseline]


def test_an_a_brand_new_exposure_implies_its_host_exists() -> None:
    """Everything else needs evidence the host is real; a new exposure is the exception."""
    graph = lab_estate()
    hypothesis = Hypothesis.new_exposure("hyp-1", "brand-new.example", port=443, service="https")

    run = simulate(graph, (hypothesis,))

    assert run.refusals == ()
    assert run.model_after["hosts"] == run.model_before["hosts"] + 1
    # One hop is not a path: an exposure alone is not a chain.
    assert [path.path.asset for path in run.introduced] == []


def test_an_applied_fix_removes_a_path_and_its_stored_candidate_row() -> None:
    """A fix that closes two links leaves an exposure with nothing to reach."""
    graph = lab_estate()
    change = ChangeSet(
        name="harden-app",
        hypotheses=(
            Hypothesis.applied_fix("fix-1", APP_HOST, "m4.default-credentials"),
            Hypothesis.applied_fix("fix-2", APP_HOST, "m3.sqli-oracle"),
        ),
    )

    run = simulate(graph, change.hypotheses)

    assert run.refusals == ()
    assert [path.id for path in run.baseline] != []
    assert run.result == ()
    assert len(run.removed) == 1
    assert run.exposure_before == 10
    assert run.exposure_after == 0


def test_an_applied_fix_for_a_weakness_nobody_observed_is_refused() -> None:
    graph = lab_estate()
    hypothesis = Hypothesis.applied_fix("fix-1", APP_HOST, "m3.nonexistent-check")

    run = simulate(graph, (hypothesis,))

    assert len(run.refusals) == 1
    assert "no observed" in run.refusals[0].reason


def test_a_what_if_run_never_mutates_the_model_it_read() -> None:
    graph = lab_estate()
    before = (graph.nodes, graph.edges, graph.weaknesses, graph.services)

    simulate(
        graph,
        (
            Hypothesis.new_exposure("hyp-1", LEGACY_HOST, port=8443),
            Hypothesis.compromised_credential("hyp-2", DB_HOST),
            Hypothesis.new_vulnerability("hyp-3", LEGACY_HOST, title="x", severity="low"),
        ),
    )

    assert (graph.nodes, graph.edges, graph.weaknesses, graph.services) == before


def test_the_run_is_audited_as_a_simulation_over_the_named_scans() -> None:
    graph = lab_estate()
    sink = MemoryAuditSink()
    auditor = Auditor(sink, actor="pytest")

    simulate(
        graph,
        (Hypothesis.new_exposure("hyp-1", LEGACY_HOST, port=8443),),
        auditor=auditor,
    )

    events = sink.of_action(AuditAction.SIMULATION_RUN)
    assert len(events) == 1
    assert events[0].meta["provenance"] == "simulated"
    assert events[0].meta["hypotheses"] == 1
    assert events[0].meta["scans"] == [1]


def test_the_hypothesis_budget_is_hard() -> None:
    graph = lab_estate()
    hypotheses = (
        Hypothesis.new_exposure("hyp-1", LEGACY_HOST, port=8443),
        Hypothesis.new_exposure("hyp-2", APP_HOST, port=8443),
    )

    with pytest.raises(SimulationError, match="more than the 1"):
        simulate(graph, hypotheses, max_hypotheses=1)


def test_exposure_score_ranks_by_business_severity_not_by_path_count() -> None:
    graph = lab_estate()
    run = simulate(graph, ())

    assert exposure_score(list(run.baseline)) == 10
    assert run.exposure_before == 10


# ------------------------------------------------------------------ hypothesis documents


def test_a_hypothesis_document_parses_into_validated_states() -> None:
    parsed = parse_hypotheses(
        {
            "hypotheses": [
                {"id": "a", "kind": "new-exposure", "asset": APP_HOST, "port": 8080},
                {
                    "id": "b",
                    "kind": "compromised-credential",
                    "asset": DB_HOST,
                    "identity": "portal",
                    "severity": "critical",
                },
                {
                    "id": "c",
                    "kind": "new-vulnerability",
                    "asset": APP_HOST,
                    "title": "CVE-2026-0001",
                    "severity": "high",
                    "cwe": "89",
                },
                {"id": "d", "kind": "applied-fix", "asset": APP_HOST, "check_id": "m3.sqli-oracle"},
            ]
        }
    )

    assert [item.kind for item in parsed] == [
        HypothesisKind.NEW_EXPOSURE,
        HypothesisKind.COMPROMISED_CREDENTIAL,
        HypothesisKind.NEW_VULNERABILITY,
        HypothesisKind.APPLIED_FIX,
    ]
    assert parsed[0].severity == "high"  # the kind's default
    assert parsed[0].check_id == "sim.new-exposure.a"
    assert parsed[1].severity == "critical"
    assert parsed[2].cwe == "CWE-89"  # a bare number is normalised
    assert parsed[3].target_check_id == "m3.sqli-oracle"


@pytest.mark.parametrize(
    ("document", "message"),
    [
        (
            {"hypotheses": [{"id": "a", "kind": "nope", "asset": APP_HOST}]},
            "unknown hypothesis kind",
        ),
        ({"hypotheses": [{"kind": "new-exposure", "asset": APP_HOST}]}, "needs an id"),
        ({"hypotheses": [{"id": "a", "kind": "new-exposure"}]}, "needs an 'asset'"),
        (
            {
                "hypotheses": [
                    {"id": "a", "kind": "new-exposure", "asset": APP_HOST, "severity": "wow"}
                ]
            },
            "unknown severity",
        ),
        (
            {"hypotheses": [{"id": "a", "kind": "new-exposure", "asset": APP_HOST, "port": 0}]},
            "between 1 and 65535",
        ),
        (
            {
                "hypotheses": [
                    {"id": "a", "kind": "new-exposure", "asset": APP_HOST},
                    {"id": "a", "kind": "new-exposure", "asset": DB_HOST},
                ]
            },
            "duplicate hypothesis id",
        ),
        (
            {"hypotheses": [{"id": "a", "kind": "applied-fix", "asset": APP_HOST}]},
            "target_check_id",
        ),
        ({"not_hypotheses": []}, "no 'hypotheses' list"),
        ({"hypotheses": []}, "names no hypothesis"),
    ],
)
def test_a_malformed_hypothesis_document_fails_closed_with_the_reason(
    document: dict[str, object], message: str
) -> None:
    with pytest.raises(SimulationError, match=message):
        parse_hypotheses(document)


def test_a_hypothesis_document_loads_from_yaml(tmp_path: Path) -> None:
    path = tmp_path / "what-if.yaml"
    path.write_text(
        "hypotheses:\n"
        "  - id: public-admin\n"
        "    kind: new-exposure\n"
        "    asset: app.example\n"
        "    port: 8443\n"
        "    service: https\n"
        "    note: the admin console is published by mistake\n"
        "  - id: leaked-password\n"
        "    kind: compromised-credential\n"
        "    asset: db.internal\n"
        "    identity: portal\n",
        encoding="utf-8",
    )

    hypotheses = load_hypotheses(path)

    assert [item.id for item in hypotheses] == ["public-admin", "leaked-password"]
    assert hypotheses[0].port == 8443


def test_a_change_set_loads_with_its_name(tmp_path: Path) -> None:
    path = tmp_path / "change.yaml"
    path.write_text(
        "name: publish-and-retire\n"
        "description: publish the admin console, retire the legacy service\n"
        "hypotheses:\n"
        "  - id: h1\n"
        "    kind: new-exposure\n"
        "    asset: app.example\n"
        "    port: 8443\n",
        encoding="utf-8",
    )

    change = load_change_set(path)

    assert change.name == "publish-and-retire"
    assert change.description.startswith("publish the admin console")
    assert len(change.hypotheses) == 1, "the name must not be read as a hypothesis"


def test_a_missing_hypothesis_document_is_a_clean_refusal(tmp_path: Path) -> None:
    with pytest.raises(SimulationError, match="not found"):
        load_hypotheses(tmp_path / "absent.yaml")

    with pytest.raises(SimulationError, match="not found"):
        load_change_set(tmp_path / "absent.yaml")


def test_an_empty_change_set_name_is_refused() -> None:
    with pytest.raises(SimulationError, match="needs a name"):
        ChangeSet(name="  ")
