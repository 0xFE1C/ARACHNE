"""Change simulation: the before/after exposure delta of a proposed design (S28, REQ-SIM-005).

A change is only useful if the *comparison* is honest, so the tests assert both directions:
a change that closes the three-hop chain, and a change that opens a critical one. The
`exposure_delta` sign is part of the contract — an operator reading ``-10`` must be reading an
improvement.
"""

from __future__ import annotations

from tests.helpers.estate import APP_HOST, LEGACY_HOST, lab_estate

from arachne.sim.change import simulate_change
from arachne.sim.hypotheses import ChangeSet, Hypothesis


def test_a_hardening_change_closes_the_chain_and_the_delta_is_negative() -> None:
    graph = lab_estate()
    change = ChangeSet(
        name="harden-app",
        description="backend fix closes the default credentials and the injection flaw",
        hypotheses=(
            Hypothesis.applied_fix("fix-1", APP_HOST, "m4.default-credentials", note="rotate"),
            Hypothesis.applied_fix("fix-2", APP_HOST, "m3.sqli-oracle", note="parameterise"),
        ),
    )

    delta = simulate_change(graph, change)

    assert delta.change.name == "harden-app"
    assert len(delta.before) == 1
    assert delta.after == ()
    assert len(delta.removed) == 1
    assert delta.removed[0].asset == APP_HOST
    assert delta.exposure_before == 10
    assert delta.exposure_after == 0
    assert delta.exposure_delta == -10
    assert delta.introduced == ()
    assert delta.provenance == "simulated"


def test_a_publishing_change_opens_a_critical_chain_and_the_delta_is_positive() -> None:
    graph = lab_estate()
    change = ChangeSet(
        name="publish-legacy",
        hypotheses=(
            Hypothesis.new_exposure("pub-1", LEGACY_HOST, port=8443, service="https"),
            Hypothesis.new_vulnerability(
                "pub-2",
                LEGACY_HOST,
                title="Newly published RCE in the legacy console",
                severity="critical",
                cwe="CWE-89",
            ),
        ),
    )

    delta = simulate_change(graph, change)

    assert len(delta.before) == 1
    assert len(delta.after) == 2
    assert [path.path.asset for path in delta.introduced] == [LEGACY_HOST]
    assert delta.introduced[0].path.severity == "critical"
    assert delta.exposure_delta == 10
    assert delta.removed == ()


def test_a_change_that_adds_no_chain_reports_a_zero_delta() -> None:
    """A new host with one exposed service is one hop, and one hop is not a path."""
    graph = lab_estate()
    change = ChangeSet(
        name="add-an-isolated-host",
        hypotheses=(Hypothesis.new_exposure("h1", "isolated.example", port=443),),
    )

    delta = simulate_change(graph, change)

    assert delta.exposure_delta == 0
    assert delta.introduced == ()
    assert delta.removed == ()
    assert delta.exposure_before == delta.exposure_after == 10


def test_an_exposure_that_completes_a_chain_is_not_a_no_op() -> None:
    """The legacy host's access-stage finding means one exposure is worth two points."""
    graph = lab_estate()
    change = ChangeSet(
        name="publish-legacy-console",
        hypotheses=(Hypothesis.new_exposure("h1", LEGACY_HOST, port=9443),),
    )

    delta = simulate_change(graph, change)

    assert delta.exposure_delta == 2
    assert [path.path.asset for path in delta.introduced] == [LEGACY_HOST]
    assert delta.introduced[0].path.severity == "medium"


def test_the_delta_serializes_for_the_report_and_the_cli() -> None:
    graph = lab_estate()
    change = ChangeSet(
        name="harden-app",
        hypotheses=(Hypothesis.applied_fix("fix-1", APP_HOST, "m3.sqli-oracle"),),
    )

    payload = simulate_change(graph, change).to_dict()

    assert payload["name"] == "harden-app"
    assert payload["provenance"] == "simulated"
    assert payload["exposure_before"] == 10
    assert payload["exposure_after"] == 5
    assert payload["exposure_delta"] == -5
    assert payload["paths_before"] == 1
    assert payload["refusals"] == []


def test_a_refusal_inside_a_change_is_carried_into_the_delta() -> None:
    graph = lab_estate()
    change = ChangeSet(
        name="partly-wrong",
        hypotheses=(
            Hypothesis.applied_fix("ok", APP_HOST, "m3.sqli-oracle"),
            Hypothesis.applied_fix("bad", APP_HOST, "m3.not-a-weakness"),
        ),
    )

    delta = simulate_change(graph, change)

    assert len(delta.refusals) == 1
    assert delta.to_dict()["refusals"][0]["id"] == "bad"
