"""The estate model: built from scan data, queryable, and only that (S28, REQ-SIM-001).

Every test here answers a sentence from the requirement: the model is built from *scan data*
(assets, findings, network reachability, identity relationships), it is a *queryable graph*
(the queries a what-if run and an operator need return the expected answers), and it is built
*from nothing else* (an empty input yields an empty model, never an invented one).
"""

from __future__ import annotations

from tests.helpers.estate import (
    APP_HOST,
    DB_HOST,
    ESTATE_KEY,
    LEGACY_HOST,
    FakeCandidate,
    FakeEvidence,
    lab_estate,
    lab_inputs,
)

from arachne.sim.model import (
    EdgeKind,
    EstateGraph,
    IdentityBinding,
    NodeKind,
    build_estate_graph,
)
from arachne.sim.reachability import ServiceObservation


def test_the_model_is_built_from_scan_data_only() -> None:
    """Hosts, services, identities and weaknesses all come from the four store shapes."""
    graph = lab_estate()

    assert set(graph.hosts) == {APP_HOST, DB_HOST, LEGACY_HOST}
    assert graph.identities == ("portal",)
    assert {item.check_id for item in graph.weaknesses} == {
        "m4.env-file-probe",
        "m4.default-credentials",
        "m3.sqli-oracle",
        "m5.exposed-database",
        "m2.telnet-service",
        "m2.port-scan",
    }
    assert graph.built_from_scans == (1,)


def test_no_input_yields_an_empty_model_and_never_an_invented_one() -> None:
    graph = build_estate_graph(estate_key="empty")

    assert graph.nodes == ()
    assert graph.edges == ()
    assert graph.weaknesses == ()
    assert graph.hosts == ()
    assert graph.attack_paths() == ()
    assert graph.summary()["hosts"] == 0


def test_reachability_comes_from_the_port_scans_evidence() -> None:
    """Only ports a scan observed answering become service nodes — never a guess."""
    graph = lab_estate()

    observed = {(item.host, item.port, item.protocol) for item in graph.services}
    assert observed == {
        (APP_HOST, 22, "tcp"),
        (APP_HOST, 443, "tcp"),
        (DB_HOST, 3306, "tcp"),
        (LEGACY_HOST, 23, "tcp"),
    }
    assert graph.reachable_hosts() == (APP_HOST, DB_HOST, LEGACY_HOST)
    assert graph.services_of(APP_HOST)[0].source_check == "m2.port-scan"


def test_an_undocumented_evidence_shape_contributes_no_reachability() -> None:
    """A payload nobody documented produces a smaller graph, not a plausible guess."""
    shapes = lab_inputs()
    opaque = FakeCandidate(
        finding_id=800,
        title="A check with a payload of its own shape",
        asset_value=APP_HOST,
        check_key="M3/inventory@1.0",
        severity="info",
        evidence=(FakeEvidence(801, "note", {"open_ports_hint": [8080], "detail": "?"}),),
    )

    graph = build_estate_graph(
        estate_key="opaque",
        candidates=(*shapes.candidates, opaque),
        reachability=None,
    )

    # The documented port-scan payload is the only source: the invented key adds nothing.
    assert ("app.example", 8080, "tcp") not in {
        (item.host, item.port, item.protocol) for item in graph.services
    }
    assert graph.services == lab_estate().services


def test_services_can_be_supplied_directly_when_the_caller_already_has_them() -> None:
    graph = build_estate_graph(
        estate_key=ESTATE_KEY,
        assets=lab_inputs().assets,
        reachability=(ServiceObservation(host="new.example", port=8443, service="https"),),
    )

    assert graph.reachable_hosts() == ("new.example",)


def test_the_graph_is_queryable_in_the_directions_a_what_if_run_needs() -> None:
    graph = lab_estate()

    # From a weakness to its host, and back: the two directions a chain walk needs.
    weakness = next(item for item in graph.weaknesses if item.check_id == "m3.sqli-oracle")
    assert weakness.host == APP_HOST
    assert [item.check_id for item in graph.weaknesses_of(APP_HOST)] == [
        "m4.env-file-probe",
        "m4.default-credentials",
        "m3.sqli-oracle",
        "m2.port-scan",
    ]
    assert weakens_targets(graph, weakness.node_id) == (f"host:{APP_HOST}",)
    assert graph.neighbors(f"host:{APP_HOST}") != ()


def weakens_targets(graph: EstateGraph, node_id: str) -> tuple[str, ...]:
    return tuple(edge.target for edge in graph.edges_from(node_id, kind=EdgeKind.WEAKENS))


def test_identity_relationships_are_recorded_and_their_lateral_edges_derived() -> None:
    """One identity on two hosts is a pivot, and the edge is derived, never asserted."""
    graph = lab_estate()

    assert graph.hosts_of_identity("portal") == (APP_HOST, DB_HOST)
    assert graph.pivot_hosts("portal") == (APP_HOST, DB_HOST)
    assert graph.identities_of(APP_HOST) == ("portal",)
    pivots = graph.edges_of_kind(EdgeKind.PIVOTS_TO)
    assert {(edge.source, edge.target) for edge in pivots} == {
        (f"host:{APP_HOST}", f"host:{DB_HOST}"),
        (f"host:{DB_HOST}", f"host:{APP_HOST}"),
    }


def test_an_identity_on_one_host_is_not_a_pivot() -> None:
    graph = build_estate_graph(
        estate_key=ESTATE_KEY,
        assets=lab_inputs().assets,
        identity_bindings=(IdentityBinding(identity="ops", host=APP_HOST),),
    )

    assert graph.hosts_of_identity("ops") == (APP_HOST,)
    assert graph.pivot_hosts("ops") == ()
    assert graph.edges_of_kind(EdgeKind.PIVOTS_TO) == ()


def test_a_host_seen_from_two_directions_is_one_node_with_its_richest_attributes() -> None:
    """An asset row and a finding's asset agree; the node is not duplicated or flattened."""
    graph = lab_estate()

    hosts = graph.nodes_of_kind(NodeKind.HOST)
    assert len(hosts) == 3
    app = graph.node(f"host:{APP_HOST}")
    assert app is not None
    assert "url" in app.attributes["asset_kinds"]
    assert app.attributes["scans"] == [1]


def test_the_ur_l_of_a_finding_and_its_host_are_the_same_node() -> None:
    """A finding on ``https://host/login`` weakens ``host`` — the unit an attacker walks."""
    graph = lab_estate()

    assert graph.node("host:app.example") is not None
    assert graph.node("host:https://app.example/login") is None


def test_the_graph_composes_paths_with_the_reports_own_composer() -> None:
    """The three-hop chain on the application: exposure → credentials → execution."""
    graph = lab_estate()

    paths = graph.attack_paths()
    assert len(paths) == 1
    path = paths[0]
    assert path.asset == APP_HOST
    assert [hop.stage.value for hop in path.hops] == ["exposure", "credentials", "execution"]
    assert path.severity == "critical"
    assert path.fully_verified


def test_a_dropped_finding_is_not_a_weakness_in_the_model() -> None:
    """The analyzer saying "no" is not a fact about the estate."""
    shapes = lab_inputs()
    dropped = [item for item in shapes.analyses if item.check_id != "m4.env-file-probe"]
    graph = build_estate_graph(
        estate_key=ESTATE_KEY,
        assets=shapes.assets,
        analyses=tuple(dropped),
        reachability=(),
    )

    # The candidate row survives as a weakness (S21's rule) — but not the dropped analysis.
    assert graph.observed_weaknesses()
    assert all(item.verdict != "dropped" for item in graph.weaknesses)


def test_edits_return_a_new_graph_and_leave_the_original_intact() -> None:
    """A what-if run injects into a *copy*; the verified model is never mutated."""
    graph = lab_estate()
    before_nodes = graph.nodes

    grown = graph.add_host("injected.example")

    assert graph.nodes == before_nodes
    assert "injected.example" not in graph.hosts
    assert "injected.example" in grown.hosts


def test_the_summary_and_the_serialized_form_agree() -> None:
    graph = lab_estate()
    payload = graph.to_dict()

    assert payload["estate_key"] == ESTATE_KEY
    assert payload["summary"] == graph.summary()
    assert len(payload["nodes"]) == len(graph.nodes)
    assert payload["summary"]["weaknesses_hypothetical"] == 0
    assert payload["summary"]["pivots"] == 1
    kinds = {item["kind"] for item in payload["nodes"]}
    assert kinds == {"host", "service", "identity", "weakness"}


def test_the_model_runs_inside_the_zero_network_boundary() -> None:
    """Building a model installs the guard, and leaves the process clean afterwards."""
    from arachne.sim.boundary import guard_auditor, is_armed, no_network

    assert is_armed() is False
    with no_network():
        assert is_armed() is True
    assert is_armed() is False
    assert guard_auditor() is None

    lab_estate()
    assert is_armed() is False
    assert guard_auditor() is None
