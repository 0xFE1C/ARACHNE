"""Acceptance: the estate model, the what-if engine and the trend over a real lab scan.

REQ-SIM-001's accept criterion is *"model built from lab scans; graph queries return expected
paths"* and REQ-SIM-002's is *"what-if run yields correct paths on the lab model"*. Both are
statements about data that came out of a scan rather than a fixture, so this file runs a
genuine M2 scan against the loopback lab, persists it in a real SQLite stack, and then does
everything area SIM does to it:

* build the model **through the composition root** (``build_estate_graph_for_scan``) and assert
  the host and its services are the lab's — i.e. that reachability is read out of the scan's
  own evidence and not invented;
* inject hypothetical states and assert the resulting paths, on a host the scan found;
* prove the simulation left the store untouched — same candidate set, same gate counts;
* round-trip the trend through the ``simulation_points`` table, drive it from the event bus,
  and render it in the posture view (REQ-SIM-006).
"""

from __future__ import annotations

import asyncio
from collections.abc import Iterator
from pathlib import Path

import pytest
from tests.lab.arachne_lab import LabFixture, m2_lab

from arachne.cli.ci import gate_exit_code
from arachne.core.audit import AuditAction
from arachne.core.config import (
    NetSettings,
    OsintSettings,
    RateLimitSettings,
    SafetySettings,
    Settings,
    SimSettings,
)
from arachne.core.events import Event
from arachne.core.events import EventType as EventKind
from arachne.core.orchestrator import Orchestrator
from arachne.core.safety import Scope, UrlSafetyPolicy
from arachne.core.target import ScanOptions, ScanRequest, TargetDefinition, TargetSelector
from arachne.data.api_store import ApiQueryStore
from arachne.data.db import create_all
from arachne.data.services import (
    ScanServices,
    build_estate_graph_for_scan,
    build_resimulator_for,
    build_services,
)
from arachne.modules.handlers import build_handlers
from arachne.posture.estate import assemble_estate
from arachne.posture.trend import estate_payload, render_estate_markdown
from arachne.sim.hypotheses import Hypothesis
from arachne.sim.trend import build_simulation_trend
from arachne.sim.whatif import simulate

LAB_HOST = "127.0.0.1"
ESTATE = "lab-estate"

#: The five stages, in order — a chain strictly increases through them (the S21 rule the
#: simulation deliberately shares rather than restates).
_STAGE_RANK = {"exposure": 0, "credentials": 1, "access": 2, "execution": 3, "impact": 4}

#: The hypotheticals a what-if run injects on the lab: a service published by mistake, and an
#: advisory assumed exploitable. Together they must produce one chain on the scanned host.
HYPOTHESES = (
    Hypothesis.new_exposure(
        "hyp-1", LAB_HOST, port=8443, service="https", note="the console is published by mistake"
    ),
    Hypothesis.new_vulnerability(
        "hyp-2",
        LAB_HOST,
        title="Newly published RCE in the published console",
        severity="critical",
        cwe="CWE-89",
        note="assume the advisory is exploitable",
    ),
)


def _write_lab_catalog(lab: LabFixture, directory: Path) -> Path:
    """A port catalogue covering the lab's ephemeral ports (F-09-04, ADR-080.4).

    The lab binds ephemeral ports so tests can run in parallel, and the port policy is exactly
    the managed data that decides what ARACHNE probes — so without this the scan would probe
    the standard top-20 ports and find nothing, and the model would have no reachability to
    read.
    """
    entries = "\n".join(
        f"  - {{port: {lab.port(name)}, service: {service}, probe: {probe}}}"
        for name, service, probe in (
            ("ssh", "ssh-alt", "ssh"),
            ("http", "http-alt", "http"),
            ("tls", "https-alt", "tls"),
            ("mysql", "mysql", "mysql"),
            ("redis", "redis", "redis"),
            ("vnc", "vnc", "vnc"),
            ("smtp", "smtp", "smtp"),
            ("dns", "dns", "dns"),
            ("ldap", "ldap", "ldap"),
            ("modbus", "modbus", "modbus"),
            ("smb", "smb", "smb"),
        )
    )
    document = (
        'catalog_version: "lab"\n'
        "source: the ephemeral ports the stdlib lab fixture bound for this test run\n"
        f"tcp:\n{entries}\n"
        "udp: []\n"
    )
    path = directory / "lab-ports.yaml"
    path.write_text(document, encoding="utf-8")
    return path


def _settings(db_path: Path, catalog: Path) -> Settings:
    return Settings(
        database_url=f"sqlite:///{db_path}",
        log_level="CRITICAL",
        log_json=False,
        actor="pytest",
        safety=SafetySettings(
            # The lab is on loopback, which the default policy refuses on purpose.
            policy=UrlSafetyPolicy(allow_loopback=True, allow_private_ips=True),
            scope=Scope(allowed_hosts=(LAB_HOST,)),
        ),
        rate_limit=RateLimitSettings(
            per_host_rate=1000.0,
            per_host_burst=1000,
            global_rate=1000.0,
            global_burst=1000,
        ),
        net=NetSettings(
            connect_timeout_s=1.0,
            read_timeout_s=1.0,
            banner_wait_s=0.2,
            tls_cipher_probes=("DES-CBC3-SHA", "AES128-SHA"),
            max_ports=30,
            max_hosts=4,
            concurrency=8,
            allow_udp=False,
            port_catalog=str(catalog),
            nmap_enabled=False,
        ),
        osint=OsintSettings(enabled=False),
        # REQ-SIM-006 is an opt-in: the re-simulator is *built* either way (so ``--run`` works
        # by hand) but only subscribes to the bus when the deployment asks for it.
        sim=SimSettings(resimulate=True),
    )


def _definition() -> TargetDefinition:
    return TargetDefinition(
        name="s28-lab",
        targets=(TargetSelector(kind="ip", value=LAB_HOST),),
        attestation={
            "attested_by": "S28 builder <s28@arachne.test>",
            "attested_at": "2026-10-01T00:00:00Z",
            "scope_statement": "S28 simulation acceptance on the loopback lab fixture",
            "allowed_targets": [LAB_HOST],
            "authorization_ref": "TEST-S28",
            "active_checks_authorized": True,
        },
    )


@pytest.fixture
def scanned(tmp_path: Path) -> Iterator[tuple[ScanServices, int]]:
    """A real M2 scan of the loopback lab, persisted in a real store."""
    with m2_lab() as lab:
        catalog = _write_lab_catalog(lab, tmp_path)
        services = build_services(_settings(tmp_path / "sim.db", catalog), check_schema=False)
        create_all(services.engine)
        try:
            handlers = build_handlers(
                settings=services.settings,
                registry=services.registry,
                findings=services.findings,
                analyses=services.analyses,
                auditor=services.auditor,
                feeds=services.feeds,
                vault=services.credentials,
                posture=services.posture,
            )
            orchestrator = Orchestrator(
                settings=services.settings,
                store=services.store,
                target_store=services.target_store,
                auditor=services.auditor,
                bus=services.bus,
                handlers=handlers,
                registry=services.registry,
            )
            session = asyncio.run(
                orchestrator.scan(
                    ScanRequest(target=_definition(), options=ScanOptions(active_checks=True))
                )
            )
            assert session.scan_id is not None
            yield services, int(session.scan_id)
        finally:
            services.close()


def _audit_actions(services: ScanServices) -> list[str]:
    """Every action in this deployment's durable audit trail (the chain writes the rows)."""
    from sqlalchemy import select

    from arachne.data import models

    with services.session_factory() as session:
        return [str(row) for row in session.scalars(select(models.AuditLog.action))]


def test_the_model_is_built_from_a_real_lab_scan(scanned: tuple[ScanServices, int]) -> None:
    """REQ-SIM-001: hosts and reachability come from the scan's own stored evidence."""
    services, scan_id = scanned

    graph = build_estate_graph_for_scan(services, scan_id=scan_id, estate_key=ESTATE)

    assert graph.built_from_scans == (scan_id,)
    assert LAB_HOST in graph.hosts
    # The port scan answered, so the model has services — none of them invented.
    observed = graph.services_of(LAB_HOST)
    assert observed, "the lab answered a port probe, so the model must carry services"
    assert all(item.source_check.startswith(("m2.", "m6.")) for item in observed)
    assert graph.observed_weaknesses()
    assert all(item.observed for item in graph.weaknesses)

    # The audit trail records the model's provenance, and that it ran no target interaction.
    assert AuditAction.SIMULATION_MODEL_BUILT.value in _audit_actions(services)


def test_a_what_if_run_yields_the_expected_path_on_the_lab_model(
    scanned: tuple[ScanServices, int],
) -> None:
    """REQ-SIM-002: the injected states produce exactly one new chain, on the scanned host."""
    services, scan_id = scanned
    graph = build_estate_graph_for_scan(services, scan_id=scan_id, estate_key=ESTATE)

    run = simulate(graph, HYPOTHESES, auditor=services.auditor)

    assert run.refusals == ()
    assert run.provenance == "simulated"
    introduced = [path for path in run.introduced if path.path.asset == LAB_HOST]
    assert len(introduced) == 1, [path.path.asset for path in run.introduced]
    path = introduced[0]
    assert path.hypothetical
    assert path.path.severity == "critical"
    # The injected exposure is what opens the chain, and the injected advisory is one of its
    # steps; the chain may then continue into what the scan already found (here, an
    # impact-stage correlation), which is the point of composing over the real estate.
    assert path.hops[0].hop.check_id == "sim.new-exposure.hyp-1"
    assert "sim.new-vulnerability.hyp-2" in [item.hop.check_id for item in path.hops]
    assert [item.hypothesis_id for item in path.hops if item.hypothetical] == ["hyp-1", "hyp-2"]

    # The hypotheticals *lengthen* the chain on that host — the estate as scanned could not
    # reach this many stages without them.
    baseline_here = [item for item in run.baseline if item.asset == LAB_HOST]
    assert baseline_here, "the lab scan composed a path of its own on this host"
    assert len(path.hops) > max(len(item.hops) for item in baseline_here)

    # A chain is a strictly increasing walk, so any hop the scan observed on the way is
    # interleaved in stage order — the composer is the report's own, on scanned data.
    ranks = [_STAGE_RANK[item.hop.stage.value] for item in path.hops]
    assert ranks == sorted(ranks) and len(set(ranks)) == len(ranks)

    # Everything the scan found on this host between the two injected stages must be in the
    # chain: the hypotheticals *extend* the observed estate, they do not replace it.
    between = {
        item.stage.value
        for item in graph.weaknesses_of(LAB_HOST)
        if item.observed
        and _STAGE_RANK["exposure"] < _STAGE_RANK[item.stage.value] < _STAGE_RANK["execution"]
    }
    assert between <= {item.hop.stage.value for item in path.hops}

    # And the baseline is exactly what the verified report composes for this scan.
    assert {item.id for item in run.baseline} == {item.id for item in graph.attack_paths()}


def test_a_simulation_leaves_the_scan_store_and_the_gate_verdict_untouched(
    scanned: tuple[ScanServices, int],
) -> None:
    """REQ-SIM-004: nothing simulated enters a finding store or a gate verdict."""
    services, scan_id = scanned
    queries = ApiQueryStore(services.session_factory)

    before_candidates = [record.id for record in services.findings.list_candidates(scan_id)]
    before_counts = dict(queries.severity_counts(scan_id))
    before_gate = gate_exit_code(before_counts, "high")

    graph = build_estate_graph_for_scan(services, scan_id=scan_id, estate_key=ESTATE)
    run = simulate(graph, HYPOTHESES, auditor=services.auditor)
    assert run.introduced, "the run must produce something, or this proves nothing"

    after_candidates = [record.id for record in services.findings.list_candidates(scan_id)]
    after_counts = dict(queries.severity_counts(scan_id))

    assert after_candidates == before_candidates
    assert after_counts == before_counts
    assert gate_exit_code(after_counts, "high") == before_gate
    # The audit trail says a simulation ran, so the absence of writes is deliberate.
    assert AuditAction.SIMULATION_RUN.value in _audit_actions(services)


def test_the_trend_round_trips_and_feeds_the_posture_view(
    scanned: tuple[ScanServices, int],
) -> None:
    """REQ-SIM-006: a re-simulation stores a point, the bus drives it, posture shows it."""
    services, scan_id = scanned
    store = services.simulations
    assert store is not None

    resim = build_resimulator_for(
        services, estate_key=ESTATE, hypotheses=HYPOTHESES, scan_id=scan_id
    )
    first = resim.run_once(scan_id=scan_id)
    assert first is not None
    assert first.provenance == "simulated"
    assert first.scan_id == scan_id

    # The event-driven half: a finished scan is a model update.
    resim.subscribe(services.bus)
    asyncio.run(services.bus.publish(Event(type=EventKind.SCAN_FINISHED, scan_id=scan_id)))
    resim.close()

    points = store.points(estate_key=ESTATE)
    assert len(points) == 2
    assert all(point.provenance == "simulated" for point in points)

    trend = build_simulation_trend(store.points(estate_key=ESTATE), estate_key=ESTATE)
    assert trend.trend_direction == "flat"
    assert trend.points[0].exposure_score == first.exposure_score

    # The posture view renders the simulated series as its own labelled section...
    estate = assemble_estate(services, project_id=None, name="whole deployment")
    markdown = render_estate_markdown(estate, simulation=trend)
    assert "## Simulated outlook (what-if)" in markdown
    assert "**Simulated.**" in markdown
    assert "area SIM" in markdown

    # ...and the JSON carries it under its own key, never merged into the scan trend.
    payload = estate_payload(estate, simulation=trend)
    assert payload["simulation"]["provenance"] == "simulated"
    assert len(payload["simulation"]["points"]) == 2
    assert payload["scans"], "the observed trend is still there, unmerged"

    # Without a trend the posture view is byte-identical to its pre-S28 form.
    assert "Simulated outlook" not in render_estate_markdown(estate)
    assert "simulation" not in estate_payload(estate)


def test_the_re_simulation_can_be_driven_by_hand_without_an_estate_key(
    scanned: tuple[ScanServices, int],
) -> None:
    """``--run`` without a name still works: the key defaults to the estate's own."""
    services, scan_id = scanned

    resim = build_resimulator_for(services, estate_key="", scan_id=scan_id)
    point = resim.run_once(scan_id=scan_id)

    assert point is not None
    assert point.estate_key == f"scan:{scan_id}"

    payload = point.to_dict()
    assert payload["provenance"] == "simulated"
    assert payload["scan_id"] == scan_id
