"""Acceptance: M1 runs against recorded data and emits evidence-bearing candidates.

This is the stage's headline behaviour (docs/spec/08- Phase 1, roadmap): the nine M1 checks
execute end to end, discover assets, raise candidates with evidence, respect the scope guard,
and never touch a network — third-party responses come from recorded fixtures
(``ARACHNE_OSINT_FIXTURES``) and the target's own content from a recording too
(``ARACHNE_HTTP_FIXTURES``).

The scan runs through the real wiring (``build_handlers`` + the lifecycle machine) rather
than by calling checks one at a time, because what is being verified is the *framework*: the
registry selecting checks, the context handing them a scoped client, the scope guard
discarding what is out of scope, and the store persisting candidates with their evidence.
"""

from __future__ import annotations

import socket
from collections.abc import Iterator
from pathlib import Path

import pytest

from arachne.core.audit import AuditAction, Auditor, MemoryAuditSink
from arachne.core.config import OsintSettings, Settings
from arachne.core.events import EventBus, EventType
from arachne.core.http import ScopedHttpClient, fixture_transport
from arachne.core.lifecycle import MemoryScanStateStore, ScanStatus
from arachne.core.orchestrator import Orchestrator
from arachne.core.planner import ScanStep
from arachne.core.safety import Scope, StaticResolver, classify_ip
from arachne.core.target import load_scan_request
from arachne.data.finding_store import MemoryFindingStore
from arachne.modules.handlers import build_handlers
from arachne.modules.providers.fixtures import FIXTURE_ADDRESS, FixtureReplay, load_fixture_routes
from arachne.modules.registry import ModuleRegistry

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
TARGET_FIXTURE = FIXTURES / "targets" / "m1-fixture.yaml"
OSINT_FIXTURES = FIXTURES / "osint"
HTTP_FIXTURES = FIXTURES / "http"
SEARCH_URL = "https://search.example.net/search?q={query}&limit={limit}&format=json"


@pytest.fixture(autouse=True)
def _no_sockets(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[str]]:
    """Fail loudly if anything in this module tries to open a real connection."""
    attempts: list[str] = []

    def forbidden(*args: object, **kwargs: object) -> None:
        attempts.append(str(args[:1]))
        raise AssertionError("the M1 replay scan attempted real network access")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    yield attempts
    assert attempts == [], f"unexpected socket use: {attempts}"


def build_settings(*, osint_enabled: bool = True, search_url: str | None = SEARCH_URL) -> Settings:
    """Settings for a fully offline M1 run (recorded responses on both clients)."""
    return Settings(
        database_url="sqlite:///:memory:",
        log_level="CRITICAL",
        http_fixtures=str(HTTP_FIXTURES),
        osint=OsintSettings(
            enabled=osint_enabled,
            providers=("crtsh", "circl", "wayback", "commoncrawl", "internetdb"),
            search_url=search_url,
            fixtures_dir=str(OSINT_FIXTURES),
            request_budget=50,
        ),
    )


def build_orchestrator(
    settings: Settings,
    *,
    sink: MemoryAuditSink | None = None,
    findings: MemoryFindingStore | None = None,
) -> tuple[Orchestrator, MemoryFindingStore, MemoryAuditSink, EventBus]:
    """An orchestrator over in-memory state with the module-backed handlers wired in."""
    registry = ModuleRegistry.discover()
    store = findings or MemoryFindingStore()
    audit_sink = sink or MemoryAuditSink()
    auditor = Auditor(audit_sink, actor="pytest")
    bus = EventBus()
    handlers = build_handlers(settings=settings, registry=registry, findings=store, auditor=auditor)
    orchestrator = Orchestrator(
        settings=settings,
        store=MemoryScanStateStore(),
        auditor=auditor,
        bus=bus,
        handlers=handlers,
        registry=registry,
        client_factory=lambda scope: _target_client(scope, auditor),
    )
    return orchestrator, store, audit_sink, bus


def _target_client(scope: Scope, auditor: Auditor) -> ScopedHttpClient:
    """The target-scoped client in replay mode (the same wiring the CLI uses)."""
    replay = FixtureReplay(load_fixture_routes(HTTP_FIXTURES))
    return ScopedHttpClient(
        scope=scope,
        auditor=auditor,
        resolver=StaticResolver(replay.address()),
        transport=fixture_transport(replay.responses()),
    )


async def run_scan(settings: Settings | None = None):  # type: ignore[no-untyped-def]
    effective = settings or build_settings()
    orchestrator, findings, sink, bus = build_orchestrator(effective)
    request = load_scan_request(TARGET_FIXTURE)
    session = await orchestrator.scan(request)
    return orchestrator, findings, sink, bus, session


# ------------------------------------------------------------------ the scan itself
async def test_m1_discovers_assets_and_raises_candidates() -> None:
    orchestrator, findings, _sink, bus, session = await run_scan()

    assert session.status is ScanStatus.COMPLETED
    assert session.outcome is not None
    assert session.outcome.assets > 0

    asset_values = {record.value for record in orchestrator.store.list_assets(session.scan_id or 0)}
    # Certificate transparency + passive DNS + archives all fed the inventory.
    assert {"staging.example.com", "jira.example.com", "mail.example.com"} <= asset_values
    assert {"https://example.com/.env", "https://example.com/backup.zip"} <= asset_values
    assert "93.184.216.34" in asset_values

    candidates = findings.list_candidates(session.scan_id or 0)
    assert candidates, "M1 emitted no candidate findings"
    titles = " | ".join(record.title for record in candidates)
    for expected in ("indexed", "archived", "credential pattern", "CVE", "address pattern"):
        assert expected.lower() in titles.lower(), (
            f"missing a candidate about {expected!r}: {titles}"
        )

    # Every candidate carries evidence, and every evidence item is redacted + hashed.
    for record in candidates:
        assert record.evidence, f"{record.title!r} carries no evidence"
        assert record.severity is None, "the module layer must not score (ADR-02)"
        for item in record.evidence:
            assert item.kind in {"note", "artifact", "http_request", "http_response", "banner"}
            assert item.payload
            if item.kind in {"http_request", "http_response"}:
                assert item.sha256

    # The findings/evidences lifecycle was exercised through the real step handler.
    record = orchestrator.store.get_scan(session.scan_id or 0)
    assert record is not None
    step = record.step_state(ScanStep.RECON)
    assert step is not None
    assert step.stats["candidates"] == len(candidates)
    assert step.stats["checks_run"] >= 9

    # The check-completion and finding events fired (docs/spec/02- §2.1).
    types = bus.types()
    assert EventType.HOST_DISCOVERED in types
    assert EventType.CHECK_COMPLETED in types
    assert EventType.FINDING_RAISED in types


async def test_out_of_scope_discovery_is_discarded_and_audited() -> None:
    """A CNAME target outside the scope must not enter the inventory (F-01-02)."""
    orchestrator, _findings, sink, _bus, session = await run_scan()
    values = {record.value for record in orchestrator.store.list_assets(session.scan_id or 0)}
    assert "example-net.example-cdn.net" not in values
    assert not any(value.endswith("example-cdn.net") for value in values)
    assert "admin.example.com" not in values

    discarded = [event for event in sink.events if event.action is AuditAction.SCOPE_DISCARDED]
    assert discarded, "an out-of-scope discovery must be logged"


async def test_the_third_party_script_reference_is_never_fetched() -> None:
    """The target page points at a CDN; the scope guard refuses it (F-01-02, F-08-03)."""
    _orchestrator, _findings, sink, _bus, _session = await run_scan()
    rejected = [event for event in sink.events if event.action is AuditAction.SCOPE_REJECTED]
    assert any("cdn.example.net" in str(event.target) for event in rejected)


async def test_osint_disabled_by_default_means_m1_makes_no_third_party_request() -> None:
    """The safe default (F-02-09): with no OSINT access, only target-scoped work happens."""
    settings = build_settings(osint_enabled=False)
    orchestrator, findings, sink, _bus, session = await run_scan(settings)

    assert session.status is ScanStatus.COMPLETED
    # No third-party source was consulted, and nothing was refused for lack of budget.
    assert not [event for event in sink.events if event.action is AuditAction.OSINT_QUERY]
    assert not [event for event in sink.events if event.action is AuditAction.BUDGET_EXHAUSTED]
    # The only check that can run without OSINT is the one that reads the target's own URLs.
    candidates = findings.list_candidates(session.scan_id or 0)
    assert {record.check_key for record in candidates} <= {"M1/js-asset-scan@1.0"}

    record = orchestrator.store.get_scan(session.scan_id or 0)
    assert record is not None
    step = record.step_state(ScanStep.RECON)
    assert step is not None
    assert step.stats["checks_skipped"] >= 8
    # ``osint_requests`` is only reported when an OSINT client exists at all.
    assert step.stats.get("osint_requests", 0) == 0


async def test_secrets_are_reported_masked_never_in_the_clear() -> None:
    """A hardcoded key extracted from JavaScript is stored masked and hashed (F-08-04)."""
    _orchestrator, findings, _sink, _bus, session = await run_scan()
    blob = repr([record.to_dict() for record in findings.list_candidates(session.scan_id or 0)])
    assert "AKIAIOSFODNN7EXAMPLE" not in blob
    assert "aws-access-key-id" in blob


async def test_a_budget_that_runs_out_degrades_to_a_recorded_finding() -> None:
    """The request budget bounds a scan; hitting it is data, not a crash (docs/spec/07- §4)."""
    settings = build_settings()
    settings = Settings(
        database_url=settings.database_url,
        log_level=settings.log_level,
        http_fixtures=settings.http_fixtures,
        osint=OsintSettings(
            enabled=True,
            providers=settings.osint.providers,
            search_url=SEARCH_URL,
            fixtures_dir=str(OSINT_FIXTURES),
            request_budget=2,
        ),
    )
    _orchestrator, _findings, sink, _bus, session = await run_scan(settings)
    assert session.status is ScanStatus.COMPLETED
    assert [event for event in sink.events if event.action is AuditAction.BUDGET_EXHAUSTED]


def test_the_fixture_address_is_public() -> None:
    """Guard the replay resolver's choice: a private address would be refused by policy."""
    assert classify_ip(FIXTURE_ADDRESS) is None
