"""Acceptance: candidates flow through the analyzer, and weak signals compound.

Two DONE criteria of stage S5, end to end over the real wiring:

1. A live scan's candidates reach the analysis step and land as **analysed findings** —
   severity, confidence, CWE, narrative and remediation in the database. The scan runs
   against recorded responses (no socket), so "live" here means the full pipeline, not a
   network.
2. Two weak signals on one asset produce **one compound finding** whose severity is
   upgraded, with its contributors recorded.
"""

from __future__ import annotations

import json
import socket
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from arachne.analyzer.handlers import build_analysis_handlers
from arachne.core.audit import Auditor, MemoryAuditSink
from arachne.core.config import OsintSettings, Settings
from arachne.core.events import EventBus
from arachne.core.http import ScopedHttpClient, fixture_transport
from arachne.core.lifecycle import StepContext
from arachne.core.orchestrator import Orchestrator
from arachne.core.planner import ScanStep
from arachne.core.results import CheckResult, Evidence
from arachne.core.safety import Scope, StaticResolver
from arachne.core.target import load_scan_request
from arachne.data.analysis_store import SqlAnalysisStore
from arachne.data.db import create_all, create_session_factory, create_sqlite_engine
from arachne.data.finding_store import SqlFindingStore
from arachne.data.models import AnalysisLog, Check, Finding
from arachne.data.scan_store import SqlScanStateStore
from arachne.data.target_store import SqlTargetStore
from arachne.modules.handlers import build_handlers
from arachne.modules.providers.fixtures import FixtureReplay, load_fixture_routes
from arachne.modules.registry import ModuleRegistry

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
TARGET_FIXTURE = FIXTURES / "targets" / "m1-fixture.yaml"
OSINT_FIXTURES = FIXTURES / "osint"
HTTP_FIXTURES = FIXTURES / "http"
SEARCH_URL = "https://search.example.net/search?q={query}&limit={limit}&format=json"


@pytest.fixture(autouse=True)
def _no_sockets(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[str]]:
    attempts: list[str] = []

    def forbidden(*args: object, **kwargs: object) -> None:
        attempts.append(str(args[:1]))
        raise AssertionError("the analysis integration test attempted real network access")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    yield attempts
    assert attempts == []


@pytest.fixture
def settings() -> Settings:
    return Settings(
        database_url="sqlite:///:memory:",
        log_level="CRITICAL",
        http_fixtures=str(HTTP_FIXTURES),
        osint=OsintSettings(
            enabled=True,
            providers=("crtsh", "circl", "wayback", "commoncrawl", "internetdb"),
            search_url=SEARCH_URL,
            fixtures_dir=str(OSINT_FIXTURES),
            request_budget=50,
        ),
    )


@pytest.fixture
def factory(tmp_path: Path) -> Iterator[sessionmaker[Session]]:
    engine = create_sqlite_engine(f"sqlite:///{tmp_path / 'pipeline.db'}")
    create_all(engine)
    try:
        yield create_session_factory(engine)
    finally:
        engine.dispose()


def _client(scope: Scope, auditor: Auditor) -> ScopedHttpClient:
    replay = FixtureReplay(load_fixture_routes(HTTP_FIXTURES))
    return ScopedHttpClient(
        scope=scope,
        auditor=auditor,
        resolver=StaticResolver(replay.address()),
        transport=fixture_transport(replay.responses()),
    )


# --------------------------------------------------------------------------- criterion 1


async def test_a_live_scan_produces_analysed_findings(
    settings: Settings, factory: sessionmaker[Session]
) -> None:
    registry = ModuleRegistry.discover()
    store = SqlScanStateStore(factory)
    findings = SqlFindingStore(factory)
    analyses = SqlAnalysisStore(factory)
    auditor = Auditor(MemoryAuditSink(), actor="pytest")
    handlers = build_handlers(
        settings=settings,
        registry=registry,
        findings=findings,
        auditor=auditor,
        analyses=analyses,
    )
    orchestrator = Orchestrator(
        settings=settings,
        store=store,
        target_store=SqlTargetStore(factory),
        auditor=auditor,
        bus=EventBus(),
        handlers=handlers,
        registry=registry,
        client_factory=lambda scope: _client(scope, auditor),
    )
    request = load_scan_request(TARGET_FIXTURE)
    session = await orchestrator.scan(request)
    scan_id = session.scan_id or 0

    with factory() as db:
        rows = db.scalars(select(Finding).where(Finding.scan_id == scan_id)).all()
        logs = db.scalars(
            select(AnalysisLog).where(
                AnalysisLog.finding_id.in_(select(Finding.id).where(Finding.scan_id == scan_id))
            )
        ).all()
    assert rows, "the scan produced no candidate findings"
    assert len(logs) >= len(rows)

    for row in rows:
        # DONE criterion 1: severity, confidence and remediation are all set by the analyzer.
        assert row.severity in {"critical", "high", "medium", "low", "info"}
        assert row.confidence is not None and 0 <= row.confidence <= 100
        assert row.remediation_id
        assert row.status in {"open", "verified", "fp", "merged"}

    payloads = [json.loads(json.dumps(log.output_json)) for log in logs]
    for payload in payloads:
        assert payload["narrative"], "every analysis carries a narrative"
        assert payload["remediation"]["summary"]
        assert payload["cwe"], "every analysis carries a classification"
        assert payload["provenance"]["engine"] == "heuristic"
    # At least one analysis came from a specific rule rather than a module baseline.
    assert any(
        rule
        for payload in payloads
        for rule in payload["provenance"]["rule_ids"]
        if not rule.startswith("baseline.")
    )

    # The step's own statistics record what the analyzer decided.
    record = orchestrator.store.get_scan(scan_id)
    assert record is not None
    analysis_state = record.step_state(ScanStep.ANALYSIS)
    assert analysis_state is not None
    assert analysis_state.status.value == "completed"
    assert analysis_state.stats["candidates_analyzed"] >= 1
    assert analysis_state.stats["findings"] >= 1


# --------------------------------------------------------------------------- criterion 2


def seed(factory: sessionmaker[Session]) -> tuple[int, int, int]:
    """Create a scan with one web finding and one service finding on the same host."""
    store = SqlScanStateStore(factory)
    findings = SqlFindingStore(factory)
    from arachne.data.target_store import SqlTargetStore

    target_id = SqlTargetStore(factory).save(load_scan_request(TARGET_FIXTURE).target)
    scan = store.create_scan(target_id=target_id, engine="heuristic", plan={})
    scan_id = scan.id
    web = store.add_asset(scan_id, kind="url", value="https://example.com/app.js")
    host = store.add_asset(scan_id, kind="host", value="example.com")
    with factory() as db:
        web_check = Check(module="M1", name="js-asset-scan", version="1.0", cwe="CWE-798")
        db_check = Check(module="M2", name="db-service-probe", version="1.0", cwe="CWE-284")
        db.add_all([web_check, db_check])
        db.commit()
        web_check_id = int(web_check.id)
        db_check_id = int(db_check.id)

    findings.record_candidate(
        scan_id,
        result=CheckResult(
            status="vulnerable",
            title="1 credential pattern(s) matched in client-side assets at https://example.com/",
            detail="kinds: aws_access_key",
            cwe="CWE-798",
            confidence=0.8,
            check="M1/js-asset-scan@1.0",
            module="M1",
            evidence=(
                Evidence.of(
                    "artifact",
                    {
                        "page": "https://example.com/",
                        "scripts_analysed": 3,
                        "matched_patterns": {"aws_access_key": ["https://example.com/app.js"]},
                    },
                    source="https://example.com/",
                ),
            ),
        ),
        check_id=web_check_id,
        asset_id=web.id,
        asset=("url", "https://example.com/app.js"),
    )
    findings.record_candidate(
        scan_id,
        result=CheckResult(
            status="vulnerable",
            title="unauthenticated Redis instance on example.com:6379",
            detail="Redis answered PING and served INFO without any authentication.",
            cwe="CWE-284",
            confidence=0.95,
            check="M2/db-service-probe@1.0",
            module="M2",
            evidence=(
                Evidence.of(
                    "note",
                    {
                        "service": {
                            "host": "example.com",
                            "port": 6379,
                            "protocol": "tcp",
                            "service": "redis",
                            "identity": {
                                "protocol": "redis",
                                "product": "Redis",
                                "version": "5.0.7",
                            },
                        },
                        "facts": {"authentication": "not required"},
                    },
                    source="example.com:6379",
                ),
            ),
        ),
        check_id=db_check_id,
        asset_id=host.id,
        asset=("host", "example.com"),
    )
    return scan_id, web.id or 0, host.id or 0


async def test_two_weak_signals_become_one_compound_finding(
    settings: Settings, factory: sessionmaker[Session]
) -> None:
    scan_id, _web_asset, _host_asset = seed(factory)
    findings = SqlFindingStore(factory)
    analyses = SqlAnalysisStore(factory)
    registry = ModuleRegistry.discover()
    handlers = build_analysis_handlers(
        settings=settings, registry=registry, findings=findings, analyses=analyses
    )
    context = StepContext(
        scan_id=scan_id,
        step=ScanStep.ANALYSIS,
        definition=load_scan_request(TARGET_FIXTURE).target,
        options=load_scan_request(TARGET_FIXTURE).options,
        scope=Scope.deny_all,
        store=SqlScanStateStore(factory),
        bus=EventBus(),
        auditor=Auditor(MemoryAuditSink(), actor="pytest"),
        http=None,
    )
    analysis_outcome = await handlers[ScanStep.ANALYSIS](context)
    assert analysis_outcome.stats["findings"] == 2

    correlation_outcome = await handlers[ScanStep.CORRELATION](context)
    assert correlation_outcome.stats["compounds"] == 1, correlation_outcome.stats

    with factory() as db:
        compounds = db.scalars(
            select(Finding).where(Finding.scan_id == scan_id, Finding.check_id.is_(None))
        ).all()
        assert len(compounds) == 1
        compound = compounds[0]
        assert compound.severity == "critical"  # upgraded from the contributing severities
        assert compound.check_id is None
        assert "credentials" in compound.title.lower()
        log = db.scalars(select(AnalysisLog).where(AnalysisLog.finding_id == compound.id)).one()
        output = log.output_json
        assert output["correlated"] is True
        assert len(output["contributors"]) == 2
        assert output["narrative"]
        assert output["rule_trace"][0]["rule_id"].startswith("correlation.")

    # Both contributing findings are still there, so the report can show the detail.
    stored = analyses.list_analyses(scan_id)
    assert len(stored) >= 3
    severities = {row.severity for row in stored}
    assert "critical" in severities
    _ = datetime.now(UTC)


async def test_re_running_the_correlation_step_does_not_duplicate_the_compound(
    settings: Settings, factory: sessionmaker[Session]
) -> None:
    """A failed step is re-run on resume; the compound it already wrote must not double."""
    scan_id, _web_asset, _host_asset = seed(factory)
    findings = SqlFindingStore(factory)
    analyses = SqlAnalysisStore(factory)
    registry = ModuleRegistry.discover()
    handlers = build_analysis_handlers(
        settings=settings, registry=registry, findings=findings, analyses=analyses
    )
    context = StepContext(
        scan_id=scan_id,
        step=ScanStep.ANALYSIS,
        definition=load_scan_request(TARGET_FIXTURE).target,
        options=load_scan_request(TARGET_FIXTURE).options,
        scope=Scope.deny_all,
        store=SqlScanStateStore(factory),
        bus=EventBus(),
        auditor=Auditor(MemoryAuditSink(), actor="pytest"),
        http=None,
    )
    assert (await handlers[ScanStep.ANALYSIS](context)).stats["findings"] == 2
    assert (await handlers[ScanStep.CORRELATION](context)).stats["compounds"] == 1

    second_analysis = await handlers[ScanStep.ANALYSIS](context)
    assert second_analysis.stats["candidates_analyzed"] == 0  # already-analysed rows are skipped
    second = await handlers[ScanStep.CORRELATION](context)
    assert second.stats["compounds"] == 0
    with factory() as db:
        compounds = db.scalars(
            select(Finding).where(Finding.scan_id == scan_id, Finding.check_id.is_(None))
        ).all()
    assert len(compounds) == 1
