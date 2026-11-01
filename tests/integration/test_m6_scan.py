"""Acceptance: M6 detects the planted webshell through the real scan pipeline (S11).

The stage's definition of done is "a planted webshell fixture (obfuscated PHP) is detected".
This test runs a *complete* scan — registry selection, the checks step, the heuristic analyzer,
correlation — over a target whose only asset is a local web root holding the fixture, so the
finding is what the pipeline actually persists, not what a check returns in isolation. A
socket guard proves the scan stays offline (M6's local checks send nothing).
"""

from __future__ import annotations

import socket
from collections.abc import Iterator
from pathlib import Path

import pytest
import yaml
from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from arachne.core.audit import Auditor, MemoryAuditSink
from arachne.core.config import Settings
from arachne.core.events import EventBus
from arachne.core.http import ScopedHttpClient, fixture_transport
from arachne.core.orchestrator import Orchestrator
from arachne.core.target import load_scan_request
from arachne.data.analysis_store import SqlAnalysisStore
from arachne.data.db import create_all, create_session_factory, create_sqlite_engine
from arachne.data.finding_store import SqlFindingStore
from arachne.data.models import Finding
from arachne.data.scan_store import SqlScanStateStore
from arachne.data.target_store import SqlTargetStore
from arachne.modules.handlers import build_handlers
from arachne.modules.registry import ModuleRegistry

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
WEBROOT = (FIXTURES / "webroot").resolve()


@pytest.fixture(autouse=True)
def _no_sockets(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[str]]:
    attempts: list[str] = []

    def forbidden(*args: object, **kwargs: object) -> None:
        attempts.append(str(args[:1]))
        raise AssertionError("an M6 local scan attempted network access")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "create_connection", forbidden)
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    yield attempts
    assert attempts == [], f"unexpected socket use: {attempts}"


def _target_fixture(path: Path) -> Path:
    document = {
        "target": {
            "name": "m6-webroot",
            "targets": [{"kind": "cloud", "value": f"repo:{WEBROOT}"}],
            "attestation": {
                "attested_by": "Jane Operator <jane.operator@example.com>",
                "attested_at": "2026-10-01T00:00:00Z",
                "expires_at": "2027-10-01T00:00:00Z",
                "authorization_ref": "S11-TEST",
                "scope_statement": "Unit authorization covering the local web-root fixture",
                "allowed_targets": [f"repo:{WEBROOT}"],
                "active_checks_authorized": False,
            },
        },
        "options": {
            "engine": "heuristic",
            "active_checks": False,
            "modules": {"enabled": ["M6"], "disabled": [], "checks": []},
        },
    }
    fixture = path / "m6-target.yaml"
    fixture.write_text(yaml.safe_dump(document), encoding="utf-8")
    return fixture


@pytest.fixture
def factory(tmp_path: Path) -> Iterator[sessionmaker[Session]]:
    engine = create_sqlite_engine(f"sqlite:///{tmp_path / 'm6.db'}")
    create_all(engine)
    try:
        yield create_session_factory(engine)
    finally:
        engine.dispose()


async def test_a_full_scan_persists_the_webshell_finding(
    tmp_path: Path, factory: sessionmaker[Session]
) -> None:
    settings = Settings(database_url="sqlite:///:memory:", log_level="CRITICAL")
    registry = ModuleRegistry.discover()
    store = SqlScanStateStore(factory)
    findings = SqlFindingStore(factory)
    analyses = SqlAnalysisStore(factory)
    auditor = Auditor(MemoryAuditSink(), actor="pytest")
    handlers = build_handlers(
        settings=settings, registry=registry, findings=findings, auditor=auditor, analyses=analyses
    )

    def client_factory(scope: object) -> ScopedHttpClient:
        # A client that answers nothing: the scan declares no URL asset, so M6 makes no
        # request, and the socket guard above would catch one if it did.
        return ScopedHttpClient(
            scope=scope,  # type: ignore[arg-type]
            auditor=auditor,
            transport=fixture_transport([]),
        )

    orchestrator = Orchestrator(
        settings=settings,
        store=store,
        target_store=SqlTargetStore(factory),
        auditor=auditor,
        bus=EventBus(),
        handlers=handlers,
        registry=registry,
        client_factory=client_factory,
    )
    request = load_scan_request(_target_fixture(tmp_path))
    session = await orchestrator.scan(request)
    scan_id = session.scan_id or 0
    assert scan_id, "the scan produced no id"

    candidates = findings.list_candidates(scan_id)
    webshells = [
        item
        for item in candidates
        if item.check_key and item.check_key.startswith("M6/webshell-yara@")
    ]
    assert webshells, f"no webshell candidate persisted: {[c.title for c in candidates]}"
    # DONE criterion 1: the obfuscated fixture is detected, and the analyzer graded it.
    assert any("shell.php" in item.title for item in webshells)
    with factory() as db:
        rows = db.scalars(select(Finding).where(Finding.scan_id == scan_id)).all()
    assert rows
    assert any(row.severity == "critical" for row in rows)
    assert any(row.remediation_id for row in rows)

    # The signal the rules read is present in the evidence.
    artifact_signals = {
        evidence.payload.get("signal")
        for item in webshells
        for evidence in item.evidence
        if evidence.payload.get("signal")
    }
    assert "webshell" in artifact_signals
