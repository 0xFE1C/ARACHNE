"""SQL-backed report path: the diff table, the audit reader and ``build_report_for_scan``."""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy.orm import Session, sessionmaker
from tests.helpers.report import PLAN

from arachne.analyzer.model import (
    Analysis,
    Provenance,
    Remediation,
    RuleTraceEntry,
    ScoreBreakdown,
)
from arachne.core.audit import AuditAction, AuditEvent, AuditOutcome
from arachne.core.config import Settings
from arachne.core.results import CheckResult, Evidence
from arachne.data.analysis_store import SqlAnalysisStore
from arachne.data.audit_sink import SqlAuditSink
from arachne.data.db import create_all, create_session_factory, create_sqlite_engine
from arachne.data.finding_store import SqlFindingStore
from arachne.data.models import Target
from arachne.data.report_store import SqlAuditReader, SqlScanDiffStore
from arachne.data.scan_store import SqlScanStateStore
from arachne.modules.registry import ModuleRegistry
from arachne.report import build_report_for_scan, render_json

NOW = datetime(2026, 10, 27, 12, 0, tzinfo=UTC)


@pytest.fixture
def factory(tmp_path: Path) -> Iterator[sessionmaker[Session]]:
    engine = create_sqlite_engine(f"sqlite:///{tmp_path / 'report.db'}")
    create_all(engine)
    try:
        yield create_session_factory(engine)
    finally:
        engine.dispose()


def _metadata():
    registry = ModuleRegistry.discover()
    wanted = {"m4.env-file-probe", "m3.security-headers"}
    return [
        metadata
        for group in registry.groups
        for metadata in group.metadata()
        if metadata.id in wanted
    ]


def _analysis() -> Analysis:
    return Analysis(
        title="Sensitive environment file exposed",
        severity="high",
        confidence=92,
        narrative="The .env path returned 200 with credentials (redacted).",
        remediation=Remediation(
            id="env-file-exposure",
            summary="Block .env and rotate the credentials.",
            steps=("1. Add a deny rule.",),
            verification=("1. Re-request; it must be 404.",),
            references=("https://cwe.mitre.org/data/definitions/200.html",),
        ),
        cwe="CWE-200",
        score=ScoreBreakdown(cvss_base=7.5, owasp_risk="high", confidence=92),
        provenance=Provenance(
            engine="heuristic",
            rule_ids=("exposure.env-file",),
            template_version="narrative-v1",
        ),
        rule_trace=(
            RuleTraceEntry(
                rule_id="exposure.env-file",
                clause="severity_if",
                expression="secrets_found and http_status == 200",
                value="high",
            ),
        ),
    )


def _target_id(factory: sessionmaker[Session], name: str = "target.example") -> int:
    with factory() as session:
        target = Target(name=name, scope_json={"allowed_hosts": [name]})
        session.add(target)
        session.commit()
        return int(target.id)


def _new_scan(factory: sessionmaker[Session]) -> int:
    return (
        SqlScanStateStore(factory)
        .create_scan(target_id=_target_id(factory), engine="heuristic", plan=PLAN)
        .id
    )


def _seed_scan(
    factory: sessionmaker[Session],
) -> tuple[int, SqlScanStateStore, SqlFindingStore, SqlAnalysisStore]:
    scans = SqlScanStateStore(factory)
    record = scans.create_scan(target_id=_target_id(factory), engine="heuristic", plan=PLAN)
    scans.update_scan(record.id, status=None, mark_started=True)
    asset = scans.add_asset(
        record.id,
        kind="url",
        value="https://target.example/.env",
        meta={"tags": ["web"], "source": "declared"},
    )
    findings = SqlFindingStore(factory)
    ids = findings.record_checks(_metadata())
    candidate = findings.record_candidate(
        record.id,
        result=CheckResult(
            status="vulnerable",
            title="Sensitive environment file exposed",
            detail="returned 200 with credentials",
            cwe="CWE-200",
            confidence=0.9,
            check="m4.env-file-probe",
            module="M4",
            evidence=(
                Evidence.of(
                    "http_request",
                    {"method": "GET", "url": "https://target.example/.env"},
                ),
                Evidence.of(
                    "http_response",
                    {"status_code": 200, "body": "AWS_ACCESS_KEY_ID=[REDACTED:aws-key]"},
                ),
            ),
        ),
        check_id=ids["M4/env-file-probe@1.0"],
        asset_id=asset.id,
        asset=("url", "https://target.example/.env"),
    )
    analyses = SqlAnalysisStore(factory)
    analyses.apply(
        record.id,
        [replace(_analysis(), finding_id=candidate.id)],
        engine="heuristic",
    )
    sink = SqlAuditSink(factory)
    sink.record(
        AuditEvent(
            ts=datetime.now(UTC),
            actor="pytest",
            action=AuditAction.HTTP_REQUEST,
            scan_id=record.id,
            target="https://target.example/.env",
            meta={"outcome": "allowed"},
        )
    )
    sink.record(
        AuditEvent(
            ts=datetime.now(UTC),
            actor="pytest",
            action=AuditAction.SCOPE_DISCARDED,
            outcome=AuditOutcome.BLOCKED,
            scan_id=record.id,
            target="evil.example",
            reason="not in scope",
        )
    )
    scans.update_scan(record.id, status=None, mark_finished=True)
    return record.id, scans, findings, analyses


def test_build_report_for_scan_reads_the_sql_store(factory: sessionmaker[Session]) -> None:
    scan_id, scans, findings, analyses = _seed_scan(factory)
    reader = SqlAuditReader(factory)
    record = scans.get_scan(scan_id)
    assert record is not None
    events = reader.events_for_scan(
        scan_id, started_at=record.started_at, finished_at=record.finished_at
    )
    report = build_report_for_scan(
        scan_id=scan_id,
        scans=scans,
        findings=findings,
        analyses=analyses,
        audit_events=events,
        module_versions={"M4": "1.0.0"},
        arachne_version="0.1.0",
        settings=Settings(database_url="sqlite:///:memory:"),
        generated_at=NOW,
    )
    assert len(report.findings) == 1
    finding = report.findings[0]
    assert finding.id.startswith("F-") and len(finding.id) == 8
    assert finding.severity == "high"
    assert finding.score.confidence == 92
    assert finding.provenance.analysis_log_id is not None
    assert finding.timestamps.first_seen is not None
    assert finding.evidence_refs
    assert report.appendix.audit.total_events == 2
    assert report.appendix.audit.blocked_events == 1
    assert report.scope.checks_run >= 1
    # The JSON document renders from the SQL-built DTO.
    from arachne.report.model import REPORT_SCHEMA_VERSION

    assert f'"schema_version": "{REPORT_SCHEMA_VERSION}"' in render_json(report)


def test_the_audit_reader_ignores_other_scans(factory: sessionmaker[Session]) -> None:
    scan_id, _scans, _findings, _analyses = _seed_scan(factory)
    SqlAuditSink(factory).record(
        AuditEvent(
            ts=NOW,
            actor="pytest",
            action=AuditAction.HTTP_REQUEST,
            scan_id=scan_id + 1,
            target="other.example",
        )
    )
    events = SqlAuditReader(factory).events_for_scan(scan_id)
    assert all(event.target != "other.example" for event in events)


def test_the_diff_store_upserts_one_row_per_pair(factory: sessionmaker[Session]) -> None:
    scan_a = _new_scan(factory)
    scan_b = _new_scan(factory)
    store = SqlScanDiffStore(factory)
    first = store.save(scan_a, scan_b, {"new": ["a"], "counts": {"new": 1}})
    again = store.save(scan_a, scan_b, {"new": ["a", "b"], "counts": {"new": 2}})
    assert first.id == again.id
    stored = store.get(scan_a, scan_b)
    assert stored is not None
    assert stored.changes["counts"]["new"] == 2
    assert [item.id for item in store.list_for_scan(scan_b)] == [stored.id]
    assert store.get(scan_b, scan_a) is None
