"""Data-model tests (F-09-02).

These assert the spec's column contract and the relational behaviour the orchestrator
will rely on (FK enforcement, cascades), not SQLAlchemy itself.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import Engine, inspect
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from arachne.core.audit import AuditAction, Auditor
from arachne.data.audit_sink import SqlAuditSink
from arachne.data.db import create_db_engine, create_session_factory, session_scope
from arachne.data.models import (
    AnalysisLog,
    Asset,
    AuditLog,
    Base,
    Check,
    Evidence,
    Finding,
    Scan,
    ScanDiff,
    Target,
)
from arachne.data.schema import TABLE_NAMES

#: Columns required by the evidence store (extra columns are allowed).
SPEC_COLUMNS: dict[str, set[str]] = {
    "targets": {"id", "name", "scope_json", "auth_attestation", "created_at"},
    "scans": {
        "id",
        "target_id",
        "status",
        "plan_json",
        "engine",
        "started_at",
        "finished_at",
        "stats_json",
    },
    "assets": {"id", "scan_id", "kind", "value", "meta_json"},
    "checks": {"id", "module", "name", "version", "description", "cwe", "research_ref"},
    "findings": {
        "id",
        "scan_id",
        "check_id",
        "asset_id",
        "title",
        "severity",
        "confidence",
        "status",
        "evidence_refs_json",
        "remediation_id",
    },
    "evidences": {"id", "finding_id", "kind", "payload_json", "sha256"},
    "analysis_log": {
        "id",
        "finding_id",
        "engine",
        "model",
        "template_version",
        "prompt_hash",
        "output_json",
        "tokens_used",
    },
    "audit_log": {"id", "ts", "actor", "action", "meta_json"},
    "scans_diff": {"id", "scan_id_a", "scan_id_b", "changes_json"},
}


@pytest.fixture
def engine(tmp_path: Path) -> Engine:
    engine = create_db_engine(f"sqlite:///{tmp_path / 'store.db'}")
    Base.metadata.create_all(engine)
    try:
        yield engine
    finally:
        engine.dispose()


@pytest.fixture
def session(engine: Engine) -> Session:
    """A plain session: tests flush explicitly and roll back on teardown.

    Deliberately not ``session_scope``: several tests assert that a flush raises
    ``IntegrityError``, which leaves the transaction unusable, so committing on teardown
    would turn a passing assertion into an error.
    """
    unit = create_session_factory(engine)()
    try:
        yield unit
    finally:
        unit.rollback()
        unit.close()


def test_all_spec_tables_exist(engine: Engine) -> None:
    assert set(TABLE_NAMES) <= set(inspect(engine).get_table_names())


@pytest.mark.parametrize("table", sorted(SPEC_COLUMNS))
def test_spec_columns_present(engine: Engine, table: str) -> None:
    columns = {column["name"] for column in inspect(engine).get_columns(table)}
    missing = SPEC_COLUMNS[table] - columns
    assert not missing, f"{table} is missing spec columns: {sorted(missing)}"


def test_target_scan_asset_finding_evidence_round_trip(session: Session) -> None:
    target = Target(
        name="lab",
        scope_json={"hosts": ["example.com"]},
        auth_attestation={"actor": "felix", "scope": "example.com", "signed_at": "2026-10-28"},
    )
    session.add(target)
    session.flush()

    scan = Scan(target_id=target.id, status="running", engine="heuristic", plan_json={"steps": []})
    session.add(scan)
    session.flush()

    asset = Asset(scan_id=scan.id, kind="url", value="https://example.com/", meta_json={})
    check = Check(
        module="M4",
        name="env-file-probe",
        version="0.1.0",
        description="Probe for an exposed .env",
        cwe="CWE-200",
        research_ref="ch04#1",
    )
    session.add_all([asset, check])
    session.flush()

    finding = Finding(
        scan_id=scan.id,
        check_id=check.id,
        asset_id=asset.id,
        title="Exposed .env",
        severity="high",
        confidence=0.9,
        status="open",
        evidence_refs_json=[{"kind": "http_response"}],
    )
    session.add(finding)
    session.flush()

    evidence = Evidence(
        finding_id=finding.id, kind="http_response", payload_json={"status": 200}, sha256="a" * 64
    )
    analysis = AnalysisLog(
        finding_id=finding.id,
        engine="heuristic",
        model=None,
        template_version="v1",
        prompt_hash=None,
        output_json={"severity": "high"},
        tokens_used=0,
    )
    session.add_all([evidence, analysis])
    session.flush()

    assert session.get(Finding, finding.id).title == "Exposed .env"
    assert session.get(Evidence, evidence.id).finding_id == finding.id
    assert session.get(AnalysisLog, analysis.id).tokens_used == 0


def test_foreign_keys_are_enforced(session: Session) -> None:
    session.add(Scan(target_id=999999, status="pending", engine="heuristic"))
    with pytest.raises(IntegrityError):
        session.flush()


def test_deleting_a_target_cascades_to_scans_assets_and_findings(session: Session) -> None:
    target = Target(name="lab", scope_json={})
    session.add(target)
    session.flush()
    scan = Scan(target_id=target.id)
    session.add(scan)
    session.flush()
    session.add(Asset(scan_id=scan.id, kind="host", value="example.com"))
    session.add(Finding(scan_id=scan.id, title="t"))
    session.flush()

    session.delete(target)
    session.flush()

    assert session.query(Scan).count() == 0
    assert session.query(Asset).count() == 0
    assert session.query(Finding).count() == 0


def test_check_catalogue_is_unique_per_module_name_version(session: Session) -> None:
    session.add(Check(module="M1", name="dork-sweep", version="1.0.0"))
    session.flush()
    session.add(Check(module="M1", name="dork-sweep", version="1.0.0"))
    with pytest.raises(IntegrityError):
        session.flush()


def test_scan_diff_rows_reference_two_scans(session: Session) -> None:
    target = Target(name="lab", scope_json={})
    session.add(target)
    session.flush()
    first = Scan(target_id=target.id)
    second = Scan(target_id=target.id)
    session.add_all([first, second])
    session.flush()

    diff = ScanDiff(
        scan_id_a=first.id,
        scan_id_b=second.id,
        changes_json={"new": 1, "fixed": 0, "regressed": 0},
    )
    session.add(diff)
    session.flush()

    assert session.get(ScanDiff, diff.id).changes_json["new"] == 1


def test_sql_audit_sink_persists_events(engine: Engine) -> None:
    factory = create_session_factory(engine)
    auditor = Auditor(SqlAuditSink(factory), actor="pytest")
    event = auditor.record(
        AuditAction.HTTP_REQUEST,
        target="https://example.com/",
        meta={"method": "GET", "status": 200},
    )

    with session_scope(factory) as unit:
        rows = unit.query(AuditLog).all()

    assert len(rows) == 1
    assert rows[0].action == "http.request"
    assert rows[0].actor == "pytest"
    assert rows[0].meta_json["meta"]["status"] == 200
    # SQLite has no timezone type: values round-trip as naive UTC. Compare the instant,
    # not the tzinfo.
    assert rows[0].ts.replace(tzinfo=None) == event.ts.replace(tzinfo=None)


def test_session_scope_rolls_back_on_error(engine: Engine) -> None:
    factory = create_session_factory(engine)
    with pytest.raises(RuntimeError):
        with session_scope(factory) as unit:
            unit.add(Target(name="rolled-back", scope_json={}))
            raise RuntimeError("boom")

    with session_scope(factory) as unit:
        assert unit.query(Target).count() == 0
