"""The operator's chain verification, end to end (WP-14, REQ-PROOF-018).

The unit tests prove the arithmetic; this one runs the command an operator actually runs,
against a real migrated database, and reads its verdict and exit code:

* a clean store verifies and exits 0;
* a blob edited behind the store's back makes ``arachne verify-chain`` exit 1 and print
  ``[evidence.mismatch]`` naming the evidence id;
* the run is itself audited (``integrity.tamper``), so the refusal to say "intact" is part of
  the trail.

It is a *CLI* test on purpose: REQ-PROOF-018's acceptance criterion is about what the command
reports, and a helper called directly would let the command drift from what the helpers do.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import select
from typer.testing import CliRunner

from arachne.cli.main import app
from arachne.core.audit import AuditAction, build_auditor
from arachne.core.config import Settings, get_settings, reset_settings_cache
from arachne.core.integrity import payload_digest
from arachne.data.db import create_session_factory
from arachne.data.integrity_store import SqlAuditChain
from arachne.data.models import AuditLog, Evidence, Finding, Scan, Target

runner = CliRunner()


@pytest.fixture
def database(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / "custody-cli.db"
    monkeypatch.setenv("ARACHNE_DATABASE_URL", f"sqlite:///{path}")
    monkeypatch.setenv("ARACHNE_LOG_LEVEL", "CRITICAL")
    reset_settings_cache()
    upgraded = runner.invoke(app, ["db", "upgrade"])
    assert upgraded.exit_code == 0, upgraded.output
    return path


def _seed(path: Path) -> dict[str, Any]:
    """One scan with one evidence blob, whose digest is recorded in the chain."""
    from arachne.data.db import create_sqlite_engine

    settings = get_settings()
    engine = create_sqlite_engine(f"sqlite:///{path}")
    factory = create_session_factory(engine)
    chain = SqlAuditChain(factory, signer=None)
    auditor = build_auditor(
        Settings(database_url=settings.database_url), chain=chain, logging_enabled=False
    )
    with factory() as session:
        target = Target(name="fixture", scope_json={}, auth_attestation=None)
        session.add(target)
        session.flush()
        scan = Scan(
            target_id=target.id,
            status="completed",
            plan_json={},
            engine="heuristic",
            stats_json={},
        )
        session.add(scan)
        session.flush()
        finding = Finding(
            scan_id=int(scan.id),
            check_id=None,
            asset_id=None,
            title="fixture finding",
            severity=None,
            confidence=50.0,
            status="open",
            evidence_refs_json=[],
        )
        session.add(finding)
        session.flush()
        row = Evidence(
            finding_id=int(finding.id),
            kind="http_response",
            payload_json={"body": "the captured response"},
            sha256=None,
            size_bytes=64,
            storage="inline",
        )
        session.add(row)
        session.flush()
        evidence_id = int(row.id)
        scan_id = int(scan.id)
        record = {
            "evidence_id": evidence_id,
            "sha256": payload_digest(dict(row.payload_json)),
            "kind": row.kind,
            "storage": "inline",
            "size": int(row.size_bytes or 0),
        }
        session.commit()
    # The chain append goes *after* the rows are committed: the chain writes on its own
    # connection, and SQLite would otherwise deadlock against the open write transaction
    # (the same ordering SqlFindingStore keeps in production).
    auditor.record(
        AuditAction.EVIDENCE_CAPTURED,
        scan_id=scan_id,
        target=f"evidence:{evidence_id}",
        meta=record,
    )
    engine.dispose()
    return {"scan": scan_id, "evidence": evidence_id}


def _mutate(path: Path, evidence_id: int) -> None:
    from arachne.data.db import create_sqlite_engine

    engine = create_sqlite_engine(f"sqlite:///{path}")
    with create_session_factory(engine)() as session:
        row = session.get(Evidence, evidence_id)
        assert row is not None
        row.payload_json = {**dict(row.payload_json or {}), "body": "edited after capture"}
        session.commit()
    engine.dispose()


def _actions(path: Path) -> list[str]:
    from arachne.data.db import create_sqlite_engine

    engine = create_sqlite_engine(f"sqlite:///{path}")
    with create_session_factory(engine)() as session:
        actions = [str(value) for value in session.scalars(select(AuditLog.action)).all()]
    engine.dispose()
    return actions


def test_a_clean_store_verifies_and_exits_zero(database: Path) -> None:
    _seed(database)
    result = runner.invoke(app, ["verify-chain"])
    assert result.exit_code == 0, result.output
    assert "intact" in result.output
    assert "[evidence.mismatch]" not in result.output


def test_an_edited_evidence_blob_names_its_id_and_exits_one(database: Path) -> None:
    seeded = _seed(database)
    _mutate(database, seeded["evidence"])
    result = runner.invoke(app, ["verify-chain"])
    assert result.exit_code == 1, result.output
    assert "[evidence.mismatch]" in result.output
    assert f"evidence:{seeded['evidence']}" in result.output
    assert "was edited after capture" in result.output
    # The command's own verdict is audited: refusing to say "intact" leaves a trail.
    assert AuditAction.INTEGRITY_TAMPER.value in _actions(database)


def test_the_json_report_names_the_check_and_the_id(database: Path) -> None:
    seeded = _seed(database)
    _mutate(database, seeded["evidence"])
    result = runner.invoke(app, ["verify-chain", "--json"])
    assert result.exit_code == 1, result.output
    import json

    payload = json.loads(result.output[result.output.index("{") :])
    assert payload["ok"] is False
    issues = [issue for issue in payload["issues"] if issue["check"] == "evidence"]
    assert issues and issues[0]["kind"] == "mismatch"
    assert issues[0]["subject"] == f"evidence:{seeded['evidence']}"


def test_a_pruned_scan_is_a_note_not_a_failure(database: Path) -> None:
    seeded = _seed(database)
    from arachne.data.db import create_sqlite_engine

    engine = create_sqlite_engine(f"sqlite:///{database}")
    with create_session_factory(engine)() as session:
        scan = session.get(Scan, seeded["scan"])
        assert scan is not None
        session.delete(scan)
        session.commit()
    engine.dispose()
    result = runner.invoke(app, ["verify-chain"])
    assert result.exit_code == 0, result.output
    assert "pruned" in result.output
