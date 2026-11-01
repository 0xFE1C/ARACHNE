"""The pre-deploy IaC/CI gate (S23, REQ-POSTURE-002).

The acceptance criteria, end to end through the real CLI, the real orchestrator and the
real analyzer: the misconfigured fixture **blocks** the gate (exit 2 at/above the
threshold), the clean fixture **passes** (exit 0), and the findings carry the same
schema as any scan — check provenance, evidence, analyzer severity — because the gate
*is* a scan. The database the CLI writes is read back through the project's own store
API only, never through hand-built SQL.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from typer.testing import CliRunner

from arachne.cli.main import app
from arachne.core.config import get_settings, reset_settings_cache
from arachne.data.db import create_db_engine, create_session_factory
from arachne.data.finding_store import SqlFindingStore
from arachne.data.models import Base

runner = CliRunner()

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "iac"
MISCONFIGURED = FIXTURES / "misconfigured"
CLEAN = FIXTURES / "clean"


@pytest.fixture()
def cli_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    monkeypatch.setenv("ARACHNE_DATABASE_URL", f"sqlite:///{tmp_path / 'iac-gate.db'}")
    monkeypatch.setenv("ARACHNE_LOG_LEVEL", "CRITICAL")
    monkeypatch.setenv("ARACHNE_LOG_JSON", "false")
    reset_settings_cache()
    # A deployment runs `arachne db upgrade` once; the test creates the same schema.
    engine = create_db_engine(settings=get_settings())
    Base.metadata.create_all(engine)
    yield
    reset_settings_cache()


def _store() -> SqlFindingStore:
    """A finding store over the configured database (the sanctioned read path)."""
    engine = create_db_engine(settings=get_settings())
    Base.metadata.create_all(engine)
    return SqlFindingStore(create_session_factory(engine))


def _confirmed_titles() -> list[str]:
    store = _store()
    scan_rows = tuple(_store_scan_ids())
    titles: list[str] = []
    for scan_id in scan_rows:
        for candidate in store.list_candidates(scan_id):
            if candidate.severity is not None and candidate.status != "fp":
                titles.append(candidate.title)
    return titles


def _store_scan_ids() -> list[int]:
    """Every scan id in the database, via the scan store."""
    from arachne.data.scan_store import SqlScanStateStore

    engine = create_db_engine(settings=get_settings())
    Base.metadata.create_all(engine)
    store = SqlScanStateStore(create_session_factory(engine))
    return [record.id for record in store.list_scans(limit=10)]


def test_the_misconfigured_fixture_blocks_the_gate(cli_db: None) -> None:
    """REQ-POSTURE-002's accept criterion: a misconfigured IaC fixture blocks the gate."""
    result = runner.invoke(app, ["iac", "gate", str(MISCONFIGURED), "--fail-on", "high"])
    assert result.exit_code == 2, result.output
    titles = " ".join(_confirmed_titles())
    # Terraform review, the structured Kubernetes policy rules and the CI workflow audit
    # all contributed — through the same finding schema, with analyzer severities.
    assert "0.0.0.0/0" in titles or "open to the world" in titles
    assert "privileged" in titles.lower()
    assert "pull_request_target" in titles or "untrusted PR trigger" in titles


def test_the_clean_fixture_passes_the_gate(cli_db: None) -> None:
    """REQ-POSTURE-002's accept criterion: a clean fixture passes (exit 0)."""
    result = runner.invoke(app, ["iac", "gate", str(CLEAN), "--fail-on", "info"])
    assert result.exit_code == 0, result.output
    assert _confirmed_titles() == []


def test_the_gate_threshold_distinguishes_severities(cli_db: None) -> None:
    """The F-07-05 exit-code policy applies unchanged: 0/1/2 by threshold."""
    result = runner.invoke(app, ["iac", "gate", str(MISCONFIGURED), "--fail-on", "critical"])
    # Findings exist but none is critical → "below threshold" is exit 1.
    assert result.exit_code == 1, result.output
    assert _confirmed_titles()


def test_the_gate_scan_is_a_real_scan_with_check_provenance(cli_db: None) -> None:
    """The findings carry the same schema: check ids, evidence, and the store's rows."""
    runner.invoke(app, ["iac", "gate", str(MISCONFIGURED)])
    store = _store()
    candidates = [
        candidate
        for scan_id in _store_scan_ids()
        for candidate in store.list_candidates(scan_id)
        if candidate.severity is not None
    ]
    assert any(candidate.check_key == "M5/tfstate-exposure@1.1" for candidate in candidates)
    assert all("repo:" in (candidate.asset_value or "") for candidate in candidates)
    # The same capture → store path as any scan: each finding carries linked evidence.
    assert all(candidate.evidence for candidate in candidates)
    assert any(
        item.kind == "artifact"
        for candidate in candidates
        for item in candidate.evidence
    )
