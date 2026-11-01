"""``arachne report`` — the CLI path (F-06-02/05, F-07-01).

The unit tests cover the builder and the renderers; this file proves the command wires them
to the evidence store: a stored scan becomes a Markdown report, ``--format json`` writes the
versioned document, and ``--diff-with`` records exactly one ``scans_diff`` row.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path

import pytest
from tests.helpers.report import PLAN
from typer.testing import CliRunner

from arachne.analyzer.model import Analysis, Provenance, Remediation, ScoreBreakdown
from arachne.cli.main import app
from arachne.core.config import get_settings, reset_settings_cache
from arachne.core.results import CheckResult, Evidence
from arachne.data.analysis_store import SqlAnalysisStore
from arachne.data.db import create_db_engine, create_session_factory
from arachne.data.finding_store import SqlFindingStore
from arachne.data.models import Target
from arachne.data.report_store import SqlScanDiffStore
from arachne.data.scan_store import SqlScanStateStore
from arachne.modules.registry import ModuleRegistry

runner = CliRunner()


@pytest.fixture
def cli_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[str]:
    monkeypatch.setenv("ARACHNE_DATABASE_URL", f"sqlite:///{tmp_path / 'cli-report.db'}")
    monkeypatch.setenv("ARACHNE_LOG_LEVEL", "CRITICAL")
    monkeypatch.setenv("ARACHNE_LOG_JSON", "false")
    reset_settings_cache()
    try:
        upgraded = runner.invoke(app, ["db", "upgrade"])
        assert upgraded.exit_code == 0, upgraded.output
        yield get_settings().database_url
    finally:
        reset_settings_cache()


def _seed_scan(*, asset_value: str = "https://target.example/.env") -> int:
    engine = create_db_engine(settings=get_settings())
    factory = create_session_factory(engine)
    try:
        with factory() as session:
            target = Target(name="target.example", scope_json={"allowed_hosts": ["target.example"]})
            session.add(target)
            session.commit()
            target_id = int(target.id)
        scans = SqlScanStateStore(factory)
        scan = scans.create_scan(target_id=target_id, engine="heuristic", plan=PLAN)
        scans.update_scan(scan.id, status=None, mark_started=True)
        asset = scans.add_asset(scan.id, kind="url", value=asset_value, meta={"tags": ["web"]})
        findings = SqlFindingStore(factory)
        ids = findings.record_checks(
            [
                m
                for g in ModuleRegistry.discover().groups
                for m in g.metadata()
                if m.id == "m4.env-file-probe"
            ]
        )
        candidate = findings.record_candidate(
            scan.id,
            result=CheckResult(
                status="vulnerable",
                title="Sensitive environment file exposed",
                detail="returned 200",
                cwe="CWE-200",
                confidence=0.9,
                check="m4.env-file-probe",
                module="M4",
                evidence=(
                    Evidence.of("http_request", {"method": "GET", "url": asset_value}),
                    Evidence.of(
                        "http_response",
                        {"status_code": 200, "body": "AWS_ACCESS_KEY_ID=[REDACTED:aws-key]"},
                    ),
                ),
            ),
            check_id=ids["M4/env-file-probe@1.0"],
            asset_id=asset.id,
            asset=("url", asset_value),
        )
        analysis = Analysis(
            title=candidate.title,
            severity="high",
            confidence=92,
            narrative="The file returned 200 with credentials (redacted).",
            remediation=Remediation(
                id="env-file-exposure",
                summary="Block .env and rotate the credentials.",
                steps=("1. Add a deny rule.",),
                verification=("1. Re-request; it must be 404.",),
                references=("https://cwe.mitre.org/data/definitions/200.html",),
            ),
            cwe="CWE-200",
            score=ScoreBreakdown(cvss_base=7.5, owasp_risk="high", confidence=92),
            provenance=Provenance(engine="heuristic", rule_ids=("exposure.env-file",)),
        )
        SqlAnalysisStore(factory).apply(
            scan.id, [replace(analysis, finding_id=candidate.id)], engine="heuristic"
        )
        scans.update_scan(scan.id, status=None, mark_finished=True)
        return scan.id
    finally:
        engine.dispose()


def test_report_prints_markdown_by_default(cli_db: str) -> None:
    scan_id = _seed_scan()
    result = runner.invoke(app, ["report", "--scan", str(scan_id)])
    assert result.exit_code == 0, result.output
    assert "# Security Assessment Report — target.example" in result.output
    assert "## 1. Executive summary" in result.output
    assert "## 12. Appendix" in result.output
    assert "| High | 1 |" in result.output


def test_report_writes_a_json_document(cli_db: str, tmp_path: Path) -> None:
    import json

    scan_id = _seed_scan()
    out = tmp_path / "report.json"
    result = runner.invoke(
        app, ["report", "--scan", str(scan_id), "--format", "json", "--output", str(out)]
    )
    assert result.exit_code == 0, result.output
    document = json.loads(out.read_text())
    from arachne.report.model import REPORT_SCHEMA_VERSION

    assert document["schema_version"] == REPORT_SCHEMA_VERSION
    assert document["findings"][0]["severity"] == "high"
    assert "wrote json report" in result.output


def test_report_diff_records_exactly_one_scans_diff_row(cli_db: str) -> None:
    older = _seed_scan(asset_value="https://target.example/.env")
    newer = _seed_scan(asset_value="https://target.example/admin")
    result = runner.invoke(app, ["report", "--scan", str(newer), "--diff-with", str(older)])
    assert result.exit_code == 0, result.output
    assert f"Change since scan scan_{older}" in result.output

    engine = create_db_engine(settings=get_settings())
    factory = create_session_factory(engine)
    try:
        store = SqlScanDiffStore(factory)
        stored = store.get(older, newer)
        assert stored is not None
        assert stored.changes["counts"]["new"] == 1
        assert stored.changes["counts"]["fixed"] == 1
        # Running the comparison again replaces the row rather than appending.
        again = runner.invoke(app, ["report", "--scan", str(newer), "--diff-with", str(older)])
        assert again.exit_code == 0
        assert store.get(older, newer) is not None
        assert len(store.list_for_scan(newer)) == 1
    finally:
        engine.dispose()


def test_report_rejects_an_unknown_scan(cli_db: str) -> None:
    result = runner.invoke(app, ["report", "--scan", "999"])
    assert result.exit_code != 0
