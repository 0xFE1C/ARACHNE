"""``arachne compliance`` over a real (SQLite) scan store (S22, REQ-TRUST-001).

The export's verification is end-to-end: a seeded scan with a real finding, the
command run through the CLI, and the written document checked for what makes it
audit-ready — framework identity, per-control states, the finding's evidence payloads
inline, the audit summary, and the unmapped remainder stated.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path

import pytest
from typer.testing import CliRunner

from arachne.analyzer.model import Analysis, Provenance, ScoreBreakdown
from arachne.analyzer.remediation import Remediation
from arachne.cli.main import app
from arachne.core.config import get_settings, reset_settings_cache
from arachne.core.errors import ConfigurationError, ReportError
from arachne.core.results import CheckResult, Evidence
from arachne.data.analysis_store import SqlAnalysisStore
from arachne.data.db import create_db_engine, create_session_factory
from arachne.data.finding_store import SqlFindingStore
from arachne.data.models import Target
from arachne.data.scan_store import SqlScanStateStore
from arachne.modules.registry import ModuleRegistry

runner = CliRunner()


@pytest.fixture
def cli_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[str]:
    monkeypatch.setenv("ARACHNE_DATABASE_URL", f"sqlite:///{tmp_path / 'cli-compliance.db'}")
    monkeypatch.setenv("ARACHNE_LOG_LEVEL", "CRITICAL")
    monkeypatch.setenv("ARACHNE_LOG_JSON", "false")
    reset_settings_cache()
    try:
        upgraded = runner.invoke(app, ["db", "upgrade"])
        assert upgraded.exit_code == 0, upgraded.output
        yield get_settings().database_url
    finally:
        reset_settings_cache()


def _seed_scan() -> int:
    engine = create_db_engine(settings=get_settings())
    factory = create_session_factory(engine)
    try:
        with factory() as session:
            target = Target(name="target.example", scope_json={"allowed_hosts": ["target.example"]})
            session.add(target)
            session.commit()
            target_id = int(target.id)
        scans = SqlScanStateStore(factory)
        scan = scans.create_scan(
            target_id=target_id,
            engine="heuristic",
            plan={
                "target_name": "target.example",
                "engine": "heuristic",
                "checks": [
                    {
                        "module": "M4",
                        "name": "env-file-probe",
                        "version": "1.0",
                        "title": "Exposed environment file",
                        "included": True,
                    }
                ],
            },
        )
        scans.update_scan(scan.id, status=None, mark_started=True)
        asset = scans.add_asset(scan.id, kind="url", value="https://target.example/.env", meta={})
        findings = SqlFindingStore(factory)
        ids = findings.record_checks(
            [
                metadata
                for group in ModuleRegistry.discover().groups
                for metadata in group.metadata()
                if metadata.id == "m4.env-file-probe"
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
                    Evidence.of(
                        "http_request", {"method": "GET", "url": "https://target.example/.env"}
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
                references=(),
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


def test_frameworks_lists_the_bundled_maps() -> None:
    result = runner.invoke(app, ["compliance", "frameworks"])
    assert result.exit_code == 0, result.output
    out = result.output
    for framework in ("cis", "iso27001", "nist-csf", "pci-dss"):
        assert framework in out
    assert "of 93 controls mapped" in out
    assert "of 153 safeguards mapped" in out


def test_the_export_writes_a_self_contained_document(
    cli_db: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    scan_id = _seed_scan()
    target = tmp_path / "iso-evidence.json"
    result = runner.invoke(
        app,
        [
            "compliance",
            "export",
            "--scan",
            str(scan_id),
            "--framework",
            "iso27001",
            "--output",
            str(target),
        ],
    )
    assert result.exit_code == 0, result.output
    document = json.loads(target.read_text(encoding="utf-8"))

    assert document["document"] == "arachne-control-evidence"
    assert document["framework"]["framework"] == "iso27001"
    assert document["framework"]["edition"] == "2022"
    coverage = document["coverage"]
    assert coverage["total_controls"] == 93
    assert coverage["mapped"] == 16 and coverage["unmapped"] == 77
    assert coverage["fail"] >= 1, "the env-file finding fails A.5.17"
    note = coverage["note"]
    assert "not proof of conformity" in note and "cannot be assessed by any scan" in note

    failing = [row for row in document["controls"] if row["status"] == "fail"]
    assert any(row["control"] == "A.5.17" for row in failing)
    a517 = next(row for row in failing if row["control"] == "A.5.17")
    finding_doc = a517["findings"][0]
    assert finding_doc["title"] == "Sensitive environment file exposed"
    assert finding_doc["severity"] == "high"
    assert finding_doc["evidence"], "the evidence payloads travel inline"
    assert finding_doc["evidence"][0]["payload"]["method"] == "GET"
    # Redaction still holds inside the export.
    assert "AKIA" not in json.dumps(document)
    assert "[REDACTED:aws-key]" in json.dumps(document)

    assert document["audit"] is not None, "the audit-trail summary rides along"
    assert document["scan"]["target"] == "target.example"

    # stdout form (no --output) prints the same document.
    stdout = runner.invoke(
        app, ["compliance", "export", "--scan", str(scan_id), "--framework", "iso27001"]
    )
    assert stdout.exit_code == 0, stdout.output
    again = json.loads(stdout.output)
    again.pop("generated_at"), document.pop("generated_at")  # two invocations, two stamps
    assert again == document


def test_the_export_refuses_an_unknown_framework(cli_db: str) -> None:
    result = runner.invoke(app, ["compliance", "export", "--scan", "1", "--framework", "soc2"])
    assert result.exit_code != 0
    assert isinstance(result.exception, ConfigurationError)
    assert "unknown compliance framework" in str(result.exception)


def test_the_export_refuses_an_unknown_scan(cli_db: str) -> None:
    result = runner.invoke(app, ["compliance", "export", "--scan", "9999", "--framework", "cis"])
    assert result.exit_code != 0
    assert isinstance(result.exception, ReportError)
    assert "does not exist" in str(result.exception)
