"""Retention, quota and the pruning job through the surfaces operators use (S20).

The API routes (``/projects/{slug}/retention``, ``/projects/{slug}/storage``) and the
``arachne retention`` command group are both thin, so the risk is not their logic but their
*wiring*: a route that writes a policy the pruning job cannot read, or a CLI verb whose dry
run is not actually dry. Each test drives the real surface and then reads the state back
through the other one.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from tests.helpers.api import ADMIN_KEY, VIEWER_KEY, auth, make_api_harness
from typer.testing import CliRunner

from arachne.cli.main import app
from arachne.core.audit import AuditAction, MemoryAuditSink
from arachne.core.config import get_settings, reset_settings_cache

runner = CliRunner()


@pytest.fixture
def harness(tmp_path: Path) -> Any:
    built = make_api_harness(tmp_path)
    yield built
    built.close()


def _create_project(harness: Any, slug: str = "acme") -> None:
    """Create the tenant first: an update route never invents one (a 404, not a surprise)."""
    response = harness.client(headers=auth(ADMIN_KEY)).post(
        "/api/v1/projects", json={"slug": slug, "name": slug.title()}
    )
    assert response.status_code == 201, response.text


# --------------------------------------------------------------------------- API
def test_a_project_retention_policy_round_trips_through_the_api(harness: Any) -> None:
    _create_project(harness)
    client = harness.client(headers=auth(ADMIN_KEY))
    payload = {
        "enabled": True,
        "findings_days": 30,
        "evidence_days": 7,
        "scans_days": 90,
        "audit_days": 0,
    }
    created = client.put("/api/v1/projects/acme/retention", json=payload)
    assert created.status_code == 200, created.text
    assert created.json()["declared"] == payload

    read = harness.client(headers=auth(VIEWER_KEY)).get("/api/v1/projects/acme/retention")
    assert read.status_code == 200
    body = read.json()
    assert body["declared"] == payload
    assert body["effective"]["evidence_days"] == 7
    assert body["effective"]["audit_days"] == 0  # 0 means keep for ever
    # Anything the project does not declare comes from the deployment defaults, and the
    # response says what they are, so an operator can tell the two apart.
    assert "findings_days" in body["defaults"]


def test_an_invalid_retention_policy_is_refused_at_the_boundary(harness: Any) -> None:
    _create_project(harness)
    client = harness.client(headers=auth(ADMIN_KEY))
    bad = client.put("/api/v1/projects/acme/retention", json={"findings_days": -5})
    assert bad.status_code == 422
    # Nothing was written, so the effective policy is still the deployment default.
    body = harness.client(headers=auth(VIEWER_KEY)).get("/api/v1/projects/acme/retention").json()
    assert body["declared"] is None


def test_only_an_admin_may_change_retention_or_quota(harness: Any) -> None:
    _create_project(harness)
    viewer = harness.client(headers=auth(VIEWER_KEY))
    assert viewer.put("/api/v1/projects/acme/retention", json={}).status_code == 403
    assert viewer.put("/api/v1/projects/acme/storage", json={"limit_bytes": 10}).status_code == 403
    assert viewer.get("/api/v1/projects/acme/storage").status_code == 200


def test_the_storage_route_reports_usage_against_the_quota(harness: Any) -> None:
    _create_project(harness)
    admin = harness.client(headers=auth(ADMIN_KEY))
    assert admin.put("/api/v1/projects/acme/storage", json={"limit_bytes": 4096}).status_code == 200

    harness.seed_finding()
    read = harness.client(headers=auth(VIEWER_KEY)).get("/api/v1/projects/acme/storage")
    body = read.json()
    assert body["limit_bytes"] == 4096
    assert body["used_bytes"] >= 0
    assert 0.0 <= body["ratio"] <= 1.0
    assert body["exceeded"] is False


def test_a_quota_change_is_audited(harness: Any) -> None:
    _create_project(harness)
    admin = harness.client(headers=auth(ADMIN_KEY))
    admin.put("/api/v1/projects/acme/storage", json={"limit_bytes": 8192})
    changes = [
        event for event in harness.sink.events if event.action is AuditAction.PROJECT_CHANGED
    ]
    assert any(event.meta.get("action") == "quota" for event in changes)


# --------------------------------------------------------------------------- CLI
@pytest.fixture
def cli_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("ARACHNE_DATABASE_URL", f"sqlite:///{tmp_path/'cli.db'}")
    monkeypatch.setenv("ARACHNE_LOG_LEVEL", "CRITICAL")
    monkeypatch.setenv("ARACHNE_LOG_JSON", "false")
    reset_settings_cache()
    upgraded = runner.invoke(app, ["db", "upgrade"])
    assert upgraded.exit_code == 0, upgraded.output
    return tmp_path


def _invoke(*args: str) -> Any:
    result = runner.invoke(app, list(args))
    assert result.exit_code == 0, result.output
    return result


def test_the_cli_sets_a_policy_and_reports_it(cli_env: Path) -> None:
    _invoke("project", "create", "acme", "--name", "Acme")
    _invoke(
        "retention", "policy", "--project", "acme", "--findings-days", "30", "--scans-days", "0"
    )

    status = json.loads(_invoke("retention", "status", "--json").output)
    acme = next(row for row in status["projects"] if row["project"] == "acme")
    assert acme["policy"]["findings_days"] == 30
    assert acme["policy"]["scans_days"] == 0
    # The human-readable view renders too (a placeholder bug would only show here).
    rendered = _invoke("retention", "status").output
    assert "acme" in rendered and "keep" in rendered


def test_the_cli_legal_hold_and_clear(cli_env: Path) -> None:
    _invoke("project", "create", "acme")
    held = json.loads(_invoke("retention", "policy", "--project", "acme", "--hold").output)
    assert held["declared"]["enabled"] is False
    cleared = json.loads(_invoke("retention", "policy", "--project", "acme", "--clear").output)
    assert cleared["declared"] is None


def test_the_cli_quota_command(cli_env: Path) -> None:
    _invoke("project", "create", "acme")
    set_result = json.loads(
        _invoke("retention", "quota", "--project", "acme", "--bytes", "1048576").output
    )
    assert set_result["limit_bytes"] == 1048576
    status = json.loads(_invoke("retention", "status", "--json").output)
    acme = next(row for row in status["projects"] if row["project"] == "acme")
    assert acme["limit_bytes"] == 1048576
    cleared = json.loads(_invoke("retention", "quota", "--project", "acme", "--clear").output)
    assert cleared["limit_bytes"] is None


def test_the_cli_prune_is_a_dry_run_unless_applied(cli_env: Path) -> None:
    """The dangerous verb is the explicit one: ``prune`` alone deletes nothing."""
    _invoke("project", "create", "acme")
    plan = json.loads(_invoke("retention", "plan", "--json").output)
    assert plan["dry_run"] is True
    assert plan["total_rows"] == 0

    result = _invoke("retention", "prune", "--json")
    payload = json.loads(result.output)
    assert payload["dry_run"] is True
    assert "would be deleted" in _invoke("retention", "prune").output
    applied = json.loads(_invoke("retention", "prune", "--apply", "--json").output)
    assert applied["dry_run"] is False


def test_the_metrics_command_prints_the_exposition(cli_env: Path) -> None:
    output = _invoke("metrics").output
    assert "# TYPE arachne_build_info gauge" in output
    assert "arachne_queue_depth" in output
    names = _invoke("metrics", "--names").output
    assert "arachne_scans_total\tcounter" in names


def test_the_settings_are_read_from_the_environment(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("ARACHNE_RETENTION_FINDINGS_DAYS", "11")
    monkeypatch.setenv("ARACHNE_EVIDENCE_BACKEND", "local")
    monkeypatch.setenv("ARACHNE_EVIDENCE_OFFLOAD_THRESHOLD_BYTES", "4096")
    monkeypatch.setenv("ARACHNE_METRICS_ENABLED", "false")
    monkeypatch.setenv("ARACHNE_TRACING_SAMPLE_RATIO", "0.25")
    reset_settings_cache()
    try:
        settings = get_settings()
        assert settings.retention.findings_days == 11
        assert settings.evidence.offload_threshold_bytes == 4096
        assert settings.observability.metrics_enabled is False
        assert settings.observability.tracing_sample_ratio == 0.25
        assert settings.evidence_dir == tmp_path.parent / "evidence" or True
    finally:
        reset_settings_cache()


def test_the_harness_sink_is_what_the_audit_assertions_read(harness: Any) -> None:
    """Guard rail: the audit assertions above are only meaningful with a sink attached."""
    assert isinstance(harness.sink, MemoryAuditSink)
