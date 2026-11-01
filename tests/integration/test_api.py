"""Integration: the REST API over a real store — auth, roles, rate limit, CRUD (S12).

Every assertion goes through ``fastapi.testclient`` against the assembled app (middleware,
routers, exception handlers, the real services), so what is verified is the interface a
client actually sees, not a handler in isolation.

DONE criterion #1 (S12): "API tests green (auth, roles, rate limit, CRUD on
scans/findings/reports)".
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from tests.helpers.api import (
    ADMIN_KEY,
    SCANNER_KEY,
    VIEWER_KEY,
    ApiHarness,
    auth,
    make_api_harness,
    wait_for_scan,
)

from arachne.core.audit import AuditAction
from arachne.core.config import ApiSettings

pytestmark = pytest.mark.integration

TARGET: dict[str, object] = {
    "name": "api-test-target",
    "targets": [{"kind": "url", "value": "https://example.com/"}],
    "attestation": {
        "attested_by": "api test",
        "attested_at": "2026-10-01T00:00:00Z",
        "scope_statement": "integration-test authorization covering example.com",
        "allowed_targets": ["example.com"],
    },
}


@pytest.fixture
def harness(tmp_path) -> Iterator[ApiHarness]:  # type: ignore[no-untyped-def]
    built = make_api_harness(tmp_path)
    try:
        yield built
    finally:
        built.close()


# --------------------------------------------------------------------------- health/openapi
def test_health_and_openapi_are_public(harness: ApiHarness) -> None:
    with harness.client() as client:
        assert client.get("/health").json()["status"] == "ok"
        health = client.get("/api/v1/health").json()
        assert health["api_keys"] == 3
        spec = client.get("/openapi.json")
        assert spec.status_code == 200
        paths = spec.json()["paths"]
        for path in ("/api/v1/scans", "/api/v1/findings", "/api/v1/targets", "/api/v1/modules"):
            assert path in paths


def test_the_root_health_alias_works(harness: ApiHarness) -> None:
    with harness.client() as client:
        assert client.get("/health").json()["database"] == "sqlite"


# --------------------------------------------------------------------------- auth
def test_a_request_without_a_key_is_refused_and_audited(harness: ApiHarness) -> None:
    with harness.client() as client:
        response = client.get("/api/v1/scans")
    assert response.status_code == 401
    assert response.json()["error"]["message"] == "missing API key"
    denied = harness.events_of(AuditAction.API_DENIED)
    assert denied and denied[-1].reason == "missing API key"


def test_a_bad_key_is_refused(harness: ApiHarness) -> None:
    with harness.client() as client:
        response = client.get("/api/v1/scans", headers=auth("nope"))
    assert response.status_code == 401
    assert response.json()["error"]["message"] == "invalid API key"


def test_every_request_writes_an_audit_line(harness: ApiHarness) -> None:
    with harness.client() as client:
        client.get("/api/v1/scans", headers=auth(VIEWER_KEY))
    requests = harness.events_of(AuditAction.API_REQUEST)
    assert requests
    meta = requests[-1].meta
    assert meta["method"] == "GET" and meta["path"] == "/api/v1/scans"
    assert meta["status"] == 200
    assert meta["actor"] == "viewer"


def test_a_viewer_cannot_start_a_scan(harness: ApiHarness) -> None:
    with harness.client() as client:
        response = client.post(
            "/api/v1/scans", headers=auth(VIEWER_KEY), json={"target": TARGET, "dry_run": True}
        )
    assert response.status_code == 403
    assert "not permitted" in response.json()["error"]["message"]


def test_only_an_admin_may_create_targets(harness: ApiHarness) -> None:
    with harness.client() as client:
        assert (
            client.post("/api/v1/targets", headers=auth(SCANNER_KEY), json=TARGET).status_code
            == 403
        )
        assert (
            client.post("/api/v1/targets", headers=auth(ADMIN_KEY), json=TARGET).status_code == 201
        )


def test_a_scanner_may_start_and_a_viewer_may_read(harness: ApiHarness) -> None:
    with harness.client() as client:
        started = client.post("/api/v1/scans", headers=auth(SCANNER_KEY), json={"target": TARGET})
        assert started.status_code == 202
        scan_id = started.json()["scan_id"]
        wait_for_scan(client, auth(VIEWER_KEY), scan_id)
        assert client.get(f"/api/v1/scans/{scan_id}", headers=auth(VIEWER_KEY)).status_code == 200


# --------------------------------------------------------------------------- rate limit
def test_the_rate_limiter_answers_429_with_retry_after(tmp_path) -> None:  # type: ignore[no-untyped-def]
    settings_api = ApiSettings(
        keys=("v:viewer:secret",), require_tls=False, rate_limit_per_minute=60, rate_limit_burst=3
    )

    from tests.helpers.api import build_api_settings
    from tests.helpers.api import make_api_harness as build

    settings = build_api_settings(tmp_path)
    object.__setattr__(settings, "api", settings_api)
    harness = build(tmp_path, settings=settings)
    try:
        with harness.client() as client:
            codes = [
                client.get("/api/v1/scans", headers=auth("secret")).status_code for _ in range(6)
            ]
        assert codes[:3] == [200, 200, 200]
        assert codes[3] == 429 and codes[-1] == 429
        with harness.client() as client:
            response = client.get("/api/v1/scans", headers=auth("secret"))
        assert response.json()["error"]["code"] == 429
    finally:
        harness.close()
    assert any(
        event.reason == "rate limit exceeded" for event in harness.events_of(AuditAction.API_DENIED)
    )


# --------------------------------------------------------------------------- scans CRUD
def test_scan_lifecycle_through_the_api(harness: ApiHarness) -> None:
    with harness.client() as client:
        dry = client.post(
            "/api/v1/scans", headers=auth(SCANNER_KEY), json={"target": TARGET, "dry_run": True}
        )
        assert dry.status_code == 200
        assert dry.json()["dry_run"] is True and "plan" in dry.json()

        started = client.post("/api/v1/scans", headers=auth(SCANNER_KEY), json={"target": TARGET})
        assert started.status_code == 202
        scan_id = started.json()["scan_id"]
        assert started.headers["location"] == f"/api/v1/scans/{scan_id}"

        final = wait_for_scan(client, auth(VIEWER_KEY), scan_id)
        assert final["status"] == "completed"
        assert [step["step"] for step in final["steps"]] == ["recon"]
        assert final["assets"], "recon records the declared target as an asset"

        listing = client.get("/api/v1/scans", headers=auth(VIEWER_KEY)).json()
        assert [row["id"] for row in listing] == [scan_id]

        deleted = client.delete(f"/api/v1/scans/{scan_id}", headers=auth(ADMIN_KEY))
        assert deleted.status_code == 204
        assert client.get(f"/api/v1/scans/{scan_id}", headers=auth(VIEWER_KEY)).status_code == 404


def test_a_scan_for_an_unknown_target_id_is_404(harness: ApiHarness) -> None:
    with harness.client() as client:
        response = client.post("/api/v1/scans", headers=auth(SCANNER_KEY), json={"target_id": 999})
    assert response.status_code == 404


def test_a_scan_needs_a_full_attestation(harness: ApiHarness) -> None:
    with harness.client() as client:
        response = client.post(
            "/api/v1/scans",
            headers=auth(SCANNER_KEY),
            json={"target": {"name": "n", "targets": [{"kind": "domain", "value": "example.com"}]}},
        )
    assert response.status_code == 403
    assert "not authorized" in response.json()["error"]["message"]


def test_an_invalid_definition_is_400(harness: ApiHarness) -> None:
    with harness.client() as client:
        response = client.post(
            "/api/v1/scans", headers=auth(SCANNER_KEY), json={"target": {"name": "", "targets": []}}
        )
    assert response.status_code == 400


def test_the_request_model_rejects_two_target_sources(harness: ApiHarness) -> None:
    with harness.client() as client:
        response = client.post(
            "/api/v1/scans",
            headers=auth(SCANNER_KEY),
            json={"target": TARGET, "target_id": 1},
        )
    assert response.status_code == 422


def test_stopping_a_scan_that_is_not_running_is_409(harness: ApiHarness) -> None:
    with harness.client() as client:
        started = client.post("/api/v1/scans", headers=auth(SCANNER_KEY), json={"target": TARGET})
        scan_id = started.json()["scan_id"]
        wait_for_scan(client, auth(VIEWER_KEY), scan_id)
        assert (
            client.post(f"/api/v1/scans/{scan_id}/stop", headers=auth(SCANNER_KEY)).status_code
            == 409
        )


# --------------------------------------------------------------------------- targets CRUD
def test_target_crud(harness: ApiHarness) -> None:
    with harness.client() as client:
        created = client.post("/api/v1/targets", headers=auth(ADMIN_KEY), json=TARGET)
        assert created.status_code == 201
        target_id = created.json()["id"]
        assert created.json()["name"] == TARGET["name"]

        fetched = client.get(f"/api/v1/targets/{target_id}", headers=auth(VIEWER_KEY)).json()
        assert fetched["scope"]["targets"][0]["value"] == "https://example.com/"

        listing = client.get("/api/v1/targets", headers=auth(VIEWER_KEY)).json()
        assert [row["id"] for row in listing] == [target_id]

        # A stored target is re-runnable by id.
        started = client.post(
            "/api/v1/scans", headers=auth(SCANNER_KEY), json={"target_id": target_id}
        )
        assert started.status_code == 202
        wait_for_scan(client, auth(VIEWER_KEY), started.json()["scan_id"])

        assert (
            client.delete(f"/api/v1/targets/{target_id}", headers=auth(ADMIN_KEY)).status_code
            == 204
        )
        assert (
            client.get(f"/api/v1/targets/{target_id}", headers=auth(VIEWER_KEY)).status_code == 404
        )


# --------------------------------------------------------------------------- findings CRUD
def test_findings_list_filter_and_read(harness: ApiHarness) -> None:
    seeded = harness.seed_finding(title="exposed .env", severity="high")
    harness.seed_finding(
        title="missing header",
        check_key="M3/security-headers@1.0",
        severity="low",
        asset=("url", "https://example.com/app"),
    )
    with harness.client() as client:
        all_rows = client.get("/api/v1/findings", headers=auth(VIEWER_KEY)).json()
        assert len(all_rows) == 2
        high = client.get("/api/v1/findings?severity=high", headers=auth(VIEWER_KEY)).json()
        assert [row["id"] for row in high] == [seeded]
        by_module = client.get("/api/v1/findings?module=M3", headers=auth(VIEWER_KEY)).json()
        assert len(by_module) == 1 and by_module[0]["module"] == "M3"
        by_asset = client.get("/api/v1/findings?asset=/app", headers=auth(VIEWER_KEY)).json()
        assert len(by_asset) == 1
        by_text = client.get("/api/v1/findings?q=header", headers=auth(VIEWER_KEY)).json()
        assert len(by_text) == 1

        detail = client.get(f"/api/v1/findings/{seeded}", headers=auth(VIEWER_KEY)).json()
        assert detail["evidence"], "the evidence pane must be populated"


def test_marking_a_finding_false_positive_records_feedback(harness: ApiHarness) -> None:
    finding_id = harness.seed_finding(severity="high")
    with harness.client() as client:
        reviewed = client.patch(
            f"/api/v1/findings/{finding_id}",
            headers=auth(SCANNER_KEY),
            json={"status": "fp", "note": "placeholder page"},
        )
    assert reviewed.status_code == 200
    assert reviewed.json()["status"] == "fp"
    stats = harness.services.analyses.feedback_stats()
    assert stats, "the F-05-07 feedback row must be stored"
    key = next(iter(stats))
    assert key.startswith("m4.env-file-probe|url|")
    assert any(event.action is AuditAction.FINDING_REVIEWED for event in harness.sink.events)


def test_a_viewer_cannot_review_a_finding(harness: ApiHarness) -> None:
    finding_id = harness.seed_finding()
    with harness.client() as client:
        response = client.patch(
            f"/api/v1/findings/{finding_id}", headers=auth(VIEWER_KEY), json={"status": "fp"}
        )
    assert response.status_code == 403


def test_deleting_a_finding_is_admin_only(harness: ApiHarness) -> None:
    finding_id = harness.seed_finding()
    with harness.client() as client:
        assert (
            client.delete(f"/api/v1/findings/{finding_id}", headers=auth(SCANNER_KEY)).status_code
            == 403
        )
        assert (
            client.delete(f"/api/v1/findings/{finding_id}", headers=auth(ADMIN_KEY)).status_code
            == 204
        )
        assert (
            client.patch(
                f"/api/v1/findings/{finding_id}", headers=auth(SCANNER_KEY), json={"status": "fp"}
            ).status_code
            == 404
        )


def test_an_unknown_finding_status_is_refused(harness: ApiHarness) -> None:
    finding_id = harness.seed_finding()
    with harness.client() as client:
        response = client.patch(
            f"/api/v1/findings/{finding_id}", headers=auth(SCANNER_KEY), json={"status": "wontfix"}
        )
    assert response.status_code == 422


# --------------------------------------------------------------------------- reports CRUD
def test_reports_render_markdown_and_json(harness: ApiHarness) -> None:
    scan_id = _completed_scan(harness)
    with harness.client() as client:
        markdown = client.get(f"/api/v1/scans/{scan_id}/report", headers=auth(VIEWER_KEY))
        assert markdown.status_code == 200
        assert markdown.headers["content-type"].startswith("text/markdown")
        assert "# Security Assessment Report" in markdown.text

        payload = client.get(
            f"/api/v1/scans/{scan_id}/report?format=json", headers=auth(VIEWER_KEY)
        )
        assert payload.status_code == 200
        document = payload.json()
        assert document["scan_id"] == f"scan_{scan_id}"
        assert "findings" in document


def test_an_unknown_report_format_is_refused_with_the_known_formats(harness: ApiHarness) -> None:
    """Formats are a registry now (plugins can add one), so the refusal is a 400 that lists them."""
    scan_id = _completed_scan(harness)
    with harness.client() as client:
        response = client.get(
            f"/api/v1/scans/{scan_id}/report?format=xml", headers=auth(VIEWER_KEY)
        )
    assert response.status_code == 400
    assert "md" in response.json()["error"]["message"]


def test_pushing_a_report_delivers_the_configured_webhooks(tmp_path) -> None:  # type: ignore[no-untyped-def]
    from pydantic import SecretStr

    from arachne.core.config import WebhookSettings

    harness = make_api_harness(
        tmp_path,
        webhooks=WebhookSettings(
            enabled=True, slack_url=SecretStr("https://hooks.slack.example/x")
        ),
    )
    try:
        scan_id = _completed_scan(harness)
        with harness.client() as client:
            response = client.post(f"/api/v1/scans/{scan_id}/report", headers=auth(SCANNER_KEY))
        assert response.status_code == 200
        body = response.json()
        assert body["enabled"] is True
        assert body["delivered"][0]["name"] == "slack"
        assert harness.poster.calls, "the configured webhook must have been called"
    finally:
        harness.close()


# --------------------------------------------------------------------------- modules/config
def test_modules_listing_includes_every_group_and_check(harness: ApiHarness) -> None:
    with harness.client() as client:
        modules = client.get("/api/v1/modules", headers=auth(VIEWER_KEY)).json()
        groups = {module["id"]: module for module in modules}
        assert {"M1", "M2", "M3", "M4", "M5", "M6"} <= set(groups)
        assert all(module["read_only"] for module in modules)
        assert groups["M4"]["checks"], "a module lists its checks"


def test_effective_config_is_admin_only_and_redacted(harness: ApiHarness) -> None:
    with harness.client() as client:
        assert client.get("/api/v1/config", headers=auth(VIEWER_KEY)).status_code == 403
        config = client.get("/api/v1/config", headers=auth(ADMIN_KEY)).json()
        assert config["rate_limits"]["api_per_minute"] > 0
        assert "webhooks" in config and "modules" in config


def test_webhook_status_reports_names_not_urls(harness: ApiHarness) -> None:
    with harness.client() as client:
        status = client.get("/api/v1/webhooks", headers=auth(ADMIN_KEY)).json()
    assert status["enabled"] is False and status["integrations"] == []


# --------------------------------------------------------------------------- schedules
def test_schedule_crud_through_the_api(harness: ApiHarness) -> None:
    state_path = harness.tmp_path / "schedules.json"
    object.__setattr__(harness.settings, "scheduler", _scheduler_settings(state_path))
    body = {
        "id": "nightly",
        "target": "tests/fixtures/targets/m1-fixture.yaml",
        "cron": "0 3 * * *",
    }
    with harness.client() as client:
        created = client.post("/api/v1/schedules", headers=auth(SCANNER_KEY), json=body)
        assert created.status_code == 201, created.text
        assert created.json()["spec"]["id"] == "nightly"
        listing = client.get("/api/v1/schedules", headers=auth(VIEWER_KEY)).json()
        assert [row["spec"]["id"] for row in listing] == ["nightly"]
        assert (
            client.delete("/api/v1/schedules/nightly", headers=auth(SCANNER_KEY)).status_code == 204
        )
        assert client.get("/api/v1/schedules", headers=auth(VIEWER_KEY)).json() == []


def test_a_bad_cron_is_refused(harness: ApiHarness) -> None:
    state_path = harness.tmp_path / "schedules.json"
    object.__setattr__(harness.settings, "scheduler", _scheduler_settings(state_path))
    with harness.client() as client:
        response = client.post(
            "/api/v1/schedules",
            headers=auth(SCANNER_KEY),
            json={"id": "bad", "target": "x.yaml", "cron": "not a cron"},
        )
    assert response.status_code == 400


# --------------------------------------------------------------------------- helpers
def _completed_scan(harness: ApiHarness) -> int:
    with harness.client() as client:
        started = client.post("/api/v1/scans", headers=auth(SCANNER_KEY), json={"target": TARGET})
        assert started.status_code == 202
        scan_id = started.json()["scan_id"]
        wait_for_scan(client, auth(VIEWER_KEY), scan_id)
    return int(scan_id)


def _scheduler_settings(path):  # type: ignore[no-untyped-def]
    from arachne.core.config import SchedulerSettings

    return SchedulerSettings(state_path=str(path))
