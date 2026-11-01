"""Integration: a live scan renders in the web UI, and webhooks reach a stub endpoint (S12).

Two DONE criteria of S12:

#2 — "UI renders a live scan report in a browser". A real M1 replay scan runs through the API
(a recorded-fixture scan: no socket), then the UI pages are fetched and asserted to contain
the analysed findings, their severity, their evidence and their remediation.
#3 — "Webhook smoke tests pass against stub endpoints". The *default* webhook sender posts
to a real loopback HTTP server, proving the wire path (not just the payload mapping).
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from tests.helpers.api import ADMIN_KEY, SCANNER_KEY, VIEWER_KEY, auth

from arachne.api.webhooks import WebhookNotifier, build_webhook_sender
from arachne.core.audit import Auditor, MemoryAuditSink
from arachne.core.config import OsintSettings, Settings, WebhookSettings
from arachne.core.planner import DEFAULT_PIPELINE
from arachne.core.safety import StaticResolver, UrlSafetyPolicy
from arachne.core.target import load_scan_request

pytestmark = pytest.mark.integration

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
TARGET_FIXTURE = FIXTURES / "targets" / "m1-fixture.yaml"
OSINT_FIXTURES = FIXTURES / "osint"
HTTP_FIXTURES = FIXTURES / "http"
SEARCH_URL = "https://search.example.net/search?q={query}&limit={limit}&format=json"


def _m1_settings(tmp_path: Path, **api_overrides: object) -> Settings:
    from arachne.core.config import ApiSettings

    base = {
        "keys": (
            f"admin:admin:{ADMIN_KEY}",
            f"scanner:scanner:{SCANNER_KEY}",
            f"viewer:viewer:{VIEWER_KEY}",
        ),
        "require_tls": False,
        "rate_limit_per_minute": 100_000,
        "rate_limit_burst": 100_000,
    }
    base.update(api_overrides)
    return Settings(
        database_url=f"sqlite:///{tmp_path / 'ui.db'}",
        log_level="CRITICAL",
        log_json=False,
        actor="pytest",
        http_fixtures=str(HTTP_FIXTURES),
        osint=OsintSettings(
            enabled=True,
            providers=("crtsh", "circl", "wayback", "commoncrawl", "internetdb"),
            search_url=SEARCH_URL,
            fixtures_dir=str(OSINT_FIXTURES),
            request_budget=50,
        ),
        api=ApiSettings(**base),  # type: ignore[arg-type]
    )


@pytest.fixture
def live_harness(tmp_path):  # type: ignore[no-untyped-def]
    from tests.helpers.api import make_api_harness

    harness = make_api_harness(tmp_path, settings=_m1_settings(tmp_path), pipeline=DEFAULT_PIPELINE)
    try:
        yield harness
    finally:
        harness.close()


def test_a_live_scan_report_renders_in_the_ui(live_harness) -> None:  # type: ignore[no-untyped-def]
    request = load_scan_request(TARGET_FIXTURE)
    target_document = request.target.model_dump(mode="json")

    with live_harness.client() as client:
        started = client.post(
            "/api/v1/scans",
            headers=auth(SCANNER_KEY),
            json={"target": target_document, "options": {"modules": {"enabled": ["M1"]}}},
        )
        assert started.status_code == 202, started.text
        scan_id = started.json()["scan_id"]

        # Poll through the API until the pipeline finishes.
        import time

        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            payload = client.get(f"/api/v1/scans/{scan_id}", headers=auth(VIEWER_KEY)).json()
            if payload["status"] not in {"pending", "running"}:
                break
            time.sleep(0.2)
        assert payload["status"] == "completed", payload

        # The API report is a real document with findings.
        report = client.get(
            f"/api/v1/scans/{scan_id}/report?format=json", headers=auth(VIEWER_KEY)
        ).json()
        titles = [item["title"] for item in report["findings"]]
        assert titles, "the M1 replay scan must produce findings"

        # Log in to the UI and render the dashboard, the scan page and the report.
        login = client.post(
            "/ui/login",
            data={"key": VIEWER_KEY, "next": f"/ui/scans/{scan_id}"},
            follow_redirects=False,
        )
        assert login.status_code == 303  # the cookie is now in the client's jar

        dashboard = client.get("/ui/")
        assert dashboard.status_code == 200
        assert "Dashboard" in dashboard.text
        assert f"/ui/scans/{scan_id}" in dashboard.text

        scan_page = client.get(f"/ui/scans/{scan_id}")
        assert scan_page.status_code == 200
        assert "Findings" in scan_page.text
        # A finding's title, its severity badge and its evidence all reach the page.
        assert any(title in scan_page.text for title in titles)
        assert "sev-" in scan_page.text
        assert "Evidence" in scan_page.text
        assert "Remediation" in scan_page.text

        # The Markdown report page shows the rendered document.
        report_page = client.get(f"/ui/scans/{scan_id}/report")
        assert report_page.status_code == 200
        assert "# Security Assessment Report" in report_page.text

        # The findings partial (what htmx swaps in) filters server-side.
        partial = client.get(f"/ui/scans/{scan_id}/findings?module=M1")
        assert partial.status_code == 200
        empty = client.get(f"/ui/scans/{scan_id}/findings?module=ZZ")
        assert "No findings match" in empty.text

        # The module config page describes the effective deployment.
        modules_page = client.get("/ui/modules")
        assert modules_page.status_code == 200
        assert "M1" in modules_page.text and "m1." in modules_page.text


def test_the_ui_requires_a_key_and_sets_a_cookie(live_harness) -> None:  # type: ignore[no-untyped-def]
    with live_harness.client() as client:
        redirected = client.get("/ui/", follow_redirects=False)
        assert redirected.status_code == 303
        assert "/ui/login" in redirected.headers["location"]

        bad = client.post("/ui/login", data={"key": "wrong"}, follow_redirects=False)
        assert bad.status_code == 200 and "not accepted" in bad.text

        good = client.post("/ui/login", data={"key": VIEWER_KEY}, follow_redirects=False)
        assert good.status_code == 303
        cookie = good.headers.get("set-cookie", "")
        assert "HttpOnly" in cookie and "SameSite=strict" in cookie


def test_a_ui_state_change_needs_the_htmx_marker(live_harness) -> None:  # type: ignore[no-untyped-def]
    with live_harness.client() as client:
        client.post("/ui/login", data={"key": SCANNER_KEY}, follow_redirects=False)
        request = load_scan_request(TARGET_FIXTURE)
        body = {"definition": json.dumps(request.target.model_dump(mode="json"))}
        # No HX-Request header: a cross-site form post cannot forge it.
        blocked = client.post("/ui/scans", data=body, follow_redirects=False)
        assert blocked.status_code == 403
        # With the header htmx sends, it is accepted.
        allowed = client.post(
            "/ui/scans",
            data=body,
            headers={"HX-Request": "true"},
            follow_redirects=False,
        )
        assert allowed.status_code == 303


def test_a_viewer_cannot_post_a_ui_scan(live_harness) -> None:  # type: ignore[no-untyped-def]
    with live_harness.client() as client:
        client.post("/ui/login", data={"key": VIEWER_KEY}, follow_redirects=False)
        request = load_scan_request(TARGET_FIXTURE)
        response = client.post(
            "/ui/scans",
            data={"definition": json.dumps(request.target.model_dump(mode="json"))},
            headers={"HX-Request": "true"},
            follow_redirects=False,
        )
    assert response.status_code == 403


# --------------------------------------------------------------------------- webhook wire
class _StubEndpoint(BaseHTTPRequestHandler):
    """A loopback endpoint that records what it received."""

    received: list[dict] = []

    def do_POST(self) -> None:
        length = int(self.headers.get("content-length", "0"))
        raw = self.rfile.read(length) if length else b""
        type(self).received.append(
            {
                "path": self.path,
                "auth": self.headers.get("authorization"),
                "body": json.loads(raw or b"{}"),
            }
        )
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"ok": true}')

    def log_message(self, *args: object) -> None:  # keep the test output quiet
        return


@pytest.fixture
def stub_endpoint():  # type: ignore[no-untyped-def]
    _StubEndpoint.received = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _StubEndpoint)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}", _StubEndpoint.received
    finally:
        server.shutdown()
        server.server_close()


@pytest.mark.asyncio
async def test_the_default_sender_delivers_to_a_real_stub_endpoint(stub_endpoint) -> None:  # type: ignore[no-untyped-def]
    from pydantic import SecretStr
    from tests.helpers.report import synthetic_report

    base, received = stub_endpoint
    hooks = WebhookSettings(
        enabled=True,
        slack_url=SecretStr(f"{base}/slack"),
        teams_url=SecretStr(f"{base}/teams"),
    )
    settings = Settings(
        webhooks=hooks,
        log_level="CRITICAL",
        # The stub is on loopback: allow it explicitly and pin its resolution.
        safety=_safety_allow_loopback(),
    )
    sink = MemoryAuditSink()
    sender = build_webhook_sender(
        settings,
        auditor=Auditor(sink),
        resolver=StaticResolver(("127.0.0.1",)),
    )
    notifier = WebhookNotifier(settings, auditor=Auditor(sink), post_json=sender)
    results = await notifier.notify(synthetic_report())  # type: ignore[arg-type]

    assert all(item.ok for item in results), [item.to_dict() for item in results]
    assert {call["path"] for call in received} == {"/slack", "/teams"}
    slack_body = next(call["body"] for call in received if call["path"] == "/slack")
    assert "text" in slack_body
    teams_body = next(call["body"] for call in received if call["path"] == "/teams")
    assert teams_body["@type"] == "MessageCard"


def _safety_allow_loopback():  # type: ignore[no-untyped-def]
    from arachne.core.config import SafetySettings

    return SafetySettings(
        policy=UrlSafetyPolicy(allow_loopback=True, allow_private_ips=True),
    )
