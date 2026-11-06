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

from arachne.api.auth import API_KEY_COOKIE
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


# --------------------------------------------------- the state matrix on the live app
# WP-04: the five states exist in the templates (tests/unit/test_ui_states.py renders all 70
# cells). These tests are the other half — that the *routes* reach them from real data, which is
# what makes "implemented" mean "reachable" rather than "present in a template".


def test_the_overview_and_the_scan_list_render_their_empty_states(live_harness) -> None:  # type: ignore[no-untyped-def]
    with live_harness.client() as client:
        client.cookies.set(API_KEY_COOKIE, VIEWER_KEY)
        page = client.get("/ui/")
        assert page.status_code == 200
        assert 'data-state="empty"' in page.text
        assert "No scans yet." in page.text

        scans = client.get("/ui/scans")
        assert scans.status_code == 200
        assert 'data-state="empty"' in scans.text
        # §4.5: the empty state offers the next action, and the start form survives it.
        assert "Start a scan" in scans.text
        assert "Dry run" in scans.text


def test_a_read_only_session_is_flagged_on_a_page_with_data(live_harness) -> None:  # type: ignore[no-untyped-def]
    """§4.2/§4.5 refused: a viewer sees the page, marked read-only and told why."""
    with live_harness.client() as client:
        client.cookies.set(API_KEY_COOKIE, VIEWER_KEY)
        live_harness.seed_scan()
        overview = client.get("/ui/")
        assert overview.status_code == 200
        assert 'data-state="refused"' in overview.text

        scans = client.get("/ui/scans")
        assert scans.status_code == 200
        assert 'data-state="refused"' in scans.text
        # §4.5: a refusal at admission is audited and never becomes a scan row — said plainly
        # rather than leaving an operator to wonder why the history is missing an entry.
        assert "never becomes a row here" in scans.text


def test_the_scan_detail_page_carries_a_working_loading_indicator(live_harness) -> None:  # type: ignore[no-untyped-def]
    """`loading` as a real affordance: htmx adds ``htmx-request`` to this element while the
    filter request is in flight, and the stylesheet reveals the skeleton."""
    with live_harness.client() as client:
        client.cookies.set(API_KEY_COOKIE, VIEWER_KEY)
        scan_id = live_harness.seed_scan()
        page = client.get(f"/ui/scans/{scan_id}")
        assert page.status_code == 200, page.text
        assert 'id="findings-loading"' in page.text
        assert 'hx-indicator="#findings-loading"' in page.text
        assert 'data-state="loading"' in page.text


# --------------------------------------------------- the findings workspace (§4.3, §4.4)
def test_the_findings_workspace_lists_filters_and_pages(live_harness) -> None:  # type: ignore[no-untyped-def]
    with live_harness.client() as client:
        client.cookies.set(API_KEY_COOKIE, VIEWER_KEY)
        scan_id = live_harness.seed_scan()
        live_harness.seed_finding(scan_id=scan_id, title="alpha finding", severity="high")
        live_harness.seed_finding(scan_id=scan_id, title="beta finding", severity="low")

        page = client.get("/ui/findings")
        assert page.status_code == 200, page.text
        assert "alpha finding" in page.text and "beta finding" in page.text
        # §4.3 partial: the footer reports the rows shown without a total.
        assert 'data-state="partial"' in page.text
        # §4.3 partial: the footer reports the rows shown without a total. The count and its
        # noun come from the catalogue's plural form (REQ-UIX-008).
        assert "Showing 2 findings." in page.text

        # A filter is the server's filter, and only what it names comes back.
        filtered = client.get("/ui/findings?severity=high")
        assert filtered.status_code == 200
        assert "alpha finding" in filtered.text
        assert "beta finding" not in filtered.text

        # §4.3 empty (filtered to nothing): the filters stay and clearing them is offered.
        nothing = client.get("/ui/findings?severity=critical")
        assert nothing.status_code == 200
        assert 'data-state="empty"' in nothing.text
        assert "No findings match these filters." in nothing.text
        assert "Clear filters" in nothing.text


def test_the_findings_workspace_pages_with_an_opaque_cursor(live_harness) -> None:  # type: ignore[no-untyped-def]
    """§2.2/REQ-UIX-001: the workspace pages by cursor, and the token is not hand-built."""
    with live_harness.client() as client:
        client.cookies.set(API_KEY_COOKIE, VIEWER_KEY)
        scan_id = live_harness.seed_scan()
        for index in range(3):
            live_harness.seed_finding(scan_id=scan_id, title=f"finding {index}")
        first = client.get("/ui/findings?limit=2")
        assert first.status_code == 200
        assert "cursor=" in first.text
        assert "Load more" in first.text
        # The newest two rows, in the endpoint's total order (id descending).
        assert "finding 2" in first.text and "finding 1" in first.text
        assert "finding 0" not in first.text
        # Following the link the page produced returns exactly the remaining row.
        target = first.text.split('href="/ui/findings?', 1)[1].split('"', 1)[0]
        rest = client.get(f"/ui/findings?{target.replace('&amp;', '&')}")
        assert rest.status_code == 200
        assert "finding 0" in rest.text
        assert "finding 2" not in rest.text
        # The last page has nothing after it, so the affordance disappears rather than lying.
        assert "Load more" not in rest.text

        # A malformed cursor is a 400 rather than a 500 (the codec is shared with the API).
        broken = client.get("/ui/findings?cursor=not-a-cursor")
        assert broken.status_code == 400


def test_a_finding_detail_renders_an_unverified_finding_honestly(tmp_path: Path) -> None:
    """§4.4 refused: an unverified finding is INFO with a banner, not a hidden 404.

    "Verified" is the report's own verdict: a finding the report publishes as a confirmed one.
    Lowering that bar in this harness is how a test plants the unverified case — it is a real
    deployment setting (``report.min_confidence``), not a flag invented for the test.
    """
    from dataclasses import replace

    from tests.helpers.api import make_api_harness

    from arachne.core.config import ReportSettings

    settings = replace(_m1_settings(tmp_path), report=ReportSettings(min_confidence=90))
    harness = make_api_harness(tmp_path, settings=settings, pipeline=DEFAULT_PIPELINE)
    try:
        with harness.client() as client:
            client.cookies.set(API_KEY_COOKIE, VIEWER_KEY)
            finding_id = harness.seed_finding(title="unconfirmed candidate", severity="critical")
            page = client.get(f"/ui/findings/{finding_id}")
            assert page.status_code == 200, page.text
            assert "unconfirmed candidate" in page.text
            # The severity is forced to INFO: an unverified CRITICAL is not a CRITICAL.
            assert "sev-info" in page.text
            assert "sev-critical" not in page.text
            assert 'data-state="refused"' in page.text
            assert "No verification record" in page.text
            # §4.4: the header and the actions stay usable in every state.
            assert "Mark false positive" in page.text

            missing = client.get("/ui/findings/999999")
            assert missing.status_code == 404
    finally:
        harness.close()


def test_a_verified_finding_keeps_its_own_severity(live_harness) -> None:  # type: ignore[no-untyped-def]
    """The INFO override is a statement about evidence, not a blanket rule."""
    with live_harness.client() as client:
        client.cookies.set(API_KEY_COOKIE, VIEWER_KEY)
        finding_id = live_harness.seed_finding(title="confirmed issue", severity="critical")
        page = client.get(f"/ui/findings/{finding_id}")
        assert page.status_code == 200, page.text
        assert "sev-critical" in page.text
        assert 'data-state="refused"' not in page.text


def test_the_findings_screens_require_a_key(live_harness) -> None:  # type: ignore[no-untyped-def]
    with live_harness.client() as client:
        for path in ("/ui/findings", "/ui/findings/1"):
            response = client.get(path, follow_redirects=False)
            assert response.status_code == 303, path
            assert response.headers["location"].startswith("/ui/login")


# --------------------------------------------------- dark mode and density (REQ-UIX-009)
def test_the_theme_and_density_preferences_persist_per_user(live_harness) -> None:  # type: ignore[no-untyped-def]
    with live_harness.client() as client:
        client.cookies.set(API_KEY_COOKIE, VIEWER_KEY)
        # No preference yet: the page carries no theme attribute, so the OS preference wins.
        page = client.get("/ui/")
        assert "data-theme=" not in page.text
        assert 'data-density="compact"' not in page.text

        dark = client.post(
            "/ui/preferences", data={"theme": "dark", "next": "/ui/"}, follow_redirects=False
        )
        assert dark.status_code == 303
        assert dark.headers["location"] == "/ui/"
        page = client.get("/ui/")
        assert 'data-theme="dark"' in page.text
        # The dark palette is the token file's, so the theme switch is token-driven: the
        # stylesheet it links is the generated one and carries both palettes.
        assert "/static/tokens.css" in page.text

        compact = client.post(
            "/ui/preferences", data={"density": "compact"}, follow_redirects=False
        )
        assert compact.status_code == 303
        page = client.get("/ui/")
        assert 'data-density="compact"' in page.text
        assert 'data-theme="dark"' in page.text  # changing density did not clear the theme

        system = client.post("/ui/preferences", data={"theme": "system"}, follow_redirects=False)
        assert system.status_code == 303
        assert "data-theme=" not in client.get("/ui/").text
        # Clearing the theme left the density alone, which is what "one button, one preference"
        # means.
        assert 'data-density="compact"' in client.get("/ui/").text


def test_the_preference_endpoint_refuses_a_value_outside_its_vocabulary(live_harness) -> None:  # type: ignore[no-untyped-def]
    """A hand-edited cookie or form value cannot become a `data-theme` attribute."""
    with live_harness.client() as client:
        client.cookies.set(API_KEY_COOKIE, VIEWER_KEY)
        client.post("/ui/preferences", data={"theme": "neon"}, follow_redirects=False)
        page = client.get("/ui/")
        assert "data-theme=" not in page.text
        # A cookie set by hand is re-validated on read, not trusted.
        client.cookies.set("arachne_theme", "neon; onload=alert(1)")
        assert "data-theme=" not in client.get("/ui/").text


def test_the_preference_endpoint_cannot_redirect_off_the_interface(live_harness) -> None:  # type: ignore[no-untyped-def]
    with live_harness.client() as client:
        response = client.post(
            "/ui/preferences",
            data={"theme": "dark", "next": "https://evil.example/steal"},
            follow_redirects=False,
        )
        assert response.status_code == 303
        assert response.headers["location"] == "/ui/"


# --------------------------------------------------------------------------- webhook wire
class _StubEndpoint(BaseHTTPRequestHandler):
    """A loopback endpoint that records what it received."""

    received: list[dict] = []
    # TCP_NODELAY: the same Nagle/delayed-ACK stall as tests/lab/web_lab.py (42 ms → 0.8 ms per
    # request on loopback).
    disable_nagle_algorithm = True

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
    thread = threading.Thread(target=server.serve_forever, args=(0.05,), daemon=True)
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
