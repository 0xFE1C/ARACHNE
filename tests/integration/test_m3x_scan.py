"""Acceptance: the extended M3 families find the planted advanced scenarios.

The S10 definition of done asks for "extended lab coverage recorded (finding set per check)".
This module runs every S10 M3 check against the shared stdlib lab (``tests/lab/web_lab.py``),
whose :data:`~tests.lab.web_lab.M3X_GROUND_TRUTH` declares one planted signal per family, and
records the finding set. It also runs the two out-of-band/opt-in families (SSRF) against a
loopback callback service on ARACHNE's "own infrastructure", and asserts that the hardened
counterparts (``/safe-template``, ``/graphql-safe``, ``/checkout-safe``, ...) are not reported.

The checks are driven directly (as the checks step would) rather than through a full
orchestrator scan, because the S10 criterion is about the *finding set per check*; the S6/S7
acceptance suites already prove the pipeline end to end.
"""

from __future__ import annotations

import threading
from collections.abc import Iterator
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from tests.helpers.checks import asset_for
from tests.helpers.m5 import make_m5_harness
from tests.lab.web_lab import M3X_GROUND_TRUTH, WebLab, start_web_lab

from arachne.core.config import WebSettings
from arachne.modules.m3 import M3_CHECKS
from arachne.modules.m3.advanced_protocol import SsrfProbe

#: The explicit crawl roots: every planted surface plus the hardened controls the checks must
#: not report. Order matters a little — the checks probe the first few pages/parameters of the
#: inventory — so the planted routes come first.
ROOTS: tuple[str, ...] = (
    "/",
    "/cache-me",
    "/cache-safe",
    "/ssti?name=guest",
    "/safe-template",
    "/xxe",
    "/safe-xml",
    "/ping?host=127.0.0.1",
    "/safe-ping?host=127.0.0.1",
    "/deser",
    "/smuggle",
    "/smuggle-safe",
    "/hpp?role=user",
    "/api/profile",
    "/merge",
    "/graphql",
    "/graphql-safe",
    "/ws",
    "/ws-safe",
    "/checkout?qty=1",
    "/checkout-safe?qty=-1",
    "/redeem",
    "/oauth/authorize?redirect_uri=/home",
    "/oauth/authorize-safe?redirect_uri=/home",
    "/saml/acs",
    "/saml/acs-safe",
    "/app.js",
    "/takeover-alias",
    "/api/me",
    "/fetch?url=/home",
)


@pytest.fixture(scope="module")
def lab() -> Iterator[WebLab]:
    with start_web_lab() as running:
        yield running


def _roots(lab: WebLab) -> list[str]:
    return [f"{lab.base_url.rstrip('/')}{path}" for path in ROOTS]


async def _run(lab: WebLab, check_cls: type, *, web: WebSettings | None = None) -> list:
    # The extended lab has more than the default 20 crawl roots.
    settings = replace(web or WebSettings(), max_pages=80)
    harness = make_m5_harness(asset=asset_for("url", lab.base_url), web=settings)
    try:
        await harness.prepare(_roots(lab))
        ctx = harness.context(check_cls())
        return [result async for result in check_cls().run(ctx)]
    finally:
        await harness.aclose()


def _blob(result: object) -> str:
    evidence = getattr(result, "evidence", ())
    parts: list[str] = []
    for item in evidence:
        for key, value in item.payload.items():
            parts.append(f"{key}={value}")
    return " ".join(parts)


def _by_id() -> dict[str, type]:
    return {check.metadata.id: check for check in M3_CHECKS}


async def test_every_extended_family_reports_its_planted_signal(lab: WebLab) -> None:
    """DONE criterion 1: one planted signal per extended check, none missed."""
    checks = _by_id()
    results_by_check: dict[str, list] = {}
    for check_id, marker in M3X_GROUND_TRUTH:
        results = await _run(lab, checks[check_id])
        blob = " ".join(_blob(result) for result in results if result.status == "vulnerable")
        results_by_check[check_id] = results
        assert marker in blob, f"{check_id} did not report {marker!r}: {[r.title for r in results]}"

    # The finding set per check is recorded (and non-empty) — the S10 handoff reads this.
    print("\nM3 extended finding set:")
    for check_id, _marker in M3X_GROUND_TRUTH:
        titles = [
            result.title for result in results_by_check[check_id] if result.status == "vulnerable"
        ]
        print(f"  {check_id}: {len(titles)} candidate(s)")
        assert titles, check_id


async def test_hardened_controls_are_not_reported(lab: WebLab) -> None:
    """The false-positive traps: a hardened route must not produce a candidate for its family."""
    checks = _by_id()
    controls = {
        "m3.ssti-oracle": "/safe-template",
        "m3.cmdi-oracle": "/safe-ping",
        "m3.graphql-audit": "/graphql-safe",
        "m3.websocket-audit": "/ws-safe",
        "m3.business-logic-audit": "/checkout-safe",
        "m3.oauth-flow-audit": "/oauth/authorize-safe",
        "m3.saml-audit": "/saml/acs-safe",
    }
    for check_id, route in controls.items():
        results = await _run(lab, checks[check_id])
        offenders = [
            result.title
            for result in results
            if result.status == "vulnerable" and route in _blob(result)
        ]
        assert not offenders, f"{check_id} reported the hardened control {route}: {offenders}"


class _CallbackServer(BaseHTTPRequestHandler):
    """A loopback out-of-band callback service (ARACHNE's own infrastructure)."""

    hits: list[str] = []
    protocol_version = "HTTP/1.1"
    # TCP_NODELAY: the same Nagle/delayed-ACK stall as tests/lab/web_lab.py (42 ms → 0.8 ms per
    # request on loopback).
    disable_nagle_algorithm = True

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - stdlib signature
        return

    def do_GET(self) -> None:
        if self.path.startswith("/hits"):
            body = " ".join(type(self).hits).encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        marker = self.path.strip("/")
        type(self).hits.append(marker)
        body = f"callback-ok {marker}".encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture()
def callback() -> Iterator[str]:
    _CallbackServer.hits = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _CallbackServer)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, args=(0.05,), daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


async def test_ssrf_probe_confirms_through_the_callback(lab: WebLab, callback: str) -> None:
    """DONE criterion 1 (SSRF): a sink that fetches the callback is reported."""
    settings = WebSettings(ssrf_probe=True, ssrf_callback_url=callback)
    results = await _run(lab, SsrfProbe, web=settings)
    candidates = [result for result in results if result.status == "vulnerable"]
    assert candidates, [result.title for result in results]
    assert any("ssrf" in _blob(result) for result in candidates)
    # The lab's sink really fetched the callback (out-of-band infrastructure was reached).
    assert _CallbackServer.hits


async def test_ssrf_probe_is_inert_without_its_switch(lab: WebLab, callback: str) -> None:
    """The opt-in gate: with ARACHNE_WEB_SSRF_PROBE off, nothing is injected."""
    _CallbackServer.hits = []
    settings = WebSettings(ssrf_probe=False, ssrf_callback_url=callback)
    results = await _run(lab, SsrfProbe, web=settings)
    assert all(result.status != "vulnerable" for result in results)
    assert not _CallbackServer.hits, "an SSRF probe was sent with the switch off"
