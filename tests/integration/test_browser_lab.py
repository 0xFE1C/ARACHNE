"""Acceptance for the browser crawl against the lab, with the optional extra installed.

REQ-DET-015's capability criteria are about a real JavaScript engine: a route reachable only
after client-side rendering, and a DOM sink reachable only through JavaScript execution. Those
two claims cannot be proven in an installation that has no browser, so this module needs
``arachne[browser]`` and skips (via ``pytest.importorskip``) without it. The degradation half —
"with the extra absent, the crawl reports itself skipped" — is covered *unconditionally* by
``tests/unit/test_browser_hardening.py`` and ``tests/test_browser_safety.py``, which is why
this module's skip is an accepted, allowlisted one rather than a gap.

What it adds over the scripted navigator: the assertions are about a *running* Chromium.

* the instrumented sink really fires, with the marker planted in the fragment, and the finding
  names ``innerHTML`` and ``location.hash``;
* ``/spa/orders`` is discovered even though the server's HTML never names it;
* ``/spa-safe`` (the ``textContent`` twin) produces no finding — the false-positive control;
* **every address the browser caused to be contacted is loopback**: the finding's own evidence
  carries the proxy's dial list, and a real browser reaching a real page through it is the
  end-to-end form of "the proxy is the only egress";
* the permissions a hostile page would want are denied to it.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import replace
from typing import Any

import pytest
from tests.helpers.checks import asset_for
from tests.helpers.depth import make_depth_harness
from tests.lab.web_lab import WebLab, start_web_lab

pytest.importorskip(
    "playwright.async_api",
    reason="the optional extra arachne[browser] is not installed; the degradation half of "
    "REQ-DET-015 is asserted unconditionally by tests/unit/test_browser_hardening.py",
)

from arachne.core.config import WebSettings
from arachne.core.results import CheckResult
from arachne.modules.context import CheckContext
from arachne.modules.m3.dom_xss import DomSinkCheck

pytestmark = pytest.mark.lab


@pytest.fixture(scope="module")
def lab() -> Iterator[WebLab]:
    with start_web_lab() as running:
        yield running


def _web(**overrides: Any) -> WebSettings:
    return replace(
        WebSettings(browser_crawl=True, browser_max_pages=8, browser_time_budget_s=90.0),
        **overrides,
    )


def _blob(results: list[CheckResult]) -> str:
    return " ".join(
        f"{evidence.kind}={evidence.payload}" for result in results for evidence in result.evidence
    )


async def _run(lab: WebLab, *paths: str, web: WebSettings | None = None) -> list[CheckResult]:
    roots = [f"{lab.base_url.rstrip('/')}{path}" for path in paths]
    harness = make_depth_harness(asset=asset_for("url", lab.base_url), web=web or _web())
    try:
        await harness.prepare(roots)
        context: CheckContext = harness.context(DomSinkCheck())
        return [result async for result in DomSinkCheck().run(context)]
    finally:
        await harness.aclose()


async def test_a_dom_sink_reachable_only_through_javascript_is_detected(lab: WebLab) -> None:
    results = await _run(lab, "/spa")
    candidates = [result for result in results if result.status == "vulnerable"]
    assert candidates, [result.title for result in results]
    blob = _blob(candidates)
    assert "innerHTML" in blob
    assert "location.hash" in blob
    assert "client_side_only': True" in blob
    # The lab's shell never serves the order route's path in its own HTML.
    assert any("orders" in _blob([result]) for result in results)


async def test_a_route_only_the_rendered_dom_names_is_discovered(lab: WebLab) -> None:
    results = await _run(lab, "/spa")
    assert "/spa/orders" in _blob(results), "the browser-discovered route is not in the evidence"


async def test_every_address_the_browser_reached_is_loopback(lab: WebLab) -> None:
    """The end-to-end form of "the proxy is the only egress": a real browser, a real page."""
    results = await _run(lab, "/spa")
    candidates = [result for result in results if result.status == "vulnerable"]
    assert candidates
    proxy = candidates[0].evidence[-1].payload["browser"]["proxy"]
    assert proxy["dialed"], "the browser reached the lab through the proxy"
    for entry in proxy["dialed"]:
        assert entry.startswith("127.0.0.1:"), entry
        assert "//" not in entry and "@" not in entry, entry
    assert proxy["refusals"] == [] or all(
        "out-of-scope" in item["reason"] or "scope" in item["reason"] for item in proxy["refusals"]
    )


async def test_the_hardened_twin_is_not_reported(lab: WebLab) -> None:
    results = await _run(lab, "/spa-safe")
    candidates = [result for result in results if result.status == "vulnerable"]
    assert candidates == [], _blob(candidates)


async def test_the_permissions_a_hostile_page_would_want_are_denied(lab: WebLab) -> None:
    """The running-browser half of the six disabled capabilities.

    Clipboard, geolocation and camera/microphone are asserted *from the page* — the probe asks
    for each and records what the browser answered, so "denied" is the browser's own behaviour
    rather than a flag this test read back. The filesystem, download and WebRTC mechanisms are
    configuration by nature, so their assertion lives in
    ``tests/unit/test_browser_hardening.py``, where it does not need a browser.
    """
    from arachne.browser.driver import PlaywrightNavigator
    from arachne.browser.hardening import all_disabled, capability_report
    from arachne.browser.proxy import ScopeProxy
    from arachne.core.audit import Auditor, MemoryAuditSink
    from arachne.core.safety import Scope, UrlSafetyPolicy

    probe = """
    async () => {
      const out = {};
      out.clipboard = await navigator.clipboard.readText()
        .then(() => "granted", (e) => e.name);
      out.geolocation = await new Promise((resolve) => {
        navigator.geolocation.getCurrentPosition(
          () => resolve("granted"),
          (e) => resolve(e.code === 1 ? "denied" : "error")
        );
      });
      out.camera = await navigator.mediaDevices.getUserMedia({ video: true })
        .then(() => "granted", (e) => e.name);
      return out;
    }
    """
    sink = MemoryAuditSink()
    proxy = ScopeProxy(
        scope=Scope(allowed_hosts=("127.0.0.1",)),
        auditor=Auditor(sink, actor="pytest"),
        policy=UrlSafetyPolicy(allow_loopback=True, allow_private_ips=True),
    )
    await proxy.start()
    navigator = PlaywrightNavigator(proxy_url=proxy.proxy_url)
    await navigator.start()
    try:
        page = await navigator.navigate(lab.base_url)
        assert page.ok, page.error
        answers = await navigator._eval(probe, limit=8)
    finally:
        await navigator.aclose()
        await proxy.aclose()

    assert answers, "the probe returned nothing"
    assert answers[0] != "granted", f"the clipboard was readable: {answers}"
    assert "granted" not in str(answers), f"a permission was granted to the page: {answers}"
    assert all_disabled(proxy.proxy_url) is True
    assert capability_report(proxy.proxy_url)["webrtc"]["disabled"] is True
