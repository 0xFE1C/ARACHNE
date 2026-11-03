"""``m3.dom-xss`` — DOM-XSS sink detection through the crawl (REQ-DET-015).

The check is driven through the real depth harness (a real loopback HTTP client, a real M3
crawl, a real step context) with only the *browser* replaced by the scripted navigator — which
is the point of putting the crawl behind the ``Navigator`` protocol: everything the check
decides is exercised in an installation that has no browser.

What these tests establish:

* the two gates are real: the deployment switch and the optional extra each turn the check
  into a not-run result naming what to enable, and nothing is navigated while they are off;
* a marker that reaches a sink without appearing in the server's response is reported as a DOM
  sink with **source and sink** in the evidence;
* the same page written safely (``textContent``) produces no candidate — the false-positive
  control;
* a marker the *server* returned is not a DOM finding (the reflected-XSS control);
* a route only the rendered DOM names is recorded as a URL **asset** through the scope guard;
* the crawl's documented budget is enforced and reported.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, replace
from typing import Any

import pytest
from tests.helpers.browser import ScriptedNavigator, ScriptedPage, marker_in, sink_record
from tests.helpers.checks import asset_for, make_step_context
from tests.helpers.depth import DepthHarness, make_depth_harness
from tests.lab.web_lab import WebLab, start_web_lab

from arachne.browser.crawl import CrawlBudget, RenderedPage
from arachne.core.config import WebSettings
from arachne.core.results import CheckResult
from arachne.modules.context import CheckContext, ModuleConfig
from arachne.modules.m3 import M3_CHECKS
from arachne.modules.m3 import dom_xss as dom_xss_module
from arachne.modules.m3.dom_xss import BROWSER_SWITCH, DomSinkCheck

SPA_SHELL = "<div id='app'></div>"
SPA_ORDERS = "<div>orders</div>"


@pytest.fixture(scope="module")
def lab() -> Iterator[WebLab]:
    with start_web_lab() as running:
        yield running


@dataclass
class _Installed:
    """The navigator the check saw, and the proxy URL it was handed."""

    navigator: ScriptedNavigator
    proxy_url: str = ""


def _web(**overrides: Any) -> WebSettings:
    return replace(
        WebSettings(browser_crawl=True, browser_max_pages=10, browser_time_budget_s=30.0),
        **overrides,
    )


def _install(monkeypatch: pytest.MonkeyPatch, navigator: ScriptedNavigator) -> _Installed:
    """Replace the driver seam with a scripted navigator and capture the proxy URL."""
    installed = _Installed(navigator=navigator)

    async def fake_open(proxy_url: str, *, marker_stem: str, timeout_ms: int) -> Any:
        installed.proxy_url = proxy_url
        return navigator

    monkeypatch.setattr(dom_xss_module, "open_navigator", fake_open)
    monkeypatch.setattr(dom_xss_module, "browser_available", lambda: True)
    return installed


def _roots(lab: WebLab, *paths: str) -> list[str]:
    return [f"{lab.base_url.rstrip('/')}{path}" for path in paths]


def _spa_navigator(lab: WebLab, *, safe: bool = False) -> ScriptedNavigator:
    """A single-page application and, optionally, its hardened twin.

    The shell's raw HTML never names its own ``/orders`` route (that is what a JavaScript-only
    route means), and the vulnerable shell writes the marker into ``innerHTML`` while the
    hardened one writes it through ``textContent``.
    """
    del lab
    path = "/spa-safe" if safe else "/spa"
    records = () if safe else (sink_record("innerHTML", value="<p>{marker}</p>"),)
    return ScriptedNavigator(
        pages={
            path: ScriptedPage(
                raw_body=SPA_SHELL,
                links=(f"{path}/orders", path),
                sink_records=records,
            ),
            f"{path}/orders": ScriptedPage(raw_body=SPA_ORDERS),
        },
        fallback=ScriptedPage(raw_body=SPA_SHELL),
    )


async def _run(
    lab: WebLab,
    monkeypatch: pytest.MonkeyPatch,
    *,
    web: WebSettings | None = None,
    navigator: ScriptedNavigator | None = None,
    roots: list[str] | None = None,
    asset: Any = None,
) -> tuple[list[CheckResult], _Installed, DepthHarness]:
    harness = make_depth_harness(asset=asset or asset_for("url", lab.base_url), web=web or _web())
    try:
        await harness.prepare(roots or _roots(lab, "/spa"))
        installed = _install(monkeypatch, navigator or _spa_navigator(lab))
        context = harness.context(DomSinkCheck())
        results = [result async for result in DomSinkCheck().run(context)]
        return results, installed, harness
    finally:
        await harness.aclose()


def _not_run(results: list[CheckResult]) -> list[CheckResult]:
    """The results that carry the machine-readable "we did not look" marker."""
    return [
        result
        for result in results
        if any(evidence.payload.get("skipped") for evidence in result.evidence)
    ]


def _candidates(results: list[CheckResult]) -> list[CheckResult]:
    return [result for result in results if result.status == "vulnerable"]


def _blob(results: list[CheckResult]) -> str:
    return " ".join(
        f"{evidence.kind}={evidence.payload}" for result in results for evidence in result.evidence
    )


# ------------------------------------------------------------------ the two gates
async def test_the_switch_off_is_a_not_run_result_naming_the_switch(
    lab: WebLab, monkeypatch: pytest.MonkeyPatch
) -> None:
    navigator = _spa_navigator(lab)
    results, _installed, _harness = await _run(
        lab, monkeypatch, web=_web(browser_crawl=False), navigator=navigator
    )
    not_run = _not_run(results)
    assert not_run, [result.title for result in results]
    assert BROWSER_SWITCH in (not_run[0].detail or "")
    assert navigator.navigations == [], "nothing may be navigated while the crawl is off"


async def test_the_extra_absent_is_a_not_run_result_naming_the_extra(
    lab: WebLab, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(dom_xss_module, "browser_available", lambda: False)
    harness = make_depth_harness(asset=asset_for("url", lab.base_url), web=_web())
    try:
        await harness.prepare(_roots(lab, "/spa"))
        results = [result async for result in DomSinkCheck().run(harness.context(DomSinkCheck()))]
    finally:
        await harness.aclose()
    not_run = _not_run(results)
    assert not_run, [result.title for result in results]
    assert "[browser]" in (not_run[0].detail or "")
    assert "driver installed" in (not_run[0].detail or "")


async def test_a_dry_run_never_opens_a_browser(monkeypatch: pytest.MonkeyPatch) -> None:
    """``ctx.http is None`` is the dry run: no browser, no navigation, a not-run result."""
    opened: list[str] = []

    async def forbidden(*args: Any, **kwargs: Any) -> Any:  # pragma: no cover - must not run
        opened.append("browser")
        raise AssertionError("a dry run opened a browser")

    monkeypatch.setattr(dom_xss_module, "open_navigator", forbidden)
    monkeypatch.setattr(dom_xss_module, "browser_available", lambda: True)
    step, _memory = make_step_context(http=None)
    context = CheckContext(
        step=step,
        module=DomSinkCheck(),
        asset=asset_for("url", "http://127.0.0.1:9/"),
        config=ModuleConfig(web=_web()),
    )
    results = [result async for result in DomSinkCheck().run(context)]
    assert opened == []
    assert _not_run(results)


async def test_a_browser_that_cannot_start_is_a_not_run_result_not_a_failure(
    lab: WebLab, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The extra can be installed while the browser *binary* is not (`playwright install`).

    A launch failure must be reported with its reason, like the missing extra, rather than
    propagate out of the check as a failure — an incomplete installation is not a broken scan.
    """
    opened: list[str] = []

    async def exploding(*args: Any, **kwargs: Any) -> Any:
        opened.append("launch")
        raise RuntimeError("Executable doesn't exist at ~/.cache/ms-playwright/chromium")

    monkeypatch.setattr(dom_xss_module, "open_navigator", exploding)
    monkeypatch.setattr(dom_xss_module, "browser_available", lambda: True)
    harness = make_depth_harness(asset=asset_for("url", lab.base_url), web=_web())
    try:
        await harness.prepare(_roots(lab, "/spa"))
        results = [result async for result in DomSinkCheck().run(harness.context(DomSinkCheck()))]
    finally:
        await harness.aclose()
    assert opened == ["launch"], "the launch was attempted"
    not_run = _not_run(results)
    assert not_run, [result.title for result in results]
    assert "could not be started" in (not_run[0].detail or "")
    assert "RuntimeError" in (not_run[0].detail or "")


async def test_a_second_url_asset_on_the_origin_does_not_repeat_the_crawl(
    lab: WebLab, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One browser crawl per origin, exactly like the M3 crawl (ADR-100.2).

    Two URL assets on one origin would probe the same pages twice and emit duplicate findings
    for them, so the lexicographically-first asset owns the origin's crawl.
    """
    secondary = lab.base_url + "second/"
    harness = make_depth_harness(asset=asset_for("url", secondary), web=_web())
    try:
        await harness.prepare(_roots(lab, "/spa"))
        await harness.step.record_asset("url", lab.base_url, source="test")
        navigator = _spa_navigator(lab)
        installed = _install(monkeypatch, navigator)
        secondary_results = [
            result
            async for result in DomSinkCheck().run(
                harness.context(DomSinkCheck(), asset=asset_for("url", secondary))
            )
        ]
        owner_results = [
            result
            async for result in DomSinkCheck().run(
                harness.context(DomSinkCheck(), asset=asset_for("url", lab.base_url))
            )
        ]
    finally:
        await harness.aclose()
    assert _not_run(secondary_results), [result.title for result in secondary_results]
    assert "owns the M3 crawl" in (_not_run(secondary_results)[0].detail or "")
    assert installed.navigator.navigations, "the owning asset is the one that crawled"
    assert not _not_run(owner_results), [result.title for result in owner_results]


# ------------------------------------------------------------------ the positive and its controls
async def test_a_dom_sink_reachable_only_through_javascript_is_reported(
    lab: WebLab, monkeypatch: pytest.MonkeyPatch
) -> None:
    results, installed, _harness = await _run(lab, monkeypatch)
    candidates = _candidates(results)
    assert candidates, [result.title for result in results]
    blob = _blob(candidates)
    assert "innerHTML" in blob, "the evidence must name the sink"
    assert "location.hash" in blob or "location.search" in blob, "…and the source"
    assert "client_side_only" in blob
    artifact = candidates[0].evidence[-1].payload
    assert artifact["dom_sink"] == "innerHTML"
    assert artifact["dom_source"] in {"location.hash", "location.search"}
    assert artifact["client_side_only"] is True
    assert artifact["executed_in_browser"] is True
    assert artifact["marker"].startswith("ar9x")
    # The proxy is the browser's only egress, and its capability report travels with the
    # finding so that "the six capabilities were off" is reproducible from the report.
    assert installed.proxy_url.startswith("http://127.0.0.1:")
    assert artifact["browser"]["capabilities"]["downloads"]["disabled"] is True
    assert artifact["browser"]["capabilities"]["webrtc"]["disabled"] is True


async def test_the_hardened_twin_produces_no_candidate(
    lab: WebLab, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``textContent`` reaches the DOM but no sink: no finding, and the page still rendered."""
    navigator = _spa_navigator(lab, safe=True)
    results, _installed, _harness = await _run(
        lab, monkeypatch, navigator=navigator, roots=_roots(lab, "/spa-safe")
    )
    assert _candidates(results) == []
    assert navigator.navigations, "the page was still rendered"
    assert "textContent" not in _blob(results)


async def test_a_marker_the_server_returned_is_not_a_dom_finding(
    lab: WebLab, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The reflected-XSS control: the same sink call, but the server sent the marker."""

    class _Echoing(ScriptedNavigator):
        async def navigate(self, url: str) -> RenderedPage:  # type: ignore[override]
            page = await super().navigate(url)
            # A server that reflects the probe: whichever source the marker was planted in, the
            # response body carries it back. That is what m3.xss-oracle measures, and it is not
            # a DOM-XSS.
            planted = marker_in(url, stem=self.marker_stem) or ""
            return RenderedPage(
                url=page.url,
                status=page.status,
                raw_body=f"<p>{planted}</p>",
                links=page.links,
                sink_records=page.sink_records,
            )

    navigator = _Echoing(
        pages={
            "/spa": ScriptedPage(
                raw_body="<p>reflected</p>",
                sink_records=(sink_record("innerHTML", value="<p>{marker}</p>"),),
            )
        }
    )
    results, _installed, _harness = await _run(lab, monkeypatch, navigator=navigator)
    assert _candidates(results) == []
    # The sink *did* fire — the instrumentation saw the marker at innerHTML — but the marker
    # was in the server's own response, so the crawl refuses to call it client-side.
    blob = _blob(results)
    assert "'dom_sinks': 2" in blob
    assert "'client_side_sinks': 0" in blob


# ------------------------------------------------------------------ assets and budget
async def test_a_javascript_rendered_route_is_recorded_as_an_asset(
    lab: WebLab, monkeypatch: pytest.MonkeyPatch
) -> None:
    _results, _installed, harness = await _run(lab, monkeypatch)
    assets = [record.value for record in harness.memory.store.list_assets(harness.step.scan_id)]
    assert any(value.endswith("/spa/orders") for value in assets), assets


async def test_the_budget_is_enforced_and_reported(
    lab: WebLab, monkeypatch: pytest.MonkeyPatch
) -> None:
    navigator = _spa_navigator(lab)
    results, _installed, _harness = await _run(
        lab, monkeypatch, web=_web(browser_max_pages=1), navigator=navigator
    )
    assert len(navigator.navigations) == 1, navigator.navigations
    summary = next(result for result in results if result.status == "info" and not _is_skip(result))
    payload = summary.evidence[-1].payload
    assert payload["budget"] == {"max_pages": 1, "max_seconds": 30.0, "enforced": True}
    assert payload["budget_exhausted"] is True
    assert "documented budget" in (summary.detail or "")


def _is_skip(result: CheckResult) -> bool:
    return any(evidence.payload.get("skipped") for evidence in result.evidence)


async def test_the_budget_defaults_are_the_documented_ones() -> None:
    web = WebSettings()
    assert (web.browser_max_pages, web.browser_time_budget_s) == (25, 120.0)
    assert web.browser_crawl is False, "the browser is an operator opt-in (R-16)"
    budget = CrawlBudget(max_pages=web.browser_max_pages, max_seconds=web.browser_time_budget_s)
    assert budget.describe() == "25 navigation(s) / 120s"


async def test_a_zero_page_budget_is_refused_by_the_settings() -> None:
    from arachne.core.errors import ConfigurationError

    with pytest.raises(ConfigurationError, match="browser_max_pages"):
        replace(WebSettings(), browser_max_pages=0)
    with pytest.raises(ConfigurationError, match="browser_time_budget_s"):
        replace(WebSettings(), browser_time_budget_s=0.0)


def test_the_check_registered_with_its_framework_mapping() -> None:
    by_id = {check.metadata.id: check for check in M3_CHECKS}
    metadata = by_id["m3.dom-xss"].metadata
    assert metadata.research_ref == "ch03#3"
    assert metadata.cwe == "CWE-79"
    assert set(metadata.framework) >= {"WSTG-CLNT-01", "WSTG-CLNT-02", "CWE-79"}
    assert metadata.requires_active_checks is True
    assert metadata.safe is True
    assert metadata.runs_on_discovered is True


async def test_the_browser_proxy_inherits_the_scans_scope_policy_and_air_gap(
    lab: WebLab, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The proxy is built from the scan's own gate inputs, not from defaults.

    This is the wiring assertion behind "the same gate, not a second one": the scope, the
    address policy, the resolver and the air-gap allowlist the browser's proxy uses are the
    objects the scan's shared HTTP client holds.
    """
    real = dom_xss_module.ScopeProxy
    captured: dict[str, Any] = {}

    class _Recording(real):  # type: ignore[misc, valid-type]
        def __init__(self, **kwargs: Any) -> None:
            captured.update(kwargs)
            super().__init__(**kwargs)

    monkeypatch.setattr(dom_xss_module, "ScopeProxy", _Recording)
    _results, _installed, harness = await _run(lab, monkeypatch)
    client = harness.http_client
    assert captured["scope"] is client.scope
    assert captured["policy"] is client.policy
    assert captured["resolver"] is client.resolver
    assert captured["airgap"] is client.airgap
    assert captured["airgap_scope_hosts"] == client.airgap_scope_hosts
