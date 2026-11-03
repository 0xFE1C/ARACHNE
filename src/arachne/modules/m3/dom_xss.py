"""``m3.dom-xss`` — DOM-XSS sinks reachable only through JavaScript execution (REQ-DET-015).

The other half of research ch03#3. ``m3.xss-oracle`` measures what a *server* reflects; this
check measures what the *browser* does, which is the only way to see a sink that no response
body ever contains. It is the check the M3 package docstring and ADR-100.4 recorded as
unimplemented, and it needs a JavaScript engine — so it lives behind an optional extra
(``arachne[browser]``) and reports itself skipped when that extra is absent.

**What it does.** It starts ARACHNE's scope-bound proxy, points a hardened headless Chromium
at it, walks the crawl's same-origin routes within a documented page/time budget, and for each
page loads it twice with a fresh inert marker planted in two DOM sources (the fragment, which
never leaves the browser, and a query parameter). If the marker reaches one of the documented
sinks — ``innerHTML``, ``document.write``, ``eval``, ``location.href``, … — *and* the marker
was not in the server's own response body, then the page moved an attacker-controllable source
into a dangerous sink without any server involvement. That is a DOM-XSS, and the evidence names
the source and the sink.

**What it does not do.** The marker is alphanumeric: it cannot execute, and no payload, event
handler or ``javascript:`` URL is ever injected (the same doctrine as ``m3.xss-oracle``'s
inert probe). Nothing is exploited, downloaded or written; the browser cannot reach anything
the scan's scope does not already allow, because every request it makes goes through the
proxy, which is the same gate as every other request in the product. See
:mod:`arachne.browser` and ADR-340.

**Two switches, on purpose.** The extra must be *installed* and the operator must set
``ARACHNE_WEB_BROWSER_CRAWL=true``. R-16's mitigation is that the browser is the operator's
opt-in, so installing it does not silently start browsing every target a scan is pointed at.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from arachne.browser.crawl import (
    BrowserCrawl,
    CrawlBudget,
    CrawlResult,
    Navigator,
    close_navigator,
)
from arachne.browser.driver import PlaywrightNavigator, browser_available, unavailable_reason
from arachne.browser.hardening import capability_report
from arachne.browser.proxy import ScopeProxy, refusal_summary
from arachne.browser.sinks import sink_artifact
from arachne.core.http import HttpExchange
from arachne.core.results import CheckResult, Evidence
from arachne.core.target import TargetKind
from arachne.modules.base import CheckMetadata, Module
from arachne.modules.context import CheckContext
from arachne.modules.m3.inventory import DESTRUCTIVE_PATH_RE, origin_of
from arachne.modules.m3.support import (
    NONCE_STEM,
    WebCheck,
    exchange_from_page,
    http_or_skip,
    owns_origin,
    skip,
    web_candidate,
    web_or_skip,
)

__all__ = ["BROWSER_SWITCH", "DomSinkCheck", "open_navigator"]

#: The deployment switch that turns the browser crawl on (WebSettings.browser_crawl). Named
#: in every skipped result so an operator reading the finding knows what to set.
BROWSER_SWITCH = "ARACHNE_WEB_BROWSER_CRAWL"


async def open_navigator(proxy_url: str, *, marker_stem: str, timeout_ms: int) -> Navigator:
    """Start the real driver. The seam a test replaces with a scripted navigator.

    Module-level (rather than a call inside :meth:`DomSinkCheck.run`) for the same reason
    ``http3_available`` is: it is the one place the optional dependency is reached, so a test
    can drive the whole check — budget, scope gate, sink analysis, asset recording — without
    installing a browser.
    """
    navigator = PlaywrightNavigator(
        proxy_url=proxy_url, marker_stem=marker_stem, timeout_ms=timeout_ms
    )
    return await navigator.start()


class DomSinkCheck(WebCheck, Module):
    """``m3.dom-xss`` — DOM sink reachability through real JavaScript execution (ch03#3)."""

    metadata = CheckMetadata(
        id="m3.dom-xss",
        module="M3",
        name="dom-xss",
        version="1.0",
        title="DOM-based cross-site scripting sinks",
        description=(
            "Crawls the application in a hardened headless browser and loads each route with a "
            "fresh inert marker planted in the URL fragment and in a query parameter. When the "
            "marker reaches a documented DOM sink (innerHTML, document.write, eval, "
            "location.href, ...) and was absent from the server's own response body, the page "
            "moved an attacker-controllable source into a dangerous sink without server "
            "involvement: a DOM-XSS. The evidence names the source and the sink. Requires the "
            "optional arachne[browser] extra and ARACHNE_WEB_BROWSER_CRAWL=true; the marker is "
            "inert, nothing is executed as a payload, and every navigation passes the scope "
            "gate before the request."
        ),
        research_ref="ch03#3",
        framework=("WSTG-CLNT-01", "WSTG-CLNT-02", "CWE-79"),
        cwe="CWE-79",
        target_kinds=(TargetKind.URL,),
        severity_hint="high",
        type="active",
        safe=True,
        verifiable=False,
        estimated_requests=6,
        requires_active_checks=True,
        runs_on_discovered=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        client, skipped = http_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        web = ctx.config.web
        if not web.browser_crawl:
            yield skip(
                ctx,
                "the browser crawl is off: set "
                f"{BROWSER_SWITCH}=true to crawl JavaScript-rendered routes "
                f"(a browser is a new attack surface, so it is opt-in — R-16)",
            )
            return
        if not browser_available():
            yield skip(ctx, unavailable_reason())
            return
        if not owns_origin(ctx):
            yield skip(ctx, "another URL asset on this origin owns the M3 crawl for it")
            return
        inventory, skipped = web_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        assert inventory is not None

        budget = CrawlBudget(max_pages=web.browser_max_pages, max_seconds=web.browser_time_budget_s)
        roots = self._roots(ctx, inventory)
        if not roots:
            yield skip(ctx, "no same-origin page in the M3 crawl to render in a browser")
            return

        # The proxy is the browser's only egress, and it runs the scan's own gate: the same
        # scope, the same address policy, the same resolver the shared HTTP client uses, plus
        # the deployment's air-gap allowlist — so there is no second, weaker definition of
        # "may this host be reached" anywhere in the product.
        proxy = ScopeProxy(
            scope=ctx.scope,
            auditor=ctx.step.auditor,
            policy=client.policy,
            resolver=client.resolver,
            airgap=client.airgap,
            airgap_scope_hosts=client.airgap_scope_hosts,
        )
        await proxy.start()
        navigator: Navigator | None = None
        try:
            try:
                navigator = await open_navigator(
                    proxy.proxy_url,
                    marker_stem=NONCE_STEM,
                    timeout_ms=int(web.browser_timeout_s * 1000),
                )
            except Exception as exc:
                # The extra can be installed while the *browser binary* is not (playwright
                # needs `playwright install`, and an air-gapped estate may have only the
                # wheel). A launch failure is an absence, not a broken check: it is reported
                # with the reason, exactly as the missing extra is, and the proxy is closed.
                yield skip(
                    ctx,
                    f"the browser could not be started: {type(exc).__name__}: {exc}"[:300],
                )
                return
            crawl = BrowserCrawl(
                navigator=navigator,
                scope=ctx.scope,
                auditor=ctx.step.auditor,
                budget=budget,
                policy=client.policy,
                resolver=client.resolver,
                destructive_path_re=DESTRUCTIVE_PATH_RE,
                marker_stem=NONCE_STEM,
                capabilities=capability_report(proxy.proxy_url),
            )
            result = await crawl.run(roots)
        finally:
            if navigator is not None:
                await close_navigator(navigator)
            await proxy.aclose()

        await self._record_routes(ctx, result)
        for sink in result.client_side_sinks():
            yield self._candidate(ctx, sink, result, proxy)
        yield self._summary(ctx, result, inventory.pages.get(roots[0]), proxy)

    # ------------------------------------------------------------------ internals
    @staticmethod
    def _roots(ctx: CheckContext, inventory: Any) -> tuple[str, ...]:
        """The crawl's same-origin GET-able pages, bounded by the page budget.

        The inventory's own order is the crawl's order, so the browser opens the same surface
        the M3 checks read, and a page the crawl discovered is a page the browser can render.
        """
        origin = origin_of(ctx.asset.value)
        roots = [url for url in inventory.order if origin_of(url) == origin]
        if ctx.asset.value not in roots:
            roots.insert(0, ctx.asset.value)
        return tuple(dict.fromkeys(roots))

    async def _record_routes(self, ctx: CheckContext, result: CrawlResult) -> None:
        """Record every JavaScript-rendered route as a URL asset (REQ-DET-015).

        ``record_asset`` is the scope guard's own entry point, so a route that turned out to
        be out of scope is discarded and audited rather than stored (F-01-02) — the browser
        cannot widen the scan's asset inventory by discovering something it should not reach.
        """
        for route in result.js_only_routes():
            await ctx.record_asset(
                "url",
                route.url,
                meta={
                    "js_rendered": True,
                    "discovered_by": self.metadata.id,
                    "found_on": route.page,
                    "route_source": route.source,
                },
                source=f"{self.metadata.id}:browser-crawl",
            )

    def _candidate(
        self, ctx: CheckContext, sink: Any, result: CrawlResult, proxy: ScopeProxy
    ) -> CheckResult:
        """One DOM-XSS candidate: the sink, the source, the marker, and the proof it was DOM."""
        page = self._page(ctx, sink.route)
        exchanges: list[HttpExchange | None] = [exchange_from_page(page)] if page else []
        artifact = sink_artifact(
            sink.hit,
            source=sink.source,
            marker=sink.marker,
            client_side_only=sink.client_side_only,
            route=sink.route,
        )
        artifact["browser"] = {
            "capabilities": dict(result.capabilities),
            "navigations": result.navigations,
            "js_only_routes": len(result.js_only_routes()),
            "proxy": refusal_summary(proxy),
        }
        return web_candidate(
            ctx,
            f"DOM-XSS sink {sink.hit.sink} reached from {sink.source}",
            artifact=artifact,
            exchanges=exchanges,
            cwe="CWE-79",
            confidence=sink.hit.confidence,
            detail=(
                f"the marker planted in {sink.source} on {sink.route} reached "
                f"{sink.hit.sink} in the browser ({sink.hit.rationale}); the server's own "
                "response for that route did not contain it, so the value travelled through "
                "the DOM and not through the response body. The marker is inert — no payload "
                "was executed — so this is taint flow into a dangerous sink, not a live "
                "exploit"
            ),
            source=sink.route,
        )

    def _summary(
        self, ctx: CheckContext, result: CrawlResult, page: Any, proxy: ScopeProxy
    ) -> CheckResult:
        """The crawl's own report: what was rendered, what was skipped, what was refused."""
        web = ctx.config.web
        summary = result.summary()
        summary["budget"] = {
            "max_pages": web.browser_max_pages,
            "max_seconds": web.browser_time_budget_s,
            "enforced": True,
        }
        summary["proxy"] = refusal_summary(proxy)
        detail = (
            f"rendered {summary['navigations']} navigation(s) in a headless browser over "
            f"{summary['routes']} route(s) ({summary['js_only_routes']} reachable only after "
            f"client-side rendering); {summary['dom_sinks']} DOM sink(s) carried the marker, "
            f"{summary['client_side_sinks']} of them without it appearing in the server's "
            f"response; {summary['blocked_navigations']} navigation(s) refused by the scope "
            f"gate and {summary['refused_requests']} sub-resource request(s) refused inside "
            "the browser"
        )
        if result.budget_exhausted:
            detail += (
                "; the crawl stopped at its documented budget of "
                f"{web.browser_max_pages} navigation(s) / {web.browser_time_budget_s:g}s"
            )
        if result.notes:
            detail += "; " + "; ".join(result.notes[:5])
        return ctx.result(
            "info",
            "browser crawl of the JavaScript-rendered surface",
            detail=detail,
            evidence=(
                Evidence.of(
                    "artifact",
                    summary,
                    source=page.url if page is not None else None,
                ),
            ),
            confidence=0.4,
        )

    @staticmethod
    def _page(ctx: CheckContext, url: str) -> Any:
        """The M3 crawl's record of ``url``, when it has one (evidence without a new request)."""
        inventory = ctx.web
        if inventory is None:
            return None
        return inventory.pages.get(url)
