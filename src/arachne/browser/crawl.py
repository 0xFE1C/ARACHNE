"""The bounded browser crawl: route discovery and DOM-sink collection (REQ-DET-015).

This is the walk. It owns three things and delegates the rest:

* **the budget** — a documented page count *and* wall-clock limit, checked before every
  navigation, so the crawl cannot be made to run longer than the plan says it will;
* **the per-navigation scope gate** — :func:`~arachne.core.safety.validate_url` runs on the
  URL *before* the browser is asked to navigate, so an out-of-scope target is refused and
  audited without a request ever being attempted (the proxy refuses it too, which is the
  defence for everything the page does on its own initiative);
* **the analysis** — which rendered links are JavaScript-rendered routes, and which sink
  calls carry the planted marker.

Everything that touches a browser is behind :class:`Navigator`: the crawl contains no
browser API, no HTTP client and no socket. That is what makes the safety properties testable
without the optional extra installed — the real driver and a scripted double are
interchangeable, and the safety suite drives the hostile cases through the double.

**Two marker sources, one inert marker.** Each navigated page is loaded once per source with
a fresh ``ar9x<hex>`` marker planted in it: in the **fragment** (``#ar9x...``), which is never
sent to the server at all, and in a **query parameter**, which reaches the server the same way
the M3 reflection oracle's marker already does. The marker is alphanumeric — it cannot execute
— so a hit proves *taint flow into a dangerous sink*, which is the requirement's ask, and
never an executed payload. ``client_side_only`` is true only when the marker is absent from
the server's own response body, which is the fact that separates a DOM-XSS from a reflection.
"""

from __future__ import annotations

import contextlib
import re
import secrets
import time
from collections import deque
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Final, Protocol
from urllib.parse import urljoin

from arachne.browser.sinks import SinkHit, parse_sink_records
from arachne.browser.urls import (
    is_http_url,
    origin_of,
    path_and_query,
    same_origin,
    strip_fragment,
    with_param,
)
from arachne.core.audit import AuditAction, Auditor, AuditOutcome
from arachne.core.errors import SafetyError
from arachne.core.safety import HostResolver, Scope, UrlSafetyPolicy, validate_url

__all__ = [
    "MARKER_SOURCES",
    "QUERY_MARKER_PARAM",
    "BrowserCrawl",
    "CrawlBudget",
    "CrawlResult",
    "DomSink",
    "JsRoute",
    "Navigator",
    "RenderedPage",
    "close_navigator",
    "marker_for",
]

#: The DOM sources the marker is planted in, and the ``dom_source`` label the evidence
#: carries. ``hash`` is strictly inert (a fragment never leaves the browser); ``search`` is
#: the same GET-with-a-marker shape the M3 reflection oracle already sends.
MARKER_SOURCES: Final[tuple[tuple[str, str], ...]] = (
    ("hash", "location.hash"),
    ("search", "location.search"),
)

#: The query parameter name used for the ``search`` source. Fixed (not configurable) so the
#: request is recognisable in the target's own logs as ARACHNE's probe.
QUERY_MARKER_PARAM: Final = "arachne_dom_probe"


@dataclass(frozen=True, slots=True)
class CrawlBudget:
    """The documented page and time budget, enforced before every navigation.

    Both bounds are checked in the walk loop; the first to trip stops the crawl and is
    recorded on the result (:attr:`CrawlResult.budget_exhausted`) and in the audit trail
    (``budget.exhausted``). ``max_pages`` counts *navigations* — one per marker source per
    route — so a two-source crawl of 25 navigations covers 12 routes, and the plan prints the
    navigation bound rather than the route count.
    """

    max_pages: int = 25
    max_seconds: float = 120.0

    def __post_init__(self) -> None:
        if self.max_pages < 1:
            msg = f"a browser crawl budget needs at least one page, got {self.max_pages}"
            raise ValueError(msg)
        if self.max_seconds <= 0:
            msg = f"a browser crawl budget needs a positive time bound, got {self.max_seconds}"
            raise ValueError(msg)

    def describe(self) -> str:
        return f"{self.max_pages} navigation(s) / {self.max_seconds:g}s"


def marker_for(stem: str) -> str:
    """A fresh inert marker: ``<stem><8 hex digits>`` (the M3 oracle's shape, alphanumeric)."""
    return f"{stem}{secrets.token_hex(4)}"


@dataclass(frozen=True, slots=True)
class RenderedPage:
    """What one navigation of a real (or scripted) browser produced.

    ``raw_body`` is the **server's** response body for the main document — the bytes before
    any script ran. It is what makes both judgements possible: a route whose path is absent
    from it was rendered by JavaScript, and a marker absent from it cannot have arrived
    through the response body.
    """

    url: str
    final_url: str = ""
    status: int | None = None
    raw_body: str = ""
    links: tuple[str, ...] = ()
    sink_records: tuple[object, ...] = ()
    history_routes: tuple[str, ...] = ()
    refused_requests: tuple[str, ...] = ()
    downloads: tuple[str, ...] = ()
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.error is None


class Navigator(Protocol):
    """One browser, reduced to "navigate and report" — the only browser surface the crawl has.

    The real implementation is :class:`~arachne.browser.driver.PlaywrightNavigator`; the
    safety and unit suites substitute scripted implementations, which is why every hostile
    case (an off-scope redirect, a download, a ``file:`` navigation, a page that tries to
    reach an internal address) can be driven without a browser installed.
    """

    async def navigate(self, url: str) -> RenderedPage: ...

    async def aclose(self) -> None: ...


@dataclass(frozen=True, slots=True)
class JsRoute:
    """A route the browser reached that the server's own response did not name."""

    url: str
    page: str
    source: str  # "rendered-dom" | "history-api"
    js_only: bool

    def to_dict(self) -> dict[str, Any]:
        return {"url": self.url, "page": self.page, "source": self.source, "js_only": self.js_only}


@dataclass(frozen=True, slots=True)
class DomSink:
    """A sink call that carried the marker, attributed to the source it was planted in."""

    route: str
    source: str
    marker: str
    hit: SinkHit
    client_side_only: bool
    executed_in_browser: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "route": self.route,
            "dom_source": self.source,
            "marker": self.marker,
            "client_side_only": self.client_side_only,
            **self.hit.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class CrawlResult:
    """Everything the crawl learned, with the budget's outcome recorded."""

    routes: tuple[JsRoute, ...] = ()
    sinks: tuple[DomSink, ...] = ()
    navigations: int = 0
    blocked_navigations: tuple[str, ...] = ()
    refused_requests: tuple[str, ...] = ()
    downloads: tuple[str, ...] = ()
    budget_exhausted: bool = False
    elapsed_s: float = 0.0
    notes: tuple[str, ...] = ()
    capabilities: Mapping[str, Any] = field(default_factory=dict)

    def js_only_routes(self) -> tuple[JsRoute, ...]:
        return tuple(route for route in self.routes if route.js_only)

    def client_side_sinks(self) -> tuple[DomSink, ...]:
        """Sinks whose marker never appeared in the server's response — the DOM-XSS read."""
        return tuple(sink for sink in self.sinks if sink.client_side_only)

    def summary(self) -> dict[str, Any]:
        return {
            "navigations": self.navigations,
            "routes": len(self.routes),
            "js_only_routes": len(self.js_only_routes()),
            "dom_sinks": len(self.sinks),
            "client_side_sinks": len(self.client_side_sinks()),
            "blocked_navigations": len(self.blocked_navigations),
            "refused_requests": len(self.refused_requests),
            "downloads": len(self.downloads),
            "budget_exhausted": self.budget_exhausted,
            "elapsed_s": round(self.elapsed_s, 3),
            "notes": list(self.notes),
        }


@dataclass(slots=True)
class BrowserCrawl:
    """The bounded, scope-gated walk of a JavaScript application."""

    navigator: Navigator
    scope: Scope
    auditor: Auditor
    budget: CrawlBudget = field(default_factory=CrawlBudget)
    policy: UrlSafetyPolicy = field(default_factory=UrlSafetyPolicy)
    resolver: HostResolver | None = None
    #: Paths that are recorded but never walked (the M3 crawl's rule, applied to a transport
    #: that clicks links for real): a browser must not log the scanner out of the application
    #: it is measuring. Passed in by the caller so the two crawls cannot disagree.
    destructive_path_re: re.Pattern[str] | None = None
    marker_stem: str = "ar9x"
    sources: tuple[tuple[str, str], ...] = MARKER_SOURCES
    capabilities: Mapping[str, Any] = field(default_factory=dict)

    async def run(self, roots: Sequence[str]) -> CrawlResult:
        """Walk ``roots`` breadth-first inside the budget and return what was found.

        **Every bound is checked before every navigation**, not once per route: a route costs
        one navigation per marker source, so a per-route check would let a two-source crawl
        overshoot the time budget by a whole navigation. The loop below therefore re-checks
        both bounds immediately before asking the browser for a page, which is what makes
        "bounded by a documented page and time budget" a property of the walk rather than of
        its average.
        """
        started = time.monotonic()
        queue: deque[str] = deque(dict.fromkeys(roots))
        visited: set[str] = set()
        routes: list[JsRoute] = []
        sinks: list[DomSink] = []
        blocked: list[str] = []
        refused: list[str] = []
        downloads: list[str] = []
        notes: list[str] = []
        navigations = 0
        exhausted = False

        def out_of_budget() -> str | None:
            """The bound that is currently exceeded, or ``None``."""
            if navigations >= self.budget.max_pages:
                return "max_pages"
            if time.monotonic() - started >= self.budget.max_seconds:
                return "max_seconds"
            return None

        def stop(limit: str) -> None:
            nonlocal exhausted
            exhausted = True
            if limit == "max_pages":
                notes.append(f"page budget exhausted at {self.budget.max_pages} navigation(s)")
            else:
                notes.append(f"time budget exhausted after {self.budget.max_seconds:g}s")
            self._audit_budget(navigations, limit)

        while queue:
            limit = out_of_budget()
            if limit is not None:
                stop(limit)
                break
            url = queue.popleft()
            if url in visited:
                continue
            visited.add(url)
            if not is_http_url(url):
                continue
            if self.destructive_path_re is not None and self.destructive_path_re.search(
                path_and_query(url).split("?", 1)[0]
            ):
                notes.append(f"recorded but not walked (destructive path): {url}")
                continue
            # ---- scope validation BEFORE the request (REQ-DET-015, INV-2).
            if not await self._authorize(url):
                blocked.append(url)
                continue
            for source_key, source_label in self.sources:
                limit = out_of_budget()
                if limit is not None:
                    stop(limit)
                    break
                marker = marker_for(self.marker_stem)
                probe = self._planted(url, source_key, marker)
                page = await self.navigator.navigate(probe)
                navigations += 1
                refused.extend(page.refused_requests)
                downloads.extend(page.downloads)
                if not page.ok:
                    if page.error:
                        notes.append(f"{url}: {page.error}")
                    continue
                raw = page.raw_body or ""
                sinks.extend(
                    DomSink(
                        route=url,
                        source=source_label,
                        marker=marker,
                        hit=hit,
                        client_side_only=marker not in raw,
                    )
                    for hit in parse_sink_records(page.sink_records, nonce=marker)
                )
                routes.extend(self._routes(page, raw, url, visited, queue))
            if exhausted:
                break

        return CrawlResult(
            routes=tuple(routes),
            sinks=tuple(sinks),
            navigations=navigations,
            blocked_navigations=tuple(blocked),
            refused_requests=tuple(dict.fromkeys(refused)),
            downloads=tuple(dict.fromkeys(downloads)),
            budget_exhausted=exhausted,
            elapsed_s=time.monotonic() - started,
            notes=tuple(notes),
            capabilities=dict(self.capabilities),
        )

    # ------------------------------------------------------------------ internals
    def _routes(
        self,
        page: RenderedPage,
        raw_body: str,
        page_url: str,
        visited: set[str],
        queue: deque[str],
    ) -> list[JsRoute]:
        """The same-origin routes this page's rendered DOM names, and whether JS made them.

        ``js_only`` is a substring test against the server's own response: a route whose
        ``path?query`` appears in the raw body was in the HTML the server sent. One that does
        not was produced by script — which is the capability REQ-DET-015 asks for. When the
        raw body is empty (a navigation that failed, or a non-HTML document) nothing is
        claimed: ``js_only`` is false, because the honest answer is "not established".
        """
        origin = origin_of(page_url)
        found: list[JsRoute] = []
        history = set(page.history_routes)
        for raw_link in (*page.links, *page.history_routes):
            # The driver reads absolute hrefs out of the live DOM; resolving here as well means
            # a relative href from any transport is measured against the right origin instead of
            # being silently dropped.
            link = urljoin(page_url, raw_link) if raw_link else ""
            if not link or not same_origin(link, origin):
                continue
            clean = strip_fragment(link)
            target = path_and_query(clean)
            js_only = (
                bool(raw_body) and target not in raw_body and strip_fragment(page_url) != clean
            )
            found.append(
                JsRoute(
                    url=clean,
                    page=page_url,
                    source="history-api" if raw_link in history else "rendered-dom",
                    js_only=js_only,
                )
            )
            if clean not in visited:
                queue.append(clean)
        return found

    def _planted(self, url: str, source: str, marker: str) -> str:
        """``url`` with ``marker`` planted in the requested DOM source."""
        if source == "hash":
            return f"{strip_fragment(url)}#{marker}"
        return with_param(url, QUERY_MARKER_PARAM, marker)

    async def _authorize(self, url: str) -> bool:
        """Run the shared scope gate on ``url``; audit the refusal and return ``False``."""
        try:
            await validate_url(url, self.scope, policy=self.policy, resolver=self.resolver)
        except SafetyError as exc:
            self.auditor.record(
                AuditAction.SCOPE_REJECTED,
                outcome=AuditOutcome.BLOCKED,
                target=url,
                reason=exc.reason or str(exc),
                meta={"method_hint": "browser-navigation"},
            )
            return False
        return True

    def _audit_budget(self, navigations: int, limit: str) -> None:
        self.auditor.record(
            AuditAction.BUDGET_EXHAUSTED,
            outcome=AuditOutcome.BLOCKED,
            target=f"browser-crawl:{self.budget.describe()}",
            reason=f"browser crawl stopped at its {limit} bound",
            meta={"navigations": navigations, "limit": limit},
        )


async def close_navigator(navigator: Navigator) -> None:
    """Close a navigator, swallowing a failure to close (the crawl's result already exists)."""
    with contextlib.suppress(Exception):
        await navigator.aclose()
