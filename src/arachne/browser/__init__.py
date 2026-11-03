"""The headless-browser subsystem (REQ-DET-015, ADR-340).

ARACHNE's largest detection gap against Burp and ZAP was client-side: the M3 client module
records that the DOM-sink half of research ch03#3 "is *not* implemented", and
``m3/advanced_api.py`` records that a headless-browser check was out of scope by an earlier
ADR. The product therefore could not see a single-page application's routes, could not see
client-side rendering, and could not see a DOM-XSS sink that is reachable only through
JavaScript execution.

This package closes that gap and is, deliberately, the most safety-constrained subsystem in
the product, because a headless browser inside a scanner is a new attack surface *inside* the
scanner (R-16, score 15 — the highest-scoring technical risk in the register). Four rules
shape everything here:

1. **The browser is an optional extra.** ``arachne[browser]`` installs it; the default and the
   air-gapped installs never contain it, and with it absent every part of this package reports
   itself unavailable rather than failing (``driver.browser_available``).
2. **The proxy is the only egress.** ``proxy.ScopeProxy`` is the browser's sole way out, and it
   runs the same :func:`~arachne.core.safety.validate_url` gate every other request in the
   product passes through — plus the deployment's air-gapped egress allowlist — *before* it
   dials, then dials the address that gate validated. A second scoped transport is not a way
   around a control the first one enforces.
3. **The capabilities REQ-DET-015 names are off, and asserted off.** ``hardening`` builds the
   launch argv and the context options as data so a test can assert each of the six without
   starting a browser.
4. **The crawl's decisions are testable without a browser.** ``crawl.BrowserCrawl`` talks to a
   ``Navigator`` protocol; the real driver is one implementation of it. The budget, the
   per-navigation scope check, the JavaScript-only route test and the DOM-sink analysis are
   all exercised against scripted navigators, which is how the hostile cases (an off-scope
   redirect, a download, a ``file:`` navigation) are tests rather than edge cases.

Layout: :mod:`~arachne.browser.hardening` (what the browser may do),
:mod:`~arachne.browser.proxy` (the scope-bound egress), :mod:`~arachne.browser.sinks` (the
dom-sink instrumentation and its analysis), :mod:`~arachne.browser.urls` (URL arithmetic),
:mod:`~arachne.browser.crawl` (the bounded walk), :mod:`~arachne.browser.driver` (Chromium).
"""

from __future__ import annotations

from arachne.browser.crawl import (
    MARKER_SOURCES,
    BrowserCrawl,
    CrawlBudget,
    CrawlResult,
    DomSink,
    JsRoute,
    Navigator,
    RenderedPage,
    close_navigator,
)
from arachne.browser.driver import BROWSER_EXTRA, browser_available, unavailable_reason
from arachne.browser.hardening import (
    DISABLED_CAPABILITIES,
    all_disabled,
    capability_report,
    context_kwargs,
    launch_args,
    scheme_allowed,
)
from arachne.browser.proxy import ProxyRefusal, ScopeProxy, refusal_summary
from arachne.browser.sinks import (
    DEFAULT_STEM,
    SINK_VOCABULARY,
    SinkHit,
    instrument_source,
    parse_sink_records,
)

__all__ = [
    "BROWSER_EXTRA",
    "DEFAULT_STEM",
    "DISABLED_CAPABILITIES",
    "MARKER_SOURCES",
    "SINK_VOCABULARY",
    "BrowserCrawl",
    "CrawlBudget",
    "CrawlResult",
    "DomSink",
    "JsRoute",
    "Navigator",
    "ProxyRefusal",
    "RenderedPage",
    "ScopeProxy",
    "SinkHit",
    "all_disabled",
    "browser_available",
    "capability_report",
    "close_navigator",
    "context_kwargs",
    "instrument_source",
    "launch_args",
    "parse_sink_records",
    "refusal_summary",
    "scheme_allowed",
    "unavailable_reason",
]
