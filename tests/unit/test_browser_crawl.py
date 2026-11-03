"""The bounded browser crawl: budget, route discovery and DOM-sink attribution (REQ-DET-015).

The crawl decides everything that matters and touches no browser, so these tests drive it with
the scripted navigator in ``tests/helpers/browser.py`` and assert:

* the **page budget** and the **time budget** are enforced (the exit criteria's "the budget is
  enforced"), each recording itself on the result and in the audit trail;
* a route that only the *rendered* DOM names is reported as JavaScript-rendered, while one the
  server's HTML also names is not — the capability claim, with its counter-case;
* an out-of-scope navigation is refused **before** the browser is asked to open it, and the
  refusal is audited with the same action the HTTP client writes (the same gate, not a second
  one);
* a marker that appears in the server's own response is *not* reported as a DOM-XSS, which is
  the discriminator against a reflected finding;
* the two marker sources are planted where they claim to be (the fragment is never sent).
"""

from __future__ import annotations

import asyncio

import pytest
from tests.helpers.browser import ScriptedNavigator, ScriptedPage, marker_in, sink_record

from arachne.browser.crawl import (
    MARKER_SOURCES,
    BrowserCrawl,
    CrawlBudget,
    marker_for,
)
from arachne.browser.sinks import (
    DEFAULT_STEM,
    MAX_RECORDS,
    SINK_VOCABULARY,
    instrument_source,
    parse_sink_records,
)
from arachne.browser.urls import (
    is_http_url,
    origin_of,
    path_and_query,
    same_origin,
    strip_fragment,
    with_param,
)
from arachne.core.audit import AuditAction, Auditor, MemoryAuditSink
from arachne.core.safety import HostResolver, Scope, UrlSafetyPolicy

IN_SCOPE = "127.0.0.1"
BASE = f"http://{IN_SCOPE}:8080"
OUT_OF_SCOPE = "http://evil.example/"


class _RecordingResolver:
    """A resolver that answers nothing and remembers being asked (proving it was not)."""

    def __init__(self) -> None:
        self.asked: list[str] = []

    async def resolve(self, host: str, port: int) -> tuple[str, ...]:
        del port
        self.asked.append(host)
        return ("93.184.216.34",)


def _crawl(
    sink: MemoryAuditSink,
    navigator: ScriptedNavigator,
    *,
    budget: CrawlBudget | None = None,
    allowed_hosts: tuple[str, ...] = (IN_SCOPE,),
    resolver: HostResolver | None = None,
    destructive: bool = False,
) -> BrowserCrawl:
    import re

    return BrowserCrawl(
        navigator=navigator,
        scope=Scope(allowed_hosts=allowed_hosts),
        auditor=Auditor(sink, actor="pytest"),
        budget=budget or CrawlBudget(max_pages=50, max_seconds=30.0),
        policy=UrlSafetyPolicy(allow_loopback=True, allow_private_ips=True),
        resolver=resolver,
        destructive_path_re=re.compile(r"(?:^|/)(?:logout|delete)(?:$|[/?.#_-])")
        if destructive
        else None,
        marker_stem=DEFAULT_STEM,
    )


# ------------------------------------------------------------------ the budget
def test_a_budget_refuses_a_nonsensical_bound() -> None:
    with pytest.raises(ValueError, match="at least one page"):
        CrawlBudget(max_pages=0)
    with pytest.raises(ValueError, match="positive time bound"):
        CrawlBudget(max_seconds=0)


def test_the_budget_describes_itself_for_the_plan() -> None:
    assert CrawlBudget(max_pages=25, max_seconds=120.0).describe() == "25 navigation(s) / 120s"


async def test_the_page_budget_is_enforced_and_audited() -> None:
    """Two navigations allowed means two navigations, whatever the queue holds."""
    sink = MemoryAuditSink()
    navigator = ScriptedNavigator(
        pages={
            "/": ScriptedPage(
                raw_body="<a href='/a'>a</a><a href='/b'>b</a>",
                links=("/a", "/b"),
            ),
            "/a": ScriptedPage(raw_body="/a"),
            "/b": ScriptedPage(raw_body="/b"),
        }
    )
    crawl = _crawl(sink, navigator, budget=CrawlBudget(max_pages=2, max_seconds=30.0))
    result = await crawl.run([BASE + "/"])
    assert result.navigations == 2
    assert result.budget_exhausted is True
    assert any("page budget exhausted" in note for note in result.notes)
    exhausted = sink.of_action(AuditAction.BUDGET_EXHAUSTED)
    assert exhausted and "max_pages" in str(exhausted[0].meta)


async def test_the_time_budget_is_enforced_and_audited() -> None:
    """A slow page cannot hold the crawl open past its wall-clock bound."""
    sink = MemoryAuditSink()

    class _Slow(ScriptedNavigator):
        async def navigate(self, url: str):  # type: ignore[no-untyped-def]
            await asyncio.sleep(0.05)
            return await super().navigate(url)

    navigator = _Slow(
        pages={
            "/": ScriptedPage(raw_body="<a href='/a'>", links=("/a",)),
            "/a": ScriptedPage(raw_body="<a href='/b'>", links=("/b",)),
            "/b": ScriptedPage(raw_body="/b"),
        }
    )
    crawl = _crawl(sink, navigator, budget=CrawlBudget(max_pages=50, max_seconds=0.06))
    result = await crawl.run([BASE + "/"])
    assert result.budget_exhausted is True
    assert result.navigations < 3
    assert any("time budget exhausted" in note for note in result.notes)
    assert sink.of_action(AuditAction.BUDGET_EXHAUSTED)


async def test_the_time_budget_is_checked_before_every_navigation_not_every_route() -> None:
    """A route costs one navigation per marker source, so the check cannot be per route.

    With a budget that is already spent after the first navigation, a per-route check would
    still open the *second* source's frame (the route is not finished) and overshoot the
    documented bound by a whole navigation. Exactly one navigation must happen.
    """
    sink = MemoryAuditSink()

    class _Slow(ScriptedNavigator):
        async def navigate(self, url: str):  # type: ignore[no-untyped-def]
            await asyncio.sleep(0.05)
            return await super().navigate(url)

    navigator = _Slow(pages={"/one": ScriptedPage(raw_body="<div/>")})
    crawl = _crawl(sink, navigator, budget=CrawlBudget(max_pages=50, max_seconds=0.02))
    result = await crawl.run([BASE + "/one"])
    assert len(MARKER_SOURCES) == 2, "the point is that the second source is not opened"
    assert result.navigations == 1, navigator.navigations
    assert result.budget_exhausted is True
    assert any("time budget exhausted" in note for note in result.notes)


# ------------------------------------------------------------------ route discovery
async def test_a_route_only_the_rendered_dom_names_is_reported_as_js_rendered() -> None:
    """The capability claim: the shell's HTML does not name /spa/orders; its script does."""
    sink = MemoryAuditSink()
    navigator = ScriptedNavigator(
        pages={
            "/spa": ScriptedPage(
                # The server's bytes name the shell's own path and nothing else. The link is
                # assembled by script, so the raw body cannot contain "/spa/orders".
                raw_body="<div id='app'></div>",
                links=("/spa/orders", "/spa"),
            ),
            "/spa/orders": ScriptedPage(raw_body="<div>orders</div>"),
        }
    )
    crawl = _crawl(sink, navigator)
    result = await crawl.run([BASE + "/spa"])
    js_only = {route.url for route in result.js_only_routes()}
    assert BASE + "/spa/orders" in js_only
    assert BASE + "/spa" not in js_only, "the shell names its own path in the server's HTML"
    route = next(r for r in result.js_only_routes() if r.url.endswith("/spa/orders"))
    assert route.source == "rendered-dom"
    assert route.page == BASE + "/spa"
    # It was followed: discovery is what a browser is for.
    assert any(url.path.endswith("/spa/orders") for url in map(_split, navigator.navigations))


async def test_a_history_api_route_is_reported_as_such() -> None:
    sink = MemoryAuditSink()
    navigator = ScriptedNavigator(
        pages={
            "/app": ScriptedPage(
                raw_body="<div id='app'></div>",
                history_routes=("/app/step-two",),
            ),
            "/app/step-two": ScriptedPage(raw_body="<div/>"),
        }
    )
    result = await _crawl(sink, navigator).run([BASE + "/app"])
    route = next(r for r in result.routes if r.url.endswith("/app/step-two"))
    assert route.source == "history-api"
    assert route.js_only is True


async def test_an_off_origin_link_is_not_followed() -> None:
    """The crawl stays on the origin it started on, like the M3 crawl (ADR-100.2)."""
    sink = MemoryAuditSink()
    navigator = ScriptedNavigator(
        pages={"/": ScriptedPage(raw_body="<div/>", links=("https://evil.example/x", "/next"))},
    )
    result = await _crawl(sink, navigator).run([BASE + "/"])
    assert all("evil.example" not in route.url for route in result.routes)
    assert all("evil.example" not in url for url in navigator.navigations)
    assert result.blocked_navigations == ()
    assert result.refused_requests == ()


async def test_a_destructive_path_is_recorded_but_never_walked() -> None:
    """A browser must not log the scanner out of the application it is measuring."""
    sink = MemoryAuditSink()
    navigator = ScriptedNavigator(
        pages={
            "/": ScriptedPage(raw_body="<div/>", links=("/logout", "/next")),
            "/next": ScriptedPage(raw_body="<div/>"),
        }
    )
    result = await _crawl(sink, navigator, destructive=True).run([BASE + "/"])
    assert not any(url.path == "/logout" for url in map(_split, navigator.navigations))
    assert any("destructive path" in note for note in result.notes)


# ------------------------------------------------------------------ the per-navigation gate
async def test_an_out_of_scope_navigation_is_refused_before_the_browser_opens_it() -> None:
    """Validation happens *before* the request: the navigator is never asked (REQ-DET-015)."""
    sink = MemoryAuditSink()
    navigator = ScriptedNavigator(pages={"/": ScriptedPage(raw_body="<div/>")})
    result = await _crawl(sink, navigator).run([OUT_OF_SCOPE])
    assert navigator.navigations == [], "no browser navigation may be attempted off-scope"
    assert result.blocked_navigations == (OUT_OF_SCOPE,)
    assert result.navigations == 0
    refusals = sink.of_action(AuditAction.SCOPE_REJECTED)
    assert refusals and refusals[0].outcome.value == "blocked"
    assert "browser-navigation" in str(refusals[0].meta)


async def test_an_out_of_scope_host_is_not_resolved() -> None:
    """The gate checks scope before it resolves, so a refused host is not even looked up."""
    resolver = _RecordingResolver()
    sink = MemoryAuditSink()
    navigator = ScriptedNavigator(pages={"/": ScriptedPage(raw_body="<div/>")})
    crawl = _crawl(sink, navigator, resolver=resolver, allowed_hosts=(IN_SCOPE,))
    await crawl.run(["http://not-declared.example/"])
    assert resolver.asked == [], "an out-of-scope host must not generate a DNS query"


# ------------------------------------------------------------------ DOM-sink attribution
async def test_a_marker_absent_from_the_server_response_is_a_client_side_sink() -> None:
    sink = MemoryAuditSink()
    navigator = ScriptedNavigator(
        pages={
            "/spa": ScriptedPage(
                raw_body="<div id='app'></div>",
                sink_records=(sink_record("innerHTML", value="<p>{marker}</p>"),),
            )
        }
    )
    result = await _crawl(sink, navigator).run([BASE + "/spa"])
    client_side = result.client_side_sinks()
    assert [sink.hit.sink for sink in client_side] == ["innerHTML", "innerHTML"]
    assert {sink.source for sink in client_side} == {"location.hash", "location.search"}
    assert all(sink.client_side_only is True for sink in client_side)
    assert all(sink.executed_in_browser is True for sink in client_side)
    assert client_side[0].route == BASE + "/spa"


async def test_a_marker_the_server_itself_returned_is_not_reported_as_dom_xss() -> None:
    """The reflected-XSS false positive: the same sink call, but the server sent the marker.

    A marker present in the response body could have arrived through the HTML — that is what
    ``m3.xss-oracle`` measures — so this crawl must not claim it as a DOM sink.
    """
    sink = MemoryAuditSink()
    marker_holding_body = "placeholder"

    class _Echoing(ScriptedNavigator):
        async def navigate(self, url: str):  # type: ignore[no-untyped-def]
            page = await super().navigate(url)
            planted = marker_in(url, stem=DEFAULT_STEM) or ""
            return type(page)(
                url=page.url,
                final_url=page.final_url,
                status=page.status,
                raw_body=f"<p>{planted}</p>",
                links=page.links,
                sink_records=page.sink_records,
                history_routes=page.history_routes,
            )

    navigator = _Echoing(
        pages={
            "/reflect": ScriptedPage(
                raw_body=marker_holding_body,
                sink_records=(sink_record("innerHTML", value="<p>{marker}</p>"),),
            )
        }
    )
    result = await _crawl(sink, navigator).run([BASE + "/reflect"])
    assert len(result.sinks) == 2, "the instrumentation fired for both marker sources"
    assert result.client_side_sinks() == ()
    assert all(sink.client_side_only is False for sink in result.sinks)


async def test_both_marker_sources_are_planted_where_they_say() -> None:
    """``hash`` puts the marker in the fragment (never sent) and ``search`` in the query."""
    sink = MemoryAuditSink()
    navigator = ScriptedNavigator(pages={"/page": ScriptedPage(raw_body="<div/>")})
    await _crawl(sink, navigator).run([BASE + "/page"])
    fragments = [url for url in navigator.navigations if "#" in url]
    queries = [url for url in navigator.navigations if "arachne_dom_probe=" in url]
    assert len(fragments) == 1 and len(queries) == 1
    assert len(MARKER_SOURCES) == 2
    for url in navigator.navigations:
        assert marker_in(url) is not None


async def test_the_crawl_is_deterministic_in_source_order() -> None:
    sink = MemoryAuditSink()
    navigator = ScriptedNavigator(pages={"/page": ScriptedPage(raw_body="<div/>")})
    await _crawl(sink, navigator).run([BASE + "/page"])
    assert [source for source, _ in MARKER_SOURCES] == ["hash", "search"]
    assert navigator.navigations[0].endswith("#" + navigator.navigations[0].split("#")[1])


# ------------------------------------------------------------------ hostile page content
async def test_a_page_that_tried_to_download_or_use_another_scheme_is_recorded() -> None:
    """What the page attempted is evidence, not an error: nothing was saved or navigated."""
    sink = MemoryAuditSink()
    navigator = ScriptedNavigator(
        pages={
            "/hostile": ScriptedPage(
                raw_body="<div/>",
                refused_requests=("file:///etc/passwd", "data:text/html,<script>x</script>"),
                downloads=("payload.exe",),
            )
        }
    )
    result = await _crawl(sink, navigator).run([BASE + "/hostile"])
    assert "payload.exe" in result.downloads
    assert "file:///etc/passwd" in result.refused_requests
    summary = result.summary()
    assert summary["downloads"] == 1
    assert summary["refused_requests"] == 2
    assert result.navigations == 2, "the page still rendered; the refusal is data"


async def test_a_failed_navigation_is_a_note_and_not_a_crash() -> None:
    sink = MemoryAuditSink()
    navigator = ScriptedNavigator(
        pages={"/broken": ScriptedPage(error="TimeoutError: navigation timed out")}
    )
    result = await _crawl(sink, navigator).run([BASE + "/broken"])
    assert any("timed out" in note for note in result.notes)
    assert result.sinks == ()
    assert result.routes == ()


# ------------------------------------------------------------------ the sink vocabulary
def test_parse_sink_records_bounds_what_a_page_can_put_into_evidence() -> None:
    nonce = "ar9xdeadbeef"
    records = [
        {"sink": "innerHTML", "value": f"<p>{nonce}</p>", "url": "http://x/"},
        {"sink": "not-a-sink", "value": nonce},
        {"sink": "eval", "value": 42},
        "not-a-mapping",
        {"sink": "eval", "value": "no marker here"},
        {"sink": "eval", "value": nonce},
        {"sink": "eval", "value": nonce},  # duplicate
    ]
    hits = parse_sink_records(records, nonce=nonce)
    assert [hit.sink for hit in hits] == ["innerHTML", "eval"]
    assert parse_sink_records("a string", nonce=nonce) == ()
    assert parse_sink_records(None, nonce=nonce) == ()
    assert parse_sink_records(records, nonce="") == ()

    flood = [{"sink": "innerHTML", "value": f"{nonce}-{index}"} for index in range(200)]
    assert len(parse_sink_records(flood, nonce=nonce)) == MAX_RECORDS


def test_the_marker_stem_matches_the_m3_oracle() -> None:
    """The browser and the reflection oracle must plant the same shape of marker."""
    from arachne.modules.m3.support import NONCE_STEM

    assert DEFAULT_STEM == NONCE_STEM
    assert marker_for(DEFAULT_STEM).startswith(NONCE_STEM)


def test_the_instrumentation_is_inert_and_keys_on_the_stem() -> None:
    """No ``script`` tag, no event handler, no ``javascript:`` URL — and the stem is baked in."""
    source = instrument_source("ar9x")
    assert "ar9x" in source
    assert "javascript:" not in source
    assert "onerror" not in source.lower()
    assert "new Function(" not in source
    for sink in SINK_VOCABULARY:
        assert sink.split(".")[-1] in source, sink


# ------------------------------------------------------------------ url arithmetic
def test_the_url_helpers_agree_with_the_m3_inventory() -> None:
    from arachne.modules.m3.inventory import origin_of as inventory_origin
    from arachne.modules.m3.inventory import with_params as inventory_with_params

    url = "http://example.com:8080/a/b?x=1#frag"
    assert origin_of(url) == inventory_origin(url) == "http://example.com:8080"
    # ``with_param`` drops the fragment on purpose: it plants the marker in the query, and a
    # fragment would then be a second, unplanted source. Everywhere else the two agree.
    assert with_param(url, "x", "2") == "http://example.com:8080/a/b?x=2"
    assert with_param(url, "x", "2") == strip_fragment(inventory_with_params(url, {"x": "2"}))
    assert with_param("http://example.com/a", "y", "z") == "http://example.com/a?y=z"
    assert strip_fragment(url) == "http://example.com:8080/a/b?x=1"
    assert path_and_query(url) == "/a/b?x=1"
    assert same_origin(url, "http://example.com:8080")
    assert not same_origin(url, "http://example.com:80")
    assert is_http_url(url) and not is_http_url("file:///etc/passwd")


def _split(url: str):  # type: ignore[no-untyped-def]
    from urllib.parse import urlsplit

    return urlsplit(url)
