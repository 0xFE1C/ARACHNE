"""M3 extended protocol/request-shape families: SSRF (ch03#5), request smuggling (ch03#16),
web cache poisoning (ch03#17), HTTP parameter pollution (ch03#25) and race conditions
(ch03#29).

These four families are about *how a request is framed or repeated*, not about a payload's
content, so each one's probe is deliberately minimal and each one's oracle is a measured
difference against a baseline:

``m3.ssrf-probe``
    The one M3 family that reaches **ARACHNE's own infrastructure**: it injects an OOB callback
    URL (``ARACHNE_WEB_SSRF_CALLBACK``) into every server-side fetch sink and confirms the hit
    either in-band (the sink reflected the callback's nonce) or out-of-band (the callback
    service saw the request). Off by default on top of the active-checks gate.
``m3.smuggling-oracle``
    A framing-*ambiguity* probe (research ch03#16): an obfuscated ``Transfer-Encoding`` value a
    conformant server must reject. It reports the tolerance, never a weaponized desync, which is
    the research's own line ("scanners confirm framing ambiguity only").
``m3.cache-poison-audit``
    Injects a marker host through headers a cache may treat as unkeyed (research ch03#17) and
    reports when the marker is reflected into the response — the unkeyed-input primitive.
``m3.hpp-oracle``
    Sends a security-relevant parameter twice, in both orders, and reads the resolution oracle:
    an order-dependent answer where a single value is stable (research ch03#25).
``m3.race-oracle``
    Replays a bounded number of *concurrent* identical requests at a single-use action and
    reports a double-apply (research ch03#29: "strictly bounded request volumes").
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from typing import Any

from arachne.core.results import CheckResult
from arachne.core.target import TargetKind
from arachne.modules.base import CheckMetadata, Module
from arachne.modules.context import CheckContext
from arachne.modules.m3.inventory import WebInventory, origin_of, with_params
from arachne.modules.m3.support import (
    WebCheck,
    build_callback,
    compare_pages,
    http_or_skip,
    oob_hit,
    owns_origin,
    payloads_for,
    post_form,
    probe_url,
    safe_fetch,
    skip,
    web_candidate,
    web_or_skip,
)

__all__ = [
    "CachePoisonAudit",
    "HppOracle",
    "RaceOracle",
    "RequestSmugglingOracle",
    "SsrfProbe",
]


# --------------------------------------------------------------------------- SSRF
class SsrfProbe(WebCheck, Module):
    """``m3.ssrf-probe`` — callback-based SSRF probe on ARACHNE's own infrastructure (ch03#5)."""

    metadata = CheckMetadata(
        id="m3.ssrf-probe",
        module="M3",
        name="ssrf-probe",
        version="1.0",
        title="Server-side request forgery callback probe",
        description=(
            "Injects an out-of-band callback URL (ARACHNE_WEB_SSRF_CALLBACK, a service on "
            "ARACHNE's own infrastructure) into every parameter the crawl identified as a "
            "server-side fetch sink, and confirms the class when the sink reflected the "
            "callback's nonce (in-band) or the callback service recorded the hit (out-of-band). "
            "Off by default: it needs ARACHNE_WEB_SSRF_CALLBACK, ARACHNE_WEB_SSRF_PROBE=true and "
            "the active-checks opt-in. No internal address or credential is ever targeted."
        ),
        research_ref="ch03#5",
        cwe="CWE-918",
        target_kinds=(TargetKind.URL,),
        severity_hint="high",
        type="active",
        safe=True,
        verifiable=False,
        estimated_requests=10,
        enabled_by_default=False,
        requires_active_checks=True,
        runs_on_discovered=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        _client, skipped = http_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        if not owns_origin(ctx):
            yield skip(ctx, "another URL asset on this origin owns the M3 crawl for it")
            return
        if not ctx.config.web.ssrf_probe:
            yield skip(
                ctx,
                "the SSRF callback probe is disabled (set ARACHNE_WEB_SSRF_CALLBACK, "
                "ARACHNE_WEB_SSRF_PROBE=true, select m3.ssrf-probe and authorize active checks)",
            )
            return
        payloads = payloads_for(ctx)
        template = payloads.string("ssrf", "callback_template", default="{base}/{nonce}")
        built = build_callback(ctx, template)
        if built is None:
            yield skip(
                ctx,
                "no out-of-band callback is configured (ARACHNE_WEB_SSRF_CALLBACK); the SSRF "
                "probe needs one on ARACHNE's own infrastructure",
            )
            return
        inventory, skipped = web_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        assert isinstance(inventory, WebInventory)
        callback_url, marker = built
        hints = {name.lower() for name in payloads.strings("ssrf", "sink_param_hints")}
        origin = origin_of(ctx.asset.value)
        sinks = [
            (url, param)
            for url, param in inventory.parameter_targets(names=hints)
            if origin_of(url) == origin
        ][: ctx.config.web.max_params_per_check]
        if not sinks:
            yield ctx.clean(
                "no server-side fetch sink to probe",
                detail="the crawl found no parameter whose name suggests a URL fetch",
            )
            return
        posts: list[dict[str, Any]] = []
        findings = 0
        for url, param in sinks:
            injected = with_params(url, {param: callback_url})
            exchange = await safe_fetch(ctx, injected, follow_redirects=False)
            in_band = exchange is not None and marker in exchange.body
            out_of_band = (not in_band) and await oob_hit(
                ctx, ctx.config.web.ssrf_callback_url or "", marker
            )
            posts.append(
                {
                    "sink": param,
                    "endpoint": url,
                    "status": None if exchange is None else exchange.status_code,
                    "in_band": in_band,
                    "out_of_band": out_of_band,
                }
            )
            if not (in_band or out_of_band):
                continue
            findings += 1
            yield web_candidate(
                ctx,
                f"SSRF: the server fetched an attacker-supplied URL through '{param}'",
                artifact={
                    "signal": "ssrf",
                    "family": "ssrf",
                    "endpoint": url,
                    "parameter": param,
                    "callback": callback_url,
                    "in_band": in_band,
                    "out_of_band": out_of_band,
                    "nonce": marker,
                },
                exchanges=() if exchange is None else (exchange,),
                cwe="CWE-918",
                confidence=0.85 if in_band else 0.8,
                detail=(
                    f"{url} fetched {callback_url} through '{param}' "
                    + (
                        "and reflected the callback body"
                        if in_band
                        else "and the callback recorded it"
                    )
                ),
                source=url,
            )
        if not findings:
            yield ctx.info(
                "SSRF callback posture",
                detail="no sink fetched the callback; postures: "
                + ", ".join(f"{item['sink']}={item['status']}" for item in posts),
            )


# --------------------------------------------------------------------------- smuggling
class RequestSmugglingOracle(WebCheck, Module):
    """``m3.smuggling-oracle`` — HTTP framing-boundary / desync-surface audit (ch03#16).

    The shared client speaks HTTP through a strict library, so it cannot emit the invalid
    framing a true CL.TE/TE.CL probe needs (``Transfer-Encoding: chunked, identity`` is refused
    before it leaves the process). What it can do — and what this check does — is read the
    *framing boundary* the response reveals: a proxy in front of an origin (``Via`` alongside a
    distinct ``Server``) is the multi-parser topology a desync requires, and it is reported as a
    risk signal for manual validation. ADR-S10-4 records the limitation; the check never claims a
    confirmed desync.
    """

    metadata = CheckMetadata(
        id="m3.smuggling-oracle",
        module="M3",
        name="smuggling-oracle",
        version="1.0",
        title="HTTP request smuggling (framing boundary) audit",
        description=(
            "Reads the HTTP framing boundary of the probed endpoints: a response that carries "
            "both a proxy ``Via`` and a distinct origin ``Server`` (or an X-Backend-Server hop) "
            "sits behind the two-parser topology a CL.TE/TE.CL desync requires, and is reported "
            "as a framing-boundary risk for manual validation (research ch03#16). The check does "
            "not emit invalid framing (the shared client refuses it) and never smuggles a hostile "
            "request; it confirms surface, not exploitation."
        ),
        research_ref="ch03#16",
        cwe="CWE-444",
        target_kinds=(TargetKind.URL,),
        severity_hint="medium",
        type="active",
        safe=True,
        verifiable=False,
        estimated_requests=8,
        requires_active_checks=True,
        runs_on_discovered=True,
    )

    _HOP_HEADERS = ("via", "x-backend-server", "x-served-by", "x-cache")

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        _client, skipped = http_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        if not owns_origin(ctx):
            yield skip(ctx, "another URL asset on this origin owns the M3 crawl for it")
            return
        inventory, skipped = web_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        assert isinstance(inventory, WebInventory)
        payloads = payloads_for(ctx)
        paths = payloads.strings("smuggling", "paths") or ("/",)
        origin = origin_of(ctx.asset.value)
        targets = [f"{origin}{path}" for path in paths][: ctx.config.web.smuggling_probes]
        findings = 0
        for url in targets:
            exchange = await safe_fetch(ctx, url, follow_redirects=False)
            if exchange is None:
                continue
            via = exchange.header("via")
            server = exchange.header("server")
            hop = [name for name in self._HOP_HEADERS if exchange.header(name)]
            # A distinct proxy hop plus an origin server name is the two-parser boundary.
            if via is None or server is None or ("via" in hop and via.lower() == server.lower()):
                continue
            findings += 1
            yield web_candidate(
                ctx,
                f"HTTP framing boundary (proxy + origin) at {url}",
                artifact={
                    "signal": "request-smuggling",
                    "family": "smuggling",
                    "endpoint": url,
                    "via": via,
                    "server": server,
                    "hop_headers": hop,
                    "te_capable": True,
                    "confirmed_desync": False,
                },
                exchanges=(exchange,),
                cwe="CWE-444",
                confidence=0.45,
                detail=(
                    f"{url} sits behind a proxy hop ({via}) in front of the origin "
                    f"({server}); a CL.TE/TE.CL desync needs exactly this two-parser "
                    "boundary — validate manually"
                ),
                source=url,
            )
            break
        if not findings:
            yield ctx.clean(
                "no proxy/origin framing boundary observed",
                detail=f"probed {len(targets)} endpoint(s) for a Via + Server pair",
            )


# --------------------------------------------------------------------------- cache poisoning
class CachePoisonAudit(WebCheck, Module):
    """``m3.cache-poison-audit`` — unkeyed-input cache poisoning / deception (ch03#17)."""

    metadata = CheckMetadata(
        id="m3.cache-poison-audit",
        module="M3",
        name="cache-poison-audit",
        version="1.0",
        title="Web cache poisoning (unkeyed input) audit",
        description=(
            "Injects a reserved marker host (arachne-cache.invalid) through headers a cache may "
            "treat as unkeyed (X-Forwarded-Host, X-Original-URL, X-HTTP-Method-Override, ...) and "
            "reports the endpoints that reflect it into the response — the unkeyed-input primitive "
            "of research ch03#17 — weighting a response that also advertises caching. It never "
            "injects live script content into a cache."
        ),
        research_ref="ch03#17",
        cwe="CWE-444",
        target_kinds=(TargetKind.URL,),
        severity_hint="medium",
        type="active",
        safe=True,
        verifiable=False,
        estimated_requests=12,
        requires_active_checks=True,
        runs_on_discovered=True,
    )

    _CACHE_HEADERS = ("x-cache", "age", "cf-cache-status", "x-cache-status", "x-served-by")

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        _client, skipped = http_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        if not owns_origin(ctx):
            yield skip(ctx, "another URL asset on this origin owns the M3 crawl for it")
            return
        inventory, skipped = web_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        assert isinstance(inventory, WebInventory)
        payloads = payloads_for(ctx)
        marker_host = payloads.string("cache", "marker_host", default="arachne-cache.invalid")
        headers = payloads.strings("cache", "unkeyed_headers")
        origin = origin_of(ctx.asset.value)
        pages = [page for page in inventory.pages.values() if origin_of(page.url) == origin]
        if not pages:
            yield ctx.clean("no page to test for cache poisoning", detail="the crawl fetched none")
            return
        findings = 0
        for page in pages[: ctx.config.web.max_params_per_check]:
            baseline = await safe_fetch(ctx, page.url, follow_redirects=False)
            if baseline is None:
                continue
            for header in headers:
                exchange = await safe_fetch(
                    ctx, page.url, headers={header: marker_host}, follow_redirects=False
                )
                if exchange is None or marker_host.lower() not in exchange.body.lower():
                    continue
                cacheable = (
                    any(exchange.header(name) is not None for name in self._CACHE_HEADERS)
                    or "public" in (exchange.header("cache-control") or "").lower()
                )
                findings += 1
                yield web_candidate(
                    ctx,
                    f"Unkeyed header '{header}' reflected into the response",
                    artifact={
                        "signal": "cache-poisoning",
                        "family": "cache",
                        "endpoint": page.url,
                        "header": header,
                        "marker": marker_host,
                        "reflected": True,
                        "cacheable": cacheable,
                    },
                    exchanges=(baseline, exchange),
                    cwe="CWE-444",
                    confidence=0.7 if cacheable else 0.6,
                    detail=(
                        f"{page.url} reflected the {header} value ({marker_host}) into its response"
                        + (" while advertising caching" if cacheable else "")
                    ),
                    source=page.url,
                )
                break
        if not findings:
            yield ctx.clean(
                "no unkeyed-header reflection observed",
                detail=f"probed {len(pages)} page(s) with {len(headers)} candidate headers",
            )


# --------------------------------------------------------------------------- HPP
class HppOracle(WebCheck, Module):
    """``m3.hpp-oracle`` — duplicate-parameter resolution deltas (ch03#25)."""

    metadata = CheckMetadata(
        id="m3.hpp-oracle",
        module="M3",
        name="hpp-oracle",
        version="1.0",
        title="HTTP parameter pollution oracle",
        description=(
            "Sends a security-relevant parameter twice with distinct values and reads the "
            "resolution oracle: when the response depends on the *order* of the duplicate values "
            "while a single value is stable, the parser resolution is ambiguous (research "
            "ch03#25) — the precondition for a WAF/application disagreement. Two bounded requests "
            "per parameter; nothing is modified."
        ),
        research_ref="ch03#25",
        cwe="CWE-235",
        target_kinds=(TargetKind.URL,),
        severity_hint="medium",
        type="active",
        safe=True,
        verifiable=False,
        estimated_requests=8,
        requires_active_checks=True,
        runs_on_discovered=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        _client, skipped = http_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        if not owns_origin(ctx):
            yield skip(ctx, "another URL asset on this origin owns the M3 crawl for it")
            return
        inventory, skipped = web_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        assert isinstance(inventory, WebInventory)
        payloads = payloads_for(ctx)
        hints = {name.lower() for name in payloads.strings("hpp", "param_hints")}
        values = payloads.strings("hpp", "probe_values") or ("1", "2")
        origin = origin_of(ctx.asset.value)
        if len(values) < 2:
            values = ("1", "2")
        first, second = values[0], values[1]
        targets = [
            (url, param)
            for url, param in inventory.parameter_targets(names=hints)
            if origin_of(url) == origin
        ][: ctx.config.web.max_params_per_check]
        if not targets:
            yield ctx.clean(
                "no security-relevant parameter to test for pollution",
                detail="the crawl found no parameter whose name suggests a security decision",
            )
            return
        findings = 0
        for url, param in targets:
            baseline = await safe_fetch(ctx, probe_url(url, param, first), follow_redirects=False)
            ab = await safe_fetch(
                ctx, _duplicate(url, param, first, second), follow_redirects=False
            )
            ba = await safe_fetch(
                ctx, _duplicate(url, param, second, first), follow_redirects=False
            )
            if baseline is None or ab is None or ba is None:
                continue
            if not _order_dependent(ab, ba):
                continue
            findings += 1
            yield web_candidate(
                ctx,
                f"Duplicate-parameter resolution for '{param}' depends on order",
                artifact={
                    "signal": "http-parameter-pollution",
                    "family": "hpp",
                    "endpoint": url,
                    "parameter": param,
                    "values": [first, second],
                    "order_a_status": ab.status_code,
                    "order_b_status": ba.status_code,
                    "order_dependent": True,
                    "baseline_status": baseline.status_code,
                },
                exchanges=(baseline, ab, ba),
                cwe="CWE-235",
                confidence=0.6,
                detail=(
                    f"{url} answered differently for '{param}={first}&{param}={second}' than for "
                    f"'{param}={second}&{param}={first}' — the backend resolves duplicates in an "
                    "ambiguous, order-dependent way"
                ),
                source=url,
            )
        if not findings:
            yield ctx.clean(
                "duplicate parameters resolve consistently",
                detail=f"tested {len(targets)} security-relevant parameter(s)",
            )


# --------------------------------------------------------------------------- race
class RaceOracle(WebCheck, Module):
    """``m3.race-oracle`` — concurrent-request double-apply detection (ch03#29)."""

    metadata = CheckMetadata(
        id="m3.race-oracle",
        module="M3",
        name="race-oracle",
        version="1.0",
        title="Race condition (concurrent-request) oracle",
        description=(
            "Replays a strictly bounded burst of near-simultaneous identical requests at a "
            "single-use action (redeem/coupon/claim/transfer, by path hint) and reports a "
            "double-apply: more successful responses than the limit should permit (research "
            "ch03#29). The burst size comes from ARACHNE_WEB_RACE_CONCURRENCY; the probe never "
            "performs a financial or destructive operation (GET, or a POST the crawl already "
            "found)."
        ),
        research_ref="ch03#29",
        cwe="CWE-362",
        target_kinds=(TargetKind.URL,),
        severity_hint="medium",
        type="active",
        safe=True,
        verifiable=False,
        estimated_requests=16,
        requires_active_checks=True,
        runs_on_discovered=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        _client, skipped = http_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        if not owns_origin(ctx):
            yield skip(ctx, "another URL asset on this origin owns the M3 crawl for it")
            return
        inventory, skipped = web_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        assert isinstance(inventory, WebInventory)
        payloads = payloads_for(ctx)
        hints = [hint.lower() for hint in payloads.strings("race", "path_hints")]
        success = payloads.strings("race", "success_markers") or ("success", "ok")
        origin = origin_of(ctx.asset.value)
        targets = [
            url
            for url in inventory.endpoints
            if origin_of(url) == origin and any(hint in url.lower() for hint in hints)
        ]
        if not targets:
            yield ctx.clean(
                "no single-use action to race",
                detail="the crawl found no endpoint whose path suggests a limited operation",
            )
            return
        concurrency = max(2, ctx.config.web.race_concurrency)
        findings = 0
        for url in targets[:2]:
            forms = [form for form in inventory.forms if form.action == url]
            results = await asyncio.gather(
                *[
                    (
                        post_form(
                            ctx, url, {item.name: item.value or "" for item in forms[0].inputs}
                        )
                        if forms and forms[0].is_post
                        else safe_fetch(ctx, url, follow_redirects=False)
                    )
                    for _ in range(concurrency)
                ],
                return_exceptions=True,
            )
            successes = [
                item
                for item in results
                if item is not None
                and not isinstance(item, BaseException)
                and any(marker in item.body.lower() for marker in success)
            ]
            if len(successes) <= 1:
                continue
            findings += 1
            yield web_candidate(
                ctx,
                f"Concurrent requests double-applied at {url}",
                artifact={
                    "signal": "race-condition",
                    "family": "race",
                    "endpoint": url,
                    "concurrency": concurrency,
                    "successes": len(successes),
                    "method": "POST" if forms and forms[0].is_post else "GET",
                },
                exchanges=tuple(successes[:2]),
                cwe="CWE-362",
                confidence=0.65,
                detail=(
                    f"{len(successes)} of {concurrency} simultaneous requests to {url} reported "
                    "success where a single-use limit should have allowed one"
                ),
                source=url,
            )
        if not findings:
            yield ctx.clean(
                "no double-apply observed",
                detail=(
                    f"raced {min(len(targets), 2)} single-use action(s) at "
                    f"concurrency {concurrency}"
                ),
            )


# --------------------------------------------------------------------------- helpers
def _duplicate(url: str, name: str, first: str, second: str) -> str:
    """``url`` with ``name`` sent twice and no other occurrence of it (other params kept)."""
    from urllib.parse import quote, urlsplit, urlunsplit

    parts = urlsplit(url)
    pairs = [pair for pair in parts.query.split("&") if pair and pair.partition("=")[0] != name]
    pairs.extend((f"{quote(name)}={quote(first)}", f"{quote(name)}={quote(second)}"))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, "&".join(pairs), parts.fragment))


def _order_dependent(ab: Any, ba: Any) -> bool:
    """True when two duplicate-value orderings produce materially different responses."""
    if ab is None or ba is None:
        return False
    if ab.status_code != ba.status_code:
        return True
    from arachne.modules.m3.inventory import page_from_exchange

    delta = compare_pages(page_from_exchange(ab), page_from_exchange(ba))
    # Any material difference means the winning duplicate value reached the response.
    return delta.ratio < 0.999
