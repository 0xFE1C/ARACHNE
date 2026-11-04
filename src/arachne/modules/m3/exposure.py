"""M3 exposure checks: security headers/cookies (ch03#24) and the API surface (ch03#31).

Both are read-only: they establish what an application *advertises* (its hardening headers, its
cookie attributes, its undocumented endpoints) from responses the crawl already fetched plus a
bounded set of GET/OPTIONS probes. Neither sends a payload, so both run without the
active-checks opt-in (F-01-09 defines "active" as a non-GET interaction, fuzzing or credential
verification — a plain GET is none of those).

``m3.security-headers``
    Passive by posture: it reviews the response headers and ``Set-Cookie`` attributes of the
    pages on the asset's origin against a hardening baseline, and raises one finding per
    control class (missing headers; weak cookie flags) rather than one per page.
``m3.api-surface``
    The inventory-management check of research ch03#31: it learns the application's own
    not-found answer first, then probes a bounded hidden-path wordlist, parses any OpenAPI
    document it finds, and reads the ``Allow`` a discovered endpoint advertises. A path only
    becomes a finding when its response is *materially different* from the not-found page and
    from the application's catch-all — the two ways an inventory probe turns into noise on a
    single-page application.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Mapping, Sequence

from arachne.core.results import CheckResult
from arachne.core.target import TargetKind
from arachne.modules.base import CheckMetadata, Module
from arachne.modules.context import CheckContext
from arachne.modules.m3.inventory import Page, WebInventory, origin_of, page_from_exchange
from arachne.modules.m3.support import (
    WebCheck,
    cookie_flag_summary,
    exchange_from_page,
    http_or_skip,
    is_catchall,
    is_probably_not_found,
    nonce,
    owns_origin,
    payloads_for,
    safe_fetch,
    skip,
    text_ratio,
    web_candidate,
    web_or_skip,
    wordlist,
)

__all__ = ["ApiSurface", "SecurityHeaders"]

#: Hard cap on how many hidden endpoints one run reports (an inventory, not a crawl dump).
MAX_HIDDEN_FINDINGS = 8


def _origin_of_asset(ctx: CheckContext) -> str:
    return origin_of(ctx.asset.value)


def _pages_of_origin(inventory: WebInventory, origin: str) -> tuple[Page, ...]:
    return tuple(page for page in inventory.pages.values() if origin_of(page.url) == origin)


class SecurityHeaders(WebCheck, Module):
    """``m3.security-headers`` — response hardening and cookie-flag review (ch03#24)."""

    metadata = CheckMetadata(
        id="m3.security-headers",
        module="M3",
        name="security-headers",
        version="1.0",
        title="Security header and cookie review",
        description=(
            "Reviews the response hardening of every crawled page (Strict-Transport-Security, "
            "Content-Security-Policy with frame-ancestors, X-Frame-Options, "
            "X-Content-Type-Options, Referrer-Policy) and the attributes of every cookie the "
            "application sets (Secure, HttpOnly, SameSite), reporting the origin's missing "
            "controls. Read-only: it sends no payload and changes nothing."
        ),
        research_ref="ch03#24",
        framework=(
            "WSTG-CONF-07",
            "WSTG-CLNT-09",
            "WSTG-SESS-02",
            "API8:2023",
            "CWE-693",
        ),
        compliance=("ISO-A.8.26", "PCI-6"),
        cwe="CWE-693",
        target_kinds=(TargetKind.URL,),
        severity_hint="low",
        type="hybrid",
        safe=True,
        verifiable=False,
        estimated_requests=1,
        runs_on_discovered=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        if not owns_origin(ctx):
            yield skip(ctx, "another URL asset on this origin owns the M3 crawl for it")
            return
        inventory, skipped = web_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        assert inventory is not None
        origin = _origin_of_asset(ctx)
        pages = _pages_of_origin(inventory, origin)
        if not pages:
            yield ctx.clean(
                "no page was fetched for this origin", detail="the crawl reached no page here"
            )
            return

        protocol = "https" if origin.startswith("https://") else "http"
        expected = payloads_for(ctx).header_baseline(https=protocol == "https")
        present: dict[str, None] = {}
        for page in pages:
            for name in page.headers:
                present.setdefault(name.lower(), None)
        missing = [name for name in expected if name not in present]
        representative = _representative_page(pages, ctx.asset.value)

        if missing:
            yield web_candidate(
                ctx,
                f"Security hardening headers missing ({', '.join(missing)})",
                artifact={
                    "signal": "missing-headers",
                    "family": "security-headers",
                    "protocol": protocol,
                    "missing": missing,
                    "present": sorted(present),
                    "pages_checked": len(pages),
                    "origin": origin,
                    "server": inventory.server_banner(),
                },
                exchanges=(exchange_from_page(representative),),
                confidence=0.8,
                detail=f"missing on {origin}: {', '.join(missing)}",
            )

        session_names = payloads_for(ctx).session_cookie_names()
        cookies = tuple(
            cookie
            for page in pages
            for cookie in page.cookies
            if cookie.name.lower() in session_names or not cookie.name.lower().endswith("_prefs")
        )
        if cookies and any(cookie.missing_flags for cookie in cookies):
            summary = cookie_flag_summary(cookies)
            weak = sorted({flag for cookie in cookies for flag in cookie.missing_flags})
            yield web_candidate(
                ctx,
                f"Session cookie lacks hardening flags ({', '.join(weak)})",
                artifact={
                    "signal": "weak-cookie-flags",
                    "family": "cookies",
                    "insecure_flags": True,
                    "missing": weak,
                    "protocol": protocol,
                    "origin": origin,
                    **{k: v for k, v in summary.items() if k not in {"insecure_flags", "missing"}},
                },
                exchanges=(exchange_from_page(representative),),
                confidence=0.8,
                detail=f"cookie flags missing on {origin}: {', '.join(weak)}",
            )
        if not missing and not cookies:
            yield ctx.clean(
                "no hardening gap found",
                detail=f"{origin} carries the reviewed headers and sets no session cookie",
            )


def _representative_page(pages: Sequence[Page], asset_value: str) -> Page:
    for page in pages:
        if page.url == asset_value:
            return page
    return pages[0]


class ApiSurface(WebCheck, Module):
    """``m3.api-surface`` — hidden/undocumented endpoint discovery (ch03#31)."""

    metadata = CheckMetadata(
        id="m3.api-surface",
        module="M3",
        name="api-surface",
        version="1.0",
        title="API and hidden endpoint surface",
        description=(
            "Discovers undocumented endpoints by learning the application's own not-found "
            "response, then probing a bounded path wordlist and parsing any OpenAPI/Swagger "
            "document it finds; also reads the verbs a discovered endpoint advertises. A path "
            "only counts as a finding when its response differs from both the not-found answer "
            "and the single-page-application catch-all. GET/OPTIONS only."
        ),
        research_ref="ch03#31",
        framework=(
            "WSTG-INFO-06",
            "WSTG-INFO-07",
            "API9:2023",
            "CWE-200",
        ),
        compliance=("ISO-A.8.12", "CSF-ID.AM-02", "PCI-12"),
        cwe="CWE-200",
        target_kinds=(TargetKind.URL,),
        severity_hint="low",
        type="hybrid",
        safe=True,
        verifiable=False,
        estimated_requests=8,
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
        assert inventory is not None
        origin = _origin_of_asset(ctx)
        pages = _pages_of_origin(inventory, origin)
        root = _representative_page(pages, ctx.asset.value) if pages else None

        # 1. Learn the application's own not-found answer (one bounded request).
        marker = nonce()
        not_found_url = f"{origin}/{marker}-not-a-real-path"
        not_found_page = await self._probe(ctx, not_found_url)
        if not_found_page is None:
            yield skip(ctx, "the application did not answer the not-found probe")
            return

        payloads = payloads_for(ctx)
        entries = wordlist(
            ctx,
            payloads.string("api", "wordlist", default="wordlists/hidden-paths.txt"),
            limit=ctx.config.web.hidden_path_limit,
        )
        # S7 hand-off: an exposed OpenAPI document (m4.api-doc-exposure, ordered before this
        # check) publishes its routes into the shared inventory. Replaying them is the whole
        # point of finding the document, and it costs no wordlist guess.
        documented = [
            url
            for url, source in inventory.endpoints.items()
            if source == "api-doc" and origin_of(url) == origin
        ]
        targets: list[tuple[str, str]] = [(url, url) for url in documented]
        targets.extend((f"{origin}/{entry.lstrip('/')}", entry) for entry in entries)
        findings = 0
        reported: set[tuple[int, str]] = set()
        seen_targets: set[str] = set()
        for url, entry in targets:
            if findings >= MAX_HIDDEN_FINDINGS:
                break
            if url in seen_targets:
                continue
            seen_targets.add(url)
            page = await self._probe(ctx, url)
            if page is None:
                continue
            # ``/admin`` and ``/admin/`` are the same handler; report one finding per response,
            # not one per spelling (the wordlist deliberately carries both).
            identity = (page.status, page.body_fingerprint)
            if identity in reported:
                continue
            reported.add(identity)
            if is_probably_not_found(page, not_found_page):
                continue
            if is_catchall(page, not_found=not_found_page, root=root):
                continue
            interests = payloads.strings("api", "interest_statuses")
            if str(page.status) not in interests:
                continue
            similarity = text_ratio(page.body, not_found_page.body)
            if page.status == not_found_page.status and similarity >= 0.9:
                continue
            allow = await self._verbs(ctx, page.url)
            spec_paths = self._spec_endpoints(page, origin)
            findings += 1
            label = (
                entry
                if not entry.startswith(("http://", "https://"))
                else ("/" + page.url.split("://", 1)[-1].split("/", 1)[-1])
            )
            # Record the discovery for the modules that build on the inventory (F-01-02: the
            # scope guard decides; out-of-scope is discarded and audited).
            await ctx.record_asset("url", page.url, source=self.metadata.id)
            for spec_path in spec_paths[:10]:
                await ctx.record_asset("url", spec_path, source=self.metadata.id)
            yield web_candidate(
                ctx,
                f"Undocumented endpoint reachable: {label.rstrip('/') or '/'}",
                artifact={
                    "signal": "hidden-endpoint",
                    "family": "api-surface",
                    "path": entry,
                    "status": page.status,
                    "not_found_status": not_found_page.status,
                    "similarity_to_not_found": round(similarity, 4),
                    "content_type": page.content_type,
                    "allow": allow,
                    "spec_endpoints": spec_paths[:10],
                    "bytes": page.body_length,
                    "documented": url in documented,
                },
                exchanges=(exchange_from_page(page), exchange_from_page(not_found_page)),
                confidence=0.7 if page.status == 200 else 0.6,
                detail=(
                    f"{page.url} answered HTTP {page.status} while an unknown path answered "
                    f"HTTP {not_found_page.status}"
                ),
                source=page.url,
            )
        if not findings:
            yield ctx.clean(
                "no undocumented endpoint found",
                detail=(
                    f"probed {len(entries)} well-known paths"
                    + (f" and {len(documented)} documented route(s)" if documented else "")
                    + f" on {origin}"
                ),
            )

    # ------------------------------------------------------------------ internals
    async def _probe(self, ctx: CheckContext, url: str) -> Page | None:
        exchange = await safe_fetch(ctx, url, follow_redirects=False)
        return None if exchange is None else page_from_exchange(exchange)

    async def _verbs(self, ctx: CheckContext, url: str) -> str | None:
        """The verbs an endpoint advertises via OPTIONS (one bounded request)."""
        exchange = await safe_fetch(ctx, url, method="OPTIONS", follow_redirects=False)
        return None if exchange is None else exchange.header("allow")

    def _spec_endpoints(self, page: Page, origin: str) -> list[str]:
        """Endpoint paths from an OpenAPI/Swagger document, when the page is one."""
        content_type = page.content_type.lower()
        body = page.body.lstrip()
        if "json" not in content_type and not body.startswith("{"):
            return []
        try:
            document = json.loads(page.body)
        except (json.JSONDecodeError, ValueError):
            return []
        if not isinstance(document, Mapping):
            return []
        if not any(key in document for key in ("swagger", "openapi", "paths")):
            return []
        paths = document.get("paths")
        if not isinstance(paths, Mapping):
            return []
        return [f"{origin}{path}" for path in paths if isinstance(path, str)]
