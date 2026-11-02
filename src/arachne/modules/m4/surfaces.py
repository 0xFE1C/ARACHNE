"""M4 surface checks: API docs, debug pages, directory listings, dashboards, hidden paths,
staging environments and unsafe HTTP verbs.

These are the checks that answer "what should not have been deployed at all". They are all
path probes plus a classifier: the interesting part is never the request, it is the
distinction between a real surface and the application's own not-found or single-page
catch-all answer. Every classifier here therefore takes the learned not-found page (and, for
content discovery, the root document) into account — the two ways a path probe produces a
false positive.

``m4.webdav-verbs`` is the only check in this module that sends a non-GET verb, and it is
strictly read-only: OPTIONS, PROPFIND and TRACE. A verb that writes (PUT/DELETE/MOVE) is
reported from the ``Allow`` header, never exercised.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from urllib.parse import urlsplit

import yaml

from arachne.core.results import CheckResult
from arachne.core.target import TargetKind
from arachne.modules.base import CheckMetadata, Module
from arachne.modules.context import CheckContext
from arachne.modules.m3.inventory import Page, WebInventory, origin_of
from arachne.modules.m4.support import (
    UrlCheck,
    asset_origin,
    corpus_for,
    exchange_from_page,
    fetch_page,
    finding_cap,
    http_or_skip,
    is_catchall_page,
    listing_entries,
    looks_like_not_found,
    m4_candidate,
    not_found_for,
    owns_origin,
    path_url,
    probe_paths,
    secrets_in,
    similarity,
    skip,
    text_contains_any,
    wordlist,
)

__all__ = [
    "ApiDocExposure",
    "DashboardExposure",
    "DebugEndpoints",
    "DirectoryListing",
    "HiddenEndpointHunt",
    "StagingExposure",
    "WebdavVerbs",
]


def _pages_of(ctx: CheckContext, origin: str) -> tuple[Page, ...]:
    inventory = ctx.web
    if not isinstance(inventory, WebInventory):
        return ()
    return tuple(page for page in inventory.pages.values() if origin_of(page.url) == origin)


def _root_page(ctx: CheckContext, origin: str) -> Page | None:
    pages = _pages_of(ctx, origin)
    for page in pages:
        path = urlsplit(page.url).path or "/"
        if path == "/":
            return page
    return pages[0] if pages else None


class ApiDocExposure(UrlCheck, Module):
    """``m4.api-doc-exposure`` — Swagger/OpenAPI documents and the endpoints they map (ch04#5)."""

    metadata = CheckMetadata(
        id="m4.api-doc-exposure",
        module="M4",
        name="api-doc-exposure",
        version="1.0",
        title="API documentation exposed",
        description=(
            "Probes the conventional Swagger/OpenAPI/Redoc paths, parses a document it finds "
            "(JSON or YAML), and reports the schema plus the routes it publishes. The routes "
            "are recorded as assets and added to the shared web inventory under the "
            "'api-doc' source, so m3.api-surface replays them as part of its own endpoint "
            "coverage instead of guessing them from a wordlist."
        ),
        research_ref="ch04#5",
        framework=("WSTG-INFO-06", "API9:2023", "CWE-200"),
        cwe="CWE-200",
        target_kinds=(TargetKind.URL,),
        severity_hint="medium",
        type="hybrid",
        safe=True,
        verifiable=True,
        estimated_requests=8,
        runs_on_discovered=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        _client, skipped = http_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        if not owns_origin(ctx):
            yield skip(ctx, "another URL asset on this origin owns the M4 probes for it")
            return
        corpus = corpus_for(ctx)
        origin = asset_origin(ctx)
        not_found = await not_found_for(ctx, origin)
        paths = corpus.api_doc_paths()
        if not paths:
            yield skip(ctx, "the M4 corpus names no API-documentation paths")
            return
        document_keys = corpus.api_doc_document_keys()
        max_endpoints = corpus.api_doc_max_endpoints()
        cap = finding_cap(ctx)
        findings = 0
        for probe in await probe_paths(ctx, origin, paths, not_found=not_found):
            page = probe.page
            if page is None or page.status >= 400:
                continue
            if looks_like_not_found(page, not_found):
                continue
            document = _parse_document(page)
            if not isinstance(document, dict):
                continue
            if not any(key in document for key in document_keys):
                continue
            endpoints = _document_endpoints(document, origin)
            for endpoint in endpoints[:max_endpoints]:
                # The hand-off to m3.api-surface: the shared inventory is the channel, and
                # the asset table keeps the discovery for the rest of the run.
                inventory = ctx.web
                if isinstance(inventory, WebInventory):
                    inventory.add_endpoint(endpoint, source="api-doc")
                await ctx.record_asset("url", endpoint, source=self.metadata.id)
            findings += 1
            private = [item for item in endpoints if _looks_internal(item)]
            yield m4_candidate(
                ctx,
                f"API documentation exposed: {probe.path.lstrip('/') or '/'}",
                artifact={
                    "signal": "api-doc-exposure",
                    "family": "api-doc",
                    "path": probe.path,
                    "status": page.status,
                    "content_type": page.content_type,
                    "bytes": page.body_length,
                    "title": str(document.get("info", {}).get("title", ""))
                    if isinstance(document.get("info"), dict)
                    else "",
                    "api_version": str(document.get("openapi") or document.get("swagger") or ""),
                    "endpoint_count": len(endpoints),
                    "endpoints": endpoints[:max_endpoints],
                    "internal_endpoints": private[:10],
                    "detectors": list(secrets_in(page)),
                    "origin": origin,
                },
                exchanges=(
                    exchange_from_page(page),
                    None if not_found is None else exchange_from_page(not_found),
                ),
                confidence=0.9,
                detail=(
                    f"{probe.url} published an API schema with {len(endpoints)} route(s)"
                    + (f", {len(private)} of them internal-looking" if private else "")
                ),
                source=probe.url,
            )
            if findings >= cap:
                break
        if not findings:
            yield ctx.clean(
                "no API documentation exposed",
                detail=f"probed {len(paths)} documentation paths on {origin}",
            )


class DebugEndpoints(UrlCheck, Module):
    """``m4.debug-endpoints`` — phpinfo, server-status, Actuator and debug consoles (ch04#7)."""

    metadata = CheckMetadata(
        id="m4.debug-endpoints",
        module="M4",
        name="debug-endpoints",
        version="1.0",
        title="Debug or diagnostic endpoint reachable",
        description=(
            "Probes the fixed high-confidence debug surface: phpinfo() pages, Apache "
            "server-status/server-info, Spring Boot Actuator (including /actuator/env, "
            "/actuator/heapdump and the legacy top-level endpoints), framework debug "
            "toolbars/consoles, Prometheus /metrics and Go's /debug/vars. A hit is confirmed "
            "by the page's own markers or a stack trace; the heapdump is a hit on a binary "
            "download alone."
        ),
        research_ref="ch04#7",
        framework=("WSTG-CONF-05", "CWE-489"),
        cwe="CWE-489",
        target_kinds=(TargetKind.URL,),
        severity_hint="high",
        type="hybrid",
        safe=True,
        verifiable=True,
        estimated_requests=20,
        runs_on_discovered=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        _client, skipped = http_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        if not owns_origin(ctx):
            yield skip(ctx, "another URL asset on this origin owns the M4 probes for it")
            return
        corpus = corpus_for(ctx)
        origin = asset_origin(ctx)
        not_found = await not_found_for(ctx, origin)
        probes = corpus.debug_probes()
        if not probes:
            yield skip(ctx, "the M4 corpus names no debug surfaces")
            return
        stack_markers = corpus.debug_stack_markers()
        cap = finding_cap(ctx)
        findings = 0
        by_path = {entry.path: entry for entry in probes}
        for probe in await probe_paths(
            ctx, origin, [entry.path for entry in probes], not_found=not_found
        ):
            page = probe.page
            if page is None or page.status >= 400:
                continue
            if looks_like_not_found(page, not_found):
                continue
            definition = by_path.get(probe.path)
            family = "debug" if definition is None else definition.family
            markers = () if definition is None else definition.markers
            marker = text_contains_any(page.body, markers)
            stack_trace = text_contains_any(page.body, stack_markers)
            binary = page.body.startswith("[binary payload")
            if not (marker or stack_trace or (family == "actuator-heapdump" and binary)):
                continue
            findings += 1
            yield m4_candidate(
                ctx,
                f"Debug surface reachable: {probe.path.lstrip('/')}",
                artifact={
                    "signal": "debug-endpoint",
                    "family": family,
                    "path": probe.path,
                    "status": page.status,
                    "content_type": page.content_type,
                    "bytes": page.body_length,
                    "marker": marker,
                    "stack_trace": stack_trace,
                    "binary": binary,
                    "detectors": list(secrets_in(page)),
                    "origin": origin,
                },
                exchanges=(
                    exchange_from_page(page),
                    None if not_found is None else exchange_from_page(not_found),
                ),
                confidence=0.9 if (stack_trace or family == "actuator-env") else 0.8,
                detail=(
                    f"{probe.url} answered HTTP {page.status} with {family} content"
                    + (f" (marker: {marker!r})" if marker else "")
                ),
                source=probe.url,
            )
            if findings >= cap:
                break
        if not findings:
            yield ctx.clean(
                "no debug or diagnostic surface reachable",
                detail=f"probed {len(probes)} debug paths on {origin}",
            )


class DirectoryListing(UrlCheck, Module):
    """``m4.directory-listing`` — auto-indexed directories (ch04#9)."""

    metadata = CheckMetadata(
        id="m4.directory-listing",
        module="M4",
        name="directory-listing",
        version="1.0",
        title="Directory listing enabled",
        description=(
            "Requests candidate directories with and without the trailing slash and "
            "classifies the answer as an auto-generated index (Apache 'Index of', nginx "
            "'Directory listing for', IIS '[To Parent Directory]'). The published entries "
            "are extracted as the exposure's evidence, because a listing is a free file "
            "inventory."
        ),
        research_ref="ch04#9",
        framework=("WSTG-CONF-02", "API8:2023", "CWE-548"),
        cwe="CWE-548",
        target_kinds=(TargetKind.URL,),
        severity_hint="medium",
        type="hybrid",
        safe=True,
        verifiable=True,
        estimated_requests=10,
        runs_on_discovered=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        _client, skipped = http_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        if not owns_origin(ctx):
            yield skip(ctx, "another URL asset on this origin owns the M4 probes for it")
            return
        corpus = corpus_for(ctx)
        origin = asset_origin(ctx)
        not_found = await not_found_for(ctx, origin)
        paths = corpus.directory_paths()
        if not paths:
            yield skip(ctx, "the M4 corpus names no directory paths")
            return
        markers = corpus.directory_markers()
        max_entries = corpus.directory_max_entries()
        cap = finding_cap(ctx)
        findings = 0
        for probe in await probe_paths(ctx, origin, paths, not_found=not_found):
            page = probe.page
            if page is None or page.status >= 400:
                continue
            if looks_like_not_found(page, not_found):
                continue
            marker = text_contains_any(page.body, markers)
            if marker is None:
                continue
            entries = listing_entries(page.body, limit=max_entries)
            findings += 1
            yield m4_candidate(
                ctx,
                f"Directory listing enabled: {probe.path or '/'}",
                artifact={
                    "signal": "directory-listing",
                    "family": "directory-listing",
                    "path": probe.path or "/",
                    "status": page.status,
                    "marker": marker,
                    "entry_count": len(entries),
                    "entries": list(entries),
                    "bytes": page.body_length,
                    "origin": origin,
                },
                exchanges=(
                    exchange_from_page(page),
                    None if not_found is None else exchange_from_page(not_found),
                ),
                confidence=0.9,
                detail=(
                    f"{probe.url} published an auto-index"
                    + (f" with {len(entries)} entries" if entries else "")
                ),
                source=probe.url,
            )
            if findings >= cap:
                break
        if not findings:
            yield ctx.clean(
                "no directory listing enabled",
                detail=f"probed {len(paths)} candidate directories on {origin}",
            )


class DashboardExposure(UrlCheck, Module):
    """``m4.dashboard-exposure`` — Jenkins/Kibana/Grafana/... reachable (ch04#11)."""

    metadata = CheckMetadata(
        id="m4.dashboard-exposure",
        module="M4",
        name="dashboard-exposure",
        version="1.0",
        title="Administrative or monitoring dashboard reachable",
        description=(
            "Fingerprints the common management and observability UIs (Jenkins, Kibana, "
            "Grafana, Prometheus, Consul, phpMyAdmin, SonarQube, RabbitMQ) by path, body "
            "marker and response header, and reports each one reachable from the scanning "
            "position. It distinguishes an anonymous dashboard from one that presents a "
            "login form; the credential attempt itself belongs to m4.default-credentials."
        ),
        research_ref="ch04#11",
        framework=("WSTG-CONF-05", "CWE-284"),
        cwe="CWE-284",
        target_kinds=(TargetKind.URL,),
        severity_hint="medium",
        type="hybrid",
        safe=True,
        verifiable=True,
        estimated_requests=12,
        runs_on_discovered=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        _client, skipped = http_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        if not owns_origin(ctx):
            yield skip(ctx, "another URL asset on this origin owns the M4 probes for it")
            return
        corpus = corpus_for(ctx)
        origin = asset_origin(ctx)
        not_found = await not_found_for(ctx, origin)
        panels = corpus.dashboards()
        if not panels:
            yield skip(ctx, "the M4 corpus names no dashboard products")
            return
        header_markers = corpus.dashboard_header_markers()
        cap = finding_cap(ctx)
        findings = 0
        reported: set[str] = set()
        for panel in panels:
            if panel.product in reported:
                continue
            found = await self._probe_panel(ctx, origin, panel, not_found, header_markers)
            if found is None:
                continue
            page, path, marker, auth_challenge = found
            reported.add(panel.product)
            findings += 1
            yield m4_candidate(
                ctx,
                f"{panel.product} dashboard reachable: {path}",
                artifact={
                    "signal": "dashboard-exposure",
                    "family": "dashboard",
                    "product": panel.product,
                    "path": path,
                    "status": page.status,
                    "content_type": page.content_type,
                    "marker": marker,
                    "auth_challenge": auth_challenge,
                    "anonymous": not auth_challenge,
                    "bytes": page.body_length,
                    "detectors": list(secrets_in(page)),
                    "origin": origin,
                },
                exchanges=(
                    exchange_from_page(page),
                    None if not_found is None else exchange_from_page(not_found),
                ),
                confidence=0.85 if not auth_challenge else 0.7,
                detail=(
                    f"{path} answered HTTP {page.status} as {panel.product}"
                    + (" with a login form" if auth_challenge else " without an auth challenge")
                ),
                source=path_url(origin, path),
            )
            if findings >= cap:
                break
        if not findings:
            yield ctx.clean(
                "no management dashboard reachable",
                detail=f"fingerprinted {len(panels)} products on {origin}",
            )

    async def _probe_panel(
        self,
        ctx: CheckContext,
        origin: str,
        panel: object,
        not_found: Page | None,
        header_markers: dict[str, tuple[str, ...]],
    ) -> tuple[Page, str, str | None, bool] | None:
        from arachne.modules.m4.corpus import DashboardPanel

        assert isinstance(panel, DashboardPanel)
        header_names = header_markers.get(panel.product, ())
        for path in panel.paths:
            page = await fetch_page(ctx, path_url(origin, path))
            if page is None or page.status >= 400:
                continue
            if looks_like_not_found(page, not_found):
                continue
            header_hit = _header_marker(page, header_names)
            marker = text_contains_any(page.body, panel.markers)
            if marker is None and header_hit is None:
                continue
            auth_challenge = page.status in {401, 403} or bool(
                text_contains_any(page.body, panel.auth_markers)
            )
            return page, path, marker or header_hit, auth_challenge
        return None


class HiddenEndpointHunt(UrlCheck, Module):
    """``m4.hidden-endpoint-hunt`` — wordlist content discovery (ch04#24)."""

    metadata = CheckMetadata(
        id="m4.hidden-endpoint-hunt",
        module="M4",
        name="hidden-endpoint-hunt",
        version="1.0",
        title="Hidden endpoint or content reachable",
        description=(
            "Probes a bounded wordlist of unlinked paths (plus a few editor-artifact "
            "mutations) and reports the ones that answer differently from the application's "
            "not-found page and its single-page catch-all. Only paths that look sensitive by "
            "name or that serve a non-HTML file are reported, so the check inventories "
            "exposure rather than every route the application owns."
        ),
        research_ref="ch04#24",
        framework=("WSTG-CONF-05", "WSTG-INFO-06", "CWE-200"),
        cwe="CWE-200",
        target_kinds=(TargetKind.URL,),
        severity_hint="low",
        type="hybrid",
        safe=True,
        verifiable=False,
        estimated_requests=30,
        runs_on_discovered=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        _client, skipped = http_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        if not owns_origin(ctx):
            yield skip(ctx, "another URL asset on this origin owns the M4 probes for it")
            return
        corpus = corpus_for(ctx)
        origin = asset_origin(ctx)
        not_found = await not_found_for(ctx, origin)
        root = _root_page(ctx, origin)
        entries = wordlist(ctx, corpus.hidden_wordlist(), limit=ctx.config.m4.max_paths)
        if not entries:
            yield skip(ctx, "the M4 hidden-path wordlist is empty")
            return
        candidates = _hidden_candidates(entries, corpus.hidden_extensions())
        interest = corpus.hidden_interest_regex()
        cap = finding_cap(ctx)
        findings = 0
        reported: set[tuple[int, str]] = set()
        for probe in await probe_paths(ctx, origin, candidates, not_found=not_found):
            page = probe.page
            if page is None or page.status >= 400:
                continue
            if looks_like_not_found(page, not_found):
                continue
            if is_catchall_page(page, not_found=not_found, root=root):
                continue
            # ``/admin`` and ``/admin/`` are one handler: report one finding per
            # response, not one per spelling the wordlist carries.
            identity = (page.status, page.body_fingerprint)
            if identity in reported:
                continue
            reported.add(identity)
            interesting = bool(interest is not None and interest.search(probe.path))
            fileish = not page.content_type.lower().startswith("text/html")
            if not (interesting or fileish):
                continue
            findings += 1
            yield m4_candidate(
                ctx,
                f"Hidden endpoint reachable: {probe.path.lstrip('/')}",
                artifact={
                    "signal": "hidden-endpoint",
                    "family": "hidden-endpoint",
                    "path": probe.path,
                    "status": page.status,
                    "content_type": page.content_type,
                    "bytes": page.body_length,
                    "interesting": interesting,
                    "similarity_to_not_found": round(similarity(page, not_found), 4),
                    "similarity_to_root": round(similarity(page, root), 4),
                    "origin": origin,
                },
                exchanges=(
                    exchange_from_page(page),
                    None if not_found is None else exchange_from_page(not_found),
                ),
                confidence=0.7 if interesting else 0.55,
                detail=(
                    f"{probe.url} answered HTTP {page.status} "
                    f"({page.content_type or 'unknown type'}) where an unknown path answered "
                    f"HTTP {None if not_found is None else not_found.status}"
                ),
                source=probe.url,
            )
            if findings >= cap:
                break
        if not findings:
            yield ctx.clean(
                "no hidden endpoint found",
                detail=f"probed {len(candidates)} hidden paths on {origin}",
            )


class StagingExposure(UrlCheck, Module):
    """``m4.staging-exposure`` — dev/staging/test surfaces (ch04#25)."""

    metadata = CheckMetadata(
        id="m4.staging-exposure",
        module="M4",
        name="staging-exposure",
        version="1.0",
        title="Staging or development surface exposed",
        description=(
            "Looks for development and staging surfaces in two places: labelled paths on the "
            "declared origin (/staging/, /dev/, /test/, ...) and crawled hosts whose name "
            "carries a staging label. A path only counts when it is reachable, is not the "
            "application's not-found page, and is not the SPA shell; a labelled host is "
            "reported from the page the crawl already fetched."
        ),
        research_ref="ch04#25",
        framework=("WSTG-CONF-02", "CWE-1188"),
        cwe="CWE-1188",
        target_kinds=(TargetKind.URL,),
        severity_hint="medium",
        type="hybrid",
        safe=True,
        verifiable=False,
        estimated_requests=10,
        runs_on_discovered=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        _client, skipped = http_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        if not owns_origin(ctx):
            yield skip(ctx, "another URL asset on this origin owns the M4 probes for it")
            return
        corpus = corpus_for(ctx)
        origin = asset_origin(ctx)
        not_found = await not_found_for(ctx, origin)
        root = _root_page(ctx, origin)
        paths = corpus.staging_paths()
        markers = corpus.staging_markers()
        min_delta = corpus.staging_min_delta()
        cap = finding_cap(ctx)
        findings = 0
        for probe in await probe_paths(ctx, origin, paths, not_found=not_found):
            page = probe.page
            if page is None or page.status >= 400:
                continue
            if looks_like_not_found(page, not_found):
                continue
            if is_catchall_page(page, not_found=not_found, root=root):
                continue
            marker = text_contains_any(page.body, markers)
            delta = 1.0 - similarity(page, not_found) if not_found is not None else 1.0
            if marker is None and delta < min_delta:
                continue
            findings += 1
            yield m4_candidate(
                ctx,
                f"Staging surface exposed: {probe.path.lstrip('/') or '/'}",
                artifact={
                    "signal": "staging-exposure",
                    "family": "staging",
                    "path": probe.path,
                    "status": page.status,
                    "marker": marker,
                    "similarity_to_not_found": round(similarity(page, not_found), 4),
                    "bytes": page.body_length,
                    "origin": origin,
                },
                exchanges=(
                    exchange_from_page(page),
                    None if not_found is None else exchange_from_page(not_found),
                ),
                confidence=0.75 if marker else 0.6,
                detail=f"{probe.url} answered HTTP {page.status} and is not the not-found page",
                source=probe.url,
            )
            if findings >= cap:
                break
        # Labelled hosts the crawl already reached (a `staging.` link on a marketing page).
        for host, page in _labelled_hosts(ctx, origin, corpus.staging_labels()):
            if findings >= cap:
                break
            findings += 1
            yield m4_candidate(
                ctx,
                f"Staging host reachable: {host}",
                artifact={
                    "signal": "staging-host",
                    "family": "staging",
                    "host": host,
                    "url": page.url,
                    "status": page.status,
                    "origin": origin,
                },
                exchanges=(exchange_from_page(page),),
                confidence=0.7,
                detail=f"the crawl reached {page.url}, whose host name carries a staging label",
                source=page.url,
            )
        if not findings:
            yield ctx.clean(
                "no staging surface exposed",
                detail=f"probed {len(paths)} labelled paths on {origin}",
            )


class WebdavVerbs(UrlCheck, Module):
    """``m4.webdav-verbs`` — unsafe methods and WebDAV exposure (ch04#21)."""

    metadata = CheckMetadata(
        id="m4.webdav-verbs",
        module="M4",
        name="webdav-verbs",
        version="1.0",
        title="Unsafe HTTP methods or WebDAV enabled",
        description=(
            "Sends OPTIONS to read the advertised Allow set, PROPFIND to test WebDAV "
            "metadata access and TRACE to test cross-site tracing. A write verb (PUT, "
            "DELETE, MOVE, COPY, MKCOL) is reported from Allow and never exercised; nothing "
            "is uploaded, renamed or deleted."
        ),
        research_ref="ch04#21",
        framework=("WSTG-CONF-06", "WSTG-INPV-03", "CWE-650"),
        cwe="CWE-650",
        target_kinds=(TargetKind.URL,),
        severity_hint="medium",
        type="active",
        safe=True,
        verifiable=False,
        estimated_requests=9,
        requires_active_checks=True,
        runs_on_discovered=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        _client, skipped = http_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        if not owns_origin(ctx):
            yield skip(ctx, "another URL asset on this origin owns the M4 probes for it")
            return
        corpus = corpus_for(ctx)
        origin = asset_origin(ctx)
        write_verbs = {verb.upper() for verb in corpus.webdav_write_verbs()}
        trace_marker = corpus.webdav_trace_marker()
        targets: list[str] = []
        for path in corpus.webdav_paths() or ("/",):
            url = path_url(origin, path)
            if url not in targets:
                targets.append(url)
        for page in _pages_of(ctx, origin):
            if page.url not in targets and len(targets) < 6:
                targets.append(page.url)
        cap = finding_cap(ctx)
        findings = 0
        for endpoint in targets:
            options = await fetch_page(ctx, endpoint, method="OPTIONS")
            allow = "" if options is None else (options.header("allow") or "")
            advertised_verbs = {item.strip().upper() for item in allow.split(",")}
            advertised = sorted(verb for verb in write_verbs if verb in advertised_verbs)
            propfind = await fetch_page(ctx, endpoint, method="PROPFIND", headers={"Depth": "0"})
            dav = propfind is not None and (
                propfind.status == 207 or "multistatus" in propfind.body.lower()
            )
            trace = await fetch_page(ctx, endpoint, method="TRACE")
            trace_echo = (
                trace is not None
                and trace.status == 200
                and trace_marker.lower() in trace.body.lower()
            )
            if not (advertised or dav or trace_echo):
                continue
            findings += 1
            yield m4_candidate(
                ctx,
                f"Unsafe HTTP methods on {urlsplit(endpoint).path or '/'}"
                + (" (WebDAV)" if dav else ""),
                artifact={
                    "signal": "unsafe-verbs",
                    "family": "webdav",
                    "endpoint": endpoint,
                    "allow": allow,
                    "write_verbs": advertised,
                    "propfind_status": None if propfind is None else propfind.status,
                    "webdav": dav,
                    "trace_echo": trace_echo,
                    "safe_sent": ["OPTIONS", "PROPFIND", "TRACE"],
                },
                exchanges=(
                    None if options is None else exchange_from_page(options),
                    None if propfind is None else exchange_from_page(propfind),
                    None if trace is None else exchange_from_page(trace),
                ),
                confidence=0.85 if (dav or trace_echo) else 0.6,
                detail=(
                    f"{endpoint} advertises [{allow}]"
                    + ("; PROPFIND succeeded" if dav else "")
                    + ("; TRACE echoes the request (XST)" if trace_echo else "")
                ),
                source=endpoint,
            )
            if findings >= cap:
                break
        if not findings:
            yield ctx.clean(
                "no unsafe HTTP method observed",
                detail="OPTIONS/PROPFIND/TRACE were refused or answered without the markers",
            )


# --------------------------------------------------------------------------- helpers
def _parse_document(page: Page) -> object:
    body = page.body.lstrip()
    if body.startswith(("{", "[")):
        try:
            return json.loads(body)
        except (json.JSONDecodeError, ValueError):
            return None
    if "yaml" in page.content_type.lower() or body.startswith(("openapi:", "swagger:")):
        try:
            return yaml.safe_load(page.body)  # F-08-06: safe_load only
        except yaml.YAMLError:
            return None
    return None


def _document_endpoints(document: dict[str, object], origin: str) -> list[str]:
    paths = document.get("paths")
    if not isinstance(paths, dict):
        return []
    endpoints: list[str] = []
    for path in paths:
        if not isinstance(path, str) or not path.startswith("/"):
            continue
        endpoints.append(f"{origin}{path}")
    return list(dict.fromkeys(endpoints))


def _looks_internal(url: str) -> bool:
    path = urlsplit(url).path.lower()
    return any(
        hint in path
        for hint in ("/admin", "/internal", "/private", "/manage", "/debug", "/export", "/backup")
    )


def _header_marker(page: Page, names: tuple[str, ...]) -> str | None:
    for name in names:
        if page.header(name):
            return name
    return None


def _hidden_candidates(entries: tuple[str, ...], extensions: tuple[str, ...]) -> tuple[str, ...]:
    """The wordlist plus a few editor-artifact mutations, deduplicated and bounded."""
    candidates: list[str] = []
    seen: set[str] = set()

    def _add(value: str) -> None:
        if value not in seen:
            seen.add(value)
            candidates.append(value)

    for entry in entries:
        _add(entry)
    for entry in entries[:4]:
        for extension in extensions:
            _add(f"{entry}{extension}")
    return tuple(candidates)


def _labelled_hosts(
    ctx: CheckContext, origin: str, labels: tuple[str, ...]
) -> list[tuple[str, Page]]:
    """Crawled hosts whose name carries a staging label, in first-seen order."""
    inventory = ctx.web
    if not isinstance(inventory, WebInventory):
        return []
    found: list[tuple[str, Page]] = []
    seen: set[str] = set()
    for page in inventory.pages.values():
        host = (urlsplit(page.url).hostname or "").lower()
        if not host or host in seen:
            continue
        head = host.split(".", 1)[0]
        if head in labels or any(f".{label}." in host for label in labels):
            seen.add(host)
            found.append((host, page))
        if len(found) >= 3:
            break
    return found
