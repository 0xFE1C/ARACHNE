"""M5 exposure-hardening checks over the served origin: serverless functions, managed
datastores and search platforms (research ch05#9, #20 and #21).

These are the module's "the platform is reachable and it should not be" checks. Each one is a
bounded, read-only probe of the asset's own origin, and each confirmation is a *marker the
platform itself returns*:

``m5.serverless-functions``
    An unauthenticated function endpoint — a Lambda function URL, an API Gateway stage, an
    Azure Functions app, a Cloud Functions host or a Workers subdomain — answers 200 with a
    function response instead of a 401/403 challenge (ch05#9).
``m5.managed-datastores``
    A managed database console or proxy is reachable over HTTP: adminer/phpMyAdmin/pgAdmin at
    the conventional paths, or a cloud DB host returning its metadata (ch05#20).
``m5.search-platform-exposure``
    Elasticsearch, Kibana or OpenSearch Dashboards answers anonymously (``/_cat/indices``,
    ``/_cluster/health``, ``/app/kibana``, ``/api/status``) with product JSON/HTML (ch05#21).

Every check is GET-only: no write, no credential, no account call. A 401/403 on a probe is
the *hardened* answer and is never reported .
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from urllib.parse import urlsplit

from arachne.core.results import CheckResult
from arachne.core.target import TargetKind
from arachne.modules.base import CheckMetadata, Module
from arachne.modules.context import CheckContext
from arachne.modules.m5.corpus import M5Corpus
from arachne.modules.m5.support import (
    UrlCheck,
    corpus_for,
    endpoint_base,
    fetch_page,
    finding_cap,
    http_or_skip,
    m5_candidate,
    skip,
    text_contains_any,
)

__all__ = [
    "ManagedDatastores",
    "SearchPlatformExposure",
    "ServerlessFunctions",
]

#: Hard cap on how many paths one check probes, independent of the finding cap.
_MAX_PROBES = 8


# --------------------------------------------------------------------------- serverless
class ServerlessFunctions(UrlCheck, Module):
    """``m5.serverless-functions`` — unauthenticated serverless/function endpoints (ch05#9)."""

    metadata = CheckMetadata(
        id="m5.serverless-functions",
        module="M5",
        name="serverless-functions",
        version="1.0",
        title="Unauthenticated serverless function endpoint",
        description=(
            "Probes the web origin for a reachable serverless/function endpoint: an AWS Lambda "
            "function URL, an API Gateway stage (/prod, /dev, /stage), an Azure Functions app "
            "(/api/), a GCP Cloud Functions host or a Cloudflare Workers subdomain (research "
            "ch05#9). A 200 carrying a function response and no auth challenge is the finding; "
            "a 401/403 challenge is the hardened answer. GET only; nothing is invoked."
        ),
        research_ref="ch05#9",
        framework=("WSTG-CONF-05", "API5:2023", "CWE-284"),
        cwe="CWE-284",
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
        corpus = corpus_for(ctx)
        candidates = self._candidates(ctx, corpus)
        if not candidates:
            yield skip(
                ctx,
                "no function endpoint derived: declare the function URL or an endpoint:<url> "
                "origin to join the API Gateway/function stage paths onto",
            )
            return
        markers = corpus.serverless_response_markers()
        denied = set(corpus.serverless_auth_status())
        findings = 0
        for label, url in candidates:
            page = await fetch_page(ctx, url)
            if page is None or page.status in denied:
                continue
            marker = text_contains_any(page.body, markers)
            trace = page.header("x-amzn-trace-id")
            if page.status != 200 or (marker is None and not trace):
                continue
            findings += 1
            yield m5_candidate(
                ctx,
                f"Unauthenticated function endpoint: {label}",
                artifact={
                    "signal": "serverless-unauth",
                    "family": "serverless",
                    "endpoint": url,
                    "status": page.status,
                    "marker": marker,
                    "trace_header": trace,
                    "auth_status": sorted(denied),
                },
                confidence=0.85 if marker is not None else 0.7,
                detail=(
                    f"{url} answered HTTP {page.status} with a function response and no auth "
                    "challenge, so the function is invokable anonymously"
                ),
                source=url,
            )
            if findings >= finding_cap(ctx):
                return
        if not findings:
            yield ctx.clean(
                "no unauthenticated function endpoint found",
                detail=f"probed {len(candidates)} function candidate(s)",
            )

    def _candidates(self, ctx: CheckContext, corpus: M5Corpus) -> list[tuple[str, str]]:
        base = endpoint_base(ctx) or ctx.asset.value
        host = (urlsplit(base).hostname or "").lower()
        suffixes = corpus.serverless_host_suffixes()
        out: list[tuple[str, str]] = []
        seen: set[str] = set()
        if any(suffix and suffix in host for suffix in suffixes):
            out.append((host, base))
            seen.add(base)
        for path in corpus.serverless_stage_paths():
            candidate = base.rstrip("/") + path
            if candidate not in seen:
                seen.add(candidate)
                out.append((path, candidate))
        return out[: corpus.serverless_max_candidates()]


# --------------------------------------------------------------------------- datastores
class ManagedDatastores(UrlCheck, Module):
    """``m5.managed-datastores`` — reachable managed database consoles/APIs (ch05#20)."""

    metadata = CheckMetadata(
        id="m5.managed-datastores",
        module="M5",
        name="managed-datastores",
        version="1.0",
        title="Reachable managed database console or proxy",
        description=(
            "Probes the web origin for a publicly reachable managed-database surface: an "
            "adminer/phpMyAdmin/pgAdmin console at the conventional paths, a /.well-known "
            "database indicator, or a cloud DB proxy endpoint (RDS/Aurora, Azure SQL/Postgres, "
            "MongoDB Atlas/Compass) answering with its metadata (research ch05#20). GET only."
        ),
        research_ref="ch05#20",
        framework=("WSTG-CONF-01", "CWE-668"),
        compliance=(
            "CIS-11.2",
            "CIS-3.11",
            "CIS-3.2",
            "CIS-3.3",
            "ISO-A.8.13",
            "CSF-PR.DS-01",
            "CSF-PR.DS-11",
            "PCI-3",
        ),
        cwe="CWE-668",
        target_kinds=(TargetKind.URL,),
        severity_hint="high",
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
        corpus = corpus_for(ctx)
        base = endpoint_base(ctx)
        if base is None:
            yield skip(
                ctx,
                "no datastore endpoint: declare endpoint:<url> or a URL asset to probe the "
                "database-console paths",
            )
            return
        markers = corpus.managed_datastore_console_markers()
        denied = set(corpus.managed_datastore_auth_status())
        db_markers = corpus.managed_datastore_db_markers()
        host = (urlsplit(base).hostname or "").lower()
        db_host = any(
            suffix and suffix in host for suffix in corpus.managed_datastore_db_host_suffixes()
        )
        probes: list[tuple[str, str]] = [
            (path, base.rstrip("/") + path) for path in corpus.managed_datastore_console_paths()
        ]
        if db_host:
            probes.append(("root", base if base.endswith("/") else base + "/"))
        findings = 0
        for label, url in probes[:_MAX_PROBES]:
            page = await fetch_page(ctx, url)
            if page is None or page.status in denied or page.status != 200:
                continue
            marker = text_contains_any(page.body, markers)
            if marker is None and db_host:
                marker = text_contains_any(page.body, db_markers)
            if marker is None:
                continue
            findings += 1
            yield m5_candidate(
                ctx,
                f"Managed database surface reachable at {label}",
                artifact={
                    "signal": "managed-datastore",
                    "family": "datastore",
                    "endpoint": url,
                    "path": label,
                    "status": page.status,
                    "marker": marker,
                    "db_host": db_host,
                    "auth_status": sorted(denied),
                },
                confidence=0.8,
                detail=(
                    f"{url} answered HTTP {page.status} with a database-console/proxy marker "
                    "without authentication"
                ),
                source=url,
            )
            if findings >= finding_cap(ctx):
                return
        if not findings:
            yield ctx.clean(
                "no reachable managed database console or proxy found",
                detail=f"probed {min(len(probes), _MAX_PROBES)} datastore location(s)",
            )


# --------------------------------------------------------------------------- search
class SearchPlatformExposure(UrlCheck, Module):
    """``m5.search-platform-exposure`` — anonymous Elasticsearch/Kibana/OpenSearch (ch05#21)."""

    metadata = CheckMetadata(
        id="m5.search-platform-exposure",
        module="M5",
        name="search-platform-exposure",
        version="1.0",
        title="Unauthenticated search platform exposed",
        description=(
            "Probes the web origin for an exposed Elasticsearch, Kibana or OpenSearch "
            "Dashboards instance: ``/_cat/indices`` and ``/_cluster/health`` (Elasticsearch "
            "JSON), ``/app/kibana`` and ``/api/status`` (Kibana), and the OpenSearch Dashboards "
            "equivalents (research ch05#21). A 200 carrying the product JSON/HTML is the "
            "finding; a 401/403 is the hardened answer. GET only, read-only."
        ),
        research_ref="ch05#21",
        framework=("WSTG-CONF-05", "CWE-668"),
        cwe="CWE-668",
        target_kinds=(TargetKind.URL,),
        severity_hint="high",
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
        corpus = corpus_for(ctx)
        base = endpoint_base(ctx)
        if base is None:
            yield skip(
                ctx,
                "no search endpoint: declare endpoint:<url> or a URL asset to probe the "
                "Elasticsearch/Kibana/OpenSearch paths",
            )
            return
        markers = {
            "opensearch": corpus.search_platform_opensearch_markers(),
            "kibana": corpus.search_platform_kibana_markers(),
            "elasticsearch": corpus.search_platform_elasticsearch_markers(),
        }
        denied = set(corpus.search_platform_auth_status())
        findings = 0
        for path in corpus.search_platform_paths()[:_MAX_PROBES]:
            url = base.rstrip("/") + path
            page = await fetch_page(ctx, url)
            if page is None or page.status in denied or page.status != 200:
                continue
            product: str | None = None
            marker: str | None = None
            for candidate, product_markers in markers.items():
                found = text_contains_any(page.body, product_markers)
                if found is not None:
                    product, marker = candidate, found
                    break
            if product is None:
                continue
            findings += 1
            yield m5_candidate(
                ctx,
                f"Unauthenticated {product} response at {path}",
                artifact={
                    "signal": "search-platform-exposure",
                    "family": "search",
                    "product": product,
                    "endpoint": url,
                    "path": path,
                    "status": page.status,
                    "marker": marker,
                    "auth_status": sorted(denied),
                },
                confidence=0.9 if product == "elasticsearch" else 0.8,
                detail=(f"{url} served a {product} response without authentication"),
                source=url,
            )
            if findings >= finding_cap(ctx):
                return
        if not findings:
            yield ctx.clean(
                "no unauthenticated search platform response found",
                detail=f"probed {min(len(corpus.search_platform_paths()), _MAX_PROBES)} path(s)",
            )
