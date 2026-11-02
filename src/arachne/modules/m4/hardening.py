"""M4 hardening/exposure checks the surface set does not cover (research ch04#6/#8/#12/#23/#27/#30).

Where ``surfaces.py`` handles the *deployed surfaces* (API docs, debug consoles, directory
listings, dashboards), this module handles six narrower exposures that the same
"probe-then-classify" machinery answers:

* ``m4.verbose-errors`` (ch04#6)  — a malformed path that leaks a stack trace or framework
  error page instead of the application's ordinary not-found answer.
* ``m4.actuator-exposure`` (ch04#8) — a Spring Boot Actuator endpoint answering with its own
  management JSON from the public origin.
* ``m4.datastore-surface`` (ch04#12) — an Elasticsearch/CouchDB/OpenSearch/Solr/Redis/Consul
  API reachable through the web origin, identified by the product's own response shape.
* ``m4.robots-sitemap`` (ch04#23) — ``robots.txt``/``sitemap.xml`` naming sensitive surfaces.
* ``m4.wordpress-surface`` (ch04#27) — WordPress user enumeration, XML-RPC and the REST root.
* ``m4.alias-traversal`` (ch04#30) — a misconfigured static alias allowing encoded ``..``
  traversal to a canary file.

Everything here is a GET probe (WordPress's XML-RPC marker is read from a GET's 405 answer;
**no POST body is ever sent**), classified against the application's learned not-found page so
an ordinary 404 never becomes a finding. Secrets are the HTTP client's business: the artifacts
carry detector names, never values.
"""

from __future__ import annotations

import json
import re
from collections.abc import AsyncIterator, Sequence
from urllib.parse import urlsplit

from arachne.core.results import CheckResult
from arachne.core.target import TargetKind
from arachne.modules.base import CheckMetadata, Module
from arachne.modules.context import CheckContext
from arachne.modules.m3.inventory import Page
from arachne.modules.m4.support import (
    UrlCheck,
    asset_origin,
    exchange_from_page,
    finding_cap,
    http_or_skip,
    looks_like_not_found,
    m4_candidate,
    not_found_for,
    owns_origin,
    probe_paths,
    skip,
    text_contains_any,
)

__all__ = [
    "ActuatorExposure",
    "AliasTraversal",
    "DatastoreSurface",
    "RobotsSitemap",
    "VerboseErrors",
    "WordpressSurface",
]

_OWNED_ELSEWHERE = "another URL asset on this origin owns the M4 probes for it"


# --------------------------------------------------------------------------- verbose errors
#: A leaked error page carries one of these markers. Each entry is ``(signal, tokens)`` and
#: matches only when *every* token is present (case-insensitive), so a single generic word
#: like ``Warning:`` is not enough on its own.
_VERBOSE_SIGNALS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("python-traceback", ("traceback (most recent call last)",)),
    ("java-stacktrace", ("at com.", "exception")),
    ("php-fatal-error", ("fatal error",)),
    ("php-warning", ("warning:", "on line")),
    ("aspnet-error", ("server error in",)),
    ("spring-error", ("org.springframework",)),
    ("sql-error", ("sqlstate",)),
    ("sql-mysql-error", ("you have an error in your sql syntax",)),
    ("django-error", ("django",)),
    ("laravel-error", ("laravel",)),
    ("whoops-error", ("whoops",)),
    ("dotnet-error", (".net",)),
)

#: Paths that tend to make an unprepared application render its own error. Deliberately
#: generic: a malformed percent-escape, a stray quote in a parameter, a NUL byte.
_ERROR_PROBE_PATHS: tuple[str, ...] = (
    "/%ff%fe",
    "/?id='",
    "/api/%00",
    "/api/v1/%ff",
    "/'",
)


def verbose_error_signals(body: str) -> tuple[str, ...]:
    """The error-page signals present in ``body`` (empty for an ordinary page)."""
    lowered = body.lower()
    return tuple(
        name for name, markers in _VERBOSE_SIGNALS if all(token in lowered for token in markers)
    )


class VerboseErrors(UrlCheck, Module):
    """``m4.verbose-errors`` — error pages that leak a stack trace (ch04#6)."""

    metadata = CheckMetadata(
        id="m4.verbose-errors",
        module="M4",
        name="verbose-errors",
        version="1.0",
        title="Verbose error page exposes internals",
        description=(
            "Requests malformed and error-triggering paths and inspects the response body for "
            "the signature of a leaked error page: a Python traceback, a Java stack trace, a "
            "PHP Fatal error/Warning, an ASP.NET 'Server Error in', a Spring/SQLSTATE/Django/"
            "Laravel/Whoops error. An answer that is merely the application's own not-found "
            "page is rejected by comparison, so a styled 404 is never reported."
        ),
        research_ref="ch04#6",
        framework=("WSTG-ERRH-01", "WSTG-ERRH-02", "CWE-209"),
        cwe="CWE-209",
        target_kinds=(TargetKind.URL,),
        severity_hint="low",
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
            yield skip(ctx, _OWNED_ELSEWHERE)
            return
        origin = asset_origin(ctx)
        not_found = await not_found_for(ctx, origin)
        cap = finding_cap(ctx)
        findings = 0
        pages: list[tuple[str, Page, bool]] = []
        for probe in await probe_paths(ctx, origin, _ERROR_PROBE_PATHS, not_found=not_found):
            if probe.page is not None:
                pages.append((probe.path, probe.page, False))
        if not_found is not None:
            # The learned 404 was fetched from a random nonexistent path: if *that* answer
            # leaks a trace, the leak is exactly what this check exists to find.
            pages.append((urlsplit(not_found.url).path or "/", not_found, True))
        reported: set[str] = set()
        for path, page, is_reference in pages:
            signals = verbose_error_signals(page.body)
            if not signals:
                continue
            if not is_reference and looks_like_not_found(page, not_found):
                continue
            if page.body_fingerprint in reported:
                continue
            reported.add(page.body_fingerprint)
            findings += 1
            yield m4_candidate(
                ctx,
                f"Verbose error page at {path}",
                artifact={
                    "signal": "verbose-error",
                    "family": "verbose-error",
                    "path": path,
                    "status": page.status,
                    "content_type": page.content_type,
                    "bytes": page.body_length,
                    "markers": list(signals),
                    "origin": origin,
                },
                exchanges=(
                    exchange_from_page(page),
                    None if not_found is None else exchange_from_page(not_found),
                ),
                confidence=0.85 if page.status >= 400 else 0.7,
                detail=(
                    f"{path} answered HTTP {page.status} with error-page markers "
                    f"{', '.join(signals)}"
                ),
                source=page.url,
            )
            if findings >= cap:
                break
        if not findings:
            yield ctx.clean(
                "no verbose error page observed",
                detail=f"probed {len(_ERROR_PROBE_PATHS)} error-triggering paths on {origin}",
            )


# --------------------------------------------------------------------------- actuator
_ACTUATOR_PATHS: tuple[str, ...] = (
    "/actuator",
    "/actuator/env",
    "/actuator/health",
    "/actuator/beans",
    "/actuator/mappings",
    "/actuator/configprops",
    "/actuator/heapdump",
    "/actuator/threaddump",
    "/actuator/loggers",
    "/actuator/httptrace",
    "/actuator/jolokia/list",
)


def actuator_family(path: str, page: Page) -> str | None:
    """Which Actuator endpoint ``page`` is (``None`` when it is not one)."""
    route = path.lower()
    body = page.body
    lowered = body.lower()
    if route.rstrip("/").endswith("/heapdump") and (
        body.startswith("[binary payload") or "octet-stream" in page.content_type.lower()
    ):
        return "actuator-heapdump"
    if '"_links' in body:
        return "actuator-index"
    if "activeprofiles" in lowered or "propertysources" in lowered:
        return "actuator-env"
    if route.rstrip("/").endswith("/health") and '"status"' in lowered and "up" in lowered:
        return "actuator-health"
    if "threaddump" in route and '"threadname"' in lowered:
        return "actuator-threaddump"
    if "loggers" in route and '"loggers"' in lowered:
        return "actuator-loggers"
    if "httptrace" in route and ('"traces"' in lowered or '"exchanges"' in lowered):
        return "actuator-httptrace"
    if "jolokia" in route and ('"value"' in lowered or '"request"' in lowered):
        return "actuator-jolokia"
    if "mappings" in route and '"contexts"' in lowered:
        return "actuator-mappings"
    if "configprops" in route and '"contexts"' in lowered:
        return "actuator-configprops"
    if "beans" in route and '"beans"' in lowered:
        return "actuator-beans"
    return None


class ActuatorExposure(UrlCheck, Module):
    """``m4.actuator-exposure`` — Spring Boot Actuator reachable (ch04#8)."""

    metadata = CheckMetadata(
        id="m4.actuator-exposure",
        module="M4",
        name="actuator-exposure",
        version="1.0",
        title="Spring Boot Actuator endpoint exposed",
        description=(
            "Probes the conventional Actuator paths (/actuator, /env, /health, /beans, "
            "/mappings, /configprops, /heapdump, /threaddump, /loggers, /httptrace, "
            "/jolokia/list) and flags those that answer with Actuator's own JSON "
            "('_links', activeProfiles/propertySources, a thread dump, or a heapdump binary). "
            "A reachable Actuator index is a high-confidence finding; a health probe is not "
            "enough on its own unless it exposes status detail."
        ),
        research_ref="ch04#8",
        framework=("WSTG-CONF-05", "CWE-497"),
        cwe="CWE-497",
        target_kinds=(TargetKind.URL,),
        severity_hint="high",
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
            yield skip(ctx, _OWNED_ELSEWHERE)
            return
        origin = asset_origin(ctx)
        not_found = await not_found_for(ctx, origin)
        cap = finding_cap(ctx)
        findings = 0
        for probe in await probe_paths(ctx, origin, _ACTUATOR_PATHS, not_found=not_found):
            page = probe.page
            if page is None or looks_like_not_found(page, not_found):
                continue
            family = actuator_family(probe.path, page)
            if family is None:
                continue
            findings += 1
            yield m4_candidate(
                ctx,
                f"Actuator endpoint exposed: {probe.path}",
                artifact={
                    "signal": "actuator-exposure",
                    "family": family,
                    "path": probe.path,
                    "status": page.status,
                    "content_type": page.content_type,
                    "bytes": page.body_length,
                    "origin": origin,
                },
                exchanges=(
                    exchange_from_page(page),
                    None if not_found is None else exchange_from_page(not_found),
                ),
                confidence=0.95 if family == "actuator-index" else 0.8,
                detail=f"{probe.url} answered HTTP {page.status} with {family} content",
                source=probe.url,
            )
            if findings >= cap:
                break
        if not findings:
            yield ctx.clean(
                "no Actuator endpoint exposed",
                detail=f"probed {len(_ACTUATOR_PATHS)} Actuator paths on {origin}",
            )


# --------------------------------------------------------------------------- datastores
_DATASTORE_PATHS: tuple[str, ...] = (
    "/_cat/indices",
    "/_cluster/health",
    "/_all_dbs",
    "/_plugins/_security/api/roles",
    "/solr/admin/cores",
    "/v1/agent/self",
    "/redis/info",
    "/redis-commander/",
    "/redisinsight/",
    "/ui/",
)


def datastore_signal(path: str, body: str) -> str | None:
    """Which HTTP datastore product ``body`` clearly is at ``path`` (``None`` otherwise)."""
    route = urlsplit(path).path.lower() if path.startswith("/") else path.lower()
    lowered = body.lower()
    stripped = body.strip()
    if route.startswith(("/_cat/", "/_cluster/")) and (
        "cluster_name" in lowered
        or ('"health"' in lowered and '"status"' in lowered)
        or "_shards" in lowered
        or "docs.count" in lowered
    ):
        return "elasticsearch"
    if route.startswith("/_all_dbs") and stripped.startswith("[") and '"' in stripped:
        return "couchdb"
    if "_plugins/_security" in route and (
        "opensearch" in lowered or '"roles"' in lowered or '"permissions"' in lowered
    ):
        return "opensearch"
    if route.startswith("/solr/") and "responseheader" in lowered:
        return "solr"
    if route == "/v1/agent/self" and '"config"' in lowered and '"member"' in lowered:
        return "consul"
    if route.endswith("/info") and "redis_version" in lowered:
        return "redis"
    if ("redis-commander" in route or "redisinsight" in route) and (
        "redis" in lowered and "<html" in lowered
    ):
        return "redis-ui"
    if route in {"/ui", "/ui/"} and "consul by hashicorp" in lowered:
        return "consul"
    return None


class DatastoreSurface(UrlCheck, Module):
    """``m4.datastore-surface`` — an HTTP data store reachable (ch04#12)."""

    metadata = CheckMetadata(
        id="m4.datastore-surface",
        module="M4",
        name="datastore-surface",
        version="1.0",
        title="Data-store API reachable over HTTP",
        description=(
            "Probes the well-known HTTP APIs of Elasticsearch/OpenSearch (/ _cat/indices, "
            "/_cluster/health, /_plugins/_security/...), CouchDB (/_all_dbs), Solr "
            "(/solr/admin/cores), Consul (/v1/agent/self) and Redis web UIs. A path is only "
            "reported when the body is clearly that product's own API shape (a cluster health "
            "document, a database-name array, a Solr response header), never a generic page."
        ),
        research_ref="ch04#12",
        framework=("WSTG-CONF-01", "WSTG-CONF-05", "CWE-668"),
        cwe="CWE-668",
        target_kinds=(TargetKind.URL,),
        severity_hint="high",
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
            yield skip(ctx, _OWNED_ELSEWHERE)
            return
        origin = asset_origin(ctx)
        not_found = await not_found_for(ctx, origin)
        cap = finding_cap(ctx)
        findings = 0
        reported: set[str] = set()
        for probe in await probe_paths(ctx, origin, _DATASTORE_PATHS, not_found=not_found):
            page = probe.page
            if page is None or looks_like_not_found(page, not_found):
                continue
            product = datastore_signal(probe.path, page.body)
            if product is None:
                continue
            if page.body_fingerprint in reported:
                continue
            reported.add(page.body_fingerprint)
            findings += 1
            yield m4_candidate(
                ctx,
                f"{product} reachable over HTTP: {probe.path}",
                artifact={
                    "signal": "datastore-surface",
                    "family": "datastore",
                    "product": product,
                    "path": probe.path,
                    "status": page.status,
                    "content_type": page.content_type,
                    "bytes": page.body_length,
                    "origin": origin,
                },
                exchanges=(
                    exchange_from_page(page),
                    None if not_found is None else exchange_from_page(not_found),
                ),
                confidence=0.85,
                detail=f"{probe.url} answered HTTP {page.status} as {product}",
                source=probe.url,
            )
            if findings >= cap:
                break
        if not findings:
            yield ctx.clean(
                "no HTTP data-store API reachable",
                detail=f"probed {len(_DATASTORE_PATHS)} data-store paths on {origin}",
            )


# --------------------------------------------------------------------------- robots/sitemap
_ROBOTS_PATHS: tuple[str, ...] = ("/robots.txt", "/sitemap.xml")

#: Tokens in a Disallow/Allow entry or a sitemap <loc> that name a surface worth reporting.
_SENSITIVE_PATH_HINTS: tuple[str, ...] = (
    "admin",
    "backup",
    ".git",
    "staging",
    "dev",
    "internal",
    "api/",
    "private",
    "config",
    "secret",
    "db",
    "test",
    "old",
    "tmp",
    ".sql",
    ".bak",
    ".env",
)

_LOC_RE = re.compile(r"<loc>\s*([^<]+?)\s*</loc>", re.IGNORECASE)


def robots_entries(body: str) -> tuple[str, ...]:
    """The paths named by ``Disallow:``/``Allow:`` lines of a robots.txt."""
    entries: list[str] = []
    for line in body.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        key, _, value = stripped.partition(":")
        if key.strip().lower() in {"disallow", "allow"}:
            target = value.strip()
            if target:
                entries.append(target)
    return tuple(dict.fromkeys(entries))


def sitemap_locations(body: str) -> tuple[str, ...]:
    """The URLs published by ``<loc>`` elements of a sitemap."""
    return tuple(dict.fromkeys(match.group(1) for match in _LOC_RE.finditer(body)))


def sensitive_hits(
    entries: Sequence[str], hints: Sequence[str] = _SENSITIVE_PATH_HINTS
) -> tuple[tuple[str, str], ...]:
    """``(entry, matched-hint)`` for each entry that names a sensitive surface."""
    hits: list[tuple[str, str]] = []
    for entry in entries:
        lowered = entry.lower()
        for hint in hints:
            if hint in lowered:
                hits.append((entry, hint))
                break
    return tuple(hits)


class RobotsSitemap(UrlCheck, Module):
    """``m4.robots-sitemap`` — robots.txt/sitemap.xml name sensitive surfaces (ch04#23)."""

    metadata = CheckMetadata(
        id="m4.robots-sitemap",
        module="M4",
        name="robots-sitemap",
        version="1.0",
        title="robots.txt or sitemap.xml discloses sensitive paths",
        description=(
            "Fetches /robots.txt and /sitemap.xml and reports entries that name a sensitive "
            "surface (admin, backup, .git, staging, dev, internal, api/, private, config, "
            "secret, db, test, old, tmp, .sql, .bak, .env). The offending Disallow/Allow lines "
            "and sitemap URLs are carried as evidence. A file that lists only ordinary paths "
            "is information, not a finding."
        ),
        research_ref="ch04#23",
        framework=("WSTG-INFO-03", "CWE-200"),
        cwe="CWE-200",
        target_kinds=(TargetKind.URL,),
        severity_hint="low",
        type="hybrid",
        safe=True,
        verifiable=False,
        estimated_requests=3,
        runs_on_discovered=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        _client, skipped = http_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        if not owns_origin(ctx):
            yield skip(ctx, _OWNED_ELSEWHERE)
            return
        origin = asset_origin(ctx)
        not_found = await not_found_for(ctx, origin)
        cap = finding_cap(ctx)
        findings = 0
        ordinary: list[str] = []
        for probe in await probe_paths(ctx, origin, _ROBOTS_PATHS, not_found=not_found):
            page = probe.page
            if page is None or page.status >= 400 or looks_like_not_found(page, not_found):
                continue
            if probe.path.endswith("robots.txt"):
                source = "robots.txt"
                entries = robots_entries(page.body)
            else:
                source = "sitemap.xml"
                entries = sitemap_locations(page.body)
            if not entries:
                continue
            hits = sensitive_hits(entries)
            if not hits:
                ordinary.append(source)
                continue
            findings += 1
            yield m4_candidate(
                ctx,
                f"{source} discloses sensitive paths",
                artifact={
                    "signal": "robots-sitemap",
                    "family": "robots-sitemap",
                    "source": source,
                    "path": probe.path,
                    "status": page.status,
                    "bytes": page.body_length,
                    "sensitive_entries": [entry for entry, _hint in hits],
                    "hints": sorted({hint for _entry, hint in hits}),
                    "entry_count": len(entries),
                    "origin": origin,
                },
                exchanges=(
                    exchange_from_page(page),
                    None if not_found is None else exchange_from_page(not_found),
                ),
                confidence=0.8,
                detail=(
                    f"{probe.url} names {len(hits)} sensitive path(s): "
                    + ", ".join(entry for entry, _hint in hits[:5])
                ),
                source=probe.url,
            )
            if findings >= cap:
                break
        if not findings:
            if ordinary:
                yield ctx.info(
                    "robots.txt or sitemap.xml present without sensitive entries",
                    detail=f"{origin} publishes {', '.join(ordinary)} with only ordinary paths",
                )
            else:
                yield ctx.clean(
                    "no robots.txt or sitemap.xml",
                    detail=f"neither file answered on {origin}",
                )


# --------------------------------------------------------------------------- WordPress
_WP_PATHS: tuple[str, ...] = (
    "/wp-json/",
    "/wp-json/wp/v2/users",
    "/xmlrpc.php",
    "/?author=1",
    "/wp-login.php",
)

_AUTHOR_REDIRECT_RE = re.compile(r"/author/[^/?#]+", re.IGNORECASE)


def _parse_json(body: str) -> object:
    try:
        return json.loads(body)
    except (json.JSONDecodeError, ValueError):
        return None


def wordpress_signals(path: str, page: Page) -> tuple[str, ...]:
    """The WordPress exposures ``page`` evidences at ``path`` (empty when none)."""
    route = urlsplit(path).path.rstrip("/") or "/"
    lowered = page.body.lower()
    signals: list[str] = []
    if route.endswith("/wp-json/wp/v2/users"):
        payload = _parse_json(page.body)
        if isinstance(payload, list) and any(
            isinstance(item, dict) and ("slug" in item or "name" in item) for item in payload
        ):
            signals.append("user-enumeration")
    if route.endswith("/wp-json"):
        payload = _parse_json(page.body)
        if isinstance(payload, dict) and ("namespaces" in payload or "routes" in payload):
            signals.append("rest-api-exposed")
    if route.endswith("/xmlrpc.php") and "xml-rpc server accepts post requests only" in lowered:
        signals.append("xmlrpc-enabled")
    if page.status in {301, 302, 303, 307, 308}:
        location = page.header("location") or ""
        if _AUTHOR_REDIRECT_RE.search(location):
            signals.append("author-enumeration")
    return tuple(signals)


class WordpressSurface(UrlCheck, Module):
    """``m4.wordpress-surface`` — WordPress user/XML-RPC/REST exposure (ch04#27)."""

    metadata = CheckMetadata(
        id="m4.wordpress-surface",
        module="M4",
        name="wordpress-surface",
        version="1.0",
        title="WordPress surface exposes users or XML-RPC",
        description=(
            "Probes /wp-json/, /wp-json/wp/v2/users, /xmlrpc.php, /?author=1 and /wp-login.php. "
            "It reports a REST user list (login-name enumeration), the REST root the API "
            "publishes, an author redirect that leaks a login name and an enabled XML-RPC "
            "endpoint. It sends GETs only: XML-RPC is detected from its 'accepts POST requests "
            "only' answer, never by sending a POST body."
        ),
        research_ref="ch04#27",
        framework=("WSTG-INFO-08", "WSTG-IDNT-04", "CWE-200"),
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
            yield skip(ctx, _OWNED_ELSEWHERE)
            return
        origin = asset_origin(ctx)
        not_found = await not_found_for(ctx, origin)
        cap = finding_cap(ctx)
        findings = 0
        for probe in await probe_paths(ctx, origin, _WP_PATHS, not_found=not_found):
            page = probe.page
            if page is None or looks_like_not_found(page, not_found):
                continue
            signals = wordpress_signals(probe.path, page)
            if not signals:
                continue
            findings += 1
            yield m4_candidate(
                ctx,
                f"WordPress surface exposed: {probe.path} ({', '.join(signals)})",
                artifact={
                    "signal": "wordpress-surface",
                    "family": "wordpress",
                    "path": probe.path,
                    "status": page.status,
                    "content_type": page.content_type,
                    "bytes": page.body_length,
                    "signals": list(signals),
                    "origin": origin,
                },
                exchanges=(
                    exchange_from_page(page),
                    None if not_found is None else exchange_from_page(not_found),
                ),
                confidence=0.85 if "user-enumeration" in signals else 0.75,
                detail=f"{probe.url} answered HTTP {page.status} with WordPress {signals}",
                source=probe.url,
            )
            if findings >= cap:
                break
        if not findings:
            yield ctx.clean(
                "no WordPress surface found",
                detail=f"probed {len(_WP_PATHS)} WordPress paths on {origin}",
            )


# --------------------------------------------------------------------------- alias traversal
#: Static/alias prefixes carrying encoded ``..`` traversal to the ``/etc/passwd`` canary.
_TRAVERSAL_PATHS: tuple[str, ...] = (
    "/static/..%2f..%2f..%2fetc/passwd",
    "/assets/%2e%2e/%2e%2e/etc/passwd",
    "/images/....//....//etc/passwd",
    "/download?file=../../../../etc/passwd",
    "/media/..%2f..%2f..%2fetc/passwd",
    "/css/%2e%2e%2f%2e%2e%2f%2e%2e%2fetc/passwd",
    "/js/..%2f..%2f..%2f..%2fetc/passwd",
    "/uploads/..%2f..%2f..%2fetc/passwd",
    "/files/..%2f..%2f..%2fetc/passwd",
    "/download?file=....//....//etc/passwd",
)

#: Content that proves the canary file was read rather than a look-alike page returned.
_CANARY_MARKERS: tuple[str, ...] = ("root:x:0:0:", "/bin/bash")


class AliasTraversal(UrlCheck, Module):
    """``m4.alias-traversal`` — static alias path traversal (ch04#30)."""

    metadata = CheckMetadata(
        id="m4.alias-traversal",
        module="M4",
        name="alias-traversal",
        version="1.0",
        title="Static alias allows path traversal",
        description=(
            "Probes misconfigured static/alias prefixes (/static, /assets, /images, /media, "
            "/css, /js, /files, /uploads and a file parameter) with encoded .. traversal to "
            "the /etc/passwd canary. A path is reported only when the response body reveals "
            "the canary ('root:x:0:0:' or '/bin/bash'), so an ordinary 404 or a blob that "
            "merely echoes the name is never a finding. Read-only GETs only."
        ),
        research_ref="ch04#30",
        framework=("WSTG-ATHZ-01", "CWE-22"),
        cwe="CWE-22",
        target_kinds=(TargetKind.URL,),
        severity_hint="high",
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
            yield skip(ctx, _OWNED_ELSEWHERE)
            return
        origin = asset_origin(ctx)
        not_found = await not_found_for(ctx, origin)
        cap = finding_cap(ctx)
        findings = 0
        reported: set[str] = set()
        for probe in await probe_paths(ctx, origin, _TRAVERSAL_PATHS, not_found=not_found):
            page = probe.page
            if page is None or looks_like_not_found(page, not_found):
                continue
            canary = text_contains_any(page.body, _CANARY_MARKERS)
            if canary is None:
                continue
            if page.body_fingerprint in reported:
                continue
            reported.add(page.body_fingerprint)
            findings += 1
            yield m4_candidate(
                ctx,
                f"Static alias path traversal: {probe.path}",
                artifact={
                    "signal": "alias-traversal",
                    "family": "alias-traversal",
                    "path": probe.path,
                    "status": page.status,
                    "content_type": page.content_type,
                    "bytes": page.body_length,
                    "canary": canary,
                    "origin": origin,
                },
                exchanges=(
                    exchange_from_page(page),
                    None if not_found is None else exchange_from_page(not_found),
                ),
                confidence=0.95,
                detail=f"{probe.url} returned the canary file ({canary!r})",
                source=probe.url,
            )
            if findings >= cap:
                break
        if not findings:
            yield ctx.clean(
                "no static-alias path traversal",
                detail=f"probed {len(_TRAVERSAL_PATHS)} traversal paths on {origin}",
            )
