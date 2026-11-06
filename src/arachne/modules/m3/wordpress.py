"""WP-25 · the WordPress ecosystem family (REQ-DET-018).

Twenty-six read-only L1 checks that inventory what a WordPress installation publishes to an
unauthenticated client, over four axes the requirement names:

* **configuration and file exposure** — the ``wp-config.php`` source and the backup/spill
  names beside it, the debug log, the installer and upgrade residue, the uploads/plugins/
  themes directory listings;
* **the PHP and REST API surface** — ``xmlrpc.php`` (endpoint and RSD discovery), the REST
  route index, the user routes (including the ``?rest_route=`` form that survives pretty-
  permalink blocking), the settings route and the application-password routes;
* **the authentication surface** — author-archive and user-sitemap login-name enumeration,
  self-registration, and the application-password authorization page;
* **version and cron disclosure** — ``readme.html``, ``?ver=``-carrying asset URLs, and the
  publicly reachable ``wp-cron.php`` endpoint.

**Read-only.** Every request is a ``GET``, except the single ``OPTIONS`` the cron check sends:
``OPTIONS`` is safe by HTTP semantics (RFC 9110 §9.3.7), which is what lets the check report
the cron endpoint's reachability **without** issuing the GET that would run a due job. No
check sends a body, a credential or a state-changing verb, and none stores anything.

**Mapping.** Each check cites the ``ch03`` method its evidence bears on — ``ch03#31`` (the
application/API surface inventory), ``ch03#19`` (authentication and session management) or
``ch03#35`` (anti-automation, for the cron endpoint). M3's traceability contract pins
``research_ref`` to ``ch03`` (``tests/unit/test_m3_checks.py``); the corpus's finer-grained
WordPress method is ``ch04#27``, which this family's evidence also bears on — recorded as a
deviation in the WP-25 handoff rather than cited from here.

**A version or banner match is never ``high`` on its own** (FP-3): the version disclosure
checks carry ``severity_hint="low"`` and report a *signal*, not a vulnerability. The
disclosure checks name the exposed *identifiers* and never a value — the ``wp-config`` source
check reports ``DB_NAME``/``AUTH_KEY``, not what they are set to.

**Decoys.** A stock hardened installation and a WAF-fronted one (``tests/lab/wordpress_lab.py``)
are the assigned false-positive traps: both answer ``403``/``404``/``401`` to every path this
family probes, and every signal here requires a 2xx answer carrying the installation's own
marker, so neither decoy produces a finding.
"""

from __future__ import annotations

import json
import re
from collections.abc import AsyncIterator, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, ClassVar
from urllib.parse import urlsplit

from arachne.core.results import CheckResult
from arachne.core.target import TargetKind
from arachne.modules.base import CheckMetadata, Module
from arachne.modules.context import CheckContext
from arachne.modules.m3.inventory import Page, WebInventory, origin_of, page_from_exchange
from arachne.modules.m3.support import (
    WebCheck,
    exchange_from_page,
    http_or_skip,
    nonce,
    owns_origin,
    payloads_for,
    safe_fetch,
    skip,
    text_ratio,
    web_candidate,
)

__all__ = [
    "AdminAjaxSurface",
    "AppPasswordSurface",
    "AssetVersionDisclosure",
    "AuthorArchiveEnumeration",
    "CronSurface",
    "DebugLogExposure",
    "InstallerResidue",
    "PluginReadmeEnumeration",
    "PluginsListing",
    "ReadmeVersionDisclosure",
    "RegistrationOpen",
    "RestApiIndex",
    "RestAppPasswords",
    "RestRouteParam",
    "RestSettingsUnauth",
    "RestUserRecord",
    "RestUserRoute",
    "ThemeStylesheetEnumeration",
    "ThemesListing",
    "UpgradeResidue",
    "UploadsListing",
    "UserSitemapEnumeration",
    "WPConfigBackup",
    "WPConfigSourceDisclosure",
    "WordPressChecks",
    "XmlrpcRsd",
    "XmlrpcSurface",
]

#: The family tag every artifact carries, so one heuristic rule can cover the whole set.
FAMILY = "wordpress"

#: How many bytes of a probe response the directory-listing signature reads.
_LISTING_SCAN_LIMIT = 6000


# --------------------------------------------------------------------------- plumbing
@dataclass(frozen=True, slots=True)
class _Hit:
    """One confirmed signal: what it is, the facts behind it, and how much to trust it."""

    signal: str
    facts: Mapping[str, Any] = field(default_factory=dict)
    confidence: float = 0.75


def _paths(ctx: CheckContext, key: str, default: Sequence[str] = ()) -> tuple[str, ...]:
    """A WordPress path inventory from the payload corpus, else the check's own default."""
    configured = payloads_for(ctx).strings("wordpress", key)
    return configured or tuple(default)


def _wordpress_markers(ctx: CheckContext, key: str) -> tuple[str, ...]:
    """A lowercase marker list from the WordPress section of the payload corpus."""
    return tuple(marker.lower() for marker in payloads_for(ctx).strings("wordpress", key))


def _full_url(origin: str, path: str) -> str:
    """Join ``origin`` and a WordPress path without doubling or dropping the separator."""
    if path.startswith(("http://", "https://")):
        return path
    return origin.rstrip("/") + "/" + path.lstrip("/")


def _contains_any(body: str, markers: Sequence[str]) -> str | None:
    """The first marker present in ``body`` (case-insensitive), or ``None``."""
    lowered = body.lower()
    for marker in markers:
        if marker and marker in lowered:
            return marker
    return None


def _json_of(page: Page) -> Any:
    """The page body parsed as JSON, or ``None`` when it is not JSON."""
    try:
        return json.loads(page.body)
    except (json.JSONDecodeError, ValueError):
        return None


def _listing_entries(body: str, *, limit: int = 12) -> tuple[str, ...]:
    """The href targets a directory index publishes (bounded, deduplicated, path-safe)."""
    found: dict[str, None] = {}
    for match in re.finditer(r'href="([^"?#]+)"', body[:_LISTING_SCAN_LIMIT]):
        entry = match.group(1).strip()
        if not entry or entry.startswith(("http://", "https://", "../", "/")):
            continue
        found.setdefault(entry, None)
        if len(found) >= limit:
            break
    return tuple(found)


def _is_listing(page: Page, markers: Sequence[str]) -> bool:
    """True when the body is the web server's own directory index rendering."""
    return _contains_any(page.body, markers) is not None and 'href="' in page.body


class _WordPressProbe:
    """The shared shape of the family: bounded path probes on the asset's origin.

    A concrete check is declared ``class X(_WordPressProbe, WebCheck, Module)`` and sets its
    ``metadata`` plus the class attributes below. It declares the payload key that carries
    its path inventory, an optional default inventory, the HTTP method (always safe: GET, or
    OPTIONS for the cron reachability probe), and a :meth:`signal` that turns one response
    into a :class:`_Hit` or ``None``. Every request goes through the shared scoped client
    (ADR-05); a response the server refuses, blocks or answers with its own not-found
    rendering is skipped, so a check only fires on a *distinct, successful* answer carrying
    the installation's own marker.

    This is a plain mixin rather than a :class:`~arachne.modules.base.Module` subclass: the
    base refuses to be created without metadata, and a family base has none of its own.
    """

    #: Declared here so the shared ``run`` can read it; every concrete check supplies it.
    metadata: ClassVar[CheckMetadata]

    #: The ``wordpress:`` key holding this check's path list in the payload corpus.
    paths_key: ClassVar[str] = ""
    #: Fallback paths when the corpus key is absent (an operator-supplied corpus).
    default_paths: ClassVar[tuple[str, ...]] = ()
    #: The safe request method: GET everywhere, OPTIONS for the cron reachability probe.
    method: ClassVar[str] = "GET"
    #: Non-2xx statuses this check still evaluates: WordPress's XML-RPC endpoint answers a
    #: GET with ``405`` and its "accepts POST requests only" notice, and a web server that
    #: owns ``OPTIONS`` answers ``405`` with the verbs it allows. Every other 4xx/5xx is a
    #: refusal, a block or a missing path, and is what the decoys return.
    ok_statuses: ClassVar[tuple[int, ...]] = ()
    #: How many findings one run reports (one root cause, bounded output).
    max_findings: ClassVar[int] = 4
    #: The candidate title; ``{path}`` is the probed path.
    finding_title: ClassVar[str] = "WordPress surface exposed ({path})"

    def paths(self, ctx: CheckContext) -> tuple[str, ...]:
        return _paths(ctx, self.paths_key, self.default_paths)

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        """The signal this response carries, or ``None`` when it carries none."""
        raise NotImplementedError

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        _client, skipped = http_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        if not owns_origin(ctx):
            yield skip(ctx, "another URL asset on this origin owns the M3 crawl for it")
            return
        origin = origin_of(ctx.asset.value)
        paths = self.paths(ctx)
        if not paths:
            yield ctx.clean(
                "no WordPress path inventory configured",
                detail="the payload corpus names no probe path for this check",
            )
            return
        not_found = await _not_found(ctx, origin)
        findings = 0
        refused = 0
        for path in paths:
            if findings >= self.max_findings:
                break
            url = _full_url(origin, path)
            page = await _fetch(ctx, url, method=self.method)
            if page is None:
                continue
            if page.status >= 400 and page.status not in self.ok_statuses:
                refused += 1
                continue
            if _looks_like_not_found(page, not_found):
                continue
            hit = self.signal(path, page, ctx)
            if hit is None:
                continue
            findings += 1
            yield web_candidate(
                ctx,
                self.finding_title.format(path=path),
                artifact={
                    "signal": hit.signal,
                    "family": FAMILY,
                    "check": self.metadata.name,
                    "path": path,
                    "status": page.status,
                    "content_type": page.content_type,
                    "bytes": page.body_length,
                    "origin": origin,
                    "secret_kinds": list(page.secret_kinds),
                    **dict(hit.facts),
                },
                exchanges=(exchange_from_page(page),),
                confidence=hit.confidence,
                detail=f"{url} answered HTTP {page.status} with a {hit.signal} signal",
                source=url,
            )
        if not findings:
            yield ctx.clean(
                f"no {self.metadata.name.replace('-', ' ')} exposure found",
                detail=(
                    f"probed {len(paths)} WordPress path(s) on {origin}"
                    + (f"; {refused} refused or blocked" if refused else "")
                ),
            )


async def _fetch(
    ctx: CheckContext,
    url: str,
    *,
    method: str = "GET",
    follow_redirects: bool = False,
) -> Page | None:
    """One bounded probe as a :class:`Page` (``None`` when refused or failed)."""
    exchange = await safe_fetch(ctx, url, method=method, follow_redirects=follow_redirects)
    return None if exchange is None else page_from_exchange(exchange)


async def _not_found(ctx: CheckContext, origin: str) -> Page | None:
    """The installation's own not-found answer for ``origin``, learned once per step.

    A stock WordPress behind a rewrite rule answers an unknown path with the site's themed
    404 page, which is a *successful-looking* rendering; learning it first is what keeps a
    themed 404 from being read as a discovered endpoint.
    """
    inventory = ctx.web
    if isinstance(inventory, WebInventory):
        cached = inventory.not_found_by_origin.get(origin)
        if cached is not None:
            return cached
        if inventory.not_found is not None and origin_of(inventory.not_found.url) == origin:
            inventory.not_found_by_origin[origin] = inventory.not_found
            return inventory.not_found
    page = await _fetch(ctx, _full_url(origin, f"{nonce()}-not-a-real-path"))
    if page is not None and isinstance(inventory, WebInventory):
        inventory.not_found_by_origin[origin] = page
    return page


def _looks_like_not_found(page: Page, reference: Page | None) -> bool:
    """True when ``page`` is the installation's own not-found rendering (status + body)."""
    if reference is None:
        return False
    if page.status != reference.status:
        return False
    return text_ratio(page.body, reference.body) >= 0.9


def _user_records(value: Any) -> list[Mapping[str, Any]]:
    """The user objects in a REST user response (empty when the shape is not one)."""
    if isinstance(value, Mapping):
        candidates = [value]
    elif isinstance(value, list):
        candidates = [item for item in value if isinstance(item, Mapping)]
    else:
        return []
    return [item for item in candidates if "slug" in item or "name" in item]


# --------------------------------------------------------------------------- ch03#31 surface
class WPConfigBackup(_WordPressProbe, WebCheck, Module):
    """``m3.wp-config-backup`` — a wp-config backup/spill file is served (ch03#31, CWE-530)."""

    metadata = CheckMetadata(
        id="m3.wp-config-backup",
        module="M3",
        name="wp-config-backup",
        version="1.0",
        title="WordPress configuration backup file exposed",
        description=(
            "Probes the backup and editor-spill names WordPress deployments leave beside "
            "wp-config.php (.bak, ~, .save, .old, .orig, .txt) and reports one that is served "
            "as configuration source. The finding names the configuration identifiers the "
            "file declares (DB_NAME, AUTH_KEY, $table_prefix), never a value. Read-only GET "
            "probes."
        ),
        research_ref="ch03#31",
        framework=("WSTG-CONF-04", "WSTG-CONF-03", "ATT&CK-T1592.002", "CWE-530"),
        compliance=("ISO-A.8.12", "CSF-ID.AM-02"),
        cwe="CWE-530",
        target_kinds=(TargetKind.URL,),
        severity_hint="medium",
        type="hybrid",
        safe=True,
        verifiable=False,
        estimated_requests=10,
        runs_on_discovered=True,
    )

    paths_key = "config_backup_paths"
    finding_title = "WordPress configuration backup readable ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        markers = _wordpress_markers(ctx, "config_markers")
        decl = _contains_any(page.body, markers)
        if decl is None or "<?php" not in page.body:
            return None
        return _Hit(
            "wp-config-backup-readable",
            {
                "declares": [name for name in markers if name.lower() in page.body.lower()],
                "configuration_source": True,
            },
            confidence=0.85,
        )


class WPConfigSourceDisclosure(_WordPressProbe, WebCheck, Module):
    """``m3.wp-config-source`` — wp-config.php served as source (ch03#31, CWE-540)."""

    metadata = CheckMetadata(
        id="m3.wp-config-source",
        module="M3",
        name="wp-config-source",
        version="1.0",
        title="WordPress configuration served as source",
        description=(
            "Reports when /wp-config.php (or a .txt copy of it) answers with the PHP source "
            "of the configuration instead of executing it: the response carries the PHP open "
            "tag and the configuration's own define() calls. A correctly served "
            "wp-config.php outputs nothing, so the marker is the source itself. Read-only GET."
        ),
        research_ref="ch03#31",
        framework=("WSTG-CONF-03", "WSTG-CONF-04", "ATT&CK-T1552", "CWE-540"),
        cwe="CWE-540",
        target_kinds=(TargetKind.URL,),
        severity_hint="medium",
        type="hybrid",
        safe=True,
        verifiable=False,
        estimated_requests=3,
        runs_on_discovered=True,
    )

    paths_key = "config_source_paths"
    finding_title = "WordPress configuration source disclosed ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        source_markers = _wordpress_markers(ctx, "source_markers")
        if _contains_any(page.body, source_markers) is None:
            return None
        markers = _wordpress_markers(ctx, "config_markers")
        decl = _contains_any(page.body, markers)
        if decl is None:
            return None
        return _Hit(
            "php-source-disclosed",
            {"declares": [name for name in markers if name.lower() in page.body.lower()]},
            confidence=0.85,
        )


class XmlrpcSurface(_WordPressProbe, WebCheck, Module):
    """``m3.wp-xmlrpc-surface`` — the XML-RPC endpoint is served (ch03#31, CWE-200)."""

    metadata = CheckMetadata(
        id="m3.wp-xmlrpc-surface",
        module="M3",
        name="wp-xmlrpc-surface",
        version="1.0",
        title="WordPress XML-RPC endpoint published",
        description=(
            "Reports when /xmlrpc.php answers a GET with WordPress's own 'XML-RPC server "
            "accepts POST requests only' notice, i.e. the endpoint is served rather than "
            "blocked. The notice is the endpoint's own advertisement, which is why the check "
            "never sends the POST body that would invoke a method. Read-only GET probe."
        ),
        research_ref="ch03#31",
        framework=("WSTG-INFO-06", "WSTG-CONF-05", "ATT&CK-T1592.002", "CWE-200"),
        cwe="CWE-200",
        target_kinds=(TargetKind.URL,),
        severity_hint="low",
        type="hybrid",
        safe=True,
        verifiable=False,
        estimated_requests=2,
        runs_on_discovered=True,
    )

    paths_key = "xmlrpc_paths"
    default_paths = ("/xmlrpc.php",)
    # WordPress answers a GET to the endpoint with 405 and its own notice; that is the
    # detection, not a refusal.
    ok_statuses = (405,)
    finding_title = "WordPress XML-RPC endpoint served ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        marker = payloads_for(ctx).string(
            "wordpress", "xmlrpc_marker", default="XML-RPC server accepts POST requests only."
        )
        if marker.lower() not in page.body.lower():
            return None
        return _Hit("xmlrpc-endpoint-published", {"marker": marker}, confidence=0.8)


class XmlrpcRsd(_WordPressProbe, WebCheck, Module):
    """``m3.wp-xmlrpc-rsd`` — the RSD discovery document names the endpoint (ch03#31)."""

    metadata = CheckMetadata(
        id="m3.wp-xmlrpc-rsd",
        module="M3",
        name="wp-xmlrpc-rsd",
        version="1.0",
        title="WordPress RSD discovery document served",
        description=(
            "Requests /xmlrpc.php?rsd and reports the Really Simple Discovery document, which "
            "publishes the blog's API endpoint and name to any client. The finding is the "
            "discovery document itself, not the endpoint. Read-only GET probe."
        ),
        research_ref="ch03#31",
        framework=("WSTG-INFO-06", "ATT&CK-T1592.002", "CWE-200"),
        cwe="CWE-200",
        target_kinds=(TargetKind.URL,),
        severity_hint="low",
        type="hybrid",
        safe=True,
        verifiable=False,
        estimated_requests=2,
        runs_on_discovered=True,
    )

    paths_key = "xmlrpc_rsd_path"
    finding_title = "WordPress RSD discovery document served ({path})"

    def paths(self, ctx: CheckContext) -> tuple[str, ...]:
        configured = payloads_for(ctx).string("wordpress", "xmlrpc_rsd_path")
        return (configured,) if configured else ("/xmlrpc.php?rsd",)

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        if _contains_any(page.body, ("<rsd", "api name=")) is None:
            return None
        return _Hit("rsd-discovery-served", {"content_type": page.content_type}, confidence=0.75)


class RestApiIndex(_WordPressProbe, WebCheck, Module):
    """``m3.wp-rest-index`` — the REST route index is published (ch03#31, CWE-200)."""

    metadata = CheckMetadata(
        id="m3.wp-rest-index",
        module="M3",
        name="wp-rest-index",
        version="1.0",
        title="WordPress REST API index published",
        description=(
            "Reports when /wp-json/ answers an anonymous GET with the REST route index: the "
            "namespaces and route list the installation exposes. A hardened installation "
            "that disables the REST API for unauthenticated callers answers 401 instead. "
            "Read-only GET probe."
        ),
        research_ref="ch03#31",
        framework=("WSTG-INFO-06", "WSTG-INFO-07", "API9:2023", "CWE-200"),
        cwe="CWE-200",
        target_kinds=(TargetKind.URL,),
        severity_hint="low",
        type="hybrid",
        safe=True,
        verifiable=False,
        estimated_requests=2,
        runs_on_discovered=True,
    )

    paths_key = "rest_index_paths"
    default_paths = ("/wp-json/",)
    finding_title = "WordPress REST API index served ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        document = _json_of(page)
        if not isinstance(document, Mapping):
            return None
        if _contains_any(page.body, _wordpress_markers(ctx, "rest_index_markers")) is None:
            return None
        namespaces = document.get("namespaces")
        return _Hit(
            "rest-index-published",
            {
                "namespaces": [str(item) for item in namespaces][:12]
                if isinstance(namespaces, list)
                else [],
            },
            confidence=0.75,
        )


class RestUserRoute(_WordPressProbe, WebCheck, Module):
    """``m3.wp-rest-users`` — the REST user list enumerates login names (ch03#19, CWE-200)."""

    metadata = CheckMetadata(
        id="m3.wp-rest-users",
        module="M3",
        name="wp-rest-users",
        version="1.0",
        title="WordPress REST user route enumerates accounts",
        description=(
            "Reports when the REST user collection answers an anonymous GET with one or more "
            "user objects carrying a slug (the login name). Probes both the pretty-permalink "
            "route and its ?rest_route= form. Read-only GET probes."
        ),
        research_ref="ch03#19",
        framework=("WSTG-IDNT-04", "WSTG-CONF-05", "API9:2023", "CWE-200"),
        cwe="CWE-200",
        target_kinds=(TargetKind.URL,),
        severity_hint="medium",
        type="hybrid",
        safe=True,
        verifiable=False,
        estimated_requests=3,
        runs_on_discovered=True,
    )

    paths_key = "rest_users_paths"
    finding_title = "WordPress REST user list enumerable ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        records = _user_records(_json_of(page))
        if not records:
            return None
        return _Hit(
            "rest-user-enumeration",
            {
                "users": len(records),
                "slugs": [str(item.get("slug", "")) for item in records[:10]],
            },
            confidence=0.85,
        )


class RestUserRecord(_WordPressProbe, WebCheck, Module):
    """``m3.wp-rest-user-record`` — a single REST user record is readable (ch03#19)."""

    metadata = CheckMetadata(
        id="m3.wp-rest-user-record",
        module="M3",
        name="wp-rest-user-record",
        version="1.0",
        title="WordPress REST single-user record readable",
        description=(
            "Reports when /wp-json/wp/v2/users/<id> answers an anonymous GET with a user "
            "object: the record names the account's login slug and display name. Read-only "
            "GET probe."
        ),
        research_ref="ch03#19",
        framework=("WSTG-IDNT-04", "API9:2023", "CWE-200"),
        cwe="CWE-200",
        target_kinds=(TargetKind.URL,),
        severity_hint="medium",
        type="hybrid",
        safe=True,
        verifiable=False,
        estimated_requests=2,
        runs_on_discovered=True,
    )

    paths_key = "rest_user_paths"
    default_paths = ("/wp-json/wp/v2/users/1",)
    finding_title = "WordPress REST user record readable ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        records = _user_records(_json_of(page))
        if not records:
            return None
        record = records[0]
        return _Hit(
            "rest-user-record",
            {"slug": str(record.get("slug", "")), "account_id": record.get("id")},
            confidence=0.8,
        )


class RestRouteParam(_WordPressProbe, WebCheck, Module):
    """``m3.wp-rest-route-param`` — the same user route via ?rest_route= (ch03#19)."""

    metadata = CheckMetadata(
        id="m3.wp-rest-route-param",
        module="M3",
        name="wp-rest-route-param",
        version="1.0",
        title="WordPress REST user route reachable via rest_route",
        description=(
            "Reports when the REST user collection is reachable through the ?rest_route= "
            "query form. A deployment that blocks the route with a pretty-permalink rewrite "
            "rule leaves this form answering, which is why it is probed separately. Read-only "
            "GET probe."
        ),
        research_ref="ch03#19",
        framework=("WSTG-IDNT-04", "WSTG-INFO-06", "API9:2023", "CWE-200"),
        cwe="CWE-200",
        target_kinds=(TargetKind.URL,),
        severity_hint="medium",
        type="hybrid",
        safe=True,
        verifiable=False,
        estimated_requests=2,
        runs_on_discovered=True,
    )

    paths_key = "rest_route_param_paths"
    default_paths = ("/?rest_route=/wp/v2/users",)
    finding_title = "WordPress REST user route reachable via rest_route ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        if "rest_route" not in path:
            return None
        records = _user_records(_json_of(page))
        if not records:
            return None
        return _Hit(
            "rest-route-param-enumeration",
            {"users": len(records), "slugs": [str(item.get("slug", "")) for item in records[:10]]},
            confidence=0.8,
        )


class RestSettingsUnauth(_WordPressProbe, WebCheck, Module):
    """``m3.wp-rest-settings-unauth`` — the REST settings route answers anonymous (CWE-862)."""

    metadata = CheckMetadata(
        id="m3.wp-rest-settings-unauth",
        module="M3",
        name="wp-rest-settings-unauth",
        version="1.0",
        title="WordPress REST settings route readable without authorization",
        description=(
            "Reports when /wp-json/wp/v2/settings answers an anonymous GET with the "
            "installation's settings document. The route requires an administrator context: "
            "a 401/403 is the correct answer and is reported clean. Read-only GET probe."
        ),
        research_ref="ch03#31",
        framework=("WSTG-ATHZ-02", "WSTG-CONF-02", "API5:2023", "CWE-862"),
        cwe="CWE-862",
        target_kinds=(TargetKind.URL,),
        severity_hint="medium",
        type="hybrid",
        safe=True,
        verifiable=False,
        estimated_requests=2,
        runs_on_discovered=True,
    )

    paths_key = "rest_settings_paths"
    default_paths = ("/wp-json/wp/v2/settings",)
    finding_title = "WordPress REST settings readable anonymously ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        document = _json_of(page)
        if not isinstance(document, Mapping):
            return None
        keys = [key for key in _wordpress_markers(ctx, "rest_settings_keys") if key in document]
        if len(keys) < 2:
            return None
        return _Hit("unauthenticated-rest-settings", {"settings_keys": keys}, confidence=0.8)


class UploadsListing(_WordPressProbe, WebCheck, Module):
    """``m3.wp-uploads-listing`` — the uploads directory is indexed (ch03#31, CWE-548)."""

    metadata = CheckMetadata(
        id="m3.wp-uploads-listing",
        module="M3",
        name="wp-uploads-listing",
        version="1.0",
        title="WordPress uploads directory indexed",
        description=(
            "Reports when /wp-content/uploads/ answers with the web server's directory index, "
            "publishing every uploaded file name. The listing is recognised by the server's "
            "own index rendering, not by a status code. Read-only GET probe."
        ),
        research_ref="ch03#31",
        framework=("WSTG-CONF-02", "WSTG-CONF-04", "CWE-548"),
        cwe="CWE-548",
        target_kinds=(TargetKind.URL,),
        severity_hint="medium",
        type="hybrid",
        safe=True,
        verifiable=False,
        estimated_requests=2,
        runs_on_discovered=True,
    )

    paths_key = "uploads_paths"
    default_paths = ("/wp-content/uploads/",)
    finding_title = "WordPress uploads directory listing ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        if not _is_listing(page, _wordpress_markers(ctx, "listing_markers")):
            return None
        return _Hit(
            "directory-listing",
            {"entries": list(_listing_entries(page.body))},
            confidence=0.85,
        )


class PluginsListing(_WordPressProbe, WebCheck, Module):
    """``m3.wp-plugins-listing`` — the plugins directory is indexed (ch03#31, CWE-548)."""

    metadata = CheckMetadata(
        id="m3.wp-plugins-listing",
        module="M3",
        name="wp-plugins-listing",
        version="1.0",
        title="WordPress plugins directory indexed",
        description=(
            "Reports when /wp-content/plugins/ answers with the web server's directory index, "
            "publishing the full plugin inventory and every installed version's directory. "
            "Read-only GET probe."
        ),
        research_ref="ch03#31",
        framework=("WSTG-INFO-04", "WSTG-CONF-02", "ATT&CK-T1592.002", "CWE-548"),
        cwe="CWE-548",
        target_kinds=(TargetKind.URL,),
        severity_hint="medium",
        type="hybrid",
        safe=True,
        verifiable=False,
        estimated_requests=2,
        runs_on_discovered=True,
    )

    paths_key = "plugins_paths"
    default_paths = ("/wp-content/plugins/",)
    finding_title = "WordPress plugins directory listing ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        if not _is_listing(page, _wordpress_markers(ctx, "listing_markers")):
            return None
        return _Hit(
            "directory-listing",
            {"entries": list(_listing_entries(page.body))},
            confidence=0.85,
        )


class ThemesListing(_WordPressProbe, WebCheck, Module):
    """``m3.wp-themes-listing`` — the themes directory is indexed (ch03#31, CWE-548)."""

    metadata = CheckMetadata(
        id="m3.wp-themes-listing",
        module="M3",
        name="wp-themes-listing",
        version="1.0",
        title="WordPress themes directory indexed",
        description=(
            "Reports when /wp-content/themes/ answers with the web server's directory index, "
            "publishing the installed theme inventory. Read-only GET probe."
        ),
        research_ref="ch03#31",
        framework=("WSTG-INFO-04", "WSTG-CONF-02", "ATT&CK-T1592.002", "CWE-548"),
        cwe="CWE-548",
        target_kinds=(TargetKind.URL,),
        severity_hint="low",
        type="hybrid",
        safe=True,
        verifiable=False,
        estimated_requests=2,
        runs_on_discovered=True,
    )

    paths_key = "themes_paths"
    default_paths = ("/wp-content/themes/",)
    finding_title = "WordPress themes directory listing ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        if not _is_listing(page, _wordpress_markers(ctx, "listing_markers")):
            return None
        return _Hit(
            "directory-listing",
            {"entries": list(_listing_entries(page.body))},
            confidence=0.85,
        )


class PluginReadmeEnumeration(_WordPressProbe, WebCheck, Module):
    """``m3.wp-plugin-readme`` — installed plugins disclose their versions (ch03#31)."""

    metadata = CheckMetadata(
        id="m3.wp-plugin-readme",
        module="M3",
        name="wp-plugin-readme",
        version="1.0",
        title="WordPress plugin versions disclosed by readme",
        description=(
            "Probes the bounded plugin slug list for each plugin's readme.txt and reports the "
            "ones served, with the version their 'Stable tag:' line states. A plugin "
            "inventory with versions is what turns a core CVE list into a target list. "
            "Read-only GET probes; the slug list is the operator's (payload corpus)."
        ),
        research_ref="ch03#31",
        framework=("WSTG-INFO-04", "WSTG-INFO-08", "ATT&CK-T1592.002", "CWE-200"),
        cwe="CWE-200",
        target_kinds=(TargetKind.URL,),
        severity_hint="low",
        type="hybrid",
        safe=True,
        verifiable=False,
        estimated_requests=8,
        runs_on_discovered=True,
    )

    plugin_readme_template: ClassVar[str] = "/wp-content/plugins/{slug}/readme.txt"

    def paths(self, ctx: CheckContext) -> tuple[str, ...]:
        payloads = payloads_for(ctx)
        template = payloads.string(
            "wordpress", "plugin_readme_template", default=self.plugin_readme_template
        )
        slugs = payloads.strings("wordpress", "plugin_slugs")
        return tuple(template.format(slug=slug) for slug in slugs)

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        if _contains_any(page.body, _wordpress_markers(ctx, "readme_markers")) is None:
            return None
        version = _first(r"stable tag:\s*([0-9][\w.\-]*)", page.body, flags=re.IGNORECASE)
        return _Hit(
            "plugin-readme-disclosed",
            {"plugin": _path_segment(path, -2), "version": version or ""},
            confidence=0.75,
        )


class ThemeStylesheetEnumeration(_WordPressProbe, WebCheck, Module):
    """``m3.wp-theme-stylesheet`` — installed themes disclose their versions (ch03#31)."""

    metadata = CheckMetadata(
        id="m3.wp-theme-stylesheet",
        module="M3",
        name="wp-theme-stylesheet",
        version="1.0",
        title="WordPress theme versions disclosed by stylesheet",
        description=(
            "Probes the bounded theme slug list for each theme's style.css and reports the "
            "ones served, with the version their header states. The stylesheet header is a "
            "theme's identity and version in a file every theme ships. Read-only GET probes."
        ),
        research_ref="ch03#31",
        framework=("WSTG-INFO-04", "WSTG-INFO-08", "ATT&CK-T1592.002", "CWE-200"),
        cwe="CWE-200",
        target_kinds=(TargetKind.URL,),
        severity_hint="low",
        type="hybrid",
        safe=True,
        verifiable=False,
        estimated_requests=6,
        runs_on_discovered=True,
    )

    theme_stylesheet_template: ClassVar[str] = "/wp-content/themes/{slug}/style.css"

    def paths(self, ctx: CheckContext) -> tuple[str, ...]:
        payloads = payloads_for(ctx)
        template = payloads.string(
            "wordpress", "theme_stylesheet_template", default=self.theme_stylesheet_template
        )
        slugs = payloads.strings("wordpress", "theme_slugs")
        return tuple(template.format(slug=slug) for slug in slugs)

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        if _contains_any(page.body, _wordpress_markers(ctx, "stylesheet_markers")) is None:
            return None
        version = _first(
            r"^\s*version:\s*([\w.\-]+)", page.body, flags=re.IGNORECASE | re.MULTILINE
        )
        return _Hit(
            "theme-stylesheet-disclosed",
            {"theme": _path_segment(path, -2), "version": version or ""},
            confidence=0.75,
        )


class ReadmeVersionDisclosure(_WordPressProbe, WebCheck, Module):
    """``m3.wp-readme-version`` — readme.html discloses the core version (ch03#31)."""

    metadata = CheckMetadata(
        id="m3.wp-readme-version",
        module="M3",
        name="wp-readme-version",
        version="1.0",
        title="WordPress core version disclosed by readme",
        description=(
            "Reports when /readme.html or /readme.txt publishes the WordPress core version. "
            "A version match is a signal, never a severity on its own (FP-3): the check "
            "reports the fingerprint and leaves the CVE correlation to the intelligence "
            "stage. Read-only GET probe."
        ),
        research_ref="ch03#31",
        framework=("WSTG-INFO-08", "WSTG-INFO-09", "ATT&CK-T1592.002", "CWE-200"),
        cwe="CWE-200",
        target_kinds=(TargetKind.URL,),
        severity_hint="low",
        type="hybrid",
        safe=True,
        verifiable=False,
        estimated_requests=3,
        runs_on_discovered=True,
    )

    paths_key = "readme_paths"
    finding_title = "WordPress core version disclosed ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        if "wordpress" not in page.body.lower():
            return None
        version = _first(r"version\s+([0-9][\w.\-]*)", page.body, flags=re.IGNORECASE)
        if version is None:
            return None
        return _Hit("core-version-disclosed", {"version": version}, confidence=0.7)


class DebugLogExposure(_WordPressProbe, WebCheck, Module):
    """``m3.wp-debug-log`` — the debug log is served (ch03#31, CWE-532)."""

    metadata = CheckMetadata(
        id="m3.wp-debug-log",
        module="M3",
        name="wp-debug-log",
        version="1.0",
        title="WordPress debug log exposed",
        description=(
            "Reports when /wp-content/debug.log is served, recognised by its own PHP notice "
            "and warning lines. A debug log written with WP_DEBUG_LOG carries file paths, "
            "query fragments and sometimes credentials. Read-only GET probe."
        ),
        research_ref="ch03#31",
        framework=("WSTG-CONF-02", "WSTG-ERRH-01", "CWE-532"),
        cwe="CWE-532",
        target_kinds=(TargetKind.URL,),
        severity_hint="medium",
        type="hybrid",
        safe=True,
        verifiable=False,
        estimated_requests=2,
        runs_on_discovered=True,
    )

    paths_key = "debug_log_paths"
    default_paths = ("/wp-content/debug.log",)
    finding_title = "WordPress debug log readable ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        marker = _contains_any(page.body, _wordpress_markers(ctx, "debug_log_markers"))
        if marker is None:
            return None
        return _Hit(
            "debug-log-readable",
            {"log_marker": marker, "log_bytes": page.body_length},
            confidence=0.8,
        )


class InstallerResidue(_WordPressProbe, WebCheck, Module):
    """``m3.wp-installer-residue`` — the installer is reachable (ch03#31, CWE-200)."""

    metadata = CheckMetadata(
        id="m3.wp-installer-residue",
        module="M3",
        name="wp-installer-residue",
        version="1.0",
        title="WordPress installer reachable",
        description=(
            "Reports when /wp-admin/install.php is served to an unauthenticated client: the "
            "installation entry point answers with its own installed/reinstall rendering "
            "instead of being removed or blocked. Read-only GET probe."
        ),
        research_ref="ch03#31",
        framework=("WSTG-CONF-05", "WSTG-CONF-02", "CWE-200"),
        cwe="CWE-200",
        target_kinds=(TargetKind.URL,),
        severity_hint="low",
        type="hybrid",
        safe=True,
        verifiable=False,
        estimated_requests=2,
        runs_on_discovered=True,
    )

    paths_key = "installer_paths"
    default_paths = ("/wp-admin/install.php",)
    finding_title = "WordPress installer reachable ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        if page.body_length == 0 or "wordpress" not in page.body.lower():
            return None
        markers = _wordpress_markers(ctx, "installer_markers")
        marker = _contains_any(page.body, markers)
        if marker is None:
            return None
        return _Hit("installer-reachable", {"marker": marker}, confidence=0.75)


class UpgradeResidue(_WordPressProbe, WebCheck, Module):
    """``m3.wp-upgrade-residue`` — the upgrade script is reachable (ch03#31, CWE-200)."""

    metadata = CheckMetadata(
        id="m3.wp-upgrade-residue",
        module="M3",
        name="wp-upgrade-residue",
        version="1.0",
        title="WordPress upgrade script reachable",
        description=(
            "Reports when /wp-admin/upgrade.php is served to an unauthenticated client and "
            "answers with its database-update rendering. The upgrade entry point belongs to "
            "the installation window, not to a running site. Read-only GET probe."
        ),
        research_ref="ch03#31",
        framework=("WSTG-CONF-05", "WSTG-CONF-02", "CWE-200"),
        cwe="CWE-200",
        target_kinds=(TargetKind.URL,),
        severity_hint="low",
        type="hybrid",
        safe=True,
        verifiable=False,
        estimated_requests=2,
        runs_on_discovered=True,
    )

    paths_key = "upgrade_paths"
    default_paths = ("/wp-admin/upgrade.php",)
    finding_title = "WordPress upgrade script reachable ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        if "wordpress" not in page.body.lower():
            return None
        markers = _wordpress_markers(ctx, "upgrade_markers")
        marker = _contains_any(page.body, markers)
        if marker is None:
            return None
        return _Hit("upgrade-script-reachable", {"marker": marker}, confidence=0.75)


class AdminAjaxSurface(_WordPressProbe, WebCheck, Module):
    """``m3.wp-admin-ajax-surface`` — admin-ajax answers anonymous clients (ch03#31)."""

    metadata = CheckMetadata(
        id="m3.wp-admin-ajax-surface",
        module="M3",
        name="wp-admin-ajax-surface",
        version="1.0",
        title="WordPress AJAX entry point answers anonymous clients",
        description=(
            "Reports when /wp-admin/admin-ajax.php answers an unauthenticated GET with a 2xx "
            "document naming its registered actions, i.e. the endpoint's nopriv (anonymous) "
            "action surface is published. A blocked entry point answers 400/403. Read-only "
            "GET probe."
        ),
        research_ref="ch03#31",
        framework=("WSTG-INFO-06", "WSTG-IDNT-04", "API9:2023", "CWE-200"),
        cwe="CWE-200",
        target_kinds=(TargetKind.URL,),
        severity_hint="low",
        type="hybrid",
        safe=True,
        verifiable=False,
        estimated_requests=2,
        runs_on_discovered=True,
    )

    paths_key = "admin_ajax_paths"
    default_paths = ("/wp-admin/admin-ajax.php",)
    finding_title = "WordPress AJAX endpoint answers anonymously ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        document = _json_of(page)
        if not isinstance(document, Mapping):
            return None
        keys = [key for key in _wordpress_markers(ctx, "admin_ajax_keys") if key in document]
        if not keys:
            return None
        return _Hit(
            "admin-ajax-nopriv-surface",
            {"document_keys": keys, "content_type": page.content_type},
            confidence=0.7,
        )


class CronSurface(_WordPressProbe, WebCheck, Module):
    """``m3.wp-cron-surface`` — the cron endpoint is reachable (ch03#35, CWE-200)."""

    metadata = CheckMetadata(
        id="m3.wp-cron-surface",
        module="M3",
        name="wp-cron-surface",
        version="1.0",
        title="WordPress cron endpoint publicly reachable",
        description=(
            "Reports when /wp-cron.php is reachable by an unauthenticated client, using an "
            "OPTIONS request: OPTIONS is safe by HTTP semantics (RFC 9110 §9.3.7), so the "
            "probe reports the endpoint's reachability without issuing the GET that would "
            "run a due scheduled job. A deployment that disables the endpoint or blocks it "
            "at the edge answers 403/404. Read-only OPTIONS probe — and, because it is the "
            "family's one non-GET interaction, gated behind the active-checks opt-in exactly "
            "like m4.webdav-verbs (F-01-09)."
        ),
        research_ref="ch03#35",
        framework=("WSTG-BUSL-07", "WSTG-CONF-05", "CWE-200"),
        cwe="CWE-200",
        target_kinds=(TargetKind.URL,),
        severity_hint="low",
        type="active",
        safe=True,
        verifiable=False,
        estimated_requests=2,
        requires_active_checks=True,
        runs_on_discovered=True,
    )

    paths_key = "cron_paths"
    default_paths = ("/wp-cron.php",)
    method = "OPTIONS"
    # A web server that owns OPTIONS answers 405 with the verbs it allows: still reachable.
    ok_statuses = (405,)
    finding_title = "WordPress cron endpoint reachable ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        # A blocked endpoint answers 403/404 (filtered above); 401/429 are refusals too. A
        # served endpoint answers 2xx, or 405 naming the verbs it allows.
        allow = page.header("allow") or ""
        if page.status == 405 and not allow:
            return None
        return _Hit(
            "cron-endpoint-reachable",
            {"options_status": page.status, "allow": allow},
            confidence=0.65,
        )


# --------------------------------------------------------------------------- ch03#19 auth
class AuthorArchiveEnumeration(_WordPressProbe, WebCheck, Module):
    """``m3.wp-author-enumeration`` — ?author=N leaks the login name (ch03#19, CWE-200)."""

    metadata = CheckMetadata(
        id="m3.wp-author-enumeration",
        module="M3",
        name="wp-author-enumeration",
        version="1.0",
        title="WordPress author archive leaks login names",
        description=(
            "Requests /?author=<id> and reports a redirect to the author's /author/<slug>/ "
            "archive, where the slug is the account's login name. The probe is the numeric "
            "id, never a guessed name. A deployment with author archives disabled answers "
            "200 or 404 instead of redirecting. Read-only GET probes."
        ),
        research_ref="ch03#19",
        framework=("WSTG-IDNT-04", "WSTG-INFO-02", "CWE-200"),
        cwe="CWE-200",
        target_kinds=(TargetKind.URL,),
        severity_hint="medium",
        type="hybrid",
        safe=True,
        verifiable=False,
        estimated_requests=3,
        runs_on_discovered=True,
    )

    paths_key = "author_probe_paths"
    default_paths = ("/?author=1",)
    finding_title = "WordPress author archive enumeration ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        if page.status not in {301, 302, 303, 307, 308}:
            return None
        location = page.header("location") or ""
        pattern = payloads_for(ctx).string(
            "wordpress", "author_path_regex", default="/author/[^/?#]+"
        )
        match = re.search(pattern, location, re.IGNORECASE)
        if match is None:
            return None
        return _Hit(
            "author-archive-redirect",
            {"location": location, "archive": match.group(0)},
            confidence=0.85,
        )


class UserSitemapEnumeration(_WordPressProbe, WebCheck, Module):
    """``m3.wp-user-sitemap`` — the user sitemap lists author archives (ch03#19)."""

    metadata = CheckMetadata(
        id="m3.wp-user-sitemap",
        module="M3",
        name="wp-user-sitemap",
        version="1.0",
        title="WordPress user sitemap enumerates author archives",
        description=(
            "Reports when the user sitemap (/wp-sitemap-users-1.xml) is served, which lists "
            "every author archive URL — i.e. every login-name slug — in one document. "
            "Read-only GET probe."
        ),
        research_ref="ch03#19",
        framework=("WSTG-IDNT-04", "WSTG-INFO-03", "CWE-200"),
        cwe="CWE-200",
        target_kinds=(TargetKind.URL,),
        severity_hint="medium",
        type="hybrid",
        safe=True,
        verifiable=False,
        estimated_requests=3,
        runs_on_discovered=True,
    )

    paths_key = "user_sitemap_paths"
    finding_title = "WordPress user sitemap enumerable ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        if "wp-sitemap-users" not in path:
            return None
        if "<" not in page.body or "/author/" not in page.body:
            return None
        authors = len(re.findall(r"/author/", page.body))
        return _Hit("author-sitemap-enumeration", {"author_urls": authors}, confidence=0.8)


class RegistrationOpen(_WordPressProbe, WebCheck, Module):
    """``m3.wp-registration-open`` — self-registration is enabled (ch03#19, CWE-200)."""

    metadata = CheckMetadata(
        id="m3.wp-registration-open",
        module="M3",
        name="wp-registration-open",
        version="1.0",
        title="WordPress self-registration enabled",
        description=(
            "Reports when /wp-login.php?action=register serves the registration form, i.e. "
            "the installation accepts self-registration. A hardened installation answers the "
            "login form with registration disabled. Read-only GET probe."
        ),
        research_ref="ch03#19",
        framework=("WSTG-CONF-02", "WSTG-IDNT-04", "CWE-200"),
        cwe="CWE-200",
        target_kinds=(TargetKind.URL,),
        severity_hint="low",
        type="hybrid",
        safe=True,
        verifiable=False,
        estimated_requests=2,
        runs_on_discovered=True,
    )

    paths_key = "registration_paths"
    default_paths = ("/wp-login.php?action=register",)
    finding_title = "WordPress self-registration enabled ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        markers = _wordpress_markers(ctx, "registration_markers")
        found = [name for name in markers if name in page.body.lower()]
        # The login form itself also carries ``user_login``; the registration form is the
        # one that carries the register action as well.
        if (
            "action=register" not in page.body.lower()
            and 'id="registerform"' not in page.body.lower()
        ):
            return None
        return _Hit("self-registration-enabled", {"markers": found}, confidence=0.75)


class AppPasswordSurface(_WordPressProbe, WebCheck, Module):
    """``m3.wp-app-password-surface`` — the app-password page is unauthenticated (ch03#19)."""

    metadata = CheckMetadata(
        id="m3.wp-app-password-surface",
        module="M3",
        name="wp-app-password-surface",
        version="1.0",
        title="WordPress application-password page reachable without a session",
        description=(
            "Reports when /wp-admin/authorize-application.php answers an anonymous client "
            "with the application-password authorization page instead of redirecting to the "
            "login screen. The page is the entry point that mints credentials, so it must "
            "sit behind a session. Read-only GET probe."
        ),
        research_ref="ch03#19",
        framework=("WSTG-CONF-05", "WSTG-ATHN-04", "CWE-200"),
        cwe="CWE-200",
        target_kinds=(TargetKind.URL,),
        severity_hint="medium",
        type="hybrid",
        safe=True,
        verifiable=False,
        estimated_requests=2,
        runs_on_discovered=True,
    )

    paths_key = "app_password_paths"
    default_paths = ("/wp-admin/authorize-application.php",)
    finding_title = "WordPress application-password page unauthenticated ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        if _contains_any(page.body, _wordpress_markers(ctx, "app_password_markers")) is None:
            return None
        return _Hit(
            "app-password-page-unauthenticated",
            {"session_required": False},
            confidence=0.8,
        )


class RestAppPasswords(_WordPressProbe, WebCheck, Module):
    """``m3.wp-rest-app-passwords`` — the app-password route answers anonymous (CWE-862)."""

    metadata = CheckMetadata(
        id="m3.wp-rest-app-passwords",
        module="M3",
        name="wp-rest-app-passwords",
        version="1.0",
        title="WordPress REST application-password route readable anonymously",
        description=(
            "Reports when /wp-json/wp/v2/users/<id>/application-passwords answers an "
            "anonymous GET with an application-password record. The route requires the "
            "account's own authorization: 401 is the correct answer and is reported clean. "
            "Read-only GET probe."
        ),
        research_ref="ch03#19",
        framework=("WSTG-ATHN-04", "WSTG-CONF-05", "API5:2023", "CWE-862"),
        cwe="CWE-862",
        target_kinds=(TargetKind.URL,),
        severity_hint="medium",
        type="hybrid",
        safe=True,
        verifiable=False,
        estimated_requests=2,
        runs_on_discovered=True,
    )

    paths_key = "rest_app_password_paths"
    default_paths = ("/wp-json/wp/v2/users/1/application-passwords",)
    finding_title = "WordPress REST application-password route readable ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        document = _json_of(page)
        entries = document if isinstance(document, list) else [document]
        records = [
            item
            for item in entries
            if isinstance(item, Mapping) and ("uuid" in item or "name" in item or "app_id" in item)
        ]
        if not records:
            return None
        return _Hit(
            "unauthenticated-application-passwords",
            {"records": len(records)},
            confidence=0.85,
        )


# --------------------------------------------------------------------------- version (passive)
class AssetVersionDisclosure(WebCheck, Module):
    """``m3.wp-asset-version`` — enqueued assets carry the version query (ch03#31)."""

    metadata = CheckMetadata(
        id="m3.wp-asset-version",
        module="M3",
        name="wp-asset-version",
        version="1.0",
        title="WordPress asset URLs disclose component versions",
        description=(
            "Reads the pages the crawl already fetched and reports WordPress core and "
            "component asset URLs that carry a ?ver= version query (wp-includes/...?ver=6.4.2). "
            "A hardened installation strips the query. This check issues no request of its "
            "own; a version is a fingerprint and is never a severity on its own (FP-3)."
        ),
        research_ref="ch03#31",
        framework=("WSTG-INFO-08", "WSTG-INFO-09", "ATT&CK-T1592.002", "CWE-200"),
        cwe="CWE-200",
        target_kinds=(TargetKind.URL,),
        severity_hint="low",
        type="hybrid",
        safe=True,
        verifiable=False,
        estimated_requests=0,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        if not owns_origin(ctx):
            yield skip(ctx, "another URL asset on this origin owns the M3 crawl for it")
            return
        inventory = ctx.web
        if not isinstance(inventory, WebInventory):
            yield skip(
                ctx,
                "no web inventory for this step: the checks step crawls the endpoints (S6/M3)",
            )
            return
        origin = origin_of(ctx.asset.value)
        pattern = payloads_for(ctx).string(
            "wordpress",
            "asset_version_regex",
            default=r"(?:wp-includes|wp-content)/[^\s\"'<>]*\?ver=([0-9][\w.\-]*)",
        )
        observed: dict[str, str] = {}
        evidence_page: Page | None = None
        for url in inventory.order:
            page = inventory.pages.get(url)
            if page is None or origin_of(page.url) != origin:
                continue
            for match in re.finditer(pattern, page.body):
                asset = match.group(0)
                observed.setdefault(asset, match.group(1))
                evidence_page = evidence_page or page
        if not observed:
            yield ctx.clean(
                "no versioned WordPress asset URL found",
                detail=f"read {len(inventory.order)} crawled page(s) on {origin}",
            )
            return
        assets = list(observed.items())[:12]
        yield web_candidate(
            ctx,
            "WordPress asset URLs disclose component versions",
            artifact={
                "signal": "asset-version-disclosed",
                "family": FAMILY,
                "check": self.metadata.name,
                "origin": origin,
                "assets": [asset for asset, _ in assets],
                "versions": sorted({version for _, version in assets}),
                "requests_sent": 0,
            },
            exchanges=(exchange_from_page(evidence_page),) if evidence_page else (),
            confidence=0.65,
            detail=f"{len(observed)} versioned asset URL(s) on {origin}",
        )


#: Every check of the family, in run order (cheapest and most specific first).
WordPressChecks: tuple[type[Module], ...] = (
    WPConfigBackup,
    WPConfigSourceDisclosure,
    XmlrpcSurface,
    XmlrpcRsd,
    RestApiIndex,
    RestUserRoute,
    RestUserRecord,
    RestRouteParam,
    RestSettingsUnauth,
    UploadsListing,
    PluginsListing,
    ThemesListing,
    PluginReadmeEnumeration,
    ThemeStylesheetEnumeration,
    ReadmeVersionDisclosure,
    DebugLogExposure,
    InstallerResidue,
    UpgradeResidue,
    AdminAjaxSurface,
    CronSurface,
    AuthorArchiveEnumeration,
    UserSitemapEnumeration,
    RegistrationOpen,
    AppPasswordSurface,
    RestAppPasswords,
    AssetVersionDisclosure,
)


# --------------------------------------------------------------------------- small utilities
def _first(pattern: str, text: str, *, flags: int = 0) -> str | None:
    match = re.search(pattern, text, flags)
    return None if match is None else match.group(1)


def _path_segment(path: str, index: int) -> str:
    """One segment of a probe path (``-2`` is the slug in ``/a/<slug>/readme.txt``)."""
    segments = [segment for segment in urlsplit(path).path.split("/") if segment]
    try:
        return segments[index]
    except IndexError:
        return ""
