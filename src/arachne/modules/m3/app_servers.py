"""WP-27 · application servers and web frameworks (REQ-DET-020).

Twenty-five read-only L1 checks over the server and framework surface the requirement names:

* **Spring Boot** — the actuator endpoint index, the actuator configuration surfaces
  (``/actuator/env``, ``configprops``, ``mappings``, ``beans``) and the downloadable heap dump
  (``/actuator/heapdump``);
* **Django** — the ``DEBUG = True`` technical error page, the debug-toolbar ``__debug__``
  endpoints and the development static/media directory index;
* **Rails** — the development info controller's ``/rails/info/properties`` and
  ``/rails/info/routes``;
* **Laravel** — the Ignition/Whoops debug error page and the ``_ignition`` debug endpoints;
* **Tomcat** — the manager and host-manager applications and the default ``examples``/``docs``
  web applications;
* **JBoss** — the JMX console, the web console and the administration console;
* **WebLogic** — the administration console, the UDDI explorer and the ``wls-wsat`` component;
* **ColdFusion** — the ``CFIDE`` administrator, the ``CFIDE`` scripts directory and the
  administrator's version disclosure;
* **IIS** — the 8.3 short-name behaviour, the ASP.NET trace viewer (``trace.axd``) and the
  legacy ``iisadmpwd`` password-change surface.

**Read-only.** Every request is a ``GET``. No check sends a body, a credential or a
state-changing verb; none stores anything, and none reaches above L1. A check that could only
be decided by a login attempt (or by a POST to a management console) is not written at all.

**A console surface is a reachability claim, never a credential test.** The Tomcat manager, the
JBoss consoles, the WebLogic console and the ColdFusion administrator are reported when they
*answer an anonymous client* — with the component's own challenge (Tomcat's
``WWW-Authenticate: Basic realm="Tomcat Manager Application"``), its own login markup or its
own landing page. The finding reports that the surface is reachable and sends no credential and
attempts no login: ``"credential_test_sent": false``. Nothing about any account or password is
claimed.

**A version or banner match is never ``high`` on its own** (FP-3): the ColdFusion version
disclosure carries ``severity_hint="low"`` and reports a *signal*, not a vulnerability. The
actuator configuration check names the property *sources* and the property *names* a body
declares, never a value.

**The decoy rule, enforced twice.** Two guards keep one framework's checks off the others' and
off a block page:

1. every signal requires the framework's own *structural marker* (``_links`` for the actuator
   index, ``propertySources`` for ``/actuator/env``, ``JAVA PROFILE`` for the heap dump,
   ``you're seeing this error because`` for the Django technical page, ``Rails version`` for the
   Rails info controller, ``Tomcat Manager Application`` for the manager realm, ``JMX Agent
   View`` for the JBoss console, ``j_security_check`` for the WebLogic console, ``CFIDE`` for
   ColdFusion, ``Requests to this Application`` for the ASP.NET trace viewer), never a bare
   status code or a body word;
2. every signal additionally requires the body to **name its own framework**, so a check cannot
   fire on another framework's installation — the nine installations are decoys for one another
   — nor on a WAF block page that names the framework while carrying none of its markup.

Six checks whose evidence is not the framework's own *name* carry their own structural shape
instead, exactly as WP-25/WP-26 did for the XML-RPC advertisement and the PrestaShop realm:
the **actuator configuration document** (its ``propertySources``/``activeProfiles``/``contexts``
structure on the actuator route — the real document never spells out "actuator"), the **heap
dump** (the shared client classifies the body as non-text, or the readable body carries the
HPROF magic ``JAVA PROFILE``), the **Django media listing** (the ``Directory listing for``
heading Django's ``django.views.static`` renderer emits), the **IIS short-name** probe (the
``400`` plus IIS's own *request is badly formed* error page and the ``Server`` header naming
IIS) and the **Tomcat manager** and **host-manager** challenges (the ``WWW-Authenticate``
realms). Each is documented at its class.

**The Django and Laravel debug pages *are* how those frameworks answer an unmatched URL** when
debug mode is on, so those two checks read the technical page itself rather than a path they
expect to 500 on: the probe path is a random, non-existent one, and the check fires only when
the answer carries the framework's own technical-error markup. That is why they are the family's
two ``treat_as_not_found=False`` checks — the page they want *is* the not-found page.

**Decoys.** One production-configured instance per framework, plus a WAF-fronted one per
framework (``tests/lab/app_server_lab.py``), the same trap design WP-25/WP-26 used: the block
page echoes the requested path and names the framework, so a check that matched on body content
would fire on it.
"""

from __future__ import annotations

import json
import re
from collections.abc import AsyncIterator, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, ClassVar

from arachne.core.proof import ProofLevel
from arachne.core.results import CheckResult
from arachne.core.target import TargetKind
from arachne.modules.base import CheckMetadata, Module, SeverityHint
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
    "AppServerChecks",
    "ColdFusionAdministrator",
    "ColdFusionScriptsDirectory",
    "ColdFusionVersionDisclosure",
    "DjangoDebugPage",
    "DjangoDebugToolbar",
    "DjangoMediaListing",
    "IisLegacyPasswordSurface",
    "IisShortNameDisclosure",
    "IisTraceViewer",
    "JbossAdminConsole",
    "JbossJmxConsole",
    "JbossWebConsole",
    "LaravelDebugPage",
    "LaravelIgnitionSurface",
    "RailsInfoProperties",
    "RailsInfoRoutes",
    "SpringBootActuatorEnv",
    "SpringBootActuatorIndex",
    "SpringBootHeapdump",
    "TomcatExamplesSurface",
    "TomcatHostManagerSurface",
    "TomcatManagerSurface",
    "WebLogicConsole",
    "WebLogicUddiExplorer",
    "WebLogicWsat",
]

#: The family tag every artifact carries, so one heuristic rule can cover the whole set.
FAMILY = "app-server"

#: The name each framework publishes about itself (lowercase: matching is case-insensitive).
#: Used as the second decoy guard — see the module docstring.
_SERVER_NAMES: Mapping[str, tuple[str, ...]] = {
    "spring_boot": ("actuator",),
    "django": ("django",),
    "rails": ("rails",),
    "laravel": ("laravel", "ignition"),
    "tomcat": ("tomcat", "catalina"),
    "jboss": ("jboss", "wildfly"),
    "weblogic": ("weblogic",),
    "coldfusion": ("coldfusion", "cfide"),
    "iis": ("iis", "internet information services", "asp.net"),
}


# --------------------------------------------------------------------------- plumbing
@dataclass(frozen=True, slots=True)
class _Hit:
    """One confirmed signal: what it is, the facts behind it, and how much to trust it."""

    signal: str
    facts: Mapping[str, Any] = field(default_factory=dict)
    confidence: float = 0.75


def _meta(
    name: str,
    title: str,
    description: str,
    *,
    research_ref: str,
    cwe: str,
    framework: tuple[str, ...],
    severity: SeverityHint,
    estimated_requests: int,
    compliance: tuple[str, ...] = (),
) -> CheckMetadata:
    """Build one check's metadata: L1, hybrid, safe, default-on, URL-scoped (WP-27 contract)."""
    return CheckMetadata(
        id=f"m3.{name}",
        module="M3",
        name=name,
        version="1.0",
        title=title,
        description=description,
        research_ref=research_ref,
        cwe=cwe,
        framework=framework,
        compliance=compliance,
        severity_hint=severity,
        type="hybrid",
        safe=True,
        verifiable=False,
        enabled_by_default=True,
        proof=ProofLevel.L1,
        estimated_requests=estimated_requests,
        runs_on_discovered=True,
        target_kinds=(TargetKind.URL,),
    )


def _paths(
    ctx: CheckContext, section: str, key: str, default: Sequence[str] = ()
) -> tuple[str, ...]:
    """A path inventory from the payload corpus, else the check's own default."""
    configured = payloads_for(ctx).strings(section, key)
    return configured or tuple(default)


def _markers(
    ctx: CheckContext, section: str, key: str, default: Sequence[str] = ()
) -> tuple[str, ...]:
    """A lowercase marker list from the payload corpus, else the check's own default."""
    configured = payloads_for(ctx).strings(section, key) or tuple(default)
    return tuple(marker.lower() for marker in configured)


def _full_url(origin: str, path: str) -> str:
    """Join ``origin`` and a path without doubling or dropping the separator."""
    if path.startswith(("http://", "https://")):
        return path
    return origin.rstrip("/") + "/" + path.lstrip("/")


def _first(pattern: str, text: str, *, flags: int = 0) -> str | None:
    match = re.search(pattern, text, flags)
    return None if match is None else match.group(1)


def _contains_any(body: str, markers: Sequence[str]) -> str | None:
    """The first marker present in ``body`` (case-insensitive), or ``None``."""
    lowered = body.lower()
    for marker in markers:
        if marker and marker in lowered:
            return marker
    return None


def _markers_found(body: str, markers: Sequence[str]) -> list[str]:
    """Every marker ``body`` carries (case-insensitive), in the list's order."""
    lowered = body.lower()
    return [marker for marker in markers if marker and marker in lowered]


def _json_of(page: Page) -> Any:
    """The page body parsed as JSON, or ``None`` when it is not JSON."""
    try:
        return json.loads(page.body)
    except (json.JSONDecodeError, ValueError):
        return None


def _header(page: Page, name: str) -> str | None:
    """One response header's value (case-insensitive), or ``None``."""
    wanted = name.lower()
    for key, value in page.headers.items():
        if key.lower() == wanted:
            return value
    return None


def _json_keys(document: Mapping[str, Any], *, limit: int = 12) -> list[str]:
    """The top-level key names of a JSON document, bounded (names, never values)."""
    return sorted(str(key) for key in document)[:limit]


class _ServerProbe:
    """The shared shape of the family: bounded path probes on the asset's origin.

    A concrete check is declared ``class X(_ServerProbe, WebCheck, Module)`` and sets its
    ``metadata`` plus the class attributes below. Every request goes through the shared scoped
    client (ADR-05); a response the server refuses, blocks or answers with its own not-found
    rendering is skipped, so a check only fires on a *distinct, successful* answer carrying both
    the framework's own marker and the framework's name.

    This is a plain mixin rather than a :class:`~arachne.modules.base.Module` subclass: the base
    refuses to be created without metadata, and a family base has none of its own.
    """

    #: Declared here so the shared ``run`` can read it; every concrete check supplies it.
    metadata: ClassVar[CheckMetadata]

    #: The payload-corpus section for this framework (``spring_boot``, ``django``, ...).
    section: ClassVar[str] = ""
    #: The framework's own name(s), lowercase; the body must carry one before a signal is read.
    names: ClassVar[tuple[str, ...]] = ()
    #: False for the checks whose evidence is not the framework's own body markup.
    body_must_name: ClassVar[bool] = True
    #: False for the checks whose positive answer *is* the installation's not-found page.
    treat_as_not_found: ClassVar[bool] = True
    #: The ``<section>:`` key holding this check's path list in the payload corpus.
    paths_key: ClassVar[str] = ""
    #: Fallback paths when the corpus key is absent (an operator-supplied corpus).
    default_paths: ClassVar[tuple[str, ...]] = ()
    #: Non-2xx statuses this check still evaluates: the component's own answer to an anonymous
    #: caller. Every other 4xx/5xx is a refusal, a block or a missing path.
    ok_statuses: ClassVar[tuple[int, ...]] = ()
    #: How many findings one run reports (one root cause, bounded output).
    max_findings: ClassVar[int] = 2
    #: The candidate title; ``{path}`` is the probed path.
    finding_title: ClassVar[str] = "Application server surface exposed ({path})"

    def paths(self, ctx: CheckContext) -> tuple[str, ...]:
        return _paths(ctx, self.section, self.paths_key, self.default_paths)

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
                "no application-server path inventory configured",
                detail="the payload corpus names no probe path for this check",
            )
            return
        not_found = await _not_found(ctx, origin) if self.treat_as_not_found else None
        findings = 0
        refused = 0
        for path in paths:
            if findings >= self.max_findings:
                break
            url = _full_url(origin, path)
            page = await _fetch(ctx, url)
            if page is None:
                continue
            if page.status >= 400 and page.status not in self.ok_statuses:
                refused += 1
                continue
            if not_found is not None and _looks_like_not_found(page, not_found):
                continue
            if self.body_must_name and _contains_any(page.body, self.names) is None:
                # Another framework's installation (or a block page naming it): not this one.
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
                    "framework": self.section,
                    "check": self.metadata.name,
                    "path": path,
                    "status": page.status,
                    "content_type": page.content_type,
                    "bytes": page.body_length,
                    "binary": page.binary,
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
            label = self.metadata.name.replace("-", " ")
            yield ctx.clean(
                f"no {label} surface found",
                detail=(
                    f"probed {len(paths)} path(s) on {origin}"
                    + (f"; {refused} refused or blocked" if refused else "")
                ),
            )


async def _fetch(ctx: CheckContext, url: str) -> Page | None:
    """One bounded GET probe as a :class:`Page` (``None`` when refused or failed)."""
    exchange = await safe_fetch(ctx, url, method="GET")
    return None if exchange is None else page_from_exchange(exchange)


async def _not_found(ctx: CheckContext, origin: str) -> Page | None:
    """The installation's own not-found answer for ``origin``, learned once per step."""
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


# --------------------------------------------------------------------------- shared signals
def _realm_names_tomcat(page: Page, component: str) -> bool:
    """True when the answer is Tomcat's own Basic challenge for ``component``."""
    realm = _header(page, "www-authenticate") or ""
    lowered = realm.lower()
    return "tomcat" in lowered and component in lowered and "realm=" in lowered


def _admin_login_hit(markers: Sequence[str], surface: str) -> _Hit | None:
    """The component's own login/landing markup is served to an anonymous client."""
    if not markers:
        return None
    return _Hit(
        surface,
        {
            "markers": list(markers),
            # The surface is reported as configuration. No credential is sent, and the check
            # makes no claim about any account: see the module docstring.
            "default_credential_surface": True,
            "credential_test_sent": False,
        },
        confidence=0.75,
    )


def _surface_hit(surface: str, markers: Sequence[str], *, confidence: float = 0.8) -> _Hit | None:
    """A structural marker list confirmed the component's own page."""
    if not markers:
        return None
    return _Hit(surface, {"markers": list(markers)}, confidence=confidence)


def _confirmed(page: Page, markers: Sequence[str], required: Sequence[str]) -> list[str]:
    """The markers ``page`` carries when at least one of ``required`` is present, else ``[]``.

    One half of the decoy rule in one place: a framework's page is confirmed only when its own
    *required* structural token is present, and the returned list is every related marker the
    page then shows — the facts a reviewer reads.
    """
    lowered = page.body.lower()
    if not any(token in lowered for token in required):
        return []
    return _markers_found(page.body, markers)


def _version_hit(
    page: Page, ctx: CheckContext, section: str, default: str, *, name: str = "coldfusion"
) -> _Hit | None:
    """The framework's own version artefact publishes a version (a signal, never a severity)."""
    if _contains_any(page.body, _markers(ctx, section, "version_markers")) is None:
        return None
    pattern = payloads_for(ctx).string(section, "version_regex", default=default) or default
    version = _first(pattern, page.body, flags=re.IGNORECASE)
    if version is None:
        return None
    return _Hit(f"{name}-version-disclosed", {"version": version}, confidence=0.7)


# --------------------------------------------------------------------------- Spring Boot
class SpringBootActuatorIndex(_ServerProbe, WebCheck, Module):
    """``m3.spring-boot-actuator-index`` — the actuator endpoint index is served (ch03#31)."""

    section = "spring_boot"
    names = _SERVER_NAMES[section]
    metadata = _meta(
        "spring-boot-actuator-index",
        "Spring Boot actuator endpoint index published",
        "Reports when the Spring Boot actuator index answers an anonymous GET with its own "
        'endpoint map: the JSON document carries a "_links" object whose entries are the '
        "actuator endpoints the application exposes. The index itself is an inventory of the "
        "management surface; the check names the endpoints it lists and makes no claim about "
        "which of them disclose data. Read-only GET probes.",
        research_ref="ch03#31",
        cwe="CWE-200",
        framework=("WSTG-CONF-05", "WSTG-INFO-06", "ATT&CK-T1592.002", "CWE-200"),
        severity="medium",
        estimated_requests=4,
    )

    paths_key = "actuator_index_paths"
    default_paths = ("/actuator", "/actuator/", "/actuator/health")
    finding_title = "Spring Boot actuator index served ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        document = _json_of(page)
        if not isinstance(document, Mapping):
            return None
        links = document.get("_links")
        if not isinstance(links, Mapping) or not links:
            return None
        if "actuator" not in page.body.lower():
            return None
        return _Hit(
            "actuator-index-exposed",
            {"endpoints": sorted(str(key) for key in links)[:12], "endpoint_count": len(links)},
            confidence=0.8,
        )


class SpringBootActuatorEnv(_ServerProbe, WebCheck, Module):
    """``m3.spring-boot-actuator-env`` — an actuator configuration surface reads (ch03#31)."""

    section = "spring_boot"
    # The actuator's own configuration document does not spell out "actuator": it is recognised
    # by its structure (propertySources/activeProfiles/contexts) on the actuator route, which is
    # the framework's own shape rather than its name — see the module docstring.
    body_must_name = False
    metadata = _meta(
        "spring-boot-actuator-env",
        "Spring Boot actuator configuration surface readable",
        "Reports when an actuator configuration endpoint answers an anonymous GET with its own "
        "JSON document: the response carries Spring's environment structure (propertySources "
        "and activeProfiles for /actuator/env, contexts for configprops, mappings and beans). "
        "The finding names the property *sources* and the property *names* the document "
        "declares, never a value. Read-only GET probes.",
        research_ref="ch03#31",
        cwe="CWE-200",
        framework=("WSTG-CONF-05", "WSTG-CONF-02", "ATT&CK-T1552", "CWE-200"),
        compliance=("ISO-A.8.12", "CSF-ID.AM-02"),
        severity="medium",
        estimated_requests=5,
    )

    paths_key = "actuator_config_paths"
    default_paths = (
        "/actuator/env",
        "/actuator/configprops",
        "/actuator/mappings",
        "/actuator/beans",
    )
    max_findings = 2
    finding_title = "Spring Boot actuator configuration readable ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        if "/actuator/" not in path:
            return None
        document = _json_of(page)
        if not isinstance(document, Mapping):
            return None
        structural = [
            key for key in ("propertySources", "activeProfiles", "contexts") if key in document
        ]
        if not structural:
            return None
        names: list[str] = []
        sources = document.get("propertySources")
        if isinstance(sources, list):
            names = [
                str(source.get("name"))
                for source in sources
                if isinstance(source, Mapping) and source.get("name") is not None
            ]
        return _Hit(
            "actuator-configuration-readable",
            {
                "document_keys": _json_keys(document),
                "structural_keys": structural,
                "property_sources": names[:8],
                "reports": "names, never a value",
            },
            confidence=0.8,
        )


class SpringBootHeapdump(_ServerProbe, WebCheck, Module):
    """``m3.spring-boot-heapdump`` — the actuator heap-dump route serves a download (ch03#31)."""

    section = "spring_boot"
    body_must_name = False
    metadata = _meta(
        "spring-boot-heapdump",
        "Spring Boot actuator heap dump endpoint enabled",
        "Reports when the actuator's heap-dump route answers an anonymous GET with a binary "
        "download rather than the application's JSON or an error page: either the shared client "
        "classifies the body as non-text (a real heap dump is an HPROF binary, and its bytes "
        "are never decoded or stored), or the readable body begins with the HPROF magic "
        "'JAVA PROFILE'. The finding reports that the endpoint is enabled and serves a "
        "download, with its content type and size; the dump is fetched once and never parsed. "
        "Read-only GET probes.",
        research_ref="ch03#31",
        cwe="CWE-200",
        framework=("WSTG-CONF-05", "WSTG-INFO-06", "ATT&CK-T1552", "CWE-200"),
        compliance=("ISO-A.8.12", "CSF-ID.AM-02"),
        severity="medium",
        estimated_requests=2,
    )

    paths_key = "heapdump_paths"
    default_paths = ("/actuator/heapdump",)
    max_findings = 1
    finding_title = "Spring Boot heap dump endpoint enabled ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        if "heapdump" not in path:
            return None
        binary = page.binary
        magic = page.body[:64].strip().upper().startswith("JAVA PROFILE")
        if not binary and not magic:
            return None
        return _Hit(
            "heap-dump-downloadable",
            {
                "binary": binary,
                "magic_present": magic,
                "content_type": page.content_type,
                "note": page.body[:64] if binary else "",
                "reports": "the download, not its contents",
            },
            confidence=0.8,
        )


# --------------------------------------------------------------------------- Django
class DjangoDebugPage(_ServerProbe, WebCheck, Module):
    """``m3.django-debug-page`` — Django's DEBUG technical page is served (ch03#31)."""

    section = "django"
    names = _SERVER_NAMES[section]
    treat_as_not_found = False
    metadata = _meta(
        "django-debug-page",
        "Django debug error page disclosed",
        "Reports when Django answers a request for a non-existent path with its own technical "
        "page: the response carries Django's debug markup (the 'You're seeing this error "
        "because you have DEBUG = True' notice plus the URL-pattern or traceback section) "
        "instead of a plain 404. With DEBUG on, that page discloses the settings, the URL "
        "configuration and, for an exception, the stack. Read-only GET probes.",
        research_ref="ch03#31",
        cwe="CWE-209",
        framework=("WSTG-ERRH-01", "WSTG-ERRH-02", "WSTG-CONF-02", "CWE-209"),
        compliance=("ISO-A.8.12",),
        severity="medium",
        estimated_requests=3,
    )

    paths_key = "debug_paths"
    default_paths = ("/arachne-debug-probe/", "/arachne-debug-probe")
    # Django's technical page is served *as* the 404 for an unmatched URL, so the 404 is the
    # positive answer and must be evaluated rather than skipped.
    ok_statuses = (404,)
    max_findings = 1
    finding_title = "Django debug page disclosed ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        markers = _markers_found(
            page.body,
            _markers(
                ctx,
                self.section,
                "debug_markers",
                ("you're seeing this error because", "debug = true", "traceback", "url pattern"),
            ),
        )
        if "you're seeing this error because" not in page.body.lower() and "debug = true" not in (
            page.body.lower()
        ):
            return None
        if not markers:
            return None
        return _Hit(
            "debug-page-disclosed",
            {"markers": markers, "status": page.status},
            confidence=0.8,
        )


class DjangoDebugToolbar(_ServerProbe, WebCheck, Module):
    """``m3.django-debug-toolbar`` — the debug-toolbar endpoints answer (ch03#31)."""

    section = "django"
    names = ("djdt", "debug toolbar", "django")
    metadata = _meta(
        "django-debug-toolbar",
        "Django debug toolbar endpoints served",
        "Reports when the django-debug-toolbar's own endpoints (/__debug__/ and its panel "
        "renderer) answer an anonymous request with the toolbar's markup or JSON (the djDebug "
        "container, the DJDT cookie contract or a panel payload) instead of a 404. The toolbar "
        "exposes the SQL, settings and request data of every rendered page. Read-only GET "
        "probes; no panel is rendered with attacker input.",
        research_ref="ch03#31",
        cwe="CWE-497",
        framework=("WSTG-CONF-05", "WSTG-ERRH-01", "CWE-497"),
        severity="medium",
        estimated_requests=4,
    )

    paths_key = "toolbar_paths"
    default_paths = ("/__debug__/", "/__debug__/render_panel/", "/__debug__/history_sidebar/")
    max_findings = 2
    finding_title = "Django debug toolbar served ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        markers = _markers_found(
            page.body, ("djdebug", "djdt", "debug toolbar", "__debug__", "render_panel")
        )
        if "__debug__" not in path:
            return None
        if "djdebug" not in page.body.lower() and "__debug__" not in page.body.lower():
            return None
        return _surface_hit("debug-toolbar-served", markers)


class DjangoMediaListing(_ServerProbe, WebCheck, Module):
    """``m3.django-media-listing`` — Django's dev media index is listed (ch03#31)."""

    section = "django"
    body_must_name = False
    metadata = _meta(
        "django-media-listing",
        "Django development media directory listed",
        "Reports when Django's development static/media server answers an anonymous GET with a "
        "directory index: the response carries the 'Directory listing for' heading and the "
        "entry list that django.views.static renders for a media or static root, rather than a "
        "404. The check reports the path and the entry count, never the file contents. "
        "Read-only GET probes.",
        research_ref="ch03#31",
        cwe="CWE-548",
        framework=("WSTG-CONF-04", "WSTG-CONF-03", "CWE-548"),
        severity="low",
        estimated_requests=5,
    )

    paths_key = "media_paths"
    default_paths = ("/media/", "/media/uploads/", "/static/", "/static/admin/")
    max_findings = 2
    finding_title = "Django media directory listed ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        lowered = page.body.lower()
        if "directory listing for" not in lowered:
            return None
        # The listing is Django's own renderer, so the marker is paired with one of the two
        # roots it serves (see the module docstring's third-guard paragraph).
        if not path.startswith(("/media", "/static")):
            return None
        entries = len(re.findall(r"<li><a href=", page.body, flags=re.IGNORECASE))
        return _Hit(
            "media-directory-listed",
            {"entries": entries, "renderer": "django.views.static"},
            confidence=0.75,
        )


# --------------------------------------------------------------------------- Rails
class RailsInfoProperties(_ServerProbe, WebCheck, Module):
    """``m3.rails-info-properties`` — the Rails info controller reads (ch03#31)."""

    section = "rails"
    names = _SERVER_NAMES[section]
    metadata = _meta(
        "rails-info-properties",
        "Rails development info properties disclosed",
        "Reports when the Rails info controller's /rails/info/properties answers an anonymous "
        "GET with its properties table: the response names the Rails version, the Ruby "
        "version and the application root, which the route only serves while the application "
        "runs in development mode. The finding reports the properties the page declares. "
        "Read-only GET probes.",
        research_ref="ch03#31",
        cwe="CWE-497",
        framework=("WSTG-INFO-02", "WSTG-INFO-08", "WSTG-CONF-02", "CWE-497"),
        severity="low",
        estimated_requests=3,
    )

    paths_key = "info_properties_paths"
    default_paths = ("/rails/info/properties", "/rails/info")
    max_findings = 1
    finding_title = "Rails info properties disclosed ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        markers = _markers_found(
            page.body,
            ("rails version", "ruby version", "application root", "rails/info/properties"),
        )
        if not any(m in page.body.lower() for m in ("rails version", "ruby version")):
            return None
        return _surface_hit("rails-info-properties", markers)


class RailsInfoRoutes(_ServerProbe, WebCheck, Module):
    """``m3.rails-info-routes`` — the route table is published (ch03#31)."""

    section = "rails"
    names = _SERVER_NAMES[section]
    metadata = _meta(
        "rails-info-routes",
        "Rails route table disclosed",
        "Reports when /rails/info/routes answers an anonymous GET with the application's route "
        "table: the response carries the Rails route listing's own columns (Prefix, Verb, URI "
        "Pattern, Controller#Action) and names the issuing framework. The table is a complete "
        "map of the application's endpoints. Read-only GET probes.",
        research_ref="ch03#31",
        cwe="CWE-200",
        framework=("WSTG-INFO-06", "WSTG-CONF-05", "CWE-200"),
        severity="low",
        estimated_requests=3,
    )

    paths_key = "info_routes_paths"
    default_paths = ("/rails/info/routes", "/rails/info/routes?path=/")
    max_findings = 1
    finding_title = "Rails route table disclosed ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        lowered = page.body.lower()
        columns = [
            name
            for name in ("prefix", "verb", "uri pattern", "controller#action")
            if name in lowered
        ]
        if len(columns) < 3:
            return None
        routes = lowered.count("controller#action")
        return _Hit("route-table-disclosed", {"columns": columns, "routes": routes}, confidence=0.8)


# --------------------------------------------------------------------------- Laravel
class LaravelDebugPage(_ServerProbe, WebCheck, Module):
    """``m3.laravel-debug-page`` — Laravel's debug error page is served (ch03#31)."""

    section = "laravel"
    names = _SERVER_NAMES[section]
    treat_as_not_found = False
    metadata = _meta(
        "laravel-debug-page",
        "Laravel debug error page disclosed",
        "Reports when Laravel answers a request for a non-existent path with its own debug "
        "error page rather than a plain 404: the response carries the Ignition/Whoops markup "
        "(the ignition container, the APP_DEBUG notice or the 'Whoops' frame list) and names "
        "the framework. With the debug page on, an exception discloses the environment, the "
        "route list and the file paths. Read-only GET probes.",
        research_ref="ch03#31",
        cwe="CWE-209",
        framework=("WSTG-ERRH-01", "WSTG-ERRH-02", "WSTG-CONF-02", "CWE-209"),
        compliance=("ISO-A.8.12",),
        severity="medium",
        estimated_requests=3,
    )

    paths_key = "debug_paths"
    default_paths = ("/arachne-debug-probe/", "/arachne-debug-probe")
    # Laravel's debug error page is served *as* the 404 for an unmatched route, so the 404 is
    # the positive answer and must be evaluated rather than skipped.
    ok_statuses = (404,)
    max_findings = 1
    finding_title = "Laravel debug error page disclosed ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        markers = _confirmed(
            page,
            ("ignition", "whoops", "app_debug", "laravel", "route list"),
            ("ignition", "whoops", "app_debug"),
        )
        if not markers:
            return None
        return _Hit(
            "debug-page-disclosed", {"markers": markers, "status": page.status}, confidence=0.8
        )


class LaravelIgnitionSurface(_ServerProbe, WebCheck, Module):
    """``m3.laravel-ignition-surface`` — the Ignition debug endpoints answer (ch03#31)."""

    section = "laravel"
    names = _SERVER_NAMES[section]
    metadata = _meta(
        "laravel-ignition-surface",
        "Laravel Ignition debug endpoints served",
        "Reports when the Ignition debug component's endpoints (/\\_ignition/health-check and "
        "the /\\_ignition index) answer an anonymous GET with Ignition's own document (the "
        "can_execute_commands health payload or the Ignition landing markup) instead of a 404. "
        "The route set belongs to local development; the check reports that it is reachable "
        "and sends no request that would evaluate a solution. Read-only GET probes.",
        research_ref="ch03#31",
        cwe="CWE-497",
        framework=("WSTG-CONF-05", "WSTG-ERRH-01", "CWE-497"),
        severity="low",
        estimated_requests=4,
    )

    paths_key = "ignition_paths"
    default_paths = ("/_ignition/health-check", "/_ignition/")
    max_findings = 2
    finding_title = "Laravel Ignition endpoint served ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        if "_ignition" not in path:
            return None
        lowered = page.body.lower()
        # Ignition's own health payload names can_execute_commands; its landing page names
        # Ignition. Either is the component's own document, never a generic error page.
        if "can_execute_commands" not in lowered and "ignition" not in lowered:
            return None
        markers = _markers_found(page.body, ("_ignition", "ignition", "can_execute_commands"))
        return _surface_hit("ignition-endpoint-served", markers)


# --------------------------------------------------------------------------- Tomcat
class TomcatManagerSurface(_ServerProbe, WebCheck, Module):
    """``m3.tomcat-manager-surface`` — the Tomcat manager answers (ch03#19)."""

    section = "tomcat"
    names = _SERVER_NAMES[section]
    body_must_name = False
    metadata = _meta(
        "tomcat-manager-surface",
        "Tomcat Manager application reachable",
        "Reports when the Tomcat manager application answers an anonymous client with its own "
        'Basic challenge (WWW-Authenticate: Basic realm="Tomcat Manager Application") or with '
        "its own manager page (the /manager/html deployment console). The finding reports that "
        "the surface is reachable: the check sends no credential and attempts no login. "
        "Read-only GET probes.",
        research_ref="ch03#19",
        cwe="CWE-200",
        framework=("WSTG-CONF-05", "WSTG-INFO-06", "ATT&CK-T1592.002", "CWE-200"),
        compliance=("ISO-A.8.12", "CSF-ID.AM-02"),
        severity="medium",
        estimated_requests=5,
    )

    paths_key = "manager_paths"
    default_paths = ("/manager/html", "/manager/status", "/manager/text/list")
    # Tomcat answers an anonymous manager request with its own 401 challenge: that is the
    # detection, not a refusal.
    ok_statuses = (401,)
    max_findings = 2
    finding_title = "Tomcat Manager reachable ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        if _realm_names_tomcat(page, "manager"):
            return _Hit(
                "manager-application-challenge",
                {
                    "realm": _header(page, "www-authenticate"),
                    "default_credential_surface": True,
                    "credential_test_sent": False,
                },
                confidence=0.8,
            )
        lowered = page.body.lower()
        if "manager" not in path:
            return None
        markers = _markers_found(
            page.body, ("tomcat manager", "manager application", "/manager/html")
        )
        if "tomcat manager" not in lowered and "/manager/html" not in lowered:
            return None
        return _admin_login_hit(markers, "manager-application-served")


class TomcatHostManagerSurface(_ServerProbe, WebCheck, Module):
    """``m3.tomcat-host-manager-surface`` — the host-manager answers (ch03#19)."""

    section = "tomcat"
    names = _SERVER_NAMES[section]
    body_must_name = False
    metadata = _meta(
        "tomcat-host-manager-surface",
        "Tomcat Host Manager application reachable",
        "Reports when the Tomcat host-manager application answers an anonymous client with its "
        'own Basic challenge (WWW-Authenticate: Basic realm="Tomcat Host Manager '
        'Application") or with its own virtual-host page. The finding reports that the surface '
        "is reachable: the check sends no credential and attempts no login. Read-only GET "
        "probes.",
        research_ref="ch03#19",
        cwe="CWE-200",
        framework=("WSTG-CONF-05", "WSTG-INFO-06", "ATT&CK-T1592.002", "CWE-200"),
        compliance=("ISO-A.8.12",),
        severity="medium",
        estimated_requests=4,
    )

    paths_key = "host_manager_paths"
    default_paths = ("/host-manager/html", "/host-manager/", "/host-manager/text/list")
    ok_statuses = (401,)
    max_findings = 2
    finding_title = "Tomcat Host Manager reachable ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        if _realm_names_tomcat(page, "host"):
            return _Hit(
                "host-manager-application-challenge",
                {
                    "realm": _header(page, "www-authenticate"),
                    "default_credential_surface": True,
                    "credential_test_sent": False,
                },
                confidence=0.8,
            )
        if "host-manager" not in path:
            return None
        lowered = page.body.lower()
        markers = _markers_found(
            page.body, ("tomcat virtual host manager", "host manager", "virtual host")
        )
        if "virtual host" not in lowered and "host manager" not in lowered:
            return None
        return _surface_hit("host-manager-application-served", markers)


class TomcatExamplesSurface(_ServerProbe, WebCheck, Module):
    """``m3.tomcat-examples-surface`` — the default Tomcat webapps are served (ch03#31)."""

    section = "tomcat"
    names = _SERVER_NAMES[section]
    metadata = _meta(
        "tomcat-examples-surface",
        "Tomcat default example applications reachable",
        "Reports when the example and documentation web applications Tomcat ships by default "
        "(/examples/ and /docs/) answer an anonymous GET with the project's own pages, naming "
        "Apache Tomcat. The documentation application publishes the server version and the "
        "examples application ships sample servlets; both belong to a stock installation and "
        "are removed in a hardened one. Read-only GET probes.",
        research_ref="ch03#31",
        cwe="CWE-200",
        framework=("WSTG-CONF-05", "WSTG-INFO-02", "CWE-200"),
        severity="low",
        estimated_requests=4,
    )

    paths_key = "examples_paths"
    default_paths = ("/examples/", "/examples/servlets/", "/docs/")
    max_findings = 2
    finding_title = "Tomcat example application reachable ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        lowered = page.body.lower()
        markers = _markers_found(
            page.body,
            ("apache tomcat", "servlet and jsp examples", "tomcat examples", "documentation index"),
        )
        if "apache tomcat" not in lowered:
            return None
        if not any(token in lowered for token in ("example", "documentation")):
            return None
        return _surface_hit("default-webapp-served", markers)


# --------------------------------------------------------------------------- JBoss
class JbossJmxConsole(_ServerProbe, WebCheck, Module):
    """``m3.jboss-jmx-console`` — the JBoss JMX console answers (ch03#19)."""

    section = "jboss"
    names = _SERVER_NAMES[section]
    metadata = _meta(
        "jboss-jmx-console",
        "JBoss JMX console reachable",
        "Reports when the JBoss JMX console (/jmx-console/ and its HtmlAdaptor) answers an "
        "anonymous GET with the console's own page: the response names the JMX agent view and "
        "the issuing JBoss server. The console exposes every registered MBean operation, and "
        "the check reports that it is reachable without sending any MBean invocation. "
        "Read-only GET probes.",
        research_ref="ch03#19",
        cwe="CWE-200",
        framework=("WSTG-CONF-05", "WSTG-INFO-06", "ATT&CK-T1592.002", "CWE-200"),
        compliance=("ISO-A.8.12", "CSF-ID.AM-02"),
        severity="medium",
        estimated_requests=4,
    )

    paths_key = "jmx_console_paths"
    default_paths = ("/jmx-console/", "/jmx-console/HtmlAdaptor")
    max_findings = 1
    finding_title = "JBoss JMX console reachable ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        tokens = ("jmx agent view", "htmladaptor", "jmx-console")
        markers = _confirmed(page, tokens, tokens)
        if not markers:
            return None
        return _surface_hit("jmx-console-served", markers)


class JbossWebConsole(_ServerProbe, WebCheck, Module):
    """``m3.jboss-web-console`` — the JBoss web console answers (ch03#19)."""

    section = "jboss"
    names = _SERVER_NAMES[section]
    metadata = _meta(
        "jboss-web-console",
        "JBoss web console reachable",
        "Reports when the JBoss web console (/web-console/ and its ServerInfo view) answers an "
        "anonymous GET with the console's own page or the ServerInfo JSP's content, naming the "
        "issuing JBoss server. The page publishes the server's configuration and deployment "
        "inventory; the check reports reachability and reads nothing further. Read-only GET "
        "probes.",
        research_ref="ch03#19",
        cwe="CWE-200",
        framework=("WSTG-CONF-05", "WSTG-INFO-06", "CWE-200"),
        severity="medium",
        estimated_requests=4,
    )

    paths_key = "web_console_paths"
    default_paths = ("/web-console/", "/web-console/ServerInfo.jsp")
    max_findings = 1
    finding_title = "JBoss web console reachable ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        tokens = ("web console", "serverinfo", "web-console")
        markers = _confirmed(page, tokens, tokens)
        if not markers:
            return None
        return _surface_hit("web-console-served", markers)


class JbossAdminConsole(_ServerProbe, WebCheck, Module):
    """``m3.jboss-admin-console`` — the JBoss administration console answers (ch03#19)."""

    section = "jboss"
    names = _SERVER_NAMES[section]
    metadata = _meta(
        "jboss-admin-console",
        "JBoss administration console reachable",
        "Reports when the JBoss administration console (/admin-console/) answers an anonymous "
        "GET with the console's own page or its login view, naming the issuing JBoss server. "
        "The console is the server's management surface; the check reports that it is reachable "
        "and sends no credential and attempts no login. Read-only GET probes.",
        research_ref="ch03#19",
        cwe="CWE-200",
        framework=("WSTG-CONF-05", "WSTG-IDNT-04", "ATT&CK-T1592.002", "CWE-200"),
        severity="medium",
        estimated_requests=4,
    )

    paths_key = "admin_console_paths"
    default_paths = ("/admin-console/", "/admin-console/login.seam")
    max_findings = 1
    finding_title = "JBoss administration console reachable ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        tokens = ("administrator console", "admin console", "management console", "login.seam")
        markers = _confirmed(page, tokens, tokens)
        if not markers:
            return None
        return _admin_login_hit(markers, "administration-console-served")


# --------------------------------------------------------------------------- WebLogic
class WebLogicConsole(_ServerProbe, WebCheck, Module):
    """``m3.weblogic-console`` — the WebLogic administration console answers (ch03#19)."""

    section = "weblogic"
    names = _SERVER_NAMES[section]
    metadata = _meta(
        "weblogic-console",
        "WebLogic administration console reachable",
        "Reports when the Oracle WebLogic Server administration console (/console/ and its "
        "login form) answers an anonymous GET with the console's own page or login markup "
        "(the j_security_check form action), naming the issuing server. The console is the "
        "domain's management surface; the check reports that it is reachable and sends no "
        "credential and attempts no login. Read-only GET probes.",
        research_ref="ch03#19",
        cwe="CWE-200",
        framework=("WSTG-CONF-05", "WSTG-IDNT-04", "ATT&CK-T1592.002", "CWE-200"),
        compliance=("ISO-A.8.12", "CSF-ID.AM-02"),
        severity="medium",
        estimated_requests=4,
    )

    paths_key = "console_paths"
    default_paths = ("/console/", "/console/login/LoginForm.jsp")
    max_findings = 1
    finding_title = "WebLogic administration console reachable ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        required = ("administration console", "j_security_check", "loginform.jsp")
        markers = _confirmed(
            page,
            ("administration console", "j_security_check", "loginform.jsp", "weblogic server"),
            required,
        )
        if not markers:
            return None
        return _admin_login_hit(markers, "administration-console-served")


class WebLogicUddiExplorer(_ServerProbe, WebCheck, Module):
    """``m3.weblogic-uddi-explorer`` — the UDDI explorer answers (ch03#31)."""

    section = "weblogic"
    names = _SERVER_NAMES[section]
    metadata = _meta(
        "weblogic-uddi-explorer",
        "WebLogic UDDI explorer reachable",
        "Reports when the UDDI explorer application WebLogic deploys by default "
        "(/uddiexplorer/) answers an anonymous GET with its own search page, naming WebLogic "
        "and the UDDI registry surface. The application belongs to the server's default "
        "deployment and is removed in a hardened one. Read-only GET probes.",
        research_ref="ch03#31",
        cwe="CWE-200",
        framework=("WSTG-CONF-05", "WSTG-INFO-06", "CWE-200"),
        severity="medium",
        estimated_requests=4,
    )

    paths_key = "uddi_paths"
    default_paths = ("/uddiexplorer/", "/uddiexplorer/SearchPublicRegistries.jsp")
    max_findings = 1
    finding_title = "WebLogic UDDI explorer reachable ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        lowered = page.body.lower()
        markers = _markers_found(
            page.body, ("uddi explorer", "uddiexplorer", "searchpublicregistries")
        )
        if "uddi" not in lowered:
            return None
        return _surface_hit("uddi-explorer-served", markers)


class WebLogicWsat(_ServerProbe, WebCheck, Module):
    """``m3.weblogic-wsat`` — the wls-wsat component answers (ch03#31)."""

    section = "weblogic"
    names = _SERVER_NAMES[section]
    metadata = _meta(
        "weblogic-wsat",
        "WebLogic wls-wsat component reachable",
        "Reports when the wls-wsat component WebLogic Server deploys by default (/wls-wsat/) "
        "answers an anonymous GET with the component's own page or endpoint listing, naming "
        "the Web Services Atomic Transaction surface. The component is a SOAP endpoint; the "
        "check establishes that it is deployed and publishes no SOAP message, so no service is "
        "invoked. Read-only GET probes.",
        research_ref="ch03#31",
        cwe="CWE-200",
        framework=("WSTG-CONF-05", "WSTG-INFO-06", "ATT&CK-T1592.002", "CWE-200"),
        severity="medium",
        estimated_requests=4,
    )

    paths_key = "wsat_paths"
    default_paths = ("/wls-wsat/", "/wls-wsat/CoordinatorPortType")
    max_findings = 1
    finding_title = "WebLogic wls-wsat component reachable ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        lowered = page.body.lower()
        markers = _markers_found(
            page.body, ("wls-wsat", "atomic transaction", "coordinatorporttype", "webservices")
        )
        if "wls-wsat" not in lowered and "atomic transaction" not in lowered:
            return None
        return _surface_hit("wsat-component-served", markers)


# --------------------------------------------------------------------------- ColdFusion
class ColdFusionAdministrator(_ServerProbe, WebCheck, Module):
    """``m3.coldfusion-administrator`` — the CFIDE administrator answers (ch03#19)."""

    section = "coldfusion"
    names = _SERVER_NAMES[section]
    metadata = _meta(
        "coldfusion-administrator",
        "ColdFusion administrator console reachable",
        "Reports when the ColdFusion administrator (/CFIDE/administrator/ and its index) "
        "answers an anonymous GET with the administrator's own page, naming the ColdFusion "
        "administrator and the CFIDE tree. The console exposes the server's datasources, "
        "scheduled tasks and mappings; the check reports that it is reachable and sends no "
        "credential and attempts no login. Read-only GET probes.",
        research_ref="ch03#19",
        cwe="CWE-200",
        framework=("WSTG-CONF-05", "WSTG-IDNT-04", "ATT&CK-T1592.002", "CWE-200"),
        compliance=("ISO-A.8.12", "CSF-ID.AM-02"),
        severity="medium",
        estimated_requests=4,
    )

    paths_key = "administrator_paths"
    default_paths = ("/CFIDE/administrator/", "/CFIDE/administrator/index.cfm")
    max_findings = 1
    finding_title = "ColdFusion administrator reachable ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        lowered = page.body.lower()
        markers = _markers_found(
            page.body, ("coldfusion administrator", "cfide", "administrator login")
        )
        if "cfide" not in lowered and "coldfusion" not in lowered:
            return None
        if "administrator" not in lowered:
            return None
        return _admin_login_hit(markers, "administrator-console-served")


class ColdFusionScriptsDirectory(_ServerProbe, WebCheck, Module):
    """``m3.coldfusion-scripts-directory`` — the CFIDE scripts tree is listed (ch03#31)."""

    section = "coldfusion"
    names = _SERVER_NAMES[section]
    metadata = _meta(
        "coldfusion-scripts-directory",
        "ColdFusion CFIDE scripts directory listed",
        "Reports when the ColdFusion CFIDE scripts tree (/CFIDE/scripts/) answers an anonymous "
        "GET with a directory index or one of the editor components it bundles (the FCKeditor "
        "file-manager connector), naming the CFIDE path. The tree is served by the "
        "installation's web server and is removed in a hardened one. Read-only GET probes.",
        research_ref="ch03#31",
        cwe="CWE-548",
        framework=("WSTG-CONF-04", "WSTG-CONF-03", "CWE-548"),
        severity="medium",
        estimated_requests=4,
    )

    paths_key = "scripts_paths"
    default_paths = (
        "/CFIDE/scripts/",
        "/CFIDE/scripts/ajax/FCKeditor/editor/filemanager/browser/default/browser.html",
    )
    max_findings = 2
    finding_title = "ColdFusion CFIDE scripts tree exposed ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        lowered = page.body.lower()
        if "cfide" not in lowered:
            return None
        markers = _markers_found(
            page.body, ("index of /cfide", "directory listing", "fckeditor", "cfide/scripts")
        )
        if not any(
            token in lowered
            for token in ("index of /cfide", "directory listing", "fckeditor", "cfide/scripts")
        ):
            return None
        return _surface_hit("scripts-tree-exposed", markers)


class ColdFusionVersionDisclosure(_ServerProbe, WebCheck, Module):
    """``m3.coldfusion-version-disclosure`` — the version is published (ch03#31)."""

    section = "coldfusion"
    names = _SERVER_NAMES[section]
    metadata = _meta(
        "coldfusion-version-disclosure",
        "ColdFusion version disclosed",
        "Reports when the ColdFusion administrator's own pages publish the server's version "
        "(the administrator footer's build string), naming ColdFusion. A version is a "
        "fingerprint and is never a severity on its own (FP-3): the check reports the version "
        "and leaves the CVE correlation to the intelligence stage. Read-only GET probes.",
        research_ref="ch03#31",
        cwe="CWE-200",
        framework=("WSTG-INFO-02", "WSTG-INFO-08", "CWE-200"),
        severity="low",
        estimated_requests=4,
    )

    paths_key = "version_paths"
    default_paths = (
        "/CFIDE/administrator/enter.cfm",
        "/CFIDE/administrator/index.cfm",
        "/CFIDE/administrator/",
    )
    max_findings = 2
    finding_title = "ColdFusion version disclosed ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        return _version_hit(
            page,
            ctx,
            self.section,
            r"ColdFusion\s+(?:Administrator\s+)?(?:version\s+)?([0-9][0-9.]*)",
        )


# --------------------------------------------------------------------------- IIS
class IisShortNameDisclosure(_ServerProbe, WebCheck, Module):
    """``m3.iis-short-name-disclosure`` — IIS answers a short-name probe (ch03#31)."""

    section = "iis"
    names = _SERVER_NAMES[section]
    body_must_name = False
    metadata = _meta(
        "iis-short-name-disclosure",
        "IIS 8.3 short-name behaviour observable",
        "Reports when IIS answers a request for a tilde short-name path with its own 400 error "
        "page ('HTTP Error 400. The request is badly formed.') and a Server header naming IIS, "
        "while a request for an equally non-existent long name answers 404. That difference is "
        "the observable 8.3 short-name behaviour the tilde trick measures; the check reports "
        "the probe and the server banner and enumerates no name it did not probe. Read-only GET "
        "probes.",
        research_ref="ch03#31",
        cwe="CWE-200",
        framework=("WSTG-CONF-03", "WSTG-INFO-02", "CWE-200"),
        severity="medium",
        estimated_requests=4,
    )

    paths_key = "short_name_paths"
    default_paths = ("/a~1.aspx", "/b~1.txt", "/c~1/")
    # IIS's answer to a malformed tilde request is its own 400: that is the detection.
    ok_statuses = (400,)
    max_findings = 2
    finding_title = "IIS short-name behaviour observed ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        if page.status != 400:
            return None
        if "~" not in path:
            return None
        lowered = page.body.lower()
        server = (_header(page, "server") or "").lower()
        iis_page = "badly formed" in lowered and "400" in lowered
        if not iis_page or ("iis" not in server and "iis" not in lowered):
            return None
        return _Hit(
            "short-name-behaviour-observed",
            {
                "status": page.status,
                "server": _header(page, "server"),
                "markers": _markers_found(page.body, ("badly formed", "http error 400")),
            },
            confidence=0.7,
        )


class IisTraceViewer(_ServerProbe, WebCheck, Module):
    """``m3.iis-trace-viewer`` — the ASP.NET trace viewer answers (ch03#31)."""

    section = "iis"
    names = _SERVER_NAMES[section]
    metadata = _meta(
        "iis-trace-viewer",
        "ASP.NET trace viewer served",
        "Reports when the ASP.NET trace viewer (/trace.axd) answers an anonymous GET with its "
        "own page: the response carries the viewer's own headings (Requests to this "
        "Application, Trace Information) and names the .NET runtime that serves it. With "
        "tracing enabled the page publishes every recent request's form, cookie and server "
        "variable data. Read-only GET probes.",
        research_ref="ch03#31",
        cwe="CWE-497",
        framework=("WSTG-CONF-05", "WSTG-ERRH-01", "CWE-497"),
        compliance=("ISO-A.8.12",),
        severity="medium",
        estimated_requests=3,
    )

    paths_key = "trace_paths"
    default_paths = ("/trace.axd", "/Trace.axd")
    max_findings = 1
    finding_title = "ASP.NET trace viewer served ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        lowered = page.body.lower()
        markers = _markers_found(
            page.body, ("requests to this application", "trace information", "trace.axd")
        )
        if "requests to this application" not in lowered:
            return None
        if "trace information" not in lowered and "trace.axd" not in lowered:
            return None
        return _surface_hit("trace-viewer-served", markers, confidence=0.8)


class IisLegacyPasswordSurface(_ServerProbe, WebCheck, Module):
    """``m3.iis-legacy-password-surface`` — the legacy IIS password UI answers (ch03#19)."""

    section = "iis"
    names = _SERVER_NAMES[section]
    metadata = _meta(
        "iis-legacy-password-surface",
        "IIS legacy password-change surface reachable",
        "Reports when the legacy IIS password-change components (/iisadmpwd/ and its .htr "
        "handlers, /scripts/iisadmin/) answer an anonymous GET with the Internet Services "
        "Administrator's own page rather than a 404. The components belong to retired IIS "
        "releases and a current installation removes them; the check reports that they are "
        "served and submits no password. Read-only GET probes.",
        research_ref="ch03#19",
        cwe="CWE-200",
        framework=("WSTG-CONF-04", "WSTG-CONF-05", "ATT&CK-T1592.002", "CWE-200"),
        severity="medium",
        estimated_requests=4,
    )

    paths_key = "legacy_password_paths"
    default_paths = ("/iisadmpwd/aexp2b.asp", "/iisadmpwd/achg.htr", "/scripts/iisadmin/ism.dll")
    max_findings = 2
    finding_title = "IIS legacy password surface reachable ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        lowered = page.body.lower()
        markers = _markers_found(
            page.body,
            ("internet services administrator", "iisadmpwd", "password administrator", "iisadmin"),
        )
        if "iisadmpwd" not in lowered and "internet services administrator" not in lowered:
            return None
        return _admin_login_hit(markers, "legacy-password-surface-served")


#: Every check the WP-27 family registers, in the order the registry selects them.
AppServerChecks: tuple[type[Module], ...] = (
    SpringBootActuatorIndex,
    SpringBootActuatorEnv,
    SpringBootHeapdump,
    DjangoDebugPage,
    DjangoDebugToolbar,
    DjangoMediaListing,
    RailsInfoProperties,
    RailsInfoRoutes,
    LaravelDebugPage,
    LaravelIgnitionSurface,
    TomcatManagerSurface,
    TomcatHostManagerSurface,
    TomcatExamplesSurface,
    JbossJmxConsole,
    JbossWebConsole,
    JbossAdminConsole,
    WebLogicConsole,
    WebLogicUddiExplorer,
    WebLogicWsat,
    ColdFusionAdministrator,
    ColdFusionScriptsDirectory,
    ColdFusionVersionDisclosure,
    IisShortNameDisclosure,
    IisTraceViewer,
    IisLegacyPasswordSurface,
)
