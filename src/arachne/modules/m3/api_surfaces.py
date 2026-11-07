"""WP-28 · API and modern web surfaces (REQ-DET-021).

Twenty-four read-only L1 checks over the API and modern-web surface the requirement names:

* **OpenAPI / Swagger** — the v3 OpenAPI document, the v2 Swagger document, the Swagger UI and
  ReDoc browsing interfaces, the springfox resource index, and an operation the published
  document declares answering an *anonymous* GET (the "unauthenticated invocation" half of the
  scope item);
* **GraphQL** — introspection over an anonymous GET, field-suggestion disclosure on a wrong
  field name, the GraphiQL/Playground IDE, and the mutation surface the schema advertises;
* **gRPC** — the browser-facing gRPC surface: the Connect protocol's side-effect-free
  ``GET`` form of a service method, and the gRPC-Web CORS preflight;
* **WebSocket** — origin handling: the ``null`` origin, a sibling subdomain of the target's own
  host, and an origin that merely *ends with* the target's host (a naive suffix match);
* **Serverless and edge functions** — a Netlify function, a Vercel function route, a Google
  Cloud Functions invocation, an unauthenticated OpenFaaS gateway, and an edge-function bundle's
  source map;
* **CORS** — a trusted sibling subdomain and a suffix-spoofed origin on a simple request, plus
  two preflight readings: the methods and the request headers the policy authorizes.

**Read-only, and read-only *by construction*.** Every request is a ``GET`` or an ``OPTIONS``
(HTTP's own safe method, RFC 9110 §9.3.7); nothing here sends a body, names a state-changing
verb, or attempts a GraphQL mutation. The GraphQL checks read the schema with a *query*
operation and report the mutation *names* it advertises — never sending one, which is the
requirement's own reading ("a readable schema and a reachable mutation name are enough at L1").
Every request goes out on the client's anonymous path (S29): a probe whose whole claim is
"reachable without credentials" must not inherit a session the crawl picked up.

**An unauthenticated answer is the signal, never a credential test.** No check sends a
credential, attempts a login, or makes any claim about an account. A deployment that publishes
its API documentation *deliberately, behind authentication* answers ``401`` with its own
challenge; every check treats that as a refusal and reports nothing — which is exactly the
decoy the requirement names.

**The decoy rule, enforced twice.** No check fires on a status code or a bare body word:

1. every signal requires a *structural* fact of the artefact itself — the document's own
   ``openapi``/``swagger`` key beside its ``paths`` object, the introspection result's
   ``__schema`` object, a completed RFC 6455 handshake (``101`` plus ``Sec-WebSocket-Accept``),
   the platform's own function-invocation response header, a source-map document carrying
   ``"version": 3`` and ``sources``, or the ``Access-Control-Allow-*`` triple a preflight
   actually needs;
2. the HTML browsing interfaces additionally require the body to **name their own tool**
   (Swagger UI, ReDoc, GraphiQL/Playground), so a WAF block page that names the tool while
   carrying none of its markup cannot fire one.

Twenty-one of the twenty-four checks carry their own **structural** shape instead of a name —
only the three HTML interfaces require the body to name their tool — and each shape is
documented at its class: the two JSON documents (a version key beside a non-empty ``paths``
object), the springfox resource index (a list whose entries name a group and its document URL),
the three ``__schema`` shapes the introspection results carry, the Connect method answer (a JSON
body on a ``/grpc.`` route), the four platform function response headers, the source-map
document (``"version": 3`` plus a non-empty ``sources``), the completed RFC 6455 handshake
(``101`` plus ``Sec-WebSocket-Accept``) and the CORS/preflight header triples.

**Severity is not raised by a banner.** Introspection is left on deliberately in many
development deployments, so it is ``medium`` and so is the document exposure around it; the
suggestion leak, the IDE, the mutation-name inventory, the function-endpoint headers and the
source map are ``low`` — each is a *signal*, and a rule in the shipped corpus is what raises a
finding. No check claims more than the answer it read.

**Decoys.** ``tests/lab/api_lab.py`` serves each of the six surfaces from its own origin in
three modes. The requirement's own decoy is the ``production`` mode: a conformant deployment
whose documentation is published deliberately *behind authentication*. The package adds a
``waf`` mode per surface — the block page echoes the requested path and names the platform, the
"block page that contains the payload" archetype of the decoy catalogue
(``docs/plugin-developer-guide.md`` §2.1) — and the six vulnerable installations, which are
decoys for one another's checks.
"""

from __future__ import annotations

import json
import re
from collections.abc import AsyncIterator, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, ClassVar
from urllib.parse import quote

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
    "ApiSurfaceChecks",
    "CorsPreflightHeaders",
    "CorsPreflightMethods",
    "CorsSubdomainTrust",
    "CorsSuffixSpoof",
    "EdgeFunctionSourceMap",
    "GcfFunctionEndpoint",
    "GraphqlIdeExposed",
    "GraphqlIntrospectionGet",
    "GraphqlMutationSurface",
    "GraphqlSuggestionDisclosure",
    "GrpcConnectEndpoint",
    "GrpcWebPreflight",
    "NetlifyFunctionEndpoint",
    "OpenApiDocumentExposed",
    "OpenApiOperationUnauth",
    "OpenfaasGatewayExposed",
    "RedocExposed",
    "SwaggerDocumentExposed",
    "SwaggerResourcesIndex",
    "SwaggerUiExposed",
    "VercelFunctionEndpoint",
    "WebSocketOriginNull",
    "WebSocketOriginSibling",
    "WebSocketOriginSuffixSpoof",
]

#: The family tag every artifact carries, so one heuristic rule can cover the whole set.
FAMILY = "api-modern"

#: Bodies that mean "the server refused the call" rather than "here is the operation's answer".
#: Used by the unauthenticated-invocation check: a 2xx body that still says one of these is not
#: an answer the anonymous client may read.
_AUTH_REFUSAL_MARKERS: tuple[str, ...] = (
    "unauthorized",
    "authentication required",
    "invalid api key",
    "login required",
    "please sign in",
    "access denied",
)

#: A path template's placeholder (``/users/{id}``): substituted with this before probing, so the
#: probe is a concrete, benign URL rather than a literal brace in a path.
_PARAM_PLACEHOLDER_RE = re.compile(r"\{[^/{}]+\}")

#: A beneficial substitution for a path template parameter.
_PARAM_VALUE = "1"

#: The RFC 6455 example key from the standard itself — an inert nonce, not a secret.
_WS_KEY = "dGhlIHNhbXBsZSBub25jZQ=="

#: The request headers that are specific to a browser-facing gRPC call. A preflight that
#: authorizes one of these is a gRPC-Web policy, which is what tells this check apart from a
#: generic CORS policy that merely reflects an origin.
_GRPC_WEB_HEADERS: frozenset[str] = frozenset(
    {"*", "x-grpc-web", "grpc-timeout", "grpc-encoding", "connect-protocol-version"}
)

#: The complete upgrade handshake every WebSocket-origin check sends. The checks differ only in
#: the ``Origin`` header, which is the whole claim.
_WS_UPGRADE_HEADERS: Mapping[str, str] = {
    "Connection": "Upgrade",
    "Upgrade": "websocket",
    "Sec-WebSocket-Version": "13",
    "Sec-WebSocket-Key": _WS_KEY,
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
    active: bool = False,
) -> CheckMetadata:
    """Build one check's metadata: L1, safe, default-on, URL-scoped (the WP-28 contract).

    ``active`` is set only for the three checks whose probe is an ``OPTIONS`` preflight. The
    corpus's own rule for the catalogue's ``requires_active_checks`` flag is "anything beyond a
    plain GET", and WP-25 gated its one OPTIONS probe (``m3.wp-cron-surface``) the same way, so
    the flag and the type travel together here too (F-01-09). Every check remains L1: an
    ``OPTIONS`` is a safe request and changes nothing.
    """
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
        type="active" if active else "hybrid",
        safe=True,
        verifiable=False,
        enabled_by_default=True,
        proof=ProofLevel.L1,
        estimated_requests=estimated_requests,
        requires_active_checks=active,
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


def _keys(document: Mapping[str, Any], *, limit: int = 12) -> list[str]:
    """The top-level key names of a JSON document, bounded (names, never values)."""
    return sorted(str(key) for key in document)[:limit]


def _host_of(origin: str) -> str:
    """The hostname of an origin string (no scheme, no port)."""
    return origin.split("//", 1)[-1].split("/", 1)[0].split(":", 1)[0]


def _scheme_of(origin: str) -> str:
    return origin.split("://", 1)[0] if "://" in origin else "https"


class _ApiProbe:
    """The shared shape of the family: bounded path probes on the asset's origin.

    A concrete check is declared ``class X(_ApiProbe, WebCheck, Module)`` and sets its
    ``metadata`` plus the class attributes below. Every request goes through the shared scoped
    client on the **anonymous** path (S29), and a response the server refuses (4xx/5xx, except
    the statuses the check declares as the component's own answer) or renders as its own
    not-found page is skipped — so a check fires only on a distinct, successful answer carrying
    the structural fact its signal requires.

    This is a plain mixin rather than a :class:`~arachne.modules.base.Module` subclass: the base
    refuses to be created without metadata, and a family base has none of its own.
    """

    #: Declared here so the shared ``run`` can read it; every concrete check supplies it.
    metadata: ClassVar[CheckMetadata]

    #: The payload-corpus section for this surface (``api_openapi``, ``graphql_api``, ...).
    section: ClassVar[str] = ""
    #: The tool's own name(s), lowercase; the body must carry one for the HTML UI checks.
    names: ClassVar[tuple[str, ...]] = ()
    #: True only for the checks whose evidence is a *name* the body must carry.
    body_must_name: ClassVar[bool] = False
    #: False only for a check whose positive answer *is* the installation's own 404 rendering.
    treat_as_not_found: ClassVar[bool] = True
    #: The ``<section>:`` key holding this check's path list in the payload corpus.
    paths_key: ClassVar[str] = ""
    #: Fallback paths when the corpus key is absent (an operator-supplied corpus).
    default_paths: ClassVar[tuple[str, ...]] = ()
    #: Non-2xx statuses this check still evaluates: the surface's own answer to a probe.
    ok_statuses: ClassVar[tuple[int, ...]] = ()
    #: How many findings one run reports (one root cause, bounded output).
    max_findings: ClassVar[int] = 1
    #: The request method. ``GET`` everywhere but the three OPTIONS preflight checks.
    method: ClassVar[str] = "GET"
    #: The candidate title; ``{path}`` is the probed path.
    finding_title: ClassVar[str] = "API surface exposed ({path})"

    def paths(self, ctx: CheckContext) -> tuple[str, ...]:
        return _paths(ctx, self.section, self.paths_key, self.default_paths)

    def url_for(self, ctx: CheckContext, origin: str, path: str) -> str:
        """The URL this check fetches for ``path`` (the joined URL by default)."""
        return _full_url(origin, path)

    def headers(self, ctx: CheckContext, path: str) -> Mapping[str, str] | None:
        """Extra request headers for ``path`` (none by default)."""
        return None

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
                "no path inventory configured",
                detail="the payload corpus names no probe path for this check",
            )
            return
        not_found = await _not_found(ctx, origin) if self.treat_as_not_found else None
        findings = 0
        refused = 0
        for path in paths:
            if findings >= self.max_findings:
                break
            url = self.url_for(ctx, origin, path)
            page = await _fetch(ctx, url, method=self.method, headers=self.headers(ctx, path))
            if page is None:
                continue
            if page.status >= 400 and page.status not in self.ok_statuses:
                refused += 1
                continue
            if not_found is not None and _looks_like_not_found(page, not_found):
                continue
            if self.body_must_name and _contains_any(page.body, self.names) is None:
                # A block page (or another surface's installation) that names the tool while
                # carrying none of its markup is not this tool.
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
                    "surface": self.section,
                    "check": self.metadata.name,
                    "path": path,
                    "method": self.method,
                    "status": page.status,
                    "content_type": page.content_type,
                    "bytes": page.body_length,
                    "origin": origin,
                    # The claim is "an anonymous client reached this", never "a credential
                    # worked": no credential is ever sent, and none is claimed.
                    "anonymous": True,
                    "credential_test_sent": False,
                    **dict(hit.facts),
                },
                exchanges=(exchange_from_page(page),),
                confidence=hit.confidence,
                detail=f"{url} answered HTTP {page.status} (anonymous {self.method})",
                source=url,
            )
        if not findings:
            label = self.metadata.name.replace("-", " ")
            yield ctx.clean(
                f"no {label} surface found",
                detail=(
                    f"probed {len(paths)} path(s) anonymously on {origin}"
                    + (f"; {refused} refused or blocked" if refused else "")
                ),
            )


async def _fetch(
    ctx: CheckContext,
    url: str,
    *,
    method: str = "GET",
    headers: Mapping[str, str] | None = None,
) -> Page | None:
    """One bounded anonymous probe as a :class:`Page` (``None`` when refused or failed)."""
    exchange = await safe_fetch(
        ctx, url, method=method, headers=headers, anonymous=True, follow_redirects=False
    )
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


def _permissive_acao(page: Page, origin: str) -> str | None:
    """The ``Access-Control-Allow-Origin`` value when it reflects ``origin`` or is ``*``."""
    acao = _header(page, "access-control-allow-origin")
    if acao is None:
        return None
    value = acao.strip()
    if value == origin or value == "*":
        return value
    return None


def _allow_list(page: Page, name: str) -> list[str]:
    """A comma-separated CORS list header as lowercase tokens."""
    raw = _header(page, name) or ""
    return [token.strip().lower() for token in raw.split(",") if token.strip()]


# --------------------------------------------------------------------------- OpenAPI / Swagger
def _document_paths(document: Mapping[str, Any], *, limit: int = 4) -> list[str]:
    """The GET-operation paths an OpenAPI/Swagger document declares, bounded and concrete."""
    paths = document.get("paths")
    if not isinstance(paths, Mapping):
        return []
    out: list[str] = []
    for raw_path, operations in paths.items():
        if not isinstance(raw_path, str) or not raw_path.startswith("/"):
            continue
        if not isinstance(operations, Mapping) or "get" not in operations:
            continue
        out.append(_PARAM_PLACEHOLDER_RE.sub(_PARAM_VALUE, raw_path))
        if len(out) >= limit:
            break
    return out


class OpenApiDocumentExposed(_ApiProbe, WebCheck, Module):
    """``m3.openapi-document-exposed`` — an OpenAPI 3 document is served anonymously (ch03#31)."""

    section = "api_openapi"
    metadata = _meta(
        "openapi-document-exposed",
        "OpenAPI document published without authentication",
        "Reports when a JSON document declaring an OpenAPI 3 specification — the document's own "
        "'openapi' version key beside its 'paths' object — is served to an anonymous client. "
        "The finding names the spec version and the operation paths the document declares, "
        "never a value. A deployment that publishes its documentation deliberately behind "
        "authentication answers a challenge and is not reported. Read-only GET probes.",
        research_ref="ch03#31",
        cwe="CWE-200",
        framework=("WSTG-APIT-01", "WSTG-INFO-06", "WSTG-CONF-05", "API9:2023", "CWE-200"),
        compliance=("ISO-A.8.12", "CSF-ID.AM-02"),
        severity="medium",
        estimated_requests=4,
    )

    paths_key = "document_paths"
    default_paths = ("/openapi.json", "/v3/api-docs", "/api-docs")
    max_findings = 1
    finding_title = "OpenAPI document served anonymously ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        document = _json_of(page)
        if not isinstance(document, Mapping):
            return None
        version = document.get("openapi")
        if not isinstance(version, str) or not version:
            return None
        operations = _document_paths(document)
        if not operations:
            # The 'paths' object is what makes this an API document rather than any JSON body
            # that happens to carry an 'openapi' key.
            return None
        return _Hit(
            "openapi-document-exposed",
            {
                "spec_version": version,
                "document_keys": _keys(document),
                "operation_paths": operations,
                "operation_count": len(operations),
            },
            confidence=0.85,
        )


class SwaggerDocumentExposed(_ApiProbe, WebCheck, Module):
    """``m3.swagger-document-exposed`` — a Swagger 2.0 document is served anonymously (ch03#31)."""

    section = "api_openapi"
    metadata = _meta(
        "swagger-document-exposed",
        "Swagger 2.0 document published without authentication",
        "Reports when a JSON document declaring the Swagger 2.0 specification — the document's "
        "own 'swagger' version key beside its 'paths' object — is served to an anonymous "
        "client. Swagger 2.0 is the pre-OpenAPI-3 generation and is still the live document of "
        "many published APIs; the finding names the version and the declared operation paths. "
        "Read-only GET probes.",
        research_ref="ch03#31",
        cwe="CWE-200",
        framework=("WSTG-APIT-01", "WSTG-INFO-06", "WSTG-CONF-05", "API9:2023", "CWE-200"),
        compliance=("ISO-A.8.12", "CSF-ID.AM-02"),
        severity="medium",
        estimated_requests=4,
    )

    paths_key = "v2_document_paths"
    default_paths = ("/swagger.json", "/v2/api-docs", "/swagger/v1/swagger.json")
    max_findings = 1
    finding_title = "Swagger 2.0 document served anonymously ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        document = _json_of(page)
        if not isinstance(document, Mapping):
            return None
        version = document.get("swagger")
        if not isinstance(version, str) or not version:
            return None
        operations = _document_paths(document)
        if not operations:
            return None
        return _Hit(
            "swagger-document-exposed",
            {
                "spec_version": version,
                "document_keys": _keys(document),
                "operation_paths": operations,
                "operation_count": len(operations),
            },
            confidence=0.85,
        )


class SwaggerUiExposed(_ApiProbe, WebCheck, Module):
    """``m3.swagger-ui-exposed`` — the Swagger UI browsing interface is served (ch03#31)."""

    section = "api_openapi"
    names = ("swagger", "openapi")
    body_must_name = True
    metadata = _meta(
        "swagger-ui-exposed",
        "Swagger UI interface served without authentication",
        "Reports when the Swagger UI browsing interface is served to an anonymous client: the "
        "HTML page carries Swagger UI's own bundle wiring ('swagger-ui' plus the SwaggerUIBundle "
        "or swagger-ui-init script it renders) and names the tool, which is how the interface "
        "is told apart from a page that merely links to one. An interactive console over an API "
        "surface is a discovery aid for whoever reaches it. Read-only GET probes.",
        research_ref="ch03#31",
        cwe="CWE-200",
        framework=("WSTG-APIT-01", "WSTG-INFO-06", "WSTG-CONF-05", "API9:2023", "CWE-200"),
        severity="low",
        estimated_requests=3,
    )

    paths_key = "ui_paths"
    default_paths = ("/swagger-ui/index.html", "/swagger-ui.html", "/swagger/")
    max_findings = 1
    finding_title = "Swagger UI served ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        if not page.is_html:
            return None
        markers = _markers_found(
            page.body,
            _markers(
                ctx,
                self.section,
                "ui_markers",
                ("swagger-ui", "swaggeruibundle", "swagger-ui-init", "swagger-ui-bundle"),
            ),
        )
        required = [marker for marker in markers if marker.startswith("swagger-ui")]
        if not required:
            return None
        return _Hit(
            "swagger-ui-served",
            {"markers": markers, "interface": "swagger-ui"},
            confidence=0.8,
        )


class RedocExposed(_ApiProbe, WebCheck, Module):
    """``m3.redoc-exposed`` — the ReDoc browsing interface is served (ch03#31)."""

    section = "api_openapi"
    names = ("redoc",)
    body_must_name = True
    metadata = _meta(
        "redoc-exposed",
        "ReDoc interface served without authentication",
        "Reports when the ReDoc API documentation interface is served to an anonymous client: "
        "the HTML page carries ReDoc's own renderer wiring (a redoc element or the "
        "redoc-standalone bundle) and names the tool. Like Swagger UI it turns a published "
        "document into a browsable console. Read-only GET probes.",
        research_ref="ch03#31",
        cwe="CWE-200",
        framework=("WSTG-APIT-01", "WSTG-INFO-06", "WSTG-CONF-05", "API9:2023", "CWE-200"),
        severity="low",
        estimated_requests=3,
    )

    paths_key = "redoc_paths"
    default_paths = ("/docs/", "/redoc", "/redoc.html")
    max_findings = 1
    finding_title = "ReDoc interface served ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        if not page.is_html:
            return None
        markers = _markers_found(
            page.body,
            _markers(
                ctx,
                self.section,
                "redoc_markers",
                ("<redoc", "redoc-standalone", "redoc.init", "redoc.min.js"),
            ),
        )
        if not markers:
            return None
        return _Hit("redoc-served", {"markers": markers, "interface": "redoc"}, confidence=0.8)


class SwaggerResourcesIndex(_ApiProbe, WebCheck, Module):
    """``m3.swagger-resources-index`` — the springfox resource index answers (ch03#31)."""

    section = "api_openapi"
    metadata = _meta(
        "swagger-resources-index",
        "API documentation resource index served",
        "Reports when the documentation resource index a springfox-style deployment publishes "
        "answers an anonymous client with its own JSON inventory: a list whose entries name a "
        "group and the URL its document is served from. The index is the map of every document "
        "the deployment publishes, and it is what makes the documents discoverable without "
        "guessing a path. Read-only GET probes.",
        research_ref="ch03#31",
        cwe="CWE-200",
        framework=("WSTG-APIT-01", "WSTG-INFO-06", "API9:2023", "CWE-200"),
        severity="low",
        estimated_requests=3,
    )

    paths_key = "resource_index_paths"
    default_paths = ("/swagger-resources", "/swagger-resources/configuration/ui")
    max_findings = 1
    finding_title = "API documentation resource index served ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        if "swagger-resources" not in path:
            return None
        document = _json_of(page)
        if not isinstance(document, list) or not document:
            return None
        groups = [
            str(entry.get("name"))
            for entry in document
            if isinstance(entry, Mapping)
            and entry.get("name") is not None
            and (entry.get("location") is not None or entry.get("url") is not None)
        ]
        if not groups:
            return None
        return _Hit(
            "resource-index-served",
            {"groups": groups[:8], "group_count": len(groups)},
            confidence=0.8,
        )


class OpenApiOperationUnauth(_ApiProbe, WebCheck, Module):
    """``m3.openapi-operation-unauth`` — a declared operation answers an anonymous GET (ch03#31).

    This is the family's one two-step check: it reads a published document, takes the read-only
    operations the document declares, and probes each with an anonymous ``GET``. A ``2xx`` answer
    that carries no authentication challenge and no refusal marker is the finding — the
    requirement's "unauthenticated invocation". Only operations the document itself declares
    *without* a body (``get``) are probed: nothing here names a write verb or sends a payload.
    The check is bounded to two documents and four operations per document.
    """

    section = "api_openapi"
    metadata = _meta(
        "openapi-operation-unauth",
        "API operation answers an unauthenticated request",
        "Reads a published OpenAPI/Swagger document, takes the read-only GET operations it "
        "declares, and reports one that answers an anonymous request with a success status and "
        "no authentication challenge — the unauthenticated-invocation half of the API surface "
        "scope. The finding names the document, the operation path and the status; no request "
        "body, no write verb and no credential is ever sent. Read-only GET probes.",
        research_ref="ch03#31",
        cwe="CWE-306",
        framework=("WSTG-APIT-01", "WSTG-CONF-05", "API2:2023", "API5:2023", "CWE-306"),
        compliance=("ISO-A.8.12",),
        severity="medium",
        estimated_requests=6,
    )

    paths_key = "document_paths"
    default_paths = (
        "/openapi.json",
        "/swagger.json",
        "/v3/api-docs",
        "/v2/api-docs",
    )
    max_findings = 1
    finding_title = "API operation answers an unauthenticated request ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        # The shared loop never reaches the signal: this check drives its own walk (``run``
        # below) because an operation path is only knowable after the document is read.
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
        not_found = await _not_found(ctx, origin)
        documents = self.paths(ctx)[:2]
        probed = 0
        for doc_path in documents:
            doc_url = _full_url(origin, doc_path)
            document = await _fetch(ctx, doc_url)
            probed += 1
            if document is None or document.status != 200:
                continue
            parsed = _json_of(document)
            if not isinstance(parsed, Mapping):
                continue
            for operation in _document_paths(parsed):
                url = _full_url(origin, operation)
                page = await _fetch(ctx, url)
                if page is None or not 200 <= page.status < 300:
                    continue
                if _looks_like_not_found(page, not_found):
                    continue
                if _header(page, "www-authenticate") is not None:
                    # The server answered the operation with its own challenge: authenticated.
                    continue
                if _contains_any(page.body, _AUTH_REFUSAL_MARKERS) is not None:
                    continue
                yield web_candidate(
                    ctx,
                    self.finding_title.format(path=operation),
                    artifact={
                        "signal": "operation-reachable-anonymously",
                        "family": FAMILY,
                        "surface": self.section,
                        "check": self.metadata.name,
                        "document": doc_path,
                        "operation": operation,
                        "status": page.status,
                        "content_type": page.content_type,
                        "origin": origin,
                        "anonymous": True,
                        "credential_test_sent": False,
                        "declared_operations": _document_paths(parsed),
                    },
                    exchanges=(exchange_from_page(document), exchange_from_page(page)),
                    confidence=0.8,
                    detail=(
                        f"the operation {operation} declared by {doc_url} answered HTTP "
                        f"{page.status} to an anonymous GET with no authentication challenge"
                    ),
                    source=url,
                )
                return
        yield ctx.clean(
            "no declared API operation answers an anonymous request",
            detail=f"read {probed} candidate document(s); none declared a reachable GET operation",
        )


# --------------------------------------------------------------------------- GraphQL
_INTROSPECTION_QUERY = "query ArachneSchemaInventory { __schema { types { name kind } } }"
_MUTATION_QUERY = (
    "query ArachneMutationInventory { __schema { mutationType { name fields { name } } } }"
)
_SUGGESTION_QUERY = "query { __schema { arachneProbeNonexistentField } }"


def _graphql_url(origin: str, path: str, query: str) -> str:
    """A GraphQL **query** over GET: the operation travels as a URL parameter, not a body."""
    return f"{_full_url(origin, path)}?query={quote(query)}"


class GraphqlIntrospectionGet(_ApiProbe, WebCheck, Module):
    """``m3.graphql-introspection-get`` — introspection answers an anonymous GET (ch03#32)."""

    section = "graphql_api"
    metadata = _meta(
        "graphql-introspection-get",
        "GraphQL introspection enabled over GET",
        "Reports when a GraphQL endpoint answers an anonymous GET carrying the introspection "
        "query with its own schema result (the __schema object beside queryType and the type "
        "list). Introspection is a development and tooling feature; left on in production it "
        "publishes the whole schema — every type, field and mutation name — to anyone who asks. "
        "Reported at medium: it is frequently deliberate. Read-only GET; the operation sent is "
        "a query, never a mutation.",
        research_ref="ch03#32",
        cwe="CWE-200",
        framework=("WSTG-APIT-01", "API9:2023", "CWE-200"),
        severity="medium",
        estimated_requests=3,
    )

    paths_key = "endpoint_paths"
    default_paths = ("/graphql", "/api/graphql", "/v1/graphql", "/gql")
    max_findings = 1
    finding_title = "GraphQL introspection enabled ({path})"

    def url_for(self, ctx: CheckContext, origin: str, path: str) -> str:
        query = payloads_for(ctx).string(
            self.section, "introspection_query", default=_INTROSPECTION_QUERY
        )
        return _graphql_url(origin, path, query or _INTROSPECTION_QUERY)

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        document = _json_of(page)
        if not isinstance(document, Mapping):
            return None
        data = document.get("data")
        if not isinstance(data, Mapping):
            return None
        schema = data.get("__schema")
        if not isinstance(schema, Mapping):
            return None
        types = schema.get("types")
        if not isinstance(types, list) or not types:
            return None
        names = [
            str(entry.get("name"))
            for entry in types[:12]
            if isinstance(entry, Mapping) and entry.get("name") is not None
        ]
        return _Hit(
            "graphql-introspection-enabled",
            {
                "schema_keys": _keys(schema),
                "type_count": len(types),
                "types": names,
                "query_type": _type_name(schema.get("queryType")),
            },
            confidence=0.85,
        )


def _type_name(value: Any) -> str | None:
    """The ``name`` of a GraphQL type reference in an introspection result, if any."""
    if isinstance(value, Mapping) and value.get("name") is not None:
        return str(value["name"])
    return None


class GraphqlSuggestionDisclosure(_ApiProbe, WebCheck, Module):
    """``m3.graphql-suggestion-disclosure`` — field suggestions leak on a wrong name (ch03#32)."""

    section = "graphql_api"
    metadata = _meta(
        "graphql-suggestion-disclosure",
        "GraphQL field suggestions disclosed",
        "Reports when a GraphQL endpoint answers a query naming a field that does not exist "
        "with a suggestion ('Did you mean ...') or a validation message naming the field it "
        "could not find. The suggestion engine turns a blind field-name guess into a guided "
        "walk of the schema even where introspection is disabled. Reported at low: the answer "
        "is an error message, not data. Read-only GET probe.",
        research_ref="ch03#32",
        cwe="CWE-200",
        framework=("WSTG-APIT-01", "WSTG-ERRH-02", "API9:2023", "CWE-200"),
        severity="low",
        estimated_requests=3,
    )

    paths_key = "endpoint_paths"
    default_paths = ("/graphql", "/api/graphql", "/v1/graphql", "/gql")
    max_findings = 1
    finding_title = "GraphQL field suggestions disclosed ({path})"

    def url_for(self, ctx: CheckContext, origin: str, path: str) -> str:
        query = payloads_for(ctx).string(
            self.section, "suggestion_query", default=_SUGGESTION_QUERY
        )
        return _graphql_url(origin, path, query or _SUGGESTION_QUERY)

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        document = _json_of(page)
        if not isinstance(document, Mapping):
            return None
        errors = document.get("errors")
        if not isinstance(errors, list) or not errors:
            return None
        messages = [
            str(entry.get("message"))
            for entry in errors
            if isinstance(entry, Mapping) and entry.get("message") is not None
        ]
        markers = _markers(
            ctx,
            self.section,
            "suggestion_markers",
            ("did you mean", "cannot query field", "unknown field", "suggestions"),
        )
        found = [
            marker for marker in markers if any(marker in message.lower() for message in messages)
        ]
        if not found:
            return None
        return _Hit(
            "graphql-suggestions-disclosed",
            {
                "markers": found,
                "error_count": len(errors),
                "probe_field": "arachneProbeNonexistentField",
            },
            confidence=0.75,
        )


class GraphqlIdeExposed(_ApiProbe, WebCheck, Module):
    """``m3.graphql-ide-exposed`` — a GraphQL IDE is served (ch03#32)."""

    section = "graphql_api"
    names = ("graphql", "graphiql", "apollo")
    body_must_name = True
    metadata = _meta(
        "graphql-ide-exposed",
        "GraphQL IDE served without authentication",
        "Reports when a GraphQL in-browser IDE (GraphiQL, GraphQL Playground or Apollo "
        "Sandbox) is served to an anonymous client: the HTML page carries the IDE's own bundle "
        "wiring and names the tool. The IDE gives whoever reaches it a clickable schema "
        "browser and a console over the endpoint. Read-only GET probe.",
        research_ref="ch03#32",
        cwe="CWE-200",
        framework=("WSTG-APIT-01", "WSTG-INFO-06", "API9:2023", "CWE-200"),
        severity="low",
        estimated_requests=3,
    )

    paths_key = "ide_paths"
    default_paths = ("/graphiql", "/graphql")
    max_findings = 1
    finding_title = "GraphQL IDE served ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        if not page.is_html:
            return None
        markers = _markers_found(
            page.body,
            _markers(
                ctx,
                self.section,
                "ide_markers",
                ("graphiql", "graphql playground", "graphql-playground", "apollo sandbox"),
            ),
        )
        if not markers:
            return None
        return _Hit("graphql-ide-served", {"markers": markers}, confidence=0.8)


class GraphqlMutationSurface(_ApiProbe, WebCheck, Module):
    """``m3.graphql-mutation-surface`` — the schema advertises its mutations (ch03#32).

    The write surface is read, never exercised: the check sends the introspection *query* that
    selects ``mutationType { name fields { name } }`` and reports the mutation names the schema
    publishes. No mutation is sent — a readable schema and a reachable mutation name are the
    whole claim at L1.
    """

    section = "graphql_api"
    metadata = _meta(
        "graphql-mutation-surface",
        "GraphQL mutation surface published",
        "Reads the mutation inventory a GraphQL schema publishes to an anonymous client: the "
        "introspection query returns the mutation type's name and its fields, so the write "
        "surface — every operation that changes state — is enumerable by anyone who reaches the "
        "endpoint. The finding names the mutations; no mutation is ever sent. Reported at low: "
        "the schema is a description, not a state change. Read-only GET probe.",
        research_ref="ch03#32",
        cwe="CWE-200",
        framework=("WSTG-APIT-01", "API9:2023", "CWE-200"),
        severity="low",
        estimated_requests=2,
    )

    paths_key = "endpoint_paths"
    default_paths = ("/graphql", "/api/graphql", "/v1/graphql", "/gql")
    max_findings = 1
    finding_title = "GraphQL mutation surface published ({path})"

    def url_for(self, ctx: CheckContext, origin: str, path: str) -> str:
        query = payloads_for(ctx).string(self.section, "mutation_query", default=_MUTATION_QUERY)
        return _graphql_url(origin, path, query or _MUTATION_QUERY)

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        document = _json_of(page)
        if not isinstance(document, Mapping):
            return None
        data = document.get("data")
        if not isinstance(data, Mapping):
            return None
        schema = data.get("__schema")
        if not isinstance(schema, Mapping):
            return None
        mutation = schema.get("mutationType")
        if not isinstance(mutation, Mapping):
            return None
        fields = mutation.get("fields")
        if not isinstance(fields, list) or not fields:
            return None
        names = [
            str(entry.get("name"))
            for entry in fields[:12]
            if isinstance(entry, Mapping) and entry.get("name") is not None
        ]
        if not names:
            return None
        return _Hit(
            "graphql-mutation-surface-published",
            {
                "mutation_type": _type_name(mutation),
                "mutation_count": len(fields),
                "mutations": names,
                "mutations_sent": 0,
            },
            confidence=0.8,
        )


# --------------------------------------------------------------------------- gRPC / Connect
class GrpcConnectEndpoint(_ApiProbe, WebCheck, Module):
    """``m3.grpc-connect-endpoint`` — a gRPC service method answers an HTTP GET (ch03#31)."""

    section = "grpc_web"
    metadata = _meta(
        "grpc-connect-endpoint",
        "gRPC service method reachable over HTTP without authentication",
        "Reports when the browser-facing side of a gRPC service answers an anonymous HTTP GET: "
        "the Connect protocol defines a GET form for methods that are side-effect free, so an "
        "endpoint that answers it publishes the service's method names and their messages over "
        "plain HTTP to anyone who can reach the origin. The check probes the standard health "
        "method and reports its answer; no RPC with a side effect is ever called. Read-only GET.",
        research_ref="ch03#31",
        cwe="CWE-306",
        framework=("WSTG-APIT-01", "WSTG-INFO-06", "API2:2023", "CWE-306"),
        severity="medium",
        estimated_requests=4,
    )

    paths_key = "method_paths"
    default_paths = (
        "/grpc.health.v1.Health/Check",
        "/grpc.health.v1.Health/Watch",
    )
    max_findings = 1
    finding_title = "gRPC service method reachable over HTTP ({path})"

    def url_for(self, ctx: CheckContext, origin: str, path: str) -> str:
        # The Connect protocol's GET encoding: the (empty) request message travels as JSON in
        # a query parameter, so the probe is a plain URL with no body.
        return f"{_full_url(origin, path)}?encoding=json&message=%7B%7D"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        if "/grpc." not in path:
            return None
        document = _json_of(page)
        if not isinstance(document, Mapping):
            return None
        if "status" not in document and "message" not in document:
            return None
        return _Hit(
            "grpc-connect-method-answered",
            {
                "method": path,
                "response_keys": _keys(document),
                "protocol": "connect-get",
                "rpc_invoked": "side-effect-free GET form only",
            },
            confidence=0.8,
        )


class GrpcWebPreflight(_ApiProbe, WebCheck, Module):
    """``m3.grpc-web-preflight`` — the gRPC-Web CORS preflight is wide open (ch03#23)."""

    section = "grpc_web"
    method = "OPTIONS"
    metadata = _meta(
        "grpc-web-preflight",
        "gRPC-Web CORS preflight permissive",
        "Sends the CORS preflight a browser would send before a gRPC-Web call and reports a "
        "policy that reflects an arbitrary origin *and* authorizes the gRPC-Web request "
        "headers (x-grpc-web, grpc-timeout, content-type). That combination lets any site call "
        "the service from a visitor's browser. Reported at low: it is a policy statement, not a "
        "call — no RPC is sent. Read-only OPTIONS probe.",
        research_ref="ch03#23",
        cwe="CWE-942",
        framework=("WSTG-CLNT-07", "WSTG-APIT-01", "API8:2023", "CWE-942"),
        compliance=("CIS-3.3", "ISO-A.8.26", "PCI-6"),
        severity="low",
        estimated_requests=3,
        active=True,
    )

    paths_key = "method_paths"
    default_paths = ("/grpc.health.v1.Health/Check",)
    ok_statuses = (204,)
    max_findings = 1
    finding_title = "gRPC-Web CORS preflight permissive ({path})"

    def headers(self, ctx: CheckContext, path: str) -> Mapping[str, str] | None:
        return {
            "Origin": _probe_origin(ctx, self.section),
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "content-type,x-grpc-web,grpc-timeout",
        }

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        origin = _probe_origin(ctx, self.section)
        acao = _permissive_acao(page, origin)
        if acao is None:
            return None
        allowed_headers = _allow_list(page, "access-control-allow-headers")
        grpc_headers = [header for header in allowed_headers if header in _GRPC_WEB_HEADERS]
        if not grpc_headers:
            return None
        return _Hit(
            "grpc-web-preflight-permissive",
            {
                "request_origin": origin,
                "acao": acao,
                "allowed_headers": allowed_headers[:8],
                "grpc_headers_allowed": grpc_headers,
                "status": page.status,
            },
            confidence=0.75,
        )


def _probe_origin(ctx: CheckContext, section: str, *, index: int = 0) -> str:
    """The reserved probe origin from the payload corpus (the check's own default otherwise)."""
    configured = payloads_for(ctx).strings(section, "probe_origins")
    if configured:
        return configured[min(index, len(configured) - 1)]
    return "https://arachne-api.invalid"


# --------------------------------------------------------------------------- WebSocket origin
def _handshake_accepted(page: Page) -> bool:
    """True when the answer is a *completed* RFC 6455 handshake, not a plain 200.

    The ``Sec-WebSocket-Accept`` value is the server's own proof that it read the key and
    agreed to speak frames, which is what makes "the upgrade was accepted" a fact rather than a
    status code anyone could return.
    """
    accept = _header(page, "sec-websocket-accept")
    return (
        page.status == 101
        and accept is not None
        and "websocket" in (_header(page, "upgrade") or "").lower()
    )


class WebSocketOriginNull(_ApiProbe, WebCheck, Module):
    """``m3.websocket-origin-null`` — the null origin completes an upgrade (ch03#33)."""

    section = "websocket_origin"
    metadata = _meta(
        "websocket-origin-null",
        "WebSocket upgrade accepted for the null origin",
        "Attempts the RFC 6455 upgrade with the literal null origin — what a sandboxed iframe "
        "or a data: URL sends — and reports a server that completes it. Accepting null means "
        "the origin check is absent or treats the least trustworthy value on the wire as "
        "trusted. The handshake is abandoned immediately: no frame is sent. Read-only GET "
        "upgrade probe.",
        research_ref="ch03#33",
        cwe="CWE-1385",
        framework=("WSTG-CLNT-10", "WSTG-CLNT-07", "CWE-1385"),
        severity="medium",
        estimated_requests=3,
    )

    paths_key = "handshake_paths"
    default_paths = ("/ws", "/socket.io/", "/realtime")
    max_findings = 1
    finding_title = "WebSocket upgrade accepted for the null origin ({path})"

    def headers(self, ctx: CheckContext, path: str) -> Mapping[str, str] | None:
        return {**_WS_UPGRADE_HEADERS, "Origin": "null"}

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        if not _handshake_accepted(page):
            return None
        return _Hit(
            "websocket-null-origin-accepted",
            {"request_origin": "null", "status": page.status, "frames_sent": 0},
            confidence=0.75,
        )


class WebSocketOriginSibling(_ApiProbe, WebCheck, Module):
    """``m3.websocket-origin-sibling`` — a sibling subdomain completes an upgrade (ch03#33)."""

    section = "websocket_origin"
    metadata = _meta(
        "websocket-origin-sibling",
        "WebSocket upgrade accepted for a sibling subdomain",
        "Attempts the RFC 6455 upgrade with an origin on a *sibling* subdomain of the target's "
        "own host and reports a server that completes it. A deployment that trusts every host "
        "under a domain trusts every other tenant, staging instance and abandoned subdomain "
        "under it too. The handshake is abandoned immediately: no frame is sent. Read-only GET "
        "upgrade probe.",
        research_ref="ch03#33",
        cwe="CWE-1385",
        framework=("WSTG-CLNT-10", "WSTG-CLNT-07", "CWE-1385"),
        severity="medium",
        estimated_requests=3,
    )

    paths_key = "handshake_paths"
    default_paths = ("/ws", "/socket.io/", "/realtime")
    max_findings = 1
    finding_title = "WebSocket upgrade accepted for a sibling subdomain ({path})"

    def headers(self, ctx: CheckContext, path: str) -> Mapping[str, str] | None:
        return {**_WS_UPGRADE_HEADERS, "Origin": _sibling_origin(ctx)}

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        if not _handshake_accepted(page):
            return None
        return _Hit(
            "websocket-sibling-origin-accepted",
            {
                "request_origin": _sibling_origin(ctx),
                "target_host": _host_of(origin_of(ctx.asset.value)),
                "status": page.status,
                "frames_sent": 0,
            },
            confidence=0.75,
        )


class WebSocketOriginSuffixSpoof(_ApiProbe, WebCheck, Module):
    """``m3.websocket-origin-suffix-spoof`` — a suffix-spoofed origin completes (ch03#33)."""

    section = "websocket_origin"
    metadata = _meta(
        "websocket-origin-suffix-spoof",
        "WebSocket upgrade accepted for a suffix-spoofed origin",
        "Attempts the RFC 6455 upgrade with an origin whose host merely *ends with* the "
        "target's own host — the shape an origin check written with a suffix or substring test "
        "accepts — and reports a server that completes it. The attacker's own domain is the "
        "suffix, so every visitor to that domain is a cross-site WebSocket hijacking vector. "
        "The handshake is abandoned immediately: no frame is sent. Read-only GET upgrade probe.",
        research_ref="ch03#33",
        cwe="CWE-1385",
        framework=("WSTG-CLNT-10", "WSTG-CLNT-07", "CWE-1385"),
        severity="medium",
        estimated_requests=3,
    )

    paths_key = "handshake_paths"
    default_paths = ("/ws", "/socket.io/", "/realtime")
    max_findings = 1
    finding_title = "WebSocket upgrade accepted for a suffix-spoofed origin ({path})"

    def headers(self, ctx: CheckContext, path: str) -> Mapping[str, str] | None:
        return {**_WS_UPGRADE_HEADERS, "Origin": _suffixed_origin(ctx)}

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        if not _handshake_accepted(page):
            return None
        return _Hit(
            "websocket-suffix-spoof-accepted",
            {
                "request_origin": _suffixed_origin(ctx),
                "target_host": _host_of(origin_of(ctx.asset.value)),
                "status": page.status,
                "frames_sent": 0,
            },
            confidence=0.75,
        )


def _sibling_origin(ctx: CheckContext) -> str:
    """``https://<probe-label>.<target host>`` — a sibling subdomain of the target's own host."""
    origin = origin_of(ctx.asset.value)
    label = _probe_origin(ctx, "websocket_origin", index=1).split("//")[-1].split("/")[0]
    label = label or "arachne-sibling"
    return f"{_scheme_of(origin)}://{label}.{_host_of(origin)}"


def _suffixed_origin(ctx: CheckContext) -> str:
    """``https://<target host>.<attacker label>`` — an origin a suffix test would accept."""
    origin = origin_of(ctx.asset.value)
    label = _probe_origin(ctx, "websocket_origin", index=2).split("//")[-1].split("/")[0]
    label = label or "arachne-suffix.invalid"
    return f"{_scheme_of(origin)}://{_host_of(origin)}.{label}"


# --------------------------------------------------------------------------- serverless / edge
class NetlifyFunctionEndpoint(_ApiProbe, WebCheck, Module):
    """``m3.netlify-function-endpoint`` — a Netlify function answers anonymously (ch03#31)."""

    section = "serverless"
    metadata = _meta(
        "netlify-function-endpoint",
        "Netlify function endpoint reachable without authentication",
        "Reports when a Netlify function route answers an anonymous request and the answer "
        "carries Netlify's own invocation header (x-nf-request-id), which is how the platform "
        "marks a response it produced by running the deploy's function. A function invoked "
        "without authentication is an entry point into the deployment's own code. Read-only "
        "GET probe.",
        research_ref="ch03#31",
        cwe="CWE-200",
        framework=("WSTG-INFO-06", "WSTG-CONF-05", "CWE-200"),
        severity="low",
        estimated_requests=3,
    )

    paths_key = "netlify_paths"
    default_paths = ("/.netlify/functions/hello", "/.netlify/functions/index")
    max_findings = 1
    finding_title = "Netlify function endpoint reachable ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        invocation = _header(page, "x-nf-request-id")
        if invocation is None:
            return None
        if not 200 <= page.status < 300:
            return None
        return _Hit(
            "netlify-function-invoked",
            {
                "platform": "netlify",
                "invocation_header": "x-nf-request-id",
                "invocation_id_present": bool(invocation),
                "status": page.status,
            },
            confidence=0.8,
        )


class VercelFunctionEndpoint(_ApiProbe, WebCheck, Module):
    """``m3.vercel-function-endpoint`` — a Vercel function route answers anonymously (ch03#31)."""

    section = "serverless"
    metadata = _meta(
        "vercel-function-endpoint",
        "Vercel function route reachable without authentication",
        "Reports when a function route on a Vercel deployment (/api/...) answers an anonymous "
        "request and carries Vercel's own platform header (x-vercel-id), which is what marks a "
        "response the platform produced. The finding names the route and the status; a "
        "production deployment whose function requires authorization answers a challenge and is "
        "not reported. Read-only GET probe.",
        research_ref="ch03#31",
        cwe="CWE-200",
        framework=("WSTG-INFO-06", "WSTG-CONF-05", "CWE-200"),
        severity="low",
        estimated_requests=3,
    )

    paths_key = "vercel_paths"
    default_paths = ("/api/hello", "/api/index")
    max_findings = 1
    finding_title = "Vercel function route reachable ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        if not path.startswith("/api/"):
            return None
        platform_id = _header(page, "x-vercel-id")
        if platform_id is None or not 200 <= page.status < 300:
            return None
        return _Hit(
            "vercel-function-invoked",
            {
                "platform": "vercel",
                "platform_header": "x-vercel-id",
                "status": page.status,
                "content_type": page.content_type,
            },
            confidence=0.75,
        )


class GcfFunctionEndpoint(_ApiProbe, WebCheck, Module):
    """``m3.gcf-function-endpoint`` — a Cloud Functions invocation answers anonymously (ch03#31)."""

    section = "serverless"
    metadata = _meta(
        "gcf-function-endpoint",
        "Serverless function invoked without authentication",
        "Reports when an endpoint answers an anonymous request with a header the function "
        "runtime itself sets per invocation (function-execution-id, which Cloud Functions "
        "attaches to the response it produced), so the answer is the function's own output "
        "rather than a static page. A function that runs for an unauthenticated caller is an "
        "entry point into the deployment's code. Read-only GET probe.",
        research_ref="ch03#31",
        cwe="CWE-200",
        framework=("WSTG-INFO-06", "WSTG-CONF-05", "CWE-200"),
        severity="low",
        estimated_requests=3,
    )

    paths_key = "gcf_paths"
    default_paths = ("/hello", "/api/hello")
    max_findings = 1
    finding_title = "Serverless function invoked anonymously ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        execution_id = _header(page, "function-execution-id")
        if execution_id is None or not 200 <= page.status < 300:
            return None
        return _Hit(
            "serverless-function-invoked",
            {
                "platform": "google-cloud-functions",
                "invocation_header": "function-execution-id",
                "status": page.status,
            },
            confidence=0.8,
        )


class OpenfaasGatewayExposed(_ApiProbe, WebCheck, Module):
    """``m3.openfaas-gateway-exposed`` — the OpenFaaS gateway lists its functions (ch03#31)."""

    section = "serverless"
    metadata = _meta(
        "openfaas-gateway-exposed",
        "OpenFaaS gateway function inventory exposed",
        "Reports when the OpenFaaS gateway answers an anonymous request for its function "
        "inventory: the JSON array names each deployed function and the image it runs. An "
        "unauthenticated gateway is both an inventory of the deployment and an invocation path "
        "for every function in it. The finding names the functions, never a value. Read-only "
        "GET probe.",
        research_ref="ch03#31",
        cwe="CWE-306",
        framework=("WSTG-INFO-06", "WSTG-CONF-05", "API2:2023", "CWE-306"),
        severity="medium",
        estimated_requests=3,
    )

    paths_key = "openfaas_paths"
    default_paths = ("/system/functions",)
    max_findings = 1
    finding_title = "OpenFaaS gateway function inventory exposed ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        if "/system/" not in path:
            return None
        document = _json_of(page)
        if not isinstance(document, list) or not document:
            return None
        functions = [
            str(entry.get("name"))
            for entry in document
            if isinstance(entry, Mapping)
            and entry.get("name") is not None
            and (entry.get("image") is not None or entry.get("replicas") is not None)
        ]
        if not functions:
            return None
        return _Hit(
            "openfaas-gateway-inventory-exposed",
            {"functions": functions[:12], "function_count": len(functions)},
            confidence=0.8,
        )


class EdgeFunctionSourceMap(_ApiProbe, WebCheck, Module):
    """``m3.edge-function-sourcemap`` — a deployed bundle serves its source map (ch03#31)."""

    section = "serverless"
    metadata = _meta(
        "edge-function-sourcemap",
        "Edge function bundle source map published",
        "Reports when a source map beside a deployed JavaScript bundle answers an anonymous "
        "request with a real map document (version 3 and a non-empty sources list). A source "
        "map reverses the bundler's work: the function's original source, its module structure "
        "and often its comments are readable from it, and bundles built for the edge commonly "
        "ship one by default. The check names the map and the sources count, never the "
        "declarations in it. Read-only GET probe.",
        research_ref="ch03#31",
        cwe="CWE-540",
        framework=("WSTG-INFO-05", "WSTG-CONF-05", "CWE-540"),
        severity="low",
        estimated_requests=4,
    )

    paths_key = "sourcemap_paths"
    default_paths = ("/app.js.map", "/main.js.map", "/functions/index.js.map")
    max_findings = 1
    finding_title = "Edge function bundle source map published ({path})"

    def paths(self, ctx: CheckContext) -> tuple[str, ...]:
        """The configured map paths, plus a map beside every JS bundle the crawl already saw."""
        configured = _paths(ctx, self.section, self.paths_key, self.default_paths)
        origin = origin_of(ctx.asset.value)
        discovered: list[str] = []
        inventory = ctx.web
        if isinstance(inventory, WebInventory):
            for url in inventory.endpoints:
                if origin_of(url) != origin:
                    continue
                route = url.split("?", 1)[0]
                if route.endswith(".js") and f"{route}.map" not in configured:
                    discovered.append(f"{route}.map")
        return (*configured, *discovered[:3])

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        if not path.endswith(".map"):
            return None
        document = _json_of(page)
        if not isinstance(document, Mapping):
            return None
        if document.get("version") != 3:
            return None
        sources = document.get("sources")
        if not isinstance(sources, list) or not sources:
            return None
        names = [str(item) for item in sources[:8]]
        return _Hit(
            "source-map-published",
            {
                "map": path,
                "source_count": len(sources),
                "sources": names,
                "sources_reported": "names only",
            },
            confidence=0.8,
        )


# --------------------------------------------------------------------------- CORS
class CorsSubdomainTrust(_ApiProbe, WebCheck, Module):
    """``m3.cors-subdomain-trust`` — a sibling subdomain's origin is reflected (ch03#23)."""

    section = "cors_policy"
    metadata = _meta(
        "cors-subdomain-trust",
        "CORS policy reflects a sibling subdomain",
        "Sends a simple cross-origin request whose Origin is a sibling subdomain of the "
        "target's own host and reports a policy that reflects it back. Reflecting any host "
        "under the deployment's domain is the trust decision that turns one weak subdomain "
        "into cross-origin read access to this one. The probe is one read-only GET; no "
        "credential is sent and nothing is read from the answer beyond the policy headers.",
        research_ref="ch03#23",
        cwe="CWE-942",
        framework=("WSTG-CLNT-07", "WSTG-CLNT-13", "CWE-942"),
        compliance=("CIS-3.3", "ISO-A.8.26", "PCI-6"),
        severity="medium",
        estimated_requests=3,
    )

    paths_key = "paths"
    default_paths = ("/api/config", "/api/v1/config")
    max_findings = 1
    finding_title = "CORS policy reflects a sibling subdomain ({path})"

    def headers(self, ctx: CheckContext, path: str) -> Mapping[str, str] | None:
        return {"Origin": _sibling_origin(ctx)}

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        origin = _sibling_origin(ctx)
        acao = _header(page, "access-control-allow-origin")
        if acao is None or acao.strip() != origin:
            return None
        credentials = (_header(page, "access-control-allow-credentials") or "").lower() == "true"
        return _Hit(
            "cors-sibling-origin-reflected",
            {
                "request_origin": origin,
                "acao": acao.strip(),
                "allows_auth": credentials,
                "trust_class": "sibling-subdomain",
            },
            confidence=0.85 if credentials else 0.75,
        )


class CorsSuffixSpoof(_ApiProbe, WebCheck, Module):
    """``m3.cors-suffix-spoof`` — an origin that only *ends with* the host is reflected."""

    section = "cors_policy"
    metadata = _meta(
        "cors-suffix-spoof",
        "CORS policy accepts a suffix-spoofed origin",
        "Sends a simple cross-origin request whose Origin host merely *ends with* the target's "
        "own host (the target's host, a dot, then the attacker's domain) and reports a policy "
        "that reflects it. That answer is the fingerprint of an origin check written with a "
        "suffix or substring test, which any attacker can satisfy with a domain of their own. "
        "The probe is one read-only GET; no credential is sent.",
        research_ref="ch03#23",
        cwe="CWE-942",
        framework=("WSTG-CLNT-07", "WSTG-CLNT-13", "CWE-942"),
        compliance=("CIS-3.3", "ISO-A.8.26", "PCI-6"),
        severity="medium",
        estimated_requests=3,
    )

    paths_key = "paths"
    default_paths = ("/api/config", "/api/v1/config")
    max_findings = 1
    finding_title = "CORS policy accepts a suffix-spoofed origin ({path})"

    def headers(self, ctx: CheckContext, path: str) -> Mapping[str, str] | None:
        return {"Origin": _suffixed_origin(ctx)}

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        origin = _suffixed_origin(ctx)
        acao = _header(page, "access-control-allow-origin")
        if acao is None or acao.strip() != origin:
            return None
        credentials = (_header(page, "access-control-allow-credentials") or "").lower() == "true"
        return _Hit(
            "cors-suffix-spoof-accepted",
            {
                "request_origin": origin,
                "acao": acao.strip(),
                "allows_auth": credentials,
                "trust_class": "host-suffix",
            },
            confidence=0.85 if credentials else 0.75,
        )


class CorsPreflightMethods(_ApiProbe, WebCheck, Module):
    """``m3.cors-preflight-methods`` — the preflight authorizes write verbs (ch03#23)."""

    section = "cors_policy"
    method = "OPTIONS"
    metadata = _meta(
        "cors-preflight-methods",
        "CORS preflight authorizes state-changing methods",
        "Sends the CORS preflight a browser would send before a state-changing call and "
        "reports a policy that reflects an arbitrary origin *and* lists a write verb — PUT, "
        "PATCH or DELETE, or a wildcard — among the methods it authorizes. The policy is what "
        "decides whether any site may drive those verbs from a visitor's browser. Reported at "
        "low: it is a policy statement, and no state-changing request is ever sent. Read-only "
        "OPTIONS probe.",
        research_ref="ch03#23",
        cwe="CWE-942",
        framework=("WSTG-CLNT-07", "WSTG-CLNT-13", "API8:2023", "CWE-942"),
        compliance=("CIS-3.3", "ISO-A.8.26", "PCI-6"),
        severity="low",
        estimated_requests=3,
        active=True,
    )

    paths_key = "paths"
    default_paths = ("/api/config", "/api/v1/config")
    ok_statuses = (204,)
    max_findings = 1
    finding_title = "CORS preflight authorizes state-changing methods ({path})"

    def headers(self, ctx: CheckContext, path: str) -> Mapping[str, str] | None:
        return {
            "Origin": _probe_origin(ctx, self.section),
            "Access-Control-Request-Method": "DELETE",
        }

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        origin = _probe_origin(ctx, self.section)
        acao = _permissive_acao(page, origin)
        if acao is None:
            return None
        methods = _allow_list(page, "access-control-allow-methods")
        write_verbs = [
            verb for verb in ("put", "patch", "delete") if verb in methods or "*" in methods
        ]
        if not write_verbs:
            return None
        credentials = (_header(page, "access-control-allow-credentials") or "").lower() == "true"
        return _Hit(
            "cors-preflight-write-methods",
            {
                "request_origin": origin,
                "acao": acao,
                # ``allows_auth``, not ``allow_credentials``: the evidence redactor blanks any
                # key containing "credential" (ADR-120.7), so the flag is named for its meaning.
                "allows_auth": credentials,
                "allowed_methods": methods[:10],
                "write_verbs": write_verbs,
                "status": page.status,
            },
            confidence=0.7,
        )


class CorsPreflightHeaders(_ApiProbe, WebCheck, Module):
    """``m3.cors-preflight-headers`` — the preflight authorizes any request header (ch03#23)."""

    section = "cors_policy"
    method = "OPTIONS"
    metadata = _meta(
        "cors-preflight-headers",
        "CORS preflight authorizes arbitrary request headers",
        "Sends the CORS preflight a browser would send to attach an authorization header and "
        "reports a policy that reflects an arbitrary origin *and* answers with a wildcard "
        "header list (or names authorization explicitly). Together the two let any site attach "
        "a caller's own credentials to a cross-origin request. Reported at low: it is a policy "
        "statement, and no credential is sent. Read-only OPTIONS probe.",
        research_ref="ch03#23",
        cwe="CWE-942",
        framework=("WSTG-CLNT-07", "WSTG-CLNT-13", "API8:2023", "CWE-942"),
        compliance=("CIS-3.3", "ISO-A.8.26", "PCI-6"),
        severity="low",
        estimated_requests=3,
        active=True,
    )

    paths_key = "paths"
    default_paths = ("/api/config", "/api/v1/config")
    ok_statuses = (204,)
    max_findings = 1
    finding_title = "CORS preflight authorizes arbitrary request headers ({path})"

    def headers(self, ctx: CheckContext, path: str) -> Mapping[str, str] | None:
        return {
            "Origin": _probe_origin(ctx, self.section),
            "Access-Control-Request-Method": "GET",
            "Access-Control-Request-Headers": "authorization,x-arachne-probe",
        }

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        origin = _probe_origin(ctx, self.section)
        acao = _permissive_acao(page, origin)
        if acao is None:
            return None
        allowed = _allow_list(page, "access-control-allow-headers")
        permissive = "*" in allowed or "authorization" in allowed
        if not permissive:
            return None
        credentials = (_header(page, "access-control-allow-credentials") or "").lower() == "true"
        return _Hit(
            "cors-preflight-arbitrary-headers",
            {
                "request_origin": origin,
                "acao": acao,
                "allows_auth": credentials,
                "allowed_headers": allowed[:10],
                "wildcard": "*" in allowed,
                "status": page.status,
            },
            confidence=0.7,
        )


#: Every check the WP-28 family registers, in the order the registry selects them. The three
#: OPTIONS preflight checks are opt-in-active (F-01-09) and are selected only when the scan
#: authorizes active checks; every other row is a plain anonymous GET.
ApiSurfaceChecks: tuple[type[Module], ...] = (
    OpenApiDocumentExposed,
    SwaggerDocumentExposed,
    SwaggerUiExposed,
    RedocExposed,
    SwaggerResourcesIndex,
    OpenApiOperationUnauth,
    GraphqlIntrospectionGet,
    GraphqlSuggestionDisclosure,
    GraphqlIdeExposed,
    GraphqlMutationSurface,
    GrpcConnectEndpoint,
    GrpcWebPreflight,
    WebSocketOriginNull,
    WebSocketOriginSibling,
    WebSocketOriginSuffixSpoof,
    NetlifyFunctionEndpoint,
    VercelFunctionEndpoint,
    GcfFunctionEndpoint,
    OpenfaasGatewayExposed,
    EdgeFunctionSourceMap,
    CorsSubdomainTrust,
    CorsSuffixSpoof,
    CorsPreflightMethods,
    CorsPreflightHeaders,
)
