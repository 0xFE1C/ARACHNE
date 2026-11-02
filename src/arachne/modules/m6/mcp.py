"""``m6.mcp-*`` — the MCP (Model Context Protocol) security family, read-only (REQ-DET-005).

MCP servers have a precise, published security specification (the *Security Best Practices*
page, spec version 2025-11-25) and no scanner covers it. Three of its classes are decidable
at **L1 with ``GET`` alone**, which is the whole reason this family is here:

``m6.mcp-token-audience``
    *Token passthrough.* The spec forbids a server accepting a bearer token issued for
    another audience. The protected-resource metadata (RFC 9728) is where a server declares
    the ``resource`` its tokens must be audienced to; metadata without one cannot enforce
    audience binding. Reported from the published document.
``m6.mcp-session-auth``
    *Session-based authentication.* The spec is absolute: "MCP Servers **MUST NOT** use
    sessions for authentication." An endpoint that answers an unauthenticated request with a
    session identifier and no authentication challenge is doing exactly that.
``m6.mcp-oauth-metadata``
    *Unvalidated OAuth metadata discovery.* A discovery document that advertises an issuer or
    authorization server that is not HTTPS, or that points into a private, loopback or
    link-local range, is the SSRF surface the spec warns about (``169.254.169.254``,
    localhost, internal hosts). The check reads the *published strings* and never fetches
    them: fetching a target-supplied URL would be the very SSRF it reports.

**Safety.** Every request in this module is a ``GET`` to a path on the target's own origin,
with no request body and no ``Authorization`` header — the checks never authenticate to,
write to or start an MCP server, and they never follow a URL the target supplied. The
``tests/test_mcp_safety.py`` suite asserts both halves (the source shape and the wire).
"""

from __future__ import annotations

import ipaddress
from collections.abc import AsyncIterator, Mapping, Sequence
from typing import Any
from urllib.parse import urlsplit

from arachne.core.results import CheckResult
from arachne.core.target import TargetKind
from arachne.modules.base import Asset, CheckMetadata, Module
from arachne.modules.context import CheckContext
from arachne.modules.m5.support import endpoint_base
from arachne.modules.m6.support import m6_candidate, safe_fetch, skip

__all__ = ["MCP_CHECKS", "McpOauthMetadata", "McpSessionAuth", "McpTokenAudience"]

#: RFC 9728 — the protected-resource metadata a client reads first.
PROTECTED_RESOURCE_PATH = "/.well-known/oauth-protected-resource"
#: RFC 8414 — the authorization-server metadata.
AUTHORIZATION_SERVER_PATH = "/.well-known/oauth-authorization-server"
#: The path an MCP server answers on when the asset is a bare origin.
DEFAULT_MCP_PATH = "/mcp"

#: Cookie names that read as a session identifier (the thing the MCP spec forbids as auth).
_SESSION_COOKIE_MARKERS = ("session", "sid", "phpsessid", "jsessionid", "asp.net_sessionid")


def _origin(ctx: CheckContext) -> str | None:
    """``scheme://host[:port]`` for this asset, or ``None`` when it names no endpoint."""
    base = endpoint_base(ctx)
    if base is None:
        return None
    parts = urlsplit(base)
    if not parts.scheme or not parts.netloc:
        return None
    return f"{parts.scheme}://{parts.netloc}"


def _mcp_endpoint(ctx: CheckContext, origin: str) -> str:
    """The MCP endpoint URL: the asset's own path when it has one, else ``origin + /mcp``."""
    base = endpoint_base(ctx)
    parts = urlsplit(base or "")
    if parts.path and parts.path not in {"/", ""}:
        return (base or origin).rstrip("/")
    return f"{origin}{DEFAULT_MCP_PATH}"


def _supports_url(asset: Asset) -> bool:
    return asset.kind == "url" and asset.value.lower().startswith(("http://", "https://"))


def _unsafe_discovery_url(url: str) -> str | None:
    """Why ``url`` is unfit as an OAuth discovery target, or ``None`` when it is public HTTPS.

    Only the literal is inspected: a host name is left to DNS, and nothing here resolves or
    fetches the URL (that is the SSRF the check exists to report, not to perform).
    """
    parts = urlsplit(url)
    if parts.scheme.lower() != "https":
        return f"{url} is advertised over {parts.scheme or 'no scheme'}, not HTTPS"
    host = parts.hostname
    if not host:
        return f"{url} names no host"
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return None
    if not address.is_global:
        return f"{url} names the non-public address {address}"
    return None


def _authorization_servers(document: Mapping[str, Any] | None) -> tuple[str, ...]:
    """Every discovery URL a protected-resource or authorization-server document advertises."""
    if not document:
        return ()
    found: list[str] = []
    servers = document.get("authorization_servers")
    if isinstance(servers, Sequence) and not isinstance(servers, (str, bytes)):
        found.extend(str(item) for item in servers if isinstance(item, str))
    for key in ("issuer", "authorization_server", "resource"):
        value = document.get(key)
        if isinstance(value, str):
            found.append(value)
    return tuple(found)


class McpTokenAudience(Module):
    """``m6.mcp-token-audience`` — does the server bind tokens to its own audience?"""

    metadata = CheckMetadata(
        id="m6.mcp-token-audience",
        module="M6",
        name="mcp-token-audience",
        version="1.0",
        title="MCP protected-resource metadata declares no token audience",
        description=(
            "Reads the MCP server's protected-resource metadata (RFC 9728) with one anonymous "
            "GET and reports it when it publishes no `resource` identifier. Without one the "
            "server cannot bind an access token to its own audience, which is the token-"
            "passthrough condition the MCP Security Best Practices forbid. Read-only: the "
            "published document is parsed, and no token is ever presented."
        ),
        research_ref="ch06#15",
        framework=("API2:2023", "ASI03:2026", "CWE-287"),
        cwe="CWE-287",
        target_kinds=(TargetKind.URL,),
        severity_hint="medium",
        type="hybrid",
        safe=True,
        verifiable=True,
        estimated_requests=1,
    )

    def supports(self, asset: Asset) -> bool:
        return Module.supports(self, asset) and _supports_url(asset)

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        origin = _origin(ctx)
        if origin is None:
            yield skip(ctx, "no HTTP origin on this asset: declare a URL target")
            return
        url = f"{origin}{PROTECTED_RESOURCE_PATH}"
        exchange = await safe_fetch(ctx, url, anonymous=True)
        if exchange is None or not exchange.ok:
            yield ctx.clean(
                "no protected-resource metadata published",
                detail=f"{url} did not answer 2xx, so no audience claim was made to review",
            )
            return
        document = exchange.json_body()
        if not isinstance(document, Mapping):
            yield ctx.clean(
                "protected-resource metadata is not JSON",
                detail=f"{url} answered {exchange.status_code} without a JSON document",
            )
            return
        resource = document.get("resource")
        if isinstance(resource, str) and resource.strip():
            yield ctx.clean(
                "the server binds tokens to a declared audience",
                detail=f"the protected-resource metadata names resource {resource!r}",
            )
            return
        yield m6_candidate(
            ctx,
            f"MCP protected-resource metadata at {PROTECTED_RESOURCE_PATH} declares no audience",
            artifact={
                "signal": "mcp-token-passthrough",
                "family": "mcp",
                "endpoint": url,
                "metadata": dict(document),
                "severity_hint": "medium",
            },
            exchanges=(exchange,),
            cwe="CWE-287",
            confidence=0.6,
            detail=(
                "the document has no `resource` field, so a token issued for any audience "
                "would satisfy it — the token-passthrough class the MCP specification forbids"
            ),
            source=url,
        )


class McpSessionAuth(Module):
    """``m6.mcp-session-auth`` — does the server authenticate with a session?"""

    metadata = CheckMetadata(
        id="m6.mcp-session-auth",
        module="M6",
        name="mcp-session-auth",
        version="1.0",
        title="MCP endpoint authenticates with a session",
        description=(
            "Sends one anonymous GET to the MCP endpoint and reports it when the endpoint "
            "answers without any authentication challenge while issuing a session identifier "
            "(an `Mcp-Session-Id` header or a session cookie). The MCP Security Best Practices "
            "say a server MUST NOT use sessions for authentication. Read-only: no credential "
            "is sent and nothing is written; the check only reads the challenge the server sent."
        ),
        research_ref="ch06#15",
        framework=("API2:2023", "ASI07:2026", "CWE-306"),
        cwe="CWE-306",
        target_kinds=(TargetKind.URL,),
        severity_hint="medium",
        type="hybrid",
        safe=True,
        verifiable=True,
        estimated_requests=1,
    )

    def supports(self, asset: Asset) -> bool:
        return Module.supports(self, asset) and _supports_url(asset)

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        origin = _origin(ctx)
        if origin is None:
            yield skip(ctx, "no HTTP origin on this asset: declare a URL target")
            return
        endpoint = _mcp_endpoint(ctx, origin)
        exchange = await safe_fetch(ctx, endpoint, anonymous=True)
        if exchange is None:
            yield skip(ctx, f"the MCP endpoint {endpoint} could not be reached")
            return
        challenge = exchange.header("WWW-Authenticate")
        if exchange.status_code in {401, 403} or challenge:
            yield ctx.clean(
                "the endpoint asks for authentication rather than a session",
                detail=f"{endpoint} answered {exchange.status_code} with a bearer challenge",
            )
            return
        session_header = exchange.header("Mcp-Session-Id")
        session_cookies = tuple(
            cookie.name for cookie in exchange.cookies if _looks_like_session(cookie.name)
        )
        if not session_header and not session_cookies:
            yield ctx.clean(
                "no session identifier is used as authentication",
                detail=f"{endpoint} answered {exchange.status_code} without a session identifier",
            )
            return
        identifier = session_header or ", ".join(session_cookies)
        yield m6_candidate(
            ctx,
            f"MCP endpoint {endpoint} answers unauthenticated with a session identifier",
            artifact={
                "signal": "mcp-session-auth",
                "family": "mcp",
                "endpoint": endpoint,
                "status": exchange.status_code,
                "session_identifier": identifier,
                "www_authenticate": challenge,
                "severity_hint": "medium",
            },
            exchanges=(exchange,),
            cwe="CWE-306",
            confidence=0.6,
            detail=(
                "the endpoint issued a session identifier to an unauthenticated request with no "
                "bearer challenge; the MCP specification forbids sessions as authentication"
            ),
            source=endpoint,
        )


def _looks_like_session(name: str) -> bool:
    lowered = name.lower()
    return any(marker in lowered for marker in _SESSION_COOKIE_MARKERS)


class McpOauthMetadata(Module):
    """``m6.mcp-oauth-metadata`` — is the advertised discovery target safe?"""

    metadata = CheckMetadata(
        id="m6.mcp-oauth-metadata",
        module="M6",
        name="mcp-oauth-metadata",
        version="1.0",
        title="MCP OAuth metadata advertises an unsafe discovery target",
        description=(
            "Reads the MCP server's protected-resource and authorization-server metadata with "
            "two anonymous GETs and reports an advertised issuer or authorization server that "
            "is not HTTPS or that points into a private, loopback or link-local range — the "
            "unvalidated-discovery SSRF surface the MCP Security Best Practices warn about. "
            "Read-only: the advertised URLs are parsed, never fetched — following one would be "
            "the SSRF the check reports."
        ),
        research_ref="ch06#15",
        framework=("WSTG-INPV-19", "API7:2023", "ASI07:2026", "CWE-918"),
        cwe="CWE-918",
        target_kinds=(TargetKind.URL,),
        severity_hint="medium",
        type="hybrid",
        safe=True,
        verifiable=True,
        estimated_requests=2,
    )

    def supports(self, asset: Asset) -> bool:
        return Module.supports(self, asset) and _supports_url(asset)

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        origin = _origin(ctx)
        if origin is None:
            yield skip(ctx, "no HTTP origin on this asset: declare a URL target")
            return
        documents: list[tuple[str, Mapping[str, Any], Any]] = []
        for path in (PROTECTED_RESOURCE_PATH, AUTHORIZATION_SERVER_PATH):
            url = f"{origin}{path}"
            exchange = await safe_fetch(ctx, url, anonymous=True)
            if exchange is None or not exchange.ok:
                continue
            document = exchange.json_body()
            if isinstance(document, Mapping):
                documents.append((url, document, exchange))
        if not documents:
            yield ctx.clean(
                "no OAuth discovery metadata published",
                detail="neither well-known document answered 2xx with JSON",
            )
            return

        findings = 0
        for url, document, exchange in documents:
            for advertised in _authorization_servers(document):
                problem = _unsafe_discovery_url(advertised)
                if problem is None:
                    continue
                findings += 1
                yield m6_candidate(
                    ctx,
                    f"MCP OAuth metadata advertises an unsafe discovery target ({advertised})",
                    artifact={
                        "signal": "mcp-oauth-metadata",
                        "family": "mcp",
                        "endpoint": url,
                        "advertised": advertised,
                        "problem": problem,
                        "severity_hint": "medium",
                    },
                    exchanges=(exchange,),
                    cwe="CWE-918",
                    confidence=0.6,
                    detail=(
                        f"{problem}; a client induced to fetch it would be steered at an internal "
                        "or downgraded host (the unvalidated-discovery class)"
                    ),
                    source=url,
                )
        if not findings:
            yield ctx.clean(
                "every advertised discovery target is public HTTPS",
                detail=f"{len(documents)} metadata document(s) reviewed; no unsafe target named",
            )


#: Every MCP check, so the family's safety test can enumerate them (REQ-DET-005).
MCP_CHECKS: tuple[type[Module], ...] = (McpTokenAudience, McpSessionAuth, McpOauthMetadata)
