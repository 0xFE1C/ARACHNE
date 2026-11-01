"""OIDC login routes: ``/auth/sso/*`` and ``/auth/me`` (S17, area IDAM).

The browser half of REQ-IDAM-001 — three steps, each audit-logged:

``GET /auth/sso/login``
    Start an authorization-code flow: mint ``state`` + OIDC ``nonce`` + PKCE verifier,
    persist the pending flow server-side, and 302 the browser to the IdP. Refused with 503
    when no IdP is configured, so a deployment that never enabled SSO exposes nothing
    (REQ-IDAM-002).
``GET /auth/sso/callback``
    Consume the flow (single-use ``state``), exchange the code, verify the ID token against
    the provider JWKS, map the group claim onto one of the three roles, then mint an opaque
    session cookie. A login whose groups map to no role is **denied** and audited.
``POST /auth/sso/logout``
    Revoke the session server-side and clear the cookie.

``GET /auth/me`` is deliberately credential-agnostic: it answers for an API-key caller
and an SSO session alike, and its ``actor`` field is the "user X via key Y" string the
audit trail records (REQ-IDAM-004).
"""

from __future__ import annotations

from typing import Annotated
from urllib.parse import quote

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import RedirectResponse

from arachne.api.auth import SSO_SESSION_COOKIE, Principal
from arachne.api.deps import ContextDep, get_principal
from arachne.api.oidc import new_code_verifier, new_nonce
from arachne.core.audit import AuditAction, AuditOutcome
from arachne.core.errors import IdentityError

__all__ = ["CALLBACK_PATH", "sso_router"]

sso_router = APIRouter()

#: Where the IdP redirects back to (fixed; ``sso.redirect_url`` overrides for proxies).
CALLBACK_PATH = "/api/v1/auth/sso/callback"


@sso_router.get("/auth/sso/login", tags=["auth"])
async def sso_login(
    request: Request,
    context: ContextDep,
    next_path: Annotated[str, Query(alias="next")] = "/ui/",
) -> RedirectResponse:
    """Begin an OIDC authorization-code login (REQ-IDAM-001)."""
    provider = context.oidc
    if provider is None or not provider.configured:
        context.auditor.record(
            AuditAction.API_DENIED,
            outcome=AuditOutcome.BLOCKED,
            target="/auth/sso/login",
            reason="single sign-on is not configured",
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="single sign-on is not configured on this deployment",
        )
    sessions = context.services.auth_sessions
    flows = context.services.identity_flows
    if sessions is None or flows is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="the identity store is unavailable",
        )
    redirect_uri = _redirect_uri(context, request)
    verifier = new_code_verifier()
    nonce = new_nonce()
    flow = flows.create(
        nonce=nonce,
        code_verifier=verifier,
        redirect_uri=redirect_uri,
        next_path=_safe_next(next_path),
        ttl_s=context.settings.sso.flow_ttl_s,
    )
    url = await provider.authorization_url(
        redirect_uri=redirect_uri, state=flow.state, nonce=nonce, verifier=verifier
    )
    context.auditor.record(
        AuditAction.AUTH_SSO_LOGIN,
        outcome=AuditOutcome.ALLOWED,
        target="authorization request",
        reason="started",
        meta={"state": flow.state[:8], "next": flow.next_path},
    )
    return RedirectResponse(url, status_code=status.HTTP_303_SEE_OTHER)


@sso_router.get("/auth/sso/callback", tags=["auth"])
async def sso_callback(
    request: Request,
    context: ContextDep,
    code: Annotated[str | None, Query()] = None,
    state: Annotated[str | None, Query()] = None,
    error: Annotated[str | None, Query()] = None,
) -> RedirectResponse:
    """Complete an OIDC login: exchange, verify, map to a role, mint a session."""
    provider = context.oidc
    if provider is None or not provider.configured:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="single sign-on is not configured on this deployment",
        )
    flows = context.services.identity_flows
    sessions = context.services.auth_sessions
    if flows is None or sessions is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="the identity store is unavailable",
        )
    if error:
        return _fail(context, None, f"the provider returned an error: {error}")

    flow = flows.consume(state or "")
    if flow is None:
        return _fail(context, None, "the login state is unknown, expired or already used")
    if not code:
        return _fail(context, flow.next_path, "the provider returned no authorization code")

    try:
        tokens = await provider.exchange_code(
            code=code, verifier=flow.code_verifier, redirect_uri=flow.redirect_uri
        )
        id_token = tokens.get("id_token")
        if not isinstance(id_token, str) or not id_token:
            msg = "the provider returned no ID token"
            raise IdentityError(msg)
        claims = await provider.verify_id_token(id_token, nonce=flow.nonce)
    except IdentityError as exc:
        return _fail(context, flow.next_path, str(exc))

    role = provider.role_for(claims)
    if role is None:
        identity_hint = str(claims.get("email") or claims.get("sub") or "unknown")
        context.auditor.record(
            AuditAction.API_DENIED,
            outcome=AuditOutcome.BLOCKED,
            target="/auth/sso/callback",
            reason="no group maps to a role and no default role is configured",
            meta={"user": identity_hint, "groups": list(provider.groups_from(claims))},
        )
        return _fail(
            context,
            flow.next_path,
            "your account is not entitled to access this deployment",
        )

    identity = provider.identity_from(claims)
    subject = identity["subject"] or ""
    if not subject:
        return _fail(context, flow.next_path, "the ID token carries no subject")

    groups = provider.groups_from(claims)
    _record, token = sessions.create(
        subject=subject,
        role=role,
        email=identity["email"],
        name=identity["name"],
        groups=groups,
        ttl_s=context.settings.sso.session_max_age_s,
    )
    actor = f"user {identity['email'] or identity['name'] or subject}"
    context.auditor.record(
        AuditAction.AUTH_SSO_LOGIN,
        outcome=AuditOutcome.ALLOWED,
        target="session",
        reason=f"granted role {role}",
        meta={"actor": actor, "role": role, "groups": list(groups)},
    )
    response = RedirectResponse(flow.next_path, status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(
        SSO_SESSION_COOKIE,
        token,
        max_age=context.settings.sso.session_max_age_s,
        httponly=True,
        samesite="strict",
        secure=context.settings.api.tls_configured,
        path="/",
    )
    return response


@sso_router.post("/auth/sso/logout", tags=["auth"])
async def sso_logout(request: Request, context: ContextDep) -> RedirectResponse:
    """Revoke the current SSO session and clear the cookie."""
    token = request.cookies.get(SSO_SESSION_COOKIE)
    sessions = context.services.auth_sessions
    revoked = bool(sessions and sessions.revoke(token))
    if revoked:
        context.auditor.record(
            AuditAction.AUTH_SSO_LOGOUT,
            target="session",
            reason="logged out",
        )
    response = RedirectResponse("/ui/login", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie(SSO_SESSION_COOKIE, path="/")
    return response


@sso_router.get("/auth/me", tags=["auth"])
def whoami(principal: Annotated[Principal, Depends(get_principal)]) -> dict[str, object]:
    """The authenticated caller's identity — the same ``actor`` the audit trail records."""
    return {
        "label": principal.label,
        "role": principal.role.value,
        "actor": principal.actor,
        "source": principal.source,
        "user": principal.user,
        "email": principal.email,
        "project": principal.project,
        "groups": list(principal.groups),
    }


def _redirect_uri(context: ContextDep, request: Request) -> str:
    if context.settings.sso.redirect_url:
        return context.settings.sso.redirect_url
    base = context.settings.api.base_url
    if base:
        return f"{base.rstrip('/')}{CALLBACK_PATH}"
    return f"{str(request.base_url).rstrip('/')}{CALLBACK_PATH}"


def _safe_next(path: str) -> str:
    """Only local UI paths survive; anything else becomes the dashboard (no open redirect)."""
    candidate = (path or "").strip()
    if candidate.startswith("/") and not candidate.startswith("//"):
        return candidate
    return "/ui/"


def _fail(context: ContextDep, next_path: str | None, reason: str) -> RedirectResponse:
    """Audit a refused login and send the browser back to the login page with the reason."""
    context.auditor.record(
        AuditAction.API_DENIED,
        outcome=AuditOutcome.BLOCKED,
        target="/auth/sso/callback",
        reason=reason,
    )
    destination = "/ui/login"
    if next_path and next_path.startswith("/ui"):
        destination = f"{destination}?next={quote(next_path)}"
    return RedirectResponse(destination, status_code=status.HTTP_303_SEE_OTHER)
