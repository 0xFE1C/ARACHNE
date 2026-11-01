"""Authenticated web checks (S19, area CREDS: REQ-CREDS-001).

``m3.auth-session-audit`` (S6) established the *anonymous* half of research ch03#19 — cookie
flags, cleartext login transport, user-enumeration differentials — and recorded the gap
explicitly: "session fixation and logout invalidation are not implemented, both need a
successful login, which would mean supplying real credentials". S19 supplies exactly that,
through the credential broker (ADR-240.1), so the two checks here close the gap:

``m3.authenticated-surface``
    What a session reaches that an anonymous client does not. The checks handler crawls
    anonymously *first*, then logs in, then crawls again; this check diffs the two and reports
    the additional surface — the authenticated area, with the pages it exposes. This is the
    finding that a credentialed scan exists to produce, and it is why the accept criterion for
    REQ-CREDS-001 is "the authenticated area yields findings the unauthenticated scan cannot".

``m3.session-logout``
    Does logout actually end the session? A logout that clears the client's cookie but leaves
    the server-side session alive keeps a captured token usable (CWE-613). The check logs out
    and then re-probes the session; a session that still works is the finding.

Both are **opt-in** (``enabled_by_default=False``) and declare ``requires_credentials``, so a
default scan neither selects them nor pays for a login. Both ask the broker for outcomes and
never touch a credential: the session cookie lives in the HTTP client's own jar, and the
findings cite redacted exchanges.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from arachne.core.results import CheckResult
from arachne.core.target import TargetKind
from arachne.modules.base import CheckMetadata, Module
from arachne.modules.context import CheckContext
from arachne.modules.m3.inventory import origin_of
from arachne.modules.m3.support import (
    WebCheck,
    http_or_skip,
    owns_origin,
    skip,
    web_candidate,
    web_or_skip,
)

__all__ = ["AuthenticatedSurface", "SessionLogout"]

#: Path fragments that mark an authenticated-only page as *sensitive* rather than merely
#: additional. Heuristic and deliberately small: the finding's value is the surface itself,
#: and a long list of guesses would dilute the evidence.
_SENSITIVE_FRAGMENTS = (
    "admin",
    "account",
    "user",
    "profile",
    "setting",
    "config",
    "billing",
    "invoice",
    "order",
    "customer",
    "private",
    "internal",
    "export",
    "report",
    "portal",
    "dashboard",
)

#: How many URLs a finding names before it summarises (report readability).
MAX_URLS = 12

#: What a logout endpoint looks like when the application advertises one.
_LOGOUT_FRAGMENTS = ("logout", "log-out", "signout", "sign-out", "logoff", "exit")


def _sensitive(url: str) -> bool:
    path = url.lower()
    return any(fragment in path for fragment in _SENSITIVE_FRAGMENTS)


class AuthenticatedSurface(WebCheck, Module):
    """``m3.authenticated-surface`` — the surface only a session reaches (ch03#19)."""

    metadata = CheckMetadata(
        id="m3.authenticated-surface",
        module="M3",
        name="authenticated-surface",
        version="1.0",
        title="Authenticated-only web surface",
        description=(
            "Compares the anonymous crawl with the crawl made after authenticating with the "
            "scan's configured credential, and reports the pages added by a session: content "
            "behind a login wall, and in particular administrative or account areas that an "
            "unauthenticated client cannot reach. Runs only when the scan names a credential; "
            "it never handles the credential itself."
        ),
        research_ref="ch03#19",
        cwe="CWE-284",
        target_kinds=(TargetKind.URL,),
        severity_hint="medium",
        type="active",
        safe=True,
        verifiable=False,
        enabled_by_default=False,
        estimated_requests=4,
        requires_active_checks=True,
        requires_credentials=("web",),
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

        session = ctx.web_session
        if session is None or not session.authenticated:
            yield skip(ctx, _why_unauthenticated(ctx))
            return

        additional = tuple(session.authenticated_only)
        if not additional:
            yield ctx.clean(
                "the session reaches no additional surface",
                detail=(
                    f"authenticated as {session.label!r}: the crawl after login returned the "
                    "same pages as the anonymous crawl, so a credential adds no reachable "
                    "surface on this origin"
                ),
            )
            return

        sensitive = tuple(url for url in additional if _sensitive(url))
        shown = tuple(sensitive or additional)[:MAX_URLS]
        origin = origin_of(ctx.asset.value)
        exchanges = tuple(session.login_exchanges)
        yield web_candidate(
            ctx,
            f"A session reaches {len(additional)} page(s) an anonymous client cannot",
            artifact={
                "signal": "authenticated-surface",
                "family": "access-control",
                "credential": session.label,
                "authenticated_only": list(additional),
                "authenticated_only_count": len(additional),
                "sensitive_urls": list(sensitive),
                "anonymous_pages": len(ctx.web_baseline.order) if ctx.web_baseline else 0,
                "authenticated_pages": len(inventory.order),
                "login_detected": bool(session.spec is not None and session.spec.detected),
            },
            exchanges=exchanges,
            confidence=0.7 if sensitive else 0.5,
            detail=(
                f"authenticated with the configured credential, the crawl on {origin} reached "
                f"{len(additional)} page(s) the anonymous crawl did not"
                + (
                    f", including {len(sensitive)} whose path suggests administrative or "
                    "account data"
                    if sensitive
                    else ""
                )
                + ": "
                + ", ".join(shown)
                + (" …" if len(additional) > len(shown) else "")
            ),
            source=shown[0] if shown else origin,
        )


def _why_unauthenticated(ctx: CheckContext) -> str:
    """A machine-readable reason for running unauthenticated, for the skip's evidence."""
    broker = ctx.credentials
    if broker is None:
        return (
            "no credential broker is wired for this step: the checks step builds one when the "
            "scan names a credential (options.credentials)"
        )
    if not broker.configured:
        return (
            "this scan names no credential, or this node has no vault: an authenticated-surface "
            "comparison needs a login (set options.credentials to a vault label)"
        )
    refusals = "; ".join(f"{item.label}: {item.reason}" for item in broker.refusals)
    if refusals:
        return f"no usable credential for this scan ({refusals})"
    return (
        "the credential did not establish a session: the login was refused, no login form was "
        "found, or the credential declares no login flow"
    )


class SessionLogout(WebCheck, Module):
    """``m3.session-logout`` — does logout actually end the session? (ch03#19, CWE-613)."""

    metadata = CheckMetadata(
        id="m3.session-logout",
        module="M3",
        name="session-logout",
        version="1.0",
        title="Session invalidation on logout",
        description=(
            "Logs out and then re-probes the session. A logout that only clears the client's "
            "cookie leaves the server-side session usable, so a captured token keeps working "
            "and a shared or stolen session cannot be ended by the user; that is reported. "
            "Uses the logout endpoint the credential declares, or one the crawl saw the "
            "application advertise; never guesses a path."
        ),
        research_ref="ch03#19",
        cwe="CWE-613",
        target_kinds=(TargetKind.URL,),
        severity_hint="medium",
        type="active",
        safe=True,
        verifiable=True,
        enabled_by_default=False,
        estimated_requests=4,
        requires_active_checks=True,
        requires_credentials=("web",),
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

        session = ctx.web_session
        if session is None or not session.authenticated:
            yield skip(ctx, _why_unauthenticated(ctx))
            return
        broker = ctx.credentials
        if broker is None:
            yield skip(ctx, "no credential broker is wired for this step")
            return

        logout_url = _logout_url(session, inventory, origin_of(ctx.asset.value))
        if logout_url is None:
            yield skip(
                ctx,
                "no logout endpoint is known: the credential declares none and the crawl saw "
                "the application advertise none, so the check will not guess a path",
            )
            return
        if session.spec is not None and not session.spec.logout_url:
            session.spec = _with_logout(session.spec, logout_url)

        outcome = await broker.logout(client=ctx.http, session=session)
        if outcome is None:
            yield skip(ctx, "the logout request could not be answered, so no verdict is possible")
            return
        exchanges = (
            *outcome.exchanges,
            session.login_exchanges[0] if session.login_exchanges else None,
        )
        if outcome.survived:
            yield web_candidate(
                ctx,
                "The session is still valid after logging out",
                artifact={
                    "signal": "session-logout",
                    "family": "session-management",
                    "credential": session.label,
                    "logout_url": outcome.url,
                    "session_survived": True,
                },
                exchanges=exchanges,
                confidence=0.8,
                detail=(
                    f"after requesting {outcome.url}, the session authenticated as "
                    f"{session.label!r} still returned the protected response; a logout that "
                    "does not invalidate the server-side session leaves a captured token "
                    "usable (CWE-613)"
                ),
                source=outcome.url,
            )
            return
        yield ctx.clean(
            "the logout invalidated the session",
            detail=f"{outcome.url} ended the session: the protected page no longer answered",
            evidence=[],
        )


def _with_logout(spec: Any, logout_url: str) -> Any:
    """A copy of ``spec`` carrying the discovered logout URL."""
    from dataclasses import replace

    return replace(spec, logout_url=logout_url)


def _logout_url(session: Any, inventory: Any, origin: str) -> str | None:
    """The logout endpoint: declared, else one the application itself advertised."""
    spec = session.spec
    if spec is not None and spec.logout_url:
        return str(spec.logout_url)
    for url in inventory.endpoints:
        if origin_of(url) != origin:
            continue
        if any(fragment in url.lower() for fragment in _LOGOUT_FRAGMENTS):
            return str(url)
    return None
