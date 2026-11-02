"""Identity checks: session/auth posture (ch03#19), IDOR (ch03#18), CSRF (ch03#4).

``m3.auth-session-audit``
    Three structural signals from research ch03#19 that need no credential: the hardening
    attributes of the session cookie (``Secure``/``HttpOnly``/``SameSite``), the transport a
    login form posts over (plaintext ``http://`` is a credential in the clear), and the
    user-enumeration oracle — a plausible privileged name versus a random one, both with a
    single dummy password, compared for a differential. The enumeration pass is
    *existence verification*, bounded and lockout-safe, exactly as M2's Kerberos check is
    (research ch02#19); it never tries a real credential (F-01-09).
    Session fixation and logout invalidation are **not** implemented — both need a successful
    login, which would mean supplying real credentials; ADR-100.6 records the gap.

``m3.idor-oracle``
    Research ch03#18's cross-account differential, degraded honestly for a scanner with no
    credentials: enumerate adjacent identifiers on an object-id parameter and require *both* a
    single-record-shaped response *and* a per-record identity (an email/username field) that
    changes with the identifier. When a second session is configured
    (``ARACHNE_WEB_SESSION_B_COOKIE``), the same identifier is read as both identities and a
    foreign-object read is reported. Bounded to a handful of identifiers.

``m3.csrf-audit``
    Read-only classification of research ch03#4: a state-changing endpoint is reported when its
    form carries no anti-CSRF token *and* the session cookie is not ``SameSite``-protected — the
    two-part check the research describes — plus a note when a mutating action is reachable by
    GET. No payload is sent.
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator
from typing import Any
from urllib.parse import urlencode

from arachne.core.results import CheckResult
from arachne.core.target import TargetKind
from arachne.modules.base import CheckMetadata, Module
from arachne.modules.context import CheckContext
from arachne.modules.m3.inventory import Form, origin_of, page_from_exchange
from arachne.modules.m3.support import (
    WebCheck,
    compare_pages,
    http_or_skip,
    nonce,
    owns_origin,
    payloads_for,
    probe_url,
    safe_fetch,
    skip,
    web_candidate,
    web_or_skip,
)

__all__ = ["AuthSessionAudit", "CsrfAudit", "IdorOracle"]

#: Identifier values the IDOR check enumerates (small, adjacent, deterministic).
IDOR_IDS: tuple[str, ...] = ("1", "2", "3")

#: A single-record page carries a *few* identity values; a listing carries many. Requiring the
#: count to be small is what separates "id=2 returned another user" from "a paginated list".
MAX_IDENTITY_MARKERS = 4

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_JSON_IDENTITY_RE = re.compile(
    r'"(?:user(?:name)?|email|mail|login|account|owner|customer|name)"\s*:', re.IGNORECASE
)


class AuthSessionAudit(WebCheck, Module):
    """``m3.auth-session-audit`` — session, transport and enumeration posture (ch03#19)."""

    metadata = CheckMetadata(
        id="m3.auth-session-audit",
        module="M3",
        name="auth-session-audit",
        version="1.0",
        title="Authentication and session handling audit",
        description=(
            "Reviews the session cookie's hardening attributes, the transport a login form "
            "posts over, and whether the login response distinguishes a plausible privileged "
            "user name from a random one (user enumeration). The enumeration pass sends a "
            "single dummy password per name, is bounded to a few names and never attempts a "
            "real credential. Session fixation and logout invalidation are out of scope."
        ),
        research_ref="ch03#19",
        framework=(
            "WSTG-IDNT-04",
            "WSTG-ATHN-01",
            "WSTG-ATHN-04",
            "API2:2023",
            "CWE-287",
        ),
        cwe="CWE-287",
        target_kinds=(TargetKind.URL,),
        severity_hint="medium",
        type="active",
        safe=True,
        verifiable=False,
        estimated_requests=8,
        requires_active_checks=True,
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

        payloads = payloads_for(ctx)
        origin = origin_of(ctx.asset.value)
        session_names = payloads.session_cookie_names()
        findings = 0

        # 1. Session cookie hardening.
        cookies = tuple(
            cookie for cookie in inventory.cookies() if cookie.name.lower() in session_names
        )
        weak = tuple(cookie for cookie in cookies if cookie.missing_flags)
        if weak:
            findings += 1
            missing = sorted({flag for cookie in weak for flag in cookie.missing_flags})
            yield web_candidate(
                ctx,
                f"Session cookie is missing hardening attributes ({', '.join(missing)})",
                artifact={
                    "signal": "session-cookie-hardening",
                    "family": "auth-session",
                    "technique": "cookie-flags",
                    "origin": origin,
                    "cookies": [cookie.to_dict() for cookie in weak],
                    "missing": missing,
                    "protocol": "https" if origin.startswith("https://") else "http",
                },
                confidence=0.8,
                cwe="CWE-614",
                detail=f"{origin}: {', '.join(f'{c.name} lacks {c.missing_flags}' for c in weak)}",
            )

        # 2. Login transport.
        login_forms = [
            form
            for form in inventory.login_forms(
                user_fields=payloads.strings("auth", "user_fields"),
                password_fields=payloads.strings("auth", "password_fields"),
            )
            if origin_of(form.action) == origin or origin_of(form.page_url) == origin
        ]
        for form in login_forms:
            if form.action.lower().startswith("http://"):
                findings += 1
                yield web_candidate(
                    ctx,
                    "Login credentials are submitted over plaintext HTTP",
                    artifact={
                        "signal": "insecure-login-transport",
                        "family": "auth-session",
                        "technique": "transport",
                        "endpoint": form.action,
                        "scheme": "http",
                    },
                    confidence=0.8,
                    cwe="CWE-319",
                    detail=f"{form.action} accepts credentials over http://",
                    source=form.action,
                )

        # 3. User-enumeration oracle (bounded, one dummy password, existence-only).
        for form in login_forms[:1]:
            enumeration = await self._enumeration(ctx, form)
            if enumeration is not None:
                findings += 1
                yield enumeration

        if not findings:
            yield ctx.clean(
                "no auth/session weakness observed",
                detail=(
                    f"reviewed {len(cookies)} session cookie(s) and "
                    f"{len(login_forms)} login form(s)"
                ),
            )

    async def _enumeration(self, ctx: CheckContext, form: Form) -> CheckResult | None:
        payloads = payloads_for(ctx)
        user_field = form.any_input_named(payloads.strings("auth", "user_fields"))
        password_field = form.any_input_named(payloads.strings("auth", "password_fields"))
        if user_field is None or password_field is None:
            return None
        dummy = payloads.string("auth", "dummy_password", default="arachne-not-a-credential")
        unknown = f"arachne-nonexistent-{nonce()}"
        names = [*payloads.strings("auth", "usernames")[:2], unknown]
        responses: dict[str, Any] = {}
        for name in names:
            fields = _form_fields(form, overrides={user_field: name, password_field: dummy})
            exchange = await safe_fetch(
                ctx,
                form.action,
                method="POST",
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                content=urlencode(fields),
                follow_redirects=False,
            )
            if exchange is None:
                return None
            responses[name] = exchange

        baseline = responses[unknown]
        differential: list[str] = []
        for name in names[:-1]:
            candidate = responses[name]
            delta = compare_pages(page_from_exchange(baseline), page_from_exchange(candidate))
            if delta.status_changed or delta.ratio < 0.9:
                differential.append(name)
        if not differential:
            return None
        strongest = responses[differential[0]]
        return web_candidate(
            ctx,
            f"Login response distinguishes a known user name ({', '.join(differential)})",
            artifact={
                "signal": "user-enumeration",
                "family": "auth-session",
                "technique": "login-differential",
                "endpoint": form.action,
                "plausible_names": differential,
                "unknown_status": baseline.status_code,
                "differential_status": strongest.status_code,
                "responses_differ": True,
                "dummy_logins_attempted": 1,
            },
            exchanges=(baseline, strongest),
            confidence=0.65,
            cwe="CWE-200",
            detail=(
                f"{form.action} answered differently for {', '.join(differential)} than for a "
                "random name (one dummy password each)"
            ),
            source=form.action,
        )


class IdorOracle(WebCheck, Module):
    """``m3.idor-oracle`` — object-reference enumeration and cross-account read (ch03#18)."""

    metadata = CheckMetadata(
        id="m3.idor-oracle",
        module="M3",
        name="idor-oracle",
        version="1.0",
        title="IDOR / object-level authorization oracle",
        description=(
            "Enumerates adjacent identifiers on object-id parameters and reports a finding only "
            "when several return distinct single-record pages that each carry a per-record "
            "identity (an email/username field). When a second session is configured the same "
            "identifier is read as both identities, and a foreign-object read is reported. "
            "Read-only: only GET requests are sent."
        ),
        research_ref="ch03#18",
        framework=("WSTG-ATHZ-04", "API1:2023", "CWE-639"),
        cwe="CWE-639",
        target_kinds=(TargetKind.URL,),
        severity_hint="high",
        type="active",
        safe=True,
        verifiable=False,
        estimated_requests=18,
        requires_active_checks=True,
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

        payloads = payloads_for(ctx)
        object_params = {name.lower() for name in payloads.strings("params", "object_ids")}
        origin = origin_of(ctx.asset.value)
        targets = [
            (url, param)
            for url, param in inventory.parameter_targets(names=object_params)
            if origin_of(url) == origin
        ][: max(1, ctx.config.web.max_params_per_check // 2)]
        if not targets:
            yield ctx.clean(
                "no object-identifier parameter to probe",
                detail="the crawl found no parameter whose name suggests an object reference",
            )
            return

        findings = 0
        for url, param in targets:
            observation = await self._enumerate(ctx, url, param)
            if observation is None:
                continue
            findings += 1
            yield observation
        if not findings:
            yield ctx.clean(
                "no cross-object access observed",
                detail=f"enumerated {len(targets)} object-identifier parameter(s)",
            )

    async def _enumerate(self, ctx: CheckContext, url: str, param: str) -> CheckResult | None:
        pages: list[tuple[str, Any]] = []
        for identifier in IDOR_IDS:
            exchange = await safe_fetch(
                ctx, probe_url(url, param, identifier), follow_redirects=False
            )
            if exchange is None:
                return None
            if exchange.status_code != 200:
                continue
            pages.append((identifier, exchange))
        if len(pages) < 2:
            return None

        distinct: list[str] = []
        bodies: list[str] = []
        for identifier, exchange in pages:
            others = [other for _, other in pages if other is not exchange]
            if all(
                compare_pages(page_from_exchange(exchange), page_from_exchange(other)).ratio < 0.9
                for other in others
            ):
                distinct.append(identifier)
            bodies.append(exchange.body)
        identities = [len(_identity_markers(body)) for body in bodies]
        if not distinct or not all(0 < count <= MAX_IDENTITY_MARKERS for count in identities):
            return None
        observed = _identity_markers(pages[0][1].body)

        cross_account: bool | None = None
        if ctx.config.web.has_second_identity():
            cross_account = await self._cross_account(ctx, url, param, pages[0][0])
        confidence = 0.8 if cross_account else 0.65
        return web_candidate(
            ctx,
            f"Object reference '{param}' exposes other records",
            artifact={
                "signal": "idor",
                "family": "idor",
                "endpoint": url,
                "parameter": param,
                "identifiers": [identifier for identifier, _ in pages],
                "distinct_records": distinct,
                "identity_markers": observed[:3],
                "authenticated": ctx.config.web.session_cookie is not None,
                "second_identity": cross_account,
                "shape": _record_shape(pages[0][1].body),
            },
            exchanges=tuple(exchange for _, exchange in pages),
            confidence=confidence,
            cwe="CWE-639",
            detail=(
                f"{url} parameter '{param}': identifiers "
                f"{', '.join(identifier for identifier, _ in pages)} returned distinct "
                "single-record responses carrying per-record identities"
            ),
            source=url,
        )

    async def _cross_account(
        self, ctx: CheckContext, url: str, param: str, identifier: str
    ) -> bool | None:
        """Read the same identifier as a second identity and compare the two records."""
        first = await safe_fetch(ctx, probe_url(url, param, identifier), follow_redirects=False)
        second = await safe_fetch(
            ctx,
            probe_url(url, param, identifier),
            follow_redirects=False,
            second_identity=True,
        )
        if first is None or second is None:
            return None
        if first.status_code != 200 or second.status_code != 200:
            return None
        delta = compare_pages(page_from_exchange(first), page_from_exchange(second))
        # Two identities reading the same object and getting *different* records means at least
        # one of them read an object it does not own.
        return delta.ratio < 0.99 and delta.significant(min_ratio_drop=0.01)


class CsrfAudit(WebCheck, Module):
    """``m3.csrf-audit`` — state-changing endpoints without anti-CSRF controls (ch03#4)."""

    metadata = CheckMetadata(
        id="m3.csrf-audit",
        module="M3",
        name="csrf-audit",
        version="1.0",
        title="CSRF protection audit",
        description=(
            "Classifies every state-changing form the crawl found by whether it carries a "
            "per-session anti-CSRF token and whether the session cookie is SameSite-protected, "
            "and reports mutating actions reachable by GET. Read-only: this check sends no "
            "payload and submits no form."
        ),
        research_ref="ch03#4",
        framework=("WSTG-SESS-05", "WSTG-BUSL-02", "CWE-352"),
        cwe="CWE-352",
        target_kinds=(TargetKind.URL,),
        severity_hint="medium",
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

        payloads = payloads_for(ctx)
        state_change = payloads.strings("csrf", "state_change_fragments")
        token_hints = payloads.strings("csrf", "token_fields")
        origin = origin_of(ctx.asset.value)
        session_names = payloads.session_cookie_names()
        cookies = tuple(
            cookie for cookie in inventory.cookies() if cookie.name.lower() in session_names
        )
        samesite = sorted({c.samesite for c in cookies if c.samesite}, key=str)
        same_site_protected = any(
            (cookie.samesite or "").lower() in {"strict", "lax"} for cookie in cookies
        )

        forms = [
            form
            for form in inventory.state_changing_forms(state_change)
            if origin_of(form.action) == origin or origin_of(form.page_url) == origin
        ]
        findings = 0
        for form in forms:
            token_fields = [
                item.name
                for item in form.inputs
                if any(hint in item.name.lower() for hint in token_hints)
            ]
            get_mutation = not form.is_post
            if token_fields and not get_mutation:
                continue
            if not token_fields and same_site_protected and not get_mutation:
                # A per-session token is absent, but the cookie's SameSite policy is the
                # defence the research accepts as mitigating the class: not a finding.
                continue
            findings += 1
            yield web_candidate(
                ctx,
                (
                    f"State-changing action is reachable by GET ({form.action})"
                    if get_mutation
                    else f"State-changing form has no anti-CSRF token ({form.action})"
                ),
                artifact={
                    "signal": "csrf",
                    "family": "csrf",
                    "endpoint": form.action,
                    "form_method": form.method,
                    "reachable_via_get": get_mutation,
                    "csrf_fields": token_fields,
                    "cookie_names": [cookie.name for cookie in cookies],
                    "samesite": samesite or None,
                    "samesite_protected": same_site_protected,
                    "origin": origin,
                },
                confidence=0.6 if get_mutation else 0.65,
                cwe="CWE-352",
                detail=(
                    f"{form.action} is a {form.method} form with "
                    f"{'no' if not token_fields else 'a'} anti-CSRF token"
                ),
                source=form.action,
            )
        if not findings:
            yield ctx.clean(
                "no unprotected state-changing endpoint found",
                detail=f"reviewed {len(forms)} form(s) on {origin}",
            )


# --------------------------------------------------------------------------- helpers
def _form_fields(form: Form, *, overrides: dict[str, str]) -> dict[str, str]:
    """The form's fields with ``overrides`` applied (defaults from the crawled page)."""
    fields: dict[str, str] = {}
    for item in form.inputs:
        if item.type.lower() in {"submit", "button", "file", "image", "reset"}:
            continue
        fields[item.name] = item.value or ""
    fields.update(overrides)
    return fields


def _identity_markers(body: str) -> list[str]:
    """Per-record identity values in a body (emails, and JSON identity field names)."""
    markers = _EMAIL_RE.findall(body)
    if not markers:
        markers = _JSON_IDENTITY_RE.findall(body)
    return list(dict.fromkeys(markers))


def _record_shape(body: str) -> str:
    stripped = body.lstrip()
    if stripped.startswith(("{", "[")):
        return "json"
    return "html"
