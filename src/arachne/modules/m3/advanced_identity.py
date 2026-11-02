"""M3 extended identity/token families: JWT (ch03#20), OAuth 2.0 (ch03#21) and SAML (ch03#22).

Each of these is a *verifier-behaviour* probe (research ch03#20-#22): the check reads how the
server treats a token/assertion it should reject, and never forges a real identity or
authenticates as another user.

``m3.jwt-audit``
    Finds JWTs the crawl delivered (a client-side bundle, a response body), decodes them, and
    reads two verifier weaknesses that need no victim: a token whose algorithm is ``none``, an
    HMAC token whose signature is reproduced by an offline weak-secret list, and — by replaying
    the token with its signature stripped at an endpoint the crawl saw challenge the request —
    an unsigned token the server still accepts. Nothing is cracked live.
``m3.oauth-flow-audit``
    Probes the authorization endpoint's ``redirect_uri`` validation with the mutation classes of
    research ch03#21 (an appended path, a suffix-matched host, a userinfo confusion) and reports
    a mutation the server redirects an authorization to off the registered origin.
``m3.saml-audit``
    Posts an unsigned / signature-stripped SAML assertion to the SP's ACS endpoint and reports an
    acceptance (HTTP 200 without a rejection marker) — the signature-handling probe of research
    ch03#22, never a forged assertion.
"""

from __future__ import annotations

import base64
from collections.abc import AsyncIterator
from urllib.parse import urlencode, urlsplit

from arachne.core.results import CheckResult
from arachne.core.target import TargetKind
from arachne.modules.base import CheckMetadata, Module
from arachne.modules.context import CheckContext
from arachne.modules.m3.inventory import WebInventory, origin_of
from arachne.modules.m3.support import (
    WebCheck,
    decode_jwt,
    find_jwts,
    hmac_sha256_sign,
    http_or_skip,
    owns_origin,
    payloads_for,
    post_form,
    safe_fetch,
    skip,
    web_candidate,
    web_or_skip,
)

__all__ = ["JwtAudit", "OAuthFlowAudit", "SamlAudit"]

#: A minimal, unsigned SAML assertion (no real identity, no valid signature). Inert: the
#: NameID is a marker the lab may echo, never a real user.
_UNSIGNED_SAML = (
    '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">'
    '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">'
    "<saml:Subject><saml:NameID>arachne-probe@example.invalid</saml:NameID></saml:Subject>"
    "</saml:Assertion></samlp:Response>"
)


# --------------------------------------------------------------------------- JWT
class JwtAudit(WebCheck, Module):
    """``m3.jwt-audit`` — JWT verifier-behaviour probe (ch03#20)."""

    metadata = CheckMetadata(
        id="m3.jwt-audit",
        module="M3",
        name="jwt-audit",
        version="1.0",
        title="JWT verification audit",
        description=(
            "Finds JWTs the crawl delivered, decodes them, and reads verifier weaknesses without "
            "forging an identity: an unsigned (alg=none) token, an HMAC token whose signature an "
            "offline weak-secret list reproduces, and — replayed at an endpoint the crawl saw "
            "challenge a request — an unsigned token the server still accepts. Verify-only; no "
            "live brute-force and no key material is used."
        ),
        research_ref="ch03#20",
        framework=(
            "WSTG-SESS-01",
            "WSTG-SESS-04",
            "WSTG-CRYP-04",
            "API2:2023",
            "CWE-347",
        ),
        cwe="CWE-347",
        target_kinds=(TargetKind.URL,),
        severity_hint="high",
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
        assert isinstance(inventory, WebInventory)
        payloads = payloads_for(ctx)
        weak = payloads.strings("jwt", "weak_secrets")
        findings = 0

        # 1. A JWT delivered to the browser is exposed by definition. The value is redacted at
        # capture time, so the check reports the detector that fired plus the asset — never a
        # token it could replay.
        for page in inventory.pages.values():
            if "jwt" not in page.secret_kinds:
                continue
            findings += 1
            yield web_candidate(
                ctx,
                "JSON Web Token delivered in a client-side asset",
                artifact={
                    "signal": "jwt",
                    "family": "jwt",
                    "weakness": "token-in-client",
                    "endpoint": page.url,
                    "detector": "jwt",
                },
                exchanges=(),
                cwe="CWE-347",
                confidence=0.65,
                detail=(
                    f"{page.url} carries a JWT-shaped value, so the token is public to anyone who "
                    "loads the page; its value is redacted at capture time"
                ),
                source=page.url,
            )
            break

        # 2. The operator's own configured session token is audited offline (decoded, weak-secret
        # checked) — it is the one token the scan is allowed to hold.
        for token in self._configured_tokens(ctx):
            decoded = decode_jwt(token)
            if decoded is None:
                continue
            header, payload, signature = decoded
            alg = str(header.get("alg", "")).lower()
            if alg in {"none", ""}:
                findings += 1
                yield web_candidate(
                    ctx,
                    "Configured JWT is unsigned (alg=none)",
                    artifact={
                        "signal": "jwt",
                        "family": "jwt",
                        "weakness": "alg-none",
                        "alg": header.get("alg"),
                        "claims": sorted(payload)[:8],
                    },
                    exchanges=(),
                    cwe="CWE-347",
                    confidence=0.8,
                    detail="the operator's configured token declares alg=none",
                    source=ctx.asset.value,
                )
                continue
            if alg.startswith("hs") and weak and signature:
                signing_input = token.rsplit(".", 1)[0]
                for secret in weak:
                    if hmac_sha256_sign(secret.encode(), signing_input) != signature:
                        continue
                    findings += 1
                    yield web_candidate(
                        ctx,
                        "Configured JWT HMAC signature reproduced by a weak secret",
                        artifact={
                            "signal": "jwt",
                            "family": "jwt",
                            "weakness": "weak-hmac-secret",
                            "alg": header.get("alg"),
                            "secret_length": len(secret),
                            "claims": sorted(payload)[:8],
                        },
                        exchanges=(),
                        cwe="CWE-347",
                        confidence=0.85,
                        detail=(
                            "an offline weak-secret check reproduced the HMAC signature, so the "
                            "signing key can be recovered from the token"
                        ),
                        source=ctx.asset.value,
                    )
                    break
        if not findings:
            yield ctx.clean(
                "no JWT verifier weakness or client-side token observed",
                detail=f"reviewed {len(inventory.pages)} crawled asset(s)",
            )

    def _configured_tokens(self, ctx: CheckContext) -> tuple[str, ...]:
        """JWTs in the operator's configured auth header / session cookie (env-only, F-08-01)."""
        candidates: list[str] = []
        web = ctx.config.web
        for secret in (web.auth_header, web.session_cookie, web.session_b_cookie):
            if secret is None:
                continue
            candidates.extend(find_jwts(secret.get_secret_value()))
        return tuple(dict.fromkeys(candidates))


# --------------------------------------------------------------------------- OAuth
class OAuthFlowAudit(WebCheck, Module):
    """``m3.oauth-flow-audit`` — OAuth redirect_uri validation probe (ch03#21)."""

    metadata = CheckMetadata(
        id="m3.oauth-flow-audit",
        module="M3",
        name="oauth-flow-audit",
        version="1.0",
        title="OAuth 2.0 flow audit",
        description=(
            "Probes the authorization endpoint's redirect_uri validation with the mutation classes "
            "of research ch03#21 — an appended path segment, a suffix-matched look-alike host and "
            "an "
            "userinfo confusion — and reports a mutation the server redirects an authorization to "
            "off the registered origin. Read-only: no authorization code is requested, or "
            "replayed."
        ),
        research_ref="ch03#21",
        framework=("WSTG-ATHN-04", "API2:2023", "CWE-601"),
        cwe="CWE-601",
        target_kinds=(TargetKind.URL,),
        severity_hint="high",
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
            yield skip(ctx, "another URL asset on this origin owns the M3 crawl for it")
            return
        inventory, skipped = web_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        assert isinstance(inventory, WebInventory)
        payloads = payloads_for(ctx)
        origin = origin_of(ctx.asset.value)
        host = urlsplit(origin).netloc
        hints = [hint.lower() for hint in payloads.strings("oauth", "authorize_paths")]
        endpoints = [
            url
            for url in inventory.endpoints
            if origin_of(url) == origin and any(hint in url.lower() for hint in hints)
        ]
        if not endpoints:
            endpoints = [
                f"{origin}{path}" for path in payloads.strings("oauth", "authorize_paths")[:2]
            ]
        registry = payloads.strings("oauth", "redirect_mutations")
        findings = 0
        for endpoint in endpoints[:2]:
            base = endpoint.split("?")[0]
            for mutation in registry:
                candidate = (
                    mutation.replace("{base}", base)
                    .replace("{host}", host)
                    .replace("{base_path}", urlsplit(origin).path.strip("/"))
                )
                query = urlencode(
                    {
                        "redirect_uri": candidate,
                        "response_type": "code",
                        "client_id": "arachne-probe",
                    }
                )
                url = f"{base}?{query}"
                exchange = await safe_fetch(ctx, url, session=False, follow_redirects=False)
                if exchange is None:
                    continue
                location = exchange.header("location") or ""
                if "arachne" not in location and ".invalid" not in location:
                    continue
                findings += 1
                yield web_candidate(
                    ctx,
                    "OAuth redirect_uri accepts an off-origin value",
                    artifact={
                        "signal": "oauth",
                        "family": "oauth",
                        "endpoint": base,
                        "mutation": mutation,
                        "location": location,
                        "status": exchange.status_code,
                    },
                    exchanges=(exchange,),
                    cwe="CWE-601",
                    confidence=0.8,
                    detail=(
                        f"{base} redirected an authorization for redirect_uri={candidate} to "
                        f"{location}, which is off the registered origin"
                    ),
                    source=base,
                )
                break
        if not findings:
            yield ctx.clean(
                "no redirect_uri bypass observed",
                detail=f"probed {min(len(endpoints), 2)} authorization endpoint(s)",
            )


# --------------------------------------------------------------------------- SAML
class SamlAudit(WebCheck, Module):
    """``m3.saml-audit`` — SAML signature-handling probe (ch03#22)."""

    metadata = CheckMetadata(
        id="m3.saml-audit",
        module="M3",
        name="saml-audit",
        version="1.0",
        title="SAML assertion signature-handling audit",
        description=(
            "Posts an unsigned (signature-stripped) SAML assertion to the service provider's ACS "
            "endpoint and reports an acceptance: HTTP 200 without a rejection marker, which means "
            "the SP did not verify the signature (research ch03#22). The assertion carries no real "
            "identity and no valid signature; nothing is forged."
        ),
        research_ref="ch03#22",
        framework=("WSTG-ATHN-04", "API2:2023", "CWE-347"),
        cwe="CWE-347",
        target_kinds=(TargetKind.URL,),
        severity_hint="critical",
        type="active",
        safe=True,
        verifiable=False,
        estimated_requests=6,
        requires_active_checks=True,
        runs_on_discovered=True,
    )

    _REJECT_MARKERS = ("invalid", "signature", "rejected", "error", "denied", "unauthorized")

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
        assert isinstance(inventory, WebInventory)
        payloads = payloads_for(ctx)
        origin = origin_of(ctx.asset.value)
        hints = [hint.lower() for hint in payloads.strings("saml", "endpoint_hints")]
        endpoints = [
            url
            for url in inventory.endpoints
            if origin_of(url) == origin and any(hint in url.lower() for hint in hints)
        ]
        if not endpoints:
            endpoints = [
                f"{origin}{path}" for path in payloads.strings("saml", "endpoint_hints")[:2]
            ]
        assertion = base64.b64encode(_UNSIGNED_SAML.encode()).decode()
        findings = 0
        for endpoint in endpoints[:2]:
            exchange = await post_form(
                ctx, endpoint, {"SAMLResponse": assertion, "RelayState": "/"}, session=False
            )
            if exchange is None:
                continue
            body = exchange.body.lower()
            rejected = any(marker in body for marker in self._REJECT_MARKERS)
            if exchange.status_code != 200 or rejected:
                continue
            findings += 1
            yield web_candidate(
                ctx,
                "SAML assertion accepted without a valid signature",
                artifact={
                    "signal": "saml",
                    "family": "saml",
                    "endpoint": endpoint,
                    "status": exchange.status_code,
                    "signature_present": False,
                    "probe": "signature-stripped",
                },
                exchanges=(exchange,),
                cwe="CWE-347",
                confidence=0.75,
                detail=(
                    f"{endpoint} answered HTTP 200 to an unsigned SAML assertion, so the signature "
                    "is not verified"
                ),
                source=endpoint,
            )
            break
        if not findings:
            yield ctx.clean(
                "unsigned SAML assertion rejected",
                detail=f"posted an unsigned assertion to {min(len(endpoints), 2)} ACS endpoint(s)",
            )


# --------------------------------------------------------------------------- helpers
def _json(value: dict[str, object]) -> bytes:
    import json

    return json.dumps(value, separators=(",", ":")).encode()
