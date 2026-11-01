"""M4 transport-hygiene checks: headers, TLS, cookies, CORS and email authentication.

This module is the "configuration review" half of M4. Three of its five checks are pure
review of what the crawl already fetched (headers, cookies) or of a bounded origin matrix
(CORS); the TLS review uses the raw-network client M2 built; the email review asks a
DNS-over-HTTPS resolver for the domain's SPF/DKIM/DMARC records through the OSINT layer, so
it is off unless OSINT is enabled and the ``dns`` provider is selected.

The overlap with M3 is deliberate and resolved by the correlation engine: ``CWE-693``
(headers), ``CWE-614`` (cookies) and ``CWE-942`` (CORS) are the same root cause whichever
module observes it, so the dedupe pass keeps one finding with both modules as contributors
(docs/spec/05- "Deduplication & overlap rules").
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

from arachne.core.results import CheckResult
from arachne.core.target import TargetKind
from arachne.modules.base import Asset, CheckMetadata, Module
from arachne.modules.context import CheckContext
from arachne.modules.m3.inventory import Page, WebInventory, origin_of
from arachne.modules.m3.support import cookie_flag_summary, web_or_skip
from arachne.modules.m4.support import (
    UrlCheck,
    asset_origin,
    corpus_for,
    exchange_from_page,
    fetch_page,
    finding_cap,
    http_or_skip,
    m4_candidate,
    owns_origin,
    skip,
)
from arachne.modules.providers.sources import dns_txt_url, parse_doh_txt

if TYPE_CHECKING:
    from arachne.modules.providers import OsintAccess

__all__ = [
    "CookieFlagAudit",
    "CorsConfigReview",
    "EmailAuthReview",
    "SecurityHeaderReview",
    "TlsConfigReview",
]

_SPF_ALL_RE = re.compile(r"(?i)([+~?-])\s*all\b")
_DMARC_POLICY_RE = re.compile(r"(?i)\bp\s*=\s*(none|quarantine|reject)\b")
_IP_LITERAL_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$|^\[?[0-9a-f:]+\]?$", re.IGNORECASE)


def _pages_of(ctx: CheckContext, origin: str) -> tuple[Page, ...]:
    inventory = ctx.web
    if not isinstance(inventory, WebInventory):
        return ()
    return tuple(page for page in inventory.pages.values() if origin_of(page.url) == origin)


def _representative(pages: tuple[Page, ...], preferred: str) -> Page | None:
    for page in pages:
        if page.url == preferred:
            return page
    return pages[0] if pages else None


def _domain_of(ctx: CheckContext) -> str | None:
    """The registrable domain this asset asks about (``None`` for an IP or a bare host)."""
    value = ctx.asset.value
    host = urlsplit(value).hostname if "://" in value else value
    if not host:
        return None
    host = host.strip("[]").lower()
    if _IP_LITERAL_RE.match(host) or host in {"localhost"}:
        return None
    return host


class SecurityHeaderReview(UrlCheck, Module):
    """``m4.security-header-review`` — response hardening baseline (ch04#16)."""

    metadata = CheckMetadata(
        id="m4.security-header-review",
        module="M4",
        name="security-header-review",
        version="1.0",
        title="Security response headers missing or weak",
        description=(
            "Reviews every crawled page's response headers against the hardening baseline "
            "(HSTS on HTTPS, CSP with frame-ancestors, X-Frame-Options, "
            "X-Content-Type-Options, Referrer-Policy, Permissions-Policy) and flags a CSP "
            "that names unsafe-inline/unsafe-eval/a bare wildcard. One finding per origin, "
            "because the gap is an origin-wide configuration decision."
        ),
        research_ref="ch04#16",
        cwe="CWE-693",
        target_kinds=(TargetKind.URL,),
        severity_hint="low",
        type="hybrid",
        safe=True,
        verifiable=False,
        estimated_requests=1,
        runs_on_discovered=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        _client, skipped = http_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        if not owns_origin(ctx):
            yield skip(ctx, "another URL asset on this origin owns the M4 review for it")
            return
        inventory, skipped = web_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        assert isinstance(inventory, WebInventory)
        corpus = corpus_for(ctx)
        origin = asset_origin(ctx)
        pages = _pages_of(ctx, origin)
        if not pages:
            yield ctx.clean(
                "no page was fetched for this origin", detail="the crawl reached no page here"
            )
            return
        protocol = "https" if origin.startswith("https://") else "http"
        expected = corpus.header_baseline(https=protocol == "https")
        present: dict[str, None] = {}
        for page in pages:
            for name in page.headers:
                present.setdefault(name.lower(), None)
        missing = [name for name in expected if name not in present]
        weak_csp = _weak_csp(pages, corpus.weak_csp_markers())
        representative = _representative(pages, ctx.asset.value)
        if not missing and not weak_csp:
            yield ctx.clean(
                "response hardening headers present",
                detail=f"{origin} carries the reviewed headers",
            )
            return
        yield m4_candidate(
            ctx,
            "Security hardening headers missing"
            + (f" ({', '.join(missing)})" if missing else " or weak"),
            artifact={
                "signal": "missing-headers",
                "family": "security-headers",
                "protocol": protocol,
                "missing": missing,
                "weak_csp": weak_csp,
                "present": sorted(present),
                "pages_checked": len(pages),
                "origin": origin,
                "server": inventory.server_banner(),
            },
            exchanges=(None if representative is None else exchange_from_page(representative),),
            confidence=0.8,
            detail=f"missing on {origin}: {', '.join(missing) or 'none'}"
            + (f"; weak CSP directives: {', '.join(weak_csp)}" if weak_csp else ""),
        )


class CookieFlagAudit(UrlCheck, Module):
    """``m4.cookie-flag-audit`` — Secure/HttpOnly/SameSite review (ch04#18)."""

    metadata = CheckMetadata(
        id="m4.cookie-flag-audit",
        module="M4",
        name="cookie-flag-audit",
        version="1.0",
        title="Session cookie lacks hardening attributes",
        description=(
            "Reads the structural Set-Cookie projection the HTTP client captures (name and "
            "attributes only — never the value) and reports session-like cookies missing "
            "Secure, HttpOnly or SameSite, weighted by whether the name suggests a session "
            "and whether the cookie was set over plaintext HTTP."
        ),
        research_ref="ch04#18",
        cwe="CWE-614",
        target_kinds=(TargetKind.URL,),
        severity_hint="medium",
        type="hybrid",
        safe=True,
        verifiable=False,
        estimated_requests=1,
        runs_on_discovered=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        _client, skipped = http_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        if not owns_origin(ctx):
            yield skip(ctx, "another URL asset on this origin owns the M4 review for it")
            return
        inventory, skipped = web_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        assert isinstance(inventory, WebInventory)
        corpus = corpus_for(ctx)
        origin = asset_origin(ctx)
        pages = _pages_of(ctx, origin)
        session_names = corpus.session_cookie_names()
        cookies = tuple(
            cookie
            for cookie in inventory.cookies()
            if cookie.name.lower() in session_names
            or any(token in cookie.name.lower() for token in ("sess", "auth", "sid", "token"))
        )
        weak = tuple(cookie for cookie in cookies if cookie.missing_flags)
        protocol = "https" if origin.startswith("https://") else "http"
        if not weak:
            yield ctx.clean(
                "no session cookie hardening gap found",
                detail=f"{origin} sets {len(cookies)} session-like cookie(s) with their flags",
            )
            return
        missing = sorted({flag for cookie in weak for flag in cookie.missing_flags})
        representative = _representative(pages, ctx.asset.value)
        yield m4_candidate(
            ctx,
            f"Session cookie lacks hardening attributes ({', '.join(missing)})",
            artifact={
                "signal": "weak-cookie-flags",
                "family": "cookies",
                "protocol": protocol,
                "missing": missing,
                "cookie_names": [cookie.name for cookie in weak][:10],
                "detail": [cookie.to_dict() for cookie in weak][:10],
                "origin": origin,
                "summary": cookie_flag_summary(weak),
            },
            exchanges=(None if representative is None else exchange_from_page(representative),),
            confidence=0.8,
            detail=f"{origin}: " + ", ".join(f"{c.name} lacks {c.missing_flags}" for c in weak),
        )


class CorsConfigReview(UrlCheck, Module):
    """``m4.cors-config-review`` — origin matrix against sensitive endpoints (ch04#19)."""

    metadata = CheckMetadata(
        id="m4.cors-config-review",
        module="M4",
        name="cors-config-review",
        version="1.0",
        title="CORS policy allows cross-origin reads",
        description=(
            "Runs the origin matrix of research ch04#19 — an arbitrary origin, the literal "
            "'null', and a look-alike host — against the crawled JSON/API endpoints and "
            "reads Access-Control-Allow-Origin/Allow-Credentials. A reflected origin with "
            "credentials is a cross-origin read primitive; a null acceptance and a wildcard "
            "with credentials each carry their own weight. GET only."
        ),
        research_ref="ch04#19",
        cwe="CWE-942",
        target_kinds=(TargetKind.URL,),
        severity_hint="medium",
        type="active",
        safe=True,
        verifiable=False,
        estimated_requests=9,
        requires_active_checks=True,
        runs_on_discovered=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        _client, skipped = http_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        if not owns_origin(ctx):
            yield skip(ctx, "another URL asset on this origin owns the M4 probes for it")
            return
        inventory, skipped = web_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        assert isinstance(inventory, WebInventory)
        corpus = corpus_for(ctx)
        origin = asset_origin(ctx)
        origins = corpus.cors_origins() or ("https://arachne-cors.invalid", "null")
        candidates = [
            page.url
            for page in inventory.pages.values()
            if origin_of(page.url) == origin and _api_shaped(page)
        ]
        if not candidates:
            candidates = [page.url for page in _pages_of(ctx, origin)][:3]
        if not candidates:
            yield ctx.clean(
                "no endpoint to probe for CORS policy",
                detail="the crawl fetched no page on this origin",
            )
            return
        cap = finding_cap(ctx)
        findings = 0
        for url in candidates[:4]:
            # One finding per endpoint, not one per probe origin: the reflection is one root
            # cause, and the artifact records every origin that was tried. The most severe
            # combination observed is the one reported.
            best: tuple[int, Page, bool, bool, bool, str] | None = None
            tested: list[str] = []
            reflected_any = wildcard_any = null_reflected = False
            for probe_origin in origins:
                page = await fetch_page(ctx, url, headers={"Origin": probe_origin})
                if page is None:
                    continue
                acao = page.header("access-control-allow-origin")
                acac = (page.header("access-control-allow-credentials") or "").lower()
                credentials = acac == "true"
                if acao is None:
                    continue
                tested.append(probe_origin)
                reflected = acao == probe_origin
                wildcard = acao.strip() == "*"
                if not (reflected or wildcard):
                    continue
                reflected_any = reflected_any or reflected
                wildcard_any = wildcard_any or wildcard
                null_reflected = null_reflected or (reflected and probe_origin == "null")
                if wildcard and not credentials:
                    continue
                severity = 2 if (reflected and credentials) else (1 if reflected else 0)
                if best is None or severity > best[0]:
                    best = (severity, page, reflected, wildcard, credentials, probe_origin)
            if best is None:
                continue
            _severity, page, reflected, wildcard, credentials, probe_origin = best
            acao = page.header("access-control-allow-origin") or ""
            acac = page.header("access-control-allow-credentials") or ""
            findings += 1
            yield m4_candidate(
                ctx,
                (
                    f"CORS reflects an arbitrary origin with credentials ({url})"
                    if reflected and credentials
                    else f"Permissive CORS policy on {url} (ACAO: {acao})"
                ),
                artifact={
                    "signal": "cors",
                    "family": "cors",
                    "endpoint": url,
                    "request_origin": probe_origin,
                    "origins_tested": tested,
                    "acao": acao,
                    "acac": acac or None,
                    "reflected": reflected_any,
                    "wildcard": wildcard_any,
                    # Not "allow_credentials": the evidence redactor blanks any key
                    # containing "credential" (ADR-050.3), and a rule needs this boolean.
                    "allows_auth": credentials,
                    "null_origin": null_reflected,
                },
                exchanges=(exchange_from_page(page),),
                confidence=0.85 if (reflected and credentials) else 0.7,
                detail=(
                    f"{url} answered Origin: {probe_origin} with "
                    f"Access-Control-Allow-Origin: {acao}"
                    + (", Allow-Credentials: true" if credentials else "")
                ),
                source=url,
            )
            if findings >= cap:
                return
        if not findings:
            yield ctx.clean(
                "no permissive CORS policy observed",
                detail=f"probed {len(candidates[:4])} endpoint(s) with {len(origins)} origin(s)",
            )


class TlsConfigReview(UrlCheck, Module):
    """``m4.tls-config-review`` — protocol/cipher/certificate posture (ch04#17)."""

    metadata = CheckMetadata(
        id="m4.tls-config-review",
        module="M4",
        name="tls-config-review",
        version="1.0",
        title="Weak TLS configuration",
        description=(
            "Profiles the TLS endpoint behind an https URL asset with the raw-network "
            "client: negotiated version and cipher, whether a deprecated protocol (SSLv3, "
            "TLS 1.0/1.1) still completes a handshake, and whether the certificate chain "
            "validates for the host name. A light review; M2's deep scan is the exhaustive "
            "one."
        ),
        research_ref="ch04#17",
        cwe="CWE-326",
        target_kinds=(TargetKind.URL,),
        severity_hint="medium",
        type="active",
        safe=True,
        verifiable=False,
        estimated_requests=8,
        requires_active_checks=True,
        runs_on_discovered=True,
    )

    def supports(self, asset: Asset) -> bool:
        if not super().supports(asset):
            return False
        return asset.value.lower().startswith("https://")

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        if ctx.net is None:
            yield skip(ctx, "no network client in this run: the TLS review needs a live scan")
            return
        parts = urlsplit(ctx.asset.value)
        host = parts.hostname
        if not host:
            yield skip(ctx, "the asset has no host to profile")
            return
        port = parts.port or 443
        from arachne.modules.m2.tls import profile_tls

        try:
            assessment = await profile_tls(
                ctx.net,
                host=host,
                port=port,
                server_name=host,
                probe_versions=True,
                probe_ciphers=False,
            )
        except Exception as exc:  # a refused handshake is data, not a check failure
            yield ctx.error(exc)
            return
        if assessment.profile.error:
            yield ctx.clean(
                "no TLS service to review",
                detail=f"{host}:{port} did not complete a TLS handshake: "
                f"{assessment.profile.error}",
            )
            return
        issues = list(assessment.issues)
        trust_error = assessment.profile.trust_error
        if not issues:
            yield ctx.clean(
                "TLS configuration is acceptable",
                detail=f"{host}:{port} negotiated {assessment.supported_versions or ['unknown']}",
            )
            return
        representative_endpoint = f"https://{host}:{port}/"
        yield m4_candidate(
            ctx,
            f"TLS posture issue on {host}:{port}: {', '.join(issue.kind for issue in issues)}",
            artifact={
                "signal": "weak-tls",
                "family": "tls",
                "host": host,
                "port": port,
                "supported_versions": list(assessment.supported_versions),
                "weak_versions": list(assessment.weak_versions),
                "trust_error": trust_error,
                "issues": [issue.to_dict() for issue in issues],
                "certificate": (
                    assessment.certificate.to_dict() if assessment.certificate else None
                ),
                "probes": list(assessment.probes),
            },
            confidence=0.9,
            detail=(
                f"{host}:{port} supports {assessment.supported_versions or 'unknown versions'}; "
                f"issues: {', '.join(issue.summary for issue in issues)}"
            ),
            source=representative_endpoint,
            cwe="CWE-326",
        )


class EmailAuthReview(UrlCheck, Module):
    """``m4.email-auth-review`` — SPF/DKIM/DMARC posture (ch04#20)."""

    metadata = CheckMetadata(
        id="m4.email-auth-review",
        module="M4",
        name="email-auth-review",
        version="1.0",
        title="Email authentication missing or permissive",
        description=(
            "Asks a DNS-over-HTTPS resolver for the domain's SPF, DMARC and DKIM TXT records "
            "and reports the spoofable configurations: no SPF, an SPF ending in +all/?all, "
            "no DMARC, a DMARC policy of none, and no DKIM selector answered. It is a "
            "third-party lookup, so it runs only when OSINT is enabled and the 'dns' "
            "provider is selected (safe defaults, F-02-09)."
        ),
        research_ref="ch04#20",
        cwe="CWE-290",
        target_kinds=(TargetKind.URL, TargetKind.DOMAIN),
        severity_hint="medium",
        type="passive",
        safe=True,
        verifiable=False,
        estimated_requests=6,
    )

    def supports(self, asset: Asset) -> bool:
        if asset.kind == "url":
            return super().supports(asset)
        return Module.supports(self, asset)

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        from arachne.modules.context import require_osint

        access, skipped = require_osint(ctx, "dns")
        if skipped is not None:
            yield skipped
            return
        assert access is not None
        domain = _domain_of(ctx)
        if domain is None:
            yield skip(ctx, "the asset names no domain to check email authentication for")
            return
        corpus = corpus_for(ctx)
        queries = 0
        spf_records, queries = await _txt(access, domain, queries)
        dmarc_records, queries = await _txt(
            access, f"{corpus.email_dmarc_name()}.{domain}", queries
        )
        selectors: list[str] = []
        for selector in corpus.email_dkim_selectors()[:4]:
            records, queries = await _txt(access, f"{selector}._domainkey.{domain}", queries)
            if records:
                selectors.append(selector)
        spf = spf_records[0] if spf_records else None
        dmarc = dmarc_records[0] if dmarc_records else None
        spf_all = _spf_all_qualifier(spf)
        dmarc_policy = _dmarc_policy(dmarc)
        issues: list[str] = []
        if spf is None:
            issues.append("no-spf")
        elif spf_all in corpus.email_permissive_spf():
            issues.append(f"spf-{spf_all}")
        if dmarc is None:
            issues.append("no-dmarc")
        elif dmarc_policy in (None, "none"):
            issues.append("dmarc-not-enforced" if dmarc_policy == "none" else "dmarc-malformed")
        if not selectors:
            issues.append("no-dkim-selector")
        artifact = {
            "signal": "email-auth",
            "family": "email-auth",
            "domain": domain,
            "spf_present": spf is not None,
            "spf_all": spf_all,
            "spf_permissive": spf_all in corpus.email_permissive_spf(),
            "dmarc_present": dmarc is not None,
            "dmarc_policy": dmarc_policy,
            "dmarc_enforced": dmarc_policy in {"quarantine", "reject"},
            "dkim_selectors": selectors,
            "issues": issues,
            "queries": queries,
        }
        spf_summary = "SPF absent" if spf is None else f"SPF qualifier {spf_all or 'none'}"
        dmarc_summary = (
            "DMARC absent" if dmarc is None else f"DMARC policy {dmarc_policy or 'malformed'}"
        )
        if not issues:
            yield ctx.clean(
                "email authentication is configured",
                detail=f"{domain}: SPF, DMARC ({dmarc_policy}) and a DKIM selector are present",
            )
            return
        yield m4_candidate(
            ctx,
            f"Email authentication gaps for {domain} ({', '.join(issues)})",
            artifact=artifact,
            confidence=0.85,
            detail=(
                f"{domain}: {spf_summary}, {dmarc_summary}, "
                f"DKIM selectors answered: {', '.join(selectors) or 'none'}"
            ),
            source=domain,
        )


# --------------------------------------------------------------------------- helpers
async def _txt(access: OsintAccess, name: str, queries: int) -> tuple[tuple[str, ...], int]:
    """Query one TXT name; returns ``(records, queries_used)`` and never raises."""
    try:
        response = await access.fetch("dns", dns_txt_url(name))
    except Exception:  # a provider error is "nothing found" for this record
        return (), queries + 1
    payload = response.json()
    return parse_doh_txt(payload), queries + 1


def _spf_all_qualifier(record: str | None) -> str | None:
    if not record:
        return None
    match = _SPF_ALL_RE.search(record)
    return None if match is None else f"{match.group(1)}all"


def _dmarc_policy(record: str | None) -> str | None:
    if not record:
        return None
    match = _DMARC_POLICY_RE.search(record)
    return None if match is None else match.group(1).lower()


def _weak_csp(pages: tuple[Page, ...], markers: tuple[str, ...]) -> list[str]:
    """CSP directives that defeat the policy (one finding per origin, not per page)."""
    weak: dict[str, None] = {}
    for page in pages:
        policy = page.header("content-security-policy")
        if not policy:
            continue
        lowered = policy.lower()
        for marker in markers:
            if marker.lower() in lowered:
                weak.setdefault(marker, None)
    return sorted(weak)


def _api_shaped(page: Page) -> bool:
    content_type = page.content_type.lower()
    path = urlsplit(page.url).path.lower()
    return "json" in content_type or any(
        fragment in path for fragment in ("/api/", "/v1/", "/v2/", "/graphql", "/rest/")
    )
