"""Transport-level checks: open redirect (ch03#14), CORS (ch03#23), rate limiting (ch03#35).

``m3.open-redirect``
    Research ch03#14's oracle reads the ``Location`` header: the parameter is fed the URL
    classes (absolute, scheme-relative, backslash-confusion, userinfo, encoded, bare host) and
    a finding requires the answer to point at the *reserved* probe host — ``arachne-…invalid``,
    an RFC 2606 name that can never resolve, so a redirect that is followed anyway cannot reach
    anything. Redirects are not followed, so this check sees the 3xx it asked for.

``m3.cors-audit``
    Research ch03#23's origin-reflection matrix, read as a *read-privilege* oracle: the pair
    (``Access-Control-Allow-Origin`` echoing the probe origin, ``Access-Control-Allow-
    Credentials: true``) is what lets a malicious page read an authenticated response. A
    reflected origin without credentials, a ``null`` acceptance and a wildcard-with-credentials
    are reported at their own (lower) weight. GET with an ``Origin`` header only.

``m3.rate-limit-audit``
    Research ch03#35's *bounded* profile: a small, fixed number of identical requests to the
    endpoints whose anti-automation posture matters (login, password reset), then the same
    number again with a rotating client-supplied ``X-Forwarded-For``. The finding is the
    *absence* of throttling (or a throttle that a spoofable header defeats) — this check
    characterizes controls; it never mounts a brute-force (docs/spec/05- M3 Safety).
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Sequence
from urllib.parse import urljoin, urlsplit, urlunsplit

from arachne.core.http import HttpExchange
from arachne.core.results import CheckResult
from arachne.core.target import TargetKind
from arachne.modules.base import CheckMetadata, Module
from arachne.modules.context import CheckContext
from arachne.modules.m3.inventory import origin_of
from arachne.modules.m3.support import (
    WebCheck,
    http_or_skip,
    owns_origin,
    payloads_for,
    probe_url,
    safe_fetch,
    skip,
    web_candidate,
    web_or_skip,
)

__all__ = ["CorsAudit", "OpenRedirect", "RateLimitAudit"]

#: How many pages the CORS matrix probes on one origin (each costs one request per origin).
MAX_CORS_TARGETS = 8

#: Path fragments that mark an endpoint whose cross-origin policy matters most.
_CORS_PRIORITY_HINTS = ("/api", "/graphql", "/rest", "/json", "/v1", "/v2", "config")


def _cors_priority(url: str) -> tuple[int, str]:
    """Sort key: API-ish endpoints (and the root) before the rest, then stable by URL."""
    path = urlsplit(url).path.lower()
    if any(hint in path for hint in _CORS_PRIORITY_HINTS):
        return (0, url)
    if path in {"", "/"}:
        return (1, url)
    return (2, url)


class OpenRedirect(WebCheck, Module):
    """``m3.open-redirect`` — redirect-location reflection (ch03#14)."""

    metadata = CheckMetadata(
        id="m3.open-redirect",
        module="M3",
        name="open-redirect",
        version="1.0",
        title="Open redirect oracle",
        description=(
            "Feeds redirect-style parameters the URL classes of research ch03#14 (absolute, "
            "scheme-relative, backslash confusion, userinfo, encoded, bare host) and reads the "
            "Location header. A finding requires the answer to point at the reserved, "
            "non-resolving probe host, so it can never redirect a user anywhere real. "
            "Redirects are not followed."
        ),
        research_ref="ch03#14",
        cwe="CWE-601",
        target_kinds=(TargetKind.URL,),
        severity_hint="medium",
        type="active",
        safe=True,
        verifiable=False,
        estimated_requests=12,
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
        redirect_params = {name.lower() for name in payloads.strings("params", "redirect")}
        probe_host = payloads.string("redirect", "probe_host", default="arachne-redirect.invalid")
        templates = payloads.strings("redirect", "payloads")
        origin = origin_of(ctx.asset.value)
        targets = [
            (url, param)
            for url, param in inventory.parameter_targets(names=redirect_params)
            if origin_of(url) == origin
        ][: ctx.config.web.max_params_per_check]
        if not targets:
            yield ctx.clean(
                "no redirect-style parameter to probe",
                detail="the crawl found no parameter whose name suggests a redirect target",
            )
            return

        findings = 0
        for url, param in targets:
            for template in templates:
                payload = template.format(host=probe_host)
                exchange = await safe_fetch(
                    ctx, probe_url(url, param, payload), follow_redirects=False
                )
                if exchange is None or exchange.status_code not in {301, 302, 303, 307, 308}:
                    continue
                location = exchange.header("location")
                resolved = _resolve_location(location, url)
                if resolved is None or urlsplit(resolved).hostname != probe_host:
                    continue
                findings += 1
                yield web_candidate(
                    ctx,
                    f"Open redirect via '{param}' (Location reflects an arbitrary host)",
                    artifact={
                        "signal": "open-redirect",
                        "family": "redirect",
                        "endpoint": url,
                        "parameter": param,
                        "payload_class": _payload_class(template),
                        "status": exchange.status_code,
                        "location_host": probe_host,
                        "location_scheme": urlsplit(resolved).scheme,
                        "probe_host_reserved": True,
                    },
                    exchanges=(exchange,),
                    confidence=0.85,
                    cwe="CWE-601",
                    detail=(
                        f"{url} parameter '{param}' answered HTTP {exchange.status_code} with a "
                        f"Location pointing at {probe_host}"
                    ),
                    source=url,
                )
                break
        if not findings:
            yield ctx.clean(
                "no open redirect observed",
                detail=f"probed {len(targets)} redirect-style parameter(s)",
            )


def _resolve_location(location: str | None, base: str) -> str | None:
    if not location:
        return None
    candidate = location.strip()
    if candidate.startswith("//"):
        return f"{urlsplit(base).scheme}:{candidate}"
    resolved = urljoin(base, candidate)
    if not urlsplit(resolved).scheme:
        # A bare host in a Location is interpreted relative to the scheme by browsers.
        resolved = urlunsplit(("https", candidate, "", "", ""))
    return resolved


def _payload_class(template: str) -> str:
    if template.startswith("//"):
        return "scheme-relative"
    if template.startswith("/\\"):
        return "backslash-confusion"
    if template.startswith("%2f"):
        return "encoded-scheme-relative"
    if "@" in template:
        return "userinfo-confusion"
    if template.startswith("https://{host}"):
        return "absolute-url"
    return "bare-host"


class CorsAudit(WebCheck, Module):
    """``m3.cors-audit`` — origin reflection and credential policy (ch03#23)."""

    metadata = CheckMetadata(
        id="m3.cors-audit",
        module="M3",
        name="cors-audit",
        version="1.0",
        title="CORS configuration audit",
        description=(
            "Sends a probe Origin header to the crawled endpoints and reads the "
            "Access-Control-Allow-Origin / Allow-Credentials pair: a reflected origin with "
            "credentials is a cross-origin read primitive, a reflected origin alone, a null "
            "acceptance and a wildcard with credentials each carry their own weight. GET only."
        ),
        research_ref="ch03#23",
        cwe="CWE-942",
        target_kinds=(TargetKind.URL,),
        severity_hint="medium",
        type="active",
        safe=True,
        verifiable=False,
        estimated_requests=10,
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
        origins = payloads.strings("cors", "origins") or ["https://arachne-cors.invalid"]
        origin = origin_of(ctx.asset.value)
        # API-shaped endpoints first: a permissive policy is far more likely — and far more
        # consequential — on a JSON endpoint than on a marketing page, and the probe budget is
        # bounded, so the interesting pages must be the ones that get it.
        candidates = [url for url in inventory.order if origin_of(url) == origin]
        candidates.sort(key=_cors_priority)
        targets = candidates[:MAX_CORS_TARGETS]
        if not targets:
            yield ctx.clean(
                "no endpoint to probe for CORS policy",
                detail="the crawl fetched no page on this origin",
            )
            return

        findings = 0
        for url in targets:
            for probe_origin in origins:
                exchange = await safe_fetch(
                    ctx,
                    url,
                    headers={"Origin": probe_origin},
                    follow_redirects=False,
                )
                if exchange is None:
                    continue
                acao = exchange.header("access-control-allow-origin")
                acac = (exchange.header("access-control-allow-credentials") or "").lower()
                credentials = acac == "true"
                if acao is None:
                    continue
                reflected = acao == probe_origin
                wildcard = acao.strip() == "*"
                if not (reflected or wildcard):
                    continue
                if wildcard and not credentials:
                    continue
                findings += 1
                yield web_candidate(
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
                        "acao": acao,
                        "acac": acac or None,
                        "reflected": reflected,
                        "wildcard": wildcard,
                        "allows_auth": credentials,
                        "null_origin": probe_origin == "null" and reflected,
                    },
                    exchanges=(exchange,),
                    confidence=0.85 if (reflected and credentials) else 0.7,
                    cwe="CWE-942",
                    detail=(
                        f"{url} answered Origin: {probe_origin} with "
                        f"Access-Control-Allow-Origin: {acao}"
                        + (", Allow-Credentials: true" if credentials else "")
                    ),
                    source=url,
                )
        if not findings:
            yield ctx.clean(
                "no permissive CORS policy observed",
                detail=f"probed {len(targets)} endpoint(s) with {len(origins)} origin value(s)",
            )


class RateLimitAudit(WebCheck, Module):
    """``m3.rate-limit-audit`` — bounded anti-automation profile (ch03#35)."""

    metadata = CheckMetadata(
        id="m3.rate-limit-audit",
        module="M3",
        name="rate-limit-audit",
        version="1.0",
        title="Rate limiting and anti-automation audit",
        description=(
            "Issues a small, fixed number of identical requests to the endpoints whose "
            "anti-automation posture matters (login, password reset, registration) and reads "
            "whether any throttling appears (429, lockout, CAPTCHA), then repeats with a "
            "rotating client-supplied forwarded-for header to test whether the control is keyed "
            "on a spoofable value. Strictly bounded: it characterizes controls and never mounts "
            "a brute-force (ARACHNE_WEB_RATE_PROBES controls the volume)."
        ),
        research_ref="ch03#35",
        cwe="CWE-770",
        target_kinds=(TargetKind.URL,),
        severity_hint="low",
        type="active",
        safe=True,
        verifiable=False,
        estimated_requests=12,
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
        probes = ctx.config.web.rate_limit_probes
        if probes < 2:
            yield skip(ctx, "ARACHNE_WEB_RATE_PROBES is below 2: no bounded sequence to run")
            return
        throttle_statuses = {
            int(value) for value in payloads.strings("rate_limit", "throttle_statuses")
        }
        throttle_markers = payloads.strings("rate_limit", "throttle_markers")
        spoof_headers = payloads.strings("rate_limit", "spoof_headers")
        origin = origin_of(ctx.asset.value)
        targets = self._targets(ctx, inventory, origin)
        if not targets:
            yield ctx.clean(
                "no anti-automation-sensitive endpoint found",
                detail="the crawl found no login/reset/registration endpoint on this origin",
            )
            return

        findings = 0
        for url in targets:
            plain = await self._sequence(ctx, url, probes, spoof=None)
            if not plain:
                continue
            throttled, evidence_exchange = _throttle(plain, throttle_statuses, throttle_markers)
            if not throttled:
                findings += 1
                yield web_candidate(
                    ctx,
                    f"No anti-automation control observed within {probes} requests ({url})",
                    artifact={
                        "signal": "no-rate-limit",
                        "family": "rate-limit",
                        "endpoint": url,
                        "requests_sent": len(plain),
                        "statuses": [item.status_code for item in plain],
                        "throttle_observed": False,
                        "spoofable": None,
                    },
                    exchanges=(plain[-1],),
                    confidence=0.5,
                    cwe="CWE-770",
                    detail=(
                        f"{url} answered {len(plain)} consecutive requests with no 429, lockout "
                        "or challenge"
                    ),
                    source=url,
                )
                continue
            spoof_header = spoof_headers[0] if spoof_headers else None
            if spoof_header is None:
                continue
            spoofed = await self._sequence(ctx, url, probes, spoof=spoof_header)
            spoofed_throttled, _ = _throttle(spoofed, throttle_statuses, throttle_markers)
            if spoofed and not spoofed_throttled:
                findings += 1
                yield web_candidate(
                    ctx,
                    f"Rate limiting is keyed on a client-supplied header ({url})",
                    artifact={
                        "signal": "spoofable-rate-limit",
                        "family": "rate-limit",
                        "endpoint": url,
                        "requests_sent": len(plain) + len(spoofed),
                        "throttle_observed": True,
                        "spoof_header": spoof_header,
                        "spoofable": True,
                        "statuses": [item.status_code for item in plain],
                    },
                    exchanges=(evidence_exchange, spoofed[-1]),
                    confidence=0.7,
                    cwe="CWE-770",
                    detail=(
                        f"{url} throttled the plain sequence but not the one carrying a rotating "
                        f"{spoof_header} header"
                    ),
                    source=url,
                )
        if not findings:
            yield ctx.clean(
                "rate limiting appears effective",
                detail=f"every probed endpoint throttled within {probes} requests",
            )

    # ------------------------------------------------------------------ internals
    def _targets(self, ctx: CheckContext, inventory: object, origin: str) -> list[str]:
        payloads = payloads_for(ctx)
        hints = tuple(path.lower() for path in payloads.strings("rate_limit", "paths"))
        urls: list[str] = []
        for url in getattr(inventory, "order", []):
            if origin_of(url) != origin:
                continue
            path = urlsplit(url).path.lower()
            if any(hint in path for hint in hints):
                urls.append(url)
        # A login endpoint is usually not linked — it is the target of a form — so the forms'
        # actions are the primary source and pages only a supplement.
        for form in getattr(inventory, "forms", ()):
            if origin_of(form.action) != origin:
                continue
            path = urlsplit(form.action).path.lower()
            if any(hint in path for hint in hints):
                urls.append(form.action)
        return list(dict.fromkeys(urls))[:2]

    async def _sequence(
        self, ctx: CheckContext, url: str, count: int, *, spoof: str | None
    ) -> list[HttpExchange]:
        responses: list[HttpExchange] = []
        for index in range(count):
            headers = None
            if spoof:
                headers = {spoof: f"192.0.2.{index + 1}"}
            exchange = await safe_fetch(ctx, url, headers=headers, follow_redirects=False)
            if exchange is None:
                return responses
            responses.append(exchange)
        return responses


def _throttle(
    responses: Sequence[HttpExchange], statuses: set[int], markers: Sequence[str]
) -> tuple[bool, HttpExchange | None]:
    """Whether any response in the sequence shows a throttling/anti-bot control."""
    for exchange in responses:
        if exchange.status_code in statuses:
            return True, exchange
        body = exchange.body.lower()
        if any(marker in body for marker in markers):
            return True, exchange
    return False, None
