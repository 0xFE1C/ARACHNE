"""The shared, scoped, rate-limited, audited HTTP client (ADR-05, F-01-07/08, F-08-03/04).

Every outbound HTTP interaction in ARACHNE goes through :class:`ScopedHttpClient`. No
module may use ``httpx`` or ``requests`` directly; ``tests/unit/
test_http_hygiene.py`` enforces that mechanically.

Order of operations for **every** request, including every redirect hop and every retry
attempt:

1. **validate** — URL safety policy + scope allowlist
   (:func:`arachne.core.safety.validate_url`); failures are audited as
   ``safety.blocked`` / ``scope.rejected`` and raise.
2. **throttle** — per-host and global token buckets. Retries re-acquire tokens, so a
   retry can never bypass the budget.
3. **send** — with timeouts; redirects are followed manually, hop by hop, so each new
   location is validated (this is what stops ``Location: http://169.254.169.254/``).
4. **capture** — the caller receives an :class:`HttpExchange` whose request and response
   are already redacted and hashed. Raw bytes never leave this module.
5. **audit** — one ``http.request`` event per attempt with method, redacted URL, status,
   duration, resolved addresses, and whether it was throttled.
"""

from __future__ import annotations

import json
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx

from arachne.core.airgap import AirgapError, build_airgap_policy
from arachne.core.audit import AuditAction, Auditor, AuditOutcome
from arachne.core.config import HttpSettings, SafetySettings, Settings, get_settings
from arachne.core.errors import OutOfScopeError, RequestError, SafetyError
from arachne.core.logging import get_logger
from arachne.core.ratelimit import HostRateLimiter
from arachne.core.redaction import (
    SECRET_PATTERNS,
    masked_secret_findings,
    redact_headers,
    redact_text,
    redact_text_report,
    redact_url,
    redact_value,
)
from arachne.core.results import Evidence, sha256_of
from arachne.core.safety import HostResolver, ResolvedUrl, Scope, UrlSafetyPolicy, validate_url
from arachne.core.secrets import SecretsManifest
from arachne.core.tracing import OTLP_SPAN_KIND_CLIENT, get_tracer

__all__ = [
    "CookieInfo",
    "HttpExchange",
    "RawExchange",
    "RecordedResponse",
    "ScopedHttpClient",
    "fixture_transport",
]

_logger = get_logger("core.http")

#: Status codes treated as retryable transport-level failures.
_RETRYABLE_STATUS = frozenset({502, 503, 504})
_REDIRECT_STATUS = frozenset({301, 302, 303, 307, 308})
_BINARY_SNIFF = b"\x00"


@dataclass(frozen=True, slots=True)
class CookieInfo:
    """A ``Set-Cookie`` observed on a response, **without its value** (F-08-04, M3/M4).

    A cookie audit needs the cookie's *name and attributes* — whether it carries ``Secure``,
    ``HttpOnly`` and a ``SameSite`` policy is exactly the security posture a header review
    reports — but never the session value itself. The redactor blanks the whole ``set-cookie``
    header, so this structural projection is captured here, at the same point redaction
    happens, and it is the only form in which cookie data crosses the module boundary. The
    value is dropped, not masked: nothing downstream can reconstruct it.
    """

    name: str
    secure: bool = False
    httponly: bool = False
    samesite: str | None = None
    path: str | None = None
    domain: str | None = None

    @property
    def flags(self) -> tuple[str, ...]:
        """The attributes the cookie does carry, lower-cased (for the report and rules)."""
        present: list[str] = []
        if self.secure:
            present.append("secure")
        if self.httponly:
            present.append("httponly")
        if self.samesite:
            present.append(f"samesite={self.samesite.lower()}")
        return tuple(present)

    @property
    def missing_flags(self) -> tuple[str, ...]:
        """The hardening attributes the cookie lacks — the audit's actual finding."""
        missing: list[str] = []
        if not self.secure:
            missing.append("secure")
        if not self.httponly:
            missing.append("httponly")
        if not self.samesite or self.samesite.lower() == "none":
            missing.append("samesite")
        return tuple(missing)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "secure": self.secure,
            "httponly": self.httponly,
            "samesite": self.samesite,
            "path": self.path,
            "domain": self.domain,
            "flags": list(self.flags),
            "missing_flags": list(self.missing_flags),
        }


def parse_set_cookie(value: str) -> CookieInfo | None:
    """Parse one ``Set-Cookie`` header value into a :class:`CookieInfo` (value dropped).

    Deliberately hand-written rather than ``http.cookies.SimpleCookie``: the cookie's *value*
    must never be materialised, and the attribute grammar is small (``;``-separated
    attributes after a ``name=value`` pair). A malformed header yields ``None`` rather than an
    exception — a hostile or broken server must not break a scan.
    """
    if not value:
        return None
    parts = [segment.strip() for segment in value.split(";")]
    if not parts or not parts[0]:
        return None
    name, separator, _raw_value = parts[0].partition("=")
    if not separator or not name.strip():
        return None
    info = CookieInfo(name=name.strip())
    samesite: str | None = None
    path: str | None = None
    domain: str | None = None
    secure = httponly = False
    for attribute in parts[1:]:
        if not attribute:
            continue
        key, _, attr_value = attribute.partition("=")
        lowered = key.strip().lower()
        if lowered == "secure":
            secure = True
        elif lowered == "httponly":
            httponly = True
        elif lowered == "samesite":
            samesite = attr_value.strip() or None
        elif lowered == "path":
            path = attr_value.strip() or None
        elif lowered == "domain":
            domain = attr_value.strip() or None
    return CookieInfo(
        name=info.name,
        secure=secure,
        httponly=httponly,
        samesite=samesite,
        path=path,
        domain=domain,
    )


def parse_set_cookies(headers: Mapping[str, str]) -> tuple[CookieInfo, ...]:
    """Every ``Set-Cookie`` on a response, in header order (values dropped)."""
    found: list[CookieInfo] = []
    for key, value in headers.items():
        if key.lower() != "set-cookie":
            continue
        if isinstance(value, str):
            info = parse_set_cookie(value)
            if info is not None:
                found.append(info)
    return tuple(found)


@dataclass(frozen=True, slots=True)
class HttpExchange:
    """A redacted, self-contained record of one HTTP exchange.

    This is the only shape in which HTTP data crosses a module boundary, which is how
    "redaction at capture time" (F-08-04) is guaranteed rather than hoped for.
    """

    method: str
    url: str
    status_code: int
    request_headers: dict[str, str] = field(default_factory=dict)
    request_body: str | None = None
    response_headers: dict[str, str] = field(default_factory=dict)
    body: str = ""
    elapsed_ms: float = 0.0
    attempts: int = 1
    redirect_chain: tuple[str, ...] = field(default_factory=tuple)
    resolved_addresses: tuple[str, ...] = field(default_factory=tuple)
    captured_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    body_truncated: bool = False
    body_is_binary: bool = False
    #: Names of the secret detectors that fired on this body, in pattern order. The values
    #: are already placeholders by the time a caller sees ``body`` (F-08-04); this is how a
    #: check reports "the bundle hardcodes an AWS key" without ever receiving the key.
    secret_kinds: tuple[str, ...] = field(default_factory=tuple)
    #: Structured ``Set-Cookie`` projections (names and attributes only — never values), so a
    #: header/cookie audit can read a cookie's hardening without the redaction gate hiding it.
    cookies: tuple[CookieInfo, ...] = field(default_factory=tuple)

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 300

    def header(self, name: str, default: str | None = None) -> str | None:
        """Case-insensitive header lookup."""
        lowered = name.lower()
        for key, value in self.response_headers.items():
            if key.lower() == lowered:
                return value
        return default

    def json_body(self) -> Any:
        """Parse the (redacted) body as JSON; ``None`` when it is not JSON."""
        try:
            return json.loads(self.body)
        except (json.JSONDecodeError, ValueError):
            return None

    def to_evidence(self) -> tuple[Evidence, Evidence]:
        """Return ``(request evidence, response evidence)`` (spec 02- §2.4 kinds)."""
        request = Evidence.of(
            "http_request",
            {
                "method": self.method,
                "url": self.url,
                "headers": self.request_headers,
                "body": self.request_body,
                "attempts": self.attempts,
                "redirect_chain": list(self.redirect_chain),
            },
            source=self.url,
        )
        response = Evidence.of(
            "http_response",
            {
                "status_code": self.status_code,
                "headers": self.response_headers,
                "body": self.body,
                "elapsed_ms": self.elapsed_ms,
                "truncated": self.body_truncated,
                "binary": self.body_is_binary,
                "cookies": [cookie.to_dict() for cookie in self.cookies],
            },
            source=self.url,
        )
        return request, response

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "url": self.url,
            "status_code": self.status_code,
            "request_headers": self.request_headers,
            "request_body": self.request_body,
            "response_headers": self.response_headers,
            "body": self.body,
            "elapsed_ms": self.elapsed_ms,
            "attempts": self.attempts,
            "redirect_chain": list(self.redirect_chain),
            "resolved_addresses": list(self.resolved_addresses),
            "captured_at": self.captured_at.isoformat(),
            "body_truncated": self.body_truncated,
            "body_is_binary": self.body_is_binary,
            "captured_patterns": list(self.secret_kinds),
            "cookies": [cookie.to_dict() for cookie in self.cookies],
        }


@dataclass(frozen=True, slots=True)
class RawExchange:
    """A response whose body is returned **verbatim**, as bytes (S20, ADR-250.4).

    Only :meth:`ScopedHttpClient.request_bytes` produces one. The URL and headers are
    redacted exactly as they are for an :class:`HttpExchange`; only the *body* skips the
    redaction pass, because its caller needs the exact bytes it stored or fetched.
    """

    method: str
    url: str
    status_code: int
    headers: dict[str, str] = field(default_factory=dict)
    content: bytes = b""
    truncated: bool = False
    body_bytes: int = 0
    elapsed_ms: float = 0.0
    attempts: int = 1

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 300


class ScopedHttpClient:
    """The single HTTP entry point for the whole scanner.

    ``transport`` exists so tests can inject ``httpx.MockTransport`` and assert on the
    safety pipeline without touching a network.
    """

    def __init__(
        self,
        *,
        settings: Settings | None = None,
        scope: Scope | None = None,
        policy: UrlSafetyPolicy | None = None,
        resolver: HostResolver | None = None,
        limiter: HostRateLimiter | None = None,
        auditor: Auditor | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        client: httpx.AsyncClient | None = None,
        secrets_manifest: SecretsManifest | None = None,
        redaction_enabled: bool | None = None,
        max_body_bytes: int | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        safety: SafetySettings = self.settings.safety
        self.scope = scope if scope is not None else safety.scope
        self.policy = policy if policy is not None else safety.policy
        self.resolver = resolver
        self.limiter = limiter or HostRateLimiter(self.settings.rate_limit)
        self.auditor = auditor or Auditor(actor=self.settings.actor)
        #: The operator's encrypted ledger of *masked* credentials seen in responses (S7,
        #: F-08-04). ``None`` means "no manifest configured", which is the default.
        self.secrets_manifest = secrets_manifest
        self.http_settings: HttpSettings = self.settings.http
        #: Redaction is on by default. ``redaction_enabled`` overrides the deployment
        #: setting for one client instance. Exactly two call sites pass it, both asserted by
        #: ``tests/unit/test_http_hygiene.py``: the OIDC token exchange (ADR-220.3), which
        #: must read credentials *back* to function, and the threat-intel feed sync
        #: (ADR-230.3), whose payload is integrity-verified before import and would be
        #: refused — or worse, silently altered — if a redaction pass edited it. The
        #: scanning client never passes it.
        self.redaction_enabled = (
            safety.redaction_enabled if redaction_enabled is None else redaction_enabled
        )
        #: The response-body cap. ``max_body_bytes`` overrides the deployment bound for one
        #: instance: a feed page is legitimately megabytes, and a truncated body cannot be
        #: verified against its published digest (the sync refuses a truncated read).
        self.body_limit = (
            self.http_settings.max_body_bytes if max_body_bytes is None else max_body_bytes
        )
        self._owns_client = client is None
        #: The transport a cookie-less probe reuses (see :meth:`_client_for`). Kept so the
        #: anonymous client is the same egress path, not a second one.
        self._transport = transport
        #: Built lazily, only when a check asks for an anonymous request.
        self._anonymous_client: httpx.AsyncClient | None = None
        self._client = client or httpx.AsyncClient(
            transport=transport,
            timeout=httpx.Timeout(
                self.http_settings.timeout_s,
                connect=self.http_settings.connect_timeout_s,
            ),
            verify=self.http_settings.verify_tls,
            follow_redirects=False,  # redirects are validated hop by hop below
            headers={"User-Agent": self.http_settings.user_agent},
        )
        # Set when a request was blocked, for tests and callers that inspect the client.
        self.last_exchange: HttpExchange | None = None
        #: The air-gapped egress allowlist (S25, REQ-RESIL-001). Inert unless the deployment
        #: set ``ARACHNE_AIRGAPPED``; when it did, the only reachable hosts are the
        #: *deployment's* scan targets (never this instance's pinned scope, which for a
        #: webhook or metrics client is exactly the external host the mode exists to refuse).
        self._airgap = build_airgap_policy(self.settings)
        self._airgap_scope_hosts: tuple[str, ...] = tuple(safety.scope.allowed_hosts) + tuple(
            safety.scope.allowed_domains
        )

    # ------------------------------------------------------------------ context manager
    async def __aenter__(self) -> ScopedHttpClient:
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        # The manifest is flushed here: a scan's client is closed by the orchestrator even
        # when a step failed, so the operator gets the ledger of what was exposed.
        if self.secrets_manifest is not None:
            try:
                self.secrets_manifest.flush()
            except Exception as exc:  # a ledger failure must not fail the scan
                _logger.warning(
                    "could not write the secrets manifest",
                    extra={"event": "secrets.manifest_failed", "error": str(exc)},
                )
        if self._owns_client:
            await self._client.aclose()
        if self._anonymous_client is not None:
            await self._anonymous_client.aclose()
            self._anonymous_client = None

    # ------------------------------------------------------------------ public requests
    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        content: bytes | str | None = None,
        follow_redirects: bool | None = None,
        max_redirects: int | None = None,
        anonymous: bool = False,
    ) -> HttpExchange:
        """Perform one validated, rate-limited, audited request.

        ``anonymous`` asks for the request to be issued on the cookie-less client (see
        :meth:`_client_for`): a probe whose whole claim is "this is reachable *without*
        credentials" must not inherit a session the crawl (or a credentialed broker) picked up.

        Tracing (REQ-OPS-004) is a thin wrapper around :meth:`_request`: one client span per
        request, carrying the redacted URL and the method, with the W3C ``traceparent``
        header injected by the request path itself. Disabled tracing is a no-op span, so the
        default deployment pays nothing beyond one context manager.
        """
        tracer = get_tracer()
        with tracer.start_span(
            f"http.{method.upper()}",
            attributes={"http.method": method.upper(), "http.url": redact_url(url)},
            kind=OTLP_SPAN_KIND_CLIENT,
        ) as span:
            try:
                exchange = await self._request(
                    method,
                    url,
                    headers=headers,
                    content=content,
                    follow_redirects=follow_redirects,
                    max_redirects=max_redirects,
                    anonymous=anonymous,
                )
            except Exception as exc:
                span.set_status("error", str(exc)[:200])
                raise
            span.set_attribute("http.status_code", exchange.status_code)
            span.set_status("ok" if exchange.ok else "unset")
            return exchange

    async def _request(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        content: bytes | str | None = None,
        follow_redirects: bool | None = None,
        max_redirects: int | None = None,
        anonymous: bool = False,
    ) -> HttpExchange:
        """The request itself (see :meth:`request` for the tracing wrapper)."""
        method = method.upper()
        follow = (
            self.http_settings.follow_redirects if follow_redirects is None else follow_redirects
        )
        redirect_budget = (
            self.http_settings.max_redirects if max_redirects is None else max_redirects
        )

        request_headers = dict(headers or {})
        # W3C trace context (REQ-OPS-004): a trace that stops at the scanner's edge is worth
        # little; carrying it tells the target-side observer — and the operator's collector —
        # that both halves belong to one scan. Absent when tracing is off.
        traceparent = get_tracer().traceparent()
        if traceparent:
            request_headers.setdefault("traceparent", traceparent)
        current_url = url
        chain: list[str] = []
        addresses: tuple[str, ...] = ()
        total_attempts = 0
        started = time.monotonic()
        redirects_left = redirect_budget

        while True:
            resolved = await self._validate(current_url)
            self._enforce_airgap(resolved.host)
            addresses = resolved.addresses
            waited = await self.limiter.acquire(resolved.host_port)
            response, attempts = await self._send_with_retries(
                method,
                resolved,
                request_headers,
                content,
                host_key=resolved.host_port,
                anonymous=anonymous,
            )
            total_attempts += attempts

            if (
                follow
                and response.status_code in _REDIRECT_STATUS
                and response.headers.get("location")
                and redirects_left > 0
            ):
                next_url = self._absolute_url(str(response.headers["location"]), resolved.url)
                chain.append(redact_url(next_url))
                redirects_left -= 1
                current_url = next_url
                if response.status_code == 303 or (
                    response.status_code in {301, 302} and method not in {"GET", "HEAD"}
                ):
                    method, content = "GET", None
                await response.aclose()
                continue

            elapsed_ms = (time.monotonic() - started) * 1000.0
            exchange = await self._capture(
                method=method,
                resolved=resolved,
                request_headers=request_headers,
                content=content,
                response=response,
                elapsed_ms=elapsed_ms,
                attempts=total_attempts,
                chain=tuple(chain),
                addresses=addresses,
                waited_s=waited,
            )
            await response.aclose()
            self.last_exchange = exchange
            return exchange

    async def get(self, url: str, **kwargs: Any) -> HttpExchange:
        return await self.request("GET", url, **kwargs)

    async def head(self, url: str, **kwargs: Any) -> HttpExchange:
        return await self.request("HEAD", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> HttpExchange:
        return await self.request("POST", url, **kwargs)

    async def put(self, url: str, **kwargs: Any) -> HttpExchange:
        return await self.request("PUT", url, **kwargs)

    async def patch(self, url: str, **kwargs: Any) -> HttpExchange:
        return await self.request("PATCH", url, **kwargs)

    async def delete(self, url: str, **kwargs: Any) -> HttpExchange:
        return await self.request("DELETE", url, **kwargs)

    async def request_bytes(
        self,
        method: str,
        url: str,
        *,
        headers: Mapping[str, str] | None = None,
        content: bytes | str | None = None,
        max_bytes: int | None = None,
    ) -> RawExchange:
        """Fetch a response body as **bytes**, without a redaction pass (S20, ADR-250.4).

        Every other request in ARACHNE returns an :class:`HttpExchange`, whose body is a
        decoded, redacted string — the shape that makes "redaction at capture time" true
        everywhere. That shape is wrong for one kind of payload: bytes that are already
        safe (they were redacted when they were captured as evidence) and that are
        integrity-bearing (a compressed container whose digest is recorded). Running them
        through a text decoder and a redactor would corrupt them and change the digest.

        So this is the *second* documented exception (the first two are the OIDC exchange
        and the feed sync, which disable redaction for one instance). It is deliberately a
        separate method rather than a flag on :meth:`request`: a caller has to name the
        behaviour it wants, the safety pipeline (scope, scope refusal auditing, rate
        limiting, retries, the audit line with the response digest) still runs unchanged,
        and ``tests/unit/test_http_hygiene.py`` pins the call sites at one module.

        ``max_bytes`` caps *this* response; it never widens the client's configured bound.
        A body over the cap is truncated and flagged, so the caller can refuse to use it.
        """
        method = method.upper()
        resolved = await self._validate(url)
        self._enforce_airgap(resolved.host)
        waited = await self.limiter.acquire(resolved.host_port)
        started = time.monotonic()
        response, attempts = await self._send_with_retries(
            method,
            resolved,
            dict(headers or {}),
            content,
            host_key=resolved.host_port,
        )
        elapsed_ms = (time.monotonic() - started) * 1000.0
        limit = self.body_limit if max_bytes is None else max_bytes
        raw = response.content
        truncated = len(raw) > limit
        payload = raw[:limit]
        status_code = response.status_code
        response_headers = {str(key): str(value) for key, value in response.headers.items()}
        await response.aclose()

        self.auditor.record(
            AuditAction.HTTP_REQUEST,
            outcome=AuditOutcome.ALLOWED if 200 <= status_code < 300 else AuditOutcome.BLOCKED,
            target=resolved.url,
            meta={
                "method": method,
                "status": status_code,
                "host": resolved.host,
                "port": resolved.port,
                "resolved_addresses": list(resolved.addresses),
                "elapsed_ms": round(elapsed_ms, 3),
                "attempts": attempts,
                "throttled_ms": round(waited * 1000.0, 3),
                "response_sha256": sha256_of(payload),
                "body_bytes": len(payload),
                "verbatim": True,
            },
        )
        _logger.info(
            "http request",
            extra={
                "event": "http.request",
                "method": method,
                "url": redact_url(resolved.url),
                "status": status_code,
                "elapsed_ms": round(elapsed_ms, 3),
                "attempts": attempts,
                "body_bytes": len(payload),
            },
        )
        return RawExchange(
            method=method,
            url=redact_url(resolved.url),
            status_code=status_code,
            headers=response_headers,
            content=payload,
            truncated=truncated,
            body_bytes=len(raw),
            elapsed_ms=round(elapsed_ms, 3),
            attempts=attempts,
        )

    # ------------------------------------------------------------------ internals
    def _enforce_airgap(self, host: str) -> None:
        """Refuse a host the air-gapped allowlist does not cover (S25, REQ-RESIL-001).

        Placed on the shared egress path rather than in each feature, so a feed sync, an
        OSINT provider, a cloud AI provider, a webhook, an OTLP collector or an IdP all
        inherit the guarantee without remembering to check it. The refusal is audited before
        it is raised: an attempt to reach the outside from an air-gapped estate is a
        security event, not just a failed request.
        """
        refusal = self._airgap.refusal(host, scope_hosts=self._airgap_scope_hosts)
        if refusal is None:
            return
        self.auditor.record(
            AuditAction.AIRGAP_BLOCKED,
            outcome=AuditOutcome.BLOCKED,
            target=f"https://{host}",
            reason=refusal,
            meta={"host": host},
        )
        raise AirgapError(refusal)

    async def _validate(self, url: str) -> ResolvedUrl:
        """Run the safety + scope gate, auditing every refusal (F-01-08)."""
        try:
            return await validate_url(url, self.scope, policy=self.policy, resolver=self.resolver)
        except SafetyError as exc:
            action = (
                AuditAction.SCOPE_REJECTED
                if isinstance(exc, OutOfScopeError)
                else AuditAction.SAFETY_BLOCKED
            )
            self.auditor.record(
                action,
                outcome=AuditOutcome.BLOCKED,
                target=url,
                reason=exc.reason or str(exc),
                meta={"method_hint": "validate_url"},
            )
            _logger.warning(
                "request blocked by safety gate",
                extra={"event": "http.blocked", "url": redact_url(url), "reason": exc.reason},
            )
            raise

    def _client_for(self, *, anonymous: bool) -> httpx.AsyncClient:
        """The httpx client a request is issued on.

        ``anonymous`` selects a second client that carries **no cookie jar**. The main client
        keeps one on purpose: the M3 crawl is supposed to carry the session it establishes, so
        that an authenticated surface is reachable (F-08-01). An "is this reachable without
        credentials?" probe is the opposite case — it would be worthless if a cookie the crawl
        (or the credentialed broker's login) picked up were silently attached, turning an
        anonymous probe into an authenticated one and the finding into a false positive. The
        anonymous client shares the transport, timeout and TLS settings, so it is the *same*
        egress path with strictly fewer credentials: this narrows, and can never widen, what a
        request carries.
        """
        if not anonymous:
            return self._client
        if self._anonymous_client is None:
            transport = self._transport
            if transport is None:
                # A caller injected a fully-built client; reuse its transport so an anonymous
                # request reaches the same place (a test's recorded transport, usually).
                transport = getattr(self._client, "_transport", None)
            self._anonymous_client = httpx.AsyncClient(
                transport=transport,
                timeout=httpx.Timeout(
                    self.http_settings.timeout_s,
                    connect=self.http_settings.connect_timeout_s,
                ),
                verify=self.http_settings.verify_tls,
                follow_redirects=False,
                headers={"User-Agent": self.http_settings.user_agent},
            )
        return self._anonymous_client

    async def _send_with_retries(
        self,
        method: str,
        resolved: ResolvedUrl,
        headers: Mapping[str, str],
        content: bytes | str | None,
        *,
        host_key: str,
        anonymous: bool = False,
    ) -> tuple[httpx.Response, int]:
        """Send once, retrying transport failures; each attempt re-acquires tokens."""
        attempts = 0
        last_error: Exception | None = None
        max_attempts = max(1, self.http_settings.retries + 1)
        client = self._client_for(anonymous=anonymous)

        while attempts < max_attempts:
            attempts += 1
            if attempts > 1:
                # Rate limits are never bypassed by retries .
                await self.limiter.acquire(host_key)
            try:
                response = await client.request(
                    method,
                    resolved.url,
                    headers=dict(headers),
                    content=content,
                    follow_redirects=False,
                )
            except httpx.TimeoutException as exc:
                last_error = exc
                continue
            except httpx.HTTPError as exc:
                last_error = exc
                continue

            if response.status_code in _RETRYABLE_STATUS and attempts < max_attempts:
                await response.aclose()
                last_error = httpx.HTTPStatusError(
                    f"retryable status {response.status_code}",
                    request=response.request,
                    response=response,
                )
                continue
            return response, attempts

        raise RequestError(
            f"request to {redact_url(resolved.url)} failed after {attempts} attempt(s): "
            f"{last_error.__class__.__name__}: {redact_text(str(last_error))}",
        )

    async def _capture(
        self,
        *,
        method: str,
        resolved: ResolvedUrl,
        request_headers: Mapping[str, str],
        content: bytes | str | None,
        response: httpx.Response,
        elapsed_ms: float,
        attempts: int,
        chain: tuple[str, ...],
        addresses: tuple[str, ...],
        waited_s: float,
    ) -> HttpExchange:
        body, truncated, is_binary, secret_kinds, masked = self._read_body(response)
        if masked and self.secrets_manifest is not None:
            # Masked fingerprints only: the raw match is discarded inside the redactor, and
            # the ledger is encrypted at rest (F-08-04, ADR-120.6).
            self.secrets_manifest.extend(
                masked, source=redact_url(str(response.request.url)) if response.request else ""
            )
        # Parsed from the *raw* response headers, before redaction blanks ``set-cookie``: the
        # projection keeps the cookie's name and attributes and drops the value (CookieInfo).
        cookies = parse_set_cookies(response.headers)
        exchange = HttpExchange(
            method=method,
            url=redact_url(str(response.request.url)) if response.request else resolved.url,
            status_code=response.status_code,
            request_headers=self._redact(request_headers),
            request_body=self._redact_body(content),
            response_headers=self._redact(response.headers),
            body=body,
            elapsed_ms=round(elapsed_ms, 3),
            attempts=attempts,
            redirect_chain=chain,
            resolved_addresses=addresses,
            body_truncated=truncated,
            body_is_binary=is_binary,
            secret_kinds=secret_kinds,
            cookies=cookies,
        )
        self.auditor.record(
            AuditAction.HTTP_REQUEST,
            outcome=AuditOutcome.ALLOWED,
            target=str(response.request.url) if response.request else resolved.url,
            meta={
                "method": method,
                "status": response.status_code,
                "host": resolved.host,
                "port": resolved.port,
                "resolved_addresses": list(addresses),
                "elapsed_ms": exchange.elapsed_ms,
                "attempts": attempts,
                "throttled_ms": round(waited_s * 1000.0, 3),
                "redirects": len(chain),
                "response_sha256": sha256_of(body),
            },
        )
        _logger.info(
            "http request",
            extra={
                "event": "http.request",
                "method": method,
                "url": redact_url(str(response.request.url)) if response.request else resolved.url,
                "status": response.status_code,
                "elapsed_ms": exchange.elapsed_ms,
                "attempts": attempts,
            },
        )
        return exchange

    def _read_body(
        self, response: httpx.Response
    ) -> tuple[str, bool, bool, tuple[str, ...], tuple[tuple[str, str], ...]]:
        limit = self.body_limit
        raw = response.content
        truncated = len(raw) > limit
        payload = raw[:limit]
        is_binary = _BINARY_SNIFF in payload[:1024]
        if is_binary:
            return f"[binary payload: {len(raw)} bytes]", truncated, True, (), ()
        text = payload.decode(response.encoding or "utf-8", errors="replace")
        if not self.redaction_enabled:
            return text, truncated, False, (), ()
        # The ledger is fed from the raw text *before* redaction (the only place a value
        # exists); what it receives is already masked by ``masked_secret_findings``.
        masked = masked_secret_findings(text)
        # JSON bodies get key-aware redaction as well as pattern redaction: a field
        # literally named "password" is a secret even when its value matches no pattern.
        if _looks_like_json(response, text):
            parsed = _parse_json(text)
            if parsed is not None:
                kinds = tuple(_secret_kinds_of(text))
                return (
                    json.dumps(parsed, ensure_ascii=False, default=str),
                    truncated,
                    False,
                    kinds,
                    masked,
                )
        redacted, kinds = redact_text_report(text)
        return redacted, truncated, False, kinds, masked

    # ------------------------------------------------------------------ redaction helpers
    def _redact_text(self, text: str) -> str:
        return redact_text(text) if self.redaction_enabled else text

    def _redact(self, mapping: Mapping[str, Any]) -> dict[str, str]:
        flattened = {str(k): str(v) for k, v in mapping.items()}
        return redact_headers(flattened) if self.redaction_enabled else flattened

    def _redact_body(self, content: bytes | str | None) -> str | None:
        if content is None:
            return None
        text = content.decode("utf-8", errors="replace") if isinstance(content, bytes) else content
        limit = self.body_limit
        if len(text) > limit:
            text = text[:limit]
        return self._redact_text(text)

    @staticmethod
    def _absolute_url(location: str, base: str) -> str:
        """Resolve a redirect target; refuses non-http(s) schemes via validation later."""
        parsed = urlsplit(location)
        if parsed.scheme and parsed.scheme.lower() not in {"http", "https"}:
            # Keep the raw scheme so validate_url rejects it with an audited reason.
            return location
        return urljoin(base, location)


def _looks_like_json(response: httpx.Response, text: str) -> bool:
    content_type = response.headers.get("content-type", "").lower()
    if "json" in content_type:
        return True
    stripped = text.lstrip()
    return stripped.startswith(("{", "["))


def _parse_json(text: str) -> Any:
    """Parse the body and return the key-aware redacted structure, or ``None``."""
    try:
        parsed = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None
    return redact_value(parsed)


def _secret_kinds_of(text: str) -> list[str]:
    """Pattern names that fire on ``text`` (the JSON branch redacts per key, not per text)."""
    return [pattern.name for pattern in SECRET_PATTERNS if pattern.regex.search(text)]


# --------------------------------------------------------------------------- fixtures
#: A recorded response: what a fixture file stores for one request (vcrpy-style, but
#: stored as plain JSON so a fixture is reviewable and diffable in the repository).
@dataclass(frozen=True, slots=True)
class RecordedResponse:
    """One recorded response, keyed in a fixture file by ``METHOD url``."""

    method: str
    url: str
    status: int = 200
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> RecordedResponse:
        """Build from a fixture entry; raises ``KeyError``/``TypeError`` on a bad shape."""
        return cls(
            method=str(data["method"]).upper(),
            url=str(data["url"]),
            status=int(data.get("status", 200)),
            headers={str(k): str(v) for k, v in dict(data.get("headers") or {}).items()},
            body=str(data.get("body", "")),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "url": self.url,
            "status": self.status,
            "headers": dict(self.headers),
            "body": self.body,
        }


def fixture_transport(responses: Iterable[RecordedResponse]) -> httpx.AsyncBaseTransport:
    """Build a transport that replays recorded responses .

    Lives here — the one module allowed to import ``httpx`` (ADR-05) — so recorded-fixture
    mode is a property of the shared client rather than a second egress path. Matching is by
    exact ``METHOD url`` first, then by ``METHOD host+path`` *when exactly one recording has
    that host+path*: a fallback that had to choose between two recordings would answer with
    the wrong body, and a fixture gap must be loud rather than plausible. An unmatched
    request therefore returns ``501`` with an explanatory body.
    """
    exact: dict[str, RecordedResponse] = {}
    by_path: dict[str, RecordedResponse] = {}
    ambiguous: set[str] = set()
    for response in responses:
        exact[f"{response.method} {response.url}"] = response
        parts = urlsplit(response.url)
        key = f"{response.method} {parts.netloc}{parts.path}"
        if key in by_path:
            ambiguous.add(key)
        by_path.setdefault(key, response)

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        parts = urlsplit(url)
        method = request.method.upper()
        key = f"{method} {url}"
        path_key = f"{method} {parts.netloc}{parts.path}"
        match = exact.get(key)
        if match is None and path_key not in ambiguous:
            match = by_path.get(path_key)
        if match is None:
            reason = f"no recorded fixture for {key}"
            return httpx.Response(
                501,
                text=json.dumps({"error": "fixture-missing", "detail": reason}),
                headers={"content-type": "application/json"},
            )
        return httpx.Response(
            match.status,
            text=match.body,
            headers=match.headers or {"content-type": "application/json"},
        )

    return httpx.MockTransport(handler)
