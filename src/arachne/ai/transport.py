"""The provider egress path: a second scope-bound client for model endpoints (ADR-05).

Provider calls are not target calls, so they must not travel through the target-scoped client
— but they must not become a hole in ADR-05 either. This module builds a **second**
:class:`~arachne.core.http.ScopedHttpClient` whose scope is exactly the hosts of the
configured providers, and every adapter posts through it: the same URL validation, the same
per-host and global rate limits, the same capture-time redaction and the same audit trail as a
request to a scan target (``http.request`` lines, one per attempt).

Two decisions worth stating:

* **Scope is derived, not declared twice.** :func:`provider_hosts` reads the hosts out of the
  configured ``base_url`` values, so "call this model endpoint" and "this host is in scope"
  cannot drift apart. An endpoint that is not configured is out of scope, and the request is
  refused and audited rather than sent.
* **Loopback is allowed only when an operator declared a local endpoint.** The URL policy
  refuses loopback and private addresses by default (F-08-03), which would make the documented
  local path (Ollama/vLLM on the same host) unusable. So the AI client's
  policy allows loopback/private addresses **iff** some configured provider base_url resolves
  to one — an explicit declaration of intent, exactly as the OSINT client treats a configured
  search endpoint (``modules.providers``). The target scan's policy is untouched.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Mapping
from dataclasses import dataclass
from ipaddress import ip_address
from typing import Any
from urllib.parse import urlsplit

from arachne.ai.types import (
    ProviderAuthError,
    ProviderError,
    ProviderRateLimitError,
    ProviderTimeoutError,
    ProviderUnavailableError,
    TransportResponse,
)
from arachne.core.audit import Auditor
from arachne.core.config import Settings
from arachne.core.errors import RequestError, SafetyError
from arachne.core.http import ScopedHttpClient
from arachne.core.logging import get_logger
from arachne.core.redaction import redact_text, redact_url
from arachne.core.safety import Scope, UrlSafetyPolicy

__all__ = [
    "HttpLlmTransport",
    "build_llm_client",
    "build_llm_transport",
    "is_local_endpoint",
    "provider_hosts",
]

_logger = get_logger("ai.transport")

#: Statuses that mean "come back later" .
_RETRYABLE_STATUS = frozenset({408, 409, 425, 429, 500, 502, 503, 504, 529})
_AUTH_STATUS = frozenset({401, 403})
_LOCAL_HOSTS = frozenset({"localhost", "localhost.localdomain", "host.docker.internal"})


def _host_of(base_url: str) -> str:
    return (urlsplit(base_url).hostname or "").strip().lower()


def is_local_endpoint(base_url: str) -> bool:
    """True when ``base_url`` points at this machine (loopback, private, or a local name).

    Deliberately conservative: an unresolvable name is *not* local, so the default policy
    still refuses it. A private address is local because the documented self-hosted paths
    (Ollama, vLLM, LM Studio on a LAN box) are private by nature.
    """
    host = _host_of(base_url)
    if not host:
        return False
    if host in _LOCAL_HOSTS or host.endswith((".local", ".localhost")):
        return True
    try:
        address = ip_address(host.strip("[]"))
    except ValueError:
        return False
    return address.is_loopback or address.is_private or address.is_link_local


def provider_hosts(base_urls: Mapping[str, str]) -> tuple[str, ...]:
    """The distinct hosts of the configured provider base URLs, in stable order."""
    hosts = [_host_of(url) for url in base_urls.values()]
    return tuple(dict.fromkeys(host for host in hosts if host))


def build_llm_client(
    *,
    base_urls: Mapping[str, str],
    settings: Settings | None = None,
    auditor: Auditor | None = None,
    scope: Scope | None = None,
    policy: UrlSafetyPolicy | None = None,
    transport: Any = None,
) -> ScopedHttpClient:
    """Build the scope-bound client the AI adapters post through.

    An empty ``base_urls`` yields a **deny-all** scope, so a misconfigured deployment makes no
    request at all rather than an unscoped one.
    """
    hosts = provider_hosts(base_urls)
    effective_scope = (
        scope if scope is not None else (Scope(allowed_hosts=hosts) if hosts else Scope.deny_all())
    )
    if policy is not None:
        effective_policy = policy
    else:
        local = any(is_local_endpoint(url) for url in base_urls.values())
        effective_policy = UrlSafetyPolicy(
            allow_loopback=local,
            allow_private_ips=local,
        )
    return ScopedHttpClient(
        settings=settings,
        scope=effective_scope,
        policy=effective_policy,
        auditor=auditor,
        transport=transport,
    )


@dataclass
class HttpLlmTransport:
    """A :class:`~arachne.ai.types.LlmTransport` over the shared scoped client."""

    client: ScopedHttpClient
    provider: str = ""

    async def post_json(
        self,
        url: str,
        payload: Mapping[str, Any],
        *,
        headers: Mapping[str, str] | None = None,
        timeout_s: float | None = None,
    ) -> TransportResponse:
        request_headers = {
            "content-type": "application/json",
            "accept": "application/json",
            **{str(key): str(value) for key, value in (headers or {}).items()},
        }
        body = json.dumps(payload, ensure_ascii=False)
        try:
            call = self.client.post(url, headers=request_headers, content=body)
            exchange = (
                await asyncio.wait_for(call, timeout=timeout_s)
                if timeout_s is not None
                else await call
            )
        except TimeoutError as exc:
            raise ProviderTimeoutError(
                f"{self._label()} did not answer within {timeout_s}s",
                provider=self.provider,
            ) from exc
        except SafetyError as exc:
            # A refusal by the scope or the URL policy is a configuration error, not a
            # transient fault: retrying the same URL can never make it allowed.
            raise ProviderError(
                f"{self._label()} refused by the safety gate: {exc.reason}",
                provider=self.provider,
                transient=False,
            ) from exc
        except RequestError as exc:
            raise ProviderUnavailableError(
                f"{self._label()} unreachable: {redact_text(str(exc))}",
                provider=self.provider,
            ) from exc

        self._raise_for_status(exchange.status_code, exchange.body, exchange.header("retry-after"))
        return TransportResponse(
            status=exchange.status_code,
            body=exchange.body,
            headers=dict(exchange.response_headers),
            url=redact_url(exchange.url),
        )

    async def aclose(self) -> None:
        await self.client.aclose()

    # ------------------------------------------------------------------ internals
    def _label(self) -> str:
        return f"provider {self.provider!r}" if self.provider else "the model endpoint"

    def _raise_for_status(self, status: int, body: str, retry_after: str | None) -> None:
        if 200 <= status < 300:
            return
        excerpt = redact_text(body)[:300]
        if status in _AUTH_STATUS:
            raise ProviderAuthError(
                f"{self._label()} rejected the credential (HTTP {status}): {excerpt}",
                provider=self.provider,
                status=status,
            )
        if status == 429:
            raise ProviderRateLimitError(
                f"{self._label()} rate-limited the call (HTTP 429)",
                provider=self.provider,
                status=status,
                retry_after=_parse_retry_after(retry_after),
            )
        if status in _RETRYABLE_STATUS or status >= 500:
            raise ProviderUnavailableError(
                f"{self._label()} answered HTTP {status}: {excerpt}",
                provider=self.provider,
                status=status,
                retry_after=_parse_retry_after(retry_after),
            )
        raise ProviderError(
            f"{self._label()} answered HTTP {status}: {excerpt}",
            provider=self.provider,
            status=status,
            transient=False,
        )


def _parse_retry_after(value: str | None) -> float | None:
    """Read a ``Retry-After`` header (delta-seconds form); ``None`` when absent/unparseable."""
    if not value:
        return None
    try:
        seconds = float(value.strip())
    except ValueError:
        return None
    return max(0.0, seconds)


def build_llm_transport(
    *,
    base_urls: Mapping[str, str],
    provider: str = "",
    settings: Settings | None = None,
    auditor: Auditor | None = None,
    scope: Scope | None = None,
    policy: UrlSafetyPolicy | None = None,
    transport: Any = None,
) -> HttpLlmTransport:
    """Build the shipped transport for one deployment (see :func:`build_llm_client`)."""
    client = build_llm_client(
        base_urls=base_urls,
        settings=settings,
        auditor=auditor,
        scope=scope,
        policy=policy,
        transport=transport,
    )
    _logger.debug(
        "ai transport built",
        extra={
            "event": "ai.transport",
            "provider": provider,
            "hosts": list(provider_hosts(base_urls)),
            "local": any(is_local_endpoint(url) for url in base_urls.values()),
        },
    )
    return HttpLlmTransport(client=client, provider=provider)
