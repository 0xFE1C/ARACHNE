"""The adapter seam: one ``plan`` → one ``interpret`` per provider class (03- §3).

Every adapter in this package is the same two transformations:

``plan(request)``
    Turn the provider-neutral :class:`~arachne.ai.types.CompletionRequest` into exactly what
    this API format wants — URL, headers, JSON body — and name the structured-output mechanism
    it chose (``json_object``, ``tool_use``, ``response_mime``, ``format``, ``guided_json``).
``interpret(data, plan)``
    Turn the provider's parsed JSON answer into text plus usage, raising a typed
    :class:`~arachne.ai.types.ProviderError` when the endpoint reports an error *inside* a 200
    response (Ollama and Gemini both do that).

Keeping the split this strict is what makes the adapters testable without a socket: a test
calls ``plan`` and asserts the body, then calls ``interpret`` with a recorded payload. The
transport is the only part that talks to a network, and it is injected.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from arachne.ai.config import ResolvedProvider
from arachne.ai.types import (
    CompletionRequest,
    CompletionResult,
    LlmTransport,
    ProviderError,
    ResponseFormat,
    Usage,
)
from arachne.core.redaction import redact_url

__all__ = ["HttpProvider", "ProviderCall", "redact_snippet", "usage_of", "value_at"]


@dataclass(frozen=True, slots=True)
class ProviderCall:
    """The concrete HTTP request one adapter derived, plus the mechanism it implies."""

    url: str
    payload: Mapping[str, Any]
    headers: Mapping[str, str] = field(default_factory=dict)
    mechanism: str = "text"


class HttpProvider(ABC):
    """Base class for the seven HTTP adapters."""

    #: The adapter name as spelled in the configuration (``openai_compatible``, ``ollama``, ...).
    name: str = ""
    #: The structured-output mechanism this API uses by default .
    mechanism: str = "text"

    def __init__(self, config: ResolvedProvider, transport: LlmTransport) -> None:
        self.config = config
        self.transport = transport

    # ------------------------------------------------------------------ interface
    @property
    def model(self) -> str:
        return self.config.model

    @property
    def base_url(self) -> str:
        return self.config.base_url.rstrip("/")

    async def complete(self, request: CompletionRequest) -> CompletionResult:
        """Plan, send, interpret — one call, no retry policy here (see ``ai.reliability``)."""
        call = self.plan(request)
        started = time.monotonic()
        response = await self.transport.post_json(
            call.url,
            call.payload,
            headers=call.headers,
            timeout_s=request.timeout_s,
        )
        latency_ms = (time.monotonic() - started) * 1000.0
        data = response.json()
        if data is None:
            raise ProviderError(
                f"provider {self.name!r} answered non-JSON at {redact_url(call.url)}: "
                f"{redact_snippet(response.body)}",
                provider=self.name,
                status=response.status,
                transient=response.status >= 500,
            )
        text, usage = self.interpret(data, call, request)
        return CompletionResult(
            text=text,
            raw=data if isinstance(data, Mapping) else {"data": data},
            usage=usage,
            model=request.model or self.model,
            mechanism=call.mechanism,
            attempts=1,
            latency_ms=latency_ms,
        )

    # ------------------------------------------------------------------ to implement
    @abstractmethod
    def plan(self, request: CompletionRequest) -> ProviderCall:
        """The request this API needs for ``request``."""

    @abstractmethod
    def interpret(
        self, data: Any, call: ProviderCall, request: CompletionRequest
    ) -> tuple[str, Usage]:
        """The ``(text, usage)`` this API's answer carries."""

    # ------------------------------------------------------------------ helpers
    def _format(self, request: CompletionRequest) -> ResponseFormat:
        return self.config.response_format or request.response_format

    def _headers_with_key(self, header: str, *, prefix: str = "") -> dict[str, str]:
        headers: dict[str, str] = {}
        key = self.config.api_key
        if key is not None:
            headers[header] = f"{prefix}{key.get_secret_value()}"
        return headers


def redact_snippet(text: str) -> str:
    """A bounded, redacted excerpt of a provider body for an error message."""
    from arachne.core.redaction import redact_text

    return redact_text(text)[:200]


def usage_of(
    data: Mapping[str, Any],
    *,
    prompt_keys: tuple[str, ...] = (
        "prompt_tokens",
        "input_tokens",
        "promptTokenCount",
    ),
    completion_keys: tuple[str, ...] = (
        "completion_tokens",
        "output_tokens",
        "candidatesTokenCount",
    ),
    total_keys: tuple[str, ...] = ("total_tokens", "totalTokenCount"),
) -> Usage | None:
    """Extract token counts from whichever of the known key spellings the API used."""
    source = data
    for candidate in ("usage", "usageMetadata"):
        nested = data.get(candidate)
        if isinstance(nested, Mapping):
            source = nested
            break
    prompt = _first_int(source, prompt_keys)
    completion = _first_int(source, completion_keys)
    total = _first_int(source, total_keys)
    if prompt is None and completion is None and total is None:
        return None
    total = total if total is not None else (prompt or 0) + (completion or 0)
    return Usage(prompt_tokens=prompt or 0, completion_tokens=completion or 0, total_tokens=total)


def _first_int(source: Mapping[str, Any], keys: tuple[str, ...]) -> int | None:
    for key in keys:
        value = source.get(key)
        if isinstance(value, int) and not isinstance(value, bool):
            return value
    return None


def value_at(data: Any, path: str) -> Any:
    """Read ``a.b.0.c`` out of a parsed JSON document; ``None`` when the path is absent."""
    current = data
    for part in path.split("."):
        if isinstance(current, Mapping):
            current = current.get(part)
        elif isinstance(current, (list, tuple)):
            try:
                current = current[int(part)]
            except (ValueError, IndexError):
                return None
        else:
            return None
        if current is None:
            return None
    return current
