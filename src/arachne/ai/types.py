"""The provider-neutral vocabulary of the AI layer (F-04-01).

Everything above the adapters — the pipeline stages, the prompt store, the budget ledger, the
caching and the retry policy — talks only to :class:`LLMProvider` and these value types. That
is what makes "support various API formats" (F-04-01) a matter of adding an adapter rather
than touching the engine, and it is why a provider can be replaced in a test by an object
that answers three methods.

Two deliberate choices:

* **The transport is a protocol, not httpx.** :class:`LlmTransport` is injected into the
  adapters, and the shipped implementation goes through
  :class:`~arachne.core.http.ScopedHttpClient` like every other egress path in ARACHNE
  (ADR-05, ``tests/unit/test_http_hygiene.py``). A test that wants to inspect the exact
  request bytes supplies its own transport and never opens a socket.
* **Failures are typed and classified.** A provider error carries ``transient`` (retry or
  not) and ``retry_after`` (a server's own instruction), because the retry policy in
  ``ai.reliability`` is the only place allowed to decide, and it must not guess from a status
  code it cannot see.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Protocol, runtime_checkable

from arachne.core.errors import ArachneError, ErrorCategory

__all__ = [
    "AiError",
    "CompletionRequest",
    "CompletionResult",
    "LLMProvider",
    "LlmTransport",
    "PrivacyError",
    "ProviderAuthError",
    "ProviderError",
    "ProviderRateLimitError",
    "ProviderTimeoutError",
    "ProviderUnavailableError",
    "ResponseFormat",
    "StructuredOutputError",
    "TransportResponse",
    "Usage",
]


class ResponseFormat(StrEnum):
    """What shape of answer a stage wants ."""

    #: Any valid JSON object (``response_format: {"type": "json_object"}``).
    JSON = "json"
    #: JSON constrained by a schema (``json_schema`` / ``responseSchema`` / a grammar).
    JSON_SCHEMA = "json_schema"
    #: Free text; no parsing is attempted.
    TEXT = "text"


@dataclass(frozen=True, slots=True)
class CompletionRequest:
    """One model call, in provider-neutral terms .

    ``messages`` is a sequence (not a list) because the request is frozen: a stage builds one
    request and may reuse it across retries and repair attempts, and nothing downstream should
    be able to mutate what a provider was asked.
    """

    model: str
    system: str
    messages: tuple[Mapping[str, Any], ...]
    response_format: ResponseFormat = ResponseFormat.JSON
    json_schema: Mapping[str, Any] | None = None
    max_tokens: int = 2000
    #: 0.0 by default: analysis wants the same answer twice .
    temperature: float = 0.0
    timeout_s: float = 60.0
    #: ``guided_json``-style constrained decoding, when the provider supports it.
    constrained_decoding: bool = False

    def user_text(self) -> str:
        """The concatenated user-role content (what the prompt hash is computed over)."""
        parts: list[str] = []
        for message in self.messages:
            content = message.get("content")
            if isinstance(content, str):
                parts.append(content)
        return "\n".join(parts)


@dataclass(frozen=True, slots=True)
class Usage:
    """Token accounting for one call (F-04-07).

    ``cost_usd`` is an estimate from the managed price table, never a billing figure: the
    point is a per-scan budget gate, and a deployment that cares about the exact number reads
    its provider's invoice.
    """

    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    cost_usd: float = 0.0

    def merge(self, other: Usage) -> Usage:
        return Usage(
            prompt_tokens=self.prompt_tokens + other.prompt_tokens,
            completion_tokens=self.completion_tokens + other.completion_tokens,
            total_tokens=self.total_tokens + other.total_tokens,
            cost_usd=self.cost_usd + other.cost_usd,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
            "cost_usd": round(self.cost_usd, 6),
        }


@dataclass(frozen=True, slots=True)
class CompletionResult:
    """A provider's answer, plus what it cost and how it was obtained ."""

    text: str
    raw: Mapping[str, Any] = field(default_factory=dict)
    usage: Usage | None = None
    model: str = ""
    #: The structured-output mechanism that produced ``text`` :
    #: ``json_object``/``json_schema``/``tool_use``/``response_mime``/``format``/``text``.
    mechanism: str = "text"
    attempts: int = 1
    latency_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "model": self.model,
            "mechanism": self.mechanism,
            "attempts": self.attempts,
            "latency_ms": round(self.latency_ms, 3),
            "usage": self.usage.to_dict() if self.usage is not None else None,
            "text_chars": len(self.text),
        }


@dataclass(frozen=True, slots=True)
class TransportResponse:
    """A raw HTTP answer, already redacted by the shared client (ADR-05)."""

    status: int
    body: str
    headers: Mapping[str, str] = field(default_factory=dict)
    url: str = ""

    def json(self) -> Any:
        """Parse the body as JSON; ``None`` when it is not JSON."""
        import json

        try:
            return json.loads(self.body)
        except (ValueError, TypeError):
            return None


@runtime_checkable
class LlmTransport(Protocol):
    """The one thing an adapter needs from the network (ADR-05 keeps this in core)."""

    async def post_json(
        self,
        url: str,
        payload: Mapping[str, Any],
        *,
        headers: Mapping[str, str] | None = None,
        timeout_s: float | None = None,
    ) -> TransportResponse: ...

    async def aclose(self) -> None: ...


# --------------------------------------------------------------------------- interfaces


@runtime_checkable
class LLMProvider(Protocol):
    """The unified provider interface of the AI layer (F-04-01).

    Everything above the adapters talks only to this: the stage runner, the prompt store, the
    budget ledger and the retry wrapper. A test can therefore substitute a provider that
    answers ``complete`` from a dictionary and exercise the whole engine without a network.
    """

    @property
    def name(self) -> str: ...

    @property
    def model(self) -> str: ...

    async def complete(self, request: CompletionRequest) -> CompletionResult: ...


# --------------------------------------------------------------------------- errors


class AiError(ArachneError):
    """Base class for every deliberate AI-layer failure."""

    category = ErrorCategory.AI


class ProviderError(AiError):
    """A provider call failed.

    ``transient`` is the retry policy's input ("only on transient errors
    (429/5xx/network), never on validation failures"), and ``retry_after`` carries a server's
    own pacing instruction when it sent one.
    """

    def __init__(
        self,
        message: str,
        *,
        provider: str = "",
        status: int | None = None,
        transient: bool = True,
        retry_after: float | None = None,
    ) -> None:
        super().__init__(message)
        self.provider = provider
        self.status = status
        self.transient = transient
        self.retry_after = retry_after


class ProviderTimeoutError(ProviderError):
    """The call exceeded its timeout (connect/read/time-to-first-token)."""

    category = ErrorCategory.TIMEOUT


class ProviderRateLimitError(ProviderError):
    """The provider answered 429 (or an equivalent quota signal)."""


class ProviderUnavailableError(ProviderError):
    """The endpoint could not be reached, or answered 5xx."""


class ProviderAuthError(ProviderError):
    """The provider rejected the credential; retrying cannot help."""

    def __init__(self, message: str, *, provider: str = "", status: int | None = None) -> None:
        super().__init__(message, provider=provider, status=status, transient=False)


class StructuredOutputError(AiError):
    """No schema-valid object could be obtained .

    Raised after the repair attempt, and always caught by the engine, which degrades the
    stage to the heuristic result and records the reason in provenance.
    """

    def __init__(self, message: str, *, stage: str = "", attempts: int = 0) -> None:
        super().__init__(message)
        self.stage = stage
        self.attempts = attempts


class PrivacyError(AiError):
    """A privacy mode forbids the call (``local-only`` against an external endpoint)."""

    category = ErrorCategory.SAFETY


def merge_messages(*messages: Mapping[str, Any]) -> tuple[Mapping[str, Any], ...]:
    """Build the ``messages`` tuple of a request from ``{role, content}`` mappings."""
    return tuple(dict(message) for message in messages)


def as_text_sequence(values: Sequence[Any]) -> list[str]:
    """Stringify a sequence for a prompt payload (kept here so stages share one rule)."""
    return [value if isinstance(value, str) else str(value) for value in values]
