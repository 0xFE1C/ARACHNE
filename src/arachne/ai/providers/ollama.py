"""Ollama's native API adapter — the fully local path.

``POST {base_url}/api/chat`` with ``stream: false``. Structured output uses Ollama's own
``format`` field: the string ``"json"`` for JSON mode, or a full JSON **schema object**, which
current Ollama versions turn into a grammar (constrained decoding). That is why the local path
is the one that can genuinely *guarantee* a shape without a hosted provider's tool-use support,
and it is the path the documentation calls out with "``format: \"json\"`` + optional
JSONSchema grammar".

No credential: Ollama has no authentication, and the scope/URL policy is what decides whether
the endpoint may be contacted at all (a non-loopback base URL still has to be declared).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from arachne.ai.providers.base import (
    HttpProvider,
    ProviderCall,
    redact_snippet,
    usage_of,
    value_at,
)
from arachne.ai.types import (
    CompletionRequest,
    ProviderError,
    ResponseFormat,
    Usage,
)

__all__ = ["OllamaProvider"]


class OllamaProvider(HttpProvider):
    """``POST {base_url}/api/chat`` (native, not the ``/v1`` compatibility shim)."""

    name = "ollama"
    mechanism = "format"

    def plan(self, request: CompletionRequest) -> ProviderCall:
        messages: list[dict[str, str]] = []
        if request.system:
            messages.append({"role": "system", "content": request.system})
        for message in request.messages:
            messages.append(
                {
                    "role": str(message.get("role") or "user"),
                    "content": _content(message),
                }
            )
        payload: dict[str, Any] = {
            "model": request.model or self.model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": request.temperature,
                "num_predict": request.max_tokens,
            },
        }
        mechanism = "text"
        wanted = self._format(request)
        schema = request.json_schema
        if wanted is ResponseFormat.JSON_SCHEMA and schema is not None:
            payload["format"] = dict(schema)
            mechanism = "format_schema"
        elif wanted is not ResponseFormat.TEXT:
            payload["format"] = "json"
            mechanism = "format"
        extra_body = self.config.extra.get("extra_body")
        if isinstance(extra_body, Mapping):
            payload.update(dict(extra_body))
        return ProviderCall(
            url=f"{self.base_url}/api/chat",
            payload=payload,
            headers={"content-type": "application/json"},
            mechanism=mechanism,
        )

    def interpret(
        self, data: Any, call: ProviderCall, request: CompletionRequest
    ) -> tuple[str, Usage]:
        if isinstance(data, Mapping) and data.get("error"):
            # Ollama reports a missing model as HTTP 404 with an ``error`` body; the transport
            # has already raised for 4xx, so this is a defensive branch for a 200-with-error.
            raise ProviderError(
                f"provider {self.name!r} returned an error: "
                f"{redact_snippet(str(data.get('error')))}",
                provider=self.name,
                transient=False,
            )
        text = value_at(data, "message.content")
        if not isinstance(text, str):
            raise ProviderError(
                f"provider {self.name!r} answered without message.content",
                provider=self.name,
                transient=False,
            )
        usage = usage_of(
            data if isinstance(data, Mapping) else {},
            prompt_keys=("prompt_eval_count",),
            completion_keys=("eval_count",),
            total_keys=(),
        )
        return text, usage or Usage()


def _content(message: Mapping[str, Any]) -> str:
    content = message.get("content")
    return content if isinstance(content, str) else ""
