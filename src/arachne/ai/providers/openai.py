"""The OpenAI family: ``openai``, ``openai_compatible`` and ``mistral`` (docs/spec/03- §3).

One implementation, three names, because the API format is one thing. ``openai`` is the
canonical ``POST /chat/completions``; ``openai_compatible`` is the same request aimed at a
user-supplied base URL, which is what covers vLLM, LM Studio, llama.cpp, Ollama's ``/v1``,
Groq, OpenRouter, Together, Fireworks, DeepSeek and Azure OpenAI (an Azure deployment is the
same body with the deployment in the URL and ``api-version`` in the query — both configurable);
``mistral`` is the same schema at ``api.mistral.ai``.

Structured output (docs/spec/03- §6), in preference order:

1. ``response_format: {"type": "json_schema", ...}`` — a schema the provider enforces;
2. ``guided_json`` — vLLM/llama.cpp grammar-constrained decoding, when the deployment declares
   it (``constrained_decoding: true``);
3. ``response_format: {"type": "json_object"}`` — JSON mode;
4. no hint at all (``text``), leaving parsing to :mod:`arachne.ai.structured`.

The adapter records which one it used, so a deployment can see whether its model actually
constrains decoding or is merely being *asked* nicely.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from urllib.parse import urlencode

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

__all__ = ["MistralProvider", "OpenAICompatibleProvider", "OpenAIProvider"]


class OpenAICompatibleProvider(HttpProvider):
    """``POST {base_url}/chat/completions`` (the canonical request shape)."""

    name = "openai_compatible"
    mechanism = "json_object"

    def plan(self, request: CompletionRequest) -> ProviderCall:
        payload, mechanism = self._payload(request)
        headers = self._headers_with_key("Authorization", prefix="Bearer ")
        headers["content-type"] = "application/json"
        return ProviderCall(url=self._url(), payload=payload, headers=headers, mechanism=mechanism)

    def interpret(
        self, data: Any, call: ProviderCall, request: CompletionRequest
    ) -> tuple[str, Usage]:
        if isinstance(data, Mapping) and data.get("error") and not data.get("choices"):
            raise ProviderError(
                f"provider {self.name!r} returned an error: {_error_text(data)}",
                provider=self.name,
            )
        text = value_at(data, "choices.0.message.content")
        if not isinstance(text, str):
            raise ProviderError(
                f"provider {self.name!r} answered without choices[0].message.content "
                f"({_shape(data)})",
                provider=self.name,
                transient=False,
            )
        return text, usage_of(data if isinstance(data, Mapping) else {}) or Usage()

    # ------------------------------------------------------------------ internals
    def _url(self) -> str:
        url = f"{self.base_url}/chat/completions"
        version = self.config.api_version
        if version:
            separator = "&" if "?" in url else "?"
            url = f"{url}{separator}{urlencode({'api-version': version})}"
        return url

    def _payload(self, request: CompletionRequest) -> tuple[dict[str, Any], str]:
        messages: list[dict[str, str]] = []
        if request.system:
            messages.append({"role": "system", "content": request.system})
        for message in request.messages:
            role = str(message.get("role") or "user")
            content = message.get("content")
            messages.append({"role": role, "content": content if isinstance(content, str) else ""})
        payload: dict[str, Any] = {
            "model": request.model or self.model,
            "messages": messages,
            "temperature": request.temperature,
            "max_tokens": request.max_tokens,
        }
        mechanism = self._apply_response_format(payload, request)
        extra = self.config.extra
        extra_body = extra.get("extra_body")
        if isinstance(extra_body, Mapping):
            payload.update(dict(extra_body))
        for key, value in extra.items():
            if key in {"extra_body", "response_path", "usage_path"}:
                continue
            payload.setdefault(key, value)
        return payload, mechanism

    def _apply_response_format(self, payload: dict[str, Any], request: CompletionRequest) -> str:
        """Attach the strongest structured-output hint this deployment supports (§6)."""
        wanted = self._format(request)
        schema = request.json_schema
        if wanted is ResponseFormat.TEXT:
            return "text"
        if request.constrained_decoding and schema is not None:
            # vLLM and llama.cpp read ``guided_json`` as a grammar; the same key works as
            # ``json_schema`` on a few gateways, which is why it is one clear name.
            payload["guided_json"] = dict(schema)
            return "guided_json"
        if wanted is ResponseFormat.JSON_SCHEMA and schema is not None:
            payload["response_format"] = {
                "type": "json_schema",
                "json_schema": {
                    "name": "emit",
                    "schema": dict(schema),
                    "strict": True,
                },
            }
            return "json_schema"
        payload["response_format"] = {"type": "json_object"}
        return "json_object"


class OpenAIProvider(OpenAICompatibleProvider):
    """The canonical OpenAI endpoint (``https://api.openai.com/v1``)."""

    name = "openai"


class MistralProvider(OpenAICompatibleProvider):
    """Mistral's chat completions (OpenAI-compatible schema, docs/spec/03- §3)."""

    name = "mistral"


def _error_text(data: Mapping[str, Any]) -> str:
    error = data.get("error")
    if isinstance(error, Mapping):
        return redact_snippet(str(error.get("message") or error))
    return redact_snippet(str(error))


def _shape(data: Any) -> str:
    """A short description of an unexpected answer, for the error message."""
    if isinstance(data, Mapping):
        return f"keys: {sorted(str(key) for key in data)[:8]}"
    return type(data).__name__
