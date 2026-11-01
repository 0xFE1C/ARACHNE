"""Google Gemini ``generateContent`` adapter .

The shape is Google's: ``contents[].parts[].text`` in, ``candidates[].content.parts[].text``
out, with the system prompt in ``systemInstruction`` and the structured-output request in
``generationConfig`` — ``responseMimeType: application/json`` plus, when a schema is supplied,
``responseSchema`` (Gemini's OpenAPI-subset spelling).

Auth is either ``?key=`` (the documented API-key form) or Application Default Credentials. This
adapter implements the key form; with no key configured it sends no credential and lets the
deployment's ADC proxy (or a gateway in front of the API) supply one — which is why the
``gemini`` provider is allowed to run unconfigured-key in a local deployment but *not* by
default (``DEFAULT_API_KEY_ENV`` names ``GEMINI_API_KEY`` and the resolver refuses a missing
credential for the hosted provider).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from urllib.parse import quote, urlencode

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

__all__ = ["GeminiProvider"]


class GeminiProvider(HttpProvider):
    """``POST {base_url}/v1beta/models/{model}:generateContent``."""

    name = "gemini"
    mechanism = "response_mime"

    def plan(self, request: CompletionRequest) -> ProviderCall:
        model = request.model or self.model
        url = f"{self.base_url}/v1beta/models/{quote(model, safe='')}:generateContent"
        key = self.config.api_key
        if key is not None:
            url = f"{url}?{urlencode({'key': key.get_secret_value()})}"
        generation: dict[str, Any] = {
            "temperature": request.temperature,
            "maxOutputTokens": request.max_tokens,
        }
        mechanism = "text"
        wanted = self._format(request)
        schema = request.json_schema
        if wanted is not ResponseFormat.TEXT:
            generation["responseMimeType"] = "application/json"
            mechanism = "response_mime"
            if wanted is ResponseFormat.JSON_SCHEMA and schema is not None:
                generation["responseSchema"] = _gemini_schema(schema)
                mechanism = "response_schema"
        payload: dict[str, Any] = {
            "contents": [
                {
                    "role": "user" if str(message.get("role") or "user") == "user" else "model",
                    "parts": [{"text": _content(message)}],
                }
                for message in request.messages
            ],
            "generationConfig": generation,
        }
        if request.system:
            payload["systemInstruction"] = {"parts": [{"text": request.system}]}
        extra_body = self.config.extra.get("extra_body")
        if isinstance(extra_body, Mapping):
            payload.update(dict(extra_body))
        headers = {"content-type": "application/json"}
        api_version = self.config.extra.get("api_version_header")
        if isinstance(api_version, str) and api_version:
            headers["x-goog-api-version"] = api_version
        return ProviderCall(url=url, payload=payload, headers=headers, mechanism=mechanism)

    def interpret(
        self, data: Any, call: ProviderCall, request: CompletionRequest
    ) -> tuple[str, Usage]:
        if isinstance(data, Mapping) and data.get("error"):
            raise ProviderError(
                f"provider {self.name!r} returned an error: "
                f"{redact_snippet(str(data.get('error')))}",
                provider=self.name,
            )
        parts = value_at(data, "candidates.0.content.parts")
        if not isinstance(parts, list):
            blocked = value_at(data, "promptFeedback.blockReason")
            if blocked:
                raise ProviderError(
                    f"provider {self.name!r} blocked the prompt ({blocked})",
                    provider=self.name,
                    transient=False,
                )
            raise ProviderError(
                f"provider {self.name!r} answered without candidates[0].content.parts",
                provider=self.name,
                transient=False,
            )
        texts = [
            str(part.get("text") or "")
            for part in parts
            if isinstance(part, Mapping) and not part.get("thought")
        ]
        joined = "\n".join(text for text in texts if text)
        if not joined.strip():
            raise ProviderError(
                f"provider {self.name!r} returned no text",
                provider=self.name,
                transient=False,
            )
        return joined, usage_of(data if isinstance(data, Mapping) else {}) or Usage()


def _content(message: Mapping[str, Any]) -> str:
    content = message.get("content")
    return content if isinstance(content, str) else ""


def _gemini_schema(schema: Mapping[str, Any]) -> dict[str, Any]:
    """Translate JSON Schema into Gemini's OpenAPI-subset dialect.

    The subset has no ``$defs``/``$ref`` and only upper-case types, so a generated schema is
    rewritten rather than forwarded: the stage models are deliberately flat, which makes this
    a small, total transformation instead of a general one.
    """
    out: dict[str, Any] = {}
    type_name = schema.get("type")
    if isinstance(type_name, str):
        out["type"] = type_name.upper()
    for key in ("description", "enum", "required", "minimum", "maximum", "format"):
        if key in schema:
            out[key] = schema[key]
    properties = schema.get("properties")
    if isinstance(properties, Mapping):
        out["properties"] = {
            str(name): _gemini_schema(value)
            for name, value in properties.items()
            if isinstance(value, Mapping)
        }
    items = schema.get("items")
    if isinstance(items, Mapping):
        out["items"] = _gemini_schema(items)
    return out
