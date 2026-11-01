"""Anthropic Messages API adapter (docs/spec/03- §3).

Three differences from the OpenAI shape matter, and each is encoded here rather than papered
over:

* the system prompt is a **top-level** parameter, not a message;
* the credential is ``x-api-key`` (plus a required ``anthropic-version``), not a bearer token;
* structured output is **tool use**: a single ``emit`` tool whose ``input_schema`` is the
  stage's schema, with ``tool_choice`` forcing it. That is stronger than asking for JSON — the
  provider validates the arguments against the schema before returning them — and the adapter
  names the mechanism ``tool_use`` so the provenance says so.
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

__all__ = ["AnthropicProvider"]

#: Pinned API version. A provider that changes its answer shape must be opted into.
ANTHROPIC_VERSION = "2023-06-01"


class AnthropicProvider(HttpProvider):
    """``POST {base_url}/v1/messages``."""

    name = "anthropic"
    mechanism = "tool_use"

    def plan(self, request: CompletionRequest) -> ProviderCall:
        payload: dict[str, Any] = {
            "model": request.model or self.model,
            "max_tokens": request.max_tokens,
            "temperature": request.temperature,
            "messages": [
                {"role": str(message.get("role") or "user"), "content": _content(message)}
                for message in request.messages
            ],
        }
        if request.system:
            payload["system"] = request.system
        mechanism = "text"
        wanted = self._format(request)
        schema = request.json_schema
        if wanted is not ResponseFormat.TEXT and schema is not None:
            payload["tools"] = [
                {
                    "name": "emit",
                    "description": "Return the analysis as structured data.",
                    "input_schema": dict(schema),
                }
            ]
            payload["tool_choice"] = {"type": "tool", "name": "emit"}
            mechanism = "tool_use"
        elif wanted is not ResponseFormat.TEXT:
            # No schema supplied: the closest honest request is "answer with JSON only".
            payload["system"] = (
                f"{request.system}\n\nReply with a single JSON object and nothing else."
            ).strip()
            mechanism = "json_object"
        extra_body = self.config.extra.get("extra_body")
        if isinstance(extra_body, Mapping):
            payload.update(dict(extra_body))
        headers = self._headers_with_key("x-api-key")
        headers["anthropic-version"] = str(
            self.config.extra.get("anthropic_version") or ANTHROPIC_VERSION
        )
        headers["content-type"] = "application/json"
        return ProviderCall(
            url=f"{self.base_url}/v1/messages",
            payload=payload,
            headers=headers,
            mechanism=mechanism,
        )

    def interpret(
        self, data: Any, call: ProviderCall, request: CompletionRequest
    ) -> tuple[str, Usage]:
        if isinstance(data, Mapping) and data.get("type") == "error":
            raise ProviderError(
                f"provider {self.name!r} returned an error: "
                f"{redact_snippet(str(data.get('error')))}",
                provider=self.name,
            )
        blocks = value_at(data, "content")
        if not isinstance(blocks, list):
            raise ProviderError(
                f"provider {self.name!r} answered without a content block list",
                provider=self.name,
                transient=False,
            )
        tool_inputs = [
            block.get("input")
            for block in blocks
            if isinstance(block, Mapping) and block.get("type") == "tool_use"
        ]
        if tool_inputs:
            import json

            return json.dumps(tool_inputs[0], ensure_ascii=False), usage_of(
                data if isinstance(data, Mapping) else {}
            ) or Usage()
        texts = [
            str(block.get("text") or "")
            for block in blocks
            if isinstance(block, Mapping) and block.get("type") == "text"
        ]
        if not any(text.strip() for text in texts):
            raise ProviderError(
                f"provider {self.name!r} returned neither tool input nor text",
                provider=self.name,
                transient=False,
            )
        return "\n".join(texts), usage_of(data if isinstance(data, Mapping) else {}) or Usage()


def _content(message: Mapping[str, Any]) -> str:
    content = message.get("content")
    return content if isinstance(content, str) else ""
