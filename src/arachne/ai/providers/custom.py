"""The ``custom`` adapter: a user-defined JSON mapping for any future API format (03- §3).

The spec's escape hatch. Instead of guessing an API shape, the deployment describes it::

    providers:
      custom:
        base_url: https://gateway.internal/v2/analyse
        model: house-model
        api_key_env: GATEWAY_TOKEN
        extra:
          api_key_header: Authorization
          api_key_prefix: "Bearer "
          headers:
            X-Tenant: acme
          request_template:
            model: "{{model}}"
            instruction: "{{system}}"
            input: "{{prompt}}"
            max_output_tokens: "{{max_tokens}}"
            format:
              type: "json"
          response_path: "result.0.text"
          usage_path:
            prompt_tokens: "meta.input_tokens"
            completion_tokens: "meta.output_tokens"

Substitution rules are deliberately small and total: a template value that is exactly
``"{{name}}"`` takes the named value **with its type** (so ``max_tokens`` stays an integer), and
a longer string has the placeholders interpolated textually. The response ``response_path`` and
``usage_path`` are dotted paths (``a.0.b``), read by :func:`~arachne.ai.providers.base.value_at`.

Nothing here evaluates Jinja and nothing reaches into Python: the mapping is data, which is what
keeps "support any API format" from becoming "ship an arbitrary code runner".
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from arachne.ai.providers.base import (
    HttpProvider,
    ProviderCall,
    redact_snippet,
    value_at,
)
from arachne.ai.types import (
    CompletionRequest,
    ProviderError,
    Usage,
)

__all__ = ["CustomProvider"]

_PLACEHOLDER_RE = re.compile(r"\{\{\s*([A-Za-z_][A-Za-z0-9_]*)\s*\}\}")


class CustomProvider(HttpProvider):
    """A provider whose request/response mapping comes entirely from configuration."""

    name = "custom"
    mechanism = "custom"

    def plan(self, request: CompletionRequest) -> ProviderCall:
        extra = self.config.extra
        template = extra.get("request_template")
        if not isinstance(template, Mapping):
            raise ProviderError(
                "the 'custom' adapter needs extra.request_template (a JSON mapping with "
                "{{model}}/{{system}}/{{prompt}} placeholders)",
                provider=self.name,
                transient=False,
            )
        variables: dict[str, Any] = {
            "model": request.model or self.model,
            "system": request.system,
            "prompt": request.user_text(),
            "messages": [dict(message) for message in request.messages],
            "max_tokens": request.max_tokens,
            "temperature": request.temperature,
            "schema": dict(request.json_schema) if request.json_schema else None,
        }
        payload = _fill(dict(template), variables)
        headers = {
            "content-type": "application/json",
            **_string_map(extra.get("headers")),
        }
        header_name = extra.get("api_key_header")
        key = self.config.api_key
        if isinstance(header_name, str) and header_name and key is not None:
            prefix = extra.get("api_key_prefix")
            headers[header_name] = f"{prefix or ''}{key.get_secret_value()}"
        response_format = extra.get("response_format")
        if isinstance(response_format, str):
            payload.setdefault("response_format", response_format)
        return ProviderCall(
            url=self.base_url,
            payload=payload,
            headers=headers,
            mechanism=str(extra.get("mechanism") or "custom"),
        )

    def interpret(
        self, data: Any, call: ProviderCall, request: CompletionRequest
    ) -> tuple[str, Usage]:
        extra = self.config.extra
        path = extra.get("response_path")
        if not isinstance(path, str) or not path:
            raise ProviderError(
                "the 'custom' adapter needs extra.response_path "
                "(e.g. 'outputs.0.text') to locate the answer",
                provider=self.name,
                transient=False,
            )
        value = value_at(data, path)
        if isinstance(value, Mapping):
            import json

            text = json.dumps(dict(value), ensure_ascii=False)
        elif isinstance(value, str):
            text = value
        else:
            raise ProviderError(
                f"provider {self.name!r}: response_path {path!r} did not resolve to text "
                f"({redact_snippet(str(data))})",
                provider=self.name,
                transient=False,
            )
        usage = self._usage(data, extra.get("usage_path"))
        return text, usage

    def _usage(self, data: Any, mapping: Any) -> Usage:
        if not isinstance(mapping, Mapping):
            return Usage()
        prompt = _int_at(data, mapping.get("prompt_tokens"))
        completion = _int_at(data, mapping.get("completion_tokens"))
        total = _int_at(data, mapping.get("total_tokens"))
        if prompt is None and completion is None and total is None:
            return Usage()
        return Usage(
            prompt_tokens=prompt or 0,
            completion_tokens=completion or 0,
            total_tokens=total if total is not None else (prompt or 0) + (completion or 0),
        )


def _fill(value: Any, variables: Mapping[str, Any]) -> Any:
    """Substitute ``{{name}}`` placeholders, preserving the type of an exact reference."""
    if isinstance(value, str):
        exact = _PLACEHOLDER_RE.fullmatch(value.strip())
        if exact is not None:
            return variables.get(exact.group(1))
        return _PLACEHOLDER_RE.sub(lambda match: str(variables.get(match.group(1), "")), value)
    if isinstance(value, Mapping):
        return {str(key): _fill(item, variables) for key, item in value.items()}
    if isinstance(value, list):
        return [_fill(item, variables) for item in value]
    return value


def _string_map(value: Any) -> dict[str, str]:
    if not isinstance(value, Mapping):
        return {}
    return {str(key): str(item) for key, item in value.items()}


def _int_at(data: Any, path: Any) -> int | None:
    if not isinstance(path, str) or not path:
        return None
    value = value_at(data, path)
    return value if isinstance(value, int) and not isinstance(value, bool) else None
