"""The seven provider adapters, the transport mapping and the scope of the AI egress path.

docs/spec/03- §3 is a table of API formats; this module tests that each adapter produces the
request that table describes and reads the answer it returns. ``plan()`` is asserted directly
(no socket, exact bytes), ``complete()`` is driven through a scripted transport, and one case
replays a **vcrpy cassette** so the real ``httpx`` path — through the shared scoped client —
is covered by a recorded fixture rather than by a live endpoint (docs/spec/07- §6).
"""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest
import vcr
from tests.helpers.ai import triage_request

from arachne.ai.config import ResolvedProvider
from arachne.ai.providers.base import ProviderCall, usage_of, value_at
from arachne.ai.providers.registry import build_provider
from arachne.ai.transport import (
    HttpLlmTransport,
    build_llm_client,
    is_local_endpoint,
    provider_hosts,
)
from arachne.ai.types import (
    CompletionRequest,
    ProviderAuthError,
    ProviderError,
    ProviderRateLimitError,
    ProviderUnavailableError,
    ResponseFormat,
    TransportResponse,
)
from arachne.core.config import Settings
from arachne.core.http import ScopedHttpClient
from arachne.core.safety import Scope, StaticResolver, UrlSafetyPolicy

SCHEMA = {
    "type": "object",
    "properties": {"severity": {"type": "string"}},
    "required": ["severity"],
    "additionalProperties": False,
}

CASSETTE_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "ai"


def request(
    *,
    response_format: ResponseFormat = ResponseFormat.JSON_SCHEMA,
    constrained: bool = False,
    model: str = "test-model",
    with_schema: bool = True,
) -> CompletionRequest:
    return CompletionRequest(
        model=model,
        system="You are a triage analyst.",
        messages=(
            {"role": "user", "content": "[CONTEXT]\nscan: 1\n\n[TARGET_DATA]\n<delim>200</delim>"},
        ),
        response_format=response_format,
        json_schema=(
            SCHEMA if with_schema and response_format is not ResponseFormat.TEXT else None
        ),
        max_tokens=321,
        temperature=0.0,
        timeout_s=12.0,
        constrained_decoding=constrained,
    )


def resolved(name: str, **overrides: object) -> ResolvedProvider:
    base: dict[str, object] = {
        "name": name,
        "base_url": {
            "openai": "https://api.openai.com/v1",
            "openai_compatible": "http://127.0.0.1:9999/v1",
            "anthropic": "https://api.anthropic.com",
            "gemini": "https://generativelanguage.googleapis.com",
            "ollama": "http://localhost:11434",
            "mistral": "https://api.mistral.ai/v1",
            "custom": "https://gateway.example/analyse",
        }[name],
        "model": "test-model",
        "api_key": None,
    }
    base.update(overrides)
    return ResolvedProvider(**base)  # type: ignore[arg-type]


class ScriptedTransport:
    """A transport that records the request and answers with a fixed body."""

    def __init__(self, body: object, *, status: int = 200) -> None:
        self.body = body if isinstance(body, str) else json.dumps(body)
        self.status = status
        self.calls: list[tuple[str, dict[str, object], dict[str, str]]] = []

    async def post_json(
        self,
        url: str,
        payload: object,
        *,
        headers: object = None,
        timeout_s: object = None,
    ) -> TransportResponse:
        self.calls.append((url, dict(payload), dict(headers or {})))  # type: ignore[arg-type]
        return TransportResponse(status=self.status, body=self.body, headers={}, url=url)

    async def aclose(self) -> None:
        return None


# --------------------------------------------------------------------------- OpenAI family


def test_openai_plan_is_the_canonical_chat_completion() -> None:
    provider = build_provider(resolved("openai", api_key=_secret("sk-test")), ScriptedTransport({}))
    call = provider.plan(request())

    assert call.url == "https://api.openai.com/v1/chat/completions"
    assert call.headers["Authorization"] == "Bearer sk-test"
    assert call.payload["model"] == "test-model"
    assert call.payload["temperature"] == 0.0
    assert call.payload["max_tokens"] == 321
    assert call.payload["messages"][0] == {
        "role": "system",
        "content": "You are a triage analyst.",
    }
    assert call.payload["messages"][1]["role"] == "user"
    # json_schema is the strongest mechanism when a schema exists (docs/spec/03- §6).
    assert call.payload["response_format"] == {
        "type": "json_schema",
        "json_schema": {"name": "emit", "schema": SCHEMA, "strict": True},
    }
    assert call.mechanism == "json_schema"
    assert "_mechanism" not in call.payload  # never leaked to the provider


def test_openai_falls_back_to_json_object_then_text() -> None:
    provider = build_provider(resolved("openai"), ScriptedTransport({}))
    json_mode = provider.plan(request(response_format=ResponseFormat.JSON))
    assert json_mode.payload["response_format"] == {"type": "json_object"}
    assert json_mode.mechanism == "json_object"

    text = provider.plan(request(response_format=ResponseFormat.TEXT))
    assert "response_format" not in text.payload
    assert text.mechanism == "text"


def test_openai_compatible_supports_constrained_decoding() -> None:
    provider = build_provider(
        resolved("openai_compatible", constrained_decoding=True), ScriptedTransport({})
    )
    call = provider.plan(request(constrained=True))
    assert call.payload["guided_json"] == SCHEMA
    assert call.mechanism == "guided_json"


def test_azure_style_deployments_carry_the_api_version() -> None:
    provider = build_provider(resolved("openai", api_version="2024-10-21"), ScriptedTransport({}))
    assert provider.plan(request()).url.endswith("?api-version=2024-10-21")


def test_openai_interpret_reads_content_and_usage() -> None:
    body = {
        "choices": [{"message": {"role": "assistant", "content": '{"severity": "high"}'}}],
        "usage": {"prompt_tokens": 10, "completion_tokens": 4, "total_tokens": 14},
    }
    provider = build_provider(resolved("openai"), ScriptedTransport(body))
    import asyncio

    result = asyncio.run(provider.complete(request()))
    assert result.text == '{"severity": "high"}'
    assert result.usage is not None
    assert result.usage.total_tokens == 14
    assert result.mechanism == "json_schema"
    assert result.latency_ms >= 0.0


def test_openai_interprets_an_error_object_in_a_200() -> None:
    provider = build_provider(
        resolved("openai"), ScriptedTransport({"error": {"message": "quota exceeded"}})
    )
    import asyncio

    with pytest.raises(ProviderError, match="quota exceeded"):
        asyncio.run(provider.complete(request()))


def test_mistral_uses_the_same_format_at_its_own_endpoint() -> None:
    provider = build_provider(resolved("mistral"), ScriptedTransport({}))
    call = provider.plan(request())
    assert call.url == "https://api.mistral.ai/v1/chat/completions"
    assert provider.name == "mistral"


# --------------------------------------------------------------------------- Anthropic


def test_anthropic_plan_is_the_messages_api_with_tool_use() -> None:
    provider = build_provider(
        resolved("anthropic", api_key=_secret("ak-test")), ScriptedTransport({})
    )
    call = provider.plan(request())

    assert call.url == "https://api.anthropic.com/v1/messages"
    assert call.headers["x-api-key"] == "ak-test"
    assert call.headers["anthropic-version"] == "2023-06-01"
    # system is top-level; the user turn is a message (docs/spec/03- §3).
    assert call.payload["system"] == "You are a triage analyst."
    assert call.payload["messages"][0]["role"] == "user"
    assert "You are a triage analyst." not in json.dumps(call.payload["messages"])
    assert call.payload["tools"][0]["input_schema"] == SCHEMA
    assert call.payload["tool_choice"] == {"type": "tool", "name": "emit"}
    assert call.mechanism == "tool_use"


def test_anthropic_interpret_reads_the_tool_input() -> None:
    body = {
        "type": "message",
        "content": [
            {"type": "tool_use", "id": "t1", "name": "emit", "input": {"severity": "high"}}
        ],
        "usage": {"input_tokens": 30, "output_tokens": 5},
    }
    provider = build_provider(resolved("anthropic"), ScriptedTransport(body))
    import asyncio

    result = asyncio.run(provider.complete(request()))
    assert json.loads(result.text) == {"severity": "high"}
    assert result.usage is not None
    assert result.usage.prompt_tokens == 30  # type: ignore[union-attr]


def test_anthropic_falls_back_to_text_blocks() -> None:
    body = {"type": "message", "content": [{"type": "text", "text": '{"severity": "low"}'}]}
    provider = build_provider(resolved("anthropic"), ScriptedTransport(body))
    import asyncio

    result = asyncio.run(provider.complete(request()))
    assert result.text == '{"severity": "low"}'


def test_anthropic_without_a_schema_asks_for_json_in_the_system_prompt() -> None:
    provider = build_provider(resolved("anthropic"), ScriptedTransport({}))
    call = provider.plan(request(response_format=ResponseFormat.JSON, with_schema=False))
    assert "single JSON object" in str(call.payload["system"])
    assert call.mechanism == "json_object"


# --------------------------------------------------------------------------- Gemini


def test_gemini_plan_is_generate_content_with_response_mime() -> None:
    provider = build_provider(resolved("gemini", api_key=_secret("gem-key")), ScriptedTransport({}))
    call = provider.plan(request())

    assert call.url.startswith(
        "https://generativelanguage.googleapis.com/v1beta/models/test-model:generateContent"
    )
    assert "key=gem-key" in call.url
    assert call.payload["systemInstruction"]["parts"][0]["text"] == "You are a triage analyst."
    generation = call.payload["generationConfig"]
    assert generation["responseMimeType"] == "application/json"
    assert generation["responseSchema"]["type"] == "OBJECT"  # Gemini's upper-case dialect
    assert generation["maxOutputTokens"] == 321
    assert call.mechanism == "response_schema"


def test_gemini_interpret_reads_candidate_parts_and_usage() -> None:
    body = {
        "candidates": [{"content": {"parts": [{"text": '{"severity": "high"}'}]}}],
        "usageMetadata": {"promptTokenCount": 11, "candidatesTokenCount": 3, "totalTokenCount": 14},
    }
    provider = build_provider(resolved("gemini"), ScriptedTransport(body))
    import asyncio

    result = asyncio.run(provider.complete(request()))
    assert result.text == '{"severity": "high"}'
    assert result.usage is not None
    assert result.usage.total_tokens == 14


def test_gemini_reports_a_blocked_prompt() -> None:
    provider = build_provider(
        resolved("gemini"), ScriptedTransport({"promptFeedback": {"blockReason": "SAFETY"}})
    )
    import asyncio

    with pytest.raises(ProviderError, match="blocked"):
        asyncio.run(provider.complete(request()))


# --------------------------------------------------------------------------- Ollama


def test_ollama_plan_is_the_native_chat_api_with_a_schema_format() -> None:
    provider = build_provider(resolved("ollama"), ScriptedTransport({}))
    call = provider.plan(request())

    assert call.url == "http://localhost:11434/api/chat"
    assert call.payload["stream"] is False
    assert call.payload["format"] == SCHEMA  # a grammar, i.e. constrained decoding
    assert call.payload["options"] == {"temperature": 0.0, "num_predict": 321}
    assert call.payload["messages"][0]["role"] == "system"
    assert call.mechanism == "format_schema"


def test_ollama_uses_the_json_string_for_json_mode() -> None:
    provider = build_provider(resolved("ollama"), ScriptedTransport({}))
    call = provider.plan(request(response_format=ResponseFormat.JSON))
    assert call.payload["format"] == "json"
    assert call.mechanism == "format"


def test_ollama_interpret_reads_message_content_and_eval_counts() -> None:
    body = {
        "message": {"content": '{"severity": "high"}'},
        "prompt_eval_count": 40,
        "eval_count": 9,
    }
    provider = build_provider(resolved("ollama"), ScriptedTransport(body))
    import asyncio

    result = asyncio.run(provider.complete(request()))
    assert result.text == '{"severity": "high"}'
    assert result.usage is not None
    assert result.usage.prompt_tokens == 40
    assert result.usage.completion_tokens == 9
    assert result.usage.total_tokens == 49


# --------------------------------------------------------------------------- custom


def test_custom_maps_the_request_and_response_from_configuration() -> None:
    provider = build_provider(
        resolved(
            "custom",
            api_key=_secret("gw-token"),
            extra={
                "api_key_header": "Authorization",
                "api_key_prefix": "Bearer ",
                "headers": {"X-Tenant": "acme"},
                "request_template": {
                    "model": "{{model}}",
                    "instruction": "{{system}}",
                    "input": "{{prompt}}",
                    "max_output_tokens": "{{max_tokens}}",
                    "temperature": "{{temperature}}",
                },
                "response_path": "result.0.text",
                "usage_path": {
                    "prompt_tokens": "meta.input_tokens",
                    "completion_tokens": "meta.output_tokens",
                },
            },
        ),
        ScriptedTransport(
            {
                "result": [{"text": '{"severity": "high"}'}],
                "meta": {"input_tokens": 7, "output_tokens": 2},
            }
        ),
    )
    call = provider.plan(request())
    assert call.url == "https://gateway.example/analyse"
    assert call.headers["Authorization"] == "Bearer gw-token"
    assert call.headers["X-Tenant"] == "acme"
    assert call.payload["instruction"] == "You are a triage analyst."
    assert call.payload["max_output_tokens"] == 321  # exact-reference keeps the type
    assert "[TARGET_DATA]" in str(call.payload["input"])

    import asyncio

    result = asyncio.run(provider.complete(request()))
    assert result.text == '{"severity": "high"}'
    assert result.usage is not None
    assert result.usage.total_tokens == 9


def test_custom_without_a_template_is_a_configuration_error() -> None:
    provider = build_provider(resolved("custom"), ScriptedTransport({}))
    with pytest.raises(ProviderError, match="request_template"):
        provider.plan(request())


def test_custom_without_a_response_path_is_refused() -> None:
    provider = build_provider(
        resolved("custom", extra={"request_template": {"m": "{{model}}"}}),
        ScriptedTransport({"result": "x"}),
    )
    import asyncio

    with pytest.raises(ProviderError, match="response_path"):
        asyncio.run(provider.complete(request()))


# --------------------------------------------------------------------------- transport


def test_the_transport_maps_every_status_to_a_typed_error() -> None:
    def client(
        status: int, body: str = "{}", headers: dict[str, str] | None = None
    ) -> HttpLlmTransport:
        async def handler(_request: httpx.Request) -> httpx.Response:
            return httpx.Response(status, text=body, headers=headers or {})

        scoped = ScopedHttpClient(
            settings=Settings.from_env({}),
            scope=Scope(allowed_hosts=("model.example",)),
            policy=UrlSafetyPolicy(),
            resolver=StaticResolver(("93.184.216.34",)),
            transport=httpx.MockTransport(handler),
        )
        return HttpLlmTransport(client=scoped, provider="test")

    import asyncio

    cases: list[tuple[int, dict[str, str] | None, type[Exception], str]] = [
        (429, {"retry-after": "9"}, ProviderRateLimitError, "rate-limited"),
        (401, None, ProviderAuthError, "credential"),
        (403, None, ProviderAuthError, "credential"),
        (500, None, ProviderUnavailableError, "HTTP 500"),
        (400, None, ProviderError, "HTTP 400"),
    ]
    for status, headers, expected, fragment in cases:
        transport = client(status, headers=headers)
        with pytest.raises(expected, match=fragment) as excinfo:
            asyncio.run(
                transport.post_json(
                    "https://model.example/v1/chat/completions", {"a": 1}, timeout_s=5
                )
            )
        if status == 429:
            assert excinfo.value.retry_after == 9.0  # type: ignore[attr-defined]
        if status == 400:
            assert excinfo.value.transient is False  # type: ignore[attr-defined]

    asyncio.run(client(429).aclose())


def test_a_successful_transport_call_returns_the_body() -> None:
    async def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200, text='{"ok": true}', headers={"content-type": "application/json"}
        )

    import asyncio

    scoped = ScopedHttpClient(
        settings=Settings.from_env({}),
        scope=Scope(allowed_hosts=("model.example",)),
        policy=UrlSafetyPolicy(),
        resolver=StaticResolver(("93.184.216.34",)),
        transport=httpx.MockTransport(handler),
    )
    transport = HttpLlmTransport(client=scoped, provider="test")
    response = asyncio.run(
        transport.post_json("https://model.example/v1/chat/completions", {"a": 1}, timeout_s=5)
    )
    assert response.status == 200
    assert response.json() == {"ok": True}
    asyncio.run(transport.aclose())


def test_an_out_of_scope_endpoint_is_refused_before_it_is_sent() -> None:
    scoped = ScopedHttpClient(
        settings=Settings.from_env({}),
        scope=Scope(allowed_hosts=("model.example",)),
        policy=UrlSafetyPolicy(),
        resolver=StaticResolver(("93.184.216.34",)),
        transport=httpx.MockTransport(lambda _r: httpx.Response(200, text="{}")),
    )
    transport = HttpLlmTransport(client=scoped, provider="test")
    import asyncio

    with pytest.raises(ProviderError, match="refused by the safety gate") as excinfo:
        asyncio.run(transport.post_json("https://elsewhere.example/v1", {}))
    assert excinfo.value.transient is False


# --------------------------------------------------------------------------- scoping


@pytest.mark.parametrize(
    "url, local",
    [
        ("http://localhost:11434", True),
        ("http://127.0.0.1:8000/v1", True),
        ("http://[::1]:11434", True),
        ("http://192.168.1.4:11434", True),
        ("http://box.local:8080", True),
        ("https://api.openai.com/v1", False),
        ("https://generativelanguage.googleapis.com", False),
        ("https://unresolvable-name.example/v1", False),
    ],
)
def test_local_endpoint_detection(url: str, local: bool) -> None:
    assert is_local_endpoint(url) is local


def test_provider_hosts_are_derived_from_the_base_urls() -> None:
    hosts = provider_hosts(
        {
            "openai_compatible": "https://api.openai.com/v1",
            "ollama": "http://localhost:11434",
            "dup": "https://api.openai.com/v1/other",
        }
    )
    assert hosts == ("api.openai.com", "localhost")


def test_the_ai_client_scope_is_exactly_the_provider_hosts() -> None:
    client = build_llm_client(
        base_urls={"a": "https://api.example.com/v1", "b": "http://localhost:11434"},
        settings=Settings.from_env({}),
    )
    assert client.scope.allowed_hosts == ("api.example.com", "localhost")
    # A local provider declaration is what allows loopback; nothing else widens it.
    assert client.policy.allow_loopback is True
    assert client.policy.allow_private_ips is True


def test_a_remote_only_configuration_keeps_loopback_closed() -> None:
    client = build_llm_client(
        base_urls={"a": "https://api.example.com/v1"}, settings=Settings.from_env({})
    )
    assert client.policy.allow_loopback is False
    assert client.policy.allow_private_ips is False


def test_an_empty_provider_set_yields_a_deny_all_scope() -> None:
    client = build_llm_client(base_urls={}, settings=Settings.from_env({}))
    assert client.scope.is_empty


# --------------------------------------------------------------------------- vcr cassette


def test_the_openai_adapter_replays_a_recorded_exchange(cassette_dir: Path = CASSETTE_DIR) -> None:
    """A recorded HTTP exchange (vcrpy), replayed through the real scoped client.

    The recorded URI is normalised to ``https://model.example`` so the cassette is portable;
    DNS is stubbed because vcrpy intercepts the transport, and the safety pipeline (scheme,
    scope, policy) still runs — that is the point of recording at this layer.
    """
    import asyncio

    cassette = cassette_dir / "openai-compatible-triage.yaml"
    assert cassette.is_file(), f"missing recorded cassette {cassette}"

    async def run() -> object:
        scoped = ScopedHttpClient(
            settings=Settings.from_env({}),
            scope=Scope(allowed_hosts=("model.example",)),
            policy=UrlSafetyPolicy(),
            resolver=StaticResolver(("93.184.216.34",)),
        )
        transport = HttpLlmTransport(client=scoped, provider="openai_compatible")
        provider = build_provider(
            resolved(
                "openai_compatible",
                base_url="https://model.example/v1",
                api_key=_secret("sk-cassette"),
            ),
            transport,
        )
        try:
            with vcr.use_cassette(str(cassette), record_mode="none"):
                return await provider.complete(triage_request())
        finally:
            await transport.aclose()

    result = asyncio.run(run())
    payload = json.loads(result.text)
    assert payload["severity"] == "critical"
    assert payload["confidence"] == 92
    assert payload["fp_likely"] is False
    assert result.usage is not None
    assert result.usage.total_tokens == 160
    assert result.mechanism == "json_schema"


# --------------------------------------------------------------------------- helpers


def test_usage_extraction_handles_both_key_spellings() -> None:
    openai = usage_of({"usage": {"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3}})
    assert openai is not None
    assert openai.total_tokens == 3
    google = usage_of({"usageMetadata": {"promptTokenCount": 4, "candidatesTokenCount": 5}})
    assert google is not None
    assert google.prompt_tokens == 4
    assert usage_of({}) is None


def test_value_at_reads_dotted_paths() -> None:
    data = {"a": {"b": [{"c": "found"}]}}
    assert value_at(data, "a.b.0.c") == "found"
    assert value_at(data, "a.b.9.c") is None
    assert value_at(data, "missing.path") is None


def test_a_provider_call_without_a_schema_still_works() -> None:
    call = ProviderCall(url="u", payload={}, headers={}, mechanism="text")
    assert call.mechanism == "text"


def _secret(value: str) -> object:
    from pydantic import SecretStr

    return SecretStr(value)
