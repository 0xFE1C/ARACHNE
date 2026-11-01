"""Optional live check against a local Ollama (the fully local path of docs/spec/03- §3).

The suite never depends on a model being installed: without one this module skips with the
reason, which is the honest form of "test it if it is there". With Ollama running it exercises
the one thing a fixture cannot — that a real local model's answer survives our structured-output
contract — and it exercises the local ``format`` schema path, not the OpenAI-compatible one.

Run it explicitly with::

    ARACHNE_LIVE_OLLAMA=1 pytest tests/integration/test_ai_live_local.py -q -s

``ARACHNE_LIVE_OLLAMA_MODEL`` picks the model (default: the first one Ollama reports).
"""

from __future__ import annotations

import json
import os
import socket
from urllib.parse import urlsplit

import pytest
from tests.helpers.ai import env_candidate

from arachne.ai.config import ResolvedProvider
from arachne.ai.prompts import load_prompt_store
from arachne.ai.providers.registry import build_provider
from arachne.ai.stages import SCHEMAS, build_triage_input
from arachne.ai.structured import parse_structured
from arachne.ai.transport import HttpLlmTransport, build_llm_client
from arachne.ai.types import CompletionRequest, ResponseFormat
from arachne.core.config import Settings
from arachne.core.safety import Scope, UrlSafetyPolicy

OLLAMA_BASE = os.environ.get("ARACHNE_LIVE_OLLAMA_BASE_URL", "http://localhost:11434")


def _running(url: str) -> bool:
    parts = urlsplit(url)
    if parts.hostname is None or parts.port is None:
        return False
    try:
        with socket.create_connection((parts.hostname, parts.port), timeout=0.5):
            return True
    except OSError:
        return False


def _first_model(url: str) -> str:
    import asyncio

    async def fetch() -> str:
        client = build_llm_client(
            base_urls={"ollama": url},
            settings=Settings.from_env({}),
            scope=Scope(allowed_hosts=("localhost",)),
            policy=UrlSafetyPolicy(allow_loopback=True, allow_private_ips=True),
        )
        try:
            exchange = await client.get(f"{url.rstrip('/')}/api/tags")
        finally:
            await client.aclose()
        parsed = exchange.json_body() or {}
        models = [item.get("name") for item in parsed.get("models", []) if item.get("name")]
        return str(models[0]) if models else ""

    return asyncio.run(fetch())


pytestmark = [
    pytest.mark.lab,
    pytest.mark.skipif(
        os.environ.get("ARACHNE_LIVE_OLLAMA") != "1",
        reason="set ARACHNE_LIVE_OLLAMA=1 to run against a local Ollama",
    ),
    pytest.mark.skipif(
        not _running(OLLAMA_BASE),
        reason=f"no Ollama listening on {OLLAMA_BASE}",
    ),
]


async def test_a_local_model_answers_the_triage_stage_with_valid_structured_output() -> None:
    model = os.environ.get("ARACHNE_LIVE_OLLAMA_MODEL") or _first_model(OLLAMA_BASE)
    if not model:
        pytest.skip("Ollama is running but has no model installed")

    client = build_llm_client(
        base_urls={"ollama": OLLAMA_BASE},
        settings=Settings.from_env({}),
        scope=Scope(allowed_hosts=("localhost",)),
        policy=UrlSafetyPolicy(allow_loopback=True, allow_private_ips=True),
    )
    transport = HttpLlmTransport(client=client, provider="ollama")
    provider = build_provider(
        ResolvedProvider(
            name="ollama",
            base_url=OLLAMA_BASE,
            model=model,
            timeout_s=120.0,
            max_tokens=512,
            temperature=0.0,
        ),
        transport,
    )

    candidate = env_candidate()
    anchor = None
    stage_input = build_triage_input(candidate, anchor)
    rendered = load_prompt_store().render(
        "triage",
        context_lines=stage_input.context_lines,
        target_data=stage_input.target_data,
        model=model,
    )
    spec = SCHEMAS["triage"]
    request = CompletionRequest(
        model=model,
        system=rendered.system,
        messages=({"role": "user", "content": rendered.user},),
        response_format=ResponseFormat.JSON_SCHEMA,
        json_schema=spec.json_schema,
        max_tokens=512,
        temperature=0.0,
        timeout_s=120.0,
    )
    try:
        result = await provider.complete(request)
    finally:
        await transport.aclose()

    value = parse_structured(result.text, spec)
    allowed = SCHEMAS["triage"].json_schema["properties"]["severity"]["enum"]
    assert value["severity"] in allowed
    assert 0 <= value["confidence"] <= 100
    assert isinstance(value["fp_likely"], bool)
    assert result.usage is not None
    # Print rather than assert: the numbers are informational for a local model.
    print(json.dumps({"model": model, "answer": value, "usage": result.usage.to_dict()}))
