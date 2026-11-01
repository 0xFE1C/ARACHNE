"""The adapter registry: provider name → class (docs/spec/03- §3's table).

One table, so "supported providers" is answerable in one place and the configuration loader's
vocabulary (``ai.config.ADAPTERS``) cannot drift from what can actually be built. A test asserts
the two agree.
"""

from __future__ import annotations

from collections.abc import Mapping

from arachne.ai.config import ADAPTERS, ResolvedProvider
from arachne.ai.providers.anthropic import AnthropicProvider
from arachne.ai.providers.base import HttpProvider
from arachne.ai.providers.custom import CustomProvider
from arachne.ai.providers.gemini import GeminiProvider
from arachne.ai.providers.ollama import OllamaProvider
from arachne.ai.providers.openai import (
    MistralProvider,
    OpenAICompatibleProvider,
    OpenAIProvider,
)
from arachne.ai.types import LlmTransport
from arachne.core.errors import ConfigurationError

__all__ = ["PROVIDER_CLASSES", "build_provider", "provider_class"]

PROVIDER_CLASSES: dict[str, type[HttpProvider]] = {
    "openai": OpenAIProvider,
    "openai_compatible": OpenAICompatibleProvider,
    "anthropic": AnthropicProvider,
    "gemini": GeminiProvider,
    "ollama": OllamaProvider,
    "mistral": MistralProvider,
    "custom": CustomProvider,
}


def provider_class(name: str) -> type[HttpProvider]:
    """The adapter class for ``name`` (a configuration error when unknown)."""
    try:
        return PROVIDER_CLASSES[name]
    except KeyError as exc:
        raise ConfigurationError(
            f"unknown AI provider {name!r}; supported: {list(ADAPTERS)}"
        ) from exc


def build_provider(
    config: ResolvedProvider,
    transport: LlmTransport,
    *,
    name: str | None = None,
) -> HttpProvider:
    """Instantiate the adapter ``config`` describes, bound to ``transport``."""
    adapter = name or config.name
    return provider_class(adapter)(config, transport)


def describe() -> Mapping[str, str]:
    """``{provider: class}`` for a plan or a log line."""
    return {name: cls.__name__ for name, cls in PROVIDER_CLASSES.items()}
