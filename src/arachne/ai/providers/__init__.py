"""Provider adapters: the provider table, one module per API shape.

``base``      the plan → send → interpret seam every adapter fills in
``openai``    ``openai``, ``openai_compatible``, ``mistral`` (one format, three names)
``anthropic`` ``x-api-key`` + tool-use for structured output
``gemini``    ``generateContent`` + ``responseMimeType``/``responseSchema``
``ollama``    the native ``/api/chat`` API + ``format`` grammars (the fully local path)
``custom``    a configuration-defined request template and response path

Construct via :func:`arachne.ai.providers.registry.build_provider`; nothing else in ARACHNE
imports an adapter directly.
"""

from __future__ import annotations

from arachne.ai.providers.base import HttpProvider, ProviderCall
from arachne.ai.providers.registry import PROVIDER_CLASSES, build_provider, provider_class

__all__ = [
    "PROVIDER_CLASSES",
    "HttpProvider",
    "ProviderCall",
    "build_provider",
    "provider_class",
]
