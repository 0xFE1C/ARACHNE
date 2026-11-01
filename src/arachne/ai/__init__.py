"""The AI integration layer (docs/spec/03-, F-04-*): optional, explicit and swappable.

The layer is built so that every capability it adds has a heuristic counterpart already
(``docs/spec/04-``), and so that a scan's *result* never depends on a model being reachable:

============================  ==================================================
``ai.types``                  the provider-neutral request/result vocabulary
``ai.config``                 the docs/spec/03- §3 provider file, credentials from env
``ai.transport``              the scope-bound HTTP path (ADR-05's second client)
``ai.providers``              seven adapters, one module per API shape
``ai.structured``             four mechanisms → one pydantic validator (docs/spec/03- §6)
``ai.prompts``                versioned templates + the untrusted-data policy (§5)
``ai.privacy``                ``local-only`` / ``redact`` / ``default`` (§8)
``ai.budget``                 per-scan token and cost caps, and Prometheus counters (§7)
``ai.cache``                  identical requests hit the cache (§7)
``ai.reliability``            retries, backoff, pacing, circuit breaker (§7)
``ai.stages``                 triage / correlate / remediate / narrative / explain / prioritize (§4)
``ai.runner``                 one stage call with every policy around it
``ai.engine``                 ``AiEngine`` — the ``Analyzer`` that anchors on the heuristic result
============================  ==================================================

Typical use::

    from arachne.ai import build_ai_engine

    engine = build_ai_engine(settings)          # None when no provider is configured
    analyses = await engine.analyze_async(candidates, context)
"""

from __future__ import annotations

from typing import Any

from arachne.ai.budget import BudgetLedger, Metrics, PriceTable, load_price_table
from arachne.ai.cache import RequestCache, cache_key
from arachne.ai.config import (
    ADAPTERS,
    AiConfig,
    ProviderConfig,
    ResolvedProvider,
    load_ai_config,
    parse_ai_config,
)
from arachne.ai.engine import AiEngine, AiPolicies, CompoundSuggestion, build_ai_engine
from arachne.ai.privacy import PrivacyMode, Redactor, TokenMapper, apply_privacy
from arachne.ai.prompts import (
    INJECTION_INSTRUCTION,
    PromptStore,
    RenderedPrompt,
    load_prompt_store,
    wrap_target_data,
)
from arachne.ai.reliability import RetryingProvider, RetryPolicy
from arachne.ai.runner import StageOutcome, StageRunner
from arachne.ai.stages import CANDIDATE_STAGES, SCHEMAS, STAGES, StageInput
from arachne.ai.structured import SchemaSpec, parse_structured
from arachne.ai.transport import build_llm_client, build_llm_transport, provider_hosts
from arachne.ai.types import (
    AiError,
    CompletionRequest,
    CompletionResult,
    LLMProvider,
    LlmTransport,
    PrivacyError,
    ProviderAuthError,
    ProviderError,
    ProviderRateLimitError,
    ProviderTimeoutError,
    ProviderUnavailableError,
    ResponseFormat,
    StructuredOutputError,
    TransportResponse,
    Usage,
)

__all__ = [
    "ADAPTERS",
    "CANDIDATE_STAGES",
    "INJECTION_INSTRUCTION",
    "SCHEMAS",
    "STAGES",
    "AiConfig",
    "AiEngine",
    "AiError",
    "AiPolicies",
    "BudgetLedger",
    "CompletionRequest",
    "CompletionResult",
    "CompoundSuggestion",
    "LLMProvider",
    "LlmTransport",
    "Metrics",
    "PriceTable",
    "PrivacyError",
    "PrivacyMode",
    "PromptStore",
    "ProviderAuthError",
    "ProviderConfig",
    "ProviderError",
    "ProviderRateLimitError",
    "ProviderTimeoutError",
    "ProviderUnavailableError",
    "Redactor",
    "RenderedPrompt",
    "RequestCache",
    "ResolvedProvider",
    "ResponseFormat",
    "RetryPolicy",
    "RetryingProvider",
    "SchemaSpec",
    "StageInput",
    "StageOutcome",
    "StageRunner",
    "StructuredOutputError",
    "TokenMapper",
    "TransportResponse",
    "Usage",
    "apply_privacy",
    "build_ai_engine",
    "build_llm_client",
    "build_llm_transport",
    "cache_key",
    "load_ai_config",
    "load_price_table",
    "load_prompt_store",
    "parse_ai_config",
    "parse_structured",
    "provider_hosts",
    "wrap_target_data",
]


def __getattr__(name: str) -> Any:  # pragma: no cover - reserved for future lazy exports
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
