"""One stage call, with every policy -§7 attaches to it.

:class:`StageRunner` is the only place a model is called. It sequences the things that must
happen around a call, in order, and it never raises: a failed stage returns an outcome whose
``fallback`` names the reason, which is what lets the engine degrade one candidate while the
rest of the scan keeps its AI analysis .

The order is deliberate:

1. **render** the prompt from data (``ai.prompts``), with target content delimited, escaped and
   truncated and the mandatory injection instruction in the system prompt;
2. **apply the privacy mode** to the payloads (``ai.privacy``) — before the prompt exists, so
   the un-tokenized text is never assembled;
3. **look in the cache** (``ai.cache``), keyed on stage + template version + model + prompt;
4. **refuse a prompt containing a provider credential** (``assert_no_provider_secrets``);
5. **estimate and check the budget** (``ai.budget``), so the cap is enforced before the spend;
6. **call** through the retrying, rate-limited provider (``ai.reliability``);
7. **validate** against the stage's pydantic schema (``ai.structured``), with the single
   repair retry the budget allows;
8. **record** usage, latency and outcome on the ledger, the metrics and the audit trail.
"""

from __future__ import annotations

import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from pydantic import SecretStr

from arachne.ai.budget import BudgetLedger, Metrics, estimate_prompt_tokens
from arachne.ai.cache import RequestCache, cache_key
from arachne.ai.privacy import Redactor, assert_no_provider_secrets
from arachne.ai.prompts import PromptStore
from arachne.ai.reliability import RetryingProvider
from arachne.ai.stages import StageInput, schema_for
from arachne.ai.structured import parse_structured, repair_prompt
from arachne.ai.types import (
    AiError,
    CompletionRequest,
    PrivacyError,
    ProviderError,
    ResponseFormat,
    StructuredOutputError,
)
from arachne.core.audit import AuditAction, Auditor, AuditOutcome
from arachne.core.errors import BudgetExhaustedError
from arachne.core.logging import get_logger

__all__ = [
    "FALLBACK_BUDGET",
    "FALLBACK_INTERNAL",
    "FALLBACK_PRIVACY",
    "FALLBACK_PROVIDER",
    "FALLBACK_STRUCTURED",
    "StageOutcome",
    "StageRunner",
]

_logger = get_logger("ai.runner")

#: Fallback reason codes recorded in provenance (a closed vocabulary, like the audit actions).
FALLBACK_PROVIDER = "provider_error"
FALLBACK_BUDGET = "budget_exhausted"
FALLBACK_STRUCTURED = "structured_output_failed"
FALLBACK_PRIVACY = "privacy_refusal"
FALLBACK_INTERNAL = "internal_error"


@dataclass(frozen=True, slots=True)
class StageOutcome:
    """What one stage produced, and what it cost — success or fallback."""

    stage: str
    ok: bool
    value: Mapping[str, Any] = field(default_factory=dict)
    template_id: str = ""
    template_version: str = ""
    prompt_hash: str = ""
    schema: str = ""
    mechanism: str = ""
    cached: bool = False
    attempts: int = 0
    latency_ms: float = 0.0
    model: str = ""
    #: Tokens attributed to *this stage's* contribution (REQ-AGENT-008). The ledger answers
    #: "what has the scan spent"; these answer "what did this finding cost", summed across the
    #: candidate's stages and carried onto its analysis row. A cache hit is zero by definition.
    prompt_tokens: int = 0
    completion_tokens: int = 0
    fallback: str | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "stage": self.stage,
            "ok": self.ok,
            "cached": self.cached,
            "attempts": self.attempts,
            "latency_ms": round(self.latency_ms, 3),
            "model": self.model,
            "mechanism": self.mechanism,
            "template_id": self.template_id,
            "template_version": self.template_version,
            "prompt_hash": self.prompt_hash,
            "schema": self.schema,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "fallback": self.fallback,
            "error": self.error,
        }


@dataclass
class StageRunner:
    """Runs one stage per call, under the policies of -§7."""

    provider: RetryingProvider
    prompts: PromptStore
    ledger: BudgetLedger
    metrics: Metrics
    cache: RequestCache | None = None
    redactor: Redactor | None = None
    secrets: tuple[SecretStr | None, ...] = ()
    auditor: Auditor | None = None
    provider_name: str = ""
    temperature: float = 0.0
    max_tokens: int = 2000
    timeout_s: float = 60.0
    constrained_decoding: bool = False
    #: One repair attempt when validation fails .
    allow_repair: bool = True

    async def run(
        self,
        stage: str,
        stage_input: StageInput,
        *,
        model: str | None = None,
    ) -> StageOutcome:
        """Render, guard, call, validate and record one stage (never raises)."""
        spec = schema_for(stage)
        effective_model = model or self.provider.model
        payload = (
            stage_input.with_privacy(self.redactor.transform)
            if self.redactor is not None
            else stage_input
        )
        rendered = self.prompts.render(
            stage,
            context_lines=payload.context_lines,
            target_data=payload.target_data,
            model=effective_model,
            values=payload.values,
        )
        key = cache_key(
            stage=stage,
            template_version=rendered.template_version,
            model=effective_model,
            prompt=f"{rendered.system}\n{rendered.user}",
        )
        if self.cache is not None:
            cached = self.cache.get(key)
            if cached is not None:
                self.ledger.record(
                    _zero_usage(),
                    stage=stage,
                    provider=self.provider_name,
                    model=effective_model,
                    cached=True,
                )
                self.metrics.inc(
                    "arachne_ai_cache_hits_total", {"stage": stage, "provider": self.provider_name}
                )
                self._audit(
                    stage,
                    outcome="cached",
                    meta={"cached": True, "prompt_hash": rendered.prompt_hash},
                )
                return StageOutcome(
                    stage=stage,
                    ok=True,
                    value=cached,
                    template_id=rendered.template_id,
                    template_version=rendered.template_version,
                    prompt_hash=rendered.prompt_hash,
                    schema=spec.name,
                    mechanism="cache",
                    cached=True,
                    model=effective_model,
                )

        request = self._request(rendered, spec.json_schema, effective_model)
        started = time.monotonic()
        try:
            assert_no_provider_secrets(f"{rendered.system}\n{rendered.user}", self.secrets)
            self.ledger.check(
                self.ledger.estimate(
                    effective_model,
                    prompt_tokens=estimate_prompt_tokens(rendered.system, rendered.user),
                    max_tokens=request.max_tokens,
                ),
                stage=stage,
                model=effective_model,
            )
            result = await self.provider.complete(request)
            value = parse_structured(result.text, spec)
            mechanism = result.mechanism
            attempts = 1
        except StructuredOutputError as exc:
            if not self.allow_repair:
                return self._failure(stage, FALLBACK_STRUCTURED, exc, rendered, spec.name)
            repaired = await self._repair(request, exc, spec, rendered)
            if repaired is None:
                return self._failure(stage, FALLBACK_STRUCTURED, exc, rendered, spec.name)
            value, result, mechanism = repaired
            attempts = 2
        except BudgetExhaustedError as exc:
            self.ledger.note_degraded()
            self._audit(
                stage,
                outcome="budget",
                meta={"reason": str(exc), "prompt_hash": rendered.prompt_hash},
                action=AuditAction.BUDGET_EXHAUSTED,
                outcome_kind=AuditOutcome.BLOCKED,
            )
            return self._failure(stage, FALLBACK_BUDGET, exc, rendered, spec.name)
        except PrivacyError as exc:
            return self._failure(stage, FALLBACK_PRIVACY, exc, rendered, spec.name)
        except ProviderError as exc:
            self.ledger.note_degraded()
            return self._failure(stage, FALLBACK_PROVIDER, exc, rendered, spec.name)
        except AiError as exc:
            return self._failure(stage, FALLBACK_INTERNAL, exc, rendered, spec.name)
        except Exception as exc:  # a stage failure must never fail a scan
            _logger.exception("ai stage raised", extra={"event": "ai.stage_error", "stage": stage})
            return self._failure(stage, FALLBACK_INTERNAL, exc, rendered, spec.name)

        latency_ms = (time.monotonic() - started) * 1000.0
        usage = result.usage
        self.ledger.record(
            usage if usage is not None else _zero_usage(),
            stage=stage,
            provider=self.provider_name,
            model=effective_model,
            cached=False,
        )
        if usage is not None:
            self.metrics.inc(
                "arachne_ai_tokens_total",
                {"provider": self.provider_name, "kind": "prompt"},
                float(usage.prompt_tokens),
            )
            self.metrics.inc(
                "arachne_ai_tokens_total",
                {"provider": self.provider_name, "kind": "completion"},
                float(usage.completion_tokens),
            )
            self.metrics.inc(
                "arachne_ai_cost_usd_total", {"provider": self.provider_name}, usage.cost_usd
            )
        self.metrics.inc(
            "arachne_ai_requests_total", {"provider": self.provider_name, "stage": stage}
        )
        self.metrics.observe(
            "arachne_ai_latency_seconds", latency_ms / 1000.0, {"provider": self.provider_name}
        )
        if self.cache is not None:
            self.cache.put(key, value)
        self._audit(
            stage,
            outcome="ok",
            meta={
                "cached": False,
                "mechanism": mechanism,
                "attempts": attempts,
                "prompt_hash": rendered.prompt_hash,
                "template_version": rendered.template_version,
                "tokens": usage.total_tokens if usage is not None else 0,
                "cost_usd": round(usage.cost_usd, 6) if usage is not None else 0.0,
                "latency_ms": round(latency_ms, 3),
            },
        )
        _logger.info(
            "ai stage completed",
            extra={
                "event": "ai.stage",
                "stage": stage,
                "provider": self.provider_name,
                "model": effective_model,
                "mechanism": mechanism,
                "tokens": usage.total_tokens if usage is not None else 0,
            },
        )
        return StageOutcome(
            stage=stage,
            ok=True,
            value=value,
            template_id=rendered.template_id,
            template_version=rendered.template_version,
            prompt_hash=rendered.prompt_hash,
            schema=spec.name,
            mechanism=mechanism,
            attempts=attempts,
            latency_ms=latency_ms,
            model=effective_model,
            prompt_tokens=usage.prompt_tokens if usage is not None else 0,
            completion_tokens=usage.completion_tokens if usage is not None else 0,
        )

    # ------------------------------------------------------------------ internals
    def _request(
        self, rendered: Any, json_schema: Mapping[str, Any], model: str
    ) -> CompletionRequest:
        wanted = (
            ResponseFormat.TEXT
            if rendered.response_format is ResponseFormat.TEXT
            else ResponseFormat.JSON_SCHEMA
        )
        return CompletionRequest(
            model=model,
            system=rendered.system,
            messages=({"role": "user", "content": rendered.user},),
            response_format=wanted,
            json_schema=json_schema if wanted is not ResponseFormat.TEXT else None,
            max_tokens=self.max_tokens,
            temperature=self.temperature,
            timeout_s=self.timeout_s,
            constrained_decoding=self.constrained_decoding,
        )

    async def _repair(
        self,
        request: CompletionRequest,
        error: StructuredOutputError,
        spec: Any,
        rendered: Any,
    ) -> tuple[dict[str, Any], Any, str] | None:
        """The single repair attempt permitted by the budget."""
        repair = CompletionRequest(
            model=request.model,
            system=request.system,
            messages=(
                *request.messages,
                {"role": "user", "content": repair_prompt(str(error), spec)},
            ),
            response_format=request.response_format,
            json_schema=request.json_schema,
            max_tokens=request.max_tokens,
            temperature=request.temperature,
            timeout_s=request.timeout_s,
            constrained_decoding=request.constrained_decoding,
        )
        try:
            self.ledger.check(
                self.ledger.estimate(
                    request.model,
                    prompt_tokens=estimate_prompt_tokens(request.system, rendered.user),
                    max_tokens=request.max_tokens,
                ),
                stage=f"{spec.name}:repair",
                model=request.model,
            )
            result = await self.provider.complete(repair)
            value = parse_structured(result.text, spec)
        except (BudgetExhaustedError, ProviderError, StructuredOutputError) as exc:
            _logger.info(
                "ai repair attempt failed",
                extra={"event": "ai.repair_failed", "stage": spec.name, "error": str(exc)},
            )
            return None
        usage = result.usage
        self.ledger.record(
            usage if usage is not None else _zero_usage(),
            stage=f"{spec.name}:repair",
            provider=self.provider_name,
            model=request.model,
            cached=False,
        )
        return value, result, f"{result.mechanism}+repair"

    def _failure(
        self,
        stage: str,
        reason: str,
        exc: Exception,
        rendered: Any,
        schema_name: str,
    ) -> StageOutcome:
        message = f"{exc.__class__.__name__}: {exc}"
        _logger.warning(
            "ai stage degraded to heuristic",
            extra={
                "event": "ai.degraded",
                "stage": stage,
                "reason": reason,
                "detail": message[:300],
            },
        )
        self._audit(
            stage,
            outcome=reason,
            meta={"reason": message[:300], "prompt_hash": rendered.prompt_hash},
            action=AuditAction.AI_DEGRADED,
            outcome_kind=AuditOutcome.ERROR,
        )
        return StageOutcome(
            stage=stage,
            ok=False,
            template_id=rendered.template_id,
            template_version=rendered.template_version,
            prompt_hash=rendered.prompt_hash,
            schema=schema_name,
            fallback=reason,
            error=message[:500],
            model=self.provider.model,
        )

    def _audit(
        self,
        stage: str,
        *,
        outcome: str,
        meta: Mapping[str, Any],
        action: AuditAction = AuditAction.AI_REQUEST,
        outcome_kind: AuditOutcome = AuditOutcome.ALLOWED,
    ) -> None:
        if self.auditor is None:
            return
        self.auditor.record(
            action,
            outcome=outcome_kind,
            target=f"ai:{stage}",
            reason=outcome if outcome_kind is not AuditOutcome.ALLOWED else None,
            meta={
                "stage": stage,
                "provider": self.provider_name,
                "model": self.provider.model,
                "outcome": outcome,
                **dict(meta),
            },
        )


def _zero_usage() -> Any:
    from arachne.ai.types import Usage

    return Usage()
