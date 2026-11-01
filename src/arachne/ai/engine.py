"""``AiEngine``: the AI analyzer, anchored to the deterministic verdict (F-03-01/04/05).

The engine implements the same ``Analyzer`` protocol as :class:`~arachne.analyzer.engine.
HeuristicEngine` — ``analyze_async(candidates, context) -> tuple[Analysis, ...]`` — and its
design is best stated as one sentence: **the heuristic verdict is the anchor, and the AI
annotates it.**

Why anchor at all? Because docs/spec/04- §5 (G-05) requires the finding set — and, for
deterministic checks, the verdict — to be identical in both engines, so that a report "cannot
tell which engine produced a finding except via the ``provenance`` field". Anchoring makes that
a structural property instead of a coincidence: the AI engine runs the heuristic engine first and
only *enriches* what it produced (narrative, remediation when the catalog has no entry, the
reasoning, the explanation, a prioritisation). An AI assessment that disagrees is **recorded**,
in ``risk_notes`` and in the analysis payload, and it is adopted only for checks a deployment
has explicitly declared authoritative (``ARACHNE_AI_AUTHORITATIVE_CHECKS``) — the M5/M6 and
novel-combination cases docs/spec/04- §4 says AI is for.

The degradation chain of docs/spec/03- §7 is implemented by *not* special-casing it: every
stage returns an outcome (``ai.runner``), a failed stage leaves its part of the analysis at the
heuristic value, and an analysis with no successful stage is marked
``engine="heuristic"`` + ``provenance.fallback="heuristic_fallback:<reason>"``. A scan therefore
never loses a finding because a provider died, which is DONE criterion 3.
"""

from __future__ import annotations

import asyncio
import hashlib
from collections.abc import AsyncIterator, Callable, Mapping, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass, field, replace
from typing import Any

from arachne.ai.budget import BudgetLedger, Metrics, load_price_table
from arachne.ai.cache import RequestCache
from arachne.ai.config import AiConfig, ResolvedProvider, load_ai_config
from arachne.ai.privacy import Redactor, enforce_local_only
from arachne.ai.prompts import PromptStore, load_prompt_store
from arachne.ai.providers.registry import build_provider
from arachne.ai.reliability import RetryingProvider, RetryPolicy
from arachne.ai.runner import StageOutcome, StageRunner
from arachne.ai.stages import (
    CANDIDATE_STAGES,
    StageInput,
    build_correlate_input,
    build_explain_input,
    build_narrative_input,
    build_prioritize_input,
    build_remediate_input,
    build_triage_input,
)
from arachne.ai.transport import build_llm_transport
from arachne.ai.types import (
    AiError,
    LLMProvider,
    LlmTransport,
)
from arachne.analyzer.engine import Analyzer, HeuristicEngine
from arachne.analyzer.model import (
    Analysis,
    Candidate,
    Provenance,
    Remediation,
    ScanContext,
    clamp_confidence,
)
from arachne.core.audit import Auditor
from arachne.core.config import Settings
from arachne.core.logging import get_logger
from arachne.core.ratelimit import TokenBucket

__all__ = [
    "AiEngine",
    "AiPolicies",
    "CompoundSuggestion",
    "build_ai_engine",
    "engine_description",
]

_logger = get_logger("ai.engine")

#: Remediation sources that outrank a model's proposal (docs/spec/06- §6, ADR-130).
#:
#: A *specific* catalog entry (by rule reference or check/CWE) is authoritative. The generic
#: ``catalog-default`` is the catalog saying "nothing matched", which is exactly the case
#: docs/spec/06- §6 lets an AI proposal fill — and then only as ``source="ai-suggested"``.
_AUTHORITATIVE_REMEDIATION = frozenset({"catalog", "rule-ref+catalog"})

#: Stages skipped first when the budget is nearly spent (docs/spec/03- §7).
_EXPENSIVE_STAGES = frozenset({"explain", "remediate", "narrative", "correlate", "prioritize"})

#: The builder for each per-candidate stage.
_BUILDERS: dict[str, Callable[[Candidate, Analysis | None], StageInput]] = {
    "triage": build_triage_input,
    "explain": build_explain_input,
    "remediate": build_remediate_input,
    "narrative": build_narrative_input,
}


@dataclass(frozen=True, slots=True)
class AiPolicies:
    """The deployment's AI behaviour, resolved from configuration."""

    stages: tuple[str, ...] = CANDIDATE_STAGES
    #: Check ids/modules whose AI verdict replaces the deterministic one (empty by default).
    authoritative_checks: tuple[str, ...] = ()
    correlate_threshold: int = 3
    max_narrative_chars: int = 4000
    #: Below this confidence an AI-adopted verdict is still reported as a low-confidence
    #: observation by the report layer; the engine does not need it, but a caller may.
    minimum_confidence: int = 55

    def policy_for(self, candidate: Candidate) -> str:
        """``"ai"`` or ``"preserve"`` for one candidate (docs/spec/04- §5's parity rule)."""
        identifiers = {
            candidate.check_id or "",
            candidate.check_module or "",
            candidate.check_name or "",
        }
        for entry in self.authoritative_checks:
            if entry in identifiers:
                return "ai"
            if candidate.check_id and candidate.check_id.startswith(f"{entry}."):
                return "ai"
        return "preserve"


@dataclass(frozen=True, slots=True)
class CompoundSuggestion:
    """An AI-written compound finding description (the ``correlate`` stage's output)."""

    title: str
    reasoning: str
    shared_root_cause: str = ""
    severity: str | None = None
    provenance: Mapping[str, Any] = field(default_factory=dict)


class AiEngine:
    """The AI analyzer: heuristic anchor + model-annotated ``Analysis`` objects."""

    name = "ai"

    def __init__(
        self,
        *,
        heuristic: Analyzer,
        config: AiConfig,
        resolved: ResolvedProvider,
        prompts: PromptStore,
        ledger: BudgetLedger,
        metrics: Metrics | None = None,
        provider_factory: Callable[[LlmTransport], LLMProvider] | None = None,
        transport: LlmTransport | None = None,
        transport_factory: Callable[[], LlmTransport] | None = None,
        cache: RequestCache | None = None,
        redactor: Redactor | None = None,
        auditor: Auditor | None = None,
        policies: AiPolicies | None = None,
        retry_policy: RetryPolicy | None = None,
        limiter: TokenBucket | None = None,
    ) -> None:
        if transport is None and transport_factory is None:
            msg = "AiEngine needs a transport or a transport factory"
            raise AiError(msg)
        self.heuristic = heuristic
        self.config = config
        self.resolved = resolved
        self.prompts = prompts
        self.ledger = ledger
        self.metrics = metrics or Metrics()
        self.cache = cache
        self.redactor = redactor or Redactor(mode=config.privacy)
        self.auditor = auditor
        self.policies = policies or AiPolicies(
            stages=tuple(config.stages),
            authoritative_checks=tuple(config.authoritative_checks),
            correlate_threshold=config.correlate_threshold,
        )
        self.retry_policy = retry_policy or RetryPolicy(attempts=config.retries)
        self.limiter = limiter or TokenBucket(resolved.requests_per_second, 1)
        self._provider_factory: Callable[[LlmTransport], LLMProvider] = provider_factory or (
            lambda transport: build_provider(resolved, transport)
        )
        self._transport = transport
        self._transport_factory = transport_factory
        self.last_provider_snapshot: Mapping[str, object] = {}

    # ------------------------------------------------------------------ interface
    @property
    def provider_name(self) -> str:
        return self.resolved.name

    @property
    def model(self) -> str:
        return self.resolved.model

    def analyze(
        self, candidates: Sequence[Candidate], context: ScanContext
    ) -> tuple[Analysis, ...]:
        """Synchronous ``Analyzer`` conformance (tests, the CLI); prefers ``analyze_async``.

        Inside a running event loop this refuses loudly rather than deadlocking or silently
        dropping the AI half: the step handler awaits :meth:`analyze_async`, and a caller that
        cannot await should pass ``engine="heuristic"``.
        """
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(self.analyze_async(candidates, context))
        msg = (
            "AiEngine.analyze() cannot run inside an event loop; await "
            "AiEngine.analyze_async() instead"
        )
        raise AiError(msg)

    async def analyze_async(
        self, candidates: Sequence[Candidate], context: ScanContext
    ) -> tuple[Analysis, ...]:
        """Analyse every candidate, AI-annotated, in input order (deterministic ordering)."""
        anchor = self.heuristic.analyze(candidates, context)
        if not candidates:
            return anchor
        results: list[Analysis] = []
        async with self._session() as runner:
            for candidate, baseline in zip(candidates, anchor, strict=True):
                results.append(await self._annotate(candidate, baseline, runner))
        return tuple(results)

    # ------------------------------------------------------------------ batch stages
    async def suggest_compound(
        self,
        *,
        host: str,
        members: Sequence[tuple[str, str, str]],
        trigger: str,
    ) -> CompoundSuggestion | None:
        """Ask the model to describe a correlation group (docs/spec/03- §4 ``correlate``).

        The *existence* of the compound is still the correlation engine's decision; this only
        supplies a better title/reasoning for a group it already found, so the finding set is
        unaffected (docs/spec/04- §5).
        """
        if len(members) < max(2, self.policies.correlate_threshold):
            return None
        if self.ledger.low_water:
            return None
        try:
            async with self._session() as runner:
                outcome = await runner.run(
                    "correlate",
                    build_correlate_input(host=host, members=members, trigger=trigger),
                )
        except AiError as exc:  # a session cannot be opened: the scan continues without it
            _logger.info(
                "ai correlate unavailable",
                extra={"event": "ai.correlate_unavailable", "error": str(exc)},
            )
            return None
        if not outcome.ok:
            return None
        value = outcome.value
        return CompoundSuggestion(
            title=str(value.get("title") or "").strip()[:300],
            reasoning=str(value.get("reasoning") or "").strip()[:3000],
            shared_root_cause=str(value.get("shared_root_cause") or "").strip()[:300],
            severity=(str(value["severity"]) if value.get("severity") else None),
            provenance=outcome.to_dict(),
        )

    async def prioritize_async(self, analyses: Sequence[Analysis]) -> Mapping[str, Any] | None:
        """Ask the model for a fix order over the finding set (``prioritize``)."""
        analysed = [item for item in analyses if item.verdict == "analyzed"]
        if not analysed or self.ledger.low_water:
            return None
        try:
            async with self._session() as runner:
                outcome = await runner.run("prioritize", build_prioritize_input(analysed))
        except AiError:
            return None
        return dict(outcome.value) | {"_meta": outcome.to_dict()} if outcome.ok else None

    async def run_stage(self, stage: str, stage_input: StageInput) -> StageOutcome | None:
        """Run **one** stage through the provider, ledger, cache and retry chain (S21).

        This is the seam the agentic hypothesis engine uses: it wants the stage machinery
        (versioned prompt, schema, budget, circuit breaker) but not the per-candidate
        pipeline. ``None`` means "the stage was not attempted" — no budget left, or the
        provider could not be opened — and the caller degrades to the heuristic engine. A
        *failed* stage returns its :class:`StageOutcome` (``ok=False``) so the failure reason
        reaches the journal rather than being flattened into ``None``.
        """
        if self.ledger.low_water:
            return None
        try:
            async with self._session() as runner:
                return await runner.run(stage, stage_input)
        except AiError as exc:
            _logger.info(
                "ai stage unavailable",
                extra={"event": "ai.stage_unavailable", "stage": stage, "error": str(exc)},
            )
            return None

    # ------------------------------------------------------------------ internals
    @asynccontextmanager
    async def _session(self) -> AsyncIterator[StageRunner]:
        """Open the provider for one batch, closing the client only if this opened it."""
        transport = self._transport
        owns = False
        if transport is None:
            assert self._transport_factory is not None  # guarded by __init__
            transport = self._transport_factory()
            owns = True
        provider = RetryingProvider(
            provider=self._provider_factory(transport),
            policy=self.retry_policy,
            limiter=self.limiter,
        )
        runner = StageRunner(
            provider=provider,
            prompts=self.prompts,
            ledger=self.ledger,
            metrics=self.metrics,
            cache=self.cache,
            redactor=self.redactor,
            secrets=(self.resolved.api_key,),
            auditor=self.auditor,
            provider_name=self.resolved.name,
            temperature=self.resolved.temperature,
            max_tokens=self.resolved.max_tokens,
            timeout_s=self.resolved.timeout_s,
            constrained_decoding=self.resolved.constrained_decoding,
        )
        try:
            yield runner
        finally:
            self.last_provider_snapshot = provider.snapshot()
            if owns:
                await transport.aclose()

    async def _annotate(
        self, candidate: Candidate, anchor: Analysis, runner: StageRunner
    ) -> Analysis:
        """Run the candidate stages and merge their outputs into the anchor analysis."""
        outcomes: list[StageOutcome] = []
        skipped: list[str] = []
        for stage in self.policies.stages:
            builder = _BUILDERS.get(stage)
            if builder is None:
                continue
            if stage in _EXPENSIVE_STAGES and self.ledger.low_water:
                skipped.append(stage)
                continue
            outcomes.append(await runner.run(stage, builder(candidate, anchor)))
        return self._merge(candidate, anchor, outcomes, skipped=skipped)

    def _merge(
        self,
        candidate: Candidate,
        anchor: Analysis,
        outcomes: Sequence[StageOutcome],
        *,
        skipped: Sequence[str] = (),
    ) -> Analysis:
        policy = self.policies.policy_for(candidate)
        stages: dict[str, Any] = {}
        fallbacks: list[str] = []
        for outcome in outcomes:
            if outcome.ok:
                stages[outcome.stage] = dict(outcome.value) | {
                    "_meta": {
                        "cached": outcome.cached,
                        "mechanism": outcome.mechanism,
                        "prompt_hash": outcome.prompt_hash,
                        "template_version": outcome.template_version,
                        "schema": outcome.schema,
                        "model": outcome.model,
                    }
                }
            else:
                fallbacks.append(f"{outcome.stage}:{outcome.fallback}")

        severity = anchor.severity
        confidence = anchor.confidence
        verdict = anchor.verdict
        drop_reason = anchor.drop_reason
        notes = anchor.risk_notes
        deviation: str | None = None

        triage = stages.get("triage")
        if triage is not None:
            proposed_severity = str(triage.get("severity") or anchor.severity)
            proposed_confidence = clamp_confidence(float(triage.get("confidence") or 0))
            fp_likely = bool(triage.get("fp_likely"))
            reason = str(triage.get("reason") or "").strip()[:500]
            if policy == "ai":
                severity = proposed_severity
                confidence = proposed_confidence
                if fp_likely:
                    verdict = "dropped"
                    drop_reason = f"ai triage: {reason or 'the model judged this a false positive'}"
            elif (
                proposed_severity != anchor.severity
                or abs(proposed_confidence - anchor.confidence) >= 10
                or fp_likely
            ):
                deviation = (
                    f"AI triage proposed {proposed_severity} at confidence "
                    f"{proposed_confidence}{' (likely false positive)' if fp_likely else ''}"
                    f"{': ' + reason if reason else ''}"
                )
                notes = _compose(
                    notes,
                    deviation
                    + "; the deterministic verdict stands so the finding set and verdicts stay "
                    "reproducible (docs/spec/04- §5)",
                )

        remediation = anchor.remediation
        rem = stages.get("remediate")
        if rem is not None and anchor.remediation.source not in _AUTHORITATIVE_REMEDIATION:
            summary = str(rem.get("summary") or "").strip()
            steps = tuple(str(item).strip() for item in rem.get("steps") or () if str(item).strip())
            if summary or steps:
                remediation = Remediation(
                    id=f"ai-{_slug(candidate.cwe or candidate.check_id or 'finding')}",
                    summary=summary or anchor.remediation.summary,
                    steps=steps or anchor.remediation.steps,
                    verification=anchor.remediation.verification,
                    references=tuple(
                        str(item).strip()
                        for item in rem.get("references") or ()
                        if str(item).strip()
                    )
                    or anchor.remediation.references,
                    source="ai-suggested",
                )

        narrative = anchor.narrative
        narr = stages.get("narrative")
        if narr is not None:
            proposed = str(narr.get("narrative") or "").strip()
            if proposed:
                narrative = proposed[: self.policies.max_narrative_chars]
                stages["narrative"]["heuristic"] = anchor.narrative

        provenance = Provenance(
            engine="ai" if stages else "heuristic",
            rule_ids=anchor.provenance.rule_ids,
            template_version=self.prompts.version,
            model=self.model if stages else None,
            provider=self.provider_name if stages else None,
            prompt_template=",".join(sorted(stages)) or None,
            prompt_hash=_combined_prompt_hash(outcomes) if stages else None,
            fallback=_fallback_marker(stages, fallbacks),
        )
        return replace(
            anchor,
            severity=severity,
            confidence=confidence,
            verdict=verdict,
            drop_reason=drop_reason,
            narrative=narrative,
            remediation=remediation,
            risk_notes=notes,
            provenance=provenance,
            ai={
                "policy": policy,
                "privacy": self.redactor.mode.value,
                "stages": stages,
                "fallback": fallbacks,
                "skipped": list(skipped),
                "deviation": deviation,
            },
        )

    # ------------------------------------------------------------------ description
    def describe(self) -> dict[str, Any]:
        """The AI half of a plan/log line, with no credential in it."""
        return {
            "engine": self.name,
            "provider": self.resolved.name,
            "model": self.resolved.model,
            "privacy": self.redactor.mode.value,
            "stages": list(self.policies.stages),
            "authoritative_checks": list(self.policies.authoritative_checks),
            "prompt_corpus": self.prompts.version,
            "budget": self.ledger.snapshot(),
        }


def engine_description(engine: Any) -> dict[str, Any]:
    """``describe()`` for an AI engine, and a plain label for anything else."""
    describe = getattr(engine, "describe", None)
    if callable(describe):
        return dict(describe())
    return {"engine": getattr(engine, "name", "unknown")}


def _compose(*notes: str | None) -> str:
    return "; ".join(item for item in notes if item)


def _slug(value: str) -> str:
    import re

    return re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-") or "finding"


def _combined_prompt_hash(outcomes: Sequence[StageOutcome]) -> str | None:
    hashes = sorted(
        outcome.prompt_hash for outcome in outcomes if outcome.ok and outcome.prompt_hash
    )
    if not hashes:
        return None
    digest = hashlib.sha256()
    for item in hashes:
        digest.update(item.encode())
        digest.update(b"\x1f")
    return digest.hexdigest()


def _fallback_marker(stages: Mapping[str, Any], fallbacks: Sequence[str]) -> str | None:
    """The provenance marker of the degradation chain (docs/spec/03- §7).

    ``None`` when every configured stage succeeded; ``heuristic_fallback:<reason>`` when none
    did; ``partial:<stage>:<reason>`` when the analysis carries both AI and heuristic parts.
    """
    if not fallbacks:
        return None
    reasons = sorted({item.split(":", 1)[-1] for item in fallbacks})
    if not stages:
        return f"heuristic_fallback:{reasons[0]}"
    return "partial:" + ",".join(sorted(fallbacks))


# --------------------------------------------------------------------------- factory


def build_ai_engine(
    settings: Settings | None = None,
    *,
    heuristic: Analyzer | None = None,
    transport: LlmTransport | None = None,
    prompts: PromptStore | None = None,
    cache: RequestCache | None = None,
    auditor: Auditor | None = None,
    env: Mapping[str, str] | None = None,
) -> AiEngine | None:
    """Build the configured AI engine, or ``None`` when no provider is configured (F-03-03).

    ``None`` is the important return value: it is what keeps "no external network call happens
    unless an AI provider is configured for the scan" true by construction, and it is what makes
    ``select_engine("ai")`` fail with an actionable message instead of silently degrading.
    """
    effective_settings = settings
    config = load_ai_config(effective_settings, env=env)
    if not config.configured:
        return None
    env_map = env if env is not None else _environ()
    resolved = config.provider(None, env_map)
    enforce_local_only(config.privacy, [resolved.base_url])
    stages = tuple(ordering for ordering in config.stages)
    store = prompts or load_prompt_store(
        effective_settings.ai.prompts if effective_settings is not None else None,
        stages=stages,
    )
    ledger = BudgetLedger(
        max_tokens_per_scan=config.budget.max_tokens_per_scan,
        max_cost_usd=config.budget.max_cost_usd,
        prices=load_price_table(
            effective_settings.ai.pricing if effective_settings is not None else None
        ),
    )
    transport_factory = None
    if transport is None:
        base_urls = {name: block.base_url for name, block in config.providers.items()}
        transport_factory = lambda: build_llm_transport(  # noqa: E731 - a factory, not a value
            base_urls=base_urls,
            provider=resolved.name,
            settings=effective_settings,
            auditor=auditor,
        )
    cache_dir = effective_settings.ai.cache_dir if effective_settings is not None else None
    if cache is None and cache_dir:
        from pathlib import Path

        cache = RequestCache(path=str(Path(cache_dir).expanduser() / "analysis-cache.json"))
    policies = AiPolicies(
        stages=stages,
        authoritative_checks=tuple(config.authoritative_checks),
        correlate_threshold=config.correlate_threshold,
    )
    return AiEngine(
        heuristic=heuristic or HeuristicEngine(),
        config=config,
        resolved=resolved,
        prompts=store,
        ledger=ledger,
        transport=transport,
        transport_factory=transport_factory,
        cache=cache,
        redactor=Redactor(mode=config.privacy),
        auditor=auditor,
        policies=policies,
    )


def _environ() -> Mapping[str, str]:
    import os

    return os.environ
