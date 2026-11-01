"""The ``analysis`` and ``correlation`` pipeline steps .

These two handlers are the seam between the detection layer and the analyzer, and they exist
separately for one reason: **the analyzer must not import the module layer or the ORM.** So
the translation from stored candidate rows (:class:`~arachne.data.finding_store.CandidateRecord`)
to the engine's :class:`~arachne.analyzer.model.Candidate` happens here, in one place, together
with the join that attaches each candidate's check metadata (``severity_hint``,
``research_ref``, ``cwe``, ``verifiable``).

``analysis``
    Read the scan's candidates, verify the verifiable ones (the only I/O in the stage), run
    the heuristic engine, and persist severity/confidence/narrative per finding.
``correlation``
    Read the analyses the previous step stored, dedupe them by root cause, apply the
    correlation rules, and persist the compound findings.

Both steps are *idempotent in outcome*: re-running them over the same rows produces the same
analyses (the same data files, the same evidence, the same deterministic engine), which is
what makes a resumed scan safe (F-01-04).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import replace
from typing import Any, Final

from arachne.ai.engine import AiEngine, build_ai_engine, engine_description
from arachne.analyzer.correlation import CorrelationEngine, load_correlation_rules
from arachne.analyzer.engine import (
    AnalysisPolicies,
    Analyzer,
    HeuristicEngine,
    select_engine,
    summarize,
)
from arachne.analyzer.fp import (
    FpTuner,
    HttpVerifier,
    NullVerifier,
    VerificationTarget,
    Verifier,
    feedback_key,
    load_fp_filters,
    load_fp_thresholds,
)
from arachne.analyzer.model import (
    Candidate,
    EvidenceFact,
    FpStats,
    ScanContext,
    VerificationOutcome,
)
from arachne.analyzer.narrative import NarrativeSynthesizer, load_narrative_templates
from arachne.analyzer.remediation import load_remediation_catalog
from arachne.analyzer.rules import RuleEngine, load_rule_set
from arachne.analyzer.scoring import ScoringModel, load_vector_table
from arachne.analyzer.signatures import SignatureLibrary
from arachne.core.audit import AuditAction, AuditOutcome
from arachne.core.config import AnalysisSettings, Settings
from arachne.core.events import Event
from arachne.core.lifecycle import StepContext, StepHandler, StepOutcome
from arachne.core.logging import get_logger
from arachne.core.planner import ScanStep
from arachne.data.analysis_store import AnalysisStore, MemoryAnalysisStore, analysis_from_log
from arachne.data.finding_store import CandidateRecord, FindingStore, MemoryFindingStore

__all__ = [
    "CandidateMetadata",
    "EngineResolver",
    "build_analysis_handlers",
    "candidate_from_record",
    "candidates_from_store",
    "create_correlation_engine",
    "create_heuristic_engine",
    "make_analysis_handler",
    "make_correlation_handler",
    "metadata_map",
    "select_analysis_engine",
]

_logger = get_logger("analyzer.handlers")


class CandidateMetadata:
    """The check metadata the analyzer needs, decoupled from the registry's type.

    ``registry.metadata()`` supplies these today; a plugin supplying a check through the
    entry-point mechanism supplies the same fields, so nothing here is registry-specific.
    """

    __slots__ = ("cve", "cwe", "key", "research_ref", "severity_hint", "verifiable")

    def __init__(
        self,
        *,
        key: str,
        research_ref: str | None = None,
        cwe: str | None = None,
        cve: str | None = None,
        severity_hint: str | None = None,
        verifiable: bool = False,
    ) -> None:
        self.key = key
        self.research_ref = research_ref
        self.cwe = cwe
        self.cve = cve
        self.severity_hint = severity_hint
        self.verifiable = verifiable

    @classmethod
    def from_metadata(cls, metadata: Any) -> CandidateMetadata:
        return cls(
            key=str(metadata.key),
            research_ref=metadata.research_ref,
            cwe=metadata.cwe,
            cve=getattr(metadata, "cve", None),
            severity_hint=getattr(metadata, "severity_hint", None),
            verifiable=bool(getattr(metadata, "verifiable", False)),
        )


# --------------------------------------------------------------------------- factory


class EngineResolver:
    """Resolves — and memoises — the engine a *scan* asked for (F-03-01/F-03-04).

    The engine is a per-scan choice (``ScanOptions.engine``), not a deployment-wide one, so the
    handler cannot be built around a single instance. This holds the deployment's settings and
    hands out the right engine per step context: ``heuristic`` always works, ``hybrid`` is the
    AI engine when a provider is configured and the heuristic engine otherwise,
    and ``ai`` without a provider is refused loudly rather than silently
    downgraded (F-03-03).

    The AI engine is built lazily and once per resolver, so a deployment that configures AI but
    runs a heuristic scan pays nothing, and a scan that asks for ``ai`` gets a fresh budget
    ledger, provider and cache rather than another scan's leftovers.
    """

    def __init__(
        self,
        settings: Settings | None = None,
        *,
        engine: Analyzer | None = None,
        ai_engine: AiEngine | None = None,
        auditor: Any = None,
    ) -> None:
        self.settings = settings
        self.auditor = auditor
        self._fixed = engine
        self._ai = ai_engine
        self._ai_resolved = ai_engine is not None
        self._heuristic: Analyzer | None = None

    def heuristic_engine(self) -> Analyzer:
        if self._heuristic is None:
            self._heuristic = create_heuristic_engine(self.settings)
        return self._heuristic

    def ai_engine(self) -> AiEngine | None:
        """The configured AI engine, or ``None`` when this deployment has no provider."""
        if not self._ai_resolved:
            self._ai = build_ai_engine(
                self.settings, heuristic=self.heuristic_engine(), auditor=self.auditor
            )
            self._ai_resolved = True
        return self._ai

    def for_scan(self, ctx: StepContext) -> Analyzer:
        """The engine for ``ctx``'s scan, by name."""
        if self._fixed is not None:
            return self._fixed
        return select_engine(
            ctx.options.engine.value,
            heuristic=self.heuristic_engine(),
            ai=self.ai_engine(),
        )

    def describe(self, ctx: StepContext) -> dict[str, Any]:
        """``{engine, ...}`` for the step statistics and the audit line, credential-free."""
        engine = self.for_scan(ctx)
        return engine_description(engine)


def create_heuristic_engine(
    settings: Settings | None = None, *, analysis: AnalysisSettings | None = None
) -> HeuristicEngine:
    """Build the shipped heuristic engine, honouring every managed-data override."""
    config = analysis or (settings.analysis if settings is not None else AnalysisSettings())
    return HeuristicEngine(
        rules=RuleEngine(load_rule_set(config.rules)),
        scoring=ScoringModel(load_vector_table(config.scoring_vectors)),
        narratives=NarrativeSynthesizer(load_narrative_templates(config.narrative_templates)),
        remediation=load_remediation_catalog(config.remediation_catalog),
        signatures=SignatureLibrary.load(config.signature_dirs or None),
        fp_filters=load_fp_filters(config.fp_filters),
        tuner=FpTuner(thresholds=load_fp_thresholds(config.fp_thresholds)),
        policies=engine_policies(settings, analysis=config),
    )


def create_correlation_engine(
    settings: Settings | None = None, *, analysis: AnalysisSettings | None = None
) -> CorrelationEngine:
    """Build the correlation engine over the same data the analyzer used."""
    config = analysis or (settings.analysis if settings is not None else AnalysisSettings())
    return CorrelationEngine(
        load_correlation_rules(config.correlation_rules),
        scoring=ScoringModel(load_vector_table(config.scoring_vectors)),
        narratives=NarrativeSynthesizer(load_narrative_templates(config.narrative_templates)),
        remediation=load_remediation_catalog(config.remediation_catalog),
        minimum_severity="info",
    )


# --------------------------------------------------------------------------- candidates


def candidate_from_record(
    record: CandidateRecord, metadata: CandidateMetadata | None = None
) -> Candidate:
    """Adapt one stored candidate row to the engine's input (see the module docstring)."""
    module, name, version = _split_check_key(record.check_key, fallback_module=record.module)
    check_id = f"{module.lower()}.{name}" if module and name else record.check_key
    evidence = tuple(
        EvidenceFact(
            kind=row.kind,
            payload=dict(row.payload),
            sha256=row.sha256,
            source=row.payload.get("source")
            if isinstance(row.payload.get("source"), str)
            else None,
            id=row.id,
        )
        for row in record.evidence
        if not (row.kind == "note" and row.payload.get("skipped"))
    )
    return Candidate(
        scan_id=record.scan_id,
        title=record.title,
        finding_id=record.id,
        status=record.status,
        check_id=check_id,
        check_module=module,
        check_name=name,
        check_version=version,
        research_ref=(metadata.research_ref if metadata is not None else record.research_ref),
        cwe=metadata.cwe if metadata is not None else None,
        cve=metadata.cve if metadata is not None else None,
        severity_hint=metadata.severity_hint if metadata is not None else None,
        verifiable=bool(metadata.verifiable) if metadata is not None else False,
        check_confidence=record.confidence,
        asset_id=record.asset_id,
        asset_kind=record.asset_kind,
        asset_value=record.asset_value,
        evidence=evidence,
    )


def _split_check_key(
    key: str | None, *, fallback_module: str | None
) -> tuple[str | None, str | None, str | None]:
    """``M4/env-file-probe@1.0`` → ``("M4", "env-file-probe", "1.0")``."""
    if not key:
        return fallback_module, None, None
    head, _, version = key.partition("@")
    module, _, name = head.partition("/")
    return (module or fallback_module), (name or None), (version or None)


def candidates_from_store(
    findings: FindingStore,
    scan_id: int,
    metadata: Mapping[str, CandidateMetadata],
    *,
    only_candidates: bool = True,
) -> tuple[Candidate, ...]:
    """The scan's candidate findings, adapted to the engine's input.

    ``only_candidates`` keeps the *step* honest: it analyses rows that are still candidates
    (``severity IS NULL``, produced by a check) and never re-analyses a finding it already
    scored, nor the compound findings the correlation step created — a compound has no check
    and no evidence of its own, so re-analysing it would overwrite its promoted severity with
    a hint-derived one. The CLI's read-only preview passes ``False``, because there the point
    *is* to re-run the current corpus over everything.
    """
    records = findings.list_candidates(scan_id)
    return tuple(
        candidate_from_record(record, metadata.get(record.check_key or ""))
        for record in records
        if not only_candidates or (record.severity is None and record.check_key is not None)
    )


def metadata_map(registry: Any) -> dict[str, CandidateMetadata]:
    if registry is None:
        return {}
    return {item.key: CandidateMetadata.from_metadata(item) for item in registry.metadata()}


#: The severities whose findings must be re-requested before acceptance (F-05-07).
_HIGH_SEVERITIES: Final[tuple[str, ...]] = ("critical", "high")


def _needs_verification(candidate: Candidate, *, high_severity: bool) -> bool:
    """Whether a candidate should be re-requested (F-05-07).

    A check that declared itself ``verifiable`` is always re-requested. When the
    high-severity policy is on, a candidate whose *declared* severity is high or critical is
    re-requested as well — but only when a re-request is actually possible (the capture
    names a URL), because a bare network finding has nothing to replay and is handled by the
    engine's unflagged "not re-verified" path instead.
    """
    if candidate.verifiable:
        return True
    if not high_severity:
        return False
    if (candidate.severity_hint or "").strip().lower() not in _HIGH_SEVERITIES:
        return False
    return VerificationTarget.from_candidate(candidate) is not None


async def _verify(
    ctx: StepContext,
    candidates: Sequence[Candidate],
    *,
    config: AnalysisSettings,
    verifier: Verifier | None = None,
) -> dict[str, VerificationOutcome]:
    """Re-request the candidates that must reproduce before acceptance (F-05-07).

    A dry run has no client and verification is skipped entirely; a live scan re-requests at
    most ``max_verifications`` candidates through the same scoped client the checks used, so
    every verification appears in the audit log like any other request. High-severity
    findings are re-requested *before* they are accepted, which is the F-05-07 policy for the
    strongest claims: an operator reading a critical finding can see whether it reproduced.
    """
    if not config.verify:
        return {}
    active: Verifier = verifier or (
        HttpVerifier(ctx.http, max_verifications=config.max_verifications)
        if ctx.http is not None
        else NullVerifier()
    )
    outcomes: dict[str, VerificationOutcome] = {}
    for candidate in candidates:
        if not _needs_verification(candidate, high_severity=config.verify_high_severity):
            continue
        outcome = await active.verify(candidate)
        if outcome.attempted or outcome.contradicted:
            outcomes[candidate.key] = outcome
    return outcomes


# --------------------------------------------------------------------------- handlers


def make_analysis_handler(
    *,
    engine: Analyzer | None = None,
    findings: FindingStore,
    analyses: AnalysisStore,
    registry: Any = None,
    settings: Settings | None = None,
    verifier: Verifier | None = None,
    resolver: EngineResolver | None = None,
) -> StepHandler:
    """The ``analysis`` step: candidates in, analysed findings out (F-03-01, F-05-01..06).

    ``engine`` pins one engine for every scan (the unit tests do this); otherwise the scan's
    own ``options.engine`` decides, through a :class:`EngineResolver` — which is how
    ``--engine ai`` reaches the AI engine and how ``hybrid`` stays the heuristic engine in a
    deployment with no provider configured.
    """
    config = settings.analysis if settings is not None else AnalysisSettings()
    metadata = metadata_map(registry)
    engines = resolver or EngineResolver(settings, engine=engine)

    async def handler(ctx: StepContext) -> StepOutcome:
        candidates = candidates_from_store(findings, ctx.scan_id, metadata)
        selected = engines.for_scan(ctx)
        if not candidates:
            await ctx.emit(
                Event.analysis_done(
                    scan_id=ctx.scan_id,
                    engine=selected.name,
                    findings=0,
                    provenance={"stage": "analysis", "candidates": 0},
                )
            )
            return StepOutcome(stats={"candidates_analyzed": 0, "findings": 0})

        verification = await _verify(ctx, candidates, config=config, verifier=verifier)
        tuner = _tuner(config, analyses, candidates)
        context = ScanContext(
            scan_id=ctx.scan_id,
            engine=selected.name,
            asset_criticality=config.criticality_map(),
            verification=verification,
            fp=tuner,
            can_verify=ctx.http is not None,
        )
        results, ai_stats = await _analyze(selected, candidates, context)
        stored = analyses.apply(ctx.scan_id, results, engine=selected.name)
        summary = summarize(results, candidates, context, minimum_confidence=config.min_confidence)

        stats = summary.to_stats()
        if ai_stats:
            stats["ai"] = ai_stats
        await ctx.audit(
            AuditAction.ANALYSIS_COMPLETED,
            target=f"scan:{ctx.scan_id}",
            meta={
                **stats,
                "engine": selected.name,
                "rule_corpus": getattr(getattr(selected, "rules", None), "version", None),
                "analysis_rows": len(stored),
            },
        )
        await ctx.emit(
            Event.analysis_done(
                scan_id=ctx.scan_id,
                engine=selected.name,
                findings=summary.analyzed,
                provenance={
                    "stage": "analysis",
                    "engine": selected.name,
                    "severities": dict(summary.severities),
                    "rules_fired": list(summary.rules),
                    **(ai_stats or {}),
                },
            )
        )
        for analysis in results:
            if analysis.verdict == "dropped":
                await ctx.audit(
                    AuditAction.ANALYSIS_DROPPED,
                    outcome=AuditOutcome.BLOCKED,
                    target=analysis.asset,
                    reason=analysis.drop_reason,
                    meta={
                        "check": analysis.check_id,
                        "finding_id": analysis.finding_id,
                        "engine": analysis.provenance.engine,
                    },
                )
        _logger.info(
            "analysis completed",
            extra={
                "event": "analysis.completed",
                "scan_id": ctx.scan_id,
                "engine": selected.name,
                "candidates": len(candidates),
                "findings": summary.analyzed,
                "dropped": summary.dropped,
                "severities": dict(summary.severities),
                "ai_degraded": (ai_stats or {}).get("degraded"),
            },
        )
        return StepOutcome(stats=stats)

    return handler


async def _analyze(
    engine: Analyzer,
    candidates: Sequence[Candidate],
    context: ScanContext,
) -> tuple[tuple[Any, ...], dict[str, Any] | None]:
    """Run the selected engine, awaiting its async form when it has one (the AI engine).

    The AI engine's own batch stages (``prioritize``) and its budget/provider state are
    collected here, so the step statistics and the audit line carry "what the model cost and
    whether it degraded" without the lifecycle machine knowing anything about AI.
    """
    analyze_async = getattr(engine, "analyze_async", None)
    results = (
        await analyze_async(candidates, context)
        if callable(analyze_async)
        else engine.analyze(candidates, context)
    )
    ai_stats = _ai_stats(engine, results)
    prioritize = getattr(engine, "prioritize_async", None)
    if ai_stats and callable(prioritize):
        priority = await prioritize(results)
        if priority:
            ai_stats["prioritize"] = dict(priority)
    return tuple(results), ai_stats


def _ai_stats(engine: Any, results: Sequence[Any]) -> dict[str, Any] | None:
    """The AI half of the step statistics, or ``None`` for a non-AI engine."""
    ledger = getattr(engine, "ledger", None)
    if ledger is None:
        return None
    fallbacks: dict[str, int] = {}
    engines: dict[str, int] = {}
    for analysis in results:
        provenance = getattr(analysis, "provenance", None)
        if provenance is None:
            continue
        engines[provenance.engine] = engines.get(provenance.engine, 0) + 1
        if provenance.fallback:
            key = provenance.fallback.split(":", 1)[0]
            fallbacks[key] = fallbacks.get(key, 0) + 1
    return {
        "provider": getattr(engine, "provider_name", ""),
        "model": getattr(engine, "model", ""),
        "privacy": getattr(getattr(engine, "redactor", None), "mode", None),
        "budget": ledger.snapshot(),
        "provider_state": dict(getattr(engine, "last_provider_snapshot", {}) or {}),
        "engines": engines,
        "fallbacks": fallbacks,
        "degraded": sum(fallbacks.values()),
    }


def _ai_compound(engine: Any, suggestion: Any, compound: Any) -> Any:
    """Rewrite a compound's prose from an AI suggestion, keeping the engine's verdict."""
    from arachne.analyzer.model import Provenance

    title = getattr(suggestion, "title", "") or compound.title
    reasoning = getattr(suggestion, "reasoning", "") or compound.narrative
    provenance = Provenance(
        engine="ai",
        rule_ids=compound.provenance.rule_ids,
        template_version=getattr(getattr(engine, "prompts", None), "version", None),
        model=getattr(engine, "model", None),
        provider=getattr(engine, "provider_name", None),
        prompt_template="correlate",
        prompt_hash=(suggestion.provenance or {}).get("prompt_hash"),
    )
    return replace(
        compound,
        title=title[:512],
        narrative=reasoning,
        provenance=provenance,
        ai={"policy": "preserve", "stage": "correlate", "suggestion": dict(suggestion.provenance)},
    )


def make_correlation_handler(
    *,
    engine: CorrelationEngine,
    findings: FindingStore,
    analyses: AnalysisStore,
    store: Any = None,
    registry: Any = None,
    enabled: bool = True,
    engines: EngineResolver | None = None,
) -> StepHandler:
    """The ``correlation`` step: dedupe, then compound findings (F-05-03).

    With the AI engine selected for the scan, a group of at least
    ``ai.correlate_threshold`` candidates gets an AI-written title and reasoning
    . The *existence*, the contributors and the severity of the
    compound stay the correlation engine's decision, so the finding set is identical in both
    engine modes and only the prose differs.
    """
    metadata = metadata_map(registry)

    async def handler(ctx: StepContext) -> StepOutcome:
        if not enabled:
            return StepOutcome(
                stats={"compounds": 0, "merged": 0},
                skipped=True,
                note="correlation is disabled by configuration",
            )
        existing = analyses.list_analyses(ctx.scan_id)
        stored = [analysis_from_log(row) for row in existing]
        analysed = tuple(
            item
            for item in stored
            if item is not None and item.verdict == "analyzed" and not item.correlated
        )
        if not analysed:
            return StepOutcome(stats={"compounds": 0, "merged": 0})

        candidates = candidates_from_store(findings, ctx.scan_id, metadata, only_candidates=False)
        by_finding = {
            candidate.finding_id: candidate
            for candidate in candidates
            if candidate.finding_id is not None
        }
        outcome = engine.correlate(analysed, by_finding)
        compounds, ai_notes = await _ai_correlate(
            _ai_engine_for(engines, ctx), outcome=outcome, analysed=analysed
        )
        # Only the analyses the correlation pass *changed* are written again: a merged finding
        # (its status becomes ``merged``) and an owner that absorbed contributors. Re-writing
        # every pass-through analysis would duplicate its ``analysis_log`` row on each resume.
        changed = tuple(
            item
            for item in outcome.analyses
            if item.verdict == "merged" or item.contributors or item.merged_evidence_refs
        )
        if changed:
            analyses.apply(ctx.scan_id, changed, engine="heuristic")
        asset_ids = _asset_ids(store, ctx.scan_id)
        already = {(item.check_id, item.payload.get("title")) for item in existing}
        created: list[Any] = []
        for compound in compounds:
            if (compound.check_id, compound.title) in already:
                # A re-run of a failed correlation step must not duplicate a compound it
                # already wrote; the pair (rule, title) identifies it.
                continue
            analyses.create_compound(
                ctx.scan_id,
                compound,
                engine=compound.provenance.engine,
                asset_id=asset_ids.get(compound.asset or ""),
            )
            created.append(compound)
        stats: dict[str, Any] = {
            "compounds": len(created),
            "correlated": len(outcome.compounds),
            "merged": len(outcome.merged),
            "groups": [group.to_dict() for group in outcome.groups],
            "candidates_considered": len(analysed),
        }
        if ai_notes:
            stats["ai"] = ai_notes
        await ctx.audit(
            AuditAction.CORRELATION_COMPLETED,
            target=f"scan:{ctx.scan_id}",
            meta={
                "compounds": len(created),
                "merged": len(outcome.merged),
                "rules": [group.rule_id for group in outcome.groups],
                "ai_groups": ai_notes.get("groups", 0) if ai_notes else 0,
            },
        )
        await ctx.emit(
            Event.analysis_done(
                scan_id=ctx.scan_id,
                engine="heuristic",
                findings=len(created),
                provenance={
                    "stage": "correlation",
                    "compounds": [item.title for item in created],
                    **(ai_notes or {}),
                },
            )
        )
        _logger.info(
            "correlation completed",
            extra={
                "event": "correlation.completed",
                "scan_id": ctx.scan_id,
                "compounds": len(outcome.compounds),
                "merged": len(outcome.merged),
            },
        )
        return StepOutcome(stats=stats)

    return handler


def _ai_engine_for(engines: EngineResolver | None, ctx: StepContext) -> Any | None:
    """The AI engine for ``ctx``, when the scan asked for one (``None`` otherwise)."""
    if engines is None:
        return None
    if ctx.options.engine.value == "heuristic":
        return None
    return engines.ai_engine()


async def _ai_correlate(
    ai: Any | None,
    *,
    outcome: Any,
    analysed: Sequence[Any],
) -> tuple[tuple[Any, ...], dict[str, Any] | None]:
    """Enrich each correlation group's compound with an AI title/reasoning (``correlate``)."""
    if ai is None or not outcome.compounds:
        return tuple(outcome.compounds), None
    by_id = {item.finding_id: item for item in analysed if item.finding_id is not None}
    enriched: list[Any] = []
    used = 0
    for compound in outcome.compounds:
        group = _group_for(outcome.groups, compound)
        members = [
            (
                str(item.asset or f"finding {item.finding_id}"),
                item.severity,
                item.title,
            )
            for contributor in compound.contributors
            if (item := by_id.get(contributor)) is not None
        ]
        if group is None or not members:
            enriched.append(compound)
            continue
        suggestion = await ai.suggest_compound(
            host=str(compound.asset or group.group_key),
            members=members,
            trigger=str(group.rule_id),
        )
        if suggestion is None or not suggestion.title:
            enriched.append(compound)
            continue
        enriched.append(_ai_compound(ai, suggestion, compound))
        used += 1
    notes: dict[str, Any] = {
        "groups": used,
        "provider": getattr(ai, "provider_name", ""),
        "model": getattr(ai, "model", ""),
        "budget": ai.ledger.snapshot(),
    }
    return tuple(enriched), notes


def _group_for(groups: Sequence[Any], compound: Any) -> Any | None:
    """The correlation group a compound came from (matched by its contributors)."""
    contributors = set(compound.contributors)
    for group in groups:
        if contributors and set(group.contributor_ids) == contributors:
            return group
    return None


def build_analysis_handlers(
    *,
    settings: Settings | None = None,
    registry: Any = None,
    findings: FindingStore | None = None,
    analyses: AnalysisStore | None = None,
    engine: Any = None,
    correlation: CorrelationEngine | None = None,
    verifier: Verifier | None = None,
    store: Any = None,
    ai_engine: Any = None,
    engines: EngineResolver | None = None,
    auditor: Any = None,
) -> dict[ScanStep, StepHandler]:
    """The two analyzer-backed handlers, wired to this deployment's settings.

    ``engine`` pins a single engine (the unit tests' shape). Left out, the per-scan
    :class:`EngineResolver` decides, which is what makes ``--engine ai`` reach the AI engine.
    """
    effective_findings = findings or MemoryFindingStore()
    effective_analyses = analyses or MemoryAnalysisStore()
    config = settings.analysis if settings is not None else AnalysisSettings()
    correlation_engine = correlation or create_correlation_engine(settings)
    resolver = engines or EngineResolver(
        settings, engine=engine, ai_engine=ai_engine, auditor=auditor
    )
    return {
        ScanStep.ANALYSIS: make_analysis_handler(
            findings=effective_findings,
            analyses=effective_analyses,
            registry=registry,
            settings=settings,
            verifier=verifier,
            resolver=resolver,
        ),
        ScanStep.CORRELATION: make_correlation_handler(
            engine=correlation_engine,
            findings=effective_findings,
            analyses=effective_analyses,
            store=store,
            registry=registry,
            enabled=config.correlation_enabled,
            engines=resolver,
        ),
    }


# --------------------------------------------------------------------------- helpers


def _tuner(
    config: AnalysisSettings, analyses: AnalysisStore, candidates: Sequence[Candidate]
) -> Mapping[str, FpStats]:
    """The FP-tuner snapshot for this run: per-key totals, read once (F-05-07)."""
    if not config.fp_tuner_enabled:
        return {}
    keys: Iterable[str] = (feedback_key(candidate) for candidate in candidates)
    return dict(analyses.feedback_stats(keys))


def _asset_ids(store: Any, scan_id: int) -> dict[str, int | None]:
    """``{"kind:value" → id}`` plus ``{value → id}`` for the scan's assets."""
    if store is None:
        return {}
    out: dict[str, int | None] = {}
    for record in store.list_assets(scan_id):
        out[f"{record.kind}:{record.value}"] = record.id
        out.setdefault(record.value, record.id)
    return out


def select_analysis_engine(settings: Settings | None, engine_name: str) -> Any:
    """Resolve the scan's engine by name, building the AI engine when it is configured.

    ``ai`` without a provider is refused (F-03-03); ``hybrid`` falls back to the heuristic
    engine, which is the default behaviour for a deployment with no AI.
    """
    resolver = EngineResolver(settings)
    return select_engine(
        engine_name,
        heuristic=resolver.heuristic_engine(),
        ai=resolver.ai_engine(),
    )


def engine_policies(
    settings: Settings | None = None, *, analysis: AnalysisSettings | None = None
) -> AnalysisPolicies:
    """The policies a deployment's settings imply (used by the CLI's preview)."""
    config = analysis or (settings.analysis if settings is not None else AnalysisSettings())
    return AnalysisPolicies(
        drop_on_contradiction=config.drop_on_contradiction,
        drop_on_placeholder=config.drop_on_placeholder,
        tuner_enabled=config.fp_tuner_enabled,
        minimum_confidence=config.min_confidence,
        require_verification_for_high=config.verify_high_severity,
    )
