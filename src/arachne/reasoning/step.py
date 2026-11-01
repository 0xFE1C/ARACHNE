"""The ``hypothesis`` pipeline step: propose, gate, execute, record (S21, area AGENT).

This is where the pieces meet. The step runs *after* correlation and *before* reporting, only
for a scan that enabled agentic reasoning, and it does five things in a fixed order:

1. **Read the scan's state** — the analysed findings, the correlation groups, the rules whose
   families are half-explored, and any suspected injection content in the target's own output.
   That reading is frozen into a :class:`~arachne.reasoning.model.HypothesisInput`, whose hash
   anchors the whole run (REQ-AGENT-002).
2. **Propose** through the reasoner (heuristic, AI, or both) and persist the proposal list in
   the journal. The journal is written *before* anything runs, so a crash loses no decision.
3. **Check the kill switch** before every hypothesis (REQ-AGENT-007) and, if the operator
   paused or aborted, persist the state and raise — which fails the step, fails the scan, and
   leaves exactly the resumable state a ``--resume`` continues from.
4. **Gate and execute** through :class:`~arachne.reasoning.executor.HypothesisExecutor`: the
   planner re-runs every gate, and the checks engine runs the probe. Every refusal is a
   recorded decision with a machine-readable code (REQ-AGENT-005).
5. **Persist after every decision** — the same write-ahead discipline as S15's proof ledger, so
   an interrupted run never reports work it did not do.

``build_hypothesis_input`` is split out and pure-ish on purpose: it is the only place that turns
target-influenced data into the engine's input, and the replay path rebuilds the exact same
object from the journal (see :mod:`arachne.reasoning.replay`).
"""

from __future__ import annotations

import fnmatch
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

from arachne.analyzer.rules import Rule, RuleSet, load_rule_set
from arachne.core.audit import AuditAction, AuditOutcome
from arachne.core.errors import ConfigurationError
from arachne.core.lifecycle import StepContext, StepHandler, StepOutcome
from arachne.core.logging import get_logger
from arachne.core.planner import MODULE_STEP, ScanStep
from arachne.reasoning.control import NullControl
from arachne.reasoning.engine import HypothesisProposal, HypothesisReasoner
from arachne.reasoning.executor import HypothesisExecutor, HypothesisInterrupted, audit_refusal
from arachne.reasoning.heuristic import HeuristicHypothesisEngine, HypothesisPolicies
from arachne.reasoning.index import CheckIndex
from arachne.reasoning.injection import scan_text
from arachne.reasoning.input import FindingLine, GroupLine, UnexploredLine
from arachne.reasoning.model import (
    Hypothesis,
    HypothesisBudget,
    HypothesisDecision,
    HypothesisInput,
    HypothesisJournal,
    HypothesisJournalState,
    HypothesisMode,
    HypothesisOutcome,
)

__all__ = [
    "HypothesisRuntime",
    "as_hypothesis_engine",
    "build_hypothesis_input",
    "build_hypothesis_step",
    "load_rules",
    "make_hypothesis_handler",
    "module_of_check",
]

_logger = get_logger("reasoning.step")

#: How many evidence characters one candidate contributes to the injection scan. Bounded so a
#: hostile body cannot make the step read a megabyte per finding.
_INJECTION_SCAN_CHARS = 4000

#: The kill switch's two directives, in the past tense an operator-facing message needs.
_PAST_TENSE: Final[dict[str, str]] = {"pause": "paused", "abort": "aborted"}


@dataclass(frozen=True, slots=True)
class HypothesisRuntime:
    """The per-deployment collaborators a hypothesis step needs (all injected)."""

    index: CheckIndex
    registry: Any
    findings: Any
    analyses: Any
    gate: Any
    settings: Any = None
    rules: RuleSet | None = None
    config: Any = None
    osint: Any = None
    callback_service: Any = None
    control: NullControl | None = None
    #: A memoising factory for the AI engine (S21's ``hypothesize`` stage). ``None`` means
    #: "no provider is available", and a heuristic run never calls one.
    ai_factory: Any = None
    #: An already-built AI engine, when the caller has one (the tests do).
    ai_engine: Any = None


# --------------------------------------------------------------------------- input


def build_hypothesis_input(
    ctx: StepContext,
    *,
    index: CheckIndex,
    analyses: Any,
    findings: Any,
    rules: RuleSet | None,
    engine: str = "heuristic",
) -> HypothesisInput:
    """Freeze the scan's state into the deterministic input the engines reason over."""
    records = analyses.list_analyses(ctx.scan_id)
    finding_lines: list[str] = []
    for record in records:
        check_id = record.check_id
        if not check_id or index.get(check_id) is None:
            # A compound finding has no check of its own: it is a statement *about* other
            # findings, and the group lines below are how the engine sees it.
            continue
        asset = str(record.payload.get("asset") or "")
        if not asset:
            continue
        finding_lines.append(
            FindingLine(
                check_id=check_id,
                asset=asset,
                severity=record.severity,
                confidence=int(record.confidence),
                verdict=record.verdict,
                verified=bool(record.payload.get("verified")),
            ).encode()
        )
    candidates = findings.list_candidates(ctx.scan_id)
    covered = tuple(sorted({_check_id_of_getattr(record) for record in candidates} - {""}))
    assets = tuple(
        sorted(f"{record.kind}:{record.value}" for record in ctx.store.list_assets(ctx.scan_id))
    )
    groups = _group_lines(records, candidates, index)
    unexplored = _unexplored_lines(records, covered, rules, index) if rules else ()
    observations = _observations(candidates)
    return HypothesisInput(
        scan_id=ctx.scan_id,
        engine=engine,
        rules_version=rules.version if rules is not None else "",
        correlation_version=_correlation_version(ctx),
        assets=assets,
        findings=tuple(sorted(set(finding_lines))),
        groups=tuple(sorted(set(groups))),
        unexplored=tuple(sorted(set(unexplored))),
        covered=covered,
        observations=observations,
    )


def _check_id_of_getattr(record: Any) -> str:
    """``M3/xss-oracle@2.0`` → ``m3.xss-oracle`` (the finding row's key, as an id)."""
    key = getattr(record, "check_key", None) or ""
    head, _, _version = str(key).partition("@")
    module, _, name = head.partition("/")
    return f"{module.lower()}.{name}" if module and name else ""


def _correlation_version(ctx: StepContext) -> str:
    """The correlation corpus version the scan's groups came from, when it recorded one."""
    record = ctx.store.get_scan(ctx.scan_id)
    if record is None:
        return ""
    for state in record.steps:
        if state.step is ScanStep.CORRELATION:
            value = state.stats.get("corpus_version") or state.stats.get("version")
            return str(value) if value else ""
    return ""


def _group_lines(
    records: Sequence[Any], candidates: Sequence[Any], index: CheckIndex
) -> list[str]:
    """One line per correlation group: its asset and the module-mates worth trying next.

    The next hop is derived, not guessed: a group on an asset proves that the *module* that
    produced at least one of its members has more to say about that asset, so the module's
    other checks — minus the ones that already ran — are the candidate hops, in catalogue
    order. That is a rule an operator can read and disagree with; a model's intuition is not.
    """
    covered = {_check_id_of_getattr(record) for record in candidates}
    by_finding: dict[int, Any] = {}
    for record in candidates:
        by_finding[record.id] = record
    out: list[str] = []
    for record in records:
        payload = record.payload
        if not payload.get("correlated"):
            continue
        asset = str(payload.get("asset") or "")
        contributors = payload.get("contributors") or ()
        module: str | None = None
        for contributor in contributors:
            member = by_finding.get(int(contributor)) if isinstance(contributor, int) else None
            if member is not None and getattr(member, "module", None):
                module = str(member.module)
                break
        if module is None or not asset:
            continue
        next_hops = tuple(
            entry.id for entry in index.of_module(module) if entry.id not in covered
        )[:3]
        if not next_hops:
            continue
        out.append(
            GroupLine(
                rule_id=_rule_id_of(payload),
                group_key=asset,
                check_ids=next_hops,
                severity=str(record.severity or "info"),
            ).encode()
        )
    return out


def _rule_id_of(payload: Mapping[str, Any]) -> str:
    """The correlation rule that produced a compound, when the payload recorded one."""
    provenance = payload.get("provenance")
    if isinstance(provenance, Mapping):
        rule_ids = provenance.get("rule_ids")
        if isinstance(rule_ids, (list, tuple)) and rule_ids:
            return str(rule_ids[0])
    return "correlation"


def _unexplored_lines(
    records: Sequence[Any],
    covered: Sequence[str],
    rules: RuleSet | None,
    index: CheckIndex,
) -> list[str]:
    """Rules whose *family* produced a finding but whose concrete check never ran.

    A rule's ``check_ref`` names the checks its conditions apply to. When one of them ran and
    another did not, the rule is half-explored on that asset — if a family is worth a rule, the
    sibling check is worth one probe. Only ``check`` and ``module`` selectors participate: a
    ``research:chNN#M`` reference names a corpus method rather than an executable check, so it
    cannot found a probe.
    """
    if rules is None:
        return []
    covered_set = set(covered)
    out: list[str] = []
    for rule in rules.enabled():
        concrete = _concrete_checks(rule, index)
        if len(concrete) < 2:
            continue
        missing = tuple(check for check in concrete if check not in covered_set)
        if not missing:
            continue
        for record in records:
            check_id = record.check_id
            if not check_id or check_id not in covered_set:
                continue
            if not _selector_matches(rule, check_id):
                continue
            asset = str(record.payload.get("asset") or "")
            if not asset:
                continue
            for candidate in missing:
                out.append(
                    UnexploredLine(rule_id=rule.id, check_id=candidate, asset=asset).encode()
                )
    return out


def _concrete_checks(rule: Rule, index: CheckIndex) -> tuple[str, ...]:
    """The executable checks a rule's ``check_ref`` resolves to, in catalogue order."""
    out: list[str] = []
    for selector in rule.selectors():
        if selector.kind == "check":
            pattern = selector.check_pattern or ""
            out.extend(
                entry.id for entry in index.all() if fnmatch.fnmatchcase(entry.id, pattern)
            )
        elif selector.kind == "module":
            out.extend(entry.id for entry in index.of_module(selector.module or ""))
    return tuple(dict.fromkeys(out))


def _selector_matches(rule: Rule, check_id: str) -> bool:
    for selector in rule.selectors():
        if selector.kind == "check" and fnmatch.fnmatchcase(
            check_id, selector.check_pattern or ""
        ):
            return True
        if selector.kind == "module" and check_id.startswith(
            (selector.module or "").lower() + "."
        ):
            return True
    return False


def _observations(candidates: Sequence[Any]) -> tuple[str, ...]:
    """Suspected prompt-injection content in the target's own output (REQ-AGENT-006).

    The content is *hostile input* and is labelled as such. It never becomes an instruction:
    the engine sees it in the ``observations`` half (untrusted by construction), and the gates
    that decide what may run do not read the input at all.
    """
    out: list[str] = []
    for record in candidates:
        blob = _evidence_text(record)
        if not blob:
            continue
        for finding in scan_text(blob):
            out.append(f"suspected-injection[{finding.label}] {finding.excerpt}")
    return tuple(sorted(set(out))[:8])


def _evidence_text(record: Any) -> str:
    parts: list[str] = []
    for item in getattr(record, "evidence", ()) or ():
        payload = getattr(item, "payload", None) or {}
        for value in payload.values():
            if isinstance(value, str):
                parts.append(value)
    return " ".join(parts)[:_INJECTION_SCAN_CHARS]


# --------------------------------------------------------------------------- the handler


def build_hypothesis_step(
    *,
    gate: Any,
    index: CheckIndex,
    registry: Any,
    findings: Any,
    analyses: Any,
    settings: Any = None,
    rules: RuleSet | None = None,
    config: Any = None,
    osint: Any = None,
    callback_service: Any = None,
    control: Any = None,
    auditor: Any = None,
    ai_engine: Any = None,
    ai_factory: Any = None,
) -> StepHandler:
    """Assemble the hypothesis handler: runtime, lazily-built AI engine, and the gate.

    The AI engine is built on first use, so a heuristic-only deployment never constructs a
    provider, never opens a prompt corpus it does not use, and never touches the network — the
    same "pay for what you configure" rule the analyzer follows (F-03-03). A caller that
    already has an engine (the tests) passes it as ``ai_engine``.
    """
    resolved: list[Any] = [ai_engine]

    def build_ai() -> Any:
        if resolved[0] is None:
            resolved[0] = _build_hypothesis_ai_engine(settings, auditor)
        return resolved[0]

    runtime = HypothesisRuntime(
        index=index,
        registry=registry,
        findings=findings,
        analyses=analyses,
        gate=gate,
        settings=settings,
        rules=rules,
        config=config,
        osint=osint,
        callback_service=callback_service,
        control=control,
        ai_factory=ai_factory if ai_factory is not None else build_ai,
    )
    return make_hypothesis_handler(runtime)


def _resolve_ai(runtime: HypothesisRuntime, mode: HypothesisMode) -> Any:
    """The ``hypothesize`` stage engine for this run, or ``None`` for a heuristic run."""
    if not mode.wants_ai:
        return None
    factory = runtime.ai_factory
    candidate = factory() if callable(factory) else runtime.ai_engine
    return as_hypothesis_engine(candidate)


def as_hypothesis_engine(candidate: Any) -> Any:
    """Wrap an :class:`~arachne.ai.engine.AiEngine` so it can propose hypotheses.

    Accepts either an already-wrapped engine (anything with ``propose_async``) or a bare
    :class:`AiEngine` — which is what the composition root and the tests have — and wraps the
    latter. A bare engine reaching the reasoner unused would degrade to the heuristic half
    silently, which is exactly the kind of wiring mistake that looks like a working feature.
    """
    if candidate is None:
        return None
    if callable(getattr(candidate, "propose_async", None)):
        return candidate
    from arachne.reasoning.ai import AiHypothesisEngine

    return AiHypothesisEngine(candidate)


def _build_hypothesis_ai_engine(settings: Any, auditor: Any) -> Any:
    """The AI engine for the ``hypothesize`` stage, or ``None`` when none is configured."""
    from arachne.ai.engine import build_ai_engine
    from arachne.ai.prompts import load_prompt_store
    from arachne.analyzer.engine import HeuristicEngine

    path = settings.ai.prompts if settings is not None else None
    try:
        prompts = load_prompt_store(path, stages=("hypothesize",))
    except ConfigurationError:  # pragma: no cover - a broken corpus is an operator error
        return None
    return build_ai_engine(
        settings, heuristic=HeuristicEngine(), prompts=prompts, auditor=auditor
    )


def make_hypothesis_handler(runtime: HypothesisRuntime) -> StepHandler:
    """Build the ``hypothesis`` step handler (the orchestrator injects the gate)."""

    async def handler(ctx: StepContext) -> StepOutcome:
        settings = runtime.settings
        mode = _effective_mode(ctx, settings)
        if mode is HypothesisMode.OFF:
            return StepOutcome(
                stats={"mode": "off"},
                skipped=True,
                note="agentic reasoning is not enabled for this scan",
            )
        index = runtime.index
        policies = _policies(settings)
        journal = _load_journal(ctx)
        if journal is not None and journal.state is HypothesisJournalState.COMPLETED:
            return StepOutcome(stats=_stats(journal))

        engine_name = ctx.options.engine.value
        source = build_hypothesis_input(
            ctx,
            index=index,
            analyses=runtime.analyses,
            findings=runtime.findings,
            rules=runtime.rules,
            engine=engine_name,
        )
        for observation in source.observations:
            await _audit_injection(ctx, observation)

        # An existing journal is always continued, never re-derived. Its hash identifies the
        # inputs the *run* started from; executing a probe adds findings, so re-deriving on
        # resume would reset the cursor and the budget — exactly what a resume must not do.
        if journal is None:
            journal = await _propose(
                ctx, runtime=runtime, source=source, mode=mode, policies=policies
            )
        else:
            journal = _clear_if_resuming(ctx, runtime=runtime, journal=journal)
            if journal.input is not None and journal.inputs_hash != source.inputs_hash:
                journal = _persist(
                    ctx,
                    journal.model_copy(
                        update={
                            "note": (
                                "the scan's findings changed while the run was in progress; the "
                                "journal's inputs hash identifies what the run started from"
                            )
                        }
                    ),
                )
            await ctx.audit(
                AuditAction.HYPOTHESIS_RESUMED,
                target=f"scan:{ctx.scan_id}",
                meta={"cursor": journal.cursor, "proposed": journal.proposed},
            )

        executor = HypothesisExecutor(
            ctx=ctx,
            index=index,
            registry=runtime.registry,
            findings=runtime.findings,
            gate=runtime.gate,
            config=runtime.config,
            osint=runtime.osint,
            callback_service=runtime.callback_service,
            approved=tuple(ctx.options.proof_approved),
        )
        journal = await _run_proposals(ctx, runtime=runtime, executor=executor, journal=journal)
        stats = _stats(journal)
        stats["crawl_pages"] = executor.crawl_pages
        _logger.info(
            "hypothesis run completed",
            extra={"event": "hypothesis.completed", "scan_id": ctx.scan_id, **stats},
        )
        return StepOutcome(stats=stats)

    return handler


async def _propose(
    ctx: StepContext,
    *,
    runtime: HypothesisRuntime,
    source: HypothesisInput,
    mode: HypothesisMode,
    policies: HypothesisPolicies,
) -> HypothesisJournal:
    """Run one reasoning pass and persist the proposals before anything executes."""
    settings = runtime.settings
    ai = _resolve_ai(runtime, mode)
    reasoner = HypothesisReasoner(
        heuristic=HeuristicHypothesisEngine(runtime.index, policies=policies),
        ai=ai,
        mode=mode,
    )
    proposal: HypothesisProposal = await reasoner.propose(source, runtime.index)
    budget = ctx.options.hypothesis_budget or HypothesisBudget(
        max_hypotheses=_int_setting(settings, "max_hypotheses", policies.max_proposals),
        max_probes=_int_setting(settings, "max_probes", 50),
    )
    journal = HypothesisJournal(
        scan_id=ctx.scan_id,
        mode=mode,
        engine=proposal.engine,
        inputs_hash=source.inputs_hash,
        rules_version=source.rules_version,
        correlation_version=source.correlation_version,
        state=HypothesisJournalState.RUNNING,
        budget=budget,
        proposals=proposal.hypotheses,
        proposed=proposal.count,
        fallback=proposal.fallback,
        input=source,
        note="resumed reasoning" if proposal.fallback and proposal.hypotheses else "",
    )
    journal = _persist(ctx, journal)
    await ctx.audit(
        AuditAction.HYPOTHESIS_PROPOSED,
        target=f"scan:{ctx.scan_id}",
        meta={
            "mode": mode.value,
            "engine": proposal.engine,
            "proposed": proposal.count,
            "budget": budget.to_dict(),
            "fallback": proposal.fallback,
            "checks": [item.check_id for item in proposal.hypotheses],
        },
    )
    _logger.info(
        "hypotheses proposed",
        extra={
            "event": "hypothesis.proposed",
            "scan_id": ctx.scan_id,
            "mode": mode.value,
            "engine": proposal.engine,
            "proposed": proposal.count,
            "fallback": proposal.fallback,
        },
    )
    return journal


async def _run_proposals(
    ctx: StepContext,
    *,
    runtime: HypothesisRuntime,
    executor: HypothesisExecutor,
    journal: HypothesisJournal,
) -> HypothesisJournal:
    """Gate, execute and record each remaining proposal, persisting after every decision."""
    budget = journal.budget
    decisions: list[HypothesisDecision] = list(journal.decisions)
    for hypothesis in journal.proposals[len(decisions) :]:
        directive = runtime.control.directive(ctx.scan_id) if runtime.control else "none"
        if directive in ("pause", "abort"):
            state = (
                HypothesisJournalState.PAUSED
                if directive == "pause"
                else HypothesisJournalState.ABORTED
            )
            journal = _persist(
                ctx,
                journal.model_copy(
                    update={
                        "decisions": tuple(decisions),
                        "budget": budget,
                        "state": state,
                        "note": (
                            f"the operator {_PAST_TENSE[directive]} the run before "
                            f"hypothesis {journal.cursor + 1}"
                        ),
                    }
                ),
            )
            action = (
                AuditAction.HYPOTHESIS_PAUSED
                if directive == "pause"
                else AuditAction.HYPOTHESIS_ABORTED
            )
            await ctx.audit(
                action,
                outcome=AuditOutcome.BLOCKED,
                target=f"scan:{ctx.scan_id}",
                reason=journal.note,
                meta={"cursor": journal.cursor, "proposed": journal.proposed},
            )
            raise HypothesisInterrupted(
                f"scan {ctx.scan_id}: agentic expansion {_PAST_TENSE[directive]} by the "
                f"operator after {journal.cursor} of {journal.proposed} hypotheses"
            )

        refusal = executor.validate(hypothesis, budget=budget)
        if refusal is not None:
            audit_refusal(ctx, hypothesis, refusal)
            if refusal.code == "budget-exhausted":
                budget = budget.defer()
                outcome, reason = HypothesisOutcome.DEFERRED, f"budget: {refusal.reason}"
            else:
                outcome, reason = HypothesisOutcome.REFUSED, f"{refusal.code}: {refusal.reason}"
            decisions.append(
                _decision(journal, hypothesis, outcome=outcome, reason=reason, probes=0)
            )
            journal = _persist(
                ctx, journal.model_copy(update={"decisions": tuple(decisions), "budget": budget})
            )
            continue

        result = await executor.execute(hypothesis)
        if result.outcome is HypothesisOutcome.EXECUTED:
            budget = budget.spend(probes=result.probes)
            await ctx.audit(
                AuditAction.HYPOTHESIS_EXECUTED,
                target=hypothesis.asset,
                meta={
                    "check": hypothesis.check_id,
                    "kind": hypothesis.kind.value,
                    "source": hypothesis.source,
                    "probes": result.probes,
                    "candidates": len(result.produced),
                    **(result.detail or {}),
                },
            )
        elif result.outcome is HypothesisOutcome.SKIPPED:
            budget = budget.spend(probes=result.probes)
        decisions.append(
            _decision(
                journal,
                hypothesis,
                outcome=result.outcome,
                reason=result.reason,
                probes=result.probes,
                produced=result.produced,
            )
        )
        journal = _persist(
            ctx, journal.model_copy(update={"decisions": tuple(decisions), "budget": budget})
        )
    journal = _persist(
        ctx,
        journal.model_copy(
            update={
                "decisions": tuple(decisions),
                "budget": budget,
                "state": HypothesisJournalState.COMPLETED,
            }
        ),
    )
    await ctx.audit(
        AuditAction.HYPOTHESIS_COMPLETED,
        target=f"scan:{ctx.scan_id}",
        meta={
            "proposed": journal.proposed,
            "executed": len(journal.executed),
            "refused": len(journal.refused),
            "budget": budget.to_dict(),
            "engine": journal.engine,
        },
    )
    return journal


# --------------------------------------------------------------------------- helpers


def _effective_mode(ctx: StepContext, settings: Any) -> HypothesisMode:
    if ctx.options.hypotheses is not HypothesisMode.OFF:
        return ctx.options.hypotheses
    configured = getattr(getattr(settings, "hypotheses", None), "mode", HypothesisMode.OFF)
    return configured if isinstance(configured, HypothesisMode) else HypothesisMode.OFF


def _policies(settings: Any) -> HypothesisPolicies:
    block = getattr(settings, "hypotheses", None)
    return HypothesisPolicies(
        verify_below=_int_setting(settings, "verify_below", 70),
        max_proposals=_int_setting(settings, "max_proposals", 32),
        min_confidence=30 if block is None else max(0, int(getattr(block, "min_confidence", 30))),
    )


def _int_setting(settings: Any, name: str, fallback: int) -> int:
    block = getattr(settings, "hypotheses", None)
    if block is None:
        return fallback
    value = getattr(block, name, None)
    return int(value) if isinstance(value, int) else fallback


def _load_journal(ctx: StepContext) -> HypothesisJournal | None:
    record = ctx.store.get_scan(ctx.scan_id)
    if record is None:
        return None
    return HypothesisJournal.from_document((record.stats or {}).get("hypotheses"))


def _persist(ctx: StepContext, journal: HypothesisJournal) -> HypothesisJournal:
    """Write the journal into the scan's stats, preserving every other key (S15's lesson)."""
    record = ctx.store.get_scan(ctx.scan_id)
    stats = dict(record.stats) if record is not None and record.stats else {}
    stats["hypotheses"] = journal.to_dict()
    ctx.store.update_scan(ctx.scan_id, stats=stats)
    return journal


def _clear_if_resuming(
    ctx: StepContext, *, runtime: HypothesisRuntime, journal: HypothesisJournal
) -> HypothesisJournal:
    """A pause or abort applied to *this run*; the resume clears it (REQ-AGENT-007).

    Otherwise one pause would stop every later resume for ever. A deployment-wide stop is
    recorded without a scan id (``arachne reason abort --all``) and a resume never clears it.
    """
    if runtime.control is None or journal.state not in (
        HypothesisJournalState.PAUSED,
        HypothesisJournalState.ABORTED,
    ):
        return journal
    clear = getattr(runtime.control, "clear", None)
    if callable(clear):
        clear(ctx.scan_id)
    return journal.model_copy(update={"state": HypothesisJournalState.RUNNING, "note": ""})


def _decision(
    journal: HypothesisJournal,
    hypothesis: Hypothesis,
    *,
    outcome: HypothesisOutcome,
    reason: str,
    probes: int,
    produced: tuple[int, ...] = (),
) -> HypothesisDecision:
    return HypothesisDecision(
        hypothesis_id=hypothesis.id,
        check_id=hypothesis.check_id,
        asset=hypothesis.asset,
        kind=hypothesis.kind,
        source=hypothesis.source,
        inputs_hash=journal.inputs_hash,
        outcome=outcome,
        reason=reason[:1000],
        probes=probes,
        engine=journal.engine,
        fallback=journal.fallback,
        produced=produced,
    )


def _stats(journal: HypothesisJournal) -> dict[str, Any]:
    return {
        "mode": journal.mode.value,
        "engine": journal.engine,
        "proposed": journal.proposed,
        "decisions": journal.cursor,
        "executed": len(journal.executed),
        "refused": len(journal.refused),
        "deferred": journal.budget.deferred,
        "probes_spent": journal.budget.probes_spent,
        "inputs_hash": journal.inputs_hash,
        "fallback": journal.fallback,
        "state": journal.state.value,
    }


async def _audit_injection(ctx: StepContext, observation: str) -> None:
    """One audit line per suspected injection (REQ-AGENT-006: detected, never obeyed)."""
    label = observation.split("]", 1)[0].removeprefix("suspected-injection[")
    await ctx.audit(
        AuditAction.HYPOTHESIS_INJECTION_SUSPECTED,
        outcome=AuditOutcome.BLOCKED,
        target=f"scan:{ctx.scan_id}",
        reason="target-derived content attempted to influence the reasoning half",
        meta={"label": label, "excerpt": observation[:200]},
    )


def load_rules(settings: Any = None) -> RuleSet:
    """The rule corpus a deployment reasons over (the analyzer's own corpus)."""
    from arachne.core.config import Settings

    effective = settings if isinstance(settings, Settings) else None
    path = effective.analysis.rules if effective is not None else None
    try:
        return load_rule_set(path)
    except ConfigurationError:  # pragma: no cover - a broken corpus is an operator error
        return load_rule_set(None)


def module_of_check(check_id: str) -> ScanStep | None:
    """The pipeline step a check id belongs to (``None`` for an unknown module)."""
    module = check_id.split(".", 1)[0].upper()
    return MODULE_STEP.get(module)
