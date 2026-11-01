"""Executing hypotheses — through the planner/orchestrator, or not at all (REQ-AGENT-001/005).

This is the cage. A hypothesis is a proposal; this module is the only thing that turns one into
a request, and it does so by asking the *orchestrator* to plan the probe (which re-runs the
scope gate, the authorization gate and the proof gate on the executing path) before it asks the
*checks* engine to run it. There is no second execution path, no direct client, and no way for a
proposal to skip a gate: :class:`HypothesisExecutor` cannot even be constructed without a gate.

Four boundaries are enforced here, in this order, and each refusal is a recorded decision rather
than an exception (REQ-AGENT-005):

1. **The check exists and this build implements it.** An unknown or unimplemented check id is
   refused — a model cannot invent capability.
2. **The asset is one the scan already knows, and it is in scope.** A proposal cannot introduce
   a host, a URL or a port; the scope is re-checked anyway, because defence in depth is cheap.
3. **Proof and approval.** An L2+ proposal needs the operator's explicit approval
   (``options.proof_approved``); an L3/L4 proposal additionally needs the attestation's
   state-change authorization. Neither can be minted by anything a model said.
4. **The budget.** The per-scan allowance is checked before the probe is planned, and spent only
   when it runs. It can only move down.

After the gates, the probe is planned *again* through the orchestrator for its own subset and
the planner's verdict is honoured: a check the planner withholds for any reason is refused with
the planner's own skip code, which keeps one authority for "may this run?".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Final, Protocol

from arachne.core.audit import AuditAction, AuditOutcome
from arachne.core.errors import ArachneError
from arachne.core.lifecycle import StepContext
from arachne.core.logging import get_logger
from arachne.core.planner import MODULE_STEP, ScanPlan, ScanStep
from arachne.core.target import ModuleSelection, ScanOptions, ScanRequest
from arachne.modules.context import ModuleConfig
from arachne.modules.registry import ModuleRegistry
from arachne.reasoning.index import CheckIndex
from arachne.reasoning.model import (
    Hypothesis,
    HypothesisBudget,
    HypothesisMode,
    HypothesisOutcome,
)

__all__ = [
    "ExecutionOutcome",
    "HypothesisExecutor",
    "HypothesisGate",
    "Refusal",
]

_logger = get_logger("reasoning.executor")

#: The asset kinds a hypothesis may name in the ``kind:value`` form (the ``assets.kind``
#: vocabulary of :func:`arachne.core.steps.seed_asset`).
_ASSET_KINDS: Final[frozenset[str]] = frozenset(
    {"url", "host", "domain", "domain_pattern", "network", "ip", "git", "cloud"}
)


class HypothesisGate(Protocol):
    """The gate a probe must pass: the orchestrator's own planning path.

    Typed as a protocol rather than imported from ``core.orchestrator`` so the reasoning layer
    never imports the orchestrator (which imports the module layer). The only implementation
    that matters — and the only one the wiring passes — is
    :meth:`arachne.core.orchestrator.Orchestrator.plan_hypothesis`.
    """

    def plan_hypothesis(self, request: ScanRequest) -> ScanPlan: ...


@dataclass(frozen=True, slots=True)
class Refusal:
    """Why a proposal was not executed. ``code`` is machine-readable; ``reason`` is for a human."""

    code: str
    reason: str


@dataclass(frozen=True, slots=True)
class ExecutionOutcome:
    """What one executed probe produced."""

    outcome: HypothesisOutcome
    reason: str = ""
    probes: int = 0
    produced: tuple[int, ...] = ()
    detail: dict[str, Any] = field(default_factory=dict)


class HypothesisInterrupted(ArachneError):  # noqa: N818 - a pause is not an error condition
    """Raised when the operator's kill switch stopped the run (REQ-AGENT-007).

    A distinct exception, not a bare ``ArachneError``: the lifecycle machine fails the step and
    fails the scan, which is exactly the state a resume continues from, and the step handler
    records ``paused``/``aborted`` in the journal *before* this is raised.
    """


class HypothesisExecutor:
    """Validates and runs hypotheses through the orchestrator's gates."""

    def __init__(
        self,
        *,
        ctx: StepContext,
        index: CheckIndex,
        registry: ModuleRegistry,
        findings: Any,
        gate: HypothesisGate,
        config: ModuleConfig | None = None,
        osint: Any = None,
        callback_service: Any = None,
        approved: tuple[str, ...] = (),
    ) -> None:
        self.ctx = ctx
        self.index = index
        self.registry = registry
        self.findings = findings
        self.gate = gate
        self.config = config or ModuleConfig()
        self.osint = osint
        self.callback_service = callback_service
        self.approved = frozenset(approved)
        #: Pages fetched by the one shared crawl a web hypothesis needs, for the step's stats.
        self.crawl_pages = 0

    # ------------------------------------------------------------------ validation
    def validate(self, hypothesis: Hypothesis, *, budget: HypothesisBudget) -> Refusal | None:
        """The four boundaries, in order. ``None`` means "this proposal may run"."""
        entry = self.index.get(hypothesis.check_id)
        if entry is None:
            return Refusal(
                "unknown-check",
                f"{hypothesis.check_id!r} is not a check in this build's catalogue",
            )
        if self.registry.get(hypothesis.check_id) is None:
            return Refusal(
                "not-implemented",
                f"{hypothesis.check_id!r} is catalogued but this build cannot execute it",
            )
        asset = self._resolve_asset(hypothesis.asset)
        if asset is None:
            return Refusal(
                "unknown-asset",
                f"{hypothesis.asset!r} is not an asset this scan knows; a hypothesis may not "
                "introduce a target",
            )
        kind, value = asset
        decision = self.ctx.scope.check_value(kind, value)
        if not decision.allowed:
            return Refusal(
                "out-of-scope",
                f"{hypothesis.check_id} on {value}: {decision.reason}",
            )
        proof_refusal = self._check_proof(entry)
        if proof_refusal is not None:
            return proof_refusal
        probes = self._probes_for(entry.estimated_requests)
        if not budget.affords(probes=probes):
            return Refusal(
                "budget-exhausted",
                f"the per-scan hypothesis budget allows {budget.hypotheses_left} more "
                f"hypothesis(es) and {budget.probes_left} probe(s); this one needs {probes}",
            )
        return None

    def _check_proof(self, entry: Any) -> Refusal | None:
        """L2+ needs approval; L3/L4 additionally needs the state-change attestation."""
        if entry.is_state_change:
            attestation = self.ctx.definition.attestation
            authorized = bool(attestation is not None and attestation.state_changes_authorized)
            if entry.id not in self.approved:
                return Refusal(
                    "approval-required",
                    f"{entry.id} is an {entry.proof} state-changing proof; it needs the "
                    "operator's explicit approval (options.proof_approved)",
                )
            if not authorized:
                return Refusal(
                    "proof-not-attested",
                    f"{entry.id} is an {entry.proof} proof but the attestation does not "
                    "authorize state changes",
                )
        elif entry.needs_approval and entry.id not in self.approved:
            return Refusal(
                "approval-required",
                f"{entry.id} runs at {entry.proof}; out-of-band hypotheses need the "
                "operator's explicit approval (options.proof_approved)",
            )
        if entry.requires_active_checks and not self._active_authorized():
            return Refusal(
                "active-checks-not-authorized",
                f"{entry.id} requires active checks, which this scan has not opted into and "
                "the attestation does not authorize",
            )
        return None

    def _active_authorized(self) -> bool:
        if not self.ctx.options.active_checks:
            return False
        attestation = self.ctx.definition.attestation
        return bool(attestation is not None and attestation.active_checks_authorized)

    def _resolve_asset(self, value: str) -> tuple[str, str] | None:
        """A proposal's asset → the recorded ``(kind, value)``, or ``None``.

        Matching is by exact value first (the form the findings use), then by the
        ``kind:value`` form a hypothesis may carry. There is no normalisation beyond that: if
        the scan did not record the asset, the agent may not reach for it.
        """
        records = self.ctx.store.list_assets(self.ctx.scan_id)
        for record in records:
            if record.value == value:
                return (record.kind, record.value)
        kind, _, rest = value.partition(":")
        if kind in _ASSET_KINDS and rest:
            for record in records:
                if record.kind == kind and record.value == rest:
                    return (kind, rest)
        return None

    @staticmethod
    def _probes_for(estimated: int) -> int:
        """The probe cost charged against the budget (at least one, never negative)."""
        return max(1, int(estimated))

    # ------------------------------------------------------------------ execution
    async def execute(self, hypothesis: Hypothesis) -> ExecutionOutcome:
        """Plan the probe through the gate, then run it through the checks engine."""
        entry = self.index.get(hypothesis.check_id)
        if entry is None:  # pragma: no cover - validate() ran first
            return ExecutionOutcome(HypothesisOutcome.REFUSED, "unknown-check")
        request = self._subset_request(hypothesis.check_id)
        try:
            plan = self.gate.plan_hypothesis(request)
        except ArachneError as exc:
            # A gate refusal (scope, attestation, proof) is a decision, not a crash: the
            # orchestrator already audited the refusal.
            return ExecutionOutcome(HypothesisOutcome.REFUSED, f"gate: {exc}", probes=0)
        planned = self._planned_check(plan, hypothesis.check_id)
        if planned is None or not planned.included:
            reason = "the planner did not include the probe"
            if planned is not None and planned.skip_code:
                reason = f"{planned.skip_code}: {planned.skip_reason or 'withheld'}"
            return ExecutionOutcome(HypothesisOutcome.REFUSED, reason, probes=0)

        await self._ensure_crawl(entry.module)
        before = {record.id for record in self.findings.list_candidates(self.ctx.scan_id)}
        previous_options = self.ctx.options
        self.ctx.options = request.options
        try:
            stats = await self._run_probe(entry.module)
        finally:
            self.ctx.options = previous_options
        after = {record.id for record in self.findings.list_candidates(self.ctx.scan_id)}
        produced = tuple(sorted(after - before))
        probes = self._probes_for(entry.estimated_requests)
        if not stats.get("checks_run"):
            return ExecutionOutcome(
                HypothesisOutcome.SKIPPED,
                "the check supports no asset in this scan",
                probes=probes,
                detail={"check_stats": _small(stats)},
            )
        return ExecutionOutcome(
            HypothesisOutcome.EXECUTED,
            "",
            probes=probes,
            produced=produced,
            detail={"check_stats": _small(stats), "candidates": len(produced)},
        )

    def _subset_request(self, check_id: str) -> ScanRequest:
        """The probe's own request: the same target and scope, an exact one-check allowlist."""
        options: ScanOptions = self.ctx.options.model_copy(
            update={
                # ``only`` bounds the probe to this one check; ``checks`` names it, which is
                # what an opt-in (S7) or an L3/L4 check needs before the planner will consider
                # it at all. The proof gate still decides whether an L3/L4 probe may run.
                "modules": ModuleSelection(only=(check_id,), checks=(check_id,)),
                # The nested plan is only ever planned, never run as a scan: leaving the mode
                # off makes that structural, so a probe can never spawn a hypothesis run.
                "hypotheses": HypothesisMode.OFF,
            }
        )
        return ScanRequest(target=self.ctx.definition, options=options)

    @staticmethod
    def _planned_check(plan: ScanPlan, check_id: str) -> Any | None:
        for check in plan.checks:
            if f"{check.module.lower()}.{check.name}" == check_id:
                return check
        return None

    async def _run_probe(self, module: str) -> dict[str, Any]:
        """Run one check through the same engine the checks step uses (no second path)."""
        from arachne.modules.handlers import run_checks

        return await run_checks(
            self.ctx,
            step=MODULE_STEP[module],
            registry=self.registry,
            findings=self.findings,
            osint=self.osint,
            config=self.config,
            callback_service=self.callback_service,
        )

    async def _ensure_crawl(self, module: str) -> None:
        """Crawl once when a proposed check reads the web surface (REQ-AGENT-001 execution).

        A hypothesis step sits *after* the checks step, so ``ctx.web`` is long gone. A web
        check without a crawl would silently skip itself, which would make the whole web half
        of the hypothesis engine a no-op — so the crawl is redone here, once per hypothesis
        step, through the same scoped client, bounds and audit trail as the checks step's.
        """
        if self.ctx.web is not None or self.ctx.http is None:
            return
        if MODULE_STEP.get(module) is not ScanStep.CHECKS:
            return
        from arachne.modules.handlers import crawl_web_surface

        inventory = await crawl_web_surface(self.ctx, self.config)
        self.ctx.web = inventory
        self.ctx.web_baseline = inventory
        self.crawl_pages = len(inventory.order)
        _logger.info(
            "hypothesis crawl completed",
            extra={
                "event": "hypothesis.crawl",
                "scan_id": self.ctx.scan_id,
                "pages": self.crawl_pages,
            },
        )


def _small(stats: dict[str, Any]) -> dict[str, Any]:
    """A few counters from a check run, for the journal (never the payloads)."""
    keys = ("checks_selected", "checks_run", "checks_skipped", "checks_failed", "candidates")
    return {key: stats.get(key) for key in keys if key in stats}


def audit_refusal(ctx: StepContext, hypothesis: Hypothesis, refusal: Refusal) -> None:
    """One audit line per refused proposal (REQ-AGENT-005: every refusal is recorded)."""
    ctx.auditor.record(
        AuditAction.HYPOTHESIS_REFUSED,
        outcome=AuditOutcome.BLOCKED,
        scan_id=ctx.scan_id,
        target=hypothesis.asset,
        reason=refusal.reason,
        meta={
            "check": hypothesis.check_id,
            "code": refusal.code,
            "source": hypothesis.source,
            "kind": hypothesis.kind.value,
        },
    )
