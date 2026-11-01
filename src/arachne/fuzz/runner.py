"""The bounded fuzzing runner (S30, area FUZZ, REQ-FUZZ-001...005).

This is where the area's rules are actually enforced, in one place, on the path every case takes:

1. **Authorization first, and nothing before it.** :func:`~arachne.fuzz.attestation.authorize_fuzz`
   runs before any client is constructed, so an unattested request cannot even reach the code
   that could open a socket. It audits its refusal itself.
2. **Inherited gates, not re-implemented ones.** Every case goes out through
   :class:`~arachne.core.net.ScopedNetClient` or :class:`~arachne.core.http.ScopedHttpClient` —
   the same two clients every other capability uses — so the scope allowlist, the address policy,
   the air-gap allowlist, the per-host rate limiter and the audit line (``net.probe`` /
   ``http.request``) are inherited rather than re-derived. The runner adds no egress of its own.
3. **Hard budgets.** A :class:`~arachne.fuzz.bounds.BudgetLedger` is asked *before* each request
   and every send spends against it, so a bound is enforced on the intent rather than discovered
   in the totals. Exhausting one ends the run and still produces a report.
4. **Health before and after every batch, and inside it.** A batch is bracketed by health probes
   and interleaved with more, and the guard is re-judged after every case. The first degradation
   signal stops the run — for *all* remaining targets, because a fuzzer that has just made one
   service struggle should not move on to the next.
5. **Candidates, never findings.** The runner writes :class:`~arachne.fuzz.candidates.FuzzCandidate`
   records and audits ``fuzz.candidate``. It never constructs a ``CheckResult``, so there is no
   path from area FUZZ to a reported vulnerability: only the proof ladder reports.

The one thing the runner does *not* decide is which mutations to try — that is the engine's job
(:mod:`arachne.fuzz.engines`), and the engine sees neither the budget, nor the network, nor the
audit trail.
"""

from __future__ import annotations

import hashlib
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Final

from arachne.core.audit import AuditAction, Auditor, AuditOutcome
from arachne.core.config import Settings
from arachne.core.errors import (
    ArachneError,
    FuzzBudgetExhaustedError,
    FuzzPayloadRefused,
    NetProbeError,
    OutOfScopeError,
    SafetyError,
)
from arachne.core.events import Event, EventBus
from arachne.core.http import ScopedHttpClient
from arachne.core.net import ScopedNetClient
from arachne.core.safety import Scope
from arachne.core.target import TargetDefinition
from arachne.fuzz.attestation import FuzzAuthorization, FuzzingAttestation, authorize_fuzz
from arachne.fuzz.bounds import (
    STOP_ABORTED,
    STOP_BUDGET,
    STOP_COMPLETED,
    BudgetLedger,
    FuzzBudget,
)
from arachne.fuzz.candidates import (
    SIGNAL_CONFIDENCE,
    CandidateSignal,
    CandidateStatus,
    FuzzCandidate,
    candidate_id,
    preview_hex,
)
from arachne.fuzz.engines import (
    DEFAULT_ENGINE,
    OUTCOME_ANSWERED,
    OUTCOME_ERROR,
    OUTCOME_REFUSED,
    OUTCOME_TIMEOUT,
    CaseOutcome,
    FuzzEngine,
    fingerprint,
    get_engine,
)
from arachne.fuzz.grammar import FuzzCase, MessageGrammar
from arachne.fuzz.health import (
    DEFAULT_PROBE_INTERVAL,
    DegradationPolicy,
    HealthBaseline,
    HealthSample,
    HealthWindow,
    health_sample,
    transport_failure,
)
from arachne.fuzz.http_params import (
    HttpFuzzCase,
    HttpFuzzPlan,
    HttpParameter,
    HttpReading,
    http_cases,
    load_fuzz_payloads,
    read_http_response,
    verifier_for,
)
from arachne.fuzz.prohibitions import ProhibitionSummary, require_non_destructive
from arachne.fuzz.wire import get_grammar

__all__ = [
    "BASELINE_PROBES",
    "FuzzPlan",
    "FuzzReport",
    "FuzzRunner",
    "TargetReport",
    "WireTargetSpec",
]

#: How many health probes establish the baseline a batch is judged against. Three, so the
#: median latency has something to be a median *of*.
BASELINE_PROBES: Final = 3


@dataclass(frozen=True, slots=True)
class WireTargetSpec:
    """One wire-protocol endpoint a run fuzzes."""

    label: str
    grammar: str
    host: str
    port: int
    transport: str = "tcp"
    #: The asset the hypothesis pipeline knows this endpoint by. Defaults to ``host:port``.
    asset: str | None = None
    #: Overrides the grammar's own verifier, for a deployment that knows a better check.
    verifier: str | None = None
    notes: str = ""

    @property
    def resolved_asset(self) -> str:
        return self.asset or f"{self.host}:{self.port}"

    @property
    def target(self) -> str:
        return f"{self.host}:{self.port}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "grammar": self.grammar,
            "host": self.host,
            "port": self.port,
            "transport": self.transport,
            "asset": self.resolved_asset,
            "verifier": self.verifier,
        }


@dataclass(frozen=True, slots=True)
class FuzzPlan:
    """A bounded fuzzing run: the targets, the grant, and the ceiling.

    The definition carries the *scan's* attestation (the inherited gate) and this plan carries
    the fuzzing one (the area's own). Both are required; neither substitutes for the other.
    """

    definition: TargetDefinition
    attestation: FuzzingAttestation | None
    wire_targets: tuple[WireTargetSpec, ...] = ()
    http_plans: tuple[HttpFuzzPlan, ...] = ()
    #: The plan's requested ceiling. Clamped to the deployment's, never raised above it.
    budget: FuzzBudget | None = None
    engine: str | None = None
    scan_id: int | None = None
    run_id: str = field(default_factory=lambda: f"fz-{uuid.uuid4().hex[:12]}")
    notes: str = ""

    @property
    def target_count(self) -> int:
        return len(self.wire_targets) + len(self.http_plans)

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "scan_id": self.scan_id,
            "definition": self.definition.name,
            "engine": self.engine or DEFAULT_ENGINE,
            "budget": self.budget.to_dict() if self.budget is not None else None,
            "wire_targets": [target.to_dict() for target in self.wire_targets],
            "http_plans": [plan.to_dict() for plan in self.http_plans],
            "notes": self.notes,
        }


@dataclass(frozen=True, slots=True)
class TargetReport:
    """What happened to one target."""

    label: str
    kind: str
    target: str
    asset: str
    protocol: str
    engine: str
    baseline: HealthBaseline
    cases_planned: int = 0
    cases_run: int = 0
    requests: int = 0
    payloads_refused: int = 0
    batches: int = 0
    candidates: tuple[FuzzCandidate, ...] = ()
    health_after: tuple[HealthSample, ...] = ()
    aborted: bool = False
    abort_reasons: tuple[str, ...] = ()
    stop_reason: str = STOP_COMPLETED
    refusals: tuple[str, ...] = ()
    ledger: dict[str, Any] = field(default_factory=dict)

    @property
    def healthy_after(self) -> bool:
        """True when every post-batch probe was healthy — the REQ-FUZZ-002 evidence."""
        return bool(self.health_after) and all(sample.ok for sample in self.health_after)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "label": self.label,
            "kind": self.kind,
            "target": self.target,
            "asset": self.asset,
            "protocol": self.protocol,
            "engine": self.engine,
            "baseline": self.baseline.to_dict(),
            "cases_planned": self.cases_planned,
            "cases_run": self.cases_run,
            "requests": self.requests,
            "payloads_refused": self.payloads_refused,
            "batches": self.batches,
            "candidates": [candidate.to_dict() for candidate in self.candidates],
            "candidate_count": len(self.candidates),
            "health_after": [sample.to_dict() for sample in self.health_after],
            "healthy_after": self.healthy_after,
            "aborted": self.aborted,
            "stop_reason": self.stop_reason,
            "ledger": self.ledger,
        }
        if self.abort_reasons:
            payload["abort_reasons"] = list(self.abort_reasons)
        if self.refusals:
            payload["refusals"] = list(self.refusals)
        return payload


@dataclass(frozen=True, slots=True)
class FuzzReport:
    """The whole run, as a report renders it."""

    run_id: str
    status: str
    aborted: bool
    started_at: datetime
    finished_at: datetime
    authorization: FuzzAuthorization | None = None
    definition: str = ""
    engine: str = DEFAULT_ENGINE
    engine_description: str = ""
    budget: FuzzBudget | None = None
    targets: tuple[TargetReport, ...] = ()
    refusal_reason: str | None = None
    prohibitions: ProhibitionSummary = field(default_factory=ProhibitionSummary)
    notes: str = ""

    @property
    def candidates(self) -> tuple[FuzzCandidate, ...]:
        return tuple(
            candidate for target in self.targets for candidate in target.candidates
        )

    @property
    def cases_run(self) -> int:
        return sum(target.cases_run for target in self.targets)

    @property
    def healthy_after(self) -> bool:
        """True when every target that was fuzzed was healthy at the end of it."""
        fuzzed = [target for target in self.targets if target.cases_run]
        return bool(fuzzed) and all(target.healthy_after for target in fuzzed)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "run_id": self.run_id,
            "status": self.status,
            "aborted": self.aborted,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat(),
            "definition": self.definition,
            "engine": self.engine,
            "engine_description": self.engine_description,
            "budget": self.budget.to_dict() if self.budget is not None else None,
            "targets": [target.to_dict() for target in self.targets],
            "candidate_count": len(self.candidates),
            "cases_run": self.cases_run,
            "healthy_after": self.healthy_after,
            "prohibitions": self.prohibitions.to_dict(),
            "notes": self.notes,
        }
        if self.authorization is not None:
            payload["authorization"] = self.authorization.to_dict()
        if self.refusal_reason:
            payload["refusal_reason"] = self.refusal_reason
        return payload


class FuzzRunner:
    """Runs a bounded fuzzing plan. One instance per run.

    Every collaborator is injectable — the clients (so a test can use a scripted transport), the
    clock (so a test can prove the time budget without sleeping), the engine, and the payload
    corpus — because the interesting properties of a fuzzer are all about what it *stops* doing,
    and proving a stop is much easier against a controllable clock and transport than against a
    real one.
    """

    def __init__(
        self,
        *,
        settings: Settings,
        scope: Scope,
        auditor: Auditor,
        bus: EventBus | None = None,
        run_id: str | None = None,
        clock: Callable[[], float] = time.monotonic,
        net_factory: Callable[[Scope], ScopedNetClient] | None = None,
        http_factory: Callable[[Scope], ScopedHttpClient] | None = None,
        engine: FuzzEngine | None = None,
        payloads_path: str | None = None,
        probe_interval: int = DEFAULT_PROBE_INTERVAL,
    ) -> None:
        self.settings = settings
        self.scope = scope
        self.auditor = auditor
        self.bus = bus
        self.run_id = run_id
        self._clock = clock
        self._net_factory = net_factory
        self._http_factory = http_factory
        self._engine = engine
        self.payloads_path = payloads_path
        self.probe_interval = max(1, probe_interval)
        self._net: ScopedNetClient | None = None
        self._http: ScopedHttpClient | None = None
        self._engine_used: FuzzEngine | None = None

    # ------------------------------------------------------------------ run
    async def run(self, plan: FuzzPlan) -> FuzzReport:
        """Authorize, then fuzz every target within the bounds. Never raises for a target."""
        run_id = plan.run_id or self.run_id or f"fz-{uuid.uuid4().hex[:12]}"
        started = datetime.now(UTC)
        engine = self._engine or get_engine(plan.engine or self.settings.fuzz.engine)
        self._engine_used = engine
        ceiling = FuzzBudget.from_settings(self.settings.fuzz)
        requested = plan.budget or ceiling
        budget = ceiling.narrowed(
            max_cases=requested.max_cases,
            max_requests=requested.max_requests,
            max_seconds=requested.max_seconds,
            batch_size=requested.batch_size,
        )

        authorization = authorize_fuzz(
            plan.definition,
            plan.attestation,
            settings=self.settings.fuzz,
            auditor=self.auditor,
            run_id=run_id,
        )
        # The grant's own bounds are a ceiling too, and they win over the plan's request: an
        # authorization that says "at most 20 cases" is not advice a plan may override.
        if authorization.overrides:
            budget = budget.narrowed(**authorization.overrides)  # type: ignore[arg-type]
        if self.bus is not None:
            await self.bus.emit(
                self._started_event(plan, run_id, engine, plan.target_count)
            )

        policy = DegradationPolicy.from_settings(self.settings.fuzz)
        targets: list[TargetReport] = []
        stop_reason = STOP_COMPLETED
        for spec in plan.wire_targets:
            report, stop_reason = await self._run_wire(
                plan, spec, budget=budget, policy=policy, engine=engine, run_id=run_id
            )
            targets.append(report)
            if stop_reason != STOP_COMPLETED:
                break
        if stop_reason == STOP_COMPLETED:
            for http_plan in plan.http_plans:
                report, stop_reason = await self._run_http(
                    plan, http_plan, budget=budget, policy=policy, run_id=run_id
                )
                targets.append(report)
                if stop_reason != STOP_COMPLETED:
                    break

        aborted = stop_reason == STOP_ABORTED
        fuzz_report = FuzzReport(
            run_id=run_id,
            status=stop_reason,
            aborted=aborted,
            started_at=started,
            finished_at=datetime.now(UTC),
            authorization=authorization,
            definition=plan.definition.name,
            engine=engine.name,
            engine_description=getattr(engine, "description", ""),
            budget=budget,
            targets=tuple(targets),
            prohibitions=ProhibitionSummary(),
            notes=plan.notes,
        )
        self._audit_finish(fuzz_report, plan, run_id)
        if self.bus is not None:
            await self.bus.emit(
                self._finished_event(fuzz_report, plan, run_id, aborted, stop_reason)
            )
        return fuzz_report

    # ------------------------------------------------------------------ wire
    async def _run_wire(
        self,
        plan: FuzzPlan,
        spec: WireTargetSpec,
        *,
        budget: FuzzBudget,
        policy: DegradationPolicy,
        engine: FuzzEngine,
        run_id: str,
    ) -> tuple[TargetReport, str]:
        grammar = get_grammar(spec.grammar)
        verifier = spec.verifier if spec.verifier is not None else grammar.verifier
        ledger = BudgetLedger(budget, clock=self._clock)
        try:
            cases = engine.plan(grammar, limit=budget.max_cases)
        except FuzzPayloadRefused as exc:
            return (
                self._empty_report(
                    spec.label,
                    "wire",
                    spec.target,
                    spec.resolved_asset,
                    grammar.protocol,
                    engine.name,
                    ledger,
                    refusals=(f"the engine's case plan was refused: {exc.reason}",),
                ),
                STOP_COMPLETED,
            )
        client = self._net_client()
        baseline, refusals = await self._wire_baseline(client, spec, grammar, ledger)
        if refusals:
            return (
                self._empty_report(
                    spec.label,
                    "wire",
                    spec.target,
                    spec.resolved_asset,
                    grammar.protocol,
                    engine.name,
                    ledger,
                    baseline=baseline,
                    refusals=refusals,
                ),
                STOP_COMPLETED,
            )
        if not baseline.ok:
            reason = (
                f"{spec.label}: the target did not pass its own health probe before fuzzing "
                f"({len(baseline.failures)} of {len(baseline.samples)} probes failed), so the run "
                f"refused to start against it"
            )
            self._audit(
                AuditAction.FUZZ_REFUSED,
                outcome=AuditOutcome.BLOCKED,
                target=spec.target,
                reason=reason,
                meta={"run_id": run_id, "label": spec.label},
            )
            return (
                self._empty_report(
                    spec.label,
                    "wire",
                    spec.target,
                    spec.resolved_asset,
                    grammar.protocol,
                    engine.name,
                    ledger,
                    baseline=baseline,
                    refusals=(reason,),
                ),
                STOP_COMPLETED,
            )

        window = HealthWindow(policy, baseline=baseline)
        candidates: list[FuzzCandidate] = []
        health_after: list[HealthSample] = []
        abort_reasons: tuple[str, ...] = ()
        stop_reason = STOP_COMPLETED
        cases_run = 0
        batches = 0
        queue: list[FuzzCase] = list(cases)
        index = 0
        while index < len(queue):
            case = queue[index]
            index += 1
            # A batch boundary: probe, and confirm the previous batch left the service healthy.
            if cases_run % budget.batch_size == 0:
                if batches:
                    sample = await self._wire_probe(client, spec, grammar, ledger)
                    health_after.append(sample)
                    self._audit_health(sample, spec.target, run_id, batch=batches)
                    if not sample.ok:
                        abort_reasons = (
                            f"the post-batch health probe failed ({sample.outcome}: "
                            f"{sample.detail or 'no detail'})",
                        )
                        stop_reason = STOP_ABORTED
                        break
                window.reset()
                before = await self._wire_probe(client, spec, grammar, ledger)
                self._audit_health(before, spec.target, run_id, batch=batches + 1, phase="before")
                if not before.ok:
                    abort_reasons = (
                        f"the pre-batch health probe failed ({before.outcome}: "
                        f"{before.detail or 'no detail'})",
                    )
                    stop_reason = STOP_ABORTED
                    break
                batches += 1

            if not self._payload_allowed(
                case.payload, grammar, spec.target, engine, ledger, run_id
            ):
                continue
            if not ledger.affords(requests=1):
                stop_reason = STOP_BUDGET
                self._audit_budget(ledger, spec.target, run_id)
                break
            outcome, case_candidate, extra = await self._excite_wire(
                client, spec, grammar, case, ledger, verifier, run_id
            )
            cases_run += 1
            if case_candidate is not None:
                candidates.append(case_candidate)
                self._audit_candidate(case_candidate, run_id)
            for extra_case in extra:
                queue.append(extra_case)
            if outcome.outcome in (OUTCOME_TIMEOUT, OUTCOME_ERROR):
                sample = transport_failure(
                    spec.target,
                    at=self._clock(),
                    outcome=outcome.outcome,
                    latency_s=outcome.latency_s,
                    detail=outcome.detail,
                )
                verdict = window.record(sample)
                if verdict.degraded:
                    abort_reasons = verdict.reasons
                    stop_reason = STOP_ABORTED
                    break
            elif cases_run % self.probe_interval == 0 and ledger.affords(requests=1):
                sample = await self._wire_probe(client, spec, grammar, ledger)
                self._audit_health(sample, spec.target, run_id, batch=batches, phase="inline")
                verdict = window.record(sample)
                if verdict.degraded:
                    abort_reasons = verdict.reasons
                    stop_reason = STOP_ABORTED
                    break

        if stop_reason == STOP_COMPLETED and cases_run:
            sample = await self._wire_probe(client, spec, grammar, ledger)
            health_after.append(sample)
            self._audit_health(sample, spec.target, run_id, batch=batches, phase="after")
            if not sample.ok:
                abort_reasons = (
                    f"the final health probe failed ({sample.outcome}: "
                    f"{sample.detail or 'no detail'})",
                )
                stop_reason = STOP_ABORTED

        report = TargetReport(
            label=spec.label,
            kind="wire",
            target=spec.target,
            asset=spec.resolved_asset,
            protocol=grammar.protocol,
            engine=engine.name,
            baseline=baseline,
            cases_planned=len(cases),
            cases_run=cases_run,
            requests=ledger.requests,
            payloads_refused=ledger.payloads_refused,
            batches=batches,
            candidates=tuple(candidates),
            health_after=tuple(health_after),
            aborted=stop_reason == STOP_ABORTED,
            abort_reasons=abort_reasons,
            stop_reason=stop_reason,
            ledger=ledger.to_dict(),
        )
        if stop_reason == STOP_ABORTED:
            self._audit_abort(report, run_id)
        return report, stop_reason

    async def _excite_wire(
        self,
        client: ScopedNetClient,
        spec: WireTargetSpec,
        grammar: MessageGrammar,
        case: FuzzCase,
        ledger: BudgetLedger,
        verifier: str | None,
        run_id: str,
    ) -> tuple[CaseOutcome, FuzzCandidate | None, tuple[FuzzCase, ...]]:
        """Send one wire case and read the answer. Never raises for a target failure."""
        started = self._clock()
        try:
            ledger.spend(requests=1)
            if spec.transport == "udp":
                datagram = await client.udp(spec.host, spec.port, case.payload)
                data = datagram.payload or b""
                answered = datagram.state == "open"
            else:
                stream = await client.tcp(spec.host, spec.port, payload=case.payload, reads=1)
                data = stream.banner
                # On TCP every request is expected to produce bytes, so an accepted connection
                # that answers *nothing* is the shape of a service that has stopped coping — a
                # transport failure, and a degradation signal. On UDP silence is a legitimate
                # answer to a query a target does not like, which is why the two differ here.
                answered = stream.is_open and bool(data)
        except (SafetyError, OutOfScopeError) as exc:
            # A refusal by *our* policy is never a target fault, and never spends the target's
            # goodwill. The egress client has already audited it (`net.blocked`/`scope.rejected`).
            return (
                CaseOutcome(
                    case_index=case.index,
                    grammar=case.grammar,
                    field=case.field,
                    operator=case.operator.value,
                    outcome=OUTCOME_REFUSED,
                    detail=str(exc),
                ),
                None,
                (),
            )
        except NetProbeError as exc:
            ledger.spend(requests=0)
            elapsed = max(0.0, self._clock() - started)
            outcome = CaseOutcome(
                case_index=case.index,
                grammar=case.grammar,
                field=case.field,
                operator=case.operator.value,
                outcome=OUTCOME_ERROR,
                latency_s=elapsed,
                detail=str(exc),
            )
            return outcome, self._wire_candidate(case, spec, verifier, outcome, run_id), ()
        except ArachneError as exc:
            ledger.spend(requests=0)
            elapsed = max(0.0, self._clock() - started)
            outcome = CaseOutcome(
                case_index=case.index,
                grammar=case.grammar,
                field=case.field,
                operator=case.operator.value,
                outcome=OUTCOME_ERROR,
                latency_s=elapsed,
                detail=str(exc),
            )
            return outcome, self._wire_candidate(case, spec, verifier, outcome, run_id), ()

        elapsed = max(0.0, self._clock() - started)
        if not answered:
            outcome = CaseOutcome(
                case_index=case.index,
                grammar=case.grammar,
                field=case.field,
                operator=case.operator.value,
                outcome=OUTCOME_TIMEOUT,
                latency_s=elapsed,
                detail="the target did not answer",
            )
            return outcome, self._wire_candidate(case, spec, verifier, outcome, run_id), ()

        reading = grammar.read_response(data)
        outcome = CaseOutcome(
            case_index=case.index,
            grammar=case.grammar,
            field=case.field,
            operator=case.operator.value,
            outcome=OUTCOME_ANSWERED,
            response_outcome=reading.outcome,
            response_bytes=len(data),
            fingerprint=fingerprint(data, detail=reading.outcome),
            latency_s=elapsed,
            detail=reading.detail,
        )
        if not reading.is_fault:
            return outcome, None, ()
        candidate = self._wire_candidate(case, spec, verifier, outcome, run_id)
        return outcome, candidate, ()

    def _wire_candidate(
        self,
        case: FuzzCase,
        spec: WireTargetSpec,
        verifier: str | None,
        outcome: CaseOutcome,
        run_id: str,
    ) -> FuzzCandidate:
        """The candidate a fault-like wire outcome produces."""
        if outcome.outcome in (OUTCOME_TIMEOUT, OUTCOME_ERROR):
            signal = CandidateSignal.NO_RESPONSE
        elif outcome.response_outcome == "fault":
            signal = CandidateSignal.FAULT
        else:
            signal = CandidateSignal.ANOMALY
        return FuzzCandidate(
            id=candidate_id(
                grammar=case.grammar,
                target=spec.target,
                field=case.field,
                operator=case.operator.value,
            ),
            run_id=run_id,
            engine=outcome.grammar,
            grammar=case.grammar,
            protocol=case.protocol,
            target=spec.target,
            asset=spec.resolved_asset,
            field=case.field,
            operator=case.operator.value,
            signal=signal,
            status=(
                CandidateStatus.PROPOSED if verifier else CandidateStatus.NEEDS_MANUAL_TRIAGE
            ),
            confidence=SIGNAL_CONFIDENCE[signal],
            observation=(
                f"{spec.transport.upper()} {spec.target}: {outcome.detail or signal.value}"
            ),
            evidence={
                "transport": spec.transport,
                "outcome": outcome.outcome,
                "response_outcome": outcome.response_outcome,
                "response_bytes": outcome.response_bytes,
                "latency_ms": round(outcome.latency_s * 1000, 1),
            },
            payload_sha256=case.payload_sha256,
            payload_bytes=len(case.payload),
            payload_preview_hex=preview_hex(case.payload),
            verifier=verifier,
            detail=outcome.detail,
        )

    async def _wire_probe(
        self,
        client: ScopedNetClient,
        spec: WireTargetSpec,
        grammar: MessageGrammar,
        ledger: BudgetLedger,
    ) -> HealthSample:
        """One well-formed health probe. A probe that cannot run is an error sample."""
        payload = grammar.health_payload()
        started = self._clock()
        try:
            # A probe costs a request but no *case*: the case budget is what an operator
            # granted for mutated messages, and letting health probes consume it would end a
            # run early for asking how the target was doing.
            ledger.spend(requests=1, cases=0)
        except FuzzBudgetExhaustedError as exc:
            return transport_failure(
                spec.target, at=self._clock(), outcome=OUTCOME_ERROR, detail=str(exc)
            )
        try:
            if spec.transport == "udp":
                datagram = await client.udp(spec.host, spec.port, payload)
                answered = datagram.replied
                data = datagram.payload or b""
            else:
                stream = await client.tcp(spec.host, spec.port, payload=payload, reads=1)
                answered = stream.is_open and bool(stream.banner)
                data = stream.banner
        except SafetyError as exc:
            return HealthSample(
                target=spec.target,
                at=self._clock(),
                outcome=OUTCOME_REFUSED,
                latency_s=max(0.0, self._clock() - started),
                detail=str(exc),
            )
        except (NetProbeError, ArachneError) as exc:
            return transport_failure(
                spec.target,
                at=self._clock(),
                outcome=OUTCOME_ERROR,
                latency_s=max(0.0, self._clock() - started),
                detail=str(exc),
            )
        elapsed = max(0.0, self._clock() - started)
        if not answered:
            # On TCP "not open" is a real answer about the service; on UDP silence is a normal
            # reply to a query a filtered target does not like, but *not* to the seed's own
            # well-formed request, which is what a health probe sends.
            return transport_failure(
                spec.target,
                at=self._clock(),
                outcome=OUTCOME_TIMEOUT,
                latency_s=elapsed,
                detail="the target did not answer the health probe",
            )
        reading = grammar.read_response(data)
        return health_sample(
            spec.target,
            at=self._clock(),
            ok=reading.is_healthy,
            latency_s=elapsed,
            detail=reading.detail or reading.outcome,
        )

    async def _wire_baseline(
        self,
        client: ScopedNetClient,
        spec: WireTargetSpec,
        grammar: MessageGrammar,
        ledger: BudgetLedger,
    ) -> tuple[HealthBaseline, tuple[str, ...]]:
        """Establish the pre-fuzzing reading, or report why the target cannot be fuzzed."""
        samples: list[HealthSample] = []
        for _ in range(BASELINE_PROBES):
            sample = await self._wire_probe(client, spec, grammar, ledger)
            samples.append(sample)
            if sample.outcome == OUTCOME_REFUSED:
                return (
                    HealthBaseline(tuple(samples)),
                    (f"{spec.label}: the egress client refused the health probe: {sample.detail}",),
                )
        return HealthBaseline(tuple(samples)), ()

    # ------------------------------------------------------------------ http
    async def _run_http(
        self,
        plan: FuzzPlan,
        http_plan: HttpFuzzPlan,
        *,
        budget: FuzzBudget,
        policy: DegradationPolicy,
        run_id: str,
    ) -> tuple[TargetReport, str]:
        client = self._http_client()
        payloads = load_fuzz_payloads(self.payloads_path)
        ledger = BudgetLedger(budget, clock=self._clock)
        cases = http_cases(http_plan, payloads, limit=budget.max_cases)
        asset = http_plan.resolved_asset
        first = http_plan.parameters[0]
        baseline_samples: list[HealthSample] = []
        baseline_reading = None
        for _ in range(BASELINE_PROBES):
            sample, reading = await self._http_probe(client, first, ledger)
            baseline_samples.append(sample)
            baseline_reading = baseline_reading or reading
        baseline = HealthBaseline(tuple(baseline_samples))
        if not baseline.ok:
            reason = (
                f"{http_plan.label}: the origin failed its baseline request "
                f"({len(baseline.failures)} of {len(baseline.samples)} failed), so the run "
                f"refused to fuzz it"
            )
            self._audit(
                AuditAction.FUZZ_REFUSED,
                outcome=AuditOutcome.BLOCKED,
                target=asset,
                reason=reason,
                meta={"run_id": run_id, "label": http_plan.label},
            )
            return (
                self._empty_report(
                    http_plan.label,
                    "http",
                    asset,
                    asset,
                    "http",
                    self._engine_used.name if self._engine_used else DEFAULT_ENGINE,
                    ledger,
                    baseline=baseline,
                    refusals=(reason,),
                ),
                STOP_COMPLETED,
            )

        window = HealthWindow(policy, baseline=baseline)
        candidates: list[FuzzCandidate] = []
        health_after: list[HealthSample] = []
        abort_reasons: tuple[str, ...] = ()
        stop_reason = STOP_COMPLETED
        cases_run = 0
        batches = 0
        baseline_status = baseline_reading.status if baseline_reading else None
        baseline_bytes = baseline_reading.length if baseline_reading else None
        baseline_latency = baseline.latency_s

        while cases_run < len(cases):
            if cases_run % budget.batch_size == 0:
                if batches:
                    sample, _ = await self._http_probe(client, first, ledger)
                    health_after.append(sample)
                    self._audit_health(sample, asset, run_id, batch=batches)
                    if not sample.ok:
                        abort_reasons = (
                            f"the post-batch health probe failed ({sample.outcome}: "
                            f"{sample.detail or 'no detail'})",
                        )
                        stop_reason = STOP_ABORTED
                        break
                window.reset()
                batches += 1
            case = cases[cases_run]
            if not self._payload_allowed(
                case.payload.encode("utf-8", "replace"),
                None,
                case.url,
                self._engine_used,
                ledger,
                run_id,
            ):
                continue
            if not ledger.affords(requests=1):
                stop_reason = STOP_BUDGET
                self._audit_budget(ledger, asset, run_id)
                break
            outcome, candidate = await self._excite_http(
                client,
                http_plan,
                case,
                ledger,
                asset,
                run_id,
                baseline_status=baseline_status,
                baseline_bytes=baseline_bytes,
                baseline_latency=baseline_latency,
            )
            cases_run += 1
            if candidate is not None:
                candidates.append(candidate)
                self._audit_candidate(candidate, run_id)
            if outcome.outcome in (OUTCOME_TIMEOUT, OUTCOME_ERROR):
                verdict = window.record(
                    transport_failure(
                        asset,
                        at=self._clock(),
                        outcome=outcome.outcome,
                        latency_s=outcome.latency_s,
                        detail=outcome.detail,
                    )
                )
                if verdict.degraded:
                    abort_reasons = verdict.reasons
                    stop_reason = STOP_ABORTED
                    break
            elif cases_run % self.probe_interval == 0 and ledger.affords(requests=1):
                sample, _ = await self._http_probe(client, first, ledger)
                self._audit_health(sample, asset, run_id, batch=batches, phase="inline")
                verdict = window.record(sample)
                if verdict.degraded:
                    abort_reasons = verdict.reasons
                    stop_reason = STOP_ABORTED
                    break

        if stop_reason == STOP_COMPLETED and cases_run:
            sample, _ = await self._http_probe(client, first, ledger)
            health_after.append(sample)
            self._audit_health(sample, asset, run_id, batch=batches, phase="after")
            if not sample.ok:
                abort_reasons = (
                    f"the final health probe failed ({sample.outcome}: "
                    f"{sample.detail or 'no detail'})",
                )
                stop_reason = STOP_ABORTED

        report = TargetReport(
            label=http_plan.label,
            kind="http",
            target=asset,
            asset=asset,
            protocol="http",
            engine=self._engine_used.name if self._engine_used else DEFAULT_ENGINE,
            baseline=baseline,
            cases_planned=len(cases),
            cases_run=cases_run,
            requests=ledger.requests,
            payloads_refused=ledger.payloads_refused,
            batches=batches,
            candidates=tuple(candidates),
            health_after=tuple(health_after),
            aborted=stop_reason == STOP_ABORTED,
            abort_reasons=abort_reasons,
            stop_reason=stop_reason,
            ledger=ledger.to_dict(),
        )
        if stop_reason == STOP_ABORTED:
            self._audit_abort(report, run_id)
        return report, stop_reason

    async def _excite_http(
        self,
        client: ScopedHttpClient,
        http_plan: HttpFuzzPlan,
        case: HttpFuzzCase,
        ledger: BudgetLedger,
        asset: str,
        run_id: str,
        *,
        baseline_status: int | None,
        baseline_bytes: int | None,
        baseline_latency: float,
    ) -> tuple[CaseOutcome, FuzzCandidate | None]:
        started = self._clock()
        headers = None
        if case.body is not None:
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
        try:
            ledger.spend(requests=1)
            exchange = await client.request(
                case.method, case.url, headers=headers, content=case.body
            )
        except SafetyError as exc:
            return (
                CaseOutcome(
                    case_index=case.index,
                    grammar=case.family,
                    field=case.parameter,
                    operator=f"{case.family}:{case.encoding}",
                    outcome=OUTCOME_REFUSED,
                    detail=str(exc),
                ),
                None,
            )
        except ArachneError as exc:
            ledger.spend(requests=0)
            elapsed = max(0.0, self._clock() - started)
            outcome = CaseOutcome(
                case_index=case.index,
                grammar=case.family,
                field=case.parameter,
                operator=f"{case.family}:{case.encoding}",
                outcome=OUTCOME_ERROR,
                latency_s=elapsed,
                detail=str(exc),
            )
            return outcome, self._http_candidate(
                case, asset, outcome, None, run_id
            )
        elapsed = max(0.0, self._clock() - started)
        ratio = (elapsed / baseline_latency) if baseline_latency > 0 else 0.0
        body = exchange.body or ""
        reading = read_http_response(
            case,
            status=exchange.status_code,
            body=body,
            payloads=load_fuzz_payloads(self.payloads_path),
            baseline_status=baseline_status,
            baseline_bytes=baseline_bytes,
            latency_ratio=ratio,
        )
        outcome = CaseOutcome(
            case_index=case.index,
            grammar=case.family,
            field=case.parameter,
            operator=f"{case.family}:{case.encoding}",
            outcome=OUTCOME_ANSWERED,
            response_outcome=reading.signal.value if reading.signal else "",
            response_bytes=len(body),
            fingerprint=fingerprint(
                body.encode("utf-8", "replace"),
                detail=str(exchange.status_code),
            ),
            latency_s=elapsed,
            detail=reading.detail,
        )
        if reading.signal is None:
            return outcome, None
        verifier = verifier_for(reading.signal) or case.verifier
        return outcome, self._http_candidate(case, asset, outcome, reading, run_id, verifier)

    def _http_candidate(
        self,
        case: HttpFuzzCase,
        asset: str,
        outcome: CaseOutcome,
        reading: HttpReading | None,
        run_id: str,
        verifier: str | None = None,
    ) -> FuzzCandidate:
        signal = (
            reading.signal
            if reading is not None and reading.signal is not None
            else CandidateSignal.NO_RESPONSE
        )
        resolved = verifier if verifier is not None else verifier_for(signal)
        return FuzzCandidate(
            id=candidate_id(
                grammar=case.family, target=asset, field=case.parameter, operator=case.encoding
            ),
            run_id=run_id,
            engine=case.family,
            grammar=case.family,
            protocol="http",
            target=case.url,
            asset=asset,
            field=case.parameter,
            operator=case.encoding,
            signal=signal,
            status=(
                CandidateStatus.PROPOSED if resolved else CandidateStatus.NEEDS_MANUAL_TRIAGE
            ),
            confidence=SIGNAL_CONFIDENCE[signal],
            observation=(
                reading.detail if reading is not None and reading.detail else outcome.detail
            ),
            evidence={
                **(reading.evidence if reading is not None else {}),
                "method": case.method,
                "payload": case.payload[:200],
                "encoding": case.encoding,
                "response_bytes": outcome.response_bytes,
                "latency_ms": round(outcome.latency_s * 1000, 1),
            },
            payload_sha256=hashlib.sha256(
                case.payload.encode("utf-8", "replace")
            ).hexdigest(),
            payload_bytes=len(case.payload.encode("utf-8", "replace")),
            payload_preview_hex=case.payload.encode("utf-8", "replace")[:512].hex(),
            verifier=resolved,
            detail=outcome.detail,
        )

    async def _http_probe(
        self,
        client: ScopedHttpClient,
        parameter: HttpParameter,
        ledger: BudgetLedger,
    ) -> tuple[HealthSample, _HttpBaseline | None]:
        """One well-formed request to the baseline URL: the origin's health, and its shape."""
        url = parameter.url
        started = self._clock()
        try:
            # A probe costs a request but no *case*: the case budget is what an operator
            # granted for mutated messages, and letting health probes consume it would end a
            # run early for asking how the target was doing.
            ledger.spend(requests=1, cases=0)
        except FuzzBudgetExhaustedError as exc:
            return (
                transport_failure(
                    url, at=self._clock(), outcome=OUTCOME_ERROR, detail=str(exc)
                ),
                None,
            )
        try:
            exchange = await client.get(url)
        except SafetyError as exc:
            return (
                HealthSample(
                    target=url,
                    at=self._clock(),
                    outcome=OUTCOME_REFUSED,
                    latency_s=max(0.0, self._clock() - started),
                    detail=str(exc),
                ),
                None,
            )
        except ArachneError as exc:
            return (
                transport_failure(
                    url,
                    at=self._clock(),
                    outcome=OUTCOME_ERROR,
                    latency_s=max(0.0, self._clock() - started),
                    detail=str(exc),
                ),
                None,
            )
        elapsed = max(0.0, self._clock() - started)
        status = exchange.status_code
        healthy = status < 500
        return (
            health_sample(
                url,
                at=self._clock(),
                ok=healthy,
                latency_s=elapsed,
                detail=f"HTTP {status}",
            ),
            _HttpBaseline(status=status, length=len(exchange.body or "")),
        )

    # ------------------------------------------------------------------ clients
    def _net_client(self) -> ScopedNetClient:
        if self._net is None:
            if self._net_factory is not None:
                self._net = self._net_factory(self.scope)
            else:
                self._net = ScopedNetClient(
                    settings=self.settings, scope=self.scope, auditor=self.auditor
                )
        return self._net

    def _http_client(self) -> ScopedHttpClient:
        if self._http is None:
            if self._http_factory is not None:
                self._http = self._http_factory(self.scope)
            else:
                self._http = ScopedHttpClient(
                    settings=self.settings,
                    scope=self.scope,
                    policy=self.settings.safety.policy,
                    auditor=self.auditor,
                )
        return self._http

    # ------------------------------------------------------------------ reporting
    def _empty_report(
        self,
        label: str,
        kind: str,
        target: str,
        asset: str,
        protocol: str,
        engine: str,
        ledger: BudgetLedger,
        *,
        baseline: HealthBaseline | None = None,
        refusals: tuple[str, ...] = (),
    ) -> TargetReport:
        return TargetReport(
            label=label,
            kind=kind,
            target=target,
            asset=asset,
            protocol=protocol,
            engine=engine,
            baseline=baseline or HealthBaseline(),
            refusals=refusals,
            ledger=ledger.to_dict(),
        )

    def _payload_allowed(
        self,
        payload: bytes,
        grammar: MessageGrammar | None,
        target: str,
        engine: FuzzEngine | None,
        ledger: BudgetLedger,
        run_id: str,
    ) -> bool:
        """The prohibition table, applied to what an *engine* built. ``False``: discard the case.

        The grammar already refuses to build a prohibited payload, so for the shipped engine this
        is redundant — and it stays because the engine is a pluggable interface (REQ-FUZZ-006) and
        a third-party one could hand the runner anything. This is the last gate before a send, and
        it is a *payload* check on the exact bytes, which is sound: unlike a scan of raw bytes for
        an operation code, it cannot be confused by a length-changing mutation.
        """
        try:
            require_non_destructive(
                payload,
                protocol=grammar.protocol if grammar is not None else None,
                source=f"engine {engine.name if engine else 'unknown'}",
            )
        except FuzzPayloadRefused as exc:
            ledger.note_refused_payload()
            self._audit(
                AuditAction.FUZZ_PAYLOAD_REFUSED,
                outcome=AuditOutcome.BLOCKED,
                target=target,
                reason=exc.reason,
                meta={
                    "run_id": run_id,
                    "bytes": len(payload),
                    "engine": engine.name if engine else None,
                    "detail": exc.reason,
                },
            )
            return False
        return True

    # ------------------------------------------------------------------ audit / events
    def _audit(
        self,
        action: AuditAction,
        *,
        outcome: AuditOutcome = AuditOutcome.ALLOWED,
        target: str,
        reason: str | None = None,
        meta: dict[str, Any] | None = None,
    ) -> None:
        self.auditor.record(action, outcome=outcome, target=target, reason=reason, meta=meta)

    def _audit_health(
        self,
        sample: HealthSample,
        target: str,
        run_id: str,
        *,
        batch: int = 0,
        phase: str = "after",
    ) -> None:
        self._audit(
            AuditAction.FUZZ_HEALTH,
            outcome=AuditOutcome.ALLOWED if sample.ok else AuditOutcome.ERROR,
            target=target,
            reason=sample.detail or None,
            meta={
                "run_id": run_id,
                "batch": batch,
                "phase": phase,
                "outcome": sample.outcome,
                "latency_ms": round(sample.latency_s * 1000, 1),
            },
        )

    def _audit_candidate(self, candidate: FuzzCandidate, run_id: str) -> None:
        self._audit(
            AuditAction.FUZZ_CANDIDATE,
            target=candidate.target,
            reason=candidate.observation or None,
            meta={
                "run_id": run_id,
                "candidate_id": candidate.id,
                "grammar": candidate.grammar,
                "field": candidate.field,
                "operator": candidate.operator,
                "signal": candidate.signal.value,
                "verifier": candidate.verifier,
                # Restated so the trail itself cannot be read as a finding.
                "is_finding": False,
            },
        )

    def _audit_budget(self, ledger: BudgetLedger, target: str, run_id: str) -> None:
        self._audit(
            AuditAction.FUZZ_BUDGET_EXHAUSTED,
            outcome=AuditOutcome.BLOCKED,
            target=target,
            reason=ledger.exhausted_reason(),
            meta={"run_id": run_id, "ledger": ledger.to_dict()},
        )

    def _audit_abort(self, report: TargetReport, run_id: str) -> None:
        self._audit(
            AuditAction.FUZZ_ABORTED,
            outcome=AuditOutcome.ERROR,
            target=report.target,
            reason="; ".join(report.abort_reasons),
            meta={
                "run_id": run_id,
                "label": report.label,
                "reasons": list(report.abort_reasons),
                "cases_run": report.cases_run,
                "requests": report.requests,
                "batches": report.batches,
            },
        )

    def _audit_finish(self, report: FuzzReport, plan: FuzzPlan, run_id: str) -> None:
        for target in report.targets:
            self._audit(
                AuditAction.FUZZ_BATCH_COMPLETE,
                target=target.target,
                meta={
                    "run_id": run_id,
                    "label": target.label,
                    "batches": target.batches,
                    "cases_run": target.cases_run,
                    "candidates": len(target.candidates),
                    "healthy_after": target.healthy_after,
                    "stop_reason": target.stop_reason,
                },
            )
        self._audit(
            AuditAction.FUZZ_FINISHED,
            outcome=AuditOutcome.ERROR if report.aborted else AuditOutcome.ALLOWED,
            target=plan.definition.name,
            reason=report.status,
            meta={
                "run_id": run_id,
                "status": report.status,
                "aborted": report.aborted,
                "cases_run": report.cases_run,
                "candidates": len(report.candidates),
                "targets": len(report.targets),
                "healthy_after": report.healthy_after,
            },
        )

    def _started_event(
        self, plan: FuzzPlan, run_id: str, engine: FuzzEngine, targets: int
    ) -> Event:
        return Event.fuzz_started(
            scan_id=plan.scan_id, run_id=run_id, engine=engine.name, targets=targets
        )

    def _finished_event(
        self,
        report: FuzzReport,
        plan: FuzzPlan,
        run_id: str,
        aborted: bool,
        stop_reason: str,
    ) -> Event:
        return Event.fuzz_finished(
            scan_id=plan.scan_id,
            run_id=run_id,
            cases=report.cases_run,
            candidates=len(report.candidates),
            aborted=aborted,
            stop_reason=stop_reason,
        )


@dataclass(frozen=True, slots=True)
class _HttpBaseline:
    """The origin's shape, for a differential."""

    status: int
    length: int


