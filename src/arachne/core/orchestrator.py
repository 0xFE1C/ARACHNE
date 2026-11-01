"""The Orchestrator (docs/spec/02- §2.1, F-01-02/03/04/09/10).

The Orchestrator owns the three gates that must all pass before a scan may touch a
network, and it owns the wiring between them:

1. **Scope gate** (F-01-02). Every declared target must be allowed by the scope compiled
   from the target definition *and* by the deployment allowlist (``ARACHNE_SCOPE_*``)
   when the deployment declares one. A refusal is audited as ``scope.rejected`` with the
   reason, and no request is ever made.
2. **Authorization gate** (F-01-09, F-08-05). A *live* scan additionally requires a
   complete, unexpired attestation covering every target; the attestation is recorded in
   the audit log. A dry run needs no attestation (it sends nothing) but reports
   ``live_ready`` and refuses anyway if the scope gate fails.
3. **Safety gate** — not here: it lives in the shared HTTP client (S1), which every
   request passes through (ADR-05). The Orchestrator only ever hands out a client bound to
   a compiled scope.

Gate 1 runs for both modes, gate 2 only for live runs; the intent is that
``--dry-run`` is a safe way to ask "what would this scan do, and am I allowed to run it?".
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from arachne.core.audit import AuditAction, Auditor, AuditOutcome, build_auditor
from arachne.core.catalog import PlanningCatalog, load_catalog
from arachne.core.config import Settings, get_settings
from arachne.core.errors import (
    AuthorizationError,
    ConfigurationError,
    OutOfScopeError,
    ScanStateError,
)
from arachne.core.events import Event, EventBus, EventType
from arachne.core.http import ScopedHttpClient
from arachne.core.lifecycle import (
    DEFAULT_PIPELINE,
    MemoryScanStateStore,
    ScanMachine,
    ScanOutcome,
    ScanRecord,
    ScanStateStore,
    ScanStatus,
    StepHandler,
)
from arachne.core.logging import get_logger
from arachne.core.net import ScopedNetClient
from arachne.core.planner import (
    MODULE_STEP,
    Planner,
    ScanPlan,
    ScanStep,
    pipeline_with_hypotheses,
)
from arachne.core.proof import ProofRefused
from arachne.core.safety import Scope
from arachne.core.target import (
    DetectionWindow,
    ScanOptions,
    ScanRequest,
    TargetDefinition,
    TargetSelector,
)
from arachne.reasoning.model import HypothesisMode

__all__ = ["Orchestrator", "ScanSession"]

_logger = get_logger("core.orchestrator")

#: Builds the HTTP client a live scan may use. Injectable so tests (and the sandboxed
#: network namespace of a later stage) can substitute one; the default is bound to the
#: compiled scope, so a handler cannot widen it.
ClientFactory = Callable[[Scope], ScopedHttpClient]
#: Same shape for the S4 network client: bound to the compiled scope, injectable for tests.
NetClientFactory = Callable[[Scope], ScopedNetClient]


@dataclass(frozen=True, slots=True)
class ScanSession:
    """What an orchestrator call returns: the plan, and the run when there was one."""

    plan: ScanPlan
    scan_id: int | None = None
    record: ScanRecord | None = None
    outcome: ScanOutcome | None = None

    @property
    def status(self) -> ScanStatus:
        if self.record is not None:
            return self.record.status
        return ScanStatus.PENDING


class Orchestrator:
    """Plans and runs scans against one store, one event bus and one audit trail."""

    def __init__(
        self,
        *,
        settings: Settings | None = None,
        catalog: PlanningCatalog | None = None,
        store: ScanStateStore | None = None,
        target_store: Any = None,
        auditor: Auditor | None = None,
        bus: EventBus | None = None,
        handlers: Mapping[ScanStep, StepHandler] | None = None,
        client_factory: ClientFactory | None = None,
        net_client_factory: NetClientFactory | None = None,
        registry: Any = None,
        pipeline: tuple[ScanStep, ...] = DEFAULT_PIPELINE,
        project_id: int | None = None,
        project_scope: Scope | None = None,
        intel_snapshot: Callable[[], Mapping[str, Any]] | None = None,
        evidence: Any = None,
        hypothesis_factory: Callable[[Any], StepHandler] | None = None,
        integrity: Any = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.catalog = catalog or load_catalog()
        self.planner = Planner(self.catalog, settings=self.settings.planner)
        self.store: ScanStateStore = store or MemoryScanStateStore()
        self.target_store = target_store
        #: The tenant this scan belongs to (F-07-06). ``None`` is the default workspace.
        self.project_id = project_id
        #: The project's own scope allowlist; ``None``/empty adds no restriction. Checked
        #: in :meth:`assert_in_scope` *after* the deployment allowlist, so a tenant can never
        #: widen what the deployment allows and the deployment can never widen a tenant.
        self.project_scope = (
            None if project_scope is None or project_scope.is_empty else project_scope
        )
        # The module registry is the executable counterpart of the catalogue (F-02-10): the
        # plan reports which planned checks this build can actually run.
        self.registry = registry if registry is not None else _default_registry()
        # The auditor persists *and* records the attestation (F-08-05), and every refusal
        # therefore lands wherever the deployment sends its audit trail.
        self.auditor = auditor or build_auditor(self.settings)
        self.bus = bus or EventBus()
        # ``None`` means "the built-in handler set for this deployment"; an empty mapping is
        # a deliberate choice by the caller and is honoured as such.
        built: Mapping[ScanStep, StepHandler] = (
            _default_handlers(self.settings, self.registry, self.auditor)
            if handlers is None
            else handlers
        )
        self.handlers: Mapping[ScanStep, StepHandler] = dict(built)
        #: The agentic hypothesis step (S21, area AGENT). It is built *here*, from a factory
        #: that receives this orchestrator, because the step's executor must plan its probes
        #: through :meth:`plan_hypothesis` — the same gates as everything else. A deployment
        #: that passes no factory has no hypothesis handler, and therefore cannot run agentic
        #: reasoning, whatever a scan's options say (there is nothing to run).
        if hypothesis_factory is not None:
            self.handlers = {
                **self.handlers,
                ScanStep.HYPOTHESIS: hypothesis_factory(self),
            }
        self.pipeline = pipeline
        #: Records the threat-intel freshness snapshot on each admitted scan (S18,
        #: REQ-INTEL-001). Injected rather than imported because it needs the feed store, and
        #: ``core`` deliberately does not depend on the data layer. ``None`` means "record
        #: nothing", which is what a dry run and the core test doubles want.
        self.intel_snapshot = intel_snapshot
        #: The evidence seam (S20, area DATA): offloads oversized payloads and enforces the
        #: project's storage quota before the finding store writes them. Injected for the
        #: same reason ``intel_snapshot`` is — it needs the data layer, which ``core`` does
        #: not import. ``None`` means every payload is written inline.
        self.evidence = evidence
        #: The tamper-evidence seam (S25, REQ-TRUST-005). The scan machine walks it to the
        #: completing scan's seal; ``None`` means the deployment has no integrity service and
        #: a completed scan is therefore not sealed.
        self.integrity = integrity
        self._client_factory = client_factory or self._default_client
        self._net_client_factory = net_client_factory or self._default_net_client

    # ------------------------------------------------------------------ gates
    def effective_scope(self, definition: TargetDefinition) -> tuple[Scope, Scope | None]:
        """Return ``(request scope, deployment allowlist)``.

        The request scope is compiled from the target definition, so every request is
        bounded by what the operator declared. The deployment allowlist is returned
        separately when the deployment declares one (an empty ``ARACHNE_SCOPE_*`` set means
        "no extra restriction, the definition is the declaration"); it is a *plan-time*
        gate — see :meth:`assert_in_scope`.
        """
        definition_scope = definition.compile_scope()
        deployment = self.settings.safety.scope
        return definition_scope, (None if deployment.is_empty else deployment)

    def assert_in_scope(self, request: ScanRequest) -> None:
        """Refuse the scan when a declared target is outside the declared scope (F-01-02).

        Three allowlists are applied, narrowest last: the target definition's own scope,
        the deployment allowlist (``ARACHNE_SCOPE_*``) and the project's scope (F-07-06).
        Every dimension must allow a selector — a tenant cannot reach past its workspace and
        a workspace cannot reach past the deployment.
        """
        definition = request.target
        scope, deployment = self.effective_scope(definition)
        for selector in definition.targets:
            self._require_selector(scope, selector, origin="target definition")
            if deployment is not None:
                self._require_selector(deployment, selector, origin="deployment scope")
            if self.project_scope is not None:
                self._require_selector(self.project_scope, selector, origin="project scope")

    def _require_selector(self, scope: Scope, selector: TargetSelector, *, origin: str) -> None:
        decision = scope.check_value(selector.kind.value, selector.value)
        if decision.allowed:
            return
        reason = f"{origin}: {decision.reason}"
        self.auditor.record(
            AuditAction.SCOPE_REJECTED,
            outcome=AuditOutcome.BLOCKED,
            target=selector.value,
            reason=reason,
            meta={"kind": selector.kind.value, "origin": origin},
        )
        _logger.warning(
            "scan refused by scope gate",
            extra={
                "event": "scope.rejected",
                "kind": selector.kind.value,
                "reason": reason,
            },
        )
        raise OutOfScopeError(
            f"target {selector.kind.value}:{selector.value} is out of scope ({reason})",
            reason=reason,
        )

    def assert_authorized(
        self, request: ScanRequest, *, purple: bool = False, now: datetime | None = None
    ) -> None:
        """Refuse a live scan without a complete attestation (F-01-09, F-08-05).

        ``purple`` (S24, REQ-VALID-001) additionally demands the detection-window
        attestation class: a purple-team replay is refused at the *authorization* gate, not
        only at the window gate, so an unwindowed run cannot even be planned.
        """
        definition = request.target
        options = request.options
        moment = now or datetime.now(UTC)
        try:
            attestation = definition.assert_authorized(
                active_checks=options.active_checks, purple=purple, now=moment
            )
        except AuthorizationError as exc:
            self.auditor.record(
                AuditAction.AUTH_REJECTED,
                outcome=AuditOutcome.BLOCKED,
                target=definition.name,
                reason=exc.reason,
                meta={"active_checks": options.active_checks, "purple": purple},
            )
            _logger.warning(
                "scan refused by authorization gate",
                extra={"event": "auth.rejected", "target": definition.name, "reason": exc.reason},
            )
            raise
        self.auditor.record(
            AuditAction.ATTESTATION_RECORDED,
            target=definition.name,
            meta=attestation.summary(),
        )

    def _oob_available(self) -> bool:
        """True when the out-of-band callback service is configured for this deployment.

        The callback base (``ARACHNE_WEB_SSRF_CALLBACK``) is what an L2 check needs; its
        *absence* downgrades an L2 check to its in-band L1 behaviour (with a recorded
        note) rather than blocking the check or, worse, upgrading anything.
        """
        return bool(self.settings.web.ssrf_callback_url)

    # ------------------------------------------------------------------ purple team (S24)
    def _purple_gate(
        self, request: ScanRequest, *, live: bool, now: datetime | None = None
    ) -> DetectionWindow | None:
        """The detection-window gate for a purple-team run (S24, REQ-VALID-001/003).

        Three refusals, all audited as ``purple.window_refused`` with the window and the
        moment:

        1. **no window** — an attestation without the detection-window class cannot
           authorize a detection test. (The authorization gate refuses this earlier and
           more loudly; this is the defence in depth for a crafted stored request.)
        2. **not open yet / already closed** — the coordinated interval is the whole point;
           a test before the defender watches, or after they have stopped, is an attack.
        3. **the map disagrees with the catalogue** — an action whose declared proof level
           differs from the check's own metadata would mislabel where on the ladder the
           test sits, so the plan is refused rather than the label being trusted.

        ``live=False`` (a dry run) reports the requirement without raising: a dry run sends
        nothing, and the operator still needs to see what a live run would need. Returns
        the window when the run may proceed.
        """
        options = request.options
        if options.purple is None:
            return None
        moment = (now or datetime.now(UTC)).astimezone(UTC)
        definition = request.target
        attestation = definition.attestation
        window = attestation.detection_window if attestation is not None else None
        from arachne.core.errors import DetectionWindowError
        from arachne.purple.attack import load_technique_map
        from arachne.purple.window import WindowState, window_payload, window_state

        problems: list[str] = []
        state = window_state(window, moment)
        if window is None:
            problems.append(
                "the target definition carries no detection-window attestation "
                "(attestation.detection_window)"
            )
        elif state is not WindowState.OPEN:
            problems.append(
                f"the coordinated detection window is {state.value} at {moment.isoformat()} "
                f"({window.starts_at.isoformat()}..{window.ends_at.isoformat()})"
            )
        technique_map = load_technique_map(self.settings.purple.map_path)
        for check_id in options.purple.actions:
            try:
                action = technique_map.require(check_id)
            except ConfigurationError as exc:
                problems.append(str(exc))
                continue
            declared = self._declared_proof_level(check_id)
            if declared is not None and declared != action.level:
                problems.append(
                    f"the purple technique map declares {check_id} at {action.level} but the "
                    f"module catalogue declares {declared}"
                )
        if not problems:
            return window
        reason = "purple-team run refused: " + "; ".join(problems)
        self.auditor.record(
            AuditAction.PURPLE_WINDOW_REFUSED,
            outcome=AuditOutcome.BLOCKED,
            target=definition.name,
            reason=reason,
            meta={
                "campaign": options.purple.campaign,
                "nonce": options.purple.nonce,
                "actions": list(options.purple.actions),
                "window": window_payload(window, moment),
                "state": state.value,
                "live": live,
                "dry_run": not live,
            },
        )
        _logger.warning(
            "purple-team run refused by the detection-window gate",
            extra={
                "event": "purple.window_refused",
                "campaign": options.purple.campaign,
                "reason": reason,
            },
        )
        if live:
            raise DetectionWindowError(reason, reason=reason)
        return None

    def _declared_proof_level(self, check_id: str) -> str | None:
        """The proof level the module catalogue declares for ``check_id`` (or ``None``)."""
        registry = self.registry
        if registry is None:
            return None
        for metadata in registry.metadata():
            if metadata.id == check_id:
                level: str = metadata.proof.value
                return level
        return None

    # ------------------------------------------------------------------ agentic (S21)
    def _agentic_enabled(self, options: ScanOptions) -> bool:
        """Whether this scan runs the hypothesis step (S21, area AGENT).

        Two conditions, both required: the scan (or the deployment default) asked for a
        hypothesis mode other than ``off``, *and* this orchestrator holds a hypothesis
        handler. The second is what makes "a deployment without the agentic wiring cannot
        reason" structural rather than a configuration convention.
        """
        if ScanStep.HYPOTHESIS not in self.handlers:
            return False
        if options.hypotheses is not HypothesisMode.OFF:
            return True
        configured = self.settings.hypotheses.mode
        return configured is not HypothesisMode.OFF

    def _pipeline_for(self, options: ScanOptions) -> tuple[ScanStep, ...]:
        """The pipeline this scan runs: the deployment's, plus the agentic step when enabled."""
        if not self._agentic_enabled(options):
            return tuple(self.pipeline)
        return pipeline_with_hypotheses(self.pipeline)

    def plan_hypothesis(self, request: ScanRequest) -> ScanPlan:
        """Plan one hypothesis probe through every gate (S21, REQ-AGENT-001/005).

        Deliberately *not* :meth:`plan`: a probe is not a scan, so it gets no new admission
        record and no ``target.loaded``/``scan.planned`` line (the hypothesis step writes its
        own ``hypothesis.*`` trail). What it does get is every gate — scope, authorization,
        engine availability, the proof gate — from the same code, in the same order. A
        refusal raises, exactly as it does on the scan path, and the caller records it as a
        refused decision rather than a crash.
        """
        definition = request.target
        options = request.options
        self.assert_in_scope(request)
        self.assert_authorized(request, purple=options.purple is not None)
        self._assert_engine_available(options.engine.value)
        self._purple_gate(request, live=True)
        scope, deployment = self.effective_scope(definition)
        active_authorized = bool(
            definition.attestation is not None and definition.attestation.active_checks_authorized
        )
        state_authorized = bool(
            definition.attestation is not None and definition.attestation.state_changes_authorized
        )
        plan = self.planner.plan(
            request,
            dry_run=False,
            scope=scope,
            deployment_scope=deployment,
            active_checks_allowed=options.active_checks and active_authorized,
            handled_steps=frozenset(self.handlers),
            implemented_checks=frozenset(self._implemented_check_keys()),
            # A probe never dispatches steps: its plan exists to answer "may this check run?".
            pipeline=(),
            oob_available=self._oob_available(),
            state_changes_authorized=state_authorized,
        )
        self._assert_proof_gate(request, plan, live=True)
        return plan

    def _assert_proof_gate(self, request: ScanRequest, plan: ScanPlan, *, live: bool) -> None:
        """The proof gate (S15, REQ-PROOF-003): L3/L4 demands a state-change attestation.

        Evaluated at plan time and re-checked at execute/resume, so an attestation that
        expired (or was never granted) after admission still stops the scan. A refusal is
        audited as ``proof.rejected`` with the reason; a dry run only *prints* the
        requirement (REQ-PROOF-004) and never sends anything anyway.
        """
        definition = request.target
        unauthorized = tuple(
            check
            for check in plan.included_checks
            if check.proof.needs_state_attestation
            and not (
                definition.attestation is not None
                and definition.attestation.state_changes_authorized
            )
        )
        if not unauthorized:
            return
        names = ", ".join(check.key for check in unauthorized)
        reason = (
            f"{len(unauthorized)} L3/L4 check(s) in the plan ({names}) require an attestation "
            "that authorizes state changes (state_changes_authorized), which this target "
            "definition does not carry"
        )
        self.auditor.record(
            AuditAction.PROOF_REJECTED,
            outcome=AuditOutcome.BLOCKED,
            target=definition.name,
            reason=reason,
            meta={
                "checks": [check.key for check in unauthorized],
                "live": live,
                "dry_run": not live,
            },
        )
        _logger.warning(
            "scan refused by proof gate",
            extra={"event": "proof.rejected", "target": definition.name, "reason": reason},
        )
        if live:
            raise ProofRefused(reason, reason=reason)

    # ------------------------------------------------------------------ planning
    def plan(self, request: ScanRequest, *, dry_run: bool, now: datetime | None = None) -> ScanPlan:
        """Run the gates and compute the plan; makes no network request (F-01-10)."""
        definition = request.target
        options = request.options
        moment = (now or datetime.now(UTC)).astimezone(UTC)

        self.auditor.record(
            AuditAction.TARGET_LOADED,
            target=definition.name,
            meta={
                "targets": [item.to_dict() for item in definition.targets],
                "exclusions": [item.to_dict() for item in definition.exclusions],
                "engine": options.engine.value,
                "dry_run": dry_run,
            },
        )
        self.assert_in_scope(request)
        if not dry_run:
            # S24 (REQ-VALID-001): purple mode is refused at the *authorization* gate when
            # the attestation carries no detection window — no window class, no detection
            # test — and then bounded by the window gate below.
            self.assert_authorized(
                request, purple=options.purple is not None, now=moment
            )
        self._assert_engine_available(options.engine.value)
        # S24 (REQ-VALID-001): a purple-team run additionally needs an *open* coordinated
        # detection window, checked on the same path that admits the scan.
        self._purple_gate(request, live=not dry_run, now=moment)

        scope, deployment = self.effective_scope(definition)
        active_authorized = bool(
            definition.attestation is not None and definition.attestation.active_checks_authorized
        )
        state_authorized = bool(
            definition.attestation is not None
            and definition.attestation.state_changes_authorized
        )
        plan = self.planner.plan(
            request,
            dry_run=dry_run,
            scope=scope,
            deployment_scope=deployment,
            active_checks_allowed=options.active_checks and active_authorized,
            handled_steps=frozenset(self.handlers),
            implemented_checks=frozenset(self._implemented_check_keys()),
            pipeline=self._pipeline_for(options),
            now=moment,
            oob_available=self._oob_available(),
            state_changes_authorized=state_authorized,
        )
        if plan.totals.proof_downgrades:
            # REQ-PROOF-003: a downgrade is recorded, never silent. (Upgrades do not exist:
            # ``proof_effective <= proof`` is a planner invariant.)
            self.auditor.record(
                AuditAction.PROOF_DOWNGRADED,
                target=definition.name,
                meta={
                    "downgrades": plan.totals.proof_downgrades,
                    "checks": [
                        check.key
                        for check in plan.included_checks
                        if check.proof_effective.rank < check.proof.rank
                    ],
                },
            )
        self._assert_proof_gate(request, plan, live=not dry_run)
        self.auditor.record(
            AuditAction.SCAN_PLANNED,
            target=definition.name,
            meta={
                "dry_run": dry_run,
                "included_checks": plan.totals.included_checks,
                "withheld_checks": plan.totals.withheld_checks,
                "planned_only_checks": plan.totals.planned_only_checks,
                "estimated_requests": plan.totals.estimated_requests,
                "live_ready": plan.live_ready,
            },
        )
        return plan

    def _initial_stats(self, base: Mapping[str, Any]) -> dict[str, Any]:
        """The scan's starting stats, including the intel snapshot when one is available.

        A broken feed store must never stop a scan from being admitted, so a failing snapshot
        is dropped rather than raised: the report then omits the freshness section, which is
        the honest outcome (no claim about data integrity is better than a false one).
        """
        stats = dict(base)
        if self.intel_snapshot is None:
            return stats
        try:
            snapshot = self.intel_snapshot()
        except Exception as exc:  # pragma: no cover - defensive: a store failure is not fatal
            self.auditor.record(
                AuditAction.INTEL_FEED_FETCHED,
                outcome=AuditOutcome.ERROR,
                target="scan-admission",
                reason=f"intel snapshot unavailable: {exc.__class__.__name__}: {exc}",
            )
            return stats
        stats["intel"] = dict(snapshot)
        return stats

    def _implemented_check_keys(self) -> tuple[str, ...]:
        """``module/name@version`` of every check this build can execute (F-02-10)."""
        registry = self.registry
        if registry is None:
            return ()
        return tuple(metadata.key for metadata in registry.metadata())

    def _assert_engine_available(self, name: str) -> None:
        """Refuse an explicit ``ai`` scan when no provider is configured (F-03-03).

        Checked at plan time, not at the analysis step, so a misconfigured deployment does not
        spend a whole scan's requests before discovering it cannot analyse them. The import is
        function-local on purpose: ``core`` does not depend on the AI layer at module level
        (the same shape as the module-handler import below).
        """
        if (name or "heuristic").lower() != "ai":
            return
        from arachne.ai.config import load_ai_config

        if load_ai_config(self.settings).configured:
            return
        msg = (
            "this scan asks for engine 'ai' but no AI provider is configured; set "
            "ARACHNE_AI_CONFIG (or ARACHNE_AI_PROVIDER/ARACHNE_AI_BASE_URL/ARACHNE_AI_MODEL), "
            "or use engine 'heuristic' or 'hybrid'"
        )
        raise ConfigurationError(msg)

    # ------------------------------------------------------------------ running
    async def scan(self, request: ScanRequest, *, dry_run: bool = False) -> ScanSession:
        """Plan and, unless ``dry_run``, execute the scan to completion."""
        plan = self.plan(request, dry_run=dry_run)
        if dry_run:
            return ScanSession(plan=plan)

        definition = request.target
        options = request.options
        scope, _ = self.effective_scope(definition)
        target_id = self._persist_target(definition)
        record = self.store.create_scan(
            target_id=target_id,
            engine=options.engine.value,
            plan=plan.to_dict(),
            stats=self._initial_stats({"target_name": definition.name, "dry_run": False}),
            project_id=self.project_id,
            request_json=request.model_dump(mode="json"),
        )
        self.auditor.record(
            AuditAction.SCAN_CREATED,
            scan_id=record.id,
            target=definition.name,
            meta={"estimated_requests": plan.totals.estimated_requests},
        )
        await self.bus.publish(
            Event(
                type=EventType.SCAN_PLANNED,
                scan_id=record.id,
                payload={
                    "target": definition.name,
                    "estimated_requests": plan.totals.estimated_requests,
                    "included_checks": plan.totals.included_checks,
                },
            )
        )
        outcome = await self._run(
            record.id,
            definition=definition,
            options=options,
            scope=scope,
            plan=plan,
            resume=False,
        )
        return ScanSession(
            plan=plan, scan_id=record.id, record=self.store.get_scan(record.id), outcome=outcome
        )

    async def launch(self, request: ScanRequest, *, requested_by: str | None = None) -> ScanSession:
        """Plan, admit and persist a scan **without running it** (the API's async start).

        The REST API must answer "accepted" before a scan that can take minutes finishes
        (S12), so admission is split from execution: ``launch`` runs every gate, writes the
        ``scans`` row and returns it in ``pending``; the caller then runs :meth:`execute` in
        the background. Behaviour is otherwise identical to :meth:`Orchestrator.scan`'s
        first half — the two share it, so a gate can never be enforced on one path only.
        The admitted request document is persisted with the row (S16), so a distributed
        worker can rebuild the very same request on another node (REQ-SCALE-006).
        ``requested_by`` (S17) records the caller's actor identity on the scan and on the
        ``scan.created`` audit event (REQ-IDAM-001/004).
        """
        plan = self.plan(request, dry_run=False)
        definition = request.target
        options = request.options
        target_id = self._persist_target(definition)
        stats = self._initial_stats({"target_name": definition.name, "dry_run": False})
        if requested_by:
            stats["requested_by"] = requested_by
        record = self.store.create_scan(
            target_id=target_id,
            engine=options.engine.value,
            plan=plan.to_dict(),
            stats=stats,
            project_id=self.project_id,
            request_json=request.model_dump(mode="json"),
        )
        self.auditor.record(
            AuditAction.SCAN_CREATED,
            scan_id=record.id,
            target=definition.name,
            meta={
                "estimated_requests": plan.totals.estimated_requests,
                "deferred": True,
                "requested_by": requested_by,
            },
        )
        await self.bus.publish(
            Event(
                type=EventType.SCAN_PLANNED,
                scan_id=record.id,
                payload={
                    "target": definition.name,
                    "estimated_requests": plan.totals.estimated_requests,
                    "included_checks": plan.totals.included_checks,
                },
            )
        )
        return ScanSession(plan=plan, scan_id=record.id, record=record)

    async def execute(self, scan_id: int, request: ScanRequest) -> ScanSession:
        """Run an already-admitted scan to completion (the pair of :meth:`launch`).

        The target definition is supplied again — the store keeps the plan, not the fixture —
        and the scope/authorization gates are re-checked, so an admitted scan cannot be
        executed after its attestation expired.
        """
        record = self.store.get_scan(scan_id)
        if record is None:
            msg = f"scan {scan_id} does not exist"
            raise ScanStateError(msg)
        definition = request.target
        self.assert_in_scope(request)
        if record.status is not ScanStatus.COMPLETED:
            self.assert_authorized(request, purple=request.options.purple is not None)
        scope, _ = self.effective_scope(definition)
        plan = self._plan_from_record(record) or self.plan(request, dry_run=False)
        # REQ-PROOF-003: the proof gate is re-checked on the executing path, against the
        # plan actually stored with the scan — an admitted scan whose attestation lapsed
        # (or never covered L3/L4) is refused here, before any handler runs.
        if record.status is not ScanStatus.COMPLETED:
            self._assert_proof_gate(request, plan, live=True)
            # S24 (REQ-VALID-001): the detection window is re-checked too — an admitted
            # purple run whose window closed while it queued must not fire (the "auto-stop
            # at window end" property, enforced on the way in as well as mid-run).
            self._purple_gate(request, live=True)
        outcome = await self._run(
            scan_id,
            definition=definition,
            options=request.options,
            scope=scope,
            plan=plan,
            resume=False,
        )
        return ScanSession(
            plan=plan, scan_id=scan_id, record=self.store.get_scan(scan_id), outcome=outcome
        )

    async def resume(self, scan_id: int, request: ScanRequest) -> ScanSession:
        """Continue an interrupted or failed scan from its last completed step (F-01-04).

        The target definition is supplied again (the fixture is the source of truth), and
        must describe the same target as the stored scan: resuming scan X with a different
        definition is refused rather than silently mixing two scans' state.
        """
        record = self.store.get_scan(scan_id)
        if record is None:
            msg = f"scan {scan_id} does not exist"
            raise ScanStateError(msg)
        definition = request.target
        stored_name = record.plan.get("target_name") if isinstance(record.plan, dict) else None
        if stored_name is not None and stored_name != definition.name:
            msg = (
                f"scan {scan_id} targets {stored_name!r}; refusing to resume it with "
                f"definition {definition.name!r}"
            )
            raise ScanStateError(msg)

        self.assert_in_scope(request)
        if record.status is not ScanStatus.COMPLETED:
            self.assert_authorized(request, purple=request.options.purple is not None)

        scope, _ = self.effective_scope(definition)
        # The plan is stored with the scan; if it cannot be re-read (older write format),
        # re-plan from the definition rather than resuming without one.
        plan = self._plan_from_record(record) or self.plan(request, dry_run=False)
        # REQ-PROOF-003: resume re-checks the proof gate exactly like execute — resumption
        # must not become the path around an attestation that no longer covers L3/L4.
        if record.status is not ScanStatus.COMPLETED:
            self._assert_proof_gate(request, plan, live=True)
            # S24: and the detection window (REQ-VALID-001/003) — a resumed purple run
            # cannot outlive the coordinated interval either.
            self._purple_gate(request, live=True)
        outcome = await self._run(
            scan_id,
            definition=definition,
            options=request.options,
            scope=scope,
            plan=plan,
            resume=True,
        )
        return ScanSession(
            plan=plan, scan_id=scan_id, record=self.store.get_scan(scan_id), outcome=outcome
        )

    # ------------------------------------------------------------------ internals
    async def _run(
        self,
        scan_id: int,
        *,
        definition: TargetDefinition,
        options: ScanOptions,
        scope: Scope,
        plan: ScanPlan | None,
        resume: bool,
    ) -> ScanOutcome:
        machine = ScanMachine(
            self.store,
            bus=self.bus,
            auditor=self.auditor,
            pipeline=self._pipeline_for(options),
            evidence=self.evidence,
            project_id=self.project_id,
            integrity=self.integrity,
        )
        # Both clients are constructed only for a live run and closed even on failure, so a
        # scan never leaks a connection pool. Each is bound to the compiled scope, which is
        # the only scope a handler can reach.
        client = self._client_factory(scope)
        net_client = self._net_client_factory(scope)
        async with client, net_client:
            return await machine.run(
                scan_id,
                self.handlers,
                definition=definition,
                options=options,
                scope=scope,
                plan=plan,
                http=client,
                net=net_client,
                resume=resume,
            )

    def _default_net_client(self, scope: Scope) -> ScopedNetClient:
        """The raw-network client a live scan uses (S4/M2): scoped, throttled, audited.

        Unlike the HTTP client there is no fixture transport: recordings of a TLS handshake
        or an SMB negotiation would prove nothing about the wire path, so M2's deterministic
        tests inject a :class:`~arachne.core.net.ScriptedNetTransport` at the *transport*
        boundary (or run against the local lab fixture) while the client itself stays real.
        """
        return ScopedNetClient(settings=self.settings, scope=scope, auditor=self.auditor)

    def _default_client(self, scope: Scope) -> ScopedHttpClient:
        """The client a live scan uses: scoped, audited, and optionally replaying fixtures.

        With ``ARACHNE_HTTP_FIXTURES`` set, the transport reads recorded responses instead of
        opening a socket. Everything else about the request path is unchanged — validation,
        scope, rate limiting, redaction, audit — so a replayed scan exercises the real code
        (docs/spec/07- §6) and a demonstration run needs no network (docs/spec/07- §9.1).
        """
        fixtures = self.settings.http_fixtures
        # The operator's masked-credential ledger (F-08-04, S7); ``None`` unless configured.
        from arachne.core.secrets import SecretsManifest

        manifest = SecretsManifest.from_settings(self.settings)
        if not fixtures:
            return ScopedHttpClient(
                settings=self.settings,
                scope=scope,
                auditor=self.auditor,
                secrets_manifest=manifest,
            )
        from arachne.core.http import fixture_transport
        from arachne.core.safety import StaticResolver
        from arachne.modules.providers.fixtures import FixtureReplay, load_fixture_routes

        replay = FixtureReplay(load_fixture_routes(fixtures))
        return ScopedHttpClient(
            settings=self.settings,
            scope=scope,
            auditor=self.auditor,
            resolver=StaticResolver(replay.address()),
            transport=fixture_transport(replay.responses()),
            secrets_manifest=manifest,
        )

    def _persist_target(self, definition: TargetDefinition) -> int | None:
        if self.target_store is None:
            return None
        if self.project_id is None:
            return int(self.target_store.save(definition))
        return int(self.target_store.save(definition, project_id=self.project_id))

    @staticmethod
    def _plan_from_record(record: ScanRecord) -> ScanPlan | None:
        if not record.plan:
            return None
        try:
            return ScanPlan.model_validate(record.plan)
        except Exception:  # a plan written by an older version must not break a resume
            _logger.warning(
                "stored plan could not be re-read",
                extra={"event": "orchestrator.plan_unreadable", "scan_id": record.id},
            )
            return None


def module_of_step(step: ScanStep) -> tuple[str, ...]:
    """Modules whose checks belong to ``step`` (used by tests and the CLI summary)."""
    return tuple(module for module, mapped in MODULE_STEP.items() if mapped is step)


def _default_registry() -> Any:
    """The installed module registry (imported lazily: the core must not hard-depend on it)."""
    from arachne.modules.registry import ModuleRegistry

    return ModuleRegistry.discover()


def _default_handlers(
    settings: Settings, registry: Any, auditor: Auditor | None = None
) -> Mapping[ScanStep, StepHandler]:
    """The handler set a scan runs when the caller does not supply one (F-01-03).

    The module-backed set (``arachne.modules.handlers``) rather than S2's offline pair: a
    scan with no module handler registers no detection work at all, which is exactly the
    state S3 ends. With OSINT disabled — the default — every M1 check reports a skipped
    result, so a default live scan still makes no request.
    """
    from arachne.modules.handlers import build_handlers

    return build_handlers(settings=settings, registry=registry, auditor=auditor)
