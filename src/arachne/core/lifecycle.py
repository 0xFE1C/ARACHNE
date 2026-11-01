"""Scan lifecycle: state machine, step persistence and resumability (F-01-03/04).

The machine is deliberately small and boring, because its whole job is to make a crash
survivable:

* **State is persisted before work, and again after it.** A step is marked ``running``
  and committed *before* its handler is invoked, so a hard kill (``SIGKILL``, power loss,
  container eviction) leaves a durable record of exactly where the scan stopped.
* **Completion is the unit of resumption.** On restart, steps in ``completed`` or
  ``skipped`` state are never re-run; the first non-terminal step is where work resumes.
  A step left in ``running`` is re-run — at-least-once, which is the correct trade for a
  scanner whose steps are reads and idempotent writes.
* **A failing step is data, not a crash.** The exception is summarized (bounded, redacted)
  into the step row and the scan is marked ``failed``; the exception is re-raised so the
  caller can decide the process exit code.
* **Orchestration state lives in the store, never in globals** (docs/spec/07- §4). The
  machine holds a :class:`ScanStateStore` and nothing else that a restart would lose.

The store is a protocol so the persistence backend is replaceable — ``SQLite`` today
(:class:`arachne.data.scan_store.SqlScanStateStore`), Postgres later — and so the dry run
can use an in-memory implementation without touching a database.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Protocol

from arachne.core.audit import AuditAction, Auditor, AuditOutcome
from arachne.core.errors import ScanStateError, error_info
from arachne.core.events import Event, EventBus, EventType
from arachne.core.logging import get_logger
from arachne.core.metrics import REGISTRY
from arachne.core.planner import DEFAULT_PIPELINE, ScanPlan, ScanStep
from arachne.core.redaction import redact_text, redact_url
from arachne.core.safety import Scope
from arachne.core.target import ScanOptions, TargetDefinition
from arachne.core.tracing import get_tracer

__all__ = [
    "DEFAULT_PIPELINE",
    "AssetRecord",
    "MemoryScanStateStore",
    "ScanMachine",
    "ScanOutcome",
    "ScanRecord",
    "ScanStateStore",
    "ScanStatus",
    "StepContext",
    "StepHandler",
    "StepOutcome",
    "StepState",
    "StepStatus",
]

_logger = get_logger("core.lifecycle")


class ScanStatus(StrEnum):
    """Lifecycle state of a scan."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    ABORTED = "aborted"


class StepStatus(StrEnum):
    """Lifecycle state of one pipeline step."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    SKIPPED = "skipped"
    FAILED = "failed"


#: Statuses that mean "this step will not be run again on resume".
_TERMINAL_STEP_STATUSES = frozenset({StepStatus.COMPLETED, StepStatus.SKIPPED})


@dataclass(frozen=True, slots=True)
class StepState:
    """Persisted state of one pipeline step (one row of ``scan_steps``)."""

    step: ScanStep
    status: StepStatus = StepStatus.PENDING
    attempts: int = 0
    started_at: datetime | None = None
    finished_at: datetime | None = None
    error: str | None = None
    stats: dict[str, Any] = field(default_factory=dict)

    @property
    def is_terminal(self) -> bool:
        return self.status in _TERMINAL_STEP_STATUSES


@dataclass(frozen=True, slots=True)
class AssetRecord:
    """A discovered/seeded asset belonging to a scan (``assets`` table)."""

    id: int | None
    scan_id: int
    kind: str
    value: str
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class ScanRecord:
    """Persisted state of one scan (``scans`` table plus its step rows)."""

    id: int
    target_id: int | None
    status: ScanStatus
    engine: str
    plan: dict[str, Any] = field(default_factory=dict)
    stats: dict[str, Any] = field(default_factory=dict)
    started_at: datetime | None = None
    finished_at: datetime | None = None
    created_at: datetime | None = None
    steps: tuple[StepState, ...] = ()
    #: The tenant/workspace this scan belongs to (F-07-06); ``None`` is the default one.
    project_id: int | None = None
    #: The admitted request document (S16, area SCALE) — target + options as the producer
    #: admitted them, so any node can rebuild the very same :class:`ScanRequest`.
    #: ``None`` for rows written before S16.
    request_json: dict[str, Any] | None = None

    def step_state(self, step: ScanStep) -> StepState | None:
        for state in self.steps:
            if state.step is step:
                return state
        return None

    @property
    def completed_steps(self) -> tuple[ScanStep, ...]:
        return tuple(state.step for state in self.steps if state.status is StepStatus.COMPLETED)

    def next_step(self, pipeline: Sequence[ScanStep] = DEFAULT_PIPELINE) -> ScanStep | None:
        """The first step that still needs to run — where a resume would continue."""
        for step in pipeline:
            state = self.step_state(step)
            if state is None or not state.is_terminal:
                return step
        return None


class ScanStateStore(Protocol):
    """Persistence boundary for scan state (F-01-04)."""

    def create_scan(
        self,
        *,
        target_id: int | None,
        engine: str,
        plan: dict[str, Any],
        stats: dict[str, Any] | None = None,
        status: ScanStatus = ScanStatus.PENDING,
        project_id: int | None = None,
        request_json: dict[str, Any] | None = None,
    ) -> ScanRecord: ...

    def get_scan(self, scan_id: int) -> ScanRecord | None: ...

    def list_scans(
        self,
        *,
        limit: int = 50,
        project_id: int | None = None,
        include_unassigned: bool = False,
    ) -> tuple[ScanRecord, ...]: ...

    def update_scan(
        self,
        scan_id: int,
        *,
        status: ScanStatus | None = None,
        stats: dict[str, Any] | None = None,
        plan: dict[str, Any] | None = None,
        mark_started: bool = False,
        mark_finished: bool = False,
    ) -> ScanRecord: ...

    def save_step(self, scan_id: int, state: StepState) -> StepState: ...

    def add_asset(
        self,
        scan_id: int,
        *,
        kind: str,
        value: str,
        meta: Mapping[str, Any] | None = None,
    ) -> AssetRecord: ...

    def list_assets(self, scan_id: int) -> tuple[AssetRecord, ...]: ...


class MemoryScanStateStore:
    """In-memory store: the dry run's store, and the fixture for lifecycle tests."""

    def __init__(self, *, clock: Any = None) -> None:
        self._clock = clock or (lambda: datetime.now(UTC))
        self._scans: dict[int, ScanRecord] = {}
        self._assets: dict[int, list[AssetRecord]] = {}
        self._next_id = 1
        self._next_asset_id = 1

    def create_scan(
        self,
        *,
        target_id: int | None,
        engine: str,
        plan: dict[str, Any],
        stats: dict[str, Any] | None = None,
        status: ScanStatus = ScanStatus.PENDING,
        project_id: int | None = None,
        request_json: dict[str, Any] | None = None,
    ) -> ScanRecord:
        record = ScanRecord(
            id=self._next_id,
            target_id=target_id,
            status=status,
            engine=engine,
            plan=dict(plan),
            stats=dict(stats or {}),
            created_at=self._clock(),
            project_id=project_id,
            request_json=dict(request_json) if request_json is not None else None,
        )
        self._scans[record.id] = record
        self._assets[record.id] = []
        self._next_id += 1
        return record

    def get_scan(self, scan_id: int) -> ScanRecord | None:
        return self._scans.get(scan_id)

    def list_scans(
        self,
        *,
        limit: int = 50,
        project_id: int | None = None,
        include_unassigned: bool = False,
    ) -> tuple[ScanRecord, ...]:
        ordered = sorted(self._scans.values(), key=lambda item: item.id, reverse=True)
        if project_id is not None:
            allowed = {project_id} | ({None} if include_unassigned else set())
            ordered = [item for item in ordered if item.project_id in allowed]
        return tuple(ordered[:limit])

    def update_scan(
        self,
        scan_id: int,
        *,
        status: ScanStatus | None = None,
        stats: dict[str, Any] | None = None,
        plan: dict[str, Any] | None = None,
        mark_started: bool = False,
        mark_finished: bool = False,
    ) -> ScanRecord:
        record = self._require(scan_id)
        updated = replace(
            record,
            status=status or record.status,
            stats=dict(stats) if stats is not None else record.stats,
            plan=dict(plan) if plan is not None else record.plan,
            started_at=(
                self._clock() if mark_started and record.started_at is None else record.started_at
            ),
            finished_at=self._clock() if mark_finished else record.finished_at,
        )
        self._scans[scan_id] = updated
        return updated

    def save_step(self, scan_id: int, state: StepState) -> StepState:
        record = self._require(scan_id)
        steps = [existing for existing in record.steps if existing.step is not state.step]
        steps.append(state)
        order = list(DEFAULT_PIPELINE)
        steps.sort(key=lambda item: order.index(item.step) if item.step in order else len(order))
        self._scans[scan_id] = replace(record, steps=tuple(steps))
        return state

    def add_asset(
        self,
        scan_id: int,
        *,
        kind: str,
        value: str,
        meta: Mapping[str, Any] | None = None,
    ) -> AssetRecord:
        self._require(scan_id)
        asset = AssetRecord(
            id=self._next_asset_id,
            scan_id=scan_id,
            kind=kind,
            value=value,
            meta=dict(meta or {}),
        )
        self._next_asset_id += 1
        self._assets.setdefault(scan_id, []).append(asset)
        return asset

    def list_assets(self, scan_id: int) -> tuple[AssetRecord, ...]:
        return tuple(self._assets.get(scan_id, ()))

    def _require(self, scan_id: int) -> ScanRecord:
        record = self._scans.get(scan_id)
        if record is None:
            msg = f"scan {scan_id} does not exist"
            raise ScanStateError(msg)
        return record


@dataclass(frozen=True, slots=True)
class StepOutcome:
    """What a step handler reports back to the machine."""

    stats: dict[str, Any] = field(default_factory=dict)
    skipped: bool = False
    note: str | None = None


@dataclass
class StepContext:
    """Everything a step handler may use.

    Handlers get the *scoped* HTTP client (never a bare library), the compiled scope, the
    event bus and the audit trail; they never receive the whole orchestrator, which keeps
    them unit-testable and stops a check from reaching past its gate.
    """

    scan_id: int
    step: ScanStep
    definition: TargetDefinition
    options: ScanOptions
    scope: Scope
    store: ScanStateStore
    bus: EventBus
    auditor: Auditor
    plan: ScanPlan | None = None
    #: Present only for a live scan; ``None`` in dry-run mode, where nothing may be sent.
    http: Any = None
    #: The raw-network counterpart of ``http`` (S4/M2): scoped, rate-limited, audited TCP/UDP/
    #: TLS probes. Also ``None`` in dry-run mode. Typed as ``Any`` because ``core`` must not
    #: import the network client's siblings in the module layer (the same reason ``http`` is).
    net: Any = None
    #: Per-step shared state for the module whose checks form a pipeline (M2's network
    #: inventory, ADR-080.2). ``None`` for a step that has no such state.
    inventory: Any = None
    #: The checks step's web crawl (S6/M3, ADR-100.2): the pages, forms, parameters and
    #: endpoints every M3 check reads instead of crawling again. ``None`` outside that step.
    web: Any = None
    #: The scan's proof journal (S15, area PROOF): the nonce→probe map, every L4 state
    #: change and its cleanup status. ``Any`` for the same reason ``http``/``net`` are —
    #: ``core`` does not import the proof services; the checks step attaches it.
    proof: Any = None
    #: The credentialed-scan state (S19, area CREDS). ``web_session`` is the authenticated
    #: web session (or ``None``); ``web_baseline`` the *unauthenticated* crawl the
    #: authenticated one is diffed against; ``credentials`` the per-scan
    #: :class:`~arachne.creds.broker.CredentialBroker` — the only thing a check may ask for
    #: authenticated reach, and never a credential itself. ``Any`` for the same reason as
    #: ``http``: ``core`` does not import the credential services.
    web_session: Any = None
    web_baseline: Any = None
    credentials: Any = None
    #: The evidence seam (S20, area DATA): the object that offloads oversized payloads and
    #: enforces the project's storage quota (``EvidenceService``). ``None`` means the step
    #: writes every payload inline, which is what a dry run and the core test doubles want.
    #: ``Any`` for the same reason as ``http``/``proof``: ``core`` does not import the data
    #: layer.
    evidence: Any = None
    #: The continuous-posture capability boundary (S23, area POSTURE): the object through
    #: which a check reads the drift baseline of *its* scope and commits a new one. ``None``
    #: means the step wired no posture store, and a continuous check then runs stateless
    #: (point-in-time policies only, with a recorded note) — never an implicit store.
    posture: Any = None
    #: The purple-team capability boundary (S24, area VALID): the object through which the
    #: checks step knows it is replaying detection tests — the run nonce every emitted
    #: artifact carries, the coordinated window (auto-stop at its end) and the per-action
    #: technique tags (REQ-VALID-001/003). ``None`` means an ordinary scan: no nonce, no
    #: technique tagging and no window. ``Any`` for the same reason as ``http``/``proof``:
    #: ``core`` does not import the purple services.
    purple: Any = None
    #: The tenant the scan belongs to, so the quota and the retention trail are attributed
    #: without a second lookup (``None`` is the implicit default workspace).
    project_id: int | None = None

    async def emit(self, event: Event) -> None:
        await self.bus.publish(event)

    async def audit(
        self,
        action: AuditAction,
        *,
        outcome: AuditOutcome = AuditOutcome.ALLOWED,
        target: str | None = None,
        reason: str | None = None,
        meta: dict[str, Any] | None = None,
    ) -> None:
        self.auditor.record(
            action, outcome=outcome, target=target, reason=reason, scan_id=self.scan_id, meta=meta
        )

    async def record_asset(
        self,
        kind: str,
        value: str,
        *,
        meta: Mapping[str, Any] | None = None,
        enforce_scope: bool = True,
        source: str | None = None,
    ) -> AssetRecord | None:
        """Persist a discovered asset, discarding it when it is out of scope (F-01-02).

        Discovery outside scope is discarded, *logged*, and never reported: the asset is
        not written, an ``out_of_scope_discarded`` event is published and a
        ``scope.discarded`` audit line is written with the reason.
        """
        if enforce_scope:
            decision = self.scope.check_value(kind, value)
            if not decision.allowed:
                await self.bus.publish(
                    Event.out_of_scope_discarded(
                        scan_id=self.scan_id, value=value, reason=decision.reason, origin=source
                    )
                )
                self.auditor.record(
                    AuditAction.SCOPE_DISCARDED,
                    outcome=AuditOutcome.BLOCKED,
                    target=value,
                    reason=decision.reason,
                    scan_id=self.scan_id,
                    meta={"kind": kind, "origin": source},
                )
                _logger.info(
                    "asset discarded as out of scope",
                    extra={
                        "event": "scope.discarded",
                        "value": redact_url(value),
                        "reason": decision.reason,
                        "scan_id": self.scan_id,
                    },
                )
                return None
        return self.store.add_asset(
            self.scan_id,
            kind=kind,
            value=value,
            meta={**(meta or {}), "source": source} if source else meta,
        )


#: A pipeline step implementation: an async callable taking the step's context. A plain
#: ``async def`` satisfies it, and S3 supplies module-backed handlers this way.
StepHandler = Callable[[StepContext], Awaitable[StepOutcome]]


@dataclass(frozen=True, slots=True)
class ScanOutcome:
    """Result of a machine run."""

    scan_id: int
    status: ScanStatus
    resumed: bool
    executed: tuple[ScanStep, ...] = ()
    skipped: tuple[ScanStep, ...] = ()
    already_completed: tuple[ScanStep, ...] = ()
    assets: int = 0
    error: str | None = None


def _as_utc(value: datetime | None) -> datetime | None:
    """Re-attach UTC to a naive database timestamp (the store does the same on read)."""
    if value is None:
        return None
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


class ScanMachine:
    """Drives a persisted scan through its pipeline, resumably."""

    def __init__(
        self,
        store: ScanStateStore,
        *,
        bus: EventBus,
        auditor: Auditor,
        pipeline: Sequence[ScanStep] = DEFAULT_PIPELINE,
        evidence: Any = None,
        project_id: int | None = None,
        integrity: Any = None,
    ) -> None:
        self.store = store
        self.bus = bus
        self.auditor = auditor
        self.pipeline: tuple[ScanStep, ...] = tuple(pipeline)
        #: The evidence seam and the tenant (S20, area DATA); both are passed through to every
        #: :class:`StepContext` so the checks step can offload payloads and enforce the quota.
        self.evidence = evidence
        self.project_id = project_id
        #: The tamper-evidence seam (S25, REQ-TRUST-005): its ``seal_scan`` writes the signed
        #: manifest of this scan's findings and evidence the moment the scan completes, which
        #: is what makes a *deleted* row detectable later. ``None`` means this deployment has
        #: no integrity service, and the scan simply is not sealed.
        self.integrity = integrity

    async def run(
        self,
        scan_id: int,
        handlers: Mapping[ScanStep, StepHandler],
        *,
        definition: TargetDefinition,
        options: ScanOptions,
        scope: Scope,
        plan: ScanPlan | None = None,
        http: Any = None,
        net: Any = None,
        resume: bool = False,
    ) -> ScanOutcome:
        """Run (or resume) ``scan_id`` to completion."""
        record = self.store.get_scan(scan_id)
        if record is None:
            msg = f"scan {scan_id} does not exist"
            raise ScanStateError(msg)
        if record.status is ScanStatus.COMPLETED:
            return ScanOutcome(
                scan_id=scan_id,
                status=record.status,
                resumed=False,
                already_completed=tuple(self.pipeline),
                assets=len(self.store.list_assets(scan_id)),
            )

        resuming = resume or record.status is not ScanStatus.PENDING
        record = self.store.update_scan(scan_id, status=ScanStatus.RUNNING, mark_started=True)
        self.auditor.record(
            AuditAction.SCAN_RESUMED if resuming else AuditAction.SCAN_STARTED,
            scan_id=scan_id,
            target=definition.name,
            meta={"resuming": resuming, "pipeline": [step.value for step in self.pipeline]},
        )
        await self.bus.publish(
            Event(
                type=EventType.SCAN_RESUMED if resuming else EventType.SCAN_STARTED,
                scan_id=scan_id,
                payload={"target": definition.name, "resuming": resuming},
            )
        )

        executed: list[ScanStep] = []
        skipped: list[ScanStep] = []
        already: list[ScanStep] = []

        for step in self.pipeline:
            existing = record.step_state(step)
            if existing is not None and existing.is_terminal:
                already.append(step)
                continue

            attempts = (existing.attempts if existing else 0) + 1
            started_at = datetime.now(UTC)
            self.store.save_step(
                scan_id,
                StepState(
                    step=step,
                    status=StepStatus.RUNNING,
                    attempts=attempts,
                    started_at=started_at,
                    stats=dict(existing.stats) if existing else {},
                ),
            )
            self.auditor.record(
                AuditAction.SCAN_STEP_STARTED,
                scan_id=scan_id,
                target=step.value,
                meta={"attempt": attempts},
            )
            await self.bus.publish(
                Event(
                    type=EventType.STEP_STARTED,
                    scan_id=scan_id,
                    payload={"step": step.value, "attempt": attempts},
                )
            )

            handler = handlers.get(step)
            if handler is None:
                await self._finish_step(
                    scan_id,
                    step,
                    status=StepStatus.SKIPPED,
                    stats={},
                    error=None,
                    note="no step handler is registered in this build",
                    attempts=attempts,
                )
                skipped.append(step)
                continue

            context = StepContext(
                scan_id=scan_id,
                step=step,
                definition=definition,
                options=options,
                scope=scope,
                store=self.store,
                bus=self.bus,
                auditor=self.auditor,
                plan=plan,
                http=http,
                net=net,
                evidence=self.evidence,
                project_id=self.project_id,
            )
            try:
                # One span per step (REQ-OPS-004): the orchestrator's own trace, nested under
                # the scan's root span, with the HTTP client's spans as its children.
                with get_tracer().start_span(
                    f"scan.step.{step.value}",
                    attributes={
                        "scan.id": scan_id,
                        "scan.step": step.value,
                        "scan.attempt": attempts,
                    },
                ) as span:
                    try:
                        outcome = await handler(context)
                    except Exception as exc:
                        span.set_status("error", error_info(exc).summary())
                        raise
                    span.set_status("ok")
            except Exception as exc:
                summary = error_info(exc).summary()
                await self._finish_step(
                    scan_id,
                    step,
                    status=StepStatus.FAILED,
                    stats={},
                    error=summary,
                    note=None,
                    attempts=attempts,
                )
                self.store.update_scan(scan_id, status=ScanStatus.FAILED, mark_finished=True)
                self._count_completion("failed", self.store.get_scan(scan_id))
                await get_tracer().aflush()
                self.auditor.record(
                    AuditAction.SCAN_FAILED,
                    outcome=AuditOutcome.ERROR,
                    scan_id=scan_id,
                    target=step.value,
                    reason=summary,
                )
                await self.bus.publish(
                    Event(
                        type=EventType.SCAN_FAILED,
                        scan_id=scan_id,
                        payload={"step": step.value, "error": summary},
                    )
                )
                raise ScanStateError(
                    f"scan {scan_id} failed in step {step.value}: {summary}"
                ) from exc

            await self._finish_step(
                scan_id,
                step,
                status=StepStatus.SKIPPED if outcome.skipped else StepStatus.COMPLETED,
                stats=outcome.stats,
                error=None,
                note=outcome.note,
                attempts=attempts,
            )
            (skipped if outcome.skipped else executed).append(step)

        assets = len(self.store.list_assets(scan_id))
        # Re-read the record: steps persisted their own stats meanwhile (the proof journal
        # of S15 lives in ``stats["proof"]``), and composing from the stale record would
        # silently drop them.
        record = self.store.get_scan(scan_id) or record
        stats = dict(record.stats)
        stats.update(
            {
                "steps_executed": [step.value for step in executed],
                "steps_skipped": [step.value for step in skipped],
                "steps_already_completed": [step.value for step in already],
                "assets": assets,
            }
        )
        self.store.update_scan(
            scan_id, status=ScanStatus.COMPLETED, stats=stats, mark_finished=True
        )
        self._count_completion("completed", record)
        await get_tracer().aflush()
        self.auditor.record(
            AuditAction.SCAN_FINISHED,
            scan_id=scan_id,
            target=definition.name,
            meta={"assets": assets, "steps_executed": [step.value for step in executed]},
        )
        await self.bus.publish(
            Event(
                type=EventType.SCAN_FINISHED,
                scan_id=scan_id,
                payload={"assets": assets, "executed": [step.value for step in executed]},
            )
        )
        if self.integrity is not None:
            # Seal *after* the scan is marked complete and the finish event is out, so the
            # manifest covers every row the scan will ever write (S25, REQ-TRUST-005). A seal
            # failure must not fail a scan that succeeded: the rows are durable either way,
            # and the operator sees the missing seal from `arachne verify-chain`.
            try:
                self.integrity.seal_scan(scan_id, reason="finish")
            except Exception as exc:
                _logger.warning(
                    "could not seal the completed scan",
                    extra={
                        "event": "integrity.seal_failed",
                        "scan_id": scan_id,
                        "error": str(exc),
                    },
                )
        return ScanOutcome(
            scan_id=scan_id,
            status=ScanStatus.COMPLETED,
            resumed=resuming,
            executed=tuple(executed),
            skipped=tuple(skipped),
            already_completed=tuple(already),
            assets=assets,
        )

    def _count_completion(self, status: str, record: ScanRecord | None) -> None:
        """Scan counts and durations (REQ-OPS-003): what this process finished, and how long
        it took. The database-derived gauge (``arachne_scans``) reports what the deployment
        holds; this counter reports what this worker did, which is what makes it monotonic.
        """
        REGISTRY.increment("arachne_scans_total", {"status": status})
        if record is None:
            return
        started = _as_utc(record.started_at)
        finished = _as_utc(record.finished_at)
        if started is None or finished is None:
            return
        REGISTRY.observe(
            "arachne_scan_duration_seconds", max(0.0, (finished - started).total_seconds())
        )

    async def _finish_step(
        self,
        scan_id: int,
        step: ScanStep,
        *,
        status: StepStatus,
        stats: dict[str, Any],
        error: str | None,
        note: str | None,
        attempts: int,
    ) -> None:
        previous = self.store.get_scan(scan_id)
        existing = previous.step_state(step) if previous else None
        merged = dict(existing.stats) if existing else {}
        merged.update(stats)
        if note:
            merged["note"] = redact_text(note)
        self.store.save_step(
            scan_id,
            StepState(
                step=step,
                status=status,
                attempts=attempts,
                started_at=existing.started_at if existing else None,
                finished_at=datetime.now(UTC),
                error=redact_text(error) if error else None,
                stats=merged,
            ),
        )
        action = {
            StepStatus.COMPLETED: AuditAction.SCAN_STEP_COMPLETED,
            StepStatus.SKIPPED: AuditAction.SCAN_STEP_SKIPPED,
            StepStatus.FAILED: AuditAction.SCAN_FAILED,
            StepStatus.RUNNING: AuditAction.SCAN_STEP_STARTED,
            StepStatus.PENDING: AuditAction.SCAN_STEP_STARTED,
        }[status]
        self.auditor.record(
            action,
            outcome=AuditOutcome.ERROR if status is StepStatus.FAILED else AuditOutcome.ALLOWED,
            scan_id=scan_id,
            target=step.value,
            reason=redact_text(note) if note else None,
            meta={"attempts": attempts, "stats_keys": sorted(merged)},
        )
        if status is not StepStatus.FAILED:
            event_type = (
                EventType.STEP_SKIPPED if status is StepStatus.SKIPPED else EventType.STEP_COMPLETED
            )
            await self.bus.publish(
                Event(
                    type=event_type,
                    scan_id=scan_id,
                    payload={"step": step.value, "stats": merged, "note": note},
                )
            )
