"""Run due schedules and compute the change-detection diff (F-01-05, F-06-05, S16).

The scheduler is a thin coordinator over machinery that already exists: it turns a
:class:`~arachne.scheduler.model.ScheduleSpec` into a :class:`ScanRequest` and hands it to
the pipeline. Since S16 it is a **producer** when the deployment runs distributed mode
(REQ-SCALE-007): the request is admitted through the real orchestrator (every gate, the
plan persisted) and the scan id goes on the Postgres work queue — the scheduler never
executes the scan itself. An agent that finishes a scan produced by a schedule computes
the deferred diff (``previous_scan_id`` rides on the queue row; see
:class:`arachne.agent.service.AgentService.complete`), so F-06-05's change detection
survives the hand-off.

In single-node mode the scheduler keeps the S11 behaviour: it runs the scan inline via
the real orchestrator and compares it with the previous run of the *same schedule*,
persisting the ``new``/``fixed``/``regressed``/``recurring`` sets (F-06-05) so
``arachne report --diff-with`` and the trend section can read them.

Two seams make it testable without a full deployment: ``scan_runner`` and ``diff_writer``
are injectable. The defaults use the real services (a scan through
:class:`~arachne.core.orchestrator.Orchestrator`, and the report builder's finding projection
plus :func:`~arachne.report.diff.build_diff`), so the integration test exercises the real path.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Iterable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from arachne import __version__
from arachne.core.audit import AuditAction, AuditOutcome
from arachne.core.config import Settings, get_settings
from arachne.core.errors import ConfigurationError
from arachne.core.logging import get_logger
from arachne.core.orchestrator import ScanSession
from arachne.core.target import ModuleSelection, ScanRequest, load_scan_request
from arachne.data.analysis_store import SqlAnalysisStore
from arachne.data.leader_store import LeaderElector
from arachne.data.services import (
    ScanServices,
    build_intel_snapshotter,
    build_orchestrator,
    build_services,
)
from arachne.report.builder import build_report_for_scan
from arachne.report.diff import build_diff, diff_payload
from arachne.report.model import ReportDiff
from arachne.scheduler.model import (
    ScheduleBudget,
    ScheduleRun,
    ScheduleSpec,
    ScheduleState,
)
from arachne.scheduler.store import ScheduleStore, StoredSchedule

__all__ = [
    "Scheduler",
    "default_diff_writer",
    "default_scan_runner",
    "store_diff_for_scans",
]

_logger = get_logger("scheduler")

#: ``(services, request) -> scan session``. Injectable so a unit test can avoid a real scan.
ScanRunner = Callable[[ScanServices, ScanRequest], Awaitable[ScanSession]]
#: ``(services, earlier_scan_id, current_scan_id) -> diff`` (``None`` when not comparable).
DiffWriter = Callable[[ScanServices, int, int], ReportDiff | None]
#: ``(services, request, spec, previous) -> admitted scan id`` — the S16 producer: admit
#: through the orchestrator (every gate), then enqueue. Injectable for tests.
Producer = Callable[[ScanServices, ScanRequest, ScheduleSpec, int | None], Awaitable[int]]


async def default_scan_runner(services: ScanServices, request: ScanRequest) -> ScanSession:
    """Run one scan over the configured services (the real pipeline)."""
    orchestrator = build_orchestrator(services)
    return await orchestrator.scan(request)


async def default_producer(
    services: ScanServices, request: ScanRequest, spec: ScheduleSpec, previous: int | None
) -> int:
    """Admit the scan (every gate) and enqueue it for the agents (REQ-SCALE-007).

    The diff against ``previous`` is *deferred*: the queue row carries the schedule id
    and the previous scan id, and the agent's completion path computes it once the scan
    actually finishes — comparing a queued scan against an older one would be fiction.
    """
    from arachne.core.orchestrator import Orchestrator

    queue = services.queue
    if queue is None:
        msg = (
            "distributed mode requires the S16 services stack (a work queue); "
            "rebuild the services with build_services()"
        )
        raise ConfigurationError(msg)
    orchestrator = Orchestrator(
        settings=services.settings,
        store=services.store,
        target_store=services.target_store,
        auditor=services.auditor,
        bus=services.bus,
        handlers=_default_handlers(services),
        registry=services.registry,
        intel_snapshot=build_intel_snapshotter(services),
    )
    session = await orchestrator.launch(request)
    scan_id = session.scan_id
    assert scan_id is not None  # launch always persists a scan
    record = services.store.get_scan(scan_id)
    queue.enqueue(
        scan_id,
        project_id=record.project_id if record is not None else None,
        requested_by=f"schedule:{spec.id}",
        schedule_id=spec.id,
        previous_scan_id=previous,
    )
    services.auditor.record(
        AuditAction.SCAN_ENQUEUED,
        scan_id=scan_id,
        meta={"producer": "scheduler", "schedule": spec.id, "previous_scan_id": previous},
    )
    return scan_id


def _default_handlers(services: ScanServices) -> Any:
    """The module-backed handler set for admission (the plan only needs handled steps)."""
    from arachne.modules.handlers import build_handlers

    return build_handlers(
        settings=services.settings,
        registry=services.registry,
        findings=services.findings,
        auditor=services.auditor,
        analyses=services.analyses,
        feeds=services.feeds,
        posture=getattr(services, "posture", None),
    )


def _finding_sets(services: ScanServices, scan_ids: Iterable[int]) -> dict[int, Any]:
    findings = services.findings
    analyses = SqlAnalysisStore(services.session_factory)
    out: dict[int, Any] = {}
    for scan_id in scan_ids:
        out[scan_id] = build_report_for_scan(
            scan_id=scan_id,
            scans=services.store,
            findings=findings,
            analyses=analyses,
            module_versions=_module_versions(services),
            arachne_version=__version__,
            settings=services.settings,
        )
    return out


def _module_versions(services: ScanServices) -> dict[str, str]:
    return {group.id: group.version for group in services.registry.groups}


def store_diff_for_scans(services: ScanServices, earlier: int, current: int) -> ReportDiff | None:
    """Compare two stored scans and persist the diff; ``None`` when a scan is missing."""
    from arachne.data.report_store import SqlScanDiffStore

    if services.store.get_scan(earlier) is None or services.store.get_scan(current) is None:
        return None
    reports = _finding_sets(services, (earlier, current))
    diff = build_diff(
        reports[earlier].findings,
        reports[current].findings,
        scan_a=f"scan_{earlier}",
        scan_b=f"scan_{current}",
        suppressions=_active_suppressions(services),
    )
    SqlScanDiffStore(services.session_factory).save(earlier, current, diff_payload(diff))
    return diff


def _active_suppressions(services: ScanServices) -> Any:
    """The suppression rules in force (S21), or an empty set when none are wired."""
    from arachne.quality.suppressions import SuppressionSet

    quality = getattr(services, "quality", None)
    if quality is None:
        return SuppressionSet()
    return quality.active_suppressions()


def default_diff_writer(services: ScanServices, earlier: int, current: int) -> ReportDiff | None:
    """The default change-detection writer (persists ``scans_diff`` and returns the diff)."""
    return store_diff_for_scans(services, earlier, current)


class Scheduler:
    """Evaluate the schedule file, run (or enqueue) what is due, and record the result."""

    def __init__(
        self,
        settings: Settings | None = None,
        *,
        store: ScheduleStore | None = None,
        services: ScanServices | None = None,
        scan_runner: ScanRunner | None = None,
        diff_writer: DiffWriter | None = None,
        producer: Producer | None = None,
        leader: LeaderElector | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        self.store = store or ScheduleStore(self.settings.scheduler.state_path)
        self._services = services
        self._owns_services = services is None
        self.scan_runner: ScanRunner = scan_runner or default_scan_runner
        self.diff_writer: DiffWriter = diff_writer or default_diff_writer
        self.producer: Producer = producer or default_producer
        #: The singleton lease that makes the scheduler run **once** across API replicas
        #: (S25, REQ-RESIL-002). ``None`` — the default — keeps the pre-S25 behaviour exactly:
        #: a caller that has not opted into leader election is unaffected. A scheduler *given*
        #: a lease is fail-closed: it admits nothing until it holds one.
        self.leader = leader

    @property
    def distributed(self) -> bool:
        """Producer mode (S16): due schedules enqueue scans instead of running them."""
        return bool(self.settings.distributed.enabled)

    # ------------------------------------------------------------------ services
    @property
    def services(self) -> ScanServices:
        if self._services is None:
            self._services = build_services(self.settings)
        return self._services

    def close(self) -> None:
        if self._owns_services and self._services is not None:
            self._services.close()
            self._services = None

    # ------------------------------------------------------------------ queries
    def schedules(self) -> tuple[StoredSchedule, ...]:
        return self.store.load()

    def due(self, now: datetime | None = None) -> tuple[StoredSchedule, ...]:
        """The enabled schedules whose next run is at or before ``now``."""
        moment = _as_utc(now or datetime.now(UTC))
        out: list[StoredSchedule] = []
        for row in self.store.load():
            if not row.spec.enabled:
                continue
            next_run = row.state.next_run_at or row.state.last_run_at
            if next_run is not None and _as_utc(next_run) > moment:
                continue
            out.append(row)
        out.sort(key=lambda row: _as_utc(row.state.next_run_at or row.state.last_run_at or moment))
        return tuple(out)

    def next_run(self, spec: ScheduleSpec, *, now: datetime | None = None) -> datetime:
        return spec.expression.next_after(now or datetime.now(UTC))

    # ------------------------------------------------------------------ budgets (S23, R-13)
    def _effective_budget(self, spec: ScheduleSpec) -> ScheduleBudget | None:
        """The spec's own budget, or the deployment default for a continuous schedule."""
        if spec.budget is not None:
            return spec.budget
        if not spec.continuous:
            return None
        posture = self.settings.posture
        return ScheduleBudget(
            max_runs_per_day=posture.default_max_runs_per_day,
            max_estimated_requests=posture.default_max_requests,
        )

    def _budget_refusal(
        self,
        spec: ScheduleSpec,
        state: ScheduleState,
        budget: ScheduleBudget,
        moment: datetime,
    ) -> str | None:
        """The refusal reason when the budget stops this run, else ``None``."""
        window_start = moment - timedelta(hours=24)
        if budget.max_runs_per_day is not None:
            recent = state.runs_since(window_start)
            if recent >= budget.max_runs_per_day:
                return (
                    f"schedule budget exhausted: {recent} run(s) in the last 24h "
                    f"(cap {budget.max_runs_per_day}); next run keeps to the cron schedule "
                    "but will be refused until the window frees"
                )
        if budget.max_estimated_requests is not None:
            estimated = self._estimated_requests(spec)
            if estimated is not None and estimated > budget.max_estimated_requests:
                return (
                    f"schedule budget exceeded: the plan estimates {estimated} request(s) "
                    f"(cap {budget.max_estimated_requests}); narrow the schedule's target or "
                    "raise ARACHNE_POSTURE_MAX_REQUESTS"
                )
        return None

    def _estimated_requests(self, spec: ScheduleSpec) -> int | None:
        """The plan's request estimate for one run (offline dry-plan; ``None`` if unplanable)."""
        try:
            orchestrator = build_orchestrator(self.services)
            plan = orchestrator.plan(self._request_for(spec), dry_run=True)
            return int(plan.totals.estimated_requests)
        except Exception:
            # A plan that cannot be computed offline (a missing fixture, a refused scope)
            # is not a budget verdict; the real run reports it through the usual paths.
            return None

    def audit_budget_refusal(self, spec: ScheduleSpec, reason: str, moment: datetime) -> None:
        """The audited guardrail refusal (risk R-13): visible in the trail, never silent."""
        self.services.auditor.record(
            AuditAction.SCHEDULE_BUDGET_REFUSED,
            outcome=AuditOutcome.BLOCKED,
            target=spec.id,
            reason=reason,
            meta={
                "schedule": spec.id,
                "continuous": spec.continuous,
                "budget": spec.budget.to_dict() if spec.budget else "deployment-default",
                "at": moment.isoformat(),
            },
        )

    # ------------------------------------------------------------------ fix loop (S23)
    def _reconcile_fixes(self, scan_id: int) -> tuple[Any, ...]:
        """Reopen closed findings the completed scan reports again (REQ-POSTURE-003)."""
        from arachne.posture.verify import FixVerificationService

        if getattr(self.services, "posture", None) is None:
            return ()
        return FixVerificationService(self.services).reconcile(scan_id)

    # ------------------------------------------------------------------ execution
    async def run_due(
        self, now: datetime | None = None, *, limit: int | None = None
    ) -> tuple[ScheduleRun, ...]:
        moment = now or datetime.now(UTC)
        cap = limit if limit is not None else self.settings.scheduler.max_runs_per_tick
        if self.leader is not None and not self.leader.try_acquire(reason="run_due"):
            # Another replica holds this singleton's lease: it will admit the due schedules.
            # Returning an empty result (rather than raising) is deliberate — a replica that
            # is not the leader is *healthy*, it simply has nothing to do this tick, and the
            # transition itself is recorded in the audit trail by LeaderElector.
            return ()
        results: list[ScheduleRun] = []
        for row in self.due(moment)[: max(0, cap)]:
            results.append(await self.run_one(row.spec, now=moment))
        return tuple(results)

    async def run_one(self, spec: ScheduleSpec, *, now: datetime | None = None) -> ScheduleRun:
        """Run (or, in distributed mode, enqueue) one schedule now and record its state.

        A continuous schedule (S23) passes the budget gate first (risk R-13): the run cap
        over the last 24h and the estimated-request cap are both checked before anything
        is admitted, and a breach is an audited refusal (``schedule.budget_refused``) —
        the guardrail working is a trail event, not a silent skip.
        """
        moment = _as_utc(now or datetime.now(UTC))
        row = self.store.get(spec.id)
        state = row.state if row is not None else ScheduleState()
        previous = state.last_scan_id
        budget = self._effective_budget(spec)
        if budget is not None:
            refusal = self._budget_refusal(spec, state, budget, moment)
            if refusal is not None:
                self.audit_budget_refusal(spec, refusal, moment)
                self._record(spec, moment, scan_id=None, status="budget_refused", detail=refusal)
                recorded = self.store.get(spec.id)
                if recorded is not None:
                    self.store.record(spec.id, recorded.state.with_run(moment))
                return ScheduleRun(
                    schedule_id=spec.id,
                    previous_scan_id=previous,
                    status="budget_refused",
                    detail=refusal,
                )
        if spec.purple_campaign is not None:
            # S24 (REQ-VALID-006): a purple-team campaign schedule delegates to the campaign
            # service, which enforces the detection window itself and records the coverage
            # run. A window refusal is a *recorded* run, not a crash, so the trend shows it.
            return await self._run_purple_campaign(spec, moment, previous)
        request = self._request_for(spec)
        if self.distributed:
            return await self._produce_one(spec, moment, request, previous)
        try:
            session = await self.scan_runner(self.services, request)
        except Exception as exc:  # a failed run must not take the scheduler down
            _logger.error(
                "scheduled scan failed",
                extra={"event": "scheduler.run.failed", "schedule": spec.id, "error": str(exc)},
            )
            self._record(spec, moment, scan_id=None, status="failed", detail=str(exc)[:500])
            return ScheduleRun(
                schedule_id=spec.id, previous_scan_id=previous, status="failed", detail=str(exc)
            )
        scan_id = session.scan_id
        status = session.status.value
        diff: ReportDiff | None = None
        if (
            self.settings.scheduler.diff_on_run
            and scan_id is not None
            and previous is not None
            and previous != scan_id
        ):
            try:
                diff = self.diff_writer(self.services, previous, scan_id)
            except Exception as exc:  # the scan succeeded; a diff failure is reported, not fatal
                _logger.error(
                    "scheduled diff failed",
                    extra={
                        "event": "scheduler.diff.failed",
                        "schedule": spec.id,
                        "error": str(exc),
                    },
                )
        # S23 (REQ-POSTURE-003): the fix-verification loop's reopen half runs on every
        # scheduled completion — a closed finding the new scan reports again is reopened
        # with its evidence linked. A failure here is reported, never fatal to the run.
        if scan_id is not None:
            try:
                self._reconcile_fixes(scan_id)
            except Exception as exc:
                _logger.error(
                    "fix-verification reconcile failed",
                    extra={
                        "event": "scheduler.reconcile.failed",
                        "schedule": spec.id,
                        "error": str(exc),
                    },
                )
        self._record(spec, moment, scan_id=scan_id, status=status)
        recorded = self.store.get(spec.id)
        if recorded is not None:
            self.store.record(spec.id, recorded.state.with_run(moment))
        return ScheduleRun(
            schedule_id=spec.id,
            scan_id=scan_id,
            previous_scan_id=previous,
            status=status,
            detail="" if diff is not None else _detail(previous, scan_id, self.settings),
            diff=diff_payload(diff) if diff is not None else None,
        )

    async def _run_purple_campaign(
        self, spec: ScheduleSpec, moment: datetime, previous: int | None
    ) -> ScheduleRun:
        """Run a purple-team campaign on its schedule (S24, REQ-VALID-006).

        The campaign service owns the window gate, the scan and the coverage scoring; this
        only records the schedule's own run state. A window refusal comes back as a
        *status*, so the schedule keeps its cadence and the trend keeps the refusal — a
        defence that stops firing because one run was early would be worse than useless.
        """
        from arachne.purple.campaign import PurpleCampaignService

        name = str(spec.purple_campaign)
        try:
            service = PurpleCampaignService(self.services, auditor=self.services.auditor)
            result = await service.run_campaign(name, now=moment)
        except Exception as exc:  # a failed run must not take the scheduler down
            _logger.error(
                "purple campaign run failed",
                extra={"event": "scheduler.purple.failed", "schedule": spec.id, "error": str(exc)},
            )
            self._record(spec, moment, scan_id=None, status="failed", detail=str(exc)[:500])
            return ScheduleRun(
                schedule_id=spec.id, previous_scan_id=previous, status="failed", detail=str(exc)
            )
        self._record(spec, moment, scan_id=result.scan_id, status=result.status, detail="")
        recorded = self.store.get(spec.id)
        if recorded is not None:
            self.store.record(spec.id, recorded.state.with_run(moment))
        return ScheduleRun(
            schedule_id=spec.id,
            scan_id=result.scan_id,
            previous_scan_id=previous,
            status=result.status,
            detail=(
                f"purple campaign {name}: coverage {result.coverage_pct:.1f}%"
                if result.status == "completed"
                else (result.note or f"purple campaign {name}: {result.status}")
            ),
        )

    async def _produce_one(
        self,
        spec: ScheduleSpec,
        moment: datetime,
        request: ScanRequest,
        previous: int | None,
    ) -> ScheduleRun:
        """Producer mode (S16): admit + enqueue; the diff is deferred to completion."""
        try:
            scan_id = await self.producer(self.services, request, spec, previous)
        except Exception as exc:  # a failed run must not take the scheduler down
            _logger.error(
                "scheduled scan failed",
                extra={"event": "scheduler.run.failed", "schedule": spec.id, "error": str(exc)},
            )
            self._record(spec, moment, scan_id=None, status="failed", detail=str(exc)[:500])
            return ScheduleRun(
                schedule_id=spec.id, previous_scan_id=previous, status="failed", detail=str(exc)
            )
        self._record(spec, moment, scan_id=scan_id, status="queued")
        recorded = self.store.get(spec.id)
        if recorded is not None:
            self.store.record(spec.id, recorded.state.with_run(moment))
        return ScheduleRun(
            schedule_id=spec.id,
            scan_id=scan_id,
            previous_scan_id=previous,
            status="queued",
            detail="enqueued for distributed execution; the diff is computed on completion",
        )

    def _record(
        self,
        spec: ScheduleSpec,
        moment: datetime,
        *,
        scan_id: int | None,
        status: str,
        detail: str = "",
    ) -> None:
        state = ScheduleState(
            last_run_at=moment,
            last_scan_id=scan_id,
            last_status=status,
            next_run_at=self.next_run(spec, now=moment),
        )
        existing = self.store.get(spec.id)
        if existing is None:
            self.store.upsert(spec, state=state)
        else:
            # The run history (S23 budget windows) is carried across re-records: a status
            # update never rewrites when the schedule actually ran.
            state = ScheduleState(
                last_run_at=moment,
                last_scan_id=scan_id,
                last_status=status,
                next_run_at=self.next_run(spec, now=moment),
                run_times=existing.state.run_times,
            )
            self.store.record(spec.id, state)

    # ------------------------------------------------------------------ request
    def _request_for(self, spec: ScheduleSpec) -> ScanRequest:
        request = load_scan_request(Path(spec.target))
        options = request.options
        overrides: dict[str, Any] = {}
        if spec.engine is not None:
            overrides["engine"] = spec.engine
        if spec.active_checks is not None:
            overrides["active_checks"] = spec.active_checks
        if spec.modules or spec.checks:
            overrides["modules"] = ModuleSelection(
                enabled=spec.modules or options.modules.enabled,
                disabled=options.modules.disabled,
                checks=spec.checks or options.modules.checks,
            )
        if not overrides:
            return request
        return request.model_copy(update={"options": options.model_copy(update=overrides)})


def _detail(previous: int | None, scan_id: int | None, settings: Settings) -> str:
    if scan_id is None:
        return "the scan produced no id"
    if previous is None:
        return "first run: no earlier scan to compare with"
    if not settings.scheduler.diff_on_run:
        return "change detection is disabled (ARACHNE_SCHEDULER_DIFF=false)"
    return "no diff was produced"


def _as_utc(value: datetime) -> datetime:
    """Compare aware and naive datetimes uniformly (a naive value is read as UTC)."""
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)
