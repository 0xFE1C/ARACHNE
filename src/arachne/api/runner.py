"""Background scan execution for the API (F-07-02, S12; enqueue-and-track, S16).

A REST request must return before the scan it starts has finished. This module is the
small amount of bookkeeping that makes that true and honest:

* :meth:`ScanRunner.start` runs the orchestrator's gates and admission
  (:meth:`~arachne.core.orchestrator.Orchestrator.launch`), and then depends on the
  deployment mode:
  - **single-node** (the default): schedules
    :meth:`~arachne.core.orchestrator.Orchestrator.execute` on the running event loop and
    owns the scan until it finishes — the S12 behaviour, unchanged.
  - **distributed** (``ARACHNE_DISTRIBUTED=true``, S16): *enqueues* the admitted scan on
    the Postgres work queue and returns. This process is no longer the scan's owner — an
    ``arachne agent`` leases and executes it; this runner only tracks (REQ-SCALE-007).
* :meth:`ScanRunner.stop` cancels the task (single-node) or cancels the queue row
  (distributed: the holding agent sees the lost renewal and aborts locally; a queued row
  never leases). The scan row is marked ``aborted`` either way — a crash-free resume from
  the last completed step, the machinery S2 built, reused.
* Completion fans out to the configured webhooks (F-06-06) and never lets a broken
  integration change the scan's outcome (single-node; in distributed mode the agent's
  completion path fans out instead).

In distributed mode ``is_running`` consults the queue row, so the API reports a scan as
running while *another node* executes it — the fleet is one store, not one process.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from arachne.core.audit import AuditAction, AuditOutcome
from arachne.core.config import Settings
from arachne.core.errors import ConfigurationError
from arachne.core.lifecycle import ScanStatus
from arachne.core.logging import get_logger
from arachne.core.orchestrator import Orchestrator, ScanSession
from arachne.core.target import ScanRequest
from arachne.data.queue_store import QueueBackend
from arachne.data.services import ScanServices

__all__ = ["ScanRunner", "StartedScan"]

_logger = get_logger("api.runner")

#: How the runner runs an admitted scan. Injectable so a test can avoid a real scan.
Executor = Callable[[Orchestrator, int, ScanRequest], Awaitable[ScanSession]]
#: How the runner builds an orchestrator for one scan, given the caller's actor identity
#: (``user X via key Y``; ``None`` for an anonymous/CLI admission). The actor is threaded
#: into the orchestrator *and* its handlers, so every audit line a scan writes names its
#: requester (REQ-IDAM-004).
OrchestratorFactory = Callable[[ScanServices, "str | None"], Orchestrator]


@dataclass(frozen=True, slots=True)
class StartedScan:
    """The handle :meth:`ScanRunner.start` returns."""

    scan_id: int
    status: str

    def to_dict(self) -> dict[str, Any]:
        return {"scan_id": self.scan_id, "status": self.status}


async def _default_executor(
    orchestrator: Orchestrator, scan_id: int, request: ScanRequest
) -> ScanSession:
    return await orchestrator.execute(scan_id, request)


class ScanRunner:
    """Admit scans, then own them (single-node) or enqueue-and-track them (distributed)."""

    def __init__(
        self,
        services: ScanServices,
        *,
        settings: Settings | None = None,
        orchestrator_factory: OrchestratorFactory | None = None,
        executor: Executor | None = None,
        notifier: Any = None,
    ) -> None:
        self._services = services
        self._settings = settings or services.settings
        self._orchestrator_factory = orchestrator_factory or _default_orchestrator
        self._executor: Executor = executor or _default_executor
        self._notifier = notifier
        self._tasks: dict[int, asyncio.Task[None]] = {}
        self._requests: dict[int, ScanRequest] = {}
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------------ mode
    @property
    def distributed(self) -> bool:
        """True when admitted scans are enqueued instead of run in this process (S16)."""
        return bool(self._settings.distributed.enabled)

    @property
    def queue(self) -> QueueBackend:
        """The work queue; a distributed runner cannot exist without one."""
        queue = self._services.queue
        if queue is None:
            msg = (
                "distributed mode requires the S16 services stack (a work queue); "
                "rebuild the services with build_services()"
            )
            raise ConfigurationError(msg)
        return queue

    # ------------------------------------------------------------------ queries
    def is_running(self, scan_id: int) -> bool:
        """Whether a scan is executing — here, or on any node of the fleet."""
        if self.distributed:
            entry = self.queue.entry_for(scan_id)
            return entry is not None and entry.status == "leased"
        task = self._tasks.get(scan_id)
        return task is not None and not task.done()

    def running_ids(self) -> tuple[int, ...]:
        """Scan ids currently executing (local tasks, or leased rows fleet-wide)."""
        if self.distributed:
            return tuple(
                entry.scan_id for entry in self.queue.list_entries(status="leased", limit=500)
            )
        return tuple(scan_id for scan_id, task in self._tasks.items() if not task.done())

    def request_for(self, scan_id: int) -> ScanRequest | None:
        return self._requests.get(scan_id)

    # ------------------------------------------------------------------ control
    async def start(
        self,
        request: ScanRequest,
        *,
        project_id: int | None = None,
        project_scope: Any = None,
        requested_by: str | None = None,
    ) -> StartedScan:
        """Admit ``request`` and run (or enqueue) it; returns immediately.

        ``project_id``/``project_scope`` bind the scan to a tenant (F-07-06): the
        orchestrator refuses a target outside the project's scope in both :meth:`launch`
        and :meth:`execute`, and the scan row records the project. ``requested_by`` is
        the caller's actor identity ("user X via key Y", REQ-IDAM-004); it is recorded on
        the scan row, on the queue row (distributed) and as the actor of every audit line
        the scan execution writes.
        """
        orchestrator = self._orchestrator_factory(self._services, requested_by)
        if project_id is not None:
            orchestrator.project_id = project_id
        if project_scope is not None and not project_scope.is_empty:
            orchestrator.project_scope = project_scope
        session = await orchestrator.launch(request, requested_by=requested_by)
        scan_id = session.scan_id
        assert scan_id is not None  # launch always persists a scan
        if self.distributed:
            self._enqueue(scan_id, project_id=project_id, requested_by=requested_by)
            return StartedScan(scan_id=scan_id, status=session.status.value)
        async with self._lock:
            self._requests[scan_id] = request
            self._tasks[scan_id] = asyncio.create_task(
                self._run(orchestrator, scan_id, request), name=f"arachne-scan-{scan_id}"
            )
        return StartedScan(scan_id=scan_id, status=session.status.value)

    async def stop(self, scan_id: int) -> bool:
        """Cancel a running scan; mark the row ``aborted``. ``False`` when it is not ours.

        In distributed mode "ours" means "queued or leased by an agent": the queue row is
        cancelled and the holding agent aborts on its next heartbeat renewal.
        """
        if self.distributed:
            if not self.queue.cancel(scan_id):
                return False
            self._mark_aborted(scan_id)
            return True
        async with self._lock:
            task = self._tasks.get(scan_id)
        if task is None or task.done():
            return False
        task.cancel()
        # The cancellation is the point of the call: swallow it and record the outcome.
        with contextlib.suppress(asyncio.CancelledError):
            await task
        self._mark_aborted(scan_id)
        return True

    async def wait(self, scan_id: int) -> None:
        """Await a running scan (tests and shutdown use this)."""
        task = self._tasks.get(scan_id)
        if task is not None:
            await asyncio.shield(task)

    async def shutdown(self) -> None:
        """Cancel every in-flight scan this process owns (called on app shutdown)."""
        for scan_id in list(self._tasks):
            await self.stop(scan_id)

    # ------------------------------------------------------------------ internals
    def _enqueue(self, scan_id: int, *, project_id: int | None, requested_by: str | None) -> None:
        """Put an admitted scan on the work queue (REQ-SCALE-001/007)."""
        entry = self.queue.enqueue(scan_id, project_id=project_id, requested_by=requested_by)
        self._services.auditor.record(
            AuditAction.SCAN_ENQUEUED,
            scan_id=scan_id,
            meta={
                "queue_id": entry.id,
                "requested_by": requested_by,
                "mode": "distributed",
            },
        )
        _logger.info(
            "scan enqueued for distributed execution",
            extra={"event": "scan.enqueued", "scan_id": scan_id, "queue_id": entry.id},
        )

    async def _run(self, orchestrator: Orchestrator, scan_id: int, request: ScanRequest) -> None:
        try:
            session = await self._executor(orchestrator, scan_id, request)
        except asyncio.CancelledError:
            _logger.info("scan cancelled", extra={"event": "scan.aborted", "scan_id": scan_id})
            raise
        except Exception as exc:
            _logger.error(
                "background scan failed",
                extra={
                    "event": "scan.failed",
                    "scan_id": scan_id,
                    "error": f"{exc.__class__.__name__}: {exc}",
                },
            )
            self._services.auditor.record(
                AuditAction.SCAN_FAILED,
                outcome=AuditOutcome.ERROR,
                scan_id=scan_id,
                reason=f"{exc.__class__.__name__}: {exc}",
            )
            return
        finally:
            async with self._lock:
                self._tasks.pop(scan_id, None)
        await self._after_completion(scan_id, session)

    async def _after_completion(self, scan_id: int, session: ScanSession) -> None:
        """Fan a finished scan out to the webhooks (F-06-06); a failure never propagates."""
        if self._notifier is None or not getattr(self._notifier, "enabled", False):
            return
        from arachne.api.report_service import ReportService

        report_service = ReportService(
            self._services, settings=self._settings, notifier=self._notifier
        )
        try:
            await report_service.notify(scan_id)
        except Exception as exc:  # deliverability is never the scan's problem
            _logger.warning(
                "webhook fan-out failed",
                extra={"event": "webhook.error", "scan_id": scan_id, "error": str(exc)},
            )

    def _mark_aborted(self, scan_id: int) -> None:
        record = self._services.store.get_scan(scan_id)
        if record is None or record.status in (ScanStatus.COMPLETED, ScanStatus.FAILED):
            return
        self._services.store.update_scan(scan_id, status=ScanStatus.ABORTED, mark_finished=True)
        self._services.auditor.record(
            AuditAction.SCAN_ABORTED,
            outcome=AuditOutcome.BLOCKED,
            scan_id=scan_id,
            reason="cancelled by operator",
        )


def _default_orchestrator(services: ScanServices, actor: str | None = None) -> Orchestrator:
    from arachne.data.services import build_orchestrator

    auditor = services.auditor.with_actor(actor) if actor else None
    return build_orchestrator(services, auditor=auditor)
