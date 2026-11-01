"""The agent loop (S16, REQ-SCALE-002/003/006/008): lease, execute, heartbeat, ack.

:class:`AgentLoop` is the running behaviour of the ``arachne agent`` role. One cycle:

1. **lease** up to the concurrency cap (default 1 — one scan at a time). The control
   plane reclaims expired leases first, so a dead agent's scan becomes re-leasable here.
2. **execute** each leased scan through the orchestrator — on the *executing node*:
   the scope gate (the node's own deployment allowlist and the project's scope), the
   authorization gate (the attestation as it stands *now*), and the proof gate are all
   re-evaluated before any handler runs (REQ-SCALE-008). The plan is the one stored with
   the scan at admission, so every node runs the same plan (REQ-SCALE-006), and
   interrupted scans resume from the persisted lifecycle state (REQ-SCALE-003).
3. **heartbeat** the lease while the scan runs; a lost renewal cancels the local
   execution (the scan was stopped or re-leased elsewhere — it must not continue here).
4. **ack** with ``complete`` (a failure is a terminal ack too — no auto-retry). A
   cancellation *never* acks: the lease is abandoned and expires, which is what makes an
   agent-kill re-leasable on another node.

Findings and evidence are written by the handlers to the shared store as they are
produced — the streaming requirement (REQ-SCALE-005) — not bulk-inserted at scan end.
"""

from __future__ import annotations

import asyncio
import contextlib
import socket
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

from arachne import __version__
from arachne.agent.control import AgentLease, ControlPlane
from arachne.core.errors import ArachneError, ControlPlaneError
from arachne.core.lifecycle import ScanRecord, ScanStatus
from arachne.core.logging import get_logger
from arachne.core.planner import DEFAULT_PIPELINE, ScanStep
from arachne.core.target import ScanRequest
from arachne.data.services import ScanServices, build_orchestrator

__all__ = ["AgentLoop", "ExecutionResult", "build_executor", "rebuild_request"]

_logger = get_logger("agent.runner")

#: Runs one leased scan on this node. Injectable so tests can stage interruptions.
Executor = Callable[[AgentLease], Awaitable["ExecutionResult"]]


@dataclass(frozen=True, slots=True)
class ExecutionResult:
    """What executing one lease produced (the ack decision's input)."""

    scan_id: int
    status: str
    resumed: bool = False
    error: str | None = None


def rebuild_request(services: ScanServices, record: ScanRecord) -> ScanRequest:
    """Rebuild the admitted :class:`ScanRequest` for ``record`` on *this* node.

    The options (engine, module selection, active-checks opt-in) are the operator's
    admitted intent, read from the persisted request document. The target *definition*
    is re-read from the stored target row when one exists — the authorization state the
    target carries *now* is what the executing node's gates evaluate (REQ-SCALE-008), so
    an attestation revoked after enqueue is honoured at execution time.
    """
    document = dict(record.request_json or {})
    options: dict[str, Any] = dict(document.get("options") or {})
    options.setdefault("engine", record.engine)
    target_row = (
        services.target_store.get_target(record.target_id) if record.target_id is not None else None
    )
    if target_row is not None:
        definition = target_row.to_definition()
        return ScanRequest.model_validate(
            {"target": definition.model_dump(mode="json"), "options": options}
        )
    stored_target = document.get("target")
    if isinstance(stored_target, dict) and stored_target:
        return ScanRequest.model_validate({"target": stored_target, "options": options})
    msg = f"scan {record.id} carries no request document and no stored target; cannot execute it"
    raise ArachneError(msg)


def build_executor(
    services: ScanServices,
    *,
    name: str,
    handlers: Any = None,
    pipeline: tuple[ScanStep, ...] = DEFAULT_PIPELINE,
    mode: str | None = None,
) -> Executor:
    """The default executor: the real orchestrator, signed as ``agent:<name>``.

    Every audit line the execution writes carries the agent's identity (REQ-SCALE-004),
    and every gate is evaluated here, on the executing node, against this node's
    deployment allowlist and the scan's project scope (REQ-SCALE-008).

    ``mode`` (S19, REQ-CREDS-003) is ``external`` or ``internal``, defaulting to this
    deployment's ``ARACHNE_AGENT_MODE``. An **internal** agent runs inside the target network:
    it authenticates scans with *its own* credential vault (a node-local encrypted file), so no
    credential material crosses the control plane — only labels do — and it resolves a label
    **after** leasing, on this node. The mode adds no relaxation: the scope, authorization and
    proof gates are the same code path either way, and a label this node does not hold is
    refused with an audit (``credential.unresolved``) rather than fetched from elsewhere.
    """
    auditor = services.auditor.with_actor(f"agent:{name}")
    effective_mode = mode or ("internal" if services.settings.distributed.internal else "external")

    async def execute(lease: AgentLease) -> ExecutionResult:
        _note_mode(services, auditor, lease, effective_mode)
        orchestrator = build_orchestrator(
            services, handlers=handlers, pipeline=pipeline, auditor=auditor
        )
        if lease.project_id is not None:
            orchestrator.project_id = lease.project_id
            project = services.projects.get(lease.project_id)
            if project is not None:
                # An empty project scope means "no extra restriction" — the same
                # normalization the orchestrator applies to a constructor argument.
                scope = project.to_scope()
                orchestrator.project_scope = None if scope.is_empty else scope
        record = services.store.get_scan(lease.scan_id)
        if record is None:
            return ExecutionResult(scan_id=lease.scan_id, status="failed", error="scan vanished")
        try:
            request = rebuild_request(services, record)
            if record.status is ScanStatus.PENDING:
                session = await orchestrator.execute(lease.scan_id, request)
            else:
                # An interrupted scan (a previous lease expired) resumes from the
                # persisted lifecycle state: completed steps are never re-run.
                session = await orchestrator.resume(lease.scan_id, request)
        except asyncio.CancelledError:
            raise  # agent death or a lost lease: abandon, never ack
        except Exception as exc:
            return _record_failure(services, auditor, lease, exc)
        status = session.record.status.value if session.record is not None else "unknown"
        resumed = session.outcome.resumed if session.outcome is not None else False
        return ExecutionResult(scan_id=lease.scan_id, status=status, resumed=resumed)

    return execute


def _note_mode(
    services: ScanServices, auditor: Any, lease: AgentLease, mode: str
) -> None:
    """Record how this node executed the scan, once per lease (S19, REQ-CREDS-003).

    The trail has to answer "was this scan run from outside the target network or inside it?"
    because that decides where its credential came from. The record names the mode and whether
    a vault is present — never a label's content.
    """
    from arachne.core.audit import AuditAction

    vault = services.credentials
    # ``ScanServices.credentials`` is a ``FileCredentialVault`` — a node-local encrypted file —
    # so "an internal agent only holds its own credentials" is a property of the type, not a
    # runtime check (ADR-240.2). This record is what makes the deployment's mode auditable.
    auditor.record(
        AuditAction.AGENT_MODE,
        scan_id=lease.scan_id,
        target=f"agent:{mode}",
        meta={
            "mode": mode,
            "vault": "local" if vault is not None else "absent",
            "private_network_posture": bool(services.settings.safety.policy.allow_private_ips),
        },
    )


def _record_failure(
    services: ScanServices, auditor: Any, lease: AgentLease, exc: Exception
) -> ExecutionResult:
    """A refusal (or crash) on the executing node is data, not a disappearing scan.

    A gate refusal happens before the lifecycle machine starts, so nothing else would
    mark the row; leaving it ``pending`` would strand a scan no agent may run. The same
    principle the machine applies to a failing step, applied to the whole execution.
    """
    from arachne.core.audit import AuditAction, AuditOutcome
    from arachne.core.lifecycle import ScanStatus

    summary = f"{exc.__class__.__name__}: {exc}"[:500]
    record = services.store.get_scan(lease.scan_id)
    if record is not None and record.status not in (
        ScanStatus.COMPLETED,
        ScanStatus.FAILED,
        ScanStatus.ABORTED,
    ):
        stats = dict(record.stats)
        stats["failure"] = summary
        services.store.update_scan(
            lease.scan_id, status=ScanStatus.FAILED, stats=stats, mark_finished=True
        )
        auditor.record(
            AuditAction.SCAN_FAILED,
            outcome=AuditOutcome.ERROR,
            scan_id=lease.scan_id,
            reason=summary,
            meta={"agent": auditor.actor},
        )
    return ExecutionResult(scan_id=lease.scan_id, status="failed", error=summary)


class AgentLoop:
    """Lease → execute → heartbeat → ack, until stopped or the queue is drained."""

    def __init__(
        self,
        control: ControlPlane,
        *,
        name: str,
        executor: Executor,
        concurrency: int = 1,
        lease_ttl_s: float = 300.0,
        heartbeat_interval_s: float = 15.0,
        poll_interval_s: float = 1.0,
        node: str | None = None,
        sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    ) -> None:
        self._control = control
        self._name = name
        self._executor = executor
        self._concurrency = max(1, concurrency)
        self._lease_ttl_s = lease_ttl_s
        self._heartbeat_interval_s = heartbeat_interval_s
        self._poll_interval_s = poll_interval_s
        self._node = node or socket.gethostname()
        self._sleep = sleep
        #: Scans whose lease was lost mid-execution (the renewal watcher records them so
        #: a cancellation is read as "abort locally", not as "the agent died").
        self._lost_leases: set[int] = set()

    @property
    def name(self) -> str:
        return self._name

    async def start(self) -> dict[str, Any]:
        """Register with the deployment (idempotent) and return the agent record."""
        return await self._control.register(
            self._name, node=self._node, version=__version__, concurrency=self._concurrency
        )

    async def close(self) -> None:
        """Release the control plane's resources (the HTTP client, if one is held)."""
        await self._control.close()

    async def run_forever(self) -> None:
        """The worker's main loop: run what is due, sleep when the queue is empty."""
        await self.start()
        while True:
            try:
                worked = await self.run_one()
            except ControlPlaneError as exc:
                _logger.warning(
                    "control plane refused; retrying",
                    extra={"event": "agent.control_error", "agent": self._name, "error": str(exc)},
                )
                worked = False
            if not worked:
                await self._sleep(self._poll_interval_s)

    async def run_until_drained(self, *, max_scans: int | None = None) -> int:
        """Drain the queue (tests and ``arachne agent --once``); returns scans executed."""
        await self.start()  # registration is idempotent; leasing requires it
        executed = 0
        while max_scans is None or executed < max_scans:
            if not await self.run_one():
                return executed
            executed += 1
        return executed

    async def run_one(self) -> bool:
        """One lease-execute-ack cycle; ``False`` when the queue had nothing to claim."""
        leases = await self._control.lease(
            self._name, cap=self._concurrency, ttl_s=self._lease_ttl_s
        )
        if not leases:
            return False
        if len(leases) == 1:
            await self._run_lease(leases[0])
        else:
            # The concurrency cap is > 1: the leased scans run concurrently, each under
            # its own heartbeat, and the cap bounds exactly how many run at once.
            await asyncio.gather(*(self._run_lease(lease) for lease in leases))
        return True

    # ------------------------------------------------------------------ internals
    async def _run_lease(self, lease: AgentLease) -> ExecutionResult:
        execution = asyncio.ensure_future(self._executor(lease))
        heartbeat = asyncio.ensure_future(self._renew_while(lease, execution))
        try:
            result = await execution
        except asyncio.CancelledError:
            heartbeat.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await heartbeat
            if lease.scan_id in self._lost_leases:
                # A lost lease is an operational event, not an agent death: the local
                # execution stops, nothing is acked, and the loop lives on.
                self._lost_leases.discard(lease.scan_id)
                return ExecutionResult(scan_id=lease.scan_id, status="aborted", resumed=False)
            # Agent death: no ack on purpose — the abandoned lease expires and the scan
            # becomes re-leasable with an interruption note.
            raise
        except Exception as exc:
            # A failed scan is a terminal ack: no automatic retry hides a failure.
            heartbeat.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await heartbeat
            await self._complete(lease)
            _logger.error(
                "leased scan failed",
                extra={
                    "event": "agent.scan_failed",
                    "agent": self._name,
                    "scan_id": lease.scan_id,
                    "error": str(exc)[:200],
                },
            )
            return ExecutionResult(
                scan_id=lease.scan_id, status="failed", error=f"{exc.__class__.__name__}: {exc}"
            )
        heartbeat.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await heartbeat
        await self._complete(lease)
        _logger.info(
            "leased scan finished",
            extra={
                "event": "agent.scan_finished",
                "agent": self._name,
                "scan_id": lease.scan_id,
                "status": result.status,
                "resumed": result.resumed,
            },
        )
        return result

    async def _renew_while(
        self, lease: AgentLease, execution: asyncio.Future[ExecutionResult]
    ) -> None:
        """Keep the lease alive while the scan runs; abort locally when it is lost."""
        while True:
            await self._sleep(self._heartbeat_interval_s)
            renewals = await self._control.heartbeat(self._name)
            if not renewals.get(lease.scan_id, False):
                _logger.warning(
                    "lease lost; aborting the local execution",
                    extra={
                        "event": "agent.lease_lost",
                        "agent": self._name,
                        "scan_id": lease.scan_id,
                    },
                )
                self._lost_leases.add(lease.scan_id)
                execution.cancel()
                return

    async def _complete(self, lease: AgentLease) -> None:
        try:
            await self._control.complete(self._name, lease.scan_id)
        except ControlPlaneError as exc:
            _logger.error(
                "completion ack failed; the lease will expire and the scan re-lease",
                extra={
                    "event": "agent.ack_failed",
                    "agent": self._name,
                    "scan_id": lease.scan_id,
                    "error": str(exc),
                },
            )
