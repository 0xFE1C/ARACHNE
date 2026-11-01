"""The agent control plane (S16, REQ-SCALE-002/003/004): register, heartbeat, lease.

:class:`AgentService` is the deployment-side half of the agent protocol. The REST API
mounts it under ``/api/v1/agent`` with every route requiring a scanner-role key
(:class:`~arachne.api.deps.ScannerPrincipal` — REQ-SCALE-004), and the in-process
control plane calls it directly; both get exactly the same behaviour and the same audit
trail. The service is deliberately thin bookkeeping over machinery that already exists:

* **lease** reclaims expired leases first, records an interruption note on every
  interrupted scan (REQ-SCALE-003), then claims within the agent's concurrency cap.
* **complete** acks a finished scan and, when the scan was enqueued by the scheduler,
  computes the change-detection diff the producer deferred (REQ-SCALE-007).
* Every call is audited with the agent's name, and the API's own middleware records the
  key label that made the call — the agent's identity is in the audit trail twice over.
"""

from __future__ import annotations

from typing import Any

from arachne.core.audit import AuditAction, Auditor, AuditOutcome
from arachne.core.config import Settings
from arachne.core.errors import ScanStateError
from arachne.core.logging import get_logger
from arachne.data.queue_store import AgentRecord, AgentRegistry, QueueBackend, QueueEntry
from arachne.data.services import ScanServices

__all__ = ["AgentService"]

_logger = get_logger("agent.service")


class AgentService:
    """Register/heartbeat/lease/complete over the queue stores, audited."""

    def __init__(self, services: ScanServices, *, settings: Settings | None = None) -> None:
        self._services = services
        self._settings = settings or services.settings
        self._auditor: Auditor = services.auditor
        queue = services.queue
        agents = services.agents
        if queue is None or agents is None:
            msg = "these services were built without the work queue (S16 stack required)"
            raise ScanStateError(msg)
        self.queue: QueueBackend = queue
        self.agents: AgentRegistry = agents

    # ------------------------------------------------------------------ control plane
    def register(
        self,
        name: str,
        *,
        principal: str,
        node: str | None = None,
        version: str | None = None,
        concurrency: int | None = None,
    ) -> AgentRecord:
        """Register (or re-register) an agent; the cap defaults to the deployment's."""
        record = self.agents.register(
            name,
            node=node,
            version=version,
            concurrency=concurrency if concurrency is not None else self._cap(),
        )
        self._auditor.record(
            AuditAction.AGENT_REGISTERED,
            target=name,
            meta={"agent": name, "node": node, "concurrency": record.concurrency, "key": principal},
        )
        return record

    def heartbeat(self, name: str, *, principal: str) -> dict[int, bool]:
        """Liveness + lease renewal. A ``False`` renewal means "abort that scan"."""
        record = self.agents.heartbeat(name)
        if record is None:
            raise ScanStateError(f"agent {name!r} is not registered")
        renewals = self.queue.renew(
            name, [entry.scan_id for entry in self.queue.held_by(name)], ttl_s=self._ttl()
        )
        self._auditor.record(
            AuditAction.AGENT_HEARTBEAT,
            target=name,
            meta={
                "agent": name,
                "key": principal,
                "held": sorted(renewals),
                "renewed": sorted(scan_id for scan_id, ok in renewals.items() if ok),
            },
        )
        return renewals

    def lease(
        self,
        name: str,
        *,
        principal: str,
        cap: int | None = None,
        ttl_s: float | None = None,
    ) -> tuple[QueueEntry, ...]:
        """Claim up to ``cap`` scans; expired leases are reclaimed (and noted) first."""
        record = self.agents.get(name)
        if record is None:
            raise ScanStateError(f"agent {name!r} is not registered")
        if not record.is_active:
            raise ScanStateError(f"agent {name!r} is retired and cannot claim work")
        for expired in self.queue.reclaim_expired():
            self._record_interruption(expired)
        effective_cap = min(cap if cap is not None else self._cap(), record.concurrency)
        claimed = self.queue.lease_next(
            name,
            agent_id=record.id,
            cap=effective_cap,
            ttl_s=ttl_s if ttl_s is not None else self._ttl(),
        )
        for entry in claimed:
            self._auditor.record(
                AuditAction.SCAN_LEASED,
                scan_id=entry.scan_id,
                target=f"agent:{name}",
                meta={
                    "agent": name,
                    "key": principal,
                    "attempt": entry.attempts,
                    "requested_by": entry.requested_by,
                },
            )
        return claimed

    def complete(self, name: str, scan_id: int, *, principal: str) -> bool:
        """Ack a finished scan. When the scheduler produced it, compute its diff."""
        released = self.queue.complete(name, scan_id)
        if not released:
            return False
        entry = self.queue.entry_for(scan_id)
        self._auditor.record(
            AuditAction.SCAN_RELEASED,
            scan_id=scan_id,
            target=f"agent:{name}",
            meta={
                "agent": name,
                "key": principal,
                "schedule_id": entry.schedule_id if entry else None,
            },
        )
        if entry is not None and entry.schedule_id and entry.previous_scan_id:
            self._diff_for_schedule(entry.previous_scan_id, scan_id)
        return True

    def queue_overview(self) -> dict[str, Any]:
        """Queue counts + the registered fleet (the operator's fleet view)."""
        return {
            "stats": self.queue.stats(),
            "agents": [record.to_dict() for record in self.agents.list_agents()],
        }

    # ------------------------------------------------------------------ internals
    def _record_interruption(self, expired: Any) -> None:
        """A dead agent's scan becomes re-leasable, with the interruption on record."""
        from datetime import datetime

        record = self._services.store.get_scan(int(expired.scan_id))
        stats = dict(record.stats) if record is not None else {}
        interruptions = list(stats.get("interruptions") or [])
        moment = expired.expired_at if isinstance(expired.expired_at, datetime) else None
        interruptions.append(
            {
                "agent": expired.agent_name,
                "at": moment.isoformat() if moment else None,
                "reason": "lease expired without a heartbeat; the scan was re-queued",
                "attempt": int(expired.attempts),
            }
        )
        stats["interruptions"] = interruptions
        if record is not None:
            self._services.store.update_scan(int(expired.scan_id), stats=stats)
        self._auditor.record(
            AuditAction.SCAN_INTERRUPTED,
            outcome=AuditOutcome.ERROR,
            scan_id=int(expired.scan_id),
            reason="lease expired without a heartbeat; the scan was re-queued",
            meta={"agent": expired.agent_name, "attempt": int(expired.attempts)},
        )

    def _diff_for_schedule(self, earlier: int, current: int) -> None:
        """The producer (scheduler) deferred its diff to the completion path."""
        from arachne.scheduler.runner import store_diff_for_scans

        try:
            store_diff_for_scans(self._services, earlier, current)
        except Exception as exc:  # the scan succeeded; a diff failure is reported, not fatal
            _logger.error(
                "scheduled diff failed",
                extra={
                    "event": "scheduler.diff.failed",
                    "scan_id": current,
                    "error": str(exc),
                },
            )

    def _cap(self) -> int:
        return self._settings.distributed.concurrency

    def _ttl(self) -> float:
        return float(self._settings.distributed.lease_ttl_s)
