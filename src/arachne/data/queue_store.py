"""The Postgres work queue and the agent registry (S16, area SCALE).

The database is the broker. A producer (the API or the scheduler) enqueues an *admitted*
scan — the gates have already run at admission — and an ``arachne agent`` leases it. Two
tables carry the whole protocol (REQ-SCALE-001…004):

* ``scan_queue`` — one row per enqueued scan. ``scan_id`` is UNIQUE, so a scan is
  enqueued exactly once, and a row moves ``queued → leased → done`` (or ``cancelled``
  when an operator stops the scan). Leases expire: a row left ``leased`` past its
  ``lease_expires_at`` is reclaimed by the next claimant and becomes re-leasable, with
  the interruption recorded on the scan (REQ-SCALE-003).
* ``scan_agents`` — one row per registered agent; the heartbeat keeps it live and the
  queue stamps every lease with the agent's id, so the audit trail names the node that
  executed a scan (REQ-SCALE-004).

**Claiming.** On Postgres the claim is the canonical
``SELECT … FOR UPDATE SKIP LOCKED``: concurrent agents lock disjoint rows, never block
each other, and never see the same row. On other dialects (SQLite — the single-node and
test backend) the claim is a single atomic ``UPDATE … WHERE status = 'queued'`` whose
``rowcount`` decides the win: one writer commits, the loser's guard fails. Both paths
satisfy the same invariant — **no scan may execute on two nodes at once** — and the
Postgres statement shape is pinned by a unit test.

The stores here stay schema-mechanical (like :mod:`arachne.data.scan_store`): auditing,
interruption notes and diff computation belong to :mod:`arachne.agent.service`, which
wraps them.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Protocol

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session, sessionmaker

from arachne.core.errors import ScanStateError
from arachne.data.models import Scan, ScanAgent, ScanQueue
from arachne.data.scan_store import as_utc

__all__ = [
    "QUEUE_ACTIVE_STATUSES",
    "AgentRecord",
    "AgentRegistry",
    "ExpiredLease",
    "QueueBackend",
    "QueueEntry",
    "WorkQueue",
]

#: Statuses of a queue row that can still move (i.e. the scan may still run).
QUEUE_ACTIVE_STATUSES: frozenset[str] = frozenset({"queued", "leased"})


def _utcnow() -> datetime:
    return datetime.now(UTC)


def _as_utc_or_none(value: datetime | None) -> datetime | None:
    return as_utc(value)


@dataclass(frozen=True, slots=True)
class QueueEntry:
    """One row of the work queue, as the control plane and the UI see it."""

    id: int
    scan_id: int
    project_id: int | None
    status: str
    priority: int
    agent_id: int | None
    agent_name: str | None
    lease_expires_at: datetime | None
    attempts: int
    requested_by: str | None
    schedule_id: str | None
    previous_scan_id: int | None
    meta: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "project_id": self.project_id,
            "status": self.status,
            "priority": self.priority,
            "agent": self.agent_name,
            "lease_expires_at": self.lease_expires_at.isoformat()
            if self.lease_expires_at
            else None,
            "attempts": self.attempts,
            "requested_by": self.requested_by,
            "schedule_id": self.schedule_id,
            "previous_scan_id": self.previous_scan_id,
        }


@dataclass(frozen=True, slots=True)
class AgentRecord:
    """One registered agent (``scan_agents`` row)."""

    id: int
    name: str
    node: str | None = None
    version: str | None = None
    concurrency: int = 1
    status: str = "active"
    last_heartbeat_at: datetime | None = None
    registered_at: datetime | None = None

    @property
    def is_active(self) -> bool:
        return self.status == "active"

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "node": self.node,
            "version": self.version,
            "concurrency": self.concurrency,
            "status": self.status,
            "last_heartbeat_at": self.last_heartbeat_at.isoformat()
            if self.last_heartbeat_at
            else None,
        }


@dataclass(frozen=True, slots=True)
class ExpiredLease:
    """A lease the reaper took back from an agent that stopped answering."""

    scan_id: int
    agent_name: str | None
    attempts: int
    expired_at: datetime


def _agent_row_to_record(row: ScanAgent) -> AgentRecord:
    return AgentRecord(
        id=int(row.id),
        name=str(row.name),
        node=row.node,
        version=row.version,
        concurrency=int(row.concurrency),
        status=str(row.status),
        last_heartbeat_at=_as_utc_or_none(row.last_heartbeat_at),
        registered_at=_as_utc_or_none(row.created_at),
    )


class AgentRegistry:
    """Registration and heartbeat for the ``arachne agent`` role (REQ-SCALE-002)."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    def register(
        self,
        name: str,
        *,
        node: str | None = None,
        version: str | None = None,
        concurrency: int = 1,
        meta: dict[str, Any] | None = None,
        now: datetime | None = None,
    ) -> AgentRecord:
        """Idempotent registration: a re-registering agent refreshes its row."""
        if not name.strip():
            msg = "an agent must have a non-empty name"
            raise ScanStateError(msg)
        if concurrency < 1:
            msg = f"agent {name!r} concurrency cap must be >= 1, got {concurrency}"
            raise ScanStateError(msg)
        moment = _as_utc_or_none(now) or _utcnow()
        with self._session_factory() as session:
            row = session.scalar(select(ScanAgent).where(ScanAgent.name == name))
            if row is None:
                row = ScanAgent(name=name, concurrency=concurrency)
                session.add(row)
            row.node = node
            row.version = version
            row.concurrency = concurrency
            row.status = "active"
            row.last_heartbeat_at = moment
            if meta:
                row.meta_json = dict(meta)
            session.commit()
            session.refresh(row)
            return _agent_row_to_record(row)

    def heartbeat(self, name: str, *, now: datetime | None = None) -> AgentRecord | None:
        """Refresh the agent's liveness; ``None`` for an unregistered name."""
        moment = _as_utc_or_none(now) or _utcnow()
        with self._session_factory() as session:
            row = session.scalar(select(ScanAgent).where(ScanAgent.name == name))
            if row is None:
                return None
            row.last_heartbeat_at = moment
            session.commit()
            session.refresh(row)
            return _agent_row_to_record(row)

    def get(self, name: str) -> AgentRecord | None:
        with self._session_factory() as session:
            row = session.scalar(select(ScanAgent).where(ScanAgent.name == name))
            return None if row is None else _agent_row_to_record(row)

    def list_agents(self) -> tuple[AgentRecord, ...]:
        with self._session_factory() as session:
            rows = session.scalars(select(ScanAgent).order_by(ScanAgent.name)).all()
        return tuple(_agent_row_to_record(row) for row in rows)

    def retire(self, name: str) -> bool:
        """Mark an agent retired: it no longer claims work. ``False`` when unknown."""
        with self._session_factory() as session:
            row = session.scalar(select(ScanAgent).where(ScanAgent.name == name))
            if row is None:
                return False
            row.status = "retired"
            session.commit()
            return True


class QueueBackend(Protocol):
    """The queue interface a backend implements (REQ-SCALE-001's reserved adapter seam).

    The default backend is the Postgres table (:class:`WorkQueue` — the database is the
    broker and no message broker is a default dependency). A Redis (or other) adapter
    implements this protocol and is wired in at the composition root; nothing above
    this layer knows which backend holds the rows.
    """

    def enqueue(
        self,
        scan_id: int,
        *,
        project_id: int | None = None,
        priority: int = 0,
        requested_by: str | None = None,
        schedule_id: str | None = None,
        previous_scan_id: int | None = None,
        meta: dict[str, Any] | None = None,
    ) -> QueueEntry: ...

    def lease_next(
        self,
        agent_name: str,
        *,
        agent_id: int,
        cap: int = 1,
        ttl_s: float = 300.0,
        now: datetime | None = None,
    ) -> tuple[QueueEntry, ...]: ...

    def reclaim_expired(self, *, now: datetime | None = None) -> tuple[ExpiredLease, ...]: ...

    def renew(
        self,
        agent_name: str,
        scan_ids: Iterable[int],
        *,
        ttl_s: float,
        now: datetime | None = None,
    ) -> dict[int, bool]: ...

    def complete(self, agent_name: str, scan_id: int, *, now: datetime | None = None) -> bool: ...

    def cancel(self, scan_id: int) -> bool: ...

    def entry_for(self, scan_id: int) -> QueueEntry | None: ...

    def held_by(self, agent_name: str) -> tuple[QueueEntry, ...]: ...

    def list_entries(
        self, *, status: str | None = None, limit: int = 100
    ) -> tuple[QueueEntry, ...]: ...

    def stats(self) -> dict[str, int]: ...


class WorkQueue:
    """The scan work queue over ``scan_queue`` (REQ-SCALE-001/003)."""

    def __init__(self, session_factory: sessionmaker[Session], *, dialect: str = "sqlite") -> None:
        self._session_factory = session_factory
        self._dialect = dialect

    # ------------------------------------------------------------------ produce
    def enqueue(
        self,
        scan_id: int,
        *,
        project_id: int | None = None,
        priority: int = 0,
        requested_by: str | None = None,
        schedule_id: str | None = None,
        previous_scan_id: int | None = None,
        meta: dict[str, Any] | None = None,
    ) -> QueueEntry:
        """Queue an admitted scan. Refuses a second enqueue of the same scan."""
        with self._session_factory() as session:
            self._require_scan(session, scan_id)
            existing = session.scalar(select(ScanQueue).where(ScanQueue.scan_id == scan_id))
            if existing is not None:
                msg = f"scan {scan_id} is already queued (status {existing.status!r})"
                raise ScanStateError(msg)
            row = ScanQueue(
                scan_id=scan_id,
                project_id=project_id,
                status="queued",
                priority=priority,
                requested_by=requested_by,
                schedule_id=schedule_id,
                previous_scan_id=previous_scan_id,
                meta_json=dict(meta or {}),
            )
            session.add(row)
            session.commit()
            session.refresh(row)
            return self._entry(session, row)

    def cancel(self, scan_id: int) -> bool:
        """A producer/stop request: a queued or leased row becomes ``cancelled``.

        An agent holding the lease discovers the cancellation on its next heartbeat or
        ack (renew returns ``False``) and aborts locally — the row never runs again.
        """
        with self._session_factory() as session:
            row = session.scalar(select(ScanQueue).where(ScanQueue.scan_id == scan_id))
            if row is None or row.status not in QUEUE_ACTIVE_STATUSES:
                return False
            row.status = "cancelled"
            row.agent_id = None
            row.lease_expires_at = None
            session.commit()
            return True

    # ------------------------------------------------------------------ consume
    def lease_next(
        self,
        agent_name: str,
        *,
        agent_id: int,
        cap: int = 1,
        ttl_s: float = 300.0,
        now: datetime | None = None,
    ) -> tuple[QueueEntry, ...]:
        """Claim up to ``cap`` queued scans for ``agent_id`` ( honouring the cap).

        Expired leases are reclaimed first (so a dead agent's scan is re-leasable in the
        same beat); the caller records the interruption notes from
        :meth:`reclaim_expired`. The claim itself locks out concurrent claimants:
        ``FOR UPDATE SKIP LOCKED`` on Postgres, an atomic guarded ``UPDATE`` elsewhere.
        """
        if cap < 1:
            msg = "the lease cap must be >= 1"
            raise ScanStateError(msg)
        moment = _as_utc_or_none(now) or _utcnow()
        held = len(self.held_by(agent_name))
        claimed: list[QueueEntry] = []
        while held + len(claimed) < cap:
            entry = self._claim_one(agent_id, ttl_s=ttl_s, now=moment)
            if entry is None:
                break
            claimed.append(entry)
        return tuple(claimed)

    def reclaim_expired(self, *, now: datetime | None = None) -> tuple[ExpiredLease, ...]:
        """Re-queue leases whose ``lease_expires_at`` has passed (REQ-SCALE-003).

        Returns what was reclaimed so the caller can record the interruption on the
        scan; the guard in the ``UPDATE`` makes a concurrent reclaim idempotent.
        """
        moment = _as_utc_or_none(now) or _utcnow()
        with self._session_factory() as session:
            rows = session.execute(
                select(ScanQueue.scan_id, ScanAgent.name, ScanQueue.attempts, ScanQueue.id)
                .join(ScanAgent, ScanQueue.agent_id == ScanAgent.id, isouter=True)
                .where(
                    ScanQueue.status == "leased",
                    ScanQueue.lease_expires_at.is_not(None),
                    ScanQueue.lease_expires_at <= moment,
                )
            ).all()
            if not rows:
                return ()
            ids = [row[3] for row in rows]
            result = session.execute(
                update(ScanQueue)
                .where(
                    ScanQueue.id.in_(ids),
                    ScanQueue.status == "leased",
                    ScanQueue.lease_expires_at <= moment,
                )
                .values(
                    status="queued",
                    agent_id=None,
                    lease_expires_at=None,
                    updated_at=moment,
                )
                .execution_options(synchronize_session=False)
            )
            session.commit()
            if int(result.rowcount or 0) != len(ids):  # type: ignore[attr-defined]
                return ()  # a concurrent reaper got there first
            return tuple(
                ExpiredLease(
                    scan_id=int(row[0]),
                    agent_name=row[1],
                    attempts=int(row[2]),
                    expired_at=moment,
                )
                for row in rows
            )

    def renew(
        self,
        agent_name: str,
        scan_ids: Iterable[int],
        *,
        ttl_s: float,
        now: datetime | None = None,
    ) -> dict[int, bool]:
        """Heartbeat renewal: extend the agent's held leases; ``False`` when not held.

        A ``False`` value is the agent's signal to abort the scan locally: the row was
        cancelled, reclaimed, or completed by someone else.
        """
        moment = _as_utc_or_none(now) or _utcnow()
        out: dict[int, bool] = {}
        with self._session_factory() as session:
            agent_id = session.scalar(select(ScanAgent.id).where(ScanAgent.name == agent_name))
            for scan_id in scan_ids:
                result = session.execute(
                    update(ScanQueue)
                    .where(
                        ScanQueue.scan_id == int(scan_id),
                        ScanQueue.status == "leased",
                        ScanQueue.agent_id == agent_id,
                    )
                    .values(lease_expires_at=_plus(moment, ttl_s), updated_at=moment)
                    .execution_options(synchronize_session=False)
                )
                # CursorResult.rowcount is the claim decision; the typing stubs of
                # Result do not carry it (the same pattern as api_store.py).
                out[int(scan_id)] = int(result.rowcount or 0) == 1  # type: ignore[attr-defined]
            session.commit()
        return out

    def complete(self, agent_name: str, scan_id: int, *, now: datetime | None = None) -> bool:
        """Acknowledge a finished (or failed) scan: the row leaves the active set."""
        moment = _as_utc_or_none(now) or _utcnow()
        with self._session_factory() as session:
            agent_id = session.scalar(select(ScanAgent.id).where(ScanAgent.name == agent_name))
            result = session.execute(
                update(ScanQueue)
                .where(
                    ScanQueue.scan_id == scan_id,
                    ScanQueue.status == "leased",
                    ScanQueue.agent_id == agent_id,
                )
                .values(status="done", agent_id=None, lease_expires_at=None, updated_at=moment)
                .execution_options(synchronize_session=False)
            )
            session.commit()
            return int(result.rowcount or 0) == 1  # type: ignore[attr-defined]

    # ------------------------------------------------------------------ queries
    def entry_for(self, scan_id: int) -> QueueEntry | None:
        with self._session_factory() as session:
            row = session.scalar(select(ScanQueue).where(ScanQueue.scan_id == scan_id))
            return None if row is None else self._entry(session, row)

    def held_by(self, agent_name: str) -> tuple[QueueEntry, ...]:
        with self._session_factory() as session:
            rows = session.execute(
                select(ScanQueue)
                .join(ScanAgent, ScanQueue.agent_id == ScanAgent.id)
                .where(ScanAgent.name == agent_name, ScanQueue.status == "leased")
            ).scalars().all()
            return tuple(self._entry(session, row) for row in rows)

    def list_entries(
        self, *, status: str | None = None, limit: int = 100
    ) -> tuple[QueueEntry, ...]:
        with self._session_factory() as session:
            query = (
                select(ScanQueue)
                .order_by(ScanQueue.id.desc())
                .limit(max(1, limit))
            )
            if status is not None:
                query = query.where(ScanQueue.status == status)
            rows = session.scalars(query).all()
            return tuple(self._entry(session, row) for row in rows)

    def stats(self) -> dict[str, int]:
        """``{status: count}`` over the whole queue (the fleet dashboard's numbers)."""
        with self._session_factory() as session:
            rows = session.execute(
                select(ScanQueue.status, func.count()).group_by(ScanQueue.status)
            ).all()
        return {str(status): int(count) for status, count in rows}

    # ------------------------------------------------------------------ internals
    def _claim_one(
        self, agent_id: int, *, ttl_s: float, now: datetime
    ) -> QueueEntry | None:
        """Claim exactly one queued row, or ``None`` when the queue is drained."""
        with self._session_factory() as session:
            if self._dialect == "postgresql":
                # REQ-SCALE-001: the canonical Postgres claim — concurrent agents lock
                # disjoint rows and skip the locked ones, so no scan is ever handed to
                # two nodes and nobody queues behind a slow claimer.
                subquery = (
                    select(ScanQueue.id)
                    .where(ScanQueue.status == "queued")
                    .order_by(ScanQueue.priority.desc(), ScanQueue.id)
                    .limit(1)
                    .with_for_update(skip_locked=True)
                )
                locked = session.scalars(subquery).first()
                if locked is None:
                    return None
                result = session.execute(
                    update(ScanQueue)
                    .where(ScanQueue.id == int(locked), ScanQueue.status == "queued")
                    .values(
                        status="leased",
                        agent_id=agent_id,
                        lease_expires_at=_plus(now, ttl_s),
                        attempts=ScanQueue.attempts + 1,
                        updated_at=now,
                    )
                    .returning(ScanQueue.id)
                    .execution_options(synchronize_session=False)
                )
                claimed_id = result.scalar_one_or_none()
                session.commit()
                if claimed_id is None:
                    return None
                row = session.get(ScanQueue, int(claimed_id))
                return None if row is None else self._entry(session, row)

            # Portable path (SQLite — single-node and tests): one guarded UPDATE whose
            # RETURNING row decides the win. The WHERE clause is re-checked at write
            # time, so two claimants can never both flip the same row to ``leased``.
            next_id: Any = (
                select(ScanQueue.id)
                .where(ScanQueue.status == "queued")
                .order_by(ScanQueue.priority.desc(), ScanQueue.id)
                .limit(1)
                .scalar_subquery()
            )
            result = session.execute(
                update(ScanQueue)
                .where(ScanQueue.id == next_id, ScanQueue.status == "queued")
                .values(
                    status="leased",
                    agent_id=agent_id,
                    lease_expires_at=_plus(now, ttl_s),
                    attempts=ScanQueue.attempts + 1,
                    updated_at=now,
                )
                .returning(ScanQueue.id)
                .execution_options(synchronize_session=False)
            )
            claimed_id = result.scalar_one_or_none()
            session.commit()
            if claimed_id is None:
                return None
            row = session.get(ScanQueue, int(claimed_id))
            return None if row is None else self._entry(session, row)

    def _entry(self, session: Session, row: ScanQueue) -> QueueEntry:
        agent_name: str | None = None
        if row.agent_id is not None:
            agent_name = session.scalar(select(ScanAgent.name).where(ScanAgent.id == row.agent_id))
        return QueueEntry(
            id=int(row.id),
            scan_id=int(row.scan_id),
            project_id=row.project_id,
            status=str(row.status),
            priority=int(row.priority),
            agent_id=row.agent_id,
            agent_name=agent_name,
            lease_expires_at=_as_utc_or_none(row.lease_expires_at),
            attempts=int(row.attempts),
            requested_by=row.requested_by,
            schedule_id=row.schedule_id,
            previous_scan_id=row.previous_scan_id,
            meta=dict(row.meta_json or {}),
        )

    @staticmethod
    def _require_scan(session: Session, scan_id: int) -> Scan:
        scan = session.get(Scan, scan_id)
        if scan is None:
            msg = f"scan {scan_id} does not exist"
            raise ScanStateError(msg)
        return scan


def _plus(moment: datetime, ttl_s: float) -> datetime:
    """The lease deadline: ``moment`` plus ``ttl_s`` seconds."""
    return moment + timedelta(seconds=ttl_s)
