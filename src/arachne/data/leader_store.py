"""Leader election for the HA control plane (S25, REQ-RESIL-002).

A multi-replica API is N identical pods, but several of its jobs must run **once**: the
scheduler tick (which would otherwise admit every due schedule N times), the retention
prune, the automatic chain anchor. The lease lives in the database every replica already
shares rather than in a second coordination service, following the same "the database is
the broker" posture the work queue takes (REQ-SCALE-001, ADR-210.1).

Two properties make it usable in a replica-kill test rather than merely in a diagram:

* **The acquisition is a compare-and-swap.** ``leader_leases.token`` is the ORM's *version
  counter*, so every update the ORM emits carries ``WHERE token = <the value this session
  read>``. Two replicas that race a free lease therefore cannot both win: the loser's
  update matches no row, SQLAlchemy raises ``StaleDataError``, and this class reports "not
  the leader". No lock service, no split brain.
* **Liveness is computed, never stored.** A lease whose ``expires_at`` has passed is free
  regardless of what ``holder`` says, so a replica that is SIGKILLed hands the lease on by
  simply not renewing it. There is no cleanup step for the killer to skip.
"""

from __future__ import annotations

import os
import socket
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError as SaIntegrityError
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.orm.exc import StaleDataError

from arachne.core.audit import AuditAction, Auditor
from arachne.core.logging import get_logger
from arachne.data.models import LeaderLease
from arachne.data.scan_store import as_utc

__all__ = ["LeaderElector", "LeaseState", "default_holder"]

_logger = get_logger("data.leader")


def default_holder(name: str) -> str:
    """A replica identity: hostname, pid and the lease name — what an operator greps for."""
    try:
        host = socket.gethostname()
    except OSError:  # pragma: no cover - a sandbox without a hostname
        host = "unknown-host"
    return f"{host}:{os.getpid()}:{name}"


@dataclass(frozen=True, slots=True)
class LeaseState:
    """Who holds a lease right now (``holder`` is ``None`` when it is free)."""

    name: str
    holder: str | None
    expires_at: datetime | None
    token: int

    @property
    def held(self) -> bool:
        return self.holder is not None

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "holder": self.holder,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "token": self.token,
            "held": self.held,
        }


class LeaderElector:
    """One named singleton lease, held by at most one replica at a time."""

    def __init__(
        self,
        session_factory: sessionmaker[Session],
        *,
        name: str,
        holder: str | None = None,
        ttl_s: int = 30,
        auditor: Auditor | None = None,
    ) -> None:
        if not name.strip():
            msg = "a leader lease needs a name"
            raise ValueError(msg)
        if ttl_s < 1:
            msg = "a leader lease needs a positive TTL"
            raise ValueError(msg)
        self._session_factory = session_factory
        self.name = name
        self.holder = holder or default_holder(name)
        self.ttl_s = ttl_s
        self.auditor = auditor

    # ------------------------------------------------------------------ reads
    def state(self) -> LeaseState:
        """The lease as stored, with an expired holder read as free."""
        with self._session_factory() as session:
            row = session.scalar(select(LeaderLease).where(LeaderLease.name == self.name))
            if row is None:
                return LeaseState(name=self.name, holder=None, expires_at=None, token=0)
            expires = as_utc(row.expires_at)
            live = expires is None or expires > datetime.now(UTC)
            return LeaseState(
                name=self.name,
                holder=str(row.holder) if live and row.holder else None,
                expires_at=expires,
                token=int(row.token),
            )

    def is_leader(self) -> bool:
        """True when **this** replica currently holds the lease."""
        return self.state().holder == self.holder

    # ------------------------------------------------------------------ acts
    def try_acquire(self, *, reason: str = "tick") -> bool:
        """Try to take (or renew) the lease. ``True`` when this replica holds it now."""
        now = datetime.now(UTC)
        with self._session_factory() as session:
            row = session.scalar(select(LeaderLease).where(LeaderLease.name == self.name))
            if row is None:
                try:
                    session.add(
                        LeaderLease(
                            name=self.name,
                            holder=self.holder,
                            acquired_at=now,
                            expires_at=now + timedelta(seconds=self.ttl_s),
                            token=1,
                            updated_at=now,
                        )
                    )
                    session.commit()
                except SaIntegrityError:  # another replica created it first
                    session.rollback()
                    return False
                self._audit(AuditAction.LEADER_ACQUIRED, reason, token=1)
                return True

            expires = as_utc(row.expires_at)
            free = expires is None or expires <= now
            if not (free or row.holder == self.holder):
                return False
            # The version counter (``leader_leases.token``) makes this a compare-and-swap:
            # SQLAlchemy adds ``WHERE token = <observed>`` to the UPDATE, so a replica that
            # lost the race sees no row match and is refused here rather than double-holding.
            row.holder = self.holder
            row.acquired_at = now
            row.expires_at = now + timedelta(seconds=self.ttl_s)
            row.updated_at = now
            try:
                session.commit()
            except StaleDataError:
                session.rollback()
                return False
            token = int(row.token)
        self._audit(AuditAction.LEADER_ACQUIRED, reason, token=token)
        return True

    def release(self, *, reason: str = "shutdown") -> bool:
        """Give the lease up voluntarily (a graceful shutdown)."""
        now = datetime.now(UTC)
        with self._session_factory() as session:
            row = session.scalar(select(LeaderLease).where(LeaderLease.name == self.name))
            if row is None or row.holder != self.holder:
                return False
            row.holder = None
            row.expires_at = now
            row.updated_at = now
            try:
                session.commit()
            except StaleDataError:  # someone else already took it: nothing to release
                session.rollback()
                return False
        self._audit(AuditAction.LEADER_LOST, reason, token=None)
        return True

    def _audit(self, action: AuditAction, reason: str, *, token: int | None) -> None:
        if self.auditor is None:
            return
        self.auditor.record(
            action,
            target=self.name,
            meta={"holder": self.holder, "reason": reason, "token": token},
        )
