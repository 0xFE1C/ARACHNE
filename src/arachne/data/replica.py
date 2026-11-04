"""Read-replica failover for the control plane (REQ-SCALE-011).

**What this is for.** A deployment may point reads at a database replica. A replica can go
away — a failover, a restart, a network partition — and a read endpoint must not fail with
it. :class:`ReadReplicaRouter` hands out read sessions from a healthy replica and falls back
to the primary when the replica cannot answer, recording the degradation (a log line and a
counter) rather than hiding it.

**The consistency model, stated.** Writes always go to the primary; they are never routed.
Reads through this router may therefore be **stale** by the replica's replication lag, which
is why it is wired only to endpoints that were already read-only and eventually consistent —
the catalogue and listing queries — and never to a store that serves the response of a
mutation. An operator who needs read-your-writes must read the primary; that is what the
test suite and the CLI do.

**Why a probe rather than a lazy error.** A ``sessionmaker`` hands out a session whose
connection is opened lazily, so a dead replica would surface as an exception *inside* the
caller's query — after the endpoint had committed to it. ``read_session`` therefore opens the
replica's connection before handing a session out (no statement is executed: opening it is
the reachability test). That is one connection acquisition per read while a replica is
healthy; on a failure the replica is marked unhealthy and skipped for
:data:`DEFAULT_COOLDOWN_S`, so a dead replica costs one probe per cooldown, not one per
request.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from arachne.core.logging import get_logger
from arachne.core.metrics import REGISTRY

__all__ = [
    "DEFAULT_COOLDOWN_S",
    "FAILOVER_METRIC",
    "ReadReplicaRouter",
    "ReplicaState",
    "build_read_replica_router",
]

_logger = get_logger("data.replica")

#: How long a replica that failed its probe is skipped before it is tried again. Long enough
#: that a dead replica costs one probe per window, short enough that a recovered replica is
#: back in service without a restart.
DEFAULT_COOLDOWN_S = 30.0

#: The counter a failover increments. The ``replica`` label names which one failed.
FAILOVER_METRIC = "arachne_read_replica_failovers_total"


@dataclass(slots=True)
class ReplicaState:
    """One configured read replica and what the router knows about it."""

    name: str
    factory: sessionmaker[Session]
    healthy: bool = True
    failures: int = 0
    last_failure_at: float | None = None
    last_error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "healthy": self.healthy,
            "failures": self.failures,
            "last_error": self.last_error,
        }


@dataclass(slots=True)
class ReadReplicaRouter:
    """Hand out read sessions from a healthy replica, or from the primary.

    ``clock`` is injectable so a test can advance time past the cooldown without sleeping.
    """

    primary: sessionmaker[Session]
    replicas: tuple[ReplicaState, ...] = ()
    cooldown_s: float = DEFAULT_COOLDOWN_S
    clock: Callable[[], float] = time.monotonic
    _failovers: int = field(default=0, init=False)

    # ------------------------------------------------------------------ sessions
    def read_session(self) -> Session:
        """A session bound to a healthy replica, or to the primary when there is none."""
        for state in self.replicas:
            if not state.healthy and not self._cooldown_elapsed(state):
                continue
            if self._probe(state):
                if not state.healthy:  # it answered again: it is back in service
                    state.healthy = True
                    state.last_error = None
                    _logger.info(
                        "read replica recovered",
                        extra={"event": "db.replica_recovered", "replica": state.name},
                    )
                return state.factory()
        if self.replicas:
            self._failovers += 1
            REGISTRY.increment(FAILOVER_METRIC, {"replica": "all"})
        return self.primary()

    def __call__(self) -> Session:
        """``sessionmaker``-compatible: a store that calls the factory gets a read session."""
        return self.read_session()

    # ------------------------------------------------------------------ health
    def _cooldown_elapsed(self, state: ReplicaState) -> bool:
        if state.last_failure_at is None:
            return True
        return (self.clock() - state.last_failure_at) >= self.cooldown_s

    def _probe(self, state: ReplicaState) -> bool:
        """True when the replica's connection opens; a closed/failed replica raises here."""
        try:
            with state.factory() as session:
                session.connection()
            return True
        except SQLAlchemyError as exc:
            state.healthy = False
            state.failures += 1
            state.last_failure_at = self.clock()
            state.last_error = f"{exc.__class__.__name__}: {exc}"[:300]
            REGISTRY.increment(FAILOVER_METRIC, {"replica": state.name})
            _logger.warning(
                "read replica unavailable; falling back to the primary",
                extra={
                    "event": "db.read_replica_fallback",
                    "replica": state.name,
                    "error": state.last_error,
                    "consecutive_failures": state.failures,
                },
            )
            return False

    def stats(self) -> dict[str, Any]:
        """The degradation state, for the health surface and the tests."""
        return {
            "replicas": [state.to_dict() for state in self.replicas],
            "degraded": any(not state.healthy for state in self.replicas),
            "failovers": self._failovers,
            "cooldown_s": self.cooldown_s,
        }


def build_read_replica_router(
    primary: sessionmaker[Session],
    replica_factories: Iterable[tuple[str, sessionmaker[Session]]],
) -> ReadReplicaRouter | None:
    """A router over named replica session factories, or ``None`` when none are configured.

    ``replica_factories`` is an iterable of ``(name, sessionmaker)`` pairs — the shape
    :func:`arachne.data.services.build_services` constructs from the deployment's replica
    URLs.
    """
    replicas = tuple(
        ReplicaState(name=name, factory=factory) for name, factory in replica_factories
    )
    if not replicas:
        return None
    return ReadReplicaRouter(primary=primary, replicas=replicas)
