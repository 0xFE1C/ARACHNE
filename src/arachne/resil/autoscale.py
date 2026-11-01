"""Scan-farm autoscaling on queue depth (S25, REQ-RESIL-003).

The scan farm is the pool of agent pods that drain the work queue (REQ-SCALE-001). Its
correct size is a function of one number — how much work is waiting — so the autoscaling
decision is a pure function and this module is it:

* :func:`plan_replicas` turns a queue depth into a desired replica count:
  ``ceil(depth / queue_depth_per_replica)``, clamped to ``[min, max]``. ``min_replicas=0``
  is **scale-to-zero**: an idle estate runs no scanning pods at all, which is the point of
  a farm that costs money per hour.
* :class:`QueueDepthSource` is the seam: the production implementation reads the queue's
  ``queued`` count, and a test supplies a fake so the decision can be exercised without a
  cluster. :class:`StaticDepthSource` is that fake, shipped rather than written per test.
* :class:`ScaleToZeroPolicy` adds the one piece of state a pure function cannot carry: a
  scale-to-zero decision only happens after the queue has been empty for a cooldown, so a
  burst that arrives between two scrapes does not make the farm thrash.

What acts on the decision is Kubernetes: the Helm chart ships a KEDA ``ScaledObject`` (and
a plain-HPA alternative) that queries the ``arachne_queue_depth`` gauge this build already
exposes (REQ-OPS-003). ``arachne queue autoscale`` prints the same decision for an operator
who wants to see it without a cluster, and it is the command the acceptance test drives
with a fake depth source.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

__all__ = [
    "QueueDepthSource",
    "ScaleDecision",
    "ScaleToZeroPolicy",
    "StaticDepthSource",
    "plan_replicas",
    "queue_depth_source",
]

#: How long (seconds) the queue must stay empty before scale-to-zero is allowed. Kubernetes'
#: own scale-down stabilisation does the same job for the HPA/KEDA path; this is the piece
#: the CLI's planner needs to give the same answer.
DEFAULT_IDLE_COOLDOWN_S = 300.0


class QueueDepthSource(Protocol):
    """Where the planner reads "how much work is waiting" from."""

    def depth(self) -> int:
        """The number of queued (not leased, not done) scans."""
        ...


class StaticDepthSource:
    """A fixed depth, or a scripted sequence (tests, and ``arachne queue autoscale --depth``)."""

    def __init__(self, depth: int = 0, *, script: list[int] | None = None) -> None:
        self._depth = depth
        self._script = list(script or [])
        self.calls = 0

    def depth(self) -> int:
        self.calls += 1
        if self._script:
            self._depth = self._script.pop(0)
        return self._depth

    def set(self, depth: int) -> None:
        self._depth = depth


@dataclass(frozen=True, slots=True)
class ScaleDecision:
    """One planner decision, with the arithmetic that produced it."""

    depth: int
    desired: int
    #: The unclamped ceiling the depth alone asked for, before ``max_replicas``.
    raw: int
    min_replicas: int
    max_replicas: int
    per_replica: int
    reason: str

    @property
    def scale_to_zero(self) -> bool:
        return self.desired == 0

    @property
    def clamped(self) -> bool:
        return self.raw != self.desired

    def to_dict(self) -> dict[str, Any]:
        return {
            "depth": self.depth,
            "desired": self.desired,
            "raw": self.raw,
            "min_replicas": self.min_replicas,
            "max_replicas": self.max_replicas,
            "per_replica": self.per_replica,
            "reason": self.reason,
            "scale_to_zero": self.scale_to_zero,
            "clamped": self.clamped,
        }


def plan_replicas(
    depth: int,
    *,
    per_replica: int = 4,
    min_replicas: int = 0,
    max_replicas: int = 8,
) -> ScaleDecision:
    """The number of scan workers ``depth`` queued scans justify.

    ``per_replica`` is the queue depth one worker is expected to keep up with; it is the
    sizing knob an operator tunes from observed scan durations, not a guess this module
    makes. The ceiling is a safety property, not a cost one: an unbounded fan-out on a
    sudden queue spike would take the database down with it, so the clamp wins over the
    arithmetic.
    """
    if per_replica < 1:
        msg = "per_replica must be >= 1"
        raise ValueError(msg)
    if min_replicas < 0 or max_replicas < min_replicas:
        msg = "replicas must satisfy 0 <= min_replicas <= max_replicas"
        raise ValueError(msg)
    waiting = max(0, int(depth))
    raw = -(-waiting // per_replica)  # ceil division, without floating point
    desired = min(max(raw, min_replicas), max_replicas)
    if waiting == 0 and desired == 0:
        reason = "queue empty and scale-to-zero is allowed"
    elif desired == max_replicas and raw > max_replicas:
        reason = f"queue depth {waiting} wants {raw} workers; clamped to max_replicas"
    elif desired == min_replicas and raw < min_replicas:
        reason = f"queue depth {waiting} is below min_replicas"
    else:
        reason = f"queue depth {waiting} ÷ {per_replica} per worker = {desired}"
    return ScaleDecision(
        depth=waiting,
        desired=desired,
        raw=raw,
        min_replicas=min_replicas,
        max_replicas=max_replicas,
        per_replica=per_replica,
        reason=reason,
    )


class ScaleToZeroPolicy:
    """Adds the idle cooldown scale-to-zero needs (and a clock seam for tests).

    A pure ``plan_replicas(0, min_replicas=0)`` returns 0 immediately, which would drop the
    farm to nothing between two scans of a busy hour and immediately scale it back. This
    policy holds a floor of 1 until the queue has been empty for ``idle_cooldown_s``.
    """

    def __init__(
        self,
        *,
        idle_cooldown_s: float = DEFAULT_IDLE_COOLDOWN_S,
        clock: Callable[[], float] | None = None,
    ) -> None:
        if idle_cooldown_s < 0:
            msg = "idle_cooldown_s must be >= 0"
            raise ValueError(msg)
        self.idle_cooldown_s = idle_cooldown_s
        self._clock = clock or time.monotonic
        self._idle_since: float | None = None

    def decide(
        self,
        depth: int,
        *,
        per_replica: int = 4,
        min_replicas: int = 0,
        max_replicas: int = 8,
    ) -> ScaleDecision:
        if depth > 0:
            self._idle_since = None
            return plan_replicas(
                depth,
                per_replica=per_replica,
                min_replicas=min_replicas,
                max_replicas=max_replicas,
            )
        now = self._clock()
        if self._idle_since is None:
            self._idle_since = now
        idle_for = now - self._idle_since
        if min_replicas == 0 and idle_for < self.idle_cooldown_s:
            return ScaleDecision(
                depth=0,
                desired=1,
                raw=0,
                min_replicas=min_replicas,
                max_replicas=max_replicas,
                per_replica=per_replica,
                reason=(
                    f"queue empty for {idle_for:.0f}s of the {self.idle_cooldown_s:.0f}s "
                    "cooldown: holding one worker before scaling to zero"
                ),
            )
        return plan_replicas(
            0, per_replica=per_replica, min_replicas=min_replicas, max_replicas=max_replicas
        )


def queue_depth_source(services: Any) -> QueueDepthSource:
    """The production depth source: the ``queued`` count of this deployment's work queue.

    Returns a static zero when the deployment has no queue wired (a single-process install),
    so a caller never has to special-case the absence of distributed mode.
    """

    class _StoreDepth:
        def depth(self) -> int:
            queue = getattr(services, "queue", None)
            if queue is None:
                return 0
            stats = queue.stats()
            return int(stats.get("queued", 0))

    return _StoreDepth()
