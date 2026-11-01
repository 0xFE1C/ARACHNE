"""API request rate limiting (F-08-02, S12).

The scanner's own limiter (:mod:`arachne.core.ratelimit`) *waits* — a scan is polite and
slow by design. An API must not wait: it answers ``429 Too Many Requests`` and tells the
client when to come back. This module is the small non-blocking counterpart: a token
bucket per identity, refilled from a monotonic clock, with a ``try_acquire`` that never
sleeps.

The identity is the presented API key's digest when there is one, otherwise the client
address, so an unauthenticated flood against the login endpoint is bounded too. The clock
is injectable, which is what makes the unit test exact rather than three seconds long.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

__all__ = ["ApiRateLimiter", "RateLimitDecision"]

Clock = Callable[[], float]


@dataclass(frozen=True, slots=True)
class RateLimitDecision:
    """The outcome of one rate-limit check."""

    allowed: bool
    remaining: int = 0
    retry_after_s: float = 0.0
    limit: int = 0


class _Bucket:
    """One token bucket, refilled lazily on access (no background task)."""

    __slots__ = ("_tokens", "_updated", "capacity", "rate")

    def __init__(self, rate_per_second: float, capacity: float, now: float) -> None:
        self.rate = rate_per_second
        self.capacity = capacity
        self._tokens = capacity
        self._updated = now

    def take(self, now: float) -> tuple[bool, float, float]:
        """Try to take one token; return ``(allowed, tokens_left, seconds_until_one)``."""
        elapsed = now - self._updated
        if elapsed > 0:
            self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
            self._updated = now
        if self._tokens >= 1.0:
            self._tokens -= 1.0
            return True, self._tokens, 0.0
        deficit = 1.0 - self._tokens
        return False, self._tokens, deficit / self.rate


class ApiRateLimiter:
    """Per-identity token bucket in front of every API request."""

    def __init__(
        self,
        *,
        per_minute: int = 120,
        burst: int = 30,
        clock: Clock | None = None,
        max_identities: int = 4096,
    ) -> None:
        if per_minute < 1 or burst < 1:
            msg = "per_minute and burst must be >= 1"
            raise ValueError(msg)
        self.per_minute = per_minute
        self.burst = burst
        self._rate = per_minute / 60.0
        self._clock = clock or _monotonic
        self._max_identities = max_identities
        self._buckets: dict[str, _Bucket] = {}

    def check(self, identity: str) -> RateLimitDecision:
        """Take one token for ``identity``; never blocks."""
        now = self._clock()
        bucket = self._buckets.get(identity)
        if bucket is None:
            if len(self._buckets) >= self._max_identities:
                # Bounded memory: drop the oldest-inserted entry rather than grow without
                # limit under a flood of spoofed identities.
                self._buckets.pop(next(iter(self._buckets)), None)
            bucket = _Bucket(self._rate, float(self.burst), now)
            self._buckets[identity] = bucket
        allowed, remaining, retry_after = bucket.take(now)
        return RateLimitDecision(
            allowed=allowed,
            remaining=int(remaining),
            retry_after_s=round(retry_after, 3),
            limit=self.per_minute,
        )


def _monotonic() -> float:
    import time

    return time.monotonic()
