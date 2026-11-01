"""Token-bucket rate limiting enforced in the shared HTTP client (F-01-07).

Two budgets apply to every outbound request ("never bypassed by
retries"): a **per-host** budget and a **global** budget. Both are classic token
buckets: ``rate`` tokens are added per second up to ``burst`` capacity, and a caller
waits until a token is available.

The clock and the sleep function are injectable, which makes the limiter deterministic
in tests (no real waiting, no flakiness) while remaining a plain ``time.monotonic`` +
``asyncio.sleep`` implementation in production.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Final

__all__ = ["HostRateLimiter", "RateLimitSettings", "TokenBucket"]

Clock = Callable[[], float]
Sleeper = Callable[[float], Awaitable[None]]

#: Guards against a zero-delay busy loop when the clock and the computation disagree by
#: floating-point noise.
_EPSILON: Final = 1e-9


@dataclass(frozen=True, slots=True)
class RateLimitSettings:
    """Rate-limit budgets. Defaults follow F-01-07 (a conservative, polite scan)."""

    per_host_rate: float = 5.0
    per_host_burst: int = 5
    global_rate: float = 20.0
    global_burst: int = 20

    def __post_init__(self) -> None:
        for label, value in (
            ("per_host_rate", self.per_host_rate),
            ("global_rate", self.global_rate),
        ):
            if value <= 0:
                msg = f"{label} must be > 0, got {value}"
                raise ValueError(msg)
        bursts = (("per_host_burst", self.per_host_burst), ("global_burst", self.global_burst))
        for label, burst in bursts:
            if burst < 1:
                msg = f"{label} must be >= 1, got {burst}"
                raise ValueError(msg)


class TokenBucket:
    """Async token bucket."""

    def __init__(
        self,
        rate: float,
        burst: int,
        *,
        clock: Clock = time.monotonic,
        sleep: Sleeper = asyncio.sleep,
    ) -> None:
        if rate <= 0:
            msg = f"rate must be > 0, got {rate}"
            raise ValueError(msg)
        if burst < 1:
            msg = f"burst must be >= 1, got {burst}"
            raise ValueError(msg)
        self.rate = float(rate)
        self.capacity = float(burst)
        self._tokens = float(burst)
        self._clock = clock
        self._sleep = sleep
        self._updated = clock()
        self._lock = asyncio.Lock()
        self._waiters = 0

    @property
    def tokens(self) -> float:
        """Tokens currently available (without advancing the bucket)."""
        return self._tokens

    def _refill(self) -> None:
        now = self._clock()
        elapsed = now - self._updated
        if elapsed > 0:
            self._tokens = min(self.capacity, self._tokens + elapsed * self.rate)
            self._updated = now

    async def acquire(self, tokens: float = 1.0) -> float:
        """Wait until ``tokens`` are available; return the seconds waited."""
        if tokens > self.capacity:
            msg = f"cannot acquire {tokens} tokens from a bucket of capacity {self.capacity}"
            raise ValueError(msg)

        waited = 0.0
        self._waiters += 1
        try:
            while True:
                async with self._lock:
                    self._refill()
                    if self._tokens >= tokens:
                        self._tokens -= tokens
                        return waited
                    deficit = tokens - self._tokens
                    delay = deficit / self.rate + _EPSILON
                # Sleep outside the lock so other waiters are not blocked on the timer.
                await self._sleep(delay)
                waited += delay
        finally:
            self._waiters -= 1


class HostRateLimiter:
    """Per-host + global token buckets, created lazily per host."""

    def __init__(
        self,
        settings: RateLimitSettings | None = None,
        *,
        clock: Clock = time.monotonic,
        sleep: Sleeper = asyncio.sleep,
    ) -> None:
        self.settings = settings or RateLimitSettings()
        self._clock = clock
        self._sleep = sleep
        self._global = TokenBucket(
            self.settings.global_rate,
            self.settings.global_burst,
            clock=clock,
            sleep=sleep,
        )
        self._hosts: dict[str, TokenBucket] = {}
        self._lock = asyncio.Lock()

    @staticmethod
    def normalize_host(host: str) -> str:
        """Lower-case the host and drop any port, so budgets are per-host."""
        return host.strip().lower().rstrip(".").split(":", 1)[0]

    async def bucket_for(self, host: str) -> TokenBucket:
        key = self.normalize_host(host)
        async with self._lock:
            bucket = self._hosts.get(key)
            if bucket is None:
                bucket = TokenBucket(
                    self.settings.per_host_rate,
                    self.settings.per_host_burst,
                    clock=self._clock,
                    sleep=self._sleep,
                )
                self._hosts[key] = bucket
            return bucket

    async def acquire(self, host: str) -> float:
        """Acquire one request slot for ``host``; returns total seconds waited.

        Order is deliberate: the per-host budget is consulted first so a host that is
        being throttled does not consume global capacity while it waits.
        """
        host_bucket = await self.bucket_for(host)
        waited = await host_bucket.acquire()
        waited += await self._global.acquire()
        return waited
