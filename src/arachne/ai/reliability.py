"""Retry, backoff, pacing and the circuit breaker (F-04-06).

 asks for four things at once, and they interact, so they live together:

**Retries with exponential backoff + jitter**, "only on transient errors (429/5xx/network),
never on validation failures". The classification comes from the error itself
(:attr:`~arachne.ai.types.ProviderError.transient`), not from a status code guessed here.

**Rate limits**, a token bucket per provider, plus the server's own ``Retry-After`` when it sent
one — a provider that says "wait 20 seconds" is obeyed rather than second-guessed.

**Timeouts**, enforced once, in the transport (``asyncio.wait_for`` around the HTTP call), so a
hung endpoint degrades a stage instead of a scan.

**A circuit breaker.** Without one, a provider that is down costs ``attempts`` round trips *per
candidate*: a scan with 200 candidates would spend 600 timeouts learning what the first one
already proved. After ``failure_threshold`` consecutive transient failures the provider is
marked degraded, further calls fail immediately, and the engine's degradation chain takes over.
That is what "any provider failure falls back to heuristic mode or to the previous successful
analysis without losing the scan" means in practice.
"""

from __future__ import annotations

import asyncio
import random as random_module
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Final

from arachne.ai.types import (
    CompletionRequest,
    CompletionResult,
    LLMProvider,
    ProviderError,
    ProviderUnavailableError,
)
from arachne.core.logging import get_logger
from arachne.core.ratelimit import TokenBucket

__all__ = ["RetryPolicy", "RetryingProvider"]

_logger = get_logger("ai.reliability")

_DEFAULT_MAX_DELAY: Final = 20.0


@dataclass(frozen=True, slots=True)
class RetryPolicy:
    """How hard to try, and how long to wait between tries."""

    #: Total attempts, including the first .
    attempts: int = 3
    base_delay_s: float = 0.5
    max_delay_s: float = _DEFAULT_MAX_DELAY
    #: Fraction of the delay added as random jitter (avoids a synchronised retry storm).
    jitter: float = 0.25
    #: Consecutive transient failures after which the provider is treated as down.
    failure_threshold: int = 3

    def __post_init__(self) -> None:
        if self.attempts < 1:
            msg = "retry attempts must be >= 1"
            raise ValueError(msg)
        if self.base_delay_s < 0 or self.max_delay_s < 0:
            msg = "retry delays must be >= 0"
            raise ValueError(msg)
        if not 0.0 <= self.jitter <= 1.0:
            msg = "retry jitter must be within [0, 1]"
            raise ValueError(msg)
        if self.failure_threshold < 1:
            msg = "failure_threshold must be >= 1"
            raise ValueError(msg)

    def delay_for(self, attempt: int, *, retry_after: float | None = None) -> float:
        """Seconds to wait before attempt ``attempt + 1`` (server hint wins when present)."""
        if retry_after is not None:
            return max(0.0, retry_after)
        # ``attempt`` is 1-based, so the exponent is never negative; ``2.0 **`` keeps the
        # expression a float (``int.__pow__`` is typed ``Any`` for the negative case).
        exponential = min(self.max_delay_s, self.base_delay_s * (2.0 ** (attempt - 1)))
        jitter_factor = float(1.0 + self.jitter * random_module.random())  # noqa: S311
        return exponential * jitter_factor


@dataclass
class RetryingProvider:
    """An :class:`~arachne.ai.types.LLMProvider` that retries, paces and gives up."""

    provider: LLMProvider
    policy: RetryPolicy = field(default_factory=RetryPolicy)
    limiter: TokenBucket | None = None
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep
    clock: Callable[[], float] = time.monotonic
    consecutive_failures: int = 0
    degraded: bool = False
    degraded_reason: str = ""
    total_attempts: int = 0
    total_retries: int = 0

    @property
    def name(self) -> str:
        return self.provider.name

    @property
    def model(self) -> str:
        return self.provider.model

    async def complete(self, request: CompletionRequest) -> CompletionResult:
        """Call the provider, retrying transient failures; raises on exhaustion or if down."""
        if self.degraded:
            raise ProviderUnavailableError(
                f"provider {self.name!r} is degraded ({self.degraded_reason}); "
                "not calling it again",
                provider=self.name,
            )
        last: ProviderError | None = None
        for attempt in range(1, self.policy.attempts + 1):
            if self.limiter is not None:
                await self.limiter.acquire()
            self.total_attempts += 1
            try:
                result = await self.provider.complete(request)
            except ProviderError as exc:
                last = exc
                self.consecutive_failures += 1
                if not exc.transient or attempt == self.policy.attempts:
                    self._maybe_degrade(exc)
                    raise
                delay = self.policy.delay_for(attempt, retry_after=exc.retry_after)
                self.total_retries += 1
                _logger.info(
                    "retrying provider call",
                    extra={
                        "event": "ai.retry",
                        "provider": self.name,
                        "attempt": attempt,
                        "delay_s": round(delay, 3),
                        "error": exc.__class__.__name__,
                    },
                )
                await self.sleep(delay)
                continue
            self.consecutive_failures = 0
            return result
        # Unreachable: the loop either returns or raises. Kept as a typed safety net.
        raise last or ProviderUnavailableError(f"provider {self.name!r} failed", provider=self.name)

    # ------------------------------------------------------------------ internals
    def _maybe_degrade(self, exc: ProviderError) -> None:
        if self.consecutive_failures >= self.policy.failure_threshold and not self.degraded:
            self.degraded = True
            self.degraded_reason = f"{exc.__class__.__name__}: {exc}"
            _logger.warning(
                "provider marked degraded",
                extra={
                    "event": "ai.provider_degraded",
                    "provider": self.name,
                    "failures": self.consecutive_failures,
                    "reason": self.degraded_reason,
                },
            )

    def reset(self) -> None:
        """Forget the circuit-breaker state (a new scan starts with a clean provider)."""
        self.degraded = False
        self.degraded_reason = ""
        self.consecutive_failures = 0

    def snapshot(self) -> dict[str, object]:
        return {
            "provider": self.name,
            "model": self.model,
            "attempts": self.total_attempts,
            "retries": self.total_retries,
            "degraded": self.degraded,
            "degraded_reason": self.degraded_reason or None,
        }
