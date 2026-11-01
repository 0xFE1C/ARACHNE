"""Hard bounds for a fuzzing run (S30, area FUZZ, REQ-FUZZ-001).

"Bounded" is the whole requirement: a fuzzing run must be incapable of spending more time,
more requests or more cases than its operator authorized, whatever it finds, and an operator's
plan may ask for *less* than the deployment's ceiling but never for more. Three axes, because
each catches a failure the others do not:

``max_cases``
    bounds the work — how many mutated messages a target receives.
``max_requests``
    bounds the target's load — a case can cost more than one request (one to send, one to
    confirm a fault), and a health probe is a request too.
``max_seconds``
    bounds wall-clock time — which is the only bound that still holds when a target answers so
    slowly that a request count tells you nothing.

:class:`BudgetLedger` is the enforcement: every request path in the runner spends against it
*before* the egress call, and a spent bound raises
:class:`~arachne.core.errors.FuzzBudgetExhaustedError`. Exhausting a bound therefore ends the run
and still produces a report, because "we stopped because we hit the ceiling" is a result an
operator needs to see. The clock is injectable so a test can prove the time bound without
sleeping.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Final

from arachne.core.config import FuzzSettings
from arachne.core.errors import ConfigurationError, FuzzBudgetExhaustedError

__all__ = ["BudgetLedger", "FuzzBudget"]

#: Why a run stopped, as the report and the audit line render it.
STOP_COMPLETED: Final = "completed"
STOP_BUDGET: Final = "budget-exhausted"
STOP_ABORTED: Final = "aborted-on-degradation"


@dataclass(frozen=True, slots=True)
class FuzzBudget:
    """One target's hard ceilings (REQ-FUZZ-001).

    Frozen and validated at construction: a budget with a negative or zero bound is a
    configuration error at the boundary rather than a run that starts and immediately stops.
    """

    max_cases: int = 200
    max_requests: int = 220
    max_seconds: float = 60.0
    batch_size: int = 25

    def __post_init__(self) -> None:
        if self.max_cases < 1:
            msg = "fuzz budget max_cases must be >= 1"
            raise ConfigurationError(msg)
        if self.max_requests < 1:
            msg = "fuzz budget max_requests must be >= 1"
            raise ConfigurationError(msg)
        if self.max_seconds <= 0:
            msg = "fuzz budget max_seconds must be > 0"
            raise ConfigurationError(msg)
        if self.batch_size < 1:
            msg = "fuzz budget batch_size must be >= 1"
            raise ConfigurationError(msg)

    @classmethod
    def from_settings(cls, settings: FuzzSettings) -> FuzzBudget:
        """The deployment's ceiling, as a budget."""
        return cls(
            max_cases=settings.max_cases,
            max_requests=settings.max_requests,
            max_seconds=settings.max_seconds,
            batch_size=settings.batch_size,
        )

    def narrowed(
        self,
        *,
        max_cases: int | None = None,
        max_requests: int | None = None,
        max_seconds: float | None = None,
        batch_size: int | None = None,
    ) -> FuzzBudget:
        """This budget with some bounds tightened — the only direction a plan may move.

        A requested value *above* the ceiling is clamped to the ceiling rather than refused:
        an operator asking for "as much as allowed" is not an error, and silently granting
        more than the deployment's ceiling would be. The clamp is reported by
        :meth:`clamped_fields` so a caller can tell the operator what it actually got.
        """
        return FuzzBudget(
            max_cases=min(self.max_cases, max_cases) if max_cases is not None else self.max_cases,
            max_requests=(
                min(self.max_requests, max_requests)
                if max_requests is not None
                else self.max_requests
            ),
            max_seconds=(
                min(self.max_seconds, max_seconds)
                if max_seconds is not None
                else self.max_seconds
            ),
            batch_size=(
                min(self.batch_size, batch_size) if batch_size is not None else self.batch_size
            ),
        )

    def clamped_fields(self, requested: FuzzBudget) -> tuple[str, ...]:
        """Which of ``requested``'s bounds the ceiling pulled down."""
        fields: list[str] = []
        for name in ("max_cases", "max_requests", "max_seconds", "batch_size"):
            if getattr(requested, name) > getattr(self, name):
                fields.append(name)
        return tuple(fields)

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_cases": self.max_cases,
            "max_requests": self.max_requests,
            "max_seconds": self.max_seconds,
            "batch_size": self.batch_size,
        }


class BudgetLedger:
    """Spend against a :class:`FuzzBudget`; refuse the request that would exceed it.

    The ledger is consulted *before* every request, so the bound is enforced on the intent
    rather than discovered in the totals afterwards. ``clock`` is injectable: the time bound is
    the one bound a test cannot exercise by waiting, so it must be provable without waiting.
    """

    def __init__(
        self,
        budget: FuzzBudget,
        *,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.budget = budget
        self._clock = clock
        self._started = clock()
        self.cases = 0
        self.requests = 0
        self.payloads_refused = 0

    # ------------------------------------------------------------------ readings
    @property
    def elapsed(self) -> float:
        return max(0.0, self._clock() - self._started)

    @property
    def remaining_seconds(self) -> float:
        return max(0.0, self.budget.max_seconds - self.elapsed)

    @property
    def remaining_cases(self) -> int:
        return max(0, self.budget.max_cases - self.cases)

    @property
    def remaining_requests(self) -> int:
        return max(0, self.budget.max_requests - self.requests)

    @property
    def spent(self) -> bool:
        """True when no further case can start."""
        return self.exhausted_reason() is not None

    def exhausted_reason(self) -> str | None:
        """Why the next case may not start, or ``None``.

        Checked in a fixed order — time, requests, cases — so the reported reason is stable
        even when two bounds run out together, which is what makes a report reproducible.
        """
        if self.elapsed >= self.budget.max_seconds:
            return (
                f"wall-clock budget spent ({self.elapsed:.1f}s of "
                f"{self.budget.max_seconds:.1f}s)"
            )
        if self.requests >= self.budget.max_requests:
            return (
                f"request budget spent ({self.requests} of {self.budget.max_requests})"
            )
        if self.cases >= self.budget.max_cases:
            return f"case budget spent ({self.cases} of {self.budget.max_cases})"
        return None

    def affords(self, *, requests: int = 1) -> bool:
        """True when another case costing ``requests`` requests may start."""
        if self.exhausted_reason() is not None:
            return False
        return self.requests + requests <= self.budget.max_requests

    # ------------------------------------------------------------------ spending
    def spend(self, *, requests: int = 1, cases: int = 1) -> None:
        """Record ``requests`` requests and ``cases`` cases, or refuse the spend.

        The check precedes the increment, so a refused spend leaves the ledger exactly as it
        was — a repeated refusal cannot walk the totals past a bound.
        """
        if requests < 0 or cases < 0:
            msg = "a budget spend cannot be negative"
            raise ConfigurationError(msg)
        blocked = self.exhausted_reason()
        if blocked is not None:
            raise FuzzBudgetExhaustedError(blocked)
        if self.requests + requests > self.budget.max_requests:
            reason = (
                f"request budget would be exceeded ({self.requests} + {requests} of "
                f"{self.budget.max_requests})"
            )
            raise FuzzBudgetExhaustedError(reason)
        if self.cases + cases > self.budget.max_cases:
            reason = (
                f"case budget would be exceeded ({self.cases} + {cases} of "
                f"{self.budget.max_cases})"
            )
            raise FuzzBudgetExhaustedError(reason)
        # The time bound is re-read here because a target that answers slowly spends it in
        # ways a case count cannot see.
        if self.elapsed >= self.budget.max_seconds:
            reason = (
                f"wall-clock budget spent during the case ({self.elapsed:.1f}s of "
                f"{self.budget.max_seconds:.1f}s)"
            )
            raise FuzzBudgetExhaustedError(reason)
        self.requests += requests
        self.cases += cases

    def note_refused_payload(self) -> None:
        """Record a generated case the prohibition table discarded before any request.

        Counted separately from ``cases``: a discarded payload is not work done, and reporting
        it as a case would overstate coverage while understating that the engine tried.
        """
        self.payloads_refused += 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "budget": self.budget.to_dict(),
            "cases": self.cases,
            "requests": self.requests,
            "payloads_refused": self.payloads_refused,
            "elapsed_seconds": round(self.elapsed, 3),
            "remaining_cases": self.remaining_cases,
            "remaining_requests": self.remaining_requests,
            "remaining_seconds": round(self.remaining_seconds, 3),
        }
