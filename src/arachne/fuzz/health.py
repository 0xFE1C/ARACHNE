"""Health probes and the abort-on-degradation guard (S30, area FUZZ, REQ-FUZZ-002/005).

Fuzzing's hard rule is "discovery, never disruption", and the only way to keep it while sending
a target inputs it has never seen is to *watch the target* and stop at the first sign that it is
not coping. That is what this module computes.

The mechanism is a bracket inside a bracket:

* A batch of cases is bracketed by **health probes** — one before, one after — which are ordinary
  well-formed requests whose response is checked against the shape a healthy target returns. A
  batch whose "after" probe fails, or whose "before" and "after" disagree, is a batch that
  disturbed the target, and the run stops there. On a protocol lab this is what proves the
  service was healthy before *and* after the batch that found the planted bug.
* Inside a batch, the guard is re-evaluated after **every** case against a rolling window
  (:class:`HealthWindow`), so the run stops at the first degradation signal rather than at the
  end of a batch that has already done twenty more things to a struggling service.

Three signals, because they catch different failures: an **error rate** (the target stopped
answering what it used to), a **timeout rate** (it stopped answering in time), and a
**latency ratio** against the pre-batch baseline (it is answering, but four times slower — the
signature of a service that is filling up rather than one that has already fallen over).
Consecutive hard failures are checked even before the rate signals have enough samples, because
two failures in a row is already a signal and waiting for the third is waiting for a reason.

**What does *not* feed the guard matters as much as what does.** A target answering a malformed
message with a protocol exception, an error status or a garbled reply is *healthy* — that is
what its parser is supposed to do, and it is the source of the candidates a run is looking for.
Feeding those responses to the guard would make fuzzing abort on its own success. So only two
kinds of observation reach it: a **health probe** (a well-formed request whose response is
checked against the healthy shape — taken before and after every batch, and interleaved inside
it) and a **transport failure** on a case (a timeout or a refused/reset connection, which is
either a crash or a service that has stopped coping, and where the safe direction is to stop and
record rather than to keep going). An answered case is a candidate, never a signal.

Everything here is pure: it takes samples and returns verdicts. The runner owns the client and
does the probing, which keeps the arithmetic testable without a socket and keeps the network
policy in one place.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass
from typing import Any, Final

from arachne.core.config import FuzzSettings

__all__ = [
    "DEFAULT_PROBE_INTERVAL",
    "OUTCOME_ERROR",
    "OUTCOME_OK",
    "OUTCOME_REFUSED",
    "OUTCOME_TIMEOUT",
    "DegradationPolicy",
    "DegradationSignals",
    "DegradationVerdict",
    "HealthBaseline",
    "HealthSample",
    "HealthWindow",
    "health_sample",
    "transport_failure",
]

#: A probe the target answered the way a healthy target does.
OUTCOME_OK: Final = "ok"
#: A probe that raised, or produced a response the health check rejected.
OUTCOME_ERROR: Final = "error"
#: A probe that did not answer within the client's read timeout.
OUTCOME_TIMEOUT: Final = "timeout"
#: A probe the *client* refused (out of scope, blocked address, air-gap). Never a target fault:
#: a refusal is recorded so the run cannot mistake "we were not allowed to look" for "it broke".
OUTCOME_REFUSED: Final = "refused"

#: How many cases may run between two interleaved health probes. Small enough that a service in
#: trouble is noticed within a handful of cases, large enough that the probes do not dominate
#: the run's request budget.
DEFAULT_PROBE_INTERVAL: Final = 5


@dataclass(frozen=True, slots=True)
class HealthSample:
    """One observation of a target's health."""

    target: str
    at: float
    outcome: str = OUTCOME_OK
    latency_s: float = 0.0
    detail: str = ""

    @property
    def ok(self) -> bool:
        return self.outcome == OUTCOME_OK

    @property
    def failed(self) -> bool:
        """True for a *target* failure. A client-side refusal is not one."""
        return self.outcome in (OUTCOME_ERROR, OUTCOME_TIMEOUT)

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "target": self.target,
            "outcome": self.outcome,
            "latency_ms": round(self.latency_s * 1000, 1),
        }
        if self.detail:
            payload["detail"] = self.detail
        return payload


def health_sample(
    target: str,
    *,
    at: float,
    ok: bool,
    latency_s: float,
    detail: str = "",
) -> HealthSample:
    """A sample from a *health probe* — a well-formed request whose answer was checked.

    Use this only for a probe the target was expected to answer normally. An error response to
    a *fuzzed* case is not a degradation signal (it is the target doing its job), and feeding it
    here would make the guard abort on the run's own findings.
    """
    return HealthSample(
        target=target,
        at=at,
        outcome=OUTCOME_OK if ok else OUTCOME_ERROR,
        latency_s=latency_s,
        detail=detail,
    )


def transport_failure(
    target: str,
    *,
    at: float,
    outcome: str = OUTCOME_TIMEOUT,
    latency_s: float = 0.0,
    detail: str = "",
) -> HealthSample:
    """A sample from a case whose *transport* failed — no answer at all, or a refused connection.

    This is the one case-level observation the guard consumes, and it is deliberately the
    ambiguous one: a timeout or a reset may be the crash the run was looking for *or* a service
    that has stopped coping. Both are reasons to stop, and the candidate that recorded the
    non-answer survives the abort — so the safe choice costs no evidence.
    """
    if outcome not in (OUTCOME_TIMEOUT, OUTCOME_ERROR):
        msg = "a transport failure is a timeout or an error, not a healthy or refused sample"
        raise ValueError(msg)
    return HealthSample(target=target, at=at, outcome=outcome, latency_s=latency_s, detail=detail)


@dataclass(frozen=True, slots=True)
class HealthBaseline:
    """The pre-batch reading a batch's window is judged against."""

    samples: tuple[HealthSample, ...] = ()

    @property
    def ok(self) -> bool:
        """True when every baseline sample was healthy.

        An unhealthy baseline is a refusal to start, not a degraded run: fuzzing a target that
        was already failing would attribute the failure to the fuzzing.
        """
        return bool(self.samples) and all(sample.ok for sample in self.samples)

    @property
    def failures(self) -> tuple[HealthSample, ...]:
        return tuple(sample for sample in self.samples if sample.failed)

    @property
    def latency_s(self) -> float:
        """Median latency of the healthy samples — the ratio's denominator."""
        healthy = [sample.latency_s for sample in self.samples if sample.ok]
        return statistics.median(healthy) if healthy else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "samples": [sample.to_dict() for sample in self.samples],
            "healthy": self.ok,
            "median_latency_ms": round(self.latency_s * 1000, 1),
        }


@dataclass(frozen=True, slots=True)
class DegradationSignals:
    """What the guard measured, so a report can state *why* it stopped."""

    samples: int = 0
    failures: int = 0
    timeouts: int = 0
    error_rate: float = 0.0
    timeout_rate: float = 0.0
    median_latency_s: float = 0.0
    baseline_latency_s: float = 0.0
    latency_ratio: float = 0.0
    consecutive_failures: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "samples": self.samples,
            "failures": self.failures,
            "timeouts": self.timeouts,
            "error_rate": round(self.error_rate, 4),
            "timeout_rate": round(self.timeout_rate, 4),
            "median_latency_ms": round(self.median_latency_s * 1000, 1),
            "baseline_latency_ms": round(self.baseline_latency_s * 1000, 1),
            "latency_ratio": round(self.latency_ratio, 3),
            "consecutive_failures": self.consecutive_failures,
        }


@dataclass(frozen=True, slots=True)
class DegradationVerdict:
    """The guard's reading: whether to stop, and the signals behind the answer."""

    degraded: bool
    reasons: tuple[str, ...] = ()
    signals: DegradationSignals = DegradationSignals()

    def to_dict(self) -> dict[str, Any]:
        return {
            "degraded": self.degraded,
            "reasons": list(self.reasons),
            "signals": self.signals.to_dict(),
        }


@dataclass(frozen=True, slots=True)
class DegradationPolicy:
    """The thresholds that decide when fuzzing stops (REQ-FUZZ-005).

    Conservative by design: a run that stops early costs some coverage, while a run that keeps
    hammering a target that is answering four times slower than it was costs the target.
    """

    min_samples: int = 3
    max_error_rate: float = 0.34
    max_timeout_rate: float = 0.25
    max_latency_ratio: float = 4.0
    max_consecutive_failures: int = 2

    @classmethod
    def from_settings(cls, settings: FuzzSettings) -> DegradationPolicy:
        return cls(
            min_samples=settings.health_min_samples,
            max_error_rate=settings.max_error_rate,
            max_timeout_rate=settings.max_timeout_rate,
            max_latency_ratio=settings.max_latency_ratio,
            max_consecutive_failures=settings.max_consecutive_failures,
        )

    def judge(
        self,
        baseline: HealthBaseline,
        window: tuple[HealthSample, ...],
    ) -> DegradationVerdict:
        """Judge ``window`` against ``baseline``.

        The consecutive-failure rule is evaluated first and does not wait for
        ``min_samples``: two failures in a row is already a degradation signal, and a guard that
        needs a third sample before it will act is a guard that sends another case to a service
        it already knows is failing.
        """
        signals = self._signals(baseline, window)
        reasons: list[str] = []
        if signals.consecutive_failures >= self.max_consecutive_failures:
            reasons.append(
                f"{signals.consecutive_failures} consecutive probe failures "
                f"(limit {self.max_consecutive_failures})"
            )
        if signals.samples >= self.min_samples:
            if signals.timeout_rate > self.max_timeout_rate:
                reasons.append(
                    f"probe timeout rate {signals.timeout_rate:.0%} exceeds "
                    f"{self.max_timeout_rate:.0%}"
                )
            if signals.error_rate > self.max_error_rate:
                reasons.append(
                    f"probe error rate {signals.error_rate:.0%} exceeds "
                    f"{self.max_error_rate:.0%}"
                )
            if (
                signals.baseline_latency_s > 0
                and signals.latency_ratio > self.max_latency_ratio
            ):
                reasons.append(
                    f"probe latency {signals.median_latency_s * 1000:.0f}ms is "
                    f"{signals.latency_ratio:.1f}x the {signals.baseline_latency_s * 1000:.0f}ms "
                    f"baseline (limit {self.max_latency_ratio:.1f}x)"
                )
        return DegradationVerdict(
            degraded=bool(reasons), reasons=tuple(reasons), signals=signals
        )

    def _signals(
        self, baseline: HealthBaseline, window: tuple[HealthSample, ...]
    ) -> DegradationSignals:
        samples = len(window)
        failures = sum(1 for sample in window if sample.failed)
        timeouts = sum(1 for sample in window if sample.outcome == OUTCOME_TIMEOUT)
        latencies = [sample.latency_s for sample in window if sample.ok]
        median = statistics.median(latencies) if latencies else 0.0
        base = baseline.latency_s
        consecutive = 0
        for sample in reversed(window):
            if sample.failed:
                consecutive += 1
            else:
                break
        return DegradationSignals(
            samples=samples,
            failures=failures,
            timeouts=timeouts,
            error_rate=(failures / samples) if samples else 0.0,
            timeout_rate=(timeouts / samples) if samples else 0.0,
            median_latency_s=median,
            baseline_latency_s=base,
            latency_ratio=(median / base) if base > 0 else 0.0,
            consecutive_failures=consecutive,
        )


class HealthWindow:
    """The rolling window of in-batch samples, with the guard's running judgement.

    Bounded on purpose: the window keeps the most recent ``capacity`` samples, because a target
    that failed three cases ago and has been healthy since is not currently degraded, and an
    unbounded window would keep saying so.
    """

    def __init__(
        self,
        policy: DegradationPolicy,
        *,
        baseline: HealthBaseline,
        capacity: int = 12,
    ) -> None:
        self.policy = policy
        self.baseline = baseline
        self.capacity = max(1, capacity)
        self._samples: list[HealthSample] = []
        self._verdict = DegradationVerdict(degraded=False)

    @property
    def samples(self) -> tuple[HealthSample, ...]:
        return tuple(self._samples)

    @property
    def verdict(self) -> DegradationVerdict:
        return self._verdict

    @property
    def degraded(self) -> bool:
        return self._verdict.degraded

    def record(self, sample: HealthSample) -> DegradationVerdict:
        """Add a sample and re-judge. The verdict is the guard's answer *now*."""
        self._samples.append(sample)
        if len(self._samples) > self.capacity:
            del self._samples[: len(self._samples) - self.capacity]
        self._verdict = self.policy.judge(self.baseline, tuple(self._samples))
        return self._verdict

    def reset(self) -> None:
        """Start a new batch's window against the same baseline."""
        self._samples.clear()
        self._verdict = DegradationVerdict(degraded=False)

    def to_dict(self) -> dict[str, Any]:
        return {
            "samples": [sample.to_dict() for sample in self._samples],
            "verdict": self._verdict.to_dict(),
        }
