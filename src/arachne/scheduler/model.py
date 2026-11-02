"""The scheduler's data model: a schedule definition, its state, and one run's result.

A schedule is deliberately *not* a scan: it names a target fixture, a cron expression and the
scan options to apply, and the scheduler creates a fresh scan each time it fires (F-01-05).
Keeping the definition and the state separate is what makes "what is scheduled?" answerable
without a database, and what lets the state file be deleted and rebuilt without losing the
definitions if they are managed in configuration.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

from arachne.core.errors import ConfigurationError
from arachne.scheduler.cron import CronExpression

__all__ = ["ScheduleBudget", "ScheduleRun", "ScheduleSpec", "ScheduleState"]

_SCHEDULE_ID = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")


@dataclass(frozen=True, slots=True)
class ScheduleBudget:
    """A continuous schedule's cost guardrails (S23, risk R-13).

    ``max_runs_per_day`` bounds how many times the schedule may fire in any rolling 24h
    window; ``max_estimated_requests`` bounds what one run may estimate (the plan's
    ``estimated_requests`` — the scheduler dry-plans a budgeted schedule before admitting
    it). A budget breach is a *refused run*, audited (``schedule.budget_refused``), never
    a silent skip. ``None`` in a field means "unbounded in that dimension".
    """

    max_runs_per_day: int | None = None
    max_estimated_requests: int | None = None

    def __post_init__(self) -> None:
        for label, value in (
            ("max_runs_per_day", self.max_runs_per_day),
            ("max_estimated_requests", self.max_estimated_requests),
        ):
            if value is not None and value < 1:
                msg = f"schedule budget {label} must be >= 1, got {value}"
                raise ConfigurationError(msg)

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_runs_per_day": self.max_runs_per_day,
            "max_estimated_requests": self.max_estimated_requests,
        }

    @classmethod
    def from_dict(cls, data: Any) -> ScheduleBudget | None:
        if not isinstance(data, Mapping):
            return None
        runs = data.get("max_runs_per_day")
        requests = data.get("max_estimated_requests")
        if runs is None and requests is None:
            return None
        return cls(
            max_runs_per_day=int(runs) if runs is not None else None,
            max_estimated_requests=int(requests) if requests is not None else None,
        )


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value is not None else None


def _parse_dt(value: Any) -> datetime | None:
    if value in (None, ""):
        return None
    try:
        return datetime.fromisoformat(str(value))
    except ValueError as exc:
        msg = f"schedule timestamp {value!r} is not an ISO-8601 datetime"
        raise ConfigurationError(msg) from exc


@dataclass(frozen=True, slots=True)
class ScheduleSpec:
    """One recurring scan definition (F-01-05)."""

    id: str
    target: str
    cron: str
    engine: str | None = None
    active_checks: bool | None = None
    modules: tuple[str, ...] = ()
    checks: tuple[str, ...] = ()
    enabled: bool = True
    #: Continuous mode (S23, area POSTURE): a watching schedule over an M5 cloud-config
    #: endpoint (or any recurring target). Marks intent and turns the deployment's default
    #: budget on when the spec carries none of its own.
    continuous: bool = False
    #: This schedule's own budget (risk R-13). ``None`` inherits the deployment default
    #: when ``continuous`` — a plain scheduled scan is bounded by ``max_runs_per_tick``
    #: as before, with no extra guardrail.
    budget: ScheduleBudget | None = None
    #: The purple-team campaign this schedule runs (S24, REQ-VALID-006). When set, a due run
    #: delegates to the campaign service instead of running a plain scan of ``target``: the
    #: campaign owns what gets replayed and the coverage trend, and the detection window is
    #: enforced by the campaign's own gate (a run outside the coordinated interval is
    #: recorded as ``window_refused``, never forced).
    purple_campaign: str | None = None

    def __post_init__(self) -> None:
        if not _SCHEDULE_ID.match(self.id):
            msg = f"schedule id {self.id!r} must be kebab-case"
            raise ConfigurationError(msg)
        if not self.target.strip() and not self.purple_campaign:
            # A purple schedule names a *campaign*, and the campaign names the attested
            # target it replays against — so the schedule itself needs no fixture.
            msg = "a schedule must name a target fixture"
            raise ConfigurationError(msg)
        CronExpression.parse(self.cron)  # validates; the message names the expression
        if self.engine is not None and self.engine not in {"ai", "heuristic", "hybrid"}:
            msg = f"schedule engine must be ai, heuristic or hybrid, got {self.engine!r}"
            raise ConfigurationError(msg)
        if self.purple_campaign is not None and not _SCHEDULE_ID.match(self.purple_campaign):
            msg = f"purple_campaign {self.purple_campaign!r} must be a kebab-case campaign id"
            raise ConfigurationError(msg)

    @property
    def expression(self) -> CronExpression:
        return CronExpression.parse(self.cron)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "target": self.target,
            "cron": self.cron,
            "engine": self.engine,
            "active_checks": self.active_checks,
            "modules": list(self.modules),
            "checks": list(self.checks),
            "enabled": self.enabled,
            "continuous": self.continuous,
            "budget": self.budget.to_dict() if self.budget is not None else None,
            "purple_campaign": self.purple_campaign,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ScheduleSpec:
        return cls(
            id=str(data.get("id", "")),
            target=str(data.get("target", "")),
            cron=str(data.get("cron", "")),
            engine=(str(data["engine"]) if data.get("engine") else None),
            active_checks=(
                bool(data["active_checks"]) if data.get("active_checks") is not None else None
            ),
            modules=tuple(str(item) for item in data.get("modules") or ()),
            checks=tuple(str(item) for item in data.get("checks") or ()),
            enabled=bool(data.get("enabled", True)),
            continuous=bool(data.get("continuous", False)),
            budget=ScheduleBudget.from_dict(data.get("budget")),
            purple_campaign=(str(data["purple_campaign"]) if data.get("purple_campaign") else None),
        )


@dataclass(frozen=True, slots=True)
class ScheduleState:
    """What the scheduler remembers about one schedule between ticks."""

    last_run_at: datetime | None = None
    last_scan_id: int | None = None
    last_status: str | None = None
    next_run_at: datetime | None = None
    #: When this schedule actually ran (bounded to the recent window). The continuous
    #: budget (S23, risk R-13) counts runs in the last 24h from this list, so "how many
    #: times did this watcher fire today?" is answerable from the state document itself.
    run_times: tuple[datetime, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "last_run_at": _iso(self.last_run_at),
            "last_scan_id": self.last_scan_id,
            "last_status": self.last_status,
            "next_run_at": _iso(self.next_run_at),
            "run_times": [_iso(item) for item in self.run_times],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any] | None) -> ScheduleState:
        payload = dict(data or {})
        scan_id = payload.get("last_scan_id")
        return cls(
            last_run_at=_parse_dt(payload.get("last_run_at")),
            last_scan_id=int(scan_id) if scan_id is not None else None,
            last_status=(str(payload["last_status"]) if payload.get("last_status") else None),
            next_run_at=_parse_dt(payload.get("next_run_at")),
            run_times=tuple(
                moment
                for moment in (_parse_dt(item) for item in payload.get("run_times") or ())
                if moment is not None
            ),
        )

    def with_run(
        self, moment: datetime, *, window_hours: int = 25, cap: int = 400
    ) -> ScheduleState:
        """A copy with ``moment`` appended and the run list pruned to the budget window."""
        window_start = moment - timedelta(hours=window_hours)
        kept = tuple(item for item in self.run_times if window_start <= item <= moment)
        pruned = (*kept, moment)[max(0, len(kept) + 1 - cap) :]
        return ScheduleState(
            last_run_at=self.last_run_at,
            last_scan_id=self.last_scan_id,
            last_status=self.last_status,
            next_run_at=self.next_run_at,
            run_times=pruned,
        )

    def runs_since(self, moment: datetime) -> int:
        """How many recorded runs fall at or after ``moment``."""
        return sum(1 for item in self.run_times if item >= moment)


@dataclass(frozen=True, slots=True)
class ScheduleRun:
    """The outcome of one scheduled run (and its change-detection diff, when computed)."""

    schedule_id: str
    scan_id: int | None = None
    previous_scan_id: int | None = None
    status: str = "pending"
    detail: str = ""
    diff: Mapping[str, Any] | None = field(default=None)

    @property
    def counts(self) -> dict[str, int]:
        if not self.diff:
            return {}
        counts = self.diff.get("counts")
        return dict(counts) if isinstance(counts, Mapping) else {}

    def to_dict(self) -> dict[str, Any]:
        return {
            "schedule_id": self.schedule_id,
            "scan_id": self.scan_id,
            "previous_scan_id": self.previous_scan_id,
            "status": self.status,
            "detail": self.detail,
            "diff": dict(self.diff) if self.diff is not None else None,
            "counts": self.counts,
        }
