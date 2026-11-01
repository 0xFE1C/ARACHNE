"""Continuous-schedule budgets (S23, risk R-13): the guardrail bites and is audited.

A continuous schedule without its own budget inherits the deployment defaults; a run past
the daily cap — or a run whose plan estimates more requests than the cap — is *refused*,
the refusal is an audited ``schedule.budget_refused`` (not a silent skip), and the run
history that feeds the window count is carried across status updates.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from arachne.core.audit import AuditAction, Auditor, MemoryAuditSink
from arachne.core.config import PostureSettings, SchedulerSettings, Settings
from arachne.scheduler.model import ScheduleBudget, ScheduleSpec, ScheduleState
from arachne.scheduler.runner import Scheduler
from arachne.scheduler.store import ScheduleStore

MOMENT = datetime(2026, 10, 31, 9, 0, 0, tzinfo=UTC)


def _spec(**overrides: object) -> ScheduleSpec:
    payload: dict[str, object] = {
        "id": "estate-watch",
        "target": "examples/targets/lab-fixture.yaml",
        "cron": "*/10 * * * *",
        "continuous": True,
    }
    payload.update(overrides)
    return ScheduleSpec(**payload)  # type: ignore[arg-type]


def _settings(**posture: object) -> Settings:
    return Settings(
        database_url="sqlite:///:memory:",
        log_level="CRITICAL",
        scheduler=SchedulerSettings(state_path="/tmp/does-not-matter-s23.json"),
        posture=PostureSettings(**posture),  # type: ignore[arg-type]
    )


def _scheduler(tmp_path: Path, settings: Settings) -> Scheduler:
    return Scheduler(
        settings,
        store=ScheduleStore(tmp_path / "schedules.json"),
        scan_runner=None,  # type: ignore[arg-type]
    )


def test_budget_defaults_apply_only_to_continuous_schedules() -> None:
    scheduler = _scheduler(Path("/tmp"), _settings(default_max_runs_per_day=7))
    continuous = _spec()
    plain = _spec(id="plain-scan", continuous=False)
    assert scheduler._effective_budget(continuous) == ScheduleBudget(
        max_runs_per_day=7, max_estimated_requests=5000
    )
    assert scheduler._effective_budget(plain) is None
    explicit = _spec(budget=ScheduleBudget(max_runs_per_day=2))
    assert scheduler._effective_budget(explicit) == ScheduleBudget(max_runs_per_day=2)


@pytest.mark.asyncio
async def test_a_run_past_the_daily_cap_is_refused_and_audited(tmp_path: Path) -> None:
    settings = _settings(default_max_runs_per_day=1)
    scheduler = _scheduler(tmp_path, settings)
    sink = MemoryAuditSink()
    scheduler._services = _ServicesStub(Auditor(sink))  # type: ignore[attr-defined]
    scheduler._owns_services = False
    spec = _spec()
    # The schedule has already run once inside the window.
    scheduler.store.upsert(spec, state=ScheduleState(run_times=(MOMENT - timedelta(hours=1),)))
    run = await scheduler.run_one(spec, now=MOMENT)
    assert run.status == "budget_refused"
    assert "cap 1" in run.detail
    assert run.scan_id is None
    events = sink.of_action(AuditAction.SCHEDULE_BUDGET_REFUSED)
    assert len(events) == 1
    assert events[0].outcome.value == "blocked"
    # The refusal is recorded as a run (so the next tick does not re-fire immediately) and
    # the window history is preserved.
    state = scheduler.store.get(spec.id).state  # type: ignore[union-attr]
    assert state.last_status == "budget_refused"
    assert state.runs_since(MOMENT - timedelta(hours=24)) == 2


def test_runs_since_counts_the_window(tmp_path: Path) -> None:
    state = ScheduleState(
        run_times=(
            MOMENT - timedelta(hours=30),
            MOMENT - timedelta(hours=2),
            MOMENT - timedelta(minutes=30),
        )
    )
    assert state.runs_since(MOMENT - timedelta(hours=24)) == 2
    pruned = state.with_run(MOMENT)
    assert pruned.run_times[-1] == MOMENT
    assert len(pruned.run_times) == 3  # the 30h-old run is pruned from the window copy


class _ServicesStub:
    """Only the auditor is touched on the refusal path."""

    def __init__(self, auditor: Auditor) -> None:
        self.auditor = auditor
        self.settings = _settings()
