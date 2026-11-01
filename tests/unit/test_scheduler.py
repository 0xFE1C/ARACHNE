"""The recurring-scan scheduler: cron parsing, state persistence and the run loop (F-01-05).

The scheduler is tested in two halves. The pure half (cron, the model, the JSON store) is
exact. The run loop is driven with injected ``scan_runner`` / ``diff_writer`` seams, so the
test asserts the *coordination* — which schedule is due, what state is recorded, and that a
first run records "no earlier scan" while a second records the diff — without a deployment.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from arachne.core.config import SchedulerSettings, Settings
from arachne.core.errors import ConfigurationError
from arachne.report.model import ReportDiff
from arachne.scheduler import (
    CronExpression,
    Scheduler,
    ScheduleRun,
    ScheduleSpec,
    ScheduleState,
    ScheduleStore,
    parse_cron,
)

TARGET = str(Path(__file__).resolve().parents[2] / "examples" / "targets" / "lab-fixture.yaml")


def _spec(schedule_id: str = "nightly", cron: str = "0 3 * * *", **kwargs: object) -> ScheduleSpec:
    return ScheduleSpec(id=schedule_id, target=TARGET, cron=cron, **kwargs)  # type: ignore[arg-type]


def _settings(**overrides: object) -> Settings:
    return Settings(
        database_url="sqlite:///:memory:",
        log_level="CRITICAL",
        scheduler=SchedulerSettings(**overrides),  # type: ignore[arg-type]
    )


# --------------------------------------------------------------------------- cron
def test_a_five_field_expression_parses_and_matches() -> None:
    expression = parse_cron("*/15 8-9 * * 1-5")
    assert expression.matches(datetime(2026, 10, 26, 9, 30))  # Monday
    assert not expression.matches(datetime(2026, 10, 25, 9, 30))  # Sunday
    assert not expression.matches(datetime(2026, 10, 26, 9, 31))


def test_sunday_is_both_zero_and_seven() -> None:
    for text in ("0 0 * * 0", "0 0 * * 7"):
        assert parse_cron(text).matches(datetime(2026, 10, 25, 0, 0))  # a Sunday


def test_day_of_month_and_weekday_are_ored_when_both_are_restricted() -> None:
    expression = parse_cron("0 0 1 * 1")  # the 1st OR a Monday
    assert expression.matches(datetime(2026, 12, 1, 0, 0))  # the 1st (a Tuesday)
    assert expression.matches(datetime(2026, 10, 26, 0, 0))  # a Monday
    assert not expression.matches(datetime(2026, 10, 27, 0, 0))


def test_next_after_finds_the_next_matching_minute() -> None:
    expression = parse_cron("0 3 * * *")
    start = datetime(2026, 10, 29, 10, 0, tzinfo=UTC)
    assert expression.next_after(start) == datetime(2026, 10, 30, 3, 0, tzinfo=UTC)


@pytest.mark.parametrize(
    "text",
    ["* * * *", "* * * * * *", "60 * * * *", "* 24 * * *", "*/0 * * * *", "a * * * *", ""],
)
def test_a_malformed_expression_is_refused(text: str) -> None:
    with pytest.raises(ConfigurationError):
        CronExpression.parse(text)


# --------------------------------------------------------------------------- model
def test_a_spec_validates_its_id_cron_and_engine() -> None:
    _spec()  # valid
    with pytest.raises(ConfigurationError, match="kebab-case"):
        _spec(schedule_id="Not Kebab")
    with pytest.raises(ConfigurationError, match="must name a target"):
        ScheduleSpec(id="x", target="", cron="* * * * *")
    with pytest.raises(ConfigurationError, match="engine"):
        _spec(engine="magic")


def test_a_spec_round_trips_through_dict() -> None:
    spec = _spec(
        engine="hybrid", active_checks=True, modules=("M6",), checks=("m6.deception-listeners",)
    )
    assert ScheduleSpec.from_dict(spec.to_dict()) == spec


def test_a_run_exposes_its_change_counts() -> None:
    run = ScheduleRun(
        schedule_id="nightly",
        scan_id=2,
        previous_scan_id=1,
        status="completed",
        diff={"counts": {"new": 1, "fixed": 2, "regressed": 0, "recurring": 3}},
    )
    assert run.counts == {"new": 1, "fixed": 2, "regressed": 0, "recurring": 3}
    assert run.to_dict()["scan_id"] == 2


# --------------------------------------------------------------------------- store
def test_the_store_round_trips_and_upserts(tmp_path: Path) -> None:
    store = ScheduleStore(tmp_path / "s.json")
    assert store.load() == ()
    spec = _spec()
    store.upsert(spec, state=ScheduleState(next_run_at=datetime(2026, 10, 30, 3, 0, tzinfo=UTC)))
    reloaded = ScheduleStore(tmp_path / "s.json").get("nightly")
    assert reloaded is not None
    assert reloaded.spec == spec
    assert reloaded.state.next_run_at == datetime(2026, 10, 30, 3, 0, tzinfo=UTC)

    # Upsert replaces the definition without losing the state.
    store.upsert(_spec(cron="0 4 * * *"))
    again = store.get("nightly")
    assert again is not None and again.spec.cron == "0 4 * * *"
    assert again.state.next_run_at is not None

    assert store.remove("nightly") is True
    assert store.remove("nightly") is False
    assert store.load() == ()


def test_the_store_records_a_run(tmp_path: Path) -> None:
    store = ScheduleStore(tmp_path / "s.json")
    store.upsert(_spec())
    updated = store.record(
        "nightly",
        ScheduleState(last_scan_id=9, last_status="completed", last_run_at=datetime.now(UTC)),
    )
    assert updated.state.last_scan_id == 9


def test_recording_an_unknown_schedule_is_an_error(tmp_path: Path) -> None:
    with pytest.raises(ConfigurationError, match="does not exist"):
        ScheduleStore(tmp_path / "s.json").record("ghost", ScheduleState())


def test_a_corrupt_state_file_is_reported(tmp_path: Path) -> None:
    path = tmp_path / "s.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ConfigurationError, match="not valid JSON"):
        ScheduleStore(path).load()


# --------------------------------------------------------------------------- run loop
class _StubStatus:
    value = "completed"


class _StubSession:
    def __init__(self, scan_id: int) -> None:
        self.scan_id = scan_id
        self.status = _StubStatus()


def _recording_runner(counter: list[int], *, start: int = 0) -> object:
    async def run(_services: object, _request: object) -> _StubSession:
        counter.append(len(counter) + 1)
        return _StubSession(start + len(counter))

    return run


def test_due_lists_never_run_and_past_due_schedules(tmp_path: Path) -> None:
    store = ScheduleStore(tmp_path / "s.json")
    store.upsert(_spec("never"), state=ScheduleState())
    store.upsert(
        _spec("past"),
        state=ScheduleState(next_run_at=datetime(2026, 1, 1, tzinfo=UTC)),
    )
    store.upsert(
        _spec("future"),
        state=ScheduleState(next_run_at=datetime(2030, 1, 1, tzinfo=UTC)),
    )
    store.upsert(_spec("off", enabled=False), state=ScheduleState())

    scheduler = Scheduler(_settings(), store=store, services=object())
    due = {row.spec.id for row in scheduler.due(datetime(2026, 6, 1, tzinfo=UTC))}
    assert due == {"never", "past"}


async def test_a_first_run_records_state_and_the_next_run(tmp_path: Path) -> None:
    store = ScheduleStore(tmp_path / "s.json")
    spec = _spec()
    store.upsert(spec, state=ScheduleState())
    scheduler = Scheduler(
        _settings(),
        store=store,
        services=object(),
        scan_runner=_recording_runner([]),  # type: ignore[arg-type]
    )
    moment = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)
    run = await scheduler.run_one(spec, now=moment)
    assert run.scan_id == 1
    assert run.previous_scan_id is None
    assert run.diff is None  # first run: nothing to compare
    stored = store.get("nightly")
    assert stored is not None
    assert stored.state.last_scan_id == 1
    assert stored.state.last_status == "completed"
    assert stored.state.next_run_at == datetime(2026, 6, 2, 3, 0, tzinfo=UTC)


async def test_a_second_run_produces_and_persists_a_diff(tmp_path: Path) -> None:
    store = ScheduleStore(tmp_path / "s.json")
    spec = _spec()
    store.upsert(spec, state=ScheduleState(last_scan_id=1))
    seen: list[tuple[int, int]] = []

    def writer(_services: object, earlier: int, current: int) -> ReportDiff:
        seen.append((earlier, current))
        return ReportDiff(
            scan_a=f"scan_{earlier}",
            scan_b=f"scan_{current}",
            new=("m6.webshell-yara|repo:/web",),
            fixed=("m6.ci-secret-leak|repo:/web",),
            regressed=("m6.secret-scan-at-scale|repo:/web",),
        )

    scheduler = Scheduler(
        _settings(),
        store=store,
        services=object(),
        scan_runner=_recording_runner([], start=1),  # type: ignore[arg-type]
        diff_writer=writer,  # type: ignore[arg-type]
    )
    run = await scheduler.run_one(spec, now=datetime(2026, 6, 2, 3, 0, tzinfo=UTC))
    assert seen == [(1, 2)]
    assert run.previous_scan_id == 1
    assert run.counts == {"new": 1, "fixed": 1, "regressed": 1, "recurring": 0, "suppressed": 0}


async def test_run_due_respects_the_tick_limit(tmp_path: Path) -> None:
    store = ScheduleStore(tmp_path / "s.json")
    for name in ("a", "b", "c"):
        store.upsert(_spec(name), state=ScheduleState())
    scheduler = Scheduler(
        _settings(max_runs_per_tick=2),
        store=store,
        services=object(),
        scan_runner=_recording_runner([]),  # type: ignore[arg-type]
    )
    runs = await scheduler.run_due(datetime(2026, 6, 1, tzinfo=UTC))
    assert len(runs) == 2


async def test_a_failed_scan_is_recorded_and_does_not_raise(tmp_path: Path) -> None:
    store = ScheduleStore(tmp_path / "s.json")
    spec = _spec()
    store.upsert(spec, state=ScheduleState())

    async def boom(_services: object, _request: object) -> object:
        raise RuntimeError("the target is down")

    scheduler = Scheduler(
        _settings(),
        store=store,
        services=object(),
        scan_runner=boom,  # type: ignore[arg-type]
    )
    run = await scheduler.run_one(spec, now=datetime(2026, 6, 1, tzinfo=UTC))
    assert run.status == "failed"
    assert "down" in run.detail
    stored = store.get("nightly")
    assert stored is not None and stored.state.last_status == "failed"
    # The next run is still scheduled, so the failure does not hot-loop.
    assert stored.state.next_run_at is not None


async def test_change_detection_can_be_disabled(tmp_path: Path) -> None:
    store = ScheduleStore(tmp_path / "s.json")
    spec = _spec()
    store.upsert(spec, state=ScheduleState(last_scan_id=1))
    scheduler = Scheduler(
        _settings(diff_on_run=False),
        store=store,
        services=object(),
        scan_runner=_recording_runner([]),  # type: ignore[arg-type]
    )
    run = await scheduler.run_one(spec, now=datetime.now(UTC) + timedelta(days=1))
    assert run.diff is None
    assert "disabled" in run.detail


# --------------------------------------------------------------------------- CLI
def test_the_schedule_cli_adds_lists_and_removes(tmp_path: Path, monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """The four verbs round-trip through the JSON state file (F-01-05)."""
    import json

    from typer.testing import CliRunner

    from arachne.cli.main import app
    from arachne.core.config import reset_settings_cache

    monkeypatch.setenv("ARACHNE_SCHEDULER_STATE", str(tmp_path / "state.json"))
    monkeypatch.setenv("ARACHNE_LOG_LEVEL", "CRITICAL")
    reset_settings_cache()
    runner = CliRunner()

    added = runner.invoke(
        app, ["schedule", "add", "--id", "nightly", "--target", TARGET, "--cron", "0 3 * * *"]
    )
    assert added.exit_code == 0, added.output
    assert "next run" in added.output

    listed = runner.invoke(app, ["schedule", "list", "--json"])
    assert listed.exit_code == 0, listed.output
    payload = json.loads(listed.output)
    assert payload[0]["spec"]["id"] == "nightly"
    assert payload[0]["state"]["next_run_at"]

    bad = runner.invoke(
        app, ["schedule", "add", "--id", "nightly", "--target", TARGET, "--cron", "nope"]
    )
    assert bad.exit_code == 2
    assert "cron" in bad.output

    removed = runner.invoke(app, ["schedule", "remove", "nightly"])
    assert removed.exit_code == 0, removed.output
    assert json.loads(runner.invoke(app, ["schedule", "list", "--json"]).output) == []
    reset_settings_cache()
