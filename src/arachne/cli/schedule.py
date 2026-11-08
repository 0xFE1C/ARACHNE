"""``arachne schedule`` — manage and run recurring scans (F-01-05, S11).

Four commands, one state file (``ARACHNE_SCHEDULER_STATE``, default ``.arachne/schedules.json``):

``add``
    register a schedule (id, target fixture, cron expression, optional scan options).
``list``
    show every schedule with its last run and next run.
``remove``
    delete a schedule (its past scans and diffs stay in the evidence store).
``run``
    execute what is due now — or, with ``--id``, one schedule immediately — and report each
    scan id and its change-detection diff (new/fixed/regressed/recurring).
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime
from pathlib import Path
from typing import Annotated

import typer

from arachne.core.config import get_settings
from arachne.core.errors import ConfigurationError
from arachne.scheduler.model import ScheduleRun, ScheduleSpec, ScheduleState
from arachne.scheduler.runner import Scheduler
from arachne.scheduler.store import ScheduleStore

__all__ = ["schedule_add", "schedule_app", "schedule_list", "schedule_remove", "schedule_run"]

schedule_app = typer.Typer(
    name="schedule",
    help="Register, inspect and run recurring scans.",
    no_args_is_help=True,
)


def _store() -> ScheduleStore:
    return ScheduleStore(get_settings().scheduler.state_path)


@schedule_app.command("add")
def schedule_add(
    schedule_id: Annotated[str, typer.Option("--id", help="Kebab-case schedule id.")],
    cron: Annotated[
        str, typer.Option("--cron", help="5-field cron: 'minute hour day month weekday'.")
    ],
    target: Annotated[
        Path | None,
        typer.Option(
            "--target", "-t", help="Target definition fixture (omit for a purple campaign)."
        ),
    ] = None,
    engine: Annotated[str | None, typer.Option("--engine", help="ai|heuristic|hybrid.")] = None,
    active_checks: Annotated[
        bool | None,
        typer.Option("--active-checks/--no-active-checks", help="Opt in to active checks."),
    ] = None,
    module: Annotated[
        str | None, typer.Option("--module", help="Comma-separated module ids to enable.")
    ] = None,
    check: Annotated[
        str | None, typer.Option("--check", help="Comma-separated opt-in check ids.")
    ] = None,
    purple_campaign: Annotated[
        str | None,
        typer.Option(
            "--purple-campaign",
            help="Run this purple-team campaign instead of scanning --target.",
        ),
    ] = None,
) -> None:
    """Register (or update) a recurring scan."""
    try:
        spec = ScheduleSpec(
            id=schedule_id,
            target=str(target) if target is not None else "",
            cron=cron,
            engine=engine,
            active_checks=active_checks,
            modules=_csv_upper(module),
            checks=_csv_lower(check),
            purple_campaign=purple_campaign,
        )
    except ConfigurationError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    store = _store()
    next_run = spec.expression.next_after(datetime.now().astimezone())
    store.upsert(spec, state=ScheduleState(next_run_at=next_run))
    typer.echo(
        f"schedule {spec.id}: {spec.cron} → next run {next_run.isoformat()} (target {spec.target})"
    )


@schedule_app.command("list")
def schedule_list(
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Show every registered schedule."""
    rows = _store().load()
    if json_output:
        typer.echo(
            json.dumps(
                [{"spec": row.spec.to_dict(), "state": row.state.to_dict()} for row in rows],
                indent=2,
            )
        )
        return
    if not rows:
        typer.echo("no schedules registered (arachne schedule add ...)")
        return
    typer.echo(f"{'id':20}{'cron':18}{'enabled':9}{'last run':26}{'next run':26}target")
    for row in rows:
        typer.echo(
            f"{row.spec.id:20}{row.spec.cron:18}{row.spec.enabled!s:9}"
            f"{_when(row.state.last_run_at):26}{_when(row.state.next_run_at):26}{row.spec.target}"
        )


@schedule_app.command("remove")
def schedule_remove(
    schedule_id: Annotated[str, typer.Argument(help="Schedule id to remove.")],
) -> None:
    """Remove a schedule."""
    if not _store().remove(schedule_id):
        typer.echo(f"error: no schedule {schedule_id!r}", err=True)
        raise typer.Exit(code=2)
    typer.echo(f"removed schedule {schedule_id}")


@schedule_app.command("run")
def schedule_run(
    schedule_id: Annotated[
        str | None, typer.Option("--id", help="Run this schedule now (even if not due).")
    ] = None,
    now: Annotated[
        str | None,
        typer.Option("--now", help="Evaluate due schedules at this ISO-8601 time."),
    ] = None,
    limit: Annotated[
        int | None, typer.Option("--limit", help="Maximum schedules to run this tick.")
    ] = None,
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Run due schedules (or one named schedule) and report their diffs."""
    moment = _parse_now(now)
    scheduler = Scheduler()
    runs: tuple[ScheduleRun, ...]
    try:
        if schedule_id is not None:
            row = scheduler.store.get(schedule_id)
            if row is None:
                typer.echo(f"error: no schedule {schedule_id!r}", err=True)
                raise typer.Exit(code=2)
            # An explicit `--id` run is an operator act: it is never leader-gated, because a
            # human asking for this one schedule now has already made the decision the lease
            # exists to make automatically (S25, REQ-RESIL-002).
            runs = (asyncio.run(scheduler.run_one(row.spec, now=moment)),)
        else:
            # The tick loop is the singleton: with a lease wired it runs on one replica only.
            scheduler.leader = scheduler.services.leader
            runs = asyncio.run(scheduler.run_due(moment, limit=limit))
    finally:
        scheduler.close()
    if json_output:
        typer.echo(json.dumps([run.to_dict() for run in runs], indent=2))
        return
    if not runs:
        typer.echo("no schedules are due")
        return
    for run in runs:
        counts = run.counts
        trend = (
            f" · new {counts.get('new', 0)} / fixed {counts.get('fixed', 0)} / "
            f"regressed {counts.get('regressed', 0)} / recurring {counts.get('recurring', 0)}"
            if counts
            else ""
        )
        previous = f" (vs scan {run.previous_scan_id})" if run.previous_scan_id else ""
        detail = f" — {run.detail}" if run.detail else ""
        typer.echo(f"{run.schedule_id}: scan {run.scan_id} {run.status}{previous}{trend}{detail}")


def _csv_upper(value: str | None) -> tuple[str, ...]:
    return tuple(item.strip().upper() for item in (value or "").split(",") if item.strip())


def _csv_lower(value: str | None) -> tuple[str, ...]:
    return tuple(item.strip().lower() for item in (value or "").split(",") if item.strip())


def _when(value: datetime | None) -> str:
    return value.isoformat(timespec="minutes") if value is not None else "—"


def _parse_now(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError as exc:
        typer.echo(f"error: --now {value!r} is not an ISO-8601 datetime", err=True)
        raise typer.Exit(code=2) from exc
