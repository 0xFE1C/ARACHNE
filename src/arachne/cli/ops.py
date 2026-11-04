"""``arachne slo`` — the service-level objectives, their budgets and their alerts (REQ-OPS-007).

The definitions live in the repository (``deploy/observability/slos/``) and the alert rules
are generated from them, so these two commands are views rather than a second source of
truth: ``show`` is what an operator reads when an alert fires, and ``check`` is what CI runs
when someone edits a definition.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Any

import typer

from arachne.ops.slo import (
    SLO,
    Finding,
    check,
    default_alert_rules,
    default_slo_dir,
    load_slos,
    recorded_series,
    render_alert_rules,
)

__all__ = ["slo_app"]

slo_app = typer.Typer(
    name="slo",
    help="Service-level objectives: targets, error budgets and burn-rate alerts (REQ-OPS-007).",
    no_args_is_help=True,
)


def _load(slo_dir: Path | None) -> tuple[SLO, ...]:
    try:
        return load_slos(slo_dir or default_slo_dir())
    except (FileNotFoundError, ValueError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=2) from exc


@slo_app.command("show")
def slo_show(
    slo_dir: Annotated[
        Path | None, typer.Option("--dir", help="Directory of SLO definitions.")
    ] = None,
    identifier: Annotated[
        str | None, typer.Argument(help="Show one objective (default: all).")
    ] = None,
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Print every objective with its target, window, budget and measurement query."""
    slos = _load(slo_dir)
    if identifier is not None:
        slos = tuple(slo for slo in slos if slo.id == identifier)
        if not slos:
            typer.echo(f"no such objective: {identifier}", err=True)
            raise typer.Exit(code=1)
    if json_output:
        typer.echo(json.dumps([slo.to_dict() for slo in slos], indent=2))
        return
    for slo in slos:
        budget = slo.error_budget_ratio
        typer.echo(f"{slo.id} — {slo.title} (owner: {slo.owner})")
        typer.echo(f"  target:   {slo.target * 100:g}% of {slo.service} over {slo.window}")
        typer.echo(f"  budget:   {budget * 100:g}% of events may be bad")
        typer.echo(f"  measure:  {slo.query()}")
        for policy in slo.burn_policies:
            typer.echo(
                f"  alert:    {policy.severity} at {policy.threshold:g}x over "
                f"{policy.lookback} for {policy.for_duration}"
            )
        typer.echo(f"  runbook:  {slo.runbook_anchor}")


@slo_app.command("check")
def slo_check(
    slo_dir: Annotated[
        Path | None, typer.Option("--dir", help="Directory of SLO definitions.")
    ] = None,
    rules: Annotated[
        Path | None, typer.Option("--rules", help="The generated alert-rules file.")
    ] = None,
    render: Annotated[
        bool, typer.Option("--render", help="Rewrite the alert rules from the definitions.")
    ] = False,
) -> None:
    """Fail when a definition names a metric the endpoint does not expose, or the rules drifted."""
    directory = slo_dir or default_slo_dir()
    target = rules or default_alert_rules()
    if render:
        slos = _load(directory)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(render_alert_rules(slos), encoding="utf-8")
        typer.echo(f"wrote {target} from {len(slos)} definition(s)")
        return
    try:
        findings: tuple[Finding, ...] = check(slo_dir=directory, rules_path=target)
    except (FileNotFoundError, ValueError) as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(code=2) from exc
    if findings:
        for finding in findings:
            typer.echo(f"FAIL {finding}", err=True)
        raise typer.Exit(code=1)
    slos = load_slos(directory)
    internal: list[Any] = list(recorded_series(slos))
    assert internal  # the generated series exist, so the check was not vacuous
    typer.echo(
        f"ok: {len(slos)} SLO(s), every metric reference exposed by /metrics, "
        "burn alerts in step with the definitions"
    )
