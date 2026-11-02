"""``arachne purple`` — detection validation (S24, area VALID).

The operator surface of a purple-team programme:

- ``campaign add`` / ``list`` / ``enable`` / ``disable`` / ``remove`` — define what gets
  replayed against which attested target, and (optionally) how often.
- ``campaign run <name>`` — run one campaign inside its coordinated detection window:
  refuse (audited) outside it, scan, collect the defender's alerts, score control coverage
  and alert on regressions. Exit ``0`` completed, ``2`` refused (window not open, unknown
  campaign, disabled).
- ``alerts ingest --file <path>`` / ``alerts list`` / ``alerts clear`` — the SIEM ingest
  when a webhook is not the route (an export, or a manual replay).
- ``score <name>`` — re-score a run against whatever alerts have arrived since. Coverage is
  deliberately re-computable: a defender's pipeline reports late.
- ``report <name>`` — the defender report: coverage, Sigma rule-hit/rule-miss, and the
  attack paths an attacker could walk **unseen** (REQ-VALID-005).
- ``trend <name>`` — control coverage over time with regression alerts (REQ-VALID-006).

The area's hard rule is printed by ``--help`` and by ``campaign run``'s banner: purple-team
tests are designed to be **seen**. Payloads go out verbatim, tagged with the run nonce,
inside the window, under the ordinary rate limit; there is no evasion anywhere in this
tool.
"""

from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime
from itertools import pairwise
from pathlib import Path
from typing import Annotated, Any

import typer

from arachne.core.config import get_settings
from arachne.core.errors import ArachneError, ConfigurationError
from arachne.core.target import EngineName
from arachne.purple.attack import NO_EVASION_POLICY
from arachne.purple.campaign import (
    PurpleCampaignService,
    PurpleCampaignSpec,
)
from arachne.purple.report import alignments_from_run, build_defender_report

__all__ = ["app"]

app = typer.Typer(
    help=(
        "Detection validation (purple team). Tests are designed to be SEEN: no evasion, "
        "no stealth — emitted verbatim inside a coordinated detection window."
    )
)

campaign_app = typer.Typer(help="Replayable campaigns and their coordinated runs.")
app.add_typer(campaign_app, name="campaign")
alerts_app = typer.Typer(help="Defender alerts ingested from the SIEM.")
app.add_typer(alerts_app, name="alerts")


def _service(settings: Any = None) -> Any:
    from arachne.data.services import build_services

    services = build_services(settings or get_settings())
    return services, PurpleCampaignService(services)


# ------------------------------------------------------------------ campaigns
@campaign_app.command("add")
def campaign_add(
    name: Annotated[str, typer.Argument(help="Campaign id (lowercase, . _ -).")],
    target: Annotated[str, typer.Option("--target", help="A stored, attested target name.")],
    actions: Annotated[
        list[str],
        typer.Option(
            "--action",
            help="A replayable proof action (repeatable), e.g. m3.cmdi-oob.",
        ),
    ],
    cron: Annotated[
        str | None, typer.Option("--cron", help="Recurring schedule (REQ-VALID-006).")
    ] = None,
    engine: Annotated[str, typer.Option("--engine", help="heuristic | hybrid | ai.")] = "heuristic",
    delay: Annotated[
        int,
        typer.Option("--collect-delay", help="Seconds to wait for the SIEM after the window."),
    ] = 0,
    disabled: Annotated[
        bool, typer.Option("--disabled", help="Store it without arming it.")
    ] = False,
    notes: Annotated[str | None, typer.Option("--notes")] = None,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Create or replace a campaign (validates every action against the shipped map)."""
    services, service = _service()
    try:
        if not actions:
            msg = "a campaign needs at least one --action"
            raise ConfigurationError(msg)
        spec = PurpleCampaignSpec(
            target=target,
            actions=tuple(actions),
            engine=EngineName(engine),
            cron=cron,
            enabled=not disabled,
            collect_delay_s=delay,
            notes=notes,
        )
        campaign = service.create_campaign(name, spec)
    except ArachneError as exc:
        services.close()
        typer.secho(f"purple campaign add: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc
    services.close()
    if json_output:
        typer.echo(json.dumps(campaign.to_dict(), indent=2))
    else:
        typer.echo(
            f"campaign {campaign.name}: {len(campaign.spec.actions)} action(s) against "
            f"{campaign.spec.target}"
            + (f", cron {campaign.spec.cron}" if campaign.spec.cron else "")
            + ("" if campaign.enabled else " (disabled)")
        )


@campaign_app.command("list")
def campaign_list(
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Every stored campaign."""
    services, service = _service()
    try:
        campaigns = service.list_campaigns()
    finally:
        services.close()
    if json_output:
        typer.echo(json.dumps([item.to_dict() for item in campaigns], indent=2))
        return
    if not campaigns:
        typer.echo("no purple campaigns are defined")
        return
    for item in campaigns:
        state = "enabled" if item.enabled else "disabled"
        typer.echo(
            f"{item.name}: {state} · target {item.spec.target} · "
            f"{len(item.spec.actions)} action(s) · {item.spec.cron or 'manual'}"
        )


@campaign_app.command("enable")
def campaign_enable(
    name: Annotated[str, typer.Argument()],
    disable: Annotated[bool, typer.Option("--disable", help="Disable instead.")] = False,
) -> None:
    """Arm or park a campaign (its history is kept either way)."""
    services, service = _service()
    try:
        campaign = service.set_enabled(name, not disable)
    finally:
        services.close()
    if campaign is None:
        typer.secho(f"purple campaign enable: no campaign named {name!r}", err=True)
        raise typer.Exit(code=2)
    typer.echo(f"campaign {campaign.name}: {'enabled' if campaign.enabled else 'disabled'}")


@campaign_app.command("remove")
def campaign_remove(name: Annotated[str, typer.Argument()]) -> None:
    """Delete a campaign and its run history."""
    services, service = _service()
    try:
        removed = service.remove_campaign(name)
    finally:
        services.close()
    if not removed:
        typer.secho(f"purple campaign remove: no campaign named {name!r}", err=True)
        raise typer.Exit(code=2)
    typer.echo(f"campaign {name}: removed")


@campaign_app.command("run")
def campaign_run(
    name: Annotated[str, typer.Argument(help="The campaign to run.")],
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Run one campaign inside its coordinated window (refused and audited outside it)."""
    services, service = _service()
    if not json_output:
        typer.secho(NO_EVASION_POLICY, fg=typer.colors.YELLOW)
    try:
        result = asyncio.run(service.run_campaign(name))
    except ArachneError as exc:
        services.close()
        typer.secho(f"purple campaign run: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc
    services.close()
    if json_output:
        typer.echo(json.dumps(result.to_dict(), indent=2))
    else:
        if result.status == "window_refused":
            typer.secho(f"campaign {name}: refused — {result.note}", fg=typer.colors.RED)
        else:
            typer.echo(
                f"campaign {name}: run #{result.run_id} (scan {result.scan_id}) · "
                f"nonce {result.nonce} · coverage {result.coverage_pct:.1f}% "
                f"({len(result.gaps)} gap(s))"
            )
            for item in result.sigma:
                typer.echo(f"  {item.check_id}: {item.verdict}")
            for technique in result.regressions:
                typer.secho(
                    f"  regression: {technique} was seen before and is unseen now",
                    fg=typer.colors.RED,
                )
    raise typer.Exit(code=0 if result.status == "completed" else 2)


# ------------------------------------------------------------------ alerts
@alerts_app.command("ingest")
def alerts_ingest(
    file: Annotated[Path, typer.Option("--file", help="SIEM export (JSON or NDJSON).")],
    source: Annotated[str, typer.Option("--source", help="Where the alerts came from.")] = "file",
) -> None:
    """Ingest a defender alert export (the webhook route is ``POST /api/v1/purple/alerts``)."""
    services, service = _service()
    try:
        text = Path(file).read_text(encoding="utf-8")
        added = service.ingest_text(text, source=source)
    except (ArachneError, OSError) as exc:
        services.close()
        typer.secho(f"purple alerts ingest: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc
    services.close()
    typer.echo(f"ingested {added} new alert(s) from {file}")


@alerts_app.command("list")
def alerts_list(
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Every ingested defender alert."""
    services, service = _service()
    try:
        alerts = service.alerts()
    finally:
        services.close()
    if json_output:
        typer.echo(
            json.dumps(
                [item.to_alert().to_dict() | {"source": item.source} for item in alerts], indent=2
            )
        )
        return
    if not alerts:
        typer.echo("no defender alerts have been ingested")
        return
    for item in alerts:
        technique = item.technique or "—"
        nonce = item.nonce or "no nonce"
        typer.echo(
            f"{item.observed_at.isoformat()} {item.source} {item.alert_id}: "
            f"{technique} ({nonce}) — {item.title}"
        )


@alerts_app.command("clear")
def alerts_clear() -> None:
    """Drop every ingested alert (a fresh window, a fresh ingest)."""
    services, service = _service()
    try:
        removed = service.store.clear_alerts()
    finally:
        services.close()
    typer.echo(f"cleared {removed} alert(s)")


# ------------------------------------------------------------------ scoring & reporting
@app.command("score")
def score_command(
    name: Annotated[str, typer.Argument(help="The campaign to score.")],
    run_id: Annotated[int | None, typer.Option("--run", help="A specific run.")] = None,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Re-score a run against the alerts ingested so far (coverage is re-computable)."""
    services, service = _service()
    try:
        report = service.score(name, run_id=run_id)
    except ArachneError as exc:
        services.close()
        typer.secho(f"purple score: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc
    services.close()
    if json_output:
        typer.echo(json.dumps(report.to_dict(), indent=2))
        return
    typer.echo(
        f"{name}: {report.seen_count}/{report.total} technique(s) seen "
        f"({report.coverage_pct:.1f}%) · {len(report.gaps)} gap(s)"
    )
    for tactic in report.tactics:
        typer.echo(f"  {tactic.label}: {tactic.coverage_pct:.1f}%")
    for gap in report.gaps:
        typer.echo(f"  unseen: {gap.technique} ({gap.tactic}) via {', '.join(gap.actions)}")


@app.command("report")
def report_command(
    name: Annotated[str, typer.Argument(help="The campaign to report on.")],
    run_id: Annotated[int | None, typer.Option("--run", help="A specific run.")] = None,
    json_output: Annotated[bool, typer.Option("--json", help="JSON instead of markdown.")] = False,
    output: Annotated[
        Path | None, typer.Option("--output", help="Write to this file instead of stdout.")
    ] = None,
) -> None:
    """The defender report: coverage, Sigma alignment and what an attacker could do unseen."""
    from arachne.analyzer.paths import build_attack_paths
    from arachne.data.analysis_store import analysis_from_log

    services, service = _service()
    try:
        run = service.store.run(run_id) if run_id is not None else None
        if run is None:
            runs = service.store.runs(name, limit=1)
            run = runs[-1] if runs else None
        if run is None:
            msg = f"campaign {name!r} has no run to report on"
            raise ConfigurationError(msg)
        coverage = service.score(name, run_id=run.id)
        paths: tuple[Any, ...] = ()
        if run.scan_id is not None:
            stored = services.analyses.list_analyses(run.scan_id)
            rebuilt = [
                item for item in (analysis_from_log(row) for row in stored) if item is not None
            ]
            paths = build_attack_paths(
                rebuilt, candidates=services.findings.list_candidates(run.scan_id)
            )
        # Re-read the run: ``score`` has just written the coverage onto it.
        refreshed = service.store.run(run.id) or run
        report = build_defender_report(
            campaign=name,
            run=refreshed,
            coverage=coverage,
            sigma=alignments_from_run(refreshed),
            attack_paths=paths,
            technique_map=service.technique_map,
            generated_at=datetime.now(UTC),
        )
    except ArachneError as exc:
        services.close()
        typer.secho(f"purple report: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(code=2) from exc
    services.close()
    rendered = json.dumps(report.to_dict(), indent=2) if json_output else report.render_markdown()
    if output is not None:
        Path(output).write_text(rendered, encoding="utf-8")
        typer.echo(f"wrote {output}")
    else:
        typer.echo(rendered)


@app.command("trend")
def trend_command(
    name: Annotated[str, typer.Argument(help="The campaign to trend.")],
    limit: Annotated[int, typer.Option("--limit", help="How many runs to consider.")] = 30,
    json_output: Annotated[bool, typer.Option("--json")] = False,
) -> None:
    """Control coverage over time, with the regression alerts between runs (REQ-VALID-006)."""
    from arachne.purple.coverage import detect_regressions

    services, service = _service()
    try:
        points = service.trend(name, limit=limit)
    finally:
        services.close()
    if json_output:
        typer.echo(json.dumps([item.to_dict() for item in points], indent=2))
        return
    if not points:
        typer.echo(f"campaign {name}: no runs recorded yet")
        return
    typer.echo(f"# Control coverage — {name}")
    typer.echo("")
    typer.echo("| Run | Started | Coverage | Seen | Unseen |")
    typer.echo("|---|---|---|---|---|")
    for point in points:
        typer.echo(
            f"| {point.run_id} | {point.started_at.isoformat()} | "
            f"{point.coverage_pct:.1f}% | {len(point.seen)} | {point.unseen_count} |"
        )
    for previous, current in pairwise(points):
        for technique in detect_regressions(previous, current):
            typer.secho(
                f"regression: {technique} was seen in run {previous.run_id} and is "
                f"unseen in run {current.run_id}",
                fg=typer.colors.RED,
            )
