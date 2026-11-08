"""``arachne simulate`` — simulation & what-if modeling (S28, area SIM).

Four verbs, in the order an operator uses them:

- ``model`` — build the estate model for a scan (or a project's recent scans) and show what
  it holds: hosts, observed services, identities, weaknesses, and the paths the *verified*
  composer already finds. Read-only, and the answer to "what does ARACHNE think my estate
  is?" before any hypothetical is injected.
- ``what-if <scan> --hypotheses <file>`` — inject hypothetical states and print the paths they
  produce, each hop marked ``observed`` or ``hypothetical``. Every line is labelled
  ``simulated``.
- ``change <scan> --change <file>`` — the before/after exposure delta of a proposed design
  (REQ-SIM-005), with the paths the change introduces and the ones it closes.
- ``trend`` — the re-simulation trend, and ``--run`` to trigger one re-simulation by hand.

None of these verbs can touch a target, and that is not a promise in this docstring: the
engine runs inside :func:`arachne.sim.boundary.no_network`, so a socket call from anywhere in
the call graph is refused, audited and raised (REQ-SIM-003). Nothing here writes a finding
either — a simulated path exists only in the output and in its own trend table (REQ-SIM-004).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Any, NoReturn

import typer

from arachne.core.config import get_settings
from arachne.core.errors import ArachneError, SimulationError
from arachne.sim.change import simulate_change
from arachne.sim.hypotheses import (
    Hypothesis,
    load_change_set,
    load_hypotheses,
)
from arachne.sim.model import EstateGraph
from arachne.sim.trend import build_simulation_trend
from arachne.sim.whatif import SimulationRun, severity_sort_key, simulate

__all__ = ["app"]

app = typer.Typer(help="Simulation & what-if modeling: the estate model and hypothetical states.")


def _fail(message: str, code: int = 2) -> NoReturn:
    typer.secho(f"simulate: {message}", fg=typer.colors.RED, err=True)
    raise typer.Exit(code=code)


def _services_and_graph(
    *, scan: int | None, project: int | None, estate_key: str
) -> tuple[Any, EstateGraph]:
    """The stack and the estate model for the requested scope (read-only)."""
    from arachne.data.services import build_estate_graph_for_scan, build_services

    try:
        services = build_services(get_settings())
    except ArachneError as exc:
        _fail(str(exc))
    try:
        graph = build_estate_graph_for_scan(
            services, scan_id=scan, project_id=project, estate_key=estate_key
        )
    except ArachneError as exc:
        services.close()
        _fail(str(exc))
    return services, graph


def _hypotheses_from(inline: str, path: Path | None) -> tuple[Hypothesis, ...]:
    if path is not None:
        return load_hypotheses(path)
    if inline.strip():
        return load_hypotheses_from_text(inline)
    return ()


def load_hypotheses_from_text(text: str) -> tuple[Hypothesis, ...]:
    """Parse a hypothesis document given inline (``--hypothesis-inline``)."""
    import yaml

    from arachne.sim.hypotheses import parse_hypotheses

    try:
        document = yaml.safe_load(text)
    except yaml.YAMLError as exc:  # pragma: no cover - malformed operator input
        msg = f"the inline hypothesis document is not valid YAML or JSON ({exc.__class__.__name__})"
        raise SimulationError(msg) from exc
    if not isinstance(document, (dict, list)):
        msg = "the inline hypothesis document must be a mapping or a list"
        raise SimulationError(msg)
    return parse_hypotheses(document)


# ------------------------------------------------------------------ model
@app.command(name="model")
def model_command(
    scan: Annotated[int | None, typer.Option("--scan", help="Model this scan.")] = None,
    project: Annotated[int | None, typer.Option("--project", help="Model this project.")] = None,
    estate_key: Annotated[str, typer.Option("--estate", help="Key for this estate.")] = "",
    json_output: Annotated[bool, typer.Option("--json", help="Machine-readable output.")] = False,
) -> None:
    """Build the estate model from scan data and show what it holds."""
    services, graph = _services_and_graph(scan=scan, project=project, estate_key=estate_key)
    try:
        if json_output:
            typer.echo(json.dumps(graph.to_dict(), indent=2, sort_keys=True))
            return
        summary = graph.summary()
        typer.echo(f"estate: {graph.estate_key} (model {graph.model_version})")
        typer.echo(
            f"built from scan(s): {', '.join(str(item) for item in graph.built_from_scans)}"
            if graph.built_from_scans
            else "built from scan(s): —"
        )
        typer.echo(
            f"hosts={summary['hosts']} services={summary['services']} "
            f"identities={summary['identities']} weaknesses={summary['weaknesses']} "
            f"edges={summary['edges']} pivots={summary['pivots']}"
        )
        typer.echo("")
        typer.echo("hosts (observed services):")
        for host in graph.hosts:
            ports = ", ".join(f"{item.port}/{item.protocol}" for item in graph.services_of(host))
            identities = ", ".join(graph.identities_of(host))
            suffix = f" identities: {identities}" if identities else ""
            typer.echo(f"  {host} — {ports or 'no observed service'}{suffix}")
        typer.echo("")
        typer.echo("verified attack paths already composed from the estate:")
        paths = graph.attack_paths()
        if not paths:
            typer.echo("  (none)")
        for path in paths:
            typer.echo(
                f"  {path.id} {path.asset} "
                f"{' → '.join(hop.stage.value for hop in path.hops)} "
                f"(terminal {path.severity})"
            )
    finally:
        services.close()


# ------------------------------------------------------------------ what-if
@app.command(name="what-if")
def what_if_command(
    scan: Annotated[int | None, typer.Option("--scan", help="Model this scan.")] = None,
    project: Annotated[int | None, typer.Option("--project", help="Model this project.")] = None,
    hypotheses: Annotated[
        Path | None, typer.Option("--hypotheses", help="YAML/JSON hypothesis document.")
    ] = None,
    hypothesis_inline: Annotated[
        str, typer.Option("--hypothesis-inline", help="Inline YAML/JSON hypotheses.")
    ] = "",
    estate_key: Annotated[str, typer.Option("--estate", help="Key for this estate.")] = "",
    json_output: Annotated[bool, typer.Option("--json", help="Machine-readable output.")] = False,
) -> None:
    """Inject hypothetical states and print the paths they produce."""
    try:
        states = _hypotheses_from(hypothesis_inline, hypotheses)
    except ArachneError as exc:
        _fail(str(exc))
    if not states:
        _fail("name a hypothesis document with --hypotheses (or --hypothesis-inline)")

    services, graph = _services_and_graph(scan=scan, project=project, estate_key=estate_key)
    try:
        effective = services.settings.sim
        run = simulate(
            graph,
            states,
            max_hypotheses=effective.max_hypotheses,
            max_paths=effective.max_paths,
            min_confidence=effective.min_confidence,
            auditor=services.auditor,
        )
    except ArachneError as exc:
        services.close()
        _fail(str(exc))
    try:
        _emit_run(run, json_output=json_output)
    finally:
        services.close()


def _emit_run(run: SimulationRun, *, json_output: bool) -> None:
    if json_output:
        typer.echo(json.dumps(run.to_dict(), indent=2, sort_keys=True))
        return
    typer.echo(
        f"simulated what-if over {run.estate_key} "
        f"(model {run.model_version}, scans {', '.join(str(i) for i in run.built_from_scans)})"
    )
    typer.echo(
        "NOTHING HERE WAS OBSERVED ON A TARGET — this is a computation over stored scan data."
    )
    typer.echo("")
    typer.echo("hypotheses:")
    for item in run.hypotheses:
        typer.echo(f"  {item.id} ({item.kind.value}) {item.asset}: {item.note or item.title}")
    for refusal in run.refusals:
        typer.echo(
            f"  refused {refusal.hypothesis.id}: {refusal.reason}",
            err=True,
        )
    typer.echo("")
    typer.echo(
        f"exposure score: {run.exposure_before} → {run.exposure_after} "
        f"({len(run.introduced)} path(s) exist only under the hypotheses)"
    )
    typer.echo("")
    if not run.result:
        typer.echo("no path follows from the estate plus these hypothetical states.")
        return
    for path in sorted(run.result, key=severity_sort_key):
        marker = "hypothetical" if path.hypothetical else "as scanned"
        typer.echo(f"{path.path.id} — {path.path.asset} (terminal {path.path.severity}, {marker})")
        for hop in path.hops:
            origin = "hypothetical" if hop.hypothetical else "observed"
            source = f" [{hop.hypothesis_id}]" if hop.hypothesis_id else ""
            typer.echo(
                f"    {hop.hop.stage.value:<11} {hop.hop.check_id} on {hop.hop.asset} "
                f"({hop.hop.severity}, {origin}){source}"
            )
        if path.cheapest_label:
            typer.echo(f"    cheapest break: {path.cheapest_label}")
        typer.echo("")


# ------------------------------------------------------------------ change
@app.command(name="change")
def change_command(
    change_path: Annotated[Path, typer.Argument(help="YAML/JSON change document.")],
    scan: Annotated[int | None, typer.Option("--scan", help="Model this scan.")] = None,
    project: Annotated[int | None, typer.Option("--project", help="Model this project.")] = None,
    estate_key: Annotated[str, typer.Option("--estate", help="Key for this estate.")] = "",
    json_output: Annotated[bool, typer.Option("--json", help="Machine-readable output.")] = False,
) -> None:
    """Simulate a proposed change and print the before/after exposure delta."""
    try:
        change = load_change_set(change_path)
    except ArachneError as exc:
        _fail(str(exc))
    services, graph = _services_and_graph(scan=scan, project=project, estate_key=estate_key)
    try:
        effective = services.settings.sim
        delta = simulate_change(
            graph,
            change,
            max_hypotheses=effective.max_hypotheses,
            max_paths=effective.max_paths,
            min_confidence=effective.min_confidence,
            auditor=services.auditor,
        )
    except ArachneError as exc:
        services.close()
        _fail(str(exc))
    try:
        if json_output:
            typer.echo(json.dumps(delta.to_dict(), indent=2, sort_keys=True))
            return
        typer.echo(f"change: {delta.change.name}")
        if delta.change.description:
            typer.echo(delta.change.description)
        typer.echo("SIMULATED — nothing here was observed on a target.")
        typer.echo("")
        typer.echo(
            f"exposure: {delta.exposure_before} → {delta.exposure_after} "
            f"({delta.exposure_delta:+d})  paths: {len(delta.before)} → {len(delta.after)}"
        )
        if delta.introduced:
            typer.echo("introduced:")
            for path in delta.introduced:
                typer.echo(
                    f"  {path.path.id} {path.path.asset} "
                    f"({' → '.join(hop.hop.stage.value for hop in path.hops)}) "
                    f"terminal {path.path.severity}"
                )
        if delta.removed:
            typer.echo("removed:")
            for removed in delta.removed:
                typer.echo(f"  {removed.id} {removed.asset} (terminal {removed.severity})")
    finally:
        services.close()


# ------------------------------------------------------------------ trend
@app.command(name="trend")
def trend_command(
    estate_key: Annotated[str, typer.Option("--estate", help="Key for this estate.")] = "",
    scan: Annotated[int | None, typer.Option("--scan", help="Model this scan.")] = None,
    project: Annotated[int | None, typer.Option("--project", help="Model this project.")] = None,
    run_now: Annotated[
        bool, typer.Option("--run", help="Re-simulate once, then print the trend.")
    ] = False,
    hypotheses: Annotated[
        Path | None, typer.Option("--hypotheses", help="YAML/JSON hypothesis document.")
    ] = None,
    json_output: Annotated[bool, typer.Option("--json", help="Machine-readable output.")] = False,
) -> None:
    """Show the re-simulation trend, optionally re-simulating once first."""
    from arachne.data.services import build_resimulator_for, build_services

    try:
        states = _hypotheses_from("", hypotheses)
    except ArachneError as exc:
        _fail(str(exc))
    try:
        services = build_services(get_settings())
    except ArachneError as exc:
        _fail(str(exc))
    try:
        key = estate_key or (f"scan:{scan}" if scan is not None else "estate:default")
        store = services.simulations
        if run_now:
            resim = build_resimulator_for(
                services,
                estate_key=key,
                hypotheses=states,
                scan_id=scan,
                project_id=project,
            )
            if resim.run_once(scan_id=scan) is None:
                _fail("nothing to simulate: no scan data for this estate")
        limit = services.settings.sim.trend_limit
        points = store.points(estate_key=key, limit=limit) if store else ()
        trend = build_simulation_trend(points, estate_key=key)
        if json_output:
            typer.echo(json.dumps(trend.payload(), indent=2, sort_keys=True))
            return
        typer.echo(f"simulation trend — {trend.estate_key} ({trend.provenance})")
        typer.echo("")
        typer.echo(trend.markdown())
        if trend.points:
            typer.echo("")
            typer.echo(f"direction: {trend.trend_direction}")
    finally:
        services.close()
