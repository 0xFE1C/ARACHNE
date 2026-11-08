"""``arachne module`` and ``arachne coverage`` — the registry's operator interfaces.

``module list``
    what is installed: every module group with its version and its checks with theirs
    (F-02-10, F-07-01). ``--json`` for machine consumers.
``coverage``
    the G-01 matrix: which of the research corpus's methods are mapped to checks, produced by
    grepping ``research_ref`` values out of the source tree. ``--write`` emits the
    ``coverage_matrix.md`` the roadmap asks for.

Both are read-only: they describe the build, they do not scan anything.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from pathlib import Path
from typing import Annotated

import typer

from arachne.modules.coverage import (
    build_coverage,
    build_ledger,
    check_ledger,
    default_ledger_paths,
    render_coverage_text,
    render_ledger_json,
    render_ledger_markdown,
    write_coverage_markdown,
)
from arachne.modules.registry import ModuleGroup, ModuleRegistry

__all__ = ["coverage_app", "coverage_command", "module_app", "render_module_list"]

module_app = typer.Typer(
    name="module",
    help="Inspect the installed detection modules and checks.",
    no_args_is_help=True,
)

#: ``arachne coverage`` — the G-01 research-method matrix and the framework ledger.
coverage_app = typer.Typer(
    name="coverage",
    help="Coverage reporting: the research-method matrix and the framework coverage ledger.",
    no_args_is_help=True,
)


@module_app.command("list")
def module_list(
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit the module inventory as JSON.")
    ] = False,
    module: Annotated[
        str | None, typer.Option("--module", "-m", help="Limit the listing to one module id.")
    ] = None,
) -> None:
    """List the installed modules and the checks each one provides."""
    registry = ModuleRegistry.discover()
    if module is not None:
        selected = registry.group(module)
        if selected is None:
            typer.echo(f"error: no module {module!r} is installed", err=True)
            raise typer.Exit(code=2)
        groups: Sequence[ModuleGroup] = (selected,)
    else:
        groups = registry.groups

    if json_output:
        payload = {
            "totals": registry.totals(),
            "versions": registry.check_versions(),
            "modules": [group.summary() for group in groups],
        }
        typer.echo(json.dumps(payload, indent=2))
        return
    typer.echo(render_module_list(groups, registry=registry))


def render_module_list(
    groups: Sequence[ModuleGroup], *, registry: ModuleRegistry | None = None
) -> str:
    """Human-readable module inventory."""
    registry = registry or ModuleRegistry.discover()
    lines: list[str] = [
        "ARACHNE modules (installed checks and their versions)",
        f"  entry-point group for plugins: {registry.totals()['modules']} module(s), "
        f"{registry.totals()['checks']} check(s) registered",
        "",
    ]
    for group in groups:
        lines.append(
            f"{group.id}  {group.title}  v{group.version}  "
            f"({len(group.checks)} check(s), pipeline step: {group.step.value})"
        )
        if group.research_chapter:
            lines.append(f"    research: {group.research_chapter}  origin: {group.origin}")
        lines.append(f"    {'check':26}{'version':9}{'type':8}{'ref':11}{'requests':9}flags")
        for metadata in group.metadata():
            flags: list[str] = []
            if metadata.is_opt_in:
                flags.append("opt-in")
            if metadata.requires_active_checks:
                flags.append("active")
            if metadata.requires_credentials:
                flags.append("needs " + ",".join(metadata.requires_credentials))
            if metadata.runs_on_discovered:
                flags.append("discovered-assets")
            lines.append(
                f"    {metadata.id:26}{metadata.version:9}{metadata.type:8}"
                f"{metadata.research_ref:11}{metadata.estimated_requests:<9}"
                f"{' '.join(flags) or '-'}"
            )
        lines.append("")
    totals = registry.totals()
    lines.append(
        f"totals: {totals['modules']} module(s), {totals['checks']} check(s), "
        f"{totals['opt_in_checks']} opt-in, {totals['active_checks']} active"
    )
    return "\n".join(lines)


@module_app.command("coverage")
def coverage_command(
    json_output: Annotated[bool, typer.Option("--json", help="Emit the matrix as JSON.")] = False,
    write: Annotated[
        Path | None,
        typer.Option("--write", help="Write the markdown matrix to this path."),
    ] = None,
    research_dir: Annotated[
        Path | None,
        typer.Option("--research-dir", help="Directory holding the research chapters."),
    ] = None,
    include_templates: Annotated[
        bool,
        typer.Option(
            "--include-templates/--implemented-only",
            help="Also count the planning catalogue's references, not just implemented checks.",
        ),
    ] = False,
    root: Annotated[
        list[Path] | None,
        typer.Option("--root", help="Source root to grep (repeatable)."),
    ] = None,
) -> None:
    """Report which research methods are mapped to checks (G-01)."""
    report = build_coverage(
        research_dir,
        source_roots=tuple(root) if root else None,
        include_templates=include_templates,
    )
    if write is not None:
        target = write_coverage_markdown(report, write)
        typer.echo(f"wrote {target}")
    if json_output:
        typer.echo(report.to_json())
        return
    typer.echo(render_coverage_text(report))


# ``arachne coverage matrix`` is the same command as ``arachne module coverage``: one
# implementation, two spellings (the roadmap's G-01 name and the inventory's neighbourhood).
coverage_app.command("matrix")(coverage_command)


@coverage_app.command("ledger")
def coverage_ledger(
    output_format: Annotated[
        str, typer.Option("--format", help="Output format: json (default) or markdown.")
    ] = "json",
    write: Annotated[
        Path | None,
        typer.Option("--write", help="Write the ledger to this path instead of stdout."),
    ] = None,
    check: Annotated[
        bool,
        typer.Option("--check", help="Fail when the committed ledger differs from the registry."),
    ] = False,
    generated_at: Annotated[
        str | None,
        typer.Option("--generated-at", help="Override the ledger's generation date (YYYY-MM-DD)."),
    ] = None,
) -> None:
    """Emit the framework coverage ledger generated from the check registry.

    One record per registered check — id, module, title, proof level, target kinds, framework
    items and last-verified date — plus the WSTG per-id states and the API Top 10 tally.
    ``--check`` is the CI gate: it regenerates from the committed date and compares bytes,
    naming every check id that moved.
    """
    if check:
        ok, differences = check_ledger(*default_ledger_paths())
        if not ok:
            for difference in differences:
                typer.echo(f"error: {difference}", err=True)
            typer.echo(
                "error: the coverage ledger is stale; run `arachne coverage ledger --write`",
                err=True,
            )
            raise typer.Exit(code=1)
        typer.echo("the committed coverage ledger is up to date")
        return

    ledger = build_ledger(generated_at=generated_at)
    if output_format not in {"json", "markdown"}:
        typer.echo(f"error: unknown format {output_format!r} (expected json or markdown)", err=True)
        raise typer.Exit(code=2)
    payload = (
        render_ledger_json(ledger) if output_format == "json" else render_ledger_markdown(ledger)
    )
    if write is not None:
        target = Path(write).expanduser()
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(payload, encoding="utf-8")
        typer.echo(f"wrote {target}")
        return
    typer.echo(payload, nl=False)
