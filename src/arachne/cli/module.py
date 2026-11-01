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
    render_coverage_text,
    write_coverage_markdown,
)
from arachne.modules.registry import ModuleGroup, ModuleRegistry

__all__ = ["coverage_command", "module_app", "render_module_list"]

module_app = typer.Typer(
    name="module",
    help="Inspect the installed detection modules and checks (F-02-10, F-07-01).",
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
    """List the installed modules and the checks each one provides (F-02-10)."""
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
