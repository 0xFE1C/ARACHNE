"""``arachne feeds`` — import and manage CVE/EPSS feeds (F-09-03, S14).

Ingestion is offline: you bring a file, ARACHNE validates and normalises it, and the M6
correlation check consumes the normalised artefact on the next scan. No request is made and
no third-party host is contacted — which is what makes the workflow usable on an air-gapped
deployment and keeps the scanner's egress rules intact.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Annotated, Any

import typer

from arachne.core.config import get_settings
from arachne.data.services import build_services

__all__ = ["feeds_app"]

feeds_app = typer.Typer(
    name="feeds",
    help="Import and inspect CVE/EPSS feed artefacts.",
    no_args_is_help=True,
)


@feeds_app.command("import")
def import_feed(
    path: Annotated[Path, typer.Argument(help="EPSS CSV, KEV JSON or CVE JSON/YAML export.")],
    kind: Annotated[
        str | None,
        typer.Option("--kind", help="epss | kev | cve (inferred from the file when omitted)."),
    ] = None,
    name: Annotated[str | None, typer.Option("--name", help="Label for this feed.")] = None,
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Validate, normalise and store a feed file; the next scan uses it automatically."""
    settings = get_settings()
    services = build_services(settings)
    try:
        record = services.feeds.import_file(
            path,
            kind=kind,
            name=name,
            imported_by=settings.actor,
            max_entries=settings.feeds.max_entries,
        )
    finally:
        services.close()
    payload = record.to_dict()
    if json_output:
        typer.echo(json.dumps(payload, indent=2))
        return
    typer.echo(
        f"imported {payload['kind']} feed #{payload['id']} {payload['name']!r}: "
        f"{payload['record_count']} CVE row(s) -> {payload['path']}"
    )
    typer.echo("the next scan will use it (no environment change needed)")


@feeds_app.command("list")
def list_feeds(
    kind: Annotated[str | None, typer.Option("--kind", help="Filter by kind.")] = None,
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """List imported feeds, newest first."""
    services = build_services(get_settings())
    try:
        records = [record.to_dict() for record in services.feeds.list_feeds(kind=kind)]
    finally:
        services.close()
    if json_output:
        typer.echo(json.dumps(records, indent=2))
        return
    typer.echo(f"{'ID':<5} {'KIND':<5} {'ENTRIES':>8} {'VERSION':<18} NAME")
    for row in records:
        typer.echo(
            f"{row['id']:<5} {row['kind']:<5} {row['record_count']:>8} "
            f"{(row['version'] or '-'):<18} {row['name']}"
        )


@feeds_app.command("show")
def show_feed(
    feed_id: Annotated[int, typer.Argument(help="Feed id.")],
    limit: Annotated[int, typer.Option("--limit", help="Rows to print.")] = 20,
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Show one feed's provenance and a sample of its normalised rows."""
    services = build_services(get_settings())
    try:
        record = services.feeds.get(feed_id)
        entries = services.feeds.entries(feed_id, limit=limit) if record else ()
    finally:
        services.close()
    if record is None:
        raise typer.BadParameter(f"feed {feed_id} does not exist")
    payload = {**record.to_dict(), "sample": list(entries)}
    typer.echo(json.dumps(payload, indent=2) if json_output else _render(record.to_dict(), entries))


@feeds_app.command("lookup")
def lookup_cve(
    cve: Annotated[str, typer.Argument(help="A CVE id, e.g. CVE-2021-44228.")],
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Look a CVE up in the active ingested feeds."""
    services = build_services(get_settings())
    try:
        found = services.feeds.lookup(cve)
    finally:
        services.close()
    if found is None:
        typer.echo(f"{cve.upper()}: not present in the active ingested feeds")
        raise typer.Exit(code=1)
    typer.echo(json.dumps(found, indent=2) if json_output else _render_lookup(found))


@feeds_app.command("stats")
def feed_stats(
    json_output: Annotated[bool, typer.Option("--json", help="Emit JSON.")] = False,
) -> None:
    """Counts per feed kind and the artefacts directory."""
    services = build_services(get_settings())
    try:
        stats = services.feeds.stats()
    finally:
        services.close()
    if json_output:
        typer.echo(json.dumps(stats, indent=2))
        return
    typer.echo(f"feeds directory: {stats['directory']}")
    for kind, counts in stats["by_kind"].items():
        typer.echo(f"  {kind:<5} {counts['feeds']:>3} feed(s), {counts['entries']:>8} row(s)")


@feeds_app.command("delete")
def delete_feed(
    feed_id: Annotated[int, typer.Argument(help="Feed id.")],
    force: Annotated[bool, typer.Option("--force", help="Do not ask for confirmation.")] = False,
) -> None:
    """Delete a feed: its rows, its record and its normalised artefact."""
    services = build_services(get_settings())
    try:
        record = services.feeds.get(feed_id)
        if record is None:
            raise typer.BadParameter(f"feed {feed_id} does not exist")
        if not force:
            typer.confirm(f"delete {record.kind} feed {record.name!r}?", abort=True)
        services.feeds.delete(feed_id)
    finally:
        services.close()
    typer.echo(f"deleted feed {feed_id}")


def _render(payload: dict[str, object], entries: tuple[dict[str, object], ...]) -> str:
    lines = [
        f"id:           {payload['id']}",
        f"kind:         {payload['kind']}",
        f"name:         {payload['name']}",
        f"version:      {payload.get('version') or '(none)'}",
        f"source:       {payload.get('source') or '(none)'}",
        f"artefact:     {payload['path']}",
        f"entries:      {payload['record_count']}",
        f"imported by:  {payload.get('imported_by') or '(unknown)'}",
        "",
        "sample:",
    ]
    for row in entries:
        rest = {key: value for key, value in row.items() if key != "cve"}
        lines.append(f"  {row.get('cve')}: {json.dumps(rest)}")
    return "\n".join(lines)


def _render_lookup(payload: dict[str, Any]) -> str:
    lines = [f"{payload['cve']}"]
    for key in ("epss", "percentile", "kev", "cvss"):
        if key in payload:
            lines.append(f"  {key}: {payload[key]}")
    for source in payload.get("sources") or []:
        lines.append(f"  from: {source}")
    return "\n".join(lines)
