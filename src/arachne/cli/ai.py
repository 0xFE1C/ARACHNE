"""``arachne ai`` — the AI provenance export (WP-15, REQ-AGENT-008).

One operator verb, and it exists because of one sentence in the requirement: a regulated
customer has to be able to answer *"which provider received how many tokens for this scan, and
what did the model decide?"* (REQ-AGENT-008). The answer is in
``analysis_log.provenance``, one record per analysis row; this command aggregates those records
per scan or per project and writes the document.

``provenance``
    ``--scan N`` for one scan, or ``--project P`` for every scan of a project, printed as JSON
    (default) or a one-line-per-provider table. The document carries the origins, the provider
    and model totals with their row counts, the per-stage contribution counts, and
    ``uncited_ai_rows`` — a counter that must be zero, because an AI row that cites no evidence
    is the thing ``REQ-AGENT-008`` forbids.

The export names no prompt body and no evidence payload: ids, hashes and counts only, so it can
be attached to an audit ticket without leaking what the scan saw.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Annotated, Any

import typer

from arachne.core.config import get_settings
from arachne.core.errors import ConfigurationError

__all__ = ["ai_app"]

ai_app = typer.Typer(
    name="ai",
    help="AI provenance: what a model contributed to a scan, and what it cost (WP-15).",
    no_args_is_help=True,
)


@ai_app.command("provenance")
def provenance_command(
    scan: Annotated[
        int | None,
        typer.Option("--scan", "-s", help="Scan id to export provenance for."),
    ] = None,
    project: Annotated[
        int | None,
        typer.Option(
            "--project",
            "-p",
            help="Project id to export provenance for (every scan of the project).",
        ),
    ] = None,
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write the JSON document here (default stdout)."),
    ] = None,
    table: Annotated[
        bool,
        typer.Option("--table", help="Print a per-provider table instead of the JSON document."),
    ] = False,
) -> None:
    """Export the AI provenance of one scan, or of a whole project."""
    if (scan is None) == (project is None):
        raise ConfigurationError("pass exactly one of --scan or --project")
    from arachne.data.analysis_store import SqlAnalysisStore
    from arachne.data.services import build_services

    settings = get_settings()
    services = build_services(settings)
    analyses = SqlAnalysisStore(services.session_factory)
    if scan is not None:
        if services.store.get_scan(scan) is None:
            raise ConfigurationError(f"scan {scan} does not exist")
        records = analyses.provenance_for_scan(scan)
        scope: dict[str, Any] = {"kind": "scan", "scan_id": scan}
    else:
        records = analyses.provenance_for_project(project)
        scope = {"kind": "project", "project_id": project}

    from arachne.ai.provenance import summarize_provenance

    summary = summarize_provenance(records, scan_ids=[scan] if scan is not None else ())
    document = provenance_document(records, scope=scope, summary=summary)
    if table:
        typer.echo(_table(summary))
        return
    payload = json.dumps(document, indent=2, sort_keys=False)
    if output is None:
        typer.echo(payload)
        return
    output.write_text(payload + "\n", encoding="utf-8")
    typer.echo(f"wrote {output}")


def _table(summary: Mapping[str, Any]) -> str:
    """A one-line-per-provider rendering, for an operator reading a terminal."""
    lines = [
        f"rows: {summary['rows']} (ai {summary['ai_rows']}, heuristic {summary['heuristic_rows']})",
        f"uncited AI rows: {summary['uncited_ai_rows']}",
    ]
    providers = summary.get("providers") or {}
    if not isinstance(providers, Mapping) or not providers:
        lines.append("no AI contribution recorded")
        return "\n".join(lines)
    lines.append(f"{'provider':22s} {'rows':>6s} {'prompt':>9s} {'completion':>11s} {'total':>9s}")
    for name, entry in sorted(providers.items()):
        values = entry if isinstance(entry, Mapping) else {}
        lines.append(
            f"{name!s:22s} {int(values.get('rows', 0)):6d} "
            f"{int(values.get('prompt_tokens', 0)):9d} "
            f"{int(values.get('completion_tokens', 0)):11d} "
            f"{int(values.get('total_tokens', 0)):9d}"
        )
    return "\n".join(lines)


def provenance_document(
    records: Sequence[Mapping[str, Any]],
    *,
    scope: Mapping[str, Any],
    summary: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """The export document: the scope, the summary, and the identity a reader greps for.

    ``summary`` is accepted so a caller that has already computed it (the CLI does, for its
    table) does not compute it twice; the compliance export builds its own block from the same
    :func:`~arachne.ai.provenance.summarize_provenance` and passes the scope it wants.
    """
    from arachne.ai.provenance import summarize_provenance

    body = dict(summary) if summary is not None else summarize_provenance(records)
    return {
        "document": "arachne-ai-provenance",
        "version": "1.0",
        "scope": dict(scope),
        **body,
    }
