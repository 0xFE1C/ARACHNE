"""``arachne compliance`` — framework maps and the audit-ready evidence export (S22).

Two operator verbs (REQ-TRUST-001):

``frameworks``
    The frameworks this deployment can map onto: the bundled names, plus any
    custom map in the configured override directory
    (``ARACHNE_REPORT_COMPLIANCE_MAPS``).
``export``
    One scan's per-control evidence as a self-contained JSON document: for every
    control of ``--framework``, its state (pass/fail/gap), the failing findings and
    their redacted evidence payloads, the audit-trail summary, and the framework's
    unmapped remainder stated explicitly. Written to ``--output`` or stdout, so it can
    be attached to an audit ticket without re-deriving anything from a live database.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated

import typer

from arachne import __version__
from arachne.core.config import get_settings
from arachne.core.errors import ConfigurationError, ReportError
from arachne.modules.compliance_map import TARGET_RATIOS

__all__ = ["compliance_app"]

#: How many unassessed controls ``frameworks`` prints before summarising the rest. The full list
#: is in the export and in the generated map file, which is where an auditor reads it.
OUTSIDE_PREVIEW = 5

compliance_app = typer.Typer(
    name="compliance",
    help="Compliance framework maps and per-control evidence export (S22).",
    no_args_is_help=True,
)


def plural(kind: str) -> str:
    """`subcategory` → `subcategories`, anything else +`s` (a display nicety)."""
    return (kind[:-1] + "ies") if kind.endswith("y") else kind + "s"


@compliance_app.command("frameworks")
def frameworks_command() -> None:
    """List the frameworks the check catalogue can map onto."""
    from arachne.report.compliance import available_frameworks, load_compliance_framework

    maps_dir = get_settings().report.compliance_map_dir
    for name in available_frameworks():
        try:
            map_data = load_compliance_framework(name, maps_dir=maps_dir)
        except ConfigurationError as exc:
            typer.echo(f"{name}: unavailable ({exc})", err=True)
            continue
        origin = "custom" if maps_dir else "bundled"
        # REQ-TRUST-009: the ratio first, then the gap by name — "16 of 93 mapped" used to leave
        # the reader to guess what the other 77 were.
        typer.echo(
            f"{name:10s} {map_data.name} ({map_data.edition}) — "
            f"{map_data.assessed} of {map_data.total_controls} {plural(map_data.kind)} assessed "
            f"(target {TARGET_RATIOS[name][0]}), "
            f"{len(map_data.outside_assessed_set)} outside the assessed set "
            f"[{origin}, map v{map_data.map_version}]"
        )
        if map_data.outside_assessed_set:
            for control in map_data.outside_assessed_set[:OUTSIDE_PREVIEW]:
                typer.echo(f"             · {control.id}: {control.reason}")
            remaining = len(map_data.outside_assessed_set) - OUTSIDE_PREVIEW
            if remaining > 0:
                typer.echo(
                    f"             · ...and {remaining} more, in "
                    f"`arachne compliance export` and templates/compliance/{name}.yaml"
                )


@compliance_app.command("export")
def export_command(
    scan: Annotated[int, typer.Option("--scan", "-s", help="Scan id to export.")],
    framework: Annotated[
        str,
        typer.Option(
            "--framework",
            "-f",
            help="Framework to export (one of `arachne compliance frameworks`).",
        ),
    ],
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write the JSON document here (default stdout)."),
    ] = None,
) -> None:
    """Export one scan's per-control evidence for a framework as audit-ready JSON."""
    from arachne.ai.provenance import summarize_provenance
    from arachne.data.analysis_store import SqlAnalysisStore
    from arachne.data.finding_store import SqlFindingStore
    from arachne.data.report_store import SqlAuditReader
    from arachne.data.services import build_services
    from arachne.report import build_report_for_scan
    from arachne.report.compliance import (
        canonical_framework,
        export_control_evidence,
        load_compliance_framework,
    )

    settings = get_settings()
    canonical = canonical_framework(framework)
    if canonical is None:
        raise ConfigurationError(
            f"unknown compliance framework {framework!r} (see `arachne compliance frameworks`)"
        )
    map_data = load_compliance_framework(canonical, maps_dir=settings.report.compliance_map_dir)

    services = build_services(settings)
    try:
        record = services.store.get_scan(scan)
        if record is None:
            raise ReportError(f"scan {scan} does not exist")
        findings = SqlFindingStore(services.session_factory)
        analyses = SqlAnalysisStore(services.session_factory)
        audit_reader = SqlAuditReader(services.session_factory)
        audit_events = audit_reader.events_for_scan(
            scan, started_at=record.started_at, finished_at=record.finished_at
        )
        report = build_report_for_scan(
            scan_id=scan,
            scans=services.store,
            findings=findings,
            analyses=analyses,
            audit_events=audit_events,
            arachne_version=__version__,
            settings=settings,
            compliance_frameworks=(canonical,),
        )
        # WP-15 (REQ-AGENT-008): the AI-governance answer an auditor asks for — which provider
        # received how many tokens for this scan — read from the records the scan persisted.
        ai_provenance = {
            "scope": {"kind": "scan", "scan_id": scan},
            **summarize_provenance(analyses.provenance_for_scan(scan), scan_ids=(scan,)),
        }
    finally:
        services.close()

    document = export_control_evidence(
        map_data,
        report,
        generated_at=datetime.now(UTC).isoformat(),
        ai_provenance=ai_provenance,
    )
    rendered = json.dumps(document, indent=2, ensure_ascii=False, default=str) + "\n"
    if output is not None:
        output.write_text(rendered, encoding="utf-8")
        controls = document["controls"]
        count = len(controls) if isinstance(controls, list) else 0
        typer.echo(f"wrote {output} ({count} controls)")
    else:
        typer.echo(rendered.rstrip())
