"""``arachne report`` — render a stored scan as Markdown or JSON (F-06-02, F-06-05).

One command, three jobs:

``arachne report --scan ID``
    print the complete Markdown report (the default format) to stdout.
``--format json``
    print the machine-readable document, whose schema is versioned and shipped
    (``REPORT_SCHEMA_VERSION``).
``--diff-with OTHER``
    compare ``OTHER`` (the earlier scan) with ``--scan`` (the later one), persist the
    ``new``/``fixed``/``regressed``/``recurring`` sets in ``scans_diff`` (F-06-05), and
    include the trend in the rendered report.

The command is read-only with respect to findings: it writes at most one ``scans_diff`` row,
and only when a comparison was asked for.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any

import typer

from arachne import __version__
from arachne.core.config import get_settings
from arachne.core.errors import ReportError
from arachne.data.analysis_store import SqlAnalysisStore
from arachne.data.finding_store import SqlFindingStore
from arachne.data.report_store import SqlAuditReader, SqlScanDiffStore
from arachne.data.services import build_services
from arachne.report import (
    Branding,
    branding_from_dict,
    build_diff,
    build_report_for_scan,
    diff_payload,
    load_branding,
    module_versions_for,
    not_run_checks,
    render_pdf,
    render_report,
    resolve_branding,
)

__all__ = ["report_command", "unrun_opt_in_checks"]

#: Thin aliases: the helpers moved into the report package (S12) so the REST API shares
#: them, but the CLI's public names stay stable for callers and tests.
unrun_opt_in_checks = not_run_checks
_module_versions = module_versions_for


def report_command(
    scan: Annotated[int, typer.Option("--scan", "-s", help="Scan id to report on.")],
    format: Annotated[  # noqa: A002 - matches the CLI's own vocabulary
        str,
        typer.Option("--format", "-f", help="Output format: md (default), html, json or pdf."),
    ] = "md",
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Write the report to this file instead of stdout."),
    ] = None,
    diff_with: Annotated[
        int | None,
        typer.Option(
            "--diff-with",
            help="Compare this earlier scan with --scan and record the diff.",
        ),
    ] = None,
    project: Annotated[
        str | None,
        typer.Option(
            "--project",
            help="Apply this project's white-label branding (default: the scan's project).",
        ),
    ] = None,
    brand: Annotated[
        Path | None,
        typer.Option("--brand", help="Branding YAML/JSON to apply instead of the configured one."),
    ] = None,
    locale: Annotated[
        str | None,
        typer.Option(
            "--locale",
            help=(
                "Report language (e.g. en, fr). Default: the project's locale, else "
                "ARACHNE_REPORT_LOCALE, else en."
            ),
        ),
    ] = None,
    simulate: Annotated[
        bool,
        typer.Option(
            "--simulate",
            help=(
                "Attach a what-if simulation of this scan's estate, rendered in its own "
                "section with 'simulated' provenance."
            ),
        ),
    ] = False,
    hypotheses: Annotated[
        Path | None,
        typer.Option(
            "--hypotheses",
            help=(
                "Hypothesis document for --simulate (YAML/JSON); without one the section "
                "shows the estate as scanned."
            ),
        ),
    ] = None,
) -> None:
    """Render a stored scan's report."""
    services = build_services(get_settings())
    try:
        scans = services.store
        findings = SqlFindingStore(services.session_factory)
        analyses = SqlAnalysisStore(services.session_factory)
        audit_reader = SqlAuditReader(services.session_factory)
        record = scans.get_scan(scan)
        if record is None:
            raise ReportError(f"scan {scan} does not exist")
        branding = _resolve_branding(services, record, project=project, brand=brand)
        selected = _resolve_locale(services, record, project=project, locale=locale)
        module_versions = _module_versions(services.registry, record.plan)
        audit_events = audit_reader.events_for_scan(
            scan, started_at=record.started_at, finished_at=record.finished_at
        )
        not_run = unrun_opt_in_checks(services.registry, findings.list_candidates(scan))

        # S28: an operator-requested what-if block. ``None`` unless ``--simulate`` was asked
        # for, so an ordinary report is unchanged and a simulated path never reaches the
        # verified sections (REQ-SIM-004).
        simulation = _simulation_block(services, scan, hypotheses) if simulate else None

        diff = None
        if diff_with is not None:
            earlier = scans.get_scan(diff_with)
            if earlier is None:
                raise ReportError(f"scan {diff_with} does not exist")
            earlier_audit = audit_reader.events_for_scan(
                diff_with, started_at=earlier.started_at, finished_at=earlier.finished_at
            )
            earlier_report = build_report_for_scan(
                scan_id=diff_with,
                scans=scans,
                findings=findings,
                analyses=analyses,
                audit_events=earlier_audit,
                module_versions=module_versions,
                arachne_version=__version__,
                settings=services.settings,
                generated_at=earlier.finished_at or earlier.created_at,
                branding=branding,
                locale=selected,
            )
            # The current scan's finding set is needed before its full report exists.
            current_report = build_report_for_scan(
                scan_id=scan,
                scans=scans,
                findings=findings,
                analyses=analyses,
                audit_events=audit_events,
                module_versions=module_versions,
                arachne_version=__version__,
                settings=services.settings,
                generated_at=record.finished_at or record.created_at,
                not_run_checks=not_run,
                branding=branding,
                locale=selected,
            )
            diff = build_diff(
                earlier_report.findings,
                current_report.findings,
                scan_a=f"scan_{diff_with}",
                scan_b=f"scan_{scan}",
                suppressions=_active_suppressions(services),
            )
            SqlScanDiffStore(services.session_factory).save(diff_with, scan, diff_payload(diff))
            # Rebuild with the diff attached so the executive summary carries the trend
            # paragraph, not only the structured change counts.
            report = build_report_for_scan(
                scan_id=scan,
                scans=scans,
                findings=findings,
                analyses=analyses,
                audit_events=audit_events,
                module_versions=module_versions,
                arachne_version=__version__,
                settings=services.settings,
                generated_at=record.finished_at or record.created_at,
                not_run_checks=not_run,
                diff=diff,
                branding=branding,
                locale=selected,
                criticality=_criticality_index(services),
                simulation=simulation,
            )
        else:
            report = build_report_for_scan(
                scan_id=scan,
                scans=scans,
                findings=findings,
                analyses=analyses,
                audit_events=audit_events,
                module_versions=module_versions,
                arachne_version=__version__,
                settings=services.settings,
                generated_at=record.finished_at or record.created_at or datetime.now(UTC),
                not_run_checks=not_run,
                branding=branding,
                locale=selected,
                criticality=_criticality_index(services),
                simulation=simulation,
            )
        normalized = format.lower()
        if normalized == "pdf":
            # PDF is binary and its provenance (which headless backend ran) is worth saying.
            result = render_pdf(report)
            if output is None:
                output = Path(f"arachne-scan-{scan}.pdf")
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(result.data)
            backend_note = result.backend
            if result.fallback:
                backend_note += f" (fallback: {result.fallback})"
            typer.echo(
                f"scan {scan}: wrote pdf report to {output} via {backend_note} "
                f"({len(result.data)} bytes, {len(report.findings)} finding(s))"
            )
            return
        rendered = render_report(report, normalized)
        if output is not None:
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text(rendered, encoding="utf-8")
            typer.echo(
                f"scan {scan}: wrote {format} report to {output} "
                f"({len(report.findings)} finding(s), schema {report.schema_version})"
            )
            return
        typer.echo(rendered, nl=False)
    finally:
        services.close()


def _resolve_branding(
    services: Any,
    record: Any,
    *,
    project: str | None,
    brand: Path | None,
) -> Branding:
    """Deployment default ⊕ the scan's project branding ⊕ white-label mode (S26).

    ``resolve_branding`` is shared with the API and the builder so all three agree on the
    presentation *and* on whether MSSP mode (REQ-ECOS-006) is in force. An explicit ``--brand``
    file is itself passed through the same resolver, so a lab run cannot accidentally emit
    ARACHNE attribution in white-label mode.
    """
    override = load_branding(brand) if brand is not None else None
    if override is None:
        target = _project_for(services, record, project)
        if target is not None:
            override = branding_from_dict(target.branding)
    return resolve_branding(services.settings, override)


def _resolve_locale(services: Any, record: Any, *, project: str | None, locale: str | None) -> str:
    """The report language: ``--locale``, else the project's, else the deployment default.

    Returns ``""`` when nothing selects one, leaving the choice to the deployment setting and
    then the i18n module (S26, REQ-ECOS-005).
    """
    if locale and locale.strip():
        return locale.strip()
    target = _project_for(services, record, project)
    stored = getattr(target, "report_locale", None) if target is not None else None
    return str(stored).strip() if stored else ""


def _project_for(services: Any, record: Any, project: str | None) -> Any:
    """The project to take branding/locale from: the named one, else the scan's."""
    target = services.projects.resolve(project) if project else None
    if target is None and getattr(record, "project_id", None) is not None:
        target = services.projects.get(record.project_id)
    return target


def _active_suppressions(services: Any) -> Any:
    """The suppression rules in force (S21), or an empty set when none are wired."""
    from arachne.quality.suppressions import SuppressionSet

    quality = getattr(services, "quality", None)
    return SuppressionSet() if quality is None else quality.active_suppressions()


def _criticality_index(services: Any) -> Any:
    """The CMDB criticality index (S23, REQ-POSTURE-006), or ``None`` without an import.

    ``None`` keeps the report byte-identical to its pre-S23 form: paths without an
    imported tier carry no criticality label and rank exactly as they did.
    """
    from arachne.posture.cmdb import CriticalityIndex

    store = getattr(services, "posture", None)
    if store is None:
        return None
    tiers = store.criticality_index()
    return CriticalityIndex(tiers) if tiers else None


def _simulation_block(services: Any, scan: int, hypotheses: Path | None) -> Any:
    """The S28 what-if block for a report (``--simulate``).

    Built here, at the composition root, because it is the only place that may read the
    stores: the model itself is assembled by ``build_estate_graph_for_scan`` and the block by
    ``report.builder.simulation_block``, so area SIM stays storage-free and the report stays
    the only renderer of a simulated path.
    """
    from arachne.data.services import build_estate_graph_for_scan
    from arachne.report.builder import simulation_block
    from arachne.sim.hypotheses import load_hypotheses
    from arachne.sim.whatif import simulate

    graph = build_estate_graph_for_scan(services, scan_id=scan)
    states = load_hypotheses(hypotheses) if hypotheses is not None else ()
    effective = services.settings.sim
    run = simulate(
        graph,
        states,
        max_hypotheses=effective.max_hypotheses,
        max_paths=effective.max_paths,
        min_confidence=effective.min_confidence,
        auditor=services.auditor,
    )
    return simulation_block(run=run)
