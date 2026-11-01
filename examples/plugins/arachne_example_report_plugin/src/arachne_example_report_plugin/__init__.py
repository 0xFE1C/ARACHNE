"""A complete, minimal ARACHNE **report-format** plugin (F-09-01).

This is the second worked example. Where the check plugin extends detection through
``arachne.modules``, this package adds an output format through
``arachne.report_formats``: it renders the *same* immutable
:class:`~arachne.report.model.ReportData` DTO the built-in renderers read, so a CSV export
cannot disagree with the Markdown report about a severity or an evidence reference.

Two rules the format contract enforces:

* **Consume the DTO, invent nothing.** The renderer formats what it is handed; it never
  re-reads the evidence store.
* **Declare binary-ness.** A text format returns ``str``; a binary one returns ``bytes``
  and sets ``binary=True`` so the API serves the right ``Content-Type`` and the CLI writes
  bytes instead of text.

Install it next to ARACHNE and ``arachne report --scan N --format example-csv`` works with
no change to the core package.
"""

from __future__ import annotations

import csv
import io

from arachne.report.formats import ReportFormat
from arachne.report.model import ReportData

__all__ = ["CSV_FORMAT", "render_csv"]

#: Column order of the export. Deliberately flat: one row per finding is what a spreadsheet
#: or a ticketing importer wants, and the nesting lives in the JSON format.
_COLUMNS: tuple[str, ...] = (
    "finding_id",
    "scan_id",
    "severity",
    "confidence",
    "module",
    "check_id",
    "cwe",
    "cve",
    "asset_kind",
    "asset_value",
    "title",
    "status",
    "remediation_id",
    "evidence_refs",
)


def render_csv(report: ReportData) -> str:
    """Render ``report`` as one CSV row per confirmed finding (plus low-confidence ones)."""
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(_COLUMNS)
    for finding in (*report.findings, *report.low_confidence):
        writer.writerow(
            [
                finding.id,
                finding.scan_id,
                finding.severity,
                finding.score.confidence,
                finding.module,
                finding.check_id,
                finding.classification.cwe or "",
                finding.classification.cve or "",
                finding.asset.kind,
                finding.asset.value,
                finding.title,
                finding.status,
                finding.remediation.id,
                " ".join(finding.evidence_refs),
            ]
        )
    return buffer.getvalue()


#: The entry-point target. ``name`` must not collide with a built-in or another plugin's
#: spelling; the registry refuses a duplicate rather than letting the last package win.
CSV_FORMAT = ReportFormat(
    name="example-csv",
    render=render_csv,
    media_type="text/csv; charset=utf-8",
    aliases=("csv",),
    description="One row per finding, for spreadsheets and ticket importers.",
    origin="example-report-plugin",
)