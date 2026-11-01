"""Report engine and renderers (docs/spec/06-, F-06-*).

The pipeline is three steps and one contract:

1. :mod:`arachne.report.builder` reads the evidence store and produces the immutable
   :class:`~arachne.report.model.ReportData` DTO (the finding schema of docs/spec/06- §1).
2. :mod:`arachne.report.summary` writes the executive summary from that DTO in heuristic
   mode (docs/spec/06- §3 section 2, docs/spec/04- §2.5).
3. A renderer formats the *same* DTO. Formats live in :mod:`arachne.report.formats`: the
   built-ins are Markdown (default), HTML, JSON and PDF, and a third-party package can add
   one through the ``arachne.report_formats`` entry-point group without a core change
   (F-09-01).

``render_report`` / ``report_bytes`` are the small facades the CLI and the API use, so
"which formats exist" is answered in one place and an unknown format is a clean error that
lists what *is* installed.

White-label presentation rides on the DTO (:class:`~arachne.report.model.Branding`), not on
a renderer argument, so the Markdown, HTML, PDF and JSON outputs of one report always carry
the same branding (S14).
"""

from __future__ import annotations

from arachne.report.branding import (
    BrandingError,
    branding_from_dict,
    branding_from_settings,
    load_branding,
    merge_branding,
    resolve_branding,
    white_label,
    white_label_enabled,
)
from arachne.report.builder import (
    ReportInputs,
    build_report_data,
    build_report_for_scan,
    check_runs_from_plan,
    module_versions_for,
    not_run_checks,
    split_check_key,
)
from arachne.report.diff import build_diff, diff_payload
from arachne.report.evidence import DEFAULT_EVIDENCE_BODY_LIMIT, project_evidence
from arachne.report.formats import (
    ENTRY_POINT_GROUP as REPORT_FORMAT_ENTRY_POINT,
)
from arachne.report.formats import (
    ReportFormat,
    ReportFormatRegistry,
    default_registry,
    discover_formats,
    reset_format_cache,
)
from arachne.report.html_render import HTML_CSS, html_to_text, render_html
from arachne.report.json_render import load_report_schema, render_json, report_payload
from arachne.report.markdown import render_markdown
from arachne.report.model import REPORT_SCHEMA_VERSION, Branding, ReportData
from arachne.report.owasp import load_owasp_map
from arachne.report.pdf import (
    PdfResult,
    available_backends,
    pdf_text,
    render_pdf,
    select_backend,
)
from arachne.report.sarif import render_sarif
from arachne.report.summary import build_executive_summary, load_summary_templates

__all__ = [
    "DEFAULT_EVIDENCE_BODY_LIMIT",
    "HTML_CSS",
    "REPORT_FORMATS",
    "REPORT_FORMAT_ENTRY_POINT",
    "REPORT_SCHEMA_VERSION",
    "Branding",
    "BrandingError",
    "PdfResult",
    "ReportData",
    "ReportFormat",
    "ReportFormatRegistry",
    "ReportInputs",
    "available_backends",
    "branding_from_dict",
    "branding_from_settings",
    "build_diff",
    "build_executive_summary",
    "build_report_data",
    "build_report_for_scan",
    "check_runs_from_plan",
    "default_registry",
    "diff_payload",
    "discover_formats",
    "html_to_text",
    "load_branding",
    "load_owasp_map",
    "load_report_schema",
    "load_summary_templates",
    "media_type",
    "merge_branding",
    "module_versions_for",
    "not_run_checks",
    "pdf_text",
    "project_evidence",
    "render_html",
    "render_json",
    "render_markdown",
    "render_pdf",
    "render_report",
    "render_report_bytes",
    "render_sarif",
    "report_formats",
    "report_payload",
    "reset_format_cache",
    "resolve_branding",
    "select_backend",
    "split_check_key",
    "white_label",
    "white_label_enabled",
]

#: The built-in format spellings (kept for compatibility; the registry is authoritative).
REPORT_FORMATS: tuple[str, ...] = ("md", "markdown", "html", "json", "pdf")

# Alias kept so code that imported the literal type still type-checks.
ReportFormatName = str


def report_formats() -> tuple[str, ...]:
    """Every format name this build can render, including installed plugins."""
    return default_registry().names()


def media_type(format: str) -> str:  # noqa: A002 - matches the CLI/API vocabulary
    """The MIME type of a report format, for the API's ``Content-Type``."""
    return default_registry().media_type(format)


def report_bytes(report: ReportData, format: str) -> bytes:  # noqa: A002
    """Render ``report`` to bytes in any format, including a binary plugin format."""
    return default_registry().require(format).to_bytes(report)


def render_report(report: ReportData, format: str = "md") -> str:  # noqa: A002
    """Render ``report`` as text (any non-binary format, built-in or installed).

    A binary format (PDF, or a plugin that declares ``binary=True``) is served by
    :func:`report_bytes` and raises here, because a caller asking for text has already
    made a mistake it should hear about.
    """
    return default_registry().require(format).to_text(report)


#: The primary name for "render any format to bytes"; `report_bytes` is the implementation.
render_report_bytes = report_bytes
