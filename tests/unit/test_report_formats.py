"""The report-format registry: built-ins, aliases, plugins and the refusal paths (F-09-01)."""

from __future__ import annotations

import pytest

from arachne.core.errors import ReportError
from arachne.report import default_registry, media_type, render_report, report_bytes
from arachne.report.formats import (
    ENTRY_POINT_GROUP,
    ReportFormat,
    ReportFormatRegistry,
)
from arachne.report.model import ReportData


def _csv(report: ReportData) -> str:
    return f"cve,title\n{report.scan_id},{report.findings[0].title if report.findings else ''}\n"


def test_the_builtins_cover_the_spec_formats() -> None:
    registry = default_registry()
    for name in ("md", "markdown", "html", "json", "pdf", "defectdojo", "sarif"):
        assert registry.get(name) is not None
    assert registry.canonical("markdown") == "md"
    # defectdojo joins the builtins in S22 (REQ-OPS-001) as a text JSON format; sarif joins in
    # S26 (REQ-ECOS-003) as the CI code-scanning / PR-annotation format.
    assert [item.name for item in registry.formats] == [
        "md",
        "html",
        "json",
        "pdf",
        "defectdojo",
        "sarif",
    ]


def test_a_plugin_format_is_first_class(synthetic_report: object) -> None:
    plugin = ReportFormat(
        name="example-csv",
        render=_csv,  # type: ignore[arg-type]
        media_type="text/csv; charset=utf-8",
        aliases=("csv",),
        description="test export",
        origin="test-plugin",
    )
    registry = ReportFormatRegistry.discover(extra=[plugin])
    assert registry.canonical("csv") == "example-csv"
    text = registry.require("csv").to_text(synthetic_report)  # type: ignore[arg-type]
    assert text.startswith("cve,title")
    assert registry.media_type("csv") == "text/csv; charset=utf-8"
    assert registry.summary()[-1]["origin"] == "test-plugin"


def test_the_entry_point_group_name_is_the_documented_one() -> None:
    assert ENTRY_POINT_GROUP == "arachne.report_formats"


def test_a_duplicate_name_is_refused() -> None:
    registry = ReportFormatRegistry.discover()
    with pytest.raises(ReportError, match="registered twice"):
        registry.register(ReportFormat(name="md", render=_csv))  # type: ignore[arg-type]


def test_a_duplicate_alias_is_refused() -> None:
    registry = ReportFormatRegistry.discover()
    with pytest.raises(ReportError, match="already used by"):
        registry.register(
            ReportFormat(name="other", render=_csv, aliases=("markdown",))  # type: ignore[arg-type]
        )


def test_an_unknown_format_lists_what_is_installed(synthetic_report: object) -> None:
    with pytest.raises(ReportError, match="unknown report format"):
        render_report(synthetic_report, "docx")  # type: ignore[arg-type]


def test_a_binary_plugin_format_is_served_as_bytes(synthetic_report: object) -> None:
    plugin = ReportFormat(
        name="bin",
        render=lambda report: b"BINARY",
        binary=True,
        media_type="application/octet-stream",
    )
    registry = ReportFormatRegistry.discover(extra=[plugin])
    assert registry.require("bin").to_bytes(synthetic_report) == b"BINARY"  # type: ignore[arg-type]
    with pytest.raises(ReportError, match="binary"):
        registry.require("bin").to_text(synthetic_report)  # type: ignore[arg-type]


def test_a_callable_entry_point_becomes_a_text_format() -> None:
    from arachne.report.formats import _formats_from_object

    formats = _formats_from_object(_csv, name="plain")
    assert formats[0].name == "plain"
    assert formats[0].binary is False
    assert formats[0].origin == "plain"


def test_an_entry_point_returning_nothing_usable_is_a_clear_error() -> None:
    from arachne.report.formats import _formats_from_object

    with pytest.raises(ReportError, match="must resolve to a ReportFormat"):
        _formats_from_object(object(), name="nope")


def test_media_type_reports_octet_stream_for_unknown() -> None:
    assert media_type("does-not-exist") == "application/octet-stream"


def test_report_bytes_uses_the_registry(synthetic_report: object) -> None:
    assert report_bytes(synthetic_report, "json").lstrip().startswith(b"{")  # type: ignore[arg-type]
    assert report_bytes(synthetic_report, "pdf").startswith(b"%PDF-1.4")  # type: ignore[arg-type]
