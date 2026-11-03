"""The report DTO: ids, counts and immutability (ADR-06)."""

from __future__ import annotations

import pytest
from pydantic import ValidationError
from tests.helpers.report import report_verification

from arachne.report.model import (
    REPORT_SCHEMA_VERSION,
    ReportFinding,
    SeverityCounts,
    evidence_id,
    finding_id,
)


def test_ids_use_the_spec_formats() -> None:
    assert finding_id(42) == "F-000042"
    assert finding_id(1) == "F-000001"
    assert evidence_id(1) == "E-0001"
    assert evidence_id(1234) == "E-1234"


def test_severity_counts_total_and_rows() -> None:
    counts = SeverityCounts(critical=1, high=3, medium=7, low=12, info=5)
    assert counts.total == 28
    assert counts.as_rows() == (
        ("Critical", 1),
        ("High", 3),
        ("Medium", 7),
        ("Low", 12),
        ("Info", 5),
    )
    assert counts.for_severity("high") == 3
    assert counts.for_severity("unknown") == 0


def test_report_data_is_immutable(synthetic_report: object) -> None:
    report = synthetic_report
    with pytest.raises(ValidationError):
        report.scan_id = "scan_2"  # type: ignore[attr-defined]


def test_the_schema_version_is_carried_on_the_document() -> None:
    from arachne.report.json_render import load_report_schema

    schema = load_report_schema()
    assert schema["properties"]["schema_version"]["const"] == REPORT_SCHEMA_VERSION
    assert schema["$id"].endswith(f"report-{REPORT_SCHEMA_VERSION}.json")


def test_a_finding_requires_a_severity_from_the_vocabulary(tmp_path: object) -> None:
    from arachne.report.model import AssetRef, RemediationPlan, Score

    with pytest.raises(ValidationError):
        ReportFinding(
            id="F-000001",
            scan_id="scan_1",
            module="M4",
            check_id="m4.env-file-probe",
            title="x",
            asset=AssetRef(kind="url", value="https://example.test/"),
            severity="urgent",  # type: ignore[arg-type]
            score=Score(confidence=90),
            verification=report_verification(),
            remediation=RemediationPlan(id="x", summary="fix it"),
        )
