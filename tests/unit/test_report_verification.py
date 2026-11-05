"""The verification record in the report (WP-13, REQ-PROOF-015).

REQ-PROOF-015's acceptance criteria, one test each:

* report JSON validates against a schema version in which ``verification`` is **required**
  (and the shipped schema file is that version);
* a finding constructed without a record is downgraded to ``info`` and marked ``unverified``;
* Markdown, HTML, PDF and SARIF all surface the record (JSON does by construction, and is
  asserted here too, so all five are covered in one place).
"""

from __future__ import annotations

import json

import jsonschema
import pytest
from tests.helpers.report import (
    make_analysis,
    make_candidate,
    make_inputs,
    report_verification,
    synthetic_report,
)

from arachne.report import (
    load_report_schema,
    render_html,
    render_json,
    render_markdown,
    report_bytes,
)
from arachne.report.builder import build_report_data
from arachne.report.model import (
    REPORT_SCHEMA_VERSION,
    UNVERIFIED_REASON,
    AssetRef,
    RemediationPlan,
    ReportData,
    ReportFinding,
    Score,
)
from arachne.report.sarif import render_sarif


# --------------------------------------------------------------------------- the schema
def test_the_schema_version_requires_the_verification_record() -> None:
    """REQ-PROOF-015: ``verification`` is in the finding's ``required`` list."""
    schema = load_report_schema()
    # WP-21 moved the schema to 1.14 (the feed-freshness SLA fields, REQ-INTEL-006). The
    # verification requirement below is unchanged by that additive bump.
    assert REPORT_SCHEMA_VERSION == "1.14"
    finding = schema["$defs"]["ReportFinding"]
    assert "verification" in finding["required"], finding["required"]
    assert "$ref" in finding["properties"]["verification"]
    assert schema["properties"]["schema_version"]["const"] == "1.14"


def test_the_shipped_schema_file_is_the_current_version() -> None:
    from pathlib import Path

    root = Path(__file__).resolve().parents[2]
    path = (
        root
        / "src"
        / "arachne"
        / "templates"
        / "report"
        / f"report-schema-{REPORT_SCHEMA_VERSION}.json"
    )
    assert path.is_file(), f"{path.name} must be committed"
    document = json.loads(path.read_text(encoding="utf-8"))
    assert "verification" in document["$defs"]["ReportFinding"]["required"]


def test_every_rendered_finding_carries_a_record(synthetic_report: ReportData) -> None:
    document = json.loads(render_json(synthetic_report))
    assert document["findings"], "the fixture must have at least one finding"
    for finding in document["findings"]:
        assert finding["verification"]["status"] == "verified"
        assert finding["verification"]["level"]
    jsonschema.validate(document, load_report_schema())


# --------------------------------------------------------------------------- the downgrade
def test_a_finding_built_without_a_record_is_downgraded_and_marked_unverified() -> None:
    """The acceptance criterion, at the model: no record ⇒ ``info`` and ``unverified``."""
    finding = ReportFinding(
        id="F-000001",
        scan_id="scan_1",
        module="M3",
        check_id="m3.sqli-oracle",
        title="SQL injection",
        asset=AssetRef(kind="url", value="https://t.example/search?id=1"),
        severity="critical",
        score=Score(confidence=90),
        remediation=RemediationPlan(id="fix", summary="parameterise the query"),
    )
    assert finding.severity == "info", "a finding without a record may not claim a severity"
    assert finding.verification.status == "unverified"
    assert finding.verification.verified is False
    assert finding.verification.method == UNVERIFIED_REASON
    assert finding.verification_history == ()


def test_a_candidate_without_a_stored_record_is_downgraded_by_the_builder() -> None:
    """The same rule on the real path: a candidate with no record cannot score."""
    candidate = make_candidate(
        number=5, title="t", asset_value="https://t/x", with_verification=False
    )
    analysis = make_analysis(candidate, severity="high")
    from dataclasses import replace

    analysis = replace(analysis, severity="high")
    report = build_report_data(make_inputs(candidates=[candidate], analyses=[analysis]))
    assert report.findings, "the finding is still reported — as an observation"
    finding = report.findings[0]
    assert finding.severity == "info"
    assert finding.verification.status == "unverified"
    # The counts table agrees with the findings it summarises.
    assert report.executive_summary.counts.info >= 1
    assert report.executive_summary.counts.high == 0


def test_an_unverified_record_is_still_a_validation_error_for_a_bad_severity() -> None:
    """An invalid severity is refused, not silently rewritten by the downgrade rule."""
    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        ReportFinding(
            id="F-000001",
            scan_id="scan_1",
            module="M3",
            check_id="m3.x",
            title="t",
            asset=AssetRef(kind="url", value="https://t/x"),
            severity="urgent",  # type: ignore[arg-type]
            score=Score(confidence=10),
            remediation=RemediationPlan(id="fix", summary="s"),
        )


# --------------------------------------------------------------------------- five renderers
def _finding_with_history() -> ReportFinding:
    """A finding whose current record is a re-verification of an earlier one."""
    return ReportFinding(
        id="F-000009",
        scan_id="scan_1",
        module="M3",
        check_id="m3.sqli-oracle",
        check_version="1.0",
        title="SQL injection in 'id'",
        asset=AssetRef(kind="url", value="https://t.example/search?id=1"),
        severity="high",
        score=Score(confidence=90),
        remediation=RemediationPlan(id="fix", summary="parameterise the query"),
        verification=report_verification(),
        verification_history=(report_verification(),),
    )


@pytest.fixture
def report_with_record() -> ReportData:
    base = synthetic_report()
    findings = (_finding_with_history(), *base.findings[1:])
    return base.model_copy(update={"findings": findings})


def test_all_five_formats_surface_the_record(report_with_record: ReportData) -> None:
    markdown = render_markdown(report_with_record)
    assert "**Verification:**" in markdown
    assert "level L1 · verified" in markdown
    assert "reproducibility:" in markdown
    assert "observation:" in markdown

    html = render_html(report_with_record)
    assert "<h4>Verification</h4>" in html
    assert "reproducibility" in html
    assert "verified" in html

    # PDF renders the HTML above, so the record's text is in the PDF's own content stream.
    pdf = report_bytes(report_with_record, "pdf")
    assert b"Verification" in pdf
    assert b"reproducibility" in pdf

    document = json.loads(render_json(report_with_record))
    entry = next(item for item in document["findings"] if item["id"] == "F-000009")
    assert entry["verification"]["status"] == "verified"
    assert entry["verification"]["level"] == "L1"
    assert entry["verification"]["observations"]
    assert entry["verification_history"], "the per-finding history is in the document"

    sarif = json.loads(render_sarif(report_with_record))
    result = next(
        item
        for item in sarif["runs"][0]["results"]
        if item["properties"]["findingId"] == "F-000009"
    )
    assert result["properties"]["verification"]["status"] == "verified"
    assert result["properties"]["verification"]["level"] == "L1"
    assert "reproducibility" in result["properties"]["verification"]


def test_the_always_unverified_finding_renders_as_unverified_in_markdown() -> None:
    """A pre-WP-13 finding renders its reason, not a blank — and never a severity."""
    candidate = make_candidate(
        number=9, title="legacy", asset_value="https://t/x", with_verification=False
    )
    report = build_report_data(
        make_inputs(candidates=[candidate], analyses=[make_analysis(candidate)])
    )
    text = render_markdown(report)
    assert "**Verification:**" in text
    assert "unverified" in text
    assert UNVERIFIED_REASON in text


def test_the_record_survives_a_json_round_trip(report_with_record: ReportData) -> None:
    document = json.loads(render_json(report_with_record))
    restored = ReportData.model_validate(document)
    entry = next(item for item in restored.findings if item.id == "F-000009")
    assert entry.verification.verified
    assert entry.verification.reproducibility == report_verification().reproducibility
