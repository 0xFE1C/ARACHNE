"""Markdown and JSON renderers: the §9 skeleton, determinism and schema validity."""

from __future__ import annotations

import json

import jsonschema
import pytest
from tests.helpers.report import report_verification

from arachne.core.errors import ReportError
from arachne.report import (
    load_report_schema,
    media_type,
    render_json,
    render_markdown,
    render_report,
    report_bytes,
)
from arachne.report.model import (
    AssetRef,
    RemediationPlan,
    ReportFinding,
    Score,
)


def test_markdown_has_every_section_of_the_sample_skeleton(synthetic_report: object) -> None:
    text = render_markdown(synthetic_report)
    headings = [
        "# Security Assessment Report — target.example",
        "## 1. Executive summary",
        "## 2. Scope & methodology",
        "## 3. Asset inventory",
        "## 4. Findings — Critical",
        "## 5. Findings — High",
        "## 6. Findings — Medium",
        "## 7. Findings — Low",
        "## 8. Findings — Info",
        "## 10. Low-confidence observations",
        "## 11. Patch-gap & exposure (M6)",
        "## 12. Appendix",
        "### A. Evidence payloads (redacted)",
        "### B. Audit log summary",
        "### C. Out-of-scope events",
        "### D. False positives",
        "### E. Glossary",
    ]
    for heading in headings:
        assert heading in text, heading


def test_findings_are_grouped_by_severity(synthetic_report: object) -> None:
    text = render_markdown(synthetic_report)
    critical_heading = text.index("## 4. Findings — Critical")
    high_heading = text.index("## 5. Findings — High")
    critical_body = text[critical_heading:high_heading]
    assert "F-000002" in critical_body  # the critical finding
    assert "F-000001" not in critical_body
    high_body = text[high_heading : text.index("## 6. Findings — Medium")]
    assert "F-000001" in high_body


def test_the_cover_carries_scan_attestation_and_versions(synthetic_report: object) -> None:
    text = render_markdown(synthetic_report)
    assert "Scan: scan_1 · 2026-10-27" in text
    assert "ARACHNE 0.1.0" in text
    assert "engine: heuristic" in text
    assert "attested by felix@corp" in text
    assert "expires 2026-11-30T00:00:00+00:00" in text


def test_each_finding_block_has_evidence_remediation_and_provenance(
    synthetic_report: object,
) -> None:
    text = render_markdown(synthetic_report)
    findings_start = text.index("## 4.")
    for finding in synthetic_report.findings:
        start = text.index(finding.id, findings_start)
        end = text.find("\n### ", start + 1)
        section_end = text.find("\n## ", start + 1)
        candidates = [value for value in (end, section_end) if value != -1]
        block = text[start : min(candidates) if candidates else len(text)]
        for expected in (
            "**Description:**",
            "**Evidence:**",
            "**Remediation:**",
            "**Verification of fix:**",
            "**Provenance:**",
            "Classification:",
        ):
            assert expected in block, (finding.id, expected)
        for ref in finding.evidence_refs:
            assert ref in block, (finding.id, ref)


def test_low_confidence_findings_are_only_in_their_own_section(
    synthetic_report: object,
) -> None:
    text = render_markdown(synthetic_report)
    low = synthetic_report.low_confidence[0]
    findings_text = text[text.index("## 4.") : text.index("## 9.")]
    assert low.id not in findings_text
    low_text = text[text.index("## 10.") : text.index("## 11.")]
    assert low.id in low_text


def test_markdown_and_json_are_byte_for_byte_deterministic(
    synthetic_report: object,
) -> None:
    assert render_markdown(synthetic_report) == render_markdown(synthetic_report)
    assert render_json(synthetic_report) == render_json(synthetic_report)


def test_json_validates_against_the_versioned_schema(synthetic_report: object) -> None:
    schema = load_report_schema()
    jsonschema.validate(json.loads(render_json(synthetic_report)), schema)


def test_json_is_the_full_dto(synthetic_report: object) -> None:
    from arachne.report.model import REPORT_SCHEMA_VERSION

    document = json.loads(render_json(synthetic_report))
    assert document["schema_version"] == REPORT_SCHEMA_VERSION
    assert document["scan_id"] == "scan_1"
    assert len(document["findings"]) == len(synthetic_report.findings)
    assert document["executive_summary"]["counts"]["high"] == 1
    assert document["appendix"]["evidence"]
    finding = document["findings"][0]
    for key in (
        "id",
        "scan_id",
        "module",
        "check_id",
        "title",
        "asset",
        "severity",
        "score",
        "classification",
        "description",
        "evidence_refs",
        "remediation",
        "status",
        "provenance",
        "timestamps",
        # WP-13 (REQ-PROOF-015): required on every finding, so it is part of the contract.
        "verification",
    ):
        assert key in finding, key


def test_a_table_breaking_title_is_escaped() -> None:
    finding = ReportFinding(
        id="F-000001",
        scan_id="scan_1",
        module="M4",
        check_id="m4.env-file-probe",
        title="pipes | and\nnewlines",
        asset=AssetRef(kind="url", value="https://t.example/"),
        severity="high",
        score=Score(confidence=90),
        verification=report_verification(),
        remediation=RemediationPlan(id="x", summary="fix it"),
    )
    from datetime import UTC, datetime

    from arachne.report.model import (
        Appendix,
        ExecutiveSummary,
        ReportCover,
        ReportData,
        ScopeMethodology,
    )

    report = ReportData(
        scan_id="scan_1",
        target_name="t",
        cover=ReportCover(
            title="Security Assessment Report — t",
            target="t",
            scan_id="scan_1",
            generated_at=datetime(2026, 10, 27, tzinfo=UTC),
        ),
        executive_summary=ExecutiveSummary(),
        scope=ScopeMethodology(target_name="t"),
        findings=(finding,),
        appendix=Appendix(),
    )
    text = render_markdown(report)
    assert "pipes \\| and newlines" in text


def test_a_body_cannot_close_its_code_fence() -> None:
    """A target-controlled body containing ``` must not write Markdown into the report."""
    from datetime import UTC, datetime

    from arachne.report.model import (
        Appendix,
        ExecutiveSummary,
        ReportCover,
        ReportData,
        ReportEvidence,
        ScopeMethodology,
    )

    body = "ok\n```\n# injected heading\n```\n"
    evidence = ReportEvidence(
        id="E-0001",
        kind="http_response",
        summary="HTTP 200",
        payload={"status_code": 200, "body": body},
    )
    report = ReportData(
        scan_id="scan_1",
        target_name="t",
        cover=ReportCover(
            title="Security Assessment Report — t",
            target="t",
            scan_id="scan_1",
            generated_at=datetime(2026, 10, 27, tzinfo=UTC),
        ),
        executive_summary=ExecutiveSummary(),
        scope=ScopeMethodology(target_name="t"),
        appendix=Appendix(evidence=(evidence,)),
    )
    text = render_markdown(report)
    assert "````" in text  # the fence grew past the body's own backtick run


def test_an_unknown_format_is_a_clean_error(synthetic_report: object) -> None:
    with pytest.raises(ReportError, match="unknown report format"):
        render_report(synthetic_report, "docx")  # type: ignore[arg-type]


def test_pdf_is_a_binary_format_served_by_report_bytes(synthetic_report: object) -> None:
    """`pdf` became a real format in S13; the text facade points at the bytes one (F-06-02)."""
    with pytest.raises(ReportError, match="binary"):
        render_report(synthetic_report, "pdf")
    data = report_bytes(synthetic_report, "pdf")  # type: ignore[arg-type]
    assert data.startswith(b"%PDF-1.4")
    assert media_type("pdf") == "application/pdf"


def test_a_report_with_a_diff_still_validates_and_renders_the_trend(
    synthetic_report: object,
) -> None:
    import json

    import jsonschema

    from arachne.report import build_diff

    report = synthetic_report
    diff = build_diff(report.findings[:1], report.findings, scan_a="scan_1", scan_b="scan_2")
    with_diff = report.model_copy(update={"diff": diff})
    jsonschema.validate(json.loads(render_json(with_diff)), load_report_schema())
    text = render_markdown(with_diff)
    assert "### Change since scan scan_1" in text
    assert "new ·" in text
