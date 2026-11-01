"""The pure CI delivery-surface emitters (S26, REQ-ECOS-003).

:mod:`arachne.ecos.ci_gate` is the review half of the gate: it turns findings into GitHub
workflow-command annotations and GitLab Code Quality rows. Because it is pure — no DB, no
network, no clock — every output is pinned byte-for-byte here: the exact annotation line
(including ``file``/``line``/``col``), the threshold filter, the cap and its ordering, the
GitLab JSON and the stability of its fingerprint. The SARIF path is asserted to be the
report package's single emitter, not a second one.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime

from arachne.cli.ci import gate_summary
from arachne.ecos.ci_gate import (
    GateFinding,
    annotation_lines,
    code_quality_issues,
    findings_from_report,
    fingerprint,
    render_github_annotations,
    render_gitlab_code_quality,
    sarif_report,
    severity_counts,
    summary,
)
from arachne.report.model import (
    AssetRef,
    ExecutiveSummary,
    RemediationPlan,
    ReportCover,
    ReportData,
    ReportFinding,
    ScopeMethodology,
    Score,
)
from arachne.report.sarif import render_sarif


def _finding(
    *,
    severity: str = "high",
    path: str = "main.tf",
    line: int = 1,
    column: int = 1,
    check_id: str = "m5.tfstate-exposure@1.1",
    title: str = "IaC misconfiguration: CIDR open to the world",
    description: str = "",
) -> GateFinding:
    return GateFinding(
        check_id=check_id,
        title=title,
        severity=severity,
        path=path,
        line=line,
        column=column,
        description=description,
    )


def _report() -> ReportData:
    finding = ReportFinding(
        id="F-000001",
        scan_id="1",
        module="M5",
        check_id="m5.tfstate-exposure",
        title="open security group",
        asset=AssetRef(kind="cloud", value="main.tf"),
        severity="high",
        score=Score(confidence=70),
        description="the security group allows 0.0.0.0/0",
        remediation=RemediationPlan(id="REM-1", summary="restrict the CIDR"),
    )
    return ReportData(
        scan_id="1",
        target_name="iac:fixture",
        cover=ReportCover(
            title="ARACHNE report",
            target="iac:fixture",
            scan_id="1",
            generated_at=datetime(2026, 1, 1, tzinfo=UTC),
        ),
        executive_summary=ExecutiveSummary(),
        scope=ScopeMethodology(target_name="iac:fixture"),
        findings=(finding,),
    )


# ------------------------------------------------------------------ GitHub annotations
def test_annotations_are_exact_workflow_commands_worst_first() -> None:
    findings = [
        _finding(),
        _finding(
            path=".github/workflows/ci.yml",
            check_id="M5/cicd-audit@1.0",
            title="CI/CD risk in .github/workflows/ci.yml: untrusted PR trigger with secrets",
        ),
    ]
    assert annotation_lines(findings) == (
        "::error file=.github/workflows/ci.yml,line=1,col=1::"
        "CI/CD risk in .github/workflows/ci.yml: untrusted PR trigger with secrets",
        "::error file=main.tf,line=1,col=1::IaC misconfiguration: CIDR open to the world",
    )
    # The rendered stream is one newline-terminated line per finding.
    assert render_github_annotations(findings).count("\n") == 2


def test_annotations_carry_the_line_and_column() -> None:
    assert annotation_lines([_finding(path="infra/main.tf", line=42, column=7)]) == (
        "::error file=infra/main.tf,line=42,col=7::IaC misconfiguration: CIDR open to the world",
    )


def test_annotations_filter_at_or_above_the_threshold() -> None:
    findings = [
        _finding(severity="info", path="a", title="info"),
        _finding(severity="low", path="b", title="low"),
        _finding(severity="medium", path="c", title="medium"),
        _finding(severity="high", path="d", title="high"),
        _finding(severity="critical", path="e", title="critical"),
    ]
    default = annotation_lines(findings)
    assert len(default) == 2  # high + critical only
    assert all(item.startswith("::error ") for item in default)
    medium = annotation_lines(findings, severity_threshold="medium")
    assert len(medium) == 3
    assert medium[2].startswith("::warning ")
    low = annotation_lines(findings, severity_threshold="low")
    assert len(low) == 4
    assert low[-1].startswith("::notice ")  # low maps to notice
    info = annotation_lines(findings, severity_threshold="info")
    assert len(info) == 5
    assert info[-1].startswith("::notice ")  # info maps to notice
    # "none" disables the filter entirely rather than hiding everything.
    assert len(annotation_lines(findings, severity_threshold="none")) == 5


def test_annotations_are_capped_worst_first() -> None:
    findings = [
        _finding(severity="medium", path="m", title="medium"),
        _finding(severity="critical", path="c", title="critical"),
        _finding(severity="high", path="h", title="high"),
    ]
    capped = annotation_lines(findings, severity_threshold="info", max_annotations=2)
    assert len(capped) == 2
    assert "critical" in capped[0]
    assert "high" in capped[1]
    assert annotation_lines(findings, severity_threshold="info", max_annotations=0) == ()


def test_annotation_message_and_properties_are_escaped() -> None:
    finding = _finding(path="dir:name,other%.tf", title="line1\nline2", severity="high")
    (line,) = annotation_lines([finding])
    assert "file=dir%3Aname%2Cother%25.tf" in line
    assert line.endswith("::line1%0Aline2")


# ------------------------------------------------------------------ GitLab Code Quality
def test_gitlab_code_quality_rows_are_exact() -> None:
    finding = _finding(
        severity="critical", path=".github/workflows/ci.yml", check_id="M5/cicd-audit@1.0"
    )
    expected_fingerprint = hashlib.sha256(
        b"17:M5/cicd-audit@1.0:.github/workflows/ci.yml"
    ).hexdigest()
    assert code_quality_issues([finding]) == [
        {
            "description": "IaC misconfiguration: CIDR open to the world",
            "check_name": "M5/cicd-audit@1.0",
            "fingerprint": expected_fingerprint,
            "severity": "blocker",
            "location": {"path": ".github/workflows/ci.yml", "lines": {"begin": 1}},
        }
    ]
    rendered = render_gitlab_code_quality([finding])
    assert json.loads(rendered) == code_quality_issues([finding])
    assert rendered.endswith("\n")


def test_gitlab_severity_uses_gitlab_vocabulary() -> None:
    severities = {
        item.severity: code_quality_issues([item])[0]["severity"]
        for item in (
            _finding(severity="info"),
            _finding(severity="low"),
            _finding(severity="medium"),
            _finding(severity="high"),
            _finding(severity="critical"),
        )
    }
    assert severities == {
        "info": "info",
        "low": "minor",
        "medium": "major",
        "high": "critical",
        "critical": "blocker",
    }


def test_gitlab_fingerprint_is_stable_and_identity_bound() -> None:
    first = fingerprint("M5/tfstate-exposure@1.1", "main.tf")
    assert first == fingerprint("M5/tfstate-exposure@1.1", "main.tf")
    assert len(first) == 64
    # A different check or a different asset is a different issue.
    assert fingerprint("M5/cicd-audit@1.0", "main.tf") != first
    assert fingerprint("M5/tfstate-exposure@1.1", "other.tf") != first
    # The length prefix keeps the two parts unambiguous: no pair of inputs concatenates to
    # the same bytes as another pair.
    assert fingerprint("a:b", "c") != fingerprint("a", "b:c")


def test_gitlab_report_is_ordered_worst_first() -> None:
    rendered = json.loads(
        render_gitlab_code_quality(
            [_finding(severity="low", path="a"), _finding(severity="critical", path="b")]
        )
    )
    assert [row["location"]["path"] for row in rendered] == ["b", "a"]


# ------------------------------------------------------------------ policy reuse
def test_summary_and_counts_reuse_the_cli_policy() -> None:
    findings = [_finding(severity="high"), _finding(severity="high", path="b")]
    counts = severity_counts(findings)
    assert counts == {"info": 0, "low": 0, "medium": 0, "high": 2, "critical": 0}
    assert summary(counts, "high") == gate_summary(counts, "high")
    assert summary(counts, "high")["exit_code"] == 2
    assert summary(counts, "critical")["exit_code"] == 1


# ------------------------------------------------------------------ SARIF passthrough
def test_sarif_is_delegated_to_the_report_emitter() -> None:
    report = _report()
    assert sarif_report(report) == render_sarif(report)
    document = json.loads(sarif_report(report))
    assert document["version"] == "2.1.0"
    assert document["runs"][0]["results"][0]["ruleId"] == "m5.tfstate-exposure"


def test_findings_from_report_anchors_on_the_asset() -> None:
    findings = findings_from_report(_report())
    assert len(findings) == 1
    assert findings[0].check_id == "m5.tfstate-exposure"
    assert findings[0].path == "main.tf"
    assert findings[0].severity == "high"
    assert findings[0].line == 1
    assert annotation_lines(findings)[0].startswith("::error file=main.tf,line=1,col=1::")
