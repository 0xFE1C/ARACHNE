"""Diff and trend rendering (F-06-05, docs/spec/06- §7; S11 completes the S8 skeleton)."""

from __future__ import annotations

from types import SimpleNamespace

from arachne.report.diff import build_diff, diff_payload
from arachne.report.markdown import _diff_section, _severity_trend, _webshell_line
from arachne.report.model import AssetRef, RemediationPlan, ReportDiff, ReportFinding, Score


def _finding(number: int, *, check: str, asset: str, severity: str) -> ReportFinding:
    return ReportFinding(
        id=f"F-{number:06d}",
        scan_id="scan_1",
        module=check.split(".", 1)[0].upper(),
        check_id=check,
        title="Finding",
        asset=AssetRef(kind="url", value=asset),
        severity=severity,  # type: ignore[arg-type]
        score=Score(confidence=90),
        remediation=RemediationPlan(id="x", summary="fix it"),
    )


def test_the_diff_section_renders_a_severity_trend_table() -> None:
    before = [
        _finding(1, check="m6.webshell-yara", asset="repo:/w", severity="medium"),
        _finding(2, check="m6.ci-secret-leak", asset="repo:/w", severity="high"),
    ]
    after = [
        _finding(3, check="m6.webshell-yara", asset="repo:/w", severity="critical"),
        _finding(4, check="m6.secret-scan-at-scale", asset="repo:/w", severity="high"),
    ]
    diff = build_diff(before, after, scan_a="scan_1", scan_b="scan_2")
    lines = _diff_section(SimpleNamespace(diff=diff))
    text = "\n".join(lines)
    assert "Change since scan scan_1" in text
    assert "1 new" in text and "1 fixed" in text and "1 regressed" in text
    assert "| Severity | scan_1 | scan_2 |" in text
    assert "consecutive scan(s)" in text


def test_the_diff_section_is_absent_without_a_diff() -> None:
    assert _diff_section(SimpleNamespace(diff=None)) == []


def test_a_single_scan_trend_has_no_table() -> None:
    assert _severity_trend({"scan_1": {"critical": 0}}) == []


def test_the_trend_table_lists_every_severity() -> None:
    lines = _severity_trend(
        {
            "scan_1": {"critical": 1, "high": 2, "medium": 0, "low": 0, "info": 1},
            "scan_2": {"critical": 0, "high": 1, "medium": 3, "low": 0, "info": 0},
        }
    )
    text = "\n".join(lines)
    for severity in ("critical", "high", "medium", "low", "info"):
        assert f"| {severity} |" in text
    assert "| critical | 1 | 0 |" in text


def test_the_patch_gap_webshell_line_distinguishes_ran_from_not_run() -> None:
    assert _webshell_line(None) == "not run"
    assert _webshell_line({"findings": 0}) == "0 finding(s)"
    assert _webshell_line({"findings": 2}) == "2 finding(s)"


def test_the_diff_payload_carries_the_counts() -> None:
    diff = ReportDiff(scan_a="scan_1", scan_b="scan_2", new=("a|b",))
    payload = diff_payload(diff)
    assert payload["counts"]["new"] == 1
    assert payload["scan_b"] == "scan_2"
