"""Scan-to-scan diff: the four change kinds and the persisted payload (F-06-05)."""

from __future__ import annotations

from tests.helpers.report import report_verification

from arachne.report.diff import build_diff, diff_from_payload, diff_payload
from arachne.report.model import AssetRef, RemediationPlan, ReportFinding, Score


def finding(
    number: int,
    *,
    check: str,
    asset: str,
    severity: str,
    title: str = "Finding",
) -> ReportFinding:
    return ReportFinding(
        id=f"F-{number:06d}",
        scan_id="scan_1",
        module=check.split(".", 1)[0].upper(),
        check_id=check,
        title=title,
        asset=AssetRef(kind="url", value=asset),
        severity=severity,  # type: ignore[arg-type]
        score=Score(confidence=90),
        verification=report_verification(),
        remediation=RemediationPlan(id="x", summary="fix it"),
    )


def test_new_fixed_recurring_and_regressed() -> None:
    before = [
        finding(1, check="m4.env-file-probe", asset="https://t/.env", severity="high"),
        finding(2, check="m3.security-headers", asset="https://t/", severity="low"),
        finding(3, check="m4.backup-file-hunt", asset="https://t/db.bak", severity="medium"),
    ]
    after = [
        # still there, worse → regressed
        finding(1, check="m4.env-file-probe", asset="https://t/.env", severity="critical"),
        # still there, same → recurring
        finding(2, check="m3.security-headers", asset="https://t/", severity="low"),
        # gone → fixed
        # (finding 3 absent)
        # new
        finding(4, check="m4.dashboard-exposure", asset="https://t/admin", severity="high"),
    ]
    diff = build_diff(before, after, scan_a="scan_1", scan_b="scan_2")
    assert diff.new == ("m4.dashboard-exposure|https://t/admin",)
    assert diff.fixed == ("m4.backup-file-hunt|https://t/db.bak",)
    assert diff.regressed == ("m4.env-file-probe|https://t/.env",)
    assert diff.recurring == ("m3.security-headers|https://t/",)
    assert diff.counts == {
        "new": 1,
        "fixed": 1,
        "regressed": 1,
        "recurring": 1,
        "suppressed": 0,
    }


def test_a_severity_decrease_is_recurring_not_regressed() -> None:
    before = [finding(1, check="m4.env-file-probe", asset="https://t/.env", severity="high")]
    after = [finding(1, check="m4.env-file-probe", asset="https://t/.env", severity="medium")]
    diff = build_diff(before, after, scan_a="scan_1", scan_b="scan_2")
    assert diff.recurring == ("m4.env-file-probe|https://t/.env",)
    assert diff.regressed == ()


def test_severity_trend_counts_both_scans() -> None:
    before = [
        finding(1, check="a.x", asset="u1", severity="critical"),
        finding(2, check="a.y", asset="u2", severity="low"),
    ]
    after = [finding(3, check="a.z", asset="u3", severity="high")]
    diff = build_diff(before, after, scan_a="scan_1", scan_b="scan_2")
    assert diff.severity_trend["scan_1"] == {
        "critical": 1,
        "high": 0,
        "medium": 0,
        "low": 1,
        "info": 0,
    }
    assert diff.severity_trend["scan_2"]["high"] == 1


def test_the_payload_round_trips() -> None:
    before = [finding(1, check="m4.env-file-probe", asset="https://t/.env", severity="high")]
    diff = build_diff(before, [], scan_a="scan_1", scan_b="scan_2")
    payload = diff_payload(diff)
    assert payload["counts"]["fixed"] == 1
    restored = diff_from_payload(payload)
    assert restored == diff


def test_the_diff_is_order_independent() -> None:
    a = [
        finding(1, check="m4.env-file-probe", asset="https://t/.env", severity="high"),
        finding(2, check="m3.security-headers", asset="https://t/", severity="low"),
    ]
    b = list(reversed(a))
    forward = build_diff(a, b, scan_a="scan_1", scan_b="scan_2")
    backward = build_diff(b, a, scan_a="scan_1", scan_b="scan_2")
    assert forward.recurring == backward.recurring
    assert forward.severity_trend == backward.severity_trend
