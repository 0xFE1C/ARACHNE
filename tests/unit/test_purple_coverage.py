"""Control-coverage scoring and the campaign trend (S24, REQ-VALID-002/006).

The scoring rule is the part of this area that can flatter itself most easily, so it is
pinned from both directions: what *counts* as seen (this run's nonce, inside the window, a
matching technique) and what deliberately does **not** (a technique-named alert with no
nonce, an alert outside the window, an alert naming no technique — each counted, each
reported, none of them coverage).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from arachne.core.target import DetectionWindow
from arachne.purple.alerts import DefenderAlert
from arachne.purple.coverage import (
    CoveragePoint,
    Emission,
    coverage_points,
    detect_regressions,
    emissions_from_payloads,
    score_coverage,
)

START = datetime(2026, 10, 31, 12, 0, tzinfo=UTC)
END = START + timedelta(hours=1)
NONCE = "abcdef0123456789abcdef01"
OTHER = "ffffffffffffffffffffffff"


def _window() -> DetectionWindow:
    return DetectionWindow(starts_at=START, ends_at=END, coordinator="soc")


def _emission(technique: str, tactic: str, when: datetime | None = None) -> Emission:
    return Emission(
        check_id="m3.cmdi-oob",
        title="Out-of-band command injection",
        technique=technique,
        tactic=tactic,
        severity="high",
        nonce=NONCE,
        emitted_at=when or (START + timedelta(minutes=5)),
    )


def _alert(
    alert_id: str,
    *,
    technique: str | None,
    nonce: str | None = NONCE,
    when: datetime | None = None,
) -> DefenderAlert:
    return DefenderAlert(
        alert_id=alert_id,
        source="siem",
        observed_at=when or (START + timedelta(minutes=10)),
        title=f"alert {alert_id}",
        technique=technique,
        nonce=nonce,
    )


def test_coverage_counts_only_alerts_linked_to_this_run() -> None:
    emissions = (
        _emission("T1190", "initial-access"),
        _emission("T1059", "execution"),
        _emission("T1565.001", "impact"),
    )
    alerts = (
        _alert("A1", technique="T1190"),  # linked
        _alert("A2", technique="T1059", nonce=None),  # right technique, no nonce
        _alert("A3", technique="T1565.001", nonce=OTHER),  # another run's nonce
        _alert("A4", technique=None),  # no technique at all
        _alert("A5", technique="T1190", when=END + timedelta(minutes=5)),  # out of window
    )
    report = score_coverage(
        emissions, alerts, campaign="camp", nonce=NONCE, window=_window(), now=START
    )

    by_technique = {item.technique: item for item in report.techniques}
    assert by_technique["T1190"].seen is True
    assert by_technique["T1190"].alert_ids == ("A1",)
    assert by_technique["T1059"].seen is False
    assert by_technique["T1059"].unlinked_alert_ids == ("A2",)
    assert by_technique["T1565.001"].seen is False
    assert {item.technique for item in report.gaps} == {"T1059", "T1565.001"}
    assert report.seen_count == 1 and report.total == 3
    assert report.coverage_pct == 33.3
    assert report.alerts_out_of_window == 1
    assert report.alerts_without_technique == 1
    assert report.alerts_other_run == 1
    assert any("outside the coordinated window" in note for note in report.notes)


def test_coverage_is_reported_per_tactic_and_the_percentage_is_honest() -> None:
    emissions = (
        _emission("T1190", "initial-access"),
        _emission("T1190", "initial-access"),
        _emission("T1059", "execution"),
    )
    alerts = (_alert("A1", technique="T1190"),)
    report = score_coverage(
        emissions, alerts, campaign="camp", nonce=NONCE, window=_window(), now=START
    )
    tactics = {item.tactic: item for item in report.tactics}
    assert tactics["initial-access"].total == 1, "one technique, however many emissions"
    assert tactics["initial-access"].coverage_pct == 100.0
    assert tactics["execution"].coverage_pct == 0.0
    assert tactics["initial-access"].label == "Initial Access"
    assert report.coverage_pct == 50.0


def test_a_tactic_nothing_tested_is_not_a_gap() -> None:
    """ "0% of nothing" would drag the estate number down for a decision nobody made."""
    report = score_coverage(
        (_emission("T1059", "execution"),),
        (),
        campaign="camp",
        nonce=NONCE,
        window=_window(),
        now=START,
    )
    assert [item.tactic for item in report.tactics] == ["execution"]
    assert report.coverage_pct == 0.0


def test_a_parent_alert_sees_a_sub_technique_emission_and_vice_versa() -> None:
    emissions = (_emission("T1059.004", "execution"), _emission("T1190", "initial-access"))
    alerts = (_alert("A1", technique="T1059"), _alert("A2", technique="T1190.001"))
    report = score_coverage(
        emissions, alerts, campaign="camp", nonce=NONCE, window=_window(), now=START
    )
    assert report.seen_count == 2
    assert report.coverage_pct == 100.0


def test_an_alert_for_an_unemitted_technique_is_counted_but_is_not_coverage() -> None:
    """The defender's other traffic: the SIEM fired, just not for our test."""
    report = score_coverage(
        (_emission("T1059", "execution"),),
        (_alert("A1", technique="T1486"),),
        campaign="camp",
        nonce=NONCE,
        window=_window(),
        now=START,
    )
    assert report.seen_count == 0
    assert report.alerts_linked == 0
    assert report.alerts_other_technique == 1
    assert report.other_techniques == ("T1486",)
    assert any("did not emit" in note for note in report.notes)
    assert report.to_dict()["alerts"]["other_technique"] == 1


def test_the_report_round_trips_through_json_ready_payloads() -> None:
    emissions = (_emission("T1190", "initial-access"),)
    report = score_coverage(
        emissions,
        (_alert("A1", technique="T1190"),),
        campaign="camp",
        nonce=NONCE,
        window=_window(),
        now=START,
    )
    document = report.to_dict()
    assert document["coverage_pct"] == 100.0
    assert document["tactics"][0]["label"] == "Initial Access"
    assert document["gaps"] == []
    assert document["window"]["coordinator"] == "soc"
    rebuilt = emissions_from_payloads(
        [
            {
                "check_id": "m3.cmdi-oob",
                "title": "t",
                "technique": "t1190",
                "tactic": "initial-access",
                "severity": "high",
                "nonce": NONCE,
                "emitted_at": START.isoformat(),
            }
        ]
    )
    assert rebuilt[0].technique == "T1190"


def test_the_trend_reads_back_oldest_first_and_flags_only_real_regressions() -> None:
    payloads = [
        {
            "run_id": 2,
            "started_at": (START + timedelta(hours=2)).isoformat(),
            "coverage": {
                "coverage_pct": 33.0,
                "seen_ids": ["T1059"],
                "technique_ids": ["T1190", "T1059", "T1565.001"],
                "gap_ids": ["T1190", "T1565.001"],
            },
        },
        {
            "run_id": 1,
            "started_at": START.isoformat(),
            "coverage": {
                "coverage_pct": 66.0,
                "seen_ids": ["T1190", "T1059"],
                "technique_ids": ["T1190", "T1059", "T1565.001"],
                "gap_ids": ["T1565.001"],
            },
        },
    ]
    points = coverage_points(payloads)
    assert [point.run_id for point in points] == [1, 2]
    assert detect_regressions(points[0], points[1]) == ("T1190",)
    # A technique that was never seen cannot regress, and one newly seen is an improvement.
    assert detect_regressions(None, points[0]) == ()
    assert detect_regressions(points[1], points[0]) == ()
    assert points[1].unseen_count == 2
    assert isinstance(points[0], CoveragePoint)
