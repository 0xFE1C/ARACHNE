"""The quality workflow's pure parts and its store (S21, area QUAL).

Four requirements, four properties that can be checked without a scan:

* a suppression needs a reason, is attributed and takes the next version (REQ-QUAL-001/002);
* an acceptance needs an owner, a justification and an expiry, and an expired one re-opens its
  finding on an injected clock (REQ-QUAL-003);
* the diff respects suppressions and states the count rather than hiding it (REQ-QUAL-002);
* FP-rate trends are computed per key over a synthetic history, with a rising one alerting
  (REQ-QUAL-004).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from arachne.analyzer.fp import FeedbackEvent, compute_trends, rising_alerts
from arachne.core.audit import Auditor, MemoryAuditSink
from arachne.data.models import Base
from arachne.data.quality_store import MemoryQualityStore, SqlQualityStore
from arachne.quality.acceptance import (
    AcceptanceSet,
    RiskAcceptance,
    active_at,
    reopen_expired,
)
from arachne.quality.suppressions import Suppression, SuppressionSet
from arachne.report.diff import build_diff, diff_payload, suppression_summary
from arachne.report.model import AssetRef, RemediationPlan, ReportFinding, Score

NOW = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)


def _finding(
    number: int,
    *,
    check_id: str = "m3.xss-oracle",
    asset: str = "https://app.example/search",
    severity: str = "medium",
) -> ReportFinding:
    return ReportFinding(
        id=f"F-{number:06d}",
        scan_id="scan_2",
        module="M3",
        check_id=check_id,
        title=f"finding {number}",
        asset=AssetRef(kind="url", value=asset),
        severity=severity,  # type: ignore[arg-type]
        score=Score(confidence=80),
        remediation=RemediationPlan(id="fix-it", summary="fix it"),
    )


# --------------------------------------------------------------------------- suppressions


def test_a_suppression_needs_a_reason_and_is_attributed() -> None:
    with pytest.raises(ValueError, match="at least 8 characters"):
        Suppression(kind="rule", check_id="m3.xss-oracle", reason="fp")
    rule = Suppression(
        kind="rule", check_id="m3.xss-oracle", reason="hardened at the WAF", actor="alice"
    )
    assert rule.actor == "alice"
    assert rule.active
    assert rule.matches(check_id="m3.xss-oracle", asset="https://app.example/search")
    assert not rule.matches(check_id="m3.sqli-oracle", asset="https://app.example/search")


def test_the_three_selector_kinds_match_what_they_say() -> None:
    pattern = Suppression(
        kind="pattern",
        check_id="m3.xss-oracle",
        asset_pattern="https://app.example/*",
        reason="reflected input is escaped by the front end",
    )
    assert pattern.matches(check_id="m3.xss-oracle", asset="https://app.example/search")
    assert not pattern.matches(check_id="m3.xss-oracle", asset="https://other.example/")

    single = Suppression(kind="finding", finding_id=42, reason="this instance is a test fixture")
    assert single.matches(check_id="m3.xss-oracle", asset="https://x/", finding_id=42)
    assert not single.matches(check_id="m3.xss-oracle", asset="https://x/", finding_id=7)


def test_an_expired_or_revoked_suppression_stops_applying() -> None:
    expired = Suppression(
        kind="rule",
        check_id="m3.xss-oracle",
        reason="temporary exemption during the migration",
        expires_at=datetime.now(UTC) - timedelta(days=1),
    )
    assert not expired.matches(check_id="m3.xss-oracle", asset="https://x/")
    revoked = expired.model_copy(update={"expires_at": None, "active": False})
    assert not revoked.matches(check_id="m3.xss-oracle", asset="https://x/")


def test_the_rule_set_is_versioned_and_ordered_most_specific_first() -> None:
    rules = SuppressionSet.of(
        [
            Suppression(
                id=1,
                version=1,
                kind="rule",
                check_id="m3.xss-oracle",
                reason="hardened at the WAF",
            ),
            Suppression(
                id=2,
                version=2,
                kind="pattern",
                check_id="m3.xss-oracle",
                asset_pattern="https://app.example/*",
                reason="escaped by the front end",
            ),
        ]
    )
    assert rules.version == 2
    assert rules.match(check_id="m3.xss-oracle", asset="https://app.example/x").id == 2
    assert rules.match(check_id="m3.xss-oracle", asset="https://other.example/").id == 1
    assert rules.describe()["kinds"] == {"finding": 0, "rule": 1, "pattern": 1}


def test_the_store_takes_a_monotonic_version_and_audits_every_change() -> None:
    sink = MemoryAuditSink()
    store = MemoryQualityStore(auditor=Auditor(sink, actor="pytest"))
    first = store.add_suppression(
        Suppression(kind="rule", check_id="m3.xss-oracle", reason="hardened at the WAF")
    )
    second = store.add_suppression(
        Suppression(kind="rule", check_id="m3.sqli-oracle", reason="input is parameterised")
    )
    assert (first.version, second.version) == (1, 2)
    assert store.suppression_version() == 2
    revoked = store.revoke_suppression(first.id or 0, actor="bob")
    assert revoked is not None and not revoked.active
    assert len(store.list_suppressions()) == 1
    assert all(event.action.value == "suppression.changed" for event in sink.events)


def test_the_sql_store_round_trips_a_suppression(tmp_path) -> None:
    factory = _factory(tmp_path)
    store = SqlQualityStore(factory)
    stored = store.add_suppression(
        Suppression(
            kind="pattern",
            check_id="m3.xss-oracle",
            asset_pattern="https://a/*",
            reason="escaped upstream",
            actor="alice",
        )
    )
    assert stored.id is not None and stored.version == 1
    again = store.list_suppressions()
    assert len(again) == 1 and again[0].reason == "escaped upstream"
    assert store.active_suppressions().covers(check_id="m3.xss-oracle", asset="https://a/b")
    revoked = store.revoke_suppression(stored.id or 0, actor="bob")
    assert revoked is not None and not revoked.active
    assert store.list_suppressions() == ()


# --------------------------------------------------------------------------- acceptances


def test_an_acceptance_needs_an_owner_a_reason_and_an_expiry() -> None:
    with pytest.raises(ValueError, match="justification"):
        RiskAcceptance(
            finding_id=1,
            owner="bob",
            justification="ok",
            accepted_at=NOW,
            expires_at=NOW + timedelta(days=1),
        )
    with pytest.raises(ValueError, match="expire after"):
        RiskAcceptance(
            finding_id=1,
            owner="bob",
            justification="compensating control in place",
            accepted_at=NOW,
            expires_at=NOW,
        )


def test_an_expired_acceptance_reopens_its_finding_on_the_injected_clock() -> None:
    acceptance = RiskAcceptance(
        id=7,
        finding_id=42,
        owner="bob",
        justification="mitigated by the network control",
        accepted_at=NOW - timedelta(days=30),
        expires_at=NOW - timedelta(days=1),
    )
    assert not active_at(acceptance, NOW)
    assert active_at(acceptance, NOW - timedelta(days=2))
    decisions = reopen_expired([acceptance], moment=NOW)
    assert len(decisions) == 1
    assert decisions[0].finding_id == 42 and decisions[0].acceptance_id == 7
    # The clock is honoured: before the expiry nothing re-opens.
    assert reopen_expired([acceptance], moment=NOW - timedelta(days=2)) == ()
    # And an already-reopened or withdrawn acceptance is not reopened twice.
    reopened = acceptance.model_copy(update={"reopened_at": NOW})
    assert reopen_expired([reopened], moment=NOW) == ()
    withdrawn = acceptance.model_copy(update={"revoked_at": NOW - timedelta(days=3)})
    assert reopen_expired([withdrawn], moment=NOW) == ()


def test_a_rule_wide_acceptance_produces_no_single_finding_decision() -> None:
    acceptance = RiskAcceptance(
        finding_id=None,
        check_id="m3.xss-oracle",
        owner="bob",
        justification="accepted for the whole estate until the WAF lands",
        accepted_at=NOW - timedelta(days=30),
        expires_at=NOW - timedelta(days=1),
    )
    assert reopen_expired([acceptance], moment=NOW) == ()


def test_the_acceptance_set_covers_by_finding_or_by_check() -> None:
    acceptance = RiskAcceptance(
        finding_id=8,
        owner="bob",
        justification="compensating control in place",
        accepted_at=NOW,
        expires_at=NOW + timedelta(days=10),
    )
    active = AcceptanceSet.of([acceptance], moment=NOW)
    assert active.covers(check_id="m3.xss-oracle", asset="https://x/", finding_id=8)
    assert not active.covers(check_id="m3.xss-oracle", asset="https://x/", finding_id=9)
    assert len(AcceptanceSet.of([acceptance], moment=NOW + timedelta(days=11))) == 0


def test_the_sql_store_reopens_the_finding_it_accepted(tmp_path) -> None:
    factory = _factory(tmp_path)
    sink = MemoryAuditSink()
    store = SqlQualityStore(factory, auditor=Auditor(sink, actor="pytest"))
    finding_id = _seed_finding(factory)
    stored = store.add_acceptance(
        RiskAcceptance(
            finding_id=finding_id,
            owner="bob",
            justification="compensated by the network control",
            accepted_at=NOW - timedelta(days=30),
            expires_at=NOW - timedelta(days=1),
        )
    )
    _set_status(factory, finding_id, "accepted")
    decisions = store.reopen_expired(now=NOW)
    assert [item.finding_id for item in decisions] == [finding_id]
    assert _status_of(factory, finding_id) == "open"
    assert [event.action.value for event in sink.events] == [
        "acceptance.changed",
        "acceptance.expired",
    ]
    # A second run is a no-op: the acceptance is stamped as reopened.
    assert store.reopen_expired(now=NOW) == ()
    assert store.list_acceptances(finding_id=finding_id)[0].reopened_at is not None
    assert stored.id is not None


# --------------------------------------------------------------------------- the diff


def test_the_diff_respects_suppressions_and_says_so() -> None:
    before = [_finding(1)]
    after = [
        _finding(1),
        _finding(2, check_id="m3.sqli-oracle", asset="https://app.example/product"),
        _finding(3, check_id="m3.xss-oracle", asset="https://app.example/profile"),
    ]
    rules = SuppressionSet.of(
        [
            Suppression(
                id=1,
                version=4,
                kind="pattern",
                check_id="m3.xss-oracle",
                asset_pattern="https://app.example/*",
                reason="escaped by the front end",
            )
        ]
    )
    diff = build_diff(before, after, scan_a="scan_1", scan_b="scan_2", suppressions=rules)
    assert diff.new == ("m3.sqli-oracle|https://app.example/product",)
    assert diff.suppressed == ("m3.xss-oracle|https://app.example/profile",)
    assert diff.counts["suppressed"] == 1
    assert diff.suppression_version == 4
    assert "Suppressed by rule: 1" in suppression_summary(diff)
    # The stored payload carries it too, so a re-read diff is not silently smaller.
    payload = diff_payload(diff)
    assert payload["suppressed"] == ["m3.xss-oracle|https://app.example/profile"]
    assert payload["suppression_version"] == 4


def test_a_suppression_does_not_hide_a_change_to_a_known_finding() -> None:
    """Only *new* findings are filtered: a recurring finding stays visible."""
    before = [_finding(1, severity="medium")]
    after = [_finding(1, severity="high")]
    rules = SuppressionSet.of(
        [Suppression(kind="rule", check_id="m3.xss-oracle", reason="escaped by the front end")]
    )
    diff = build_diff(before, after, scan_a="scan_1", scan_b="scan_2", suppressions=rules)
    assert diff.regressed == ("m3.xss-oracle|https://app.example/search",)
    assert diff.suppressed == ()


def test_a_diff_with_no_rules_states_that_none_apply() -> None:
    diff = build_diff([_finding(1)], [_finding(1)], scan_a="scan_1", scan_b="scan_2")
    assert "No suppression rules are in force" in suppression_summary(diff)
    assert diff.suppressed == ()


# --------------------------------------------------------------------------- trends


def test_fp_rate_trends_are_computed_per_key_and_alert_when_rising() -> None:
    events: list[FeedbackEvent] = []
    # A flat key: 1 false positive out of 4 marks, every day.
    for offset in range(5):
        day = NOW - timedelta(days=4 - offset)
        events.extend(
            FeedbackEvent(key="m3.xss-oracle|url|none", is_fp=index == 0, at=day)
            for index in range(4)
        )
    # A rising key: 0/4 then 3/4 then 4/4.
    for offset, false_positives in enumerate((0, 0, 3, 4)):
        day = NOW - timedelta(days=3 - offset)
        events.extend(
            FeedbackEvent(key="m3.sqli-oracle|url|none", is_fp=index < false_positives, at=day)
            for index in range(4)
        )
    trends = {trend.key: trend for trend in compute_trends(events, days=4, now=NOW)}
    assert set(trends) == {"m3.xss-oracle|url|none", "m3.sqli-oracle|url|none"}
    assert trends["m3.xss-oracle|url|none"].fp_rate == pytest.approx(0.25)
    assert trends["m3.sqli-oracle|url|none"].recent_rate(window=2) == pytest.approx(7 / 8)

    alerts = rising_alerts(trends.values(), threshold=0.1, window=2, min_marks=3)
    assert [alert.key for alert in alerts] == ["m3.sqli-oracle|url|none"]
    assert alerts[0].delta > 0.5


def test_a_trend_needs_enough_marks_before_it_alerts() -> None:
    events = [
        FeedbackEvent(key="k", is_fp=False, at=NOW - timedelta(days=3)),
        FeedbackEvent(key="k", is_fp=True, at=NOW),
    ]
    trends = compute_trends(events, days=4, now=NOW)
    assert rising_alerts(trends, threshold=0.1, window=1, min_marks=3) == ()


def test_the_history_reads_the_feedback_rows_with_their_times() -> None:
    store = MemoryQualityStore()
    store.record_feedback_event(FeedbackEvent(key="k", is_fp=True, at=NOW))
    assert store.feedback_history(since=NOW - timedelta(hours=1))[0].is_fp
    assert store.feedback_history(since=NOW + timedelta(hours=1)) == ()


# --------------------------------------------------------------------------- helpers


def _factory(tmp_path) -> sessionmaker:  # type: ignore[type-arg]
    engine = create_engine(f"sqlite:///{tmp_path / 'quality.db'}")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)


def _seed_finding(factory: sessionmaker) -> int:  # type: ignore[type-arg]
    from arachne.data.models import Asset, Scan, Target

    with factory() as session:
        target = Target(name="quality-target", scope_json={})
        session.add(target)
        session.commit()
        scan = Scan(target_id=target.id, engine="heuristic", plan_json={}, stats_json={})
        session.add(scan)
        session.commit()
        asset = Asset(scan_id=scan.id, kind="url", value="https://app.example/login")
        session.add(asset)
        session.commit()
        from arachne.data.models import Finding

        finding = Finding(
            scan_id=scan.id, asset_id=asset.id, title="accepted finding", status="open"
        )
        session.add(finding)
        session.commit()
        return int(finding.id)


def _set_status(factory: sessionmaker, finding_id: int, status: str) -> None:  # type: ignore[type-arg]
    from arachne.data.models import Finding

    with factory() as session:
        row = session.get(Finding, finding_id)
        assert row is not None
        row.status = status
        session.commit()


def _status_of(factory: sessionmaker, finding_id: int) -> str:  # type: ignore[type-arg]
    from arachne.data.models import Finding

    with factory() as session:
        row = session.get(Finding, finding_id)
        assert row is not None
        return str(row.status)
