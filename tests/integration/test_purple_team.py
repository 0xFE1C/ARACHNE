"""Purple-team detection validation, end to end (S24, REQ-VALID-001...006).

One acceptance demonstration, over the real web lab and the real services stack:

A stored, attested target carries a **coordinated detection window**; a campaign replays the
lab's own proof actions inside it as a real scan through the orchestrator; the lab's SIEM
fixture — planted alerts, some linked to the run by its nonce, some deliberately not — is
ingested; control coverage is scored (seen per technique, % per ATT&CK tactic, an explicit
gap list); Sigma alignment reports rule-hit/rule-miss with the L4 marker as the deliberate
miss; and the defender report joins the gaps to the attack paths an attacker could walk
unseen.

The window and the nonce are the two things a purple run must never be able to fudge, so
both are asserted from the artifacts rather than from the code under test.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from tests.helpers.api import make_api_harness
from tests.lab.web_lab import WebLab, start_web_lab

from arachne.analyzer.paths import build_attack_paths
from arachne.core.audit import AuditAction
from arachne.core.config import (
    ApiSettings,
    PurpleSettings,
    RateLimitSettings,
    SafetySettings,
    Settings,
)
from arachne.core.errors import DetectionWindowError
from arachne.core.safety import UrlSafetyPolicy
from arachne.core.target import ScanOptions, ScanRequest, TargetDefinition
from arachne.data.services import build_orchestrator
from arachne.purple.campaign import PurpleCampaignService, PurpleCampaignSpec
from arachne.purple.report import alignments_from_run, build_defender_report

#: The replayable actions this campaign uses — L1 (in-band oracle), L2 (out-of-band) and
#: the L4 state marker, so the ladder is represented and the deliberate rule-miss is in it.
ACTIONS = ("m3.sqli-oracle", "m3.cmdi-oob", "m3.state-marker")

SIEM_FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "purple" / "siem-alerts.json"
#: The fixture's own nominal window start, used to shift its timestamps into the run's.
FIXTURE_ANCHOR = datetime(2026, 10, 31, 12, 0, tzinfo=UTC)


@pytest.fixture(scope="module")
def lab() -> Iterator[WebLab]:
    with start_web_lab() as running:
        yield running


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        database_url=f"sqlite:///{tmp_path / 'purple.db'}",
        log_level="CRITICAL",
        log_json=False,
        actor="pytest",
        api=ApiSettings(
            keys=("admin:admin:rootsecret",),
            require_tls=False,
            rate_limit_per_minute=100_000,
            rate_limit_burst=100_000,
        ),
        rate_limit=RateLimitSettings(
            per_host_rate=1000.0, per_host_burst=1000, global_rate=1000.0, global_burst=1000
        ),
        safety=SafetySettings(policy=UrlSafetyPolicy(allow_loopback=True, allow_private_ips=True)),
        purple=PurpleSettings(),
    )


def _window(now: datetime) -> dict[str, str]:
    """A window the run is *inside* — the coordinated interval, not a comfortable one."""
    return {
        "starts_at": (now - timedelta(minutes=5)).isoformat(),
        "ends_at": (now + timedelta(minutes=30)).isoformat(),
        "coordinator": "soc-lead@corp",
        "defender": "blue-team@corp",
        "reference": "CHG-4242",
    }


def _definition(lab: WebLab, window: dict[str, str]) -> TargetDefinition:
    now = datetime.now(UTC)
    return TargetDefinition.model_validate(
        {
            "name": "lab-web",
            "targets": [{"kind": "url", "value": lab.base_url}],
            "attestation": {
                "attested_by": "S24 integration test",
                "attested_at": (now - timedelta(hours=6)).isoformat(),
                "scope_statement": "coordinated purple-team window over the lab web target",
                "allowed_targets": [lab.base_url, "127.0.0.1"],
                "active_checks_authorized": True,
                "expires_at": (now + timedelta(hours=4)).isoformat(),
                "detection_window": window,
            },
        }
    )


def _planted_alerts(window: dict[str, str], nonce: str):  # type: ignore[no-untyped-def]
    """The SIEM fixture, shifted into *this* run's window and tagged with *its* nonce.

    The fixture is a template of a defender's report shapes (linked, out-of-window,
    no-nonce, no-technique); the test places it in the coordinated interval, because the
    window and the nonce are minted per run and must never be constants in a file.
    """
    from arachne.purple.alerts import parse_alert_document

    document = json.loads(SIEM_FIXTURE.read_text(encoding="utf-8"))
    shift = datetime.fromisoformat(window["starts_at"]) - FIXTURE_ANCHOR
    for alert in document["alerts"]:
        moment = datetime.fromisoformat(alert["timestamp"].replace("Z", "+00:00"))
        alert["timestamp"] = (moment + shift).isoformat()
        for key in ("message", "description"):
            if key in alert:
                alert[key] = alert[key].replace("{{NONCE}}", nonce)
    return parse_alert_document(document, source="lab-siem")


def _stored_target(harness: Any, lab: WebLab, window: dict[str, str]) -> None:
    harness.services.target_store.save(_definition(lab, window))


# ------------------------------------------------------------------ the acceptance run
@pytest.mark.asyncio
async def test_the_campaign_scores_coverage_against_the_planted_siem_fixture(
    lab: WebLab, tmp_path: Path
) -> None:
    """REQ-VALID-001/002/003/004/005/006 in one run over the lab."""
    harness = make_api_harness(tmp_path, settings=_settings(tmp_path))
    now = datetime.now(UTC)
    window = _window(now)
    _stored_target(harness, lab, window)

    service = PurpleCampaignService(harness.services)
    campaign = service.create_campaign(
        "nightly-web",
        PurpleCampaignSpec(target="lab-web", actions=ACTIONS, collect_delay_s=0),
    )
    assert campaign.spec.actions == ACTIONS

    # --- the run: a real scan through the orchestrator, inside the window ---------------
    # The run's nonce is minted in the service; to plant alerts against it the test reads
    # it back from the admitted scan's stats, which is also what a defender would do.
    result = await service.run_campaign("nightly-web")
    assert result.status == "completed"
    assert result.scan_id is not None and result.nonce

    # 1. The scan is a purple run: every emitted artifact is tagged with the run nonce
    #    (REQ-VALID-003), and the ledger of emissions names the techniques replayed.
    scan = harness.services.store.get_scan(result.scan_id)
    assert scan is not None
    purple_stats = dict((scan.stats or {}).get("purple") or {})
    assert purple_stats["campaign"] == "nightly-web"
    assert purple_stats["nonce"] == result.nonce
    assert purple_stats["window"]["state_at"] == "open"
    assert purple_stats["stopped_at"] is None
    emissions = purple_stats["emissions"]
    assert {item["technique"] for item in emissions} == {"T1190", "T1059", "T1565.001"}
    for item in emissions:
        assert item["nonce"] == result.nonce

    # Every *finding* the run emitted carries the purple tag, nonce and all. The lab's
    # SQL-injectable parameter is the L1 oracle's target, so at least one exists.
    findings = harness.services.findings.list_candidates(result.scan_id)
    tagged = [
        evidence
        for candidate in findings
        for evidence in candidate.evidence
        if evidence.kind == "purple"
    ]
    assert tagged, "the purple run produced no tagged artifact"
    for evidence in tagged:
        assert evidence.payload["nonce"] == result.nonce
        assert evidence.payload["campaign"] == "nightly-web"
        assert evidence.payload["techniques"]
        assert "detection_note" in evidence.payload

    # 2. The audit trail shows the run, the emission and the window it ran inside.
    started = harness.sink.of_action(AuditAction.PURPLE_RUN_STARTED)
    assert started and started[0].meta["window"]["state_at"] == "open"
    emitted = harness.sink.of_action(AuditAction.PURPLE_ACTION_EMITTED)
    assert emitted and all(event.meta["nonce"] == result.nonce for event in emitted)
    assert harness.sink.of_action(AuditAction.PURPLE_WINDOW_REFUSED) == []

    # 3. The SIEM's planted alerts are ingested and scored (REQ-VALID-002).
    added = service.ingest(_planted_alerts(window, result.nonce), source="lab-siem")
    assert added == 5
    assert harness.sink.of_action(AuditAction.PURPLE_ALERT_INGESTED)

    coverage = service.score("nightly-web", run_id=result.run_id)
    by_technique = {item.technique: item for item in coverage.techniques}
    assert set(by_technique) == {"T1190", "T1059", "T1565.001"}
    assert by_technique["T1190"].seen is True, "the planted linked alert must count"
    assert by_technique["T1059"].seen is True
    assert by_technique["T1565.001"].seen is False, "nothing reported the marker"
    assert [item.technique for item in coverage.gaps] == ["T1565.001"]
    assert coverage.coverage_pct == 66.7

    tactics = {item.tactic: item for item in coverage.tactics}
    assert tactics["initial-access"].coverage_pct == 100.0
    assert tactics["execution"].coverage_pct == 100.0
    assert tactics["impact"].coverage_pct == 0.0

    # The three ways an alert can fail to be coverage are each counted, not swallowed.
    assert coverage.alerts_ingested == 5
    assert coverage.alerts_out_of_window == 1, "the pre-window alert does not count"
    assert coverage.alerts_without_technique == 1
    assert coverage.alerts_other_technique == 1, "the impact alert is not our test"
    assert coverage.other_techniques == ("T1486",)
    # Two scoring passes are audited: the run's own (before any alert had arrived — 3 gaps)
    # and this re-score once the defender reported (1 gap). Coverage is re-computable by
    # design, because a SIEM reports after the window closes.
    scored_events = harness.sink.of_action(AuditAction.PURPLE_COVERAGE_SCORED)
    assert len(scored_events) == 2
    assert scored_events[0].meta["coverage_pct"] == 0.0
    assert scored_events[-1].meta["gaps"] == ["T1565.001"]
    assert scored_events[-1].meta["coverage_pct"] == 66.7

    # 4. Sigma alignment with the deliberate miss (REQ-VALID-004).
    stored_run = service.store.run(result.run_id)
    assert stored_run is not None
    alignments = {item.check_id: item for item in alignments_from_run(stored_run)}
    assert alignments["m3.cmdi-oob"].verdict == "rule-hit"
    assert alignments["m3.state-marker"].verdict == "rule-miss"
    assert alignments["m3.state-marker"].hits == ()

    # 5. The defender report joins the gaps to what an attacker could do unseen
    #    (REQ-VALID-005) and states the miss (REQ-VALID-004).
    stored_analyses = [
        item for item in harness.services.analyses.list_analyses(result.scan_id) if item is not None
    ]
    from arachne.data.analysis_store import analysis_from_log

    rebuilt = [item for item in (analysis_from_log(row) for row in stored_analyses) if item]
    paths = build_attack_paths(
        rebuilt, candidates=harness.services.findings.list_candidates(result.scan_id)
    )
    report = build_defender_report(
        campaign="nightly-web",
        run=stored_run,
        coverage=coverage,
        sigma=tuple(alignments.values()),
        attack_paths=paths,
        technique_map=service.technique_map,
        generated_at=now,
    )
    markdown = report.render_markdown()
    assert "# Defender report — nightly-web" in markdown
    assert f"Run nonce: `{result.nonce}`" in markdown
    assert "**2 of 3 technique(s) seen (66.7%)**" in markdown
    assert "| Impact | 1 | 0 | 0.0% |" in markdown
    assert "| T1565.001 | Impact | high | m3.state-marker | 0 |" in markdown
    assert "rule-miss" in markdown and "m3.state-marker" in markdown
    assert "Rule-miss: the shipped hunt library has no rule" in markdown
    assert "5 ingested · 2 linked to this run" in markdown
    assert "The defender reported techniques this run did not emit: T1486" in markdown
    assert markdown == report.render_markdown(), "the rendering is deterministic"
    assert json.dumps(report.to_dict(), sort_keys=True)

    # 6. The trend keeps the run, and re-scoring is idempotent (REQ-VALID-006).
    points = service.trend("nightly-web")
    assert [point.run_id for point in points] == [result.run_id]
    assert points[0].coverage_pct == 66.7
    again = service.score("nightly-web", run_id=result.run_id)
    assert again.coverage_pct == coverage.coverage_pct


@pytest.mark.asyncio
async def test_a_second_run_regresses_when_the_defender_stops_reporting(
    lab: WebLab, tmp_path: Path
) -> None:
    """REQ-VALID-006's acceptance: the trend flags a technique that was seen and is not."""
    harness = make_api_harness(tmp_path, settings=_settings(tmp_path))
    now = datetime.now(UTC)
    window = _window(now)
    _stored_target(harness, lab, window)
    service = PurpleCampaignService(harness.services)
    service.create_campaign("trend", PurpleCampaignSpec(target="lab-web", actions=ACTIONS))

    first = await service.run_campaign("trend")
    assert first.status == "completed" and first.nonce
    service.ingest(_planted_alerts(window, first.nonce), source="lab-siem")
    scored = service.score("trend", run_id=first.run_id)
    assert scored.coverage_pct == 66.7

    # The defender's pipeline goes quiet: no alerts for the second run at all. The campaign
    # must still run (it is a test, not a monitor) and the trend must flag the regression.
    harness.services.purple.clear_alerts()
    second = await service.run_campaign("trend")
    assert second.status == "completed"
    assert second.regressions == ("T1059", "T1190"), "seen before, unseen now (sorted)"
    regressed = harness.sink.of_action(AuditAction.PURPLE_COVERAGE_REGRESSED)
    assert regressed and regressed[0].outcome.value == "blocked"
    assert second.coverage_pct == 0.0

    points = service.trend("trend")
    assert [point.coverage_pct for point in points] == [66.7, 0.0]


@pytest.mark.asyncio
async def test_a_run_outside_the_window_is_refused_recorded_and_never_scanned(
    lab: WebLab, tmp_path: Path
) -> None:
    """The window's other half: a scheduled campaign that fires early is refused, audited
    and *recorded* — so the trend shows it rather than the schedule silently breaking."""
    harness = make_api_harness(tmp_path, settings=_settings(tmp_path))
    now = datetime.now(UTC)
    # A window that has already closed: the campaign is coordinated for a later slot.
    window = {
        "starts_at": (now - timedelta(hours=3)).isoformat(),
        "ends_at": (now - timedelta(hours=2)).isoformat(),
        "coordinator": "soc-lead@corp",
    }
    _stored_target(harness, lab, window)
    service = PurpleCampaignService(harness.services)
    service.create_campaign("early", PurpleCampaignSpec(target="lab-web", actions=ACTIONS))

    result = await service.run_campaign("early")
    assert result.status == "window_refused"
    assert result.scan_id is None and result.coverage is None
    refused = harness.sink.of_action(AuditAction.PURPLE_WINDOW_REFUSED)
    assert refused and refused[0].outcome.value == "blocked"
    assert refused[0].meta["state"] == "closed"
    assert harness.sink.of_action(AuditAction.SCAN_CREATED) == [], "no scan was admitted"
    assert harness.sink.of_action(AuditAction.PURPLE_ACTION_EMITTED) == []

    # The refusal is in the run history, which is what keeps the schedule honest.
    runs = harness.services.purple.runs("early")
    assert [run.status for run in runs] == ["window_refused"]
    assert "closed" in (runs[0].note or "")


@pytest.mark.asyncio
async def test_an_admitted_purple_scan_rechecks_the_window_before_it_executes(
    lab: WebLab, tmp_path: Path
) -> None:
    """Resumption/execution must not become the way around the window (REQ-VALID-001).

    The run is *admitted* inside its window (``launch``: plan, gates, scan row, no
    execution) and then executed after the window has lapsed — the case a distributed queue
    or a paused scheduler produces. The executing path re-checks the window and refuses.
    """
    harness = make_api_harness(tmp_path, settings=_settings(tmp_path))
    now = datetime.now(UTC)
    _stored_target(harness, lab, _window(now))
    orchestrator = build_orchestrator(harness.services)
    request = ScanRequest(
        target=_definition(lab, _window(now)),
        options=ScanOptions(
            engine="heuristic",
            active_checks=True,
            modules={"only": list(ACTIONS)},
            purple={"campaign": "exec-test", "actions": list(ACTIONS)},
        ),
    )
    session = await orchestrator.launch(request)
    assert session.scan_id is not None
    admitted = harness.services.store.get_scan(session.scan_id)
    assert admitted is not None and admitted.status.value == "pending"

    lapsed = ScanRequest(
        target=_definition(
            lab,
            {
                "starts_at": (now - timedelta(hours=3)).isoformat(),
                "ends_at": (now - timedelta(hours=2)).isoformat(),
                "coordinator": "soc-lead@corp",
            },
        ),
        options=request.options,
    )
    with pytest.raises(DetectionWindowError, match="closed at"):
        await orchestrator.execute(session.scan_id, lapsed)

    refused = harness.sink.of_action(AuditAction.PURPLE_WINDOW_REFUSED)
    assert refused and refused[-1].outcome.value == "blocked"
    assert refused[-1].meta["state"] == "closed"
    # Nothing fired: no emitted test artifact was audited for this run.
    assert harness.sink.of_action(AuditAction.PURPLE_ACTION_EMITTED) == []
