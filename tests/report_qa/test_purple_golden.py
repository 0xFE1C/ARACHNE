"""The S24 golden files: the defender report and the detection-validation appendix.

Two renderings, pinned so they cannot drift silently:

* REQ-VALID-005 — the **defender report**: control coverage, the Sigma rule-hit/rule-miss
  table and the attack paths an attacker could walk *unseen*, with the deliberate rule-miss
  stated as a gap in the rule set rather than a clean result.
* REQ-VALID-003/004 — the **scan report's** ``detection_validation`` block: the nonce, the
  window, the techniques and the Sigma verdict, and — the property that matters as much —
  the block's *absence* for an ordinary scan, whose report is then byte-identical to its
  pre-S24 form.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import jsonschema

from arachne.analyzer.paths import build_attack_paths
from arachne.data.analysis_store import analysis_from_log
from arachne.purple.attack import load_technique_map
from arachne.purple.coverage import Emission, score_coverage
from arachne.purple.report import build_defender_report
from arachne.purple.sigma import align_actions
from arachne.report import REPORT_SCHEMA_VERSION, load_report_schema, render_markdown
from arachne.report.builder import ReportInputs, build_report_data
from tests.helpers.report import make_analysis, make_candidate, make_inputs

NOW = datetime(2026, 10, 31, 12, 0, 0, tzinfo=UTC)
NONCE = "abcdef0123456789abcdef01"
WINDOW = {
    "starts_at": NOW.isoformat(),
    "ends_at": (NOW + timedelta(hours=1)).isoformat(),
    "coordinator": "soc-lead@corp",
    "defender": "blue-team@corp",
    "reference": "CHG-4242",
}


def _two_hop_path(host: str = "payments.example"):
    """A two-hop chain whose hops map to *known-unseen* and *unmapped* techniques.

    The exposure hop is the L4 state marker (T1565.001 — the technique nothing in the
    shipped hunt library covers, so it is demonstrably unseen), and the terminal hop's
    check is outside the technique map entirely, which is the honest "untested/unknown"
    case the report must not present as blindness.
    """
    exposure = make_candidate(
        number=1,
        title="Marker row written by the state-change proof",
        asset_value=f"https://{host}/poc-sql",
        module="M3",
        check="state-marker",
        research_ref="ch03#19",
        severity="high",
        confidence=90,
        evidence_start=1,
    )
    terminal = make_candidate(
        number=2,
        title="Unauthenticated data API",
        asset_value=f"https://{host}/api/users",
        module="M4",
        check="unauth-api-audit",
        research_ref="ch04#2",
        severity="critical",
        confidence=95,
        evidence_start=20,
    )
    analyses = [
        make_analysis(exposure, severity="high", confidence=90, cwe="CWE-441"),
        make_analysis(terminal, severity="critical", confidence=95, cwe="CWE-306"),
    ]
    return [exposure, terminal], analyses


def _rebuilt(stored: list[object]) -> list[object]:
    """``StoredAnalysis`` rows as the analyzer's ``Analysis`` objects (what paths compose)."""
    rebuilt = [analysis_from_log(row) for row in stored]  # type: ignore[arg-type]
    return [item for item in rebuilt if item is not None]


def _coverage_with_one_gap():
    emissions = (
        Emission(
            "m3.sqli-oracle",
            "In-band SQL injection oracle",
            "T1190",
            "initial-access",
            "high",
            NONCE,
            NOW + timedelta(minutes=2),
        ),
        Emission(
            "m3.cmdi-oob",
            "Out-of-band command injection",
            "T1059",
            "execution",
            "high",
            NONCE,
            NOW + timedelta(minutes=3),
        ),
        Emission(
            "m3.state-marker",
            "Minimal reversible state change",
            "T1565.001",
            "impact",
            "high",
            NONCE,
            NOW + timedelta(minutes=4),
        ),
    )
    from arachne.core.target import DetectionWindow
    from arachne.purple.alerts import DefenderAlert

    window = DetectionWindow(
        starts_at=NOW, ends_at=NOW + timedelta(hours=1), coordinator="soc-lead@corp"
    )
    alerts = [
        DefenderAlert(
            alert_id="SIEM-9001",
            source="lab-siem",
            observed_at=NOW + timedelta(minutes=6),
            title="SQL injection attempt",
            technique="T1190",
            nonce=NONCE,
        ),
        DefenderAlert(
            alert_id="SIEM-9002",
            source="lab-siem",
            observed_at=NOW + timedelta(minutes=8),
            title="Web worker spawned a shell",
            technique="T1059",
            nonce=NONCE,
        ),
    ]
    return score_coverage(
        emissions, alerts, campaign="nightly-web", nonce=NONCE, window=window, now=NOW
    )


# ------------------------------------------------------------------ REQ-VALID-005
def test_the_defender_report_renders_the_gaps_the_sigma_miss_and_an_unseen_path() -> None:
    """The golden defender report: coverage, the deliberate Sigma miss, one unseen path."""
    candidates, analyses = _two_hop_path()
    paths = build_attack_paths(_rebuilt(analyses), candidates=candidates)
    assert len(paths) == 1

    replay = load_technique_map()
    actions = replay.select(("m3.sqli-oracle", "m3.cmdi-oob", "m3.state-marker"))
    report = build_defender_report(
        campaign="nightly-web",
        run=_RunView(),
        coverage=_coverage_with_one_gap(),
        sigma=align_actions(actions),
        attack_paths=paths,
        technique_map=replay,
        generated_at=NOW,
    )

    markdown = report.render_markdown()
    assert markdown == report.render_markdown(), "deterministic across renders"

    # The header: the run's two load-bearing facts, the window and the nonce.
    assert "# Defender report — nightly-web" in markdown
    assert "Generated 2026-10-31 12:00 UTC · run #7 · scan 42" in markdown
    assert f"Run nonce: `{NONCE}`" in markdown
    assert "2026-10-31T12:00:00+00:00 .. 2026-10-31T13:00:00+00:00" in markdown
    assert "coordinated with soc-lead@corp" in markdown

    # Coverage: the percentage, the per-tactic table and the explicit gap list.
    assert "**2 of 3 technique(s) seen (66.7%)**" in markdown
    assert "| Initial Access | 1 | 1 | 100.0% |" in markdown
    assert "| Execution | 1 | 1 | 100.0% |" in markdown
    assert "| Impact | 1 | 0 | 0.0% |" in markdown
    assert "| T1565.001 | Impact | high | m3.state-marker | 0 |" in markdown

    # The Sigma alignment: the hit, and the two misses named as rule-set gaps — the L4
    # marker (the deliberate miss) and the L1 oracle (the library simply has no SQLi rule).
    assert "| m3.sqli-oracle | T1190 | rule-miss | none |" in markdown
    assert "| m3.cmdi-oob | T1059 | rule-hit |" in markdown
    assert "| m3.state-marker | T1565.001 | rule-miss | none |" in markdown
    assert (
        "Rule-miss: the shipped hunt library has no rule matching the telemetry of "
        "m3.sqli-oracle (T1190), m3.state-marker (T1565.001)." in markdown
    )

    # "What an attacker could do unseen": the path, its hops' verdicts and the break.
    assert "## 3. What an attacker could do unseen" in markdown
    impact = paths[0].business_severity or paths[0].severity
    assert f"### {paths[0].id} — payments.example (terminal impact: {impact})" in markdown
    assert (
        "execution: `m3.state-marker` Marker row written by the state-change proof "
        "— T1565.001 (unseen)" in markdown
    )
    assert "access: `m4.unauth-api-audit` Unauthenticated data API — — (unmapped)" in markdown

    payload = report.to_dict()
    assert payload["unseen_paths"] == [paths[0].id]
    assert payload["coverage"]["gap_ids"] == ["T1565.001"]
    assert [item["verdict"] for item in payload["sigma"]] == [
        "rule-miss",
        "rule-hit",
        "rule-miss",
    ]
    assert json.dumps(payload, sort_keys=True) == json.dumps(report.to_dict(), sort_keys=True)


class _RunView:
    """The stored-run shape the report reads (id, scan, nonce, window)."""

    id = 7
    scan_id = 42
    nonce = NONCE
    window = dict(WINDOW)
    sigma: tuple[object, ...] = ()


def test_a_path_with_no_unseen_hop_is_not_claimed_as_unseen() -> None:
    """The report must not overclaim: an unmapped hop is unknown, not blind."""
    candidates, analyses = _two_hop_path("quiet.example")
    paths = build_attack_paths(_rebuilt(analyses), candidates=candidates)
    report = build_defender_report(
        campaign="c",
        run=_RunView(),
        coverage=_coverage_with_one_gap(),
        sigma=(),
        attack_paths=paths,
        technique_map=load_technique_map(),
        generated_at=NOW,
    )
    entry = report.paths[0]
    assert entry.unmapped == ("m4.unauth-api-audit",)
    assert "T1565.001" in entry.unseen
    assert report.unseen_paths == (entry,)


# ------------------------------------------------------------------ REQ-VALID-003/004
def _report_inputs(**overrides: object) -> ReportInputs:
    base = make_inputs()
    return ReportInputs(
        **{**{field: getattr(base, field) for field in base.__dataclass_fields__}, **overrides}
    )


def test_an_ordinary_report_carries_no_detection_validation_block() -> None:
    """The optional-block property: a scan that is not a detection test is unaffected."""
    report = build_report_data(_report_inputs())
    assert report.detection_validation is None
    markdown = render_markdown(report)
    assert "Detection validation" not in markdown
    document = json.loads(report.model_dump_json())
    assert document["detection_validation"] is None
    # WP-13 bumped the report schema to 1.12: the per-finding ``verification`` record became
    # required (REQ-PROOF-015). Pinned so a further bump is a conscious act, not silent
    # drift.
    assert document["schema_version"] == REPORT_SCHEMA_VERSION == "1.13"
    jsonschema.validate(document, load_report_schema())


def test_a_purple_scan_report_carries_the_nonce_the_window_and_the_sigma_verdict() -> None:
    """REQ-VALID-003/004 in the *scan* report: the artifact is visibly a tagged test."""
    replay = load_technique_map()
    actions = replay.select(("m3.cmdi-oob", "m3.state-marker"))
    alignments = align_actions(actions)
    purple_block = {
        "campaign": "nightly-web",
        "nonce": NONCE,
        "window": {**WINDOW, "present": True, "state_at": "open"},
        "actions": [action.check_id for action in actions],
        "emissions": [
            {
                "check_id": action.check_id,
                "title": action.title,
                "technique": action.techniques[0],
                "tactic": action.tactic,
                "severity": action.severity,
                "nonce": NONCE,
                "emitted_at": NOW.isoformat(),
                "level": action.level,
            }
            for action in actions
        ],
        "sigma": [item.to_dict() for item in alignments],
        "stopped_at": None,
        "stop_reason": None,
    }
    report = build_report_data(
        _report_inputs(
            detection_validation=purple_block,
            detection_sigma={"alignments": [item.to_dict() for item in alignments]},
        )
    )
    block = report.detection_validation
    assert block is not None
    assert block.campaign == "nightly-web" and block.nonce == NONCE
    assert block.window_state == "open"
    assert {item.technique for item in block.actions} == {"T1059", "T1565.001"}
    assert {item.sigma_verdict for item in block.actions} == {"rule-hit", "rule-miss"}
    assert block.rule_misses == ("T1565.001",)

    markdown = render_markdown(report)
    assert "### I. Detection validation (purple team)" in markdown
    assert "designed to be seen" in markdown
    assert f"Run nonce `{NONCE}`" in markdown
    assert "| `m3.cmdi-oob` | T1059 | Execution | high | rule-hit |" in markdown
    assert "| `m3.state-marker` | T1565.001 | Impact | high | rule-miss |" in markdown
    assert f"`{NONCE}`" in markdown
    assert (
        "Rule-miss: the shipped hunt library has no rule matching the telemetry of "
        "T1565.001" in markdown
    )

    document = json.loads(report.model_dump_json())
    assert document["detection_validation"]["nonce"] == NONCE
    assert document["detection_validation"]["rule_misses"] == ["T1565.001"]
    jsonschema.validate(document, load_report_schema())


def test_a_stopped_purple_run_says_so_in_the_report() -> None:
    """The auto-stop is visible where a reader looks, not only in the audit trail."""
    stopped = {
        "campaign": "nightly-web",
        "nonce": NONCE,
        "window": {**WINDOW, "present": True, "state_at": "closed"},
        "emissions": [],
        "stopped_at": (NOW + timedelta(minutes=30)).isoformat(),
        "stop_reason": "the detection window closed",
    }
    report = build_report_data(_report_inputs(detection_validation=stopped))
    markdown = render_markdown(report)
    assert "Auto-stopped at 2026-10-31T12:30:00+00:00" in markdown
    assert "remaining actions were skipped rather than fired outside it" in markdown
