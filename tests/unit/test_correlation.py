"""The correlation engine: dedupe and compound findings (docs/spec/04- §2.3, F-05-03).

The headline behaviour is the demo the stage asks for: two weak signals on one asset become
one compound finding whose severity is upgraded, with the contributors and their evidence
attached. The dedupe pass is tested separately because it changes what the correlation pass
sees.
"""

from __future__ import annotations

import pytest

from arachne.analyzer.conditions import build_facts
from arachne.analyzer.correlation import (
    CorrelationEngine,
    CorrelationRuleSet,
    parse_correlation_rules,
)
from arachne.analyzer.model import Analysis, Candidate, EvidenceFact, Remediation, ScoreBreakdown
from arachne.analyzer.remediation import load_remediation_catalog
from arachne.analyzer.scoring import ScoringModel


def analysis(
    *,
    finding_id: int,
    severity: str = "medium",
    check_id: str = "m4.admin-panel",
    module: str = "M4",
    cwe: str = "CWE-284",
    asset: str = "example.com",
    title: str = "finding",
    confidence: int = 70,
) -> Analysis:
    return Analysis(
        title=title,
        severity=severity,
        confidence=confidence,
        narrative="",
        remediation=Remediation(id="generic", summary="fix it"),
        finding_id=finding_id,
        check_id=check_id,
        asset=asset,
        cwe=cwe,
        score=ScoreBreakdown(confidence=confidence),
    )


def candidate(
    *,
    finding_id: int,
    check_id: str,
    module: str,
    asset_value: str,
    asset_kind: str = "url",
    name: str | None = None,
    evidence: tuple[EvidenceFact, ...] = (),
) -> Candidate:
    return Candidate(
        scan_id=1,
        title="finding",
        finding_id=finding_id,
        check_id=check_id,
        check_module=module,
        check_name=name or check_id.split(".", 1)[-1],
        asset_kind=asset_kind,
        asset_value=asset_value,
        evidence=evidence,
    )


TWO_SIGNAL_RULES = {
    "version": "test",
    "dedupe": {"enabled": True, "owner_preference": ["M4", "M3", "M2", "M1"]},
    "rules": [
        {
            "id": "correlation.weak-pair",
            "title": "Two weak signals on one host",
            "group_by": "host",
            "min_weak_signals": 2,
            "signals": [
                {"id": "admin", "module": ["M4"], "name_token": ["admin"]},
                {"id": "cors", "module": ["M3"], "name_token": ["cors"]},
            ],
            "upgrade_if": ["admin and cors -> high"],
            "max_severity": "critical",
            "cwe": "CWE-693",
            "narrative": None,
        }
    ],
}


def engine(rules: dict[str, object] | None = None) -> CorrelationEngine:
    return CorrelationEngine(
        parse_correlation_rules(rules or TWO_SIGNAL_RULES),
        scoring=ScoringModel(),
        remediation=load_remediation_catalog(),
    )


# --------------------------------------------------------------------------- correlation demo


def test_two_weak_signals_produce_one_compound_finding_with_an_upgraded_severity() -> None:
    admin = analysis(finding_id=1, severity="medium", check_id="m4.admin-panel", module="M4")
    cors = analysis(
        finding_id=2,
        severity="medium",
        check_id="m3.cors-policy",
        module="M3",
        cwe="CWE-942",
    )
    candidates = {
        1: candidate(
            finding_id=1,
            check_id="m4.admin-panel",
            module="M4",
            asset_value="https://example.com/admin",
        ),
        2: candidate(
            finding_id=2,
            check_id="m3.cors-policy",
            module="M3",
            asset_value="https://example.com/api",
        ),
    }
    outcome = engine().correlate([admin, cors], candidates)

    assert len(outcome.compounds) == 1
    compound = outcome.compounds[0]
    assert compound.title == "Two weak signals on one host"
    assert compound.severity == "high"  # upgraded from medium by upgrade_if
    assert compound.correlated is True
    assert compound.contributors == (1, 2)
    assert compound.cwe == "CWE-693"
    assert compound.verdict == "analyzed"
    assert compound.narrative  # a compound finding always carries prose
    assert outcome.groups[0].signal_ids == ("admin", "cors")
    # Both original analyses are still in the result list: the compound explains, it does not
    # replace the underlying findings.
    assert [item.finding_id for item in outcome.analyses if not item.correlated] == [1, 2]


def test_below_the_threshold_no_compound_is_emitted() -> None:
    admin = analysis(finding_id=1, check_id="m4.admin-panel", module="M4")
    candidates = {
        1: candidate(
            finding_id=1,
            check_id="m4.admin-panel",
            module="M4",
            asset_value="https://example.com/admin",
        )
    }
    outcome = engine().correlate([admin], candidates)
    assert outcome.compounds == ()
    assert outcome.groups == ()


def test_signals_on_different_hosts_do_not_correlate() -> None:
    admin = analysis(finding_id=1, check_id="m4.admin-panel", module="M4")
    cors = analysis(finding_id=2, check_id="m3.cors-policy", module="M3")
    candidates = {
        1: candidate(
            finding_id=1,
            check_id="m4.admin-panel",
            module="M4",
            asset_value="https://a.example.com/x",
        ),
        2: candidate(
            finding_id=2,
            check_id="m3.cors-policy",
            module="M3",
            asset_value="https://b.example.com/y",
        ),
    }
    assert engine().correlate([admin, cors], candidates).compounds == ()


def test_group_by_asset_keeps_a_url_and_its_host_apart() -> None:
    rules = {**TWO_SIGNAL_RULES, "rules": [{**TWO_SIGNAL_RULES["rules"][0], "group_by": "asset"}]}  # type: ignore[index]
    admin = analysis(finding_id=1, check_id="m4.admin-panel", module="M4")
    cors = analysis(finding_id=2, check_id="m3.cors-policy", module="M3")
    candidates = {
        1: candidate(
            finding_id=1,
            check_id="m4.admin-panel",
            module="M4",
            asset_value="https://example.com/admin",
        ),
        2: candidate(
            finding_id=2,
            check_id="m3.cors-policy",
            module="M3",
            asset_value="https://example.com/api",
        ),
    }
    assert engine(rules).correlate([admin, cors], candidates).compounds == ()


def test_upgrade_levels_is_used_when_no_upgrade_clause_matches() -> None:
    rules = {
        "version": "test",
        "rules": [
            {
                "id": "correlation.levels",
                "title": "Levels",
                "group_by": "host",
                "min_weak_signals": 2,
                "signals": [
                    {"id": "aa", "module": ["M4"]},
                    {"id": "bb", "module": ["M3"]},
                ],
                "upgrade_levels": 1,
                "upgrade_if": ["signal_count >= 5 -> critical"],
            }
        ],
    }
    first = analysis(finding_id=1, severity="medium", check_id="m4.one", module="M4", cwe="CWE-284")
    second = analysis(finding_id=2, severity="low", check_id="m3.two", module="M3", cwe="CWE-942")
    candidates = {
        1: candidate(finding_id=1, check_id="m4.one", module="M4", asset_value="example.com"),
        2: candidate(finding_id=2, check_id="m3.two", module="M3", asset_value="example.com"),
    }
    compound = engine(rules).correlate([first, second], candidates).compounds[0]
    assert compound.severity == "high"  # worst(medium, low) promoted by one level
    assert compound.rule_trace[0].clause == "upgrade_levels"


def test_a_rule_never_lowers_a_contributor_severity() -> None:
    rules = {
        "version": "test",
        "rules": [
            {
                "id": "correlation.lower",
                "title": "Lower",
                "group_by": "host",
                "min_weak_signals": 2,
                "signals": [{"id": "aa", "module": ["M4"]}, {"id": "bb", "module": ["M3"]}],
                "upgrade_if": ["signal_count >= 2 -> info"],
            }
        ],
    }
    first = analysis(finding_id=1, severity="high", check_id="m4.one", module="M4", cwe="CWE-284")
    second = analysis(finding_id=2, severity="high", check_id="m3.two", module="M3", cwe="CWE-942")
    candidates = {
        1: candidate(finding_id=1, check_id="m4.one", module="M4", asset_value="example.com"),
        2: candidate(finding_id=2, check_id="m3.two", module="M3", asset_value="example.com"),
    }
    compound = engine(rules).correlate([first, second], candidates).compounds[0]
    assert compound.severity == "high"


def test_max_severity_caps_the_promotion() -> None:
    rules = {
        "version": "test",
        "rules": [
            {
                "id": "correlation.capped",
                "title": "Capped",
                "group_by": "host",
                "min_weak_signals": 2,
                "signals": [{"id": "aa", "module": ["M4"]}, {"id": "bb", "module": ["M3"]}],
                "upgrade_if": ["signal_count >= 2 -> critical"],
                "max_severity": "medium",
            }
        ],
    }
    first = analysis(finding_id=1, severity="medium", check_id="m4.one", module="M4", cwe="CWE-284")
    second = analysis(
        finding_id=2, severity="medium", check_id="m3.two", module="M3", cwe="CWE-942"
    )
    candidates = {
        1: candidate(finding_id=1, check_id="m4.one", module="M4", asset_value="example.com"),
        2: candidate(finding_id=2, check_id="m3.two", module="M3", asset_value="example.com"),
    }
    compound = engine(rules).correlate([first, second], candidates).compounds[0]
    assert compound.severity == "medium"


# --------------------------------------------------------------------------- dedupe


def dedupe_rules() -> dict[str, object]:
    return {
        "version": "test",
        "dedupe": {"enabled": True, "owner_preference": ["M4", "M2", "M1"]},
        "rules": [],
    }


def test_dedupe_keeps_the_most_specific_module_as_owner() -> None:
    m2 = analysis(finding_id=1, check_id="m2.db-service-probe", module="M2", cwe="CWE-306")
    m4 = analysis(finding_id=2, check_id="m4.db-exposure", module="M4", cwe="CWE-306")
    evidence_1 = (EvidenceFact("note", {"a": 1}, id=11),)
    evidence_2 = (EvidenceFact("note", {"b": 2}, id=22),)
    candidates = {
        1: candidate(
            finding_id=1,
            check_id="m2.db-service-probe",
            module="M2",
            asset_value="example.com",
            asset_kind="host",
            evidence=evidence_1,
        ),
        2: candidate(
            finding_id=2,
            check_id="m4.db-exposure",
            module="M4",
            asset_value="example.com",
            asset_kind="host",
            evidence=evidence_2,
        ),
    }
    outcome = engine(dedupe_rules()).correlate([m2, m4], candidates)
    owner = next(item for item in outcome.analyses if item.finding_id == 2)
    merged = next(item for item in outcome.analyses if item.finding_id == 1)
    assert owner.contributors == (1,)
    assert owner.merged_evidence_refs == (11,)
    assert "merged duplicate finding(s)" in owner.risk_notes
    assert merged.verdict == "merged"
    assert merged.merged_into == 2
    assert "same CWE and asset" in (merged.drop_reason or "")
    assert outcome.evidence_owner == {1: 2}


def test_findings_with_different_cwes_are_not_merged() -> None:
    one = analysis(finding_id=1, check_id="m2.a", module="M2", cwe="CWE-200")
    two = analysis(finding_id=2, check_id="m4.b", module="M4", cwe="CWE-284")
    candidates = {
        1: candidate(finding_id=1, check_id="m2.a", module="M2", asset_value="example.com"),
        2: candidate(finding_id=2, check_id="m4.b", module="M4", asset_value="example.com"),
    }
    outcome = engine(dedupe_rules()).correlate([one, two], candidates)
    assert outcome.merged == ()
    assert all(not item.contributors for item in outcome.analyses)


def test_dedupe_can_be_disabled() -> None:
    rules = {**dedupe_rules(), "dedupe": {"enabled": False}}
    one = analysis(finding_id=1, check_id="m2.a", module="M2", cwe="CWE-200")
    two = analysis(finding_id=2, check_id="m4.b", module="M4", cwe="CWE-200")
    candidates = {
        1: candidate(finding_id=1, check_id="m2.a", module="M2", asset_value="example.com"),
        2: candidate(finding_id=2, check_id="m4.b", module="M4", asset_value="example.com"),
    }
    outcome = engine(rules).correlate([one, two], candidates)
    assert outcome.merged == ()


# --------------------------------------------------------------------------- configuration


def test_dropped_analyses_are_kept_in_the_result() -> None:
    dropped = Analysis(
        title="dropped",
        severity="high",
        confidence=10,
        narrative="",
        remediation=Remediation(id="g", summary="fix"),
        finding_id=9,
        verdict="dropped",
        drop_reason="did not reproduce",
    )
    outcome = engine(dedupe_rules()).correlate([dropped], {})
    assert [item.verdict for item in outcome.analyses] == ["dropped"]


@pytest.mark.parametrize(
    "document",
    [
        {
            "version": "1",
            "rules": [
                {
                    "id": "r.x",
                    "title": "t",
                    "group_by": "galaxy",
                    "signals": [{"id": "a"}, {"id": "b"}],
                }
            ],
        },
        {"version": "1", "rules": [{"id": "r.x", "title": "t", "signals": [{"id": "a"}]}]},
        {
            "version": "1",
            "rules": [{"id": "r.x", "title": "t", "signals": [{"id": "a"}, {"id": "a"}]}],
        },
        {
            "version": "1",
            "rules": [
                {
                    "id": "r.x",
                    "title": "t",
                    "signals": [{"id": "a"}, {"id": "b"}],
                    "upgrade_if": ["nonsense"],
                }
            ],
        },
    ],
)
def test_invalid_correlation_rules_are_refused(document: dict[str, object]) -> None:
    from arachne.core.errors import ConfigurationError

    with pytest.raises(ConfigurationError):
        parse_correlation_rules(document, source="test")


def test_the_shipped_rules_parse() -> None:
    from arachne.analyzer.correlation import load_correlation_rules

    rules: CorrelationRuleSet = load_correlation_rules()
    assert rules.dedupe.enabled is True
    assert rules.rules
    assert all(rule.min_weak_signals >= 2 for rule in rules.rules)


def test_a_synthetic_candidate_fills_in_a_missing_candidate() -> None:
    """The pairing helper degrades to a stand-in rather than raising (a resume may differ)."""
    first = analysis(finding_id=1, check_id="m4.admin-panel", module="M4")
    outcome = engine().correlate([first], {})
    assert len(outcome.analyses) == 1
    _ = build_facts
