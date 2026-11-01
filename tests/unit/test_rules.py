"""The rule engine and the shipped corpus (F-05-01).

The important properties are behavioural: both YAML spellings from the spec mean the same
thing, the most specific rule wins, the first matching clause decides, and a rule that fires
leaves a trace an operator (and the narrative) can read. The corpus-level tests are the ones
that keep the shipped data honest — every reference a rule makes must resolve.
"""

from __future__ import annotations

import pytest

from arachne.analyzer.conditions import FactSpace, build_facts
from arachne.analyzer.correlation import load_correlation_rules
from arachne.analyzer.model import Candidate, EvidenceFact, VerificationOutcome
from arachne.analyzer.narrative import load_narrative_templates
from arachne.analyzer.remediation import load_remediation_catalog, ref_to_entry_id
from arachne.analyzer.rules import (
    Rule,
    RuleEngine,
    RuleSelector,
    RuleSet,
    load_rule_set,
    parse_rule_set,
)
from arachne.core.errors import ConfigurationError


def make_candidate(**overrides: object) -> Candidate:
    base = {
        "scan_id": 1,
        "title": "Sensitive environment file exposed",
        "check_id": "m4.env-file-probe",
        "check_module": "M4",
        "check_name": "env-file-probe",
        "research_ref": "ch04#1",
        "cwe": "CWE-200",
        "severity_hint": "high",
        "check_confidence": 80,
        "asset_kind": "url",
        "asset_value": "https://example.com/.env",
    }
    base.update(overrides)
    return Candidate(**base)  # type: ignore[arg-type]


def facts_for(candidate: Candidate, **kwargs: object) -> FactSpace:
    return build_facts(candidate, **kwargs)  # type: ignore[arg-type]


SPEC_RULE = {
    "version": "test",
    "rules": [
        {
            "id": "exposure.env-file",
            "title": "Sensitive environment file exposed",
            "check_ref": ["M4#env-file-probe", "research:ch04#1"],
            # The inline form from .
            "severity_if": [
                "secrets_found and http_status == 200 -> high",
                "file_exists and http_status == 200 -> medium",
            ],
            "confidence": [
                "secrets_found and verified_reproducible -> 0.92",
                "file_exists -> 0.78",
            ],
            "cwe": "CWE-200",
            "remediation": "remediation-catalog/env-file-exposure.yaml",
            "conditions": {
                "secrets_found": {"evidence.http_response.body matches": "AWS_|DB_|SECRET"},
                "file_exists": {"evidence.http_status in": [200]},
                "verified_reproducible": {"evidence.verification_count >= 2": None},
            },
        }
    ],
}


def test_the_spec_rule_shape_is_supported() -> None:
    rules = parse_rule_set(SPEC_RULE, source="spec")
    engine = RuleEngine(rules)
    candidate = make_candidate(
        evidence=(EvidenceFact("http_response", {"status_code": 200, "body": "DB_PASSWORD=x"}),)
    )
    facts = facts_for(
        candidate, verification=VerificationOutcome(count=2, attempted=True, reproducible=True)
    )
    match = engine.evaluate(candidate, facts)
    assert match is not None
    assert match.rule_id == "exposure.env-file"
    assert match.severity == "high"
    assert match.confidence == pytest.approx(0.92)
    assert match.cwe == "CWE-200"
    assert match.remediation_ref == "remediation-catalog/env-file-exposure.yaml"
    assert match.conditions["secrets_found"] is True
    assert match.conditions["file_exists"] is True
    assert match.conditions["verified_reproducible"] is True
    clauses = [entry.clause for entry in match.trace]
    assert "severity_if" in clauses and "confidence" in clauses
    assert any(entry.clause == "condition secrets_found" for entry in match.trace)


def test_the_weaker_clause_fires_when_the_strong_one_does_not() -> None:
    engine = RuleEngine(parse_rule_set(SPEC_RULE))
    candidate = make_candidate(
        evidence=(EvidenceFact("http_response", {"status_code": 200, "body": "nothing here"}),)
    )
    match = engine.evaluate(candidate, facts_for(candidate))
    assert match is not None
    assert match.severity == "medium"
    assert match.confidence == pytest.approx(0.78)


def test_a_rule_without_a_matching_clause_does_not_fire() -> None:
    engine = RuleEngine(parse_rule_set(SPEC_RULE))
    candidate = make_candidate(
        evidence=(EvidenceFact("http_response", {"status_code": 404, "body": "not found"}),)
    )
    assert engine.evaluate(candidate, facts_for(candidate)) is None


def test_the_explicit_clause_form_means_the_same_thing() -> None:
    rules = parse_rule_set(
        {
            "version": "test",
            "rules": [
                {
                    "id": "test.explicit",
                    "title": "Explicit clause form",
                    "check_ref": ["m4.env-file-probe"],
                    "severity_if": [{"when": "http_status == 200", "then": "high"}],
                    "confidence": [{"when": "http_status == 200", "then": 88}],
                }
            ],
        }
    )
    engine = RuleEngine(rules)
    candidate = make_candidate(
        evidence=(EvidenceFact("http_response", {"status_code": 200, "body": "x"}),)
    )
    match = engine.evaluate(candidate, facts_for(candidate))
    assert match is not None
    assert match.severity == "high"
    assert match.confidence == 88


def test_a_default_severity_turns_a_rule_into_a_floor() -> None:
    rules = parse_rule_set(
        {
            "version": "test",
            "rules": [
                {
                    "id": "baseline.m2",
                    "title": "Network baseline",
                    "check_ref": ["M2"],
                    "default_severity": "low",
                }
            ],
        }
    )
    engine = RuleEngine(rules)
    candidate = make_candidate(check_id="m2.smb-enum", check_module="M2", check_name="smb-enum")
    match = engine.evaluate(candidate, facts_for(candidate))
    assert match is not None
    assert match.severity == "low"
    assert match.confidence is None


def test_a_more_specific_rule_beats_a_module_baseline() -> None:
    rules = parse_rule_set(
        {
            "version": "test",
            "rules": [
                {
                    "id": "zzz.baseline",
                    "title": "baseline",
                    "check_ref": ["M2"],
                    "default_severity": "low",
                },
                {
                    "id": "aaa.specific",
                    "title": "specific",
                    "check_ref": ["m2.smb-enum"],
                    "default_severity": "high",
                },
            ],
        }
    )
    engine = RuleEngine(rules)
    candidate = make_candidate(check_id="m2.smb-enum", check_module="M2", check_name="smb-enum")
    match = engine.evaluate(candidate, facts_for(candidate))
    assert match is not None and match.rule_id == "aaa.specific"


@pytest.mark.parametrize(
    ("raw", "kind", "specificity"),
    [
        ("*", "any", 0),
        ("M2", "module", 1),
        ("M2#*", "module", 1),
        ("M2#smb-enum", "check", 4),
        ("m2.smb-enum", "check", 4),
        ("m2.*-enum", "check", 3),
        ("ch02#16", "research", 3),
        ("research:ch02#16", "research", 3),
    ],
)
def test_selector_forms(raw: str, kind: str, specificity: int) -> None:
    selector = RuleSelector.parse(raw, source="test")
    assert selector.kind == kind
    assert selector.specificity == specificity


def test_selectors_match_the_candidates_they_name() -> None:
    candidate = make_candidate(
        check_id="m2.smb-enum", check_module="M2", check_name="smb-enum", research_ref="ch02#16"
    )
    assert RuleSelector.parse("M2", source="t").matches(candidate)
    assert RuleSelector.parse("M2#smb-enum", source="t").matches(candidate)
    assert RuleSelector.parse("m2.*-enum", source="t").matches(candidate)
    assert RuleSelector.parse("research:ch02#16", source="t").matches(candidate)
    assert not RuleSelector.parse("M3", source="t").matches(candidate)
    assert not RuleSelector.parse("m3.sqli", source="t").matches(candidate)
    assert RuleSelector.parse("*", source="t").matches(candidate)


@pytest.mark.parametrize("raw", ["", "M9#x", "M2#", "not-a-check-id", "research:nope"])
def test_invalid_selectors_are_refused(raw: str) -> None:
    with pytest.raises(ConfigurationError):
        RuleSelector.parse(raw, source="test")


def test_a_cyclic_condition_reference_is_refused() -> None:
    rules = parse_rule_set(
        {
            "version": "test",
            "rules": [
                {
                    "id": "test.cycle",
                    "title": "cycle",
                    "check_ref": ["*"],
                    "conditions": {"a": "b", "b": "a"},
                    "default_severity": "low",
                }
            ],
        }
    )
    engine = RuleEngine(rules)
    candidate = make_candidate()
    with pytest.raises(ConfigurationError, match="cyclic"):
        engine.evaluate(candidate, facts_for(candidate))


def test_an_invalid_rule_set_fails_at_load_time() -> None:
    with pytest.raises(ConfigurationError, match="confidence"):
        parse_rule_set(
            {
                "version": "1",
                "rules": [
                    {
                        "id": "test.bad",
                        "title": "bad",
                        "check_ref": ["*"],
                        "severity_if": ["x -> low"],
                        "confidence": ["x -> nonsense"],
                        "default_severity": "low",
                    }
                ],
            }
        )
    with pytest.raises(ConfigurationError, match="duplicate rule id"):
        parse_rule_set(
            {
                "version": "1",
                "rules": [
                    {"id": "aaa", "title": "aaa", "check_ref": ["*"], "default_severity": "low"},
                    {"id": "aaa", "title": "bbb", "check_ref": ["*"], "default_severity": "low"},
                ],
            }
        )


# --------------------------------------------------------------------------- the corpus


def test_the_shipped_corpus_parses_and_is_ranked() -> None:
    rules = load_rule_set()
    assert rules.version
    assert len(rules.rules) >= 30
    ranked = rules.ranked()
    specificities = [rule.specificity for rule in ranked]
    assert specificities == sorted(specificities, reverse=True)
    ids = [rule.id for rule in rules.rules]
    assert len(ids) == len(set(ids))


def test_every_shipped_reference_resolves() -> None:
    """A rule may not point at a remediation or narrative entry that does not exist."""
    rules = load_rule_set()
    catalog = load_remediation_catalog()
    templates = load_narrative_templates()
    for rule in rules.rules:
        if rule.remediation:
            entry_id = ref_to_entry_id(rule.remediation)
            assert catalog.by_id(entry_id) is not None, (rule.id, entry_id)
        if rule.narrative:
            assert templates.by_id(rule.narrative) is not None, (rule.id, rule.narrative)


def test_every_shipped_cwe_is_known_to_the_vector_table() -> None:
    """A CWE no layer of the vector table mentions would silently get the conservative default."""
    from arachne.analyzer.scoring import load_vector_table

    table = load_vector_table()
    rules = load_rule_set()
    for rule in rules.rules:
        if rule.cwe:
            assert rule.cwe in table.by_cwe, (rule.id, rule.cwe)


def test_every_shipped_correlation_signal_has_a_match_key() -> None:
    rules = load_correlation_rules()
    assert rules.rules
    for rule in rules.rules:
        assert rule.min_weak_signals >= 2
        for signal in rule.signals:
            assert any(
                (
                    signal.check,
                    signal.module,
                    signal.cwe,
                    signal.cve,
                    signal.name_token,
                    signal.severity,
                )
            )
    assert len({signal.id for rule in rules.rules for signal in rule.signals}) >= 4


def test_the_rule_model_rejects_an_unknown_severity() -> None:
    with pytest.raises(ValueError, match="unknown severity"):
        Rule(id="x.y", title="a title", check_ref=("*",), default_severity="urgent")


def test_rule_set_exposes_only_enabled_rules() -> None:
    rules = RuleSet.model_validate(
        {
            "version": "1",
            "rules": [
                {"id": "aaa", "title": "aaa", "check_ref": ["*"], "default_severity": "low"},
                {
                    "id": "bbb",
                    "title": "bbb",
                    "check_ref": ["*"],
                    "default_severity": "low",
                    "enabled": False,
                },
            ],
        }
    )
    assert [rule.id for rule in rules.enabled()] == ["aaa"]
