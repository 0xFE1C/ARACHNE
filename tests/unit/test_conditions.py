"""The restricted condition language (F-08-06).

The language is a security boundary: rule authors write expressions, and the scanner must
never execute them. These tests pin the grammar, the any-semantics of a multi-valued fact,
the presence operators, and the failure modes (a bad expression is a load-time error, never
a silent "no match").
"""

from __future__ import annotations

import pytest

from arachne.analyzer.conditions import (
    ALIASES,
    ConditionError,
    FactSpace,
    parse_expression,
)
from arachne.analyzer.model import Candidate, EvidenceFact, VerificationOutcome


def facts(**overrides: object) -> FactSpace:
    base = {
        "check": {"id": "m4.env-file-probe", "module": "M4", "cwe": "CWE-200"},
        "asset": {"kind": "url", "value": "https://example.com/.env"},
        "finding": {"title": "Sensitive environment file exposed"},
        "analysis": {"verification_count": 2, "reproducible": True},
        "evidence": {
            "http_response": {"status_code": 200, "body": "DB_PASSWORD=s3cret"},
            "count": {"http_response": 1},
        },
    }
    base.update(overrides)
    return FactSpace(base)


# --------------------------------------------------------------------------- truthiness


@pytest.mark.parametrize(
    ("expression", "expected"),
    [
        ("http_status == 200", True),
        ("http_status == 404", False),
        ("http_status != 404", True),
        ("http_status >= 200", True),
        ("http_status > 200", False),
        ("http_status < 300", True),
        ("http_status in [200, 201]", True),
        ("http_status not in [500, 502]", True),
        ("verification_count >= 2", True),
        ("reproducible", True),
        ("not reproducible", False),
        ("reproducible and http_status == 200", True),
        ("reproducible and http_status == 404", False),
        ("reproducible or http_status == 404", True),
        ('evidence.http_response.body matches "DB_PASSWORD"', True),
        ('evidence.http_response.body matches "^AWS_"', False),
        ('evidence.http_response.body contains "s3cret"', True),
        ('evidence.http_response.body startswith "DB"', True),
        ('evidence.http_response.body endswith "s3cret"', True),
        ('check.module == "M4"', True),
        ('module == "M4"', True),
        ('asset_kind == "url"', True),
        ('title contains "environment"', True),
        ('title contains "nonexistent"', False),
        ('title matches "(?i)environment"', True),
        ("evidence.http_response", True),
        ("evidence.note", False),
        ("not evidence.note", True),
    ],
)
def test_expressions_evaluate_as_documented(expression: str, expected: bool) -> None:
    assert parse_expression(expression).evaluate(facts()) is expected


def test_a_missing_fact_satisfies_nothing() -> None:
    """A rule must never fire on a fact the candidate does not have ."""
    space = facts()
    for expression in (
        "evidence.artifact.cvss >= 7.0",
        "evidence.artifact.cvss != 7.0",
        "evidence.artifact.matches in [1]",
        'evidence.artifact.body matches ".*"',
        'evidence.artifact.body contains "x"',
    ):
        assert parse_expression(expression).evaluate(space) is False, expression


def test_presence_operators_ask_about_absence() -> None:
    space = facts()
    assert parse_expression("evidence.http_response.body present").evaluate(space) is True
    assert parse_expression("evidence.http_response.body missing").evaluate(space) is False
    assert parse_expression("evidence.missing_header missing").evaluate(space) is True
    assert parse_expression("evidence.missing_header present").evaluate(space) is False


def test_any_semantics_over_multiple_evidence_rows() -> None:
    """Three ``artifact`` rows compare with "any", which is what a rule author expects."""
    space = FactSpace(
        {
            "evidence": {
                "artifact": [
                    {"cvss": 5.0, "cve": "CVE-2020-0001"},
                    {"cvss": 9.8, "cve": "CVE-2021-0002"},
                ]
            }
        }
    )
    assert parse_expression("evidence.artifact.cvss >= 9.0").evaluate(space) is True
    assert parse_expression("evidence.artifact.cvss >= 9.9").evaluate(space) is False
    assert parse_expression('evidence.artifact.cve == "CVE-2021-0002"').evaluate(space) is True


def test_parenthesised_sub_expressions_and_precedence() -> None:
    space = facts()
    assert parse_expression("http_status == 200 and (reproducible or http_status == 404)").evaluate(
        space
    )
    assert not parse_expression(
        "(http_status == 200 and reproducible) and http_status == 404"
    ).evaluate(space)
    # ``not`` binds tighter than ``and``, which binds tighter than ``or``.
    assert parse_expression("not http_status == 404 and http_status == 200").evaluate(space)


def test_rule_local_conditions_resolve_before_facts() -> None:
    """A named condition shadows a fact alias of the same name ."""
    space = facts()
    expression = parse_expression("reproducible")
    assert expression.evaluate(space, {"reproducible": False}) is False


# --------------------------------------------------------------------------- literals


def test_literal_forms() -> None:
    space = FactSpace({"x": {"int": 2, "float": 2.5, "text": "abc", "flag": True, "none": None}})
    assert parse_expression("x.int == 2").evaluate(space)
    assert parse_expression("x.float > 2.4").evaluate(space)
    assert parse_expression('x.text == "abc"').evaluate(space)
    assert parse_expression("x.text == 'abc'").evaluate(space)
    assert parse_expression("x.flag == true").evaluate(space)
    assert parse_expression("x.none == null").evaluate(space)
    assert parse_expression("x.int in [1, 2, 3]").evaluate(space)


# --------------------------------------------------------------------------- errors


@pytest.mark.parametrize(
    "expression",
    [
        "",
        "   ",
        "http_status ==",
        "http_status = 200",
        "(http_status == 200",
        "http_status == 200 and",
        "path[0] == 1",
        "x not 3",
        "x missing extra",
        '"unterminated',
    ],
)
def test_invalid_expressions_raise(expression: str) -> None:
    with pytest.raises(ConditionError):
        parse_expression(expression)


def test_an_over_long_regex_is_refused() -> None:
    with pytest.raises(ConditionError, match="characters long"):
        parse_expression('evidence.http_response.body matches "{}"'.format("a" * 501)).evaluate(
            facts()
        )


def test_an_invalid_regex_is_refused() -> None:
    with pytest.raises(ConditionError, match="invalid regex"):
        parse_expression('body matches "([unclosed"').evaluate(FactSpace({"body": "x"}))


# --------------------------------------------------------------------------- fact builder


def test_build_facts_exposes_evidence_analysis_and_aliases() -> None:
    from arachne.analyzer.conditions import build_facts

    candidate = Candidate(
        scan_id=1,
        title="Sensitive environment file exposed",
        check_id="m4.env-file-probe",
        check_module="M4",
        check_name="env-file-probe",
        research_ref="ch04#1",
        cwe="CWE-200",
        severity_hint="high",
        verifiable=True,
        check_confidence=80,
        asset_kind="url",
        asset_value="https://example.com/.env",
        evidence=(
            EvidenceFact("http_request", {"method": "GET", "url": "https://example.com/.env"}),
            EvidenceFact(
                "http_response", {"status_code": 200, "body": "DB_PASSWORD=s3cret", "headers": {}}
            ),
        ),
    )
    space = build_facts(
        candidate,
        criticality="high",
        verification=VerificationOutcome(count=2, attempted=True, reproducible=True),
        signatures=("exposed-env-file",),
    )
    assert space.get("check.id") == "m4.env-file-probe"
    assert space.get("check.research_ref") == "ch04#1"
    assert space.get("asset.criticality") == "high"
    assert space.get("asset.host") == "example.com"
    assert space.get("analysis.verification_count") == 2
    assert space.get("analysis.reproducible") is True
    assert space.get("analysis.has_request") is True
    assert space.values("analysis.evidence_kinds") == ["http_request", "http_response"]
    assert space.get("derived.http_status") == 200
    assert space.get("derived.body_bytes") == len("DB_PASSWORD=s3cret")
    assert space.values("signature.matched") == ["exposed-env-file"]
    assert space.get("finding.confidence") == 80
    # Every alias resolves to a fact the expression language can read.
    for alias in ("http_status", "verification_count", "asset_kind", "research_ref", "title"):
        assert space.get(alias) is not None
        assert alias in ALIASES
