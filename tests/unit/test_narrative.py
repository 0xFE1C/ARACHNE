"""Explanation synthesis (F-05-05).

The narrative is generated, never written by a model, and it must always exist: these tests
pin the interpolation rules (drop an unresolvable section, step aside when it is required),
the fallback synthesis, template selection by specificity, and that a template cannot reach
into Python objects through a placeholder.
"""

from __future__ import annotations

import pytest

from arachne.analyzer.conditions import build_facts
from arachne.analyzer.model import (
    Candidate,
    Provenance,
    Remediation,
    ScoreBreakdown,
)
from arachne.analyzer.narrative import (
    NarrativeSynthesizer,
    TemplateSet,
    confidence_band,
    load_narrative_templates,
    parse_narrative_templates,
    provenance_for,
)
from arachne.core.errors import ConfigurationError

REMEDIATION = Remediation(
    id="env-file-exposure",
    summary="Block the file and rotate the credentials.",
    steps=("1. Deny /.env",),
)


def make_candidate(**overrides: object) -> Candidate:
    base = {
        "scan_id": 1,
        "title": "Sensitive environment file exposed",
        "finding_id": 9,
        "check_id": "m4.env-file-probe",
        "check_module": "M4",
        "check_name": "env-file-probe",
        "research_ref": "ch04#1",
        "cwe": "CWE-200",
        "asset_kind": "url",
        "asset_value": "https://example.com/.env",
    }
    base.update(overrides)
    return Candidate(**base)  # type: ignore[arg-type]


def templates(*items: object) -> TemplateSet:
    return parse_narrative_templates({"version": "test", "templates": list(items)})


def render(
    synthesizer: NarrativeSynthesizer,
    candidate: Candidate,
    *,
    severity: str = "high",
    confidence: int = 90,
    template_id: str | None = None,
    signatures: tuple[str, ...] = (),
) -> str:
    facts = build_facts(
        candidate,
        verification=None,
        signatures=signatures,
        criticality="high",
    )
    return synthesizer.render(
        candidate,
        severity=severity,
        confidence=confidence,
        score=ScoreBreakdown(
            cvss_base=7.5,
            owasp_risk="high",
            confidence=confidence,
            confidence_reasons=("base 80", "reproduced by a second request +10"),
        ),
        remediation=REMEDIATION,
        facts=facts,
        signatures=signatures,
        template_id=template_id,
    ).text


def test_a_template_interpolates_facts_and_computed_values() -> None:
    synthesizer = NarrativeSynthesizer(
        templates(
            {
                "id": "test.one",
                "match": {"check": ["m4.env-file-probe"]},
                "sections": [
                    {
                        "text": "{title} at {asset.value} — {severity}, confidence "
                        "{confidence.value} ({confidence.band}), CVSS {score.cvss}."
                    },
                    {"text": "Research: {research_ref}."},
                ],
            }
        )
    )
    text = render(synthesizer, make_candidate())
    assert "at url:https://example.com/.env" in text or "https://example.com/.env" in text
    assert "high, confidence 90 (high)" in text
    assert "CVSS 7.5" in text
    assert "Research: ch04#1" in text


def test_an_unresolvable_section_is_dropped() -> None:
    synthesizer = NarrativeSynthesizer(
        templates(
            {
                "id": "test.optional",
                "match": {"check": ["m4.env-file-probe"]},
                "sections": [
                    {"text": "Always rendered: {title}."},
                    {"text": "This needs {evidence.artifact.does_not_exist}."},
                ],
            }
        )
    )
    text = render(synthesizer, make_candidate())
    assert text.startswith("Always rendered:")
    assert "does_not_exist" not in text


def test_a_required_section_makes_the_template_step_aside() -> None:
    synthesizer = NarrativeSynthesizer(
        templates(
            {
                "id": "test.required",
                "match": {"check": ["m4.*"], "severity": ["high"]},
                "sections": [
                    {"text": "Needs {evidence.artifact.missing}", "required": True},
                ],
            },
            {
                "id": "test.fallback",
                "match": {"check": ["m4.*"]},
                "sections": [{"text": "Second choice for {title}."}],
            },
        )
    )
    text = render(synthesizer, make_candidate())
    assert text == "Second choice for Sensitive environment file exposed."


def test_the_most_specific_template_wins() -> None:
    synthesizer = NarrativeSynthesizer(
        templates(
            {
                "id": "test.generic",
                "match": {},
                "sections": [{"text": "generic"}],
            },
            {
                "id": "test.specific",
                "match": {"check": ["m4.env-file-probe"], "severity": ["high"]},
                "sections": [{"text": "specific"}],
            },
        )
    )
    assert render(synthesizer, make_candidate()) == "specific"


def test_a_pinned_template_is_used_verbatim() -> None:
    synthesizer = NarrativeSynthesizer(
        templates(
            {
                "id": "test.pinned",
                "match": {"check": ["nothing.matches"]},
                "sections": [{"text": "pinned for {title}"}],
            }
        )
    )
    assert render(synthesizer, make_candidate(), template_id="test.pinned") == (
        "pinned for Sensitive environment file exposed"
    )


def test_a_missing_pinned_template_falls_back_to_the_builtin_synthesis() -> None:
    synthesizer = NarrativeSynthesizer(
        templates({"id": "test.other", "match": {}, "sections": [{"text": "other"}]})
    )
    text = render(synthesizer, make_candidate(), template_id="test.does-not-exist")
    # The built-in synthesis always describes the finding, its rating and the action.
    assert "Sensitive environment file exposed" in text
    assert "high" in text
    assert "Block the file and rotate the credentials." in text


def test_conditional_sections_read_the_rules_conditions() -> None:
    candidate = make_candidate(
        check_id="m4.env-file-probe",
        cwe="CWE-200",
    )
    synthesizer = NarrativeSynthesizer(
        templates(
            {
                "id": "test.conditional",
                "match": {"check": ["m4.env-file-probe"]},
                "sections": [
                    {"text": "base."},
                    {"text": "with secrets.", "when": "secrets_found"},
                ],
            }
        )
    )
    facts = build_facts(candidate)
    rendered = synthesizer.render(
        candidate,
        severity="high",
        confidence=90,
        score=ScoreBreakdown(),
        remediation=REMEDIATION,
        facts=facts,
        conditions={"secrets_found": True},
    )
    assert rendered.text == "base. with secrets."


def test_interpolation_cannot_reach_into_python_objects() -> None:
    """``{0.__class__}``-style references are not expressions here; they stay literal text."""
    synthesizer = NarrativeSynthesizer(
        templates(
            {
                "id": "test.injection",
                "match": {},
                "sections": [{"text": "safe {0.__class__} text"}],
            }
        )
    )
    text = render(synthesizer, make_candidate())
    assert "{0.__class__}" in text
    assert "type" not in text


def test_a_broken_template_is_a_load_error() -> None:
    with pytest.raises(ConfigurationError, match="unknown match key"):
        templates({"id": "test.bad", "match": {"nonsense": ["x"]}, "sections": [{"text": "x"}]})
    with pytest.raises(ConfigurationError, match="sections"):
        templates({"id": "test.bad", "match": {}, "sections": []})


def test_the_shipped_corpus_loads_and_covers_the_generic_case() -> None:
    corpus = load_narrative_templates()
    assert corpus.version
    assert corpus.by_id("generic.finding") is not None
    assert corpus.by_id("baseline.generic") is not None
    ranked = corpus.ranked()
    # The generic template must be the least specific, i.e. last.
    assert ranked[-1].id == "generic.finding"


def test_confidence_bands() -> None:
    assert confidence_band(100) == "high"
    assert confidence_band(85) == "high"
    assert confidence_band(84) == "moderate"
    assert confidence_band(70) == "moderate"
    assert confidence_band(69) == "fair"
    assert confidence_band(55) == "fair"
    assert confidence_band(54) == "low"


def test_provenance_records_the_template() -> None:
    provenance = provenance_for(
        type("N", (), {"text": "", "template_id": "t", "template_version": "v"})()  # type: ignore[arg-type]
    )
    assert isinstance(provenance, Provenance)
    assert provenance.template_version == "v"
    assert provenance.prompt_template == "t"
    assert provenance.engine == "heuristic"


def test_a_multi_valued_fact_renders_as_a_list_not_its_first_element() -> None:
    """A template citing several values (missing headers, enumerated identifiers) says them all.

    ``FactSpace.get`` yields a path's *first* value, which is the right thing for a comparison
    and the wrong thing for prose: "missing content-security-policy" when four headers are
    absent reads as though the other three are present.
    """
    from arachne.analyzer.conditions import FactSpace
    from arachne.analyzer.narrative import _Namespace

    facts = FactSpace(
        {"evidence": {"artifact": {"missing": ["csp", "hsts"], "one": "x", "empty": []}}}
    )
    namespace = _Namespace({}, facts)
    assert namespace.resolve("evidence.artifact.missing") == "csp, hsts"
    assert namespace.resolve("evidence.artifact.one") == "x"
    assert namespace.resolve("evidence.artifact.empty") is None
    assert namespace.resolve("evidence.artifact.absent") is None
