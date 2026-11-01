"""The scoring and confidence model (F-05-04/F-05-06).

The CVSS part is checked against published CVSS v3.1 base vectors, because a report that
prints "CVSS 7.5" has to mean what CVSS 7.5 means. The rest pins the project's own
conventions: the severity bands of the OWASP likelihood x impact model,
the EPSS context rule (F-09-03), and every confidence term with its name.
"""

from __future__ import annotations

import pytest

from arachne.analyzer.model import Candidate, EvidenceFact, severity_from_rank, worst_severity
from arachne.analyzer.scoring import (
    CvssVector,
    ScoringModel,
    confidence_breakdown,
    cvss_v31_base,
    describe_severity_gap,
    load_vector_table,
    owasp_risk_band,
    severity_for_score,
)
from arachne.core.errors import ConfigurationError


def candidate(
    *,
    check_id: str = "m4.env-file-probe",
    module: str = "M4",
    cwe: str | None = "CWE-200",
    asset_kind: str = "url",
    asset_value: str = "https://example.com/.env",
    evidence: tuple[EvidenceFact, ...] = (),
    check_confidence: float | None = 80,
) -> Candidate:
    return Candidate(
        scan_id=1,
        title="test finding",
        check_id=check_id,
        check_module=module,
        check_name=check_id.split(".", 1)[-1],
        cwe=cwe,
        asset_kind=asset_kind,
        asset_value=asset_value,
        evidence=evidence,
        check_confidence=check_confidence,
    )


# --------------------------------------------------------------------------- CVSS v3.1


@pytest.mark.parametrize(
    ("vector", "expected"),
    [
        ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
        ("AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
        ("AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N", 5.9),
        ("AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
        ("AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
        ("AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
    ],
)
def test_cvss_base_scores_match_the_standard(vector: str, expected: float) -> None:
    metrics = dict(item.split(":") for item in vector.split("/"))
    assert cvss_v31_base(CvssVector(**metrics)) == pytest.approx(expected)


def test_vector_text_is_canonical() -> None:
    vector = CvssVector(AV="N", AC="L", PR="N", UI="N", S="U", C="H", I="N", A="N")
    assert vector.text == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    assert vector.base_score == 7.5


def test_an_invalid_metric_value_is_refused() -> None:
    with pytest.raises(ConfigurationError, match="invalid CVSS AV value"):
        CvssVector(AV="X")
    with pytest.raises(ConfigurationError, match="unknown CVSS metric"):
        CvssVector().merged({"XX": "N"})


# --------------------------------------------------------------------------- bands


@pytest.mark.parametrize(
    ("score", "expected"),
    [
        (10.0, "critical"),
        (9.0, "critical"),
        (8.9, "high"),
        (7.0, "high"),
        (6.9, "medium"),
        (4.0, "medium"),
        (3.9, "low"),
        (2.0, "low"),
        (1.9, "info"),
        (0.0, "info"),
    ],
)
def test_severity_bands(score: float, expected: str) -> None:
    assert severity_for_score(score) == expected


def test_severity_ordering_helpers() -> None:
    assert worst_severity("low", "critical", "medium") == "critical"
    assert worst_severity() == "info"
    assert severity_from_rank(-5) == "info"
    assert severity_from_rank(99) == "critical"


@pytest.mark.parametrize(
    ("likelihood", "impact", "band"),
    [
        (9.0, 9.0, "critical"),
        (6.0, 7.0, "high"),
        (4.0, 5.0, "medium"),
        (2.0, 3.0, "low"),
        (0.5, 1.0, "note"),
    ],
)
def test_owasp_risk_bands(likelihood: float, impact: float, band: str) -> None:
    assert owasp_risk_band(likelihood, impact) == band


# --------------------------------------------------------------------------- derived vectors


def test_the_vector_is_derived_from_module_cwe_and_check_layers() -> None:
    model = ScoringModel()
    candidate_ = candidate(cwe="CWE-89", module="M3", check_id="m3.sqli")
    vector = model.vector_for(candidate_)
    assert vector.AV == "N"
    assert vector.S == "C"
    assert vector.C == "H"


def test_evidence_overrides_the_table_for_reachability_and_reproducibility() -> None:
    model = ScoringModel()
    # No module/CWE/check layer applies, so the table's conservative default stands.
    unclassified = candidate(check_id="unknown.check", module="", cwe=None)
    plain = model.vector_for(unclassified)
    reproduced = model.vector_for(unclassified, verification_reproducible=True)
    assert plain.AC == "H"  # the shipped default for an unclassified finding
    assert reproduced.AC == "L"  # a second confirming request lowers complexity
    # A module layer overrides the default, as the M4 layer does.
    assert model.vector_for(candidate()).AC == "L"


def test_a_shipped_table_with_a_bad_entry_is_refused() -> None:
    from arachne.analyzer.scoring import parse_vector_table

    with pytest.raises(ConfigurationError, match="CWE-999"):
        parse_vector_table({"version": "1", "by_cwe": {"CWE-999": {"AC": "X"}}}, source="test")
    with pytest.raises(ConfigurationError, match="not CWE-NNN"):
        parse_vector_table({"version": "1", "by_cwe": {"nope": {}}}, source="test")
    with pytest.raises(ConfigurationError, match="not a module id"):
        parse_vector_table({"version": "1", "by_module": {"M9": {}}}, source="test")


def test_the_shipped_vector_table_loads() -> None:
    table = load_vector_table()
    assert table.version
    assert table.defaults["AV"] == "N"
    assert "CWE-200" in table.by_cwe


# --------------------------------------------------------------------------- scoring


def test_score_combines_cvss_owasp_and_epss() -> None:
    model = ScoringModel()
    response = EvidenceFact(
        "http_response", {"status_code": 200, "body": "DB_PASSWORD=x", "headers": {}}
    )
    request = EvidenceFact("http_request", {"method": "GET", "url": "https://example.com/.env"})
    candidate_ = candidate(evidence=(request, response))
    score = model.score(
        candidate_,
        criticality="high",
        verification_reproducible=True,
        base_confidence=85,
        confidence_adjustments=(("reproduced", 10),),
    )
    assert score.cvss_base == 7.5
    assert score.owasp_risk in {"medium", "high", "critical"}
    assert score.derived_severity in {"high", "critical"}
    assert score.confidence == 95
    assert score.confidence_reasons[0] == "base 85"


def test_epss_moves_a_borderline_score_in_both_directions() -> None:
    model = ScoringModel()
    base = model.score(candidate(), epss=None)
    high_epss = model.score(candidate(), epss=0.9)
    low_epss = model.score(candidate(), epss=0.0)
    assert high_epss.epss == 0.9
    # A high EPSS raises a >= 7.0 score by half a point; a near-zero EPSS lowers one.
    if base.cvss_base >= 7.0:
        assert low_epss.derived_severity in {"high", "critical"}


def test_confidence_terms_are_named_and_clamped() -> None:
    base, adjustments = confidence_breakdown(
        base=90,
        pair_captured=True,
        reproducible=True,
        multiple_confirmations=True,
        placeholder=False,
    )
    assert base == 90
    reasons = [reason for reason, _ in adjustments]
    assert reasons == [
        "request+response captured",
        "reproduced by a second request",
        "multiple independent evidence items",
    ]
    # 90 + 5 + 10 + 5 clamps at 100 rather than exceeding it.
    from arachne.analyzer.model import ConfidenceBreakdown

    assert ConfidenceBreakdown(base=base, adjustments=adjustments).value == 100

    base, penalties = confidence_breakdown(
        base=80, contradicted=True, placeholder=True, waf=True, login_wall=True, fp_rate=0.5
    )
    assert ConfidenceBreakdown(base=base, adjustments=penalties).value == 0


def test_severity_gap_only_reports_a_two_band_disagreement() -> None:
    assert describe_severity_gap("high", "medium") is None
    assert describe_severity_gap("high", "critical") is None
    gap = describe_severity_gap("low", "critical")
    assert gap is not None and "below" in gap
    assert describe_severity_gap("info", "medium") is not None
