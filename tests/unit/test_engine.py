"""The heuristic engine end to end (F-03-01, F-05-01..07).

These are the tests that state the contract: a candidate goes in, an ``Analysis`` with a
severity, a confidence, a CWE, a narrative and a remediation comes out — deterministically,
with no network and no model — and the FP policies decide when a candidate is dropped.
"""

from __future__ import annotations

import pytest

from arachne.analyzer.engine import (
    AnalysisPolicies,
    HeuristicEngine,
    engine_is_available,
    merged_evidence,
    rule_ids,
    select_engine,
    severity_histogram,
    signature_ids,
    summarize,
)
from arachne.analyzer.model import (
    Candidate,
    EvidenceFact,
    FpStats,
    ScanContext,
    VerificationOutcome,
)
from arachne.analyzer.signatures import SignatureLibrary
from arachne.core.errors import ConfigurationError


def env_candidate(**overrides: object) -> Candidate:
    base = {
        "scan_id": 1,
        "title": "Sensitive environment file exposed",
        "finding_id": 7,
        "check_id": "m4.env-file-probe",
        "check_module": "M4",
        "check_name": "env-file-probe",
        "check_version": "1.0",
        "research_ref": "ch04#1",
        "cwe": "CWE-200",
        "severity_hint": "high",
        "verifiable": True,
        "check_confidence": 80,
        "asset_kind": "url",
        "asset_value": "https://target.example/.env",
        "evidence": (
            EvidenceFact(
                "http_request",
                {"method": "GET", "url": "https://target.example/.env"},
                source="https://target.example/.env",
                id=1,
            ),
            EvidenceFact(
                "http_response",
                {
                    "status_code": 200,
                    "headers": {"content-type": "text/plain"},
                    "body": "AWS_ACCESS_KEY_ID=AKIA\nDB_PASSWORD=hunter2\nSECRET=abc",
                },
                source="https://target.example/.env",
                id=2,
            ),
            EvidenceFact("note", {"detail": "3 key-value pairs matched"}, id=3),
            # The artifact an M4 check attaches; ``exposure.env-file`` reads it as facts
            # (ADR-120.11) rather than re-deriving the verdict from the response body.
            EvidenceFact(
                "artifact",
                {
                    "signal": "exposed-env-file",
                    "family": "env",
                    "path": "/.env",
                    "status": 200,
                    "bytes": 48,
                    "marker": False,
                    "assignment_count": 3,
                    "assignment_keys": ["AWS_ACCESS_KEY_ID", "DB_PASSWORD", "SECRET"],
                    "detectors": ["aws-access-key"],
                },
                source="https://target.example/.env",
                id=4,
            ),
        ),
    }
    base.update(overrides)
    return Candidate(**base)  # type: ignore[arg-type]


def context(**overrides: object) -> ScanContext:
    base: dict[str, object] = {"scan_id": 1}
    base.update(overrides)
    return ScanContext(**base)  # type: ignore[arg-type]


@pytest.fixture
def engine() -> HeuristicEngine:
    return HeuristicEngine(signatures=SignatureLibrary.load())


def test_a_candidate_becomes_an_analyzed_finding(engine: HeuristicEngine) -> None:
    """DONE criterion 1: severity, confidence, CWE, narrative and remediation all present."""
    candidate = env_candidate()
    analysis = engine.analyze_one(
        candidate,
        context(
            verification={
                candidate.key: VerificationOutcome(count=2, attempted=True, reproducible=True)
            }
        ),
    )
    assert analysis.severity == "high"
    assert 0 < analysis.confidence <= 100
    assert analysis.cwe == "CWE-200"
    assert analysis.check_id == "m4.env-file-probe"
    assert analysis.finding_id == 7
    assert analysis.asset == "url:https://target.example/.env"
    assert analysis.remediation.id == "env-file-exposure"
    assert analysis.remediation.steps
    assert "HTTP 200" in analysis.narrative
    assert "Credential" in analysis.narrative or "credential" in analysis.narrative
    assert analysis.provenance.engine == "heuristic"
    assert analysis.provenance.rule_ids == ("exposure.env-file",)
    assert analysis.provenance.template_version
    assert analysis.score.cvss_base > 0
    assert analysis.score.owasp_risk in {"low", "medium", "high", "critical"}
    assert analysis.verdict == "analyzed"
    # Verifiable + reproduced => verified status (F-05-07).
    assert analysis.verified is True
    assert analysis.status == "verified"
    assert analysis.rule_trace


def test_the_signature_engine_participates_in_the_verdict(engine: HeuristicEngine) -> None:
    analysis = engine.analyze_one(env_candidate(), context())
    assert "exposed-env-file" in analysis.signatures
    assert "exposure.env-file" in analysis.provenance.rule_ids


def test_an_unclassified_candidate_still_gets_a_full_analysis(engine: HeuristicEngine) -> None:
    candidate = Candidate(
        scan_id=1,
        title="something a check reported",
        finding_id=1,
        check_id="m9.unknown-check",
        check_module="M9",
        check_name="unknown-check",
        severity_hint="medium",
        asset_kind="host",
        asset_value="10.0.0.9",
        evidence=(EvidenceFact("note", {"detail": "x"}),),
    )
    analysis = engine.analyze_one(candidate, context())
    assert analysis.severity in {"medium", "high"}
    assert analysis.narrative
    assert analysis.remediation.id  # never without an action
    assert analysis.score.cvss_base >= 0


def test_a_verification_contradiction_drops_the_finding(engine: HeuristicEngine) -> None:
    candidate = env_candidate()
    analysis = engine.analyze_one(
        candidate,
        context(
            verification={
                candidate.key: VerificationOutcome(
                    count=1,
                    attempted=True,
                    contradicted=True,
                    detail="re-request returned HTTP 404, the original capture recorded HTTP 200",
                )
            }
        ),
    )
    assert analysis.verdict == "dropped"
    assert analysis.status == "fp"
    assert "404" in (analysis.drop_reason or "")
    assert analysis.confidence < 90


def test_the_drop_on_contradiction_policy_can_be_turned_off() -> None:
    engine = HeuristicEngine(
        signatures=SignatureLibrary.load(),
        policies=AnalysisPolicies(drop_on_contradiction=False),
    )
    candidate = env_candidate()
    analysis = engine.analyze_one(
        candidate,
        context(
            verification={
                candidate.key: VerificationOutcome(count=1, attempted=True, contradicted=True)
            }
        ),
    )
    assert analysis.verdict == "analyzed"


def test_a_placeholder_page_is_dropped_when_it_is_the_whole_evidence(
    engine: HeuristicEngine,
) -> None:
    candidate = Candidate(
        scan_id=1,
        title="backup file downloaded",
        finding_id=2,
        check_id="m4.backup-probe",
        check_module="M4",
        check_name="backup-probe",
        cwe="CWE-530",
        severity_hint="medium",
        asset_kind="url",
        asset_value="https://example.com/index.php.bak",
        evidence=(
            EvidenceFact(
                "http_response",
                {"status_code": 200, "headers": {}, "body": "Welcome to nginx!"},
                source="https://example.com/index.php.bak",
            ),
        ),
    )
    analysis = engine.analyze_one(candidate, context())
    assert analysis.verdict == "dropped"
    assert "placeholder" in (analysis.drop_reason or "")


def test_a_waf_challenge_only_lowers_confidence(engine: HeuristicEngine) -> None:
    candidate = env_candidate(
        evidence=(
            EvidenceFact("http_request", {"method": "GET"}, source="https://target.example/.env"),
            EvidenceFact(
                "http_response",
                {
                    "status_code": 200,
                    "headers": {},
                    "body": "<html>Just a moment... checking your browser</html>",
                },
                source="https://target.example/.env",
            ),
            EvidenceFact("note", {"detail": "x"}),
        )
    )
    analysis = engine.analyze_one(candidate, context())
    assert analysis.verdict == "analyzed"
    assert "waf" in analysis.risk_notes.lower()


def test_operator_feedback_raises_the_bar(engine: HeuristicEngine) -> None:
    candidate = env_candidate()
    key = candidate.key
    analysis = engine.analyze_one(
        candidate, context(fp={key: FpStats(total=10, false_positives=10)})
    )
    assert any("operator FP rate" in reason for reason in analysis.score.confidence_reasons)
    assert analysis.confidence < 90


def test_criticality_raises_the_owasp_impact(engine: HeuristicEngine) -> None:
    candidate = env_candidate()
    normal = engine.analyze_one(candidate, context())
    critical = engine.analyze_one(
        candidate, context(asset_criticality={candidate.asset_value: "critical"})
    )
    assert critical.score.owasp_impact > normal.score.owasp_impact


def test_the_engine_is_deterministic(engine: HeuristicEngine) -> None:
    candidate = env_candidate()
    first = engine.analyze_one(candidate, context())
    second = engine.analyze_one(candidate, context())
    assert first == second


def test_the_engine_never_touches_the_network(engine: HeuristicEngine) -> None:
    """``analyze`` is pure: a ScanContext with no verifier input still produces everything."""
    candidate = env_candidate()
    analyses = engine.analyze((candidate,), context())
    assert len(analyses) == 1


def test_engine_selection_is_explicit() -> None:
    assert engine_is_available("heuristic")
    assert engine_is_available("hybrid")
    # ``ai`` is available exactly when a provider is configured (F-03-03).
    assert not engine_is_available("ai")
    assert engine_is_available("ai", ai_available=True)
    assert select_engine("heuristic").name == "heuristic"
    assert select_engine("hybrid").name == "heuristic"
    with pytest.raises(ConfigurationError, match="not configured"):
        select_engine("ai")
    with pytest.raises(ConfigurationError, match="unknown engine"):
        select_engine("magic")


def test_hybrid_prefers_the_ai_engine_when_one_is_configured() -> None:
    """: hybrid is heuristics + AI when AI is configured, heuristics alone else."""
    stub = _StubEngine("ai")
    heuristic = HeuristicEngine()
    assert select_engine("hybrid", heuristic=heuristic, ai=stub) is stub
    assert select_engine("ai", ai=stub) is stub
    assert select_engine("hybrid", heuristic=heuristic) is heuristic


class _StubEngine:
    """A minimal ``Analyzer`` used only to prove which engine the selector returned."""

    def __init__(self, name: str) -> None:
        self.name = name

    def analyze(self, candidates: object, context: object) -> tuple[object, ...]:
        del candidates, context
        return ()


def test_summary_and_histogram_helpers(engine: HeuristicEngine) -> None:
    candidates = (env_candidate(), env_candidate(finding_id=8, check_id="m1.js-asset-scan"))
    ctx = context()
    analyses = engine.analyze(candidates, ctx)
    summary = summarize(analyses, candidates, ctx, minimum_confidence=55)
    assert summary.candidates == 2
    assert summary.analyzed + summary.dropped == 2
    assert summary.severities
    assert isinstance(severity_histogram(analyses), dict)
    assert isinstance(rule_ids(analyses), tuple)
    assert isinstance(signature_ids(analyses), tuple)
    # A merged list deduplicates by (kind, sha256, source), so the two identical .env
    # candidates contribute their evidence once (request, response, note, artifact).
    assert len(merged_evidence(candidates)) == 4
    stats = summary.to_stats()
    assert stats["candidates_analyzed"] == 2


def test_a_low_confidence_finding_is_flagged(engine: HeuristicEngine) -> None:
    candidate = Candidate(
        scan_id=1,
        title="weak signal",
        finding_id=1,
        check_id="m1.email-harvest",
        check_module="M1",
        check_name="email-harvest",
        cwe="CWE-200",
        severity_hint="info",
        check_confidence=20,
        asset_kind="domain",
        asset_value="example.com",
        evidence=(EvidenceFact("artifact", {"pattern": "{first}.{last}@example.com"}),),
    )
    analysis = engine.analyze_one(candidate, context())
    assert "low-confidence observation" in analysis.risk_notes
