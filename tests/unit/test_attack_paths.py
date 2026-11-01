"""Attack-path composition (REQ-AGENT-003): verified hops only, terminal impact, cheapest break.

The requirement's four properties are each a test here, because each one is a way the feature
could lie: composing a chain from unverified findings, reporting a chain's worst hop instead of
what it achieves, hiding the unverified link, or recommending a fix that does not break the
chain. The composition is pure, so these tests are synthetic and precise.
"""

from __future__ import annotations

from typing import Any

from arachne.analyzer.model import Analysis, Provenance, Remediation, ScoreBreakdown
from arachne.analyzer.paths import (
    AttackStage,
    build_attack_paths,
    cheapest_break,
    host_of,
    stage_for,
)


def _analysis(
    finding_id: int,
    *,
    check_id: str,
    asset: str,
    cwe: str | None,
    severity: str = "high",
    confidence: int = 90,
    verified: bool = False,
    verdict: str = "analyzed",
    steps: int = 2,
    remediation_id: str | None = "fix-it",
) -> Analysis:
    return Analysis(
        title=f"{check_id} on {asset}",
        severity=severity,
        confidence=confidence,
        finding_id=finding_id,
        check_id=check_id,
        asset=asset,
        cwe=cwe,
        narrative="because",
        verdict=verdict,
        verified=verified,
        score=ScoreBreakdown(cvss_base=7.5, owasp_risk="high", confidence=confidence),
        provenance=Provenance(engine="heuristic"),
        remediation=Remediation(
            id=remediation_id if remediation_id is not None else "",
            summary="Harden it",
            steps=tuple(f"step {number}" for number in range(1, steps + 1)),
        ),
    )


def test_stages_come_from_the_weakness_class_then_the_severity() -> None:
    assert stage_for("CWE-200", "critical") is AttackStage.EXPOSURE
    assert stage_for("CWE-798", "low") is AttackStage.CREDENTIALS
    assert stage_for("CWE-306", "low") is AttackStage.ACCESS
    assert stage_for("CWE-89", "low") is AttackStage.EXECUTION
    assert stage_for("CWE-269", "low") is AttackStage.IMPACT
    # An unknown class falls back to the severity rather than guessing.
    assert stage_for("CWE-99999", "medium") is AttackStage.ACCESS
    assert stage_for(None, "critical") is AttackStage.IMPACT


def test_host_grouping_walks_one_application() -> None:
    assert host_of("https://target.example/admin") == "target.example"
    assert host_of("10.0.0.5") == "10.0.0.5"
    assert host_of("cloud:aws/123") == "cloud:aws/123"


def test_a_two_hop_path_is_composed_and_its_severity_is_the_terminal_impact() -> None:
    analyses = [
        _analysis(
            1, check_id="m4.env-file-probe", asset="https://target.example/.env",
            cwe="CWE-200", severity="medium", confidence=88,
        ),
        _analysis(
            2, check_id="m4.dashboard-exposure", asset="https://target.example/admin",
            cwe="CWE-306", severity="critical", confidence=95,
        ),
    ]
    paths = build_attack_paths(analyses)
    assert len(paths) == 1
    path = paths[0]
    assert path.asset == "target.example"
    assert [hop.stage for hop in path.hops] == [AttackStage.EXPOSURE, AttackStage.ACCESS]
    # The chain achieves what its last step achieves — the critical dashboard, not the medium
    # exposure that led to it.
    assert path.severity == "critical"
    assert path.fully_verified
    assert all(hop.verified for hop in path.hops)
    assert path.narrative().startswith("target.example: exposure → access")


def test_a_chain_cannot_run_backwards_or_stay_flat() -> None:
    analyses = [
        _analysis(1, check_id="m3.sqli-oracle", asset="https://t.example/a", cwe="CWE-89"),
        _analysis(2, check_id="m3.xss-oracle", asset="https://t.example/b", cwe="CWE-79"),
    ]
    # Two different execution-class findings are alternatives, not steps: no path.
    assert build_attack_paths(analyses) == ()


def test_the_chain_can_start_later_and_still_be_a_path() -> None:
    analyses = [
        _analysis(1, check_id="m3.idor-oracle", asset="https://t.example/api", cwe="CWE-639"),
        _analysis(2, check_id="m3.rce-echo", asset="https://t.example/api", cwe="CWE-78"),
    ]
    paths = build_attack_paths(analyses)
    assert len(paths) == 1
    assert [hop.stage for hop in paths[0].hops] == [AttackStage.ACCESS, AttackStage.EXECUTION]


def test_an_unverified_finding_is_a_candidate_hop_naming_its_verifying_check() -> None:
    analyses = [
        _analysis(
            1, check_id="m4.env-file-probe", asset="https://t.example/.env", cwe="CWE-200",
            confidence=40,
        ),
        _analysis(
            2, check_id="m4.dashboard-exposure", asset="https://t.example/admin",
            cwe="CWE-306",
        ),
    ]
    path = build_attack_paths(analyses)[0]
    candidate = path.candidate_hops[0]
    assert not candidate.verified
    assert candidate.verifying_check == "m4.env-file-probe"
    assert candidate.check_id == "m4.env-file-probe"
    assert not path.fully_verified
    assert path.verified_hops and path.verified_hops[0].verifying_check is None


def test_a_stored_candidate_without_an_analysis_becomes_a_candidate_hop() -> None:
    class Row:
        id = 7
        check_key = "M3/sqli-oracle@1.0"
        title = "SQL injection"
        asset_value = "https://t.example/product"
        severity = "high"
        confidence = 70
        evidence: tuple[Any, ...] = ()

    analyses = [
        _analysis(2, check_id="m3.rce-echo", asset="https://t.example/product", cwe="CWE-269"),
    ]
    path = build_attack_paths(analyses, [Row()])[0]
    candidate = [hop for hop in path.hops if not hop.verified]
    assert candidate and candidate[0].check_id == "m3.sqli-oracle"
    assert candidate[0].finding_id == 7
    assert candidate[0].verifying_check == "m3.sqli-oracle"


def test_a_dropped_finding_is_never_a_hop() -> None:
    analyses = [
        _analysis(
            1, check_id="m4.env-file-probe", asset="https://t.example/.env", cwe="CWE-200",
            verdict="dropped",
        ),
        _analysis(
            2, check_id="m4.dashboard-exposure", asset="https://t.example/admin",
            cwe="CWE-306",
        ),
    ]
    assert build_attack_paths(analyses) == ()


def test_the_cheapest_break_prefers_a_verified_cheap_early_hop() -> None:
    hops = build_attack_paths(
        [
            _analysis(
                1, check_id="m4.env-file-probe", asset="https://t.example/.env", cwe="CWE-200",
                steps=2,
            ),
            _analysis(
                2, check_id="m4.dashboard-exposure", asset="https://t.example/admin",
                cwe="CWE-306", steps=9,
            ),
        ]
    )[0].hops
    cheapest, reason = cheapest_break(hops)
    assert cheapest is not None and cheapest.check_id == "m4.env-file-probe"
    assert "verified hop" in reason


def test_the_cheapest_break_prefers_a_verified_hop_over_a_candidate_one() -> None:
    verified = _analysis(1, check_id="m3.a", asset="a", cwe="CWE-89", steps=6)
    candidate = _analysis(2, check_id="m3.b", asset="a", cwe="CWE-269", confidence=10, steps=1)
    cheapest, reason = cheapest_break(
        tuple(build_attack_paths([verified, candidate])[0].hops)
    )
    assert cheapest is not None and cheapest.check_id == "m3.a"
    assert "verified hop" in reason


def test_a_path_with_no_catalogued_remediation_says_so() -> None:
    analyses = [
        _analysis(1, check_id="m4.a", asset="https://t.example/x", cwe="CWE-200",
                  remediation_id=None),
        _analysis(2, check_id="m4.b", asset="https://t.example/y", cwe="CWE-306",
                  remediation_id=None),
    ]
    path = build_attack_paths(analyses)[0]
    assert path.cheapest is None
    assert "no hop" in path.cheapest_reason


def test_paths_are_deterministic_and_ordered_by_impact() -> None:
    analyses = [
        _analysis(1, check_id="m4.a", asset="https://a.example/.env", cwe="CWE-200"),
        _analysis(2, check_id="m4.b", asset="https://a.example/admin", cwe="CWE-306",
                  severity="medium"),
        _analysis(3, check_id="m4.c", asset="https://b.example/.env", cwe="CWE-200"),
        _analysis(4, check_id="m4.d", asset="https://b.example/admin", cwe="CWE-269",
                  severity="critical"),
    ]
    first = build_attack_paths(analyses)
    second = build_attack_paths(list(reversed(analyses)))
    assert [item.id for item in first] == [item.id for item in second]
    assert [item.severity for item in first] == ["critical", "medium"]  # worst first
