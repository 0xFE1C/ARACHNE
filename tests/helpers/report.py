"""Builders for report tests: stored-shaped candidates, analyses and a small report.

The report engine consumes the records the stores produce, so a report unit test should not
have to stand up a scan. This helper constructs the exact dataclasses (``CandidateRecord``,
``StoredAnalysis``) with their real field shapes, including the analysis payload
``Analysis.to_dict()`` writes — so the builder is exercised against what a real scan stores,
not a convenient subset.

``synthetic_report`` is the fixture the renderer, QA and diff tests share: one high finding
(often with a second critical), one low-confidence observation and one dropped candidate.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime

from arachne.data.analysis_store import StoredAnalysis
from arachne.data.finding_store import CandidateRecord, EvidenceRecord
from arachne.report.builder import ReportInputs, build_report_data
from arachne.report.model import ReportData

__all__ = [
    "NOW",
    "PLAN",
    "make_analysis",
    "make_candidate",
    "make_inputs",
    "synthetic_report",
]

NOW = datetime(2026, 10, 27, 12, 0, tzinfo=UTC)
LATER = datetime(2026, 10, 27, 12, 41, tzinfo=UTC)

PLAN: dict[str, object] = {
    "target_name": "target.example",
    "engine": "heuristic",
    "scope": {
        "allowed_hosts": ["target.example"],
        "excluded_hosts": ["legacy.target.example"],
    },
    "attestation": {
        "attested_by": "felix@corp",
        "attested_at": "2026-10-01T00:00:00+00:00",
        "allowed_targets": ["target.example"],
        "expires_at": "2026-11-30T00:00:00+00:00",
        "authorization_ref": "TEST-42",
    },
    "checks": [
        {
            "module": "M4",
            "name": "env-file-probe",
            "version": "1.0",
            "title": "Exposed environment file",
            "research_ref": "ch04#1",
            "cwe": "CWE-200",
            "included": True,
        },
        {
            "module": "M4",
            "name": "default-credentials",
            "version": "1.0",
            "title": "Vendor-default credentials",
            "research_ref": "ch04#26",
            "cwe": "CWE-1392",
            "included": True,
        },
        {
            "module": "M3",
            "name": "security-headers",
            "version": "1.0",
            "title": "Security header review",
            "research_ref": "ch03#35",
            "cwe": "CWE-693",
            "included": True,
        },
    ],
}


def _evidence(
    *,
    finding: int,
    start: int,
    source: str,
    body: str = "AWS_ACCESS_KEY_ID=[REDACTED:aws-access-key-id]",
) -> tuple[EvidenceRecord, ...]:
    return (
        EvidenceRecord(
            id=start,
            kind="http_request",
            payload={
                "method": "GET",
                "url": source,
                "headers": {"accept": "*/*", "cookie": "[REDACTED:header]"},
            },
            sha256="a" * 64,
            created_at=NOW,
        ),
        EvidenceRecord(
            id=start + 1,
            kind="http_response",
            payload={
                "status_code": 200,
                "headers": {"content-type": "text/plain"},
                "body": body,
                "captured_patterns": ["aws-access-key-id"],
            },
            sha256="b" * 64,
            created_at=NOW,
        ),
        EvidenceRecord(
            id=start + 2,
            kind="note",
            payload={
                "detail": f"candidate {finding} provenance",
                "check": "m4.env-file-probe",
                "module": "M4",
            },
            sha256=None,
            created_at=NOW,
        ),
    )


def make_candidate(
    *,
    number: int,
    title: str,
    asset_value: str,
    module: str = "M4",
    check: str = "env-file-probe",
    version: str = "1.0",
    research_ref: str | None = "ch04#1",
    severity: str | None = "high",
    confidence: int = 92,
    status: str = "open",
    evidence_start: int | None = None,
    with_evidence: bool = True,
) -> CandidateRecord:
    """One stored candidate, shaped like ``SqlFindingStore.list_candidates`` output."""
    start = evidence_start if evidence_start is not None else number * 10
    evidence = _evidence(finding=number, start=start, source=asset_value) if with_evidence else ()
    return CandidateRecord(
        id=number,
        scan_id=1,
        title=title,
        status=status,
        confidence=float(confidence),
        severity=severity,
        check_id=number,
        asset_id=number,
        asset_kind="url",
        asset_value=asset_value,
        check_key=f"{module}/{check}@{version}",
        module=module,
        research_ref=research_ref,
        created_at=NOW,
        evidence=evidence,
    )


def make_analysis(
    candidate: CandidateRecord,
    *,
    severity: str = "high",
    confidence: int = 92,
    cwe: str | None = "CWE-200",
    verdict: str = "analyzed",
    status: str | None = None,
    narrative: str = "The file returned HTTP 200 and contained credentials.",
    remediation_id: str = "env-file-exposure",
    merged_evidence_refs: Sequence[int] = (),
    log_id: int = 1,
    drop_reason: str | None = None,
    cve: str | None = None,
    epss: float | None = 0.03,
) -> StoredAnalysis:
    """One stored analysis whose ``payload`` matches ``Analysis.to_dict()``."""
    effective_status = status or (
        "fp" if verdict == "dropped" else "merged" if verdict == "merged" else "open"
    )
    payload = {
        "finding_id": candidate.id,
        "check_id": candidate.check_key,
        "asset": candidate.asset_value,
        "title": candidate.title,
        "severity": severity,
        "confidence": confidence,
        "cwe": cwe,
        "cve": cve,
        "narrative": narrative,
        "verdict": verdict,
        "drop_reason": drop_reason,
        "verified": False,
        "status": effective_status,
        "score": {
            "cvss_base": 7.5,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "owasp_risk": "high",
            "epss": epss,
            "derived_severity": severity,
            "confidence": confidence,
            "confidence_reasons": ["base 70", "request+response +22"],
        },
        "remediation": {
            "id": remediation_id,
            "summary": "Block .env at the web-server layer and rotate the credentials.",
            "steps": ["1. Add a deny rule for /.env.", "2. Rotate the exposed keys."],
            "verification": ["1. Re-request the path; it must return 404."],
            "references": ["https://cwe.mitre.org/data/definitions/200.html"],
            "source": "catalog",
        },
        "provenance": {
            "engine": "heuristic",
            "rule_ids": ["exposure.env-file"],
            "template_version": "narrative-v1",
            "model": None,
        },
        "rule_trace": [],
        "contributors": [],
        "merged_evidence_refs": list(merged_evidence_refs),
        "signatures": [],
        "correlated": verdict == "merged",
    }
    return StoredAnalysis(
        finding_id=candidate.id,
        scan_id=1,
        severity=severity,
        confidence=confidence,
        status=effective_status,
        engine="heuristic",
        remediation_id=remediation_id,
        template_version="narrative-v1",
        log_id=log_id,
        created_at=NOW,
        payload=payload,
    )


def make_inputs(
    *,
    candidates: Sequence[CandidateRecord] | None = None,
    analyses: Sequence[StoredAnalysis] | None = None,
    plan: dict[str, object] | None = None,
    audit_events: Sequence[object] = (),
    generated_at: datetime | None = NOW,
) -> ReportInputs:
    from arachne.core.config import Settings

    return ReportInputs(
        scan_id=1,
        target_name="target.example",
        engine="heuristic",
        plan=plan if plan is not None else PLAN,
        started_at=NOW,
        finished_at=LATER,
        assets=(),
        candidates=candidates or (),
        analyses=analyses or (),
        audit_events=audit_events,
        module_versions={"M3": "1.0.0", "M4": "1.0.0"},
        rate_limits={"per_host_per_second": 5.0, "global_per_second": 20.0},
        arachne_version="0.1.0",
        generated_at=generated_at,
        settings=Settings(database_url="sqlite:///:memory:"),
        not_run_checks={"m4.default-credentials": "not run (opt-in)"},
        research_corpus_version="narrative-v1",
    )


def synthetic_report() -> ReportData:
    """One confirmed high, one critical, one low-confidence and one dropped candidate."""
    candidates = [
        make_candidate(
            number=1,
            title="Sensitive environment file exposed",
            asset_value="https://target.example/.env",
            evidence_start=1,
        ),
        make_candidate(
            number=2,
            title="Unauthenticated admin dashboard",
            asset_value="https://target.example/admin",
            check="dashboard-exposure",
            research_ref="ch04#5",
            severity="critical",
            confidence=95,
            evidence_start=20,
        ),
        make_candidate(
            number=3,
            title="Missing HTTP security headers",
            asset_value="https://target.example/",
            module="M3",
            check="security-headers",
            research_ref="ch03#35",
            severity="low",
            confidence=48,
            evidence_start=30,
        ),
        make_candidate(
            number=4,
            title="Generic server banner",
            asset_value="https://target.example/",
            module="M3",
            check="security-headers",
            research_ref="ch03#35",
            severity="info",
            confidence=80,
            evidence_start=40,
        ),
    ]
    analyses = [
        make_analysis(candidates[0], log_id=1),
        make_analysis(
            candidates[1],
            severity="critical",
            confidence=95,
            cwe="CWE-284",
            remediation_id="admin-surface",
            log_id=2,
            epss=None,
        ),
        make_analysis(
            candidates[2],
            severity="low",
            confidence=48,
            cwe="CWE-693",
            remediation_id="security-headers",
            log_id=3,
            epss=None,
        ),
        make_analysis(
            candidates[3],
            severity="info",
            confidence=80,
            cwe="CWE-693",
            remediation_id="security-headers",
            verdict="dropped",
            drop_reason="placeholder page",
            log_id=4,
            epss=None,
        ),
    ]
    return build_report_data(make_inputs(candidates=candidates, analyses=analyses))
