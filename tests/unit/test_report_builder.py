"""The builder: stored rows → the report DTO (docs/spec/06- §1/§2/§3)."""

from __future__ import annotations

from tests.helpers.report import (
    make_analysis,
    make_candidate,
    make_inputs,
    synthetic_report,
)

from arachne.report.builder import build_report_data, split_check_key


def test_split_check_key() -> None:
    assert split_check_key("M4/env-file-probe@1.0") == ("m4.env-file-probe", "1.0")
    assert split_check_key("M3/security-headers@1.0") == ("m3.security-headers", "1.0")
    assert split_check_key(None) == ("unknown", None)


def test_a_candidate_maps_to_the_spec_finding_schema() -> None:
    candidate = make_candidate(
        number=7,
        title="Sensitive environment file exposed",
        asset_value="https://target.example/.env",
    )
    report = build_report_data(
        make_inputs(candidates=[candidate], analyses=[make_analysis(candidate)])
    )
    assert len(report.findings) == 1
    finding = report.findings[0]
    assert finding.id == "F-000007"
    assert finding.scan_id == "scan_1"
    assert finding.module == "M4"
    assert finding.check_id == "m4.env-file-probe"
    assert finding.check_version == "1.0"
    assert finding.research_ref == "ch04#1"
    assert finding.asset.kind == "url"
    assert finding.asset.value == "https://target.example/.env"
    assert finding.severity == "high"
    assert finding.score.cvss_base == 7.5
    assert finding.score.confidence == 92
    assert finding.classification.cwe == "CWE-200"
    assert finding.classification.owasp_2025 == "A05:2021-Security Misconfiguration"
    assert finding.description.startswith("The file returned HTTP 200")
    assert finding.evidence_refs
    assert finding.remediation.id == "env-file-exposure"
    assert finding.remediation.verification
    assert finding.provenance.engine == "heuristic"
    assert finding.provenance.analysis_log_id == "al_1"
    assert finding.provenance.rule_ids == ("exposure.env-file",)
    assert finding.timestamps.first_seen is not None
    assert finding.status == "open"


def test_cwe_falls_back_to_the_plan_when_the_analysis_has_none() -> None:
    candidate = make_candidate(
        number=8,
        title="Missing headers",
        asset_value="https://target.example/",
        module="M3",
        check="security-headers",
        research_ref="ch03#35",
    )
    analysis = make_analysis(candidate, cwe=None, remediation_id="security-headers")
    report = build_report_data(make_inputs(candidates=[candidate], analyses=[analysis]))
    assert report.findings[0].classification.cwe == "CWE-693"


def test_low_confidence_findings_are_split_out() -> None:
    candidate = make_candidate(
        number=9, title="weak signal", asset_value="https://t/", confidence=40
    )
    analysis = make_analysis(candidate, confidence=40, severity="low")
    report = build_report_data(make_inputs(candidates=[candidate], analyses=[analysis]))
    assert report.findings == ()
    assert len(report.low_confidence) == 1
    assert report.counts.total == 0


def test_dropped_and_merged_findings_are_not_confirmed_findings() -> None:
    dropped = make_candidate(number=10, title="dropped", asset_value="https://t/a")
    merged = make_candidate(number=11, title="merged", asset_value="https://t/b")
    report = build_report_data(
        make_inputs(
            candidates=[dropped, merged],
            analyses=[
                make_analysis(dropped, verdict="dropped", drop_reason="placeholder page"),
                make_analysis(merged, verdict="merged"),
            ],
        )
    )
    assert report.findings == ()
    assert report.low_confidence == ()
    statuses = {item.status for item in report.appendix.false_positives}
    assert statuses == {"fp", "merged"}
    reasons = " ".join(item.reason or "" for item in report.appendix.false_positives)
    assert "placeholder page" in reasons
    assert "same root cause" in reasons


def test_a_candidate_without_evidence_gets_a_provenance_note() -> None:
    candidate = make_candidate(
        number=12,
        title="no capture",
        asset_value="https://t/c",
        with_evidence=False,
    )
    report = build_report_data(make_inputs(candidates=[candidate], analyses=[]))
    finding = report.findings[0]
    assert finding.evidence_refs
    entry = report.evidence_by_id(finding.evidence_refs[0])
    assert entry is not None
    assert entry.kind == "note"


def test_merged_evidence_refs_are_attached_to_the_compound_finding() -> None:
    first = make_candidate(
        number=13, title="signal one", asset_value="https://t/d", evidence_start=100
    )
    second = make_candidate(
        number=14, title="signal two", asset_value="https://t/e", evidence_start=200
    )
    compound = make_candidate(
        number=15,
        title="compound",
        asset_value="https://t/",
        with_evidence=False,
        severity="critical",
    )
    report = build_report_data(
        make_inputs(
            candidates=[first, second, compound],
            analyses=[
                make_analysis(first, log_id=1),
                make_analysis(second, log_id=2),
                make_analysis(
                    compound,
                    severity="critical",
                    merged_evidence_refs=(100, 200),
                    log_id=3,
                ),
            ],
        )
    )
    finding = next(item for item in report.findings if item.id == "F-000015")
    assert len(finding.evidence_refs) == 2
    for ref in finding.evidence_refs:
        assert report.evidence_by_id(ref) is not None


def test_an_opt_in_check_that_did_not_run_is_marked_not_run() -> None:
    candidate = make_candidate(number=16, title="env", asset_value="https://t/.env")
    report = build_report_data(
        make_inputs(candidates=[candidate], analyses=[make_analysis(candidate)])
    )
    checks = {check.name: check for check in report.scope.checks}
    default_creds = checks["default-credentials"]
    assert default_creds.ran is False
    assert default_creds.skip_reason == "not run (opt-in)"
    assert report.scope.checks_skipped == 1


def test_assets_are_sorted_and_tags_are_carried() -> None:
    from arachne.core.lifecycle import AssetRecord
    from arachne.report.builder import ReportInputs

    assets = (
        AssetRecord(
            id=2,
            scan_id=1,
            kind="url",
            value="https://target.example/b",
            meta={"tags": ["web", "prod"], "source": "crawl"},
        ),
        AssetRecord(id=1, scan_id=1, kind="host", value="target.example", meta={}),
    )
    inputs = make_inputs(candidates=[], analyses=[])
    report = build_report_data(
        ReportInputs(
            scan_id=inputs.scan_id,
            target_name=inputs.target_name,
            engine=inputs.engine,
            plan=inputs.plan,
            assets=assets,
            settings=inputs.settings,
        )
    )
    assert [(asset.kind, asset.value) for asset in report.assets] == [
        ("host", "target.example"),
        ("url", "https://target.example/b"),
    ]
    url_asset = report.assets[1]
    assert url_asset.tags == ("prod", "web")
    assert url_asset.source == "crawl"


def test_audit_highlights_and_out_of_scope_events() -> None:
    from datetime import UTC, datetime

    from arachne.core.audit import AuditAction, AuditEvent, AuditOutcome

    events = [
        AuditEvent(ts=datetime(2026, 10, 27, tzinfo=UTC), action=AuditAction.HTTP_REQUEST),
        AuditEvent(
            ts=datetime(2026, 10, 27, tzinfo=UTC),
            action=AuditAction.SCOPE_DISCARDED,
            outcome=AuditOutcome.BLOCKED,
            target="evil.example",
            reason="not in scope",
        ),
    ]
    report = build_report_data(make_inputs(candidates=[], analyses=[], audit_events=events))
    audit = report.appendix.audit
    assert audit.total_events == 2
    assert audit.blocked_events == 1
    assert audit.actions["http.request"] == 1
    assert audit.actions["scope.discarded"] == 1
    assert any("evil.example" in item for item in audit.out_of_scope_events)


def test_patch_gap_is_reported_only_when_m6_ran() -> None:
    report = synthetic_report()
    assert report.patch_gap is None  # M3/M4 only


def test_the_report_is_deterministic() -> None:
    first = synthetic_report()
    second = synthetic_report()
    assert first.model_dump(mode="json") == second.model_dump(mode="json")


def test_coverage_section_counts_run_and_skipped_checks() -> None:
    report = synthetic_report()
    assert report.scope.checks_run == 2  # M4 env-file-probe + M3 security-headers
    assert report.scope.checks_skipped == 1
    assert "M4" in report.scope.modules
    assert "M3" in report.scope.modules
