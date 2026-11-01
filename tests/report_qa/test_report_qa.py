"""The report QA gate (docs/spec/06- §10, tests/report_qa).

Every generated report must pass these checks before release. This module builds one
report from a **real, full lab scan** — the shared stdlib web lab, M3 and M4 with their
active checks, the full analyzer and correlation pipeline — and then asserts the five
properties docs/spec/06- §10 names:

1. every finding carries evidence refs, severity, confidence and provenance;
2. no unredacted secret appears in any rendered format;
3. the executive summary counts match the findings tables;
4. the JSON report validates against the versioned schema;
5. the Markdown follows the §9 skeleton (sections, cover, per-finding block).

HTML and PDF renderers are S13's; their golden-file snapshots join this gate then.

The scan runs once per module (it is the expensive part); the assertions are separate so a
failure names the property that broke.
"""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Iterator
from datetime import UTC, datetime
from typing import Any

import jsonschema
import pytest

from arachne.core.audit import Auditor, MemoryAuditSink
from arachne.core.config import RateLimitSettings, SafetySettings, Settings
from arachne.core.events import EventBus
from arachne.core.lifecycle import MemoryScanStateStore, ScanStatus
from arachne.core.orchestrator import Orchestrator
from arachne.core.redaction import contains_secret
from arachne.core.safety import UrlSafetyPolicy
from arachne.core.target import (
    ModuleSelection,
    ScanOptions,
    ScanRequest,
    TargetDefinition,
    TargetSelector,
)
from arachne.data.analysis_store import MemoryAnalysisStore
from arachne.data.finding_store import CandidateRecord, EvidenceRecord, MemoryFindingStore
from arachne.modules.handlers import build_handlers
from arachne.modules.registry import ModuleRegistry
from arachne.report import (
    ReportData,
    build_report_data,
    load_report_schema,
    render_json,
    render_markdown,
)
from arachne.report.builder import ReportInputs
from tests.lab.web_lab import WebLab, start_web_lab

#: The credentials the lab serves in ``/.env`` and ``/app.js``. None may survive into a
#: report, in any format (docs/spec/06- §10).
LAB_SECRETS = (
    "AKIAIOSFODNN7EXAMPLE",
    "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "sup3rs3cr3t-db-password",
    "mailgun-not-really-a-password",
)


class LabReport:
    """The scan, the DTO and both rendered formats, built once."""

    def __init__(self, report: ReportData, markdown: str, document: str) -> None:
        self.report = report
        self.markdown = markdown
        self.document = document

    @property
    def json(self) -> dict[str, Any]:
        return json.loads(self.document)


@pytest.fixture(scope="module")
def lab() -> Iterator[WebLab]:
    with start_web_lab() as running:
        yield running


@pytest.fixture(scope="module")
def lab_report(lab: WebLab) -> LabReport:
    return asyncio.run(_build_lab_report(lab))


def _definition(lab: WebLab) -> TargetDefinition:
    return TargetDefinition(
        name="s8-report-lab",
        targets=(TargetSelector(kind="url", value=lab.base_url),),
        attestation={
            "attested_by": "S8 builder <s8@arachne.test>",
            "attested_at": "2026-10-01T00:00:00Z",
            "scope_statement": (
                "Local vulnerable-by-design lab fixture on loopback, owned by the test suite"
            ),
            "allowed_targets": [lab.base_url, "127.0.0.1"],
            "authorization_ref": "TEST-S8-REPORT",
            "active_checks_authorized": True,
        },
    )


async def _build_lab_report(lab: WebLab) -> LabReport:
    definition = _definition(lab)
    settings = Settings(
        database_url="sqlite:///:memory:",
        log_level="CRITICAL",
        safety=SafetySettings(
            policy=UrlSafetyPolicy(allow_loopback=True, allow_private_ips=True),
            scope=definition.compile_scope(),
        ),
        rate_limit=RateLimitSettings(
            per_host_rate=1000.0,
            per_host_burst=1000,
            global_rate=1000.0,
            global_burst=1000,
        ),
    )
    registry = ModuleRegistry.discover()
    findings = MemoryFindingStore()
    analyses = MemoryAnalysisStore()
    store = MemoryScanStateStore()
    sink = MemoryAuditSink()
    auditor = Auditor(sink, actor="pytest")
    orchestrator = Orchestrator(
        settings=settings,
        store=store,
        auditor=auditor,
        bus=EventBus(),
        handlers=build_handlers(
            settings=settings,
            registry=registry,
            findings=findings,
            analyses=analyses,
            auditor=auditor,
        ),
        registry=registry,
    )
    request = ScanRequest(
        target=definition,
        options=ScanOptions(
            active_checks=True,
            # M1's online checks report *skipped* with OSINT off; its hybrid
            # js-asset-scan still runs against the live lab, so the report spans S3-S7
            # (M2 is network-only and has its own acceptance suite).
            modules=ModuleSelection(enabled=("M1", "M3", "M4")),
        ),
    )
    session = await orchestrator.scan(request)
    assert session.status is ScanStatus.COMPLETED, session
    scan_id = session.scan_id or 0
    record = session.record
    assert record is not None
    report = build_report_data(
        ReportInputs(
            scan_id=scan_id,
            target_name=str(record.plan.get("target_name") or definition.name),
            engine=str(record.plan.get("engine") or record.engine),
            plan=dict(record.plan),
            status=record.status.value,
            started_at=record.started_at,
            finished_at=record.finished_at,
            assets=store.list_assets(scan_id),
            candidates=findings.list_candidates(scan_id),
            analyses=analyses.list_analyses(scan_id),
            audit_events=sink.events,
            module_versions={group.id: group.version for group in registry.groups},
            rate_limits={
                "per_host_per_second": settings.rate_limit.per_host_rate,
                "global_per_second": settings.rate_limit.global_rate,
            },
            arachne_version="0.1.0",
            generated_at=record.finished_at or datetime.now(UTC),
            settings=settings,
        )
    )
    return LabReport(
        report=report,
        markdown=render_markdown(report),
        document=render_json(report),
    )


# --------------------------------------------------------------------------- §9 skeleton
_SECTION_HEADINGS = (
    "# Security Assessment Report — ",
    "## 1. Executive summary",
    "## 2. Scope & methodology",
    "## 3. Asset inventory",
    "## 4. Findings — Critical",
    "## 5. Findings — High",
    "## 6. Findings — Medium",
    "## 7. Findings — Low",
    "## 8. Findings — Info",
    "## 10. Low-confidence observations",
    "## 11. Patch-gap & exposure (M6)",
    "## 12. Appendix",
)


def test_the_full_lab_report_matches_the_sample_skeleton(lab_report: LabReport) -> None:
    """DONE criterion 1: a complete Markdown report from a full lab scan."""
    report = lab_report.report
    assert report.findings, "the acceptance lab must produce confirmed findings"
    assert report.scope.checks_run > 0
    assert report.scope.checks_skipped >= 1  # the M4 opt-in checks did not run
    for heading in _SECTION_HEADINGS:
        assert heading in lab_report.markdown, heading
    # The cover names the scan, version, engine and attestation (docs/spec/06- §3.1).
    assert f"Scan: {report.scan_id}" in lab_report.markdown
    assert "engine: heuristic" in lab_report.markdown
    assert "attested by" in lab_report.markdown


def test_every_finding_carries_evidence_severity_confidence_and_provenance(
    lab_report: LabReport,
) -> None:
    """QA property 1 (docs/spec/06- §10)."""
    report = lab_report.report
    findings = list(report.findings) + list(report.low_confidence)
    assert findings
    for finding in findings:
        assert finding.evidence_refs, finding.id
        for ref in finding.evidence_refs:
            assert report.evidence_by_id(ref) is not None, (finding.id, ref)
        assert finding.severity in {"critical", "high", "medium", "low", "info"}
        assert 0 <= finding.score.confidence <= 100
        assert finding.provenance.engine
        assert finding.description.strip()
        assert finding.remediation.summary.strip()
    # The rendered per-finding block names the same facts.
    for finding in report.findings:
        block = _finding_block(lab_report.markdown, finding.id)
        assert "**Evidence:**" in block
        assert "**Provenance:**" in block
        assert "**Remediation:**" in block
        for ref in finding.evidence_refs:
            assert ref in block


def test_no_unredacted_secret_appears_in_any_format(lab_report: LabReport) -> None:
    """QA property 2: scan every rendered format for the planted credentials."""
    for secret in LAB_SECRETS:
        assert secret not in lab_report.markdown, f"secret leaked into Markdown: {secret}"
        assert secret not in lab_report.document, f"secret leaked into JSON: {secret}"
    assert not contains_secret(lab_report.markdown)
    assert not contains_secret(lab_report.document)
    # The lab *was* captured, so redaction actually happened rather than the finding being
    # absent: at least one placeholder must be present somewhere in the evidence appendix.
    assert "[REDACTED" in lab_report.markdown


def test_executive_summary_counts_match_the_findings_tables(lab_report: LabReport) -> None:
    """QA property 3."""
    report = lab_report.report
    rendered = _counts_table(lab_report.markdown)
    expected = dict(report.counts.as_rows())
    assert rendered == expected
    for severity in ("critical", "high", "medium", "low", "info"):
        heading = {
            "critical": "## 4. Findings — Critical",
            "high": "## 5. Findings — High",
            "medium": "## 6. Findings — Medium",
            "low": "## 7. Findings — Low",
            "info": "## 8. Findings — Info",
        }[severity]
        counted = _count_finding_blocks(lab_report.markdown, heading)
        assert counted == expected[severity.title()], (severity, counted, expected)
    # The structured counts agree with the rendered ones by construction, and the
    # low-confidence count is reported separately (never mixed into the table).
    assert report.counts.total == len(report.findings)
    assert report.executive_summary.low_confidence_count == len(report.low_confidence)


def test_the_json_report_validates_against_the_versioned_schema(
    lab_report: LabReport,
) -> None:
    """QA property 4."""
    schema = load_report_schema()
    jsonschema.validate(json.loads(lab_report.document), schema)
    from arachne.report.model import REPORT_SCHEMA_VERSION

    assert lab_report.json["schema_version"] == REPORT_SCHEMA_VERSION


def test_low_confidence_observations_are_not_mixed_with_confirmed_findings(
    lab_report: LabReport,
) -> None:
    """QA property 5 (docs/spec/06- §2/§6)."""
    report = lab_report.report
    findings_text = lab_report.markdown[
        lab_report.markdown.index("## 4.") : lab_report.markdown.index("## 9.")
    ]
    for finding in report.low_confidence:
        assert finding.id not in findings_text
        assert finding.low_confidence is True
    for finding in report.findings:
        assert finding.low_confidence is False


def test_the_report_is_deterministic(lab_report: LabReport) -> None:
    """ADR-06: rendering the same DTO twice is byte-identical."""
    assert render_markdown(lab_report.report) == lab_report.markdown
    assert render_json(lab_report.report) == lab_report.document


# --------------------------------------------------------------------------- parsing helpers
def _finding_block(markdown: str, finding_id: str) -> str:
    findings_start = markdown.index("## 4.")
    start = markdown.index(finding_id, findings_start)
    end = markdown.find("\n### ", start + 1)
    section_end = markdown.find("\n## ", start + 1)
    candidates = [value for value in (end, section_end) if value != -1]
    return markdown[start : min(candidates) if candidates else len(markdown)]


def _counts_table(markdown: str) -> dict[str, int]:
    start = markdown.index("| Severity | Count |")
    rows: dict[str, int] = {}
    for line in markdown[start:].splitlines()[2:]:
        match = re.match(r"\| ([A-Za-z]+) \| (\d+) \|", line)
        if match is None:
            break
        rows[match.group(1)] = int(match.group(2))
    assert rows, "the executive summary counts table is missing"
    return rows


def _count_finding_blocks(markdown: str, heading: str) -> int:
    start = markdown.index(heading) + len(heading)
    end = markdown.find("\n## ", start)
    body = markdown[start : end if end != -1 else len(markdown)]
    return len(re.findall(r"(?m)^### \d+\.\d+ ", body))


# ----------------------------------------------------------------- S15: the L4 golden case
def test_the_l4_scenario_renders_proof_sections_and_a_state_changes_table() -> None:
    """REQ-PROOF-013 (golden): an L4 scenario's report shows Proof + state changes.

    The scenario is synthetic but goes through the real builder and renderers: a candidate
    whose evidence carries the L4 proof artifact (level, method, the change record), plus
    the scan's proof journal (one inserted-and-restored marker row) — exactly what the
    proof ladder's checks attach and the ledger persists.
    """
    from datetime import UTC, datetime

    marker = "ARACHNE_POC_ab12cd34ef56 — safe proof of state-change probe, see ARACHNE report"
    record = CandidateRecord(
        id=1,
        scan_id=1,
        title="State-change access proven (marker row inserted and restored)",
        status="vulnerable",
        confidence=95,
        check_key="M3/state-marker@1.0",
        module="M3",
        asset_kind="url",
        asset_value="https://lab.example/",
        created_at=datetime.now(UTC),
        evidence=(
            EvidenceRecord(
                id=1,
                kind="proof",
                payload={
                    "level": "L4",
                    "method": "INSERT-first marker row (auto-restored)",
                    "cleanup": "restored inline and re-verified",
                    "change": {
                        "change_id": "sc-golden01",
                        "kind": "insert-marker",
                        "check_id": "m3.state-marker",
                        "table": "arachne_poc",
                        "locator": "arachne_poc.marker=ARACHNE_POC_ab12cd34ef56",
                        "before": None,
                        "after": {"marker": marker},
                        "restored": True,
                        "restore_verified": True,
                    },
                },
            ),
        ),
    )
    inputs = ReportInputs(
        scan_id=1,
        target_name="l4-golden",
        engine="heuristic",
        plan={"target_name": "l4-golden", "engine": "heuristic"},
        candidates=[record],
        proof_state={
            "state_changes": [
                {
                    "change_id": "sc-golden01",
                    "kind": "insert-marker",
                    "check_id": "m3.state-marker",
                    "table": "arachne_poc",
                    "locator": "arachne_poc.marker=ARACHNE_POC_ab12cd34ef56",
                    "before": None,
                    "after": {"marker": marker},
                    "restored": True,
                    "restore_verified": True,
                }
            ],
            "cleanups": [{"ran_at": datetime.now(UTC).isoformat(), "attempted": 0, "restored": 0}],
        },
    )
    report = build_report_data(inputs)
    markdown = render_markdown(report)
    document = json.loads(report.model_dump_json())

    # The JSON validates against the shipped schema (with the S15 proof additions).
    jsonschema.validate(document, load_report_schema())
    finding = report.findings[0]
    assert finding.proof is not None and finding.proof.level == "L4"
    assert document["state_changes"], "the report-level state-changes table is empty"
    assert all(change["restored"] for change in document["state_changes"])

    # The Markdown carries the per-finding Proof section and the state-changes table.
    assert "**Proof:**" in markdown
    assert "level L4" in markdown
    assert "INSERT-first marker row (auto-restored)" in markdown
    assert "### F. State changes on targets" in markdown
    assert "arachne_poc" in markdown
    assert "yes (verified)" in markdown
    assert "repair required" not in markdown.lower()


def test_an_unrestored_l4_change_is_a_repair_instruction_in_the_report() -> None:
    """REQ-PROOF-010: a restored=false row renders as a repair instruction."""
    from datetime import UTC, datetime

    record = CandidateRecord(
        id=2,
        scan_id=1,
        title="State-change access proven (marker row inserted and restored)",
        status="vulnerable",
        confidence=95,
        check_key="M3/state-marker@1.0",
        module="M3",
        asset_kind="url",
        asset_value="https://lab.example/",
        created_at=datetime.now(UTC),
        evidence=(
            EvidenceRecord(
                id=1,
                kind="proof",
                payload={
                    "level": "L4",
                    "method": "INSERT-first marker row (auto-restored)",
                    "cleanup": "NOT restored — see the report's state-changes table",
                    "change": {
                        "change_id": "sc-crash01",
                        "kind": "insert-marker",
                        "check_id": "m3.state-marker",
                        "table": "arachne_poc",
                        "locator": "arachne_poc.marker=ARACHNE_POC_deadbeefcafe",
                        "before": None,
                        "after": {"marker": "ARACHNE_POC_deadbeefcafe"},
                        "restored": False,
                        "restore_verified": False,
                        "error": "simulated crash between the write and the restore",
                    },
                },
            ),
        ),
    )
    report = build_report_data(
        ReportInputs(
            scan_id=1,
            target_name="l4-crash",
            engine="heuristic",
            plan={"target_name": "l4-crash", "engine": "heuristic"},
            candidates=[record],
            proof_state={
                "state_changes": [
                    {
                        "change_id": "sc-crash01",
                        "kind": "insert-marker",
                        "check_id": "m3.state-marker",
                        "table": "arachne_poc",
                        "locator": "arachne_poc.marker=ARACHNE_POC_deadbeefcafe",
                        "before": None,
                        "after": {"marker": "ARACHNE_POC_deadbeefcafe"},
                        "restored": False,
                        "restore_verified": False,
                        "error": "simulated crash between the write and the restore",
                    }
                ]
            },
        )
    )
    markdown = render_markdown(report)
    assert "**NO — repair required**" in markdown
    assert "repair instruction" in markdown
    document = json.loads(report.model_dump_json())
    assert document["state_changes"][0]["restored"] is False
    jsonschema.validate(document, load_report_schema())


def test_the_two_hop_attack_path_renders_its_hops_and_cheapest_break() -> None:
    """REQ-AGENT-003 (golden): a two-hop path's report section.

    The scenario is synthetic but goes through the real builder and renderers: an exposure on a
    host and an unauthenticated administrative surface on the same host. The section must show
    the chain, the **terminal** impact as the path's severity, each hop with its evidence, and
    the cheapest remediation that breaks the chain — and the JSON must validate against the
    schema, which is where the new ``attack_paths`` block lives.
    """
    from tests.helpers.report import make_analysis, make_candidate, make_inputs

    exposure = make_candidate(
        number=1,
        title="Sensitive environment file exposed",
        asset_value="https://train.example/.env",
        check="env-file-probe",
        severity="medium",
        confidence=88,
        evidence_start=1,
    )
    admin = make_candidate(
        number=2,
        title="Unauthenticated admin dashboard",
        asset_value="https://train.example/admin",
        check="dashboard-exposure",
        severity="critical",
        confidence=95,
        evidence_start=20,
    )
    report = build_report_data(
        make_inputs(
            candidates=[exposure, admin],
            analyses=[
                make_analysis(exposure, severity="medium", confidence=88, cwe="CWE-200"),
                make_analysis(
                    admin,
                    severity="critical",
                    confidence=95,
                    cwe="CWE-306",
                    remediation_id="dashboard-auth",
                ),
            ],
        )
    )
    assert len(report.attack_paths) == 1
    path = report.attack_paths[0]
    assert path.asset == "train.example"
    assert path.stages == ("exposure", "access")
    assert path.severity == "critical"  # the terminal hop, not the worst hop
    assert path.fully_verified
    assert [hop.evidence_refs for hop in path.hops] == [
        ("E-0001", "E-0002", "E-0003"),
        ("E-0004", "E-0005", "E-0006"),
    ]
    assert path.cheapest_check_id == "m4.env-file-probe"
    assert "verified hop" in path.cheapest_break

    markdown = render_markdown(report)
    block = markdown[markdown.index("## 9. Attack paths") : markdown.index("## 10.")]
    assert "### ap-" in block
    assert "Chain: exposure → access" in block
    assert "Terminal impact: **critical** (verified)" in block
    assert "| F-000001 | exposure | m4.env-file-probe | https://train.example/.env |" in block
    assert "| F-000002 | access | m4.dashboard-exposure | https://train.example/admin |" in block
    assert "E-0001" in block and "E-0004" in block
    assert "fix m4.env-file-probe" in block

    document = json.loads(render_json(report))
    jsonschema.validate(document, load_report_schema())
    assert document["attack_paths"][0]["severity"] == "critical"
    assert document["attack_paths"][0]["hops"][0]["verified"] is True


def test_an_unverified_hop_renders_as_a_candidate_naming_its_check() -> None:
    """REQ-AGENT-003: an unverified link is a *candidate* edge, never a proven step."""
    from tests.helpers.report import make_analysis, make_candidate, make_inputs

    weak = make_candidate(
        number=1,
        title="Configuration file reachable",
        asset_value="https://train.example/.env",
        check="env-file-probe",
        severity="medium",
        evidence_start=1,
    )
    admin = make_candidate(
        number=2,
        title="Unauthenticated admin dashboard",
        asset_value="https://train.example/admin",
        check="dashboard-exposure",
        severity="critical",
        evidence_start=20,
    )
    report = build_report_data(
        make_inputs(
            candidates=[weak, admin],
            analyses=[
                make_analysis(weak, severity="medium", confidence=20, cwe="CWE-200"),
                make_analysis(admin, severity="critical", confidence=95, cwe="CWE-306"),
            ],
        )
    )
    path = report.attack_paths[0]
    assert not path.fully_verified
    candidate_hop = next(hop for hop in path.hops if not hop.verified)
    assert candidate_hop.verifying_check == "m4.env-file-probe"
    block = render_markdown(report)[
        render_markdown(report).index("## 9. Attack paths") :
    ]
    assert "candidate — verify with m4.env-file-probe" in block


# ----------------------------------------------------------------- S22: the framework golden case
def test_the_framework_report_renders_coverage_and_explicit_gaps() -> None:
    """REQ-TRUST-001 (golden): a framework report shows per-control coverage.

    The scenario is synthetic but goes through the real builder and renderers, with the
    shipped ISO 27001 and PCI DSS maps: one finding whose check evidences A.5.17
    (fail), the helper plan's other checks running clean (pass), and everything else a
    gap — with the framework's own control count beside the assessed one, so the
    unmapped remainder is an explicit gap in the document rather than an implication of
    coverage.
    """
    import json

    from tests.helpers.report import make_candidate, make_inputs

    finding = make_candidate(
        number=1,
        title="Sensitive environment file exposed",
        asset_value="https://train.example/.env",
        check="env-file-probe",
        severity="medium",
        confidence=88,
        evidence_start=1,
    )
    inputs = make_inputs(candidates=[finding])
    report = build_report_data(
        ReportInputs(
            **{
                **{f: getattr(inputs, f) for f in inputs.__dataclass_fields__},
                "compliance_frameworks": ("iso27001", "pci-dss"),
            }
        )
    )
    markdown = render_markdown(report)
    document = json.loads(report.model_dump_json())

    # The JSON validates against the shipped schema (with the S22 compliance additions).
    jsonschema.validate(document, load_report_schema())
    assert document["schema_version"] == report.schema_version
    assert [block["framework"] for block in document["compliance"]] == ["iso27001", "pci-dss"]

    # The appendix carries the section; every framework block states its coverage.
    assert "### H. Compliance framework coverage" in markdown
    assert "#### ISO/IEC 27001:2022 Annex A (2022) — map v1.0" in markdown
    assert "#### PCI DSS (v4.0) — map v1.0" in markdown
    assert "Mapped: 16 of 93 controls" in markdown  # iso27001: mapped, of its own total
    assert "77 control(s) are outside ARACHNE's check catalogue" in markdown
    assert "Mapped: 10 of 12 requirements" in markdown
    assert "2 requirement(s) are outside ARACHNE" in markdown
    assert "This scan: " in markdown and " gap (mapped checks that did not run)" in markdown

    # The failing control is a row with its finding; the clean ones are `pass`.
    iso = report.compliance[0]
    a517 = next(row for row in iso.controls if row.control == "A.5.17")
    assert a517.status == "fail" and a517.findings == ("F-000001",)
    report_refs = {
        ref for finding in report.findings for ref in finding.evidence_refs
    }
    assert set(a517.evidence_refs) == report_refs and report_refs
    assert "| A.5.17 |" in markdown and "**fail**" in markdown
    passed = [row.control for row in iso.controls if row.status == "pass"]
    assert passed, "the helper plan's ran checks pass their controls"
    for control in passed:
        assert f"| {control} |" in markdown

    # The explicit gaps are named with the checks that did not run.
    assert "**Explicit gaps.**" in markdown
    assert "no conclusion about them can be drawn from this report" in markdown
    gaps = [row for row in iso.controls if row.status == "gap"]
    for row in gaps:
        assert f"- {row.control} " in markdown

    # Rendering is deterministic (ADR-06) — twice from the same DTO is byte-identical.
    assert render_markdown(report) == markdown


def test_a_frameworkless_report_renders_no_compliance_section() -> None:
    """No frameworks named → no section, and the pre-S22 output is unchanged."""
    from tests.helpers.report import make_candidate, make_inputs

    finding = make_candidate(
        number=1,
        title="Sensitive environment file exposed",
        asset_value="https://train.example/.env",
        check="env-file-probe",
        severity="medium",
        evidence_start=1,
    )
    report = build_report_data(make_inputs(candidates=[finding]))
    markdown = render_markdown(report)
    assert "### H. Compliance framework coverage" not in markdown
    assert report.compliance == ()
    assert "## 12. Appendix" in markdown


def test_an_unknown_framework_name_fails_the_report_loudly() -> None:
    """A typo'd framework is a ConfigurationError, never a silently missing section."""

    import pytest as _pytest

    from arachne.core.errors import ConfigurationError
    from tests.helpers.report import make_candidate, make_inputs

    finding = make_candidate(
        number=1,
        title="x",
        asset_value="https://train.example/",
        check="env-file-probe",
        severity="medium",
        evidence_start=1,
    )
    inputs = make_inputs(candidates=[finding])
    with _pytest.raises(ConfigurationError, match="unknown compliance framework"):
        build_report_data(
            ReportInputs(
                **{
                    **{f: getattr(inputs, f) for f in inputs.__dataclass_fields__},
                    "compliance_frameworks": ("soc2",),
                }
            )
        )
