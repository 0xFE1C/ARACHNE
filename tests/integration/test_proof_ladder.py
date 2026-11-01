"""The proof-ladder demo (S15, gate G1 evidence): a lab target scanned L1→L4, zero residue.

This is the ``VM`` verification of ``docs/04-verification-and-acceptance.md`` §4 — one
scan over the web lab that climbs the whole ladder and proves the safety properties at
each rung:

* **L2** — the four out-of-band variants get real callbacks: the lab's blind SQLi sink,
  its XXE parser, its command sink's execution monitor and its template renderer each
  reach the standalone ``arachne callback-server`` through their own single-use token,
  and each hit is matched to exactly one finding (REQ-PROOF-005/006).
* **L3** — ``m3.rce-echo`` executes exactly one allowlisted ``echo arachne-<nonce>``
  through the lab's command sink and reads the nonce back (REQ-PROOF-007).
* **L4** — ``m3.state-marker`` inserts one marker row through the lab's SQL sink,
  verifies it, auto-restores it and re-verifies the restore (REQ-PROOF-008).

Afterwards: the lab's database has **zero residue** (the ``arachne_poc`` table is empty,
the ``products`` row is byte-identical to its seed), the ledger records every state
change as restored and verified, the audit trail carries the whole proof story, and the
rendered report shows per-finding *Proof* sections plus the report-level *state changes*
table with every row restored (REQ-PROOF-013).
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

import pytest
from tests.lab.web_lab import WebLab, start_web_lab

from arachne.core.audit import AuditAction, Auditor, MemoryAuditSink
from arachne.core.config import RateLimitSettings, SafetySettings, Settings, WebSettings
from arachne.core.events import EventBus
from arachne.core.http import ScopedHttpClient
from arachne.core.lifecycle import MemoryScanStateStore, ScanStatus
from arachne.core.orchestrator import Orchestrator, ScanSession
from arachne.core.safety import Scope, UrlSafetyPolicy
from arachne.core.target import ModuleSelection, ScanOptions, TargetDefinition, TargetSelector
from arachne.data.analysis_store import MemoryAnalysisStore
from arachne.data.finding_store import MemoryFindingStore
from arachne.modules.handlers import build_handlers
from arachne.modules.registry import ModuleRegistry
from arachne.proof.server import start_callback_server
from arachne.report.builder import ReportInputs, build_report_data
from arachne.report.markdown import render_markdown
from arachne.report.model import REPORT_SCHEMA_VERSION

#: The proof-ladder checks the demo scan names (all opt-in by construction).
LADDER_CHECKS: tuple[str, ...] = (
    "m3.sqli-oob",
    "m3.xxe-oob",
    "m3.cmdi-oob",
    "m3.ssti-oob",
    "m3.rce-echo",
    "m3.state-marker",
)


@dataclass
class LadderRun:
    """Everything the demo assertions read: one scan's complete record."""

    session: ScanSession
    findings: MemoryFindingStore
    analyses: MemoryAnalysisStore
    sink: MemoryAuditSink
    callback_sink: MemoryAuditSink
    orchestrator: Orchestrator
    report_markdown: str = ""
    report_document: dict[str, Any] = field(default_factory=dict)

    @property
    def scan_id(self) -> int:
        assert self.session.scan_id is not None
        return self.session.scan_id

    def candidates(self) -> list[Any]:
        return self.findings.list_candidates(self.scan_id)

    def candidates_for(self, check_name: str) -> list[Any]:
        return [
            record
            for record in self.candidates()
            if (record.check_key or "").split("/")[-1].split("@")[0] == check_name
        ]

    def audit(self, action: AuditAction) -> list[Any]:
        return self.sink.of_action(action)

    def callback_audit(self, action: AuditAction) -> list[Any]:
        """The callback service's own trail (issue/hit/replay live there)."""
        return self.callback_sink.of_action(action)


@pytest.fixture(scope="module")
def callback() -> Iterator[Any]:
    """The standalone OOB callback service, real HTTP on loopback, with its own audit."""
    sink = MemoryAuditSink()
    handle = start_callback_server(auditor=Auditor(sink, actor="callback-server"))
    try:
        yield handle
    finally:
        handle.close()


@pytest.fixture(scope="module")
def lab(callback: Any) -> Iterator[WebLab]:
    """The web lab, with its execution monitor pointed at the callback service."""
    with start_web_lab(callback_base=callback.base_url) as running:
        yield running


@pytest.fixture(scope="module")
def run(callback: Any, lab: WebLab) -> LadderRun:
    """One orchestrator-driven scan that climbs L2→L4 over the lab."""
    definition = TargetDefinition(
        name="proof-ladder-lab",
        targets=(
            TargetSelector(kind="url", value=lab.base_url),
            # The callback service is ARACHNE's own infrastructure; the checks' token
            # lookups go through the scan's scoped client, so it must be in scope.
            TargetSelector(kind="url", value=callback.base_url),
        ),
        attestation={
            "attested_by": "S15 builder <s15@arachne.test>",
            "attested_at": "2026-10-01T00:00:00Z",
            "scope_statement": (
                "Local proof-ladder lab fixture on loopback, owned by the test suite"
            ),
            "allowed_targets": [lab.base_url, callback.base_url, "127.0.0.1"],
            "authorization_ref": "TEST-S15",
            "active_checks_authorized": True,
            "state_changes_authorized": True,
        },
    )
    settings = Settings(
        database_url="sqlite:///:memory:",
        log_level="CRITICAL",
        safety=SafetySettings(
            policy=UrlSafetyPolicy(allow_loopback=True, allow_private_ips=True),
            scope=Scope(allowed_hosts=("127.0.0.1",)),
        ),
        rate_limit=RateLimitSettings(
            per_host_rate=1000.0,
            per_host_burst=1000,
            global_rate=1000.0,
            global_burst=1000,
        ),
        web=WebSettings(
            ssrf_callback_url=callback.base_url,
            ssrf_probe=True,
            rce_probe=True,
            state_probe=True,
            # The OOB variants post to same-origin pages; a wider sink budget and a
            # wider crawl keep the demo independent of crawl order.
            max_params_per_check=24,
            max_pages=80,
        ),
    )
    registry = ModuleRegistry.discover()
    findings = MemoryFindingStore()
    analyses = MemoryAnalysisStore()
    sink = MemoryAuditSink()
    auditor = Auditor(sink, actor="pytest")

    def client_factory(scope: Scope) -> ScopedHttpClient:
        return ScopedHttpClient(
            settings=settings,
            scope=scope,
            policy=settings.safety.policy,
            auditor=auditor,
        )

    orchestrator = Orchestrator(
        settings=settings,
        store=MemoryScanStateStore(),
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
        client_factory=client_factory,
    )
    from arachne.core.target import ScanRequest

    request = ScanRequest(
        target=definition,
        options=ScanOptions(
            active_checks=True,
            modules=ModuleSelection(enabled=("M3",), checks=LADDER_CHECKS),
        ),
    )
    session = asyncio.run(orchestrator.scan(request))
    result = LadderRun(
        session=session,
        findings=findings,
        analyses=analyses,
        sink=sink,
        callback_sink=callback.audit_sink,
        orchestrator=orchestrator,
    )
    record = orchestrator.store.get_scan(result.scan_id)
    assert record is not None
    report = build_report_data(
        ReportInputs(
            scan_id=result.scan_id,
            target_name="proof-ladder-lab",
            engine="heuristic",
            plan=dict(record.plan),
            assets=orchestrator.store.list_assets(result.scan_id),
            candidates=findings.list_candidates(result.scan_id),
            analyses=analyses.list_analyses(result.scan_id),
            audit_events=sink.events,
            proof_state=dict(record.stats.get("proof") or {}),
        )
    )
    result.report_markdown = render_markdown(report)
    result.report_document = json.loads(report.model_dump_json())
    return result


# ------------------------------------------------------------------ the ladder climbs


def test_the_scan_completes(run: LadderRun) -> None:
    assert run.session.status is ScanStatus.COMPLETED


@pytest.mark.parametrize(
    "check_name", ["sqli-oob", "xxe-oob", "cmdi-oob", "ssti-oob", "rce-echo", "state-marker"]
)
def test_every_ladder_check_proved_its_class(run: LadderRun, check_name: str) -> None:
    """Each rung of the ladder produced a candidate with a proof artifact attached."""
    candidates = run.candidates_for(check_name)
    assert candidates, f"m3.{check_name} did not fire against the lab"
    proofs = [
        item
        for record in candidates
        for item in record.evidence
        if item.kind == "proof"
    ]
    assert proofs, f"m3.{check_name} fired without proof evidence"
    levels = {item.payload.get("level") for item in proofs}
    expected = {
        "sqli-oob": "L2",
        "xxe-oob": "L2",
        "cmdi-oob": "L2",
        "ssti-oob": "L2",
        "rce-echo": "L3",
        "state-marker": "L4",
    }[check_name]
    assert levels == {expected}


def test_oob_hits_matched_single_use_with_full_evidence(run: LadderRun) -> None:
    """REQ-PROOF-005/006: lab routes triggered callbacks, matched to findings."""
    hits = run.callback_audit(AuditAction.PROOF_OOB_HIT)
    assert len(hits) >= 4  # one per L2 variant sink that fired
    consumed = run.callback_audit(AuditAction.PROOF_OOB_REPLAY)
    assert consumed == []  # single-use: nothing was replayed
    for check_name in ("sqli-oob", "xxe-oob", "cmdi-oob", "ssti-oob"):
        proofs = [
            item
            for record in run.candidates_for(check_name)
            for item in record.evidence
            if item.kind == "proof"
        ]
        hit_payloads = [item.payload.get("hit") for item in proofs]
        assert hit_payloads and all(hit_payloads), check_name
        # The hit carries the redacted interaction: method, path with the token, source.
        hit = hit_payloads[0]
        assert hit.get("method") in {"GET", "POST"}
        assert "arachne-" in str(hit.get("path"))


def test_the_l3_proof_is_one_allowlisted_echo(run: LadderRun) -> None:
    executed = run.audit(AuditAction.PROOF_COMMAND_EXECUTED)
    assert len(executed) == 1
    meta = executed[0].meta
    assert meta["command"] == "echo"
    assert meta["allowlist"] == ["echo"]
    assert meta["payload" if "payload" in meta else "nonce"]
    assert meta["reflected"] is True


def test_the_l4_marker_was_inserted_verified_and_restored(run: LadderRun) -> None:
    changed = run.audit(AuditAction.PROOF_STATE_CHANGED)
    restored = run.audit(AuditAction.PROOF_STATE_RESTORED)
    assert len(changed) == 1 and len(restored) == 1
    assert restored[0].meta["verified"] is True


# ------------------------------------------------------------------ zero residue


def test_the_lab_database_has_zero_residue(run: LadderRun, lab: WebLab) -> None:
    """The gate G1 demo criterion: scanned L1→L4, zero residue after the cleanup pass."""
    assert lab.poc_rows("arachne_poc") == []
    assert lab.poc_rows("products") == [(1, "anchor-product", 19.99)]


def test_the_ledger_records_restored_and_verified(run: LadderRun) -> None:
    record = run.orchestrator.store.get_scan(run.scan_id)
    assert record is not None
    proof_state = record.stats.get("proof") or {}
    changes = proof_state.get("state_changes") or []
    assert changes, "the ledger has no state changes"
    assert all(change["restored"] and change["restore_verified"] for change in changes)
    cleanups = (record.stats.get("proof") or {}).get("cleanups") or []
    assert cleanups and cleanups[-1]["still_unrestored"] == []


def test_the_cleanup_pass_ran_and_found_nothing_left(run: LadderRun) -> None:
    cleanup = run.audit(AuditAction.PROOF_CLEANUP_COMPLETED)
    assert cleanup, "the end-of-step cleanup pass did not run"
    assert cleanup[0].meta["still_unrestored"] == []
    assert run.audit(AuditAction.PROOF_REPAIR_REQUIRED) == []


# ------------------------------------------------------------------ the report


def test_the_report_carries_the_state_changes_table_all_restored(run: LadderRun) -> None:
    document = run.report_document
    assert document["schema_version"] == REPORT_SCHEMA_VERSION
    changes = document["state_changes"]
    assert changes, "the report-level state-changes table is empty"
    assert all(change["restored"] and change["restore_verified"] for change in changes)
    assert "## 12. Appendix" in run.report_markdown
    assert "### F. State changes on targets" in run.report_markdown
    assert "No state change was made on any target." not in run.report_markdown
    assert "repair required" not in run.report_markdown.lower()


@pytest.mark.parametrize("check_name", ["sqli-oob", "cmdi-oob", "rce-echo", "state-marker"])
def test_report_findings_render_a_proof_section(run: LadderRun, check_name: str) -> None:
    """REQ-PROOF-013: per-finding Proof section — level, method, cleanup."""
    proofs = [
        item.payload
        for record in run.candidates_for(check_name)
        for item in record.evidence
        if item.kind == "proof"
    ]
    assert proofs
    token = proofs[0].get("token")
    if token:
        assert f"- callback token: `{token}`" in run.report_markdown
    assert f"level {proofs[0]['level']}" in run.report_markdown
    assert "cleanup:" in run.report_markdown


def test_the_report_json_validates_against_the_shipped_schema(run: LadderRun) -> None:
    import jsonschema

    from arachne.report.json_render import load_report_schema

    jsonschema.validate(run.report_document, load_report_schema())
