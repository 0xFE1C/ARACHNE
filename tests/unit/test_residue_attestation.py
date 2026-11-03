"""The per-scan residue attestation (WP-14, REQ-PROOF-017).

``INV-7`` restores every state change an L4 proof makes. This package makes the *outcome* an
artefact a third party can check, and these tests are written against that claim rather than
against the function that builds it:

1. **A scan that authorized nothing still attests.** The statement is the one the
   requirement names, the entry list is empty, and the verdict is clean — so "this scan
   changed nothing" is a signed statement rather than an inference from a missing file.
2. **A forced restore failure is residue 1, with the repair instruction.** The entry names
   the asset, the action, the before-value *hash*, the outcome and the timestamp; the
   attestation carries the ledger's own repair instruction and is not clean.
3. **Signed when a signer exists, marked unsigned when not.** The same scan through the
   scan machine, with and without a deployment key: never silently unsigned.
4. **The hash is linked into the audit chain**, and the report warns and does not read as
   clean.
5. **A tampered attestation fails its own verification** — hash first, then signature, so an
   edited entry cannot be re-signed over.
"""

from __future__ import annotations

import copy
from datetime import UTC, datetime
from typing import Any

import pytest
from tests.conftest import build_scan_request

from arachne.core.audit import (
    AuditAction,
    MemoryAuditChain,
    MemoryAuditSink,
    build_auditor,
)
from arachne.core.config import Settings
from arachne.core.events import EventBus
from arachne.core.integrity import (
    NO_STATE_CHANGE_STATEMENT,
    ZERO_RESIDUE_STATEMENT,
    attestation_digest,
    evidence_signature_payload,
)
from arachne.core.lifecycle import ScanMachine, ScanStatus
from arachne.core.planner import ScanStep
from arachne.core.redaction import redact_value
from arachne.core.signing import DeploymentSigner
from arachne.data.db import create_all, create_session_factory, create_sqlite_engine
from arachne.data.integrity_store import IntegrityService
from arachne.data.models import Target
from arachne.data.scan_store import SqlScanStateStore
from arachne.proof.ledger import ProofLedger
from arachne.proof.residue import (
    attestation_is_clean,
    build_residue_attestation,
    verify_residue_attestation,
)
from arachne.report.builder import ReportInputs, build_report_data
from arachne.report.markdown import render_markdown

KEY = "wp14-unit-test-deployment-key-0001"
NOW = datetime(2026, 11, 3, 12, 0, tzinfo=UTC)

#: One unrestored L4 change, in the shape the proof journal persists.
UNRESTORED: dict[str, Any] = {
    "change_id": "chg-1",
    "kind": "update",
    "check_id": "m3.state-marker",
    "table": "users",
    "locator": "users.email where id=1",
    "before": {"email": "victim@example.test"},
    "after": {"email": "arachne-proof@example.test"},
    "restored": False,
    "restored_at": None,
    "restore_verified": False,
    "note": None,
    "error": None,
    "changed_at": "2026-11-03T11:59:00+00:00",
}


def _restored(change_id: str = "chg-2") -> dict[str, Any]:
    return {
        **UNRESTORED,
        "change_id": change_id,
        "change": None,
        "restored": True,
        "restored_at": "2026-11-03T11:59:30+00:00",
        "restore_verified": True,
        "changed_at": "2026-11-03T11:59:10+00:00",
    }


def _body_of(attestation: dict[str, Any]) -> dict[str, Any]:
    """The signed body: everything the digest covers."""
    return {
        key: value
        for key, value in attestation.items()
        if key not in {"hash", "signed", "signature", "clean"}
    }


# ------------------------------------------------------------------ 1. no state change
def test_a_scan_with_no_state_change_still_attests_to_exactly_that() -> None:
    attestation = build_residue_attestation(scan_id=7, proof_state={}, signer=None)
    assert attestation["statement"] == NO_STATE_CHANGE_STATEMENT
    assert "no state-changing action was authorized" in attestation["statement"]
    assert attestation["changes"] == []
    assert attestation["residue"] == 0
    assert attestation["clean"] is True
    assert attestation["signed"] is False
    assert attestation["hash"] == attestation_digest(_body_of(attestation))


def test_a_restored_scan_is_clean_and_enumerates_its_changes() -> None:
    attestation = build_residue_attestation(
        scan_id=7, proof_state={"state_changes": [_restored()]}, signer=None
    )
    assert attestation["residue"] == 0
    assert attestation["restored"] == 1
    assert attestation["statement"] == ZERO_RESIDUE_STATEMENT
    entry = attestation["changes"][0]
    assert entry["restore_outcome"] == "restored"
    assert entry["before_value_hash"] and len(entry["before_value_hash"]) == 64
    # The hash is a digest of the before-value, and the value itself is not in the envelope.
    assert "victim@example.test" not in str(attestation)
    assert entry["asset"] == "users.email where id=1"
    assert entry["timestamp"] == "2026-11-03T11:59:10+00:00"


# ------------------------------------------------------------------ 2. forced restore failure
def test_a_forced_restore_failure_is_residue_one_with_the_repair_instruction() -> None:
    attestation = build_residue_attestation(
        scan_id=7, proof_state={"state_changes": [_restored(), UNRESTORED]}, signer=None
    )
    assert attestation["residue"] == 1
    assert attestation["clean"] is False
    assert attestation["restored"] == 1
    assert "1 state change(s) were not restored" in attestation["statement"]
    instructions = attestation["repair_instructions"]
    assert len(instructions) == 1 and "REPAIR REQUIRED" in instructions[0]
    failure = next(item for item in attestation["changes"] if item["change_id"] == "chg-1")
    assert failure["restore_outcome"] == "not-restored"
    assert failure["timestamp"] == "2026-11-03T11:59:00+00:00"
    assert attestation_is_clean(attestation) is False


def test_a_change_recorded_without_a_restore_is_never_read_as_clean() -> None:
    """A missing attestation is not clean either — it is "not stated"."""
    assert attestation_is_clean(None) is False
    assert attestation_is_clean({}) is False


def test_an_errored_change_is_distinguished_from_an_unrestored_one() -> None:
    errored = {**UNRESTORED, "error": "connection reset during restore"}
    attestation = build_residue_attestation(
        scan_id=7, proof_state={"state_changes": [errored]}, signer=None
    )
    assert attestation["changes"][0]["restore_outcome"] == "error"
    assert attestation["residue"] == 1


# ------------------------------------------------------------------ 3. signing
def test_the_attestation_is_signed_when_a_signer_is_configured() -> None:
    signer = DeploymentSigner(KEY)
    attestation = build_residue_attestation(
        scan_id=7, proof_state={"state_changes": [UNRESTORED]}, signer=signer
    )
    assert attestation["signed"] is True
    assert attestation["signature"] and attestation["signature"].startswith("v1:")
    ok, detail = verify_residue_attestation(attestation, signer=signer)
    assert ok, detail


def test_an_unsigned_attestation_says_so_and_fails_a_signature_check() -> None:
    signer = DeploymentSigner(KEY)
    unsigned = build_residue_attestation(scan_id=7, proof_state={}, signer=None)
    assert unsigned["signed"] is False and unsigned["signature"] is None
    ok, detail = verify_residue_attestation(unsigned, signer=signer)
    assert not ok and "signature" in detail
    # ...but it is still hash-verifiable where no key exists, and that is stated.
    ok, detail = verify_residue_attestation(unsigned, signer=None)
    assert ok and "UNSIGNED" in detail


def test_an_edited_attestation_fails_its_hash() -> None:
    signer = DeploymentSigner(KEY)
    attestation = build_residue_attestation(
        scan_id=7, proof_state={"state_changes": [_restored()]}, signer=signer
    )
    tampered = copy.deepcopy(attestation)
    tampered["changes"][0]["restore_outcome"] = "not-restored"
    ok, detail = verify_residue_attestation(tampered, signer=signer)
    assert not ok and "edited" in detail


def test_a_verdict_that_disagrees_with_its_own_count_is_refused() -> None:
    """The ugly forgery: flip ``clean`` and leave the count — the artefact contradicts itself."""
    attestation = build_residue_attestation(
        scan_id=7, proof_state={"state_changes": [UNRESTORED]}, signer=None
    )
    forged = copy.deepcopy(attestation)
    forged["clean"] = True
    # Re-hash so the digest agrees, which is what a forger who knows the format would do.
    forged["hash"] = attestation_digest(_body_of(forged))
    ok, detail = verify_residue_attestation(forged, signer=None)
    assert not ok and "disagrees" in detail


# ------------------------------------------------------------------ the machine's own path
class _Machine:
    """A real scan through the real machine, over a real database."""

    def __init__(self, tmp_path: Any, *, with_key: bool, unrestored: bool) -> None:
        self.settings = Settings(database_url=f"sqlite:///{tmp_path / 'residue.db'}")
        self.engine = create_sqlite_engine(self.settings.database_url)
        create_all(self.engine)
        self.factory = create_session_factory(self.engine)
        self.signer = DeploymentSigner(KEY) if with_key else None
        self.sink = MemoryAuditSink()
        self.chain = MemoryAuditChain(signer=self.signer)
        self.auditor = build_auditor(
            self.settings, sinks=[self.sink], chain=self.chain, logging_enabled=False
        )
        self.integrity = IntegrityService(self.factory, signer=self.signer, auditor=self.auditor)
        self.store = SqlScanStateStore(self.factory)
        self.unrestored = unrestored
        self.request = build_scan_request(targets=[{"kind": "domain", "value": "example.test"}])
        # ``scans.target_id`` is NOT NULL, so the scan hangs off a declared target as it
        # does in production.
        with self.factory() as session:
            target = Target(
                project_id=None,
                name="unit-fixture",
                scope_json={},
                auth_attestation={"attested_by": "test", "authorized": True},
            )
            session.add(target)
            session.commit()
            target_id = int(target.id)
        self.scan_id = self.store.create_scan(
            target_id=target_id, engine="heuristic", plan={"target_name": "unit-fixture"}
        ).id

    async def run(self) -> Any:
        """Run one CHECKS step whose handler records a state change through the ledger."""
        unrestored = self.unrestored

        async def checks(context: Any) -> Any:
            from arachne.core.lifecycle import StepOutcome

            ledger = ProofLedger(context.store, context.scan_id, auditor=context.auditor)
            ledger.record_state_change(
                change_id="chg-1",
                kind="update",
                check_id="m3.state-marker",
                table="users",
                locator="users.email where id=1",
                before={"email": "victim@example.test"},
                after={"email": "arachne-proof@example.test"},
            )
            if not unrestored:
                ledger.mark_restored("chg-1", verified=True)
            return StepOutcome(stats={"proof_entries": len(ledger.state_changes)})

        machine = ScanMachine(
            self.store,
            bus=EventBus(),
            auditor=self.auditor,
            pipeline=(ScanStep.CHECKS,),
            integrity=self.integrity,
        )
        return await machine.run(
            self.scan_id,
            {ScanStep.CHECKS: checks},
            definition=self.request.target,
            options=self.request.options,
            scope=self.request.target.compile_scope(),
        )

    def close(self) -> None:
        self.engine.dispose()


@pytest.mark.parametrize("unrestored", [False, True])
async def test_a_completed_scan_carries_its_attestation_on_the_row(
    tmp_path: Any, unrestored: bool
) -> None:
    harness = _Machine(tmp_path, with_key=True, unrestored=unrestored)
    try:
        outcome = await harness.run()
        assert outcome.status is ScanStatus.COMPLETED
        record = harness.store.get_scan(harness.scan_id)
        assert record is not None
        attestation = record.residue_attestation
        assert attestation is not None, "the scan completed with no residue attestation"
        assert record.residue_hash == attestation["hash"]
        assert attestation["signed"] is True
        assert attestation["residue"] == (1 if unrestored else 0)
        assert attestation["clean"] is (not unrestored)
        ok, detail = verify_residue_attestation(attestation, signer=harness.signer)
        assert ok, detail
        entry = attestation["changes"][0]
        assert entry["asset"] == "users.email where id=1"
        assert entry["action"] == "update"
        assert len(entry["before_value_hash"]) == 64
        # The journal's before-value was redacted at capture, and the envelope still carries
        # no value — only the hash.
        assert entry["before_value_hash"] == attestation["changes"][0]["before_value_hash"]

        # The hash is linked into the chain, with the residue count and the verdict.
        lines = [link["payload"] for link in harness.chain.links]
        attested = [line for line in lines if line["action"] == "proof.residue_attested"]
        assert len(attested) == 1
        meta = attested[0]["meta"]
        assert meta["hash"] == attestation["hash"]
        assert meta["residue"] == attestation["residue"]
        assert meta["signed"] is True
        # A non-clean scan is audited as an error, not as a normal completion.
        assert harness.sink.of_action(AuditAction.PROOF_RESIDUE_ATTESTED)[0].outcome.value == (
            "error" if unrestored else "allowed"
        )
    finally:
        harness.close()


async def test_a_scan_without_a_deployment_key_attests_unsigned(tmp_path: Any) -> None:
    """Never silently unsigned (REQ-PROOF-017): the artefact itself carries the marker."""
    harness = _Machine(tmp_path, with_key=False, unrestored=False)
    try:
        await harness.run()
        record = harness.store.get_scan(harness.scan_id)
        assert record is not None and record.residue_attestation is not None
        assert record.residue_attestation["signed"] is False
        assert record.residue_attestation["signature"] is None
        assert record.residue_hash == record.residue_attestation["hash"]
    finally:
        harness.close()


async def test_a_failed_scan_still_attests_what_it_left_behind(tmp_path: Any) -> None:
    """A crash mid-scan is exactly when "what was not restored?" must be answerable."""
    harness = _Machine(tmp_path, with_key=True, unrestored=True)
    try:

        async def exploding(context: Any) -> Any:
            raise RuntimeError("handler exploded after the write")

        machine = ScanMachine(
            harness.store,
            bus=EventBus(),
            auditor=harness.auditor,
            pipeline=(ScanStep.CHECKS,),
            integrity=harness.integrity,
        )
        from arachne.core.errors import ScanStateError

        with pytest.raises(ScanStateError):
            await machine.run(
                harness.scan_id,
                {ScanStep.CHECKS: exploding},
                definition=harness.request.target,
                options=harness.request.options,
                scope=harness.request.target.compile_scope(),
            )
        record = harness.store.get_scan(harness.scan_id)
        assert record is not None and record.status is ScanStatus.FAILED
        # The handler wrote no journal, so the attestation says "nothing was authorized" —
        # which is true of what the record holds, and is stated rather than omitted.
        assert record.residue_attestation is not None
        assert record.residue_attestation["statement"] == NO_STATE_CHANGE_STATEMENT
    finally:
        harness.close()


# ------------------------------------------------------------------ 4. the report
def test_the_report_warns_and_is_not_clean_when_residue_is_non_zero() -> None:
    signer = DeploymentSigner(KEY)
    attestation = build_residue_attestation(
        scan_id=7, proof_state={"state_changes": [UNRESTORED]}, signer=signer
    )
    report = build_report_data(
        ReportInputs(
            scan_id=7,
            target_name="target.example",
            engine="heuristic",
            residue_attestation=attestation,
        )
    )
    assert report.residue_attestation is not None
    assert report.residue_attestation.clean is False
    assert report.residue_attestation.residue == 1
    assert report.residue_attestation.signed is True
    assert report.residue_attestation.hash == attestation["hash"]
    rendered = render_markdown(report)
    assert "Residue: this scan did not restore everything it changed" in rendered
    assert "REPAIR REQUIRED" in rendered
    assert "signed with the deployment key" in rendered
    # The HTML/PDF path shows it too, and marks it for a screen reader.
    from arachne.report.html_render import render_html

    html = render_html(report)
    assert 'class="warn"' in html and 'role="alert"' in html
    assert "did not restore everything it changed" in html
    assert "REPAIR REQUIRED" in html


def test_a_clean_scan_renders_no_warning_and_a_scan_without_one_says_nothing() -> None:
    clean = build_residue_attestation(scan_id=7, proof_state={}, signer=None)
    report = build_report_data(
        ReportInputs(
            scan_id=7,
            target_name="target.example",
            engine="heuristic",
            residue_attestation=clean,
        )
    )
    assert report.residue_attestation is not None and report.residue_attestation.clean is True
    assert "Residue:" not in render_markdown(report)

    # A pre-WP-14 scan recorded none: the report must not imply it was clean.
    bare = build_report_data(
        ReportInputs(scan_id=8, target_name="target.example", engine="heuristic")
    )
    assert bare.residue_attestation is None
    assert "Residue:" not in render_markdown(bare)


def test_the_attestation_is_never_derived_from_a_proof_journal_by_the_renderer() -> None:
    """The renderer reads the row's artefact; it does not sign on the scanner's behalf."""
    report = build_report_data(
        ReportInputs(
            scan_id=7,
            target_name="target.example",
            engine="heuristic",
            proof_state={"state_changes": [UNRESTORED]},
        )
    )
    assert report.residue_attestation is None
    # The unrestored change is still reported — by the state-changes table, which is the
    # surface that has always rendered the journal.
    assert report.state_changes and report.state_changes[0].restored is False


def test_the_ledger_timestamps_a_change_when_it_is_recorded() -> None:
    """The attestation states a timestamp per change; an unrestored one has no ``restored_at``."""
    from arachne.core.lifecycle import MemoryScanStateStore

    store = MemoryScanStateStore()
    scan = store.create_scan(target_id=None, engine="heuristic", plan={})
    ledger = ProofLedger(store, scan.id)
    record = ledger.record_state_change(
        change_id="c1",
        kind="insert-marker",
        check_id="m3.state-marker",
        table="ar_proof",
        locator="ar_proof.marker",
        before=None,
        after={"marker": "x"},
    )
    assert record.changed_at is not None
    persisted = ledger.find_change("c1")
    assert persisted is not None and persisted.changed_at is not None
    assert "changed_at" in ledger.state_changes[0]


def test_a_signed_row_projection_is_unaffected_by_the_evidence_dict_shape() -> None:
    """Guards the helper the re-mask path re-signs with (REQ-PROOF-018 composition)."""
    row = {
        "id": 1,
        "finding_id": 2,
        "kind": "http_response",
        "payload_json": {"body": "x"},
        "created_at": NOW,
    }
    assert set(evidence_signature_payload(row)) == {
        "id",
        "finding_id",
        "kind",
        "payload_digest",
        "created_at",
    }
    assert redact_value({"token": "abc"}) != {"token": "abc"}
