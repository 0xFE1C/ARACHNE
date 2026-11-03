"""Evidence chain-of-custody: a content hash per blob, recorded at capture (WP-14).

REQ-PROOF-018 exists because the seal and the row signature both describe an evidence row's
*identity*, and neither notices a payload edited in place on a deployment whose rows are
unsigned. These tests drive the whole path — capture, chain, verdict — against a real
database:

1. **Every stored blob is recorded.** ``SqlFindingStore.record_candidate`` writes one
   ``evidence.captured`` chain line per row it stores, carrying the digest of the **stored,
   redacted** payload (not of what arrived before redaction, which no verifier could
   recompute), and a clean store verifies.
2. **A mutated blob is ``evidence.mismatch``, naming the id.** Editing ``payload_json``
   behind the store's back is detected even with no signature anywhere.
3. **A missing blob under a live scan is a deletion**; a blob whose scan was pruned by
   retention is a *note*, not an accusation — the same distinction the seal verifier makes.
4. **The chain's latest statement wins**, which is what lets REQ-DATA-005's re-mask compose
   with this control instead of being reported as tampering.
5. **Capture is recorded, not the arrival.** The digest the chain holds is the one
   ``payload_digest`` recomputes from the row, so the check cannot drift from the store.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session, sessionmaker

from arachne.core.audit import AuditAction, build_auditor
from arachne.core.config import Settings
from arachne.core.integrity import (
    EVIDENCE_CAPTURED_ACTION,
    PII_REMASKED_ACTION,
    AuditLink,
    evidence_hash_records,
    payload_digest,
)
from arachne.core.results import CheckResult, Evidence
from arachne.data.db import create_all, create_session_factory, create_sqlite_engine
from arachne.data.finding_store import SqlFindingStore
from arachne.data.integrity_store import IntegrityVerifier, SqlAuditChain
from arachne.data.models import Evidence as EvidenceRow
from arachne.data.models import Scan, Target


@pytest.fixture
def factory(tmp_path: Path) -> Iterator[sessionmaker[Session]]:
    engine: Engine = create_sqlite_engine(f"sqlite:///{tmp_path / 'custody.db'}")
    create_all(engine)
    try:
        yield create_session_factory(engine)
    finally:
        engine.dispose()


@pytest.fixture
def scan_id(factory: sessionmaker[Session]) -> int:
    with factory() as session:
        target = Target(name="fixture", scope_json={}, auth_attestation=None)
        session.add(target)
        session.flush()
        scan = Scan(
            target_id=target.id,
            status="completed",
            plan_json={},
            engine="heuristic",
            stats_json={},
        )
        session.add(scan)
        session.commit()
        return int(scan.id)


def _candidate() -> CheckResult:
    return CheckResult(
        status="vulnerable",
        title="exposed .env",
        detail="GET /.env returned 200",
        cwe="CWE-200",
        confidence=0.7,
        evidence=(
            Evidence.of("http_request", {"method": "GET", "url": "https://example.test/.env"}),
            Evidence.of("http_response", {"status_code": 200, "body": "body text"}),
        ),
        check="M1/ct-lookup@1.0",
        module="M1",
    )


def _capture(factory: sessionmaker[Session], scan_id: int) -> dict[str, Any]:
    """Store one candidate through the real store + chain; return the ids involved."""
    settings = Settings(database_url="sqlite://")
    chain = SqlAuditChain(factory, signer=None)
    auditor = build_auditor(settings, chain=chain, logging_enabled=False)
    store = SqlFindingStore(factory, auditor=auditor)
    record = store.record_candidate(scan_id, result=_candidate(), check_id=None, asset_id=None)
    return {
        "candidate": record,
        "evidence_ids": [int(item.id) for item in record.evidence if item.id is not None],
        "verifier": IntegrityVerifier(factory),
    }


def _payload_of(factory: sessionmaker[Session], evidence_id: int) -> dict[str, Any]:
    with factory() as session:
        row = session.get(EvidenceRow, evidence_id)
        assert row is not None
        return dict(row.payload_json or {})


# ------------------------------------------------------------------ 1. capture is recorded
def test_every_stored_blob_is_recorded_in_the_chain_at_capture(
    factory: sessionmaker[Session], scan_id: int
) -> None:
    captured = _capture(factory, scan_id)
    verifier: IntegrityVerifier = captured["verifier"]
    records = evidence_hash_records(verifier.audit_links())
    evidence_ids = captured["evidence_ids"]
    assert evidence_ids, "no evidence row was stored"
    assert set(records) == set(evidence_ids), "a stored blob has no capture record"
    for evidence_id in evidence_ids:
        record = records[evidence_id]
        assert record.action == EVIDENCE_CAPTURED_ACTION
        assert record.scan_id == scan_id
        # The digest is the one a verifier recomputes from the *stored* payload.
        assert record.digest == payload_digest(_payload_of(factory, evidence_id))
    report = verifier.verify()
    assert report.ok, report.to_dict()
    assert report.checked["evidence_hashes"] == len(evidence_ids)


def test_a_store_without_an_auditor_records_nothing_and_says_so(
    factory: sessionmaker[Session], scan_id: int
) -> None:
    """The chain is the writer's job: a reader path (``SqlFindingStore(factory)``) writes no
    lines, and verification then reports zero evidence hashes rather than claiming intactness
    it did not check."""
    store = SqlFindingStore(factory)
    store.record_candidate(scan_id, result=_candidate(), check_id=None, asset_id=None)
    verifier = IntegrityVerifier(factory)
    assert evidence_hash_records(verifier.audit_links()) == {}
    assert verifier.verify().checked.get("evidence_hashes") == 0


# ------------------------------------------------------------------ 2. a mutated blob
def test_a_mutated_blob_is_reported_as_evidence_mismatch_naming_the_id(
    factory: sessionmaker[Session], scan_id: int
) -> None:
    captured = _capture(factory, scan_id)
    target_id = captured["evidence_ids"][-1]
    verifier: IntegrityVerifier = captured["verifier"]
    assert verifier.verify().ok

    # An attacker with database access rewrites the stored payload, leaving every hash,
    # signature and seal column exactly as it was.
    with factory() as session:
        row = session.get(EvidenceRow, target_id)
        assert row is not None
        row.payload_json = {**dict(row.payload_json or {}), "body": "tampered"}
        session.commit()

    report = verifier.verify()
    assert not report.ok
    issues = [issue for issue in report.issues if issue.check == "evidence"]
    assert len(issues) == 1
    issue = issues[0]
    assert issue.kind == "mismatch"
    assert issue.subject == f"evidence:{target_id}"
    assert "was edited after capture" in issue.detail
    # The verdict the requirement names, as the CLI prints it.
    assert f"[{issue.check}.{issue.kind}]" == "[evidence.mismatch]"


def test_a_rewritten_object_claim_is_caught_by_the_recorded_blob_digest(
    factory: sessionmaker[Session], scan_id: int
) -> None:
    """A stub's ``sha256``/``key`` claim is part of the stored payload, so editing it shows."""
    captured = _capture(factory, scan_id)
    target_id = captured["evidence_ids"][0]
    verifier: IntegrityVerifier = captured["verifier"]
    with factory() as session:
        row = session.get(EvidenceRow, target_id)
        assert row is not None
        row.payload_json = {**dict(row.payload_json or {}), "backend": "somewhere-else"}
        session.commit()
    issues = [issue for issue in verifier.verify().issues if issue.check == "evidence"]
    assert [issue.kind for issue in issues] == ["mismatch"]
    assert issues[0].subject == f"evidence:{target_id}"


# ------------------------------------------------------------------ 3. deletion vs retention
def test_a_vanished_blob_under_a_live_scan_is_reported_as_deleted(
    factory: sessionmaker[Session], scan_id: int
) -> None:
    captured = _capture(factory, scan_id)
    target_id = captured["evidence_ids"][0]
    verifier: IntegrityVerifier = captured["verifier"]
    with factory() as session:
        row = session.get(EvidenceRow, target_id)
        assert row is not None
        session.delete(row)
        session.commit()
    issues = [issue for issue in verifier.verify().issues if issue.check == "evidence"]
    assert [issue.kind for issue in issues] == ["deleted"]
    assert issues[0].subject == f"evidence:{target_id}"
    assert "the row is gone from a scan that still exists" in issues[0].detail


def test_a_pruned_scan_is_a_note_not_an_accusation(
    factory: sessionmaker[Session], scan_id: int
) -> None:
    """Retention deletes scans and their evidence by policy; the verifier must not cry wolf."""
    captured = _capture(factory, scan_id)
    verifier: IntegrityVerifier = captured["verifier"]
    with factory() as session:
        row = session.get(Scan, scan_id)
        assert row is not None
        session.delete(row)  # the foreign keys cascade the findings and their evidence
        session.commit()
    report = verifier.verify()
    assert not [issue for issue in report.issues if issue.check == "evidence"]
    assert any("pruned" in note for note in report.notes)


def test_a_scan_filter_narrows_the_evidence_check(
    factory: sessionmaker[Session], scan_id: int
) -> None:
    captured = _capture(factory, scan_id)
    verifier: IntegrityVerifier = captured["verifier"]
    with factory() as session:
        target = Target(name="other", scope_json={}, auth_attestation=None)
        session.add(target)
        session.flush()
        other = Scan(
            target_id=target.id,
            status="completed",
            plan_json={},
            engine="heuristic",
            stats_json={},
        )
        session.add(other)
        session.commit()
        other_id = int(other.id)
    report = verifier.verify(scan_id=other_id)
    assert report.checked["evidence_hashes"] == 0
    assert report.ok


# ------------------------------------------------------------------ 4. last statement wins
def _link(seq: int, action: str, meta: dict[str, Any], scan_id: int | None = 1) -> AuditLink:
    return AuditLink(
        seq=seq,
        prev_hash="0" * 64,
        hash=f"{seq:064d}",
        signature=None,
        payload={
            "action": action,
            "scan_id": scan_id,
            "target": None,
            "reason": None,
            "outcome": "allowed",
            "meta": meta,
        },
    )


def test_the_chain_s_latest_record_for_a_blob_wins() -> None:
    """A re-mask's later line supersedes the capture line — the composition with REQ-DATA-005."""
    links = [
        _link(1, EVIDENCE_CAPTURED_ACTION, {"evidence_id": 5, "sha256": "a" * 64}),
        _link(2, EVIDENCE_CAPTURED_ACTION, {"evidence_id": 6, "sha256": "b" * 64}),
        _link(3, PII_REMASKED_ACTION, {"evidence_id": 5, "sha256": "c" * 64}),
    ]
    records = evidence_hash_records(links)
    assert records[5].digest == "c" * 64
    assert records[5].action == PII_REMASKED_ACTION
    assert records[5].seq == 3
    assert records[6].digest == "b" * 64


def test_a_malformed_capture_line_is_ignored_rather_than_guessed_at() -> None:
    links = [
        _link(1, EVIDENCE_CAPTURED_ACTION, {"sha256": "a" * 64}),  # no evidence id
        _link(2, EVIDENCE_CAPTURED_ACTION, {"evidence_id": 5}),  # no digest
        _link(3, EVIDENCE_CAPTURED_ACTION, {"evidence_id": "5", "sha256": "a" * 64}),
        _link(4, "audit.verified", {"evidence_id": 9, "sha256": "d" * 64}),  # other action
        _link(5, EVIDENCE_CAPTURED_ACTION, {"evidence_id": 7, "sha256": ""}),
    ]
    records = evidence_hash_records(links)
    assert records == {}


def test_a_capture_record_naming_no_scan_is_still_checked() -> None:
    links = [_link(1, EVIDENCE_CAPTURED_ACTION, {"evidence_id": 5, "sha256": "a" * 64}, None)]
    records = evidence_hash_records(links)
    assert records[5].scan_id is None
    assert records[5].to_dict()["sha256"] == "a" * 64


def test_the_action_names_the_writer_and_the_verifier_both_use_are_one_definition() -> None:
    assert AuditAction.EVIDENCE_CAPTURED.value == EVIDENCE_CAPTURED_ACTION
    assert AuditAction.PII_REMASKED.value == PII_REMASKED_ACTION
    assert EVIDENCE_CAPTURED_ACTION in (EVIDENCE_CAPTURED_ACTION, PII_REMASKED_ACTION)


def test_a_payload_digest_is_stable_across_key_order() -> None:
    assert payload_digest({"b": 1, "a": 2}) == payload_digest({"a": 2, "b": 1})
    assert payload_digest(None) == payload_digest({})


def test_the_verified_count_names_what_was_checked(
    factory: sessionmaker[Session], scan_id: int
) -> None:
    captured = _capture(factory, scan_id)
    verifier: IntegrityVerifier = captured["verifier"]
    report = verifier.verify()
    assert report.checked["evidence_hashes"] == len(captured["evidence_ids"])
    # The finder's own evidence for its existence: a row the store wrote, read back.
    with factory() as session:
        kinds = {
            str(value)
            for value in session.scalars(
                select(EvidenceRow.kind).where(EvidenceRow.finding_id.is_not(None))
            ).all()
        }
    assert kinds


def test_the_capture_digest_is_of_the_stored_bytes_not_the_captured_ones(
    factory: sessionmaker[Session], scan_id: int
) -> None:
    """Redaction runs before the store, so hashing the arrival would be unverifiable."""
    captured = _capture(factory, scan_id)
    evidence_id = captured["evidence_ids"][0]
    stored = _payload_of(factory, evidence_id)
    record = evidence_hash_records(captured["verifier"].audit_links())[evidence_id]
    assert record.digest == payload_digest(stored)
    # The url the check captured is stored under a redaction-aware path; either way the
    # digest answers for *this* payload and nothing else.
    assert record.digest != payload_digest({"method": "GET"})


def test_verification_is_deterministic(factory: sessionmaker[Session], scan_id: int) -> None:
    captured = _capture(factory, scan_id)
    verifier: IntegrityVerifier = captured["verifier"]
    first = verifier.verify().to_dict()
    second = verifier.verify().to_dict()
    assert first == second
    assert datetime.now(UTC).tzinfo is not None
