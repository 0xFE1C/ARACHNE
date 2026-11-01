"""Audit schema and sink tests (F-01-08, F-08-05)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from arachne.core.audit import (
    AUDIT_SCHEMA_VERSION,
    AuditAction,
    AuditEvent,
    Auditor,
    AuditOutcome,
    JsonlAuditSink,
    LoggingAuditSink,
    MemoryAuditChain,
    MemoryAuditSink,
    MultiAuditSink,
)
from arachne.core.integrity import AUDIT_DOMAIN, GENESIS_HASH
from arachne.core.signing import DeploymentSigner

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"


def test_event_schema_is_fixed() -> None:
    event = AuditEvent(action=AuditAction.HTTP_REQUEST)
    assert event.schema_version == AUDIT_SCHEMA_VERSION
    assert event.outcome is AuditOutcome.ALLOWED
    payload = event.to_dict()
    assert set(payload) == {
        "schema_version",
        "id",
        "ts",
        "actor",
        "action",
        "outcome",
        "target",
        "reason",
        "scan_id",
        "meta",
        # S25 (REQ-TRUST-005): the hash-chain fields. They are part of the event schema
        # because every sink must record the same position and digest; a deployment with no
        # chain (a dry run, a plain in-memory sink) leaves them ``None``.
        "seq",
        "prev_hash",
        "hash",
        "signature",
    }
    assert event.seq is None and event.hash is None and event.signature is None
    # Fixed schema: unknown fields are rejected rather than silently stored.
    with pytest.raises(ValidationError):
        AuditEvent(action=AuditAction.HTTP_REQUEST, unexpected="x")  # type: ignore[call-arg]


def test_a_chained_event_carries_its_position_and_digest() -> None:
    """S25: the Auditor stamps the chain fields before any sink sees the event."""
    signer = DeploymentSigner("unit-test-integrity-key-0001")
    chain = MemoryAuditChain(signer=signer)
    sink = MemoryAuditSink()
    auditor = Auditor(sink, actor="pytest", chain=chain)

    first = auditor.record(AuditAction.SCAN_STARTED, scan_id=1)
    second = auditor.record(AuditAction.SCAN_FINISHED, scan_id=1)

    assert (first.seq, second.seq) == (1, 2)
    assert first.prev_hash == GENESIS_HASH
    assert second.prev_hash == first.hash
    assert first.hash is not None and len(first.hash) == 64
    # The signature is over the hash, in the audit domain.
    assert first.signature is not None
    assert signer.verify(AUDIT_DOMAIN, (first.hash or "").encode("ascii"), first.signature)
    # The sink and the chain see the same event.
    assert [event.seq for event in sink.events] == [1, 2]


def test_with_actor_keeps_the_same_chain() -> None:
    """A node-scoped facade must not fork the sequence a verifier walks."""
    chain = MemoryAuditChain()
    auditor = Auditor(MemoryAuditSink(), actor="pytest", chain=chain)
    agent = auditor.with_actor("agent:node-a")

    first = auditor.record(AuditAction.SCAN_STARTED, scan_id=1)
    second = agent.record(AuditAction.SCAN_STEP_STARTED, scan_id=1)

    assert second.seq == first.seq + 1
    assert second.actor == "agent:node-a"
    assert second.prev_hash == first.hash


def test_event_is_immutable() -> None:
    event = AuditEvent(action=AuditAction.HTTP_REQUEST)
    with pytest.raises(ValidationError):
        event.actor = "someone-else"  # type: ignore[misc]


def test_event_requires_timezone_aware_timestamp() -> None:
    with pytest.raises(ValidationError, match="timezone-aware"):
        AuditEvent(action=AuditAction.HTTP_REQUEST, ts=datetime(2026, 1, 1))


def test_action_and_outcome_vocabularies_are_enums() -> None:
    assert AuditAction.HTTP_REQUEST.value == "http.request"
    assert AuditAction.HTTP_REQUEST_BLOCKED.value == "http.request_blocked"
    assert AuditOutcome.BLOCKED.value == "blocked"
    with pytest.raises(ValueError, match="not a valid"):
        AuditAction("not.an.action")


def test_auditor_redacts_target_reason_and_meta() -> None:
    sink = MemoryAuditSink()
    auditor = Auditor(sink, actor="pytest")
    event = auditor.record(
        AuditAction.SAFETY_BLOCKED,
        outcome=AuditOutcome.BLOCKED,
        target=f"https://example.com/x?api_key={AWS_KEY}",
        reason=f"blocked because of {AWS_KEY}",
        meta={"body": f"key={AWS_KEY}", "status": 403},
    )

    assert AWS_KEY not in (event.target or "")
    assert AWS_KEY not in (event.reason or "")
    assert AWS_KEY not in json.dumps(event.meta)
    assert event.meta["status"] == 403
    assert sink.events == [event]


def test_memory_sink_filters_by_action() -> None:
    sink = MemoryAuditSink()
    auditor = Auditor(sink)
    auditor.record(AuditAction.HTTP_REQUEST)
    auditor.record(AuditAction.SCOPE_REJECTED, outcome=AuditOutcome.BLOCKED)
    auditor.record(AuditAction.HTTP_REQUEST)

    assert len(sink.of_action(AuditAction.HTTP_REQUEST)) == 2
    assert sink.actions() == ["http.request", "scope.rejected", "http.request"]


def test_jsonl_sink_writes_one_redacted_json_object_per_line(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "audit.jsonl"
    sink = JsonlAuditSink(path)
    auditor = Auditor(sink)
    auditor.record(AuditAction.HTTP_REQUEST, target=f"https://example.com/?k={AWS_KEY}")
    auditor.record(AuditAction.SCAN_STARTED, scan_id="scan-1")

    lines = path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    first = json.loads(lines[0])
    assert first["action"] == "http.request"
    assert AWS_KEY not in lines[0]
    assert json.loads(lines[1])["scan_id"] == "scan-1"


def test_jsonl_sink_does_not_raise_on_unwritable_path(tmp_path: Path) -> None:
    """Audit failures are logged, not propagated (an audit line is not worth a scan)."""
    blocker = tmp_path / "blocker"
    blocker.write_text("not a directory", encoding="utf-8")
    sink = JsonlAuditSink(blocker / "audit.jsonl")

    sink.record(AuditEvent(action=AuditAction.HTTP_REQUEST))  # must not raise


def test_multi_sink_fans_out_and_survives_a_broken_sink() -> None:
    good = MemoryAuditSink()

    class Exploding:
        def record(self, event: AuditEvent) -> None:
            raise RuntimeError("disk on fire")

    multi = MultiAuditSink([Exploding(), good])
    multi.record(AuditEvent(action=AuditAction.HTTP_REQUEST))

    assert len(good.events) == 1


def test_logging_sink_emits_structured_record(caplog: pytest.LogCaptureFixture) -> None:
    sink = LoggingAuditSink()
    with caplog.at_level("INFO", logger="arachne.core.audit"):
        sink.record(AuditEvent(action=AuditAction.SCAN_STARTED, scan_id="scan-9"))

    assert any(record.__dict__.get("event") == "audit" for record in caplog.records)


def test_event_timestamp_defaults_to_now_utc() -> None:
    event = AuditEvent(action=AuditAction.CONFIG_LOADED)
    assert event.ts.tzinfo is UTC
    assert abs((datetime.now(UTC) - event.ts).total_seconds()) < 5
