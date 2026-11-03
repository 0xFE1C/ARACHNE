"""The PII retention re-mask, end to end (WP-14, REQ-DATA-005).

The gap this closes was not a missing feature but a **false claim**: the configuration and
``core/pii.py`` both said evidence older than ``ARACHNE_PII_RETENTION_DAYS`` is re-masked,
and nothing consumed the value. A privacy control a customer believes is active and is not
is the worst kind of defect this repository can ship, so these tests drive the *whole* path
against a real database rather than asserting that a function exists:

1. **The variable is consumed.** The pruner's window comes from
   ``settings.pii.retention_days``, and a seeded blob older than it is selected; the same
   blob under ``0`` (the default) is not. Nothing else in the tree consumes it.
2. **A dry run changes nothing.** The plan counts what it *would* mask — by category, never
   by value — and the stored payload is byte-identical afterwards.
3. **The real run masks, and says so.** The stored payload no longer contains the PII, the
   counts are reported, and there is exactly **one audit event per masked blob** carrying
   the blob's new content hash and no value.
4. **A store that cannot be re-masked is reported.** An offloaded payload stays untouched
   and is named in the plan and in an audit line, instead of vanishing from both.
5. **The evidence-integrity record follows the mutation.** A blob recorded in the chain at
   capture is re-recorded when retention masks it, so ``verify-chain`` stays green: the two
   controls compose rather than contradicting each other (REQ-PROOF-018).
6. **A legal hold freezes the re-mask** as well as the deletion: an operator who suspended
   retention has not asked for stored evidence to be rewritten.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from arachne.core.audit import (
    AuditAction,
    Auditor,
    MemoryAuditChain,
    MemoryAuditSink,
    build_auditor,
)
from arachne.core.config import PiiSettings, RetentionSettings, Settings
from arachne.core.integrity import evidence_hash_records, payload_digest
from arachne.core.pii import PIIPolicy
from arachne.data.db import create_all, create_session_factory, create_sqlite_engine
from arachne.data.integrity_store import IntegrityService, IntegrityVerifier, SqlAuditChain
from arachne.data.models import Evidence, Finding, Project, Scan, Target
from arachne.data.retention import OFFLOADED_REMASK_REASON, RetentionPruner

NOW = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)
OLD = NOW - timedelta(days=400)

#: Real-looking PII the detectors accept (an address and a Luhn-valid card number). Each is
#: checked against the *detector* rather than assumed, so a change to the patterns shows up
#: here rather than as a silently uninteresting fixture.
EMAIL = "dana.reeves@example.com"
CARD = "4111 1111 1111 1111"


def _settings(tmp_path: Any, *, retention_days: int, action: str = "mask") -> Settings:
    return Settings(
        database_url=f"sqlite:///{tmp_path / 'pii.db'}",
        retention=RetentionSettings(batch_limit=1_000),
        pii=PiiSettings(
            enabled=True,
            action=action,
            categories=("email", "credit-card"),
            retention_days=retention_days,
        ),
    )


def _seed(settings: Settings, *, age_days: int = 400, offloaded: bool = False) -> dict[str, int]:
    """One project, one scan, one finding and one evidence payload holding PII."""
    engine = create_sqlite_engine(settings.database_url)
    create_all(engine)
    factory = create_session_factory(engine)
    with factory() as session:
        project = Project(
            slug="acme",
            name="Acme",
            scope_json={},
            branding_json={},
            retention_json={
                "scans_days": 0,
                "findings_days": 0,
                "evidence_days": 0,
                "audit_days": 0,
            },
        )
        session.add(project)
        session.flush()
        target = Target(
            project_id=int(project.id),
            name="acme.example",
            scope_json={},
            auth_attestation={"attested_by": "test", "authorized": True},
        )
        session.add(target)
        session.flush()
        created = NOW - timedelta(days=age_days)
        scan = Scan(
            target_id=int(target.id),
            project_id=int(project.id),
            status="completed",
            plan_json={},
            engine="heuristic",
            stats_json={},
            created_at=created,
        )
        session.add(scan)
        session.flush()
        finding = Finding(
            scan_id=int(scan.id),
            check_id=None,
            asset_id=None,
            title="exposed export",
            severity=None,
            confidence=50.0,
            status="open",
            evidence_refs_json=[],
            created_at=created,
        )
        session.add(finding)
        session.flush()
        payload: dict[str, Any]
        storage: str
        key: str | None
        if offloaded:
            # The stub an offloaded row keeps: a bounded preview plus the object reference.
            # Its body carries no PII (the evidence service masks *before* it builds the
            # stub), which is what makes it unmaskable-here rather than already masked.
            payload = {
                "offloaded": True,
                "backend": "local",
                "key": "a" * 64,
                "sha256": "a" * 64,
                "size": 4_096,
                "body": "large response",
            }
            storage, key = "local", "a" * 64
        else:
            payload = {"body": f"contact {EMAIL} card {CARD}"}
            storage, key = "inline", None
        row = Evidence(
            finding_id=int(finding.id),
            kind="http_response",
            payload_json=payload,
            sha256=None,
            size_bytes=128,
            storage=storage,
            storage_key=key,
            created_at=created,
        )
        session.add(row)
        session.commit()
        ids = {
            "project": int(project.id),
            "scan": int(scan.id),
            "finding": int(finding.id),
            "evidence": int(row.id),
        }
    engine.dispose()
    return ids


def _pruner(settings: Settings, sink: MemoryAuditSink | None = None) -> RetentionPruner:
    engine = create_sqlite_engine(settings.database_url)
    factory = create_session_factory(engine)
    policy = PIIPolicy.from_settings(settings.pii)
    auditor = build_auditor(settings, sinks=[sink]) if sink is not None else None
    return RetentionPruner(
        factory,
        settings=settings,
        auditor=auditor,
        pii_policy=lambda project_id: policy,
    )


def _payload_of(settings: Settings, evidence_id: int) -> dict[str, Any]:
    engine = create_sqlite_engine(settings.database_url)
    factory = create_session_factory(engine)
    try:
        with factory() as session:
            row = session.get(Evidence, evidence_id)
            assert row is not None
            return dict(row.payload_json or {})
    finally:
        engine.dispose()


# ------------------------------------------------------------------ 1. the variable is consumed
def test_the_retention_window_comes_from_the_configured_variable(tmp_path: Any) -> None:
    """``ARACHNE_PII_RETENTION_DAYS`` is read by the pruner, and only it selects the blob."""
    settings = _settings(tmp_path, retention_days=90)
    ids = _seed(settings)
    pruner = _pruner(settings)
    assert pruner.pii_retention_days == 90

    plan = pruner.plan(now=NOW)
    assert plan.pii.rows == 1, "a blob older than the window was not selected"
    assert plan.pii.ids == (ids["evidence"],)
    assert plan.pii.categories == {"email": 1, "credit-card": 1}
    assert plan.pii.oldest is not None and plan.pii.oldest < NOW - timedelta(days=89)

    # ...and a blob *inside* the window is not: the fixture is aged 400 days, so a 500-day
    # window must select nothing. Without this the test would pass on "select everything".
    wide = _settings(tmp_path, retention_days=500)
    assert _pruner(wide).plan(now=NOW).pii.rows == 0

    # The default is 0 = "mask at capture only, never re-mask", so a deployment that never
    # asked for this keeps its payloads byte-identical.
    off = _settings(tmp_path, retention_days=0)
    assert _pruner(off).plan(now=NOW).pii.rows == 0


def test_the_pruner_reports_an_inactive_policy_rather_than_masking_blindly(tmp_path: Any) -> None:
    """A policy with ``enabled=false`` masks nothing, and the plan says so by being empty."""
    settings = _settings(tmp_path, retention_days=90)
    ids = _seed(settings)
    engine = create_sqlite_engine(settings.database_url)
    factory = create_session_factory(engine)
    pruner = RetentionPruner(
        factory,
        settings=settings,
        pii_policy=lambda project_id: PIIPolicy(enabled=False),
    )
    plan = pruner.plan(now=NOW)
    assert plan.pii.rows == 0
    assert EMAIL in str(_payload_of(settings, ids["evidence"]))
    engine.dispose()


# ------------------------------------------------------------------ 2 and 3. dry run, then real
async def test_a_dry_run_changes_nothing_and_the_real_run_masks(tmp_path: Any) -> None:
    """The acceptance test: dry run (no change), then real (masked), counts without values."""
    settings = _settings(tmp_path, retention_days=90)
    ids = _seed(settings)
    sink = MemoryAuditSink()
    pruner = _pruner(settings, sink)

    before = _payload_of(settings, ids["evidence"])
    assert EMAIL in str(before) and CARD in str(before)

    planned = await pruner.prune(dry_run=True, now=NOW)
    assert planned.dry_run is True
    assert planned.pii.rows == 1
    # A dry run is a *read*: the stored payload is byte-identical, and nothing was masked.
    assert _payload_of(settings, ids["evidence"]) == before
    assert sink.of_action(AuditAction.PII_REMASKED) == []
    planned_line = sink.of_action(AuditAction.RETENTION_PLANNED)[-1]
    assert planned_line.meta["dry_run"] is True
    assert planned_line.meta["pii"]["blobs"] == 1
    assert planned_line.meta["pii"]["categories"] == {"credit-card": 1, "email": 1}

    applied = await pruner.prune(dry_run=False, now=NOW)
    assert applied.pii.rows == 1
    after = _payload_of(settings, ids["evidence"])
    assert EMAIL not in str(after) and CARD not in str(after)
    assert "[PII:email]" in str(after) and "[PII:credit-card]" in str(after)

    # One audit event per masked blob, carrying counts and the new content hash — never a
    # value. One blob, so one event.
    masked = sink.of_action(AuditAction.PII_REMASKED)
    assert len(masked) == 1
    event = masked[0]
    assert event.meta["evidence_id"] == ids["evidence"]
    assert event.meta["categories"] == {"credit-card": 1, "email": 1}
    assert event.meta["total"] == 2
    assert event.meta["sha256"] == payload_digest(after)
    rendered = str(event.meta)
    assert EMAIL not in rendered and CARD not in rendered
    # The run's own line reports the re-mask too, so "what did this run do?" is one read.
    run_line = sink.of_action(AuditAction.RETENTION_PRUNED)[-1]
    assert run_line.meta["pii"]["blobs"] == 1


async def test_the_re_mask_is_reported_per_blob_across_several_blobs(tmp_path: Any) -> None:
    """Two blobs that both hold PII produce two events, not one aggregate line."""
    settings = _settings(tmp_path, retention_days=90)
    ids = _seed(settings)
    engine = create_sqlite_engine(settings.database_url)
    factory = create_session_factory(engine)
    with factory() as session:
        session.add(
            Evidence(
                finding_id=ids["finding"],
                kind="http_response",
                payload_json={"body": f"backup contact {EMAIL}"},
                sha256=None,
                size_bytes=64,
                storage="inline",
                created_at=OLD,
            )
        )
        session.commit()
    engine.dispose()

    sink = MemoryAuditSink()
    pruner = _pruner(settings, sink)
    applied = await pruner.prune(dry_run=False, now=NOW)
    assert applied.pii.rows == 2
    assert len(sink.of_action(AuditAction.PII_REMASKED)) == 2


# ------------------------------------------------------------------ 4. an unmaskable store
async def test_an_offloaded_blob_is_reported_not_silently_skipped(tmp_path: Any) -> None:
    """A store this pruner cannot re-mask is named — in the plan and in the audit trail."""
    settings = _settings(tmp_path, retention_days=90)
    ids = _seed(settings, offloaded=True)
    sink = MemoryAuditSink()
    pruner = _pruner(settings, sink)

    plan = pruner.plan(now=NOW)
    assert plan.pii.rows == 0
    assert plan.pii.unsupported == {OFFLOADED_REMASK_REASON: 1}
    assert plan.pii.unsupported_ids == (ids["evidence"],)
    as_dict = plan.to_dict()
    assert as_dict["pii"]["unsupported"] == {OFFLOADED_REMASK_REASON: 1}
    assert "unsupported" in plan.projects[0].to_dict()["pii"]

    before = _payload_of(settings, ids["evidence"])
    applied = await pruner.prune(dry_run=False, now=NOW)
    assert applied.pii.rows == 0
    # Untouched — and reported, which is the difference between "not done" and "not said".
    assert _payload_of(settings, ids["evidence"]) == before
    reported = sink.of_action(AuditAction.PII_REMASK_UNSUPPORTED)
    assert len(reported) == 1
    assert reported[0].meta["evidence_ids"] == [ids["evidence"]]
    assert reported[0].outcome.value == "error"


# ------------------------------------------------------------------ 5. composition with custody
async def test_a_re_mask_keeps_the_chain_of_custody_true(tmp_path: Any) -> None:
    """``verify-chain`` stays green after a re-mask: the chain records the new digest.

    This is the interaction that would otherwise make two controls contradict each other:
    REQ-PROOF-018 records each blob's hash in the audit chain at capture, and REQ-DATA-005
    later rewrites the blob. The re-mask's own audit line carries the new hash, and the
    verifier takes the chain's latest statement, so the privacy control does not read as
    tampering.
    """
    settings = _settings(tmp_path, retention_days=90)
    ids = _seed(settings)
    engine = create_sqlite_engine(settings.database_url)
    factory = create_session_factory(engine)

    # The capture record, exactly as SqlFindingStore writes it: the digest of the stored
    # (redacted) payload, in a chained audit row.
    chain = SqlAuditChain(factory, signer=None)
    auditor = build_auditor(settings, chain=chain, logging_enabled=False)
    with factory() as session:
        stored = session.get(Evidence, ids["evidence"])
        assert stored is not None
        auditor.record(
            AuditAction.EVIDENCE_CAPTURED,
            scan_id=ids["scan"],
            target=f"evidence:{ids['evidence']}",
            meta={
                "evidence_id": ids["evidence"],
                "sha256": payload_digest(dict(stored.payload_json or {})),
                "kind": stored.kind,
                "storage": stored.storage or "inline",
                "size": int(stored.size_bytes or 0),
            },
        )
    verifier = IntegrityVerifier(factory)
    assert verifier.verify().ok, verifier.verify().to_dict()

    policy = PIIPolicy.from_settings(settings.pii)
    pruner = RetentionPruner(
        factory,
        settings=settings,
        auditor=auditor,
        pii_policy=lambda project_id: policy,
        integrity=IntegrityService(factory, signer=None, auditor=auditor),
    )
    await pruner.prune(dry_run=False, now=NOW)

    # The chain's latest statement about the blob is now the re-mask's digest, and the
    # stored payload agrees with it — so the evidence-hash check is green.
    links = verifier.audit_links()
    records = evidence_hash_records(links)
    after = _payload_of(settings, ids["evidence"])
    assert records[ids["evidence"]].action == AuditAction.PII_REMASKED.value
    assert records[ids["evidence"]].digest == payload_digest(after)
    report = verifier.verify()
    assert report.ok, report.to_dict()

    engine.dispose()


# ------------------------------------------------------------------ 6. a legal hold freezes it
async def test_a_legal_hold_stops_the_re_mask_as_well_as_the_deletion(tmp_path: Any) -> None:
    settings = _settings(tmp_path, retention_days=90)
    ids = _seed(settings)
    engine = create_sqlite_engine(settings.database_url)
    factory = create_session_factory(engine)
    with factory() as session:
        project = session.get(Project, ids["project"])
        assert project is not None
        project.retention_json = {"enabled": False}
        session.commit()
    policy = PIIPolicy.from_settings(settings.pii)
    pruner = RetentionPruner(factory, settings=settings, pii_policy=lambda project_id: policy)
    plan = pruner.plan(now=NOW)
    assert plan.pii.rows == 0
    applied = await pruner.prune(dry_run=False, now=NOW)
    assert applied.pii.rows == 0
    assert EMAIL in str(_payload_of(settings, ids["evidence"]))
    engine.dispose()


# ------------------------------------------------------------------ the auditor's own wiring
def test_a_deployment_with_no_policy_resolver_never_remasks(tmp_path: Any) -> None:
    """``build_retention_pruner`` is the only wiring; a bare pruner masks nothing."""
    settings = _settings(tmp_path, retention_days=90)
    ids = _seed(settings)
    engine = create_sqlite_engine(settings.database_url)
    factory = create_session_factory(engine)
    pruner = RetentionPruner(factory, settings=settings)
    assert isinstance(pruner.auditor, Auditor | None)
    assert pruner.plan(now=NOW).pii.rows == 0
    assert EMAIL in str(_payload_of(settings, ids["evidence"]))
    engine.dispose()


def test_the_audit_actions_the_re_mask_emits_are_chained(tmp_path: Any) -> None:
    """The re-mask's lines go through the chain, not beside it (INV-8)."""
    chain = MemoryAuditChain()
    sink = MemoryAuditSink()
    auditor = build_auditor(Settings(), sinks=[sink], chain=chain, logging_enabled=False)
    auditor.record(AuditAction.PII_REMASKED, target="evidence:1", meta={"evidence_id": 1})
    assert [link["payload"]["action"] for link in chain.links] == ["pii.remasked"]
    assert sink.actions() == ["pii.remasked"]
