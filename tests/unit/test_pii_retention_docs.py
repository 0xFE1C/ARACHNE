"""The operator guide's retention wording, checked against the code (WP-14, REQ-DATA-005).

The defect this package closed was a *documented* behaviour that did not exist. A test that
only asserted the new behaviour would leave the same hole open in the other direction — the
guide could drift back to claiming something the pruner does not do. So this file treats the
guide's §39 as a set of claims and checks each one against the implementation:

* the variable it names is the one ``core.config`` parses and the pruner reads;
* the default it states (``0`` = mask at capture only) is the default the settings carry and
  the behaviour a pruner with that value has;
* the dry-run claim ("changes nothing") and the apply claim ("masks in place") are exercised
  through the real pruner;
* the store it says this pass cannot re-mask is the store the code reports as unsupported, by
  the *same* reason string;
* the audit actions it names exist, and the count-only claim holds (no value in the event).

The guide is prose, so the claims are matched as phrases. A phrase that disappears is a
failure here rather than a silent divergence — that is the whole point of a documentation
test.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from arachne.core.audit import AuditAction, MemoryAuditSink, build_auditor
from arachne.core.config import PiiSettings, RetentionSettings, Settings
from arachne.core.pii import PIIPolicy
from arachne.data.db import create_all, create_session_factory, create_sqlite_engine
from arachne.data.models import Evidence, Finding, Project, Scan, Target
from arachne.data.retention import OFFLOADED_REMASK_REASON, RetentionPruner

REPO_ROOT = Path(__file__).resolve().parents[2]
GUIDE = REPO_ROOT / "docs" / "operator-guide.md"
NOW = datetime(2026, 6, 1, 12, 0, tzinfo=UTC)
EMAIL = "dana.reeves@example.com"


def _guide() -> str:
    return GUIDE.read_text(encoding="utf-8")


def _section(text: str) -> str:
    """The PII retention section, from its heading to the next ``##``."""
    marker = "## 39. PII in captured evidence"
    assert marker in text, "the operator guide no longer has the PII section"
    body = text.split(marker, 1)[1]
    return body.split("\n## ", 1)[0]


# ------------------------------------------------------------------ the claims the guide makes
def test_the_guide_names_the_variable_the_pruner_actually_reads() -> None:
    section = _section(_guide())
    assert "ARACHNE_PII_RETENTION_DAYS" in section
    # The name in the guide is the name in the environment reader, and the value it sets is
    # the one the pruner exposes.
    config_source = (REPO_ROOT / "src" / "arachne" / "core" / "config.py").read_text(
        encoding="utf-8"
    )
    assert '"ARACHNE_PII_RETENTION_DAYS"' in config_source
    settings = Settings(pii=PiiSettings(retention_days=45))
    assert settings.pii.retention_days == 45


def test_the_guide_states_the_default_and_the_code_agrees() -> None:
    section = _section(_guide())
    assert "`ARACHNE_PII_RETENTION_DAYS=0`" in section
    assert "mask at capture only, never re-mask" in section
    assert PiiSettings().retention_days == 0
    assert Settings().pii.retention_days == 0


def test_the_guide_states_the_dry_run_first_behaviour() -> None:
    section = _section(_guide())
    assert "changes nothing" in section
    assert "retention prune --apply" in section


def test_the_guide_quotes_the_reason_the_code_reports_for_an_unmaskable_store() -> None:
    section = _section(_guide())
    assert "offloaded" in section.lower()
    assert "pii.remask_unsupported" in section
    # The reason the audit line and the plan carry is the constant the pruner uses, and the
    # guide describes that store — object-store bytes — rather than some other one.
    assert OFFLOADED_REMASK_REASON == "payload is offloaded to an evidence backend"
    assert "evidence backend" in section


def test_the_guide_names_the_audit_actions_that_exist() -> None:
    section = _section(_guide())
    for name in ("pii.masked", "pii.remasked", "pii.remask_unsupported"):
        assert name in section, name
    assert AuditAction.PII_MASKED.value == "pii.masked"
    assert AuditAction.PII_REMASKED.value == "pii.remasked"
    assert AuditAction.PII_REMASK_UNSUPPORTED.value == "pii.remask_unsupported"


def test_the_guide_states_the_counts_only_rule_the_events_keep() -> None:
    section = _section(_guide())
    assert "never a value" in section


def test_the_guide_states_the_legal_hold_and_the_integrity_composition() -> None:
    section = _section(_guide())
    assert "legal hold" in section
    assert "verify-chain" in section


# ------------------------------------------------------------------ the behaviour behind them
def _fixture(tmp_path: Any, *, retention_days: int, offloaded: bool) -> tuple[Settings, int]:
    settings = Settings(
        database_url=f"sqlite:///{tmp_path / 'docs.db'}",
        retention=RetentionSettings(batch_limit=100),
        pii=PiiSettings(
            enabled=True, action="mask", categories=("email",), retention_days=retention_days
        ),
    )
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
            auth_attestation=None,
        )
        session.add(target)
        session.flush()
        created = NOW - timedelta(days=400)
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
            title="t",
            severity=None,
            confidence=50.0,
            status="open",
            evidence_refs_json=[],
            created_at=created,
        )
        session.add(finding)
        session.flush()
        payload: dict[str, Any] = (
            {"offloaded": True, "key": "a" * 64, "sha256": "a" * 64, "size": 100, "body": "preview"}
            if offloaded
            else {"body": f"contact {EMAIL}"}
        )
        row = Evidence(
            finding_id=int(finding.id),
            kind="http_response",
            payload_json=payload,
            sha256=None,
            size_bytes=100,
            storage="local" if offloaded else "inline",
            storage_key="a" * 64 if offloaded else None,
            created_at=created,
        )
        session.add(row)
        session.commit()
        evidence_id = int(row.id)
    engine.dispose()
    return settings, evidence_id


def _pruner(settings: Settings, sink: MemoryAuditSink) -> RetentionPruner:
    engine = create_sqlite_engine(settings.database_url)
    factory = create_session_factory(engine)
    policy = PIIPolicy.from_settings(settings.pii)
    return RetentionPruner(
        factory,
        settings=settings,
        auditor=build_auditor(settings, sinks=[sink], logging_enabled=False),
        pii_policy=lambda project_id: policy,
    )


async def test_the_documented_default_masks_nothing(tmp_path: Any) -> None:
    settings, evidence_id = _fixture(tmp_path, retention_days=0, offloaded=False)
    sink = MemoryAuditSink()
    pruner = _pruner(settings, sink)
    applied = await pruner.prune(dry_run=False, now=NOW)
    assert applied.pii.rows == 0
    engine = create_sqlite_engine(settings.database_url)
    with create_session_factory(engine)() as session:
        payload = dict(session.get(Evidence, evidence_id).payload_json)  # type: ignore[union-attr]
    engine.dispose()
    assert EMAIL in str(payload)


async def test_the_documented_dry_run_changes_nothing_and_the_apply_masks(tmp_path: Any) -> None:
    settings, evidence_id = _fixture(tmp_path, retention_days=90, offloaded=False)
    sink = MemoryAuditSink()
    pruner = _pruner(settings, sink)

    def stored() -> dict[str, Any]:
        engine = create_sqlite_engine(settings.database_url)
        with create_session_factory(engine)() as session:
            row = session.get(Evidence, evidence_id)
            assert row is not None
            payload = dict(row.payload_json)
        engine.dispose()
        return payload

    before = stored()
    assert (await pruner.prune(dry_run=True, now=NOW)).pii.rows == 1
    assert stored() == before
    assert (await pruner.prune(dry_run=False, now=NOW)).pii.rows == 1
    assert EMAIL not in str(stored())


async def test_the_documented_unsupported_report_names_the_offloaded_store(tmp_path: Any) -> None:
    settings, evidence_id = _fixture(tmp_path, retention_days=90, offloaded=True)
    sink = MemoryAuditSink()
    pruner = _pruner(settings, sink)
    plan = pruner.plan(now=NOW)
    assert plan.pii.unsupported == {OFFLOADED_REMASK_REASON: 1}
    await pruner.prune(dry_run=False, now=NOW)
    reported = sink.of_action(AuditAction.PII_REMASK_UNSUPPORTED)
    assert reported and reported[0].meta["evidence_ids"] == [evidence_id]


async def test_the_documented_counts_only_rule_holds_in_a_real_event(tmp_path: Any) -> None:
    settings, _ = _fixture(tmp_path, retention_days=90, offloaded=False)
    sink = MemoryAuditSink()
    pruner = _pruner(settings, sink)
    await pruner.prune(dry_run=False, now=NOW)
    event = sink.of_action(AuditAction.PII_REMASKED)[0]
    assert event.meta["categories"] == {"email": 1}
    assert EMAIL not in str(event.meta)
    assert event.reason and "retention window" in event.reason


def test_the_section_is_present_once_and_has_not_been_replaced_by_a_summary() -> None:
    """A guide that loses the detail is as bad as one that overstates it."""
    text = _guide()
    assert text.count("## 39. PII in captured evidence") == 1
    section = _section(text)
    assert len(section) > 2_000, "the retention section shrank to a sentence"


def test_every_audit_action_named_in_the_guide_is_a_real_member() -> None:
    """Nothing in the section is a name an operator could search for in the trail and miss."""
    section = _section(_guide())
    known = {member.value for member in AuditAction}
    cited = {token.strip("`.,()") for token in section.split() if token.startswith("`pii.")}
    assert cited, "no audit action is cited any more"
    for name in cited:
        assert name in known, name


@pytest.mark.parametrize("member", ["PII_REMASKED", "PII_REMASK_UNSUPPORTED"])
def test_the_pruner_is_the_only_writer_of_the_re_mask_actions(member: str) -> None:
    """The events the guide describes are emitted where the guide says they are."""
    source = (REPO_ROOT / "src" / "arachne" / "data" / "retention.py").read_text(encoding="utf-8")
    assert f"AuditAction.{member}" in source, f"the pruner does not emit {member}"
    capture = (REPO_ROOT / "src" / "arachne" / "data" / "evidence_service.py").read_text(
        encoding="utf-8"
    )
    assert member not in capture, "the capture path writes a re-mask event"


def test_no_other_module_consumes_the_retention_days_setting() -> None:
    """One consumer, as the guide says: the pruner. A second one would be a second policy."""
    offenders: list[str] = []
    settings_field = "pii.retention_days"
    for path in (REPO_ROOT / "src").rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        if settings_field in text and path.name not in {"config.py", "retention.py"}:
            offenders.append(str(path.relative_to(REPO_ROOT)))
    assert offenders == []


def test_the_retention_pruner_reads_the_setting_not_a_literal(tmp_path: Any) -> None:
    """The window is the configured number, and it is a *window*: same blob, two policies."""
    for days, expected in ((17, 1), (500, 0)):
        settings = Settings(
            database_url=f"sqlite:///{tmp_path / f'window-{days}.db'}",
            retention=RetentionSettings(batch_limit=100),
            pii=PiiSettings(
                enabled=True, action="mask", categories=("email",), retention_days=days
            ),
        )
        engine = create_sqlite_engine(settings.database_url)
        create_all(engine)
        factory = create_session_factory(engine)
        with factory() as session:
            project = Project(
                slug="acme",
                name="Acme",
                scope_json={},
                branding_json={},
                retention_json={"scans_days": 0, "findings_days": 0, "evidence_days": 0},
            )
            session.add(project)
            session.flush()
            target = Target(
                project_id=int(project.id), name="t", scope_json={}, auth_attestation=None
            )
            session.add(target)
            session.flush()
            created = NOW - timedelta(days=400)
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
                title="t",
                severity=None,
                confidence=50.0,
                status="open",
                evidence_refs_json=[],
                created_at=created,
            )
            session.add(finding)
            session.flush()
            session.add(
                Evidence(
                    finding_id=int(finding.id),
                    kind="http_response",
                    payload_json={"body": f"contact {EMAIL}"},
                    sha256=None,
                    size_bytes=50,
                    storage="inline",
                    created_at=created,
                )
            )
            session.commit()
        resolved = PIIPolicy.from_settings(settings.pii)
        pruner = RetentionPruner(
            factory,
            settings=settings,
            pii_policy=lambda project_id, resolved=resolved: resolved,
        )
        assert pruner.pii_retention_days == days
        assert pruner.plan(now=NOW).pii.rows == expected
        engine.dispose()


def test_the_guide_does_not_claim_the_pass_covers_an_object_store() -> None:
    """The precise limit of the control is stated, so the guide cannot be read as universal."""
    section = _section(_guide())
    assert "not** re-masked" in section or "not re-masked" in section
    assert "backend" in section


def test_the_scan_selects_evidence_for_the_window_by_age() -> None:
    """A last, cheap guard on the predicate itself: no age filter, no control."""
    source = (REPO_ROOT / "src" / "arachne" / "data" / "retention.py").read_text(encoding="utf-8")
    assert "Evidence.created_at < cutoff" in source
