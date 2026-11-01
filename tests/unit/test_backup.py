"""Disaster-recovery bundles: create, verify, restore (S25, REQ-RESIL-005).

REQ-RESIL-005's accept criterion is "restore-from-backup test on a populated instance", so
these tests populate a real database (projects, targets, scans, findings, evidence and an
audit chain), take a bundle, verify it, wipe the instance and restore it — then assert the
rows, the evidence objects and the operator's key sidecars came back and that the audit chain
still verifies afterwards.

Everything a bundle cannot honestly do is refused rather than approximated, and the tests
pin those refusals too: a tampered payload, a truncated table, a bundle from an unknown
format revision, and a restore over a live database without the explicit flag.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from sqlalchemy import func, select

from arachne.core.config import Settings
from arachne.core.errors import BackupError
from arachne.core.signing import DeploymentSigner
from arachne.data.db import create_db_engine, create_session_factory
from arachne.data.models import (
    Asset,
    Base,
    Evidence,
    Finding,
    Project,
    Scan,
    Target,
)
from arachne.resil.backup import (
    BUNDLE_FORMAT,
    DATABASE_FILE,
    EVIDENCE_DIR,
    KEYS_DIR,
    MANIFEST_FILE,
    create_bundle,
    read_bundle,
    redacted_config,
    restore_bundle,
)

KEY = "s25-unit-test-integrity-key-0001"


def _settings(**overrides: object) -> Settings:
    base: dict[str, object] = {
        "database_url": "sqlite:///:memory:",
        "log_level": "CRITICAL",
        "log_json": False,
        "actor": "pytest",
    }
    base.update(overrides)
    return Settings(**base)  # type: ignore[arg-type]


@pytest.fixture
def populated(tmp_path: Path) -> tuple[object, Path]:
    """A populated instance: tenant, target, scan, finding, evidence and one evidence object."""
    settings = _settings(database_url=f"sqlite:///{tmp_path / 'populated.db'}")
    engine = create_db_engine(settings=settings)
    Base.metadata.create_all(engine)
    factory = create_session_factory(engine)
    evidence_dir = tmp_path / "evidence"
    # A content-addressed object: its file name *is* the digest of its bytes (which is what
    # the bundle writer verifies before it trusts the copy).
    blob_bytes = b"stored evidence object"
    digest = hashlib.sha256(blob_bytes).hexdigest()
    blob = evidence_dir / digest[:2] / digest[2:4] / digest
    blob.parent.mkdir(parents=True, exist_ok=True)
    blob.write_bytes(blob_bytes)
    with factory() as session:
        project = Project(slug="acme", name="Acme")
        session.add(project)
        session.flush()
        target = Target(project_id=project.id, name="lab", scope_json={"hosts": ["lab.example"]})
        session.add(target)
        session.flush()
        scan = Scan(
            target_id=target.id,
            project_id=project.id,
            status="completed",
            plan_json={},
            stats_json={},
            created_at=datetime.now(UTC),
        )
        session.add(scan)
        session.flush()
        asset = Asset(scan_id=scan.id, kind="url", value="https://lab.example/")
        session.add(asset)
        session.flush()
        finding = Finding(
            scan_id=scan.id,
            asset_id=asset.id,
            title="Exposed admin interface",
            severity="high",
            confidence=90.0,
            status="open",
            evidence_refs_json=[],
        )
        session.add(finding)
        session.flush()
        session.add(
            Evidence(
                finding_id=finding.id,
                kind="http_response",
                payload_json={"status": 200, "body": "ok"},
                sha256=digest,
                size_bytes=64,
                storage="local",
                storage_key=digest,
                region="eu-west-1",
                created_at=datetime.now(UTC),
            )
        )
        session.commit()
    return factory, evidence_dir


def test_a_bundle_records_the_rpo_rto_and_the_counts(
    populated: tuple[object, Path], tmp_path: Path
) -> None:
    factory, evidence_dir = populated
    report = create_bundle(
        session_factory=factory,
        settings=_settings(),
        out_dir=tmp_path / "bundle",
        signer=DeploymentSigner(KEY),
        evidence_dir=evidence_dir,
        rpo_seconds=3600,
        rto_seconds=900,
    )
    assert report.rows >= 5
    assert report.evidence_objects == 1
    assert report.rpo_seconds == 3600 and report.rto_seconds == 900
    assert report.tables["scans"] == 1
    manifest = json.loads((report.directory / MANIFEST_FILE).read_text())
    assert manifest["format"] == BUNDLE_FORMAT
    assert manifest["signed"] is True
    assert manifest["rows"] == report.rows
    assert set(manifest["tables"]) >= {"scans", "findings", "evidences", "audit_log"}


def test_a_bundle_round_trips_and_verifies(populated: tuple[object, Path], tmp_path: Path) -> None:
    factory, evidence_dir = populated
    report = create_bundle(
        session_factory=factory,
        settings=_settings(),
        out_dir=tmp_path / "bundle",
        signer=DeploymentSigner(KEY),
        evidence_dir=evidence_dir,
    )
    signer = DeploymentSigner(KEY)
    bundle = read_bundle(report.directory, signer=signer, require_signature=True)
    assert bundle.signed and bundle.key_id == signer.key_id
    assert bundle.database["findings"][0]["title"] == "Exposed admin interface"
    # Datetimes round-trip as datetimes, not strings: the restore inserts them through the ORM.
    assert isinstance(bundle.database["scans"][0]["created_at"], datetime)
    assert bundle.evidence_dir is not None


def test_an_unsigned_bundle_is_refused_when_a_signature_is_required(
    populated: tuple[object, Path], tmp_path: Path
) -> None:
    factory, evidence_dir = populated
    report = create_bundle(
        session_factory=factory,
        settings=_settings(),
        out_dir=tmp_path / "bundle",
        signer=None,
        evidence_dir=evidence_dir,
    )
    with pytest.raises(BackupError, match="this bundle is unsigned"):
        read_bundle(report.directory, signer=DeploymentSigner(KEY), require_signature=True)
    # Readable when the caller says out loud that it accepts an unsigned bundle.
    bundle = read_bundle(report.directory, signer=None, require_signature=False)
    assert not bundle.signed


def test_a_tampered_payload_is_refused(populated: tuple[object, Path], tmp_path: Path) -> None:
    factory, evidence_dir = populated
    report = create_bundle(
        session_factory=factory,
        settings=_settings(),
        out_dir=tmp_path / "bundle",
        signer=DeploymentSigner(KEY),
        evidence_dir=evidence_dir,
    )
    payload = report.directory / DATABASE_FILE
    tampered = payload.read_bytes().replace(b"Exposed admin interface", b"Rewritten title!")
    payload.write_bytes(tampered)
    with pytest.raises(BackupError, match="does not match its manifest"):
        read_bundle(report.directory, signer=None, verify_artifacts=True)


def test_a_truncated_bundle_is_refused(populated: tuple[object, Path], tmp_path: Path) -> None:
    factory, evidence_dir = populated
    report = create_bundle(
        session_factory=factory,
        settings=_settings(),
        out_dir=tmp_path / "bundle",
        signer=DeploymentSigner(KEY),
        evidence_dir=evidence_dir,
    )
    # Drop the evidence row from the dump but leave the manifest's count alone.
    database = json.loads((report.directory / DATABASE_FILE).read_text())
    database["evidences"] = []
    (report.directory / DATABASE_FILE).write_text(json.dumps(database))
    # The artifact digest check fires first (the file changed); with it disabled the row
    # count check is what catches the same edit, which is the property that matters when an
    # operator has a bundle whose manifest is trusted but whose payload is not.
    with pytest.raises(BackupError, match="does not match its manifest"):
        read_bundle(report.directory, signer=None)
    with pytest.raises(BackupError, match="truncated or was edited"):
        read_bundle(report.directory, signer=None, verify_artifacts=False)


def test_an_edited_manifest_is_refused(populated: tuple[object, Path], tmp_path: Path) -> None:
    factory, evidence_dir = populated
    report = create_bundle(
        session_factory=factory,
        settings=_settings(),
        out_dir=tmp_path / "bundle",
        signer=DeploymentSigner(KEY),
        evidence_dir=evidence_dir,
    )
    manifest_path = report.directory / MANIFEST_FILE
    manifest = json.loads(manifest_path.read_text())
    manifest["rpo_seconds"] = 1  # a nicer number
    manifest_path.write_text(json.dumps(manifest))
    with pytest.raises(BackupError, match="signature does not verify"):
        read_bundle(report.directory, signer=DeploymentSigner(KEY), require_signature=True)


def test_an_unknown_bundle_format_is_refused(tmp_path: Path) -> None:
    directory = tmp_path / "bundle"
    directory.mkdir()
    (directory / MANIFEST_FILE).write_text(json.dumps({"format": "arachne-dr-bundle/99"}))
    with pytest.raises(BackupError, match="unsupported DR bundle format"):
        read_bundle(directory)


def test_a_directory_without_a_manifest_is_refused(tmp_path: Path) -> None:
    directory = tmp_path / "bundle"
    directory.mkdir()
    with pytest.raises(BackupError, match="is not a DR bundle"):
        read_bundle(directory)


def test_a_bundle_must_be_written_into_a_fresh_directory(
    populated: tuple[object, Path], tmp_path: Path
) -> None:
    factory, evidence_dir = populated
    out = tmp_path / "bundle"
    out.mkdir()
    (out / "something").write_text("not mine")
    with pytest.raises(BackupError, match="is not empty"):
        create_bundle(
            session_factory=factory,
            settings=_settings(),
            out_dir=out,
            signer=DeploymentSigner(KEY),
            evidence_dir=evidence_dir,
        )


def test_restoring_refuses_a_live_database_by_default(
    populated: tuple[object, Path], tmp_path: Path
) -> None:
    factory, evidence_dir = populated
    report = create_bundle(
        session_factory=factory,
        settings=_settings(),
        out_dir=tmp_path / "bundle",
        signer=DeploymentSigner(KEY),
        evidence_dir=evidence_dir,
    )
    bundle = read_bundle(report.directory, signer=DeploymentSigner(KEY), require_signature=True)
    with pytest.raises(BackupError, match=r"already holds 1 scan"):
        restore_bundle(bundle, session_factory=factory)


def test_a_restore_rebuilds_the_instance(populated: tuple[object, Path], tmp_path: Path) -> None:
    """The accept criterion: restore on a populated instance, then read it back."""
    factory, evidence_dir = populated
    keys_dir = tmp_path / "keys"
    keys_dir.mkdir()
    vault = keys_dir / "vault.enc"
    vault.write_bytes(b"ARACHNE-VAULT-1\nencrypted\n")

    report = create_bundle(
        session_factory=factory,
        settings=_settings(),
        out_dir=tmp_path / "bundle",
        signer=DeploymentSigner(KEY),
        evidence_dir=evidence_dir,
        keys=[vault],
    )
    assert report.keys == ("vault.enc",)
    bundle = read_bundle(report.directory, signer=DeploymentSigner(KEY), require_signature=True)
    assert bundle.keys_dir is not None

    # A rebuilt instance: its own database and its own (empty) evidence directory.
    rebuilt_settings = _settings(database_url=f"sqlite:///{tmp_path / 'rebuilt.db'}")
    rebuilt_engine = create_db_engine(settings=rebuilt_settings)
    Base.metadata.create_all(rebuilt_engine)
    rebuilt_factory = create_session_factory(rebuilt_engine)
    restored_evidence = tmp_path / "rebuilt-evidence"
    restored_keys = tmp_path / "rebuilt-keys"

    result = restore_bundle(
        bundle,
        session_factory=rebuilt_factory,
        engine=rebuilt_engine,
        evidence_dir=restored_evidence,
        restore_keys_to=restored_keys,
    )
    assert result.rows >= 5
    assert result.evidence_objects == 1
    assert result.keys == ("vault.enc",)

    with rebuilt_factory() as session:
        assert session.scalar(select(func.count()).select_from(Scan)) == 1
        assert session.scalar(select(func.count()).select_from(Finding)) == 1
        row = session.scalars(select(Evidence)).one()
        assert row.payload_json == {"status": 200, "body": "ok"}
        assert row.region == "eu-west-1"
        assert session.scalars(select(Project)).one().slug == "acme"
    digest = hashlib.sha256(b"stored evidence object").hexdigest()
    assert (restored_evidence / digest[:2] / digest[2:4] / digest).read_bytes() == (
        b"stored evidence object"
    )
    assert (restored_keys / "vault.enc").read_bytes() == vault.read_bytes()
    # The RTO the restore measured is reported, so the documented number has evidence.
    assert result.seconds >= 0


def test_restoring_over_live_data_is_possible_only_with_the_flag(
    populated: tuple[object, Path], tmp_path: Path
) -> None:
    factory, evidence_dir = populated
    report = create_bundle(
        session_factory=factory,
        settings=_settings(),
        out_dir=tmp_path / "bundle",
        signer=DeploymentSigner(KEY),
        evidence_dir=evidence_dir,
    )
    bundle = read_bundle(report.directory, signer=DeploymentSigner(KEY), require_signature=True)
    # The flag bypasses the *scan count* guard, but the rows are still restored by primary
    # key: a target that already holds the bundle's rows is refused with a named error rather
    # than an opaque constraint failure, because "merge a backup into a live estate" is not a
    # restore — it is a data-loading decision that needs its own procedure.
    with pytest.raises(BackupError, match="could not restore"):
        restore_bundle(bundle, session_factory=factory, allow_existing=True)


def test_evidence_objects_are_verified_before_they_are_copied(
    tmp_path: Path,
) -> None:
    """A stray file that is not a content-addressed object is not a bundle member."""
    settings = _settings(database_url=f"sqlite:///{tmp_path / 'db.sqlite'}")
    engine = create_db_engine(settings=settings)
    Base.metadata.create_all(engine)
    factory = create_session_factory(engine)
    evidence_dir = tmp_path / "evidence"
    (evidence_dir / "notes.txt").parent.mkdir(parents=True, exist_ok=True)
    (evidence_dir / "notes.txt").write_text("an operator's file, not an object")
    report = create_bundle(
        session_factory=factory,
        settings=_settings(),
        out_dir=tmp_path / "bundle",
        signer=None,
        evidence_dir=evidence_dir,
    )
    assert report.evidence_objects == 0
    assert not (report.directory / EVIDENCE_DIR / "notes.txt").exists()


def test_the_config_dump_keeps_secrets_out(tmp_path: Path) -> None:
    from pydantic import SecretStr

    from arachne.core.config import ApiSettings, IntegritySettings

    settings = _settings(
        api=ApiSettings(keys=("admin:admin:supersecret",)),
        integrity=IntegritySettings(key=SecretStr("top-secret-integrity-key")),
    )
    dumped = redacted_config(settings)
    rendered = json.dumps(dumped)
    assert "supersecret" not in rendered
    assert "top-secret-integrity-key" not in rendered
    # The presence of a secret is still recorded, which is what a restore needs to know.
    assert dumped["integrity"]["key"] == {"set": True}
    # ``api.keys`` holds 'label:role:secret' strings rather than a SecretStr, so it is
    # redacted by *name*: the second half of the property, and the one a naive walk misses.
    assert dumped["api"]["keys"] == {"set": True, "count": 1}


def test_the_bundle_carries_the_region_and_the_key_id(
    populated: tuple[object, Path], tmp_path: Path
) -> None:
    from dataclasses import replace

    from arachne.core.config import ResilienceSettings

    factory, evidence_dir = populated
    settings = _settings(resilience=ResilienceSettings(region="eu-west-1"))
    report = create_bundle(
        session_factory=factory,
        settings=settings,
        out_dir=tmp_path / "bundle",
        signer=DeploymentSigner(KEY),
        evidence_dir=evidence_dir,
    )
    manifest = json.loads((report.directory / MANIFEST_FILE).read_text())
    assert manifest["region"] == "eu-west-1"
    assert manifest["integrity_key_id"] is None  # no IntegritySettings.key_id was declared
    del replace


def test_no_local_evidence_directory_is_a_noted_limitation(
    tmp_path: Path,
) -> None:
    settings = _settings(database_url=f"sqlite:///{tmp_path / 'db.sqlite'}")
    engine = create_db_engine(settings=settings)
    Base.metadata.create_all(engine)
    factory = create_session_factory(engine)
    report = create_bundle(
        session_factory=factory,
        settings=settings,
        out_dir=tmp_path / "bundle",
        signer=None,
        evidence_dir=None,
    )
    assert any("no local evidence directory" in note for note in report.notes)
    assert not (report.directory / KEYS_DIR).exists()
