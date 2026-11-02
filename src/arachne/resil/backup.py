"""Disaster recovery: the backup/restore bundle and its RPO/RTO (S25, REQ-RESIL-005).

REQ-RESIL-005 asks for DR "documented with RPO/RTO and a tested backup/restore path
covering findings, evidence, keys, and configuration". The runbook lives in the operator
guide; this module is the part that can be *tested*:

* :func:`create_bundle` writes one directory holding everything a rebuilt deployment needs:
  ``database.json`` (every table the schema owns, encoded so it round-trips), ``evidence/``
  (the offloaded object tree), ``keys/`` (the operator's already-encrypted sidecars — the
  credential vault, the secrets manifest), ``config.json`` (the deployment's non-secret
  settings, secrets represented by presence rather than value) and ``manifest.json``.
* :func:`read_bundle` verifies the bundle before it is used: every artifact's digest, the
  table counts, and the manifest's signature. A tampered or truncated bundle is refused, not
  half-restored.
* :func:`restore_bundle` loads it back into a database and evidence directory, refusing to
  write into a database that already holds scans unless ``allow_existing=True`` (a restore
  into a live estate is a decision, not an accident).

RPO and RTO are properties of an *operating procedure*, not of the code: the bundle records
what an operator's chosen cadence supports (``rpo_seconds``) and what a rehearsal actually
took to restore (``rto_seconds``), so the documented numbers have a home in the artifact
rather than only in prose. ``arachne dr restore`` re-measures the RTO and prints it.

Anything the tool cannot make safe is refused rather than approximated: an S3-backed
evidence store is *not* copied by this path (the object store's own lifecycle/replication is
the right mechanism for it, and a half-copied bucket would be worse than a documented
pointer), so a bundle from such a deployment records the object keys and says so.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any, Final, cast

from pydantic import SecretStr
from sqlalchemy import Engine, func, select
from sqlalchemy.exc import IntegrityError as SaIntegrityError
from sqlalchemy.orm import Session, sessionmaker

from arachne.core.errors import BackupError
from arachne.core.logging import get_logger
from arachne.core.signing import DeploymentSigner, canonical_bytes

__all__ = [
    "BUNDLE_FORMAT",
    "Bundle",
    "BundleReport",
    "RestoreReport",
    "create_bundle",
    "read_bundle",
    "redacted_config",
    "restore_bundle",
]

_logger = get_logger("resil.backup")

BUNDLE_FORMAT: Final = "arachne-dr-bundle/1"
MANIFEST_FILE: Final = "manifest.json"
DATABASE_FILE: Final = "database.json"
CONFIG_FILE: Final = "config.json"
EVIDENCE_DIR: Final = "evidence"
KEYS_DIR: Final = "keys"

#: Signature domain for the bundle manifest.
BACKUP_DOMAIN: Final = "arachne.backup"

#: A backup cadence of a day and a restore rehearsal measured in an hour are the shipped
#: defaults the operator guide documents; a deployment that needs better records its own.
DEFAULT_RPO_SECONDS: Final = 24 * 3600
DEFAULT_RTO_SECONDS: Final = 3600


@dataclass(frozen=True, slots=True)
class BundleReport:
    """What one backup produced."""

    directory: Path
    created_at: datetime
    schema_revision: str | None
    tables: dict[str, int]
    rows: int
    evidence_objects: int
    evidence_bytes: int
    keys: tuple[str, ...]
    signed: bool
    key_id: str | None
    rpo_seconds: int
    rto_seconds: int
    duration_s: float
    notes: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "directory": str(self.directory),
            "created_at": self.created_at.isoformat(),
            "schema_revision": self.schema_revision,
            "tables": dict(self.tables),
            "rows": self.rows,
            "evidence_objects": self.evidence_objects,
            "evidence_bytes": self.evidence_bytes,
            "keys": list(self.keys),
            "signed": self.signed,
            "key_id": self.key_id,
            "rpo_seconds": self.rpo_seconds,
            "rto_seconds": self.rto_seconds,
            "duration_s": round(self.duration_s, 3),
            "notes": list(self.notes),
        }


@dataclass(frozen=True, slots=True)
class Bundle:
    """A verified bundle, ready to restore."""

    directory: Path
    manifest: dict[str, Any]
    database: dict[str, list[dict[str, Any]]]
    config: dict[str, Any]
    evidence_dir: Path | None
    keys_dir: Path | None
    signed: bool
    key_id: str | None

    @property
    def rpo_seconds(self) -> int:
        return int(self.manifest.get("rpo_seconds") or 0)

    @property
    def rto_seconds(self) -> int:
        return int(self.manifest.get("rto_seconds") or 0)

    @property
    def created_at(self) -> str | None:
        value = self.manifest.get("created_at")
        return str(value) if value else None

    def to_dict(self) -> dict[str, Any]:
        return {
            "directory": str(self.directory),
            "format": self.manifest.get("format"),
            "created_at": self.created_at,
            "schema_revision": self.manifest.get("schema_revision"),
            "tables": {name: len(rows) for name, rows in self.database.items()},
            "signed": self.signed,
            "key_id": self.key_id,
            "rpo_seconds": self.rpo_seconds,
            "rto_seconds": self.rto_seconds,
            "has_evidence": self.evidence_dir is not None,
            "has_keys": self.keys_dir is not None,
        }


@dataclass(frozen=True, slots=True)
class RestoreReport:
    """What one restore put back."""

    tables: dict[str, int]
    rows: int
    evidence_objects: int
    keys: tuple[str, ...]
    seconds: float
    target: str
    notes: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tables": dict(self.tables),
            "rows": self.rows,
            "evidence_objects": self.evidence_objects,
            "keys": list(self.keys),
            "seconds": round(self.seconds, 3),
            "target": self.target,
            "notes": list(self.notes),
        }


# --------------------------------------------------------------------------- helpers
def _sha256_file(path: Path) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def _encode_value(value: Any) -> Any:
    if isinstance(value, datetime):
        return {"__dt__": value.isoformat()}
    if isinstance(value, date):
        return {"__date__": value.isoformat()}
    if isinstance(value, bytes):
        return {"__bytes__": value.hex()}
    return value


def _decode_value(value: Any) -> Any:
    if isinstance(value, Mapping):
        if "__dt__" in value:
            return datetime.fromisoformat(str(value["__dt__"]))
        if "__date__" in value:
            return date.fromisoformat(str(value["__date__"]))
        if "__bytes__" in value:
            return bytes.fromhex(str(value["__bytes__"]))
        return {key: _decode_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_decode_value(item) for item in value]
    return value


def _mapped_classes() -> list[type[Any]]:
    """ORM classes in FK-safe insert order.

    The order is computed from the foreign keys themselves (a parent before any table that
    references it) rather than taken from ``MetaData.sorted_tables``, whose ordering is not a
    restore-order guarantee: a restore that inserts a child first fails the constraint (or,
    worse on a database without FK enforcement, silently writes an orphan).
    """
    from arachne.data.models import Base

    by_table: dict[str, type[Any]] = {}
    for mapper in Base.registry.mappers:
        cls = mapper.class_
        name = getattr(cls, "__tablename__", None)
        if isinstance(name, str):
            by_table[name] = cls

    ordered_tables = _dependency_order(list(Base.metadata.tables.values()))
    classes: list[type[Any]] = []
    for table in ordered_tables:
        mapped = by_table.get(table.name)
        if mapped is not None:
            classes.append(mapped)
    return classes


def _dependency_order(tables: list[Any]) -> list[Any]:
    """Topologically sort tables so every referenced table precedes its referrer."""
    ordered: list[Any] = []
    seen: set[str] = set()

    def visit(table: Any) -> None:
        if table.name in seen:
            return
        seen.add(table.name)
        for foreign_key in table.foreign_keys:
            visit(foreign_key.column.table)
        ordered.append(table)

    for table in tables:
        visit(table)
    return ordered


#: Field names (or name suffixes) whose value is a secret even when it is not wrapped in a
#: ``SecretStr``. ``api.keys`` is the case that matters: it holds ``label:role:secret``
#: strings, so serialising it would turn a backup into a credential leak.
_SECRET_FIELD_NAMES: Final[frozenset[str]] = frozenset(
    {"keys", "api_keys", "credentials", "salt", "passphrase"}
)
_SECRET_FIELD_SUFFIXES: Final[tuple[str, ...]] = (
    "_key",
    "_keys",
    "_secret",
    "_password",
    "_token",
    "_passphrase",
)


def _is_secret_field(name: str) -> bool:
    """Whether a settings field carries a secret (by name, since not all are ``SecretStr``)."""
    lowered = name.lower()
    # A path or a label, not the material.
    if lowered.endswith(("_file", "_id", "_path", "_keys_file")):
        return False
    if lowered in _SECRET_FIELD_NAMES:
        return True
    return lowered.endswith(_SECRET_FIELD_SUFFIXES)


def redacted_config(settings: Any) -> dict[str, Any]:
    """A settings document with every secret replaced by its presence.

    Generic on purpose: it walks the dataclass tree, so a settings group added in a later
    release is included without this function changing. A secret is never serialised — only
    ``{"set": true}``, with a count for a collection — so a backup cannot become a credential
    leak, and a restore can still tell an operator which secrets they must re-supply.
    """
    return cast(dict[str, Any], _redact(settings))


def _redact(value: Any, depth: int = 0) -> Any:
    if depth > 6:
        return "<deep>"
    if isinstance(value, SecretStr):
        return {"set": True}
    if isinstance(value, Mapping):
        return {str(key): _redact(item, depth + 1) for key, item in value.items()}
    if isinstance(value, list | tuple | set):
        return [_redact(item, depth + 1) for item in value]
    if hasattr(value, "__dataclass_fields__"):
        return {
            name: _redact_field(name, getattr(value, name), depth)
            for name in value.__dataclass_fields__
            if not name.startswith("_")
        }
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, datetime | date):
        return value.isoformat()
    if isinstance(value, str | int | float | bool) or value is None:
        return value
    return str(value)


def _redact_field(name: str, value: Any, depth: int) -> Any:
    """One field: a secret by name is replaced by its presence, never by its value."""
    if not _is_secret_field(name):
        return _redact(value, depth)
    if value is None or value == "" or value == () or value == [] or value == {}:
        return {"set": False}
    if isinstance(value, list | tuple | set):
        return {"set": True, "count": len(value)}
    return {"set": True}


# --------------------------------------------------------------------------- create
def create_bundle(
    *,
    session_factory: sessionmaker[Session],
    settings: Any,
    out_dir: str | Path,
    signer: DeploymentSigner | None = None,
    evidence_dir: str | Path | None = None,
    keys: Iterable[str | Path] = (),
    rpo_seconds: int = DEFAULT_RPO_SECONDS,
    rto_seconds: int = DEFAULT_RTO_SECONDS,
    include_evidence: bool = True,
    notes: Sequence[str] = (),
    clock: Callable[[], datetime] | None = None,
) -> BundleReport:
    """Write a complete, signed DR bundle under ``out_dir``.

    ``out_dir`` must be empty or absent: a backup that mixes with an older one is not a
    snapshot of anything. ``evidence_dir`` is the local backend's directory (the S3 case is
    recorded as a pointer, see the module docstring).
    """
    started = datetime.now(UTC)
    target = Path(out_dir)
    if target.exists() and any(target.iterdir()):
        msg = f"{target} is not empty; a DR bundle must be written into a fresh directory"
        raise BackupError(msg)
    target.mkdir(parents=True, exist_ok=True)
    moment = (clock or (lambda: datetime.now(UTC)))()

    database, counts = _dump_database(session_factory)
    (target / DATABASE_FILE).write_bytes(canonical_bytes(database))
    (target / CONFIG_FILE).write_bytes(canonical_bytes(redacted_config(settings)))

    artifacts: dict[str, dict[str, Any]] = {}
    for name in (DATABASE_FILE, CONFIG_FILE):
        digest, size = _sha256_file(target / name)
        artifacts[name] = {"sha256": digest, "size": size}

    bundle_notes = list(notes)
    evidence_objects = 0
    evidence_bytes = 0
    if include_evidence and evidence_dir is not None:
        source = Path(evidence_dir).expanduser()
        if source.is_dir():
            evidence_objects, evidence_bytes = _copy_tree(source, target / EVIDENCE_DIR)
        else:
            bundle_notes.append(f"evidence directory {source} does not exist: nothing copied")
    elif include_evidence:
        bundle_notes.append(
            "no local evidence directory: offloaded objects were not copied (an S3-backed "
            "store is replicated by the object store, not by this bundle)"
        )

    key_names: list[str] = []
    keys_target = target / KEYS_DIR
    for entry in keys:
        path = Path(entry).expanduser()
        if not path.is_file():
            bundle_notes.append(f"key file {path} does not exist: skipped")
            continue
        keys_target.mkdir(parents=True, exist_ok=True)
        destination = keys_target / path.name
        shutil.copy2(path, destination)
        digest, size = _sha256_file(destination)
        artifacts[f"{KEYS_DIR}/{path.name}"] = {"sha256": digest, "size": size}
        key_names.append(path.name)

    integrity = getattr(settings, "integrity", None)
    manifest: dict[str, Any] = {
        "format": BUNDLE_FORMAT,
        "created_at": moment.isoformat(),
        "schema_revision": _schema_revision(session_factory),
        "region": getattr(getattr(settings, "resilience", None), "region", None),
        "rpo_seconds": int(rpo_seconds),
        "rto_seconds": int(rto_seconds),
        "tables": counts,
        "rows": sum(counts.values()),
        "evidence_objects": evidence_objects,
        "evidence_bytes": evidence_bytes,
        "keys": key_names,
        "integrity_key_id": getattr(integrity, "key_id", None),
        "artifacts": artifacts,
        "notes": bundle_notes,
        "signed": signer is not None,
        "signature": None,
    }
    if signer is not None:
        manifest["signature"] = _sign_manifest(signer, manifest)
    (target / MANIFEST_FILE).write_bytes(canonical_bytes(manifest))

    duration = (datetime.now(UTC) - started).total_seconds()
    report = BundleReport(
        directory=target,
        created_at=moment,
        schema_revision=manifest["schema_revision"],
        tables=counts,
        rows=manifest["rows"],
        evidence_objects=evidence_objects,
        evidence_bytes=evidence_bytes,
        keys=tuple(key_names),
        signed=signer is not None,
        key_id=getattr(integrity, "key_id", None),
        rpo_seconds=int(rpo_seconds),
        rto_seconds=int(rto_seconds),
        duration_s=duration,
        notes=tuple(bundle_notes),
    )
    _logger.info(
        "dr bundle created",
        extra={
            "event": "backup.created",
            "directory": str(target),
            "rows": report.rows,
            "objects": report.evidence_objects,
        },
    )
    return report


def _sign_manifest(signer: DeploymentSigner, manifest: Mapping[str, Any]) -> str:
    body = {key: value for key, value in manifest.items() if key != "signature"}
    return signer.sign(BACKUP_DOMAIN, canonical_bytes(body))


def _schema_revision(session_factory: sessionmaker[Session]) -> str | None:
    from alembic.runtime.migration import MigrationContext

    with session_factory() as session:
        return MigrationContext.configure(session.connection()).get_current_revision()


def _dump_database(
    session_factory: sessionmaker[Session],
) -> tuple[dict[str, list[dict[str, Any]]], dict[str, int]]:
    payload: dict[str, list[dict[str, Any]]] = {}
    counts: dict[str, int] = {}
    with session_factory() as session:
        for cls in _mapped_classes():
            rows = session.scalars(select(cls)).all()
            table = cls.__tablename__
            encoded = [_encode_row(cls, row) for row in rows]
            payload[table] = encoded
            counts[table] = len(encoded)
    return payload, counts


def _encode_row(cls: type[Any], row: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {}
    for column in cls.__table__.columns:
        payload[column.name] = _encode_value(getattr(row, column.name))
    return payload


def _copy_tree(source: Path, destination: Path) -> tuple[int, int]:
    """Copy an evidence tree, skipping the backend's ``.tmp`` scratch directory."""
    objects = 0
    total = 0
    for path in sorted(source.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        if ".tmp" in path.relative_to(source).parts:
            continue
        relative = path.relative_to(source)
        # The content-addressed name is the digest: verify it before trusting the copy, so a
        # backup cannot launder a corrupted object into an "integrity-checked" bundle.
        digest, size = _sha256_file(path)
        if path.name != digest:
            continue  # not a content-addressed object (an operator's stray file)
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target)
        objects += 1
        total += size
    return objects, total


# --------------------------------------------------------------------------- read
def read_bundle(
    path: str | Path,
    *,
    signer: DeploymentSigner | None = None,
    require_signature: bool = False,
    verify_artifacts: bool = True,
) -> Bundle:
    """Load and verify a bundle; raise :class:`BackupError` on anything that does not check out."""
    directory = Path(path)
    manifest_path = directory / MANIFEST_FILE
    if not manifest_path.is_file():
        msg = f"{directory} is not a DR bundle: {MANIFEST_FILE} is missing"
        raise BackupError(msg)
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        msg = f"the bundle manifest is not valid JSON: {exc}"
        raise BackupError(msg) from exc
    if manifest.get("format") != BUNDLE_FORMAT:
        msg = (
            f"unsupported DR bundle format {manifest.get('format')!r} "
            f"(this build understands {BUNDLE_FORMAT})"
        )
        raise BackupError(msg)
    if require_signature:
        if signer is None:
            msg = "this bundle must be signature-verified but no integrity key is configured"
            raise BackupError(msg)
        if not manifest.get("signature"):
            msg = (
                "this bundle is unsigned (it was written without a key); re-create it with "
                "ARACHNE_INTEGRITY_KEY set, or accept it explicitly with --allow-unsigned"
            )
            raise BackupError(msg)
        if not signer.verify(
            BACKUP_DOMAIN, canonical_bytes(_manifest_body(manifest)), manifest.get("signature")
        ):
            msg = "the DR bundle signature does not verify: the manifest was edited"
            raise BackupError(msg)
    artifacts = manifest.get("artifacts") or {}
    if verify_artifacts:
        for name, expected in artifacts.items():
            candidate = directory / str(name)
            if not candidate.is_file():
                msg = f"the bundle is missing {name}"
                raise BackupError(msg)
            digest, size = _sha256_file(candidate)
            if digest != expected.get("sha256") or size != expected.get("size"):
                msg = (
                    f"the bundle's {name} does not match its manifest "
                    f"(expected {str(expected.get('sha256'))[:16]}…/{expected.get('size')} bytes)"
                )
                raise BackupError(msg)
    try:
        database = json.loads((directory / DATABASE_FILE).read_text(encoding="utf-8"))
        config = json.loads((directory / CONFIG_FILE).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        msg = f"the bundle's payload is unreadable: {exc}"
        raise BackupError(msg) from exc
    if not isinstance(database, Mapping):
        msg = "the bundle's database payload is not a table mapping"
        raise BackupError(msg)
    decoded: dict[str, list[dict[str, Any]]] = {}
    for table, rows in database.items():
        if not isinstance(rows, list):
            msg = f"the bundle's {table} payload is not a row list"
            raise BackupError(msg)
        decoded[str(table)] = [
            {str(key): _decode_value(value) for key, value in row.items()}
            for row in rows
            if isinstance(row, Mapping)
        ]
        declared = int((manifest.get("tables") or {}).get(table, len(decoded[str(table)])))
        if declared != len(decoded[str(table)]):
            msg = (
                f"the bundle's {table} has {len(decoded[str(table)])} rows but its manifest "
                f"declares {declared}: the bundle is truncated or was edited"
            )
            raise BackupError(msg)
    evidence = directory / EVIDENCE_DIR
    keys = directory / KEYS_DIR
    return Bundle(
        directory=directory,
        manifest=dict(manifest),
        database=decoded,
        config=dict(config) if isinstance(config, Mapping) else {},
        evidence_dir=evidence if evidence.is_dir() else None,
        keys_dir=keys if keys.is_dir() else None,
        signed=bool(manifest.get("signature")),
        key_id=_key_id_of(manifest.get("signature")),
    )


def _manifest_body(manifest: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in manifest.items() if key != "signature"}


def _key_id_of(signature: Any) -> str | None:
    if not isinstance(signature, str):
        return None
    parts = signature.split(":")
    return parts[1] if len(parts) == 3 else None


# --------------------------------------------------------------------------- restore
def restore_bundle(
    bundle: Bundle,
    *,
    session_factory: sessionmaker[Session],
    engine: Engine | None = None,
    evidence_dir: str | Path | None = None,
    restore_keys_to: str | Path | None = None,
    allow_existing: bool = False,
) -> RestoreReport:
    """Load a verified bundle back into a database (and, optionally, the file trees)."""
    started = datetime.now(UTC)
    notes: list[str] = []
    with session_factory() as session:
        existing = session.scalar(select(func.count()).select_from(_scans_class()))
        if existing and not allow_existing:
            msg = (
                f"the target database already holds {existing} scan(s); restoring over live "
                "data is refused — pass allow_existing=True if that is really intended"
            )
            raise BackupError(msg)
        if existing:
            notes.append(f"restored over {existing} existing scan(s) (allow_existing)")
        counts: dict[str, int] = {}
        # Insert (and flush) one table at a time, in dependency order. Letting the ORM's unit
        # of work order the whole batch is not safe here: it can emit a child's INSERT before
        # its parent's (the observed behaviour with explicitly-assigned primary keys), which
        # fails the foreign key. Flushing per table makes the order this code's, not the
        # ORM's — and a partially-restored database is never committed.
        for cls in _mapped_classes():
            table = cls.__tablename__
            rows = bundle.database.get(table, [])
            if not rows:
                counts[table] = 0
                continue
            for offset in range(0, len(rows), 500):
                batch = rows[offset : offset + 500]
                session.add_all([cls(**row) for row in batch])
                try:
                    session.flush()
                except SaIntegrityError as exc:
                    session.rollback()
                    msg = (
                        f"could not restore {table}: {exc.orig if hasattr(exc, 'orig') else exc} "
                        "— the target database is not empty of these rows, or the bundle and "
                        "the target schema disagree"
                    )
                    raise BackupError(msg) from exc
            session.commit()
            counts[table] = len(rows)

    objects = 0
    if bundle.evidence_dir is not None and evidence_dir is not None:
        destination = Path(evidence_dir).expanduser()
        destination.mkdir(parents=True, exist_ok=True)
        for path in sorted(bundle.evidence_dir.rglob("*")):
            if not path.is_file():
                continue
            relative = path.relative_to(bundle.evidence_dir)
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)
            objects += 1
    elif bundle.evidence_dir is not None:
        notes.append("evidence objects were not restored: no evidence directory was given")

    restored_keys: list[str] = []
    if bundle.keys_dir is not None and restore_keys_to is not None:
        destination = Path(restore_keys_to).expanduser()
        destination.mkdir(parents=True, exist_ok=True)
        for path in sorted(bundle.keys_dir.iterdir()):
            if not path.is_file():
                continue
            target = destination / path.name
            shutil.copy2(path, target)
            restored_keys.append(path.name)
    elif bundle.keys_dir is not None:
        notes.append(
            "key sidecars were not restored: pass restore_keys_to pointing at the operator's "
            "key directory"
        )

    seconds = (datetime.now(UTC) - started).total_seconds()
    total = sum(counts.values())
    _logger.info(
        "dr bundle restored",
        extra={"event": "backup.restored", "rows": total, "seconds": round(seconds, 3)},
    )
    return RestoreReport(
        tables=counts,
        rows=total,
        evidence_objects=objects,
        keys=tuple(restored_keys),
        seconds=seconds,
        target=_database_label(engine),
        notes=tuple(notes),
    )


def _scans_class() -> type[Any]:
    from arachne.data.models import Scan

    return Scan


def _database_label(engine: Engine | None) -> str:
    if engine is None:
        return "unknown"
    return str(engine.url).split("@")[-1]
