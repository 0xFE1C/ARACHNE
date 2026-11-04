"""The disaster-recovery rehearsal: prove the restore works, and measure it (REQ-OPS-010).

Backups exist. A restore that has never been rehearsed is a hope: the bundle verifies, the
procedure is written down, and nobody has watched it fail. This module runs the whole
procedure — back up, rebuild into a **scratch** database, compare, verify the trail — on a
schedule, and records what it measured.

Five stages, each named and timed, because "the rehearsal failed" is not an actionable
sentence at 3 a.m.:

1. ``backup`` — write a full DR bundle from the source database.
2. ``restore`` — load it into a scratch database the rehearsal created. The source is only
   ever *read*; the scratch database is destroyed afterwards.
3. ``row-counts`` — every table's restored count must equal the count the bundle's manifest
   declares. This is the stage that catches a truncated or partially-applied restore.
4. ``audit-chain`` — the restored copy's hash chain, anchors, row signatures and evidence
   hashes must verify. Row counts prove the rows arrived; this proves they arrived *intact*,
   which is the property a restore exists to preserve (INV-8).
5. ``objectives`` — the measured RTO and RPO must be inside the declared objectives.

The two measured numbers, defined precisely because a vague RTO is a number nobody can
falsify:

* **measured RTO** — wall-clock from the start of the restore to the end of the *verification*
  stages: how long until the deployment could serve again with a state it trusts.
* **measured RPO** — the age, at the moment the backup began, of the newest row the source
  database holds. It is how far back the recovery point takes you: everything committed after
  it is what a restore would lose.

Every run writes one JSON line to the record file, pass or fail, so "we rehearse monthly" is a
file of measurements rather than a claim.
"""

from __future__ import annotations

import json
import tempfile
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final

from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker

from arachne.core.config import Settings, get_settings
from arachne.core.errors import ArachneError
from arachne.core.logging import get_logger
from arachne.core.signing import build_signer
from arachne.data.integrity_store import IntegrityVerifier
from arachne.data.models import AuditLog, Base, Scan
from arachne.data.services import build_services
from arachne.resil.backup import (
    DEFAULT_RPO_SECONDS,
    DEFAULT_RTO_SECONDS,
    create_bundle,
    read_bundle,
    restore_bundle,
)

__all__ = [
    "STAGES",
    "RehearsalReport",
    "Stage",
    "record_rehearsal",
    "rehearse",
]

_logger = get_logger("resil.rehearsal")

#: The stages, in the order they run. Named here so a report can say which one broke.
STAGES: Final = (
    "backup",
    "restore",
    "row-counts",
    "audit-chain",
    "objectives",
)


class RehearsalError(ArachneError):
    """A stage failed. The message names the stage; that is the whole point of the class."""

    def __init__(self, stage: str, detail: str) -> None:
        super().__init__(f"stage {stage!r} failed: {detail}")
        self.stage = stage
        self.detail = detail


@dataclass(frozen=True, slots=True)
class Stage:
    """One stage's outcome."""

    name: str
    ok: bool
    seconds: float
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "ok": self.ok,
            "seconds": round(self.seconds, 3),
            "detail": self.detail,
        }


@dataclass(frozen=True, slots=True)
class RehearsalReport:
    """One rehearsal, recorded."""

    source: str
    scratch: str
    bundle: str
    started_at: datetime
    finished_at: datetime
    stages: tuple[Stage, ...]
    measured_rto_seconds: float
    measured_rpo_seconds: float
    declared_rto_seconds: int
    declared_rpo_seconds: int
    rows: dict[str, int] = field(default_factory=dict)
    notes: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return all(stage.ok for stage in self.stages) and len(self.stages) == len(STAGES)

    @property
    def failed_stage(self) -> str | None:
        return next((stage.name for stage in self.stages if not stage.ok), None)

    @property
    def verdict(self) -> str:
        return "passed" if self.ok else "failed"

    def to_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "source": self.source,
            "scratch": self.scratch,
            "bundle": self.bundle,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat(),
            "duration_seconds": round((self.finished_at - self.started_at).total_seconds(), 3),
            "measured_rto_seconds": round(self.measured_rto_seconds, 3),
            "measured_rpo_seconds": round(self.measured_rpo_seconds, 3),
            "declared_rto_seconds": self.declared_rto_seconds,
            "declared_rpo_seconds": self.declared_rpo_seconds,
            "within_rto": self.measured_rto_seconds <= self.declared_rto_seconds,
            "within_rpo": self.measured_rpo_seconds <= self.declared_rpo_seconds,
            "failed_stage": self.failed_stage,
            "rows": dict(self.rows),
            "stages": [stage.to_dict() for stage in self.stages],
            "notes": list(self.notes),
        }

    def summary(self) -> str:
        if self.ok:
            return (
                f"rehearsal PASSED — restored {sum(self.rows.values())} rows in "
                f"{self.measured_rto_seconds:.1f}s (declared RTO {self.declared_rto_seconds}s), "
                f"recovery point {self.measured_rpo_seconds:.1f}s old "
                f"(declared RPO {self.declared_rpo_seconds}s)"
            )
        broken = self.failed_stage or "(a stage never ran)"
        return f"rehearsal FAILED at stage {broken!r}"


def _newest_activity(database_url: str) -> datetime | None:
    """The newest moment the database knows about: the last audit event or finished scan."""
    engine = create_engine(database_url)
    try:
        with sessionmaker(bind=engine)() as session:
            newest = session.scalar(select(func.max(AuditLog.ts)))
            finished = session.scalar(select(func.max(Scan.finished_at)))
            created = session.scalar(select(func.max(Scan.created_at)))
    finally:
        engine.dispose()
    candidates = [_as_utc(value) for value in (newest, finished, created) if value is not None]
    return max(candidates) if candidates else None


def _as_utc(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _restored_row_counts(database_url: str) -> dict[str, int]:
    """Row counts in the restored copy, read through the mapped classes (bound parameters)."""
    engine = create_engine(database_url)
    try:
        counts: dict[str, int] = {}
        with sessionmaker(bind=engine)() as session:
            for mapper in Base.registry.mappers:
                model = mapper.class_
                table = getattr(model, "__tablename__", None)
                if table is None:
                    continue
                counts[str(table)] = int(
                    session.scalar(select(func.count()).select_from(model)) or 0
                )
        return counts
    finally:
        engine.dispose()


def _scratch_database(directory: Path) -> str:
    """A fresh, empty database with the current schema, for the restore to land in."""
    url = f"sqlite:///{directory / 'restored.db'}"
    engine = create_engine(url)
    try:
        Base.metadata.create_all(engine)
    finally:
        engine.dispose()
    return url


def rehearse(
    *,
    settings: Settings | None = None,
    rto_seconds: int = DEFAULT_RTO_SECONDS,
    rpo_seconds: int = DEFAULT_RPO_SECONDS,
    scratch_dir: str | Path | None = None,
    keep_scratch: bool = False,
) -> RehearsalReport:
    """Run the whole backup→restore→verify procedure against a scratch database.

    The source database is never written to by this function: the backup reads it, and
    everything else happens in a scratch directory.
    """
    active = settings or get_settings()
    source_url = active.database_url
    services = build_services(active)
    started = datetime.now(UTC)
    stages: list[Stage] = []
    notes: list[str] = []
    rows: dict[str, int] = {}
    measured_rto = 0.0
    measured_rpo = 0.0

    work = (
        Path(scratch_dir)
        if scratch_dir is not None
        else Path(tempfile.mkdtemp(prefix="arachne-dr-"))
    )
    work.mkdir(parents=True, exist_ok=True)
    bundle_dir = work / "bundle"
    bundle_report = None
    bundle = None
    scratch_url = ""
    try:
        # --- 1. backup ---------------------------------------------------------------
        clock_started = time.monotonic()
        try:
            newest = _newest_activity(source_url)
            bundle_report = create_bundle(
                session_factory=services.session_factory,
                settings=active,
                out_dir=bundle_dir,
                signer=build_signer(active),
                evidence_dir=active.evidence_dir,
                rpo_seconds=rpo_seconds,
                rto_seconds=rto_seconds,
            )
            rows = dict(bundle_report.tables)
            stages.append(
                Stage(
                    "backup",
                    True,
                    time.monotonic() - clock_started,
                    f"{bundle_report.rows} rows across {len(bundle_report.tables)} tables, "
                    f"{bundle_report.evidence_objects} evidence objects",
                )
            )
        except Exception as exc:
            stages.append(Stage("backup", False, time.monotonic() - clock_started, str(exc)))
            raise RehearsalError("backup", str(exc)) from exc

        # The recovery point's age: how far back the newest committed activity is.
        backup_moment = datetime.now(UTC)
        if newest is None:
            measured_rpo = 0.0
            notes.append("the source database holds no dated rows: measured RPO is 0 by definition")
        else:
            measured_rpo = max(0.0, (backup_moment - newest).total_seconds())

        # --- 2. restore into a scratch database ---------------------------------------
        clock_started = time.monotonic()
        restore_seconds = 0.0
        try:
            signer = build_signer(active)
            bundle = read_bundle(bundle_dir, signer=signer, require_signature=signer is not None)
            if signer is None:
                notes.append(
                    "no integrity key is configured: the bundle was read unsigned, so this "
                    "rehearsal did not exercise the signature check"
                )
            scratch_url = _scratch_database(work)
            scratch_engine = create_engine(scratch_url)
            try:
                restore = restore_bundle(
                    bundle,
                    session_factory=sessionmaker(bind=scratch_engine),
                    engine=scratch_engine,
                    evidence_dir=work / "evidence",
                )
            finally:
                scratch_engine.dispose()
            restore_seconds = restore.seconds
            stages.append(
                Stage(
                    "restore",
                    True,
                    time.monotonic() - clock_started,
                    f"{restore.rows} rows restored into a scratch database",
                )
            )
        except Exception as exc:
            stages.append(Stage("restore", False, time.monotonic() - clock_started, str(exc)))
            raise RehearsalError("restore", str(exc)) from exc

        # --- 3. row counts ------------------------------------------------------------
        clock_started = time.monotonic()
        try:
            restored = _restored_row_counts(scratch_url)
            mismatched = {
                table: (count, restored.get(table, 0))
                for table, count in rows.items()
                if restored.get(table, 0) != count
            }
            if mismatched:
                detail = ", ".join(
                    f"{table}: declared {expected}, restored {actual}"
                    for table, (expected, actual) in sorted(mismatched.items())
                )
                raise RehearsalError("row-counts", detail)
            stages.append(
                Stage(
                    "row-counts",
                    True,
                    time.monotonic() - clock_started,
                    f"every one of {len(rows)} table(s) matches its declared count",
                )
            )
        except RehearsalError as exc:
            stages.append(Stage("row-counts", False, time.monotonic() - clock_started, exc.detail))
            raise
        except Exception as exc:
            stages.append(Stage("row-counts", False, time.monotonic() - clock_started, str(exc)))
            raise RehearsalError("row-counts", str(exc)) from exc

        # --- 4. audit-chain integrity of the restored copy -----------------------------
        clock_started = time.monotonic()
        verifier_engine = create_engine(scratch_url)
        try:
            verification = IntegrityVerifier(sessionmaker(bind=verifier_engine)).verify()
            if not verification.ok:
                raise RehearsalError("audit-chain", verification.summary())
            if not verification.checked.get("audit_rows"):
                # Say so rather than let a green stage imply more than it checked.
                notes.append(
                    "the restored copy holds no chained audit rows: the integrity stage had "
                    "nothing to verify"
                )
            stages.append(
                Stage(
                    "audit-chain",
                    True,
                    time.monotonic() - clock_started,
                    f"the restored trail verifies: {verification.summary()}",
                )
            )
        except RehearsalError as exc:
            stages.append(Stage("audit-chain", False, time.monotonic() - clock_started, exc.detail))
            raise
        except Exception as exc:
            stages.append(Stage("audit-chain", False, time.monotonic() - clock_started, str(exc)))
            raise RehearsalError("audit-chain", str(exc)) from exc
        finally:
            verifier_engine.dispose()

        # --- 5. the objectives --------------------------------------------------------
        clock_started = time.monotonic()
        measured_rto = (datetime.now(UTC) - started).total_seconds()
        breaches: list[str] = []
        if measured_rto > rto_seconds:
            breaches.append(f"measured RTO {measured_rto:.1f}s exceeds the declared {rto_seconds}s")
        if measured_rpo > rpo_seconds:
            breaches.append(f"measured RPO {measured_rpo:.1f}s exceeds the declared {rpo_seconds}s")
        if breaches:
            detail = "; ".join(breaches)
            stages.append(Stage("objectives", False, time.monotonic() - clock_started, detail))
            raise RehearsalError("objectives", detail)
        stages.append(
            Stage(
                "objectives",
                True,
                time.monotonic() - clock_started,
                f"RTO {measured_rto:.1f}s / {rto_seconds}s, "
                f"RPO {measured_rpo:.1f}s / {rpo_seconds}s",
            )
        )
        notes.append(f"restore stage took {restore_seconds:.1f}s")
        if not keep_scratch:
            notes.append("the scratch database and bundle were removed after the run")
    finally:
        services.close()
        if not keep_scratch:
            _remove_tree(work)

    finished = datetime.now(UTC)
    report = RehearsalReport(
        source=source_url,
        scratch=scratch_url,
        bundle=str(bundle_dir),
        started_at=started,
        finished_at=finished,
        stages=tuple(stages),
        measured_rto_seconds=measured_rto,
        measured_rpo_seconds=measured_rpo,
        declared_rto_seconds=rto_seconds,
        declared_rpo_seconds=rpo_seconds,
        rows=dict(rows),
        notes=tuple(notes),
    )
    _logger.info(
        "dr rehearsal",
        extra={
            "event": "dr.rehearsal",
            "verdict": report.verdict,
            "failed_stage": report.failed_stage,
            "rto": round(report.measured_rto_seconds, 3),
            "rpo": round(report.measured_rpo_seconds, 3),
        },
    )
    return report


def _remove_tree(path: Path) -> None:
    import shutil

    shutil.rmtree(path, ignore_errors=True)


def record_rehearsal(report: RehearsalReport, path: str | Path) -> Path:
    """Append one line for this run — pass or fail — and return the record file.

    Append-only and one line per run: the record is a series of measurements, and a
    rehearsal that overwrote its predecessor's failure would be worse than no record.
    """
    target = Path(path).expanduser()
    target.parent.mkdir(parents=True, exist_ok=True)
    with target.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(report.to_dict(), sort_keys=True) + "\n")
    return target


def recorded_runs(path: str | Path) -> tuple[dict[str, Any], ...]:
    """Every recorded run, oldest first (so a caller can report the trend)."""
    target = Path(path).expanduser()
    if not target.is_file():
        return ()
    runs: list[dict[str, Any]] = []
    for line in target.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        parsed = json.loads(line)
        if isinstance(parsed, dict):
            runs.append(parsed)
    return tuple(runs)
