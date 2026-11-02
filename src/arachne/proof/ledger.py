"""The per-scan proof journal (REQ-PROOF-010, REQ-PROOF-012).

Everything the proof engine does to a target — and everything it *planned* to do — is
written here first and persisted with the scan record (``scans.stats["proof"]``):

* **The nonce→probe map** (REQ-PROOF-012): every OOB token issued for the scan, which
  check owns it, whether it was consumed, and the hit it matched.
* **State changes** (REQ-PROOF-008): every L4 write as a record with its before-value,
  its restore status and its verification. Records are **write-ahead**: a change is
  persisted with ``restored=false`` *before* the write is attempted, so a crash between
  the write and its restore leaves a durable ``restored=false`` row — the repair
  instruction comes from :meth:`ProofLedger.repair_instructions` (REQ-PROOF-010), and
  the report renders the row as not restored.
* **Cleanup status** (REQ-PROOF-008): what the end-of-scan cleanup pass did, so "did
  the scan leave anything behind?" is answerable from the scan record alone.

The ledger is deliberately a plain object over the existing :class:`ScanStateStore`
protocol — no new table, no new persistence mechanism (C-04: compose with the built-in
mechanisms). ``save()`` re-reads the scan's stats each time and merges, because other
steps write stats too.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from arachne.core.audit import AuditAction, Auditor, AuditOutcome
from arachne.core.redaction import redact_value

if TYPE_CHECKING:  # runtime-free: the store protocol lives in core (S15 keeps core core-only)
    from arachne.core.lifecycle import ScanStateStore

__all__ = ["CleanupReport", "ProofLedger", "StateChangeRecord"]

#: Upper bound on recorded proof journal entries per scan. A run-away check must not be
#: able to bloat the scan record without bound.
MAX_LEDGER_ENTRIES = 512


def _now() -> datetime:
    return datetime.now(UTC)


def _redacted(value: Any) -> Any:
    """Values stored in the ledger are redacted like evidence (REQ-PROOF-012)."""
    return redact_value(value)


@dataclass(frozen=True, slots=True)
class StateChangeRecord:
    """One L4 write, from intent to verified restore (REQ-PROOF-008/010)."""

    change_id: str
    kind: str  # "insert-marker" | "update"
    check_id: str
    table: str
    locator: str  # human-readable "where": table + row/column identity
    before: dict[str, Any] | None  # captured value (UPDATE) — None for an INSERT marker
    after: dict[str, Any]
    restored: bool = False
    restored_at: datetime | None = None
    restore_verified: bool = False
    note: str | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "change_id": self.change_id,
            "kind": self.kind,
            "check_id": self.check_id,
            "table": self.table,
            "locator": self.locator,
            "before": self.before,
            "after": self.after,
            "restored": self.restored,
            "restored_at": self.restored_at.isoformat() if self.restored_at else None,
            "restore_verified": self.restore_verified,
            "note": self.note,
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> StateChangeRecord:
        return cls(
            change_id=str(data.get("change_id") or ""),
            kind=str(data.get("kind") or ""),
            check_id=str(data.get("check_id") or ""),
            table=str(data.get("table") or ""),
            locator=str(data.get("locator") or ""),
            before=(dict(data["before"]) if isinstance(data.get("before"), dict) else None),
            after=dict(data["after"]) if isinstance(data.get("after"), dict) else {},
            restored=bool(data.get("restored")),
            restored_at=None,
            restore_verified=bool(data.get("restore_verified")),
            note=data.get("note"),
            error=data.get("error"),
        )

    def repair_instruction(self) -> str:
        """The one-line operator instruction REQ-PROOF-010 requires after a crash."""
        target = f"{self.before or 'the original value'} on {self.locator}"
        return (
            f"REPAIR REQUIRED — ARACHNE L4 proof '{self.kind}' on {self.locator} "
            f"(change {self.change_id}, check {self.check_id}) was not restored: "
            f"set {target} manually, then verify. See the ARACHNE report's state-changes table."
        )


@dataclass(frozen=True, slots=True)
class CleanupReport:
    """What the end-of-scan cleanup pass found and did (REQ-PROOF-008)."""

    ran_at: datetime
    attempted: int = 0
    restored: int = 0
    still_unrestored: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "ran_at": self.ran_at.isoformat(),
            "attempted": self.attempted,
            "restored": self.restored,
            "still_unrestored": list(self.still_unrestored),
        }


class ProofLedger:
    """The scan-scoped proof journal, persisted through the scan state store."""

    def __init__(
        self,
        store: ScanStateStore,
        scan_id: int,
        *,
        auditor: Auditor | None = None,
    ) -> None:
        self._store = store
        self.scan_id = scan_id
        self._auditor = auditor
        self._oob: dict[str, dict[str, Any]] = {}
        self._changes: list[dict[str, Any]] = []
        self._cleanups: list[dict[str, Any]] = []
        self._cleanups_registered: list[Callable[[], Awaitable[CleanupReport]]] = []
        self._load()

    # ------------------------------------------------------------------ persistence
    def _load(self) -> None:
        record = self._store.get_scan(self.scan_id)
        payload = (record.stats.get("proof") if record else None) or {}
        if not isinstance(payload, dict):
            return
        oob = payload.get("oob")
        if isinstance(oob, dict):
            self._oob = {
                str(key): dict(item) for key, item in oob.items() if isinstance(item, dict)
            }
        changes = payload.get("state_changes")
        if isinstance(changes, list):
            self._changes = [dict(item) for item in changes if isinstance(item, dict)]
        cleanups = payload.get("cleanups")
        if isinstance(cleanups, list):
            self._cleanups = [dict(item) for item in cleanups if isinstance(item, dict)]

    def save(self) -> None:
        """Merge the journal into the scan record's stats (other keys are preserved)."""
        record = self._store.get_scan(self.scan_id)
        if record is None:
            return
        stats = dict(record.stats)
        stats["proof"] = {
            "oob": dict(self._oob),
            "state_changes": list(self._changes),
            "cleanups": list(self._cleanups),
        }
        self._store.update_scan(self.scan_id, stats=stats)

    # ------------------------------------------------------------------ OOB probes
    def record_oob_probe(
        self, token: str, *, check_id: str, nonce: str, consumed: bool = False
    ) -> None:
        """Record an issued token (the nonce→probe map of REQ-PROOF-012)."""
        if len(self._oob) >= MAX_LEDGER_ENTRIES:
            return
        self._oob[token] = {
            "token": token,
            "check_id": check_id,
            "nonce": nonce,
            "issued_at": _now().isoformat(),
            "consumed": consumed,
            "hit": None,
        }
        self.save()

    def mark_oob_consumed(self, token: str, hit: dict[str, Any] | None) -> None:
        entry = self._oob.get(token)
        if entry is None:
            return
        self._oob[token] = {**entry, "consumed": True, "hit": _redacted(hit or {})}
        self.save()

    @property
    def oob_probes(self) -> dict[str, dict[str, Any]]:
        """The nonce→probe map as persisted (REQ-PROOF-012)."""
        return dict(self._oob)

    # ------------------------------------------------------------------ state changes
    def record_state_change(
        self,
        *,
        change_id: str,
        kind: str,
        check_id: str,
        table: str,
        locator: str,
        before: dict[str, Any] | None,
        after: dict[str, Any],
        note: str | None = None,
    ) -> StateChangeRecord:
        """Write-ahead: persist the change with ``restored=false`` *before* it happens.

        A crash after the write but before the restore therefore leaves the durable
        ``restored=false`` row REQ-PROOF-010 requires, and the repair instruction can be
        produced from the scan record alone.
        """
        record = StateChangeRecord(
            change_id=change_id,
            kind=kind,
            check_id=check_id,
            table=table,
            locator=locator,
            before=None if before is None else _redacted(dict(before)),
            after=_redacted(dict(after)),
            restored=False,
            note=note,
        )
        if len(self._changes) < MAX_LEDGER_ENTRIES:
            self._changes.append(record.to_dict())
        self.save()
        if self._auditor is not None:
            self._auditor.record(
                AuditAction.PROOF_STATE_CHANGED,
                scan_id=self.scan_id,
                target=record.locator,
                meta={
                    "change_id": record.change_id,
                    "kind": record.kind,
                    "check": record.check_id,
                    "restored": False,
                },
            )
        return record

    def mark_restored(self, change_id: str, *, verified: bool) -> StateChangeRecord | None:
        for index, item in enumerate(self._changes):
            if item.get("change_id") != change_id:
                continue
            updated = StateChangeRecord.from_dict(item)
            restored = replace(
                updated, restored=True, restored_at=_now(), restore_verified=verified
            )
            self._changes[index] = restored.to_dict()
            self.save()
            if self._auditor is not None:
                self._auditor.record(
                    AuditAction.PROOF_STATE_RESTORED,
                    scan_id=self.scan_id,
                    target=restored.locator,
                    outcome=AuditOutcome.ALLOWED if verified else AuditOutcome.ERROR,
                    meta={
                        "change_id": restored.change_id,
                        "verified": verified,
                        "check": restored.check_id,
                    },
                )
            return restored
        return None

    def mark_change_error(self, change_id: str, error: str) -> None:
        for index, item in enumerate(self._changes):
            if item.get("change_id") == change_id:
                self._changes[index] = {**item, "error": str(error)[:500]}
                self.save()
                return

    def unrestored(self) -> tuple[StateChangeRecord, ...]:
        return tuple(
            StateChangeRecord.from_dict(item) for item in self._changes if not item.get("restored")
        )

    @property
    def state_changes(self) -> tuple[dict[str, Any], ...]:
        return tuple(dict(item) for item in self._changes)

    def find_change(self, change_id: str) -> StateChangeRecord | None:
        for item in self._changes:
            if item.get("change_id") == change_id:
                return StateChangeRecord.from_dict(item)
        return None

    # ------------------------------------------------------------------ cleanup
    def register_cleanup(self, restore: Callable[[], Awaitable[CleanupReport]]) -> None:
        """Register an L4 helper's own cleanup (its restores) with the scan-wide pass."""
        self._cleanups_registered.append(restore)

    async def run_cleanup_pass(self) -> CleanupReport:
        """The end-of-scan cleanup pass (REQ-PROOF-008).

        Every registered helper restores what it owns; changes with no live helper (a
        crashed earlier attempt) are reported as still unrestored — their repair
        instruction is audited by :func:`audit_repair_instructions`.
        """
        attempted = 0
        restored = 0
        helper_still: set[str] = set()
        for restore in self._cleanups_registered:
            report = await restore()
            attempted += report.attempted
            restored += report.restored
            helper_still.update(report.still_unrestored)
        unrestored = {change.change_id for change in self.unrestored() if change.change_id}
        orphans = unrestored - helper_still
        combined = CleanupReport(
            ran_at=_now(),
            attempted=attempted,
            restored=restored,
            still_unrestored=tuple(sorted(helper_still | orphans)),
        )
        self.record_cleanup(combined)
        return combined

    def record_cleanup(self, report: CleanupReport) -> None:
        self._cleanups.append(report.to_dict())
        self.save()

    @property
    def cleanup_status(self) -> dict[str, Any]:
        """The latest cleanup pass, or the zero state (REQ-PROOF-008/012)."""
        if not self._cleanups:
            return {"ran": False, "restored": 0, "still_unrestored": []}
        latest = self._cleanups[-1]
        return {
            "ran": True,
            "ran_at": latest.get("ran_at"),
            "attempted": latest.get("attempted", 0),
            "restored": latest.get("restored", 0),
            "still_unrestored": list(latest.get("still_unrestored") or ()),
        }

    def repair_instructions(self) -> tuple[str, ...]:
        """One instruction per unrestored change — the REQ-PROOF-010 audit content."""
        return tuple(change.repair_instruction() for change in self.unrestored())

    def summary(self) -> dict[str, Any]:
        """The report-facing shape: state changes + cleanup status + OOB count."""
        return {
            "state_changes": list(self._changes),
            "cleanup": self.cleanup_status,
            "oob_tokens": len(self._oob),
            "oob_consumed": sum(1 for item in self._oob.values() if item.get("consumed")),
        }


def audit_repair_instructions(ledger: ProofLedger, auditor: Auditor) -> int:
    """Audit one ``proof.repair_required`` line per unrestored change (REQ-PROOF-010).

    Called at scan end and on resume: a crash between an L4 write and its restore must
    leave the repair instruction in the audit trail even though the crashing process
    could not write it. Returns the number of instructions emitted.
    """
    instructions = ledger.repair_instructions()
    for instruction in instructions:
        auditor.record(
            AuditAction.PROOF_REPAIR_REQUIRED,
            outcome=AuditOutcome.ERROR,
            scan_id=ledger.scan_id,
            reason=instruction,
        )
    return len(instructions)
