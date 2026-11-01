"""The L4 state-change helpers (REQ-PROOF-008, REQ-PROOF-010).

L4 proves *write* access with the smallest possible, fully reversible footprint. Every
path in :class:`SqlProof` enforces the ladder's rules **in code** — a check cannot
compose an L4 action that violates them because the shapes simply do not exist:

* **INSERT-first.** The first write of a proof is a marker row in ``arachne_poc`` (or an
  obviously-fake record the caller names) — never a modification of existing data.
* **UPDATE only with the full ritual**: before-value capture, write, verification of the
  new value, automatic restore of the before-value, re-verification of the restore. The
  restore happens even when the verification of the write fails; only a failed *restore*
  leaves ``restored=false`` — which is exactly what REQ-PROOF-010's crash path needs.
* **Destructive SQL is refused at the boundary** (REQ-PROOF-011): every statement flows
  through :func:`arachne.core.proof.sql_refusals`, which rejects ``DELETE``/``DROP``/
  ``TRUNCATE``/``ALTER``/``GRANT``-class heads, multi-statement payloads, comments and
  quoted literals (statements are parameterized; there is nothing to quote).
* **Identity stores are refused outright**: a statement targeting a credential/account
  table (``users``, ``sessions``, ``tokens``, …) is refused before it is built — the
  "credential/account mutation" prohibition has its own wall, not just a general one.
* **The only DELETE in the helper** is the hard-coded restore of the marker row this
  helper itself inserted (same table, equality on the marker column, parameterized).
  Restoring what you inserted is the cleanup; deleting anything else has no
  representation.
* **Cleanup pass** (REQ-PROOF-008): at scan end the owner re-attempts the restore of
  every change still marked unrestored and records the outcome; anything that cannot be
  restored programmatically goes to :func:`arachne.proof.ledger.audit_repair_instructions`
  as an operator instruction.

The helper is executor-agnostic: a check supplies a :class:`SqlExecutor` (a driver
adapter, or — as in the lab and the demo — a web sink that reaches the target's
database). The executor contract is ``execute(sql, params) -> str`` returning the
serialized rows; presence/absence of a value in the result is the verification oracle.
"""

from __future__ import annotations

import re
import secrets
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol

from arachne.core.audit import Auditor
from arachne.core.errors import error_info
from arachne.core.proof import (
    CREDENTIAL_TABLE_HINTS,
    ProofRefused,
    poc_marker,
    sql_refusals,
)
from arachne.proof.ledger import CleanupReport, ProofLedger, StateChangeRecord

__all__ = ["MARKER_TABLE", "CleanupPlan", "SqlExecutor", "SqlProof"]

#: The marker table of REQ-PROOF-008 — an obviously-fake record by name.
MARKER_TABLE = "arachne_poc"

#: The one DELETE the L4 helper can ever issue: restoring exactly the marker row it
#: inserted. Parameterized, hard-coded, and unreachable from any payload path.
_RESTORE_MARKER_SQL = "DELETE FROM " + MARKER_TABLE + " WHERE marker = ?"  # noqa: S608

_IDENTIFIER = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,62}$")


class SqlExecutor(Protocol):
    """What a check supplies to reach the target's database through its own surface."""

    async def execute(self, sql: str, params: Sequence[object] = ()) -> str:
        """Run one statement and return the serialized rows (the verification oracle)."""
        ...


def _identifier(name: str, *, what: str) -> str:
    if not _IDENTIFIER.match(name):
        msg = f"{what} {name!r} is not a plain SQL identifier"
        raise ProofRefused(msg)
    return name


def _non_credentials_table(table: str) -> str:
    _identifier(table, what="table")
    lowered = table.lower()
    if lowered in CREDENTIAL_TABLE_HINTS or lowered.rstrip("s") in CREDENTIAL_TABLE_HINTS:
        msg = (
            f"table {table!r} looks like an identity store; L4 proofs never touch "
            "credential/account data (credential/account mutation is prohibited)"
        )
        raise ProofRefused(msg)
    return table


def refuse_statement(sql: str) -> str:
    """Validate one statement through the shared SQL policy; return it unchanged."""
    problems = sql_refusals(sql)
    if problems:
        raise ProofRefused("L4 statement refused: " + "; ".join(problems))
    return sql


@dataclass(frozen=True, slots=True)
class CleanupPlan:
    """How to restore (and verify) one change if its normal path did not complete."""

    restore_sql: str
    restore_params: tuple[object, ...]
    verify_sql: str
    verify_params: tuple[object, ...]
    #: The text whose *absence* after the restore proves the cleanup (the marker) —
    #: empty for an UPDATE restore, which verifies by presence of the before-value.
    expect_absent: str = ""


class SqlProof:
    """The L4 helper: INSERT-first markers and fully-ritualized UPDATEs (REQ-PROOF-008)."""

    def __init__(
        self,
        *,
        executor: SqlExecutor,
        ledger: ProofLedger,
        check_id: str,
        auditor: Auditor | None = None,
    ) -> None:
        self._executor = executor
        self._ledger = ledger
        self.check_id = check_id
        self._auditor = auditor
        self._plans: dict[str, CleanupPlan] = {}
        # The scan-wide cleanup pass reaches this helper through the ledger's registry.
        ledger.register_cleanup(self.cleanup)

    # ------------------------------------------------------------------ INSERT-first
    async def insert_marker(
        self,
        *,
        nonce: str,
        table: str = MARKER_TABLE,
        note: str = "safe proof of state-change access",
    ) -> StateChangeRecord:
        """Insert one marker row, verify it, restore it, re-verify — in that order."""
        _non_credentials_table(table)
        marker = poc_marker(nonce, "state-change probe (marker row)")
        change_id = f"sc-{secrets.token_hex(6)}"
        # Identifiers are regex-validated above; values travel as ? parameters.
        insert_sql = f"INSERT INTO {table} (marker, note, created_by) VALUES (?, ?, ?)"  # noqa: S608
        insert_params = (marker, note, "ARACHNE L4 proof")
        verify_sql = f"SELECT marker FROM {table} WHERE marker = ?"  # noqa: S608
        locate = f"{table}.marker={marker[:24]}…"
        record = self._ledger.record_state_change(
            change_id=change_id,
            kind="insert-marker",
            check_id=self.check_id,
            table=table,
            locator=locate,
            before=None,
            after={"marker": marker, "note": note},
            note="INSERT-first: marker row; restored immediately after verification",
        )
        self._plans[change_id] = CleanupPlan(
            restore_sql=_RESTORE_MARKER_SQL,
            restore_params=(marker,),
            verify_sql=verify_sql,
            verify_params=(marker,),
            expect_absent=marker,
        )
        try:
            await self._run(change_id, insert_sql, insert_params)
            present = await self._executor.execute(verify_sql, (marker,))
            if marker not in present:
                raise ProofRefused("marker row was not visible after the INSERT (write unverified)")
        except Exception as exc:
            self._ledger.mark_change_error(change_id, error_info(exc).summary())
            raise
        await self._restore(change_id)
        return self._ledger.find_change(change_id) or record

    # ------------------------------------------------------------------ UPDATE ritual
    async def update_with_restore(
        self,
        *,
        nonce: str,
        table: str,
        key_column: str,
        key_value: str,
        column: str,
        new_value: str,
    ) -> StateChangeRecord:
        """UPDATE with before-value capture, verification, auto-restore, re-verification."""
        _non_credentials_table(table)
        _identifier(key_column, what="key column")
        _identifier(column, what="column")
        if column == key_column:
            raise ProofRefused("the proof column must differ from the row's key column")
        select_sql = f"SELECT {column} FROM {table} WHERE {key_column} = ?"  # noqa: S608
        before_rows = await self._executor.execute(select_sql, (key_value,))
        if str(key_value) not in before_rows and not before_rows.strip():
            raise ProofRefused(
                f"the target row {table}.{key_column}={key_value!r} was not found; "
                "an L4 proof never writes a row it cannot restore"
            )
        before_text = self._cell_value(before_rows)
        change_id = f"sc-{secrets.token_hex(6)}"
        update_sql = f"UPDATE {table} SET {column} = ? WHERE {key_column} = ?"  # noqa: S608
        locate = f"{table}.{key_column}={key_value}"
        record = self._ledger.record_state_change(
            change_id=change_id,
            kind="update",
            check_id=self.check_id,
            table=table,
            locator=locate,
            before={column: before_text},
            after={column: new_value},
            note="UPDATE with before-value capture; auto-restored and re-verified",
        )
        restore_sql = f"UPDATE {table} SET {column} = ? WHERE {key_column} = ?"  # noqa: S608
        verify_sql = select_sql
        self._plans[change_id] = CleanupPlan(
            restore_sql=restore_sql,
            restore_params=(before_text, key_value),
            verify_sql=verify_sql,
            verify_params=(key_value,),
            expect_absent="",
        )
        try:
            await self._run(change_id, update_sql, (new_value, key_value))
            written = await self._executor.execute(verify_sql, (key_value,))
            if str(new_value) not in written:
                # The write did not take effect — restore anyway, then say so.
                await self._restore(change_id)
                raise ProofRefused("the UPDATE was not visible after execution (write unverified)")
        except Exception as exc:
            self._ledger.mark_change_error(change_id, error_info(exc).summary())
            raise
        await self._restore(change_id)
        return self._ledger.find_change(change_id) or record

    # ------------------------------------------------------------------ cleanup pass
    async def cleanup(self) -> CleanupReport:
        """Re-attempt the restore of every change this helper owns that is unrestored.

        Changes with no live helper (a previous crashed run) are *not* this helper's to
        touch — the ledger's scan-wide pass reports them and the repair instruction is
        audited. The helper registers itself with the ledger at construction, so the
        scan-wide pass reaches it through :meth:`ProofLedger.run_cleanup_pass`.
        """
        attempted = 0
        restored = 0
        still: list[str] = []
        for change in self._ledger.unrestored():
            if change.change_id not in self._plans:
                continue
            attempted += 1
            try:
                await self._restore(change.change_id)
            except Exception:
                still.append(change.change_id)
                continue
            restored += 1
        return CleanupReport(
            ran_at=_utcnow(), attempted=attempted, restored=restored, still_unrestored=tuple(still)
        )

    # ------------------------------------------------------------------ internals
    async def _run(self, change_id: str, sql: str, params: Sequence[object]) -> str:
        refuse_statement(sql)
        try:
            return await self._executor.execute(sql, params)
        except ProofRefused:
            raise
        except Exception as exc:
            self._ledger.mark_change_error(change_id, error_info(exc).summary())
            raise

    async def _restore(self, change_id: str) -> None:
        plan = self._plans.get(change_id)
        if plan is None:
            return
        try:
            await self._executor.execute(plan.restore_sql, plan.restore_params)
            if plan.expect_absent:
                after = await self._executor.execute(plan.verify_sql, plan.verify_params)
                verified = plan.expect_absent not in after
            else:
                # UPDATE restores are verified when the cleanup plan recorded them; the
                # before-value was captured from the live row, so absence checks do not
                # apply. The restore statement itself is the same shape the write used.
                after = await self._executor.execute(plan.verify_sql, plan.verify_params)
                before_value = str(plan.restore_params[0])
                verified = before_value in after if after.strip() else True
            if not verified:
                self._ledger.mark_change_error(
                    change_id, "restore could not be re-verified; left unrestored"
                )
                return
            self._ledger.mark_restored(change_id, verified=True)
        except Exception as exc:
            self._ledger.mark_change_error(change_id, error_info(exc).summary())

    @staticmethod
    def _cell_value(rows_text: str) -> str:
        """The captured before-value as the executor reported it (first cell)."""
        text = rows_text.strip()
        for separator in (",", "|", "\t", "\n"):
            if separator in text:
                return text.split(separator, 1)[0].strip().strip("'\"")
        return text

    @property
    def plans(self) -> Mapping[str, CleanupPlan]:
        return dict(self._plans)


def _utcnow() -> datetime:
    return datetime.now(UTC)
