"""The triage workspace: the keyboard contract, the bulk action and the 60-second undo.

``.spec/06-ui-ux.md`` §4.3 is the most detailed screen in the specification, and its two
load-bearing parts are a *table of shortcuts* and an *undo contract*. Both are data here, so
neither can drift from the code that implements it:

* :data:`SHORTCUTS` is the one table. It is rendered into the shortcut sheet on the page (so a
  shortcut is discoverable), and it is the oracle the JavaScript core is tested against
  (``tests/integration/test_ui_triage_usability.py`` drives the shipped ``workspace.js`` once per
  row of this table and fails unless the key produces the documented action). One table, two
  readers — a key that is documented always exists, and a key that exists is always documented.
* :class:`UndoStore` holds one :class:`UndoRecord` per bulk action: the **prior state** of every
  row it touched, so undo *restores* rather than re-runs (the WP-05 pitfall). The record is
  scoped to the actor and the tenant that created it, expires after
  :data:`UNDO_WINDOW_SECONDS`, and is audited when it is applied.

Two readings were taken, because the specification is not self-consistent about them:

* **"Mark triaged" lands on the ``verified`` status.** §4.3's footer button and its ``T``
  shortcut both say "Mark triaged", and §6.1 names the audit action ``finding.triaged`` — but the
  finding-status vocabulary is closed at ``open|verified|fp|merged``
  (:data:`arachne.data.api_store.FINDING_STATUSES`), and widening it would change the published
  OpenAPI enum, the client fixtures and the report model, none of which is this work package's
  area. ``verified`` is the one state that means "a human looked at this and it stands", so that
  is where triage lands; the action keeps the specification's label and the row shows the state
  it really has. Recorded in the WP-05 handoff.
* **Undo lives in this process, for 60 seconds.** The tree has no table for an undo record and
  ``migrations/`` is outside WP-05's work area, so the record is held in
  :class:`UndoStore` (one per application context, in ``AppContext.extras``). A 60-second window
  is inherently process-local; a restart loses it, which is the honest behaviour for "the action
  is final after a minute".
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any, Final, Literal

from arachne.core.errors import ConfigurationError

__all__ = [
    "MAX_BULK_FINDINGS",
    "SHORTCUTS",
    "TRIAGE_STATUS",
    "UNDO_WINDOW_SECONDS",
    "BulkAction",
    "Shortcut",
    "UndoRecord",
    "UndoStore",
    "UndoTarget",
    "UndoWindowClosedError",
    "WorkspaceAction",
    "parse_bulk_action",
    "shortcut_sheet",
    "shortcut_table_json",
]

#: How long an undo stays available (§4.3, §6.1: "60 s", "60 s, whole batch").
UNDO_WINDOW_SECONDS: Final = 60

#: The status "Mark triaged" sets. See the module docstring for why it is ``verified``.
TRIAGE_STATUS: Final = "verified"

#: One page of the workspace is 50 rows (REQ-UIX-001's own default), so a bulk action that
#: exceeds it is a forged request rather than a selection an operator can build.
MAX_BULK_FINDINGS: Final = 200

#: The actions a bulk request may name. A closed vocabulary: the route never dispatches on a
#: value the client invented.
WorkspaceAction = Literal["triage", "suppress", "accept"]


@dataclass(frozen=True, slots=True)
class Shortcut:
    """One row of §4.3's keyboard contract.

    ``keys`` are the literal spellings the browser core matches (``"shift+x"``, ``"mod+z"``),
    ``chord`` is what a human reads in the sheet, and ``action`` is the effect the core must
    produce. ``group`` orders the sheet.
    """

    keys: tuple[str, ...]
    chord: str
    label: str
    action: str
    group: str = "move"


#: §4.3's keyboard contract, in the specification's own order. ``escape`` is §2.2's "Esc
#: returns to the list with the same scroll position and selection" (see also §4.4).
SHORTCUTS: tuple[Shortcut, ...] = (
    Shortcut(("j",), "J", "Next row", "next", "move"),
    Shortcut(("k",), "K", "Previous row", "previous", "move"),
    Shortcut(("x",), "X", "Toggle selection on the focused row", "select", "select"),
    Shortcut(
        ("shift+x",), "Shift+X", "Select the range from the last anchor", "select-range", "select"
    ),
    Shortcut(("t",), "T", "Mark triaged (State → verified)", "triage", "decide"),
    Shortcut(("s",), "S", "Suppress — a reason is required", "suppress", "decide"),
    Shortcut(("a",), "A", "Accept risk — an expiry is required", "accept", "decide"),
    Shortcut(("enter",), "Enter", "Open the finding detail", "open", "navigate"),
    Shortcut(("mod+z",), "Cmd/Ctrl+Z", "Undo the last bulk action (60 s)", "undo", "navigate"),
    Shortcut(("/",), "/", "Focus the search box", "search", "navigate"),
    Shortcut(("?",), "?", "Show the shortcut sheet", "shortcut-sheet", "navigate"),
    Shortcut(
        ("escape",), "Esc", "Close the drawer, or return with your place kept", "escape", "navigate"
    ),
)

#: Every action the core may produce, derived from the table above (never a second list).
WORKSPACE_ACTIONS: Final[frozenset[str]] = frozenset(item.action for item in SHORTCUTS)


def shortcut_sheet() -> tuple[Shortcut, ...]:
    """The sheet's rows, in reading order (the route hands this to the template)."""
    return SHORTCUTS


def shortcut_table_json() -> list[dict[str, Any]]:
    """The same table as JSON — the oracle the JavaScript core is tested against.

    ``tests/unit/test_workspace.py`` compares this with the table ``workspace.js`` advertises, so
    a key added on one side and not the other fails the build rather than going unnoticed.
    """
    return [
        {
            "keys": list(item.keys),
            "chord": item.chord,
            "label": item.label,
            "action": item.action,
            "group": item.group,
        }
        for item in SHORTCUTS
    ]


# --------------------------------------------------------------------------- bulk actions
@dataclass(frozen=True, slots=True)
class BulkAction:
    """A validated bulk request: what to do, to which findings, and with what."""

    action: WorkspaceAction
    finding_ids: tuple[int, ...]
    #: ``triage`` only: the status to set (always :data:`TRIAGE_STATUS` today).
    status: str = TRIAGE_STATUS
    #: ``suppress`` only: the reason. Mandatory — a suppression without one is a hidden finding.
    reason: str = ""
    #: ``accept`` only: the accountable owner, the justification and the expiry in days.
    owner: str = ""
    justification: str = ""
    ttl_days: int = 0

    @property
    def label(self) -> str:
        """The wording the toast and the audit trail use."""
        if self.action == "triage":
            return "triaged"
        if self.action == "suppress":
            return "suppressed"
        return "risk accepted"


def parse_bulk_action(form: dict[str, str]) -> BulkAction:
    """Validate a bulk request's fields, or raise :class:`ConfigurationError` naming the gap.

    The route calls this *before* it touches the store: a request that cannot become a complete
    action never writes anything, which is what keeps `suppress` from degrading into a one-click
    hide (the WP-05 pitfall).
    """
    action = (form.get("action") or "").strip().lower()
    if action not in ("triage", "suppress", "accept"):
        raise ConfigurationError(f"unknown triage action {action!r}")
    ids: list[int] = []
    for chunk in (form.get("finding_ids") or "").replace(" ", "").split(","):
        if not chunk:
            continue
        if not chunk.isdigit() or int(chunk) < 1:
            raise ConfigurationError(f"finding id {chunk!r} is not a positive integer")
        value = int(chunk)
        if value not in ids:
            ids.append(value)
    if not ids:
        raise ConfigurationError("select at least one finding")
    if len(ids) > MAX_BULK_FINDINGS:
        raise ConfigurationError(
            f"a bulk action covers at most {MAX_BULK_FINDINGS} findings, got {len(ids)}"
        )
    if action == "suppress":
        reason = " ".join((form.get("reason") or "").split())
        # The length rule is the store's own (``quality.suppressions.MIN_REASON_CHARS``); asking
        # it here as well means a bad request is refused by the *route* with a sentence rather
        # than surfacing as a store exception after some rows were already written.
        from arachne.quality.suppressions import MIN_REASON_CHARS

        if len(reason) < MIN_REASON_CHARS:
            raise ConfigurationError(
                f"a suppression needs a reason of at least {MIN_REASON_CHARS} characters"
            )
        return BulkAction(action="suppress", finding_ids=tuple(ids), reason=reason)
    if action == "accept":
        # The store's own minimums (``quality.acceptance``), asked here so a bad request is a
        # sentence from the route rather than a validation error after some rows were written.
        from arachne.quality.acceptance import MIN_JUSTIFICATION_CHARS

        owner = " ".join((form.get("owner") or "").split())
        justification = " ".join((form.get("justification") or "").split())
        days = (form.get("ttl_days") or "").strip()
        if len(owner) < 2:
            raise ConfigurationError("a risk acceptance needs an accountable owner")
        if len(justification) < MIN_JUSTIFICATION_CHARS:
            raise ConfigurationError(
                f"a risk acceptance needs a justification of at least "
                f"{MIN_JUSTIFICATION_CHARS} characters"
            )
        if not days.isdigit() or not 1 <= int(days) <= 3650:
            raise ConfigurationError("a risk acceptance needs an expiry between 1 and 3650 days")
        return BulkAction(
            action="accept",
            finding_ids=tuple(ids),
            owner=owner,
            justification=justification,
            ttl_days=int(days),
        )
    return BulkAction(action="triage", finding_ids=tuple(ids), status=TRIAGE_STATUS)


# --------------------------------------------------------------------------- undo
@dataclass(frozen=True, slots=True)
class UndoTarget:
    """One row's prior state, and what it takes to put it back.

    ``kind`` names the *inverse operation*, so undo never re-runs the original action:

    ``status``      the row has a status again (``prior`` is the status it had);
    ``suppression`` a suppression created by the action is revoked (``created_id``);
    ``acceptance``  a risk acceptance created by the action is withdrawn (``created_id``).
    """

    finding_id: int
    kind: Literal["status", "suppression", "acceptance"]
    prior: str | None = None
    created_id: int | None = None


@dataclass(frozen=True, slots=True)
class UndoRecord:
    """The inverse of one bulk action, held for :data:`UNDO_WINDOW_SECONDS`."""

    token: str
    actor: str
    project_id: int | None
    action: str
    label: str
    targets: tuple[UndoTarget, ...]
    created_at: datetime
    expires_at: datetime

    def expired(self, *, now: datetime) -> bool:
        return now >= self.expires_at

    def seconds_left(self, *, now: datetime) -> int:
        return max(0, int((self.expires_at - now).total_seconds()))


class UndoWindowClosedError(ConfigurationError):
    """The undo window closed: the action is final (still reversible by a new action)."""


class UndoUnavailableError(ConfigurationError):
    """No such undo record for this actor and tenant (expired, consumed, or never theirs)."""


@dataclass(slots=True)
class UndoStore:
    """The process-local, actor-scoped undo records.

    One per application context (``AppContext.extras["undo"]``), so a test app never sees another
    app's records. Applying a record removes it: undoing twice is not a thing, and a *second*
    undo of the same batch would be a silent re-run.
    """

    _records: dict[str, UndoRecord] = field(default_factory=dict)

    def put(self, record: UndoRecord) -> UndoRecord:
        self.prune(now=record.created_at)
        self._records[record.token] = record
        return record

    def get(self, token: str, *, actor: str, project_id: int | None, now: datetime) -> UndoRecord:
        """The record ``token`` names, or raise naming which of the two reasons applies.

        The actor and the tenant are part of the lookup, not a check after it: an undo record is
        the *prior state of specific rows*, so handing it to another principal would be a
        cross-tenant write with a legitimate-looking token.
        """
        record = self._records.get(token)
        if record is None or record.actor != actor or record.project_id != project_id:
            raise UndoUnavailableError("there is no undo for this action")
        if record.expired(now=now):
            del self._records[token]
            raise UndoWindowClosedError(
                f"the {UNDO_WINDOW_SECONDS}-second undo window has closed; "
                "the action stands (a new action can still reverse it)"
            )
        return record

    def consume(
        self, token: str, *, actor: str, project_id: int | None, now: datetime
    ) -> UndoRecord:
        record = self.get(token, actor=actor, project_id=project_id, now=now)
        del self._records[token]
        return record

    def prune(self, *, now: datetime) -> int:
        """Drop every expired record; returns how many went (so a test can assert the sweep)."""
        stale = [token for token, record in self._records.items() if record.expired(now=now)]
        for token in stale:
            del self._records[token]
        return len(stale)

    def __len__(self) -> int:
        return len(self._records)


def now_utc() -> datetime:
    """The clock the undo window is measured against (patched by the expiry test)."""
    return datetime.now(UTC)


def new_undo_record(
    *,
    token: str,
    actor: str,
    project_id: int | None,
    action: str,
    label: str,
    targets: tuple[UndoTarget, ...],
    now: datetime | None = None,
) -> UndoRecord:
    created = now or now_utc()
    return UndoRecord(
        token=token,
        actor=actor,
        project_id=project_id,
        action=action,
        label=label,
        targets=targets,
        created_at=created,
        expires_at=created + timedelta(seconds=UNDO_WINDOW_SECONDS),
    )


def store_for(context: Any) -> UndoStore:
    """The app context's undo store, created on first use.

    ``AppContext.extras`` is the context's own extension slot, so this needs no field on the
    dataclass and no migration. A context built by a test is therefore isolated by construction.
    """
    store = context.extras.get("undo")
    if not isinstance(store, UndoStore):
        store = UndoStore()
        context.extras["undo"] = store
    return store
