"""The triage workspace model: the shortcut table, the bulk verb and the undo window.

REQ-UIX-006 and ``06-ui-ux.md`` §4.3/§6.1 make three claims that are data, and data can be
checked without a browser:

* the keyboard contract is one table (``SHORTCUTS``) that is both rendered into the sheet and
  used as the oracle for the shipped JavaScript — so a documented key exists and an existing key
  is documented;
* a suppression needs a reason and an acceptance an expiry, checked *before* anything is written
  (the pitfall: suppression must not become a one-click hide);
* an undo record holds the prior state of every row it touched and lives for exactly 60 seconds,
  scoped to the actor and the tenant that created it.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import pytest

from arachne.api import workspace as ws
from arachne.core.errors import ConfigurationError

FIXED_NOW = datetime(2026, 11, 2, 12, 0, 0, tzinfo=UTC)


# ---------------------------------------------------------------- the shortcut table
def test_the_shortcut_table_covers_the_specification_keyboard_contract() -> None:
    """§4.3's table, as the acceptance criterion states it: J/K, X, Shift+X, T, S, A, Enter,
    Cmd/Ctrl+Z, /, ?, Esc."""
    chords = {shortcut.chord for shortcut in ws.SHORTCUTS}
    assert chords == {
        "J",
        "K",
        "X",
        "Shift+X",
        "T",
        "S",
        "A",
        "Enter",
        "Cmd/Ctrl+Z",
        "/",
        "?",
        "Esc",
    }


def test_every_shortcut_names_a_distinct_action_and_a_distinct_key() -> None:
    actions = [shortcut.action for shortcut in ws.SHORTCUTS]
    assert len(actions) == len(set(actions)), "two shortcuts cannot claim one action"
    keys = [key for shortcut in ws.SHORTCUTS for key in shortcut.keys]
    assert len(keys) == len(set(keys)), "a key cannot be bound twice"
    assert set(actions) == set(ws.WORKSPACE_ACTIONS)


def test_the_sheet_is_the_table_and_the_json_matches_it() -> None:
    """`python -m arachne.api.workspace` prints this; the sheet renders it; one source, two
    readers (a second copy is how a key ends up documented but unimplemented)."""
    assert ws.shortcut_sheet() == ws.SHORTCUTS
    table = ws.shortcut_table_json()
    assert len(table) == len(ws.SHORTCUTS)
    for row, shortcut in zip(table, ws.SHORTCUTS, strict=True):
        assert row["keys"] == list(shortcut.keys)
        assert row["action"] == shortcut.action
        assert row["chord"] == shortcut.chord
        assert row["label"] == shortcut.label


def test_the_sheet_says_what_triage_actually_does() -> None:
    """The data model has no `triaged` state, so the label names the state that is set."""
    triage = next(item for item in ws.SHORTCUTS if item.action == "triage")
    assert ws.TRIAGE_STATUS in triage.label
    assert ws.TRIAGE_STATUS in {"open", "verified", "fp", "merged"}


# ---------------------------------------------------------------- the bulk verb
def _form(**over: str) -> dict[str, str]:
    base = {"action": "triage", "finding_ids": "1,2,3"}
    base.update(over)
    return base


def test_a_triage_request_names_its_findings_and_its_status() -> None:
    action = ws.parse_bulk_action(_form())
    assert action.action == "triage"
    assert action.finding_ids == (1, 2, 3)
    assert action.status == ws.TRIAGE_STATUS
    assert action.label == "triaged"


def test_a_duplicate_finding_id_is_collapsed() -> None:
    assert ws.parse_bulk_action(_form(finding_ids="2,2,1")).finding_ids == (2, 1)


@pytest.mark.parametrize(
    "form, expected",
    [
        (_form(action="delete"), "unknown triage action"),
        (_form(finding_ids=""), "select at least one finding"),
        (_form(finding_ids="0"), "not a positive integer"),
        (_form(finding_ids="abc"), "not a positive integer"),
        (
            _form(finding_ids=",".join(str(n) for n in range(1, ws.MAX_BULK_FINDINGS + 2))),
            "at most",
        ),
    ],
)
def test_an_impossible_bulk_request_is_refused_with_a_sentence(
    form: dict[str, str], expected: str
) -> None:
    with pytest.raises(ConfigurationError, match=expected):
        ws.parse_bulk_action(form)


def test_a_suppression_without_a_reason_is_refused() -> None:
    """§4.3: S opens a drawer requiring a reason. "One-click hide" is the failure mode."""
    with pytest.raises(ConfigurationError, match="at least 8 characters"):
        ws.parse_bulk_action(_form(action="suppress", reason=""))
    with pytest.raises(ConfigurationError, match="at least 8 characters"):
        ws.parse_bulk_action(_form(action="suppress", reason="fp"))


def test_a_suppression_with_a_reason_keeps_the_reason() -> None:
    action = ws.parse_bulk_action(
        _form(action="suppress", reason="  vendor banner,  not a finding  ")
    )
    assert action.reason == "vendor banner, not a finding"
    assert action.label == "suppressed"


def test_a_risk_acceptance_needs_an_owner_a_justification_and_a_future_expiry() -> None:
    base = {"action": "accept", "finding_ids": "7"}
    with pytest.raises(ConfigurationError, match="owner"):
        ws.parse_bulk_action({**base, "justification": "long enough text", "ttl_days": "30"})
    with pytest.raises(ConfigurationError, match="justification"):
        ws.parse_bulk_action({**base, "owner": "jane", "justification": "short", "ttl_days": "30"})
    for days in ("", "0", "9999", "soon"):
        with pytest.raises(ConfigurationError, match="expiry"):
            ws.parse_bulk_action(
                {**base, "owner": "jane", "justification": "long enough text", "ttl_days": days}
            )
    action = ws.parse_bulk_action(
        {
            **base,
            "owner": "Jane Operator",
            "justification": "accepted for the quarter",
            "ttl_days": "90",
        }
    )
    assert action.ttl_days == 90
    assert action.label == "risk accepted"


# ---------------------------------------------------------------- the undo window
def _record(now: datetime = FIXED_NOW, **over: object) -> ws.UndoRecord:
    kwargs: dict[str, object] = {
        "token": "tok",
        "actor": "scan:scanner",
        "project_id": 3,
        "action": "triage",
        "label": "triaged",
        "targets": (ws.UndoTarget(finding_id=1, kind="status", prior="open"),),
        "now": now,
    }
    kwargs.update(over)
    return ws.new_undo_record(**kwargs)  # type: ignore[arg-type]


def test_the_undo_window_is_sixty_seconds_from_the_action() -> None:
    record = _record()
    assert record.expires_at - record.created_at == timedelta(seconds=ws.UNDO_WINDOW_SECONDS)
    assert ws.UNDO_WINDOW_SECONDS == 60, "§4.3/§6.1: 60 s is the contract, not a tuning knob"
    assert record.seconds_left(now=FIXED_NOW) == 60
    assert record.seconds_left(now=FIXED_NOW + timedelta(seconds=59)) == 1
    assert record.seconds_left(now=FIXED_NOW + timedelta(seconds=120)) == 0


def test_an_undo_inside_the_window_is_returned_and_consumed() -> None:
    store = ws.UndoStore()
    store.put(_record())
    found = store.get(
        "tok", actor="scan:scanner", project_id=3, now=FIXED_NOW + timedelta(seconds=30)
    )
    assert found.targets[0].prior == "open"
    consumed = store.consume(
        "tok", actor="scan:scanner", project_id=3, now=FIXED_NOW + timedelta(seconds=31)
    )
    assert consumed.token == "tok"
    assert len(store) == 0, "an undo is used once: a second one would be a silent re-run"


def test_an_undo_after_the_window_is_refused_and_dropped() -> None:
    store = ws.UndoStore()
    store.put(_record())
    with pytest.raises(ws.UndoWindowClosedError, match="60-second undo window"):
        store.get("tok", actor="scan:scanner", project_id=3, now=FIXED_NOW + timedelta(seconds=61))
    assert len(store) == 0


def test_exactly_at_the_boundary_the_window_has_closed() -> None:
    """60.0 s is out: "available for at least one minute" is not "until 60.001 s"."""
    store = ws.UndoStore()
    store.put(_record())
    assert store.get("tok", actor="scan:scanner", project_id=3, now=FIXED_NOW).token == "tok"
    with pytest.raises(ws.UndoWindowClosedError):
        store.get("tok", actor="scan:scanner", project_id=3, now=FIXED_NOW + timedelta(seconds=60))


def test_another_actor_cannot_spend_someone_elses_undo() -> None:
    """An undo record is the prior state of specific rows, so it is scoped to its author."""
    store = ws.UndoStore()
    store.put(_record())
    with pytest.raises(ws.UndoUnavailableError):
        store.get("tok", actor="someone-else", project_id=3, now=FIXED_NOW)
    with pytest.raises(ws.UndoUnavailableError):
        store.get("tok", actor="scan:scanner", project_id=99, now=FIXED_NOW)
    with pytest.raises(ws.UndoUnavailableError):
        store.get("nope", actor="scan:scanner", project_id=3, now=FIXED_NOW)


def test_prune_sweeps_only_the_expired_records() -> None:
    store = ws.UndoStore()
    store.put(_record(token="old"))
    store.put(_record(token="new", now=FIXED_NOW + timedelta(seconds=30)))
    assert store.prune(now=FIXED_NOW + timedelta(seconds=70)) == 1
    assert len(store) == 1
    assert store.get(
        "new", actor="scan:scanner", project_id=3, now=FIXED_NOW + timedelta(seconds=71)
    )


def test_putting_a_new_record_sweeps_the_expired_ones() -> None:
    store = ws.UndoStore()
    store.put(_record(token="old"))
    store.put(_record(token="new", now=FIXED_NOW + timedelta(seconds=120)))
    assert len(store) == 1


def test_the_store_hangs_off_the_application_context_and_is_created_once() -> None:
    @dataclass
    class FakeContext:
        extras: dict[str, object]

    context = FakeContext(extras={})
    first = ws.store_for(context)
    assert ws.store_for(context) is first
    assert len(first) == 0
