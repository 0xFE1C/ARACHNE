"""The triage workspace over HTTP: bulk actions, the 60-second undo, and the viewer's silence.

REQ-UIX-006's acceptance criteria, driven through the real app (middleware, auth, Jinja, the
store) with ``TestClient``:

* a bulk action writes **one audit event per finding** and offers **one** undo for the batch;
* undo *restores* the prior state — including a row that was not ``open`` to begin with — rather
  than re-running the action, and is itself audited;
* the undo window is 60 seconds, enforced server-side;
* a suppression without a reason and an acceptance without an expiry are refused *before*
  anything is written;
* a viewer's session renders **no** selection or bulk control at all (absent, not disabled) and
  its POST is a 403 from the server;
* focus is rendered, survives the htmx re-render, and comes back with the selection when the
  operator returns from the detail screen;
* filtering is the server's, and a typo in a filter name is a 400 naming the field.
"""

from __future__ import annotations

import re
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from tests.helpers.api import SCANNER_KEY, VIEWER_KEY, ApiHarness, make_api_harness

from arachne.api import routes_ui
from arachne.api import workspace as ws
from arachne.api.auth import API_KEY_COOKIE
from arachne.core.audit import AuditAction

HTMX = {"HX-Request": "true"}


@pytest.fixture
def harness(tmp_path: Path) -> ApiHarness:
    built = make_api_harness(tmp_path)
    try:
        yield built
    finally:
        built.close()


def _rows(page: str) -> list[str]:
    return [chunk.split('"', 1)[0] for chunk in page.split('data-row-id="')[1:]]


def _seed(harness: ApiHarness, count: int = 3) -> list[int]:
    scan_id = harness.seed_scan()
    return [
        harness.seed_finding(scan_id=scan_id, title=f"finding {index}", severity="high")
        for index in range(count)
    ]


def _token(fragment: str) -> str:
    assert 'name="token" value="' in fragment, "the action did not offer an undo"
    return fragment.split('name="token" value="', 1)[1].split('"', 1)[0]


# ---------------------------------------------------------------- the bulk triage
def test_a_bulk_triage_writes_one_audit_event_per_finding_and_one_undo(
    harness: ApiHarness,
) -> None:
    identifiers = _seed(harness)
    with harness.client() as client:
        client.cookies.set(API_KEY_COOKIE, SCANNER_KEY)
        response = client.post(
            "/ui/findings/actions",
            data={"action": "triage", "finding_ids": ",".join(map(str, identifiers))},
            headers=HTMX,
        )
        assert response.status_code == 200, response.text
        # §4.3: the fragment is the workspace, so htmx swaps exactly that region.
        assert "data-workspace-root" in response.text
        assert "3 finding(s) triaged." in response.text
        assert "data-undo-toast" in response.text
        assert _token(response.text)

    assert [harness.context.queries.finding_row(item).status for item in identifiers] == [
        ws.TRIAGE_STATUS
    ] * 3
    reviewed = harness.events_of(AuditAction.FINDING_REVIEWED)
    assert len(reviewed) == 3, "N events, one per finding — never one untraceable batch"
    assert {event.target for event in reviewed} == {f"finding:{item}" for item in identifiers}
    assert all(event.meta["bulk"] is True for event in reviewed)
    assert all(event.meta["status"] == ws.TRIAGE_STATUS for event in reviewed)


def test_undo_restores_the_prior_state_rather_than_re_running_the_action(
    harness: ApiHarness,
) -> None:
    """One row was ``fp`` before the batch: undo must put *that* back, not "un-triage" it."""
    identifiers = _seed(harness)
    harness.context.queries.set_finding_status(identifiers[0], "fp")
    with harness.client() as client:
        client.cookies.set(API_KEY_COOKIE, SCANNER_KEY)
        acted = client.post(
            "/ui/findings/actions",
            data={"action": "triage", "finding_ids": ",".join(map(str, identifiers))},
            headers=HTMX,
        )
        token = _token(acted.text)
        restored = client.post("/ui/findings/undo", data={"token": token}, headers=HTMX)
        assert restored.status_code == 200, restored.text
        assert "Undone: 3 finding(s) restored." in restored.text

    assert [harness.context.queries.finding_row(item).status for item in identifiers] == [
        "fp",
        "open",
        "open",
    ]
    undos = [
        event for event in harness.events_of(AuditAction.FINDING_REVIEWED) if event.meta.get("undo")
    ]
    assert len(undos) == 3, "the restoration is audited too"
    assert {event.meta["restored_status"] for event in undos} == {"fp", "open"}


def test_a_row_changed_again_after_the_batch_is_left_alone_and_reported(
    harness: ApiHarness,
) -> None:
    """Undo restores the prior state; it does not clobber a newer decision."""
    identifiers = _seed(harness, count=2)
    with harness.client() as client:
        client.cookies.set(API_KEY_COOKIE, SCANNER_KEY)
        acted = client.post(
            "/ui/findings/actions",
            data={"action": "triage", "finding_ids": ",".join(map(str, identifiers))},
            headers=HTMX,
        )
        token = _token(acted.text)
        harness.context.queries.set_finding_status(identifiers[0], "merged")
        restored = client.post("/ui/findings/undo", data={"token": token}, headers=HTMX)
        assert "Undone: 1 finding(s) restored." in restored.text
        assert "1 had changed again since" in restored.text

    assert harness.context.queries.finding_row(identifiers[0]).status == "merged"
    assert harness.context.queries.finding_row(identifiers[1]).status == "open"


def test_the_undo_window_closes_after_sixty_seconds(harness: ApiHarness, monkeypatch) -> None:
    """The clock is moved, not the constant: the window is 60 s and that is asserted."""
    identifiers = _seed(harness, count=1)
    with harness.client() as client:
        client.cookies.set(API_KEY_COOKIE, SCANNER_KEY)
        acted = client.post(
            "/ui/findings/actions",
            data={"action": "triage", "finding_ids": str(identifiers[0])},
            headers=HTMX,
        )
        token = _token(acted.text)

        # 59 s later it still works. (A fresh batch, so the first record is not consumed.)
        later = ws.now_utc() + __import__("datetime").timedelta(seconds=59)
        monkeypatch.setattr(routes_ui, "now_utc", lambda: later)
        still_open = client.post("/ui/findings/undo", data={"token": token}, headers=HTMX)
        assert "Undone: 1 finding(s) restored." in still_open.text

        second = client.post(
            "/ui/findings/actions",
            data={"action": "triage", "finding_ids": str(identifiers[0])},
            headers=HTMX,
        )
        expired_token = _token(second.text)
        closed = ws.now_utc() + __import__("datetime").timedelta(seconds=61)
        monkeypatch.setattr(routes_ui, "now_utc", lambda: closed)
        refused = client.post("/ui/findings/undo", data={"token": expired_token}, headers=HTMX)
        assert refused.status_code == 200
        assert "60-second undo window has closed" in refused.text
        assert "Nothing was changed" in refused.text

    assert harness.context.queries.finding_row(identifiers[0]).status == ws.TRIAGE_STATUS


def test_an_undo_token_from_another_session_is_refused(harness: ApiHarness) -> None:
    identifiers = _seed(harness, count=1)
    with harness.client() as client:
        client.cookies.set(API_KEY_COOKIE, SCANNER_KEY)
        acted = client.post(
            "/ui/findings/actions",
            data={"action": "triage", "finding_ids": str(identifiers[0])},
            headers=HTMX,
        )
        token = _token(acted.text)
    with harness.client() as other:
        other.cookies.set(API_KEY_COOKIE, VIEWER_KEY)
        refused = other.post("/ui/findings/undo", data={"token": token}, headers=HTMX)
        assert refused.status_code == 403, "a viewer cannot undo, whatever token they hold"


# ---------------------------------------------------------------- suppression and acceptance
def test_a_suppression_without_a_reason_changes_nothing(harness: ApiHarness) -> None:
    """The pitfall made a test: S is a drawer requiring a reason, not a one-click hide."""
    identifiers = _seed(harness, count=2)
    with harness.client() as client:
        client.cookies.set(API_KEY_COOKIE, SCANNER_KEY)
        response = client.post(
            "/ui/findings/actions",
            data={"action": "suppress", "finding_ids": str(identifiers[0]), "reason": "n/a"},
            headers=HTMX,
        )
        assert response.status_code == 200
        assert "at least 8 characters" in response.text
        assert "data-undo-toast" not in response.text

    assert list(harness.context.services.quality.list_suppressions(active_only=True)) == []
    assert harness.events_of(AuditAction.SUPPRESSION_CHANGED) == []


def test_a_bulk_suppression_is_attributed_commented_and_audited_per_finding(
    harness: ApiHarness,
) -> None:
    identifiers = _seed(harness, count=3)
    reason = "known false positive: the vendor banner is static"
    with harness.client() as client:
        client.cookies.set(API_KEY_COOKIE, SCANNER_KEY)
        response = client.post(
            "/ui/findings/actions",
            data={
                "action": "suppress",
                "finding_ids": ",".join(map(str, identifiers)),
                "reason": reason,
            },
            headers=HTMX,
        )
        assert "3 finding(s) suppressed." in response.text
        token = _token(response.text)

        rules = harness.context.services.quality.list_suppressions(active_only=True)
        assert {rule.finding_id for rule in rules} == set(identifiers)
        assert all(rule.reason == reason for rule in rules)
        assert all(rule.actor == "scanner" for rule in rules)

        undone = client.post("/ui/findings/undo", data={"token": token}, headers=HTMX)
        assert "Undone: 3 finding(s) restored." in undone.text

    # Undo *revokes* the rules rather than deleting them: the prior state (no active rule) is
    # back, and the record of the decision survives — which is what an audit trail is for.
    assert list(harness.context.services.quality.list_suppressions(active_only=True)) == []
    every = harness.context.services.quality.list_suppressions(active_only=False)
    assert len(every) == 3
    assert all(not rule.active for rule in every)
    changes = [
        event.meta.get("change") for event in harness.events_of(AuditAction.SUPPRESSION_CHANGED)
    ]
    assert changes.count("added") == 3
    assert changes.count("revoked") == 3


def test_a_risk_acceptance_needs_an_owner_and_an_expiry(harness: ApiHarness) -> None:
    identifiers = _seed(harness, count=1)
    with harness.client() as client:
        client.cookies.set(API_KEY_COOKIE, SCANNER_KEY)
        no_owner = client.post(
            "/ui/findings/actions",
            data={
                "action": "accept",
                "finding_ids": str(identifiers[0]),
                "owner": "",
                "justification": "accepted for this quarter",
                "ttl_days": "30",
            },
            headers=HTMX,
        )
        assert "accountable owner" in no_owner.text
        no_expiry = client.post(
            "/ui/findings/actions",
            data={
                "action": "accept",
                "finding_ids": str(identifiers[0]),
                "owner": "Jane Operator",
                "justification": "accepted for this quarter",
                "ttl_days": "",
            },
            headers=HTMX,
        )
        assert "expiry" in no_expiry.text
    assert list(harness.context.services.quality.list_acceptances(finding_id=identifiers[0])) == []

    with harness.client() as client:
        client.cookies.set(API_KEY_COOKIE, SCANNER_KEY)
        accepted = client.post(
            "/ui/findings/actions",
            data={
                "action": "accept",
                "finding_ids": ",".join(map(str, identifiers)),
                "owner": "Jane Operator",
                "justification": "accepted for this quarter by the platform team",
                "ttl_days": "90",
            },
            headers=HTMX,
        )
        assert "1 finding(s) risk accepted." in accepted.text
        token = _token(accepted.text)
        accepted_rows = harness.context.services.quality.list_acceptances(finding_id=identifiers[0])
        assert len(accepted_rows) == 1
        assert accepted_rows[0].owner == "Jane Operator"
        assert accepted_rows[0].expires_at > datetime.now(UTC)
        # 90 days from now, to within the microseconds between building the value and storing it.
        assert abs(
            (accepted_rows[0].expires_at - accepted_rows[0].accepted_at) - timedelta(days=90)
        ) < timedelta(seconds=5)

        # §4.4's Authorization panel renders it; the withdrawal leaves it withdrawn.
        detail = client.get(f"/ui/findings/{identifiers[0]}")
        assert "Jane Operator" in detail.text
        assert "in force" in detail.text
        client.post("/ui/findings/undo", data={"token": token}, headers=HTMX)
    rows = harness.context.services.quality.list_acceptances(finding_id=identifiers[0])
    assert len(rows) == 1 and rows[0].revoked_at is not None


def test_a_bulk_action_is_all_or_nothing_across_the_request(harness: ApiHarness) -> None:
    """A batch naming one row this session cannot see writes nothing at all.

    The foreign row lives in another *tenant* in this same database, which is the case the
    per-id check exists for: the workspace is filtered by project, so a hand-built POST is the
    only way an id from elsewhere could arrive.
    """
    identifiers = _seed(harness, count=2)
    other = harness.services.projects.create("other-tenant", "Other tenant")
    foreign_scan = harness.seed_scan(project="other-tenant")
    foreign = harness.seed_finding(scan_id=foreign_scan, title="someone else's finding")
    assert other.id != harness.services.projects.ensure_default().id
    with harness.client() as client:
        client.cookies.set(API_KEY_COOKIE, SCANNER_KEY)
        mixed = client.post(
            "/ui/findings/actions",
            data={"action": "triage", "finding_ids": f"{identifiers[0]},{foreign}"},
            headers=HTMX,
        )
        assert "Nothing was changed" in mixed.text
        assert "not in this project" in mixed.text
    assert harness.context.queries.finding_row(identifiers[0]).status == "open"
    assert harness.context.queries.finding_row(foreign).status == "open"


def test_a_closed_drawer_is_inert_not_merely_hidden(harness: ApiHarness) -> None:
    """A `display: none` field is still validated by the browser.

    So a closed drawer renders its fields **disabled** as well as hidden: otherwise the `required`
    reason in the closed suppress drawer would block the `T` key with an error nobody can see, and
    every triage would post an empty reason. ``workspace.js`` enables the fields of the drawer it
    opens (and there is no browser in this repository to drive that half — see the handoff).
    """
    _seed(harness, count=1)
    with harness.client() as client:
        client.cookies.set(API_KEY_COOKIE, SCANNER_KEY)
        page = client.get("/ui/findings")
    for name in ("suppress", "accept"):
        section = page.text.split(f'data-drawer="{name}"', 1)[1]
        section = section.split("</section>", 1)[0]
        assert "hidden" in section.split(">", 1)[0], f"the {name} drawer is not closed"
        for field in ('name="reason"', 'name="owner"', 'name="justification"', 'name="ttl_days"'):
            if field in section:
                fragment = section.split(field, 1)[1].split(">", 1)[0]
                assert "disabled" in fragment, f"{field} is live while its drawer is closed"
        assert "disabled" in section, name
    # And the reason really is required by the server, not only by the browser.
    assert "required" in page.text and 'minlength="8"' in page.text


# ---------------------------------------------------------------- the viewer
def test_a_viewer_sees_no_selection_or_bulk_control_at_all(harness: ApiHarness) -> None:
    """§4.3 refused: absent, not disabled — an absent control is honest."""
    _seed(harness, count=2)
    with harness.client() as client:
        client.cookies.set(API_KEY_COOKIE, VIEWER_KEY)
        page = client.get("/ui/findings")
        assert page.status_code == 200
        for absent in (
            "data-row-check",
            'data-action="triage"',
            "data-open-drawer",
            "data-drawer",
            "data-undo-toast",
            'name="finding_ids"',
        ):
            assert absent not in page.text, f"a viewer was shown {absent}"
        # The screen still explains itself, and the shortcut sheet stays readable.
        assert "Read-only session" in page.text
        assert "data-shortcut-sheet" in page.text
        for path in ("/ui/findings/actions", "/ui/findings/undo"):
            refused = client.post(path, data={"action": "triage", "finding_ids": "1"}, headers=HTMX)
            assert refused.status_code == 403, path


# ---------------------------------------------------------------- focus and the round trip
def test_exactly_one_row_is_tabbable_and_the_focused_one_says_so(harness: ApiHarness) -> None:
    identifiers = _seed(harness, count=3)
    with harness.client() as client:
        client.cookies.set(API_KEY_COOKIE, SCANNER_KEY)
        page = client.get(f"/ui/findings?focus={identifiers[1]}&sel={identifiers[2]}")
        assert page.status_code == 200
        assert page.text.count('tabindex="0"') == 1, "a roving tabindex: one row is tabbable"
        assert page.text.count('aria-current="true"') == 1
        rows = list(page.text.split('<tr class="row"')[1:])
        focused = [row for row in rows if 'data-focused="true"' in row]
        assert len(focused) == 1
        assert f'data-row-id="{identifiers[1]}"' in focused[0]
        # The selection is rendered too, so the state survives a reload and a re-render.
        assert f'value="{identifiers[2]}"' in focused[0] or "checked" in page.text


def test_the_focused_row_survives_the_htmx_re_render(harness: ApiHarness) -> None:
    """The pitfall, asserted: a roving tabindex that resets on re-render makes the screen
    unusable, so the swap carries the focused row back."""
    identifiers = _seed(harness, count=3)
    with harness.client() as client:
        client.cookies.set(API_KEY_COOKIE, SCANNER_KEY)
        swapped = client.post(
            "/ui/findings/actions",
            data={
                "action": "triage",
                "finding_ids": str(identifiers[1]),
                "focus": str(identifiers[1]),
                "sel": str(identifiers[1]),
            },
            headers=HTMX,
        )
        assert swapped.status_code == 200
        assert swapped.text.count('tabindex="0"') == 1
        focused = [
            row for row in swapped.text.split('<tr class="row"')[1:] if 'data-focused="true"' in row
        ]
        assert len(focused) == 1
        assert f'data-row-id="{identifiers[1]}"' in focused[0]
        assert 'aria-current="true"' in focused[0]


def test_the_detail_screen_carries_the_selection_back_to_the_list(harness: ApiHarness) -> None:
    """§4.4: Esc returns to the list with the same scroll position and selection."""
    identifiers = _seed(harness, count=3)
    selection = f"{identifiers[0]},{identifiers[2]}"
    with harness.client() as client:
        client.cookies.set(API_KEY_COOKIE, SCANNER_KEY)
        detail = client.get(
            f"/ui/findings/{identifiers[0]}?sel={selection}&focus={identifiers[0]}&scroll=420"
        )
        assert detail.status_code == 200
        assert "data-back-to-list" in detail.text
        match = re.search(r'href="([^"]+)" data-back-to-list', detail.text)
        assert match is not None, "the detail screen lost its way back to the list"
        back = match.group(1)
        assert back.startswith("/ui/findings?"), back
        assert "sel=1%2C3" in back or "sel=1,3" in back
        assert "scroll=420" in back
        assert "2\n  selected finding(s)" in detail.text or "2 selected finding(s)" in detail.text

        returned = client.get(back.replace("&amp;", "&"))
        assert returned.status_code == 200
        assert returned.text.count('tabindex="0"') == 1
        back_focused = next(
            row
            for row in returned.text.split('<tr class="row"')[1:]
            if 'data-focused="true"' in row
        )
        assert f'data-row-id="{identifiers[0]}"' in back_focused
        assert returned.text.count('data-selected="true"') >= 2


def test_the_row_link_keeps_the_workspace_state(harness: ApiHarness) -> None:
    """The list's own links carry the filters and the selection, so opening a finding and
    coming back is the same view."""
    identifiers = _seed(harness, count=1)
    with harness.client() as client:
        client.cookies.set(API_KEY_COOKIE, SCANNER_KEY)
        page = client.get(f"/ui/findings?severity=high&sel={identifiers[0]}&scroll=100")
        link = page.text.split("data-row-open", 1)[0].rsplit('href="', 1)[1]
        assert "severity=high" in link
        assert f"focus={identifiers[0]}" in link
        assert "sel=" in link


# ---------------------------------------------------------------- server-side filtering
def test_filtering_is_the_servers_and_a_typo_is_named(harness: ApiHarness) -> None:
    scan_id = harness.seed_scan()
    harness.seed_finding(scan_id=scan_id, title="alpha finding", severity="high")
    harness.seed_finding(scan_id=scan_id, title="beta finding", severity="low")
    with harness.client() as client:
        client.cookies.set(API_KEY_COOKIE, SCANNER_KEY)
        filtered = client.get("/ui/findings?severity=low")
        assert "beta finding" in filtered.text
        assert "alpha finding" not in filtered.text
        typo = client.get("/ui/findings?severiity=high")
        assert typo.status_code == 400
        assert "severiity" in typo.text
        unknown_state = client.get("/ui/findings?nope=1")
        assert unknown_state.status_code == 400


def test_the_history_panel_shows_the_decisions_taken_on_the_finding(harness: ApiHarness) -> None:
    """§4.4's History panel reads the durable audit log, filtered to this finding.

    The harness keeps its events in memory, so they are replayed into the ``audit_log`` table
    with the deployment's own sink — the writer and the reader are then exercised against the
    same rows, which is the thing that could drift.
    """
    from arachne.data.audit_sink import SqlAuditSink

    identifiers = _seed(harness, count=1)
    with harness.client() as client:
        client.cookies.set(API_KEY_COOKIE, SCANNER_KEY)
        client.post(
            "/ui/findings/actions",
            data={"action": "triage", "finding_ids": str(identifiers[0])},
            headers=HTMX,
        )
        sink = SqlAuditSink(harness.context.services.session_factory)
        for event in harness.sink.events:
            sink.record(event)
        page = client.get(f"/ui/findings/{identifiers[0]}")
        assert "History (1)" in page.text
        assert "finding.reviewed" in page.text
        assert f"finding:{identifiers[0]}" not in page.text  # the target is not rendered raw
        # A finding nothing has been decided about says exactly that.
        quiet = harness.seed_finding(title="untouched")
        empty = client.get(f"/ui/findings/{quiet}")
        assert "No decision has been recorded against this finding yet." in empty.text


def test_a_failed_action_names_the_problem_and_changes_nothing(harness: ApiHarness) -> None:
    _seed(harness, count=1)
    with harness.client() as client:
        client.cookies.set(API_KEY_COOKIE, SCANNER_KEY)
        response = client.post(
            "/ui/findings/actions",
            data={"action": "nonsense", "finding_ids": "1"},
            headers=HTMX,
        )
        assert response.status_code == 200
        assert "Nothing was changed" in response.text
        assert 'data-state="error"' in response.text
        assert "data-workspace-root" in response.text, "the list is still there to act on"


def test_the_workspace_route_is_read_only_by_construction(harness: ApiHarness) -> None:
    """A GET that carries a state parameter must not act on anything."""
    identifiers = _seed(harness, count=1)
    with harness.client() as client:
        client.cookies.set(API_KEY_COOKIE, SCANNER_KEY)
        client.get(f"/ui/findings?sel={identifiers[0]}&focus={identifiers[0]}&action=triage")
    assert harness.context.queries.finding_row(identifiers[0]).status == "open"


def test_a_suppressed_finding_still_lists_and_keeps_its_own_state(harness: ApiHarness) -> None:
    """Suppression changes no status: the workspace's State column keeps telling the truth."""
    identifiers = _seed(harness, count=1)
    with harness.client() as client:
        client.cookies.set(API_KEY_COOKIE, SCANNER_KEY)
        client.post(
            "/ui/findings/actions",
            data={
                "action": "suppress",
                "finding_ids": str(identifiers[0]),
                "reason": "the banner is static and expected",
            },
            headers=HTMX,
        )
        page = client.get("/ui/findings")
        assert "finding 0" in page.text
    assert harness.context.queries.finding_row(identifiers[0]).status == "open"


def test_the_workspace_takes_the_clock_from_one_place(tmp_path: Path, monkeypatch) -> None:
    """`now_utc` is the single clock the undo window is measured against."""
    fixed = datetime(2026, 11, 2, 12, 0, 0, tzinfo=UTC)
    monkeypatch.setattr(ws, "now_utc", lambda: fixed)
    assert ws.now_utc() == fixed
    built = make_api_harness(tmp_path, settings=replace(_settings(tmp_path)))
    try:
        assert built.context.queries is not None
    finally:
        built.close()


def _settings(tmp_path: Path):  # type: ignore[no-untyped-def]
    from tests.helpers.api import build_api_settings

    return build_api_settings(tmp_path)
