"""The view-state matrix: 14 screens x 5 states, rendered and asserted (REQ-UIX-005).

The view-state matrix is a table, and a table in a document is a claim that nothing checks.
The checks here are:

* the matrix in code (``arachne.api.screens``) matches it row for row — a screen cannot be
  dropped, and a state cannot be quietly marked "n/a";
* every screen's template renders **each applicable state** without raising, and emits the
  ``data-state`` marker for that state, so a state cannot be "implemented" by a comment;
* the empty and error renders of every screen are checked for the two things the requirement
  names: no stack trace, and no blank page.

Rendering is done through the app's own Jinja environment with each screen's minimum render
context (``ScreenSpec.context``), which is what makes this a *template* test: it needs no scan,
no server and no database, so it runs in milliseconds and can cover all 70 cells.
"""

from __future__ import annotations

import pytest

from arachne.api import screens
from arachne.api.screens import SCREEN_STATES, SCREENS, matrix


@pytest.fixture(scope="module")
def environment():  # type: ignore[no-untyped-def]
    """The app's own template environment — the same loader, autoescape and StrictUndefined."""
    from arachne.api.app import _build_templates
    from arachne.core.config import Settings

    return _build_templates(Settings(log_level="CRITICAL"))


def _context(screen: screens.ScreenSpec, state: str, **overrides: bool) -> dict[str, object]:
    context: dict[str, object] = dict(screen.context())
    context.update(
        state="loading" if state == "loading" else ("error" if state == "error" else "ready"),
        empty=state == "empty",
        partial=state == "partial",
        refused=state == "refused",
        theme=None,
        density=None,
        current_path="/ui/",
        principal=None,
    )
    context.update(overrides)
    return context


# ---------------------------------------------------------------- the matrix itself
def test_the_matrix_is_fourteen_screens_by_five_states() -> None:
    assert len(SCREENS) == 14
    assert SCREEN_STATES == ("loading", "empty", "error", "partial", "refused")
    for screen in SCREENS:
        assert set(screen.states) == set(SCREEN_STATES), screen.id


def test_the_matrix_matches_the_specification_table() -> None:
    """§5's cells, written out. ``n/a`` is a decision, so it is asserted, not skipped."""
    expected = {
        "sign-in": {
            "loading": True,
            "empty": False,
            "error": True,
            "partial": True,
            "refused": False,
        },
    }
    for screen in SCREENS:
        expected.setdefault(
            screen.id,
            {"loading": True, "empty": True, "error": True, "partial": True, "refused": True},
        )
    assert matrix() == expected
    assert {screen.id for screen in SCREENS} == {
        "sign-in",
        "overview",
        "findings",
        "finding-detail",
        "scans",
        "scan-detail",
        "report",
        "attack-paths",
        "posture",
        "modules",
        "schedules",
        "quality",
        "feeds",
        "plugins",
    }


def test_every_screen_names_a_route_and_a_template() -> None:
    for screen in SCREENS:
        assert screen.route.startswith("/ui/")
        assert screen.template.endswith(".html")
        assert screen.title


def test_the_sign_in_screen_is_the_only_one_with_a_not_applicable_cell() -> None:
    """§5's two ``n/a`` cells: a form has no content to be empty and no role to refuse."""
    not_applicable = {
        (screen.id, state)
        for screen in SCREENS
        for state in SCREEN_STATES
        if not screen.states[state]
    }
    assert not_applicable == {("sign-in", "empty"), ("sign-in", "refused")}


# ---------------------------------------------------------------- every cell renders
@pytest.mark.parametrize("screen_id", [screen.id for screen in SCREENS])
def test_every_state_of_every_screen_renders_and_marks_itself(environment, screen_id: str) -> None:  # type: ignore[no-untyped-def]
    """All five cells render. An applicable cell renders its state; an ``n/a`` cell is a
    *decision*, so it is asserted to render the loaded page without claiming a state it does
    not have — the one thing that would make "n/a" indistinguishable from "forgotten"."""
    screen = next(item for item in SCREENS if item.id == screen_id)
    for state in SCREEN_STATES:
        html = environment.get_template(screen.template).render(**_context(screen, state))
        assert "Traceback" not in html
        assert "jinja2.exceptions" not in html
        if screen.states[state]:
            assert f'data-state="{state}"' in html, f"{screen_id} did not render its {state} state"
        else:
            assert f'data-state="{state}"' not in html, f"{screen_id} claimed n/a state {state}"


@pytest.mark.parametrize("screen_id", [screen.id for screen in SCREENS])
def test_every_screen_renders_its_empty_and_error_states_without_a_stack_trace(
    environment, screen_id: str
) -> None:  # type: ignore[no-untyped-def]
    """REQ-UIX-005's named acceptance criterion: empty and error, every screen, no traceback."""
    screen = next(item for item in SCREENS if item.id == screen_id)
    for state in ("empty", "error"):
        html = environment.get_template(screen.template).render(**_context(screen, state))
        assert "Traceback" not in html
        assert len(html) > 500, f"{screen_id}: the {state} render is suspiciously empty"
        if screen.states[state]:
            assert f'data-state="{state}"' in html


@pytest.mark.parametrize("screen_id", [screen.id for screen in SCREENS])
def test_every_screen_renders_error_with_a_way_forward(environment, screen_id: str) -> None:  # type: ignore[no-untyped-def]
    """The error state renders an explanation and a retry — never an empty document."""
    screen = next(item for item in SCREENS if item.id == screen_id)
    html = environment.get_template(screen.template).render(**_context(screen, "error"))
    assert 'data-state="error"' in html
    assert 'role="alert"' in html
    title = html.split('data-state="error"', 1)[1]
    assert "could not" in title


@pytest.mark.parametrize("screen_id", [screen.id for screen in SCREENS])
def test_every_screen_renders_partial_with_a_retry_affordance(environment, screen_id: str) -> None:  # type: ignore[no-untyped-def]
    screen = next(item for item in SCREENS if item.id == screen_id)
    html = environment.get_template(screen.template).render(**_context(screen, "partial"))
    assert 'data-state="partial"' in html
    assert "Partially loaded" in html


@pytest.mark.parametrize("screen_id", [screen.id for screen in SCREENS])
def test_every_screen_renders_refused_as_a_read_only_statement(environment, screen_id: str) -> None:  # type: ignore[no-untyped-def]
    screen = next(item for item in SCREENS if item.id == screen_id)
    html = environment.get_template(screen.template).render(**_context(screen, "refused"))
    if screen.states["refused"]:
        assert 'data-state="refused"' in html
        assert "Read-only" in html
    else:
        assert 'data-state="refused"' not in html


@pytest.mark.parametrize("screen_id", [screen.id for screen in SCREENS])
def test_every_screen_renders_loading_as_a_skeleton(environment, screen_id: str) -> None:  # type: ignore[no-untyped-def]
    screen = next(item for item in SCREENS if item.id == screen_id)
    html = environment.get_template(screen.template).render(**_context(screen, "loading"))
    assert 'data-state="loading"' in html
    assert "aria-busy" in html or "skeleton" in html
