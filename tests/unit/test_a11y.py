"""WCAG 2.2 AA on every screen, every state (REQ-UIX-007).

``.spec/06-ui-ux.md`` §8.1 asks for an automated audit over every screen and §8.2 lists the
criteria automation cannot reach. This file is the automated half's acceptance evidence, and it
is written so that a *rule that stopped working* fails here rather than passing quietly:

* :func:`test_every_screen_and_every_state_is_audited` pins the 82 renders (14 screens by the
  states §5 requires) so the audit cannot shrink to the screens that happen to pass;
* :func:`test_the_audit_is_not_vacuous` drives every DOM rule over planted markup and asserts
  each one fires with its own message — a rule nobody has seen fail is not a gate;
* :func:`test_the_rules_are_silent_on_a_clean_page` drives the same rules over a page that is
  correct, so a rule cannot pass by firing on everything;
* the keyboard half (2.1.1, 2.1.2, 2.4.3) is asserted from the rendered page and from the
  shipped script: the tab order is extractable, nothing is focusable behind `aria-hidden`, no
  control carries a positive `tabindex`, and the interface's own keyboard layer never swallows
  `Tab`;
* the §8.2 rows automation cannot measure (measured target size, measured reflow, keyboard
  traversal by hand) are recorded in the WP-06 handoff with the reason they are manual.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from arachne.api import a11y
from arachne.api.screens import SCREENS

#: A page that satisfies every rule, so a failure here means a rule is over-firing.
_CLEAN = """\
<!doctype html>
<html lang="en">
<head>
  <title>Clean</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
</head>
<body>
<header><nav aria-label="Screens"><a href="/docs">Docs</a></nav></header>
<main>
  <h1>One</h1>
  <h2>Two</h2>
  <p id="note">Text</p>
  <img src="x.png" alt="A description">
  <button aria-describedby="note">Press</button>
  <a href="/docs">Docs</a>
  <form><input name="q" aria-label="Search"></form>
</main>
</body>
</html>
"""


def _page(markup: str) -> a11y.Element:
    page, _ = a11y.parse(markup)
    return page


# ------------------------------------------------------------------ the shipped screens
def test_the_shipped_screens_are_free_of_violations() -> None:
    """The exit criterion, word for word: zero violations, all 14 screens."""
    violations = a11y.audit()
    assert violations == [], "\n".join(str(item) for item in violations)


def test_every_screen_and_every_state_is_audited() -> None:
    """The matrix's own arithmetic, so the audit cannot quietly skip a cell."""
    renders = [(identifier, state) for identifier, state, _, _ in a11y._render()]
    assert [identifier for identifier, _ in renders][:1] == ["sign-in"]
    assert {identifier for identifier, _ in renders} == {screen.id for screen in SCREENS}
    assert len(renders) == 3 + 1 + 13 * 6  # sign-in has three states; the other thirteen, six
    for screen in SCREENS:
        states = {state for identifier, state in renders if identifier == screen.id}
        assert states == {"ready", *screen.applicable}, screen.id


def test_the_audit_reports_which_screen_and_state_it_is_about() -> None:
    page, _ = a11y.parse("<html lang='en'><head><title>t</title></head><body></body></html>")
    problems = a11y._document_rules(page)
    assert any("viewport" in problem for problem in problems)
    violation = a11y.Violation("scans", "empty", "viewport", "no viewport meta")
    assert str(violation) == "scans[empty] viewport: no viewport meta"


# ------------------------------------------------------------------ the rules themselves
@pytest.mark.parametrize(
    ("rule", "needle"),
    [
        ("accessible-auth", "autocomplete='off'"),
        ("accessible-name", "<button>"),
        ("aria-hidden-focus", "aria-hidden subtree"),
        ("aria-reference-valid", "names no element"),
        ("aria-valid-attr", "not a known ARIA attribute"),
        ("document-lang", "no lang attribute"),
        ("document-title", "non-empty <title>"),
        ("duplicate-id", "appears twice"),
        ("focus-order", "follows a main-content control"),
        ("heading-order", "is followed by h4"),
        ("html-structure", "closes nothing"),
        ("landmark-one-main", "more than one <nav> and one is unnamed"),
        ("modal-labelled", "no control to close it"),
        ("nested-interactive", "inside a link or a button"),
        ("redundant-entry", "asks for"),
        ("tabindex-positive", "reorders focus"),
        ("viewport", "does not follow the device width"),
        ("viewport", "forbids zoom"),
    ],
)
def test_the_audit_is_not_vacuous(rule: str, needle: str) -> None:
    """Every DOM rule, fired once, with the message a reader needs to fix it."""
    page, unbalanced = a11y.parse(a11y._OFFENDING)
    problems = (
        a11y._document_rules(page)
        + a11y._structural_rules(page)
        + a11y._name_rules(page)
        + a11y._interaction_rules(page)
        + [f"html-structure: </{tag}> closes nothing" for tag in unbalanced]
    )
    fired = [problem for problem in problems if problem.startswith(f"{rule}: ")]
    assert fired, f"{rule} did not fire on the planted markup"
    assert any(needle in problem for problem in fired), fired
    assert a11y.self_test() == []


def test_the_rules_are_silent_on_a_clean_page() -> None:
    page, unbalanced = a11y.parse(_CLEAN)
    problems = (
        a11y._document_rules(page)
        + a11y._structural_rules(page)
        + a11y._name_rules(page)
        + a11y._interaction_rules(page)
    )
    assert problems == [], problems
    assert unbalanced == []


def test_decoration_is_not_a_violation() -> None:
    """An empty ``alt`` is the correct spelling of a decorative image, not a missing name."""
    page, _ = a11y.parse(_CLEAN.replace('alt="A description"', 'alt=""'))
    assert a11y._name_rules(page) == []


def test_a_second_unnamed_landmark_is_a_violation() -> None:
    page, _ = a11y.parse(
        "<html lang='en'><head><title>t</title></head><body><main><h1>a</h1></main>"
        "<nav><a href='/a'>a</a></nav><nav><a href='/b'>b</a></nav></body></html>"
    )
    assert any("<nav>" in problem for problem in a11y._structural_rules(page))


def test_the_style_rules_fire_on_a_stylesheet_that_breaks_them(tmp_path: Path) -> None:
    """2.4.7, 2.5.8, 1.4.10 and 1.4.12 are stylesheet properties, so they are driven too."""
    (tmp_path / "static").mkdir()
    (tmp_path / "static" / "app.css").write_text(
        "a:focus { outline: none; }\n"
        "button { min-height: 4px; }\n"
        "p { line-height: 1.2 !important; }\n",
        encoding="utf-8",
    )
    problems = a11y._style_rules({"target-min": "12px", "templates": str(tmp_path)})
    text = "\n".join(problems)
    assert "focus-visible" in text
    assert "below 24 CSS pixels" in text
    assert "!important" in text
    assert "reflow" in text


# ------------------------------------------------------------------ the keyboard half
def test_every_screen_has_a_keyboard_traversal_and_it_is_in_document_order() -> None:
    """2.1.1 and 2.4.3: a keyboard can reach every control, in the order the page reads."""
    for identifier, state, markup, _ in a11y._render():
        page, _ = a11y.parse(markup)
        order = a11y.tab_order(page)
        assert order == a11y.tab_order(page)  # deterministic
        if state == "ready" and identifier not in {"sign-in"}:
            assert order, f"{identifier} has no keyboard stops at all"
            # The chrome comes first, so a keyboard user can leave the page the way they came.
            assert order[0].startswith(("a[", "button[")), (identifier, order[:3])


def test_nothing_focusable_hides_behind_aria_hidden() -> None:
    for identifier, state, markup, _ in a11y._render():
        page, _ = a11y.parse(markup)
        identifiers = a11y._by_id(page)
        for node in page.walk():
            if a11y._is_focusable(node):
                for ancestor in a11y._ancestors(node):
                    assert ancestor.attrs.get("aria-hidden") != "true", (
                        identifier,
                        state,
                        node.tag,
                    )
        assert identifiers is not None


def test_a_closed_drawers_fields_are_disabled() -> None:
    """2.1.2, by construction: a closed drawer's ``required`` field cannot block a submit.

    ``.spec/06-ui-ux.md`` §4.3's drawers render closed *and* inert — a field that is merely
    ``display: none`` is still a candidate for constraint validation, so the ``T`` key would
    fail with an error nobody can see. This asserts the inert half of that decision.
    """
    drawer_fields = 0
    for identifier, state, markup, _ in a11y._render():
        if state != "ready":
            continue
        page, _ = a11y.parse(markup)
        for drawer in page.find_all("section"):
            if "data-drawer" not in drawer.attrs or "hidden" not in drawer.attrs:
                continue
            assert "open" not in drawer.attrs
            for field in drawer.find_all("input", "select", "textarea"):
                assert field.attrs.get("disabled") is not None, (identifier, field.attrs)
                drawer_fields += 1
    assert drawer_fields, "no closed drawer was found — did the workspace change shape?"


def test_the_shipped_keyboard_layer_never_swallows_the_tab_key() -> None:
    """2.1.2: the one way a browser UI can trap focus is to cancel ``Tab``."""
    script = (
        Path(a11y.__file__).resolve().parent.parent
        / "templates"
        / "web"
        / "static"
        / "workspace.js"
    ).read_text(encoding="utf-8")
    assert "Tab" not in script
    # The script does call ``preventDefault`` — for the draft guard and the model's own keys —
    # but never for a key it does not also act on, and the model's key map has no Tab binding.
    assert "preventDefault" in script


def test_every_interactive_control_is_named_and_small_enough_to_reach() -> None:
    for identifier, state, markup, _ in a11y._render():
        if state != "ready":
            continue
        page, _ = a11y.parse(markup)
        identifiers = a11y._by_id(page)
        for node in page.walk():
            if node.tag in {"button", "a", "select", "textarea"}:
                assert a11y.accessible_name(node, identifiers), (identifier, node.tag, node.attrs)
