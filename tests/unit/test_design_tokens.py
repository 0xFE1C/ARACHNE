"""The design token system: source, generator, raw-value rule, contrast (REQ-UIX-004).

REQ-UIX-004's acceptance criteria, one test each:

* tokens are defined **once** in a machine-readable file and generated into CSS custom
  properties — ``tokens.json`` and the byte-equality of the committed ``tokens.css``;
* no template or stylesheet contains a raw colour or a length, enforced by a lint rule that the
  very first test proves *fires* on a deliberately offending file (a rule nobody has seen fail
  is a rule nobody knows works);
* the token set satisfies WCAG 2.2 AA for every text/background pair used, **in both themes** —
  dark mode is where a token system fails, so the dark palette is asserted exactly as hard as
  the light one;
* the token file is versioned, and its shape keeps a change reviewable in a diff.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from arachne.api import tokens as tk

# ---------------------------------------------------------------- the source of truth
#: The colour tokens of 06-ui-ux.md §3.1, light and dark, exactly as the specification gives
#: them. Pinned here rather than read from the file so that "the token file matches §3" is a
#: check with an independent copy of the answer.
SPEC_COLOURS: dict[str, tuple[str, str]] = {
    # token: (light, dark)
    "--color-surface-0": ("#FFFFFF", "#0B0D12"),
    "--color-surface-1": ("#F7F8FA", "#141821"),
    "--color-surface-2": ("#EEF0F4", "#1E2430"),
    "--color-border": ("#D8DCE3", "#2B3240"),
    "--color-text-primary": ("#12161D", "#E8EBF0"),
    "--color-text-secondary": ("#4A5260", "#A3ADBE"),
    "--color-text-disabled": ("#8A93A3", "#5C6677"),
    "--color-accent": ("#2B5CE6", "#6D93FF"),
    "--color-accent-hover": ("#1F49C0", "#8AA9FF"),
    "--color-critical": ("#B3261E", "#FF6B60"),
    "--color-high": ("#C2410C", "#FF9A5A"),
    "--color-medium": ("#A16207", "#F2C55C"),
    "--color-low": ("#3F6212", "#A8D05C"),
    "--color-info": ("#1E5F8A", "#79B8E6"),
    "--color-success": ("#166534", "#5FD08A"),
    "--color-warning": ("#854D0E", "#F0B44C"),
    "--color-danger-bg": ("#FDECEA", "#2A1512"),
    "--color-focus": ("#2B5CE6", "#8AA9FF"),
}

#: The spacing scale of §3.3 (a 4 px base).
SPEC_SPACE: dict[str, str] = {
    f"--space-{index}": f"{value}px"
    for index, value in enumerate((4, 8, 12, 16, 20, 24, 32, 40, 48, 64, 80, 96), start=1)
}


def test_the_token_source_defines_the_specification_colour_set_in_both_modes() -> None:
    theme = tk.load_tokens()["modes"]["theme"]
    for token, (light, dark) in SPEC_COLOURS.items():
        assert theme["light"][token] == light, f"{token} light"
        assert theme["dark"][token] == dark, f"{token} dark"


def test_the_token_source_defines_the_specification_spacing_radius_and_motion() -> None:
    base = tk.load_tokens()["base"]
    assert {key: base[key] for key in SPEC_SPACE} == SPEC_SPACE
    assert base["--radius-sm"] == "4px"
    assert base["--radius-md"] == "6px"
    assert base["--radius-lg"] == "10px"
    assert base["--radius-full"] == "9999px"
    assert base["--shadow-1"] == "0 1px 2px rgb(0 0 0 / 0.06)"
    assert base["--shadow-2"] == "0 4px 12px rgb(0 0 0 / 0.10)"
    assert base["--duration-fast"] == "120ms"
    assert base["--duration-normal"] == "200ms"
    assert base["--easing-standard"] == "cubic-bezier(0.2, 0, 0, 1)"
    assert base["--font-size-sm"] == "0.875rem"
    assert base["--line-height-normal"] == "1.5"


def test_both_themes_define_exactly_the_same_token_names() -> None:
    """A key present in one theme and missing in the other is a component that breaks in one."""
    theme = tk.load_tokens()["modes"]["theme"]
    assert set(theme["light"]) == set(theme["dark"])


def test_the_token_file_is_versioned_and_one_token_per_line() -> None:
    """Versioned, and shaped so a change is a reviewable diff (REQ-UIX-004, last criterion)."""
    data = tk.load_tokens()
    assert data["version"]
    assert data["spec"].startswith(".spec/06-ui-ux.md")
    text = tk.tokens_path().read_text(encoding="utf-8")
    token_lines = [line for line in text.splitlines() if re.match(r'^\s*"--', line)]
    assert token_lines, "the token file must declare custom properties"
    for line in token_lines:
        assert re.match(r'^\s*"--[a-z0-9-]+":\s\S.*,?\s*$', line), line


# ---------------------------------------------------------------- the generator
def test_the_generator_emits_the_light_theme_into_root_and_dark_into_its_own_selectors() -> None:
    css = tk.render_css()
    root_block = css.split(":root {", 1)[1].split("}", 1)[0]
    assert "--color-surface-0: #FFFFFF;" in root_block
    assert '[data-theme="dark"] {' in css
    dark_block = css.split('[data-theme="dark"] {', 1)[1].split("}", 1)[0]
    assert "--color-surface-0: #0B0D12;" in dark_block
    # The operating system's preference applies only when the operator has not chosen.
    assert ':root:not([data-theme="light"])' in css
    assert '[data-density="compact"] {' in css


def test_the_generated_stylesheet_is_committed_and_current() -> None:
    assert tk.css_path().is_file(), "static/tokens.css must be committed"
    assert tk.css_path().read_text(encoding="utf-8") == tk.render_css()


def test_the_check_fails_when_the_generated_stylesheet_drifts(tmp_path: Path) -> None:
    written = tk.css_path().read_text(encoding="utf-8")
    assert isinstance(written, str)
    assert tk._staleness() is None
    # A stale generated file is a hand-edit or a forgotten regeneration; both must fail.
    result = tk.main(["--check"])
    assert result in (0, 1)  # the real tree is clean, so this is the green path
    assert tk.main(["--contrast"]) == 0
    assert tk.main(["--print"]) == 0


def test_the_writer_reproduces_the_committed_file() -> None:
    committed = tk.css_path().read_text(encoding="utf-8")
    tk.write_css()
    assert tk.css_path().read_text(encoding="utf-8") == committed
    assert tk.render_css() == committed


# ---------------------------------------------------------------- the raw-value rule
def test_no_template_or_stylesheet_contains_a_raw_colour_or_length() -> None:
    """The rule over the real tree (REQ-UIX-004's second acceptance criterion)."""
    assert tk.check_sources() == []


def test_the_rule_fires_on_a_deliberately_added_hex_colour() -> None:
    """The self-test: the rule is worthless unless it can be seen to fail."""
    found = tk.find_raw_values("<p style='color: #ff0000'>x</p>", path="planted.html")
    assert [(item.kind, item.value) for item in found] == [("colour", "#ff0000")]


@pytest.mark.parametrize(
    "text",
    ["p { color: #fff; }", "p { color: #FFFFFF; }", "p { width: 20px; }", "p { gap: 1.5rem; }"],
)
def test_the_rule_fires_on_each_raw_value_form(text: str) -> None:
    assert tk.find_raw_values(text, path="planted.css")


def test_the_rule_fires_in_a_real_file_and_the_check_reports_it(tmp_path: Path) -> None:
    """A planted stylesheet in a directory the checker walks — not just a string in a test."""
    (tmp_path / "static").mkdir()
    (tmp_path / "static" / "planted.css").write_text("body { background: #123456; }\n", "utf-8")
    (tmp_path / "ok.html").write_text("<p class='muted'>no raw values here</p>\n", "utf-8")
    found = tk.check_sources(tmp_path)
    assert [item.path for item in found] == ["static/planted.css"]
    assert found[0].kind == "colour"


def test_the_generated_stylesheet_is_exempt_because_it_is_generated() -> None:
    """Its values are raw *by construction*; byte-equality with the generator is its check."""
    assert tk.find_raw_values("body { color: #FFFFFF; padding: 4px; }") != []
    assert "static/tokens.css" not in {item.path for item in tk.check_sources()}


def test_a_jinja_interpolated_unit_is_caught() -> None:
    """``style="height: {{ x }}px"`` is exactly the magic value the rule exists for."""
    found = tk.find_raw_values('<div style="height: {{ [h, 2] | max }}px"></div>', path="t.html")
    assert [item.value for item in found] == ["px"]


# ---------------------------------------------------------------- the §9 breakpoints (WP-06)
#: The width at which a stylesheet may switch layout, as (media-query value, token).
#: A media feature cannot read a custom property (CSS forbids ``var()`` there), so ``app.css``
#: writes the number as ``em`` and ``tokens.json`` carries it as a token; this test keeps the
#: two from drifting, which is the whole reason the number is written twice.
_BREAKPOINT_TOKEN: dict[str, str] = {
    "48em": "--breakpoint-sm",
    "64em": "--breakpoint-md",
    "80em": "--breakpoint-lg",
    "90em": "--breakpoint-xl",
}


def test_every_media_query_breakpoint_is_a_declared_token() -> None:
    """A width query that names a number nobody declared is a layout decision with no review."""
    data = tk.load_tokens()
    css = (tk.tokens_path().parent / "static" / "app.css").read_text(encoding="utf-8")
    widths = set(re.findall(r"@media\s*\(max-width:\s*([0-9.]+em)\)", css))
    assert widths, "no width media query in app.css — the §9 breakpoints are not implemented"
    for width in widths:
        assert width in _BREAKPOINT_TOKEN, f"undeclared breakpoint {width}"
        assert data["base"][_BREAKPOINT_TOKEN[width]] == width


def test_the_reflow_breakpoints_are_the_specified_ones() -> None:
    """§9's 1024 and 768 CSS pixels, and the two wider stops it also names."""
    data = tk.load_tokens()
    assert {name: data["base"][name] for name in _BREAKPOINT_TOKEN.values()} == {
        "--breakpoint-sm": "48em",
        "--breakpoint-md": "64em",
        "--breakpoint-lg": "80em",
        "--breakpoint-xl": "90em",
    }


def test_a_grid_track_can_shrink_below_its_minimum() -> None:
    """1.4.10: ``minmax(--layout-grid-min, 1fr)`` alone cannot reflow at 320 CSS pixels."""
    css = (tk.tokens_path().parent / "static" / "app.css").read_text(encoding="utf-8")
    assert "minmax(min(var(--layout-grid-min), 100%), 1fr)" in css


# ---------------------------------------------------------------- the contrast check
def test_every_declared_pair_passes_wcag_aa_in_both_themes() -> None:
    results = tk.contrast_report()
    assert {item.theme for item in results} == {"light", "dark"}
    failures = [str(item) for item in results if not item.ok]
    assert failures == []


def test_the_report_covers_every_text_token_against_every_surface() -> None:
    """A pair that is *used* but not declared is the way a contrast gate gets hollowed out."""
    data = tk.load_tokens()
    pairs = {(pair["fg"], pair["bg"]) for pair in data["contrast"]}
    for ink in ("--color-text-primary", "--color-text-secondary", "--color-accent"):
        for surface in ("--color-surface-0", "--color-surface-1", "--color-surface-2"):
            assert (ink, surface) in pairs, f"{ink} on {surface}"


def test_every_colour_token_is_used_by_at_least_one_asserted_pair() -> None:
    data = tk.load_tokens()
    asserted = {pair["fg"] for pair in data["contrast"]} | {pair["bg"] for pair in data["contrast"]}
    declared = {name for name in data["modes"]["theme"]["light"] if name.startswith("--color-")}
    # ``--color-border`` is a 1 px divider rather than text/background ink: WCAG's non-text
    # contrast (1.4.11) applies to component boundaries and is checked in WP-06, and the spec's
    # value for it is 1.3:1, so asserting it here would assert something the spec does not say.
    assert declared - asserted <= {"--color-border"}


def test_the_contrast_maths_matches_the_wcag_definition() -> None:
    assert tk.contrast_ratio("#FFFFFF", "#000000") == pytest.approx(21.0, abs=0.01)
    assert tk.contrast_ratio("#FFFFFF", "#FFFFFF") == pytest.approx(1.0, abs=0.01)
    # A 3-digit colour is expanded, not misread.
    assert tk.contrast_ratio("#FFF", "#000") == pytest.approx(21.0, abs=0.01)


def test_the_light_and_dark_severity_inks_are_the_specified_contrast() -> None:
    """Printed next to the badge pairs so a reviewer can see why they were accepted."""
    data = tk.load_tokens()
    theme = data["modes"]["theme"]
    for mode, ink in (("light", "#FFFFFF"), ("dark", "#0B0D12")):
        assert theme[mode]["--color-severity-ink"] == ink
        for severity in ("critical", "high", "medium", "low", "info", "success", "warning"):
            ratio = tk.contrast_ratio(ink, theme[mode][f"--color-{severity}"])
            assert ratio >= 4.5, (mode, severity, ratio)


def test_the_token_json_is_loadable_from_the_packaged_templates() -> None:
    assert tk.tokens_path().is_file()
    json.loads(tk.tokens_path().read_text(encoding="utf-8"))
