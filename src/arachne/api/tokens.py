"""Design tokens: the one source of the UI's colour and dimension values (REQ-UIX-004).

The token file (``src/arachne/templates/web/tokens.json``) is the single machine-readable
source. This module does the three things that make it authoritative rather than decorative:

* :func:`render_css` turns it into the CSS custom properties the stylesheet and the templates
  consume, and :func:`write_css` / ``--check`` keep the committed ``tokens.css`` byte-equal to
  that output — so the generated file cannot drift from the source unnoticed.
* :func:`find_raw_values` is the raw-value rule: a hand-written template or stylesheet may not
  contain a hex colour, a ``px`` length or a ``rem`` length. Every such value has to be a token
  by name, which is what makes theming (and therefore dark mode) possible at all.
* :func:`contrast_report` checks every text/background token pair the stylesheet uses, **in both
  themes**, against WCAG 2.2 AA (4.5:1 for text, 3:1 for the focus ring), which is the contrast
  half of the same requirement — and the half a token system most often gets wrong in the dark.

Usage::

    python -m arachne.api.tokens             # the contrast report and the source check
    python -m arachne.api.tokens --print      # the generated CSS on stdout
    python -m arachne.api.tokens --write      # (re)write the generated stylesheet
    python -m arachne.api.tokens --check      # exit 1 on staleness, a raw value or a failed pair
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from functools import lru_cache
from importlib.resources import files
from pathlib import Path
from typing import Any, Final

__all__ = [
    "ContrastResult",
    "RawValue",
    "check_sources",
    "contrast_ratio",
    "contrast_report",
    "find_raw_values",
    "load_tokens",
    "main",
    "render_css",
    "tokens_path",
]

#: The generated stylesheet, relative to the web template directory.
GENERATED_CSS: Final = "static/tokens.css"

#: Files whose values are hand-written and therefore must be token-only. ``tokens.json`` is the
#: source and the generated ``tokens.css`` is built from it, so neither is scanned: that
#: file is instead compared byte-for-byte with :func:`render_css`.
_SCAN_SUFFIXES: Final = (".html", ".css")
_SKIP_FILES: Final = frozenset({GENERATED_CSS, "tokens.json"})

#: A hex colour literal (``#fff``, ``#ffff``, ``#ffffff``, ``#ffffffff``).
_HEX: Final = re.compile(r"(?<![\w#])#(?:[0-9a-fA-F]{3,4}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})\b")
#: A length in ``px`` or ``rem`` — a "magic" value that will not follow a theme. The numeric
#: part is optional so that a template's ``style="...{{ value }}px"`` is caught too: the unit
#: is raw even when the number in front of it is computed.
_LENGTH: Final = re.compile(r"(?<![\w.-])(?:\d+(?:\.\d+)?)?(?:px|rem)\b")

_HEADER: Final = "/* GENERATED FILE — do not edit by hand."

_AA_TEXT: Final = 4.5
_AA_UI: Final = 3.0


# --------------------------------------------------------------------------- the token file
def _web_dir() -> Path:
    """The filesystem directory holding the web templates and the token source."""
    return Path(str(files("arachne.templates").joinpath("web")))


def tokens_path() -> Path:
    """The committed token source."""
    return _web_dir() / "tokens.json"


def css_path() -> Path:
    """The generated stylesheet."""
    return _web_dir() / GENERATED_CSS


@lru_cache(maxsize=1)
def load_tokens() -> dict[str, Any]:
    """The parsed token source (cached; it is read many times per process)."""
    return json.loads(tokens_path().read_text(encoding="utf-8"))  # type: ignore[no-any-return]


# --------------------------------------------------------------------------- the generator
def _declarations(block: dict[str, str]) -> list[str]:
    return [f"  {name}: {value};" for name, value in block.items()]


def render_css(tokens: dict[str, Any] | None = None) -> str:
    """Emit the CSS custom properties for the token set.

    ``:root`` carries the base scale, the light theme and the comfortable density; the dark
    theme is applied by an explicit ``data-theme`` attribute **and** by the operating system's
    ``prefers-color-scheme`` when the operator has expressed no preference, so dark mode works
    with no JavaScript and an explicit choice always wins.
    """
    data = load_tokens() if tokens is None else tokens
    meta = data["name"], data["version"]
    theme: dict[str, dict[str, str]] = data["modes"]["theme"]
    density: dict[str, dict[str, str]] = data["modes"]["density"]

    lines: list[str] = [
        _HEADER,
        f"   Source: src/arachne/templates/web/tokens.json ({meta[0]} v{meta[1]})",
        "   Regenerate: python -m arachne.api.tokens --write",
        "   Verify:     python -m arachne.api.tokens --check",
        f"   Design tokens: {data['spec']} (REQ-UIX-004). */",
        "",
        ":root {",
    ]
    lines += _declarations(data["base"])
    lines += _declarations(theme["light"])
    lines += _declarations(density["comfortable"])
    lines.append("}")
    lines.append("")
    lines.append('[data-theme="dark"] {')
    lines += _declarations(theme["dark"])
    lines.append("}")
    lines.append("")
    lines.append("@media (prefers-color-scheme: dark) {")
    lines.append('  :root:not([data-theme="light"]) {')
    lines += [f"  {line}" for line in _declarations(theme["dark"])]
    lines.append("  }")
    lines.append("}")
    lines.append("")
    lines.append('[data-density="compact"] {')
    lines += _declarations(density["compact"])
    lines.append("}")
    lines.append("")
    return "\n".join(lines)


def write_css(tokens: dict[str, Any] | None = None) -> Path:
    """Write the generated stylesheet and return its path."""
    target = css_path()
    target.write_text(render_css(tokens), encoding="utf-8")
    return target


# --------------------------------------------------------------------------- the raw-value rule
@dataclass(frozen=True, slots=True)
class RawValue:
    """One raw colour or length found in a hand-written source file."""

    path: str
    line: int
    value: str
    kind: str

    def __str__(self) -> str:
        return f"{self.path}:{self.line}: raw {self.kind} {self.value!r} (use a token)"


def find_raw_values(text: str, *, path: str = "<string>") -> list[RawValue]:
    """Every raw hex colour, ``px`` length or ``rem`` length in ``text``.

    This is the lint rule REQ-UIX-004 asks for, as a function so it can be driven over the real
    tree *and* over a deliberately offending string in the test that proves it fires.
    """
    found: list[RawValue] = []
    for number, line in enumerate(text.splitlines(), 1):
        for match in _HEX.finditer(line):
            found.append(RawValue(path, number, match.group(0), "colour"))
        for match in _LENGTH.finditer(line):
            found.append(RawValue(path, number, match.group(0), "length"))
    return found


def _scannable_files(root: Path | None = None) -> list[Path]:
    base = _web_dir() if root is None else root
    return sorted(
        item
        for item in base.rglob("*")
        if item.is_file()
        and item.suffix in _SCAN_SUFFIXES
        and str(item.relative_to(base)) not in _SKIP_FILES
    )


def check_sources(root: Path | None = None) -> list[RawValue]:
    """The raw-value rule over every hand-written template and stylesheet."""
    base = _web_dir() if root is None else root
    found: list[RawValue] = []
    for item in _scannable_files(base):
        relative = str(item.relative_to(base))
        found.extend(find_raw_values(item.read_text(encoding="utf-8"), path=relative))
    return found


# --------------------------------------------------------------------------- the contrast check
def _channel(value: float) -> float:
    if value <= 0.04045:
        return value / 12.92
    return float(((value + 0.055) / 1.055) ** 2.4)


def relative_luminance(colour: str) -> float:
    """WCAG relative luminance of a ``#rgb``/``#rrggbb`` colour."""
    digits = colour.lstrip("#")
    if len(digits) == 3:
        digits = "".join(char * 2 for char in digits)
    if len(digits) != 6:
        msg = f"not a 6-digit hex colour: {colour!r}"
        raise ValueError(msg)
    red, green, blue = (int(digits[index : index + 2], 16) / 255 for index in (0, 2, 4))
    return 0.2126 * _channel(red) + 0.7152 * _channel(green) + 0.0722 * _channel(blue)


def contrast_ratio(foreground: str, background: str) -> float:
    """The WCAG contrast ratio between two hex colours (1.0 … 21.0)."""
    first = relative_luminance(foreground)
    second = relative_luminance(background)
    lighter, darker = max(first, second), min(first, second)
    return (lighter + 0.05) / (darker + 0.05)


@dataclass(frozen=True, slots=True)
class ContrastResult:
    """One asserted text/background pair in one theme."""

    theme: str
    kind: str
    foreground: str
    background: str
    ratio: float
    minimum: float
    use: str

    @property
    def ok(self) -> bool:
        return self.ratio + 1e-9 >= self.minimum

    def __str__(self) -> str:
        mark = "ok  " if self.ok else "FAIL"
        return (
            f"{mark} {self.theme:5} {self.ratio:5.2f}:1 (min {self.minimum:.1f}) "
            f"{self.foreground} on {self.background} — {self.use}"
        )


def contrast_report(tokens: dict[str, Any] | None = None) -> list[ContrastResult]:
    """Every declared text/background pair, in **both** themes, with its AA verdict."""
    data = load_tokens() if tokens is None else tokens
    theme: dict[str, dict[str, str]] = data["modes"]["theme"]
    results: list[ContrastResult] = []
    for mode, palette in theme.items():
        for pair in data["contrast"]:
            results.append(
                ContrastResult(
                    theme=mode,
                    kind=str(pair["kind"]),
                    foreground=str(palette[pair["fg"]]),
                    background=str(palette[pair["bg"]]),
                    ratio=contrast_ratio(str(palette[pair["fg"]]), str(palette[pair["bg"]])),
                    minimum=float(pair["min"]),
                    use=str(pair["use"]),
                )
            )
    return results


# --------------------------------------------------------------------------- the CLI
def _staleness() -> str | None:
    """``None`` when the committed generated stylesheet matches the generator."""
    target = css_path()
    if not target.is_file():
        return f"{GENERATED_CSS} is missing; run `python -m arachne.api.tokens --write`"
    expected = render_css()
    produced = target.read_text(encoding="utf-8")
    if produced != expected:
        return (
            f"{GENERATED_CSS} is stale (differs from the generator); run "
            "`python -m arachne.api.tokens --write` and review the diff"
        )
    return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m arachne.api.tokens")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--print", dest="show", action="store_true", help="print the CSS")
    group.add_argument("--write", action="store_true", help="regenerate tokens.css")
    group.add_argument("--check", action="store_true", help="fail on staleness or a raw value")
    group.add_argument("--contrast", action="store_true", help="only the contrast report")
    args = parser.parse_args(argv)

    if args.show:
        sys.stdout.write(render_css())
        return 0
    if args.write:
        target = write_css()
        print(f"wrote {target}")  # noqa: T201 - the CLI's output is its result
        return 0

    results = contrast_report()
    failures = [item for item in results if not item.ok]
    raw = check_sources()
    stale = _staleness()

    if args.contrast:
        for item in results:
            print(item)  # noqa: T201
        return 1 if failures else 0

    for item in results:
        print(item)  # noqa: T201
    print(  # noqa: T201
        f"\n{len(results)} contrast pair(s) across "
        f"{len({item.theme for item in results})} theme(s); {len(failures)} below AA."
    )
    for violation in raw:
        print(f"FAIL {violation}")  # noqa: T201
    print(f"{len(raw)} raw value(s) in hand-written sources.")  # noqa: T201
    if stale:
        print(f"FAIL {stale}")  # noqa: T201
    else:
        print(f"{GENERATED_CSS} is up to date.")  # noqa: T201
    return 1 if (failures or raw or stale) else 0


if __name__ == "__main__":  # pragma: no cover - exercised through main()
    raise SystemExit(main())
