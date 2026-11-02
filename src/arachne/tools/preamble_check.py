"""The shared-preamble sync gate (REQ-QUAL-014).

``PROMPT.md`` has one canonical preamble, the fenced block under "## 2. The shared
preamble", and it is copied verbatim into the head of all 23 work-package prompts in
"## 3. Work-package prompts". Nothing about a Markdown file keeps those copies in step:
editing the canonical text silently leaves 23 blocks issuing the old rules, which is the
same duplication class as a hand-typed count.

This tool extracts the canonical text and compares it **byte-for-byte** with the preamble
that precedes every ``WORK PACKAGE:`` header. There is no whitespace normalisation: the
comparison is an exact string equality against ``canonical + "\\n"``, so a one-character
drift (a changed word, a lost space, a different number of blank lines) fails.

It also checks that the preamble text has a single source: every file in the repository
other than ``PROMPT.md`` must contain none of it, and ``PROMPT.md`` itself must contain
exactly one canonical block plus one copy per work-package block.

Usage::

    python -m arachne.tools.preamble_check .       # check the repository (default: .)
    python -m arachne.tools.preamble_check --self-test

Exit code is 0 when every copy matches, 1 on any drift, 2 on a usage error.
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Final

__all__ = [
    "CANONICAL_MARKER",
    "PROMPT_NAME",
    "Violation",
    "check_repository",
    "check_text",
    "extract_canonical",
    "extract_copies",
    "main",
]

#: The first line of the canonical preamble. It is long and distinctive on purpose: the
#: illustrative line in §1 ("You are the builder for ARACHNE, ...  (the shared preamble,
#: 30 lines)") does not match it, so only the canonical block and its 23 copies do.
CANONICAL_MARKER: Final = (
    "You are the builder for ARACHNE, a defensive vulnerability scanner. You have repository"
)
PROMPT_NAME: Final = "PROMPT.md"
SECTION_2: Final = "## 2."
SECTION_3: Final = "## 3."
SECTION_4: Final = "## 4."
FENCE: Final = "```"
#: Directories that hold no shipped prompt text.
SKIP_DIRS: Final = frozenset(
    {
        ".git",
        ".venv",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "node_modules",
        "build",
        "dist",
    }
)
SCAN_SUFFIXES: Final = frozenset({".md", ".rst", ".txt"})


@dataclass(frozen=True)
class Violation:
    """A named preamble mismatch."""

    block: str
    detail: str

    def render(self) -> str:
        return f"{self.block}: {self.detail}"


def _section(lines: list[str], prefix: str) -> int | None:
    for index, line in enumerate(lines):
        if line.startswith(prefix):
            return index
    return None


def extract_canonical(text: str) -> str | None:
    """Return the canonical preamble (the fenced block under §2), or ``None`` if absent."""
    lines = text.split("\n")
    start = _section(lines, SECTION_2)
    end = _section(lines, SECTION_3)
    if start is None or end is None:
        return None
    for index in range(start, end):
        if lines[index] != FENCE or index + 1 >= len(lines):
            continue
        if lines[index + 1].startswith(CANONICAL_MARKER):
            for close in range(index + 1, end):
                if lines[close] == FENCE:
                    return "\n".join(lines[index + 1 : close])
    return None


def extract_copies(text: str) -> list[tuple[str, str]]:
    """Return ``(block label, preamble region)`` for every ``WORK PACKAGE:`` block.

    The region is everything between the block's opening fence and the ``WORK PACKAGE:``
    line, exactly as it appears in the file (no stripping, no normalisation).
    """
    lines = text.split("\n")
    start = _section(lines, SECTION_3)
    end = _section(lines, SECTION_4)
    if start is None or end is None:
        return []
    copies: list[tuple[str, str]] = []
    for index in range(start, end):
        if not lines[index].startswith("WORK PACKAGE:"):
            continue
        opening = max(
            (candidate for candidate in range(start, index) if lines[candidate] == FENCE),
            default=None,
        )
        if opening is None:
            copies.append((lines[index].strip(), ""))
            continue
        copies.append((lines[index].strip(), "\n".join(lines[opening + 1 : index])))
    return copies


def check_text(text: str) -> list[Violation]:
    """Compare every block preamble with the canonical text, byte-for-byte."""
    canonical = extract_canonical(text)
    if canonical is None:
        return [Violation(PROMPT_NAME, "the canonical preamble under §2 was not found")]
    expected = canonical + "\n"
    violations: list[Violation] = []
    copies = extract_copies(text)
    if not copies:
        violations.append(Violation(PROMPT_NAME, "no WORK PACKAGE: block was found in §3"))
    for label, region in copies:
        if region != expected:
            violations.append(
                Violation(label, "the preamble at the head of this block differs from §2")
            )
    return violations


def _iter_text_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if SKIP_DIRS & set(path.parts):
            continue
        if path.suffix.lower() in SCAN_SUFFIXES:
            files.append(path)
    return files


def check_repository(root: Path) -> list[Violation]:
    """Check the repository: every copy matches, and the preamble has one source."""
    prompt = root / PROMPT_NAME
    if not prompt.is_file():
        return [Violation(PROMPT_NAME, f"not found under {root}")]
    text = prompt.read_text(encoding="utf-8")
    violations = check_text(text)
    canonical_blocks = 1 if extract_canonical(text) is not None else 0
    expected_total = canonical_blocks + len(extract_copies(text))
    # No second source: the marker appears only in PROMPT.md, exactly once per copy.
    for path in _iter_text_files(root):
        if path == prompt:
            continue
        try:
            body = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):  # pragma: no cover - unreadable file
            continue
        if CANONICAL_MARKER in body:
            violations.append(
                Violation(
                    str(path.relative_to(root)),
                    "carries the preamble text; §2 of PROMPT.md is the single source",
                )
            )
    if text.count(CANONICAL_MARKER) != expected_total:
        violations.append(
            Violation(
                PROMPT_NAME,
                f"contains {text.count(CANONICAL_MARKER)} preamble copies; expected "
                f"{expected_total} (one canonical block plus one per work-package block)",
            )
        )
    return violations


def _self_test() -> int:
    """Prove a one-character drift and a block without a preamble both fail."""
    prompt = (
        f"{SECTION_2} The shared preamble\n\n{FENCE}\n"
        "You are the builder for ARACHNE, a defensive vulnerability scanner. You have repository\n"
        "access. Read the code.\n"
        f"{FENCE}\n\n{SECTION_3} Work-package prompts\n\n"
        "### WP-01 — one\n\n"
        f"{FENCE}\n"
        "You are the builder for ARACHNE, a defensive vulnerability scanner. You have repository\n"
        "access. Read the code.\n\n"
        "WORK PACKAGE: WP-01 — one\n"
        f"{FENCE}\n\n{SECTION_4} Mapping table\n"
    )
    if check_text(prompt):
        _out("self-test FAILED: an exact copy was reported as different")
        return 1
    drifted = prompt.replace("Read the code.\n\nWORK", "Read code.\n\nWORK")
    found = check_text(drifted)
    if len(found) != 1 or "WP-01" not in found[0].block:
        _out(f"self-test FAILED: expected one WP-01 violation, got {[v.render() for v in found]}")
        return 1
    missing = prompt.replace(
        "You are the builder for ARACHNE, a defensive vulnerability scanner. You have repository\n"
        "access. Read the code.\n\nWORK PACKAGE: WP-01",
        "WORK PACKAGE: WP-01",
    )
    found = check_text(missing)
    if len(found) != 1 or "WP-01" not in found[0].block:
        _out(f"self-test FAILED: a block without a preamble was not reported: got {found}")
        return 1
    _out("self-test passed: a one-character drift and a missing preamble both fail")
    return 0


def _out(message: str) -> None:
    sys.stdout.write(f"{message}\n")


def _err(message: str) -> None:
    sys.stderr.write(f"{message}\n")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="preamble_check", description="shared-preamble sync gate (REQ-QUAL-014)"
    )
    parser.add_argument("paths", nargs="*", type=Path, help="repository root (default: .)")
    parser.add_argument("--self-test", action="store_true", help="check the checker itself")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.self_test:
        return _self_test()
    roots = list(args.paths) or [Path()]
    missing = [root for root in roots if not root.is_dir()]
    if missing:
        _err(f"preamble_check: no such directory: {', '.join(str(p) for p in missing)}")
        return 2
    violations: list[Violation] = []
    for root in roots:
        violations.extend(check_repository(root))
    for violation in violations:
        _out(violation.render())
    if violations:
        _err(f"preamble_check: {len(violations)} problem(s)")
        return 1
    copies = len(extract_copies((roots[0] / PROMPT_NAME).read_text(encoding="utf-8")))
    _out(f"preamble_check: clean ({copies} work-package block(s) match the §2 preamble)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
