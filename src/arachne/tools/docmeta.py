"""Documentation ownership and freshness (REQ-DOC-004).

The failure mode this gate exists for is the one the repository has already suffered once: a
page with no owner and no verified date rots silently, and the drift is only discovered when a
reader follows a claim that stopped being true months ago. Naming an owner and dating the last
verification does not prevent drift on its own — but it makes drift *visible*, and this gate is
what turns "visible" into "reported before the next reader is misled".

The convention
--------------

Every shipped documentation page carries one metadata line — a blockquote, so a reader sees it
without clicking, and a machine can parse it without a Markdown parser::

    > **Owner:** <group> · **Last verified:** <YYYY-MM-DD> · **Review interval:** <N> days

It must appear within the first ``METADATA_WINDOW`` lines, so it is a header and not a footnote.
The owner must be one of the groups below, named exactly as the specification names them, so an
"owner" cannot be a word nobody answers to.

Staleness is measured, not asserted
-----------------------------------

``age`` is the whole number of days between ``last-verified`` and the evaluation date. The page
declares its own ``review interval``: once ``age`` passes one interval the page is **due** and the
gate warns; once it passes two it is **stale** and the gate fails. A warning that never escalates
is a warning everyone learns to ignore, which is why the second interval fails the build
(REQ-DOC-004's explicit "warning first, failure after two intervals").

What is covered, and what deliberately is not
---------------------------------------------

The gate covers the **shipped** documentation surface: every ``.md`` under ``docs/`` and the
user-facing root documents. It covers *that* surface because it is the one a reader can follow.

The build-time scaffolding that recorded how this repository was built — its specification
directory, its prompt library and its tracker — is deliberately **not** covered. It is not part of
the product (REQ-DOC-006) and it has been removed, so a checker that required it would fail on the
released tree. Stating the surface positively is what keeps this gate correct either way: a page
added under ``docs/`` is covered automatically, and a file that is not shipped is never asked for
an owner.

Generated pages are excluded too, named individually with their reason in ``GENERATED_PAGES``: a
hand-written date on a generated artefact is a claim that would be overwritten the next time it is
generated, and a claim that cannot be maintained is worse than no claim.

Usage::

    python -m arachne.tools.docmeta                    # check the shipped surface
    python -m arachne.tools.docmeta --warn-only         # CI on a branch: warn, do not fail
    python -m arachne.tools.docmeta --today 2027-01-01  # evaluate as of a date (tests)
    python -m arachne.tools.docmeta --self-test         # prove a stale page fails the gate
    python -m arachne.tools.docmeta --list-owners       # the vocabulary, and the intervals

Exit code is 0 when every page is fresh or merely due, 1 when a page is stale or malformed, 2 on
a usage error.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Final

__all__ = [
    "DEFAULT_INTERVAL_DAYS",
    "GENERATED_PAGES",
    "MAX_INTERVAL_DAYS",
    "MIN_INTERVAL_DAYS",
    "OWNER_GROUPS",
    "PageMeta",
    "check",
    "discover",
    "main",
    "parse_page",
]

#: The groups that may own a page, spelled as the specification's metadata tables spell them.
#: A page whose owner is not one of these has no owner in any sense a reader can act on.
OWNER_GROUPS: Final[frozenset[str]] = frozenset(
    {
        "AI group",
        "ARACHNE architecture group",
        "ARACHNE detection group",
        "ARACHNE interface group",
        "ARACHNE programme",
        "ARACHNE quality group",
        "Core group",
        "Data group",
        "Detection group",
        "Documentation owners",
        "Ecosystem group",
        "Operations",
        "Proof group",
        "Quality group",
        "Trust group",
    }
)

#: The interval a page gets when it does not declare one, and the bounds a declared interval
#: must fall inside. The floor stops a page declaring "1 day" and turning the gate into noise;
#: the ceiling stops a page declaring "100 years" and opting out of the check.
DEFAULT_INTERVAL_DAYS: Final = 180
MIN_INTERVAL_DAYS: Final = 30
MAX_INTERVAL_DAYS: Final = 3650

#: How far down the file the metadata line may appear, and the reason the window is not one
#: line: a landing page legitimately opens with a banner block before its first prose sentence.
#: The scan also stops at the first section heading, so the header must sit *above* the body on
#: every page — it is a header, not a footnote.
METADATA_WINDOW: Final = 40
_SECTION_HEADING = re.compile(r"^#{2,6}\s")

#: Resolutions a page-class defaults to. Living documents move every release; a decision record
#: is frozen by design and is only re-read to confirm its status line still reads correctly.
DEFAULT_INTERVALS: Final[dict[str, int]] = {
    "docs/adr/": 1825,
    "docs/research/": 365,
}

#: Generated pages, each with the reason it cannot carry a maintained hand-written date.
GENERATED_PAGES: dict[str, str] = {
    "docs/ai-provider-matrix.md": (
        "generated by `python -m arachne.ai.parity`; "
        "tests/parity/test_provider_matrix.py regenerates it and fails on a difference"
    ),
    "coverage_matrix.md": (
        "generated by `arachne coverage --write coverage_matrix.md` from the check catalogue "
        "and the research corpus"
    ),
    "coverage-ledger.md": (
        "generated by `python -m arachne.tools.ledger --write` from the check registry "
        "(REQ-DET-001)"
    ),
}

#: Directories under the repository root that hold shipped documentation.
DOC_DIRS: Final[tuple[str, ...]] = ("docs",)

#: Shipped, user-facing root documents. `CHANGELOG.md` is here because it is a page a user reads
#: and the change entries in it move with every release.
DOC_ROOT_FILES: Final[tuple[str, ...]] = (
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "README.md",
    "SECURITY.md",
)

_META_LINE = re.compile(
    r"^>\s*\*\*Owner:\*\*\s*(?P<owner>.+?)\s*·\s*"
    r"\*\*Last verified:\*\*\s*(?P<verified>\d{4}-\d{2}-\d{2})\s*·\s*"
    r"\*\*Review interval:\*\*\s*(?P<interval>\d+)\s*days?\s*$"
)
_ISO_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


@dataclass(frozen=True, slots=True)
class PageMeta:
    """One page's ownership header."""

    path: str
    owner: str
    verified: date
    interval_days: int

    def age_days(self, today: date) -> int:
        return (today - self.verified).days

    def state(self, today: date) -> str:
        """``fresh`` · ``due`` (past one interval) · ``stale`` (past two)."""
        age = self.age_days(today)
        if age > 2 * self.interval_days:
            return "stale"
        if age > self.interval_days:
            return "due"
        return "fresh"


def _repo_root() -> Path:
    return Path.cwd()


def discover(repo: Path) -> tuple[Path, ...]:
    """Every shipped documentation page, in a stable order."""
    found: list[Path] = [repo / name for name in DOC_ROOT_FILES]
    for directory in DOC_DIRS:
        root = repo / directory
        if root.is_dir():
            found.extend(sorted(root.rglob("*.md")))
    return tuple(path for path in found if path.is_file())


def is_generated(relative: str) -> bool:
    return relative in GENERATED_PAGES


def _relative(path: Path, repo: Path) -> str:
    try:
        return path.resolve().relative_to(repo.resolve()).as_posix()
    except ValueError:  # pragma: no cover - a path outside the tree
        return path.as_posix()


def parse_page(path: Path) -> tuple[PageMeta | None, str | None]:
    """The page's metadata, or ``(None, reason)`` when it has none/is malformed."""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):  # pragma: no cover - an unreadable file
        return None, "unreadable"
    for number, line in enumerate(lines[:METADATA_WINDOW], start=1):
        stripped = line.strip()
        if number > 1 and _SECTION_HEADING.match(stripped):
            return None, f"no owner/date header above the first section heading (line {number})"
        match = _META_LINE.match(stripped)
        if match is None:
            continue
        owner = match.group("owner").strip()
        verified_text = match.group("verified")
        interval = int(match.group("interval"))
        if owner not in OWNER_GROUPS:
            named = ", ".join(sorted(OWNER_GROUPS))
            return None, f"line {number}: owner {owner!r} is not a known group ({named})"
        if not _ISO_DATE.match(verified_text):
            return None, f"line {number}: {verified_text!r} is not a YYYY-MM-DD date"
        try:
            verified = date.fromisoformat(verified_text)
        except ValueError:
            return None, f"line {number}: {verified_text!r} is not a real calendar date"
        if not MIN_INTERVAL_DAYS <= interval <= MAX_INTERVAL_DAYS:
            return None, (
                f"line {number}: review interval {interval} is outside "
                f"{MIN_INTERVAL_DAYS}...{MAX_INTERVAL_DAYS} days"
            )
        page = PageMeta(
            path=path.as_posix(),
            owner=owner,
            verified=verified,
            interval_days=interval,
        )
        return page, None
    return None, f"no owner/date header in the first {METADATA_WINDOW} lines"


@dataclass(frozen=True, slots=True)
class Report:
    """The gate's whole result: the failures, then the warnings, both already rendered."""

    failures: tuple[str, ...]
    warnings: tuple[str, ...]
    pages: tuple[PageMeta, ...]

    @property
    def ok(self) -> bool:
        return not self.failures


def check(repo: Path, today: date) -> Report:
    """Evaluate every page's metadata against ``today``."""
    failures: list[str] = []
    warnings: list[str] = []
    pages: list[PageMeta] = []
    for path in discover(repo):
        relative = _relative(path, repo)
        if is_generated(relative):
            continue
        meta, problem = parse_page(path)
        if meta is None:
            failures.append(f"{relative}: {problem}")
            continue
        pages.append(meta)
        state = meta.state(today)
        age = meta.age_days(today)
        rendered = (
            f"{relative}: last verified {meta.verified.isoformat()} ({age} days ago), "
            f"interval {meta.interval_days} days, owner {meta.owner}"
        )
        if state == "stale":
            failures.append(f"{rendered} — STALE (past two intervals; re-verify or re-date it)")
        elif state == "due":
            warnings.append(f"{rendered} — due for review (past one interval)")
    return Report(failures=tuple(failures), warnings=tuple(warnings), pages=tuple(pages))


def _today(value: str | None) -> date:
    if value:
        return date.fromisoformat(value)
    from_env = os.environ.get("ARACHNE_DOC_TODAY")
    if from_env:
        return date.fromisoformat(from_env)
    return datetime.now(UTC).date()


def _out(message: str) -> None:
    sys.stdout.write(f"{message}\n")


def _err(message: str) -> None:
    sys.stderr.write(f"{message}\n")


def render(report: Report, today: date) -> None:
    for warning in report.warnings:
        _err(f"docmeta: warning: {warning}")
    for failure in report.failures:
        _err(f"docmeta: {failure}")
    if report.ok:
        _out(
            f"docmeta: {len(report.pages)} page(s) carry an owner and a last-verified date "
            f"(evaluated {today.isoformat()}); {len(report.warnings)} due for review"
        )


def _self_test() -> int:
    """Prove the gate fails a stale page and passes a fresh one."""
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp)
        (repo / "docs").mkdir()
        fresh = repo / "docs" / "fresh.md"
        fresh.write_text(
            "# fresh\n\n"
            "> **Owner:** Documentation owners · **Last verified:** 2026-11-01 · "
            "**Review interval:** 180 days\n",
            encoding="utf-8",
        )
        clean = check(repo, date(2026, 11, 5))
        stale = repo / "docs" / "stale.md"
        stale.write_text(
            "# stale\n\n"
            "> **Owner:** Documentation owners · **Last verified:** 2025-01-01 · "
            "**Review interval:** 180 days\n",
            encoding="utf-8",
        )
        with_stale = check(repo, date(2026, 11, 5))
        stale.unlink()
        broken = repo / "docs" / "broken.md"
        broken.write_text(
            "# broken\n\n> **Owner:** nobody · **Last verified:** 2026-11-01 · "
            "**Review interval:** 180 days\n",
            encoding="utf-8",
        )
        unknown_owner = check(repo, date(2026, 11, 5))
    if not clean.ok:
        _out(f"self-test FAILED: a current page was reported: {list(clean.failures)}")
        return 1
    if len(with_stale.failures) != 1 or "STALE" not in with_stale.failures[0]:
        _out(f"self-test FAILED: the stale page was not reported: {list(with_stale.failures)}")
        return 1
    if not unknown_owner.failures or "not a known group" not in unknown_owner.failures[0]:
        _out(f"self-test FAILED: an unknown owner was accepted: {list(unknown_owner.failures)}")
        return 1
    _out("self-test passed: a stale page fails, an unknown owner fails, a current page passes")
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="docmeta", description="Documentation ownership and freshness gate (REQ-DOC-004)"
    )
    parser.add_argument(
        "--check", action="store_true", help="check the tree and exit non-zero on a stale page"
    )
    parser.add_argument(
        "--warn-only", action="store_true", help="report but never fail (branch CI)"
    )
    parser.add_argument("--today", help="evaluate as of YYYY-MM-DD (default: today)")
    parser.add_argument("--path", type=Path, help="repository root (default: cwd)")
    parser.add_argument("--self-test", action="store_true", help="check the checker itself")
    parser.add_argument(
        "--list-owners", action="store_true", help="print the owner vocabulary and intervals"
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.self_test:
        return _self_test()
    if args.list_owners:
        for owner in sorted(OWNER_GROUPS):
            _out(owner)
        for prefix, interval in sorted(DEFAULT_INTERVALS.items()):
            _out(f"{prefix} → {interval} days (default for this class)")
        for page, reason in sorted(GENERATED_PAGES.items()):
            _out(f"{page} → generated, not checked ({reason})")
        return 0
    try:
        today = _today(args.today)
    except ValueError:
        _err(f"docmeta: --today needs a YYYY-MM-DD date, got {args.today!r}")
        return 2
    repo = args.path or _repo_root()
    report = check(repo, today)
    render(report, today)
    if report.ok or args.warn_only:
        return 0
    _err(f"docmeta: {len(report.failures)} page(s) failed the ownership/freshness gate")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
