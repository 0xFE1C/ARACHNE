"""The single changelog source, and the generated index of it (REQ-DOC-004).

``CHANGELOG.md`` is the **only** place a release change is written down. The release notes carry a
generated index of that file — the version, its date and status, a per-kind count and the entries
themselves — between two markers, and this tool is what produces it. "Release notes are generated,
not typed twice" is only true if a machine can tell the difference, so ``--check`` fails when the
committed block is not byte-for-byte what the source produces.

The source format is [Keep a Changelog](https://keepachangelog.com/en/1.1.0/): ``## [version] —
date — status`` headings and ``### Added|Changed|Deprecated|Removed|Fixed|Security`` sections of
``- `` bullets. The vocabulary is closed on purpose: a section named anything else is refused,
because the whole point of a single source is that its shape is predictable enough to generate
from.

Usage::

    python -m arachne.tools.changelog --check     # the notes match the source, or exit 1
    python -m arachne.tools.changelog --write     # regenerate the block in the release notes
    python -m arachne.tools.changelog             # print the generated index
    python -m arachne.tools.changelog --self-test # prove a stale index fails the gate

Exit code is 0 when the source is well-formed and the notes agree with it, 1 on a difference or a
malformed source, 2 on a usage error.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

__all__ = [
    "BEGIN",
    "CHANGELOG",
    "END",
    "KINDS",
    "NOTES",
    "Release",
    "check",
    "main",
    "parse",
    "render",
]

#: The single source, and the page that carries the generated index of it.
CHANGELOG: Final = "CHANGELOG.md"
NOTES: Final = "docs/release-notes.md"

#: The two markers around the generated region. Deliberately verbose: a person editing the
#: release notes by hand meets a line that says what will overwrite them.
BEGIN: Final = "<!-- BEGIN GENERATED: changelog -->"
END: Final = "<!-- END GENERATED: changelog -->"

#: The closed section vocabulary, in the order the index renders them.
KINDS: Final[tuple[str, ...]] = (
    "Added",
    "Changed",
    "Deprecated",
    "Removed",
    "Fixed",
    "Security",
)

_UNRELEASED: Final = "Unreleased"
_RELEASE_HEADING = re.compile(r"^## \[(?P<version>[^\]]+)\](?:\s*—\s*(?P<rest>.+))?\s*$")
_KIND_HEADING = re.compile(r"^### (?P<kind>.+?)\s*$")
_BULLET = re.compile(r"^[-*] (?P<text>.+?)\s*$")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


@dataclass(slots=True)
class Release:
    """One release heading and the entries under it."""

    version: str
    date: str
    status: str
    entries: dict[str, list[str]] = field(default_factory=dict)

    @property
    def unreleased(self) -> bool:
        return self.version == _UNRELEASED

    def count(self, kind: str) -> int:
        return len(self.entries.get(kind, ()))

    @property
    def total(self) -> int:
        return sum(len(items) for items in self.entries.values())


def parse(text: str) -> tuple[list[Release], list[str]]:
    """The releases in ``text``, newest first, plus every problem found."""
    problems: list[str] = []
    releases: list[Release] = []
    current: Release | None = None
    kind: str | None = None
    for number, line in enumerate(text.splitlines(), start=1):
        heading = _RELEASE_HEADING.match(line)
        if heading:
            version = heading.group("version").strip()
            rest = (heading.group("rest") or "").strip()
            parts = [part.strip() for part in rest.split("—")] if rest else []
            date = ""
            status = ""
            if parts:
                date = parts[0]
            if len(parts) > 1:
                status = " ".join(parts[1:])
            if not version:
                problems.append(f"line {number}: a release heading with no version")
            if version and any(release.version == version for release in releases):
                problems.append(f"line {number}: version {version} appears twice")
            if version != _UNRELEASED and not _DATE.match(date):
                problems.append(
                    f"line {number}: release {version} needs a YYYY-MM-DD date "
                    f"(got {date or 'nothing'!r})"
                )
            current = Release(version=version, date=date, status=status)
            releases.append(current)
            kind = None
            continue
        section = _KIND_HEADING.match(line)
        if section:
            if current is None:
                problems.append(f"line {number}: section outside any release heading")
                kind = None
                continue
            name = section.group("kind").strip()
            if name not in KINDS:
                problems.append(f"line {number}: section {name!r} is not one of {', '.join(KINDS)}")
                kind = None
                continue
            kind = name
            current.entries.setdefault(kind, [])
            continue
        bullet = _BULLET.match(line)
        if bullet and current is not None and kind is not None:
            current.entries[kind].append(bullet.group("text").strip())
    if not releases:
        problems.append(f"{CHANGELOG}: no release heading found")
    return releases, problems


def render(releases: list[Release], *, source: str = CHANGELOG) -> str:
    """The generated index block (markers included) for ``releases``."""
    lines = [BEGIN, ""]
    lines.append(f"<!-- Generated from {source} by `python -m arachne.tools.changelog --write`;")
    lines.append("     edit the source, not this block. -->")
    lines.append("")
    lines.append("## Change index")
    lines.append("")
    lines.append(
        f"The authoritative change entries live in [`{source}`](../{source}). This index is "
        "generated from them, so the two cannot drift."
    )
    lines.append("")
    header = "| Version | Date | Status | " + " | ".join(KINDS) + " |"
    divider = "|---|---|---|" + "---:|" * len(KINDS)
    lines.append(header)
    lines.append(divider)
    for release in releases:
        status = release.status or ("unreleased" if release.unreleased else "—")
        cells = [release.version, release.date or "—", status]
        cells += [str(release.count(kind)) for kind in KINDS]
        lines.append("| " + " | ".join(cells) + " |")
    lines.append("")
    for release in releases:
        parts = [release.version]
        if release.date:
            parts.append(release.date)
        if release.status:
            parts.append(release.status)
        lines.append(f"### {' — '.join(parts)}")
        lines.append("")
        if release.total == 0:
            lines.append("No entries.")
            lines.append("")
            continue
        for kind in KINDS:
            items = release.entries.get(kind, [])
            if not items:
                continue
            lines.append(f"**{kind}**")
            lines.append("")
            lines.extend(f"- {item}" for item in items)
            lines.append("")
    lines.append(END)
    return "\n".join(lines).rstrip("\n") + "\n"


def _block(text: str) -> str | None:
    start = text.find(BEGIN)
    if start < 0:
        return None
    end = text.find(END, start)
    if end < 0:
        return None
    return text[start : end + len(END)] + "\n"


@dataclass(frozen=True, slots=True)
class Report:
    failures: tuple[str, ...]
    generated: str

    @property
    def ok(self) -> bool:
        return not self.failures


def _read(repo: Path, name: str) -> str | None:
    path = repo / name
    if not path.is_file():
        return None
    return path.read_text(encoding="utf-8")


def check(repo: Path) -> Report:
    """Validate the source and compare the release notes' generated block with it."""
    failures: list[str] = []
    source = _read(repo, CHANGELOG)
    if source is None:
        missing = (f"{CHANGELOG} is missing: there is no single changelog source",)
        return Report(failures=missing, generated="")
    releases, problems = parse(source)
    failures.extend(problems)
    generated = render(releases)
    notes = _read(repo, NOTES)
    if notes is None:
        failures.append(f"{NOTES} is missing: nothing references the changelog source")
        return Report(failures=tuple(failures), generated=generated)
    if CHANGELOG not in notes:
        failures.append(f"{NOTES} does not name {CHANGELOG}: the notes must reference the source")
    block = _block(notes)
    if block is None:
        failures.append(f"{NOTES} carries no generated changelog block ({BEGIN} ... {END})")
    elif block != generated:
        failures.append(
            f"{NOTES}'s changelog block is stale: run `python -m arachne.tools.changelog --write`"
        )
    return Report(failures=tuple(failures), generated=generated)


def write(repo: Path) -> int:
    """Replace the generated block in the release notes with the current rendering."""
    source = _read(repo, CHANGELOG)
    if source is None:
        sys.stderr.write(f"changelog: {CHANGELOG} is missing\n")
        return 1
    releases, problems = parse(source)
    if problems:
        for problem in problems:
            sys.stderr.write(f"changelog: {problem}\n")
        return 1
    path = repo / NOTES
    if not path.is_file():
        sys.stderr.write(f"changelog: {NOTES} is missing\n")
        return 1
    text = path.read_text(encoding="utf-8")
    generated = render(releases)
    block = _block(text)
    if block is None:
        sys.stderr.write(f"changelog: {NOTES} has no {BEGIN}/{END} markers to replace\n")
        return 1
    path.write_text(text.replace(block, generated, 1), encoding="utf-8")
    sys.stdout.write(f"changelog: regenerated {NOTES} from {CHANGELOG}\n")
    return 0


def _self_test() -> int:
    """Prove the gate fails on a stale index and on a malformed source, and passes when fresh."""
    import tempfile

    source = (
        "# Changelog\n\n## [Unreleased]\n\nNothing yet.\n\n"
        "## [1.2.3] — 2026-01-02 — released\n\n### Added\n\n- a thing\n\n### Fixed\n\n- a bug\n"
    )
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp)
        (repo / "docs").mkdir()
        (repo / CHANGELOG).write_text(source, encoding="utf-8")
        releases, problems = parse(source)
        good = render(releases)
        index = f"# Notes\n\nSee [{CHANGELOG}]({CHANGELOG}).\n\n{good}"
        (repo / NOTES).write_text(index, encoding="utf-8")
        fresh = check(repo)
        (repo / NOTES).write_text(
            "# Notes\n\nSee [CHANGELOG.md](CHANGELOG.md).\n\n"
            + good.replace("- a thing", "- a different thing"),
            encoding="utf-8",
        )
        stale = check(repo)
        broken, broken_problems = parse("## [1.2.3]\n\n### Nonsense\n\n- x\n")
    if problems:
        _out(f"self-test FAILED: a well-formed source was rejected: {problems}")
        return 1
    if not fresh.ok:
        _out(f"self-test FAILED: a fresh index was reported: {list(fresh.failures)}")
        return 1
    if not stale.failures or "stale" not in stale.failures[0]:
        _out(f"self-test FAILED: a stale index was not reported: {list(stale.failures)}")
        return 1
    if len(broken_problems) < 2:
        _out(f"self-test FAILED: a malformed source was accepted: {broken!r}")
        return 1
    _out("self-test passed: a fresh index passes, a stale one is reported, a bad source is refused")
    return 0


def _out(message: str) -> None:
    sys.stdout.write(f"{message}\n")


def _err(message: str) -> None:
    sys.stderr.write(f"{message}\n")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="changelog", description="Single-source changelog and generated release notes"
    )
    parser.add_argument("--check", action="store_true", help="exit 1 when the notes are stale")
    parser.add_argument("--write", action="store_true", help="regenerate the notes' index block")
    parser.add_argument("--path", type=Path, help="repository root (default: cwd)")
    parser.add_argument("--self-test", action="store_true", help="check the tool itself")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.self_test:
        return _self_test()
    repo = args.path or Path.cwd()
    if args.write:
        return write(repo)
    report = check(repo)
    if args.check:
        for failure in report.failures:
            _err(f"changelog: {failure}")
        if report.ok:
            _out(f"changelog: {NOTES} matches {CHANGELOG}")
            return 0
        return 1
    _out(report.generated)
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
