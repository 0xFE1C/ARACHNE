"""The skip allowlist and the flaky quarantine (REQ-QUAL-010, REQ-QUAL-011).

Two failure modes erode a suite's authority: a test that quietly stops running (a skip
nobody reviewed) and a test that keeps flaking (a red everyone learned to ignore). Both are
addressed by *recording* the exception instead of accepting it silently.

**Skip allowlist.** ``tests/skip_allowlist.json`` names every skip the project accepts, with
a reason. A skip whose node id is not covered by an entry fails the build. The enforcement
lives in ``tests/conftest.py`` so it applies to whatever subset is run; this module is the
single place the file is parsed and matched.

**Flaky quarantine.** ``tests/quarantine.json`` names a quarantined test with an owner, the
date it was first seen and a deadline. The quarantine is an admission, not a fix: retries
are disabled, a test past its deadline fails the build, and an entry with no owner, no
first-seen date or no deadline is rejected. The file starts empty — no test is quarantined
today — and the machinery is proven by the unit tests that drive expired and malformed
entries through it.

Usage::

    python -m arachne.tools.skip_gate .       # validate both files (default: .)
    python -m arachne.tools.skip_gate --self-test

Exit code is 0 when both files are well-formed and no quarantine entry has expired, 1 on a
problem, 2 on a usage error.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Final

__all__ = [
    "ALLOWLIST_PATH",
    "QUARANTINE_PATH",
    "QuarantineEntry",
    "SkipEntry",
    "Violation",
    "check_quarantine",
    "check_skip_allowlist",
    "is_skip_allowed",
    "load_allowlist",
    "load_quarantine",
    "main",
    "unlisted_skips",
]

ALLOWLIST_PATH: Final = "tests/skip_allowlist.json"
QUARANTINE_PATH: Final = "tests/quarantine.json"


@dataclass(frozen=True)
class SkipEntry:
    """One accepted skip: a node id (or module path) and why it is accepted."""

    test: str
    reason: str


@dataclass(frozen=True)
class QuarantineEntry:
    """One quarantined test, with its owner and its deadline."""

    test: str
    owner: str
    first_seen: str
    deadline: str

    def deadline_date(self) -> date:
        return date.fromisoformat(self.deadline)


@dataclass(frozen=True)
class Violation:
    """A problem with one of the two files."""

    where: str
    detail: str

    def render(self) -> str:
        return f"{self.where}: {self.detail}"


def _read_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"{path}: {exc}") from exc


def load_allowlist(root: Path) -> list[SkipEntry]:
    """Load ``tests/skip_allowlist.json``; raise ``ValueError`` when it is malformed."""
    document = _read_json(root / ALLOWLIST_PATH)
    if not isinstance(document, dict):
        raise ValueError(f"{ALLOWLIST_PATH}: expected a JSON object")
    raw = document.get("allowed")
    if not isinstance(raw, list):
        raise ValueError(f"{ALLOWLIST_PATH}: 'allowed' must be a list")
    entries: list[SkipEntry] = []
    for item in raw:
        if not isinstance(item, dict) or not isinstance(item.get("test"), str):
            raise ValueError(f"{ALLOWLIST_PATH}: every entry needs a 'test' string")
        reason = item.get("reason")
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError(f"{ALLOWLIST_PATH}: {item['test']!r} has no reason")
        entries.append(SkipEntry(test=item["test"], reason=reason))
    return entries


def load_quarantine(root: Path) -> list[QuarantineEntry]:
    """Load ``tests/quarantine.json``; raise ``ValueError`` when it is malformed."""
    document = _read_json(root / QUARANTINE_PATH)
    if not isinstance(document, dict):
        raise ValueError(f"{QUARANTINE_PATH}: expected a JSON object")
    raw = document.get("entries")
    if not isinstance(raw, list):
        raise ValueError(f"{QUARANTINE_PATH}: 'entries' must be a list")
    entries: list[QuarantineEntry] = []
    for item in raw:
        if not isinstance(item, dict):
            raise ValueError(f"{QUARANTINE_PATH}: every entry must be an object")
        test = item.get("test")
        owner = item.get("owner")
        first_seen_raw = item.get("first_seen")
        deadline_raw = item.get("deadline")
        named = {
            "test": test,
            "owner": owner,
            "first_seen": first_seen_raw,
            "deadline": deadline_raw,
        }
        for name, value in named.items():
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{QUARANTINE_PATH}: an entry is missing its {name!r} field")
        assert isinstance(test, str) and isinstance(owner, str)  # narrowed by the loop above
        assert isinstance(first_seen_raw, str) and isinstance(deadline_raw, str)
        try:
            deadline = date.fromisoformat(deadline_raw)
            first_seen = date.fromisoformat(first_seen_raw)
        except ValueError as exc:
            raise ValueError(f"{QUARANTINE_PATH}: {test!r}: {exc}") from exc
        if deadline < first_seen:
            raise ValueError(
                f"{QUARANTINE_PATH}: {test!r}: deadline {deadline} is before "
                f"first_seen {first_seen}"
            )
        entries.append(
            QuarantineEntry(
                test=test,
                owner=owner,
                first_seen=first_seen_raw,
                deadline=deadline_raw,
            )
        )
    return entries


def is_skip_allowed(node_id: str, entries: list[SkipEntry]) -> bool:
    """True when ``node_id`` equals an entry or lives under one (``entry::test``)."""
    return any(node_id == entry.test or node_id.startswith(entry.test + "::") for entry in entries)


def unlisted_skips(skipped: list[str], entries: list[SkipEntry]) -> list[tuple[str, str]]:
    """Return ``(node_id, reason)`` for every skip not covered by the allowlist."""
    covered = {node_id for node_id in skipped if is_skip_allowed(node_id, entries)}
    return [(node_id, "") for node_id in sorted(set(skipped) - covered)]


def check_quarantine(entries: list[QuarantineEntry], *, today: date) -> list[Violation]:
    """Return a violation for every quarantine entry whose deadline has passed."""
    return [
        Violation(
            entry.test,
            f"quarantined past its deadline {entry.deadline} (owner {entry.owner})",
        )
        for entry in entries
        if entry.deadline_date() < today
    ]


def check_skip_allowlist(entries: list[SkipEntry]) -> list[Violation]:
    """Structural check: every entry has a non-empty reason and a plausible test path."""
    violations: list[Violation] = []
    for entry in entries:
        if not entry.reason.strip():
            violations.append(Violation(entry.test, "the allowlist entry has no reason"))
        if not entry.test.endswith(".py") and "::" not in entry.test:
            violations.append(Violation(entry.test, "the allowlist entry names no test file"))
    return violations


def _self_test() -> int:
    """Prove an expired entry fails and a covered/uncovered skip is judged correctly."""
    today = date(2026, 11, 2)
    expired = [QuarantineEntry("t::x", "owner", "2026-01-01", "2026-01-31")]
    if not check_quarantine(expired, today=today):
        _out("self-test FAILED: an expired quarantine entry was accepted")
        return 1
    live = [QuarantineEntry("t::x", "owner", "2026-01-01", "2999-01-31")]
    if check_quarantine(live, today=today):
        _out("self-test FAILED: a live quarantine entry was reported expired")
        return 1
    allow = [SkipEntry("tests/mod.py", "why")]
    if not is_skip_allowed("tests/mod.py::test_x", allow):
        _out("self-test FAILED: a covered skip was not matched")
        return 1
    if unlisted_skips(["tests/mod.py::test_x", "tests/other.py::test_y"], allow) != [
        ("tests/other.py::test_y", "")
    ]:
        _out("self-test FAILED: an unlisted skip was not reported")
        return 1
    _out("self-test passed: expiry, coverage and unlisted detection behave as designed")
    return 0


def _out(message: str) -> None:
    sys.stdout.write(f"{message}\n")


def _err(message: str) -> None:
    sys.stderr.write(f"{message}\n")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="skip_gate", description="skip allowlist and flaky quarantine (REQ-QUAL-010/011)"
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
        _err(f"skip_gate: no such directory: {', '.join(str(p) for p in missing)}")
        return 2
    violations: list[Violation] = []
    for root in roots:
        try:
            allow = load_allowlist(root)
            quarantine = load_quarantine(root)
        except ValueError as exc:
            violations.append(Violation("skip_gate", str(exc)))
            continue
        violations.extend(check_skip_allowlist(allow))
        violations.extend(check_quarantine(quarantine, today=datetime.now(UTC).date()))
    for violation in violations:
        _out(violation.render())
    if violations:
        _err(f"skip_gate: {len(violations)} problem(s)")
        return 1
    allow = load_allowlist(roots[0])
    quarantine = load_quarantine(roots[0])
    _out(
        f"skip_gate: clean ({len(allow)} allowlisted skip(s), "
        f"{len(quarantine)} quarantined test(s))"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
