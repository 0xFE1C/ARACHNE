"""The handoff gate (REQ-QUAL-013).

The tracker is the only place progress lives, and a handoff that nobody checks is an
assertion. ``wp_check`` takes a work-package id and mechanically verifies that package's
claims **from the repository** — commits, diffs, file contents, exit codes — rather than
from what ``STATE.md`` says about itself.

Given ``WP-02`` it checks:

1. exactly one commit exists whose subject begins ``WP-02:``;
2. that commit's body lists ``Verifies:`` ids equal **as a set** to the ids the package owns
   in ``PROMPT.md`` §4 (the mapping is read from there, never from a second copy);
3. the ``STATE.md`` work-package table row is no longer ``pending``;
4. ``STATE.md`` §7 holds a handoff for the package with every template field present;
5. no ``tests/test_*_safety.py`` file was deleted and no ``skip``/``skipif``/``xfail``/
   ``--ignore`` was added to a safety suite by that commit;
6. every path the commit changed lies inside the package's work area (``STATE.md`` §4.2),
   or is named on the handoff's ``Work-area exceptions:`` line;
7. the quality gates pass at that commit, each in a fresh process.

One line is printed per check; the exit code is non-zero if any check fails. A check that
cannot apply is reported ``SKIP`` with a reason, never ``PASS``.

Every process this tool starts is a fixed argv of literal program names with no shell and a
timeout: ``git``, ``ruff``, ``mypy`` and ``python`` are all named literally, and the only
values that enter an argv are the repository path and a commit sha — data arguments, never a
program name (asserted by ``tests/unit/test_http_hygiene.py``).

Usage::

    python -m arachne.tools.wp_check WP-02
    python -m arachne.tools.wp_check WP-02 --no-gates   # skip check 7 (used by self-tests)
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Final

__all__ = [
    "SAFETY_PATTERNS",
    "Check",
    "load_handoff_exceptions",
    "load_mapping",
    "load_work_area",
    "run_checks",
]

WP_PATTERN: Final = re.compile(r"^WP-\d{2}$")
REQ_PATTERN: Final = re.compile(r"REQ-[A-Z]+-\d+")
#: Files whose safety content is protected: deleting one, or adding a skip to one, fails.
SAFETY_PATTERNS: Final = ("tests/test_*_safety.py", "tests/test_safety.py")
SAFETY_ADDED: Final = re.compile(
    r"pytest\.mark\.(?:skip|skipif|xfail)\b|pytest\.skip\b|pytest\.importorskip\b|--ignore\b"
)
#: The template fields every handoff must carry (STATE.md §6).
HANDOFF_FIELDS: Final = (
    "**Status:**",
    "**Commit:**",
    "**Gate:**",
    "#### Requirements verified",
    "#### Commands that passed",
    "#### Files created / changed",
    "#### Deviations and decisions",
    "#### Gate progress",
    "#### Gotchas for the next WP",
    "#### Safety statement",
)
#: STATE.md is the tracker and every work package must update it (STATE.md §4.1 rule 6), so
#: it is always inside the area even though §4.2 names directories.
TRACKER_PATH: Final = "STATE.md"
HANDOFF_EXCEPTION_MARKER: Final = "Work-area exceptions"
GIT_TIMEOUT_S: Final = 120
GATE_TIMEOUT_S: Final = 1800


@dataclass(frozen=True)
class Check:
    """One mechanical check's verdict."""

    number: int
    name: str
    verdict: str  # PASS | FAIL | SKIP
    detail: str = ""

    def render(self) -> str:
        suffix = f" — {self.detail}" if self.detail else ""
        return f"check {self.number} ({self.name}): {self.verdict}{suffix}"


def _git(repo: Path, *args: str) -> str:
    completed = subprocess.run(  # noqa: S603 - a fixed argv; the program name is literal
        ["git", "--no-pager", "-C", str(repo), *args],
        capture_output=True,
        text=True,
        check=False,
        timeout=GIT_TIMEOUT_S,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)}: {completed.stderr.strip()}")
    return completed.stdout


def _heading_level(line: str) -> int:
    """Return the heading level (number of leading ``#``) or 0 when the line is not one."""
    if not line.startswith("#"):
        return 0
    hashes = len(line) - len(line.lstrip("#"))
    return hashes if line[hashes : hashes + 1] == " " else 0


def _section_bounds(lines: list[str], heading: str) -> tuple[int, int] | None:
    """Return ``(start, end)`` for a Markdown section, ending at the next same-or-higher one."""
    start = next((i for i, line in enumerate(lines) if line.startswith(heading)), None)
    if start is None:
        return None
    level = _heading_level(heading)
    end = len(lines)
    for i in range(start + 1, len(lines)):
        candidate = _heading_level(lines[i])
        if 2 <= candidate <= level:
            end = i
            break
    return start, end


def load_mapping(prompt_text: str) -> dict[str, list[str]]:
    """Read ``PROMPT.md`` §4: work-package id -> the requirement ids it owns."""
    lines = prompt_text.split("\n")
    bounds = _section_bounds(lines, "## 4.")
    if bounds is None:
        raise ValueError("PROMPT.md: §4 (the mapping table) was not found")
    start, end = bounds
    mapping: dict[str, list[str]] = {}
    for line in lines[start:end]:
        if not line.startswith("| WP-"):
            continue
        cells = [cell.strip() for cell in line.split("|")]
        if len(cells) < 6:
            continue
        if cells[1] not in mapping:
            mapping[cells[1]] = REQ_PATTERN.findall(cells[4])
    return mapping


def _state_table_row(state_text: str, wp: str) -> list[str] | None:
    lines = state_text.split("\n")
    bounds = _section_bounds(lines, "## 2.")
    if bounds is None:
        return None
    start, end = bounds
    for line in lines[start:end]:
        if not line.startswith("| WP-"):
            continue
        cells = [cell.strip() for cell in line.split("|")]
        if len(cells) >= 3 and cells[1] == wp:
            return cells[2:-1]
    return None


def load_work_area(state_text: str, wp: str) -> list[str]:
    """Read ``STATE.md`` §4.2: the backticked path tokens for the package's area."""
    lines = state_text.split("\n")
    bounds = _section_bounds(lines, "### 4.2")
    if bounds is None:
        return []
    start, end = bounds
    for line in lines[start:end]:
        if not line.startswith("| WP-"):
            continue
        cells = [cell.strip() for cell in line.split("|")]
        if len(cells) >= 3 and wp in {token.strip() for token in cells[1].split(",")}:
            return re.findall(r"`([^`]+)`", cells[2])
    return []


def _handoff_section(state_text: str, wp: str) -> str | None:
    lines = state_text.split("\n")
    bounds = _section_bounds(lines, "## 7.")
    if bounds is None:
        return None
    start, end = bounds
    index = next((i for i in range(start, end) if lines[i].startswith(f"### {wp} ")), None)
    if index is None:
        return None
    close = end
    for i in range(index + 1, end):
        if re.match(r"^#{2,3} ", lines[i]):
            close = i
            break
    return "\n".join(lines[index:close])


def load_handoff_exceptions(state_text: str, wp: str) -> list[str]:
    """Read the handoff's ``Work-area exceptions:`` line, if it has one."""
    handoff = _handoff_section(state_text, wp)
    if handoff is None:
        return []
    for raw in handoff.split("\n"):
        line = raw.strip().lstrip("-* ").strip()
        if line.startswith(HANDOFF_EXCEPTION_MARKER):
            _, _, value = line.partition(":")
            return [token.strip().strip("`").strip() for token in value.split(",") if token.strip()]
    return []


def _is_within(path: str, area: list[str]) -> bool:
    for token in area:
        if path == token:
            return True
        if token.endswith("/") and path.startswith(token):
            return True
        if "/" in token and "." not in token.rsplit("/", 1)[-1] and path.startswith(token + "/"):
            return True
    return False


def _safety_file(path: str) -> bool:
    return any(Path(path).match(pattern) for pattern in SAFETY_PATTERNS)


def _added_lines_by_file(sha: str, repo: Path) -> dict[str, list[str]]:
    patch = _git(repo, "diff-tree", "--root", "-p", "--no-color", "-r", sha)
    added: dict[str, list[str]] = {}
    current: str | None = None
    for line in patch.split("\n"):
        if line.startswith("+++ b/"):
            current = line[6:]
            added.setdefault(current, [])
        elif line.startswith("+") and not line.startswith("+++") and current is not None:
            added[current].append(line[1:])
    return added


def _judge(label: str, completed: subprocess.CompletedProcess[str]) -> str | None:
    if completed.returncode == 0:
        return None
    tail = (completed.stdout.strip().splitlines() or [""])[-1]
    return f"{label} -> exit {completed.returncode} ({tail[:120]})"


def _run_gates(repo: Path, sha: str) -> Check:
    head = _git(repo, "rev-parse", "HEAD").strip()
    dirty = _git(repo, "status", "--porcelain").strip()
    workdir = repo
    env: dict[str, str] | None = None
    worktree: Path | None = None
    if head != sha or dirty:
        worktree = Path(tempfile.mkdtemp(prefix="wp-check-"))
        _git(repo, "worktree", "add", "--detach", str(worktree), sha)
        workdir = worktree
        env = dict(os.environ, PYTHONPATH=str(worktree / "src"))
    failures: list[str] = []
    try:
        for label, completed in (
            (
                "ruff check .",
                subprocess.run(
                    ["ruff", "check", "."],
                    cwd=workdir,
                    capture_output=True,
                    text=True,
                    env=env,
                    check=False,
                    timeout=GATE_TIMEOUT_S,
                ),
            ),
            (
                "ruff format --check .",
                subprocess.run(
                    ["ruff", "format", "--check", "."],
                    cwd=workdir,
                    capture_output=True,
                    text=True,
                    env=env,
                    check=False,
                    timeout=GATE_TIMEOUT_S,
                ),
            ),
            (
                "mypy --strict src",
                subprocess.run(
                    ["mypy", "--strict", "src"],
                    cwd=workdir,
                    capture_output=True,
                    text=True,
                    env=env,
                    check=False,
                    timeout=GATE_TIMEOUT_S,
                ),
            ),
            (
                "pytest tests -m 'not perf' -q",
                subprocess.run(
                    ["python", "-m", "pytest", "tests", "-m", "not perf", "-q"],
                    cwd=workdir,
                    capture_output=True,
                    text=True,
                    env=env,
                    check=False,
                    timeout=GATE_TIMEOUT_S,
                ),
            ),
        ):
            problem = _judge(label, completed)
            if problem is not None:
                failures.append(problem)
    finally:
        if worktree is not None:
            _git(repo, "worktree", "remove", "--force", str(worktree))
    if failures:
        return Check(7, "gates pass at the commit", "FAIL", "; ".join(failures))
    return Check(7, "gates pass at the commit", "PASS", "ruff, ruff format, mypy, pytest")


def _tracker_checks(state_text: str, wp: str) -> list[Check]:
    row = _state_table_row(state_text, wp)
    if row is None:
        check3 = Check(3, "tracker row is not pending", "FAIL", f"no {wp} row in STATE.md §2")
    else:
        status = re.sub(r"[*`]", "", row[-1]).strip().split(" ")[0].lower()
        if status == "pending":
            check3 = Check(3, "tracker row is not pending", "FAIL", "the row still says pending")
        else:
            check3 = Check(3, "tracker row is not pending", "PASS", status)

    handoff = _handoff_section(state_text, wp)
    if handoff is None:
        check4 = Check(4, "handoff carries every field", "FAIL", f"no {wp} handoff in STATE.md §7")
    else:
        missing = [field for field in HANDOFF_FIELDS if field not in handoff]
        if missing:
            check4 = Check(4, "handoff carries every field", "FAIL", f"missing {missing}")
        else:
            count = len(HANDOFF_FIELDS)
            check4 = Check(4, "handoff carries every field", "PASS", f"{count} fields")
    return [check3, check4]


def _commit_checks(
    repo: Path, sha: str, wp: str, mapping: dict[str, list[str]], state_text: str
) -> list[Check]:
    owned = set(mapping[wp])
    body = _git(repo, "show", "-s", "--format=%B", sha)
    claimed: set[str] = set()
    for line in body.splitlines():
        if line.strip().startswith("Verifies:"):
            claimed.update(REQ_PATTERN.findall(line))
    if claimed == owned:
        check2 = Check(2, "Verifies set equals the owned ids", "PASS", f"{len(owned)} ids")
    else:
        missing = sorted(owned - claimed)
        extra = sorted(claimed - owned)
        parts = []
        if missing:
            parts.append(f"missing {missing}")
        if extra:
            parts.append(f"unexpected {extra}")
        check2 = Check(2, "Verifies set equals the owned ids", "FAIL", "; ".join(parts))

    name_status = _git(repo, "diff-tree", "-r", "--no-commit-id", "--name-status", sha)
    changed: list[str] = []
    deleted_safety: list[str] = []
    for line in name_status.splitlines():
        fields = line.split("\t")
        if len(fields) < 2:
            continue
        status, path = fields[0], fields[-1]
        changed.append(path)
        if status.startswith("D") and _safety_file(path):
            deleted_safety.append(path)
    added = _added_lines_by_file(sha, repo)
    skipped_safety = [
        path
        for path, lines in added.items()
        if _safety_file(path) and any(SAFETY_ADDED.search(line) for line in lines)
    ]
    problems = [f"deleted {p}" for p in deleted_safety] + [
        f"added a skip to {p}" for p in skipped_safety
    ]
    check5 = (
        Check(5, "safety suites untouched", "FAIL", "; ".join(problems))
        if problems
        else Check(5, "safety suites untouched", "PASS", f"{len(changed)} path(s) changed")
    )

    area = load_work_area(state_text, wp)
    exceptions = load_handoff_exceptions(state_text, wp)
    allowed = [*area, TRACKER_PATH, *exceptions]
    outside = [path for path in changed if not _is_within(path, allowed)]
    check6 = (
        Check(6, "paths inside the work area", "FAIL", f"outside the area: {outside}")
        if outside
        else Check(6, "paths inside the work area", "PASS", f"{len(changed)} path(s) in area")
    )
    return [check2, check5, check6]


def run_checks(repo: Path, wp: str, *, gates: bool = True) -> list[Check]:
    """Run every check for ``wp`` and return the verdicts in order."""
    prompt_text = (repo / "PROMPT.md").read_text(encoding="utf-8")
    state_text = (repo / "STATE.md").read_text(encoding="utf-8")
    mapping = load_mapping(prompt_text)
    if wp not in mapping:
        raise ValueError(f"{wp} is not a work package in PROMPT.md §4")

    checks: list[Check] = []
    log = _git(repo, "log", "--format=%H\t%s")
    commits = [
        (sha, subject)
        for sha, subject in (line.split("\t", 1) for line in log.splitlines() if "\t" in line)
        if subject.startswith(f"{wp}:")
    ]
    if len(commits) == 1:
        sha = commits[0][0]
        checks.append(Check(1, "exactly one WP commit", "PASS", sha[:12]))
    elif not commits:
        checks.append(Check(1, "exactly one WP commit", "FAIL", f"no commit subject begins {wp}:"))
        sha = ""
    else:
        detail = ", ".join(subject for _, subject in commits)
        count = len(commits)
        checks.append(Check(1, "exactly one WP commit", "FAIL", f"{count} commits: {detail}"))
        sha = ""

    checks.extend(_tracker_checks(state_text, wp))
    if not sha:
        for number, name in (
            (2, "Verifies set equals the owned ids"),
            (5, "safety suites untouched"),
            (6, "paths inside the work area"),
            (7, "gates pass at the commit"),
        ):
            checks.append(Check(number, name, "SKIP", "no unambiguous commit to inspect"))
        return sorted(checks, key=lambda check: check.number)

    checks.extend(_commit_checks(repo, sha, wp, mapping, state_text))
    if gates:
        checks.append(_run_gates(repo, sha))
    else:
        checks.append(
            Check(7, "gates pass at the commit", "SKIP", "gate execution disabled by the caller")
        )
    return sorted(checks, key=lambda check: check.number)


def _out(message: str) -> None:
    sys.stdout.write(f"{message}\n")


def _err(message: str) -> None:
    sys.stderr.write(f"{message}\n")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="wp_check", description="handoff gate (REQ-QUAL-013)")
    parser.add_argument("work_package", help="a work-package id, e.g. WP-02")
    parser.add_argument("--repo", type=Path, default=Path(), help="repository root (default: .)")
    parser.add_argument("--no-gates", action="store_true", help="skip check 7 (self-tests)")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    wp = args.work_package.upper()
    if not WP_PATTERN.match(wp):
        _err(f"wp_check: {args.work_package!r} is not a work-package id (WP-nn)")
        return 2
    try:
        checks = run_checks(args.repo.resolve(), wp, gates=not args.no_gates)
    except (ValueError, RuntimeError) as exc:
        _err(f"wp_check: {exc}")
        return 2
    for check in checks:
        _out(check.render())
    failed = [check for check in checks if check.verdict == "FAIL"]
    if failed:
        _err(f"wp_check: {wp} FAILED ({len(failed)} check(s))")
        return 1
    _out(f"wp_check: {wp} PASSED ({len(checks)} checks)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
