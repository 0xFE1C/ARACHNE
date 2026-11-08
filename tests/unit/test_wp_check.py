"""The handoff gate (REQ-QUAL-013).

``wp_check`` must not trust the builder, so these tests build throwaway repositories with
real commits and assert the tool reads *them* — a missing requirement id, an added skip in a
safety suite, a path outside the work area, a duplicate ``WP-`` commit, a handoff missing a
template field and a tracker row still marked ``pending`` each fail the check that owns them,
and a correct package passes.

The tracker's and the prompt library's file names are imported from the tool rather than
spelled here. They are build-time artefact names, and no file on the shipped surface may
contain one (REQ-DOC-006) — this module lives under ``tests/``, which the source
distribution carries, so it refers to them only through the constants.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from tools import wp_check
from tools.wp_check import (
    PROMPT_NAME,
    STATE_NAME,
    Check,
    _commit_checks,
    _remove_worktree,
    load_handoff_exceptions,
    load_mapping,
    main,
    run_checks,
)

PROMPT = """## 4. Mapping table

| WP | Phase | Area | Requirement IDs | Depends on | Gate |
|---|---|---|---|---|---|
| WP-01 | P1 | DOC | REQ-DOC-001 | — | G1 |
| WP-02 | P1 | QUAL | REQ-QUAL-006, REQ-QUAL-007 | WP-01 | G1 |

---
"""

HANDOFF = f"""### WP-02 — Quality gate hardening  ·  2026-11-02

**Status:** done
**Commit:** abc123  `WP-02: work`
**Gate:** G1 — passed

#### Requirements verified
| Requirement | Result | Evidence |
|---|---|---|
| REQ-QUAL-006 | verified | x |

#### Commands that passed
```
ruff check .
```

#### Files created / changed
- `src/arachne/tools/x.py`

#### Deviations and decisions
- Work-area exceptions: {PROMPT_NAME}

#### Gate progress
- G1 clause 6: met

#### Gotchas for the next WP
- none

#### Safety statement
No invariant was weakened.
"""

STATE = """## 2. Work-package table

| WP | Phase | Title | Scope (area) | Depends on | Status |
|---|---|---|---|---|---|
| WP-02 | P1 | Quality gate hardening | QUAL | WP-01 | {status} |

## 3. Gate tracker

## 4. Rules for each work-package execution

### 4.2 Work area

| WP | Directories you may touch |
|---|---|
| WP-01, WP-02 | `src/arachne/tools/`, `tests/` |

## 5. What to do when things go wrong

## 6. Handoff template

## 7. Completed handoffs

{handoff}

## 8. Programme-level issues
"""


def _git(repo: Path, *args: str) -> str:
    completed = subprocess.run(  # noqa: S603 - a literal argv; the temp repo is our own
        ["git", "-C", str(repo), "-c", "commit.gpgsign=false", *args],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    assert completed.returncode == 0, completed.stderr
    return completed.stdout


def _write(repo: Path, path: str, text: str) -> None:
    target = repo / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(text, encoding="utf-8")


def _commit(repo: Path, subject: str, body: str | None = None) -> None:
    _git(repo, "add", "-A")
    command = ["commit", "-m", subject]
    if body is not None:
        command += ["-m", body]
    _git(repo, *command)


def _repo(
    tmp_path: Path,
    *,
    status: str = "`done`",
    handoff: str = HANDOFF,
    verify: str = "REQ-QUAL-006, REQ-QUAL-007",
    extra_commit: str | None = None,
    change: tuple[str, str] | None = None,
) -> Path:
    """Build a throwaway repository whose WP-02 commit is (almost) correct."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "Test")
    _write(repo, PROMPT_NAME, PROMPT)
    _write(repo, STATE_NAME, STATE.format(status=status, handoff=handoff))
    _write(repo, "src/arachne/tools/x.py", "# tool\n")
    _write(repo, "tests/test_x.py", "def test_x() -> None:\n    assert True\n")
    _write(repo, "tests/test_x_safety.py", "def test_safe() -> None:\n    assert True\n")
    _commit(repo, "initial")
    path, text = change or ("src/arachne/tools/x.py", "# tool v2\n")
    _write(repo, path, text)
    _commit(repo, "WP-02: do the work", f"Verifies: {verify}")
    if extra_commit is not None:
        _write(repo, "tests/test_x.py", "def test_x() -> None:\n    assert 1\n")
        _commit(repo, extra_commit, "Verifies: REQ-QUAL-006")
    return repo


def _verdicts(repo: Path) -> dict[int, Check]:
    return {check.number: check for check in run_checks(repo, "WP-02", gates=False)}


# ------------------------------------------------------------------ the correct package
def test_a_correctly_completed_package_passes_every_check(tmp_path: Path) -> None:
    checks = _verdicts(_repo(tmp_path))
    assert checks[1].verdict == "PASS"
    for number in (2, 3, 4, 5, 6):
        assert checks[number].verdict == "PASS", checks[number].render()
    # Check 7 is not applicable when the caller disables gate execution: skipped, not passed.
    assert checks[7].verdict == "SKIP"


# ------------------------------------------------------------------ the eight defect modes
def test_a_missing_requirement_id_fails_check_2_and_names_it(tmp_path: Path) -> None:
    checks = _verdicts(_repo(tmp_path, verify="REQ-QUAL-006"))
    assert checks[2].verdict == "FAIL"
    assert "REQ-QUAL-007" in checks[2].detail


def test_an_extra_requirement_id_fails_check_2(tmp_path: Path) -> None:
    checks = _verdicts(_repo(tmp_path, verify="REQ-QUAL-006, REQ-QUAL-007, REQ-DOC-001"))
    assert checks[2].verdict == "FAIL"
    assert "REQ-DOC-001" in checks[2].detail


def test_a_stale_tracker_row_fails_check_3(tmp_path: Path) -> None:
    checks = _verdicts(_repo(tmp_path, status="`pending`"))
    assert checks[3].verdict == "FAIL"


def test_a_handoff_missing_a_field_fails_check_4(tmp_path: Path) -> None:
    handoff = HANDOFF.replace("#### Safety statement", "")
    checks = _verdicts(_repo(tmp_path, handoff=handoff))
    assert checks[4].verdict == "FAIL"
    assert "Safety statement" in checks[4].detail


def test_a_duplicate_wp_commit_fails_check_1(tmp_path: Path) -> None:
    checks = _verdicts(_repo(tmp_path, extra_commit="WP-02: follow-up"))
    assert checks[1].verdict == "FAIL"
    assert "2 commits" in checks[1].detail


def test_an_added_skip_in_a_safety_suite_fails_check_5(tmp_path: Path) -> None:
    change = (
        "tests/test_x_safety.py",
        "import pytest\n\n\n@pytest.mark.skipif(True, reason='nope')\ndef test_safe() -> None:\n"
        "    assert True\n",
    )
    checks = _verdicts(_repo(tmp_path, change=change))
    assert checks[5].verdict == "FAIL"
    assert "tests/test_x_safety.py" in checks[5].detail


def test_a_deleted_safety_suite_fails_check_5(tmp_path: Path) -> None:
    repo = _repo(tmp_path)
    (repo / "tests" / "test_x_safety.py").unlink()
    _commit(repo, "WP-02: second", "Verifies: REQ-QUAL-006, REQ-QUAL-007")
    # Two WP-02 commits now: check 1 fails first and the diff-based checks are skipped, so
    # the deletion is exercised through the helper directly.
    state = (repo / STATE_NAME).read_text(encoding="utf-8")
    sha = _git(repo, "rev-parse", "HEAD").strip()
    found = _commit_checks(repo, sha, "WP-02", {"WP-02": []}, state)
    checks = {check.number: check for check in found}
    assert checks[5].verdict == "FAIL"
    assert "deleted" in checks[5].detail


def test_a_path_outside_the_work_area_fails_check_6_and_names_it(tmp_path: Path) -> None:
    checks = _verdicts(_repo(tmp_path, change=("docs/note.md", "out of area\n")))
    assert checks[6].verdict == "FAIL"
    assert "docs/note.md" in checks[6].detail


def test_a_declared_exception_lets_out_of_area_work_pass(tmp_path: Path) -> None:
    handoff = HANDOFF.replace(f"Work-area exceptions: {PROMPT_NAME}", "Work-area exceptions: docs/")
    checks = _verdicts(_repo(tmp_path, handoff=handoff, change=("docs/note.md", "allowed\n")))
    assert checks[6].verdict == "PASS"


# ------------------------------------------------------------------ cleanup is not a check
def test_a_scratch_worktree_is_removed(tmp_path: Path) -> None:
    """Check 7 runs the gates in a scratch worktree; it must not survive the run."""
    repo = _repo(tmp_path)
    worktree = tmp_path / "scratch"
    _git(repo, "worktree", "add", "--detach", str(worktree), "HEAD")
    (worktree / ".pytest_cache").mkdir()
    (worktree / ".pytest_cache" / "leftover").write_text("x", encoding="utf-8")

    _remove_worktree(repo, worktree)

    assert not worktree.exists(), "the scratch directory survived the cleanup"
    assert str(worktree) not in _git(repo, "worktree", "list", "--porcelain")


def test_a_failed_worktree_removal_never_changes_the_verdict(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Cleanup runs in a ``finally``; its failure must not abort the command.

    ``git worktree remove --force`` refuses with "Directory not empty" when a tool the gate just
    ran creates a file while git is deleting the tree. That failure used to propagate out of the
    ``finally`` and exit 2, discarding every check's verdict — including the ones that passed.
    """
    repo = _repo(tmp_path)
    worktree = tmp_path / "scratch"
    worktree.mkdir()
    (worktree / "leftover").write_text("x", encoding="utf-8")
    real_git = wp_check._git

    def failing_git(repo_path: Path, *args: str) -> str:
        if args[:2] == ("worktree", "remove"):
            raise RuntimeError("git worktree remove --force: error: Directory not empty")
        return real_git(repo_path, *args)

    monkeypatch.setattr(wp_check, "_git", failing_git)

    _remove_worktree(repo, worktree)  # must not raise

    assert not worktree.exists(), "the fallback did not drop the scratch directory"


def test_a_gate_that_times_out_is_reported_not_raised(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Check 7 must print a line for a gate that ran too long, not a traceback.

    ``subprocess.run`` raises ``TimeoutExpired``. That used to escape ``_run_gates`` and with it
    the ``finally`` that removes the scratch worktree, so the whole command died with exit 1 and
    every check's verdict was lost — which is what happened verifying WP-23, whose suite is the
    pre-WP-24 one and outran the old 1800 s guard.
    """
    repo = _repo(tmp_path)
    head = _git(repo, "rev-parse", "HEAD").strip()
    real_run = subprocess.run

    def fake_run(argv: list[str], *args: object, **kwargs: object) -> object:
        if argv[:3] == ["python", "-m", "pytest"]:
            raise subprocess.TimeoutExpired(cmd=argv, timeout=1)
        if argv and argv[0] == "git":
            return real_run(argv, *args, **kwargs)  # type: ignore[arg-type]
        return subprocess.CompletedProcess(argv, 0, "", "")

    monkeypatch.setattr(wp_check.subprocess, "run", fake_run)

    check = wp_check._run_gates(repo, head)

    assert check.number == 7
    assert check.verdict == "FAIL", check.render()
    assert "timed out" in check.detail, check.detail
    assert "pytest" in check.detail, check.detail


# ------------------------------------------------------------------ the parser, on fixtures
def test_the_mapping_is_read_from_prompt_md() -> None:
    mapping = load_mapping(PROMPT)
    assert mapping["WP-02"] == ["REQ-QUAL-006", "REQ-QUAL-007"]
    assert mapping["WP-01"] == ["REQ-DOC-001"]


def test_a_handoff_without_exceptions_parses_to_an_empty_list() -> None:
    """No ``Work-area exceptions:`` line is an empty list, not a crash."""
    without = HANDOFF.replace(f"- Work-area exceptions: {PROMPT_NAME}\n", "")
    assert load_handoff_exceptions(STATE.format(status="`done`", handoff=without), "WP-01") == []


# ------------------------------------------------------------------ the release checkout
def test_an_absent_scaffolding_tree_is_reported_not_crashed(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    """The cleanup removes the tracker and the prompt library (REQ-DOC-006).

    The handoff gate stays in place (REQ-QUAL-015), so it must answer the only question such
    a tree can pose — there is nothing to verify — and say so. It exits non-zero rather than
    raising ``FileNotFoundError``, because a check that cannot apply is never a pass.
    """
    with pytest.raises(ValueError, match="build-time scaffolding is not present"):
        run_checks(tmp_path, "WP-02", gates=False)
    assert main(["--repo", str(tmp_path), "WP-02", "--no-gates"]) == 2
    assert "build-time scaffolding is not present" in capsys.readouterr().err
