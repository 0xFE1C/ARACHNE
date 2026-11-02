"""The handoff gate (REQ-QUAL-013).

``wp_check`` must not trust the builder, so these tests build throwaway repositories with
real commits and assert the tool reads *them* — a missing requirement id, an added skip in a
safety suite, a path outside the work area, a duplicate ``WP-`` commit, a handoff missing a
template field and a tracker row still marked ``pending`` each fail the check that owns them,
and a correct package passes.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from arachne.tools.wp_check import (
    Check,
    load_handoff_exceptions,
    load_mapping,
    load_work_area,
    run_checks,
)

REPO_ROOT = Path(__file__).resolve().parents[2]

PROMPT = """## 4. Mapping table

| WP | Phase | Area | Requirement IDs | Depends on | Gate |
|---|---|---|---|---|---|
| WP-01 | P1 | DOC | REQ-DOC-001 | — | G1 |
| WP-02 | P1 | QUAL | REQ-QUAL-006, REQ-QUAL-007 | WP-01 | G1 |

---
"""

HANDOFF = """### WP-02 — Quality gate hardening  ·  2026-11-02

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
- Work-area exceptions: PROMPT.md

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
    _write(repo, "PROMPT.md", PROMPT)
    _write(repo, "STATE.md", STATE.format(status=status, handoff=handoff))
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


# ------------------------------------------------------------------ the six defect modes
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
    from arachne.tools.wp_check import _commit_checks

    state = (repo / "STATE.md").read_text(encoding="utf-8")
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
    handoff = HANDOFF.replace("Work-area exceptions: PROMPT.md", "Work-area exceptions: docs/")
    checks = _verdicts(_repo(tmp_path, handoff=handoff, change=("docs/note.md", "allowed\n")))
    assert checks[6].verdict == "PASS"


# ------------------------------------------------------------------ the parser reads the real files
def test_the_mapping_is_read_from_prompt_md(tmp_path: Path) -> None:
    mapping = load_mapping(PROMPT)
    assert mapping["WP-02"] == ["REQ-QUAL-006", "REQ-QUAL-007"]
    assert mapping["WP-01"] == ["REQ-DOC-001"]


def test_the_real_repository_mapping_and_area_are_parsed() -> None:
    prompt = (REPO_ROOT / "PROMPT.md").read_text(encoding="utf-8")
    state = (REPO_ROOT / "STATE.md").read_text(encoding="utf-8")
    mapping = load_mapping(prompt)
    assert mapping["WP-02"] == [
        "REQ-QUAL-006",
        "REQ-QUAL-007",
        "REQ-QUAL-010",
        "REQ-QUAL-011",
        "REQ-QUAL-012",
        "REQ-QUAL-013",
        "REQ-QUAL-014",
    ]
    assert "src/arachne/tools/" in load_work_area(state, "WP-02")
    assert "tests/" in load_work_area(state, "WP-02")


def test_the_real_handoff_exceptions_are_parsed() -> None:
    state = (REPO_ROOT / "STATE.md").read_text(encoding="utf-8")
    # WP-01's handoff declares no exceptions; the parser returns an empty list, not a crash.
    assert load_handoff_exceptions(state, "WP-01") == []
