"""The quality gates that keep the suite honest (REQ-QUAL-007/010/011/012).

These are the gates a reviewer relies on: a per-test timeout that fails a hung test, a skip
allowlist that fails an unreviewed skip, a quarantine that fails past its deadline, a coverage
floor that cannot be gamed by widening ``omit``, and a wall-clock budget asserted in CI.
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
import time
import tomllib
from datetime import date
from pathlib import Path

import pytest

from arachne.tools.skip_gate import (
    QuarantineEntry,
    SkipEntry,
    check_quarantine,
    check_skip_allowlist,
    is_skip_allowed,
    load_allowlist,
    load_quarantine,
    unlisted_skips,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"
HANGING_FIXTURE = REPO_ROOT / "tests" / "fixtures" / "timeout" / "hanging.py"


def _pyproject() -> dict[str, object]:
    with (REPO_ROOT / "pyproject.toml").open("rb") as handle:
        return tomllib.load(handle)


# ------------------------------------------------------------------ per-test timeout
#: The timeout the hanging fixture is run with. Deliberately shorter than the global 60 s
#: default: the fixture's job is to prove a stuck test is killed and named, and 5 s proves
#: exactly that while costing the suite 55 s less of pure sleep. The global default is
#: asserted separately by ``test_every_test_runs_under_a_global_timeout``.
_HANG_TIMEOUT_S = 5


@pytest.mark.timeout(60)  # reviewed exception: it waits out the 5 s timeout it is proving
def test_a_deliberately_hanging_test_fails_within_the_configured_timeout() -> None:
    """REQ-QUAL-012's acceptance criterion, end to end: the test fails and names itself."""
    started = time.monotonic()
    completed = subprocess.run(  # noqa: S603 - a literal argv naming our own interpreter
        [
            "python",
            "-m",
            "pytest",
            str(HANGING_FIXTURE),
            "-q",
            "-p",
            "no:cacheprovider",
            f"--timeout={_HANG_TIMEOUT_S}",
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
    )
    elapsed = time.monotonic() - started
    assert completed.returncode != 0, completed.stdout
    assert "test_this_test_hangs" in completed.stdout
    assert "Timeout" in completed.stdout, completed.stdout
    assert elapsed < _HANG_TIMEOUT_S + 30, (
        f"the hang was not cut off near the {_HANG_TIMEOUT_S}s budget it was given"
    )


def test_every_test_runs_under_a_global_timeout() -> None:
    options = _pyproject()["tool"]["pytest"]["ini_options"]  # type: ignore[index]
    assert options["timeout"] == 60
    assert "timeout_method" in options


# ------------------------------------------------------------------ the skip allowlist
def test_the_shipped_allowlist_has_a_reason_per_entry() -> None:
    entries = load_allowlist(REPO_ROOT)
    assert entries, "the allowlist should at least carry the live/Ollama skip"
    assert check_skip_allowlist(entries) == []
    for entry in entries:
        assert entry.reason.strip()


def test_an_unlisted_skip_is_reported() -> None:
    allowlist = [SkipEntry("tests/unit/test_x.py", "why")]
    assert is_skip_allowed("tests/unit/test_x.py::test_a", allowlist)
    skipped = ["tests/unit/test_x.py::test_a", "tests/unit/test_y.py::test_b"]
    assert unlisted_skips(skipped, allowlist) == [("tests/unit/test_y.py::test_b", "")]


def test_the_corpus_gate_module_no_longer_disables_itself() -> None:
    """REQ-QUAL-011: the 23-test module-level skip is gone, and the error test still runs."""
    coverage = (REPO_ROOT / "tests" / "unit" / "test_coverage.py").read_text(encoding="utf-8")
    contract = (REPO_ROOT / "tests" / "unit" / "test_module_contract.py").read_text(
        encoding="utf-8"
    )
    assert "pytest.mark.skipif" not in coverage
    assert "pytest.skip" not in coverage
    assert "pytest.skip" not in contract
    assert "def test_an_absent_research_directory_is_an_error" in coverage


# ------------------------------------------------------------------ the flaky quarantine
def test_the_shipped_quarantine_is_empty_and_well_formed() -> None:
    assert load_quarantine(REPO_ROOT) == []


def test_an_expired_quarantine_entry_fails() -> None:
    entry = QuarantineEntry(
        test="tests/unit/test_x.py::test_a",
        owner="builder",
        first_seen="2026-01-01",
        deadline="2026-01-31",
    )
    assert check_quarantine([entry], today=date(2026, 2, 1))
    assert check_quarantine([entry], today=date(2026, 1, 15)) == []


def test_retries_are_disabled() -> None:
    """A flake is recorded, not retried (REQ-QUAL-010)."""
    options = _pyproject()["tool"]["pytest"]["ini_options"]  # type: ignore[index]
    assert "--reruns" not in options["addopts"]
    text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert "rerunfailures" not in text
    assert importlib.util.find_spec("pytest_rerunfailures") is None


# ------------------------------------------------------------------ coverage and CI wiring
def test_the_coverage_floor_is_set_and_omit_is_not_widened() -> None:
    report = _pyproject()["tool"]["coverage"]["report"]  # type: ignore[index]
    run = _pyproject()["tool"]["coverage"]["run"]  # type: ignore[index]
    assert isinstance(report.get("fail_under"), (int, float))
    assert report["fail_under"] > 0
    # The floor is easy to game by excluding files; the omit list is the original one.
    assert run["omit"] == ["src/arachne/templates/*"]


def test_ci_runs_the_coverage_gate_and_asserts_the_budget() -> None:
    text = WORKFLOW.read_text(encoding="utf-8")
    assert "--cov" in text
    assert "ARACHNE_SUITE_BUDGET" in text


def test_the_suite_budget_fails_a_run_that_exceeds_it() -> None:
    """REQ-QUAL-007's assertion: the wall clock is checked, not merely printed."""
    env = dict(os.environ, ARACHNE_SUITE_BUDGET="0")
    completed = subprocess.run(
        [
            "python",
            "-m",
            "pytest",
            "tests/unit/test_design_tokens.py",
            "-q",
            "-p",
            "no:cacheprovider",
        ],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=180,
    )
    assert completed.returncode != 0
    assert "budget" in completed.stdout
