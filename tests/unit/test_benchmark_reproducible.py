"""REQ-TRUST-010: the published result is reproducible, raw and rotating.

Three properties, three kinds of test:

* **Derivable** — the committed ``results.json`` is re-derived from the repository alone: the
  aggregates are recomputed from its own raw rows (fast), and the shipped generator is run
  again against the lab and compared on its deterministic fields (the slow test).
* **Complete** — the document carries the corpus version, the command, the environment (and
  none of the host-identifying fields) and one row per suite case, and a baseline committed
  before these fields existed still loads and still gates.
* **Rotating** — every suite records a review date within a year, today is before it, and a
  suite past its date fails the policy. The stamp mechanism is exercised on a temp file.
"""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import date, datetime
from pathlib import Path

import pytest

from arachne.quality.benchmark import (
    ROTATION_INTERVAL_DAYS,
    BenchmarkCase,
    BenchmarkResult,
    BenchmarkSuite,
    CaseResult,
    compare,
    consistency_problems,
    deterministic_projection,
    load_baseline,
    load_suite,
    load_suites,
    measure,
    result_from_score,
    rotation_problems,
    stamp_rotation,
    write_result,
)

TODAY = date(2026, 11, 5)
LAB = "arachne-lab"


class Row:
    """A stored candidate, in the shape ``list_candidates`` returns."""

    def __init__(
        self, number: int, check: str, marker: str, *, created_at: datetime | None = None
    ) -> None:
        self.id = number
        self.check_key = f"M3/{check}@1.0"
        self.title = f"candidate {number}"
        self.created_at = created_at

        class Evidence:
            payload = {"endpoint": marker}

        self.evidence = [Evidence()]


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def _committed(name: str = LAB) -> BenchmarkResult:
    path = _repo_root() / "benchmarks" / name / "results.json"
    return BenchmarkResult.model_validate(json.loads(path.read_text(encoding="utf-8")))


# --------------------------------------------------------------------------- derivable


def test_the_aggregates_are_recomputable_from_the_published_raw_rows() -> None:
    """A reader can check the score from the per-case rows, without the store."""
    result = _committed()
    cases = result.cases
    assert cases, "the published result has no raw per-case rows"
    planted = sum(1 for case in cases if case.expect == "tp")
    traps = sum(1 for case in cases if case.expect == "fp")
    true_positives = sum(1 for case in cases if case.expect == "tp" and case.matched)
    false_positives = sum(1 for case in cases if case.expect == "fp" and case.matched)
    numbers = result.numbers
    assert (numbers.planted, numbers.true_positives, numbers.false_positives) == (
        planted,
        true_positives,
        false_positives,
    )
    assert numbers.candidates == true_positives + false_positives
    assert numbers.detection == pytest.approx(true_positives / planted, abs=1e-4)
    assert numbers.precision == pytest.approx(
        true_positives / numbers.candidates if numbers.candidates else 0.0, abs=1e-4
    )
    assert sum(1 for case in cases if case.expect == "fp") == traps


def test_the_published_document_names_corpus_command_environment_and_rows() -> None:
    suite = load_suite(LAB)
    result = _committed()
    assert result.corpus_version.startswith(f"{LAB}@{suite.version}+")
    assert result.command == suite.reproduce
    assert {"python_version", "python_implementation", "platform", "arachne_version"} <= set(
        result.environment
    )
    # REQ-TRUST-010: the environment must not identify the host or the operator.
    assert not {"hostname", "host", "user", "username", "node"} & set(result.environment)
    assert set(result.environment) == {
        "python_version",
        "python_implementation",
        "platform",
        "arachne_version",
        "source_date_epoch",
    }
    # One row per suite case, in suite order.
    assert [case.case for case in result.cases] == [
        f"{case.check_id}|{case.marker}" for case in suite.cases
    ]
    assert result.timing["scan_seconds"] >= 0.0
    assert result.timing["per_case_available"] is True
    assert all(
        case.elapsed_seconds is not None and case.timing_source
        for case in result.cases
        if case.matched
    )


def test_baseline_and_results_are_the_same_published_document() -> None:
    root = _repo_root() / "benchmarks"
    for baseline in sorted(root.glob("*/baseline.json")):
        results = baseline.with_name("results.json")
        assert results.exists(), f"{baseline} has no published results.json beside it"
        assert json.loads(baseline.read_text()) == json.loads(results.read_text())


def test_precision_and_recall_are_reported_with_honest_degenerate_cases() -> None:
    suite = load_suite(LAB)
    # A clean hit on every planted case: precision and recall are both 1.0.
    rows = [
        Row(n, case.check_id.split(".")[1], case.marker) for n, case in enumerate(suite.planted, 1)
    ]
    score = measure(rows, suite)
    assert score.recall == 1.0
    assert score.precision == 1.0
    # Nothing scored: precision is undefined, reported as 0.0 rather than perfect.
    empty = measure([], suite)
    assert empty.candidates == 0
    assert empty.precision == 0.0
    # Only traps fired: still no true positive, so both are 0.0.
    trap_suite = BenchmarkSuite(
        name="traps-only",
        version="1.0",
        target="t",
        cases=(BenchmarkCase(check_id="m3.xss-oracle", marker="/safe", expect="fp"),),
    )
    trap_score = measure([Row(1, "xss-oracle", "/safe")], trap_suite)
    assert trap_score.true_positives == 0
    assert trap_score.precision == 0.0
    assert trap_score.recall == 0.0


def test_a_baseline_predating_the_new_fields_still_loads_and_gates(tmp_path: Path) -> None:
    """REQ-TRUST-010's compatibility rule: an old committed baseline must not fail."""
    old = {
        "suite": LAB,
        "suite_version": "1.0",
        "arachne_version": "0.1.0",
        "target": "in-repo",
        "source": "lab",
        "measured_at": "2026-10-30T12:00:00+00:00",
        "score": {
            "detection": 0.875,
            "true_positives": 14,
            "planted": 16,
            "false_positives": 0,
            "candidates": 14,
            "fp_rate": 0.0,
            "unscored": 0,
            "missed": [],
            "fp_examples": [],
        },
    }
    directory = tmp_path / "benchmarks"
    (directory / LAB).mkdir(parents=True)
    (directory / LAB / "baseline.json").write_text(json.dumps(old), encoding="utf-8")

    restored = load_baseline(directory, LAB)
    assert restored is not None
    assert restored.corpus_version == ""
    assert restored.command == ""
    assert restored.cases == ()
    assert restored.environment == {}
    assert consistency_problems(restored) == ()
    # The derived precision/recall come from the counts it already had.
    assert restored.numbers.precision == 1.0
    assert restored.numbers.recall == 0.875
    assert compare(restored, restored) == ()


# --------------------------------------------------------------------------- rotating


def test_every_shipped_suite_records_a_rotation_and_is_not_overdue() -> None:
    problems: dict[str, tuple[str, ...]] = {}
    for name, suite in load_suites().items():
        problems[name] = rotation_problems(suite, today=TODAY)
    assert all(not problem for problem in problems.values()), problems
    for suite in load_suites().values():
        assert suite.rotated_at is not None
        assert suite.review_by is not None
        assert 0 <= (suite.review_by - suite.rotated_at).days <= ROTATION_INTERVAL_DAYS
        assert suite.review_by > TODAY
        assert suite.rotation_history


def test_a_suite_past_its_review_date_fails_the_rotation_policy() -> None:
    overdue = BenchmarkSuite(
        name="overdue",
        version="1.0",
        target="t",
        rotated_at=date(2025, 1, 1),
        review_by=date(2026, 1, 1),
        cases=(BenchmarkCase(check_id="m3.xss-oracle", marker="/x"),),
    )
    problems = rotation_problems(overdue, today=TODAY)
    assert any("overdue" in problem for problem in problems), problems

    missing = BenchmarkSuite(
        name="unstamped",
        version="1.0",
        target="t",
        cases=(BenchmarkCase(check_id="m3.xss-oracle", marker="/x"),),
    )
    assert rotation_problems(missing, today=TODAY)

    too_long = BenchmarkSuite(
        name="too-long",
        version="1.0",
        target="t",
        rotated_at=date(2025, 1, 1),
        review_by=date(2026, 6, 1),
        cases=(BenchmarkCase(check_id="m3.xss-oracle", marker="/x"),),
    )
    assert any("annual" in problem for problem in rotation_problems(too_long, today=TODAY))


def test_stamping_a_rotation_records_it_and_preserves_the_suite_text(tmp_path: Path) -> None:
    path = tmp_path / "rot.yaml"
    path.write_text(
        "# why this suite exists\n"
        "name: rot\n"
        "version: '1.0'\n"
        "target: t\n"
        "cases:\n"
        "- {check_id: m3.xss-oracle, marker: /x, expect: tp}\n",
        encoding="utf-8",
    )
    first = stamp_rotation(path, rotated_at=date(2026, 1, 1), note="first rotation")
    assert first == date(2027, 1, 1)
    second = stamp_rotation(path, rotated_at=date(2026, 6, 1), note="second rotation")
    assert second == date(2027, 6, 1)

    text = path.read_text(encoding="utf-8")
    assert "# why this suite exists" in text
    suite = load_suite("rot", path=path)
    assert suite.rotated_at == date(2026, 6, 1)
    assert suite.review_by == date(2027, 6, 1)
    assert len(suite.rotation_history) == 2
    assert suite.rotation_history[0] == "2026-01-01: first rotation"
    assert suite.rotation_history[1] == "2026-06-01: second rotation"
    assert rotation_problems(suite, today=TODAY) == ()


# --------------------------------------------------------------------------- the generator


@pytest.mark.timeout(180)  # reviewed exception: this runs the real lab scan the command runs
def test_the_committed_result_is_reproducible_by_the_shipped_generator(tmp_path: Path) -> None:
    """Run the shipped command against the repo, then compare deterministic fields only.

    This is the third-party claim as a test: a checkout plus its interpreter reproduces the
    committed result. The comparison excludes timestamps, environment and wall-clock timing.
    """
    completed = subprocess.run(  # noqa: S603 - fixed argv, our interpreter, no shell
        [
            sys.executable,
            "-m",
            "arachne.tools.benchmark",
            "--lab",
            "--write-baseline",
            "--output-dir",
            str(tmp_path),
        ],
        capture_output=True,
        text=True,
        cwd=str(_repo_root()),
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    regenerated = tmp_path / LAB / "results.json"
    assert regenerated.exists(), completed.stdout + completed.stderr
    fresh = BenchmarkResult.model_validate(json.loads(regenerated.read_text(encoding="utf-8")))
    committed = _committed()
    assert deterministic_projection(fresh) == deterministic_projection(committed)


def test_case_result_rows_survive_a_round_trip() -> None:
    case = CaseResult(
        check_id="m3.xss-oracle",
        marker="/search",
        expect="tp",
        matched=True,
        matched_by=("7",),
        elapsed_seconds=1.25,
        timing_source="candidate.created_at minus scan.started_at",
    )
    restored = CaseResult.model_validate(json.loads(case.model_dump_json()))
    assert restored == case
    assert restored.case == "m3.xss-oracle|/search"


def test_a_written_result_keeps_the_selected_suite_shape(tmp_path: Path) -> None:
    suite = load_suites()["juice-shop"]
    result = result_from_score(
        suite,
        measure([], suite),
        arachne_version="test",
        command=suite.reproduce,
        environment={"python_version": "x"},
        cases=(),
    )
    path = write_result(tmp_path / "juice-shop" / "results.json", result)
    document = json.loads(path.read_text(encoding="utf-8"))
    assert document["suite"] == "juice-shop"
    assert document["source"] == "recorded"
    assert document["corpus_version"].startswith("juice-shop@")
    assert document["command"] == suite.reproduce
