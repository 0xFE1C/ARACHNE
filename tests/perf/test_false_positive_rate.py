"""The published false-positive rate and its release ceiling (REQ-QUAL-009).

REQ-QUAL-009 asks for a *published* number: the measured false-positive rate on the
ground-truth corpus, with the definition, the denominator and the exact command, at or below
2 per cent. This module pins the three properties a reader of that number depends on:

* the committed measurement exists, is internally consistent (its rate really is its own
  counts), and is inside the ceiling;
* the definition is the one the harness implements — false positives over *scored*
  candidates, with the unscored count reported rather than folded into the denominator; and
* the gate fails on an absolute breach, even when the run matches its own baseline.
"""

from __future__ import annotations

import json
from pathlib import Path

from arachne.quality.benchmark import (
    BenchmarkScore,
    consistency_problems,
    gate,
    load_baseline,
    load_suites,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
BASELINE_DIR = REPO_ROOT / "benchmarks"
LAB = "arachne-lab"
#: The release ceiling (REQ-QUAL-009): a false-positive rate above this fails the release
#: checklist. Stated as a fraction.
FP_CEILING = 0.02


def test_the_committed_false_positive_rate_is_published_and_within_the_ceiling() -> None:
    path = BASELINE_DIR / LAB / "baseline.json"
    assert path.exists(), "the false-positive measurement is not committed"
    document = json.loads(path.read_text(encoding="utf-8"))
    # The figure states its corpus version and where it came from.
    assert document["suite"] == LAB
    assert document["suite_version"]
    assert document["target"]
    assert document["measured_at"]

    baseline = load_baseline(BASELINE_DIR, LAB)
    assert baseline is not None
    numbers = baseline.numbers
    assert consistency_problems(baseline) == (), "the committed rate is not its own counts"
    assert numbers.candidates == numbers.true_positives + numbers.false_positives, (
        "the denominator must be the scored candidates (true positives + false positives)"
    )
    assert numbers.fp_rate <= FP_CEILING, (
        f"published false-positive rate {numbers.fp_rate:.1%} is over the {FP_CEILING:.0%} ceiling"
    )
    # The corpus must carry planted traps, or the measurement cannot detect a false positive.
    suite = load_suites()[LAB]
    assert suite.version == document["suite_version"]
    assert suite.traps, "the corpus has no planted false-positive traps"


def test_the_gate_fails_on_an_absolute_false_positive_breach(tmp_path: Path) -> None:
    """A run at 5 per cent fails even when it is its own baseline."""
    from arachne.quality.benchmark import BenchmarkResult, write_result

    score = BenchmarkScore(
        detection=1.0,
        true_positives=19,
        planted=19,
        false_positives=1,
        candidates=20,
        fp_rate=0.05,
    )
    result = BenchmarkResult(
        suite=LAB,
        suite_version="1.0",
        target="in-repo",
        score=score.to_dict(),
    )
    write_result(tmp_path / LAB / "baseline.json", result)
    report = gate(result, directory=tmp_path, max_fp_rate=FP_CEILING)
    assert not report.ok
    assert any("ceiling" in problem for problem in report.problems), report.problems


def test_the_gate_accepts_a_rate_at_or_below_the_ceiling(tmp_path: Path) -> None:
    from arachne.quality.benchmark import BenchmarkResult, write_result

    score = BenchmarkScore(
        detection=1.0,
        true_positives=20,
        planted=20,
        false_positives=0,
        candidates=20,
        fp_rate=0.0,
    )
    result = BenchmarkResult(
        suite=LAB, suite_version="1.0", target="in-repo", score=score.to_dict()
    )
    write_result(tmp_path / LAB / "baseline.json", result)
    assert gate(result, directory=tmp_path, max_fp_rate=FP_CEILING).ok
