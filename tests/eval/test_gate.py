"""The evaluation gate and its self-test (REQ-AGENT-009, G5 clause 3).

A gate that has never failed is indistinguishable from no gate. This module therefore does the
uncomfortable half first: the **degraded prompt corpus is run and the gate must reject it**, with
the CLI exiting non-zero so a CI job actually stops. The rest is bookkeeping — a metric drop is
named, a drop inside the threshold is allowed, and a corpus that changed under a fixed baseline is
refused rather than quietly re-measured.

The degraded corpus (``tests/eval/degraded/``) is a byte-for-byte copy of the shipped templates
with exactly one thing removed each: ``triage``/``narrative`` lose the target-data block (the
capture never reaches the model, so a "confident" answer has nothing behind it) and ``correlate``
loses the whole user context (so no citation is offered and the engine refuses the answer).
Degrading a prompt in a way the gate *cannot* see would be the interesting failure, and these two
are precisely the ones it exists to catch.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from arachne.ai.eval import (
    DEFAULT_THRESHOLD,
    EvalReport,
    ScriptedResponder,
    StageScore,
    corpus_sha256,
    gate,
    load_cases,
    main,
    run_suite,
)
from arachne.ai.prompts import load_prompt_store

EVAL_DIR = Path(__file__).resolve().parent
CASES = EVAL_DIR / "fixtures" / "ai-eval-cases-v1.jsonl"
BASELINE = EVAL_DIR / "fixtures" / "ai-eval-baseline-v1.json"
DEGRADED = EVAL_DIR / "degraded"


@pytest.fixture(scope="module")
def cases() -> tuple:
    return load_cases(CASES)


@pytest.fixture(scope="module")
def baseline() -> dict:
    return json.loads(BASELINE.read_text(encoding="utf-8"))


def _run(cases: tuple, prompts: Path | None) -> EvalReport:
    return run_suite(
        cases,
        provider=ScriptedResponder(),
        prompts=load_prompt_store(
            str(prompts) if prompts else None,
            stages=tuple(sorted({case.stage for case in cases})),
        ),
        fixture_version="v1",
        corpus_digest=corpus_sha256(CASES),
    )


# ------------------------------------------------------------------ the self-test


def test_a_degraded_prompt_is_caught_by_the_gate(cases: tuple, baseline: dict) -> None:
    """The whole point of the suite: a prompt regression fails the gate."""
    degraded = _run(cases, DEGRADED)
    result = gate(degraded, baseline, threshold=DEFAULT_THRESHOLD)
    assert not result.passed, "a degraded prompt must not pass the evaluation gate"
    fallen = {regression.metric for regression in result.regressions}
    # The degraded triage/narrative prompts keep the citation line but lose the capture, so the
    # pipeline still records a *cited* AI contribution — and it is confidently wrong. Only the
    # score can see that, which is exactly why the score is the gate.
    assert "narrative.recall" in fallen
    assert "triage.accuracy" in fallen
    # The degraded correlate prompt loses the context, so no citation is offered and the engine
    # refuses the answer outright: an uncited AI contribution cannot exist (REQ-AGENT-008).
    assert "correlate.recall" in fallen
    assert degraded.score("correlate") is not None
    assert degraded.score("correlate").answered == 0  # type: ignore[union-attr]


def test_the_cli_exits_non_zero_on_a_regression(cases: tuple) -> None:
    """CI's contract: the gate's verdict is an exit code, not a paragraph."""
    code = main(
        [
            "--cases",
            str(CASES),
            "--baseline",
            str(BASELINE),
            "--prompts",
            str(DEGRADED),
            "--fixture-version",
            "v1",
            "--check",
        ]
    )
    assert code == 1, "the evaluation CLI must fail a regressed prompt"


def test_the_cli_exits_zero_on_the_shipped_prompts(cases: tuple) -> None:
    code = main(
        [
            "--cases",
            str(CASES),
            "--baseline",
            str(BASELINE),
            "--fixture-version",
            "v1",
            "--check",
        ]
    )
    assert code == 0


# ------------------------------------------------------------------ threshold behaviour


def test_a_drop_beyond_the_threshold_is_reported_with_both_numbers(baseline: dict) -> None:
    report = _synthetic(triage_precision=1.0 - DEFAULT_THRESHOLD - 0.01)
    result = gate(report, baseline)
    assert not result.passed
    named = {regression.metric: regression for regression in result.regressions}
    assert "triage.precision" in named
    regression = named["triage.precision"]
    assert regression.baseline == 1.0
    assert regression.current == pytest.approx(1.0 - DEFAULT_THRESHOLD - 0.01)
    assert regression.drop > DEFAULT_THRESHOLD


def test_a_drop_inside_the_threshold_is_allowed(baseline: dict) -> None:
    report = _synthetic(triage_precision=1.0 - DEFAULT_THRESHOLD / 2)
    result = gate(report, baseline)
    assert result.passed, result.summary()


def test_a_corpus_that_changed_under_a_fixed_baseline_is_refused(baseline: dict) -> None:
    """An evaluation set edited in place measures nothing, so the digest is a hard check."""
    report = _synthetic(corpus="0" * 64)
    result = gate(report, baseline)
    assert not result.passed
    assert any("corpus digest changed" in item for item in result.mismatches)


def test_a_metric_the_baseline_does_not_know_fails_the_gate(baseline: dict) -> None:
    """A new stage scored without re-baselining is a change nobody reviewed."""
    trimmed = dict(baseline)
    trimmed["metrics"] = {
        key: value for key, value in baseline["metrics"].items() if key != "narrative.precision"
    }
    result = gate(_synthetic(), trimmed)
    assert not result.passed
    assert any("narrative.precision" in item for item in result.mismatches)


# ------------------------------------------------------------------ helpers


def _synthetic(*, triage_precision: float = 1.0, corpus: str | None = None) -> EvalReport:
    """A report whose numbers are supplied, so the gate is tested without running the suite."""
    scores = tuple(
        StageScore(
            stage=stage,
            cases=10,
            answered=10,
            labelled_positives=10,
            predicted_positives=10,
            true_positives=10,
            correct=10,
            precision=triage_precision if stage == "triage" else 1.0,
            recall=1.0,
            accuracy=1.0,
        )
        for stage in ("triage", "correlate", "narrative")
    )
    return EvalReport(
        fixture_version="v1",
        corpus_sha256=corpus if corpus is not None else corpus_sha256(CASES),
        prompt_corpus="synthetic",
        stages=scores,
        cases=30,
    )
