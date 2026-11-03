"""The offline evaluation suite (REQ-AGENT-009, G5 clause 3).

Five things are asserted here, and each one is a clause of the acceptance criteria:

1. the corpus is big enough and every case is labelled for exactly one stage;
2. the suite scores **per stage** — precision, recall and accuracy for ``triage``, ``correlate``
   and ``narrative`` — never as one number;
3. the suite runs with no network and no API key, and is deterministic across two runs;
4. the committed baseline is what the shipped prompts score (so the gate below has a floor);
5. the *degraded* prompt corpus (``tests/eval/degraded/``) is caught by the gate, and the CLI
   exits non-zero — the self-test that makes the gate a gate rather than a report.

The provider is :class:`~arachne.ai.eval.ScriptedResponder`, which answers from the rendered
prompt alone. A perfect score on the shipped corpus is therefore the expected result and means
what it says: the prompt conveys everything the labels depend on. The measurement's scope — and
what it does *not* say about a particular model — is documented in ``ai/eval.py``.
"""

from __future__ import annotations

import socket
from pathlib import Path

import pytest

from arachne.ai.eval import (
    DEFAULT_THRESHOLD,
    EVALUATED_STAGES,
    ScriptedResponder,
    corpus_sha256,
    gate,
    load_cases,
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
    import json

    return json.loads(BASELINE.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def report(cases: tuple):
    return _run(cases)


def _run(cases: tuple, prompts: Path | None = None):
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


# ------------------------------------------------------------------ 1. the corpus


def test_the_corpus_holds_at_least_two_hundred_labelled_cases(cases: tuple) -> None:
    assert len(cases) >= 200, "REQ-AGENT-009 requires at least 200 labelled cases"
    per_stage = dict.fromkeys(EVALUATED_STAGES, 0)
    for case in cases:
        per_stage[case.stage] += 1
        assert case.label, f"{case.case_id} carries no label"
        assert case.check_id and case.asset
    assert all(count > 0 for count in per_stage.values()), per_stage
    # Every evaluated stage is represented in the corpus, or a "per-stage" report would be
    # silently empty for that stage.
    assert set(per_stage) == set(EVALUATED_STAGES)


def test_triage_and_narrative_cases_carry_a_citable_evidence_id(cases: tuple) -> None:
    """A case that cannot cite is a case that cannot exercise the citation contract."""
    for case in cases:
        if case.stage == "triage":
            assert case.evidence_ids(), case.case_id


# ------------------------------------------------------------------ 2. per-stage scores


def test_every_stage_is_scored_separately(report) -> None:
    scored = {score.stage for score in report.stages}
    assert scored == set(EVALUATED_STAGES)
    for score in report.stages:
        assert score.cases > 0, score
        assert 0.0 <= score.precision <= 1.0
        assert 0.0 <= score.recall <= 1.0
        assert 0.0 <= score.accuracy <= 1.0


def test_the_report_is_keyed_per_stage_and_metric(report) -> None:
    metrics = report.metrics()
    for stage in EVALUATED_STAGES:
        for metric in ("precision", "recall", "accuracy"):
            assert f"{stage}.{metric}" in metrics


# ------------------------------------------------------------------ 3. offline, deterministic


def test_the_suite_needs_no_network_and_no_api_key(
    cases: tuple, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An armed socket: every connection attempt fails, and the suite still completes."""
    for key in (
        "OPENAI_API_KEY",
        "ANTHROPIC_API_KEY",
        "GEMINI_API_KEY",
        "MISTRAL_API_KEY",
        "ARACHNE_AI_API_KEY_ENV",
    ):
        monkeypatch.delenv(key, raising=False)

    def refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError("the evaluation suite must not open a socket (REQ-AGENT-009)")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    fresh = _run(cases)
    assert fresh.cases == len(cases)
    assert fresh.score("triage") is not None


def test_two_runs_produce_identical_results(cases: tuple, report) -> None:
    """Determinism: no clock, no randomness, no network — the report is byte-identical."""
    again = _run(cases)
    assert again.to_dict() == report.to_dict()
    # ... and the report itself carries no clock value that could differ between runs.
    assert "generated_at" not in report.to_dict()


def test_the_scripted_provider_is_not_a_registered_adapter() -> None:
    """The responder exists for the suite; no configuration may select it."""
    from arachne.ai.config import ADAPTERS
    from arachne.ai.providers.registry import PROVIDER_CLASSES

    assert ScriptedResponder().name not in ADAPTERS
    assert ScriptedResponder().name not in PROVIDER_CLASSES


# ------------------------------------------------------------------ 4. the committed floor


def test_the_shipped_prompts_score_the_committed_baseline(report, baseline: dict) -> None:
    assert report.corpus_sha256 == baseline["corpus_sha256"]
    assert report.fixture_version == baseline["fixture_version"]
    result = gate(report, baseline, threshold=DEFAULT_THRESHOLD)
    assert result.passed, result.summary()


def test_the_baseline_scores_are_perfect_on_the_shipped_corpus(report) -> None:
    """The responder answers from the prompt, so full fidelity is full marks.

    Stated as a test rather than a comment because it is the claim the whole harness rests on: if
    a shipped prompt no longer conveys what a label depends on, this fails *before* the gate's
    threshold hides it behind a two-point allowance.
    """
    for score in report.stages:
        assert score.precision == 1.0, score
        assert score.recall == 1.0, score
        assert score.answered == score.cases, score
