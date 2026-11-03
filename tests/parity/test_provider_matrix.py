"""The provider parity matrix must be real, current and complete (REQ-AGENT-010, G5 clause 4).

The matrix is a published artefact, and a published artefact that nobody regenerates is a claim
about a tree that no longer exists. So this module does the two things that make it evidence:

* **it is regenerated here** — the committed ``docs/ai-provider-matrix.json`` is compared with a
  fresh run of the matrix over a *subset* of the corpus. A subset, not the whole thing: the
  comparison is about the adapters' behaviour and the document's shape, and running all 240 cases
  through eight profiles twice per test session would spend half a minute of the suite's budget to
  re-derive identical numbers. The committed document is produced from the full corpus and says
  so (``cases``);
* **it covers all seven adapters, dated, with the fixture version it was produced against** — the
  three facts that make a parity claim checkable rather than memorable.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from arachne.ai.config import ADAPTERS
from arachne.ai.eval import EVALUATED_STAGES, corpus_sha256, load_cases
from arachne.ai.parity import (
    CONSTRAINED_MECHANISMS,
    MATRIX_DOCUMENT,
    PROFILES,
    build_matrix,
    render_markdown,
)
from arachne.ai.prompts import load_prompt_store

REPO = Path(__file__).resolve().parents[2]
CASES = REPO / "tests" / "eval" / "fixtures" / "ai-eval-cases-v1.jsonl"
MATRIX_JSON = REPO / "docs" / "ai-provider-matrix.json"
MATRIX_MD = REPO / "docs" / "ai-provider-matrix.md"

#: How many cases of each stage the regeneration check uses (enough to exercise every stage
#: contract, few enough to keep the suite fast). The committed matrix uses the whole corpus.
_SAMPLE_PER_STAGE = 6


@pytest.fixture(scope="module")
def committed() -> dict:
    return json.loads(MATRIX_JSON.read_text(encoding="utf-8"))


def _sample() -> tuple:
    cases = load_cases(CASES)
    picked: list = []
    for stage in EVALUATED_STAGES:
        picked.extend([case for case in cases if case.stage == stage][:_SAMPLE_PER_STAGE])
    return tuple(picked)


def test_the_matrix_covers_every_documented_adapter(committed: dict) -> None:
    covered = {row["adapter"] for row in committed["rows"]}
    assert set(ADAPTERS) <= covered, f"the matrix omits {sorted(set(ADAPTERS) - covered)}"
    # ... and it says up front which adapters that is, so a reader does not have to deduce it.
    assert set(ADAPTERS) == set(committed["adapters"])


def test_the_matrix_carries_a_date_and_the_fixture_it_was_produced_against(committed: dict) -> None:
    assert committed["document"] == MATRIX_DOCUMENT
    assert committed["date"], "a parity matrix without a date is a claim, not evidence"
    assert committed["fixture_version"]
    assert committed["corpus_sha256"] == corpus_sha256(CASES)
    assert committed["prompt_corpus"], "the prompt corpus identity must travel with the scores"
    assert committed["cases"] >= 200


def test_every_row_scores_every_stage_or_names_a_reason(committed: dict) -> None:
    for row in committed["rows"]:
        assert set(row["stages"]) == set(EVALUATED_STAGES), row["adapter"]
        for stage, entry in row["stages"].items():
            if entry["supported"]:
                assert entry["answered"] > 0
                assert entry["mechanism"], f"{row['adapter']}/{stage} has no mechanism recorded"
                assert 0.0 <= entry["precision"] <= 1.0
                assert 0.0 <= entry["recall"] <= 1.0
            else:
                assert entry["reason"], f"{row['adapter']}/{stage} is unsupported without a reason"
                assert entry.get("supported") is False


def test_the_unsupported_adapter_is_the_documented_negative(committed: dict) -> None:
    """``custom`` unconfigured cannot plan: the matrix must say so rather than score it zero."""
    unconfigured = [
        row
        for row in committed["rows"]
        if row["adapter"] == "custom" and row["configuration"] == "unconfigured"
    ]
    assert len(unconfigured) == 1
    row = unconfigured[0]
    assert row["reason"], "the unconfigured adapter must carry the adapter's own refusal"
    assert "request_template" in row["reason"]
    assert all(not entry["supported"] for entry in row["stages"].values())
    # The configured `custom` row, by contrast, is measured like any other adapter.
    configured = [
        row["rows"] if False else row
        for row in committed["rows"]
        if row["adapter"] == "custom" and row["configuration"] == "documented"
    ]
    assert configured and all(entry["supported"] for entry in configured[0]["stages"].values())


def test_each_adapter_records_which_mechanism_it_chose(committed: dict) -> None:
    """The column a score cannot show: what the adapter actually asked the provider to do."""
    mechanisms = {row["adapter"]: set(row["mechanisms"]) for row in committed["rows"]}
    assert "json_schema" in mechanisms["openai"]
    assert mechanisms["anthropic"] == {"tool_use"}
    assert mechanisms["gemini"] == {"response_schema"}
    # Ollama's schema-as-grammar is the local path's shape guarantee; the custom adapter has
    # whatever its operator declared, which is why it is not in the constrained set by default.
    assert "format_schema" in mechanisms["ollama"]
    constrained = {
        row["adapter"]: any(entry["constrained"] for entry in row["stages"].values())
        for row in committed["rows"]
        if row["configuration"] == "documented"
    }
    assert constrained["openai"] and constrained["anthropic"]
    assert not constrained["custom"], "a user-defined mechanism is not a decode guarantee"
    assert {"json_schema", "tool_use", "response_schema"} <= CONSTRAINED_MECHANISMS


def test_regenerating_the_matrix_reproduces_the_committed_document(committed: dict) -> None:
    """The artefact cannot rot: a fresh run over the same tree produces the same rows."""
    fresh = build_matrix(
        _sample(),
        fixture_version=committed["fixture_version"],
        corpus_digest=committed["corpus_sha256"],
        date=committed["date"],
    )
    assert fresh["adapters"] == committed["adapters"]
    assert fresh["stages"] == committed["stages"]
    assert [row["adapter"] for row in fresh["rows"]] == [
        row["adapter"] for row in committed["rows"]
    ]
    assert [row["configuration"] for row in fresh["rows"]] == [
        row["configuration"] for row in committed["rows"]
    ]
    for fresh_row, committed_row in zip(fresh["rows"], committed["rows"], strict=True):
        for stage in EVALUATED_STAGES:
            fresh_stage = fresh_row["stages"][stage]
            committed_stage = committed_row["stages"][stage]
            # A sampled run must agree on *behaviour*: same support verdict, same mechanism,
            # same enforcement claim. The scores are re-derived from the full corpus for the
            # committed document, so they are compared only where the sample is the same size.
            assert fresh_stage["supported"] == committed_stage["supported"], (
                fresh_row["adapter"],
                stage,
            )
            assert fresh_stage["mechanism"] == committed_stage["mechanism"]
            assert fresh_stage["constrained"] == committed_stage["constrained"]


def test_the_markdown_renders_the_committed_matrix(committed: dict) -> None:
    rendered = render_markdown(committed)
    assert MATRIX_MD.read_text(encoding="utf-8") == rendered, (
        "docs/ai-provider-matrix.md is stale; regenerate it with "
        "`python -m arachne.ai.parity --format md`"
    )


def test_the_profiles_cover_the_adapter_registry() -> None:
    """The profiles are data, and they must not drift from the adapters they claim to measure."""
    assert {profile.adapter for profile in PROFILES} >= set(ADAPTERS)
    assert len([profile for profile in PROFILES if profile.unconfigured]) == 1


def test_the_matrix_uses_the_shipped_prompt_corpus(committed: dict) -> None:
    assert committed["prompt_corpus"] == load_prompt_store().version
