"""The evaluation corpus is data, and this module is what keeps it honest (REQ-AGENT-009).

Three properties, each one a way an evaluation set rots:

* **it is what its builder says it is** — the committed ``.jsonl`` is byte-identical to
  :func:`arachne.ai.eval_corpus.cases_jsonl`, so the labelling rules cannot drift away from the
  file a reviewer is reading;
* **it is versioned and pinned** — the corpus's own version, the digest in the baseline, and the
  case count all agree, so a corpus edited in place fails here before it can quietly change what
  a baseline means;
* **every label is the kind its stage needs** — a triage case labels severity and ``fp_likely``, a
  narrative case labels the facts the prose must carry, a correlate case names a root cause the
  matcher's closed vocabulary can represent.
"""

from __future__ import annotations

import json
from pathlib import Path

from arachne.ai.eval import ROOT_CAUSE_KEYWORDS, load_cases, match_root_cause
from arachne.ai.eval_corpus import CORPUS_VERSION, build_cases, cases_jsonl

EVAL_DIR = Path(__file__).resolve().parent
CASES = EVAL_DIR / "fixtures" / "ai-eval-cases-v1.jsonl"
BASELINE = EVAL_DIR / "fixtures" / "ai-eval-baseline-v1.json"
SEVERITIES = frozenset({"info", "low", "medium", "high", "critical"})


def test_the_committed_corpus_is_exactly_what_the_builder_emits() -> None:
    assert CASES.read_text(encoding="utf-8") == cases_jsonl(), (
        "the committed corpus and ai.eval_corpus disagree; emit the fixture with "
        "`python -m arachne.ai.eval_corpus` and re-baseline deliberately"
    )


def test_the_corpus_version_and_digest_are_pinned_in_the_baseline() -> None:
    import hashlib

    baseline = json.loads(BASELINE.read_text(encoding="utf-8"))
    digest = hashlib.sha256(CASES.read_bytes()).hexdigest()
    assert baseline["corpus_sha256"] == digest
    assert baseline["fixture_version"] == CORPUS_VERSION
    assert baseline["cases"] == len(build_cases())


def test_every_case_is_labelled_for_its_own_stage() -> None:
    cases = load_cases(CASES)
    for case in cases:
        if case.stage == "triage":
            assert case.label["severity"] in SEVERITIES, case.case_id
            assert isinstance(case.label["fp_likely"], bool), case.case_id
            assert case.evidence, f"{case.case_id} has no evidence to judge"
        elif case.stage == "narrative":
            facts = case.label["facts"]
            assert facts, case.case_id
            assert all(isinstance(fact, str) and fact for fact in facts), case.case_id
            assert case.evidence, f"{case.case_id} has no capture to write about"
        elif case.stage == "correlate":
            key = case.label["root_cause"]
            assert key in set(ROOT_CAUSE_KEYWORDS.values()), case.case_id
            assert len(case.members) >= 2, f"{case.case_id} is not a group"
            # The label must be reachable by the committed matcher from the members the prompt
            # carries — otherwise the case is unanswerable and its recall is permanently zero.
            titles = " ".join(member[2] for member in case.members)
            assert match_root_cause(titles) == key, case.case_id


def test_a_case_id_never_leaks_its_label_into_the_prompt(cases: tuple | None = None) -> None:
    """The correlate trigger must identify a group, not name the answer it is scored against."""
    cases = load_cases(CASES)
    for case in cases:
        if case.stage != "correlate":
            continue
        for key in ROOT_CAUSE_KEYWORDS.values():
            assert key not in case.asset, f"{case.case_id}: the asset names the root cause"
        for member in case.members:
            for key in ROOT_CAUSE_KEYWORDS.values():
                assert key.replace("-", " ") not in member[0], case.case_id
