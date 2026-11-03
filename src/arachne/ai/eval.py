"""The offline evaluation harness: what an AI stage change costs, measured (REQ-AGENT-009).

"AI found N bugs" is unfalsifiable — OSS-Fuzz carries no AI-attribution field, and a vendor's
accuracy claim is not evidence. The only thing that is evidence is a **controlled comparison on a
fixed corpus**: the same labelled cases, the same provider, before and after. This module is that
comparison, and it is deliberately offline: no network, no API key, no clock, no randomness, so
two runs of the same tree produce byte-identical reports.

The provider is injected and, in the shipped suite, is a *scripted responder* that answers by
reading the rendered prompt. That is the measurement's honest scope and it is worth stating
plainly: **this harness measures the pipeline's information fidelity, not a model's quality.**
The responder can only answer from what the prompt exposed, so a prompt change that drops the
evidence (or the citation vocabulary, or the deterministic verdict) shows up as a score drop —
which is exactly the class of regression a prompt edit causes. Whether a *particular* model is
good enough for a stage is a different question, and it is answered by the parity matrix
(``ai.parity``) and by the live-endpoint integration suite, not here.

Four properties the acceptance criteria name, and how each is met:

* **≥200 labelled cases, per stage.** The corpus is one JSON object per line
  (``cases-vN.jsonl``), each case labelled for exactly one of ``triage``, ``correlate`` or
  ``narrative``. :func:`run_suite` reports precision, recall and accuracy *per stage* — never
  one number, because one number is how "AI found N bugs" started.
* **Versioned and held out.** The corpus is a committed fixture with a version, a sha256 pinned
  in the baseline, and a published labelling rule table (the module docstring of
  :mod:`arachne.ai.eval_corpus` is that table). A prompt was never developed against it: the
  labels come from the case data and the check catalogue, not from anything a prompt author
  reads. Rotating the corpus means emitting a new ``cases`` file with a new version and
  re-baselining it in one reviewed act — which the pinned hash forces.
* **A regression beyond the threshold fails.** :func:`gate` compares a report with the committed
  baseline and reports every metric that fell by more than
  :data:`REGRESSION_THRESHOLD`; ``tests/eval/test_gate.py`` fails the suite on it.
* **A degraded prompt is caught.** The same test re-runs the suite over a deliberately degraded
  prompt corpus (``tests/eval/degraded/``: the target-data block and the citation vocabulary
  removed) and asserts the gate rejects it — a gate that cannot fail on the case it exists for
  is worse than no gate.

Run it by hand::

    python -m arachne.ai.eval --cases tests/eval/fixtures/ai-eval-cases-v1.jsonl \\
        --baseline tests/eval/fixtures/ai-eval-baseline-v1.json --check
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

from arachne.ai.budget import BudgetLedger
from arachne.ai.config import ResolvedProvider, parse_ai_config
from arachne.ai.engine import AiEngine, AiPolicies
from arachne.ai.prompts import PromptStore, load_prompt_store
from arachne.ai.reliability import RetryPolicy
from arachne.ai.stages import CITATION_LINE_PREFIX, STAGES
from arachne.ai.types import (
    CompletionRequest,
    CompletionResult,
    LlmTransport,
    TransportResponse,
    Usage,
)
from arachne.analyzer.engine import HeuristicEngine
from arachne.analyzer.model import Candidate, EvidenceFact, ScanContext

__all__ = [
    "DEFAULT_THRESHOLD",
    "EVALUATED_STAGES",
    "REGRESSION_THRESHOLD",
    "EvalCase",
    "EvalReport",
    "GateResult",
    "Regression",
    "ScriptedResponder",
    "StageScore",
    "compare_to_baseline",
    "corpus_sha256",
    "gate",
    "load_cases",
    "main",
    "run_suite",
]

#: The stages the suite reports on (REQ-AGENT-009 names exactly these three).
EVALUATED_STAGES: Final[tuple[str, ...]] = ("triage", "correlate", "narrative")

#: How far a metric may fall before the gate fails. Two percentage points: below that, a single
#: case flapping on a corpus of 240 could fail a build for no change in behaviour, and any real
#: prompt regression moves these metrics by far more than that.
REGRESSION_THRESHOLD: Final[float] = 0.02

#: The threshold the CLI uses unless told otherwise.
DEFAULT_THRESHOLD: Final[float] = REGRESSION_THRESHOLD

#: The severity vocabulary, so a scripted responder and a label agree on one order.
_SEVERITY_ORDER: Final[tuple[str, ...]] = ("info", "low", "medium", "high", "critical")


# --------------------------------------------------------------------------- corpus


@dataclass(frozen=True, slots=True)
class EvalCase:
    """One labelled evaluation case: a candidate, its group (for ``correlate``) and a label."""

    case_id: str
    stage: str
    check_id: str
    module: str
    title: str
    cwe: str | None
    severity_hint: str
    asset: str
    evidence: tuple[Mapping[str, Any], ...] = ()
    label: Mapping[str, Any] = field(default_factory=dict)
    #: ``correlate`` cases only: the group's members as ``(label, severity, title)``.
    members: tuple[tuple[str, str, str], ...] = ()

    def candidate(self) -> Candidate:
        """The analyzer input this case describes (evidence ids are the case's own)."""
        return Candidate(
            scan_id=1,
            title=self.title,
            finding_id=1,
            check_id=self.check_id,
            check_module=self.module,
            check_name=self.check_id.split(".", 1)[-1],
            cwe=self.cwe,
            severity_hint=self.severity_hint,
            check_confidence=70.0,
            asset_kind="url",
            asset_value=self.asset,
            evidence=tuple(
                EvidenceFact(
                    kind=str(item.get("kind") or "note"),
                    payload=dict(item.get("payload") or {}),
                    source=_string_or_none(item.get("source")),
                    id=int(item["id"]) if item.get("id") is not None else None,
                )
                for item in self.evidence
            ),
        )

    def evidence_ids(self) -> tuple[str, ...]:
        return tuple(str(item["id"]) for item in self.evidence if item.get("id") is not None)


def load_cases(path: str | Path) -> tuple[EvalCase, ...]:
    """Load a ``cases-vN.jsonl`` corpus (one case per line, stable order)."""
    resolved = Path(path)
    cases: list[EvalCase] = []
    for number, line in enumerate(resolved.read_text(encoding="utf-8").splitlines(), start=1):
        text = line.strip()
        if not text or text.startswith("//"):
            continue
        payload = json.loads(text)
        if not isinstance(payload, Mapping):
            msg = f"{resolved}:{number}: expected a JSON object"
            raise ValueError(msg)
        stage = str(payload.get("stage") or "")
        if stage not in EVALUATED_STAGES:
            msg = f"{resolved}:{number}: stage {stage!r} is not one of {list(EVALUATED_STAGES)}"
            raise ValueError(msg)
        cases.append(
            EvalCase(
                case_id=str(payload.get("case_id") or f"case-{number}"),
                stage=stage,
                check_id=str(payload.get("check_id") or "unknown.check"),
                module=str(payload.get("module") or "M?"),
                title=str(payload.get("title") or ""),
                cwe=_string_or_none(payload.get("cwe")),
                severity_hint=str(payload.get("severity_hint") or "medium"),
                asset=str(payload.get("asset") or "https://target.example"),
                evidence=tuple(
                    dict(item)
                    for item in payload.get("evidence") or ()
                    if isinstance(item, Mapping)
                ),
                label=dict(payload.get("label") or {}),
                members=tuple(
                    (str(member[0]), str(member[1]), str(member[2]))
                    for member in payload.get("members") or ()
                    if isinstance(member, (list, tuple)) and len(member) == 3
                ),
            )
        )
    return tuple(cases)


def corpus_sha256(path: str | Path) -> str:
    """The digest of the corpus file — the value the baseline pins (REQ-AGENT-009's versioning)."""
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


# --------------------------------------------------------------------------- report


@dataclass(frozen=True, slots=True)
class StageScore:
    """One stage's measured behaviour on the corpus."""

    stage: str
    cases: int
    answered: int
    labelled_positives: int
    predicted_positives: int
    true_positives: int
    correct: int
    precision: float
    recall: float
    accuracy: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "stage": self.stage,
            "cases": self.cases,
            "answered": self.answered,
            "labelled_positives": self.labelled_positives,
            "predicted_positives": self.predicted_positives,
            "true_positives": self.true_positives,
            "correct": self.correct,
            "precision": round(self.precision, 6),
            "recall": round(self.recall, 6),
            "accuracy": round(self.accuracy, 6),
        }


@dataclass(frozen=True, slots=True)
class EvalReport:
    """The suite's result: one :class:`StageScore` per stage, plus the fixture's identity."""

    fixture_version: str
    corpus_sha256: str
    prompt_corpus: str
    stages: tuple[StageScore, ...]
    cases: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "fixture_version": self.fixture_version,
            "corpus_sha256": self.corpus_sha256,
            "prompt_corpus": self.prompt_corpus,
            "cases": self.cases,
            "stages": [score.to_dict() for score in self.stages],
        }

    def score(self, stage: str) -> StageScore | None:
        for candidate in self.stages:
            if candidate.stage == stage:
                return candidate
        return None

    def metrics(self) -> dict[str, float]:
        """Every measured number, keyed ``<stage>.<metric>`` (what the gate compares)."""
        out: dict[str, float] = {}
        for score in self.stages:
            out[f"{score.stage}.precision"] = score.precision
            out[f"{score.stage}.recall"] = score.recall
            out[f"{score.stage}.accuracy"] = score.accuracy
        return out


@dataclass(frozen=True, slots=True)
class Regression:
    """One metric that fell further than the threshold allows."""

    metric: str
    baseline: float
    current: float

    @property
    def drop(self) -> float:
        return self.baseline - self.current

    def __str__(self) -> str:
        return f"{self.metric}: {self.baseline:.4f} → {self.current:.4f} (-{self.drop:.4f})"


@dataclass(frozen=True, slots=True)
class GateResult:
    """The gate's verdict: whether this report regressed against the committed baseline."""

    passed: bool
    threshold: float
    regressions: tuple[Regression, ...] = ()
    mismatches: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "threshold": self.threshold,
            "regressions": [
                {
                    "metric": item.metric,
                    "baseline": round(item.baseline, 6),
                    "current": round(item.current, 6),
                    "drop": round(item.drop, 6),
                }
                for item in self.regressions
            ],
            "mismatches": list(self.mismatches),
        }

    def summary(self) -> str:
        if self.passed:
            return f"evaluation gate passed (threshold {self.threshold:.2f})"
        lines = [f"evaluation gate FAILED (threshold {self.threshold:.2f})"]
        lines.extend(f"  {item}" for item in self.regressions)
        lines.extend(f"  {item}" for item in self.mismatches)
        return "\n".join(lines)


# --------------------------------------------------------------------------- the suite


class OfflineTransport:
    """A transport that refuses: the evaluation suite never opens a connection (REQ-AGENT-009)."""

    calls: int = 0

    async def post_json(
        self,
        url: str,
        payload: Mapping[str, Any],
        *,
        headers: Mapping[str, Any] | None = None,
        timeout_s: float | None = None,
    ) -> TransportResponse:
        self.calls += 1
        msg = "the evaluation suite must not open a connection; inject a scripted provider"
        raise AssertionError(msg)

    async def aclose(self) -> None:
        return None


#: A ``notable`` marker in a rendered evidence line, e.g. ``notable=live-credential-exposed``.
_NOTABLE_RE: Final = re.compile(r"notable=([a-z0-9][a-z0-9_-]*)")

#: A response status in a rendered evidence line, e.g. ``status_code=200``.
_STATUS_RE: Final = re.compile(r"status_code=(\d{3})")

#: The delimited untrusted block a rendered prompt carries (``ai.prompts.wrap_target_data``).
_TARGET_BLOCK_RE: Final = re.compile(r"<delim>\n?(.*?)\n?</delim>", re.DOTALL)

#: The line offering the citable evidence ids (``ai.stages.CITATION_LINE_PREFIX``).
_CITATION_RE: Final = re.compile(re.escape(CITATION_LINE_PREFIX) + r"\s*([^\n]*)")
_EVIDENCE_ID_RE: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]*")

#: The schema field that identifies each stage (the same rule ``tests.helpers.ai`` uses — the
#: schema is the contract, not the prompt text).
_STAGE_HINTS: Final[tuple[tuple[str, str], ...]] = (
    ("fp_likely", "triage"),
    ("shared_root_cause", "correlate"),
    ("key_facts", "explain"),
    ("steps", "remediate"),
)


@dataclass
class ScriptedResponder:
    """The corpus's scripted model: a deterministic function of the rendered prompt.

    It is an ``LLMProvider`` — nothing here mocks our own classes — and it answers the way the
    measurement needs it to: **from what the prompt exposed, and nothing else.** A severity bump
    happens only if the evidence marker that justifies it survived into the prompt; a citation is
    produced only if the citation line is there; a root cause is named only from the member lines
    the prompt carried. That is why a prompt regression moves the score: the responder has no
    other source of truth, so the score *is* a measurement of what the prompt conveyed.

    It is deliberately not a registered provider: it exists for the offline suite, it is not in
    ``ai.providers.registry``, and no configuration can select it.
    """

    name: str = "scripted-eval"
    model: str = "scripted-eval-1"
    calls: list[CompletionRequest] = field(default_factory=list)

    async def complete(self, request: CompletionRequest) -> CompletionResult:
        self.calls.append(request)
        stage = _stage_of(request)
        text = "\n".join(
            [request.system, *(str(message.get("content") or "") for message in request.messages)]
        )
        answer = self._answer(stage, text)
        return CompletionResult(
            text=json.dumps(answer),
            raw={"scripted": True},
            usage=Usage(prompt_tokens=_tokens(text), completion_tokens=40, total_tokens=0),
            model=request.model or self.model,
            mechanism="json_schema",
            latency_ms=0.0,
        )

    # ------------------------------------------------------------------ rules
    def _answer(self, stage: str, text: str) -> dict[str, Any]:
        citations = _citation_ids(text)
        # Everything a *judgement* rests on is read from the delimited target block: that is the
        # untrusted capture, and the context is our own claims about the check. A responder that
        # read the whole prompt could answer from the check's hint and never notice that the
        # capture was dropped — which is the regression the suite exists to catch.
        block = _target_block(text)
        notables = _notables(block)
        if stage == "triage":
            hint = _severity_hint(text)
            marker = notables[0] if notables else ""
            fp_likely = marker in {"access-denied-response", "default-placeholder-page"}
            severity = "info" if fp_likely else _escalate(hint, marker == "live-credential-exposed")
            return {
                "severity": severity,
                "confidence": 40 if fp_likely else 90,
                "fp_likely": fp_likely,
                "reason": f"the capture shows {marker or 'no distinguishing marker'}",
                "categories": [],
                "evidence_ids": citations,
            }
        if stage == "narrative":
            facts = [*notables, *(f"status {code}" for code in _status_codes(block))]
            shown = ", ".join(facts) or "nothing distinctive"
            return {
                "narrative": (
                    f"The capture for this finding shows {shown}. It remains as the scanner "
                    "reported it."
                ),
                "headline": "Finding described from the captured evidence",
                "evidence_ids": citations,
            }
        if stage == "correlate":
            keyword = _first_keyword(block)
            cause = f"a shared {keyword} weakness across this host" if keyword else ""
            return {
                "title": "Compounding findings on one host",
                "reasoning": "The members share one underlying weakness.",
                "shared_root_cause": cause,
                "severity": None,
                "evidence_ids": citations,
            }
        return {"summary": "not evaluated", "key_facts": [], "evidence_ids": citations}


def _stage_of(request: CompletionRequest) -> str:
    schema = request.json_schema or {}
    properties = schema.get("properties") or {}
    keys = set(properties) if isinstance(properties, dict) else set()
    for hint, stage in _STAGE_HINTS:
        if hint in keys:
            return stage
    if "narrative" in keys:
        return "narrative"
    return "unknown"


def _target_block(text: str) -> str:
    """The content of the prompt's delimited target block (``""`` when the prompt has none)."""
    match = _TARGET_BLOCK_RE.search(text)
    return match.group(1) if match else ""


def _notables(text: str) -> list[str]:
    return list(dict.fromkeys(_NOTABLE_RE.findall(text)))


def _status_codes(text: str) -> list[str]:
    """Every ``status_code=N`` the prompt showed (the second narrative fact a case labels)."""
    return list(dict.fromkeys(_STATUS_RE.findall(text)))


def _citation_ids(text: str) -> list[str]:
    offered: list[str] = []
    for line in text.splitlines():
        match = _CITATION_RE.search(line)
        if match is None:
            continue
        for token in _EVIDENCE_ID_RE.findall(match.group(1)):
            if token not in offered:
                offered.append(token)
    return offered[:2]


def _severity_hint(text: str) -> str:
    match = re.search(r"check severity hint:\s*([a-z]+)", text)
    return match.group(1) if match else "medium"


def _escalate(severity: str, bump: bool) -> str:
    if not bump:
        return severity
    try:
        index = _SEVERITY_ORDER.index(severity)
    except ValueError:
        return severity
    return _SEVERITY_ORDER[min(len(_SEVERITY_ORDER) - 1, index + 1)]


def _first_keyword(text: str) -> str:
    lowered = text.lower()
    for keyword in ROOT_CAUSE_KEYWORDS:
        if keyword in lowered:
            return keyword
    return ""


def _tokens(text: str) -> int:
    return len(text) // 4 + 1


def run_suite(
    cases: Sequence[EvalCase],
    *,
    provider: Any,
    prompts: PromptStore | None = None,
    fixture_version: str = "unversioned",
    corpus_digest: str = "",
    stages: Sequence[str] = EVALUATED_STAGES,
) -> EvalReport:
    """Run ``cases`` through the real engine and score every stage (REQ-AGENT-009).

    The engine, the runner, the prompt store, the schema validation and the citation contract are
    the shipped ones; only the provider is scripted. A stage answer that the engine refused (an
    uncited answer, a schema failure, a provider error) counts as *unanswered*: it is exactly the
    behaviour a regression produces, so folding it into a wrong answer would hide the difference
    between "the model was wrong" and "the pipeline dropped the answer".
    """
    store = prompts or load_prompt_store()
    engine = _build_engine(provider, store, stages=stages)
    outcomes: dict[str, list[tuple[EvalCase, Mapping[str, Any] | None]]] = {
        stage: [] for stage in stages
    }
    candidate_stages = tuple(
        stage for stage in stages if stage in {"triage", "narrative", "explain", "remediate"}
    )
    for case in cases:
        if case.stage in candidate_stages:
            answers = _run_candidate(engine, case)
            outcomes.setdefault(case.stage, []).append((case, answers.get(case.stage)))
        elif case.stage == "correlate":
            outcomes.setdefault("correlate", []).append((case, _run_correlate(engine, case)))
    scores = tuple(
        _score_stage(stage, outcomes.get(stage, []))
        for stage in EVALUATED_STAGES
        if stage in stages
    )
    return EvalReport(
        fixture_version=fixture_version,
        corpus_sha256=corpus_digest,
        prompt_corpus=store.version,
        stages=scores,
        cases=len(cases),
    )


def _build_engine(provider: Any, prompts: PromptStore, *, stages: Sequence[str]) -> AiEngine:
    """An :class:`AiEngine` over the shipped machinery and the scripted provider."""
    config = parse_ai_config(
        {
            "ai": {
                "engine": "ai",
                "default_provider": "ollama",
                "privacy": "redact",
                "stages": list(stages),
                "budget": {"max_tokens_per_scan": 0, "max_cost_usd": 0.0},
                "providers": {
                    "ollama": {
                        "base_url": "http://localhost:11434",
                        "model": "scripted-eval",
                        # The suite makes hundreds of scripted calls in a loop; the provider
                        # token bucket is for pacing a real endpoint, and pacing here would
                        # only make CI slower without measuring anything.
                        "requests_per_second": 100_000,
                    }
                },
            }
        }
    )
    resolved: ResolvedProvider = config.provider(None, {})
    transport: LlmTransport = OfflineTransport()
    return AiEngine(
        heuristic=HeuristicEngine(),
        config=config,
        resolved=resolved,
        prompts=prompts,
        ledger=BudgetLedger(max_tokens_per_scan=0, max_cost_usd=0.0),
        transport=transport,
        provider_factory=lambda _transport: provider,
        policies=AiPolicies(stages=tuple(stages), correlate_threshold=2),
        retry_policy=RetryPolicy(attempts=1, base_delay_s=0.0, jitter=0.0),
    )


def _run_candidate(engine: AiEngine, case: EvalCase) -> Mapping[str, Mapping[str, Any] | None]:
    """Analyse one candidate and return ``{stage: answer or None}`` for the scored stages."""
    import asyncio

    candidate = case.candidate()
    context = ScanContext(scan_id=1)
    analyses = asyncio.run(engine.analyze_async([candidate], context))
    if not analyses:
        return {}
    analysis = analyses[0]
    stages = analysis.ai.get("stages") if isinstance(analysis.ai, Mapping) else None
    payload = stages if isinstance(stages, Mapping) else {}
    return {str(name): dict(value) for name, value in payload.items() if isinstance(value, Mapping)}


def _run_correlate(engine: AiEngine, case: EvalCase) -> Mapping[str, Any] | None:
    """Run one correlation group and return the model's answer, or ``None``."""
    import asyncio

    if not case.members:
        return None
    suggestion = asyncio.run(
        engine.suggest_compound(
            host=case.asset,
            members=case.members,
            # Identity without the label: the case id names the theme, so using it would leak
            # the expected root cause into the prompt and make the metric meaningless.
            trigger=f"correlation.{case.asset}",
            evidence=case.evidence_ids(),
        )
    )
    if suggestion is None:
        return None
    return {
        "title": suggestion.title,
        "reasoning": suggestion.reasoning,
        "shared_root_cause": suggestion.shared_root_cause,
        "severity": suggestion.severity,
        "evidence_ids": list(suggestion.evidence_ids),
    }


# --------------------------------------------------------------------------- scoring


def _score_stage(
    stage: str, results: Sequence[tuple[EvalCase, Mapping[str, Any] | None]]
) -> StageScore:
    """Score one stage's outcomes against their labels (precision, recall, accuracy)."""
    answered = 0
    true_positives = 0
    labelled_positives = 0
    predicted_positives = 0
    correct = 0
    for case, value in results:
        if stage == "triage":
            predicted_positive, is_correct, labelled = _score_triage(case, value)
        elif stage == "narrative":
            predicted_positive, is_correct, labelled = _score_narrative(case, value)
        else:
            predicted_positive, is_correct, labelled = _score_correlate(case, value)
        if value is not None:
            answered += 1
        if labelled:
            labelled_positives += 1
        if predicted_positive:
            predicted_positives += 1
        if predicted_positive and labelled:
            true_positives += 1
        if is_correct:
            correct += 1
    total = len(results)
    return StageScore(
        stage=stage,
        cases=total,
        answered=answered,
        labelled_positives=labelled_positives,
        predicted_positives=predicted_positives,
        true_positives=true_positives,
        correct=correct,
        precision=_ratio(true_positives, predicted_positives),
        recall=_ratio(true_positives, labelled_positives),
        accuracy=_ratio(correct, total),
    )


def _score_triage(case: EvalCase, value: Mapping[str, Any] | None) -> tuple[bool, bool, bool]:
    """``triage``: a positive is "this finding must be reported as a real weakness"."""
    label = case.label
    labelled = not bool(label.get("fp_likely")) and str(label.get("severity")) != "info"
    if value is None:
        return False, False, labelled
    severity = str(value.get("severity") or "")
    fp_likely = bool(value.get("fp_likely"))
    predicted = not fp_likely and severity != "info"
    correct = severity == str(label.get("severity")) and fp_likely == bool(label.get("fp_likely"))
    return predicted, correct, labelled


def _score_narrative(case: EvalCase, value: Mapping[str, Any] | None) -> tuple[bool, bool, bool]:
    """``narrative``: a positive is "one required fact appears in the prose".

    The label lists the facts the narrative must carry (they are the observable markers of the
    evidence). Precision and recall are therefore micro-averaged over *facts*, not over cases —
    a narrative that says three of four true things is not the same as one that says one.
    """
    required = [str(item) for item in case.label.get("facts") or ()]
    labelled = bool(required)
    if value is None:
        return False, False, labelled
    text = str(value.get("narrative") or "").lower()
    present = [fact for fact in required if fact.lower() in text]
    predicted = bool(present)
    correct = len(present) == len(required) and bool(required)
    return predicted, correct, labelled


def _score_correlate(case: EvalCase, value: Mapping[str, Any] | None) -> tuple[bool, bool, bool]:
    """``correlate``: a positive is "the group's shared root cause was named correctly"."""
    expected = str(case.label.get("root_cause") or "")
    labelled = bool(expected)
    if value is None:
        return False, False, labelled
    observed = match_root_cause(str(value.get("shared_root_cause") or ""))
    predicted = observed is not None
    correct = observed == expected
    return predicted, correct, labelled


#: The committed keyword map that reads a root-cause key out of free text. Free prose has to be
#: mapped to a label somehow; a fixed, published table is the only way to do it that a reader can
#: check and that does not move when someone edits a prompt. A text the table cannot map counts
#: as a miss — never as a lucky match.
ROOT_CAUSE_KEYWORDS: Final[dict[str, str]] = {
    "configuration drift": "exposed-configuration",
    "credential exposure": "exposed-configuration",
    "unauthenticated datastore": "unauthenticated-datastore",
    "missing header": "missing-hardening",
    "tls version": "weak-transport",
    "legacy smb dialect": "legacy-protocol",
}


def match_root_cause(text: str) -> str | None:
    """Map free text onto a root-cause key, or ``None`` when the table cannot."""
    lowered = text.lower()
    for keyword, key in ROOT_CAUSE_KEYWORDS.items():
        if keyword in lowered:
            return key
    return None


def _ratio(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


# --------------------------------------------------------------------------- the gate


def compare_to_baseline(
    report: EvalReport,
    baseline: Mapping[str, Any],
    *,
    threshold: float = DEFAULT_THRESHOLD,
) -> GateResult:
    """Compare a report with a committed baseline (REQ-AGENT-009's CI gate).

    Three things can fail it:

    * a metric that fell by more than ``threshold``;
    * a corpus whose digest is not the baseline's — an evaluation set that changed under a fixed
      baseline measures nothing, so this is a hard error rather than a warning;
    * a baseline missing a metric the current run produces (a stage added without re-baselining).
    """
    mismatches: list[str] = []
    expected_digest = str(baseline.get("corpus_sha256") or "")
    if expected_digest and report.corpus_sha256 and expected_digest != report.corpus_sha256:
        mismatches.append(
            "corpus digest changed: the baseline was produced against a different evaluation set "
            f"({expected_digest[:12]}… vs {report.corpus_sha256[:12]}…); re-baseline deliberately"
        )
    expected_version = str(baseline.get("fixture_version") or "")
    if expected_version and expected_version != report.fixture_version:
        mismatches.append(
            f"fixture version changed: baseline {expected_version}, corpus {report.fixture_version}"
        )
    baseline_metrics = baseline.get("metrics")
    metrics = baseline_metrics if isinstance(baseline_metrics, Mapping) else {}
    regressions: list[Regression] = []
    current = report.metrics()
    for name, value in current.items():
        if name not in metrics:
            mismatches.append(f"baseline has no metric {name!r}; re-baseline the suite")
            continue
        was = _as_float(metrics[name])
        if was is None:
            continue
        if was - value > threshold:
            regressions.append(Regression(metric=name, baseline=was, current=value))
    return GateResult(
        passed=not regressions and not mismatches,
        threshold=threshold,
        regressions=tuple(regressions),
        mismatches=tuple(mismatches),
    )


def gate(
    report: EvalReport, baseline: Mapping[str, Any], *, threshold: float = DEFAULT_THRESHOLD
) -> GateResult:
    """``compare_to_baseline``, spelled for the gate's reader."""
    return compare_to_baseline(report, baseline, threshold=threshold)


def baseline_document(report: EvalReport, *, created: str) -> dict[str, Any]:
    """The document to commit as ``ai-eval-baseline-vN.json``.

    ``created`` is supplied by the caller and is *not* part of the measurement: the report has no
    clock in it, so two runs of the same tree are byte-identical (REQ-AGENT-009's determinism).
    """
    return {
        "document": "arachne-ai-eval-baseline",
        "version": "1.0",
        "created": created,
        "fixture_version": report.fixture_version,
        "corpus_sha256": report.corpus_sha256,
        "prompt_corpus": report.prompt_corpus,
        "cases": report.cases,
        "threshold": DEFAULT_THRESHOLD,
        "metrics": report.metrics(),
        "stages": [score.to_dict() for score in report.stages],
    }


def _as_float(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


# --------------------------------------------------------------------------- CLI


def main(argv: Sequence[str] | None = None) -> int:
    """``python -m arachne.ai.eval`` — run the suite, print the table, optionally gate."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--cases", required=True, help="The cases-vN.jsonl corpus.")
    parser.add_argument("--baseline", help="The committed baseline to compare against.")
    parser.add_argument("--prompts", help="An alternative prompt corpus directory.")
    parser.add_argument("--fixture-version", default="v1")
    parser.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD)
    parser.add_argument("--json", action="store_true", help="Print the report as JSON.")
    parser.add_argument("--check", action="store_true", help="Exit 1 on a regression.")
    parser.add_argument(
        "--emit-baseline",
        action="store_true",
        help=(
            "Print the baseline document on stdout instead of the report (redirect it into "
            "tests/eval/fixtures/ai-eval-baseline-vN.json). This harness writes no files: the AI "
            "package must import no filesystem-write primitive (REQ-AGENT-011)."
        ),
    )
    parser.add_argument("--created", default="", help="The date to record in the baseline.")
    args = parser.parse_args(list(argv) if argv is not None else None)

    cases = load_cases(args.cases)
    report = run_suite(
        cases,
        provider=ScriptedResponder(),
        prompts=load_prompt_store(args.prompts, stages=_prompt_stages(cases)),
        fixture_version=args.fixture_version,
        corpus_digest=corpus_sha256(args.cases),
    )
    if args.emit_baseline:
        document = baseline_document(report, created=args.created)
        sys.stdout.write(json.dumps(document, indent=2) + "\n")
        return 0
    if args.json:
        _emit(json.dumps(report.to_dict(), indent=2))
    else:
        _emit(_table(report))
    if not args.check or not args.baseline:
        return 0
    baseline = json.loads(Path(args.baseline).read_text(encoding="utf-8"))
    result = compare_to_baseline(report, baseline, threshold=args.threshold)
    _emit(result.summary())
    return 0 if result.passed else 1


def _emit(text: str) -> None:
    """Write one line to stdout (``print`` is banned in ``src``; a module CLI still needs out)."""
    sys.stdout.write(f"{text}\n")


def _prompt_stages(cases: Sequence[EvalCase]) -> tuple[str, ...]:
    wanted = {case.stage for case in cases}
    return tuple(stage for stage in STAGES if stage in wanted)


def _table(report: EvalReport) -> str:
    lines = [
        f"corpus {report.fixture_version} ({report.cases} cases, {report.corpus_sha256[:12]}…)",
        f"prompt corpus {report.prompt_corpus}",
        f"{'stage':12s} {'cases':>6s} {'answered':>9s} {'precision':>10s} "
        f"{'recall':>8s} {'accuracy':>9s}",
    ]
    for score in report.stages:
        lines.append(
            f"{score.stage:12s} {score.cases:6d} {score.answered:9d} "
            f"{score.precision:10.4f} {score.recall:8.4f} {score.accuracy:9.4f}"
        )
    return "\n".join(lines)


def _string_or_none(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


if __name__ == "__main__":  # pragma: no cover - manual invocation
    sys.exit(main())
