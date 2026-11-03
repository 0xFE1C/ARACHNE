"""The provider parity matrix: seven adapters, measured the same way (REQ-AGENT-010).

Seven adapters have shipped since S9 and had never been compared. A provider swap was an act of
faith: the OpenAI-compatible path was well exercised, and whether ``ollama``'s ``format`` field, a
Gemini ``responseSchema``, an Anthropic ``emit`` tool or an operator's ``custom`` mapping carried
the *stage* contract — a schema-valid answer that cites its evidence — was not written down
anywhere.

This module writes it down. For each adapter it runs the same evaluation suite
(:mod:`arachne.ai.eval`) through that adapter's **real** ``plan``/``interpret`` code: the request
is built by the adapter, the scripted responder's answer is encoded in that provider's own wire
shape, and the adapter parses it back. No socket is opened — the encoding is the only stand-in —
so everything on either side of it is the shipped code path, and the matrix says what each adapter
does with a stage request and a provider answer.

What the matrix records, per adapter and per stage:

``mechanism``
    The structured-output mechanism that adapter chose for that stage's schema
    (``json_schema``, ``tool_use``, ``response_schema``, ``format_schema``, ``custom``). This is
    the half of "provider parity" a score cannot show.
``constrained``
    Whether that mechanism constrains *decoding* at the provider, or merely asks the model for
    JSON. A deployment comparing two adapters needs this difference stated, not averaged away.
``supported`` / ``precision`` / ``recall``
    Whether the adapter carried the stage contract, and the suite's per-stage scores.
``unsupported, with a reason``
    An adapter that cannot satisfy a stage says so. The ``custom`` adapter without an
    operator-supplied ``extra.request_template``/``response_path`` cannot even *plan* a request,
    and the matrix reports that as unsupported with the adapter's own refusal rather than as a low
    score.

**No credential is used or fabricated.** Each profile is a :class:`ResolvedProvider` built with
``api_key=None``: nothing here opens a socket (the encoding transport raises if it is ever asked
to), so a real key would buy nothing, and inventing a placeholder would put a credential-shaped
literal in the tree for no reason. The ``requires`` column is where the real requirement is
stated, per adapter, for an operator.

The committed artefacts are ``docs/ai-provider-matrix.json`` (what the parity test compares) and
``docs/ai-provider-matrix.md`` (what a human reads), both carrying the date and the fixture
version they were produced against — which is the point of the exercise: a matrix without those
two facts is a claim, not evidence.

Regenerate (the date is an argument, never read from the clock, so a re-run is reproducible)::

    python -m arachne.ai.parity --cases tests/eval/fixtures/ai-eval-cases-v1.jsonl \\
        --fixture-version v1 --date 2026-11-04 --format json > docs/ai-provider-matrix.json
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Final

from arachne.ai.config import ADAPTERS, ResolvedProvider
from arachne.ai.eval import (
    EVALUATED_STAGES,
    EvalCase,
    ScriptedResponder,
    corpus_sha256,
    load_cases,
    run_suite,
)
from arachne.ai.prompts import PromptStore, load_prompt_store
from arachne.ai.providers.base import HttpProvider
from arachne.ai.providers.registry import build_provider
from arachne.ai.stages import SCHEMAS
from arachne.ai.types import (
    CompletionRequest,
    CompletionResult,
    ProviderError,
    ResponseFormat,
    TransportResponse,
    Usage,
)

__all__ = [
    "CONSTRAINED_MECHANISMS",
    "MATRIX_DOCUMENT",
    "PROFILES",
    "AdapterProfile",
    "build_matrix",
    "known_limitations",
    "main",
    "render_markdown",
    "run_adapter",
]

#: The matrix document's identity (what a reader greps for).
MATRIX_DOCUMENT: Final = "arachne-ai-provider-matrix"

#: Mechanisms that constrain decoding *at the provider* rather than asking nicely for JSON. This
#: is the column that makes the matrix worth reading: two adapters can both score 100% while only
#: one of them has a shape guarantee behind the answer.
CONSTRAINED_MECHANISMS: Final[frozenset[str]] = frozenset(
    {"json_schema", "tool_use", "response_schema", "format_schema", "guided_json"}
)

#: Requests per second for the in-process run. The adapters' own token bucket is there to pace a
#: real endpoint; pacing a run that makes no request would only make the matrix slow to produce.
_RUN_REQUESTS_PER_SECOND: Final = 100_000


@dataclass(frozen=True, slots=True)
class AdapterProfile:
    """One adapter, configured the way its documentation says to configure it."""

    adapter: str
    base_url: str
    model: str
    requires: str
    #: Extra configuration this adapter needs to plan a request at all (``custom``).
    extra: Mapping[str, Any] = field(default_factory=dict)
    #: True for the *deliberately* unconfigured case, so the matrix documents the refusal instead
    #: of hiding it behind a compatibility shim.
    unconfigured: bool = False

    def config(self) -> ResolvedProvider:
        """The adapter's provider configuration, with no credential (see the module docstring)."""
        return ResolvedProvider(
            name=self.adapter,
            base_url=self.base_url.rstrip("/"),
            model=self.model,
            api_key=None,
            requests_per_second=_RUN_REQUESTS_PER_SECOND,
            extra=dict(self.extra),
        )


#: The seven adapters plus one deliberate negative: ``custom`` without its mapping.
PROFILES: Final[tuple[AdapterProfile, ...]] = (
    AdapterProfile(
        adapter="openai",
        base_url="https://api.openai.com/v1",
        model="gpt-4o-mini",
        requires="OPENAI_API_KEY in the environment",
    ),
    AdapterProfile(
        adapter="openai_compatible",
        base_url="https://vllm.internal/v1",
        model="Qwen/Qwen3-32B",
        requires="an operator-supplied base_url (vLLM, LM Studio, llama.cpp, Azure, Groq, ...)",
    ),
    AdapterProfile(
        adapter="anthropic",
        base_url="https://api.anthropic.com",
        model="claude-sonnet-4-5",
        requires="ANTHROPIC_API_KEY in the environment",
    ),
    AdapterProfile(
        adapter="gemini",
        base_url="https://generativelanguage.googleapis.com",
        model="gemini-2.5-pro",
        requires="GEMINI_API_KEY in the environment (or an ADC proxy in front of the API)",
    ),
    AdapterProfile(
        adapter="ollama",
        base_url="http://localhost:11434",
        model="qwen3:32b",
        requires="nothing — the fully local path; a non-loopback base_url must be declared",
    ),
    AdapterProfile(
        adapter="mistral",
        base_url="https://api.mistral.ai/v1",
        model="mistral-large-latest",
        requires="MISTRAL_API_KEY in the environment",
    ),
    AdapterProfile(
        adapter="custom",
        base_url="https://gateway.internal/v2/analyse",
        model="house-model",
        requires=(
            "extra.request_template and extra.response_path (a user-defined JSON mapping for an "
            "API format ARACHNE does not know)"
        ),
        extra={
            "request_template": {"model": "{{model}}", "prompt": "{{prompt}}"},
            "response_path": "output.text",
        },
    ),
    AdapterProfile(
        adapter="custom",
        base_url="https://gateway.internal/v2/analyse",
        model="house-model",
        requires="extra.request_template and extra.response_path",
        unconfigured=True,
    ),
)


def known_limitations() -> Mapping[str, str]:
    """What each adapter cannot do, in one sentence, for the matrix's notes column."""
    return {
        "custom": (
            "Cannot plan or interpret anything without an operator-supplied request_template and "
            "response_path: the adapter is the documented escape hatch for an unknown API format, "
            "so it has no default shape to fall back on. Unconfigured, every stage is refused "
            "before a request is built — see the 'unconfigured' row."
        ),
        "openai_compatible": (
            "Has no default base_url: a deployment must name the endpoint, because 'compatible' is "
            "a family, not a service. Structured output depends on what the endpoint supports — "
            "the adapter degrades json_schema to guided_json, json_object, then plain text, and "
            "records which one it used."
        ),
        "ollama": (
            "Unreachable without a declared local endpoint; the default is loopback only, so a "
            "remote Ollama is refused unless the operator says so. 'format' as a schema is a "
            "newer-server feature: on an old server the field is ignored and the answer is only as "
            "structured as the model is."
        ),
        "gemini": (
            "responseSchema is Google's OpenAPI subset, so a schema keyword outside that subset is "
            "dropped before the request is sent rather than sent and rejected."
        ),
        "anthropic": (
            "Constrains through a single forced tool rather than a response_format; an old pinned "
            "API version may not support tool_choice at all."
        ),
        "openai": "Requires a credential; the endpoint's JSON-schema support is model-dependent.",
        "mistral": "Requires a credential; the adapter is OpenAI-shaped but the endpoint is not.",
    }


class EncodingTransport:
    """A transport that answers in the adapter's own wire shape, from a scripted responder.

    It is the seam the matrix turns on: the adapter builds a real request, this encodes a real
    answer *as that provider would send it*, and the adapter parses it back. Nothing on our side of
    the wire is mocked and no socket is opened — the encoding is the only stand-in.
    """

    def __init__(self, adapter: str, responder: ScriptedResponder) -> None:
        self.adapter = adapter
        self.responder = responder
        self.calls = 0

    async def post_json(
        self,
        url: str,
        payload: Mapping[str, Any],
        *,
        headers: Mapping[str, Any] | None = None,
        timeout_s: float | None = None,
    ) -> TransportResponse:
        raise AssertionError("the parity matrix must not open a connection")

    async def aclose(self) -> None:
        return None

    async def answer(self, request: CompletionRequest) -> TransportResponse:
        """The provider's own response shape, carrying the scripted answer."""
        self.calls += 1
        result = await self.responder.complete(request)
        return _encode(self.adapter, result)


class AdapterProvider:
    """An ``LLMProvider`` that routes one call through an adapter's plan/interpret pair."""

    def __init__(self, adapter: str, provider: HttpProvider, transport: EncodingTransport) -> None:
        self.adapter = adapter
        self.provider = provider
        self.transport = transport
        self.name = adapter
        self.model = provider.model
        self.mechanisms: set[str] = set()

    async def complete(self, request: CompletionRequest) -> CompletionResult:
        call = self.provider.plan(request)
        self.mechanisms.add(call.mechanism)
        response = await self.transport.answer(request)
        data = response.json()
        text, usage = self.provider.interpret(data, call, request)
        return CompletionResult(
            text=text,
            raw=dict(data) if isinstance(data, Mapping) else {},
            usage=usage,
            model=request.model or self.model,
            mechanism=call.mechanism,
            attempts=1,
            latency_ms=0.0,
        )


def probe_request(stage: str = "triage") -> CompletionRequest:
    """A minimal, valid request for one stage — how an adapter is asked whether it can *plan*."""
    return CompletionRequest(
        model="probe-model",
        system="You are a probe.",
        messages=({"role": "user", "content": "probe"},),
        response_format=ResponseFormat.JSON_SCHEMA,
        json_schema=SCHEMAS[stage].json_schema,
        max_tokens=64,
        temperature=0.0,
        timeout_s=1.0,
    )


def run_adapter(
    profile: AdapterProfile,
    cases: Sequence[EvalCase],
    *,
    prompts: PromptStore | None = None,
    fixture_version: str = "v1",
    corpus_digest: str = "",
) -> dict[str, Any]:
    """Run the evaluation suite through one adapter and summarise the outcome."""
    transport = EncodingTransport(profile.adapter, ScriptedResponder())
    adapter = AdapterProvider(
        profile.adapter,
        build_provider(profile.config(), transport, name=profile.adapter),
        transport,
    )
    row: dict[str, Any] = {
        "adapter": profile.adapter,
        "configuration": "unconfigured" if profile.unconfigured else "documented",
        "requires": profile.requires,
        "limitation": known_limitations().get(profile.adapter, ""),
        "mechanisms": [],
        "stages": {},
    }
    refusal = _refusal(adapter)
    if refusal is not None:
        # The honest "cannot satisfy this stage" outcome: the adapter refused to build (or read)
        # the request at all, so there is no score to report — only the adapter's own reason.
        row["reason"] = refusal
        row["stages"] = {
            stage: {
                "supported": False,
                "reason": refusal,
                "mechanism": "",
                "constrained": False,
            }
            for stage in EVALUATED_STAGES
        }
        return row
    report = run_suite(
        cases,
        provider=adapter,
        prompts=prompts,
        fixture_version=fixture_version,
        corpus_digest=corpus_digest,
    )
    row["mechanisms"] = sorted(adapter.mechanisms)
    row["stages"] = {
        score.stage: {
            "supported": score.answered > 0,
            "mechanism": ",".join(sorted(adapter.mechanisms)),
            "constrained": bool(set(adapter.mechanisms) & CONSTRAINED_MECHANISMS),
            "cases": score.cases,
            "answered": score.answered,
            "precision": round(score.precision, 6),
            "recall": round(score.recall, 6),
            "accuracy": round(score.accuracy, 6),
            "reason": "" if score.answered else "no stage answer survived the stage contract",
        }
        for score in report.stages
    }
    row["prompt_corpus"] = report.prompt_corpus
    return row


def build_matrix(
    cases: Sequence[EvalCase],
    *,
    fixture_version: str,
    corpus_digest: str,
    date: str,
) -> dict[str, Any]:
    """The whole matrix document (one row per profile, adapters first, the negative last)."""
    prompts = load_prompt_store(stages=tuple(sorted({case.stage for case in cases})))
    rows = [
        run_adapter(
            profile,
            cases,
            prompts=prompts,
            fixture_version=fixture_version,
            corpus_digest=corpus_digest,
        )
        for profile in PROFILES
    ]
    return {
        "document": MATRIX_DOCUMENT,
        "version": "1.0",
        "date": date,
        "fixture_version": fixture_version,
        "corpus_sha256": corpus_digest,
        "prompt_corpus": prompts.version,
        "cases": len(cases),
        "adapters": list(ADAPTERS),
        "stages": list(EVALUATED_STAGES),
        "rows": rows,
    }


def render_markdown(matrix: Mapping[str, Any]) -> str:
    """The human-readable matrix: one table, then the notes that make it readable."""
    stages = [str(item) for item in matrix.get("stages") or EVALUATED_STAGES]
    adapters = ", ".join(f"`{item}`" for item in matrix.get("adapters") or [])
    lines = [
        "# AI provider parity matrix",
        "",
        "Generated by `python -m arachne.ai.parity` — **do not edit by hand**; "
        "`tests/parity/test_provider_matrix.py` regenerates it and fails on a difference.",
        "",
        f"- **Date:** {matrix.get('date')}",
        f"- **Fixture version:** `{matrix.get('fixture_version')}` "
        f"(corpus sha256 `{str(matrix.get('corpus_sha256'))[:16]}…`, {matrix.get('cases')} cases)",
        f"- **Prompt corpus:** `{matrix.get('prompt_corpus')}`",
        f"- **Adapters covered:** {adapters}",
        "",
        "Every row is the same evaluation suite "
        "([`ai/eval.py`](../src/arachne/ai/eval.py)) run through that adapter's real "
        "`plan`/`interpret` code with a scripted provider — no network, no API key. "
        "`precision`/`recall` per stage are the suite's own metrics; `constrained` says whether "
        "the mechanism that adapter chose makes the provider enforce the answer's shape, or "
        "merely asks for JSON. An adapter that cannot satisfy a stage says so instead of "
        "degrading silently.",
        "",
        "| Adapter | Configuration | " + " | ".join(stages) + " | Mechanisms |",
        "|---|---|" + "---|" * len(stages) + "---|",
    ]
    for row in matrix.get("rows") or []:
        cells = []
        for stage in stages:
            entry = (row.get("stages") or {}).get(stage) or {}
            if entry.get("supported"):
                cells.append(
                    f"P {_percent(entry.get('precision'))} / R {_percent(entry.get('recall'))}"
                )
            else:
                cells.append("**unsupported**")
        lines.append(
            f"| `{row.get('adapter')}` | {row.get('configuration')} | "
            + " | ".join(cells)
            + f" | {', '.join(row.get('mechanisms') or []) or '—'} |"
        )
    lines.extend(["", "## What each adapter requires, and what it cannot do", ""])
    for row in matrix.get("rows") or []:
        lines.append(f"### `{row.get('adapter')}` ({row.get('configuration')})")
        lines.append("")
        lines.append(f"- **Requires:** {row.get('requires')}")
        if row.get("limitation"):
            lines.append(f"- **Limitation:** {row.get('limitation')}")
        if row.get("reason"):
            lines.append(f"- **Refused:** {row.get('reason')}")
        for stage in stages:
            entry = (row.get("stages") or {}).get(stage) or {}
            if not entry.get("supported"):
                lines.append(f"- **{stage}:** unsupported — {entry.get('reason') or 'no answer'}")
            else:
                enforcement = (
                    "decode-constrained" if entry.get("constrained") else "asked, not enforced"
                )
                lines.append(
                    f"- **{stage}:** supported via `{entry.get('mechanism') or 'n/a'}`"
                    f" ({enforcement}) — {entry.get('answered')}/{entry.get('cases')} answered, "
                    f"accuracy {_percent(entry.get('accuracy'))}"
                )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def main(argv: Sequence[str] | None = None) -> int:
    """``python -m arachne.ai.parity`` — emit the matrix as JSON or Markdown on stdout."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--cases", required=True)
    parser.add_argument("--fixture-version", default="v1")
    parser.add_argument(
        "--date", required=True, help="The date to record (never read from a clock)."
    )
    parser.add_argument("--format", choices=("json", "md"), default="json")
    args = parser.parse_args(list(argv) if argv is not None else None)

    cases = load_cases(args.cases)
    matrix = build_matrix(
        cases,
        fixture_version=args.fixture_version,
        corpus_digest=corpus_sha256(args.cases),
        date=args.date,
    )
    if args.format == "md":
        sys.stdout.write(render_markdown(matrix))
    else:
        sys.stdout.write(json.dumps(matrix, indent=2, sort_keys=False) + "\n")
    return 0


def _refusal(adapter: AdapterProvider) -> str | None:
    """The adapter's own refusal to plan a stage request, or ``None`` when it can."""
    for stage in EVALUATED_STAGES:
        try:
            adapter.provider.plan(probe_request(stage))
        except ProviderError as exc:
            return _one_line(str(exc))
    return None


def _encode(adapter: str, result: CompletionResult) -> TransportResponse:
    """A provider-shaped response body carrying ``result``'s answer."""
    usage = result.usage or Usage()
    if adapter in {"openai", "openai_compatible", "mistral"}:
        body: dict[str, Any] = {
            "choices": [{"index": 0, "message": {"role": "assistant", "content": result.text}}],
            "usage": {
                "prompt_tokens": usage.prompt_tokens,
                "completion_tokens": usage.completion_tokens,
                "total_tokens": usage.total_tokens,
            },
        }
    elif adapter == "anthropic":
        body = {
            "content": [{"type": "tool_use", "name": "emit", "input": _maybe_json(result.text)}],
            "usage": {
                "input_tokens": usage.prompt_tokens,
                "output_tokens": usage.completion_tokens,
            },
        }
    elif adapter == "gemini":
        body = {
            "candidates": [{"content": {"parts": [{"text": result.text}]}}],
            "usageMetadata": {
                "promptTokenCount": usage.prompt_tokens,
                "candidatesTokenCount": usage.completion_tokens,
            },
        }
    elif adapter == "ollama":
        body = {
            "message": {"role": "assistant", "content": result.text},
            "prompt_eval_count": usage.prompt_tokens,
            "eval_count": usage.completion_tokens,
        }
    else:  # the custom adapter's path is whatever its configuration names
        body = {"output": {"text": result.text}}
    return TransportResponse(status=200, body=json.dumps(body), url="")


def _maybe_json(text: str) -> Any:
    try:
        return json.loads(text)
    except ValueError:
        return text


def _percent(value: Any) -> str:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return "n/a"
    return f"{float(value) * 100:.1f}%"


def _one_line(text: str) -> str:
    return " ".join(text.split())[:400]


if __name__ == "__main__":  # pragma: no cover - manual invocation
    raise SystemExit(main())
