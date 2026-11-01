"""Fixtures for the AI layer's tests: a scripted provider, a factory, and stage detection.

Three ideas keep the AI tests fast and honest:

* **The fake provider is an ``LLMProvider``**, not a mock of one of our classes. Everything
  above the adapter — the stage runner, the prompt store, the budget, the cache, the engine —
  therefore runs for real, and only the bytes are scripted.
* **A stage is identified by its output schema**, not by matching prompt text. The schema is
  what the engine and the provider agree on, so a test that renames a template cannot silently
  start answering the wrong stage.
* **A scripted provider can fail on purpose**: after N calls, with a chosen error, or with
  unparseable text. That is how the degradation tests drive the degradation path without a network.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from arachne.ai.budget import BudgetLedger
from arachne.ai.cache import RequestCache
from arachne.ai.config import AiConfig, ResolvedProvider, parse_ai_config
from arachne.ai.engine import AiEngine, AiPolicies
from arachne.ai.privacy import PrivacyMode, Redactor
from arachne.ai.prompts import PromptStore, load_prompt_store
from arachne.ai.reliability import RetryPolicy
from arachne.ai.stages import CANDIDATE_STAGES
from arachne.ai.types import (
    CompletionRequest,
    CompletionResult,
    ProviderError,
    ProviderUnavailableError,
    ResponseFormat,
    TransportResponse,
    Usage,
)
from arachne.analyzer.engine import HeuristicEngine

#: The stage each output schema belongs to, by a field only that stage's schema has.
_SCHEMA_HINTS: dict[str, str] = {
    "fp_likely": "triage",
    "key_facts": "explain",
    "steps": "remediate",
    "shared_root_cause": "correlate",
    "order": "prioritize",
    # S21: the agentic stage's schema is identified by its own field.
    "hypotheses": "hypothesize",
}


def stage_from_request(request: CompletionRequest) -> str:
    """Which stage ``request`` is for, read off its JSON schema (see the module docstring)."""
    schema = request.json_schema or {}
    properties = schema.get("properties") or {}
    keys = set(properties) if isinstance(properties, dict) else set()
    for hint, stage in _SCHEMA_HINTS.items():
        if hint in keys:
            return stage
    if "narrative" in keys:
        return "narrative"
    return "unknown"


#: A plausible, schema-valid answer for every stage.
DEFAULT_ANSWERS: dict[str, dict[str, Any]] = {
    "triage": {
        "severity": "critical",
        "confidence": 92,
        "fp_likely": False,
        "reason": "The evidence shows an exposed configuration file with live credentials.",
        "categories": ["exposure"],
    },
    "explain": {
        "summary": "The endpoint answered 200 with a body shaped like a secrets file.",
        "key_facts": ["status 200", "secret patterns detected"],
    },
    "remediate": {
        "summary": "Remove the file from the web root and rotate what it contained.",
        "steps": ["1. Deny dot-files at the web server.", "2. Rotate the exposed credentials."],
        "references": ["CWE-200"],
    },
    "narrative": {
        "narrative": "The deployment serves a configuration file from the web root.",
        "headline": "Configuration file exposed",
    },
    "correlate": {
        "title": "Exposed configuration plus an unauthenticated datastore",
        "reasoning": (
            "The configuration leak reveals the datastore credential the second finding needs."
        ),
        "shared_root_cause": "no configuration review before deployment",
        "severity": "critical",
    },
    "prioritize": {
        "order": ["first", "second"],
        "rationale": "Fix the credential exposure before the header hardening.",
    },
}


@dataclass
class FakeProvider:
    """An ``LLMProvider`` that answers from a dictionary, and can be made to fail."""

    name: str = "fake"
    model: str = "fake-model-1"
    answers: dict[str, dict[str, Any]] = field(default_factory=lambda: dict(DEFAULT_ANSWERS))
    calls: list[CompletionRequest] = field(default_factory=list)
    #: Raise an error from call number ``fail_after`` (1-based) onwards.
    fail_after: int | None = None
    #: Raise a non-transient error from call ``fail_after`` onwards (bad credential).
    fail_hard: bool = False
    #: Answer each call with this text instead of JSON (to exercise the repair path).
    raw_text: str | None = None
    #: Answer the first N calls with ``raw_text`` before behaving normally.
    garbage_calls: int = 0
    usage: Usage = field(default_factory=lambda: Usage(120, 40, 160, 0.0002))
    mechanism: str = "json_schema"
    latency_ms: float = 5.0

    @property
    def stages_called(self) -> list[str]:
        return [stage_from_request(request) for request in self.calls]

    async def complete(self, request: CompletionRequest) -> CompletionResult:
        self.calls.append(request)
        index = len(self.calls)
        if self.fail_after is not None and index >= self.fail_after:
            if self.fail_hard:
                raise ProviderError(
                    f"{self.name} rejected the credential", provider=self.name, transient=False
                )
            raise ProviderUnavailableError(f"{self.name} is down", provider=self.name)
        if self.garbage_calls and index <= self.garbage_calls:
            text = self.raw_text or "not json at all"
        elif self.raw_text is not None:
            text = self.raw_text
        else:
            stage = stage_from_request(request)
            answer = self.answers.get(stage)
            if answer is None:
                raise ProviderError(
                    f"{self.name} has no scripted answer for stage {stage!r}",
                    provider=self.name,
                    transient=False,
                )
            text = json.dumps(answer)
        return CompletionResult(
            text=text,
            raw={"scripted": True},
            usage=self.usage,
            model=request.model or self.model,
            mechanism=self.mechanism,
            latency_ms=self.latency_ms,
        )


@dataclass
class NullTransport:
    """A transport that fails if anything actually tries to send (the fake provider answers)."""

    calls: int = 0

    async def post_json(
        self,
        url: str,
        payload: Any,
        *,
        headers: Any = None,
        timeout_s: Any = None,
    ) -> TransportResponse:
        self.calls += 1
        raise AssertionError("the AI tests must not open a connection; inject a provider")

    async def aclose(self) -> None:
        return None


def ai_config(
    *,
    provider: str = "ollama",
    base_url: str = "http://localhost:11434",
    model: str = "fake-model-1",
    stages: tuple[str, ...] = CANDIDATE_STAGES,
    authoritative: tuple[str, ...] = (),
    privacy: str = "redact",
    correlate_threshold: int = 3,
    max_tokens: int = 200_000,
    max_cost_usd: float = 1.5,
) -> AiConfig:
    """A valid ``AiConfig`` for tests, with every knob spelled out."""
    return parse_ai_config(
        {
            "ai": {
                "engine": "ai",
                "default_provider": provider,
                "privacy": privacy,
                "stages": list(stages),
                "authoritative_checks": list(authoritative),
                "correlate_threshold": correlate_threshold,
                "budget": {
                    "max_tokens_per_scan": max_tokens,
                    "max_cost_usd": max_cost_usd,
                },
                "providers": {
                    provider: {"base_url": base_url, "model": model, "max_tokens": 300},
                },
            }
        }
    )


def resolved(config: AiConfig, env: dict[str, str] | None = None) -> ResolvedProvider:
    return config.provider(None, env or {})


def make_engine(
    *,
    provider: FakeProvider | None = None,
    config: AiConfig | None = None,
    prompts: PromptStore | None = None,
    ledger: BudgetLedger | None = None,
    cache: RequestCache | None = None,
    heuristic: HeuristicEngine | None = None,
    privacy: PrivacyMode | None = None,
    retry_policy: RetryPolicy | None = None,
    stages: tuple[str, ...] | None = None,
    authoritative: tuple[str, ...] = (),
) -> tuple[AiEngine, FakeProvider]:
    """An :class:`AiEngine` wired to a :class:`FakeProvider`, with everything real."""
    scripted = provider or FakeProvider()
    cfg = config or ai_config()
    effective_stages = stages if stages is not None else tuple(cfg.stages)
    policy = AiPolicies(
        stages=effective_stages,
        authoritative_checks=authoritative or tuple(cfg.authoritative_checks),
        correlate_threshold=cfg.correlate_threshold,
    )
    engine = AiEngine(
        heuristic=heuristic or HeuristicEngine(),
        config=cfg,
        resolved=resolved(cfg),
        prompts=prompts or load_prompt_store(),
        ledger=ledger
        or BudgetLedger(
            max_tokens_per_scan=cfg.budget.max_tokens_per_scan,
            max_cost_usd=cfg.budget.max_cost_usd,
        ),
        transport=NullTransport(),
        provider_factory=lambda _transport: scripted,
        cache=cache,
        redactor=Redactor(mode=privacy or cfg.privacy),
        policies=policy,
        retry_policy=retry_policy or RetryPolicy(attempts=2, base_delay_s=0.0, jitter=0.0),
    )
    return engine, scripted


def triage_request(*, model: str = "test-model") -> CompletionRequest:
    """A complete ``triage`` call: the real schema, a fixed prompt, a fixed model.

    Shared by the cassette recorder and the replay test, so a recorded exchange matches the
    request the test makes without either side hand-copying the body.
    """
    from arachne.ai.stages import SCHEMAS

    return CompletionRequest(
        model=model,
        system="You are a triage analyst.",
        messages=(
            {
                "role": "user",
                "content": "[CONTEXT]\nscan: 1\n\n[TARGET_DATA]\n<delim>HTTP 200</delim>",
            },
        ),
        response_format=ResponseFormat.JSON_SCHEMA,
        json_schema=SCHEMAS["triage"].json_schema,
        max_tokens=321,
        temperature=0.0,
        timeout_s=12.0,
    )


def env_candidate(finding_id: int = 1, **overrides: Any) -> Any:
    """The M4 env-file candidate the parity harness also uses."""
    from arachne.analyzer.model import Candidate, EvidenceFact

    values: dict[str, Any] = {
        "scan_id": 1,
        "title": "Sensitive environment file exposed",
        "finding_id": finding_id,
        "check_id": "m4.env-file-probe",
        "check_module": "M4",
        "check_name": "env-file-probe",
        "research_ref": "ch04#1",
        "cwe": "CWE-200",
        "severity_hint": "high",
        "verifiable": True,
        "check_confidence": 80,
        "asset_kind": "url",
        "asset_value": "https://target.example/.env",
    }
    values.update(overrides)
    return Candidate(
        **values
        | {
            "evidence": (
                EvidenceFact(
                    "http_request",
                    {"method": "GET", "url": "https://target.example/.env"},
                    source="https://target.example/.env",
                ),
                EvidenceFact(
                    "http_response",
                    {
                        "status_code": 200,
                        "headers": {"content-type": "text/plain"},
                        "body": "DB_PASSWORD=[REDACTED:value]",
                    },
                    source="https://target.example/.env",
                ),
            )
        }
    )


def scan_context(*candidates: Any) -> Any:
    from arachne.analyzer.model import ScanContext, VerificationOutcome

    return ScanContext(
        scan_id=1,
        verification={
            candidate.key: VerificationOutcome(count=2, attempted=True, reproducible=True)
            for candidate in candidates
        },
    )
