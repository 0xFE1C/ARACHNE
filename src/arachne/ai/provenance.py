"""The AI provenance record: what left the boundary, and what the model decided (REQ-AGENT-008).

The question a regulated customer has to be able to answer is not "did AI help?" but *"which
provider received which bytes, what did the model say, and what did that change about the
finding?"* (REQ-AGENT-008). Before WP-15 that was spread across
``analysis_log`` columns (engine, model, template version, prompt hash), the ``ai`` payload and
the audit trail — answerable, but only by joining three things and reading logs. This module is
the single value object that answers it from one row.

**The one invariant that is structural rather than asserted at a call site**: an ``ai``-origin
record cannot exist without at least one cited evidence id. It is enforced in
:meth:`ProvenanceRecord.__post_init__`, so every construction path — the engine, a store, a test,
a hand-written dict — hits the same refusal. The engine's half of the bargain is in
``ai.engine``: a stage answer whose citations resolve to no evidence the candidate actually has
is *not* an AI contribution, it is a failed stage, so it cannot produce an ``ai`` record either.
That is what makes "an AI row cannot exist without a cited evidence id" a property of the type
rather than a rule someone remembered to apply.

Two deliberate choices:

* **Tokens are per row, not per provider.** ``BudgetLedger`` answers "what has this scan spent",
  which is a different question from "what did *this* finding cost". The stage runner's usage is
  attributed to the analysis row that triggered it, so a per-project export can attribute spend
  to the analyses that bought it.
* **``change`` is the diff, not the value.** Recording the resulting severity is not the same as
  recording that the severity *moved* (and from where): a reviewer asking "did the model change
  anything" wants the second, and only the second can be checked after the fact.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, Final

from arachne.ai.types import AiError

__all__ = [
    "AI_ORIGIN",
    "HEURISTIC_ORIGIN",
    "ORIGINS",
    "ProvenanceError",
    "ProvenanceRecord",
    "summarize_provenance",
]

#: The provenance origins. ``ai`` means a model contributed to the row; ``heuristic`` means the
#: deterministic engine produced it unchanged (including the case where every AI stage failed or
#: was never configured).
AI_ORIGIN: Final = "ai"
HEURISTIC_ORIGIN: Final = "heuristic"
ORIGINS: Final[frozenset[str]] = frozenset({AI_ORIGIN, HEURISTIC_ORIGIN})


class ProvenanceError(AiError):
    """A provenance record that could not be true (missing citation, unknown origin)."""


@dataclass(frozen=True, slots=True)
class ProvenanceRecord:
    """One analysis row's AI provenance (REQ-AGENT-008).

    ``origin`` is the field that distinguishes an AI row from a heuristic one without reading
    logs or joining tables. Everything else is evidence for it: which adapter and model answered,
    which prompt template and rendered-prompt hash asked the question, what the call cost, which
    evidence the answer cited, and what the answer changed.
    """

    origin: str = HEURISTIC_ORIGIN
    provider: str | None = None
    model: str | None = None
    #: The declared version of the prompt corpus the templates came from.
    template_version: str | None = None
    #: The stages that answered, sorted — the templates that produced this row's AI content.
    prompt_template: str | None = None
    #: The hash of the rendered prompt(s), so "what exactly was asked" is reproducible from the
    #: corpus even though the prompt body is never stored (it can embed target data).
    prompt_hash: str | None = None
    prompt_tokens: int = 0
    completion_tokens: int = 0
    #: The evidence ids the model cited, in citation order. Never empty for an ``ai`` record.
    evidence_ids: tuple[str, ...] = ()
    #: The stages that actually contributed, in pipeline order.
    stages: tuple[str, ...] = ()
    #: The resulting change to the analysis: ``{field: [before, after]}`` for the fields the AI
    #: half moved, plus ``policy``/``adopted``. Empty for a heuristic row.
    change: Mapping[str, Any] = field(default_factory=dict)
    #: The degradation marker, exactly as ``Provenance.fallback`` spells it.
    fallback: str | None = None
    #: The privacy mode the payloads were transformed with before they left the boundary.
    privacy: str = "redact"
    #: True when at least one contributing stage answer came from the request cache.
    cached: bool = False

    def __post_init__(self) -> None:
        if self.origin not in ORIGINS:
            msg = f"unknown provenance origin {self.origin!r}; expected one of {sorted(ORIGINS)}"
            raise ProvenanceError(msg)
        if self.origin != AI_ORIGIN:
            return
        if not self.evidence_ids:
            msg = (
                "an AI-origin provenance record must cite at least one evidence id "
                "(REQ-AGENT-008); this is the invariant that makes 'AI found it' checkable"
            )
            raise ProvenanceError(msg)
        missing = [
            name
            for name, value in (
                ("provider", self.provider),
                ("model", self.model),
                ("prompt_hash", self.prompt_hash),
                ("prompt_template", self.prompt_template),
            )
            if not value
        ]
        if missing:
            msg = f"an AI-origin provenance record must name {', '.join(missing)} (REQ-AGENT-008)"
            raise ProvenanceError(msg)

    # ------------------------------------------------------------------ accessors
    @property
    def is_ai(self) -> bool:
        """True when a model contributed to the row."""
        return self.origin == AI_ORIGIN

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens

    def to_dict(self) -> dict[str, Any]:
        return {
            "origin": self.origin,
            "provider": self.provider,
            "model": self.model,
            "template_version": self.template_version,
            "prompt_template": self.prompt_template,
            "prompt_hash": self.prompt_hash,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
            "evidence_ids": list(self.evidence_ids),
            "stages": list(self.stages),
            "change": dict(self.change),
            "fallback": self.fallback,
            "privacy": self.privacy,
            "cached": self.cached,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> ProvenanceRecord:
        """Rebuild a record from a stored row (raising when the row could not be true)."""
        try:
            return cls(
                origin=str(payload.get("origin") or HEURISTIC_ORIGIN),
                provider=_string_or_none(payload.get("provider")),
                model=_string_or_none(payload.get("model")),
                template_version=_string_or_none(payload.get("template_version")),
                prompt_template=_string_or_none(payload.get("prompt_template")),
                prompt_hash=_string_or_none(payload.get("prompt_hash")),
                prompt_tokens=_int(payload.get("prompt_tokens")),
                completion_tokens=_int(payload.get("completion_tokens")),
                evidence_ids=tuple(str(item) for item in payload.get("evidence_ids") or ()),
                stages=tuple(str(item) for item in payload.get("stages") or ()),
                change=_mapping(payload.get("change")),
                fallback=_string_or_none(payload.get("fallback")),
                privacy=str(payload.get("privacy") or "redact"),
                cached=bool(payload.get("cached")),
            )
        except ProvenanceError:
            raise
        except (TypeError, ValueError) as exc:
            msg = f"malformed provenance record: {exc}"
            raise ProvenanceError(msg) from exc

    # ------------------------------------------------------------------ constructors
    @classmethod
    def heuristic(
        cls,
        *,
        fallback: str | None = None,
        privacy: str = "redact",
        stages: Iterable[str] = (),
        change: Mapping[str, Any] | None = None,
    ) -> ProvenanceRecord:
        """The record of a row no model contributed to."""
        return cls(
            origin=HEURISTIC_ORIGIN,
            fallback=fallback,
            privacy=privacy,
            stages=tuple(stages),
            change=dict(change or {}),
        )

    @classmethod
    def ai(
        cls,
        *,
        provider: str,
        model: str,
        prompt_hash: str,
        stages: Iterable[str],
        evidence_ids: Iterable[str],
        prompt_tokens: int = 0,
        completion_tokens: int = 0,
        template_version: str | None = None,
        change: Mapping[str, Any] | None = None,
        fallback: str | None = None,
        privacy: str = "redact",
        cached: bool = False,
    ) -> ProvenanceRecord:
        """The record of a row a model contributed to (refuses an uncited one)."""
        ordered = tuple(sorted(set(stages)))
        return cls(
            origin=AI_ORIGIN,
            provider=provider,
            model=model,
            template_version=template_version,
            prompt_template=",".join(ordered) or None,
            prompt_hash=prompt_hash,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            evidence_ids=tuple(dict.fromkeys(str(item) for item in evidence_ids)),
            stages=tuple(stages),
            change=dict(change or {}),
            fallback=fallback,
            privacy=privacy,
            cached=cached,
        )


def summarize_provenance(
    records: Iterable[ProvenanceRecord | Mapping[str, Any]],
    *,
    scan_ids: Iterable[int] = (),
) -> dict[str, Any]:
    """The exportable summary of a set of provenance records (per scan or per project).

    This is the document ``arachne ai provenance`` writes and the block
    ``arachne compliance export`` embeds: *"which provider received how many tokens"*, per
    provider **and** per model, with the row counts that make the number checkable, and an
    explicit ``uncited_ai_rows`` counter that must be zero (a non-zero value is a corrupt store,
    not a warning).

    It carries no prompt bodies and no evidence payloads — only ids, hashes and counts — so the
    export can be attached to an audit ticket without leaking what the scan saw.
    """
    providers: dict[str, dict[str, Any]] = {}
    models: dict[str, dict[str, Any]] = {}
    origins: dict[str, int] = {}
    stages: dict[str, int] = {}
    scans = sorted(set(scan_ids))
    ai_rows = 0
    uncited = 0
    for record in records:
        item = (
            record if isinstance(record, ProvenanceRecord) else ProvenanceRecord.from_dict(record)
        )
        origins[item.origin] = origins.get(item.origin, 0) + 1
        if not item.is_ai:
            continue
        ai_rows += 1
        if not item.evidence_ids:
            uncited += 1
        _accumulate(providers, item.provider or "unknown", item)
        _accumulate(models, item.model or "unknown", item)
        for stage in item.stages:
            stages[stage] = stages.get(stage, 0) + 1
    return {
        "rows": sum(origins.values()),
        "ai_rows": ai_rows,
        "heuristic_rows": origins.get(HEURISTIC_ORIGIN, 0),
        "origins": dict(sorted(origins.items())),
        "providers": dict(sorted(providers.items())),
        "models": dict(sorted(models.items())),
        "stages": dict(sorted(stages.items())),
        "scan_ids": scans,
        "uncited_ai_rows": uncited,
    }


def _accumulate(bucket: dict[str, dict[str, Any]], key: str, record: ProvenanceRecord) -> None:
    entry = bucket.setdefault(
        key,
        {
            "rows": 0,
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0,
            "cached_rows": 0,
        },
    )
    entry["rows"] += 1
    entry["prompt_tokens"] += record.prompt_tokens
    entry["completion_tokens"] += record.completion_tokens
    entry["total_tokens"] += record.total_tokens
    if record.cached:
        entry["cached_rows"] += 1


def _string_or_none(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _int(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return 0
    return int(value)


def _mapping(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}
