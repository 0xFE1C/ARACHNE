"""The hypothesis model: what a hypothesis *is*, and what a decision *records* (S21, area AGENT).

Area AGENT asks for an attacker's brain inside the built-in cage: hypotheses proposed in two
modes, executed only through the planner/orchestrator, under a per-scan budget, with every
decision recorded so it can be replayed offline. This module is the vocabulary of that loop and
nothing else — no I/O, no engine, no gate. Three ideas carry the whole design:

**A hypothesis is a *proposal to run a check*, never an action.** It names an existing check
(:attr:`Hypothesis.check_id`) and an asset the scan already knows, plus the reason it is worth
running. It cannot name a request, a URL or a payload: a check that does not exist in the
registry cannot be executed, which is what makes "the AI cannot widen its own capabilities"
a property of the data model rather than a promise (REQ-AGENT-005).

**A decision is the audit record of one hypothesis.** It carries the :attr:`HypothesisInput`
hash it was derived from, the chosen probe, the outcome and the reason. Replay recomputes the
hash from the recorded input and re-derives the decisions, so "what did the agent decide, and
against what inputs?" is answerable months later without the target (REQ-AGENT-002).

**The budget is per scan and unforgeable.** :class:`HypothesisBudget` is counters the engine
can only spend through :meth:`HypothesisBudget.spend`; a hypothesis that does not fit is
*deferred*, recorded, and never silently dropped or executed anyway (REQ-AGENT-001/005).
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Final

from pydantic import BaseModel, ConfigDict, Field, field_validator

__all__ = [
    "HYPOTHESIS_JOURNAL_VERSION",
    "Hypothesis",
    "HypothesisBudget",
    "HypothesisDecision",
    "HypothesisInput",
    "HypothesisJournal",
    "HypothesisJournalState",
    "HypothesisKind",
    "HypothesisMode",
    "HypothesisOutcome",
    "JournalState",
    "canonical_json",
    "hypothesis_id",
    "inputs_hash_of",
]

#: Bumped whenever the persisted journal changes shape (``scans.stats["hypotheses"]``).
HYPOTHESIS_JOURNAL_VERSION: Final = "1.0"

_MODEL = ConfigDict(frozen=True, extra="forbid")


class HypothesisMode(StrEnum):
    """How hypotheses are proposed for a scan (REQ-AGENT-001).

    ``HYBRID`` is the operational default once agentic mode is on: the AI proposes and ranks
    when a provider is configured, and the heuristic engine supplies the hypotheses when it is
    not — the same degradation contract the analyzer's two engines already have.
    """

    OFF = "off"
    HEURISTIC = "heuristic"
    HYBRID = "hybrid"
    AI = "ai"

    @property
    def wants_ai(self) -> bool:
        """True when a model should propose first (``hybrid`` and ``ai``)."""
        return self in (HypothesisMode.HYBRID, HypothesisMode.AI)

    @property
    def allows_heuristic(self) -> bool:
        """True for every mode but ``off`` — the heuristic engine is always available.

        Deliberately true in ``ai`` mode too: an explicit demand for a model still degrades to
        heuristic hypotheses when the model cannot answer (REQ-AGENT-002), because "AI failure
        degrades quality, never safety" includes "never into silence".
        """
        return self is not HypothesisMode.OFF


class HypothesisKind(StrEnum):
    """Why a hypothesis exists. Recorded so a trend can say *which* reasoning pays off."""

    #: Re-run a check whose finding is undecided or low-confidence.
    VERIFY_FINDING = "verify-finding"
    #: A rule's signals are present but no included check covered it.
    UNEXPLORED_RULE = "unexplored-rule"
    #: Follow a correlation group to the check that would confirm the next hop.
    CHAIN = "chain"
    #: The evidence names surface (a host, a path) worth checking explicitly.
    DISCOVERY = "discovery"


class HypothesisOutcome(StrEnum):
    """The fate of one hypothesis, as the journal records it."""

    PROPOSED = "proposed"
    ACCEPTED = "accepted"
    #: Refused by a gate or a boundary: an unknown check, an out-of-scope asset, an
    #: L3/L4 proposal without approval, a hostile proposal. Always carries a reason.
    REFUSED = "refused"
    EXECUTED = "executed"
    #: Ran but produced nothing (a check that supports no asset, or an empty result).
    SKIPPED = "skipped"
    #: Did not fit the budget (or waited for approval): recorded, not executed.
    DEFERRED = "deferred"


class HypothesisJournalState(StrEnum):
    """The lifecycle of one hypothesis run (REQ-AGENT-007)."""

    RUNNING = "running"
    PAUSED = "paused"
    ABORTED = "aborted"
    COMPLETED = "completed"


#: Alias kept short for callers that already import the journal.
JournalState = HypothesisJournalState


class Hypothesis(BaseModel):
    """One proposal: *run this registered check against this known asset, because …*."""

    model_config = _MODEL

    id: str
    kind: HypothesisKind
    check_id: str
    asset: str
    rationale: str = Field(max_length=2000)
    expected_signal: str = Field(default="", max_length=500)
    #: ``heuristic`` or ``ai`` — which engine proposed it.
    source: str = "heuristic"
    confidence: int = Field(default=50, ge=0, le=100)
    #: The check's declared proof level, resolved from the registry at validation time. A
    #: proposal above L1 needs explicit operator approval (REQ-AGENT-005).
    proof: str = "L1"
    rank: int = 0

    @property
    def identity(self) -> tuple[str, str]:
        return (self.check_id, self.asset)


def hypothesis_id(check_id: str, asset: str, kind: HypothesisKind) -> str:
    """A stable id for a proposal: the same proposal has the same id on every replay."""
    digest = hashlib.sha256(f"{kind.value}\x1f{check_id}\x1f{asset}".encode()).hexdigest()
    return f"h-{digest[:12]}"


def canonical_json(value: Any) -> str:
    """Deterministic JSON: sorted keys, no whitespace (the input to every hash here)."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def inputs_hash_of(payload: Mapping[str, Any]) -> str:
    """``sha256`` of the canonical form of ``payload`` — the replay anchor."""
    return hashlib.sha256(canonical_json(dict(payload)).encode()).hexdigest()


class HypothesisInput(BaseModel):
    """Everything a hypothesis engine may see, as plain data (hashable, replayable).

    Two properties matter. It is **deterministic**: no timestamps, no clock, no iteration over
    unordered containers, so ``inputs_hash`` identifies the exact state the decisions were made
    against. And it is **bounded**: it carries summaries (check ids, severities, assets, group
    keys, rule ids) rather than evidence bodies, so a replay of a scan from six months ago needs
    nothing but the journal.
    """

    model_config = _MODEL

    scan_id: int
    engine: str = "heuristic"
    rules_version: str = ""
    correlation_version: str = ""
    #: ``kind:value`` of every asset the scan recorded, sorted and de-duplicated.
    assets: tuple[str, ...] = ()
    #: One ``check_id|asset|severity|confidence|verdict|kw:...`` line per analysed finding.
    findings: tuple[str, ...] = ()
    #: One ``rule_id|group_key|contributors`` line per correlation group.
    groups: tuple[str, ...] = ()
    #: ``rule_id|check_id|asset_hint`` for rules whose signals are present but which no
    #: included check covered (the heuristic engine's reading of the rule corpus).
    unexplored: tuple[str, ...] = ()
    #: Checks that already ran for this scan (so the engine does not re-propose them blindly).
    covered: tuple[str, ...] = ()
    #: Free-form *untrusted* observations (a target-planted hint, an OSINT note). Kept
    #: explicitly out of the trusted half so a prompt-injection payload that lands here can
    #: never change a gate (REQ-AGENT-006).
    observations: tuple[str, ...] = ()

    @property
    def inputs_hash(self) -> str:
        return inputs_hash_of(self.model_dump(mode="json"))


class HypothesisBudget(BaseModel):
    """The per-scan allowance: how many hypotheses and how many requests (REQ-AGENT-001)."""

    model_config = _MODEL

    max_hypotheses: int = Field(default=5, ge=0)
    max_probes: int = Field(default=50, ge=0)
    hypotheses_spent: int = Field(default=0, ge=0)
    probes_spent: int = Field(default=0, ge=0)
    #: Proposals refused for exceeding the budget — surfaced, never silently dropped.
    deferred: int = Field(default=0, ge=0)

    @property
    def hypotheses_left(self) -> int:
        return max(0, self.max_hypotheses - self.hypotheses_spent)

    @property
    def probes_left(self) -> int:
        return max(0, self.max_probes - self.probes_spent)

    @property
    def exhausted(self) -> bool:
        return self.hypotheses_left == 0 or self.probes_left == 0

    def affords(self, *, probes: int) -> bool:
        """Whether one more hypothesis costing ``probes`` requests still fits."""
        return self.hypotheses_left > 0 and probes <= self.probes_left

    def spend(self, *, probes: int) -> HypothesisBudget:
        """Consume one hypothesis and its estimated probes (returns the new budget).

        Raises :class:`ValueError` when the spend does not fit, so a caller that forgot to
        check cannot mint budget by accident — the counters only ever move *down*.
        """
        if not self.affords(probes=probes):
            msg = (
                f"hypothesis budget exhausted (left: {self.hypotheses_left} hypotheses, "
                f"{self.probes_left} probes; asked for {probes})"
            )
            raise ValueError(msg)
        return self.model_copy(
            update={
                "hypotheses_spent": self.hypotheses_spent + 1,
                "probes_spent": self.probes_spent + max(0, probes),
            }
        )

    def defer(self) -> HypothesisBudget:
        return self.model_copy(update={"deferred": self.deferred + 1})

    def to_dict(self) -> dict[str, Any]:
        return {
            "max_hypotheses": self.max_hypotheses,
            "max_probes": self.max_probes,
            "hypotheses_spent": self.hypotheses_spent,
            "probes_spent": self.probes_spent,
            "deferred": self.deferred,
        }


class HypothesisDecision(BaseModel):
    """The audit record of one hypothesis: inputs hash, chosen probe, outcome (REQ-AGENT-002)."""

    model_config = _MODEL

    hypothesis_id: str
    check_id: str
    asset: str
    kind: HypothesisKind
    source: str = "heuristic"
    inputs_hash: str
    outcome: HypothesisOutcome
    reason: str = Field(default="", max_length=1000)
    #: Estimated requests the probe costs (0 when it was refused before costing anything).
    probes: int = Field(default=0, ge=0)
    at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    #: Which engine actually produced the proposal after degradation (``heuristic`` when the
    #: AI half failed), and the fallback marker, mirroring the analyzer's provenance.
    engine: str = "heuristic"
    fallback: str | None = None
    #: The finding ids the probe produced, when it ran.
    produced: tuple[int, ...] = ()

    @field_validator("at")
    @classmethod
    def _require_tz(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            msg = "hypothesis decisions must be timezone-aware (UTC)"
            raise ValueError(msg)
        return value.astimezone(UTC)


class HypothesisJournal(BaseModel):
    """The persisted state of one run: the budget, every decision, and where it stopped.

    ``cursor`` is the number of decisions already made, which is what makes an abort
    resumable (REQ-AGENT-007): a resumed run replays the journal, skips the decisions already
    recorded, and continues from the cursor. ``state`` distinguishes a deliberate pause (an
    operator) from an abort from a completion.
    """

    model_config = _MODEL

    version: str = HYPOTHESIS_JOURNAL_VERSION
    scan_id: int
    mode: HypothesisMode = HypothesisMode.HEURISTIC
    engine: str = "heuristic"
    inputs_hash: str = ""
    rules_version: str = ""
    correlation_version: str = ""
    state: HypothesisJournalState = HypothesisJournalState.RUNNING
    budget: HypothesisBudget = Field(default_factory=HypothesisBudget)
    #: The proposals this run is working through, in ranked order. Persisted so a resume
    #: continues the *same* plan (the cursor is ``len(decisions)``) and a replay can compare
    #: the recorded decisions against the proposals they came from.
    proposals: tuple[Hypothesis, ...] = ()
    decisions: tuple[HypothesisDecision, ...] = ()
    #: Number of proposals the engine returned before any gate or budget was applied.
    proposed: int = Field(default=0, ge=0)
    #: ``None`` when every configured engine stage succeeded.
    fallback: str | None = None
    #: The exact input the run reasoned over. Persisted so a replay needs nothing but the
    #: journal: no database, no target, no provider (REQ-AGENT-002). It is ids and counters
    #: only — never evidence bodies — so it stays small and carries no target secret.
    input: HypothesisInput | None = None
    note: str = ""
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @property
    def cursor(self) -> int:
        return len(self.decisions)

    @property
    def remaining(self) -> tuple[Hypothesis, ...]:
        """Proposals not yet decided (what a resume continues from)."""
        return self.proposals[self.cursor :]

    @property
    def executed(self) -> tuple[HypothesisDecision, ...]:
        return tuple(item for item in self.decisions if item.outcome is HypothesisOutcome.EXECUTED)

    @property
    def refused(self) -> tuple[HypothesisDecision, ...]:
        return tuple(item for item in self.decisions if item.outcome is HypothesisOutcome.REFUSED)

    def with_decisions(
        self,
        decisions: Iterable[HypothesisDecision],
        *,
        state: HypothesisJournalState | None = None,
    ) -> HypothesisJournal:
        merged = (*self.decisions, *decisions)
        return self.model_copy(
            update={
                "decisions": merged,
                "state": state or self.state,
                "updated_at": datetime.now(UTC),
            }
        )

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    @classmethod
    def from_document(cls, document: Mapping[str, Any] | None) -> HypothesisJournal | None:
        """Rebuild a journal from a persisted document (``None`` when there is none)."""
        if not document:
            return None
        return cls.model_validate(dict(document))
