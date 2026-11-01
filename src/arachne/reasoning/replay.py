"""Offline replay of a hypothesis run (REQ-AGENT-002).

"Every hypothesis decision MUST be recorded (inputs hash, chosen probe, outcome) for offline
replay." The journal already holds all of that, plus the exact input it reasoned over. This
module turns the journal back into a verdict on the run, and it needs nothing else — no target,
no database, no provider, no network:

* **The hash is recomputed** from the recorded input document. If it does not match the hash the
  decisions were made against, the record is not what it claims to be and the replay fails
  loudly. That is the property that makes the journal trustworthy rather than merely present.
* **The decision record is checked for internal consistency**: one decision per proposal, in
  order, with the proposal's identity; a decision that does not correspond to a proposal, or a
  proposal with two decisions, is a defect in the *record*.
* **The deterministic half is re-derived.** The heuristic engine is a pure function of the
  input, so replaying it must reproduce the same proposals. For a heuristic run that is a full
  reproduction; for an AI run it is a comparison — the model is not reproducible by design, and
  what replay can say is whether the heuristic reading of the same input *would* have proposed
  the same probes, which is exactly the parity question an operator asks after a degradation.

Replay never executes anything. It is a read-only audit of a decision, and the CLI's word for it
(``arachne reason replay``) is what an operator reaches for when a finding is challenged.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from arachne.reasoning.heuristic import HeuristicHypothesisEngine, HypothesisPolicies
from arachne.reasoning.index import CheckIndex
from arachne.reasoning.model import (
    HypothesisJournal,
    HypothesisJournalState,
    HypothesisOutcome,
)

__all__ = ["ReplayReport", "replay_journal"]


@dataclass(frozen=True, slots=True)
class ReplayReport:
    """What a replay established about one run."""

    scan_id: int
    engine: str
    mode: str
    state: str
    inputs_hash: str
    recomputed_hash: str
    #: ``True`` when the recomputed hash equals the recorded one (the record is intact).
    hash_matches: bool
    proposed: int
    decisions: int
    executed: int
    refused: int
    deferred: int
    #: ``True`` when the heuristic engine re-derives the recorded proposals exactly.
    proposals_reproduced: bool
    reproduced_probes: tuple[str, ...] = ()
    missing_probes: tuple[str, ...] = ()
    extra_probes: tuple[str, ...] = ()
    problems: tuple[str, ...] = ()
    notes: tuple[str, ...] = field(default_factory=tuple)

    @property
    def ok(self) -> bool:
        """A replay is ok when the record is intact and every decision maps to a proposal."""
        return self.hash_matches and not self.problems

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "engine": self.engine,
            "mode": self.mode,
            "state": self.state,
            "inputs_hash": self.inputs_hash,
            "recomputed_hash": self.recomputed_hash,
            "hash_matches": self.hash_matches,
            "proposed": self.proposed,
            "decisions": self.decisions,
            "executed": self.executed,
            "refused": self.refused,
            "deferred": self.deferred,
            "proposals_reproduced": self.proposals_reproduced,
            "probes": {
                "reproduced": list(self.reproduced_probes),
                "missing": list(self.missing_probes),
                "extra": list(self.extra_probes),
            },
            "problems": list(self.problems),
            "notes": list(self.notes),
            "ok": self.ok,
        }


def replay_journal(
    journal: HypothesisJournal,
    *,
    index: CheckIndex | None = None,
    policies: HypothesisPolicies | None = None,
) -> ReplayReport:
    """Re-derive a run from its journal and report whether the record holds up.

    ``index`` is only needed for the proposal re-derivation; the record checks work without it.
    """
    problems: list[str] = []
    notes: list[str] = []

    recorded_hash = journal.inputs_hash
    recomputed = journal.input.inputs_hash if journal.input is not None else ""
    hash_matches = bool(recomputed) and recomputed == recorded_hash
    if journal.input is None:
        problems.append("the journal carries no input document; nothing can be re-derived")
    elif not hash_matches:
        problems.append(
            "the recomputed input hash does not match the recorded one: the decisions were "
            "made against different inputs than the journal now holds"
        )

    problems.extend(_check_decisions(journal))

    reproduced: tuple[str, ...] = ()
    missing: tuple[str, ...] = ()
    extra: tuple[str, ...] = ()
    proposals_reproduced = False
    if journal.input is not None and index is not None:
        engine = HeuristicHypothesisEngine(index, policies=policies or HypothesisPolicies())
        derived = engine.propose(journal.input)
        reproduced = tuple(f"{item.check_id}|{item.asset}" for item in derived)
        recorded = tuple(f"{item.check_id}|{item.asset}" for item in journal.proposals)
        missing = tuple(item for item in recorded if item not in reproduced)
        extra = tuple(item for item in reproduced if item not in recorded)
        proposals_reproduced = not missing and not extra
        if journal.engine == "ai" and not proposals_reproduced:
            notes.append(
                "the AI run's proposals differ from a fresh heuristic reading of the same "
                "input; that is expected (a model is not reproducible) and the recorded "
                "proposals are authoritative"
            )
        elif journal.engine != "ai" and not proposals_reproduced:
            notes.append(
                "a heuristic run did not reproduce its own proposals: the rule corpus or the "
                "catalogue changed since the run (versions: "
                f"rules={journal.rules_version or 'unknown'})"
            )

    return ReplayReport(
        scan_id=journal.scan_id,
        engine=journal.engine,
        mode=journal.mode.value,
        state=journal.state.value,
        inputs_hash=recorded_hash,
        recomputed_hash=recomputed,
        hash_matches=hash_matches,
        proposed=journal.proposed,
        decisions=journal.cursor,
        executed=len(journal.executed),
        refused=len(journal.refused),
        deferred=sum(
            1 for item in journal.decisions if item.outcome is HypothesisOutcome.DEFERRED
        ),
        proposals_reproduced=proposals_reproduced,
        reproduced_probes=reproduced,
        missing_probes=missing,
        extra_probes=extra,
        problems=tuple(problems),
        notes=tuple(notes),
    )


def _check_decisions(journal: HypothesisJournal) -> list[str]:
    """Consistency of the decision record against the proposal list."""
    problems: list[str] = []
    if journal.cursor > journal.proposed or journal.cursor > len(journal.proposals):
        problems.append(
            f"{journal.cursor} decision(s) for {len(journal.proposals)} proposal(s): the "
            "record is longer than the run it describes"
        )
    if journal.state is HypothesisJournalState.COMPLETED and journal.cursor != len(
        journal.proposals
    ):
        problems.append(
            "the journal says the run completed but not every proposal has a decision"
        )
    for position, decision in enumerate(journal.decisions):
        if position >= len(journal.proposals):
            break
        proposal = journal.proposals[position]
        if (decision.check_id, decision.asset) != (proposal.check_id, proposal.asset):
            problems.append(
                f"decision {position} is {decision.check_id}|{decision.asset} but proposal "
                f"{position} is {proposal.check_id}|{proposal.asset}"
            )
        if decision.outcome is HypothesisOutcome.EXECUTED and decision.probes <= 0:
            problems.append(f"decision {position} claims execution but spent no probe")
    return problems
