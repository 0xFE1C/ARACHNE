"""Dual mode, ranking and degradation for the hypothesis engine (REQ-AGENT-001/002).

The reasoner is the one place that knows both engines exist. It has three jobs and no others:

**Dual mode.** ``heuristic`` never calls a model. ``ai`` uses the model's proposals and falls
back to the heuristic engine when the stage cannot be attempted or fails. ``hybrid`` runs both
and merges them, model proposals first. In every mode the *same* heuristic engine would produce
a usable proposal set, which is what "no AI provider is required to reason" means in practice —
and it is what the parity test exercises.

**Degradation.** A failed or unavailable AI stage never empties the proposal set: the reasoner
falls back to the heuristic engine and records ``fallback="heuristic_fallback:…"`` on the
proposal, mirroring the analyzer's ``Provenance.fallback`` (docs/spec/03- §7). The failure's
*reason* travels with it, so an operator can tell "the provider was down" from "the model
answered something unusable".

**Normalisation.** Every proposal, from either engine, is resolved against the
:class:`~arachne.reasoning.index.CheckIndex` (its declared proof level, its cost) and given a
final rank. An engine cannot smuggle a proof level or a cost past this step, because the values
written into the journal are the index's, not the proposal's.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Protocol

from arachne.reasoning.heuristic import HeuristicHypothesisEngine
from arachne.reasoning.index import CheckIndex
from arachne.reasoning.model import Hypothesis, HypothesisInput, HypothesisMode

__all__ = [
    "HypothesisEngine",
    "HypothesisProposal",
    "HypothesisReasoner",
    "normalise",
]


@dataclass(frozen=True, slots=True)
class HypothesisProposal:
    """What one reasoning pass produced, with its provenance."""

    hypotheses: tuple[Hypothesis, ...] = ()
    engine: str = "heuristic"
    fallback: str | None = None
    detail: Mapping[str, object] = field(default_factory=dict)

    @property
    def count(self) -> int:
        return len(self.hypotheses)


class HypothesisEngine(Protocol):
    """Anything that turns :class:`HypothesisInput` into proposals."""

    name: str

    def propose(self, source: HypothesisInput, index: CheckIndex) -> tuple[Hypothesis, ...]: ...


class HypothesisReasoner:
    """Runs the configured mode over the heuristic and AI engines."""

    def __init__(
        self,
        *,
        heuristic: HeuristicHypothesisEngine,
        ai: object | None = None,
        mode: HypothesisMode = HypothesisMode.HEURISTIC,
    ) -> None:
        self.heuristic = heuristic
        self.ai = ai
        self.mode = mode

    async def propose(self, source: HypothesisInput, index: CheckIndex) -> HypothesisProposal:
        """Propose hypotheses for one input, honouring the mode and the degradation chain."""
        if self.mode is HypothesisMode.OFF:
            return HypothesisProposal(hypotheses=(), engine="off")

        heuristic_set = self.heuristic.propose(source)
        if not self.mode.wants_ai or self.ai is None:
            return HypothesisProposal(
                hypotheses=normalise(heuristic_set, index), engine="heuristic"
            )

        proposal = await _propose_async(self.ai, source, index)
        if proposal.fallback is None and proposal.hypotheses:
            # ``hybrid`` asks for both readings and merges them (model first). ``ai`` asks for
            # the model alone, so its proposals are used as they came — which is what makes the
            # adversarial tests able to say "the model proposed exactly this, and here is what
            # happened to each proposal".
            hypotheses = (
                _merge(proposal.hypotheses, heuristic_set, index)
                if self.mode is HypothesisMode.HYBRID
                else normalise(proposal.hypotheses, index)
            )
            return HypothesisProposal(
                hypotheses=hypotheses,
                engine=proposal.engine,
                fallback=None,
                detail=proposal.detail,
            )
        if proposal.fallback is None and not proposal.hypotheses:
            # The model answered "nothing to run": that is a decision, not a failure, and the
            # heuristic reading is still worth offering in hybrid mode.
            if self.mode is HypothesisMode.HYBRID and heuristic_set:
                return HypothesisProposal(
                    hypotheses=normalise(heuristic_set, index),
                    engine="ai+heuristic",
                    detail=proposal.detail,
                )
            return HypothesisProposal(
                hypotheses=(), engine=proposal.engine, detail=proposal.detail
            )
        # Degraded: the AI half could not answer. The heuristic set is the fallback whenever
        # the mode allows it; ``ai`` alone (an operator's explicit demand) still yields the
        # heuristic hypotheses, because "AI failure degrades quality, never safety".
        return HypothesisProposal(
            hypotheses=normalise(heuristic_set, index),
            engine="heuristic",
            fallback=proposal.fallback,
            detail=proposal.detail,
        )


async def _propose_async(
    engine: object, source: HypothesisInput, index: CheckIndex
) -> HypothesisProposal:
    propose = getattr(engine, "propose_async", None)
    if not callable(propose):  # pragma: no cover - guarded by the caller's construction
        return HypothesisProposal(
            hypotheses=(), engine="heuristic", fallback="heuristic_fallback:no_ai_engine"
        )
    result = await propose(source, index)
    if not isinstance(result, HypothesisProposal):  # pragma: no cover - defensive
        return HypothesisProposal(
            hypotheses=(), engine="heuristic", fallback="heuristic_fallback:bad_engine"
        )
    return result


def _merge(
    ai: tuple[Hypothesis, ...], heuristic: tuple[Hypothesis, ...], index: CheckIndex
) -> tuple[Hypothesis, ...]:
    """Model proposals first, then the heuristic ones they do not already cover."""
    combined: list[Hypothesis] = list(ai)
    seen = {item.identity for item in ai}
    for item in heuristic:
        if item.identity in seen:
            continue
        seen.add(item.identity)
        combined.append(item)
    return normalise(tuple(combined), index)


def normalise(hypotheses: tuple[Hypothesis, ...], index: CheckIndex) -> tuple[Hypothesis, ...]:
    """Resolve each proposal against the index and assign final ranks.

    A proposal whose check is not in the index keeps its place in the list — the *executor*
    refuses it and records why, which is the behaviour the adversarial tests exercise. What
    changes here is only what the index is authoritative for: the declared proof level. A
    model cannot claim a check is harmless; the catalogue decides.
    """
    resolved: list[Hypothesis] = []
    for item in hypotheses:
        entry = index.get(item.check_id)
        proof = entry.proof if entry is not None else "unknown"
        resolved.append(item.model_copy(update={"proof": proof}))
    return tuple(
        item.model_copy(update={"rank": position}) for position, item in enumerate(resolved)
    )
