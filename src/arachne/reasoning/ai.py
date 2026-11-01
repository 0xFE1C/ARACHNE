"""The AI hypothesis engine: the ``hypothesize`` stage, and nothing more (REQ-AGENT-001).

The AI half of area AGENT is deliberately thin. It does not crawl, does not plan, does not
execute and does not know what a scope is. It runs one allowlisted analysis stage over the
scan's state — through the same provider, ledger, cache, retry policy and circuit breaker every
other AI stage uses — and returns *proposals*. Everything that turns a proposal into work lives
behind the executor's gate (see :mod:`arachne.reasoning.executor`), which is what keeps an AI
output from widening scope, minting attestation, disabling a gate or exceeding a budget
(REQ-AGENT-005/006).

Two contracts are inherited from the analyzer, unchanged:

* **The prompt split.** The closed list of check ids is *trusted context* (ours); findings,
  correlation groups and observations are *untrusted target data*. The prompt store wraps and
  delimits the latter, and the system prompt carries the injection instruction.
* **The degradation chain.** A stage that cannot be attempted or that fails returns a
  :class:`HypothesisProposal` with ``fallback`` set, and the reasoner falls back to the
  heuristic engine. A dead provider costs quality, never hypotheses and never safety.
"""

from __future__ import annotations

from typing import Any

from arachne.ai.engine import AiEngine
from arachne.ai.stages import HypothesizeOutput, build_hypothesize_input
from arachne.reasoning.engine import HypothesisProposal
from arachne.reasoning.heuristic import HypothesisPolicies
from arachne.reasoning.index import CheckIndex
from arachne.reasoning.model import Hypothesis, HypothesisInput, HypothesisKind, hypothesis_id

__all__ = ["AiHypothesisEngine"]

#: How many proposals one stage call may return (the schema's own cap, repeated here so the
#: engine can bound its own list even if a provider ignores the schema).
_MAX_PROPOSALS = 12


class AiHypothesisEngine:
    """Runs the ``hypothesize`` stage and adapts its output to :class:`Hypothesis` objects."""

    name = "ai"

    def __init__(
        self,
        engine: AiEngine,
        *,
        policies: HypothesisPolicies | None = None,
    ) -> None:
        self.engine = engine
        self.policies = policies or HypothesisPolicies()

    async def propose_async(
        self, source: HypothesisInput, index: CheckIndex
    ) -> HypothesisProposal:
        """Propose through the model; never raises (a failure is a recorded fallback)."""
        built = build_hypothesize_input(
            scan_id=source.scan_id,
            check_ids=index.ids(),
            finding_lines=source.findings,
            group_lines=source.groups,
            covered=source.covered,
            observations=source.observations,
            max_hypotheses=max(1, self._max_proposals()),
        )
        outcome = await self.engine.run_stage("hypothesize", built)
        if outcome is None:
            return HypothesisProposal(
                hypotheses=(),
                engine="heuristic",
                fallback="heuristic_fallback:ai_unavailable",
            )
        if not outcome.ok:
            return HypothesisProposal(
                hypotheses=(),
                engine="heuristic",
                fallback=f"heuristic_fallback:hypothesize:{outcome.fallback}",
                detail={"stage": outcome.to_dict()},
            )
        proposals = _proposals_from(outcome.value, source, limit=self._max_proposals())
        return HypothesisProposal(
            hypotheses=proposals,
            engine="ai",
            fallback=None,
            detail={
                "provider": getattr(self.engine, "provider_name", ""),
                "model": getattr(self.engine, "model", ""),
                "prompt_hash": outcome.prompt_hash,
                "template_version": outcome.template_version,
                "cached": outcome.cached,
                "mechanism": outcome.mechanism,
            },
        )

    def _max_proposals(self) -> int:
        # The stage schema caps at 12; the budget caps execution separately. Keeping the two
        # separate is what makes "the model proposed 12, the budget allowed 2" visible.
        return min(_MAX_PROPOSALS, self.policies.max_proposals)


def _proposals_from(
    value: Any, source: HypothesisInput, *, limit: int
) -> tuple[Hypothesis, ...]:
    """Turn a validated stage payload into proposals, deterministically and bounded."""
    try:
        parsed = HypothesizeOutput.model_validate(value)
    except Exception:  # a payload the schema refused is not a decision, it is a failed stage
        return ()
    out: list[Hypothesis] = []
    seen: set[tuple[str, str]] = set()
    for item in parsed.hypotheses[: max(0, limit)]:
        check_id = item.check_id.strip()
        asset = item.asset.strip() or (
            source.findings[0].split("|", 2)[1] if source.findings else ""
        )
        identity = (check_id, asset)
        if not check_id or identity in seen:
            continue
        seen.add(identity)
        out.append(
            Hypothesis(
                id=hypothesis_id(check_id, asset, HypothesisKind.CHAIN),
                kind=HypothesisKind.CHAIN,
                check_id=check_id,
                asset=asset,
                rationale=item.rationale.strip()[:2000]
                or "the model proposed confirming this check",
                expected_signal=f"evidence from {check_id} on {asset}",
                source="ai",
                confidence=item.confidence,
                rank=len(out),
            )
        )
    return tuple(out)
