"""The heuristic hypothesis engine (REQ-AGENT-001: dual mode, heuristic half).

The product must reason like an attacker *without* an AI provider — that is the parity culture
of the whole program (C-03), and for area AGENT it is a hard rule. So the heuristic engine is
not a stub that says "no hypotheses": it reads the same two deterministic sources the analyzer
already produces, and derives the same shape of proposal the AI half does.

**From the rule corpus.** A rule binds a family of checks (``check_ref``) to conditions over a
finding's evidence. When a rule's *family* produced a finding but the check that would confirm
the rule did not run, that is an unexplored hypothesis: the signals are visible, the
confirmation is one check away. The step resolves rules against the catalogue and hands the
engine ``unexplored`` lines; the engine turns them into proposals.

**From correlation output.** A correlation group is several findings that share a root cause —
the analyzer's own statement that they compound. The group's next hop is the check that would
confirm the compound; the step records the candidate check ids, and the engine proposes the
first one that has not run.

**From uncertainty.** A finding the analyzer is not confident about (or could not re-verify) is
worth confirming: the cheapest possible hypothesis is re-running the check that produced it.

Everything is a pure function of :class:`~arachne.reasoning.model.HypothesisInput`, ordered
deterministically (confidence, then kind, then ids), so the same input yields the same
proposals — which is what makes offline replay meaningful (REQ-AGENT-002).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from arachne.reasoning.index import CheckIndex
from arachne.reasoning.input import parse_finding, parse_group, parse_unexplored
from arachne.reasoning.model import (
    Hypothesis,
    HypothesisInput,
    HypothesisKind,
    hypothesis_id,
)

__all__ = ["HeuristicHypothesisEngine", "HypothesisPolicies", "severity_confidence"]

#: How much confidence a declared severity is worth before any evidence is read.
_SEVERITY_CONFIDENCE: Final[dict[str, int]] = {
    "critical": 90,
    "high": 80,
    "medium": 65,
    "low": 50,
    "info": 35,
}

#: Ordering preference when two proposals have the same confidence. Confirming an existing
#: finding is cheapest, then following the rule corpus, then a correlation chain.
_KIND_ORDER: Final[dict[HypothesisKind, int]] = {
    HypothesisKind.VERIFY_FINDING: 0,
    HypothesisKind.UNEXPLORED_RULE: 1,
    HypothesisKind.CHAIN: 2,
    HypothesisKind.DISCOVERY: 3,
}


def severity_confidence(severity: str) -> int:
    """The confidence a hypothesis inherits from the severity that motivates it."""
    return _SEVERITY_CONFIDENCE.get((severity or "").strip().lower(), 50)


@dataclass(frozen=True, slots=True)
class HypothesisPolicies:
    """How eager the heuristic engine is (all bounded, all defaulted safely)."""

    #: A finding below this confidence (or one that could not be re-verified) is confirmed.
    verify_below: int = 70
    #: Hard cap on proposals returned, so a hostile input cannot multiply work (REQ-AGENT-006).
    max_proposals: int = 32
    #: Proposals weaker than this are not worth a probe.
    min_confidence: int = 30


class HeuristicHypothesisEngine:
    """Proposes checks to run, from the rule corpus and the correlation output."""

    name = "heuristic"

    def __init__(
        self,
        index: CheckIndex,
        *,
        policies: HypothesisPolicies | None = None,
    ) -> None:
        self.index = index
        self.policies = policies or HypothesisPolicies()

    def propose(self, source: HypothesisInput) -> tuple[Hypothesis, ...]:
        """Every hypothesis this input supports, best first."""
        candidates: list[Hypothesis] = []
        candidates.extend(self._verify(source))
        candidates.extend(self._unexplored(source))
        candidates.extend(self._chains(source))
        return _rank(candidates, limit=self.policies.max_proposals)

    # ------------------------------------------------------------------ sources
    def _verify(self, source: HypothesisInput) -> list[Hypothesis]:
        """Confirm a finding the analyzer is unsure about (kind ``verify-finding``)."""
        out: list[Hypothesis] = []
        threshold = self.policies.verify_below
        for raw in source.findings:
            line = parse_finding(raw)
            if line is None or line.verdict != "analyzed":
                continue
            if line.verified and line.confidence >= threshold:
                continue
            out.append(
                Hypothesis(
                    id=hypothesis_id(line.check_id, line.asset, HypothesisKind.VERIFY_FINDING),
                    kind=HypothesisKind.VERIFY_FINDING,
                    check_id=line.check_id,
                    asset=line.asset,
                    rationale=(
                        f"{line.check_id} reported {line.severity} at confidence "
                        f"{line.confidence} on {line.asset}"
                        + ("" if line.verified else " without a successful re-verification")
                        + "; confirm it before the report treats it as settled"
                    ),
                    expected_signal=f"a reproducible {line.check_id} finding on {line.asset}",
                    source=self.name,
                    confidence=min(95, line.confidence + 10),
                )
            )
        return out

    def _unexplored(self, source: HypothesisInput) -> list[Hypothesis]:
        """Run the check a rule's family needs but that did not run (kind ``unexplored-rule``)."""
        covered = set(source.covered)
        out: list[Hypothesis] = []
        for raw in source.unexplored:
            line = parse_unexplored(raw)
            if line is None or line.check_id in covered:
                continue
            out.append(
                Hypothesis(
                    id=hypothesis_id(line.check_id, line.asset, HypothesisKind.UNEXPLORED_RULE),
                    kind=HypothesisKind.UNEXPLORED_RULE,
                    check_id=line.check_id,
                    asset=line.asset,
                    rationale=(
                        f"rule {line.rule_id} covers this asset's signals but {line.check_id} "
                        f"never ran against {line.asset}"
                    ),
                    expected_signal=f"the {line.check_id} family's evidence on {line.asset}",
                    source=self.name,
                    confidence=60,
                )
            )
        return out

    def _chains(self, source: HypothesisInput) -> list[Hypothesis]:
        """Confirm the next hop of a correlation group (kind ``chain``)."""
        covered = set(source.covered)
        out: list[Hypothesis] = []
        for raw in source.groups:
            line = parse_group(raw)
            if line is None:
                continue
            next_check = next(
                (check for check in line.check_ids if check and check not in covered), None
            )
            if next_check is None:
                continue
            asset = line.group_key or "scan"
            out.append(
                Hypothesis(
                    id=hypothesis_id(next_check, asset, HypothesisKind.CHAIN),
                    kind=HypothesisKind.CHAIN,
                    check_id=next_check,
                    asset=asset,
                    rationale=(
                        f"correlation rule {line.rule_id} grouped {asset} as a compound "
                        f"({line.severity}); {next_check} is the hop that would confirm it"
                    ),
                    expected_signal=f"the {next_check} finding that completes the chain on {asset}",
                    source=self.name,
                    confidence=max(55, severity_confidence(line.severity)),
                )
            )
        return out


def _rank(candidates: list[Hypothesis], *, limit: int) -> tuple[Hypothesis, ...]:
    """Deterministic ordering and de-duplication, then a hard cap.

    Two proposals with the same ``(check, asset)`` are the same probe; the better-ranked one
    wins, so the same reasoning is never paid for twice in one run.
    """
    ordered = sorted(
        candidates,
        key=lambda item: (
            -item.confidence,
            _KIND_ORDER.get(item.kind, 9),
            item.check_id,
            item.asset,
        ),
    )
    seen: set[tuple[str, str]] = set()
    ranked: list[Hypothesis] = []
    for item in ordered:
        if item.identity in seen:
            continue
        seen.add(item.identity)
        ranked.append(item.model_copy(update={"rank": len(ranked)}))
        if len(ranked) >= max(0, limit):
            break
    return tuple(ranked)
