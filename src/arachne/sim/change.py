"""Change simulation: the before/after exposure delta of a proposed design (REQ-SIM-005).

"What happens if we publish this service, retire that legacy application, and rotate the
shared admin password?" is a design question, and the honest answer is a *comparison*, not a
number: the paths that exist now, the paths that would exist after, and the difference. This
module produces exactly that, using the same engine as any other what-if run
(:func:`arachne.sim.whatif.simulate`), so a change is measured with the same staging rules,
the same composer and the same exposure arithmetic an operator can recompute.

The delta is deliberately three lists rather than one score: ``introduced`` (paths that only
exist after), ``removed`` (paths the change closes — what an ``applied-fix`` hypothesis buys)
and the two exposure scores. A change that trades one critical path for three low ones is
visible as such, and no weighting has to be trusted to see it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from arachne.analyzer.paths import AttackPath
from arachne.core.audit import Auditor
from arachne.sim.hypotheses import ChangeSet
from arachne.sim.whatif import (
    SIM_PROVENANCE,
    SimulatedPath,
    SimulationRun,
    simulate,
)

__all__ = ["ChangeDelta", "simulate_change"]


@dataclass(frozen=True, slots=True)
class ChangeDelta:
    """The before/after of one proposed change (REQ-SIM-005)."""

    change: ChangeSet
    before: tuple[SimulatedPath, ...]
    after: tuple[SimulatedPath, ...]
    introduced: tuple[SimulatedPath, ...]
    removed: tuple[AttackPath, ...]
    refusals: tuple[Any, ...] = ()
    provenance: str = SIM_PROVENANCE
    #: The estate this change was measured against, and the scans its model was built from.
    estate_key: str = ""
    built_from_scans: tuple[int, ...] = ()

    @property
    def exposure_before(self) -> int:
        return _score(self.before)

    @property
    def exposure_after(self) -> int:
        return _score(self.after)

    @property
    def exposure_delta(self) -> int:
        """After minus before: positive is worse, negative is an improvement."""
        return self.exposure_after - self.exposure_before

    def to_dict(self) -> dict[str, Any]:
        return {
            "provenance": self.provenance,
            "name": self.change.name,
            "description": self.change.description,
            "hypotheses": [item.to_dict() for item in self.change.hypotheses],
            "exposure_before": self.exposure_before,
            "exposure_after": self.exposure_after,
            "exposure_delta": self.exposure_delta,
            "paths_before": len(self.before),
            "paths_after": len(self.after),
            "introduced": [item.to_dict() for item in self.introduced],
            "removed": [
                {"id": path.id, "asset": path.asset, "severity": path.severity}
                for path in self.removed
            ],
            "refusals": [
                item.to_dict() if hasattr(item, "to_dict") else {"reason": str(item)}
                for item in self.refusals
            ],
        }


def _score(paths: tuple[SimulatedPath, ...]) -> int:
    from arachne.sim.whatif import exposure_score

    return exposure_score([item.path for item in paths])


def simulate_change(
    graph: Any,
    change: ChangeSet,
    *,
    max_hypotheses: int = 32,
    max_paths: int = 25,
    min_confidence: int = 55,
    max_depth: int = 5,
    auditor: Auditor | None = None,
    record_audit: bool = True,
) -> ChangeDelta:
    """Simulate ``change`` against ``graph`` and report the delta (REQ-SIM-005).

    One engine call: the baseline of the returned run *is* the "before" estate, which is what
    keeps the two halves of the comparison from drifting apart.
    """
    run: SimulationRun = simulate(
        graph,
        change.hypotheses,
        max_hypotheses=max_hypotheses,
        max_paths=max_paths,
        min_confidence=min_confidence,
        max_depth=max_depth,
        auditor=auditor,
        record_audit=record_audit,
    )
    before = tuple(SimulatedPath(path=path, hops=()) for path in run.baseline)
    return ChangeDelta(
        change=change,
        before=before,
        after=run.result,
        introduced=run.introduced,
        removed=run.removed,
        refusals=run.refusals,
        estate_key=run.estate_key,
        built_from_scans=run.built_from_scans,
    )
