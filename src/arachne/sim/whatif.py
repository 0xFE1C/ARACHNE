"""What-if simulation: inject a hypothetical state, recompose the paths (REQ-SIM-002).

The engine is deliberately small, because everything interesting is somewhere else. The
estate model comes from :mod:`arachne.sim.model` (scan data only), the hypothetical states
from :mod:`arachne.sim.hypotheses` (validated data), and the path composition from
:func:`arachne.analyzer.paths.build_attack_paths` — **the same composer the verified report
uses**. This module does nothing but join them and mark the result:

1. take the estate graph as scanned, and compose its paths → the **baseline**;
2. apply each hypothesis to a *copy* of the model (a weakness is added, or one is removed by
   an ``applied-fix``) and compose again → the **result**;
3. attach provenance: every result path knows which hypotheses produced the hops that make
   it hypothetical, and every hop knows whether it was observed or introduced.

Two consequences of reusing the composer are worth stating, because they are the honesty of
the feature:

**The staging rules do not fork.** A hypothetical exposure is staged by its CWE exactly as an
observed one is, a chain must still strictly increase through the five stages, and a path's
severity is still its terminal hop's. A simulation that used looser rules would predict
attacks the report would never show — which is the worst possible failure mode for a
capability whose whole purpose is to be believed about a future that has not happened.

**A hypothetical weakness is not an observed one.** A hop is marked
``origin="hypothetical"`` and carries the hypothesis id that put it there; the run carries
``provenance="simulated"``. Nothing here writes to a store, and nothing here returns a
``ReportFinding``: the only objects produced are :class:`SimulationRun` and its parts, which
the report renders in their own section and the gates never read (REQ-SIM-004).

The whole computation runs inside :func:`arachne.sim.boundary.no_network`, so the accept
criterion's other half — *zero target interaction* — is enforced rather than promised.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from typing import Any, Final

from arachne.analyzer.model import severity_rank
from arachne.analyzer.paths import AttackHop, AttackPath, host_of, normalise_check_id
from arachne.core.audit import AuditAction, Auditor
from arachne.core.errors import SimulationError
from arachne.sim.boundary import no_network
from arachne.sim.hypotheses import Hypothesis, HypothesisKind
from arachne.sim.model import (
    EstateGraph,
    EstateWeakness,
    IdentityBinding,
    host_node_id,
    weakness_node_id,
)
from arachne.sim.reachability import ServiceObservation

__all__ = [
    "DEFAULT_MAX_HYPOTHESES",
    "SIM_PROVENANCE",
    "SimulatedHop",
    "SimulatedPath",
    "SimulationRefusal",
    "SimulationRun",
    "apply_hypotheses",
    "exposure_score",
    "simulate",
]

#: The provenance marker every simulated artifact carries (REQ-SIM-004).
SIM_PROVENANCE: Final = "simulated"

#: How many hypotheses one run may carry, absent a deployment setting.
DEFAULT_MAX_HYPOTHESES: Final = 32

#: The exposure weight per severity, for :func:`exposure_score`. Documented rather than
#: tuned: it exists so "before" and "after" can be compared, and a reader can recompute it.
SEVERITY_WEIGHTS: Final[Mapping[str, int]] = {
    "critical": 10,
    "high": 5,
    "medium": 2,
    "low": 1,
    "info": 0,
}

ORIGIN_OBSERVED: Final = "observed"
ORIGIN_HYPOTHETICAL: Final = "hypothetical"


def exposure_score(paths: Sequence[AttackPath]) -> int:
    """A comparable number for a set of paths: the sum of their terminal impacts, weighted.

    A count of paths says nothing about whether a change made things worse — three ``info``
    chains are not worse than one ``critical`` one. The score is the sum over paths of
    :data:`SEVERITY_WEIGHTS` for the path's *business* severity (its terminal impact, floored
    by the asset's CMDB tier, exactly as the report ranks it). Deliberately a simple,
    recomputable arithmetic and never a claim of precision.
    """
    total = 0
    for path in paths:
        severity = (path.business_severity or path.severity or "info").lower()
        total += SEVERITY_WEIGHTS.get(severity, 0)
    return total


@dataclass(frozen=True, slots=True)
class SimulationRefusal:
    """A hypothesis the run could not apply, and why — reported, never silently dropped."""

    hypothesis: Hypothesis
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.hypothesis.id, "reason": self.reason}


@dataclass(frozen=True, slots=True)
class SimulatedHop:
    """One hop of a simulated path, with its origin made explicit."""

    hop: AttackHop
    origin: str
    #: The hypothesis that introduced this hop (``None`` when the scan observed it).
    hypothesis_id: str | None = None

    @property
    def hypothetical(self) -> bool:
        return self.origin == ORIGIN_HYPOTHETICAL

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.hop.check_id,
            "title": self.hop.title,
            "asset": self.hop.asset,
            "stage": self.hop.stage.value,
            "severity": self.hop.severity,
            "origin": self.origin,
            "hypothesis_id": self.hypothesis_id,
            "finding_id": self.hop.finding_id,
        }


@dataclass(frozen=True, slots=True)
class SimulatedPath:
    """A composed path inside a simulation, plus which hypotheses produced it.

    ``provenance`` is the constant ``"simulated"``: it is what a renderer keys on to keep
    this object out of anything that reads observed results.
    """

    path: AttackPath
    hops: tuple[SimulatedHop, ...]
    introduced_by: tuple[str, ...] = ()
    provenance: str = SIM_PROVENANCE

    @property
    def hypothetical(self) -> bool:
        """True when at least one hop exists only because of a hypothesis."""
        return bool(self.introduced_by)

    @property
    def observed_hops(self) -> tuple[SimulatedHop, ...]:
        return tuple(item for item in self.hops if not item.hypothetical)

    @property
    def cheapest_origin(self) -> str | None:
        """Whether the cheapest breaking hop was observed or introduced (``None`` for none)."""
        chosen = self._cheapest()
        return None if chosen is None else chosen.origin

    @property
    def cheapest_hypothesis_id(self) -> str | None:
        chosen = self._cheapest()
        return None if chosen is None else chosen.hypothesis_id

    def _cheapest(self) -> SimulatedHop | None:
        chosen = self.path.cheapest
        if chosen is None:
            return None
        for item in self.hops:
            if item.hop.check_id == chosen.check_id and item.hop.asset == chosen.asset:
                return item
        return None  # pragma: no cover - the composer picks from this path's own hops

    @property
    def cheapest_label(self) -> str:
        """The cheapest break, worded for the simulated world.

        The composer's sentence says "(verified hop)"/"(unverified hop)" because in the
        verified report that is what distinguishes a proven hop from a candidate one. Inside a
        simulation every injected hop is stamped verified by the confidence rule — a
        stipulation does hold in its own world — so reusing that sentence here would print the
        word *verified* in a section whose whole point is that nothing was verified. The choice
        is still the composer's (that is the shared semantics that matters); only the
        qualification follows the hop's origin.
        """
        chosen = self.path.cheapest
        if chosen is None:
            return self.path.cheapest_reason
        match = self._cheapest()
        if match is None or not match.hypothetical:
            return self.path.cheapest_reason
        dependents = len([item for item in self.hops if item.hop.stage.rank >= chosen.stage.rank])
        return (
            f"fix {chosen.check_id} on {chosen.asset} (hypothetical hop introduced by "
            f"{match.hypothesis_id or 'a hypothesis'}): "
            f"{chosen.remediation_summary or 'see the finding'} — "
            f"{dependents} hop(s) depend on it"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.path.id,
            "asset": self.path.asset,
            "severity": self.path.severity,
            "business_severity": self.path.business_severity,
            "criticality": self.path.criticality,
            "stages": [item.hop.stage.value for item in self.hops],
            "hypothetical": self.hypothetical,
            "introduced_by": list(self.introduced_by),
            "cheapest_break": self.cheapest_label,
            "cheapest_origin": self.cheapest_origin,
            "cheapest_hypothesis_id": self.cheapest_hypothesis_id,
            "provenance": self.provenance,
            "hops": [item.to_dict() for item in self.hops],
        }


@dataclass(frozen=True, slots=True)
class SimulationRun:
    """The result of one what-if run (REQ-SIM-002), and never a scan result.

    ``baseline`` is the estate exactly as scanned — the paths the verified report shows — so
    a reader can see what changed without a second command. ``result`` is the estate under the
    hypotheses. Nothing in this object is a finding: it is not a ``ReportFinding``, it is not
    stored in a finding table, and the report renders it in its own section.
    """

    estate_key: str
    model_version: str
    built_from_scans: tuple[int, ...]
    hypotheses: tuple[Hypothesis, ...]
    baseline: tuple[AttackPath, ...]
    result: tuple[SimulatedPath, ...]
    model_before: Mapping[str, int] = field(default_factory=dict)
    model_after: Mapping[str, int] = field(default_factory=dict)
    refusals: tuple[SimulationRefusal, ...] = ()
    provenance: str = SIM_PROVENANCE

    @property
    def introduced(self) -> tuple[SimulatedPath, ...]:
        """Paths that exist only under the hypotheses (by id, so it is exact)."""
        known = {path.id for path in self.baseline}
        return tuple(path for path in self.result if path.path.id not in known)

    @property
    def removed(self) -> tuple[AttackPath, ...]:
        """Baseline paths the hypotheses removed (what an ``applied-fix`` buys)."""
        surviving = {path.path.id for path in self.result}
        return tuple(path for path in self.baseline if path.id not in surviving)

    @property
    def hypothetical(self) -> tuple[SimulatedPath, ...]:
        """Result paths with at least one hop a hypothesis introduced."""
        return tuple(path for path in self.result if path.hypothetical)

    @property
    def exposure_before(self) -> int:
        return exposure_score(self.baseline)

    @property
    def exposure_after(self) -> int:
        return exposure_score([path.path for path in self.result])

    def to_dict(self) -> dict[str, Any]:
        return {
            "provenance": self.provenance,
            "estate_key": self.estate_key,
            "model_version": self.model_version,
            "built_from_scans": list(self.built_from_scans),
            "hypotheses": [item.to_dict() for item in self.hypotheses],
            "refusals": [item.to_dict() for item in self.refusals],
            "model_before": dict(self.model_before),
            "model_after": dict(self.model_after),
            "exposure_before": self.exposure_before,
            "exposure_after": self.exposure_after,
            "baseline_paths": [
                {"id": path.id, "asset": path.asset, "severity": path.severity}
                for path in self.baseline
            ],
            "paths": [item.to_dict() for item in self.result],
        }


def apply_hypotheses(
    graph: EstateGraph, hypotheses: Sequence[Hypothesis]
) -> tuple[EstateGraph, tuple[SimulationRefusal, ...]]:
    """The model under ``hypotheses``, plus a refusal record per hypothesis that did not fit.

    Purely functional — the input graph is never mutated — and never fatal: a hypothesis that
    names an asset the model does not hold (and whose kind does not imply that asset exists)
    or an ``applied-fix`` for a weakness nobody observed is *refused with a reason*, because a
    what-if run that answered "no new paths" to an unapplicable hypothesis would be
    misleading. The refusal is a first-class part of the result.
    """
    current = graph
    refusals: list[SimulationRefusal] = []
    for hypothesis in hypotheses:
        try:
            current = _apply_one(current, hypothesis)
        except SimulationError as exc:
            refusals.append(SimulationRefusal(hypothesis=hypothesis, reason=str(exc)))
    return current, tuple(refusals)


def _apply_one(graph: EstateGraph, hypothesis: Hypothesis) -> EstateGraph:
    host = host_of(hypothesis.asset.strip())
    if hypothesis.kind is HypothesisKind.APPLIED_FIX:
        return _apply_fix(graph, hypothesis, host)

    known = host in graph.hosts or graph.node(host_node_id(host)) is not None
    if not known and hypothesis.kind is not HypothesisKind.NEW_EXPOSURE:
        msg = (
            f"the model holds no host {host!r}: a hypothetical weakness on an asset no scan "
            "has seen would be a model of a different estate"
        )
        raise SimulationError(msg)

    if hypothesis.kind is HypothesisKind.NEW_EXPOSURE and hypothesis.port is not None:
        graph = graph.add_service(
            ServiceObservation(
                host=host,
                port=hypothesis.port,
                protocol="tcp",
                service=hypothesis.service,
                source_check=hypothesis.check_id,
            )
        )
    elif not known:
        # A brand-new exposure implies the host exists: an attacker reaching a service
        # reaches the host behind it. Every other kind requires evidence the host is real.
        graph = graph.add_host(host, attributes={"asset_kinds": ["hypothetical"]})

    if hypothesis.kind is HypothesisKind.COMPROMISED_CREDENTIAL:
        graph = graph.bind_identity(
            IdentityBinding(
                identity=hypothesis.identity or hypothesis.id,
                host=host,
                kind="compromised-credential",
                source=hypothesis.id,
            )
        )

    return graph.add_weakness(_weakness_from_hypothesis(hypothesis, host))


def _apply_fix(graph: EstateGraph, hypothesis: Hypothesis, host: str) -> EstateGraph:
    """Remove an observed weakness — and its stored candidate row, which would otherwise
    come back as an unverified candidate edge and leave the path standing.
    """
    wanted = (hypothesis.target_check_id or "").strip().lower()
    if not wanted:
        msg = "an applied-fix hypothesis needs a target check id"
        raise SimulationError(msg)
    matches = [
        item
        for item in graph.weaknesses
        if item.observed and item.host == host and item.check_id.lower() == wanted
    ]
    if not matches:
        msg = (
            f"the model holds no observed {wanted!r} weakness on {host!r}: an applied fix "
            "can only remove something a scan found"
        )
        raise SimulationError(msg)

    node_ids = {item.node_id for item in matches}
    finding_ids = {item.finding_id for item in matches if item.finding_id is not None}
    edges = tuple(
        edge
        for edge in graph.edges
        if not (edge.source in node_ids and edge.kind.value == "weakens")
    )
    nodes = tuple(node for node in graph.nodes if node.id not in node_ids)
    return replace(
        graph,
        weaknesses=tuple(item for item in graph.weaknesses if item.node_id not in node_ids),
        nodes=nodes,
        edges=edges,
        candidates=_drop_candidates(graph.candidates, finding_ids, wanted, host),
    )


def _drop_candidates(
    candidates: Sequence[Any], finding_ids: set[int], check_id: str, host: str
) -> tuple[Any, ...]:
    """The stored rows that spoke for a weakness the fix removed."""
    out: list[Any] = []
    for record in candidates:
        row_id = _field(record, "id")
        key = normalise_check_id(str(_field(record, "check_key") or ""))
        asset = str(_field(record, "asset_value") or "")
        if row_id is not None and int(row_id) in finding_ids:
            continue
        if key == check_id and host_of(asset) == host:
            continue
        out.append(record)
    return tuple(out)


def _field(record: Any, name: str) -> Any:
    if isinstance(record, Mapping):
        return record.get(name)
    return getattr(record, name, None)


def _weakness_from_hypothesis(hypothesis: Hypothesis, host: str) -> EstateWeakness:
    analysis = hypothesis.as_analysis()
    return EstateWeakness(
        node_id=weakness_node_id(hypothesis.check_id, hypothesis.asset),
        check_id=hypothesis.check_id,
        title=hypothesis.title,
        asset=hypothesis.asset,
        host=host,
        severity=hypothesis.severity,
        confidence=100,
        cwe=hypothesis.cwe,
        finding_id=None,
        verdict="analyzed",
        observed=False,
        introduced_by=hypothesis.id,
        remediation_id=analysis.remediation.id,
        remediation_summary=analysis.remediation.summary,
        remediation_steps=0,
        source=analysis,
    )


def simulate(
    graph: EstateGraph,
    hypotheses: Sequence[Hypothesis] = (),
    *,
    max_hypotheses: int = DEFAULT_MAX_HYPOTHESES,
    max_paths: int = 25,
    min_confidence: int = 55,
    max_depth: int = 5,
    auditor: Auditor | None = None,
    record_audit: bool = True,
) -> SimulationRun:
    """Run a what-if simulation over ``graph`` (REQ-SIM-002). Zero target interaction.

    The baseline is composed from the graph as it stands (so it equals what the verified
    report shows for the same scans), the result from the graph under the hypotheses.
    """
    if len(hypotheses) > max_hypotheses:
        msg = (
            f"the run carries {len(hypotheses)} hypotheses, more than the {max_hypotheses} "
            "this deployment allows (ARACHNE_SIM_MAX_HYPOTHESES)"
        )
        raise SimulationError(msg)

    with no_network(auditor):
        baseline = graph.attack_paths(
            min_confidence=min_confidence, max_paths=max_paths, max_depth=max_depth
        )
        if not hypotheses:
            run = SimulationRun(
                estate_key=graph.estate_key,
                model_version=graph.model_version,
                built_from_scans=graph.built_from_scans,
                hypotheses=(),
                baseline=baseline,
                result=_wrap(baseline, {}),
                model_before=graph.summary(),
                model_after=graph.summary(),
            )
        else:
            injected, refusals = apply_hypotheses(graph, hypotheses)
            origins = {item.check_id: item.id for item in hypotheses}
            composed = injected.attack_paths(
                min_confidence=min_confidence, max_paths=max_paths, max_depth=max_depth
            )
            run = SimulationRun(
                estate_key=graph.estate_key,
                model_version=graph.model_version,
                built_from_scans=graph.built_from_scans,
                hypotheses=tuple(hypotheses),
                baseline=baseline,
                result=_wrap(composed, origins),
                model_before=graph.summary(),
                model_after=injected.summary(),
                refusals=refusals,
            )

    if record_audit and auditor is not None:
        auditor.record(
            AuditAction.SIMULATION_RUN,
            target=run.estate_key,
            reason="what-if simulation (no target interaction)",
            meta={
                "provenance": run.provenance,
                "hypotheses": len(run.hypotheses),
                "paths": len(run.result),
                "introduced": len(run.introduced),
                "refused": len(run.refusals),
                "exposure_before": run.exposure_before,
                "exposure_after": run.exposure_after,
                "scans": list(run.built_from_scans),
            },
        )
    return run


def _wrap(paths: Sequence[AttackPath], origins: Mapping[str, str]) -> tuple[SimulatedPath, ...]:
    """Attach origin and provenance to composed paths."""
    out: list[SimulatedPath] = []
    for path in paths:
        hops = tuple(_originated(hop, origins) for hop in path.hops)
        introduced = tuple(dict.fromkeys(item.hypothesis_id for item in hops if item.hypothesis_id))
        out.append(SimulatedPath(path=path, hops=hops, introduced_by=introduced))
    return tuple(out)


def _originated(hop: AttackHop, origins: Mapping[str, str]) -> SimulatedHop:
    hypothesis_id = origins.get(hop.check_id)
    return SimulatedHop(
        hop=hop,
        origin=ORIGIN_HYPOTHETICAL if hypothesis_id else ORIGIN_OBSERVED,
        hypothesis_id=hypothesis_id,
    )


def severity_sort_key(path: SimulatedPath) -> tuple[int, int, str]:
    """Worst-first ordering for a rendered result (matches the report's own ranking)."""
    business = path.path.business_severity or path.path.severity
    return (-severity_rank(business), -len(path.hops), path.path.asset)
