"""Area SIM — simulation & what-if modeling (S28; REQ-SIM-001...006).

*Answer "what if?" without touching anything. The estate becomes a model; hypotheticals
become attack paths — computed purely, with zero target interaction, structurally enforced.*

The package is laid out as one module per question the area answers, and every one of them is
pure:

:mod:`~arachne.sim.model`
    the estate as a queryable graph — hosts, observed services, identity relationships and
    the findings that sit on them — built from stored scan data and nothing else
    (REQ-SIM-001).
:mod:`~arachne.sim.reachability`
    the one honest source of reachability: the ports a scan observed *answering*.
:mod:`~arachne.sim.hypotheses`
    the hypothetical states a run injects, as validated data (REQ-SIM-002).
:mod:`~arachne.sim.whatif`
    the engine: inject, recompose with the verified report's own composer, mark the result
    ``simulated`` (REQ-SIM-002/004).
:mod:`~arachne.sim.change`
    before/after exposure deltas for a proposed design change (REQ-SIM-005).
:mod:`~arachne.sim.trend`
    the simulation trend a re-simulation feeds into the posture view (REQ-SIM-006).
:mod:`~arachne.sim.resim`
    the event-driven re-simulation itself (REQ-SIM-006).
:mod:`~arachne.sim.boundary`
    the zero-network enforcement: a socket-denying guard around every entry point
    (REQ-SIM-003), failing closed and audited.
:mod:`~arachne.sim.hygiene`
    the same guarantee expressed statically — the imports this package may not contain, with
    the scanner that proves it.

Two invariants hold across the whole package and are what the hard rules of the area mean in
practice:

* **Nothing here performs I/O.** No socket, no HTTP client, no store: a simulation receives
  plain values the composition root read, and returns plain values. The boundary enforces it
  at runtime and :mod:`~arachne.sim.hygiene` enforces it at the source level.
* **Nothing here is a finding.** A simulated result is a :class:`~arachne.sim.whatif
  .SimulationRun`, rendered in its own report section with ``simulated`` provenance. It never
  reaches a finding store, and the gate verdicts — which read severity counts from the
  ``findings`` table — cannot see it (REQ-SIM-004).
"""

from __future__ import annotations

from arachne.sim.change import ChangeDelta, simulate_change
from arachne.sim.hypotheses import (
    ChangeSet,
    Hypothesis,
    HypothesisKind,
    load_change_set,
    load_hypotheses,
    parse_change_set,
    parse_hypotheses,
)
from arachne.sim.model import (
    ESTATE_MODEL_VERSION,
    EdgeKind,
    EstateEdge,
    EstateGraph,
    EstateNode,
    EstateWeakness,
    IdentityBinding,
    NodeKind,
    build_estate_graph,
)
from arachne.sim.reachability import ServiceObservation, services_from_candidates
from arachne.sim.resim import Resimulator, build_resimulator
from arachne.sim.trend import (
    SimulationPoint,
    SimulationStore,
    SimulationTrend,
    build_simulation_trend,
    point_from_run,
)
from arachne.sim.whatif import (
    SIM_PROVENANCE,
    SimulatedHop,
    SimulatedPath,
    SimulationRefusal,
    SimulationRun,
    apply_hypotheses,
    exposure_score,
    simulate,
)

__all__ = [
    "ESTATE_MODEL_VERSION",
    "SIM_PROVENANCE",
    "ChangeDelta",
    "ChangeSet",
    "EdgeKind",
    "EstateEdge",
    "EstateGraph",
    "EstateNode",
    "EstateWeakness",
    "Hypothesis",
    "HypothesisKind",
    "IdentityBinding",
    "NodeKind",
    "Resimulator",
    "ServiceObservation",
    "SimulatedHop",
    "SimulatedPath",
    "SimulationPoint",
    "SimulationRefusal",
    "SimulationRun",
    "SimulationStore",
    "SimulationTrend",
    "apply_hypotheses",
    "build_estate_graph",
    "build_resimulator",
    "build_simulation_trend",
    "exposure_score",
    "load_change_set",
    "load_hypotheses",
    "parse_change_set",
    "parse_hypotheses",
    "point_from_run",
    "services_from_candidates",
    "simulate",
    "simulate_change",
]
