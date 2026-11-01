"""Event-driven re-simulation: the outlook refreshes when the estate changes (REQ-SIM-006).

A model is only current if it is rebuilt when its inputs move, and area SIM's inputs move for
exactly one reason: a scan finished and stored new data. This module subscribes to that
event, rebuilds the estate graph through a caller-supplied provider, re-runs the baseline
simulation, and appends a :class:`~arachne.sim.trend.SimulationPoint` — which is what feeds the
posture trend the operator watches.

Three properties make it safe to leave running, and each is a decision worth naming:

**It is opt-in.** ``ARACHNE_SIM_RESIMULATE`` (``SimSettings.resimulate``) defaults to false, so
a deployment that never asked for continuous simulation runs exactly the pipeline it ran
before. Consistent with every other capability in the program that watches an estate
continuously.

**It cannot break a scan.** The handler returns ``None`` and swallows nothing: the event bus
already logs and counts a subscriber that raises (``EventBus.errors``), so a re-simulation
that fails is a counted error and never a failed scan. The subscription is also the *only*
thing the resimulator asks of the bus — it publishes nothing.

**It never simulates without a model.** The provider returns ``None`` when the estate has no
scan data yet (nothing to model), and the resimulator records nothing rather than inventing an
empty estate: a trend point that stood for "no data" would read as "no exposure".

Interval-driven re-simulation is a different thing and already exists: the scheduler runs
scans, and each finished scan is the event this watches.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Final

from arachne.core.audit import AuditAction, Auditor, AuditOutcome
from arachne.core.events import Event, EventBus, EventType
from arachne.sim.hypotheses import Hypothesis
from arachne.sim.model import EstateGraph
from arachne.sim.trend import SimulationPoint, SimulationStore, point_from_run
from arachne.sim.whatif import SimulationRun, simulate

__all__ = ["RESIMULATION_EVENTS", "Resimulator", "build_resimulator"]

#: The model-update events a re-simulation reacts to. Both mean the same thing for the model
#: — "a scan stored new data" — and a scan that produced no report still changed the estate.
RESIMULATION_EVENTS: Final[tuple[EventType, ...]] = (
    EventType.SCAN_FINISHED,
    EventType.REPORT_READY,
)


@dataclass
class Resimulator:
    """Keeps the simulation trend current by re-running on model updates (REQ-SIM-006).

    ``graph_provider`` is the seam that reads the stores: it is called with the event's scan
    id and returns the refreshed model, or ``None`` when there is nothing to model. Keeping it
    injected is what lets this module stay storage-free and what lets a test drive the whole
    path without a database.
    """

    store: SimulationStore
    graph_provider: Callable[[int | None], EstateGraph | None]
    hypotheses: tuple[Hypothesis, ...] = ()
    auditor: Auditor | None = None
    enabled: bool = True
    max_paths: int = 25
    min_confidence: int = 55
    _subscription: Any = field(default=None, repr=False)
    runs: int = field(default=0, repr=False)

    def subscribe(self, bus: EventBus) -> None:
        """Attach to the model-update events (idempotent per resimulator)."""
        if self._subscription is not None or not self.enabled:
            return

        def handler(event: Event) -> None:
            self.on_event(event)

        self._subscription = bus.subscribe(None, handler)

    def close(self) -> None:
        """Detach from the bus: a closed re-simulator records no further points."""
        if self._subscription is not None:
            self._subscription.unsubscribe()
            self._subscription = None

    def on_event(self, event: Event) -> SimulationPoint | None:
        """Re-simulate on a model update. Data, not control flow: never raises at the caller.

        The bus would swallow and count a raise anyway; catching here means the trend simply
        misses a point instead of the deployment logging a subscriber error for a condition
        (an empty estate, a provider that cannot read yet) that is normal during startup.
        """
        if not self.enabled or event.type not in RESIMULATION_EVENTS:
            return None
        try:
            return self.run_once(scan_id=event.scan_id)
        except Exception:
            if self.auditor is not None:
                self.auditor.record(
                    AuditAction.SIMULATION_RESIMULATED,
                    outcome=AuditOutcome.ERROR,
                    reason="re-simulation failed; the trend keeps its previous point",
                    scan_id=event.scan_id,
                )
            return None

    def run_once(self, *, scan_id: int | None = None) -> SimulationPoint | None:
        """Rebuild the model, re-simulate, and record one trend point."""
        graph = self.graph_provider(scan_id)
        if graph is None:
            return None
        run: SimulationRun = simulate(
            graph,
            self.hypotheses,
            max_paths=self.max_paths,
            min_confidence=self.min_confidence,
            auditor=self.auditor,
            record_audit=False,
        )
        point = point_from_run(run, scan_id=scan_id)
        stored = self.store.record_point(point)
        self.runs += 1
        if self.auditor is not None:
            self.auditor.record(
                AuditAction.SIMULATION_RESIMULATED,
                target=stored.estate_key,
                reason="event-driven re-simulation on a model update",
                scan_id=scan_id,
                meta={
                    "provenance": stored.provenance,
                    "paths": stored.path_count,
                    "introduced": stored.introduced,
                    "exposure_score": stored.exposure_score,
                    "hypotheses": stored.hypotheses,
                },
            )
        return stored


def build_resimulator(
    *,
    store: SimulationStore,
    graph_provider: Callable[[int | None], EstateGraph | None],
    hypotheses: tuple[Hypothesis, ...] = (),
    auditor: Auditor | None = None,
    enabled: bool = False,
    max_paths: int = 25,
    min_confidence: int = 55,
) -> Resimulator:
    """The re-simulator a deployment gets, from its settings (S28, REQ-SIM-006)."""
    return Resimulator(
        store=store,
        graph_provider=graph_provider,
        hypotheses=hypotheses,
        auditor=auditor,
        enabled=enabled,
        max_paths=max_paths,
        min_confidence=min_confidence,
    )
