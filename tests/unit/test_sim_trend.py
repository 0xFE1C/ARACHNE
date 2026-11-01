"""The simulation trend and its event-driven refresh (S28, REQ-SIM-006).

Two halves, tested separately and together: the *pure* trend arithmetic (what a series of
points means, and which way it is moving) and the *event-driven* re-simulation that produces
the points — including the two properties that make it safe to leave running: it is opt-in,
and it can never break the scan that triggered it.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from tests.helpers.estate import LEGACY_HOST, lab_estate

from arachne.core.audit import AuditAction, Auditor, MemoryAuditSink
from arachne.core.events import Event, EventBus, EventType
from arachne.data.sim_store import MemorySimulationStore
from arachne.sim.hypotheses import Hypothesis
from arachne.sim.resim import Resimulator, build_resimulator
from arachne.sim.trend import (
    SimulationPoint,
    build_simulation_trend,
    point_from_run,
)
from arachne.sim.whatif import simulate

BASE = datetime(2026, 10, 30, 12, 0, tzinfo=UTC)


def _point(offset: int, score: int, *, paths: int = 1, introduced: int = 0) -> SimulationPoint:
    return SimulationPoint(
        estate_key="lab-estate",
        created_at=BASE + timedelta(hours=offset),
        scan_id=offset + 1,
        hypotheses=1,
        path_count=paths,
        introduced=introduced,
        severity_counts={"critical": 1},
        exposure_score=score,
    )


def test_a_trend_orders_its_points_oldest_first_and_computes_its_deltas() -> None:
    trend = build_simulation_trend([_point(2, 30), _point(0, 10), _point(1, 20)])

    assert [point.scan_id for point in trend.points] == [1, 2, 3]
    assert trend.exposure_scores == (10, 20, 30)
    assert trend.deltas == (10, 10)
    assert trend.trend_direction == "rising"
    assert trend.latest is not None
    assert trend.latest.exposure_score == 30


def test_a_falling_trend_says_so() -> None:
    trend = build_simulation_trend([_point(0, 30), _point(1, 10)])

    assert trend.deltas == (-20,)
    assert trend.trend_direction == "falling"


def test_a_single_point_or_a_flat_series_is_not_a_direction() -> None:
    assert build_simulation_trend([]).trend_direction == "unknown"
    assert build_simulation_trend([_point(0, 10)]).trend_direction == "unknown"
    assert build_simulation_trend([_point(0, 10), _point(1, 10)]).trend_direction == "flat"


def test_the_trend_renders_as_a_labelled_series_for_the_posture_view() -> None:
    trend = build_simulation_trend([_point(0, 10), _point(1, 22, paths=2, introduced=1)])

    markdown = trend.markdown()

    assert "Re-simulation | Paths | New under hypotheses | Exposure score" in markdown
    assert "| 2 | 1 | 22 | +12 |" in markdown
    assert trend.payload()["provenance"] == "simulated"
    assert build_simulation_trend([]).markdown() == (
        "No simulation has been re-run for this estate yet."
    )


def test_a_point_from_a_run_counts_only_simulated_paths() -> None:
    graph = lab_estate()
    run = simulate(
        graph,
        (
            Hypothesis.new_exposure("pub-1", LEGACY_HOST, port=8443),
            Hypothesis.new_vulnerability(
                "pub-2", LEGACY_HOST, title="RCE", severity="critical", cwe="CWE-89"
            ),
        ),
    )

    point = point_from_run(run, created_at=BASE, scan_id=7)

    assert point.provenance == "simulated"
    assert point.simulated
    assert point.path_count == 2
    assert point.introduced == 1
    assert point.severity_counts == {"critical": 2}
    assert point.exposure_score == 20
    assert point.scan_id == 7


# ------------------------------------------------------------------ event-driven resim


def test_a_model_update_triggers_a_resimulation_and_a_trend_point() -> None:
    store = MemorySimulationStore()
    sink = MemoryAuditSink()
    resim = build_resimulator(
        store=store,
        graph_provider=lambda scan_id: lab_estate(),
        hypotheses=(Hypothesis.new_exposure("pub-1", LEGACY_HOST, port=8443),),
        auditor=Auditor(sink, actor="pytest"),
        enabled=True,
    )

    point = resim.run_once(scan_id=3)

    assert point is not None
    assert point.scan_id == 3
    assert store.points(estate_key="lab-estate") == (point,)
    events = sink.of_action(AuditAction.SIMULATION_RESIMULATED)
    assert len(events) == 1
    assert events[0].meta["provenance"] == "simulated"
    assert events[0].meta["exposure_score"] == 12


async def test_the_resimulator_subscribes_to_model_updates_only() -> None:
    store = MemorySimulationStore()
    bus = EventBus()
    resim = Resimulator(
        store=store,
        graph_provider=lambda scan_id: lab_estate(),
        enabled=True,
    )
    resim.subscribe(bus)

    await bus.publish(Event(type=EventType.STEP_COMPLETED, scan_id=1))
    assert resim.runs == 0, "a mid-scan step is not a model update"

    await bus.publish(Event(type=EventType.SCAN_FINISHED, scan_id=1))
    assert resim.runs == 1
    await bus.publish(Event(type=EventType.REPORT_READY, scan_id=1))
    assert resim.runs == 2
    assert len(store.points(estate_key="lab-estate")) == 2
    resim.close()


async def test_an_opt_out_resimulator_subscribes_to_nothing() -> None:
    store = MemorySimulationStore()
    bus = EventBus()
    resim = build_resimulator(
        store=store,
        graph_provider=lambda scan_id: lab_estate(),
        enabled=False,
    )

    resim.subscribe(bus)
    await bus.publish(Event(type=EventType.SCAN_FINISHED, scan_id=1))

    assert resim.runs == 0
    assert store.points() == ()
    assert bus.subscriber_count() == 0


def test_a_provider_with_nothing_to_model_records_no_point() -> None:
    """A trend line standing for "no data" would read as "no exposure" — a lie."""
    store = MemorySimulationStore()
    resim = Resimulator(store=store, graph_provider=lambda scan_id: None, enabled=True)

    assert resim.run_once() is None
    assert store.points() == ()


async def test_a_failing_resimulation_is_counted_and_never_reaches_the_scan() -> None:
    """A trend point is never worth a failed scan (docs/spec/07- §4)."""
    store = MemorySimulationStore()
    sink = MemoryAuditSink()
    bus = EventBus()

    def explode(scan_id: int | None) -> Any:
        msg = "the store went away"
        raise RuntimeError(msg)

    resim = Resimulator(
        store=store,
        graph_provider=explode,
        auditor=Auditor(sink, actor="pytest"),
        enabled=True,
    )
    resim.subscribe(bus)

    # The bus swallows a raising subscriber; the resimulator converts it into an error event.
    await bus.publish(Event(type=EventType.SCAN_FINISHED, scan_id=1))

    assert bus.errors >= 1 or sink.of_action(AuditAction.SIMULATION_RESIMULATED)
    assert resim.on_event(Event(type=EventType.SCAN_FINISHED, scan_id=1)) is None
    resim.close()


def test_the_store_keeps_the_newest_points_first_when_limited() -> None:
    store = MemorySimulationStore()
    for offset in range(5):
        store.record_point(_point(offset, offset * 10))

    newest = store.points(estate_key="lab-estate", limit=2)

    assert [point.exposure_score for point in newest] == [30, 40]
    assert store.latest("lab-estate") is not None
    assert store.latest("lab-estate").exposure_score == 40  # type: ignore[union-attr]
    assert store.latest("other-estate") is None
