"""The typed event bus ."""

from __future__ import annotations

from datetime import UTC

import pytest

from arachne.core.events import EVENT_SCHEMA_VERSION, Event, EventBus, EventType


def test_the_five_spec_domain_events_exist_with_spec_names() -> None:
    assert EventType.HOST_DISCOVERED.value == "host_discovered"
    assert EventType.CHECK_COMPLETED.value == "check_completed"
    assert EventType.FINDING_RAISED.value == "finding_raised"
    assert EventType.ANALYSIS_DONE.value == "analysis_done"
    assert EventType.REPORT_READY.value == "report_ready"


def test_lifecycle_events_are_dotted_for_cheap_filtering() -> None:
    assert EventType.SCAN_STARTED.value.startswith("scan.")
    assert EventType.STEP_COMPLETED.value.startswith("step.")


def test_domain_event_factories_build_typed_payloads() -> None:
    host = Event.host_discovered(
        scan_id=7, host="api.example.com", kind="host", addresses=("1.2.3.4",)
    )
    assert host.type is EventType.HOST_DISCOVERED
    assert host.payload["host"] == "api.example.com"
    assert host.payload["addresses"] == ["1.2.3.4"]

    check = Event.check_completed(
        scan_id=7, module="M4", check="env-file-probe", status="vulnerable"
    )
    assert check.payload["check"] == "env-file-probe"

    finding = Event.finding_raised(
        scan_id=7, module="M4", check="env-file-probe", title=".env exposed", severity="high"
    )
    assert finding.payload["severity"] == "high"

    analysis = Event.analysis_done(scan_id=7, engine="heuristic", findings=3)
    assert analysis.payload["engine"] == "heuristic"

    report = Event.report_ready(scan_id=7, report_id="r-1", formats=("md", "json"))
    assert report.payload["formats"] == ["md", "json"]


def test_event_payloads_are_redacted_at_emission() -> None:
    """An event can carry target-derived text, so it is redacted where it is built."""
    event = Event.host_discovered(
        scan_id=1,
        host="example.com",
        kind="url",
        source="https://example.com/?api_key=AKIAIOSFODNN7EXAMPLE",
    )
    assert "AKIAIOSFODNN7EXAMPLE" not in event.payload["source"]


def test_event_timestamps_must_be_timezone_aware() -> None:
    from datetime import datetime

    from pydantic import ValidationError

    with pytest.raises(ValidationError):
        Event(type=EventType.SCAN_STARTED, ts=datetime(2026, 1, 1))
    assert Event(type=EventType.SCAN_STARTED).ts.tzinfo is UTC


def test_event_envelope_is_serializable() -> None:
    payload = Event(type=EventType.SCAN_STARTED, scan_id=3).to_dict()
    assert payload["schema_version"] == EVENT_SCHEMA_VERSION
    assert payload["type"] == "scan.started"
    assert payload["scan_id"] == 3


async def test_subscribers_receive_only_their_event_type() -> None:
    bus = EventBus()
    seen: list[str] = []
    bus.subscribe(EventType.HOST_DISCOVERED, lambda event: seen.append("host"))
    bus.subscribe(EventType.SCAN_STARTED, lambda event: seen.append("scan"))

    await bus.publish(Event(type=EventType.HOST_DISCOVERED))
    await bus.publish(Event(type=EventType.FINDING_RAISED))

    assert seen == ["host"]
    assert bus.subscriber_count(EventType.HOST_DISCOVERED) == 1


async def test_a_wildcard_subscriber_sees_everything() -> None:
    bus = EventBus()
    seen: list[EventType] = []
    bus.subscribe(None, lambda event: seen.append(event.type))

    await bus.publish(Event(type=EventType.SCAN_STARTED))
    await bus.publish(Event(type=EventType.REPORT_READY))

    assert seen == [EventType.SCAN_STARTED, EventType.REPORT_READY]


async def test_async_handlers_are_awaited() -> None:
    bus = EventBus()
    seen: list[str] = []

    async def handler(event: Event) -> None:
        seen.append(event.type.value)

    bus.subscribe(None, handler)
    await bus.publish(Event(type=EventType.ANALYSIS_DONE))
    assert seen == ["analysis_done"]


async def test_a_failing_subscriber_never_breaks_the_scan() -> None:
    """: a broken consumer (a webhook, say) must not abort a scan."""
    bus = EventBus()
    seen: list[str] = []

    def boom(event: Event) -> None:
        raise RuntimeError("subscriber exploded")

    async def ok(event: Event) -> None:
        seen.append("ok")

    bus.subscribe(EventType.SCAN_STARTED, boom)
    bus.subscribe(EventType.SCAN_STARTED, ok)

    await bus.emit(Event(type=EventType.SCAN_STARTED))

    assert seen == ["ok"]
    assert bus.errors == 1


async def test_async_subscriber_failure_is_isolated_too() -> None:
    bus = EventBus()

    async def boom(event: Event) -> None:
        raise RuntimeError("async boom")

    bus.subscribe(None, boom)
    await bus.publish(Event(type=EventType.SCAN_FAILED))
    assert bus.errors == 1


async def test_emit_returns_the_event() -> None:
    bus = EventBus()
    event = Event(type=EventType.SCAN_FINISHED)
    assert await bus.emit(event) is event


async def test_unsubscribe_stops_delivery() -> None:
    bus = EventBus()
    seen: list[Event] = []
    subscription = bus.subscribe(None, seen.append)

    await bus.publish(Event(type=EventType.SCAN_STARTED))
    subscription.unsubscribe()
    await bus.publish(Event(type=EventType.SCAN_STARTED))

    assert len(seen) == 1
    assert bus.subscriber_count() == 0


async def test_unsubscribing_twice_is_harmless() -> None:
    bus = EventBus()
    subscription = bus.subscribe(None, lambda event: None)
    subscription()
    subscription()
    assert bus.subscriber_count() == 0


async def test_history_is_replayable_and_drainable() -> None:
    bus = EventBus()
    await bus.publish(Event(type=EventType.SCAN_STARTED, scan_id=1))
    await bus.publish(Event(type=EventType.HOST_DISCOVERED, scan_id=1))
    await bus.publish(Event(type=EventType.SCAN_FINISHED, scan_id=1))

    assert len(bus.history()) == 3
    assert len(bus.history(EventType.HOST_DISCOVERED)) == 1
    assert bus.types() == (
        EventType.SCAN_STARTED,
        EventType.HOST_DISCOVERED,
        EventType.SCAN_FINISHED,
    )

    drained = bus.drain()
    assert len(drained) == 3
    assert bus.history() == ()


async def test_history_is_bounded() -> None:
    bus = EventBus(history_limit=2)
    for _ in range(5):
        await bus.publish(Event(type=EventType.STEP_STARTED))
    assert len(bus.history()) == 2


def test_out_of_scope_event_carries_the_reason() -> None:
    event = Event.out_of_scope_discarded(
        scan_id=2, value="https://elsewhere.example/", reason="host is not in the declared scope"
    )
    assert event.type is EventType.OUT_OF_SCOPE_DISCARDED
    assert event.payload["reason"] == "host is not in the declared scope"


def test_bus_with_a_zero_history_limit_still_delivers() -> None:
    bus = EventBus(history_limit=0)
    assert bus.history() == ()


@pytest.mark.parametrize("event_type", list(EventType))
def test_every_event_type_round_trips_through_json(event_type: EventType) -> None:
    import json

    document = json.loads(json.dumps(Event(type=event_type, scan_id=1).to_dict()))
    assert document["type"] == event_type.value
