"""Typed event bus (docs/spec/02- §2.1): the Orchestrator's observable output.

The Orchestrator publishes what happened; the scheduler, the REST API and the webhook
integrations (S11/S12) subscribe. The five domain events the spec names —
``host_discovered``, ``check_completed``, ``finding_raised``, ``analysis_done``,
``report_ready`` — plus the lifecycle events around them are the whole vocabulary.

Three properties matter more than features:

* **Typed payloads, not free-form dicts.** Each domain event has a factory that takes named
  arguments, so the orchestrator cannot publish a ``finding_raised`` without a severity.
* **Subscribers cannot break a scan.** A handler that raises is logged and counted; the
  scan continues (docs/spec/07- §4, "errors are data"). A webhook that is down must not
  abort a scan in progress.
* **Payloads are redacted on construction.** An event can carry target-derived text, so it
  is redacted at emission (F-08-04) — a later subscriber cannot leak what it never got.
"""

from __future__ import annotations

import inspect
import uuid
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Final

from pydantic import BaseModel, ConfigDict, Field, field_validator

from arachne.core.logging import get_logger
from arachne.core.redaction import redact_value

__all__ = [
    "EVENT_SCHEMA_VERSION",
    "Event",
    "EventBus",
    "EventHandler",
    "EventType",
    "Subscription",
]

#: Bumped when the event envelope or payload shapes change.
EVENT_SCHEMA_VERSION: Final = "1.0"

_logger = get_logger("core.events")


class EventType(StrEnum):
    """The event vocabulary.

    Domain events use the spec's snake_case names verbatim (docs/spec/02- §2.1); lifecycle
    events use dotted names so a subscriber can filter ``scan.*`` cheaply.
    """

    SCAN_PLANNED = "scan.planned"
    SCAN_STARTED = "scan.started"
    SCAN_RESUMED = "scan.resumed"
    SCAN_FINISHED = "scan.finished"
    SCAN_FAILED = "scan.failed"
    STEP_STARTED = "step.started"
    STEP_COMPLETED = "step.completed"
    STEP_SKIPPED = "step.skipped"
    HOST_DISCOVERED = "host_discovered"
    CHECK_COMPLETED = "check_completed"
    FINDING_RAISED = "finding_raised"
    ANALYSIS_DONE = "analysis_done"
    REPORT_READY = "report_ready"
    OUT_OF_SCOPE_DISCARDED = "out_of_scope_discarded"
    #: S30 (area FUZZ): bounded safe fuzzing. ``fuzz.aborted`` is the one an operator must
    #: pager on — it is the degradation guard stopping the run, and it carries the measured
    #: signal that stopped it. ``fuzz.candidate`` announces a lead (never a finding), so an
    #: integration can queue it for proof-level verification.
    FUZZ_STARTED = "fuzz.started"
    FUZZ_CANDIDATE = "fuzz.candidate"
    FUZZ_ABORTED = "fuzz.aborted"
    FUZZ_FINISHED = "fuzz.finished"


EventHandler = Callable[["Event"], None] | Callable[["Event"], Awaitable[None]]


class Event(BaseModel):
    """One event. The envelope is fixed; ``payload`` carries the detail, redacted."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = EVENT_SCHEMA_VERSION
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    type: EventType
    ts: datetime = Field(default_factory=lambda: datetime.now(UTC))
    scan_id: int | None = None
    payload: dict[str, Any] = Field(default_factory=dict)

    @field_validator("ts")
    @classmethod
    def _require_tz(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            msg = "event timestamps must be timezone-aware (UTC)"
            raise ValueError(msg)
        return value.astimezone(UTC)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "id": self.id,
            "type": self.type.value,
            "ts": self.ts.isoformat(),
            "scan_id": self.scan_id,
            "payload": self.payload,
        }

    # ------------------------------------------------------------------ domain events
    # Each factory names the fields the event must carry, so an incomplete event cannot
    # be constructed, and redacts the payload at emission (F-08-04).
    @classmethod
    def host_discovered(
        cls,
        *,
        scan_id: int | None,
        host: str,
        kind: str,
        source: str | None = None,
        addresses: tuple[str, ...] = (),
    ) -> Event:
        return cls(
            type=EventType.HOST_DISCOVERED,
            scan_id=scan_id,
            payload=_redact(
                {
                    "host": host,
                    "kind": kind,
                    "source": source,
                    "addresses": list(addresses),
                }
            ),
        )

    @classmethod
    def check_completed(
        cls,
        *,
        scan_id: int | None,
        module: str,
        check: str,
        status: str,
        asset: str | None = None,
        detail: str | None = None,
    ) -> Event:
        return cls(
            type=EventType.CHECK_COMPLETED,
            scan_id=scan_id,
            payload=_redact(
                {
                    "module": module,
                    "check": check,
                    "status": status,
                    "asset": asset,
                    "detail": detail,
                }
            ),
        )

    @classmethod
    def finding_raised(
        cls,
        *,
        scan_id: int | None,
        module: str,
        check: str,
        title: str,
        severity: str | None = None,
        asset: str | None = None,
        cwe: str | None = None,
    ) -> Event:
        return cls(
            type=EventType.FINDING_RAISED,
            scan_id=scan_id,
            payload=_redact(
                {
                    "module": module,
                    "check": check,
                    "title": title,
                    "severity": severity,
                    "asset": asset,
                    "cwe": cwe,
                }
            ),
        )

    @classmethod
    def analysis_done(
        cls,
        *,
        scan_id: int | None,
        engine: str,
        findings: int,
        model: str | None = None,
        provenance: dict[str, Any] | None = None,
    ) -> Event:
        return cls(
            type=EventType.ANALYSIS_DONE,
            scan_id=scan_id,
            payload=_redact(
                {
                    "engine": engine,
                    "findings": findings,
                    "model": model,
                    "provenance": provenance or {},
                }
            ),
        )

    @classmethod
    def report_ready(
        cls,
        *,
        scan_id: int | None,
        report_id: str | None = None,
        formats: tuple[str, ...] = (),
        findings: int = 0,
    ) -> Event:
        return cls(
            type=EventType.REPORT_READY,
            scan_id=scan_id,
            payload=_redact(
                {"report_id": report_id, "formats": list(formats), "findings": findings}
            ),
        )

    @classmethod
    def out_of_scope_discarded(
        cls,
        *,
        scan_id: int | None,
        value: str,
        reason: str,
        origin: str | None = None,
    ) -> Event:
        """A discovered asset was dropped because it is out of scope (F-01-02)."""
        return cls(
            type=EventType.OUT_OF_SCOPE_DISCARDED,
            scan_id=scan_id,
            payload=_redact({"value": value, "reason": reason, "origin": origin}),
        )

    @classmethod
    def fuzz_started(
        cls,
        *,
        scan_id: int | None,
        run_id: str,
        engine: str,
        targets: int = 0,
    ) -> Event:
        """A bounded fuzzing run began (S30, REQ-FUZZ-001)."""
        return cls(
            type=EventType.FUZZ_STARTED,
            scan_id=scan_id,
            payload=_redact(
                {"run_id": run_id, "engine": engine, "targets": targets}
            ),
        )

    @classmethod
    def fuzz_candidate(
        cls,
        *,
        scan_id: int | None,
        run_id: str,
        candidate_id: str,
        grammar: str,
        target: str,
        signal: str,
        verifier: str | None = None,
    ) -> Event:
        """A fuzzing lead was recorded — a candidate, explicitly not a finding."""
        return cls(
            type=EventType.FUZZ_CANDIDATE,
            scan_id=scan_id,
            payload=_redact(
                {
                    "run_id": run_id,
                    "candidate_id": candidate_id,
                    "grammar": grammar,
                    "target": target,
                    "signal": signal,
                    "verifier": verifier,
                }
            ),
        )

    @classmethod
    def fuzz_aborted(
        cls,
        *,
        scan_id: int | None,
        run_id: str,
        target: str,
        reasons: tuple[str, ...] = (),
        sent: int = 0,
    ) -> Event:
        """The degradation guard stopped the run (S30, REQ-FUZZ-005)."""
        return cls(
            type=EventType.FUZZ_ABORTED,
            scan_id=scan_id,
            payload=_redact(
                {
                    "run_id": run_id,
                    "target": target,
                    "reasons": list(reasons),
                    "sent": sent,
                }
            ),
        )

    @classmethod
    def fuzz_finished(
        cls,
        *,
        scan_id: int | None,
        run_id: str,
        cases: int = 0,
        candidates: int = 0,
        aborted: bool = False,
        stop_reason: str | None = None,
    ) -> Event:
        """A fuzzing run ended — completed, aborted or bounded out (S30)."""
        return cls(
            type=EventType.FUZZ_FINISHED,
            scan_id=scan_id,
            payload=_redact(
                {
                    "run_id": run_id,
                    "cases": cases,
                    "candidates": candidates,
                    "aborted": aborted,
                    "stop_reason": stop_reason,
                }
            ),
        )


def _redact(payload: dict[str, Any]) -> dict[str, Any]:
    redacted = redact_value(payload)
    return redacted if isinstance(redacted, dict) else {"value": redacted}


class Subscription:
    """Handle returned by :meth:`EventBus.subscribe`; call it to unsubscribe."""

    def __init__(self, bus: EventBus, event_type: EventType | None, handler: EventHandler) -> None:
        self._bus = bus
        self._event_type = event_type
        self._handler = handler

    def unsubscribe(self) -> None:
        self._bus.unsubscribe(self._event_type, self._handler)

    def __call__(self) -> None:
        self.unsubscribe()


class EventBus:
    """In-process pub/sub with a replayable history.

    The history makes the bus usable as the scheduler/API/webhook source of truth later
    (a subscriber that attaches mid-scan can drain what it missed) and makes tests
    assertion-friendly without a mock framework.
    """

    def __init__(self, *, history_limit: int = 1000) -> None:
        self._subscribers: dict[EventType | None, list[EventHandler]] = {}
        self._history: list[Event] = []
        self._history_limit = history_limit
        self.errors = 0

    # ------------------------------------------------------------------ subscription
    def subscribe(self, event_type: EventType | None, handler: EventHandler) -> Subscription:
        """Register ``handler``; ``event_type=None`` subscribes to every event."""
        self._subscribers.setdefault(event_type, []).append(handler)
        return Subscription(self, event_type, handler)

    def unsubscribe(self, event_type: EventType | None, handler: EventHandler) -> None:
        handlers = self._subscribers.get(event_type)
        if not handlers:
            return
        try:
            handlers.remove(handler)
        except ValueError:
            return
        if not handlers:
            del self._subscribers[event_type]

    def subscriber_count(self, event_type: EventType | None = None) -> int:
        return len(self._subscribers.get(event_type, ()))

    # ------------------------------------------------------------------ publishing
    async def publish(self, event: Event) -> None:
        """Deliver ``event`` to every matching subscriber.

        A raising subscriber is logged and counted but never propagates: the scan must
        survive a broken consumer (docs/spec/07- §4).
        """
        self._history.append(event)
        if len(self._history) > self._history_limit:
            del self._history[: len(self._history) - self._history_limit]

        for handler in (*self._subscribers.get(event.type, ()), *self._subscribers.get(None, ())):
            try:
                result = handler(event)
                if inspect.isawaitable(result):
                    await result
            except Exception as exc:
                self.errors += 1
                _logger.error(
                    "event subscriber failed",
                    extra={
                        "event": "events.subscriber_error",
                        "type": event.type.value,
                        "error": f"{exc.__class__.__name__}: {exc}",
                    },
                )

    async def emit(self, event: Event) -> Event:
        """Convenience: publish and return the event (keeps orchestrator code linear)."""
        await self.publish(event)
        return event

    # ------------------------------------------------------------------ inspection
    def history(self, event_type: EventType | None = None) -> tuple[Event, ...]:
        if event_type is None:
            return tuple(self._history)
        return tuple(event for event in self._history if event.type is event_type)

    def drain(self) -> tuple[Event, ...]:
        """Return the history and clear it (used by a polling consumer)."""
        drained = tuple(self._history)
        self._history.clear()
        return drained

    def types(self) -> tuple[EventType, ...]:
        """Event types seen so far, in first-seen order."""
        return tuple(dict.fromkeys(event.type for event in self._history))
