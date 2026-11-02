"""OpenTelemetry-style tracing: opt-in, sampled, and never in the scan's way (REQ-OPS-004).

Why this is hand-written rather than ``opentelemetry-sdk``:

* **Opt-in means dependency-light too.** Tracing is off unless a deployment configures a
  collector, so the default install must not pay for it. The API this module exposes is the
  small part of the OpenTelemetry data model ARACHNE needs — a span with a name, a parent,
  attributes, a status and a start/end time — and W3C ``traceparent`` propagation, so the
  spans travel under the standard header into whatever collector the operator runs.
* **Spans are redacted like everything else.** Attributes are passed through
  :func:`~arachne.core.redaction.redact_value` before they are recorded, so a trace can carry
  a URL (the HTTP client's span wants one) without carrying the credential in its query
  string. This is the same capture-time rule evidence and audit follow.
* **A trace failure cannot fail a scan.** The exporter is a best-effort sink: an
  unreachable collector, a rejected payload or a serialization error is logged and dropped.
  Tracing observes the scan; it is never part of it.

The transport is :class:`~arachne.core.http.ScopedHttpClient` — the one egress path — pinned
to the collector's host, so an operator's deployment scope, TLS policy and audit trail apply
to traces exactly as they do to a scan.
"""

from __future__ import annotations

import contextvars
import json
import secrets
import time
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Final, Protocol

from arachne.core.config import ObservabilitySettings, Settings, get_settings
from arachne.core.logging import get_logger
from arachne.core.redaction import redact_value

__all__ = [
    "EXPORTER_KIND_INTERNAL",
    "InMemoryExporter",
    "NoopTracer",
    "OtlpJsonExporter",
    "Span",
    "SpanExporter",
    "Tracer",
    "configure_tracing",
    "get_tracer",
    "reset_tracer",
]

_logger = get_logger("core.tracing")

#: OTLP span kind for an internal span (the only kind ARACHNE emits; 2 == SERVER, 3 == CLIENT).
EXPORTER_KIND_INTERNAL: Final = 1
OTLP_SPAN_KIND_CLIENT: Final = 3

#: Spans buffered before an export is attempted.
_MAX_BATCH: Final = 64

#: Attributes recorded for one span are bounded: a trace is for a 4xx-vs-5xx question, not
#: for archiving target content.
_MAX_ATTRIBUTE_LENGTH: Final = 512


def _hex_id(bytes_len: int) -> str:
    return secrets.token_hex(bytes_len)


def _now_unix_nano() -> int:
    return time.time_ns()


def _traceparent(trace_id: str, span_id: str, sampled: bool) -> str:
    """The W3C ``traceparent`` header value for a span."""
    return f"00-{trace_id}-{span_id}-{'01' if sampled else '00'}"


def _otel_value(value: Any) -> dict[str, Any]:
    """One OTLP ``KeyValue`` value, in the JSON encoding."""
    if isinstance(value, bool):
        return {"boolValue": value}
    if isinstance(value, int):
        return {"intValue": str(value)}
    if isinstance(value, float):
        return {"doubleValue": value}
    return {"stringValue": str(value)[:_MAX_ATTRIBUTE_LENGTH]}


@dataclass(slots=True)
class Span:
    """One recorded span (mutable while open, serialized once it ends)."""

    name: str
    trace_id: str
    span_id: str
    parent_span_id: str | None
    sampled: bool
    kind: int = EXPORTER_KIND_INTERNAL
    started_ns: int = field(default_factory=_now_unix_nano)
    ended_ns: int | None = None
    attributes: dict[str, Any] = field(default_factory=dict)
    events: list[tuple[str, dict[str, Any]]] = field(default_factory=list)
    status: str = "unset"
    status_message: str | None = None

    def set_attribute(self, key: str, value: Any) -> None:
        if not self.sampled:
            return
        redacted = redact_value(value)
        self.attributes[key] = _truncate(redacted)

    def set_status(self, status: str, message: str | None = None) -> None:
        """``unset`` | ``ok`` | ``error``."""
        if not self.sampled:
            return
        self.status = status
        self.status_message = message[:_MAX_ATTRIBUTE_LENGTH] if message else None

    def add_event(self, name: str, attributes: Mapping[str, Any] | None = None) -> None:
        if not self.sampled:
            return
        redacted = redact_value(dict(attributes or {}))
        safe = redacted if isinstance(redacted, dict) else {"value": redacted}
        self.events.append((name, {str(k): _truncate(v) for k, v in safe.items()}))

    @property
    def duration_ms(self) -> float:
        end = self.ended_ns if self.ended_ns is not None else _now_unix_nano()
        return (end - self.started_ns) / 1_000_000

    @property
    def traceparent(self) -> str:
        return _traceparent(self.trace_id, self.span_id, self.sampled)

    def to_otlp(self) -> dict[str, Any]:
        """The OTLP/JSON representation of this span."""
        payload: dict[str, Any] = {
            "traceId": self.trace_id,
            "spanId": self.span_id,
            "name": self.name,
            "kind": self.kind,
            "startTimeUnixNano": str(self.started_ns),
            "endTimeUnixNano": str(
                self.ended_ns if self.ended_ns is not None else _now_unix_nano()
            ),
            "attributes": [
                {"key": key, "value": _otel_value(value)}
                for key, value in sorted(self.attributes.items())
            ],
            "status": {"code": {"unset": 0, "ok": 1, "error": 2}.get(self.status, 0)},
        }
        if self.parent_span_id:
            payload["parentSpanId"] = self.parent_span_id
        if self.status_message:
            payload["status"]["message"] = self.status_message
        if self.events:
            payload["events"] = [
                {
                    "name": name,
                    "timeUnixNano": str(self.ended_ns or self.started_ns),
                    "attributes": [
                        {"key": key, "value": _otel_value(value)}
                        for key, value in sorted(attributes.items())
                    ],
                }
                for name, attributes in self.events
            ]
        return payload


def _truncate(value: Any) -> Any:
    if isinstance(value, str):
        return value[:_MAX_ATTRIBUTE_LENGTH]
    return value


class SpanExporter(Protocol):
    """Where finished spans go."""

    def export(self, spans: Sequence[Span]) -> None: ...

    def shutdown(self) -> None: ...


class InMemoryExporter:
    """A collector that keeps spans in a list — the test double for a real collector."""

    def __init__(self) -> None:
        self.spans: list[Span] = []
        self.exports = 0
        self.failures = 0

    def export(self, spans: Sequence[Span]) -> None:
        self.exports += 1
        self.spans.extend(spans)

    def shutdown(self) -> None:
        return None

    def by_name(self, name: str) -> list[Span]:
        return [span for span in self.spans if span.name == name]


class OtlpJsonExporter:
    """An OTLP/HTTP (JSON encoding) exporter over the shared scoped HTTP client.

    The OTLP spec allows both protobuf and JSON over HTTP; JSON is the encoding that needs no
    code generator, so it is the one ARACHNE implements. Requests go through the injected
    scoped client, which means the collector's host has to be reachable under the deployment's
    safety posture (an operator whose collector sits on a private address sets
    ``ARACHNE_ALLOW_PRIVATE_IPS``, exactly as an internal agent deployment does).
    """

    def __init__(
        self,
        endpoint: str,
        *,
        service_name: str = "arachne",
        client: Any = None,
        timeout_s: float = 10.0,
        owns_client: bool = False,
    ) -> None:
        self.endpoint = endpoint.rstrip("/")
        self.service_name = service_name
        self.client = client
        self.timeout_s = timeout_s
        #: True when the exporter built the client itself, so it closes it on shutdown.
        self.owns_client = owns_client

    async def aclose(self) -> None:
        """Close the collector client, when this exporter owns it."""
        if self.owns_client and self.client is not None:
            try:
                await self.client.aclose()
            except Exception as exc:  # closing must never raise out of shutdown
                _logger.debug("could not close the trace client", extra={"error": str(exc)[:200]})

    def payload(self, spans: Sequence[Span]) -> dict[str, Any]:
        return {
            "resourceSpans": [
                {
                    "resource": {
                        "attributes": [
                            {
                                "key": "service.name",
                                "value": {"stringValue": self.service_name},
                            }
                        ]
                    },
                    "scopeSpans": [
                        {
                            "scope": {"name": "arachne"},
                            "spans": [span.to_otlp() for span in spans],
                        }
                    ],
                }
            ]
        }

    async def export_async(self, spans: Sequence[Span]) -> bool:
        """POST one batch; returns whether it was accepted. Never raises."""
        if not spans or self.client is None:
            return False

        try:
            exchange = await self.client.post(
                f"{self.endpoint}/v1/traces",
                headers={"Content-Type": "application/json"},
                content=json.dumps(self.payload(spans)),
            )
        except Exception as exc:  # a trace must never fail the thing it observes
            _logger.warning(
                "trace export failed",
                extra={"event": "tracing.export_failed", "error": str(exc)[:200]},
            )
            return False
        status = getattr(exchange, "status_code", None)
        if status is None or not 200 <= int(status) < 300:
            _logger.warning(
                "trace export rejected",
                extra={"event": "tracing.export_rejected", "status": status},
            )
            return False
        return True

    def export(self, spans: Sequence[Span]) -> None:
        """Synchronous entry point used when the exporter is drained without a loop."""
        if not spans or self.client is None:
            return
        try:
            import asyncio

            asyncio.get_running_loop()
        except RuntimeError:
            asyncio.run(self.export_async(spans))
            return
        # Inside a running loop a fire-and-forget task is the honest thing: the scan must not
        # block on the collector. The task keeps its own reference to the client.

        task = asyncio.ensure_future(self.export_async(spans))
        task.add_done_callback(lambda finished: finished.exception())

    def shutdown(self) -> None:
        return None


class NoopTracer:
    """A tracer that records nothing (tracing disabled)."""

    enabled = False
    exporter: SpanExporter | None = None

    @contextmanager
    def start_span(
        self,
        name: str,
        *,
        attributes: Mapping[str, Any] | None = None,
        kind: int = EXPORTER_KIND_INTERNAL,
    ) -> Iterator[Span]:
        span = Span(
            name=name,
            trace_id=_hex_id(16),
            span_id=_hex_id(8),
            parent_span_id=None,
            sampled=False,
            kind=kind,
        )
        yield span

    def current(self) -> Span | None:
        return None

    def traceparent(self) -> str | None:
        return None

    def flush(self) -> None:
        return None

    async def aflush(self) -> None:
        return None

    def shutdown(self) -> None:
        return None


#: The span stack, so a nested span knows its parent without threading a parameter.
_CURRENT: contextvars.ContextVar[tuple[Span, ...]] = contextvars.ContextVar(
    "arachne_spans", default=()
)


class Tracer:
    """A sampled tracer with a parent-based sampler and a buffered exporter.

    Sampling is decided once per trace, at the root span: if the root is sampled every child is
    sampled (a partial trace is worse than none), and if it is not, nothing below it records.
    A child of an *unsampled* root still propagates the parent's ``traceparent`` — the
    collector may be attached elsewhere — but does no work of its own.
    """

    enabled = True

    def __init__(
        self,
        exporter: SpanExporter,
        *,
        sample_ratio: float = 0.1,
        service_name: str = "arachne",
        max_batch: int = _MAX_BATCH,
        random_source: Any = None,
    ) -> None:
        self.exporter = exporter
        self.sample_ratio = sample_ratio
        self.service_name = service_name
        self.max_batch = max_batch
        self._random = random_source or secrets.SystemRandom()
        self._pending: list[Span] = []
        self.exported = 0

    # ------------------------------------------------------------------ spans
    def _sampled(self, parent: Span | None) -> bool:
        if parent is not None:
            return parent.sampled
        if self.sample_ratio <= 0.0:
            return False
        if self.sample_ratio >= 1.0:
            return True
        return self._random.random() < self.sample_ratio

    @contextmanager
    def start_span(
        self,
        name: str,
        *,
        attributes: Mapping[str, Any] | None = None,
        kind: int = EXPORTER_KIND_INTERNAL,
    ) -> Iterator[Span]:
        parent = self.current()
        span = Span(
            name=name,
            trace_id=parent.trace_id if parent is not None else _hex_id(16),
            span_id=_hex_id(8),
            parent_span_id=parent.span_id if parent is not None else None,
            sampled=self._sampled(parent),
            kind=kind,
        )
        token = _CURRENT.set((*_CURRENT.get(), span))
        if attributes:
            for key, value in attributes.items():
                span.set_attribute(key, value)
        try:
            yield span
        finally:
            _CURRENT.reset(token)
            span.ended_ns = _now_unix_nano()
            if span.sampled:
                self._record(span)

    def current(self) -> Span | None:
        stack = _CURRENT.get()
        return stack[-1] if stack else None

    def traceparent(self) -> str | None:
        span = self.current()
        return span.traceparent if span is not None else None

    # ------------------------------------------------------------------ export
    def _record(self, span: Span) -> None:
        self._pending.append(span)
        if len(self._pending) >= self.max_batch:
            self.flush()

    def flush(self) -> None:
        """Export whatever is buffered. Best-effort: a failure is logged, never raised."""
        if not self._pending:
            return
        batch = self._pending
        self._pending = []
        try:
            self.exporter.export(batch)
            self.exported += len(batch)
        except Exception as exc:
            _logger.warning(
                "trace export failed",
                extra={"event": "tracing.export_failed", "error": str(exc)[:200]},
            )

    async def aflush(self) -> None:
        """Await the export of whatever is buffered (the scan's own flush point).

        Preferred over :meth:`flush` wherever a loop is already running: the OTLP exporter's
        POST is real I/O, and awaiting it means the scan's spans are actually delivered
        before the process moves on — instead of a fire-and-forget task that a short-lived
        CLI process would drop on exit. Still best-effort: a failure is logged, not raised.
        """
        if not self._pending:
            return
        batch = self._pending
        self._pending = []
        exporter = self.exporter
        export_async = getattr(exporter, "export_async", None)
        try:
            if export_async is not None:
                await export_async(batch)
            else:
                exporter.export(batch)
            self.exported += len(batch)
        except Exception as exc:
            _logger.warning(
                "trace export failed",
                extra={"event": "tracing.export_failed", "error": str(exc)[:200]},
            )

    def shutdown(self) -> None:
        self.flush()
        try:
            self.exporter.shutdown()
        except Exception as exc:  # shutdown is best-effort too
            _logger.debug("trace exporter shutdown failed", extra={"error": str(exc)[:200]})

    async def aclose(self) -> None:
        """Flush, then close the exporter's client (the API's lifespan path)."""
        await self.aflush()
        aclose = getattr(self.exporter, "aclose", None)
        if aclose is None:
            return
        try:
            await aclose()
        except Exception as exc:
            _logger.debug("trace exporter shutdown failed", extra={"error": str(exc)[:200]})


#: The process-wide tracer. ``NoopTracer`` until a deployment configures tracing.
_TRACER: Tracer | NoopTracer = NoopTracer()


def get_tracer() -> Tracer | NoopTracer:
    """The configured tracer (a no-op one when tracing is off)."""
    return _TRACER


def configure_tracing(
    settings: Settings | None = None,
    *,
    exporter: SpanExporter | None = None,
    sample_ratio: float | None = None,
    client: Any = None,
) -> Tracer | NoopTracer:
    """Install the process-wide tracer.

    Disabled (the default) leaves the no-op tracer in place. A caller may inject an ``exporter``
    directly — that is how the tests collect spans — which is also how a deployment could plug
    in a different collector without a configuration surface ARACHNE has to maintain.
    """
    global _TRACER
    effective = settings or get_settings()
    observability: ObservabilitySettings = effective.observability
    owns_client = False
    if exporter is None:
        if not observability.tracing_enabled:
            _TRACER = NoopTracer()
            return _TRACER
        if not observability.otlp_endpoint:  # pragma: no cover - guarded by settings
            _TRACER = NoopTracer()
            return _TRACER
        if client is None:
            client = _build_otlp_client(effective)
            owns_client = client is not None
        exporter = OtlpJsonExporter(
            observability.otlp_endpoint,
            service_name=observability.service_name,
            client=client,
            timeout_s=observability.otlp_timeout_s,
            owns_client=owns_client,
        )
    _TRACER = Tracer(
        exporter,
        sample_ratio=(observability.tracing_sample_ratio if sample_ratio is None else sample_ratio),
        service_name=observability.service_name,
    )
    return _TRACER


def _build_otlp_client(settings: Settings) -> Any:
    """A scoped client for the collector — the one egress path, pinned to its host.

    Imported inside the function on purpose: ``core/http.py`` imports this module for its span
    wrapper, so a module-level import here would be circular.
    """
    observability: ObservabilitySettings = settings.observability
    if not observability.otlp_endpoint:
        return None
    from urllib.parse import urlparse

    from arachne.core.http import ScopedHttpClient
    from arachne.core.safety import Scope

    host = urlparse(observability.otlp_endpoint).hostname or ""
    policy = settings.safety.policy
    if observability.otlp_allow_private_ips:
        from dataclasses import replace

        policy = replace(policy, allow_private_ips=True)
    return ScopedHttpClient(settings=settings, scope=Scope(allowed_hosts=(host,)), policy=policy)


def reset_tracer() -> None:
    """Restore the no-op tracer (tests)."""
    global _TRACER
    _TRACER.shutdown()
    _TRACER = NoopTracer()
