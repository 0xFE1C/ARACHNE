"""OpenTelemetry-style tracing: opt-in, sampled, redacted and never in the scan's way.

REQ-OPS-004 asks for traces covering the orchestrator steps and the HTTP client, opt-in and
sampled, with structured JSON logging alongside. The properties worth pinning are the ones a
trace that "works" can still get wrong: it must be *off* unless configured, sampling must be
decided once per trace, attributes must go through the redactor (a URL in a span is a URL
that might carry a credential), and an unreachable collector must not fail the scan it is
observing. ``tests/integration/test_data_lifecycle.py`` covers the span tree of a real scan.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from arachne.core.config import ObservabilitySettings, Settings
from arachne.core.tracing import (
    EXPORTER_KIND_INTERNAL,
    InMemoryExporter,
    NoopTracer,
    OtlpJsonExporter,
    Tracer,
    configure_tracing,
    get_tracer,
    reset_tracer,
)


@pytest.fixture(autouse=True)
def _clean_tracer() -> Any:
    reset_tracer()
    yield
    reset_tracer()


def test_tracing_is_off_unless_it_is_configured() -> None:
    tracer = configure_tracing(Settings.from_env({}))
    assert isinstance(tracer, NoopTracer)
    assert tracer.enabled is False
    with tracer.start_span("scan.step.recon") as span:
        span.set_attribute("http.url", "https://user:hunter2@example.com/?token=abc")
    assert tracer.current() is None
    assert tracer.traceparent() is None


def test_the_noop_tracer_still_yields_a_usable_span() -> None:
    with NoopTracer().start_span("x") as span:
        assert span.sampled is False
        span.set_status("error", "ignored")
        span.add_event("ignored")
        assert span.events == []
        assert span.attributes == {}


def test_a_configured_tracer_exports_the_spans_it_records() -> None:
    exporter = InMemoryExporter()
    tracer = Tracer(exporter, sample_ratio=1.0)
    with tracer.start_span("scan.step.checks", attributes={"scan.id": 7}):
        with tracer.start_span("http.GET") as child:
            child.set_attribute("http.status_code", 200)
    tracer.flush()
    assert len(exporter.spans) == 2
    # A child span ends (and is recorded) before its parent, so the export order is inner
    # first; look them up by name rather than assuming a direction.
    parent = next(span for span in exporter.spans if span.name == "scan.step.checks")
    child = next(span for span in exporter.spans if span.name == "http.GET")
    assert parent.attributes["scan.id"] == 7
    assert child.parent_span_id == parent.span_id
    assert child.trace_id == parent.trace_id
    assert child.duration_ms >= 0


def test_sampling_decides_once_for_the_whole_trace() -> None:
    exporter = InMemoryExporter()
    tracer = Tracer(exporter, sample_ratio=0.0)
    with tracer.start_span("root"):
        with tracer.start_span("child"):
            pass
    tracer.flush()
    assert exporter.spans == []

    tracer = Tracer(exporter, sample_ratio=1.0)
    with tracer.start_span("root"):
        with tracer.start_span("child") as child:
            assert child.sampled is True
    tracer.flush()
    assert len(exporter.spans) == 2
    assert tracer.exported == 2


def test_a_mid_ratio_sample_never_records_a_partial_trace() -> None:
    exporter = InMemoryExporter()
    tracer = Tracer(exporter, sample_ratio=0.5)
    for _ in range(40):
        with tracer.start_span("root"):
            with tracer.start_span("child"):
                pass
    tracer.flush()
    # Whole traces only: the number of exported spans is even, and at least one trace was
    # sampled at a 50% ratio over 40 attempts.
    assert len(exporter.spans) % 2 == 0
    assert exporter.spans


def test_span_attributes_are_redacted() -> None:
    exporter = InMemoryExporter()
    tracer = Tracer(exporter, sample_ratio=1.0)
    with tracer.start_span("http.GET") as span:
        span.set_attribute("http.url", "https://example.com/login?password=hunter2&x=1")
        span.set_attribute("http.headers", {"authorization": "Bearer abcdefghijkl"})
        span.add_event("retry", {"token": "ghp_" + "a" * 36})
    tracer.flush()
    recorded, = exporter.spans
    payload = json.dumps(
        {
            "attributes": recorded.attributes,
            "events": recorded.events,
        }
    )
    assert "hunter2" not in payload
    assert "Bearer abcdefghijkl" not in payload
    assert "ghp_" not in payload
    assert "[REDACTED" in payload


def test_a_hostile_span_name_or_attribute_cannot_bloat_the_trace() -> None:
    exporter = InMemoryExporter()
    tracer = Tracer(exporter, sample_ratio=1.0)
    with tracer.start_span("x") as span:
        span.set_attribute("body", "A" * 100_000)
    tracer.flush()
    recorded, = exporter.spans
    assert len(str(recorded.attributes["body"])) <= 512


def test_an_exporter_failure_never_reaches_the_caller() -> None:
    class Exploding:
        def export(self, spans: Any) -> None:
            msg = "the collector is down"
            raise RuntimeError(msg)

        def shutdown(self) -> None:
            msg = "still down"
            raise RuntimeError(msg)

    tracer = Tracer(Exploding(), sample_ratio=1.0)
    with tracer.start_span("scan.step.recon"):
        pass
    tracer.flush()  # must not raise
    tracer.shutdown()  # must not raise
    assert tracer.exported == 0


def test_the_otlp_payload_is_valid_otlp_json() -> None:
    exporter = OtlpJsonExporter("https://collector.example.com", service_name="arachne")
    tracer = Tracer(InMemoryExporter(), sample_ratio=1.0)
    with tracer.start_span("scan.step.recon", attributes={"scan.id": 3}) as span:
        span.set_status("ok")
    payload = exporter.payload([span])
    resource_spans = payload["resourceSpans"][0]
    assert resource_spans["resource"]["attributes"][0]["value"]["stringValue"] == "arachne"
    encoded = resource_spans["scopeSpans"][0]["spans"][0]
    assert encoded["name"] == "scan.step.recon"
    assert encoded["kind"] == EXPORTER_KIND_INTERNAL
    assert len(encoded["traceId"]) == 32 and len(encoded["spanId"]) == 16
    assert int(encoded["endTimeUnixNano"]) >= int(encoded["startTimeUnixNano"])
    assert encoded["attributes"][0]["key"] == "scan.id"
    assert encoded["attributes"][0]["value"]["intValue"] == "3"
    assert encoded["status"]["code"] == 1


async def test_the_otlp_exporter_posts_one_batch_per_flush() -> None:
    posted: list[tuple[str, dict[str, Any]]] = []

    class Client:
        async def post(self, url: str, *, headers: Any, content: Any) -> Any:
            posted.append((url, json.loads(content)))

            class Exchange:
                status_code = 200

            return Exchange()

    exporter = OtlpJsonExporter("https://collector.example.com/", client=Client())
    tracer = Tracer(exporter, sample_ratio=1.0)
    with tracer.start_span("scan.step.recon"):
        pass
    await tracer.aflush()
    assert len(posted) == 1
    url, body = posted[0]
    assert url == "https://collector.example.com/v1/traces"
    assert body["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["name"] == "scan.step.recon"


async def test_an_otlp_collector_that_refuses_the_batch_is_not_an_error() -> None:
    class Client:
        async def post(self, url: str, *, headers: Any, content: Any) -> Any:
            class Exchange:
                status_code = 500

            return Exchange()

    exporter = OtlpJsonExporter("https://collector.example.com", client=Client())
    assert await exporter.export_async([_span()]) is False


def _span() -> Any:
    tracer = Tracer(InMemoryExporter(), sample_ratio=1.0)
    with tracer.start_span("x") as span:
        pass
    return span


def test_the_context_becomes_the_process_tracer() -> None:
    exporter = InMemoryExporter()
    tracer = configure_tracing(Settings.from_env({}), exporter=exporter, sample_ratio=1.0)
    assert get_tracer() is tracer
    with get_tracer().start_span("root"):
        assert get_tracer().traceparent() is not None
        assert get_tracer().current() is not None
    get_tracer().flush()
    assert exporter.spans


def test_the_traceparent_header_is_well_formed() -> None:
    tracer = Tracer(InMemoryExporter(), sample_ratio=1.0)
    with tracer.start_span("root") as span:
        version, trace_id, span_id, flags = span.traceparent.split("-")
        assert version == "00"
        assert trace_id == span.trace_id and len(trace_id) == 32
        assert span_id == span.span_id and len(span_id) == 16
        assert flags in {"00", "01"}


def test_tracing_requires_an_endpoint_when_enabled() -> None:
    from arachne.core.errors import ConfigurationError

    with pytest.raises(ConfigurationError):
        ObservabilitySettings(tracing_enabled=True)
    settings = ObservabilitySettings(
        tracing_enabled=True,
        otlp_endpoint="https://collector.example.com",
        tracing_sample_ratio=0.25,
    )
    assert settings.tracing_sample_ratio == 0.25
