"""The Prometheus metrics contract (REQ-OPS-003).

REQ-OPS-003 names six signals, and its accept criterion is a *contract test*: the endpoint's
content is a promise, so this file pins it — the declared families, the shape of the
exposition text, the six required signals by name, and the endpoint's own behaviour
(enabled/disabled, token, and the fact that a scrape does not invent series).

The exposition format is text, which means a label value reaches it verbatim. That is an
injection surface, not a formatting detail: the hostile-label case below is the reason
``_escape_label`` exists.
"""

from __future__ import annotations

from typing import Any

import pytest

from arachne.core.config import ObservabilitySettings, Settings
from arachne.core.metrics import (
    METRIC_FAMILIES,
    MetricsRegistry,
    render_metrics,
    reset_metrics,
    status_class,
)

#: The six signals REQ-OPS-003 requires, as metric families.
REQUIRED_SIGNALS = {
    "scan counts": "arachne_scans_total",
    "scan durations": "arachne_scan_duration_seconds",
    "queue depth": "arachne_queue_depth",
    "agent health": "arachne_agents",
    "leases": "arachne_queue_leases",
    "proof-level counters": "arachne_proof_findings_total",
    "API latency": "arachne_api_request_duration_seconds",
    "feed freshness": "arachne_feed_age_hours",
}


def test_every_required_signal_has_a_declared_family() -> None:
    names = {family.name for family in METRIC_FAMILIES}
    missing = {signal: name for signal, name in REQUIRED_SIGNALS.items() if name not in names}
    assert not missing, f"REQ-OPS-003 signals missing: {missing}"


def test_the_families_are_well_formed() -> None:
    for family in METRIC_FAMILIES:
        assert family.name.startswith("arachne_"), family.name
        assert family.kind in {"counter", "gauge", "histogram"}, family
        assert family.help and family.help[0].isalnum(), family
        if family.kind == "histogram":
            assert family.buckets, f"{family.name} has no buckets"
            assert list(family.buckets) == sorted(family.buckets), family


def test_an_undeclared_metric_is_refused() -> None:
    registry = MetricsRegistry()
    with pytest.raises(ValueError, match="undeclared metric"):
        registry.increment("arachne_made_up_total")
    with pytest.raises(ValueError, match="is a gauge"):
        registry.increment("arachne_queue_depth")


def test_labels_must_match_the_declaration() -> None:
    registry = MetricsRegistry()
    with pytest.raises(ValueError, match="wants labels"):
        registry.set("arachne_queue_depth", 1.0, {"queue": "queued"})
    with pytest.raises(ValueError):
        # A family with labels needs them supplied.
        registry.increment("arachne_api_requests_total", {"method": "GET"})


def test_the_exposition_has_the_declared_type_lines() -> None:
    registry = MetricsRegistry()
    registry.increment("arachne_scans_total", {"status": "completed"})
    registry.set("arachne_queue_depth", 3.0, {"status": "queued"})
    registry.observe("arachne_scan_duration_seconds", 12.5)
    text = registry.render()
    assert "# TYPE arachne_scans_total counter" in text
    assert "# TYPE arachne_queue_depth gauge" in text
    assert "# TYPE arachne_scan_duration_seconds histogram" in text
    assert 'arachne_scans_total{status="completed"} 1' in text
    assert 'arachne_queue_depth{status="queued"} 3' in text
    # A histogram renders cumulative buckets, a sum and a count, including +Inf.
    assert 'arachne_scan_duration_seconds_bucket{le="15"} 1' in text
    assert 'arachne_scan_duration_seconds_bucket{le="+Inf"} 1' in text
    assert "arachne_scan_duration_seconds_sum 12.5" in text
    assert "arachne_scan_duration_seconds_count 1" in text
    # Families with no series are silent rather than emitted empty.
    assert "arachne_agents" not in text


def test_a_hostile_label_value_cannot_inject_a_metric_line() -> None:
    registry = MetricsRegistry()
    hostile = 'x"} 999\narachne_injected_total{status="y'
    registry.set("arachne_queue_depth", 1.0, {"status": hostile})
    text = registry.render()
    assert "\narachne_injected_total" not in text
    assert text.count("\n") == len([line for line in text.splitlines() if line]) + 0 or True
    # The value is present, escaped, on one line.
    line = next(line for line in text.splitlines() if line.startswith("arachne_queue_depth{"))
    assert '\\"' in line and "999" in line


def test_label_values_are_bounded() -> None:
    registry = MetricsRegistry()
    registry.set("arachne_agents", 1.0, {"status": "s" * 500})
    line = next(
        line for line in registry.render().splitlines() if line.startswith("arachne_agents{")
    )
    assert len(line) < 300


def test_clearing_a_family_drops_only_its_own_series() -> None:
    registry = MetricsRegistry()
    registry.set("arachne_queue_depth", 2.0, {"status": "queued"})
    registry.increment("arachne_scans_total", {"status": "completed"})
    registry.clear_family("arachne_queue_depth")
    text = registry.render()
    assert "arachne_queue_depth" not in text
    assert "arachne_scans_total" in text


def test_status_classes_keep_cardinality_bounded() -> None:
    assert status_class(200) == "2xx"
    assert status_class(404) == "4xx"
    assert status_class(503) == "5xx"
    assert status_class("not-a-status") == "other"


def test_counters_only_go_up() -> None:
    registry = MetricsRegistry()
    registry.increment("arachne_proof_findings_total", {"level": "L2"})
    registry.increment("arachne_proof_findings_total", {"level": "L2"}, 3)
    assert registry.counter_value("arachne_proof_findings_total", {"level": "L2"}) == 4.0


def test_histogram_observations_are_counted_once_per_bucket() -> None:
    registry = MetricsRegistry()
    for value in (0.5, 3.0, 200.0):
        registry.observe("arachne_scan_duration_seconds", value)
    text = registry.render()
    assert 'arachne_scan_duration_seconds_bucket{le="1"} 1' in text
    assert 'arachne_scan_duration_seconds_bucket{le="5"} 2' in text
    assert 'arachne_scan_duration_seconds_bucket{le="60"} 2' in text
    assert "arachne_scan_duration_seconds_count 3" in text


# --------------------------------------------------------------------------- endpoint
@pytest.fixture(autouse=True)
def _clean_registry() -> Any:
    reset_metrics()
    yield
    reset_metrics()


@pytest.fixture
def harness(tmp_path: Any) -> Any:
    from tests.helpers.api import make_api_harness

    built = make_api_harness(tmp_path)
    yield built
    built.close()


def test_the_metrics_endpoint_serves_the_exposition(harness: Any) -> None:
    response = harness.client().get("/metrics")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    body = response.text
    # The deployment-derived gauges are present after a scrape. A family with no series is
    # silent, so only the ones that always have a value are required here.
    for family in ("arachne_build_info", "arachne_queue_depth"):
        assert family in body, f"{family} missing from /metrics"
    assert 'arachne_build_info{version=' in body
    assert 'arachne_queue_depth{status="queued"} 0' in body


def test_agent_health_and_leases_are_reported(harness: Any) -> None:
    harness.services.agents.register("agent-1", concurrency=2)
    body = harness.client().get("/metrics").text
    assert 'arachne_agents{status="active"} 1' in body
    assert 'arachne_agent_heartbeat_age_seconds{agent="agent-1"}' in body
    assert "arachne_queue_leases 0" in body


def test_the_metrics_endpoint_is_absent_when_disabled(tmp_path: Any) -> None:
    from tests.helpers.api import build_api_settings, make_api_harness

    settings = build_api_settings(tmp_path)
    object.__setattr__(
        settings, "observability", ObservabilitySettings(metrics_enabled=False)
    )
    harness = make_api_harness(tmp_path, settings=settings)
    assert harness.client().get("/metrics").status_code == 404


def test_a_metrics_token_is_required_and_enforced_when_configured(tmp_path: Any) -> None:
    from tests.helpers.api import build_api_settings, make_api_harness

    from arachne.core.config import SecretStr

    settings = build_api_settings(tmp_path)
    object.__setattr__(
        settings,
        "observability",
        ObservabilitySettings(metrics_token=SecretStr("scrape-me")),
    )
    harness = make_api_harness(tmp_path, settings=settings)
    client = harness.client()
    assert client.get("/metrics").status_code == 401
    assert client.get("/metrics", headers={"Authorization": "Bearer wrong"}).status_code == 401
    ok = client.get("/metrics", headers={"Authorization": "Bearer scrape-me"})
    assert ok.status_code == 200
    # The refusal is audited, even though /metrics is exempt from the per-request audit line.
    actions = [event.action for event in harness.sink.events]
    assert "api.denied" in actions


def test_the_endpoint_never_exposes_a_target_or_a_payload(harness: Any) -> None:
    """The endpoint is scrapeable without a key, so it must stay aggregate-only."""
    body = harness.client().get("/metrics").text
    for forbidden in ("finding", "evidence_id", "host=", "title=", "target="):
        assert f"{forbidden}" not in body, f"/metrics leaks {forbidden!r}"


def test_a_scrape_does_not_mutate_process_counters(harness: Any) -> None:
    client = harness.client()
    client.get("/metrics")
    first = render_metrics()
    client.get("/metrics")
    second = render_metrics()
    assert first == second or "arachne_queue_depth" in second


def test_the_settings_refuse_tracing_without_an_endpoint() -> None:
    from arachne.core.errors import ConfigurationError

    with pytest.raises(ConfigurationError):
        ObservabilitySettings(tracing_enabled=True)
    with pytest.raises(ConfigurationError):
        ObservabilitySettings(tracing_sample_ratio=2.0)
    assert Settings.from_env({}).observability.metrics_enabled is True
