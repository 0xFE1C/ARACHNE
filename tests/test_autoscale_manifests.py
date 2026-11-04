"""Queue-depth autoscaling manifests for the agent pool (S25, REQ-RESIL-003).

REQ-RESIL-003 accepts "a queue-depth scaling test with a fake metric source"; this
module is that test's static half. It validates the *chart text* (there is no helm
binary in the default test environment and no cluster to talk to): the KEDA
``ScaledObject`` and the plain-HPA fallback, plus the values that drive them.

It pins three properties a refactor could silently break:

* the queue-depth gauge the scalers read is the one the API actually exposes
  (``arachne_queue_depth``, declared in ``core/metrics.py``);
* the two scalers are mutually exclusive — a guard that lets both render would let
  two controllers fight over the agent Deployment's replica count;
* neither new template carries a literal credential, keeping REQ-OPS-006's
  no-default-credentials property true for the new surface.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

from arachne.core.metrics import METRIC_FAMILIES, MetricsRegistry
from arachne.data.metrics_source import collect_deployment_metrics

# ``tests/`` sits directly under the project root (``code/``), so ``parents[1]`` is
# the root — one shallower than ``tests/unit/`` (see test_helm_chart.py).
CHART = Path(__file__).resolve().parents[1] / "deploy" / "helm" / "arachne"
OPERATOR_GUIDE = Path(__file__).resolve().parents[1] / "docs" / "operator-guide.md"

#: The metric name the scalers read. REQ-OPS-009 calls it "the documented metric name", so it
#: is named once here and checked against the exposition, the chart and the operator guide.
QUEUE_METRIC = "arachne_queue_depth"


def _load(path: Path) -> Any:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _values() -> dict[str, Any]:
    return _load(CHART / "values.yaml")  # type: ignore[no-any-return]


def _template(name: str) -> str:
    return (CHART / "templates" / name).read_text(encoding="utf-8")


def test_values_declare_the_autoscaling_block() -> None:
    autoscaling = _values()["autoscaling"]
    assert autoscaling["enabled"] is False
    assert autoscaling["minReplicas"] == 0
    assert autoscaling["maxReplicas"] == 8
    assert autoscaling["queueDepthPerReplica"] == 4
    assert autoscaling["scaleDownStabilizationSeconds"] == 300


def test_keda_defaults_to_disabled_and_the_operator_is_not_bundled() -> None:
    """Scale-to-zero is opt-in, and the chart ships no CRD/operator dependency."""
    keda = _values()["autoscaling"]["keda"]
    assert keda["enabled"] is False
    assert keda["pollingInterval"] == 15
    assert keda["cooldownPeriod"] == 300
    assert keda["namespace"] == ""
    # No chart dependency pulls in KEDA: the cluster admin installs the operator.
    assert "dependencies" not in _load(CHART / "Chart.yaml")
    assert "keda" in (CHART / "values.yaml").read_text(encoding="utf-8").lower()


def test_scaledobject_targets_the_agent_pool_on_queue_depth() -> None:
    template = _template("scaledobject.yaml")
    assert "apiVersion: keda.sh/v1alpha1" in template
    assert "kind: ScaledObject" in template
    # The agent Deployment, named through the chart's fullname helper.
    assert 'name: {{ include "arachne.fullname" . }}-agent' in template
    assert "apiVersion: apps/v1" in template
    assert "kind: Deployment" in template
    # The trigger reads the queue-depth gauge the API exposes at /metrics.
    assert "type: prometheus" in template
    assert "arachne_queue_depth" in template
    # The in-cluster API Service is the scrape target.
    assert "-api:{{ .Values.api.service.port }}" in template
    # Scale-to-zero: the minimum is values-driven and defaults to 0.
    assert "minReplicaCount: {{ .Values.autoscaling.minReplicas }}" in template
    assert "maxReplicaCount: {{ .Values.autoscaling.maxReplicas }}" in template
    assert _values()["autoscaling"]["minReplicas"] == 0
    # Cooldown/polling come from values, not hard-coded.
    assert "pollingInterval: {{ .Values.autoscaling.keda.pollingInterval }}" in template


def test_the_plain_hpa_is_guarded_against_keda() -> None:
    """The two scalers can never render together (both own the replica count)."""
    template = _template("hpa-agent.yaml")
    assert "apiVersion: autoscaling/v2" in template
    assert "kind: HorizontalPodAutoscaler" in template
    assert "arachne_queue_depth" in template
    # KEDA supersedes it: the guard is `autoscaling.enabled AND NOT keda.enabled`.
    assert "autoscaling.keda.enabled" in template
    assert "not" in template
    assert (
        "{{- if and .Values.autoscaling.enabled (not .Values.autoscaling.keda.enabled) }}"
        in template
    )
    # And the ScaledObject is guarded the other way, so exactly one can render.
    assert "{{- if .Values.autoscaling.keda.enabled }}" in _template("scaledobject.yaml")


def test_neither_autoscaling_template_carries_a_literal_credential() -> None:
    """REQ-OPS-006 for the new templates: no literal secret, no default credential."""
    for name in ("scaledobject.yaml", "hpa-agent.yaml"):
        text = _template(name)
        assert "password" not in text, name
        assert "token:" not in text, name


# ------------------------------------------------- the metric, the code and the guide (WP-18)
class _Queue:
    """A queue whose stats name the statuses the real one does."""

    def __init__(self) -> None:
        self.calls = 0

    def stats(self) -> dict[str, int]:
        self.calls += 1
        return {"queued": 3, "leased": 1, "done": 5, "cancelled": 0}


def _boom(*args: object, **kwargs: object) -> None:
    msg = "the scaler test has no database"
    raise RuntimeError(msg)


class _ScalerServices:
    """Just enough of the services object for the queue gauges: no database behind it."""

    def __init__(self) -> None:
        self.queue = _Queue()
        self.session_factory = _boom
        self.settings = None


def test_the_scalers_read_a_metric_the_metrics_endpoint_really_exposes() -> None:
    """REQ-OPS-009's "documented metric name", checked against the exposition itself.

    The chart selects ``arachne_queue_depth{status="queued"}``. That is a claim about another
    module, so the claim is tested the only way it can be: collect the deployment metrics from
    a queue and look for exactly that series in the rendered exposition.
    """
    family = next(item for item in METRIC_FAMILIES if item.name == QUEUE_METRIC)
    assert family.kind == "gauge"
    assert family.label_names == ("status",)

    registry = MetricsRegistry()
    collect_deployment_metrics(_ScalerServices(), registry=registry, now=datetime.now(UTC))
    rendered = registry.render()
    assert f'{QUEUE_METRIC}{{status="queued"}} 3' in rendered, rendered


def test_the_chart_selects_the_series_the_collector_writes() -> None:
    """The selector in both scalers must name a status value the collector emits.

    The two scalers select it differently — the plain HPA through the external-metrics API's
    label selector, KEDA through a PromQL query — so both spellings are accepted, and both are
    checked against the statuses the collector actually writes.
    """
    registry = MetricsRegistry()
    collect_deployment_metrics(_ScalerServices(), registry=registry, now=datetime.now(UTC))
    rendered = registry.render()
    emitted = {
        line.split('status="')[1].split('"')[0]
        for line in rendered.splitlines()
        if line.startswith(f"{QUEUE_METRIC}{{")
    }
    assert "queued" in emitted
    for name in ("scaledobject.yaml", "hpa-agent.yaml"):
        text = _template(name)
        assert "status: queued" in text or 'status="queued"' in text, (
            f"{name} does not select the queued series the collector emits"
        )


def test_the_operator_guide_documents_the_metric_and_a_starting_threshold() -> None:
    """REQ-OPS-009: the metric and a sane starting threshold, in the operator guide."""
    guide = OPERATOR_GUIDE.read_text(encoding="utf-8")
    assert QUEUE_METRIC in guide
    assert "queueDepthPerReplica" in guide
    threshold = str(_values()["autoscaling"]["queueDepthPerReplica"])
    assert f"queueDepthPerReplica: {threshold}" in guide, (
        "the guide's starting threshold has drifted from the chart's default"
    )


def test_the_hpa_names_the_metric_the_guide_documents() -> None:
    for name in ("hpa-agent.yaml", "scaledobject.yaml"):
        assert QUEUE_METRIC in _template(name), name
