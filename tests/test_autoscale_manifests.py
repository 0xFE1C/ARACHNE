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

from pathlib import Path
from typing import Any

import yaml

# ``tests/`` sits directly under the project root (``code/``), so ``parents[1]`` is
# the root — one shallower than ``tests/unit/`` (see test_helm_chart.py).
CHART = Path(__file__).resolve().parents[1] / "deploy" / "helm" / "arachne"


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
