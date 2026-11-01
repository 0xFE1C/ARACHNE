"""The Helm chart's static contract (S22, REQ-OPS-005/006).

`helm lint` + the render smoke run in CI (the `.github/workflows/ci.yml` `helm` job);
this suite pins the chart's *shape* so a refactor that silently drops a required
object, a credential guard, or the multi-worker story fails locally too — and it
keeps REQ-OPS-006's no-default-credentials property true for `deploy/` the same way
the compose gate does for `docker/`.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

CHART = Path(__file__).resolve().parents[2] / "deploy" / "helm" / "arachne"


def _load(path: Path) -> Any:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _template(name: str) -> str:
    return (CHART / "templates" / name).read_text(encoding="utf-8")


@pytest.fixture
def chart_yaml() -> dict[str, Any]:
    return _load(CHART / "Chart.yaml")  # type: ignore[no-any-return]


@pytest.fixture
def values() -> dict[str, Any]:
    return _load(CHART / "values.yaml")  # type: ignore[no-any-return]


def test_the_chart_declares_itself(chart_yaml: dict[str, Any]) -> None:
    assert chart_yaml["apiVersion"] == "v2"
    assert chart_yaml["name"] == "arachne"
    assert chart_yaml["type"] == "application"
    assert chart_yaml["version"]
    assert chart_yaml["appVersion"]


def test_every_required_object_template_exists() -> None:
    """API (multi-worker), agent pool, Postgres, migration job, service, probes."""
    templates = {path.name for path in (CHART / "templates").iterdir()}
    for required in (
        "deployment-api.yaml",
        "deployment-agent.yaml",
        "statefulset-postgres.yaml",
        "service-postgres.yaml",
        "service-api.yaml",
        "job-migrate.yaml",
        "configmap.yaml",
        "secret.yaml",
        "pdb.yaml",
        "serviceaccount.yaml",
        "_helpers.tpl",
    ):
        assert required in templates, required


def test_the_api_deploys_multi_replica_with_the_multi_worker_knobs(
    values: dict[str, Any],
) -> None:
    template = _template("deployment-api.yaml")
    assert "replicas: {{ .Values.api.replicas }}" in template
    # HA default: more than one replica ships out of the box.
    assert values["api"]["replicas"] >= 2
    # uvicorn multi-worker is a first-class value (ARACHNE_API_WORKERS).
    config = _template("configmap.yaml")
    assert "ARACHNE_API_WORKERS" in config
    assert values["api"]["workers"] >= 1
    # The HA story: a disruption budget and node anti-affinity.
    assert "PodDisruptionBudget" in _template("pdb.yaml")
    assert "podAntiAffinity" in template
    # Probes are the compose contract: GET /health.
    assert "path: /health" in template


def test_the_agent_pool_is_the_distributed_worker(values: dict[str, Any]) -> None:
    template = _template("deployment-agent.yaml")
    # The pool loops (register, heartbeat, lease, execute, ack); no --once drain.
    assert 'args: ["agent"]' in template
    assert "--once" not in template
    assert "ARACHNE_DISTRIBUTED" in template
    assert "ARACHNE_AGENT_MODE" in template
    assert values["agent"]["mode"] in {"external", "internal"}


def test_the_migration_job_is_a_helm_hook() -> None:
    template = _template("job-migrate.yaml")
    assert "helm.sh/hook: pre-install,pre-upgrade" in template
    assert 'args: ["db", "upgrade"]' in template


def test_secrets_come_from_env_files_or_vault(values: dict[str, Any]) -> None:
    """The three secret sources REQ-OPS-005 names, all wired."""
    assert values["vault"]["enabled"] is False  # off by default, documented on
    template = _template("deployment-api.yaml")
    assert "secretKeyRef" in template                    # env
    assert "existingSecret" in template                  # files (mounted / referenced)
    assert "vault" in (CHART / "values.yaml").read_text(encoding="utf-8")
    # The values file documents the Vault Agent injection path.
    assert "vault.hashicorp.com/agent-inject" in (CHART / "values.yaml").read_text(
        encoding="utf-8"
    )


def test_the_chart_ships_no_default_credentials(values: dict[str, Any]) -> None:
    """REQ-OPS-006 for deploy/: empty credentials, required-guard failure, no literal."""
    assert values["postgres"]["auth"]["password"] == ""
    assert values["api"]["auth"]["apiKeys"] == ""
    assert values["agent"]["auth"]["apiKey"] == ""
    # The guards fail the render when a source is missing.
    helpers = _template("_helpers.tpl")
    assert "REQ-OPS-006" in helpers
    assert "fail \"postgres.auth.password" in helpers
    assert "fail \"api.auth.apiKeys" in helpers
    # And no template carries a literal credential value.
    for path in (CHART / "templates").iterdir():
        text = path.read_text(encoding="utf-8")
        for suspicious in ("change-me", "password123", "s3cr3t", "CHANGEME"):
            assert suspicious not in text, f"{path.name} carries {suspicious!r}"


def test_the_ci_workflow_lints_and_renders_the_chart() -> None:
    workflow = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "ci.yml"
    text = workflow.read_text(encoding="utf-8")
    assert "helm lint deploy/helm/arachne" in text
    assert "helm template arachne deploy/helm/arachne" in text
    # The render passes throwaway values (generated, not committed) because the chart
    # itself refuses to render without a password — the REQ-OPS-006 posture.
    assert "render-only-smoke" in text


def test_the_compose_smoke_still_gates_the_docker_surface() -> None:
    workflow = Path(__file__).resolve().parents[2] / ".github" / "workflows" / "ci.yml"
    text = workflow.read_text(encoding="utf-8")
    assert "docker compose -f docker/docker-compose.yml config -q" in text
