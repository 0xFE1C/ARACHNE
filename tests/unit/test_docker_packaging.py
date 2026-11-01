"""Packaging invariants: the compose stack, its secrets and the offline demo scan (F-07-04).

Docker itself is not required to check the parts that can silently rot: the service graph,
the volume/secret wiring, the loopback-only lab publication and the demo fixtures the
``scan`` service consumes. A real ``docker compose up`` additionally needs a daemon; the
compose-equivalent execution is covered by ``tests/integration/test_s14_e2e.py``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

CODE_ROOT = Path(__file__).resolve().parents[2]
COMPOSE = CODE_ROOT / "docker" / "docker-compose.yml"
PROD = CODE_ROOT / "docker" / "docker-compose.prod.yml"
DOCKERFILE = CODE_ROOT / "docker" / "Dockerfile"


def _load(path: Path) -> dict[str, Any]:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def compose() -> dict[str, Any]:
    return _load(COMPOSE)


@pytest.fixture(scope="module")
def prod() -> dict[str, Any]:
    return _load(PROD)


def test_the_stack_has_the_three_roles_and_a_database(compose: dict[str, Any]) -> None:
    services = compose["services"]
    for name in ("db", "migrate", "scan", "api", "worker"):
        assert name in services, f"missing service {name}"
    assert services["db"]["image"].startswith("postgres:")
    assert services["migrate"]["command"] == ["db", "upgrade"]
    assert services["scan"]["depends_on"]["migrate"]["condition"] == (
        "service_completed_successfully"
    )
    assert services["api"]["depends_on"]["migrate"]["condition"] == (
        "service_completed_successfully"
    )


def test_the_api_publishes_loopback_only_and_is_health_checked(compose: dict[str, Any]) -> None:
    api = compose["services"]["api"]
    assert api["ports"] == ["127.0.0.1:8080:8080"]
    assert "healthcheck" in api
    assert "/health" in " ".join(api["healthcheck"]["test"])


def test_the_named_volumes_cover_the_state(compose: dict[str, Any]) -> None:
    volumes = compose["volumes"]
    for name in ("pgdata", "reports", "feeds", "worker-data"):
        assert name in volumes
    assert any(str(item).endswith(":/reports") for item in compose["services"]["scan"]["volumes"])
    assert any(str(item).endswith(":/app/feeds") for item in compose["services"]["api"]["volumes"])


def test_offloaded_evidence_lives_on_a_shared_volume(compose: dict[str, Any]) -> None:
    """S20: the scan writes an evidence object and the API serves it — one directory.

    A Postgres URL has no "beside the database" to fall back on, so the stack sets the local
    backend and its directory explicitly, and gives every role that plays with evidence the
    same volume.
    """
    assert "evidence" in compose["volumes"]
    for name in ("scan", "api", "worker"):
        service = compose["services"][name]
        assert service["environment"]["ARACHNE_EVIDENCE_BACKEND"] == "local"
        assert service["environment"]["ARACHNE_EVIDENCE_DIR"] == "/data/evidence"
        assert any(str(item).endswith(":/data/evidence") for item in service["volumes"])


def test_the_demo_scan_is_offline(compose: dict[str, Any]) -> None:
    env = compose["services"]["scan"]["environment"]
    assert env["ARACHNE_HTTP_FIXTURES"] == "/app/demo/http"
    assert env["ARACHNE_OSINT_FIXTURES"] == "/app/demo/osint"
    assert env["ARACHNE_OSINT_ENABLED"] == "true"


def test_every_lab_service_bound_to_loopback(compose: dict[str, Any]) -> None:
    lab = [
        name
        for name, service in compose["services"].items()
        if "lab" in service.get("profiles", [])
    ]
    assert lab, "the lab profile disappeared"
    for name in lab:
        for mapping in compose["services"][name].get("ports", []):
            assert str(mapping).startswith("127.0.0.1:"), f"{name} publishes {mapping}"


def test_the_prod_overlay_uses_docker_secrets(prod: dict[str, Any]) -> None:
    assert set(prod["secrets"]) == {"postgres_password", "api_keys"}
    db = prod["services"]["db"]
    assert db["environment"]["POSTGRES_PASSWORD_FILE"].startswith("/run/secrets/")
    api = prod["services"]["api"]
    assert api["environment"]["ARACHNE_API_KEYS_FILE"] == "/run/secrets/api_keys"
    for name in ("migrate", "scan", "api", "worker"):
        assert "postgres_password" in prod["services"][name]["secrets"]
        assert prod["services"][name]["environment"]["ARACHNE_DATABASE_PASSWORD_FILE"] == (
            "/run/secrets/postgres_password"
        )


def test_the_image_is_non_root_and_ships_what_the_roles_need() -> None:
    text = DOCKERFILE.read_text(encoding="utf-8")
    assert "USER arachne" in text
    assert 'pip install --no-cache-dir ".[postgres]"' in text
    assert "COPY docker/demo ./demo" in text
    assert "/reports" in text
    assert "EXPOSE 8080" in text


def test_the_demo_fixtures_exist_and_are_installable() -> None:
    demo = CODE_ROOT / "docker" / "demo"
    assert (demo / "target.yaml").is_file()
    assert (demo / "run-demo-scan.sh").is_file()
    assert any((demo / "http").glob("*.json"))
    assert any((demo / "osint").glob("*.json"))
    script = (demo / "run-demo-scan.sh").read_text(encoding="utf-8")
    assert "arachne scan" in script
    assert "arachne report" in script
    target = yaml.safe_load((demo / "target.yaml").read_text(encoding="utf-8"))
    assert target["target"]["attestation"]["attested_by"]
    assert target["options"]["engine"] == "heuristic"


def test_the_build_context_cannot_leak_secrets() -> None:
    ignored = (CODE_ROOT / ".dockerignore").read_text(encoding="utf-8")
    assert "docker/secrets" in ignored
    assert ".env" in ignored
    assert ".venv/" in ignored
