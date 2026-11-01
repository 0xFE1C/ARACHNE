"""The lab repository's own test suite — the gate a fix proposal must pass (S27).

These assertions describe what must keep working when the deployment changes: the manifest
still parses, the image stays pinned, the container keeps its limits, the database keeps its
encryption and its snapshot policy. None of them asserts on the *security posture* the M5
review reports (privileged mode, host networking, public addresses) — that is what makes the
suite an honest gate for a hardening patch rather than a tautology.

The suite is run by ARACHNE's fix engine through the grant's declared command; it never
runs as part of ARACHNE's own suite (see ``tests/fixtures/conftest.py``).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def manifest() -> dict:
    document = yaml.safe_load((ROOT / "deploy" / "api.yaml").read_text(encoding="utf-8"))
    assert isinstance(document, dict)
    return document


def test_the_manifest_parses_as_a_deployment(manifest: dict) -> None:
    assert manifest["apiVersion"] == "apps/v1"
    assert manifest["kind"] == "Deployment"
    assert manifest["metadata"]["name"] == "payments-api"


def test_the_image_stays_pinned_to_a_tag(manifest: dict) -> None:
    image = manifest["spec"]["template"]["spec"]["containers"][0]["image"]
    assert ":" in image, "the image must carry an explicit tag"
    assert not image.endswith(":latest")


def test_the_container_keeps_its_resource_limits(manifest: dict) -> None:
    container = manifest["spec"]["template"]["spec"]["containers"][0]
    assert container["resources"]["limits"]["memory"] == "512Mi"
    assert container["securityContext"]["readOnlyRootFilesystem"] is True


def test_the_container_never_automounts_a_service_account_token(manifest: dict) -> None:
    pod = manifest["spec"]["template"]["spec"]
    assert pod["automountServiceAccountToken"] is False


def test_the_database_keeps_encryption_and_snapshot_policy() -> None:
    text = (ROOT / "infra" / "main.tf").read_text(encoding="utf-8")
    assert re.search(r"storage_encrypted\s*=\s*true", text), "the database must stay encrypted"
    assert re.search(r"skip_final_snapshot\s*=\s*false", text), (
        "the database must keep taking a final snapshot"
    )


def test_the_reports_bucket_keeps_its_environment_tag() -> None:
    text = (ROOT / "infra" / "main.tf").read_text(encoding="utf-8")
    assert 'Environment = "production"' in text
