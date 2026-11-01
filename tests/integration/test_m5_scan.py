"""Acceptance: M5 runs against the cloud lab and the risky-repo fixture.

The S10 definition of done is: "M5 checks green against the cloud-lab fixtures". The lab has two
halves, both used here:

* ``tests/lab/cloud_lab.py`` — a reachable, misconfigured S3/MinIO, Firebase, Supabase,
  Terraform backend, kubelet, Docker daemon and OCI registry on loopback;
* ``tests/fixtures/repo/`` — a clone with a risky GitHub Actions workflow, a committed
  ``.tfstate``, IaC that opens a security group to the world, a Dockerfile with an ENV secret
  and ``USER root``, plaintext Helm values, an internal-scoped dependency, a known-vulnerable
  lockfile, a GCP service-account key, a wildcard IAM policy and a ``.env`` with AWS keys.

Every check is driven directly (as the checks step would) and scored against the lab's declared
signals. The two opt-in metadata checks are proven inert with their switch off, then reported
with it on.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from tests.helpers.checks import asset_for
from tests.helpers.m5 import make_m5_harness
from tests.lab.cloud_lab import (
    CLOUD_FALSE_POSITIVE_TRAPS,
    CLOUD_GROUND_TRUTH,
    CloudLab,
    start_cloud_lab,
)
from tests.lab.web_lab import WebLab, start_web_lab

from arachne.core.config import M5Settings
from arachne.modules.m5 import M5_CHECKS
from arachne.modules.m5.cloud import AzureMiAudit, ImdsSsrf
from arachne.modules.m5.platform import TfstateExposure

REPO_FIXTURE: Path = Path(__file__).resolve().parents[1] / "fixtures" / "repo"


@pytest.fixture(scope="module")
def cloud() -> Iterator[CloudLab]:
    with start_cloud_lab() as running:
        yield running


@pytest.fixture(scope="module")
def web() -> Iterator[WebLab]:
    with start_web_lab() as running:
        yield running


def _by_id() -> dict[str, type]:
    return {check.metadata.id: check for check in M5_CHECKS}


def _blob(result: object) -> str:
    parts: list[str] = []
    for item in getattr(result, "evidence", ()):
        for key, value in item.payload.items():
            parts.append(f"{key}={value}")
    return " ".join(parts)


async def _run(
    check_cls: type, *, asset, m5: M5Settings | None = None, roots: list[str] | None = None
):
    harness = make_m5_harness(asset=asset, m5=m5)
    try:
        if roots:
            await harness.prepare(roots)
        ctx = harness.context(check_cls())
        return [result async for result in check_cls().run(ctx)]
    finally:
        await harness.aclose()


#: ``(check id, cloud-lab path prefix)`` — the endpoint families.
ENDPOINT_TARGETS = (
    ("m5.bucket-enumerator", "/storage/backup"),
    ("m5.firebase-rules", "/firebase"),
    ("m5.supabase-rls", "/supabase"),
    ("m5.tfstate-exposure", "/tfstate"),
    ("m5.k8s-exposure", "/kubelet"),
    ("m5.registry-scan", "/registry"),
    ("m5.docker-socket", "/docker"),
)

#: ``(check id, expected artifact signal)`` — the local-artifact families against the repo.
REPO_TARGETS = (
    ("m5.leaked-cloud-keys", "leaked-cloud-credentials"),
    ("m5.gcp-sa-keys", "gcp-service-account-key"),
    ("m5.iam-review", "iam-overprivilege"),
    ("m5.cicd-audit", "cicd-risk"),
    ("m5.dep-confusion", "dependency-confusion"),
    ("m5.sbom-review", "sbom-vulnerable-component"),
    ("m5.image-history-secrets", "image-secret"),
    ("m5.tfstate-exposure", "tfstate-exposure"),
)


async def test_endpoint_checks_find_the_cloud_lab_exposures(cloud: CloudLab) -> None:
    """DONE criterion 2 (endpoints): each planted cloud exposure is reported with its signal."""
    checks = _by_id()
    for check_id, prefix in ENDPOINT_TARGETS:
        asset = asset_for("cloud", f"endpoint:{cloud.endpoint(prefix)}")
        results = await _run(checks[check_id], asset=asset)
        blob = " ".join(_blob(result) for result in results if result.status == "vulnerable")
        expected = dict(CLOUD_GROUND_TRUTH).get(check_id, "")
        assert expected and expected in blob, f"{check_id}: {[r.title for r in results]}"


async def test_repo_checks_find_the_supply_chain_risks() -> None:
    """DONE criterion 2 (artifacts): the risky repo fixture is reviewed end to end."""
    checks = _by_id()
    asset = asset_for("cloud", f"repo:{REPO_FIXTURE}")
    for check_id, signal in REPO_TARGETS:
        results = await _run(checks[check_id], asset=asset)
        secret_blob = " ".join(_blob(result) for result in results if result.status == "vulnerable")
        assert signal in secret_blob, f"{check_id}: {[r.title for r in results]}"


async def test_iac_review_is_reported_alongside_the_state_file() -> None:
    """The IaC half of ``m5.tfstate-exposure`` (ch05#12) reports the open constructs."""
    asset = asset_for("cloud", f"repo:{REPO_FIXTURE}")
    results = await _run(TfstateExposure, asset=asset)
    blob = " ".join(_blob(result) for result in results)
    assert "iac-misconfiguration" in blob
    assert "tfstate-exposure" in blob


async def test_metadata_checks_are_inert_and_then_run_when_enabled(web: WebLab) -> None:
    """The two metadata families are behind ARACHNE_M5_IMDS_PROBE (off by default)."""
    roots = [f"{web.base_url.rstrip('/')}/fetch?url=/home"]
    asset = asset_for("url", web.base_url)

    for check in (ImdsSsrf, AzureMiAudit):
        results = await _run(check, asset=asset, m5=M5Settings(), roots=roots)
        assert all(result.status != "vulnerable" for result in results), check.metadata.id
    assert not [entry for entry in web.requests if "169.254.169.254" in entry], (
        "a metadata URL was sent with the switch off"
    )

    enabled = M5Settings(imds_probe=True)
    imds = await _run(ImdsSsrf, asset=asset, m5=enabled, roots=roots)
    assert any(result.status == "vulnerable" for result in imds)
    azure = await _run(AzureMiAudit, asset=asset, m5=enabled, roots=roots)
    assert any(result.status == "vulnerable" for result in azure)


async def test_the_hardened_cloud_controls_are_not_reported(cloud: CloudLab) -> None:
    """A public-access block and an authenticated kubelet must not produce a candidate."""
    checks = _by_id()
    cases = (
        ("m5.bucket-enumerator", "/storage/private"),
        ("m5.k8s-exposure", "/kubelet-hardened"),
    )
    for check_id, prefix in cases:
        asset = asset_for("cloud", f"endpoint:{cloud.endpoint(prefix)}")
        results = await _run(checks[check_id], asset=asset)
        traps = [marker for planted, marker in CLOUD_FALSE_POSITIVE_TRAPS if planted == check_id]
        blob = " ".join(_blob(result) for result in results if result.status == "vulnerable")
        assert not any(trap in blob for trap in traps), f"{check_id}: {[r.title for r in results]}"
