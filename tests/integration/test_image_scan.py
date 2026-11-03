"""Acceptance: native container-image scanning against a local registry fixture (REQ-DET-016).

The fixture is an in-process OCI registry on loopback, so every assertion is made offline
with no container runtime and no image ever executed. The gate conditions are covered
explicitly: the symlink escape is refused, the unpacked-size cap bites, a distroless image is
a valid empty result, findings carry name/installed/fixed/advisory, and the external scanner
path exists without being the default.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import pytest
from tests.helpers.checks import asset_for
from tests.helpers.m5 import make_m5_harness
from tests.lab.image_registry import (
    ImageSpec,
    gzip_layer,
    image_from_layers,
    manifest_list,
    start_image_registry,
)

from arachne.core.config import M5Settings
from arachne.modules.m5.image import ImageScan

VULNERABLE_FILES = {
    "var/lib/dpkg/status": (
        "Package: openssl\nStatus: install ok installed\n"
        "Version: 3.0.11-1~deb12u2\n\n"
        "Package: libc6\nStatus: install ok installed\nVersion: 2.36-9+deb12u4\n"
    ),
    "usr/local/lib/python3.11/site-packages/urllib3-2.0.7.dist-info/METADATA": (
        "Metadata-Version: 2.1\nName: urllib3\nVersion: 2.0.7\n"
    ),
    "app/node_modules/lodash/package.json": json.dumps({"name": "lodash", "version": "4.17.20"}),
}


def _images() -> dict[str, ImageSpec]:
    vulnerable = image_from_layers([gzip_layer(VULNERABLE_FILES)])
    distroless = image_from_layers(
        [gzip_layer({"usr/local/bin/app": b"\x7fELF static", "etc/os-release": "ID=distroless\n"})]
    )
    hostile = image_from_layers(
        [gzip_layer({"app/readme": "hello"}, symlinks={"etc/passwd": "/etc/passwd"})]
    )
    bomb = image_from_layers([gzip_layer({"var/lib/dpkg/status": "x" * 65_536})])
    indexed = image_from_layers(
        [gzip_layer({"var/lib/dpkg/status": "Package: openssl\nVersion: 3.0.11\n"})]
    )
    index = manifest_list(indexed, tag="latest")
    raw = json.dumps(index, sort_keys=True).encode("utf-8")
    import hashlib

    index_digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    indexed.manifests[index_digest] = index
    indexed.tags["v1"] = index_digest
    return {
        "app": vulnerable,
        "static": distroless,
        "hostile": hostile,
        "bomb": bomb,
        "indexed": indexed,
    }


@pytest.fixture(scope="module")
def registry() -> Iterator[object]:
    with start_image_registry(_images()) as lab:
        yield lab


async def _run(asset, *, m5: M5Settings | None = None):  # type: ignore[no-untyped-def]
    harness = make_m5_harness(asset=asset, m5=m5)
    try:
        ctx = harness.context(ImageScan())
        return [result async for result in ImageScan().run(ctx)]
    finally:
        await harness.aclose()


def _artifact(result: object, signal: str) -> dict:  # type: ignore[type-arg]
    for item in getattr(result, "evidence", ()):
        if item.payload.get("signal") == signal:
            return dict(item.payload)
    return {}


# --------------------------------------------------------------------------- native resolution
async def test_an_image_resolves_to_manifest_layers_and_packages(registry) -> None:  # type: ignore[no-untyped-def]
    """REQ-DET-016: manifest, layers and packages, with the image never executed."""
    asset = asset_for("cloud", registry.reference("app", "latest"))
    results = await _run(asset)
    inventory = next(
        _artifact(result, "image-inventory")
        for result in results
        if _artifact(result, "image-inventory")
    )
    assert inventory["manifest_digest"].startswith("sha256:")
    assert len(inventory["layers"]) == 1
    assert inventory["package_count"] == 4
    assert inventory["unpacked_bytes"] > 0
    # The image was read, never run: only manifest and blob GETs were issued.
    assert all(request.startswith("GET /v2/") for request in registry.requests)
    assert all(("manifests" in request) or ("blobs" in request) for request in registry.requests)


async def test_findings_carry_name_installed_fixed_and_advisory(registry) -> None:  # type: ignore[no-untyped-def]
    asset = asset_for("cloud", registry.reference("app", "latest"))
    results = await _run(asset)
    findings = [_artifact(result, "image-vulnerable-package") for result in results]
    findings = [item for item in findings if item]
    by_package = {item["package"]: item for item in findings}
    assert {"openssl", "libc6", "urllib3", "lodash"} <= set(by_package)
    openssl = by_package["openssl"]
    assert openssl["installed"] == "3.0.11-1~deb12u2"
    assert openssl["fixed"] == "3.0.14"
    assert openssl["advisory"] == "DSA-5610-1"
    assert openssl["cve"] == "CVE-2024-0727"
    lodash = by_package["lodash"]
    assert lodash["installed"] == "4.17.20"
    assert lodash["fixed"] == "4.17.21"
    assert lodash["advisory"] == "CVE-2021-23337"


async def test_a_manifest_list_is_followed_one_level(registry) -> None:  # type: ignore[no-untyped-def]
    asset = asset_for("cloud", registry.reference("indexed", "v1"))
    results = await _run(asset)
    assert any(
        _artifact(result, "image-vulnerable-package").get("package") == "openssl"
        for result in results
    )


# --------------------------------------------------------------------------- empty / hostile
async def test_a_distroless_image_is_a_valid_result_not_an_error(registry) -> None:  # type: ignore[no-untyped-def]
    asset = asset_for("cloud", registry.reference("static", "latest"))
    results = await _run(asset)
    assert results, "a distroless image must still produce a result"
    assert not any(result.status == "error" for result in results), results
    clean = [result for result in results if result.status == "not_vulnerable"]
    assert clean, [result.title for result in results]
    inventory = next(
        _artifact(result, "image-inventory")
        for result in results
        if _artifact(result, "image-inventory")
    )
    assert inventory["package_count"] == 0


async def test_a_symlink_escape_is_refused_and_reported(registry) -> None:  # type: ignore[no-untyped-def]
    asset = asset_for("cloud", registry.reference("hostile", "latest"))
    results = await _run(asset)
    refusals = [_artifact(result, "image-layer-refused") for result in results]
    refusals = [item for item in refusals if item]
    assert refusals, [result.title for result in results]
    assert "link or special file" in refusals[0]["reason"]
    assert not any(result.status == "error" for result in results), results


async def test_the_unpacked_size_cap_is_enforced_by_the_check(registry) -> None:  # type: ignore[no-untyped-def]
    asset = asset_for("cloud", registry.reference("bomb", "latest"))
    results = await _run(asset, m5=M5Settings(image_max_unpacked_bytes=1024))
    refusals = [_artifact(result, "image-layer-refused") for result in results]
    refusals = [item for item in refusals if item]
    assert refusals, [result.title for result in results]
    assert "cap" in refusals[0]["reason"]


# --------------------------------------------------------------------------- external path
async def test_the_native_path_is_the_default_and_needs_no_external_scanner(registry) -> None:  # type: ignore[no-untyped-def]
    defaults = M5Settings()
    assert defaults.image_scan is True
    assert defaults.registry_scan is False, "the external path must not be the default"
    asset = asset_for("cloud", registry.reference("app", "latest"))
    results = await _run(asset, m5=defaults)
    assert any(
        result.status == "vulnerable"
        and _artifact(result, "image-vulnerable-package").get("ecosystem") != "external"
        for result in results
    )


async def test_a_configured_external_report_is_merged(registry, tmp_path: Path) -> None:  # type: ignore[no-untyped-def]
    report = tmp_path / "trivy.json"
    report.write_text(
        json.dumps(
            {
                "Results": [
                    {
                        "Target": "app",
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": "CVE-2024-9999",
                                "PkgName": "external-only",
                                "InstalledVersion": "0.1.0",
                                "FixedVersion": "0.2.0",
                                "Severity": "HIGH",
                            }
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    settings = M5Settings(registry_scan=True, sbom_tool="trivy", sbom_report=str(report))
    asset = asset_for("cloud", registry.reference("app", "latest"))
    results = await _run(asset, m5=settings)
    external = [
        _artifact(result, "image-vulnerable-package")
        for result in results
        if _artifact(result, "image-vulnerable-package").get("ecosystem") == "external"
    ]
    assert external and external[0]["package"] == "external-only"
    assert external[0]["advisory"] == "CVE-2024-9999"
    assert external[0]["fixed"] == "0.2.0"
