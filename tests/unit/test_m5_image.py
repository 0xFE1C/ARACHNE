"""Unit acceptance for the native image scanner's parsing and hostile-archive handling.

Two properties here are gate conditions, not aspirations (REQ-DET-016): a crafted archive
must never write outside the temporary root, and the unpacked-size cap must be enforced. The
happy path is tested after them on purpose — the hostile layer is the one that has to be
right first.
"""

from __future__ import annotations

import gzip
import io
import json
import tarfile
from pathlib import Path

import pytest
from tests.lab.image_registry import gzip_layer

from arachne.modules.m5.corpus import VulnerableComponent
from arachne.modules.m5.external_sbom import load_external_report
from arachne.modules.m5.image import (
    ArchiveRefusedError,
    InstalledPackage,
    match_advisories,
    parse_image_reference,
    read_packages,
    unpack_layer,
)

MEDIA = "application/vnd.oci.image.layer.v1.tar+gzip"
CAPS = {"max_unpacked_bytes": 1_048_576, "max_file_bytes": 1_048_576, "max_members": 100}


def _unpack(blob: bytes, root: Path, **overrides: int):  # type: ignore[no-untyped-def]
    options = {**CAPS, **overrides}
    return unpack_layer(blob, MEDIA, root, **options)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- hostile archives
def test_a_symlink_member_refuses_the_layer_and_writes_nothing_through_it(
    tmp_path: Path,
) -> None:
    """The escape an image could attempt: a symlink, then a file through it."""
    outside = tmp_path / "outside"
    outside.mkdir()
    sentinel = outside / "pwned"
    root = tmp_path / "root"
    root.mkdir()
    layer = gzip_layer(
        {"escape/pwned": "owned", "app/readme": "hello"},
        symlinks={"escape": str(outside)},
    )
    with pytest.raises(ArchiveRefusedError, match="link or special file"):
        _unpack(layer, root)
    assert not sentinel.exists(), "a file was written through the symlink"
    assert list(root.rglob("*")) == [], "a refused layer must leave nothing behind"


def test_a_parent_traversal_member_is_refused(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    with pytest.raises(ArchiveRefusedError, match="component"):
        _unpack(gzip_layer({"../escape": "owned"}), root)


def test_an_absolute_member_is_refused(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    with pytest.raises(ArchiveRefusedError, match="absolute path"):
        _unpack(gzip_layer({"/etc/cron.d/pwned": "owned"}), root)


def test_a_hardlink_member_is_refused(tmp_path: Path) -> None:
    """The helper only emits symlinks, so a hardlink layer is constructed here."""
    root = tmp_path / "root"
    root.mkdir()
    out = io.BytesIO()
    with tarfile.open(fileobj=out, mode="w") as archive:
        info = tarfile.TarInfo("app/link")
        info.type = tarfile.LNKTYPE
        info.linkname = "app/x"
        archive.addfile(info)
    blob = gzip.compress(out.getvalue(), mtime=0)
    with pytest.raises(ArchiveRefusedError, match="link or special file"):
        _unpack(blob, root)


def test_the_unpacked_size_cap_is_enforced(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    with pytest.raises(ArchiveRefusedError, match="byte cap"):
        _unpack(gzip_layer({"big": b"x" * 4096}), root, max_unpacked_bytes=1024)
    assert list(root.rglob("*")) == []


def test_the_member_count_cap_is_enforced(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    with pytest.raises(ArchiveRefusedError, match="archive members"):
        _unpack(gzip_layer({f"f/{index}": "x" for index in range(20)}), root, max_members=5)


def test_a_zstd_layer_is_refused_without_an_external_process(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    with pytest.raises(ArchiveRefusedError, match="zstd"):
        unpack_layer(b"\x28\xb5\x2f\xfd fake", "application/zstd", root, **CAPS)


# --------------------------------------------------------------------------- packages
def test_dpkg_apk_python_and_npm_packages_are_read(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    _unpack(
        gzip_layer(
            {
                "var/lib/dpkg/status": (
                    "Package: openssl\nStatus: install ok installed\n"
                    "Version: 3.0.11-1~deb12u2\n\n"
                    "Package: removed\nStatus: deinstall ok config-files\nVersion: 1\n"
                ),
                "lib/apk/db/installed": "P:busybox\nV:1.36.0\n",
                "usr/lib/python3/dist-packages/urllib3-2.0.7.dist-info/METADATA": (
                    "Metadata-Version: 2.1\nName: urllib3\nVersion: 2.0.7\n"
                ),
                "app/node_modules/lodash/package.json": json.dumps(
                    {"name": "lodash", "version": "4.17.20"}
                ),
            }
        ),
        root,
    )
    packages = {
        (package.name, package.ecosystem): package.version for package in read_packages(root)
    }
    assert packages[("openssl", "deb")] == "3.0.11-1~deb12u2"
    assert ("removed", "deb") not in packages, "a deinstalled package is not installed"
    assert packages[("busybox", "apk")] == "1.36.0"
    assert packages[("urllib3", "pypi")] == "2.0.7"
    assert packages[("lodash", "npm")] == "4.17.20"


def test_a_distroless_root_has_no_packages(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    _unpack(
        gzip_layer({"usr/local/bin/app": b"\x7fELF", "etc/os-release": "ID=distroless\n"}), root
    )
    assert read_packages(root) == ()


# --------------------------------------------------------------------------- advisories
def test_an_advisory_match_carries_name_installed_fixed_and_advisory_id() -> None:
    packages = [
        InstalledPackage("openssl", "3.0.11-1~deb12u2", "deb", "var/lib/dpkg/status"),
        InstalledPackage("openssl", "3.0.14", "deb", "var/lib/dpkg/status"),
    ]
    advisories = [
        VulnerableComponent(
            name="openssl",
            ecosystem="deb",
            below="3.0.14",
            cve="CVE-2024-0727",
            severity="high",
            advisory="DSA-5610-1",
        )
    ]
    matched = match_advisories(packages, advisories)
    assert len(matched) == 1
    package, advisory = matched[0]
    assert package.version == "3.0.11-1~deb12u2"
    assert advisory.below == "3.0.14"
    assert advisory.advisory == "DSA-5610-1"
    assert advisory.cve == "CVE-2024-0727"


# --------------------------------------------------------------------------- references
@pytest.mark.parametrize(
    ("value", "registry", "repository", "reference"),
    [
        ("image:reg.example:5000/team/app:1.2.3", "reg.example:5000", "team/app", "1.2.3"),
        ("registry:reg.example/team/app", "reg.example", "team/app", "latest"),
        ("docker:127.0.0.1:5000/app:dev", "127.0.0.1:5000", "app", "dev"),
        (
            "image:reg.example/team/app@sha256:" + "a" * 64,
            "reg.example",
            "team/app",
            "sha256:" + "a" * 64,
        ),
    ],
)
def test_image_references_parse(value: str, registry: str, repository: str, reference: str) -> None:
    parsed = parse_image_reference(value)
    assert parsed is not None
    assert (parsed.registry, parsed.repository, parsed.reference) == (
        registry,
        repository,
        reference,
    )


@pytest.mark.parametrize(
    "value",
    ["https://example.com/app:1", "image:app:1", "image:reg.example", "endpoint:http://x/"],
)
def test_a_reference_that_names_no_image_is_refused(value: str) -> None:
    assert parse_image_reference(value) is None


def test_a_loopback_registry_uses_http_and_a_remote_one_https() -> None:
    loopback = parse_image_reference("image:127.0.0.1:5000/app:1")
    remote = parse_image_reference("image:registry.example/app:1")
    assert loopback is not None and loopback.base_url == "http://127.0.0.1:5000"
    assert remote is not None and remote.base_url == "https://registry.example"


# --------------------------------------------------------------------------- external report
def test_a_trivy_report_is_ingested_with_name_version_fix_and_advisory(tmp_path: Path) -> None:
    report = tmp_path / "trivy.json"
    report.write_text(
        json.dumps(
            {
                "Results": [
                    {
                        "Target": "app",
                        "Vulnerabilities": [
                            {
                                "VulnerabilityID": "CVE-2024-0001",
                                "PkgName": "libfoo",
                                "InstalledVersion": "1.0.0",
                                "FixedVersion": "1.0.1",
                                "Severity": "HIGH",
                            }
                        ],
                    },
                    {"Target": "sbom", "Class": "lang-pkgs"},
                ]
            }
        ),
        encoding="utf-8",
    )
    findings, note = load_external_report("trivy", report)
    assert note == ""
    assert findings == [
        {
            "package": "libfoo",
            "installed": "1.0.0",
            "fixed": "1.0.1",
            "advisory": "CVE-2024-0001",
            "severity": "HIGH",
        }
    ]


def test_a_grype_report_is_ingested(tmp_path: Path) -> None:
    report = tmp_path / "grype.json"
    report.write_text(
        json.dumps(
            {
                "matches": [
                    {
                        "artifact": {"name": "bash", "version": "5.2.0"},
                        "vulnerability": {"id": "CVE-2024-0002", "severity": "Medium"},
                        "fix": {"versions": ["5.2.1"]},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    findings, note = load_external_report("grype", report)
    assert note == ""
    assert findings[0]["package"] == "bash"
    assert findings[0]["fixed"] == "5.2.1"
    assert findings[0]["advisory"] == "CVE-2024-0002"


@pytest.mark.parametrize(
    ("tool", "path"),
    [(None, None), ("nmap", "x.json"), ("trivy", None), ("trivy", "/does/not/exist.json")],
)
def test_an_unusable_external_report_is_a_note_not_a_crash(
    tool: str | None, path: str | None
) -> None:
    findings, note = load_external_report(tool, path)
    assert findings == []
    assert note
