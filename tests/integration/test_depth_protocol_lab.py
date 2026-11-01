"""Acceptance: the S29 gRPC and OT/ICS checks meet the protocol lab's ground truth.

REQ-DEPTH-003 and REQ-DEPTH-006 both ask for a *lab fixture*: "lab gRPC fixture" and "protocol-lab
extension". This module drives the new M2 checks against ``tests/lab/arachne_lab.py``, whose S29
services are three gRPC deployments (a vulnerable one, an application-hardened one that still
speaks cleartext HTTP/2, and a TLS-only one) plus real S7comm and DNP3 peers, and asserts:

* each facet is reported on the deployment that has the misconfiguration;
* the hardened deployments produce no candidate (the false-positive control);
* the OT check sends nothing while ``ARACHNE_NET_OT_PROBE`` is off;
* the gRPC probe's own frames are well-formed enough that a real peer answers (the lab decodes
  the HPACK header block and the gRPC length-prefixed message, so a malformed request would
  simply not produce a response).

The checks are driven directly, as the checks step would, through
:func:`tests.helpers.depth.make_depth_harness` with a port catalogue that names the lab's
ephemeral ports — the documented way to tell ARACHNE where a service lives (F-09-04).
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from tests.helpers.checks import asset_for
from tests.helpers.depth import make_depth_harness
from tests.lab.arachne_lab import LabFixture, start_m2_lab

from arachne.core.config import NetSettings
from arachne.modules.m2 import M2_CHECKS

#: ``(lab service, catalogue service name, probe name)`` — the declared port map.
CATALOGUE: tuple[tuple[str, str, str], ...] = (
    ("grpc", "grpc", "grpc"),
    ("grpc-hardened", "grpc", "grpc"),
    ("grpc-tls-only", "grpc", "grpc"),
    ("s7", "iso-tsap", "s7"),
    ("dnp3", "dnp3", "dnp3"),
)


@pytest.fixture(scope="module")
def lab() -> Iterator[LabFixture]:
    fixture = start_m2_lab(include_udp=False)
    try:
        yield fixture
    finally:
        fixture.stop()


def _catalogue(lab: LabFixture, directory: Path) -> Path:
    entries = "\n".join(
        f"  - {{port: {lab.port(name)}, service: {service}, probe: {probe}}}"
        for name, service, probe in CATALOGUE
    )
    path = directory / "s29-ports.yaml"
    path.write_text(
        'catalog_version: "s29-lab"\n'
        "source: the ephemeral ports the protocol lab bound for this test run\n"
        f"tcp:\n{entries}\nudp: []\n",
        encoding="utf-8",
    )
    return path


def _by_id() -> dict[str, type]:
    return {check.metadata.id: check for check in M2_CHECKS}


async def _run(lab: LabFixture, check_id: str, tmp_path: Path, *, ot: bool = True) -> list:
    """Run one M2 check against the lab with the lab's port catalogue in force."""
    check_cls = _by_id()[check_id]
    catalogue = _catalogue(lab, tmp_path)
    harness = make_depth_harness(
        asset=asset_for("host", "127.0.0.1"),
        net=NetSettings(
            port_catalog=str(catalogue),
            ot_probe=ot,
            allow_udp=False,
            # A protocol probe against loopback answers in microseconds; the production read
            # timeout would only make the suite slow.
            read_timeout_s=1.5,
            connect_timeout_s=1.5,
        ),
        seed_services=(
            (lab.port("grpc"), "grpc"),
            (lab.port("grpc-hardened"), "grpc"),
            (lab.port("grpc-tls-only"), "https-alt"),
            (lab.port("s7"), "iso-tsap"),
            (lab.port("dnp3"), "dnp3"),
        ),
    )
    try:
        ctx = harness.context(check_cls())
        return [result async for result in check_cls().run(ctx)]
    finally:
        await harness.aclose()


def _blob(results: list) -> str:
    parts: list[str] = []
    for result in results:
        if result.status != "vulnerable":
            continue
        for item in result.evidence:
            for key, value in item.payload.items():
                parts.append(f"{key}={value}")
        parts.append(result.title)
    return " ".join(parts)


async def test_grpc_cleartext_is_reported_on_the_vulnerable_service(
    lab: LabFixture, tmp_path: Path
) -> None:
    """REQ-DEPTH-003: a cleartext HTTP/2 endpoint is found."""
    results = await _run(lab, "m2.grpc-plaintext", tmp_path)
    blob = _blob(results)
    assert f"port={lab.port('grpc')}" in blob, [r.title for r in results]
    # The TLS-only deployment must not be reported: it refuses the plaintext preface.
    assert f"port={lab.port('grpc-tls-only')}" not in blob


async def test_grpc_reflection_and_metadata_are_reported(lab: LabFixture, tmp_path: Path) -> None:
    """REQ-DEPTH-003: reflection exposure and request-metadata echo are both found."""
    reflection = await _run(lab, "m2.grpc-reflection", tmp_path)
    blob = _blob(reflection)
    assert f"port={lab.port('grpc')}" in blob, [r.title for r in reflection]
    assert f"port={lab.port('grpc-hardened')}" not in blob, "reflection reported on /grpc-hardened"

    leak = await _run(lab, "m2.grpc-metadata-leak", tmp_path)
    leak_blob = _blob(leak)
    assert f"port={lab.port('grpc')}" in leak_blob, [r.title for r in leak]
    assert f"port={lab.port('grpc-hardened')}" not in leak_blob, "leak reported on /grpc-hardened"


async def test_the_ot_probe_is_off_by_default(lab: LabFixture, tmp_path: Path) -> None:
    """REQ-DEPTH-006: OT probing is strictly opt-in — with the switch off nothing is sent."""
    results = await _run(lab, "m2.ot-protocol-probe", tmp_path, ot=False)
    assert all(result.status != "vulnerable" for result in results)
    assert any("ARACHNE_NET_OT_PROBE" in (r.detail or "") for r in results)


async def test_ot_protocols_are_found_in_the_protocol_lab(lab: LabFixture, tmp_path: Path) -> None:
    """REQ-DEPTH-006: S7comm and DNP3 peers are discovered, read-only."""
    results = await _run(lab, "m2.ot-protocol-probe", tmp_path)
    blob = _blob(results)
    assert "protocol=s7comm" in blob, [r.title for r in results]
    assert "protocol=dnp3" in blob, [r.title for r in results]
    assert f"port={lab.port('s7')}" in blob
    assert f"port={lab.port('dnp3')}" in blob
    # The read-only claims are carried in the evidence, not only in prose.
    assert "jobs_sent=0" in blob
    assert "link_reset_sent=False" in blob
