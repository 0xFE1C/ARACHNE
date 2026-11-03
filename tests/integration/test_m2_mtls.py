"""Mutual TLS against the loopback lab (REQ-DET-011).

Two real TLS servers, two real handshakes, one assertion each:

* ``tls-mtls-required`` is the **decoy**: it sends a ``CertificateRequest`` and fails the
  handshake when the client presents nothing. A correctly configured server must produce no
  finding.
* ``tls-mtls-optional`` is the planted weakness: it sends the same ``CertificateRequest`` and
  then completes the handshake with an unauthenticated client. That is the finding.

The check is L1, so the test also asserts what was *not* done: the only bytes on the wire are
TLS handshake messages (the evidence lists them), and the session ends without an
application-layer request.
"""

from __future__ import annotations

import inspect

import pytest
from tests.helpers.depth import make_depth_harness
from tests.lab.arachne_lab import m2_lab

from arachne.modules.m2 import mtls_cert, wire
from arachne.modules.m2.mtls import MutualTlsAuth

pytestmark = pytest.mark.lab


async def _run_with_lab(lab, name: str):  # type: ignore[no-untyped-def]
    port = lab.port(name)
    harness = make_depth_harness(seed_services=((port, "tls"),))
    check = MutualTlsAuth()
    results = [result async for result in check.run(harness.context(MutualTlsAuth))]
    return results, harness


async def test_the_enforcing_server_produces_no_finding() -> None:
    with m2_lab(include_udp=False) as lab:
        results, _ = await _run_with_lab(lab, "tls-mtls-required")
        statuses = [result.status for result in results]
        assert "vulnerable" not in statuses
        assert "requires a client certificate" in results[1].title
        facts = results[0].evidence[0].payload["facts"]
        assert facts["certificate_request"] is True
        assert facts["no_certificate_handshake"]["ok"] is False
        assert facts["invalid_certificate_alert"]["certificate_related"] is True


async def test_the_optional_server_is_the_finding() -> None:
    with m2_lab(include_udp=False) as lab:
        results, _ = await _run_with_lab(lab, "tls-mtls-optional")
        findings = [result for result in results if result.status == "vulnerable"]
        assert len(findings) == 1
        assert "does not require them" in findings[0].title
        assert findings[0].cwe == "CWE-295"
        facts = results[0].evidence[0].payload["facts"]
        assert facts["certificate_request"] is True
        assert facts["no_certificate_handshake"]["ok"] is True


async def test_the_probe_only_sends_tls_handshake_messages() -> None:
    """L1: no application-layer request, ever. The flight says exactly what was exchanged."""
    with m2_lab(include_udp=False) as lab:
        results, harness = await _run_with_lab(lab, "tls-mtls-optional")
        facts = results[0].evidence[0].payload["facts"]
        known = set(wire.TLS_HANDSHAKE_NAMES.values())
        assert set(facts["handshake_types"]) <= known
        # Two probes per service: one TLS handshake (observation a) and one raw flight
        # (observations b and c). The fixture serves no application protocol, and the check
        # sends none — a request would have produced an HTTP response to read.
        assert harness.net_client.probes == 2


def test_the_throwaway_certificate_never_becomes_a_credential() -> None:
    """The probe presents a certificate whose private key this product never reads."""
    assert mtls_cert.verify_self_signature(mtls_cert.certificate_der()) is True
    source = inspect.getsource(__import__("arachne.modules.m2.mtls", fromlist=["x"]))
    # The check may *build* the certificate and present it; it must never load a key into an
    # SSL context, which is what would make it able to authenticate anywhere.
    for forbidden in ("load_cert_chain", "SSLContext", "PRIVATE KEY"):
        assert forbidden not in source


def test_the_lab_export_includes_the_mtls_pair() -> None:
    with m2_lab(include_udp=False) as lab:
        assert "tls-mtls-required" in lab.services
        assert "tls-mtls-optional" in lab.services
