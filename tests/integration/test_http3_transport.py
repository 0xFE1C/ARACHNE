"""HTTP/3 transport against a real QUIC fixture (REQ-DET-006).

This file needs the optional extra (``arachne[quic]``). The rest of the suite does not: when
``aioquic`` is absent the whole module skips, which is asserted by
``tests/unit/test_http3_probe.py``'s degradation test being independent of it.
"""

from __future__ import annotations

import pytest

from arachne.modules.m2 import http3

pytest.importorskip("aioquic", reason="the optional extra arachne[quic] is not installed")

from tests.lab.quic_lab import start_http3_lab

pytestmark = pytest.mark.lab


async def test_a_quic_fixture_is_detected_and_its_headers_read() -> None:
    headers = {
        "strict-transport-security": "max-age=31536000",
        "x-content-type-options": "nosniff",
    }
    async with start_http3_lab(headers) as lab:
        response = await http3.http3_get("127.0.0.1", lab.port, server_name="127.0.0.1")
        assert response.ok, response.error
        assert response.status_code == 200
        assert response.transport == "h3"
        assert response.headers["strict-transport-security"] == "max-age=31536000"
        assert response.headers["x-content-type-options"] == "nosniff"


async def test_a_port_with_no_quic_listener_is_an_error_not_a_crash() -> None:
    async with start_http3_lab({}) as lab:
        port = lab.port
    # The fixture is closed now: the handshake must fail and say why.
    response = await http3.http3_get("127.0.0.1", port, server_name="127.0.0.1", wait_s=2.0)
    assert response.ok is False
    assert response.error


def test_header_helpers_are_transport_agnostic() -> None:
    assert http3.alt_svc_http3({"Alt-Svc": 'h3=":443"; ma=86400'}) == 'h3=":443"; ma=86400'
    assert http3.alt_svc_http3({"alt-svc": 'h2=":443"'}) is None
    assert http3.alt_svc_http3({}) is None
    missing = http3.missing_security_headers({"Strict-Transport-Security": "max-age=1"})
    assert "strict-transport-security" not in missing
    assert "content-security-policy" in missing
