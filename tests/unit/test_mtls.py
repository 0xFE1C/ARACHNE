"""Mutual-TLS observation: the throwaway certificate, the flight parser and the decision.

Three layers are proven here, because the check's honesty depends on all three:

* the **certificate** is a real, decodable, validly self-signed X.509 document that names no
  real principal and cannot authenticate anywhere (REQ-DET-011's credential rule);
* the **flight parser** reads a TLS 1.2 server flight for a ``CertificateRequest``, an alert
  and the negotiated version, and says ``undetermined`` rather than guessing at TLS 1.3;
* the **decision** produces one finding shape — "requests certificates, does not require
  them" — and nothing for the correctly configured decoy.
"""

from __future__ import annotations

import base64
import hashlib
import struct

import pytest
from tests.helpers.checks import make_m2_harness

from arachne.core.net import TcpExchange, TlsExchange
from arachne.modules.m2 import mtls_cert, wire
from arachne.modules.m2.mtls import MutualTlsAuth


# --------------------------------------------------------------------------- flight builders
def _record(content_type: int, body: bytes) -> bytes:
    return bytes([content_type]) + b"\x03\x03" + struct.pack(">H", len(body)) + body


def _handshake(message_type: int, body: bytes) -> bytes:
    return bytes([message_type]) + struct.pack(">I", len(body))[1:] + body


def _server_hello() -> bytes:
    body = (
        b"\x03\x03"
        + b"\x11" * 32
        + b"\x00"
        + b"\xc0\x2f"
        + b"\x00"
        + struct.pack(">H", 2 + 4)
        + struct.pack(">HH", 0x002B, 2)
        + struct.pack(">H", 0x0303)
    )
    return _handshake(2, body)


def _certificate() -> bytes:
    der = mtls_cert.certificate_der()
    listing = struct.pack(">I", len(der) + 3)[1:] + struct.pack(">I", len(der))[1:] + der
    return _handshake(11, listing)


def _certificate_request() -> bytes:
    # certificate_types + an empty supported_signature_algorithms + no CA list
    return _handshake(
        13, b"\x01\x40" + struct.pack(">H", 2) + struct.pack(">H", 0) + struct.pack(">H", 0)
    )


def _server_hello_done() -> bytes:
    return _handshake(14, b"")


def _flight(*, request: bool, alert: int | None = None) -> bytes:
    body = _server_hello() + _certificate()
    if request:
        body += _certificate_request()
    body += _server_hello_done()
    payload = _record(0x16, body)
    if alert is not None:
        payload += _record(0x15, bytes([2, alert]))
    return payload


# --------------------------------------------------------------------------- the certificate
def test_the_throwaway_certificate_decodes_as_a_real_x509(tmp_path) -> None:
    """The platform's own parser accepts it — otherwise the probe measures a parse error."""
    import ssl

    der = mtls_cert.certificate_der()
    body = base64.b64encode(der).decode()
    pem = tmp_path / "throwaway.pem"
    pem.write_text(
        "-----BEGIN CERTIFICATE-----\n"
        + "\n".join(body[index : index + 64] for index in range(0, len(body), 64))
        + "\n-----END CERTIFICATE-----\n",
        encoding="utf-8",
    )
    decoded = ssl._ssl._test_decode_cert(str(pem))
    assert decoded["subject"] == decoded["issuer"], "a self-signed document has one name"
    names = dict(item[0] for item in decoded["subject"])
    assert names["commonName"] == "arachne-mtls-probe.invalid"
    assert names["organizationName"].startswith("ARACHNE throwaway")


def test_the_throwaway_certificate_is_validly_self_signed() -> None:
    assert mtls_cert.verify_self_signature(mtls_cert.certificate_der()) is True


def test_a_tampered_certificate_does_not_verify() -> None:
    der = bytearray(mtls_cert.certificate_der())
    der[-1] ^= 0x01
    assert mtls_cert.verify_self_signature(bytes(der)) is False


def test_the_certificate_is_deterministic_and_needs_nothing_on_disk() -> None:
    """Generated in process, from values in the module: no file, no crypto dependency."""
    first = mtls_cert.certificate_der()
    second = mtls_cert.certificate_der()
    assert first == second
    assert first[0] == 0x30
    assert b"arachne-mtls-probe.invalid" in first


def test_the_certificate_carries_no_principal_identity() -> None:
    der = mtls_cert.certificate_der()
    for forbidden in (b"CN=localhost", b"BEGIN PRIVATE KEY", b"example.com"):
        assert forbidden not in der
    # The key size is reported so a reader can see it is a real certificate, not a blob.
    assert mtls_cert.THROWAWAY_KEY_BITS == 2048


# --------------------------------------------------------------------------- the flight parser
def test_a_tls12_flight_with_a_certificate_request_is_recognised() -> None:
    parsed = wire.parse_tls_server_flight(_flight(request=True, alert=48))
    assert parsed["certificate_request"] is True
    assert parsed["complete"] is True
    assert parsed["handshake_types"] == [
        "server_hello",
        "certificate",
        "certificate_request",
        "server_hello_done",
    ]
    assert parsed["selected_version"] == "TLSv1.2"
    assert parsed["alert"]["name"] == "unknown_ca"
    assert parsed["alert"]["certificate_related"] is True


def test_a_flight_without_a_certificate_request_says_so() -> None:
    parsed = wire.parse_tls_server_flight(_flight(request=False))
    assert parsed["certificate_request"] is False
    assert parsed["alert"] is None


def test_an_alert_before_the_flight_completes_is_undetermined() -> None:
    parsed = wire.parse_tls_server_flight(_record(0x15, b"\x02\x46"))
    assert parsed["certificate_request"] is None
    assert parsed["alert"]["name"] == "protocol_version"


def test_a_non_tls_answer_is_undetermined_not_an_error() -> None:
    parsed = wire.parse_tls_server_flight(b"HTTP/1.1 400 Bad Request\r\n\r\n")
    assert parsed["certificate_request"] is None
    assert parsed["handshake_types"] == []


def test_a_truncated_record_is_tolerated() -> None:
    flight = _flight(request=True)
    parsed = wire.parse_tls_server_flight(flight[: len(flight) // 2])
    assert parsed["certificate_request"] is None


def test_the_client_certificate_message_is_well_formed() -> None:
    der = mtls_cert.certificate_der()
    message = wire.tls_client_certificate(der)
    assert message[0] == 0x16, "a handshake record"
    body = message[5:]
    assert body[0] == 0x0B, "a Certificate message"
    assert int.from_bytes(body[1:4], "big") == len(der) + 6
    assert int.from_bytes(body[4:7], "big") == len(der) + 3
    assert int.from_bytes(body[7:10], "big") == len(der)
    assert body[10:] == der


def test_the_capped_hello_offers_only_tls12() -> None:
    # A fixed ClientHello random: the random is 32 unpredictable bytes and would otherwise
    # make a byte-scan assertion flaky.
    fixed = b"\x00" * 32
    capped = wire.tls_client_hello(include_tls13=False, random=fixed)
    modern = wire.tls_client_hello(include_tls13=True, random=fixed)
    assert struct.pack(">H", 0x0304) in modern
    assert struct.pack(">H", 0x0304) not in capped
    # Both remain well-formed ClientHellos whose declared lengths match their bodies.
    for hello in (capped, modern):
        assert hello[0] == 0x16 and hello[5] == 0x01
        assert int.from_bytes(hello[3:5], "big") == len(hello) - 5
        assert int.from_bytes(hello[6:9], "big") == len(hello) - 9


# --------------------------------------------------------------------------- the decision
async def _results(routes: dict[tuple[str, str, int], object], port: int = 443):
    harness = make_m2_harness(seed_services=((port, "tls"),))
    for (protocol, host, route_port), value in routes.items():
        harness.transport.routes[(protocol, host, route_port)] = value
    check = MutualTlsAuth()
    return [result async for result in check.run(harness.context(MutualTlsAuth))], harness


HOST = "93.184.216.34"
PORT = 443


@pytest.mark.asyncio
async def test_requests_but_does_not_require_produces_the_finding() -> None:
    results, _ = await _results(
        {
            ("tls", HOST, PORT): TlsExchange(
                ok=True, version="TLSv1.2", cipher="ECDHE", cipher_bits=128
            ),
            ("tcp", HOST, PORT): TcpExchange(
                state="open", chunks=(_flight(request=True, alert=48),)
            ),
        }
    )
    statuses = [result.status for result in results]
    assert statuses == ["info", "vulnerable"]
    finding = results[1]
    assert "does not require them" in finding.title
    assert finding.cwe == "CWE-295"


@pytest.mark.asyncio
async def test_a_required_certificate_produces_no_finding() -> None:
    results, _ = await _results(
        {
            ("tls", HOST, PORT): TlsExchange(ok=False, error="SSLV3_ALERT_HANDSHAKE_FAILURE"),
            ("tcp", HOST, PORT): TcpExchange(
                state="open", chunks=(_flight(request=True, alert=48),)
            ),
        }
    )
    assert [result.status for result in results] == ["info", "not_vulnerable"]
    assert "requires a client certificate" in results[1].title


@pytest.mark.asyncio
async def test_a_server_that_never_asks_produces_no_finding() -> None:
    results, _ = await _results(
        {
            ("tls", HOST, PORT): TlsExchange(ok=True, version="TLSv1.2"),
            ("tcp", HOST, PORT): TcpExchange(state="open", chunks=(_flight(request=False),)),
        }
    )
    assert [result.status for result in results] == ["info", "not_vulnerable"]
    assert "does not request client certificates" in results[1].title


@pytest.mark.asyncio
async def test_an_unreadable_flight_is_recorded_as_undetermined() -> None:
    results, _ = await _results(
        {
            ("tls", HOST, PORT): TlsExchange(ok=True, version="TLSv1.3"),
            ("tcp", HOST, PORT): TcpExchange(state="open", chunks=(_record(0x15, b"\x02\x46"),)),
        }
    )
    assert [result.status for result in results] == ["info", "not_vulnerable"]
    assert "undetermined" in results[1].title
    assert results[0].evidence, "the three observations are recorded even when undetermined"


@pytest.mark.asyncio
async def test_the_evidence_records_all_three_observations() -> None:
    results, _ = await _results(
        {
            ("tls", HOST, PORT): TlsExchange(ok=True, version="TLSv1.2"),
            ("tcp", HOST, PORT): TcpExchange(
                state="open", chunks=(_flight(request=True, alert=48),)
            ),
        }
    )
    payload = results[0].evidence[0].payload
    facts = payload["facts"]
    assert set(facts) >= {
        "no_certificate_handshake",
        "certificate_request",
        "invalid_certificate_alert",
    }
    assert facts["no_certificate_handshake"]["ok"] is True
    assert facts["certificate_request"] is True
    assert facts["invalid_certificate_alert"]["name"] == "unknown_ca"
    certificate = facts["throwaway_certificate"]
    assert certificate["self_signed"] is True
    assert certificate["subject"]["commonName"] == "arachne-mtls-probe.invalid"
    assert (
        certificate["sha256_prefix"] == hashlib.sha256(mtls_cert.certificate_der()).hexdigest()[:16]
    )


@pytest.mark.asyncio
async def test_no_tls_service_is_a_skip_not_a_failure() -> None:
    harness = make_m2_harness(seed_services=((22, "ssh"),))
    check = MutualTlsAuth()
    results = [result async for result in check.run(harness.context(MutualTlsAuth))]
    assert len(results) == 1
    assert results[0].status == "info"
    assert "no TLS service" in (results[0].detail or "")
