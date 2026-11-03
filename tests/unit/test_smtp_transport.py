"""SMTP transport security and relay posture (REQ-DET-012).

The four observations are driven through a scripted transport, and the relay probe's *exact
bytes* are captured and asserted: the exit criterion for this requirement is that the probe
sends no message body and never attempts delivery, and the only honest way to check that is
to look at what went on the wire.

The authorization boundary is tested the same way: without an attestation that authorizes
active checks the probe is not attempted at all (``relay["attempted"] is False``), so a scan
that may not take the risk never does.
"""

from __future__ import annotations

from tests.helpers.checks import make_m2_harness

from arachne.core.target import ScanOptions, TargetDefinition, TargetSelector
from arachne.modules.m2.remote import (
    IMPLICIT_TLS_SMTP_PORTS,
    RELAY_RECIPIENT,
    SmtpTransport,
    _is_implicit_tls,
    _smtp_replies,
)

HOST = "93.184.216.34"
PORT = 25

GREETING = b"220 lab.arachne.test ESMTP Postfix 3.4.14\r\n"
EHLO_HARDENED = b"250-lab.arachne.test\r\n250-SIZE 10240000\r\n250-STARTTLS\r\n250 HELP\r\n"
EHLO_OPEN = (
    b"250-lab.arachne.test\r\n250-SIZE 10240000\r\n250-STARTTLS\r\n250-AUTH PLAIN LOGIN\r\n"
    b"250 HELP\r\n"
)
EHLO_NO_STARTTLS = b"250-lab.arachne.test\r\n250-PIPELINING\r\n250 HELP\r\n"
RELAY_DENIED = (
    GREETING
    + b"250-lab.arachne.test\r\n250 STARTTLS\r\n"
    + b"530 5.7.0 Must issue a STARTTLS command first\r\n"
    + b"554 5.7.1 Relay access denied\r\n"
    + b"250 2.0.0 Ok\r\n"
    + b"221 2.0.0 Bye\r\n"
)
RELAY_OPEN = (
    GREETING
    + b"250-lab.arachne.test\r\n250 STARTTLS\r\n"
    + b"250 2.1.0 Ok\r\n"
    + b"250 2.1.5 Ok\r\n"
    + b"250 2.0.0 Ok\r\n"
    + b"221 2.0.0 Bye\r\n"
)


def _definition(*, active: bool) -> TargetDefinition:
    return TargetDefinition(
        name="smtp-transport-test",
        targets=(TargetSelector(kind="ip", value=HOST),),
        attestation={
            "attested_by": "WP-09 builder <wp09@arachne.test>",
            "attested_at": "2026-10-01T00:00:00Z",
            "scope_statement": "Scripted SMTP transport observations; no packet leaves a stub",
            "allowed_targets": [HOST],
            "authorization_ref": "TEST-WP09-SMTP",
            "active_checks_authorized": active,
        },
    )


async def _run(routes: list[object], *, active: bool = True, port: int = PORT):
    harness = make_m2_harness(seed_services=((port, "smtp"),))
    harness.step.definition = _definition(active=active)
    harness.step.options = ScanOptions(active_checks=active)
    harness.transport.routes[("tcp", HOST, port)] = list(routes)
    check = SmtpTransport()
    results = [result async for result in check.run(harness.context(SmtpTransport))]
    return results, harness


# --------------------------------------------------------------------------- STARTTLS / AUTH
async def test_a_hardened_server_produces_no_finding() -> None:
    results, _ = await _run(
        [
            GREETING,
            EHLO_HARDENED,
            GREETING + b"530 5.7.0 Must issue a STARTTLS command first\r\n",
            RELAY_DENIED,
        ]
    )
    assert [result.status for result in results] == ["info", "not_vulnerable"]
    facts = results[0].evidence[0].payload
    assert facts["starttls_offered"] is True
    assert facts["starttls_required"] is True
    assert facts["auth_mechanisms"] == []
    assert facts["relay"]["open"] is False


async def test_starttls_offered_but_plaintext_auth_permitted_is_reported() -> None:
    results, _ = await _run([GREETING, EHLO_OPEN, GREETING + b"250 2.1.0 Ok\r\n", RELAY_OPEN])
    findings = [result for result in results if result.status == "vulnerable"]
    titles = [finding.title for finding in findings]
    assert len(findings) == 2
    assert any("accepts authentication in the clear" in title for title in titles)
    assert any("accepts unauthenticated relay" in title for title in titles)
    facts = results[0].evidence[0].payload
    assert facts["starttls_offered"] is True
    assert facts["starttls_required"] is False
    assert facts["auth_mechanisms"] == ["PLAIN", "LOGIN"]


async def test_a_server_without_starttls_is_reported() -> None:
    results, _ = await _run(
        [GREETING, EHLO_NO_STARTTLS, GREETING + b"250 2.1.0 Ok\r\n", RELAY_OPEN]
    )
    findings = [result for result in results if result.status == "vulnerable"]
    assert any("does not offer STARTTLS" in finding.title for finding in findings)


async def test_required_starttls_is_distinguished_from_offered() -> None:
    required, _ = await _run(
        [
            GREETING,
            EHLO_HARDENED,
            GREETING + b"530 5.7.0 Must issue a STARTTLS command first\r\n",
            RELAY_DENIED,
        ]
    )
    offered, _ = await _run([GREETING, EHLO_OPEN, GREETING + b"250 2.1.0 Ok\r\n", RELAY_OPEN])
    assert required[0].evidence[0].payload["starttls_required"] is True
    assert offered[0].evidence[0].payload["starttls_required"] is False


# --------------------------------------------------------------------------- the relay probe
async def test_the_relay_probe_sends_no_body_and_never_issues_data() -> None:
    """The exit criterion, asserted on the bytes that actually left the process."""
    captured: list[bytes] = []

    def relay(payload: bytes) -> bytes:
        captured.append(payload)
        return RELAY_OPEN

    results, _ = await _run([GREETING, EHLO_OPEN, GREETING + b"250 2.1.0 Ok\r\n", relay])
    assert captured, "the relay probe ran"
    payload = captured[0]
    text = payload.decode()
    assert "DATA" not in text, "the probe must never issue DATA"
    assert "Subject:" not in text and "From:" not in text and "Content-" not in text
    verbs = [line.split(" ", 1)[0].upper() for line in text.split("\r\n") if line]
    assert verbs == ["EHLO", "MAIL", "RCPT", "RSET", "QUIT"]
    assert f"RCPT TO:<{RELAY_RECIPIENT}>" in text
    assert "@relay-probe.invalid" in text and "@relay-sender.invalid" in text
    facts = results[0].evidence[0].payload
    assert facts["probe_domains"]["body_sent"] is False
    assert facts["probe_domains"]["data_issued"] is False
    assert facts["probe_domains"]["reserved"] is True


async def test_the_relay_probe_is_withheld_without_an_active_checks_attestation() -> None:
    results, _ = await _run([GREETING, EHLO_OPEN, GREETING + b"250 2.1.0 Ok\r\n"], active=False)
    facts = results[0].evidence[0].payload
    assert facts["relay"]["attempted"] is False
    assert "relay probe withheld" in results[0].detail
    # The observations that do not need authorization still ran; the relay finding cannot.
    assert not [result for result in results if "relay" in result.title]


async def test_an_operator_opt_in_without_attestation_does_not_authorize_the_probe() -> None:
    """INV-4: both locks. A scan option is a request; the attestation is the authorization."""
    harness = make_m2_harness(seed_services=((PORT, "smtp"),))
    harness.step.definition = _definition(active=False)
    harness.step.options = ScanOptions(active_checks=True)
    harness.transport.routes[("tcp", HOST, PORT)] = [
        GREETING,
        EHLO_OPEN,
        GREETING + b"250 2.1.0 Ok\r\n",
    ]
    results = [result async for result in SmtpTransport().run(harness.context(SmtpTransport))]
    assert results[0].evidence[0].payload["relay"]["attempted"] is False


# --------------------------------------------------------------------------- small helpers
def test_multi_line_replies_collapse_to_one_code() -> None:
    text = "220 hello\r\n250-a\r\n250-b\r\n250 c\r\n550 no\r\n"
    assert _smtp_replies(text) == ["220", "250", "550"]


def test_implicit_tls_ports_are_excluded() -> None:
    from arachne.modules.m2.inventory import ServiceIdentity, ServiceRecord

    smtps = ServiceRecord(host=HOST, port=465, protocol="tcp", service="smtps")
    assert _is_implicit_tls(smtps) is True
    assert 465 in IMPLICIT_TLS_SMTP_PORTS
    submission = ServiceRecord(
        host=HOST,
        port=587,
        protocol="tcp",
        service="smtp",
        identity=ServiceIdentity(protocol="smtp", product="postfix", banner="220"),
    )
    assert _is_implicit_tls(submission) is False


async def test_a_port_that_never_greets_is_not_a_finding() -> None:
    results, _ = await _run([b"HTTP/1.1 400 Bad Request\r\n\r\n"])
    assert results[0].status == "not_vulnerable"
    assert "no SMTP greeting" in results[0].title


async def test_no_smtp_service_is_a_skip() -> None:
    harness = make_m2_harness(seed_services=((22, "ssh"),))
    results = [result async for result in SmtpTransport().run(harness.context(SmtpTransport))]
    assert len(results) == 1
    assert "no plaintext SMTP service" in (results[0].detail or "")
