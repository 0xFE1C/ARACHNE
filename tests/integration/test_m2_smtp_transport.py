"""SMTP transport posture against the loopback lab (REQ-DET-012).

Two real mail servers:

* ``smtp-hardened`` — advertises STARTTLS, refuses submission until TLS, offers no AUTH in the
  clear and refuses relay: the decoy must produce no finding.
* ``smtp-open-relay`` — advertises STARTTLS, offers AUTH PLAIN/LOGIN on the plaintext session
  and accepts MAIL FROM/RCPT TO for an external pair: the planted weakness.

The relay probe talks to a fixture that would answer DATA with ``554`` if it were ever issued;
the assertion is that it never is, and that the recipient is the reserved-domain placeholder.
"""

from __future__ import annotations

import pytest
from tests.helpers.depth import make_depth_harness
from tests.lab.arachne_lab import m2_lab

from arachne.core.target import ScanOptions, TargetDefinition, TargetSelector
from arachne.modules.m2.remote import RELAY_RECIPIENT, SmtpTransport

pytestmark = pytest.mark.lab


def _authorized(harness) -> None:  # type: ignore[no-untyped-def]
    """Replace the harness's step with one whose attestation authorizes active checks."""
    host = "127.0.0.1"
    harness.step.definition = TargetDefinition(
        name="wp09-smtp-lab",
        targets=(TargetSelector(kind="ip", value=host),),
        attestation={
            "attested_by": "WP-09 builder <wp09@arachne.test>",
            "attested_at": "2026-10-01T00:00:00Z",
            "scope_statement": "Loopback lab only; active checks are authorized for the probe",
            "allowed_targets": [host],
            "authorization_ref": "TEST-WP09-SMTP-LAB",
            "active_checks_authorized": True,
        },
    )
    harness.step.options = ScanOptions(active_checks=True)


async def _run(lab, name: str) -> tuple[list, object]:  # type: ignore[no-untyped-def]
    port = lab.port(name)
    harness = make_depth_harness(seed_services=((port, "smtp"),))
    _authorized(harness)
    check = SmtpTransport()
    results = [result async for result in check.run(harness.context(SmtpTransport))]
    return results, harness


async def test_the_hardened_server_produces_no_finding() -> None:
    with m2_lab(include_udp=False) as lab:
        results, _ = await _run(lab, "smtp-hardened")
        assert "vulnerable" not in [result.status for result in results]
        facts = results[0].evidence[0].payload
        assert facts["starttls_offered"] is True
        assert facts["starttls_required"] is True
        assert facts["auth_mechanisms"] == []
        assert facts["relay"]["open"] is False
        assert facts["relay"]["rcpt_code"] == "554"


async def test_the_open_relay_server_is_reported() -> None:
    with m2_lab(include_udp=False) as lab:
        results, _ = await _run(lab, "smtp-open-relay")
        findings = [result for result in results if result.status == "vulnerable"]
        titles = " | ".join(finding.title for finding in findings)
        assert "accepts authentication in the clear" in titles
        assert "accepts unauthenticated relay" in titles
        facts = results[0].evidence[0].payload
        assert facts["starttls_offered"] is True
        assert facts["starttls_required"] is False
        assert facts["auth_mechanisms"] == ["PLAIN", "LOGIN"]
        assert facts["relay"]["open"] is True
        assert facts["relay"]["data_issued"] is False
        assert facts["relay"]["body_sent"] is False
        assert facts["relay"]["recipient"] == RELAY_RECIPIENT


async def test_the_relay_probe_is_skipped_without_authorization() -> None:
    """Without an attestation authorizing active checks, the envelope probe never runs."""
    with m2_lab(include_udp=False) as lab:
        port = lab.port("smtp-open-relay")
        harness = make_depth_harness(seed_services=((port, "smtp"),))
        check = SmtpTransport()
        results = [result async for result in check.run(harness.context(SmtpTransport))]
        facts = results[0].evidence[0].payload
        assert facts["relay"]["attempted"] is False
        assert not [r for r in results if "relay" in r.title]


async def test_no_finding_mentions_a_message_body() -> None:
    """The evidence states the two negatives the requirement is built on."""
    with m2_lab(include_udp=False) as lab:
        results, _ = await _run(lab, "smtp-open-relay")
        facts = results[0].evidence[0].payload
        assert facts["probe_domains"] == {
            "sender": "relay-sender.invalid",
            "recipient": RELAY_RECIPIENT,
            "reserved": True,
            "body_sent": False,
            "data_issued": False,
        }
