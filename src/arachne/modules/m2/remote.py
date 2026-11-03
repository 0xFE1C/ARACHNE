"""Remote-access service checks: SSH, SMTP and RDP/VNC (research ch02#20, #24, #25).

These three checks all answer "what does this reachable service give away before anyone
authenticates?" — which is precisely the question the M2 safety framing is
about: they establish *existence* (a version, a supported algorithm, a valid mailbox, a
passwordless remote desktop) and stop there. Nothing here submits a credential, and nothing
here attempts an authentication beyond what the protocol itself answers to an anonymous
peer.

* ``m2.ssh-enum`` reads the banner and the server's KEXINIT algorithm lists. It cannot learn
  the enabled authentication methods without completing a key exchange (which would mean
  implementing SSH cryptography, and would be a client, not a scanner); what it *can* learn
  — a version mapped to CVEs, and whether the endpoint still offers the deprecated
  ``ssh-rsa``/SHA-1 and ``diffie-hellman-group1-sha1`` algorithms — is reported instead.
* ``m2.smtp-enum`` speaks VRFY/EXPN/RCPT. Those verbs are exactly what research ch02#20
  describes, and the check's lockout discipline (bounded wordlist, paced, verbs preferred
  over RCPT) is what keeps it defensible.
* ``m2.rdp-vnc-detect`` reads the X.224 negotiation and the RFB security-type list, which is
  how "RDP without NLA" and "VNC with no authentication at all" are established.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator, Sequence
from typing import Any

from arachne.core.results import CheckResult, Evidence
from arachne.core.target import TargetKind
from arachne.modules.base import CheckMetadata, Module
from arachne.modules.context import CheckContext
from arachne.modules.m2 import wire
from arachne.modules.m2.inventory import ServiceIdentity, ServiceRecord
from arachne.modules.m2.support import (
    NetworkCheck,
    inventory_or_skip,
    load_wordlist,
    net_or_skip,
    port_catalog_for,
    services_of,
    target_kinds_for_network_probes,
)

__all__ = ["RdpVncDetect", "SmtpEnum", "SshEnum"]

_NETWORK_KINDS = (*target_kinds_for_network_probes(), TargetKind.URL)

#: SSH algorithms whose presence is a finding in itself (research ch02#24).
WEAK_SSH_ALGORITHMS: dict[str, tuple[str, str]] = {
    "diffie-hellman-group1-sha1": ("CWE-327", "1024-bit Oakley group 1 DH with SHA-1 KEX"),
    "diffie-hellman-group14-sha1": ("CWE-327", "SHA-1 key exchange"),
    "diffie-hellman-group-exchange-sha1": ("CWE-327", "SHA-1 key exchange"),
    "ssh-dss": ("CWE-327", "1024-bit DSA host key (disabled by default since OpenSSH 7.0)"),
    "ssh-rsa": ("CWE-327", "SHA-1 RSA signature (disabled by default since OpenSSH 8.8)"),
    "ssh-rsa-cert-v01@openssh.com": ("CWE-327", "SHA-1 RSA certificate signature"),
    "arcfour": ("CWE-327", "RC4 stream cipher"),
    "arcfour128": ("CWE-327", "RC4 stream cipher"),
    "arcfour256": ("CWE-327", "RC4 stream cipher"),
    "3des-cbc": ("CWE-327", "64-bit block cipher (SWEET32)"),
    "blowfish-cbc": ("CWE-327", "64-bit block cipher"),
    "cast128-cbc": ("CWE-327", "64-bit block cipher"),
    "hmac-md5": ("CWE-327", "MD5-based MAC"),
    "hmac-md5-96": ("CWE-327", "MD5-based MAC"),
    "hmac-sha1-96": ("CWE-327", "truncated SHA-1 MAC"),
    "hmac-ripemd160": ("CWE-327", "RIPEMD-160 MAC"),
    "none": ("CWE-311", "no encryption at all"),
    "zlib@openssh.com": ("CWE-311", "compression before authentication (CRIME-style)"),
}

#: Lockout discipline for SMTP recipient probing (research ch02#20): a short list, paced by
#: ``ModuleConfig.smtp_pacing_s`` so a deployment can match the mail server's own policy.
SMTP_MAX_RECIPIENTS = 10


class SshEnum(NetworkCheck, Module):
    """``m2.ssh-enum`` — SSH version and algorithm enumeration (research ch02#24)."""

    metadata = CheckMetadata(
        id="m2.ssh-enum",
        module="M2",
        name="ssh-enum",
        version="1.0",
        title="SSH enumeration",
        description=(
            "Reads the SSH banner for the daemon's product and version, then exchanges a "
            "KEXINIT to enumerate the key-exchange, host-key, cipher and MAC algorithms the "
            "server offers. Reports deprecated algorithms (ssh-rsa/SHA-1, group1-sha1, RC4, "
            "3DES) as findings and feeds the version to the CVE correlation."
        ),
        research_ref="ch02#24",
        framework=("WSTG-CONF-01",),
        target_kinds=_NETWORK_KINDS,
        severity_hint="medium",
        type="active",
        safe=True,
        verifiable=True,
        estimated_requests=2,
        requires_active_checks=True,
        runs_on_discovered=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        client, skip = net_or_skip(ctx)
        if skip is not None:
            yield skip
            return
        assert client is not None
        inventory, skip = inventory_or_skip(ctx)
        if skip is not None:
            yield skip
            return
        assert inventory is not None

        catalog = port_catalog_for(ctx)
        services = _services_for(ctx, ("ssh",), catalog.ports_for_probe("ssh"))
        if not services:
            yield ctx.skipped(
                f"no SSH service recorded for asset {ctx.asset.key} "
                "(m2.port-scan and m2.service-fingerprint establish them first)"
            )
            return

        for service in services:
            exchange = await client.tcp(service.host, service.port)
            service.probes += 1
            parsed = (
                wire.parse_ssh_banner(exchange.banner_text(limit=4096))
                if exchange.is_open
                else None
            )
            notes: dict[str, Any] = {}
            if parsed is not None:
                notes["banner"] = parsed["banner"]
                notes["software"] = parsed["software"]
                notes["comment"] = parsed["comment"]
                _apply_identity(
                    service,
                    product=str(parsed["product"]).lower() or None,
                    version=parsed["version"],
                    banner=str(parsed["banner"]),
                )

            algorithms: dict[str, tuple[str, ...]] = {}
            if exchange.is_open and parsed is not None:
                kex = await client.tcp(
                    service.host,
                    service.port,
                    payload=wire.ssh_kexinit_probe(),
                    reads=1,
                )
                service.probes += 1
                parsed_kex = wire.parse_ssh_kexinit(kex.banner)
                if parsed_kex:
                    algorithms = {key: tuple(value) for key, value in parsed_kex.items()}
                    service.notes["ssh_algorithms"] = {
                        key: list(value) for key, value in algorithms.items()
                    }

            if not algorithms and parsed is None:
                yield ctx.clean(
                    f"no SSH banner or KEXINIT from {service.key}",
                    detail="The port accepted a connection but did not speak SSH.",
                    evidence=[_port_evidence(ctx, service, exchange.banner_text(limit=512))],
                    confidence=0.4,
                )
                continue

            weak = sorted(
                {
                    algorithm
                    for values in algorithms.values()
                    for algorithm in values
                    if algorithm in WEAK_SSH_ALGORITHMS
                }
            )
            evidence = [
                ctx.evidence(
                    "banner",
                    {
                        "host": service.host,
                        "port": service.port,
                        "banner": notes.get("banner"),
                        "software": notes.get("software"),
                        "version": notes.get("version"),
                        "algorithms": {key: list(value) for key, value in algorithms.items()},
                    },
                    source=service.key,
                )
            ]
            if parsed is None:
                yield ctx.info(
                    f"SSH service on {service.key} did not send a parseable banner",
                    detail="The KEXINIT exchange answered, so the port is SSH-like.",
                    evidence=evidence,
                    confidence=0.5,
                )
            else:
                yield ctx.info(
                    f"SSH {parsed['software']} on {service.key}",
                    detail=(
                        f"protocol SSH-{parsed['protocol']}; "
                        f"comment {parsed['comment'] or 'none'}; "
                        f"{len(algorithms.get('kex_algorithms', ()))} KEX / "
                        f"{len(algorithms.get('encryption_c2s', ()))} cipher / "
                        f"{len(algorithms.get('mac_c2s', ()))} MAC algorithm(s) offered; "
                        "authentication methods are not enumerated (that needs a completed key "
                        "exchange — see the check docstring)"
                    ),
                    evidence=evidence,
                    confidence=0.9,
                )
            if weak:
                yield ctx.candidate(
                    f"SSH on {service.key} offers {len(weak)} deprecated algorithm(s)",
                    detail=(
                        "The server's KEXINIT still advertises: "
                        + "; ".join(f"{name} ({WEAK_SSH_ALGORITHMS[name][1]})" for name in weak)
                    ),
                    confidence=0.85,
                    evidence=[
                        *evidence,
                        ctx.evidence(
                            "artifact",
                            {"weak_algorithms": weak},
                            source=service.key,
                        ),
                    ],
                )


class SmtpEnum(NetworkCheck, Module):
    """``m2.smtp-enum`` — SMTP verb and recipient enumeration (research ch02#20)."""

    metadata = CheckMetadata(
        id="m2.smtp-enum",
        module="M2",
        name="smtp-enum",
        version="1.0",
        title="SMTP enumeration",
        description=(
            "Speaks EHLO to read the mail server's capabilities, then uses VRFY/EXPN (or a "
            "paced MAIL FROM/RCPT TO exchange when the verbs are disabled) against a small "
            "wordlist to establish which mailboxes exist. Bounded and paced: enumeration of "
            "existence, never a delivery or an authentication attempt."
        ),
        research_ref="ch02#20",
        framework=("WSTG-CONF-01",),
        target_kinds=_NETWORK_KINDS,
        severity_hint="medium",
        type="active",
        safe=True,
        verifiable=True,
        estimated_requests=6,
        requires_active_checks=True,
        runs_on_discovered=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        client, skip = net_or_skip(ctx)
        if skip is not None:
            yield skip
            return
        assert client is not None
        inventory, skip = inventory_or_skip(ctx)
        if skip is not None:
            yield skip
            return
        assert inventory is not None

        catalog = port_catalog_for(ctx)
        smtp_ports = (25, 465, 587, 2525, *catalog.ports_for_probe("smtp"))
        services = _services_for(ctx, ("smtp",), smtp_ports)
        if not services:
            yield ctx.skipped(
                f"no SMTP service recorded for asset {ctx.asset.key} "
                "(m2.port-scan and m2.service-fingerprint establish them first)"
            )
            return

        domain = _domain_hint(ctx, ctx.asset.value)
        for service in services:
            greeting = await client.tcp(service.host, service.port)
            service.probes += 1
            banner = greeting.banner_text(limit=1024).strip()
            if not greeting.is_open or not banner.startswith("220"):
                yield ctx.clean(
                    f"no SMTP greeting from {service.key}",
                    detail=f"The port answered {greeting.state!r} without a 220 greeting.",
                    evidence=[_port_evidence(ctx, service, banner[:256])],
                    confidence=0.4,
                )
                continue

            capabilities = await _smtp_ehlo(client, service, domain)
            service.probes += 1
            verbs = {name for name, _ in capabilities}
            product, version = _smtp_product(banner)
            _apply_identity(service, product=product, version=version, banner=banner)
            service.notes["smtp_capabilities"] = sorted(verbs)

            supported = sorted(verb for verb in verbs if verb in {"VRFY", "EXPN", "RCPT"})
            found: dict[str, list[str]] = {}
            if "VRFY" in verbs or "EXPN" in verbs:
                found = await _smtp_verb_probe(ctx, client, service, domain, verbs)
            elif "RCPT" in verbs or not verbs:
                found = await _smtp_rcpt_probe(ctx, client, service, domain)

            evidence = [
                ctx.evidence(
                    "banner",
                    {
                        "host": service.host,
                        "port": service.port,
                        "greeting": banner,
                        "product": product,
                        "version": version,
                        "capabilities": sorted(verbs),
                        "verb_responses": found,
                        "domain_probed": domain,
                    },
                    source=service.key,
                )
            ]
            yield ctx.info(
                f"SMTP on {service.key}: {product or 'unknown MTA'}",
                detail=(
                    f"greeting {banner[:80]!r}; {len(verbs)} EHLO capabilit(ies) "
                    f"({', '.join(sorted(verbs)[:8]) or 'none'}); "
                    f"enumeration verbs offered: {', '.join(supported) or 'none'}"
                ),
                evidence=evidence,
                confidence=0.9,
            )
            if found:
                yield ctx.candidate(
                    f"SMTP enumeration disclosed {len(found)} confirmed recipient(s) "
                    f"on {service.key}",
                    detail="; ".join(
                        f"{address} via {'/'.join(verbs_used)}"
                        for address, verbs_used in found.items()
                    ),
                    confidence=0.8,
                    evidence=evidence,
                )
            elif supported:
                yield ctx.candidate(
                    f"SMTP user enumeration is enabled on {service.key} ({', '.join(supported)})",
                    detail=(
                        "The server answers VRFY/EXPN, which lets an attacker confirm mailbox "
                        "existence. No recipient in the shipped wordlist was confirmed, so this "
                        "is a capability finding rather than a disclosure."
                    ),
                    confidence=0.7,
                    evidence=evidence,
                )


#: RFC 2606 reserved domains for the relay probe. ``.invalid`` is guaranteed never to resolve,
#: so neither the envelope sender nor the recipient can be delivered anywhere even if a server
#: ignored the protocol. The recipient is *syntactically valid* (a real local-part at a real
#: domain syntax) and non-deliverable by construction, which is what makes the probe a test of
#: the relay policy rather than a test of DNS.
RELAY_SENDER_DOMAIN = "relay-sender.invalid"
RELAY_RECIPIENT = "postmaster@relay-probe.invalid"

#: The reply code a mail server sends when it refuses a command until STARTTLS is negotiated.
STARTTLS_REQUIRED_CODE = "530"

#: Hosts that speak TLS from the first byte (implicit TLS, RFC 8314): STARTTLS is meaningless
#: there, and a plaintext EHLO would never get a greeting at all.
IMPLICIT_TLS_SMTP_PORTS: frozenset[int] = frozenset({465})


class SmtpTransport(NetworkCheck, Module):
    """``m2.smtp-transport`` — STARTTLS enforcement, AUTH mechanisms and relay posture.

    Four observations, each read-only:

    1. **STARTTLS offered** — the EHLO capability list.
    2. **STARTTLS required** — a plaintext ``MAIL FROM`` answered ``530`` (refuse until TLS)
       versus ``250`` (accept plaintext mail submission).
    3. **AUTH mechanisms** — the ``AUTH`` capability line(s), reported as offered. A server
       that advertises AUTH on a plaintext session is offering to receive credentials in the
       clear.
    4. **Relay posture** — an envelope-only probe: ``MAIL FROM`` and ``RCPT TO`` for a
       non-deliverable recipient under a reserved domain, then ``RSET`` and ``QUIT``.
       **No ``DATA`` is ever issued and no body is ever sent**, so nothing can be queued or
       delivered; a server that answers ``250`` to both is relaying for an external sender to
       an external recipient.

    The relay probe runs only when the scan's attestation authorizes active checks
    (``active_checks_authorized``). The check as a whole is withheld without the opt-in, so
    this is the second of the two locks, not the first.
    """

    metadata = CheckMetadata(
        id="m2.smtp-transport",
        module="M2",
        name="smtp-transport",
        version="1.0",
        title="SMTP transport security and relay posture",
        description=(
            "Establishes whether SMTP STARTTLS is offered and required, which AUTH mechanisms "
            "the server advertises before any encryption, and whether it relays mail for an "
            "external sender to an external recipient. The relay probe sends an envelope only "
            "- a MAIL FROM and an RCPT TO for a non-deliverable reserved-domain recipient, "
            "then RSET and QUIT - and never issues DATA or a message body."
        ),
        research_ref="ch02#20",
        framework=("WSTG-CONF-01", "CWE-319", "CWE-441"),
        cwe="CWE-319",
        target_kinds=_NETWORK_KINDS,
        severity_hint="high",
        type="active",
        safe=True,
        verifiable=True,
        estimated_requests=4,
        requires_active_checks=True,
        runs_on_discovered=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        client, skip = net_or_skip(ctx)
        if skip is not None:
            yield skip
            return
        assert client is not None
        inventory, skip = inventory_or_skip(ctx)
        if skip is not None:
            yield skip
            return
        assert inventory is not None

        catalog = port_catalog_for(ctx)
        smtp_ports = (25, 587, 2525, *catalog.ports_for_probe("smtp"))
        services = tuple(
            service
            for service in _services_for(ctx, ("smtp",), smtp_ports)
            if not _is_implicit_tls(service)
        )
        if not services:
            yield ctx.skipped(
                f"no plaintext SMTP service recorded for asset {ctx.asset.key} "
                "(m2.port-scan and m2.service-fingerprint establish them first; implicit-TLS "
                "ports are excluded because STARTTLS does not apply to them)"
            )
            return

        domain = _domain_hint(ctx, ctx.asset.value)
        active = _relay_probe_authorized(ctx)
        for service in services:
            async for result in self._observe(ctx, client, service, domain, active=active):
                yield result

    # ------------------------------------------------------------------ the observation
    async def _observe(
        self,
        ctx: CheckContext,
        client: Any,
        service: ServiceRecord,
        domain: str,
        *,
        active: bool,
    ) -> AsyncIterator[CheckResult]:
        greeting = await client.tcp(service.host, service.port)
        service.probes += 1
        banner = greeting.banner_text(limit=1024).strip()
        if not greeting.is_open or not banner.startswith("220"):
            yield ctx.clean(
                f"no SMTP greeting from {service.key}",
                detail=f"The port answered {greeting.state!r} without a 220 greeting.",
                evidence=[_port_evidence(ctx, service, banner[:256])],
                confidence=0.4,
            )
            return

        capabilities = await _smtp_ehlo(client, service, domain)
        service.probes += 1
        verbs = {name for name, _ in capabilities}
        mechanisms = _smtp_auth_mechanisms(capabilities)
        starttls_offered = "STARTTLS" in verbs

        # Is it required? Ask the plaintext session to submit a message envelope. A server that
        # refuses until TLS answers 530; one that accepts answers 250. Either answer costs one
        # exchange and neither can deliver anything (no RCPT, no DATA, followed by RSET/QUIT).
        plaintext = await client.tcp(
            service.host,
            service.port,
            payload=(f"MAIL FROM:<probe@{RELAY_SENDER_DOMAIN}>\r\nRSET\r\nQUIT\r\n").encode(),
            reads=4,
        )
        service.probes += 1
        plaintext_replies = _smtp_replies(plaintext.banner_text(limit=4096))
        mail_code = plaintext_replies[1] if len(plaintext_replies) > 1 else ""
        starttls_required = starttls_offered and mail_code == STARTTLS_REQUIRED_CODE
        plaintext_accepted = mail_code.startswith("2")

        relay: dict[str, Any] = {"attempted": False}
        if active:
            relay = await self._relay_probe(ctx, client, service, domain)
            service.probes += 1

        _apply_identity(
            service,
            product=_smtp_product(banner)[0],
            version=_smtp_product(banner)[1],
            banner=banner,
        )
        facts = {
            "host": service.host,
            "port": service.port,
            "greeting": banner[:160],
            "starttls_offered": starttls_offered,
            "starttls_required": starttls_required,
            "plaintext_mail_code": mail_code,
            "plaintext_submission_accepted": plaintext_accepted,
            "auth_mechanisms": list(mechanisms),
            "relay": relay,
            "probe_domains": {
                "sender": RELAY_SENDER_DOMAIN,
                "recipient": RELAY_RECIPIENT,
                "reserved": True,
                "body_sent": False,
                "data_issued": False,
            },
        }
        evidence = [ctx.evidence("banner", facts, source=service.key)]
        yield ctx.info(
            f"SMTP transport posture for {service.key}",
            detail=(
                f"STARTTLS {'offered' if starttls_offered else 'not offered'}"
                + (" and required" if starttls_required else "")
                + f"; plaintext MAIL FROM answered {mail_code or 'nothing'}; "
                f"{len(mechanisms)} AUTH mechanism(s) advertised "
                f"({', '.join(mechanisms) or 'none'}); "
                + (
                    f"relay probe: RCPT answered {relay.get('rcpt_code', 'nothing')}"
                    if active
                    else "relay probe withheld (active checks are not authorized)"
                )
            ),
            evidence=evidence,
            confidence=0.9,
        )

        if not starttls_offered:
            yield ctx.candidate(
                f"SMTP service on {service.host}:{service.port} does not offer STARTTLS",
                detail=(
                    "The EHLO capability list carries no STARTTLS extension, so every "
                    "submission and every recipient on this connection — including any "
                    "credential — travels in the clear (CWE-319). A mail server that accepts "
                    "plaintext submission is readable on any path between the client and it."
                ),
                confidence=0.75,
                evidence=evidence,
            )
        elif not starttls_required and plaintext_accepted and mechanisms:
            yield ctx.candidate(
                f"SMTP service on {service.host}:{service.port} advertises STARTTLS but "
                "accepts authentication in the clear",
                detail=(
                    "The server offers STARTTLS and still advertises "
                    f"{', '.join(mechanisms)} on the plaintext session, and it accepted a "
                    f"plaintext MAIL FROM ({mail_code}). A client that authenticates before "
                    "upgrading — which the advertisement invites — sends its credential in the "
                    "clear, so the transport security the server offers is optional in "
                    "practice (CWE-319). Requiring it means refusing AUTH and MAIL until "
                    "STARTTLS has completed (Postfix 'smtpd_tls_auth_only = yes' plus "
                    "'smtpd_tls_security_level = encrypt')."
                ),
                confidence=0.8,
                evidence=evidence,
            )

        if relay.get("open"):
            yield ctx.candidate(
                f"SMTP service on {service.host}:{service.port} accepts unauthenticated relay",
                detail=(
                    "The server accepted MAIL FROM "
                    f"<probe@{RELAY_SENDER_DOMAIN}> and RCPT TO <{RELAY_RECIPIENT}> — an "
                    "external sender naming an external recipient — without authentication. "
                    "That is an open relay: it can be used to send mail to arbitrary "
                    "third parties, laundering the operator's reputation and address space "
                    "(CWE-441). The probe sent an envelope only: no DATA was issued and no "
                    "message body exists, so nothing was queued or delivered."
                ),
                confidence=0.85,
                evidence=evidence,
            )
        elif active and relay.get("rcpt_code"):
            yield ctx.clean(
                f"SMTP service on {service.key} does not relay for an external sender",
                detail=(
                    f"The relay probe was refused at RCPT with {relay['rcpt_code']}, so the "
                    "server enforces a relay policy. No message body was sent and no delivery "
                    "was attempted."
                ),
                evidence=evidence,
                confidence=0.8,
            )

    async def _relay_probe(
        self, ctx: CheckContext, client: Any, service: ServiceRecord, domain: str
    ) -> dict[str, Any]:
        """Envelope only: EHLO, MAIL FROM, RCPT TO, RSET, QUIT. Never DATA."""
        payload = (
            f"EHLO arachne-scan.{domain}\r\n"
            f"MAIL FROM:<probe@{RELAY_SENDER_DOMAIN}>\r\n"
            f"RCPT TO:<{RELAY_RECIPIENT}>\r\n"
            "RSET\r\n"
            "QUIT\r\n"
        ).encode()
        exchange = await client.tcp(service.host, service.port, payload=payload, reads=8)
        replies = _smtp_replies(exchange.banner_text(limit=8192))
        # [0] greeting, [1] EHLO, [2] MAIL FROM, [3] RCPT TO, [4] RSET, [5] QUIT
        mail_code = replies[2] if len(replies) > 2 else ""
        rcpt_code = replies[3] if len(replies) > 3 else ""
        open_relay = mail_code.startswith("2") and rcpt_code in {"250", "251"}
        return {
            "attempted": True,
            "mail_code": mail_code,
            "rcpt_code": rcpt_code,
            "rset_code": replies[4] if len(replies) > 4 else "",
            "quit_code": replies[5] if len(replies) > 5 else "",
            "open": open_relay,
            "data_issued": False,
            "body_sent": False,
            "recipient": RELAY_RECIPIENT,
            "sender": f"probe@{RELAY_SENDER_DOMAIN}",
        }


def _relay_probe_authorized(ctx: CheckContext) -> bool:
    """True when the scan's opt-in *and* its attestation authorize active checks.

    Both locks are consulted even though the planner already withholds this check without
    them: ``active_checks`` is the operator's request, the attestation is the authorization
    (INV-4), and a relay probe is the closest this product comes to sending mail.
    """
    attestation = getattr(ctx.definition, "attestation", None)
    authorized = bool(getattr(attestation, "active_checks_authorized", False))
    return bool(ctx.options.active_checks) and authorized


def _is_implicit_tls(service: ServiceRecord) -> bool:
    """True for a service that speaks TLS from the first byte (STARTTLS cannot apply)."""
    return service.port in IMPLICIT_TLS_SMTP_PORTS or service.effective_service.lower() == "smtps"


def _smtp_auth_mechanisms(capabilities: Sequence[tuple[str, str]]) -> tuple[str, ...]:
    """Every mechanism named on an ``AUTH`` capability line, de-duplicated and ordered."""
    mechanisms: list[str] = []
    for verb, argument in capabilities:
        if verb != "AUTH":
            continue
        mechanisms.extend(token.upper() for token in argument.replace("=", " ").split() if token)
    return tuple(dict.fromkeys(mechanisms))


def _smtp_replies(text: str) -> list[str]:
    """The final code of each SMTP reply, in order, with multi-line replies collapsed.

    An SMTP reply is one or more lines; continuation lines carry ``code-`` and the last line
    carries ``code `` (or just the code). Recording only the terminal code is what makes
    "[0] greeting, [1] EHLO, [2] MAIL FROM, ..." a reliable index even when the EHLO block is
    five lines long.
    """
    replies: list[str] = []
    for raw in text.replace("\r\n", "\n").splitlines():
        line = raw.strip()
        if len(line) < 3 or not line[:3].isdigit():
            continue
        if len(line) > 3 and line[3] == "-":
            continue  # a continuation line: the reply is not finished
        replies.append(line[:3])
    return replies


class RdpVncDetect(NetworkCheck, Module):
    """``m2.rdp-vnc-detect`` — RDP/VNC presence and authentication posture (ch02#25)."""

    metadata = CheckMetadata(
        id="m2.rdp-vnc-detect",
        module="M2",
        name="rdp-vnc-detect",
        version="1.0",
        title="RDP/VNC detection",
        description=(
            "Negotiates X.224 with RDP services to see whether NLA (CredSSP) is required, and "
            "reads the RFB security-type list from VNC services to see whether authentication "
            "is required at all. A passwordless VNC server and an RDP service without NLA are "
            "reported as findings; no credential is ever submitted."
        ),
        research_ref="ch02#25",
        framework=("WSTG-CONF-01",),
        target_kinds=_NETWORK_KINDS,
        severity_hint="high",
        type="active",
        safe=True,
        verifiable=True,
        estimated_requests=2,
        requires_active_checks=True,
        runs_on_discovered=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        client, skip = net_or_skip(ctx)
        if skip is not None:
            yield skip
            return
        assert client is not None
        inventory, skip = inventory_or_skip(ctx)
        if skip is not None:
            yield skip
            return
        assert inventory is not None

        catalog = port_catalog_for(ctx)
        rdp_services = _services_for(ctx, ("rdp",), (3389, *catalog.ports_for_probe("rdp")))
        vnc_services = _services_for(
            ctx, ("vnc",), (*catalog.ports_for_probe("vnc"), 5900, 5901, 5902, 5903)
        )
        if not rdp_services and not vnc_services:
            yield ctx.skipped(
                f"no RDP or VNC service recorded for asset {ctx.asset.key} "
                "(m2.port-scan and m2.service-fingerprint establish them first)"
            )
            return

        for service in rdp_services:
            async for result in self._rdp(ctx, client, service):
                yield result
        for service in vnc_services:
            async for result in self._vnc(ctx, client, service):
                yield result

    async def _rdp(
        self, ctx: CheckContext, client: Any, service: ServiceRecord
    ) -> AsyncIterator[CheckResult]:
        exchange = await client.tcp(
            service.host, service.port, payload=wire.rdp_negociation_request(), reads=1
        )
        service.probes += 1
        negotiation = wire.parse_x224_negociation(exchange.banner)
        if negotiation is None:
            yield ctx.clean(
                f"no RDP negotiation response from {service.key}",
                detail="The port answered, but not with an X.224 negotiation.",
                evidence=[_port_evidence(ctx, service, exchange.banner_text(limit=256))],
                confidence=0.4,
            )
            return
        service.notes["rdp"] = {
            "selected_protocol": negotiation.selected,
            "selected_name": negotiation.selected_name,
            "nla_required": negotiation.nla_required,
            "failure_code": negotiation.failure_code,
        }
        _apply_identity(service, product="rdp", version=None, banner=negotiation.selected_name)
        evidence = [
            ctx.evidence(
                "banner",
                {
                    "host": service.host,
                    "port": service.port,
                    "selected_protocol": negotiation.selected_name,
                    "nla_required": negotiation.nla_required,
                    "failure_code": negotiation.failure_code,
                    "response": exchange.banner_text(limit=256),
                },
                source=service.key,
            )
        ]
        yield ctx.info(
            f"RDP on {service.key} negotiates {negotiation.selected_name}",
            detail=(
                "NLA (CredSSP) is required by this server"
                if negotiation.nla_required
                else "the server accepts a connection without NLA (CredSSP)"
            ),
            evidence=evidence,
            confidence=0.9,
        )
        if not negotiation.nla_required:
            yield ctx.candidate(
                f"RDP on {service.key} does not require network-level authentication",
                detail=(
                    f"The X.224 negotiation selected {negotiation.selected_name}. Without "
                    "CredSSP the endpoint presents its pre-authentication surface to any client, "
                    "which is the posture RDP brute-force and pre-auth vulnerabilities rely on "
                    "(research ch02#25; CVE-2019-0708 class)."
                ),
                confidence=0.85,
                evidence=evidence,
            )

    async def _vnc(
        self, ctx: CheckContext, client: Any, service: ServiceRecord
    ) -> AsyncIterator[CheckResult]:
        banner = await client.tcp(service.host, service.port)
        service.probes += 1
        version = wire.parse_rfb_version(banner.banner_text(limit=256))
        if version is None:
            yield ctx.clean(
                f"no RFB banner from {service.key}",
                detail="The port answered, but not with a VNC protocol banner.",
                evidence=[_port_evidence(ctx, service, banner.banner_text(limit=256))],
                confidence=0.4,
            )
            return
        _apply_identity(
            service,
            product="vnc",
            version=f"{version[0]:03d}.{version[1]:03d}",
            banner=banner.banner_text(limit=64).strip(),
        )
        security_exchange = await client.tcp(
            service.host,
            service.port,
            payload=wire.rfb_client_version(version[0], version[1]),
            reads=2,
        )
        service.probes += 1
        security = wire.parse_rfb_security(
            security_exchange.banner[1:] if len(security_exchange.banner) > 1 else b""
        )
        if security is None:
            security = wire.parse_rfb_security(security_exchange.banner)
        evidence = [
            ctx.evidence(
                "banner",
                {
                    "host": service.host,
                    "port": service.port,
                    "rfb_version": f"{version[0]}.{version[1]}",
                    "security_types": list(security.types) if security else [],
                    "security_names": list(security.describe()) if security else [],
                },
                source=service.key,
            )
        ]
        if security is None:
            yield ctx.clean(
                f"RFB {version[0]}.{version[1]} on {service.key}: security types not offered",
                detail="The server closed the connection instead of listing security types.",
                evidence=evidence,
                confidence=0.5,
            )
            return
        service.notes["vnc"] = {"security_types": list(security.types)}
        yield ctx.info(
            f"VNC {version[0]}.{version[1]} on {service.key}",
            detail=f"security types: {', '.join(security.describe()) or 'none'}",
            evidence=evidence,
            confidence=0.9,
        )
        if security.no_authentication:
            yield ctx.candidate(
                f"VNC on {service.key} offers unauthenticated access",
                detail=(
                    "The RFB security-type list includes 'None' (type 1), so a client can "
                    "connect without any credential — research ch02#25's canonical "
                    "passwordless remote-desktop finding."
                ),
                confidence=0.95,
                evidence=evidence,
            )
        elif security.vnc_authentication:
            yield ctx.candidate(
                f"VNC on {service.key} uses the legacy VNC password scheme",
                detail=(
                    "The server offers only the original RFB authentication (type 2): an 8-byte "
                    "DES-challenge response with no TLS transport, so the password is trivially "
                    "brute-forced offline from one challenge/response pair."
                ),
                confidence=0.6,
                evidence=evidence,
            )


# --------------------------------------------------------------------------- helpers
def _services_for(
    ctx: CheckContext, protocols: Sequence[str], ports: Sequence[int]
) -> tuple[ServiceRecord, ...]:
    """Services for this asset matching a protocol identity or one of ``ports``."""
    wanted_ports = set(ports)
    matches: list[ServiceRecord] = []
    for service in services_of(ctx.inventory, ctx.asset):
        if service.protocol != "tcp":
            continue
        if service.effective_service.lower() in {item.lower() for item in protocols}:
            matches.append(service)
            continue
        if service.port in wanted_ports and service.identity is None:
            matches.append(service)
    return tuple(matches)


def _port_evidence(ctx: CheckContext, service: ServiceRecord, banner: str) -> Evidence:
    return ctx.evidence(
        "banner",
        {"host": service.host, "port": service.port, "response": banner},
        source=service.key,
    )


def _apply_identity(
    service: ServiceRecord,
    *,
    product: str | None,
    version: str | None,
    banner: str,
) -> None:
    """Fill in a versioned identity, without overwriting a version we already trust."""
    current = service.identity
    if current is not None and current.versioned:
        return
    service.identity = ServiceIdentity(
        protocol=current.protocol
        if current and current.protocol != "unknown"
        else service.effective_service,
        product=product or (current.product if current else None),
        version=version or (current.version if current else None),
        banner=banner or (current.banner if current else ""),
        confidence=0.9,
        extra=dict(current.extra) if current else {},
    )


async def _smtp_ehlo(
    client: Any, service: ServiceRecord, domain: str
) -> tuple[tuple[str, str], ...]:
    """EHLO and the capability lines it returns (``(verb, argument)`` pairs)."""
    exchange = await client.tcp(
        service.host,
        service.port,
        payload=f"EHLO arachne-scan.{domain}\r\n".encode(),
        reads=2,
    )
    lines = _smtp_lines(exchange.banner_text(limit=4096))
    capabilities: list[tuple[str, str]] = []
    for line in lines:
        parts = line.split(None, 1)
        if not parts:
            continue
        verb = parts[0].upper()
        if verb in {"250", "220", "EHLO"}:
            continue
        capabilities.append((verb, parts[1] if len(parts) > 1 else ""))
    return tuple(capabilities)


def _smtp_lines(text: str) -> list[str]:
    lines: list[str] = []
    for raw in text.replace("\r\n", "\n").splitlines():
        line = raw.strip()
        if not line:
            continue
        # Continuation markers ("250-") mean "more follows"; a plain "250 " ends the block.
        if len(line) > 4 and line[3] in "- ":
            lines.append(line[4:].strip())
        elif line[:3].isdigit():
            lines.append(line[4:].strip() if len(line) > 4 else line)
        else:
            lines.append(line)
    return [line for line in lines if line]


async def _smtp_verb_probe(
    ctx: CheckContext,
    client: Any,
    service: ServiceRecord,
    domain: str,
    verbs: set[str],
) -> dict[str, list[str]]:
    """VRFY/EXPN a bounded wordlist and record which names the server accepts."""
    found: dict[str, list[str]] = {}
    names = load_wordlist(ctx, "smtp-users")
    for name in names[:SMTP_MAX_RECIPIENTS]:
        address = f"{name}@{domain}"
        for verb in ("VRFY", "EXPN"):
            if verb not in verbs:
                continue
            reply = await client.tcp(
                service.host,
                service.port,
                payload=f"{verb} {address}\r\n".encode(),
                reads=1,
            )
            service.probes += 1
            code = _smtp_code(reply.banner_text(limit=512))
            if code in {"250", "251", "252"}:
                found.setdefault(address, []).append(f"{verb} {code}")
                break
            await asyncio.sleep(ctx.config.smtp_pacing_s)
    return found


async def _smtp_rcpt_probe(
    ctx: CheckContext, client: Any, service: ServiceRecord, domain: str
) -> dict[str, list[str]]:
    """The RCPT fallback: MAIL FROM + RCPT TO, paced, bounded and never completing a delivery."""
    found: dict[str, list[str]] = {}
    names = load_wordlist(ctx, "smtp-users")
    for name in names[:SMTP_MAX_RECIPIENTS]:
        address = f"{name}@{domain}"
        exchange = await client.tcp(
            service.host,
            service.port,
            payload=(
                f"MAIL FROM:<arachne-probe@{domain}>\r\nRCPT TO:<{address}>\r\nRSET\r\nQUIT\r\n"
            ).encode(),
            reads=4,
        )
        service.probes += 1
        text = exchange.banner_text(limit=4096)
        # The RCPT reply is the one that follows the MAIL FROM reply.
        codes = [_smtp_code(line) for line in text.replace("\r\n", "\n").splitlines()]
        if "250" in codes[1:2] or (len(codes) > 1 and codes[1] == "250"):
            found.setdefault(address, []).append("RCPT 250")
        await asyncio.sleep(ctx.config.smtp_pacing_s)
    return found


def _smtp_code(line: str) -> str:
    stripped = line.strip()
    return stripped[:3] if stripped[:3].isdigit() else ""


def _smtp_product(banner: str) -> tuple[str | None, str | None]:
    lowered = banner.lower()
    for needle, product in (
        ("postfix", "postfix"),
        ("sendmail", "sendmail"),
        ("exim", "exim"),
        ("microsoft esmtp", "microsoft exchange"),
        ("exchange", "microsoft exchange"),
        ("zimbra", "zimbra"),
        ("haraka", "haraka"),
        ("vsmtp", "vsmail"),
        ("mailenable", "mailenable"),
        ("opensmtpd", "opensmtpd"),
    ):
        if needle in lowered:
            import re

            match = re.search(rf"{re.escape(needle)}[\s/]?([\d][\w.\-]*)", lowered)
            return product, (match.group(1) if match else None)
    return None, None


def _domain_hint(ctx: CheckContext, value: str) -> str:
    """The domain to address SMTP probes to: the asset's name, else the first declared one."""
    if not _is_address(value):
        return value
    for selector in ctx.definition.targets:
        if selector.kind in {TargetKind.DOMAIN, TargetKind.DOMAIN_PATTERN}:
            return selector.value
    return "example.invalid"


def _is_address(value: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True
