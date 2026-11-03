"""Mutual-TLS and client-certificate enforcement, observed read-only (REQ-DET-011).

A service can *advertise* client-certificate authentication and not enforce it: it sends a
``CertificateRequest`` in the handshake and then completes the connection with a client that
presented nothing. That is a common and serious misconfiguration — the operator believes
mTLS is the authentication boundary, and it is not — and it is establishable without
completing a single authenticated exchange.

Three observations, one finding shape:

``no-certificate``
    :meth:`ScopedNetClient.tls` performs an ordinary handshake with **no** client
    certificate. Success means the endpoint accepts unauthenticated clients; a
    certificate-shaped failure means it does not.
``certificate-request``
    A TLS 1.2-capped ``ClientHello`` is written through the scoped TCP probe and the
    server's own flight is parsed (:func:`arachne.modules.m2.wire.parse_tls_server_flight`)
    for a ``CertificateRequest``. TLS 1.2 is chosen deliberately: a TLS 1.3 server encrypts
    its whole flight, so the request is not observable, and the probe says ``undetermined``
    rather than guessing.
``invalid-certificate``
    In the same flight the probe offers the throwaway self-signed certificate from
    :mod:`arachne.modules.m2.mtls_cert` and reads what comes back. A fatal certificate
    alert means the server asked for a certificate *and validated it* (the correctly
    configured decoy). No alert means it asked and did not reject what it could not verify.

**The credential rules, because this is the one check that presents one.** The certificate
is generated in process (no dependency, no file, discarded), its subject names no real
principal, and its key is a published throwaway — so it cannot authenticate anywhere. The
check never completes a handshake with it, never sends an application-layer byte, and never
touches a credential belonging to anyone. The private key is never even read by this module:
the certificate is all that is presented.

**Safety.** L1, read-only, active. Every byte goes through
:class:`~arachne.core.net.ScopedNetClient`, so the scope gate, the per-host rate limiter and
the audit trail apply exactly as they do to a port probe; there is no second egress path.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from arachne.core.results import CheckResult, Evidence
from arachne.core.target import TargetKind
from arachne.modules.base import CheckMetadata, Module
from arachne.modules.context import CheckContext
from arachne.modules.m2 import wire
from arachne.modules.m2.inventory import ServiceRecord
from arachne.modules.m2.mtls_cert import (
    THROWAWAY_CERTIFICATE_SUBJECT,
    THROWAWAY_KEY_BITS,
    certificate_der,
    verify_self_signature,
)
from arachne.modules.m2.support import (
    NetworkCheck,
    inventory_or_skip,
    net_or_skip,
    port_catalog_for,
    services_of,
    target_kinds_for_network_probes,
    tls_capable_services,
)

__all__ = ["MutualTlsAuth"]

_NETWORK_KINDS = (*target_kinds_for_network_probes(), TargetKind.URL)


class MutualTlsAuth(NetworkCheck, Module):
    """``m2.tls-mutual-auth`` — does client-certificate authentication actually happen?"""

    metadata = CheckMetadata(
        id="m2.tls-mutual-auth",
        module="M2",
        name="tls-mutual-auth",
        version="1.0",
        title="Mutual TLS and client-certificate enforcement",
        description=(
            "Establishes whether a TLS service actually enforces client-certificate "
            "authentication. Three read-only observations are recorded: the handshake with "
            "no client certificate, the presence of a CertificateRequest in the server's TLS "
            "1.2 flight, and the server's answer to a throwaway self-signed certificate. A "
            "service that asks for a certificate and then accepts a client that presented "
            "none is reported, because its advertised authentication boundary is absent. No "
            "credential belonging to a principal is used, and no application-layer byte is "
            "sent."
        ),
        research_ref="ch02#14",
        framework=("WSTG-CRYP-01", "CWE-295"),
        cwe="CWE-295",
        target_kinds=_NETWORK_KINDS,
        severity_hint="high",
        type="active",
        safe=True,
        verifiable=True,
        estimated_requests=3,
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

        # The throwaway certificate is built (and checked) before any socket is opened: if the
        # fixture were malformed the observation would be measuring an OpenSSL parse error.
        certificate = certificate_der()
        if not verify_self_signature(certificate):
            yield ctx.error(
                RuntimeError("the throwaway mTLS probe certificate failed its self-check")
            )
            return

        catalog = port_catalog_for(ctx)
        services = tls_capable_services(services_of(inventory, ctx.asset), catalog)
        if not services:
            yield ctx.skipped(
                f"no TLS service recorded for asset {ctx.asset.key} "
                "(m2.port-scan and m2.service-fingerprint establish them first)"
            )
            return

        for service in services:
            async for result in self._observe(ctx, client, service, certificate):
                yield result

    # ------------------------------------------------------------------ the observation
    async def _observe(
        self,
        ctx: CheckContext,
        client: Any,
        service: ServiceRecord,
        certificate: bytes,
    ) -> AsyncIterator[CheckResult]:
        server_name = service.host if not _is_address(service.host) else None

        # (a) the no-certificate handshake, through the client's real TLS path.
        without_certificate = await client.tls(
            service.host, service.port, server_hostname=server_name
        )
        service.probes += 1
        no_certificate = {
            "ok": without_certificate.ok,
            "version": without_certificate.version,
            "error": without_certificate.error,
            "verify_error": without_certificate.verify_error,
        }

        # (c) and (b): one TLS 1.2 flight, offering the throwaway certificate immediately.
        # TCP ordering means the server sends its own flight first and reads ours afterwards,
        # which is exactly the sequence a normal client produces.
        payload = wire.tls_client_hello(server_name=server_name, include_tls13=False)
        payload += wire.tls_client_certificate(certificate)
        exchange = await client.tcp(service.host, service.port, payload=payload, reads=8)
        service.probes += 1
        flight = wire.parse_tls_server_flight(exchange.banner)

        facts = {
            "host": service.host,
            "port": service.port,
            "no_certificate_handshake": no_certificate,
            "certificate_request": flight["certificate_request"],
            "handshake_types": flight["handshake_types"],
            "selected_version": flight["selected_version"],
            "invalid_certificate_alert": flight["alert"],
            "flight_complete": flight["complete"],
            "records": flight["record_count"],
            "throwaway_certificate": {
                "subject": dict(THROWAWAY_CERTIFICATE_SUBJECT),
                "key_bits": THROWAWAY_KEY_BITS,
                "self_signed": True,
                "sha256_prefix": _digest(certificate),
            },
        }
        evidence = [_evidence(ctx, service, facts)]
        yield ctx.info(
            f"mutual-TLS observation for {service.key}",
            detail=_summary(no_certificate, flight),
            evidence=evidence,
            confidence=0.85,
        )

        if flight["certificate_request"] is None:
            # The flight was not readable (TLS 1.3, an alert before ServerHelloDone, or a
            # non-TLS answer). Recording "undetermined" is the honest outcome.
            yield ctx.clean(
                f"client-certificate policy on {service.key} is undetermined",
                detail=(
                    "The server's handshake flight could not be read in the clear "
                    f"(handshake messages: {', '.join(flight['handshake_types']) or 'none'}; "
                    f"alert: {flight['alert']['name'] if flight['alert'] else 'none'}). "
                    "A TLS 1.3 server encrypts its CertificateRequest, so the probe reports "
                    "no result rather than inferring one."
                ),
                evidence=evidence,
                confidence=0.0,
            )
            return

        # Two independent questions: did the server ask for a certificate at all (below), and
        # did it let an unauthenticated client in (further below)?
        alert = flight["alert"]
        certificate_alert = bool(alert and alert["certificate_related"])
        if not flight["certificate_request"]:
            # It never asked: an ordinary TLS service. Recording the negative is the
            # decoy's evidence that the probe produced no finding for correct behaviour.
            yield ctx.clean(
                f"{service.key} does not request client certificates",
                detail=(
                    "The server's TLS 1.2 flight contained no CertificateRequest, so it does "
                    "not offer client-certificate authentication and there is nothing to "
                    "enforce."
                ),
                evidence=evidence,
                confidence=0.85,
            )
            return

        if without_certificate.ok:
            # The finding: it advertises client-certificate authentication and then completes
            # a handshake with a client that presented no certificate at all.
            yield ctx.candidate(
                f"TLS service on {service.host}:{service.port} requests client certificates "
                "but does not require them",
                detail=(
                    "The server advertised client-certificate authentication (a "
                    "CertificateRequest in its handshake) and then completed a handshake with "
                    "a client that presented no certificate. A service presenting mTLS as its "
                    "authentication boundary is therefore reachable unauthenticated "
                    f"(CWE-295). The invalid-certificate observation answered "
                    f"{alert['name'] if alert else 'with no certificate alert'}, which does not "
                    "change the outcome: the client that proved nothing was admitted. Enforcing "
                    "it means failing the handshake when no certificate is presented (nginx "
                    "'ssl_verify_client on', Apache 'SSLVerifyClient require', HAProxy "
                    "'ssl verify required')."
                ),
                confidence=0.8,
                evidence=evidence,
            )
            return

        if (
            certificate_alert
            or "certificate"
            in (
                (without_certificate.error or "") + (without_certificate.verify_error or "")
            ).lower()
        ):
            yield ctx.clean(
                f"mutual TLS on {service.key} requires a client certificate",
                detail=(
                    "The server sent a CertificateRequest and refused both the handshake with "
                    "no client certificate "
                    f"({without_certificate.error or without_certificate.verify_error}) and the "
                    f"throwaway self-signed certificate ({alert['name'] if alert else 'refused'}). "
                    "Client-certificate authentication is enforced."
                ),
                evidence=evidence,
                confidence=0.9,
            )
            return

        yield ctx.clean(
            f"client-certificate enforcement on {service.key} is undetermined",
            detail=(
                "The server sent a CertificateRequest, but the no-certificate handshake also "
                f"failed for a non-certificate reason ({without_certificate.error or 'unknown'}) "
                "and no certificate-related alert was observed. Nothing is claimed either way."
            ),
            evidence=evidence,
            confidence=0.0,
        )


# --------------------------------------------------------------------------- helpers
def _is_address(value: str) -> bool:
    import ipaddress

    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def _digest(certificate: bytes) -> str:
    """A short fingerprint of the presented certificate (never its body)."""
    import hashlib

    return hashlib.sha256(certificate).hexdigest()[:16]


def _summary(no_certificate: dict[str, Any], flight: dict[str, Any]) -> str:
    handshake = "completed" if no_certificate["ok"] else f"refused ({no_certificate['error']})"
    request = flight["certificate_request"]
    requested = {True: "present", False: "absent", None: "unreadable"}[request]
    alert = flight["alert"]
    return (
        f"no-certificate handshake: {handshake}; "
        f"CertificateRequest: {requested}; "
        f"client flight answered with: {alert['name'] if alert else 'no alert'}; "
        f"negotiated {flight['selected_version'] or 'an unknown version'}"
    )


def _evidence(ctx: CheckContext, service: ServiceRecord, facts: dict[str, Any]) -> Evidence:
    return ctx.evidence(
        "note", {"service": service.evidence_payload(), "facts": facts}, source=service.key
    )
