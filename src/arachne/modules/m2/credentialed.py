"""Credentialed host checks: SMB authentication with a vault credential (S19, REQ-CREDS-004).

M2 establishes existence, never exploitable access, and its module docstring used to say that
credential verification "belongs to a separate, separately-authorized stage". This is that
stage: ``m2.smb-auth`` is **opt-in**, needs the active-checks opt-in *and* an attestation that
authorizes active checks, and draws its credential from the vault through the broker.

The split of responsibility is the point:

* this module owns the **protocol** — the SMB2 NEGOTIATE / NTLMSSP exchange, built from
  :mod:`arachne.modules.m2.wire`;
* the broker owns the **secret** — it reads the material, calls
  :meth:`SmbAuthenticator.attempt` with a username and a password for one exchange, and
  returns a verdict. The check receives a :class:`ProtocolAuthResult` and never a value.

So "are these credentials valid?" is answerable without a credential ever entering a check, an
evidence blob, a log line or a report (REQ-CREDS-002), and without the credential being usable
against a target outside its declared scope (REQ-CREDS-005 — the broker checks that first).
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Mapping
from typing import Any

from arachne.core.results import CheckResult, Evidence
from arachne.core.target import TargetKind
from arachne.modules.base import CheckMetadata, Module
from arachne.modules.context import CheckContext
from arachne.modules.m2 import wire
from arachne.modules.m2.inventory import ServiceRecord
from arachne.modules.m2.support import (
    NetworkCheck,
    inventory_or_skip,
    net_or_skip,
    port_catalog_for,
    services_of,
    target_kinds_for_network_probes,
)

__all__ = ["SmbAuth"]

_NETWORK_KINDS = (*target_kinds_for_network_probes(), TargetKind.URL)

#: STATUS_MORE_PROCESSING_REQUIRED — the peer wants the NTLMv2 response.
_MORE_PROCESSING_REQUIRED = 0xC0000016
#: STATUS_SUCCESS.
_SUCCESS = 0x00000000


def _smb_services(ctx: CheckContext) -> tuple[ServiceRecord, ...]:
    """The SMB services this asset has (fingerprinted by the earlier M2 checks)."""
    catalog = port_catalog_for(ctx)
    wanted = {445, 139}
    wanted.update(catalog.ports_for_probe("smb"))
    matches: list[ServiceRecord] = []
    for service in services_of(ctx.inventory, ctx.asset):
        if service.protocol != "tcp":
            continue
        if service.effective_service.lower() in {"smb", "netbios-ssn", "microsoft-ds"}:
            matches.append(service)
            continue
        if service.port in wanted:
            matches.append(service)
    return tuple(matches)


class SmbAuthenticator:
    """The SMB2 NTLMv2 exchange, driven by the broker with the material it holds.

    Implements :class:`arachne.creds.broker.Authenticator`: the broker calls
    :meth:`attempt` once with the username and password, and gets back a verdict. Three SMB2
    requests, each through the scan's scoped, rate-limited, audited network client:

    1. NEGOTIATE — establish that the peer speaks SMB2 at all;
    2. SESSION_SETUP with an NTLMSSP NEGOTIATE — the peer answers a challenge;
    3. SESSION_SETUP with an NTLMSSP AUTHENTICATE carrying the NTLMv2 response — SUCCESS
       means the credentials are valid, LOGON_FAILURE means they are not.

    A peer that speaks only SMB1 is reported as "unsupported" rather than being sent a
    credential it cannot verify.
    """

    protocol = "smb"

    def __init__(self, client: Any, service: ServiceRecord) -> None:
        self.client = client
        self.service = service
        self.endpoint = service.key or f"{service.host}:{service.port}"

    async def attempt(
        self, username: str, password: str, extra: Mapping[str, str] | None = None
    ) -> Any:
        from arachne.creds.broker import ProtocolAuthResult

        # The NTLMv2 hash includes the account's domain; it comes from the credential's
        # ``extra`` block (the same place a login flow's extra form fields live).
        domain = str((extra or {}).get("domain") or "")

        host, port = self.service.host, self.service.port
        exchanges: list[Any] = []
        negotiate = await self.client.tcp(host, port, payload=wire.smb2_negotiate(), reads=1)
        exchanges.append(negotiate)
        parsed = wire.parse_smb2_negotiate(negotiate.banner)
        if parsed is None:
            return ProtocolAuthResult(
                protocol=self.protocol,
                endpoint=self.endpoint,
                attempted=True,
                accepted=False,
                status_name="NO_NEGOTIATE",
                detail="the peer did not answer an SMB2 NEGOTIATE",
                exchanges=tuple(exchanges),
            )
        if parsed.smb1_supported and parsed.dialect_revision == 1:
            return ProtocolAuthResult(
                protocol=self.protocol,
                endpoint=self.endpoint,
                attempted=True,
                accepted=False,
                status_name="SMB1_ONLY",
                detail=(
                    "the peer offered only SMBv1, whose NTLM exchange this build does not "
                    "implement; no credential was sent"
                ),
                exchanges=tuple(exchanges),
            )
        challenge_exchange = await self.client.tcp(
            host,
            port,
            payload=wire.smb2_session_setup_ntlmssp(wire.ntlmssp_negotiate()),
            reads=1,
        )
        exchanges.append(challenge_exchange)
        parsed_setup = wire.parse_smb2_session_setup(challenge_exchange.banner)
        if parsed_setup is None:
            return ProtocolAuthResult(
                protocol=self.protocol,
                endpoint=self.endpoint,
                attempted=True,
                accepted=False,
                status_name="NO_CHALLENGE",
                detail="the peer did not answer the NTLMSSP negotiate",
                exchanges=tuple(exchanges),
            )
        status, blob = parsed_setup
        challenge = wire.parse_ntlmssp_challenge(blob)
        if status != _MORE_PROCESSING_REQUIRED or challenge is None:
            return ProtocolAuthResult(
                protocol=self.protocol,
                endpoint=self.endpoint,
                attempted=True,
                accepted=False,
                status_name=wire.nt_status_name(status),
                detail="the peer did not issue an NTLM challenge",
                exchanges=tuple(exchanges),
            )
        authenticate = await self.client.tcp(
            host,
            port,
            payload=wire.smb2_session_setup_ntlmssp(
                wire.ntlmssp_authenticate(
                    username=username,
                    password=password,
                    domain=domain,
                    server_challenge=challenge.server_challenge,
                    target_info=challenge.target_info,
                )
            ),
            reads=1,
        )
        exchanges.append(authenticate)
        final = wire.parse_nt_status(authenticate.banner)
        accepted = final == _SUCCESS
        return ProtocolAuthResult(
            protocol=self.protocol,
            endpoint=self.endpoint,
            attempted=True,
            accepted=accepted,
            status_name=wire.nt_status_name(final) if final is not None else "NO_STATUS",
            detail=(
                "the peer accepted the credential"
                if accepted
                else "the peer refused the credential"
            ),
            exchanges=tuple(exchanges),
        )


class SmbAuth(NetworkCheck, Module):
    """``m2.smb-auth`` — verify a vault SMB credential against a host (ch02#16, S19)."""

    metadata = CheckMetadata(
        id="m2.smb-auth",
        module="M2",
        name="smb-auth",
        version="1.0",
        title="SMB credential verification",
        description=(
            "Authenticates to an SMB service with the credential this scan selected from the "
            "vault, using an SMB2 NTLMSSP exchange, and reports whether the peer accepted it. "
            "The credential never enters the check: the broker supplies it for one exchange "
            "and drops it, so the finding carries the peer's status and the redacted "
            "exchange only. Opt-in, active, and refused when the credential is not scoped to "
            "the target."
        ),
        research_ref="ch02#16",
        cwe="CWE-1392",
        target_kinds=_NETWORK_KINDS,
        severity_hint="medium",
        type="active",
        safe=True,
        verifiable=True,
        enabled_by_default=False,
        estimated_requests=3,
        requires_active_checks=True,
        requires_credentials=("smb",),
        runs_on_discovered=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        broker = ctx.credentials
        if broker is None:
            yield ctx.skipped(
                "no credential capability in this step: credentialed host checks need a "
                "credential selected for the scan"
            )
            return
        client, skipped = net_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        assert client is not None
        inventory, skipped = inventory_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        assert inventory is not None

        services = _smb_services(ctx)
        if not services:
            yield ctx.skipped(
                f"no SMB service recorded for asset {ctx.asset.key} "
                "(m2.port-scan and m2.service-fingerprint establish them first)"
            )
            return

        for service in services:
            result = await broker.authenticate(
                SmbAuthenticator(client, service), host=service.host, port=service.port
            )
            evidence = [self._evidence(ctx, service, result)]
            if not result.attempted:
                yield ctx.skipped(f"no SMB credential for {service.key}: {result.detail}".strip())
                continue
            service.notes["smb_auth"] = result.to_dict()
            if result.accepted:
                # Not a vulnerability on its own — the operator declared the credential, and
                # a working credential is the expected answer. It belongs in the report as
                # confirmed access, which is what a credentialed assessment needs to state.
                yield ctx.info(
                    f"SMB accepted the configured credential on {service.key}",
                    detail=(
                        f"credential {result.label!r} authenticated over SMB2 NTLMSSP "
                        f"({result.status_name}); the account has logon access to this host"
                    ),
                    evidence=evidence,
                    confidence=0.9,
                )
                continue
            yield ctx.info(
                f"SMB refused the configured credential on {service.key}",
                detail=(
                    f"credential {result.label!r} did not authenticate "
                    f"({result.status_name}): the stored secret is wrong, expired, or the "
                    "account is locked or disabled"
                    + (f" — {result.detail}" if result.detail else "")
                ),
                evidence=evidence,
                confidence=0.8,
            )

    @staticmethod
    def _evidence(ctx: CheckContext, service: ServiceRecord, result: Any) -> Evidence:
        payload: dict[str, Any] = {
            "service": service.key,
            "port": service.port,
            "protocol": result.protocol,
            "endpoint": result.endpoint,
            "credential": result.label,
            "attempted": result.attempted,
            "accepted": result.accepted,
            "nt_status": result.status_name,
            "requests": len(result.exchanges),
        }
        return Evidence.of("banner", payload, source=f"smb://{result.endpoint}")
