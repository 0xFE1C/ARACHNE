"""Directory and file-service checks: SMB, NFS, LDAP, Kerberos (ch02#16-19).

Four protocols that leak identity and structure before any credential is presented. Each is
implemented as the *smallest* exchange that establishes the exposure, and every one is
read-only:

``m2.smb-enum`` (ch02#16)
    SMB2 NEGOTIATE for dialects and signing, then an NTLMSSP **anonymous** SESSION_SETUP to
    see whether the server accepts a session with no credential at all. A server that still
    offers SMBv1 is called out separately — that dialect is exploitable on its own
    (EternalBlue class) and the CVE correlation keys on the signal.
``m2.nfs-enum`` (ch02#17)
    RPCBPROC_DUMP against portmapper/rpcbind to learn the registered programs and their
    ports, then MOUNTPROC_EXPORT against mountd for the export list. Export options decide
    the risk (a `*` host entry or a writable export), and no mount is attempted.
``m2.ldap-enum`` (ch02#18)
    The rootDSE read, then an anonymous simple bind. A directory that answers both lets an
    attacker enumerate users, groups and computers, so "anonymous bind accepted" is the
    finding; how much of the tree is readable is left to the report's evidence.
``m2.kerberos-enum`` (ch02#19)
    AS-REQ probes with the KDC's own error codes as the oracle: ``PREAUTH_REQUIRED`` means
    the principal exists, ``CLIENT_UNKNOWN`` means it does not. Pacing and a hard cap on the
    number of names are mandatory here, because the failure mode of getting this wrong is an
    account-lockout incident in the assessed domain.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
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

__all__ = ["KerberosEnum", "LdapEnum", "NfsEnum", "SmbEnum"]

_NETWORK_KINDS = (*target_kinds_for_network_probes(), TargetKind.URL)


def _service_at(
    ctx: CheckContext, probes: tuple[str, ...], ports: tuple[int, ...]
) -> tuple[ServiceRecord, ...]:
    """Services for this asset matching a protocol identity or one of ``ports``."""
    catalog = port_catalog_for(ctx)
    wanted = set(ports)
    for probe in probes:
        wanted.update(catalog.ports_for_probe(probe))
    matches: list[ServiceRecord] = []
    for service in services_of(ctx.inventory, ctx.asset):
        if service.protocol != "tcp":
            continue
        if service.effective_service.lower() in {item.lower() for item in probes}:
            matches.append(service)
            continue
        if service.port in wanted:
            matches.append(service)
    return tuple(matches)


class SmbEnum(NetworkCheck, Module):
    """``m2.smb-enum`` — SMB version, signing and anonymous access (research ch02#16)."""

    metadata = CheckMetadata(
        id="m2.smb-enum",
        module="M2",
        name="smb-enum",
        version="1.0",
        title="SMB enumeration",
        description=(
            "Negotiates SMB2 to learn the supported dialects and whether message signing is "
            "required, then attempts an NTLMSSP anonymous session to establish whether the "
            "server accepts a session with no credential. Reports SMBv1 support, missing "
            "signing requirements and anonymous access; never authenticates with a credential."
        ),
        research_ref="ch02#16",
        framework=("WSTG-CONF-01", "CWE-200"),
        cwe="CWE-200",
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

        services = _service_at(ctx, ("smb", "netbios-ssn"), (445, 139))
        if not services:
            yield ctx.skipped(
                f"no SMB service recorded for asset {ctx.asset.key} "
                "(m2.port-scan and m2.service-fingerprint establish them first)"
            )
            return

        for service in services:
            negotiate = await client.tcp(
                service.host, service.port, payload=wire.smb2_negotiate(), reads=1
            )
            service.probes += 1
            parsed = wire.parse_smb2_negotiate(negotiate.banner)
            if parsed is None:
                yield ctx.clean(
                    f"no SMB2 negotiation response from {service.key}",
                    evidence=[_evidence(ctx, service, {"response": negotiate.banner[:64].hex()})],
                    confidence=0.4,
                )
                continue
            _apply_identity(
                service,
                product="windows smb" if not parsed.smb1_supported else "smb1",
                version=parsed.dialect,
                banner=parsed.dialect_name,
            )
            anonymous_status: int | None = None
            if parsed.dialect_revision != 1:
                session = await client.tcp(
                    service.host,
                    service.port,
                    payload=wire.smb2_session_setup_anonymous(),
                    reads=1,
                )
                service.probes += 1
                anonymous_status = wire.parse_nt_status(session.banner)
            facts: dict[str, Any] = {
                "dialect": parsed.dialect,
                "dialect_revision": parsed.dialect_revision,
                "signing_required": parsed.signing_required,
                "signing_enabled": parsed.signing_enabled,
                "smb1_supported": parsed.smb1_supported,
                "anonymous_session_status": (
                    wire.nt_status_name(anonymous_status) if anonymous_status is not None else None
                ),
            }
            service.notes["smb"] = facts
            evidence = [_evidence(ctx, service, facts)]
            yield ctx.info(
                f"SMB on {service.key}: {parsed.dialect_name}",
                detail=(
                    f"signing {'required' if parsed.signing_required else 'not required'}; "
                    f"anonymous session → {facts['anonymous_session_status'] or 'not attempted'}"
                ),
                evidence=evidence,
                confidence=0.9,
            )
            if parsed.smb1_supported:
                yield ctx.candidate(
                    f"SMBv1 is supported on {service.key}",
                    detail=(
                        "The server negotiated (or offered) the SMBv1 dialect. SMBv1 is "
                        "unauthenticated at the protocol level for several request types and is "
                        "the transport of the EternalBlue/WannaCry chain; it is disabled by "
                        "default in every supported Windows and Samba release (research ch02#16)."
                    ),
                    confidence=0.9,
                    evidence=evidence,
                )
            if not parsed.signing_required:
                yield ctx.candidate(
                    f"SMB signing is not required on {service.key}",
                    detail=(
                        "The NEGOTIATE response does not require message signing, so a "
                        "man-in-the-middle can relay an SMB session (NTLM relay) without "
                        "possessing a credential (CWE-345)."
                    ),
                    confidence=0.75,
                    evidence=evidence,
                )
            if anonymous_status == 0x00000000:
                yield ctx.candidate(
                    f"SMB on {service.key} accepts an anonymous session",
                    detail=(
                        "SESSION_SETUP with an NTLMSSP anonymous token returned STATUS_SUCCESS, "
                        "so the host permits an unauthenticated session — the classic null-session "
                        "condition that leaks share and account information (research ch02#16)."
                    ),
                    confidence=0.9,
                    evidence=evidence,
                )


class NfsEnum(NetworkCheck, Module):
    """``m2.nfs-enum`` — rpcbind registrations and NFS exports (research ch02#17)."""

    metadata = CheckMetadata(
        id="m2.nfs-enum",
        module="M2",
        name="nfs-enum",
        version="1.0",
        title="NFS export enumeration",
        description=(
            "Dumps the portmapper/rpcbind registration table (RPCBPROC_DUMP) and then the "
            "NFS export list from mountd (MOUNTPROC_EXPORT), reporting which exports are "
            "offered and to whom. No filesystem is mounted and no file is read."
        ),
        research_ref="ch02#17",
        framework=("WSTG-CONF-01", "CWE-284"),
        cwe="CWE-284",
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

        services = _service_at(ctx, ("rpcbind", "nfs"), (111, 2049))
        if not services:
            yield ctx.skipped(
                f"no rpcbind/NFS service recorded for asset {ctx.asset.key} "
                "(m2.port-scan and m2.service-fingerprint establish them first)"
            )
            return

        for service in services:
            dump = await client.tcp(
                service.host, service.port, payload=wire.rpcbind_dump_call(), reads=1
            )
            service.probes += 1
            reply = wire.parse_rpc_reply(dump.banner)
            if not reply.accepted:
                yield ctx.clean(
                    f"no rpcbind answer from {service.key}",
                    detail=reply.error or "the port did not answer an ONC RPC call",
                    evidence=[_evidence(ctx, service, {"response": dump.banner[:64].hex()})],
                    confidence=0.4,
                )
                continue
            registrations = wire.parse_portmap_dump(reply.payload)
            mount_ports = [
                entry.port
                for entry in registrations
                if entry.program == 100005 and entry.protocol == 6
            ]
            facts: dict[str, Any] = {
                "registrations": [
                    {
                        "program": entry.program_name,
                        "program_id": entry.program,
                        "version": entry.version,
                        "protocol": entry.protocol_name,
                        "port": entry.port,
                    }
                    for entry in registrations
                ],
                "nfs_versions": [
                    entry.version for entry in registrations if entry.program == 100003
                ],
            }
            _apply_identity(
                service, product="rpcbind/portmapper", version=None, banner="RPCBPROC_DUMP"
            )
            exports: tuple[tuple[str, tuple[str, ...]], ...] = ()
            if mount_ports:
                export_reply = wire.parse_rpc_reply(
                    (
                        await client.tcp(
                            service.host,
                            mount_ports[0],
                            payload=wire.nfs_export_list(),
                            reads=1,
                        )
                    ).banner
                )
                service.probes += 1
                if export_reply.ok:
                    exports = wire.parse_nfs_exports(export_reply.payload)
            facts["exports"] = [{"path": path, "hosts": list(hosts)} for path, hosts in exports]
            service.notes["nfs"] = facts
            evidence = [_evidence(ctx, service, facts)]
            yield ctx.info(
                f"rpcbind on {service.key} registers {len(registrations)} program(s)",
                detail=(
                    "NFS versions: "
                    f"{', '.join(str(item) for item in facts['nfs_versions']) or 'none'}; "
                    f"{len(exports)} export(s) reported by mountd"
                ),
                evidence=evidence,
                confidence=0.9,
            )
            if exports:
                unrestricted = [path for path, hosts in exports if not hosts or "*" in hosts]
                yield ctx.candidate(
                    f"NFS exports {len(exports)} filesystem(s) on {service.host}",
                    detail=(
                        "Exports: "
                        + "; ".join(
                            f"{path} → {', '.join(hosts) or 'any host'}"
                            for path, hosts in exports[:8]
                        )
                        + (
                            f". {len(unrestricted)} are world-mountable (no host restriction)."
                            if unrestricted
                            else ""
                        )
                        + " NFSv3 authorises by host address, so an export offered to a wide "
                        "range is readable — and writable if exported read-write "
                        "(research ch02#17)."
                    ),
                    confidence=0.85,
                    evidence=evidence,
                )


class LdapEnum(NetworkCheck, Module):
    """``m2.ldap-enum`` — rootDSE and anonymous bind (research ch02#18)."""

    metadata = CheckMetadata(
        id="m2.ldap-enum",
        module="M2",
        name="ldap-enum",
        version="1.0",
        title="LDAP anonymous bind",
        description=(
            "Reads the LDAP rootDSE for the naming contexts and supported versions, then "
            "attempts an anonymous simple bind. A directory that answers an anonymous bind "
            "can be enumerated by any network client, which is the finding."
        ),
        research_ref="ch02#18",
        framework=("WSTG-CONF-01", "CWE-287"),
        compliance=("CIS-5.1", "CIS-5.3", "CIS-6.6", "ISO-A.5.16"),
        cwe="CWE-287",
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

        services = _service_at(ctx, ("ldap", "ldaps"), (389, 636))
        if not services:
            yield ctx.skipped(
                f"no LDAP service recorded for asset {ctx.asset.key} "
                "(m2.port-scan and m2.service-fingerprint establish them first)"
            )
            return

        for service in services:
            bind = await client.tcp(
                service.host,
                service.port,
                payload=wire.build_ldap_bind_request(1),
                reads=1,
            )
            service.probes += 1
            bind_message = wire.parse_ldap_message(bind.banner)
            rootdse_exchange = await client.tcp(
                service.host,
                service.port,
                payload=wire.build_ldap_search_request(2),
                reads=1,
            )
            service.probes += 1
            rootdse = wire.parse_ldap_message(rootdse_exchange.banner)
            contexts = rootdse.attribute("namingContexts") if rootdse else ()
            versions = rootdse.attribute("supportedLDAPVersion") if rootdse else ()
            facts: dict[str, Any] = {
                "anonymous_bind_result": bind_message.result_code if bind_message else None,
                "anonymous_bind_text": (
                    wire.ldap_result_text(bind_message.result_code) if bind_message else None
                ),
                "rootdse_result": rootdse.result_code if rootdse else None,
                "naming_contexts": list(contexts),
                "supported_versions": list(versions),
                "rootdse_attributes": (
                    {key: list(value) for key, value in rootdse.attributes.items()}
                    if rootdse
                    else {}
                ),
            }
            _apply_identity(service, product="ldap", version=None, banner="LDAP rootDSE")
            service.notes["ldap"] = facts
            evidence = [_evidence(ctx, service, facts)]
            anonymous_ok = bool(bind_message and bind_message.accepted)
            yield ctx.info(
                f"LDAP on {service.key}: anonymous bind "
                f"{facts['anonymous_bind_text'] or 'no answer'}",
                detail=(
                    f"naming contexts: {', '.join(contexts) or 'not readable'}; "
                    f"supported versions: {', '.join(versions) or 'not read'}"
                ),
                evidence=evidence,
                confidence=0.9,
            )
            if anonymous_ok:
                yield ctx.candidate(
                    f"LDAP on {service.key} accepts an anonymous bind",
                    detail=(
                        "The directory answered an unauthenticated simple bind, so a network "
                        "client can walk the tree for users, groups, computers and the "
                        "attributes a misconfigured directory inherits read access to "
                        "(research ch02#18). Disable anonymous bind and apply the "
                        "'do not allow anonymous enumeration of SAM and shares' policy."
                    ),
                    confidence=0.85,
                    evidence=evidence,
                )


class KerberosEnum(NetworkCheck, Module):
    """``m2.kerberos-enum`` — AS-REQ principal enumeration (research ch02#19)."""

    metadata = CheckMetadata(
        id="m2.kerberos-enum",
        module="M2",
        name="kerberos-enum",
        version="1.0",
        title="Kerberos user enumeration",
        description=(
            "Sends Kerberos AS-REQ probes and reads the KDC's error code to establish which "
            "principal names exist (PREAUTH_REQUIRED means the account is real, "
            "CLIENT_UNKNOWN means it is not). Paced and capped by design: the check must not "
            "produce the lockout event it is meant to warn about."
        ),
        research_ref="ch02#19",
        framework=("WSTG-CONF-01", "CWE-200"),
        compliance=("CIS-5.1", "CIS-5.3", "CIS-5.5", "ISO-A.5.16"),
        cwe="CWE-200",
        target_kinds=_NETWORK_KINDS,
        severity_hint="medium",
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

        services = _service_at(ctx, ("kerberos",), (88, 464))
        if not services:
            yield ctx.skipped(
                f"no Kerberos service recorded for asset {ctx.asset.key} "
                "(m2.port-scan and m2.service-fingerprint establish them first)"
            )
            return

        realm = _realm_for(ctx)
        if realm is None:
            yield ctx.skipped(
                "Kerberos enumeration needs the realm to address the KDC; declare the AD "
                "domain as a target (or set the asset to the domain name) so the AS-REQ can "
                "name it"
            )
            return

        names = load_wordlist(ctx, "kerberos-users")[: ctx.config.kerberos_max_names]
        for service in services:
            confirmed: dict[str, str] = {}
            rejected: list[str] = []
            unreadable = 0
            for name in names:
                exchange = await client.tcp(
                    service.host,
                    service.port,
                    payload=wire.kerberos_as_req(name, realm),
                    reads=1,
                )
                service.probes += 1
                code = wire.kerberos_error_code(exchange.banner)
                if code is None:
                    unreadable += 1
                elif code in {24, 25, 12, 18, 68}:  # PREAUTH_REQUIRED/FAILED/POLICY/REVOKED
                    confirmed[name] = wire.KRB_ERRORS.get(code, str(code))
                elif code == 6:  # KDC_ERR_C_PRINCIPAL_UNKNOWN
                    rejected.append(name)
                else:
                    confirmed[name] = wire.KRB_ERRORS.get(code, str(code))
                # Lockout-safe pacing (F-01-09, research ch02#19): never machine-gun a KDC.
                await asyncio.sleep(ctx.config.kerberos_pacing_s)

            facts: dict[str, Any] = {
                "realm": realm,
                "probed": len(names),
                "confirmed": confirmed,
                "unknown": rejected,
                "unreadable": unreadable,
                "pacing_s": ctx.config.kerberos_pacing_s,
            }
            service.notes["kerberos"] = facts
            _apply_identity(service, product="kerberos", version=None, banner=f"KDC realm {realm}")
            evidence = [_evidence(ctx, service, facts)]
            if not confirmed:
                yield ctx.clean(
                    f"no principal confirmed on {service.key} (realm {realm})",
                    detail=(
                        f"{len(names)} name(s) probed: {len(rejected)} answered "
                        "KDC_ERR_C_PRINCIPAL_UNKNOWN"
                        + (f"; {unreadable} gave no parseable KRB-ERROR" if unreadable else "")
                    ),
                    evidence=evidence,
                    confidence=0.6,
                )
                continue
            yield ctx.info(
                f"Kerberos on {service.key}: {len(confirmed)}/{len(names)} principals exist",
                detail="; ".join(
                    f"{name}: {reason}" for name, reason in list(confirmed.items())[:10]
                ),
                evidence=evidence,
                confidence=0.9,
            )
            yield ctx.candidate(
                f"Kerberos principal enumeration confirmed {len(confirmed)} account(s)",
                detail=(
                    "The KDC distinguishes existing from non-existing principals in its "
                    "pre-authentication error, which lets anyone on the network build a valid "
                    "username list for password spraying and targeted phishing without ever "
                    "triggering a failed logon (research ch02#19). "
                    f"Confirmed: {', '.join(list(confirmed)[:10])}."
                ),
                confidence=0.85,
                evidence=evidence,
            )


# --------------------------------------------------------------------------- helpers
def _realm_for(ctx: CheckContext) -> str | None:
    """The Kerberos realm: the asset's own name when it is a domain, else a declared one."""
    from arachne.modules.m2.remote import _is_address

    if not _is_address(ctx.asset.value) and "." in ctx.asset.value:
        return ctx.asset.value.upper()
    for selector in ctx.definition.targets:
        if (
            selector.kind in {TargetKind.DOMAIN, TargetKind.DOMAIN_PATTERN}
            and "." in selector.value
        ):
            return selector.value.upper()
    return None


def _evidence(ctx: CheckContext, service: ServiceRecord, facts: dict[str, Any]) -> Evidence:
    return ctx.evidence(
        "note",
        {"service": service.evidence_payload(), "facts": facts},
        source=service.key,
    )


def _apply_identity(
    service: ServiceRecord, *, product: str, version: str | None, banner: str
) -> None:
    current = service.identity
    if current is not None and current.versioned:
        return
    service.identity = ServiceIdentity(
        protocol=current.protocol if current and current.protocol != "unknown" else product,
        product=product or (current.product if current else None),
        version=version or (current.version if current else None),
        banner=banner or (current.banner if current else ""),
        confidence=0.9,
        extra=dict(current.extra) if current else {},
    )
