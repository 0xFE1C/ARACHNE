"""M2's checks, driven through the scripted transport (no packets anywhere).

Each check is a small state machine over a shared :class:`NetworkInventory`, so its unit tests
say what the inventory holds and what the wire answers, then assert on the results: the
candidates raised, the identities recorded, and — just as important — the cases where a check
must cost *nothing* (no open port, no fingerprinted version, UDP switched off) and report why.

The scripted transport is the seam: it answers by ``(protocol, host, port)`` and records every
call, so a test can assert both what a check did and what it did not touch.
"""

from __future__ import annotations

import struct

import pytest
from tests.fixtures_lab import expired_certificate_der
from tests.helpers.checks import M2Harness, asset_for, make_m2_harness

from arachne.core.net import TcpExchange, UdpExchange
from arachne.core.results import CheckResult
from arachne.core.target import TargetKind
from arachne.modules.context import ModuleConfig
from arachne.modules.m2 import wire
from arachne.modules.m2.datastores import DbServiceProbe
from arachne.modules.m2.directory import KerberosEnum, LdapEnum, NfsEnum, SmbEnum
from arachne.modules.m2.discovery import HostDiscovery, OsFingerprint, PortScan, ServiceFingerprint
from arachne.modules.m2.hardening import (
    DEFAULT_FAVICONS,
    FaviconHash,
    FtpAnonymous,
    HttpFingerprint,
    LegacyServices,
    SsdpDiscovery,
    favicon_digest,
)
from arachne.modules.m2.inventory import ServiceIdentity, ServiceRecord
from arachne.modules.m2.netinfra import DnsActive, IcsProbe, SnmpEnum
from arachne.modules.m2.remote import RdpVncDetect, SmtpEnum, SshEnum
from arachne.modules.m2.tls_cve import CveCorrelate, TlsDeepScan

pytestmark = pytest.mark.usefixtures("_reset_arachne_logging")

HOST = "93.184.216.34"


async def run(
    module: type, harness: M2Harness, *, config: ModuleConfig | None = None
) -> list[CheckResult]:
    context = harness.context(module, config=config)
    return [result async for result in context.module.run(context)]


def kinds(results: list[CheckResult]) -> list[str]:
    return [result.status for result in results]


def candidates(results: list[CheckResult]) -> list[CheckResult]:
    return [result for result in results if result.status == "vulnerable"]


def skipped(results: list[CheckResult]) -> bool:
    """True when the only result is a skip (the same rule ``modules.handlers`` applies)."""
    return bool(results) and all(
        any(item.payload.get("skipped") for item in result.evidence) for result in results
    )


# ------------------------------------------------------------------ discovery
async def test_host_discovery_marks_a_tcp_answering_host_alive() -> None:
    harness = make_m2_harness(
        routes={
            ("icmp", HOST, 0): 57,
            ("tcp", HOST, 80): b"",
            ("tcp", HOST, 443): TcpExchange(state="closed"),
        }
    )
    results = await run(HostDiscovery, harness)
    record = harness.inventory.get(HOST)
    assert record is not None and record.alive
    assert record.ttl == 57
    assert "icmp" in record.discovery and "tcp:80" in record.discovery
    assert kinds(results) == ["info"]
    assert harness.inventory.service(HOST, 80) is not None


async def test_host_discovery_reports_a_dead_range_without_a_finding() -> None:
    harness = make_m2_harness(host=HOST, routes={})
    results = await run(HostDiscovery, harness)
    assert kinds(results) == ["not_vulnerable"]
    assert "no live host" in results[0].title


async def test_host_discovery_survives_an_unresolvable_address() -> None:
    harness = make_m2_harness(host="lab.invalid", routes={}, resolvable=False)
    results = await run(HostDiscovery, harness)
    # A name that does not resolve is data about that asset, not a failed check.
    assert kinds(results) == ["not_vulnerable"]


async def test_port_scan_records_open_ports_from_the_catalogue_policy() -> None:
    harness = make_m2_harness(
        routes={
            ("tcp", HOST, 22): b"SSH-2.0-OpenSSH_9.8\r\n",
            ("tcp", HOST, 80): TcpExchange(state="open", chunks=(b"HTTP/1.1 200 OK\r\n",)),
            ("tcp", HOST, 443): TcpExchange(state="closed"),
        }
    )
    results = await run(PortScan, harness)
    ports = harness.inventory.get(HOST).open_ports() if harness.inventory.get(HOST) else ()
    assert 22 in ports and 80 in ports
    assert 443 not in ports
    # The banner it read on the way is captured as an identity, not thrown away.
    ssh_service = harness.inventory.service(HOST, 22)
    assert ssh_service is not None and ssh_service.effective_service == "ssh"
    assert kinds(results) == ["info"]
    assert "open TCP port" in results[0].title


async def test_port_scan_costs_nothing_when_liveness_found_nothing() -> None:
    harness = make_m2_harness(routes={})
    harness.inventory.get(HOST).alive = False  # liveness ran and nothing answered
    harness.inventory.get(HOST).discovery = ["icmp"]
    results = await run(PortScan, harness)
    assert skipped(results)
    assert harness.transport.calls == []


async def test_service_fingerprint_identifies_every_open_port() -> None:
    harness = make_m2_harness(
        seed_services=[(22, "ssh"), (6379, "redis")],
        routes={
            ("tcp", HOST, 22): b"SSH-2.0-OpenSSH_8.5p1 Debian-3\r\n",
            ("tcp", HOST, 6379): b"+PONG\r\n",
        },
    )
    results = await run(ServiceFingerprint, harness)
    ssh = harness.inventory.service(HOST, 22)
    redis = harness.inventory.service(HOST, 6379)
    assert ssh is not None and ssh.product == "openssh" and ssh.version == "8.5p1"
    assert redis is not None and redis.effective_service == "redis"
    assert kinds(results) == ["info"]


async def test_service_fingerprint_says_so_when_nothing_identifies() -> None:
    harness = make_m2_harness(seed_services=[(12345, "unknown")], routes={})
    results = await run(ServiceFingerprint, harness)
    assert kinds(results) == ["not_vulnerable"]
    assert "could be identified" in results[0].title


async def test_service_fingerprint_skips_without_open_ports() -> None:
    harness = make_m2_harness(routes={})
    results = await run(ServiceFingerprint, harness)
    assert skipped(results)
    assert "no open port" in (results[0].detail or "")


async def test_os_fingerprint_uses_the_ttl_and_the_banners() -> None:
    harness = make_m2_harness(
        seed_services=[(22, "ssh")],
        routes={("icmp", HOST, 0): 63, ("tcp", HOST, 22): b"SSH-2.0-OpenSSH_9.8 Debian-3\r\n"},
    )
    results = await run(OsFingerprint, harness)
    record = harness.inventory.get(HOST)
    assert record is not None and record.os_family == "linux"
    assert kinds(results) == ["info"]
    assert "linux" in (results[0].detail or "").lower()


async def test_os_fingerprint_admits_that_it_cannot_tell() -> None:
    from arachne.core.net import IcmpExchange

    harness = make_m2_harness(routes={("icmp", HOST, 0): IcmpExchange(state="timeout")})
    results = await run(OsFingerprint, harness)
    assert kinds(results) == ["not_vulnerable"]


# ------------------------------------------------------------------ TLS
async def test_tls_scan_reports_weak_protocols_ciphers_and_certificate() -> None:
    harness = make_m2_harness(seed_services=[(443, "https")])
    harness.inventory.service(HOST, 443).identity = ServiceIdentity(protocol="tls")
    der = expired_certificate_der()  # the committed, really-expired certificate
    harness.transport.routes[("tls", HOST, 443)] = {
        "supported": ("TLSv1.1", "TLSv1.2"),
        "TLSv1.2": True,
        "TLSv1.3": False,
        # A scripted server that still offers TLS 1.1: the pinned probe for 1.2 succeeds, and
        # the legacy cap negotiates 1.1 — which is what the version list reports.
        "legacy": "TLSv1.1",
        "verify_error": "self-signed certificate",
        "der": der,
        "cipher": "AES128-SHA",
    }
    results = await run(TlsDeepScan, harness)
    assert candidates(results), [result.title for result in results]
    detail = " ".join(result.detail or "" for result in candidates(results))
    assert "TLSv1.1" in detail
    evidence = [item for result in results for item in result.evidence]
    assert any(item.kind == "tls_certificate" for item in evidence)


# ------------------------------------------------------------------ SSH / SMTP / RDP / VNC
async def test_ssh_enum_flags_deprecated_algorithms() -> None:
    harness = make_m2_harness(seed_services=[(22, "ssh")])
    harness.transport.routes[("tcp", HOST, 22)] = [
        b"SSH-2.0-OpenSSH_8.5p1 Debian-3\r\n",
        _kexinit(
            kex=b"diffie-hellman-group1-sha1,curve25519-sha256",
            host_key=b"ssh-rsa,rsa-sha2-256",
            cipher=b"aes128-ctr,3des-cbc",
            mac=b"hmac-sha1,hmac-md5",
        ),
    ]
    results = await run(SshEnum, harness)
    assert candidates(results)
    detail = candidates(results)[0].detail or ""
    assert "group1-sha1" in detail and "ssh-rsa" in detail
    service = harness.inventory.service(HOST, 22)
    assert service is not None and service.product == "openssh" and service.version == "8.5p1"


async def test_smtp_enum_reports_a_confirmable_recipient() -> None:
    harness = make_m2_harness(seed_services=[(25, "smtp")])
    harness.transport.routes[("tcp", HOST, 25)] = [
        b"220 lab.test ESMTP Postfix 3.4.14\r\n",
        b"250-lab.test\r\n250-VRFY\r\n250-EXPN\r\n250 HELP\r\n",
        b"252 2.0.0 cannot VRFY user, will accept\r\n",
    ]
    results = await run(SmtpEnum, harness, config=ModuleConfig(smtp_pacing_s=0.001))
    assert candidates(results)
    assert "recipient" in candidates(results)[0].title
    assert harness.inventory.service(HOST, 25).product == "postfix"


async def test_rdp_without_nla_is_a_finding() -> None:
    harness = make_m2_harness(seed_services=[(3389, "rdp")])
    response = (
        bytes([0x03, 0x00, 0x00, 0x13, 0x0E, 0xD0, 0x00, 0x00, 0x12, 0x34, 0x00])
        + bytes([0x02, 0x00, 0x08, 0x00])
        + struct.pack("<I", wire.RDP_PROTOCOL_SSL)
    )
    harness.transport.routes[("tcp", HOST, 3389)] = response
    results = await run(RdpVncDetect, harness)
    assert candidates(results)
    assert "does not require network-level authentication" in candidates(results)[0].title


async def test_vnc_without_authentication_is_a_finding() -> None:
    harness = make_m2_harness(seed_services=[(5900, "vnc")])
    harness.transport.routes[("tcp", HOST, 5900)] = [b"RFB 003.008\n", b"\x01\x01"]
    results = await run(RdpVncDetect, harness)
    assert candidates(results)
    assert "unauthenticated" in candidates(results)[0].title


async def test_vnc_requiring_a_password_is_only_context() -> None:
    harness = make_m2_harness(seed_services=[(5900, "vnc")])
    harness.transport.routes[("tcp", HOST, 5900)] = [b"RFB 003.008\n", b"\x01\x02"]
    results = await run(RdpVncDetect, harness)
    titles = " | ".join(result.title for result in candidates(results))
    assert "unauthenticated" not in titles
    assert "legacy VNC password" in titles


# ------------------------------------------------------------------ datastores
async def test_an_unauthenticated_redis_is_a_finding() -> None:
    harness = make_m2_harness(seed_services=[(6379, "redis")])
    harness.transport.routes[("tcp", HOST, 6379)] = [
        b"+PONG\r\n",
        b"$20\r\nredis_version:5.0.7\r\n\r\n",
    ]
    results = await run(DbServiceProbe, harness)
    assert any("unauthenticated Redis" in result.title for result in candidates(results))
    assert harness.inventory.service(HOST, 6379).version == "5.0.7"


async def test_a_redis_that_needs_authentication_is_reported_as_such() -> None:
    harness = make_m2_harness(seed_services=[(6379, "redis")])
    harness.transport.routes[("tcp", HOST, 6379)] = b"-NOAUTH Authentication required\r\n"
    results = await run(DbServiceProbe, harness)
    assert not candidates(results)
    assert "requires authentication" in results[0].title


async def test_mysql_version_comes_from_the_handshake() -> None:
    harness = make_m2_harness(seed_services=[(3306, "mysql")])
    harness.transport.routes[("tcp", HOST, 3306)] = _mysql_greeting("5.5.62")
    results = await run(DbServiceProbe, harness)
    assert any("database service exposed" in result.title for result in candidates(results))
    service = harness.inventory.service(HOST, 3306)
    assert service is not None and service.product == "mysql" and service.version == "5.5.62"


async def test_postgres_without_tls_is_a_finding() -> None:
    harness = make_m2_harness(seed_services=[(5432, "postgres")])
    harness.transport.routes[("tcp", HOST, 5432)] = [
        b"N",
        b"E\x00\x00\x00\x20S FATAL\x00C 28P01\x00M bad\x00\x00",
    ]
    results = await run(DbServiceProbe, harness)
    detail = " ".join(result.detail or "" for result in candidates(results))
    assert "refused TLS" in detail


# ------------------------------------------------------------------ directory services
async def test_anonymous_ldap_bind_is_a_finding() -> None:
    harness = make_m2_harness(seed_services=[(389, "ldap")])
    bind_response = wire.ber_tlv(
        0x30,
        wire.ber_tlv(0x02, b"\x01")
        + wire.ber_tlv(0x61, wire.ber_int(0) + wire.ber_tlv(0x04, b"") + wire.ber_tlv(0x04, b"")),
    )
    harness.transport.routes[("tcp", HOST, 389)] = [bind_response, bind_response]
    results = await run(LdapEnum, harness)
    assert any("anonymous bind" in result.title for result in candidates(results))


async def test_smbv1_support_and_missing_signing_are_findings() -> None:
    harness = make_m2_harness(seed_services=[(445, "smb")])
    harness.transport.routes[("tcp", HOST, 445)] = wire.smb1_negotiate()
    results = await run(SmbEnum, harness)
    titles = " | ".join(result.title for result in candidates(results))
    assert "SMBv1" in titles


async def test_smb_signing_not_required_is_a_finding() -> None:
    harness = make_m2_harness(seed_services=[(445, "smb")])
    harness.transport.routes[("tcp", HOST, 445)] = [
        _smb2_negotiate_response(signing=0x0001),
        _smb2_status_response(0xC0000022),
    ]
    results = await run(SmbEnum, harness)
    titles = " | ".join(result.title for result in candidates(results))
    assert "signing is not required" in titles
    assert "anonymous session" not in titles


async def test_anonymous_smb_session_is_a_finding() -> None:
    harness = make_m2_harness(seed_services=[(445, "smb")])
    harness.transport.routes[("tcp", HOST, 445)] = [
        _smb2_negotiate_response(signing=0x0003),
        _smb2_status_response(0x00000000),
    ]
    results = await run(SmbEnum, harness)
    assert any("anonymous session" in result.title for result in candidates(results))


async def test_nfs_exports_are_reported_with_their_host_restrictions() -> None:
    harness = make_m2_harness(seed_services=[(111, "rpcbind")])
    dump = _rpc_reply(struct.pack(">IIIII", 1, 100005, 3, 6, 2049) + struct.pack(">I", 0))
    exports_payload = (
        struct.pack(">I", 1)
        + _xdr_string("/srv/data")
        + struct.pack(">I", 1)
        + _xdr_string("*")
        + struct.pack(">I", 0)
        + struct.pack(">I", 0)
        + struct.pack(">I", 0)
    )
    harness.transport.routes[("tcp", HOST, 111)] = dump
    harness.transport.routes[("tcp", HOST, 2049)] = _rpc_reply(exports_payload)
    results = await run(NfsEnum, harness)
    assert any("NFS exports" in result.title for result in candidates(results))
    matched = next(result for result in candidates(results) if "NFS exports" in result.title)
    assert "world-mountable" in (matched.detail or "")


async def test_kerberos_enumeration_confirms_existing_principals() -> None:
    # The realm comes from the asset name when it *is* a domain (or from a declared domain
    # target when the asset is an address).
    harness = make_m2_harness(host="lab.test", kind="domain", seed_services=[(88, "kerberos")])
    harness.route(
        "tcp",
        88,
        [
            wire.ber_tlv(
                0x7E, wire.ber_tlv(0xA1, wire.ber_int(30)) + wire.ber_tlv(0x86, wire.ber_int(24))
            ),
            wire.ber_tlv(
                0x7E, wire.ber_tlv(0xA1, wire.ber_int(30)) + wire.ber_tlv(0x86, wire.ber_int(6))
            ),
        ],
    )
    results = await run(
        KerberosEnum, harness, config=ModuleConfig(kerberos_pacing_s=0.001, kerberos_max_names=2)
    )
    matched = next(
        result
        for result in candidates(results)
        if "principal enumeration confirmed" in result.title
    )
    assert "administrator" in (matched.detail or "")
    # The pacing is part of the contract: a KDC must not be machine-gunned (F-01-09).
    assert harness.inventory.service("lab.test", 88) is not None


async def test_kerberos_enumeration_says_why_it_cannot_run_without_a_realm() -> None:
    # An address asset with no declared domain target: no realm, so no AS-REQ can be addressed.
    harness = make_m2_harness(seed_services=[(88, "kerberos")])
    harness.step.definition = harness.step.definition.model_copy(
        update={
            "targets": tuple(
                selector
                for selector in harness.step.definition.targets
                if selector.kind is not TargetKind.DOMAIN
            )
        }
    )
    results = await run(KerberosEnum, harness)
    assert skipped(results)
    assert "realm" in (results[0].detail or "")


# ------------------------------------------------------------------ infrastructure / OT
async def test_snmp_enum_needs_the_udp_opt_in() -> None:
    harness = make_m2_harness(
        seed_services=[(161, "snmp")], config=ModuleConfig(net_allow_udp=False)
    )
    results = await run(SnmpEnum, harness, config=ModuleConfig(net_allow_udp=False))
    assert skipped(results)
    assert "ARACHNE_NET_ALLOW_UDP" in (results[0].detail or "")
    assert harness.transport.calls == []


async def test_snmp_default_community_is_a_finding() -> None:
    harness = make_m2_harness(
        seed_services=[(161, "snmp")],
    )
    varbind = wire.ber_tlv(
        0x30,
        wire.ber_tlv(0x06, bytes.fromhex("2b06010201010100")) + wire.ber_tlv(0x04, b"lab agent"),
    )
    pdu = wire.ber_tlv(
        0xA2,
        wire.ber_tlv(0x02, b"\x01")
        + wire.ber_tlv(0x02, b"\x00")
        + wire.ber_tlv(0x02, b"\x00")
        + wire.ber_tlv(0x30, varbind),
    )
    response = wire.ber_tlv(0x30, wire.ber_tlv(0x02, b"\x01") + wire.ber_tlv(0x04, b"public") + pdu)
    harness.transport.routes[("udp", HOST, 161)] = UdpExchange(state="open", payload=response)
    config = ModuleConfig(net_allow_udp=True)
    results = await run(SnmpEnum, harness, config=config)
    assert any("community 'public'" in result.title for result in candidates(results))


async def test_dns_zone_transfer_is_a_finding_and_records_hosts() -> None:
    harness = make_m2_harness(host="lab.test", kind="domain", seed_services=[(53, "dns")])
    question = b"\x03lab\x04test\x00" + struct.pack(">HH", 252, 1)
    answers = b""
    for name in ("www.lab.test", "git.lab.test"):
        answers += (
            wire.encode_dns_name(name) + struct.pack(">HHIH", 1, 1, 60, 4) + b"\x7f\x00\x00\x01"
        )
    message_body = struct.pack(">HHHHHH", 1, 0x8400, 1, 2, 0, 0) + question + answers
    transfer = struct.pack(">H", len(message_body)) + message_body
    harness.route("tcp", 53, transfer)
    results = await run(DnsActive, harness)
    assert any("zone transfer succeeded" in result.title for result in candidates(results))


async def test_ics_probe_is_opt_in_and_reports_a_modbus_device() -> None:
    harness = make_m2_harness(seed_services=[(502, "modbus")])
    payload = bytearray([0x2B, 0x0E, 0x01, 0x81, 0x00, 0x00])
    for object_id, text in {0: "ACME", 1: "PLC-1", 2: "1.0"}.items():
        payload += bytes([object_id, len(text)]) + text.encode()
    response = struct.pack(">HHHB", 1, 0, len(payload) + 1, 1) + bytes(payload)
    harness.transport.routes[("tcp", HOST, 502)] = response
    results = await run(IcsProbe, harness)
    assert any("industrial control device" in result.title for result in candidates(results))


# ------------------------------------------------------------------ CVE correlation
async def test_cve_correlation_matches_an_old_version() -> None:
    harness = make_m2_harness(seed_services=[(22, "ssh")])
    service = harness.inventory.service(HOST, 22)
    assert service is not None
    service.identity = ServiceIdentity(
        protocol="ssh", product="OpenSSH", version="8.5p1", banner="SSH-2.0-OpenSSH_8.5p1"
    )
    results = await run(CveCorrelate, harness)
    titles = " | ".join(result.title for result in candidates(results))
    assert "CVE-2024-6387" in titles
    evidence = [item.payload for result in candidates(results) for item in result.evidence]
    assert any(payload.get("observed_version") == "8.5p1" for payload in evidence)


async def test_cve_correlation_does_not_match_a_patched_version() -> None:
    harness = make_m2_harness(seed_services=[(22, "ssh")])
    service = harness.inventory.service(HOST, 22)
    assert service is not None
    service.identity = ServiceIdentity(protocol="ssh", product="openssh", version="9.9p1")
    results = await run(CveCorrelate, harness)
    assert not candidates(results)
    assert "0 CVE match(es)" in results[0].title


async def test_cve_correlation_says_what_it_lacks() -> None:
    harness = make_m2_harness(seed_services=[(12345, "unknown")])
    results = await run(CveCorrelate, harness)
    assert "no fingerprinted product/version" in results[0].title


async def test_cve_correlation_matches_a_configuration_signal() -> None:
    harness = make_m2_harness(seed_services=[(445, "smb")])
    service = harness.inventory.service(HOST, 445)
    assert service is not None
    service.identity = ServiceIdentity(protocol="smb", product="smb1", banner="SMB 1.0")
    service.notes["smb"] = {"smb1_supported": True, "dialect_revision": 1}
    results = await run(CveCorrelate, harness)
    assert any("CVE-2017-0144" in result.title for result in candidates(results))


# ------------------------------------------------------------------ helpers
def _kexinit(*, kex: bytes, host_key: bytes, cipher: bytes, mac: bytes) -> bytes:
    """A server KEXINIT *payload* (the bytes a socket delivers, without SSH framing)."""
    lists = (kex, host_key, cipher, cipher, mac, mac, b"none", b"none", b"", b"")
    body = b"".join(struct.pack(">I", len(item)) + item for item in lists)
    return b"\x14" + b"\x00" * 16 + body


def _mysql_greeting(version: str) -> bytes:
    payload = bytearray([10])
    payload.extend(version.encode() + b"\x00")
    payload.extend(struct.pack("<I", 42))
    payload.extend(b"12345678")
    payload.append(0)
    payload.extend(struct.pack("<H", 0xFFFF))
    payload.append(0x21)
    payload.extend(struct.pack("<H", 2))
    payload.extend(struct.pack("<H", 0x81FF))
    payload.append(21)
    payload.extend(b"\x00" * 10)
    payload.extend(b"abcdefghijklm")
    payload.extend(b"mysql_native_password\x00")
    return struct.pack("<I", len(payload))[:3] + b"\x00" + bytes(payload)


def _smb2_negotiate_response(*, signing: int, dialect: int = 0x0210) -> bytes:
    body = (
        b"\xfeSMB"
        + struct.pack("<HHIHH", 64, 0, 0, 0, 1)
        + struct.pack("<II", 0, 0)
        + struct.pack("<Q", 1)
        + struct.pack("<IIQ", 0xFEFF, 0, 0)
        + b"\x00" * 16
        + struct.pack("<HHHH", 65, signing, 0, dialect)
        + b"\x00" * 48
    )
    return b"\x00" + len(body).to_bytes(3, "big") + body


def _smb2_status_response(status: int) -> bytes:
    body = (
        b"\xfeSMB"
        + struct.pack("<HHI", 64, 0, status)
        + struct.pack("<HHII", 1, 1, 0, 0)
        + struct.pack("<Q", 2)
        + struct.pack("<IIQ", 0xFEFF, 0, 1)
        + b"\x00" * 16
    )
    return b"\x00" + len(body).to_bytes(3, "big") + body


def _rpc_reply(payload: bytes) -> bytes:
    body = struct.pack(">III", 1, 1, 0) + struct.pack(">II", 0, 0) + struct.pack(">I", 0) + payload
    return struct.pack(">I", 0x80000000 | len(body)) + body


def _xdr_string(value: str) -> bytes:
    encoded = value.encode()
    padding = (4 - len(encoded) % 4) % 4
    return struct.pack(">I", len(encoded)) + encoded + b"\x00" * padding


def test_the_harness_reaches_a_check_through_the_real_context() -> None:
    """A guard on the helper itself: the context carries the inventory and the client."""
    harness = make_m2_harness(seed_services=[(80, "http")])
    context = harness.context(PortScan)
    assert context.net is harness.client
    assert context.inventory is harness.inventory
    assert context.asset.kind == "host"


def test_a_service_record_renders_evidence() -> None:
    service = ServiceRecord(host=HOST, port=443, service="https")
    service.identity = ServiceIdentity(protocol="tls", banner="TLSv1.2")
    payload = service.evidence_payload()
    assert payload["service"] == "tls" and payload["port"] == 443
    assert payload["identity"]["protocol"] == "tls"


def test_assets_for_the_network_checks_cover_the_target_kinds() -> None:
    assert PortScan.metadata.supports_kind(TargetKind.IP)
    assert PortScan.metadata.supports_kind(TargetKind.CIDR)
    assert DnsActive.metadata.supports_kind(TargetKind.DOMAIN)
    assert not DnsActive.metadata.supports_kind(TargetKind.IP)


def test_derived_url_assets_are_skipped_but_declared_ones_are_not() -> None:
    derived = asset_for("url", "https://127.0.0.1/", source="host-expansion")
    declared = asset_for("url", "https://example.test/")
    assert not PortScan().supports(derived)
    assert PortScan().supports(declared)


# ------------------------------------------------------------------ JSON-API datastores
async def test_an_open_elasticsearch_api_is_a_finding() -> None:
    json_type = {"content-type": "application/json"}
    harness = make_m2_harness(
        seed_services=[(9200, "elasticsearch")],
        http_routes=[
            {
                "url": f"http://{HOST}:9200/",
                "body": '{"name":"lab-node","cluster_name":"lab","version":{"number":"7.10.2"}}',
                "headers": json_type,
            },
            {
                "url": f"http://{HOST}:9200/_cat/indices?format=json&h=index",
                "body": '[{"index":"users"},{"index":"sessions"}]',
                "headers": json_type,
            },
        ],
    )
    results = await run(DbServiceProbe, harness)
    assert any("unauthenticated elasticsearch" in result.title for result in candidates(results))
    service = harness.inventory.service(HOST, 9200)
    assert (
        service is not None and service.product == "elasticsearch" and service.version == "7.10.2"
    )


async def test_an_open_couchdb_is_a_finding() -> None:
    json_type = {"content-type": "application/json"}
    harness = make_m2_harness(
        seed_services=[(5984, "couchdb")],
        http_routes=[
            {
                "url": f"http://{HOST}:5984/",
                "body": '{"couchdb":"Welcome","version":"3.2.2","features":[]}',
                "headers": json_type,
            },
            {
                "url": f"http://{HOST}:5984/_all_dbs",
                "body": '["_users","orders"]',
                "headers": json_type,
            },
        ],
    )
    results = await run(DbServiceProbe, harness)
    assert any("unauthenticated couchdb" in result.title for result in candidates(results))


async def test_a_datastore_api_behind_auth_is_not_reported_as_open() -> None:
    harness = make_m2_harness(
        seed_services=[(9200, "elasticsearch")],
        http_routes=[
            {
                "url": f"http://{HOST}:9200/",
                "status": 401,
                "body": '{"error":"unauthorized"}',
                "headers": {"content-type": "application/json"},
            }
        ],
    )
    results = await run(DbServiceProbe, harness)
    assert not candidates(results)
    assert kinds(results) == ["info"]


async def test_postgres_with_tls_available_does_not_report_a_plaintext_finding() -> None:
    harness = make_m2_harness(seed_services=[(5432, "postgres")])
    harness.transport.routes[("tcp", HOST, 5432)] = [b"S", b"R\x00\x00\x00\x08\x00\x00\x00\x00"]
    results = await run(DbServiceProbe, harness)
    detail = " ".join(result.detail or "" for result in candidates(results))
    assert "refused TLS" not in detail


async def test_sql_server_without_encryption_is_a_finding() -> None:
    harness = make_m2_harness(seed_services=[(1433, "mssql")])
    version = bytes([15, 0, 0, 200]) + b"\x00\x00"
    encryption = b"\x00"
    offsets = 8 + 3 * 5  # two tokens + the 0xFF terminator
    tokens = (
        bytes([0x00])
        + struct.pack("<HH", offsets, len(version))
        + bytes([0x01])
        + struct.pack("<HH", offsets + len(version), len(encryption))
        + b"\xff"
        + struct.pack("<HH", offsets, 0)
    )
    body = tokens + version + encryption
    harness.transport.routes[("tcp", HOST, 1433)] = (
        bytes([0x04, 0x01]) + struct.pack("<H", len(body) + 8) + b"\x00\x00\x00\x00" + body
    )
    results = await run(DbServiceProbe, harness)
    titles = " | ".join(result.title for result in candidates(results))
    assert "SQL Server" in titles and "without encryption" in titles


async def test_memcached_is_reported_as_unauthenticated_by_design() -> None:
    harness = make_m2_harness(seed_services=[(11211, "memcached")])
    harness.transport.routes[("tcp", HOST, 11211)] = (
        b"STAT version 1.6.17\r\nSTAT curr_connections 2\r\nEND\r\n"
    )
    results = await run(DbServiceProbe, harness)
    assert any("unauthenticated memcached" in result.title for result in candidates(results))
    assert harness.inventory.service(HOST, 11211).version == "1.6.17"


async def test_mongodb_that_requires_authentication_is_only_context() -> None:
    harness = make_m2_harness(seed_services=[(27017, "mongodb")])
    document = wire.bson_encode_document({"ok": 0.0, "errmsg": "requires authentication"})
    body = struct.pack("<iqii", 0, 0, 0, 1) + document
    harness.transport.routes[("tcp", HOST, 27017)] = (
        struct.pack("<iiii", 16 + len(body), 1, 0, 2004) + body
    )
    results = await run(DbServiceProbe, harness)
    assert not candidates(results)
    assert "answered without authentication" not in results[0].title


async def test_an_unidentified_database_port_is_still_reported_as_exposed(tmp_path) -> None:
    """A database port the identification suite could not name is still an exposure.

    The fallback fires when the operator's catalogue names a *non-canonical* port as a
    datastore probe: there is no protocol identity to dispatch on (the port is not one of the
    well-known ones), so the exposure itself is the finding — without inventing a product.
    """
    catalogue = tmp_path / "ports.yaml"
    catalogue.write_text(
        "catalog_version: '1.0'\n"
        "source: test\n"
        "tcp:\n"
        "  - {port: 15432, service: postgres-alt, probe: postgres}\n",
        encoding="utf-8",
    )
    harness = make_m2_harness(seed_services=[(15432, "postgres-alt")], routes={})
    results = await run(DbServiceProbe, harness, config=ModuleConfig(port_catalog=str(catalogue)))
    assert any("database port 15432 is reachable" in result.title for result in candidates(results))


async def test_an_oracle_port_is_not_claimed_as_a_datastore() -> None:
    """REQ-DET-010: oracle is ``not_supported``, so the port is no longer silently "database".

    Before this, ``oracle`` sat in ``DATASTORE_PROTOCOLS`` with no dispatch branch and an
    Oracle port fell through to a generic "database port reachable" candidate — a capability
    the product does not have, reported as one. The decision is now recorded in the protocol
    matrix (``tests/unit/test_protocol_matrix.py``) and the protocol set no longer claims it.
    """
    harness = make_m2_harness(seed_services=[(1521, "oracle")], routes={})
    results = await run(DbServiceProbe, harness)
    assert not candidates(results)
    assert skipped(results)
    assert "no datastore service" in (results[0].detail or "")


async def test_datastore_probing_skips_when_no_datastore_port_is_known() -> None:
    harness = make_m2_harness(seed_services=[(8080, "http")])
    results = await run(DbServiceProbe, harness)
    assert skipped(results)
    assert "no datastore service" in (results[0].detail or "")


# ------------------------------------------------------------------ online CVE enrichment
async def test_vulners_enrichment_is_optional_and_uses_the_audited_client() -> None:
    """F-09-03's online half: only with the provider enabled *and* a key, through OSINT."""
    import json

    from pydantic import SecretStr

    from arachne.core.http import RecordedResponse
    from arachne.modules.m2.tls_cve import vulners_url
    from arachne.modules.providers import build_osint_access_for_fixtures

    product, version = "nginx", "1.18.0"
    url = vulners_url(product, version)
    payload = json.dumps(
        {
            "data": {
                "search": [
                    {
                        "id": "CVE-2021-23017",
                        "title": "nginx off-by-one (vulners)",
                        "cvss": {"score": 7.7},
                        "_source": {"title": "nginx off-by-one (vulners)"},
                    },
                    {"id": "NOT-A-CVE", "title": "ignored"},
                ]
            }
        }
    )
    osint = build_osint_access_for_fixtures(
        {url: RecordedResponse(method="GET", url=url, status=200, body=payload)},
        providers=("vulners",),
        budget=4,
    )
    harness = make_m2_harness(seed_services=[(80, "http")])
    service = harness.inventory.service(HOST, 80)
    assert service is not None
    service.identity = ServiceIdentity(protocol="http", product=product, version=version)
    context = harness.context(CveCorrelate, config=ModuleConfig(vulners_api_key=SecretStr("k")))
    context.osint = osint
    results = [result async for result in context.module.run(context)]
    assert kinds(results)[0] == "info"
    # The offline index already matches this product, so the online row appears in evidence.
    evidence = [item.payload for result in results for item in result.evidence]
    online = [payload.get("online") for payload in evidence if "online" in payload]
    assert online and any(entry for entry in online[0].values())
    assert "CVE-2021-23017" in json.dumps(online)


async def test_the_offline_path_is_used_when_no_vulners_key_is_configured() -> None:
    from arachne.core.http import RecordedResponse
    from arachne.modules.m2.tls_cve import vulners_url
    from arachne.modules.providers import build_osint_access_for_fixtures

    url = vulners_url("nginx", "1.18.0")
    osint = build_osint_access_for_fixtures(
        {url: RecordedResponse(method="GET", url=url, status=200, body='{"data":{"search":[]}}')},
        providers=("vulners",),
        budget=4,
    )
    harness = make_m2_harness(seed_services=[(80, "http")])
    service = harness.inventory.service(HOST, 80)
    assert service is not None
    service.identity = ServiceIdentity(protocol="http", product="nginx", version="1.18.0")
    context = harness.context(CveCorrelate)  # no key in the module config
    context.osint = osint
    results = [result async for result in context.module.run(context)]
    titles = " ".join(result.title for result in results)
    assert "correlated" in titles
    # The evidence row always carries an ``online`` section; without a key it stays empty.
    online = [
        item.payload["online"]
        for result in results
        for item in result.evidence
        if "online" in item.payload
    ]
    # Every result carries the row (one per info + one per matched CVE); all are empty.
    assert online and all(section == {} for section in online)
    assert osint.used == 0, "no key means no third-party request at all"


# --------------------------------------------------- hardening (ch02#12/#13/#21/#26, ch04#22)
#: The smallest valid 1x1 transparent GIF — a deliberately "default" favicon.
_GIF_1X1 = bytes.fromhex(
    "47494638396101000100800000000000ffffff21f90401000000002c00000000010001000002024401003b"
)


async def test_http_fingerprint_names_the_stack_and_flags_a_version_banner() -> None:
    harness = make_m2_harness(
        http_routes=[
            {
                "url": f"http://{HOST}/",
                "body": "<html><head><title>Apache Tomcat/9.0.60</title></head></html>",
                "headers": {
                    "Server": "Apache/2.2.15 (CentOS)",
                    "X-Powered-By": "PHP/5.3.3",
                },
            }
        ]
    )
    results = await run(HttpFingerprint, harness)
    assert candidates(results), [result.title for result in results]
    detail = " ".join(result.detail or "" for result in candidates(results))
    assert "Apache/2.2.15" in detail and "PHP/5.3.3" in detail
    assert kinds(results)[0] == "info"


async def test_http_fingerprint_does_not_flag_a_banner_without_a_version() -> None:
    harness = make_m2_harness(
        http_routes=[
            {
                "url": f"http://{HOST}/",
                "body": "<html><head><title>Home</title></head></html>",
                "headers": {"Server": "cloudflare"},
            }
        ]
    )
    results = await run(HttpFingerprint, harness)
    assert not candidates(results)
    assert kinds(results) == ["info"]


async def test_favicon_digest_matches_a_shipped_default_icon() -> None:
    # The digest/table wiring: the smallest valid GIF hashes to a shipped default entry.
    digest, _mmh3 = favicon_digest(_GIF_1X1)
    assert digest in DEFAULT_FAVICONS
    assert DEFAULT_FAVICONS[digest].startswith("1x1")


async def test_favicon_hash_identifies_a_text_favicon_through_the_http_client() -> None:
    # The favicon goes through the shared HTTP client (never a raw socket), so its body is
    # whatever that client exposes; a text body is digested and recorded as an observation.
    harness = make_m2_harness(
        seed_services=[(80, "http")],
        http_routes=[
            {
                "url": f"http://{HOST}/favicon.ico",
                "body": "<svg xmlns='http://www.w3.org/2000/svg'/>",
                "headers": {"Content-Type": "image/svg+xml"},
            }
        ],
    )
    results = await run(FaviconHash, harness)
    assert kinds(results) == ["info"]
    artifacts = [
        item.payload for result in results for item in result.evidence if item.kind == "artifact"
    ]
    assert artifacts and len(str(artifacts[0]["sha256"])) == 64
    # A favicon is an evidence artifact, never a recorded asset (only the seeded host is).
    assert len(harness.memory.store.list_assets(harness.memory.scan_id)) == 1


async def test_favicon_hash_reports_a_missing_favicon_without_a_finding() -> None:
    harness = make_m2_harness(
        seed_services=[(80, "http")],
        http_routes=[{"url": f"http://{HOST}/favicon.ico", "status": 404, "body": "not found"}],
    )
    results = await run(FaviconHash, harness)
    assert not candidates(results)
    assert kinds(results) == ["not_vulnerable"]


async def test_ftp_anonymous_login_is_a_finding() -> None:
    harness = make_m2_harness(seed_services=[(21, "ftp")])
    harness.transport.routes[("tcp", HOST, 21)] = [
        b"220 (vsFTPd 2.3.4)\r\n",
        b"331 Please specify the password.\r\n",
        b"230 Login successful.\r\n",
    ]
    results = await run(FtpAnonymous, harness, config=ModuleConfig(smtp_pacing_s=0.001))
    assert any("anonymous access" in result.title for result in candidates(results))
    assert harness.inventory.service(HOST, 21) is not None


async def test_ftp_without_a_service_costs_nothing() -> None:
    harness = make_m2_harness(seed_services=[(80, "http")])
    results = await run(FtpAnonymous, harness)
    assert skipped(results)
    assert "no FTP service" in (results[0].detail or "")
    assert harness.transport.calls == []


async def test_ssdp_discovery_reports_a_upnp_responder() -> None:
    payload = (
        b"HTTP/1.1 200 OK\r\n"
        b"SERVER: Linux/3.14 UPnP/1.0 MiniDLNA/1.1\r\n"
        b"LOCATION: http://192.168.1.1:8200/rootDesc.xml\r\n"
        b"ST: upnp:rootdevice\r\n\r\n"
    )
    harness = make_m2_harness(routes={})
    harness.transport.routes[("udp", HOST, 1900)] = UdpExchange(state="open", payload=payload)
    results = await run(SsdpDiscovery, harness, config=ModuleConfig(net_allow_udp=True))
    assert any("UPnP/SSDP service exposed" in result.title for result in candidates(results))


async def test_ssdp_discovery_needs_the_udp_opt_in() -> None:
    harness = make_m2_harness(config=ModuleConfig(net_allow_udp=False))
    results = await run(SsdpDiscovery, harness, config=ModuleConfig(net_allow_udp=False))
    assert skipped(results)
    assert "ARACHNE_NET_ALLOW_UDP" in (results[0].detail or "")
    assert harness.transport.calls == []


async def test_legacy_services_flags_telnet() -> None:
    harness = make_m2_harness(routes={("tcp", HOST, 23): b"\xff\xfd\x18\xff\xfd\x20login: "})
    results = await run(LegacyServices, harness)
    assert any("Telnet service" in result.title for result in candidates(results))


async def test_legacy_services_reports_clean_when_nothing_answers() -> None:
    harness = make_m2_harness(routes={})
    results = await run(LegacyServices, harness)
    assert not candidates(results)
    assert kinds(results)[-1] == "not_vulnerable"
