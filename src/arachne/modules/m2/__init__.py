"""M2 · Network & Services .

M2 turns "some hostnames and ranges" into a precise inventory of live hosts, open ports,
services, versions and protocol postures — the inventory every later module and the CVE
correlation consume. Its checks split into four layers that run in order inside the
``discovery`` pipeline step (``core.planner.MODULE_STEP``):

1. **reachability** — :mod:`arachne.modules.m2.discovery` (``host-discovery``, ``port-scan``,
   ``os-fingerprint``, ``service-fingerprint``);
2. **protocol posture** — :mod:`~arachne.modules.m2.tls_cve` (``tls-deep-scan``),
   :mod:`~arachne.modules.m2.remote` (SSH, SMTP, RDP/VNC),
   :mod:`~arachne.modules.m2.datastores` (databases and NoSQL stores),
   :mod:`~arachne.modules.m2.directory` (SMB, NFS, LDAP, Kerberos),
   :mod:`~arachne.modules.m2.netinfra` (SNMP, active DNS, ICS);
3. **correlation** — ``cve-correlate``, also in :mod:`~arachne.modules.m2.tls_cve`.

======================================  ==========  ==========================================
check                                    ref         what it establishes
======================================  ==========  ==========================================
``m2.host-discovery``                    ch02#1-4    which addresses are alive (ICMP + TCP)
``m2.port-scan``                         ch02#4-7    open TCP ports over a top-ports policy
``m2.os-fingerprint``                    ch02#8      best-effort OS family (TTL + banners)
``m2.service-fingerprint``               ch02#9-10   product/version per open port
``m2.http-fingerprint``                  ch02#12     HTTP(S) stack from one response
``m2.favicon-hash``                      ch02#13     /favicon.ico digest vs default icons
``m2.tls-deep-scan``                     ch02#14     protocols, ciphers, certificate, trust
``m2.snmp-enum``                         ch02#15     community strings and the system group
``m2.smb-enum``                          ch02#16     dialects, signing, anonymous sessions
``m2.nfs-enum``                          ch02#17     rpcbind registrations and NFS exports
``m2.ldap-enum``                         ch02#18     rootDSE and anonymous bind
``m2.kerberos-enum``                     ch02#19     AS-REQ principal enumeration (paced)
``m2.smtp-enum``                         ch02#20     EHLO capabilities, VRFY/EXPN/RCPT
``m2.ftp-anonymous``                     ch02#21     anonymous FTP login and cleartext banner
``m2.db-service-probe``                  ch02#22-23  DBMS handshakes, NoSQL exposure
``m2.ssh-enum``                          ch02#24     SSH version and algorithm lists
``m2.rdp-vnc-detect``                    ch02#25     RDP NLA posture, VNC security types
``m2.ssdp-discovery``                    ch02#26     UPnP/SSDP multicast discovery (UDP opt-in)
``m2.ics-probe``                         ch02#27     Modbus/BACnet device discovery (opt-in)
``m2.dns-active``                        ch02#28     AXFR attempt and dictionary resolution
``m2.cve-correlate``                     ch02#29     version → CVE/EPSS correlation
``m2.legacy-services``                   ch04#22     Telnet/rlogin/finger/TFTP exposure
======================================  ==========  ==========================================

**Safety.** Every check here is active (they all contact the target) except ``cve-correlate``,
so F-01-09 applies: they need ``--active-checks`` *and* an attestation that authorizes active
checks, and a plan withholds them otherwise. On top of that gate, UDP probing and the ICS
check are opt-in even among the active checks. The credential-verification techniques of
research ch02#29-30 (default-credential spraying, password spraying) are deliberately **not**
implemented — M2 establishes existence, never exploitable access. The one credentialed check,
``m2.smb-auth`` (S19, REQ-CREDS-004), authenticates *one operator-declared* credential from
the vault to prove or disprove that access exists; it is opt-in, active, attested, and never
guesses, sprays or reuses a credential across targets (ADR-240.4).

**The numbering deviation** that S3 recorded for M1 applies again: 's M2 table
numbers its references up to ``ch02#35``, while the corpus chapter (the universe the G-01
coverage matrix counts) has 30 numbered methods. The ``research_ref`` values here are the
canonical corpus numbers; the check **ids** are exactly the spec's. See ADR-080.3.
"""

from __future__ import annotations

from arachne.modules.base import Module
from arachne.modules.m2.credentialed import SmbAuth
from arachne.modules.m2.datastores import DbServiceProbe
from arachne.modules.m2.directory import KerberosEnum, LdapEnum, NfsEnum, SmbEnum
from arachne.modules.m2.discovery import (
    HostDiscovery,
    OsFingerprint,
    PortScan,
    ServiceFingerprint,
)
from arachne.modules.m2.grpc import GrpcMetadataLeak, GrpcPlaintext, GrpcReflection
from arachne.modules.m2.hardening import (
    FaviconHash,
    FtpAnonymous,
    HttpFingerprint,
    LegacyServices,
    SsdpDiscovery,
)
from arachne.modules.m2.netinfra import DnsActive, IcsProbe, SnmpEnum
from arachne.modules.m2.ot import OtProtocolProbe
from arachne.modules.m2.remote import RdpVncDetect, SmtpEnum, SshEnum
from arachne.modules.m2.tls_cve import CveCorrelate, TlsDeepScan
from arachne.modules.registry import ModuleGroup

__all__ = ["M2", "M2_CHECKS"]

#: Every M2 check class, in the order the layers above run. ``cve-correlate`` is last because
#: it consumes what the others established; the registry selects checks in this order, so the
#: tuple *is* the pipeline. The two hybrid fingerprinting checks sit with the identification
#: layer, and the three active hardening checks stay grouped after them (research ch02#12/#13,
#: #21/#26, ch04#22).
M2_CHECKS: tuple[type[Module], ...] = (
    HostDiscovery,
    PortScan,
    OsFingerprint,
    ServiceFingerprint,
    HttpFingerprint,
    FaviconHash,
    TlsDeepScan,
    SnmpEnum,
    SmbEnum,
    NfsEnum,
    LdapEnum,
    KerberosEnum,
    SmtpEnum,
    FtpAnonymous,
    DbServiceProbe,
    RdpVncDetect,
    SshEnum,
    DnsActive,
    IcsProbe,
    SsdpDiscovery,
    LegacyServices,
    CveCorrelate,
    # S19 (area CREDS, REQ-CREDS-004): the one credentialed host check — opt-in, and the only
    # M2 check that draws a credential (from the vault, through the broker).
    SmbAuth,
    # S29 detection depth expansion (area DEPTH, REQ-DEPTH-003/006): the gRPC/HTTP-2 posture
    # family (cleartext fallback, reflection, request-metadata leakage) and the read-only
    # OT/ICS protocol probe (S7comm, DNP3). The OT check is opt-in twice over.
    GrpcPlaintext,
    GrpcReflection,
    GrpcMetadataLeak,
    OtProtocolProbe,
)

#: The M2 module group . Bump the version when the check set or a check's
#: behaviour changes: scan reports record it (F-02-10).
M2 = ModuleGroup(
    id="M2",
    title="Network & Services",
    description=(
        "Host discovery, port and service scanning, protocol enumeration (TLS, SMB, NFS, "
        "LDAP, Kerberos, SMTP, SSH, RDP/VNC, SNMP, databases, ICS) and CVE correlation over "
        "the fingerprinted inventory, plus the S29 depth families: gRPC/HTTP-2 posture "
        "(cleartext h2c, server reflection, request-metadata leakage) and the read-only OT/ICS "
        "protocols (Modbus/BACnet via m2.ics-probe, S7comm and DNP3 via m2.ot-protocol-probe)."
    ),
    version="1.2.0",
    research_chapter="ch02",
    checks=M2_CHECKS,
)
