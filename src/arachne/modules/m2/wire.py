"""Wire-format encoders and parsers for M2's protocol checks (research ch. 02).

**No I/O happens here.** Every function takes or returns bytes, which is what makes the
protocol layer testable without a network and keeps the checks thin: a check decides *what*
to ask, :mod:`arachne.core.net` moves the bytes, and this module turns bytes into facts
(MBAP, RFC 1035, RFC 4511, SNMP RFC 3416, ONC RPC RFC 5531, SMB2, X.224/RDP, RFB, the
MySQL/PostgreSQL/TDS handshakes, the Redis and memcached text protocols, BSON, and the
Kerberos AS-REQ of RFC 4120).

Three properties are deliberate:

* **Bounded.** Every decoder refuses to walk past its input and every list is capped, so a
  hostile server cannot make a parser allocate or loop (a scan must survive a target that
  answers with garbage).
* **Explicit about doubt.** A parser returns ``None``/``unknown`` for anything it does not
  fully understand rather than guessing; "we could not read this" is a legitimate answer and
  a wrong fact in a report is not.
* **Framing-aware.** The length-prefixed protocols (SMB2's NetBIOS session header, DNS over
  TCP, ONC RPC record marking, X.224 TPKT) keep their framing in the same module as their
  payload encoders, because a check that has to remember "now strip four bytes" is a check
  that will eventually forget.

The ASN.1 toolkit at the top is shared by LDAP (BER), SNMP (BER) and Kerberos (DER): the
three differ in tagging conventions but not in how a length is written.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
import struct
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

__all__ = [
    "CERTIFICATE_ALERTS",
    "TLS_HANDSHAKE_NAMES",
    "BacnetDevice",
    "BerReader",
    "Dnp3Link",
    "DnsMessage",
    "LdapMessage",
    "ModbusDeviceId",
    "NtlmAuthenticate",
    "NtlmChallenge",
    "PortmapEntry",
    "RfbSecurity",
    "RpcReply",
    "S7Connection",
    "SmbNegotiate",
    "bacnet_who_is",
    "ber_int",
    "ber_len",
    "ber_tlv",
    "bson_decode_document",
    "bson_encode_document",
    "build_ldap_bind_request",
    "build_ldap_search_request",
    "build_snmp_get",
    "dnp3_crc",
    "dnp3_link_status_request",
    "dns_axfr_query",
    "dns_query",
    "dns_tcp_payload",
    "encode_dns_name",
    "kerberos_as_req",
    "kerberos_error_code",
    "md4",
    "memcached_stats",
    "memcached_values",
    "modbus_read_device_id",
    "nfs_export_list",
    "nt_owf_v2",
    "ntlm_v2_response",
    "ntlmssp_authenticate",
    "ntlmssp_negotiate",
    "parse_bacnet_i_am",
    "parse_dnp3_link",
    "parse_dns_message",
    "parse_ldap_message",
    "parse_mssql_prelogin",
    "parse_mysql_greeting",
    "parse_ntlmssp_authenticate",
    "parse_ntlmssp_challenge",
    "parse_portmap_dump",
    "parse_postgres_message",
    "parse_rfb_security",
    "parse_rfb_version",
    "parse_rpc_reply",
    "parse_s7_connection_confirm",
    "parse_smb2_negotiate",
    "parse_smb2_session_setup",
    "parse_snmp_response",
    "parse_snmp_varbinds",
    "parse_ssh_banner",
    "parse_tls_server_flight",
    "parse_tls_server_hello",
    "parse_x224_negociation",
    "postgres_ssl_request",
    "postgres_startup",
    "rdp_negociation_request",
    "redis_command",
    "rfb_client_version",
    "rpc_call",
    "rpcbind_dump_call",
    "s7_cotp_connection_request",
    "smb1_negotiate",
    "smb2_negotiate",
    "smb2_session_setup_anonymous",
    "smb2_session_setup_ntlmssp",
    "snmp_oids",
    "ssh_kexinit_probe",
    "tls_client_certificate",
    "tls_client_hello",
]

# --------------------------------------------------------------------------- ASN.1 / BER
MAX_ASN1_DEPTH = 12
MAX_ASN1_ITEMS = 8192


def ber_len(length: int) -> bytes:
    """Encode a definite length (short form, or long form for >= 128)."""
    if length < 0x80:
        return bytes([length])
    encoded = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(encoded)]) + encoded


def ber_tlv(tag: int, value: bytes) -> bytes:
    """Encode one tag-length-value triple."""
    return bytes([tag]) + ber_len(len(value)) + value


def ber_int(value: int) -> bytes:
    """DER INTEGER body for ``value`` (minimal two's-complement form)."""
    if value == 0:
        return b"\x00"
    if value > 0:
        body = value.to_bytes((value.bit_length() + 7) // 8, "big")
        return b"\x00" + body if body[0] & 0x80 else body
    length = (value.bit_length() + 8) // 8
    return value.to_bytes(length, "big", signed=True)


class BerReader:
    """A bounded BER/DER reader.

    ``read_tlv`` returns ``(tag, value)`` and raises :class:`ValueError` on a truncated or
    over-long element — callers catch that once, at the protocol boundary, and turn it into
    "the server sent something unparseable".
    """

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    def __len__(self) -> int:
        return len(self.data) - self.pos

    @property
    def eof(self) -> bool:
        return self.pos >= len(self.data)

    def read_byte(self) -> int:
        if self.eof:
            raise ValueError("unexpected end of BER data")
        value = self.data[self.pos]
        self.pos += 1
        return value

    def read(self, count: int) -> bytes:
        if count < 0 or self.pos + count > len(self.data):
            raise ValueError("BER element runs past the end of the buffer")
        chunk = self.data[self.pos : self.pos + count]
        self.pos += count
        return chunk

    def read_length(self) -> int:
        first = self.read_byte()
        if first < 0x80:
            return first
        count = first & 0x7F
        if count == 0 or count > 4:
            raise ValueError("unsupported BER length encoding")
        return int.from_bytes(self.read(count), "big")

    def read_tlv(self) -> tuple[int, bytes]:
        tag = self.read_byte()
        length = self.read_length()
        return tag, self.read(length)

    def read_all(self, *, limit: int = MAX_ASN1_ITEMS) -> list[tuple[int, bytes]]:
        items: list[tuple[int, bytes]] = []
        while not self.eof and len(items) < limit:
            items.append(self.read_tlv())
        return items

    def read_int(self) -> int:
        tag, body = self.read_tlv()
        if tag & 0x1F != 0x02:
            raise ValueError(f"expected INTEGER, got tag 0x{tag:02x}")
        return int.from_bytes(body, "big", signed=bool(body and body[0] & 0x80))

    def read_octet_string(self) -> bytes:
        tag, body = self.read_tlv()
        if tag & 0x1F != 0x04:
            raise ValueError(f"expected OCTET STRING, got tag 0x{tag:02x}")
        return body


# --------------------------------------------------------------------------- SSH (ch02#24)
_SSH_BANNER_RE = None  # compiled lazily in parse_ssh_banner (avoids a module-level regex import)


def parse_ssh_banner(banner: str) -> dict[str, Any] | None:
    """Parse ``SSH-2.0-OpenSSH_9.8p1 Debian-3`` into protocol, software and comment."""
    import re

    if not banner:
        return None
    line = banner.strip().splitlines()[0].strip() if banner.strip() else ""
    match = re.match(r"^SSH-(2\.0|1\.99|1\.5)-([A-Za-z0-9._\-]+)(?:\s+(.*))?$", line)
    if match is None:
        return None
    software = match.group(2)
    product, _, version = software.partition("_")
    return {
        "banner": line,
        "protocol": match.group(1),
        "software": software,
        "product": product,
        "version": version or None,
        "comment": (match.group(3) or "").strip() or None,
    }


def ssh_kexinit_probe() -> bytes:
    """A minimal, syntactically valid SSH_MSG_KEXINIT (RFC 4253 §7.1).

    The scanner advertises only ``none`` algorithms and a "bogus" first kex: enough for a
    server to answer with its own KEXINIT, which is the only way to learn the algorithm
    lists without completing a key exchange. It never offers an algorithm a real client
    would use, so the exchange cannot end in a usable session.
    """
    name_lists = (
        b"bogus",  # kex algorithms
        b"ssh-rsa",  # host key algorithms
        b"none",  # encryption c2s
        b"none",  # encryption s2c
        b"none",  # mac c2s
        b"none",  # mac s2c
        b"none",  # compression c2s
        b"none",  # compression s2c
        b"",  # languages c2s
        b"",  # languages s2c
    )
    body = b"".join(struct.pack(">I", len(item)) + item for item in name_lists)
    payload = b"\x14" + _random_bytes(16) + body
    padding = _ssh_padding(len(payload) + 5)
    packet_length = len(payload) + 1 + padding
    return struct.pack(">IB", packet_length, padding) + payload + bytes(padding)


def _random_bytes(count: int) -> bytes:
    """Unpredictable-enough filler for protocol handshakes (never a secret).

    Probe nonces, session ids and paddings only need to be *different per connection*: a
    server that saw the same bytes twice could fingerprint the scanner, but nothing here is
    a credential, so ``os.urandom`` is used directly here.
    """
    return os.urandom(count)


def _probe_id(bits: int = 16) -> int:
    """A per-probe protocol identifier (DNS txid, RPC xid, Kerberos nonce).

    Randomised so two probes from the same scan are not trivially correlated, and bounded to
    ``bits`` bits the way each protocol's field expects. Not a secret: the point is
    uniqueness, not unpredictability against an adversary.
    """
    return int(int.from_bytes(os.urandom((bits + 7) // 8), "big") % (2**bits))


def _ssh_padding(body_length: int) -> int:
    """RFC 4253: total (packet_length + padding) must be a multiple of 8, padding >= 4."""
    padding = 8 - (body_length % 8)
    return padding if padding >= 4 else padding + 8


def parse_ssh_kexinit(data: bytes) -> dict[str, tuple[str, ...]] | None:
    """Extract the algorithm name-lists from a KEXINIT packet body."""
    if len(data) < 17 or data[0] != 0x14:
        return None
    reader = _ByteReader(data[17:])
    keys = (
        "kex_algorithms",
        "host_key_algorithms",
        "encryption_c2s",
        "encryption_s2c",
        "mac_c2s",
        "mac_s2c",
        "compression_c2s",
        "compression_s2c",
    )
    raw_lists: dict[str, tuple[bytes, ...]] = {}
    try:
        for key in keys:
            raw = reader.read_uint32_prefixed()
            raw_lists[key] = tuple(part for part in raw.split(b",") if part)
    except ValueError:
        return None
    return {
        key: tuple(item.decode("ascii", "replace") for item in value)
        for key, value in raw_lists.items()
    }


class _ByteReader:
    """Bounds-checked big-endian reader for the length-prefixed protocols."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        self.pos = 0

    @property
    def remaining(self) -> int:
        return len(self.data) - self.pos

    def read(self, count: int) -> bytes:
        if count < 0 or self.pos + count > len(self.data):
            raise ValueError("read past the end of the buffer")
        chunk = self.data[self.pos : self.pos + count]
        self.pos += count
        return chunk

    def read_uint8(self) -> int:
        return self.read(1)[0]

    def read_uint16(self) -> int:
        return int(struct.unpack(">H", self.read(2))[0])

    def read_uint24(self) -> int:
        return int.from_bytes(self.read(3), "big")

    def read_uint32(self) -> int:
        return int(struct.unpack(">I", self.read(4))[0])

    def read_uint32_prefixed(self) -> bytes:
        return self.read(self.read_uint32())

    # Little-endian variants. SMB2 and TDS are little-endian protocols while DNS, SSH, ONC
    # RPC and XDR are big-endian; keeping the two families explicit at the call site is what
    # stops a parser from silently reading a 16-bit field backwards.
    def read_le16(self) -> int:
        return int(struct.unpack("<H", self.read(2))[0])

    def read_le32(self) -> int:
        return int(struct.unpack("<I", self.read(4))[0])

    def read_le64(self) -> int:
        return int(struct.unpack("<Q", self.read(8))[0])


# --------------------------------------------------------------------------- DNS (ch02#28)
_DNS_TYPES = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "SOA": 6,
    "PTR": 12,
    "MX": 15,
    "TXT": 16,
    "AAAA": 28,
    "SRV": 33,
    "AXFR": 252,
    "ANY": 255,
}
_DNS_RCODE = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
    9: "NOTAUTH",
    10: "NOTZONE",
}


@dataclass(frozen=True, slots=True)
class DnsMessage:
    """A decoded DNS message (only the parts M2 acts on)."""

    rcodes: str
    id: int
    flags: int
    answer_count: int
    authority_count: int
    additionals: int
    truncated: bool
    records: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return self.rcodes == "NOERROR"

    @property
    def rcode(self) -> str:
        return self.rcodes


def encode_dns_name(name: str) -> bytes:
    """Encode a domain name as RFC 1035 labels (no compression)."""
    out = bytearray()
    for label in name.strip(".").split("."):
        encoded = label.encode("idna") if any(ord(ch) > 127 for ch in label) else label.encode()
        if len(encoded) > 63:
            raise ValueError(f"DNS label too long: {label!r}")
        out.append(len(encoded))
        out.extend(encoded)
    out.append(0)
    return bytes(out)


def dns_query(name: str, qtype: str = "A", *, txid: int | None = None) -> bytes:
    """A standard recursive DNS query message (UDP wire form)."""
    identifier = txid if txid is not None else _probe_id(16)
    header = struct.pack(">HHHHHH", identifier, 0x0100, 1, 0, 0, 0)
    question = encode_dns_name(name) + struct.pack(">HH", _DNS_TYPES.get(qtype.upper(), 1), 1)
    return header + question


def dns_axfr_query(zone: str, *, txid: int | None = None) -> bytes:
    """An AXFR request (QTYPE 252) — the zone-transfer attempt of research ch02#28."""
    identifier = txid if txid is not None else _probe_id(16)
    # RD=0: a transfer is an authoritative operation, not a recursive lookup.
    header = struct.pack(">HHHHHH", identifier, 0x0000, 1, 0, 0, 0)
    question = encode_dns_name(zone) + struct.pack(">HH", 252, 1)
    return header + question


def dns_tcp_payload(message: bytes) -> bytes:
    """Prefix a DNS message with its RFC 1035 two-byte TCP length."""
    return struct.pack(">H", len(message)) + message


def parse_dns_message(data: bytes) -> DnsMessage | None:
    """Decode a DNS message header plus a bounded walk of its answer records."""
    if len(data) < 12:
        return None
    try:
        reader = _ByteReader(data)
        identifier = reader.read_uint16()
        flags = reader.read_uint16()
        questions = reader.read_uint16()
        answers = reader.read_uint16()
        authority = reader.read_uint16()
        additionals = reader.read_uint16()
        for _ in range(questions):
            _skip_dns_name(reader, data)
            reader.read(4)
        records: list[str] = []
        for index in range(answers):
            name = _read_dns_name(reader, data)
            rtype = reader.read_uint16()
            reader.read_uint16()  # class
            reader.read_uint32()  # ttl
            length = reader.read_uint16()
            body = reader.read(length)
            records.append(_dns_record_text(name, rtype, body, data))
            if index > 500:  # a hostile server must not make us spin
                break
    except ValueError:
        return None
    return DnsMessage(
        rcodes=_DNS_RCODE.get(flags & 0x0F, f"RCODE{(flags & 0x0F)}"),
        id=identifier,
        flags=flags,
        answer_count=answers,
        authority_count=authority,
        additionals=additionals,
        truncated=bool(flags & 0x0200),
        records=tuple(records),
    )


def _dns_record_text(name: str, rtype: int, body: bytes, message: bytes) -> str:
    if rtype == 1 and len(body) == 4:
        return f"{name} A {ipaddress.IPv4Address(body)}"
    if rtype == 28 and len(body) == 16:
        return f"{name} AAAA {ipaddress.IPv6Address(body)}"
    if rtype in {2, 5, 12}:
        label = {2: "NS", 5: "CNAME", 12: "PTR"}[rtype]
        try:
            return f"{name} {label} {_name_at(body, message)}"
        except ValueError:
            return f"{name} type{rtype}"
    if rtype == 6 and len(body) >= 2:
        return f"{name} SOA"
    if rtype == 15 and len(body) >= 3:
        return f"{name} MX"
    if rtype == 16 and len(body) >= 1:
        return f"{name} TXT {body[1:].decode('utf-8', 'replace')[:120]}"
    return f"{name} type{rtype}"


def _name_at(body: bytes, message: bytes) -> str:
    reader = _ByteReader(body)
    return _read_dns_name(reader, message)


def _skip_dns_name(reader: _ByteReader, message: bytes) -> None:
    _read_dns_name(reader, message)


def _read_dns_name(reader: _ByteReader, message: bytes) -> str:
    """Decode a (possibly compressed) DNS name, following at most one pointer."""
    labels: list[str] = []
    for _ in range(32):
        length = reader.read_uint8()
        if length == 0:
            break
        if length & 0xC0 == 0xC0:
            pointer = ((length & 0x3F) << 8) | reader.read_uint8()
            if pointer >= len(message):
                raise ValueError("DNS compression pointer out of range")
            inner = _ByteReader(message[pointer:])
            labels.append(_read_dns_name(inner, message))
            break
        labels.append(reader.read(length).decode("utf-8", "replace"))
    return ".".join(part for part in labels if part)


# --------------------------------------------------------------------------- LDAP (ch02#18)
MAX_LDAP_MESSAGE = 65536


@dataclass(frozen=True, slots=True)
class LdapMessage:
    """The parts of an LDAP reply M2 uses.

    ``attributes`` is populated for a ``searchResEntry`` (0x67): the rootDSE read of
    research ch02#18 exists to learn ``namingContexts`` and the supported LDAP version, so
    dropping the entry's attributes would leave the check with a result code and no answer.
    """

    message_id: int
    tag: int
    result_code: int
    matched_dn: str = ""
    diagnostic: str = ""
    object_name: str = ""
    attributes: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    raw: bytes = b""

    @property
    def is_bind_response(self) -> bool:
        return self.tag == 0x61

    @property
    def is_search_entry(self) -> bool:
        return self.tag == 0x67

    @property
    def is_search_done(self) -> bool:
        return self.tag == 0x65

    def attribute(self, name: str) -> tuple[str, ...]:
        """Case-insensitive attribute lookup (LDAP attribute names are case-insensitive)."""
        lowered = name.lower()
        for key, value in self.attributes.items():
            if key.lower() == lowered:
                return value
        return ()

    @property
    def accepted(self) -> bool:
        return self.result_code in {0, 3, 5, 6, 10}  # success, compareTrue/False, referral, sasl


_LDAP_RESULT_TEXT = {
    0: "success",
    1: "operationsError",
    2: "protocolError",
    3: "timeLimitExceeded",
    4: "sizeLimitExceeded",
    5: "compareFalse",
    6: "compareTrue",
    7: "authMethodNotSupported",
    8: "strongerAuthRequired",
    10: "referral",
    12: "unavailableCriticalExtension",
    13: "confidentialityRequired",
    14: "saslBindInProgress",
    32: "noSuchObject",
    34: "invalidDNSyntax",
    48: "inappropriateAuthentication",
    49: "invalidCredentials",
    50: "insufficientAccessRights",
    52: "unavailable",
    53: "unwillingToPerform",
    65: "objectClassViolation",
}


def ldap_result_text(code: int) -> str:
    return _LDAP_RESULT_TEXT.get(code, f"resultCode{code}")


def build_ldap_bind_request(message_id: int, dn: str = "", password: str = "") -> bytes:
    """An anonymous (or simple) bind request: LDAPMessage → BindRequest → [APPLICATION 0]."""
    version = ber_tlv(0x02, ber_int(3))
    name = ber_tlv(0x04, dn.encode())
    # context-specific primitive [0] for simple authentication
    authentication = ber_tlv(0x80, password.encode())
    bind_request = ber_tlv(0x60, version + name + authentication)
    return ber_tlv(0x30, ber_tlv(0x02, ber_int(message_id)) + bind_request)


def build_ldap_search_request(
    message_id: int,
    base_dn: str = "",
    *,
    attributes: Sequence[str] = ("namingContexts", "supportedLDAPVersion", "subschemaSubentry"),
    filter_any: bool = True,
) -> bytes:
    """A base-object search for the rootDSE (RFC 4512 §5.1), the first step of ch02#18."""
    base = ber_tlv(0x04, base_dn.encode())
    scope = ber_tlv(0x0A, ber_int(0))  # baseObject
    deref = ber_tlv(0x0A, ber_int(0))
    size_limit = ber_tlv(0x02, ber_int(64))
    time_limit = ber_tlv(0x02, ber_int(10))
    types_only = ber_tlv(0x01, b"\x00")
    # present-filter: [7] with the attribute description "objectClass"
    present = ber_tlv(0xA7, b"objectClass")
    if not filter_any:
        present = ber_tlv(0xA7, b"namingContexts")
    attrs = b"".join(ber_tlv(0x04, name.encode()) for name in attributes)
    attributes_sequence = ber_tlv(0x30, attrs)
    body = base + scope + deref + size_limit + time_limit + types_only + present
    body += attributes_sequence
    search = ber_tlv(0x63, body)
    return ber_tlv(0x30, ber_tlv(0x02, ber_int(message_id)) + search)


def parse_ldap_message(data: bytes) -> LdapMessage | None:
    """Decode an LDAPMessage envelope and its result code (``None`` when unreadable)."""
    try:
        reader = BerReader(data)
        outer_tag, outer = reader.read_tlv()
        if outer_tag != 0x30:
            return None
        message = BerReader(outer)
        message_id = message.read_int()
        tag, body = message.read_tlv()
    except ValueError:
        return None
    result_code = 0
    matched_dn = ""
    diagnostic = ""
    object_name = ""
    attributes: dict[str, tuple[str, ...]] = {}
    try:
        inner = BerReader(body)
        if tag in {0x61, 0x65, 0x64}:  # bindResponse, searchResDone, modifyResponse
            result_code = inner.read_int()
            matched = inner.read_tlv()
            matched_dn = matched[1].decode("utf-8", "replace")
            text = inner.read_tlv()
            diagnostic = text[1].decode("utf-8", "replace")
        elif tag == 0x67:  # searchResEntry: objectName + PartialAttributeList
            object_name = inner.read_octet_string().decode("utf-8", "replace")
            list_tag, list_body = inner.read_tlv()
            if list_tag == 0x30:
                entries = BerReader(list_body)
                for _ in range(256):
                    if entries.eof:
                        break
                    entry_tag, entry_body = entries.read_tlv()
                    if entry_tag != 0x30:
                        continue
                    entry = BerReader(entry_body)
                    attribute_type = entry.read_octet_string().decode("utf-8", "replace")
                    values_tag, values_body = entry.read_tlv()
                    values: list[str] = []
                    if values_tag == 0x31:
                        value_reader = BerReader(values_body)
                        for _ in range(64):
                            if value_reader.eof:
                                break
                            _value_tag, value_body = value_reader.read_tlv()
                            values.append(value_body.decode("utf-8", "replace"))
                    attributes[attribute_type] = tuple(values)
        elif tag == 0x65:  # searchResDone
            result_code = inner.read_int()
    except (ValueError, StopIteration):
        pass
    return LdapMessage(
        message_id=message_id,
        tag=tag,
        result_code=result_code,
        matched_dn=matched_dn,
        diagnostic=diagnostic,
        object_name=object_name,
        attributes=attributes,
        raw=data[:2048],
    )


# --------------------------------------------------------------------------- SNMP (ch02#15)
#: OIDs worth walking on an exposed agent (research ch02#15): system description/name,
#: uptime, interfaces, and the process table that leaks installed software versions.
SNMP_OIDS: Mapping[str, tuple[int, ...]] = {
    "sysDescr": (1, 3, 6, 1, 2, 1, 1, 1, 0),
    "sysObjectID": (1, 3, 6, 1, 2, 1, 1, 2, 0),
    "sysName": (1, 3, 6, 1, 2, 1, 1, 5, 0),
    "sysLocation": (1, 3, 6, 1, 2, 1, 1, 6, 0),
    "sysContact": (1, 3, 6, 1, 2, 1, 1, 4, 0),
    "sysUpTime": (1, 3, 6, 1, 2, 1, 1, 3, 0),
}

SNMP_ERRORS = {
    0: "noError",
    1: "tooBig",
    2: "noSuchName",
    3: "badValue",
    4: "readOnly",
    5: "genErr",
    16: "authorizationError",
}


def snmp_oids() -> Mapping[str, tuple[int, ...]]:  # pragma: no cover - alias
    return SNMP_OIDS


def _oid_body(oid: Sequence[int]) -> bytes:
    if not oid:
        raise ValueError("empty OID")
    first = oid[0] * 40 + (oid[1] if len(oid) > 1 else 0)
    body = bytearray(_base128(first))
    for part in oid[2:]:
        body.extend(_base128(part))
    return bytes(body)


def _base128(value: int) -> bytes:
    if value < 0x80:
        return bytes([value])
    chunks = [value & 0x7F]
    value >>= 7
    while value:
        chunks.append(0x80 | (value & 0x7F))
        value >>= 7
    return bytes(reversed(chunks))


def build_snmp_get(community: str, oids: Sequence[Sequence[int]], *, request_id: int = 1) -> bytes:
    """An SNMPv2c GET-Request for ``oids`` (read-only: no SET is ever built)."""
    varbinds = b"".join(
        ber_tlv(0x30, ber_tlv(0x06, _oid_body(oid)) + ber_tlv(0x05, b"")) for oid in oids
    )
    varbind_list = ber_tlv(0x30, varbinds)
    pdu_body = (
        ber_tlv(0x02, ber_int(request_id))
        + ber_tlv(0x02, ber_int(0))
        + ber_tlv(0x02, ber_int(0))
        + varbind_list
    )
    pdu = ber_tlv(0xA0, pdu_body)
    return ber_tlv(
        0x30,
        ber_tlv(0x02, ber_int(1)) + ber_tlv(0x04, community.encode()) + pdu,
    )


def parse_snmp_varbinds(varbinds: Sequence[bytes]) -> tuple[tuple[str, str], ...]:
    """``((oid, rendered value), ...)`` from the varbind bodies SNMP responses carry.

    Only the value types a read-only walk actually returns are rendered (string, integer,
    timeticks, OID, counter); anything else becomes ``repr``-style hex so nothing is
    silently dropped from the evidence.
    """
    rendered: list[tuple[str, str]] = []
    for body in varbinds:
        try:
            reader = BerReader(body)
            oid_tag, oid_body = reader.read_tlv()
            if oid_tag != 0x06:
                continue
            value_tag, value_body = reader.read_tlv()
        except ValueError:
            continue
        oid = _format_oid_body(oid_body)
        value = _render_snmp_value(value_tag, value_body)
        rendered.append((oid, value))
    return tuple(rendered)


def _format_oid_body(body: bytes) -> str:
    if not body:
        return ""
    first = body[0]
    parts = [str(first // 40), str(first % 40)]
    value = 0
    for byte in body[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(value))
            value = 0
    return ".".join(parts)


def _render_snmp_value(tag: int, body: bytes) -> str:
    if tag == 0x04:  # OCTET STRING
        return body.decode("utf-8", "replace").strip("\x00")
    if tag == 0x02:  # INTEGER
        return str(int.from_bytes(body, "big", signed=bool(body and body[0] & 0x80)))
    if tag == 0x43:  # TimeTicks
        return f"{int.from_bytes(body, 'big')} centiseconds"
    if tag == 0x41:  # Counter32
        return str(int.from_bytes(body, "big"))
    if tag == 0x46:  # Counter64
        return str(int.from_bytes(body, "big"))
    if tag == 0x40:  # IpAddress
        return ".".join(str(byte) for byte in body)
    if tag == 0x06:  # OID
        return _format_oid_body(body)
    if tag in {0x05, 0x80, 0x81, 0x82}:  # NULL / noSuch* / endOfMibView
        return {0x05: "NULL", 0x80: "noSuchObject", 0x81: "noSuchInstance", 0x82: "endOfMibView"}[
            tag
        ]
    return body.hex()


def parse_snmp_response(data: bytes) -> tuple[int, tuple[bytes, ...]] | None:
    """``(error_status, varbind_bodies)`` from an SNMP response (``None`` when unreadable)."""
    try:
        reader = BerReader(data)
        tag, body = reader.read_tlv()
        if tag != 0x30:
            return None
        message = BerReader(body)
        version = message.read_int()
        if version not in {0, 1}:  # v1/v2c answer with a plain community string
            return None
        message.read_octet_string()
        pdu_tag, pdu_body = message.read_tlv()
        if pdu_tag & 0x1F != 0x02:  # only GetResponse (0xA2) is meaningful here
            return None
        pdu = BerReader(pdu_body)
        pdu.read_int()
        error_status = pdu.read_int()
        pdu.read_int()
        list_tag, list_body = pdu.read_tlv()
        if list_tag != 0x30:
            return None
        varbinds = tuple(value for tag, value in BerReader(list_body).read_all() if tag == 0x30)
    except ValueError:
        return None
    return error_status, varbinds


# --------------------------------------------------------------------------- ONC RPC (ch02#17)
_RPC_CALL = 0
_PORTMAP_PROGRAM = 100000
_PORTMAP_DUMP = 4
_MOUNT_PROGRAM = 100005


@dataclass(frozen=True, slots=True)
class RpcReply:
    """A decoded ONC RPC reply."""

    accepted: bool
    status: int
    payload: bytes = b""
    error: str | None = None

    @property
    def ok(self) -> bool:
        return self.accepted and self.status == 0


@dataclass(frozen=True, slots=True)
class PortmapEntry:
    program: int
    version: int
    protocol: int
    port: int

    @property
    def protocol_name(self) -> str:
        return {6: "tcp", 17: "udp"}.get(self.protocol, str(self.protocol))

    @property
    def program_name(self) -> str:
        return _RPC_PROGRAMS.get(self.program, f"program-{self.program}")


_RPC_PROGRAMS = {
    100000: "portmapper/rpcbind",
    100003: "nfs",
    100005: "mountd",
    100021: "nlockmgr",
    100024: "status",
    100227: "nfs_acl",
}


def rpc_call(
    program: int,
    version: int,
    procedure: int,
    args: bytes = b"",
    *,
    xid: int | None = None,
    auth: bool = False,
) -> bytes:
    """An ONC RPC call message, record-marked for TCP (RFC 5531 §11)."""
    identifier = xid if xid is not None else _probe_id(31) or 1
    credential = ber_tlv(0x04, b"")  # AUTH_NULL: an empty opaque body, XDR-encoded below
    body = (
        struct.pack(">IIII", identifier, _RPC_CALL, 2, program)
        + struct.pack(">II", version, procedure)
        + _xdr_opaque_auth(b"")  # credentials (AUTH_NULL)
        + _xdr_opaque_auth(b"")  # verifier (AUTH_NULL)
        + args
    )
    del credential, auth
    return _record_mark(body)


def _xdr_opaque_auth(body: bytes) -> bytes:
    return struct.pack(">II", 0, len(body)) + body + b"\x00" * ((4 - len(body) % 4) % 4)


def _record_mark(payload: bytes) -> bytes:
    return struct.pack(">I", 0x80000000 | len(payload)) + payload


def rpcbind_dump_call(*, xid: int | None = None) -> bytes:
    """RPCBPROC_DUMP: the whole portmapper registration table in one call."""
    return rpc_call(_PORTMAP_PROGRAM, 2, _PORTMAP_DUMP, xid=xid)


def parse_rpc_reply(data: bytes) -> RpcReply:
    """Decode a record-marked ONC RPC reply (``accepted`` + accept status)."""
    if len(data) < 4:
        return RpcReply(accepted=False, status=0, error="short reply")
    marker = struct.unpack(">I", data[:4])[0]
    if not marker & 0x80000000:
        return RpcReply(accepted=False, status=0, error="not a record-marked RPC message")
    payload = data[4 : 4 + (marker & 0x7FFFFFFF)]
    if len(payload) < 24:
        return RpcReply(accepted=False, status=0, error="truncated RPC reply")
    try:
        reader = _ByteReader(payload)
        reader.read_uint32()  # xid
        message_type = reader.read_uint32()
        if message_type != 1:
            return RpcReply(accepted=False, status=0, error="not a reply message")
        reply_status = reader.read_uint32()  # 0 = MSG_ACCEPTED
        if reply_status != 0:
            return RpcReply(accepted=False, status=0, error=f"RPC denied/error ({reply_status})")
        reader.read(8)  # verifier flavour + length
        accept_status = reader.read_uint32()
        return RpcReply(
            accepted=True,
            status=accept_status,
            payload=payload[reader.pos :],
            error=None if accept_status == 0 else f"accept status {accept_status}",
        )
    except ValueError as exc:
        return RpcReply(accepted=False, status=0, error=str(exc))


def parse_portmap_dump(payload: bytes) -> tuple[PortmapEntry, ...]:
    """Decode the linked list a RPCBPROC_DUMP reply carries."""
    entries: list[PortmapEntry] = []
    try:
        reader = _ByteReader(payload)
        for _ in range(512):
            more = reader.read_uint32()
            if more == 0:
                break
            program = reader.read_uint32()
            version = reader.read_uint32()
            protocol = reader.read_uint32()
            port = reader.read_uint32()
            entries.append(
                PortmapEntry(program=program, version=version, protocol=protocol, port=port)
            )
    except ValueError:
        return tuple(entries)
    return tuple(entries)


def nfs_export_list(*, xid: int | None = None) -> bytes:
    """MOUNTPROC_EXPORT (program 100005, version 3, procedure 5) — the export list."""
    return rpc_call(_MOUNT_PROGRAM, 3, 5, xid=xid)


def _read_xdr_string(reader: _ByteReader) -> str:
    """Read an XDR ``string<>`` and skip its 4-byte padding (RFC 4506 §4.11)."""
    length = reader.read_uint32()
    value = reader.read(length)
    reader.read((4 - length % 4) % 4)
    return value.decode("utf-8", "replace")


def parse_nfs_exports(payload: bytes) -> tuple[tuple[str, tuple[str, ...]], ...]:
    """``((path, (allowed_hosts...)), ...)`` from a MOUNTPROC_EXPORT reply.

    The reply is a linked list of ``dirpath`` + ``groups`` (each a ``name`` + ``netmask``).
    Only the path and the host entries are extracted; anything malformed ends the walk.
    """
    exports: list[tuple[str, tuple[str, ...]]] = []
    try:
        reader = _ByteReader(payload)
        for _ in range(128):
            if reader.read_uint32() == 0:
                break
            path = _read_xdr_string(reader)
            hosts: list[str] = []
            for _ in range(64):
                if reader.read_uint32() == 0:
                    break
                name = _read_xdr_string(reader)
                reader.read_uint32()  # netmask/prefix length
                if name:
                    hosts.append(name)
            exports.append((path, tuple(hosts)))
    except ValueError:
        return tuple(exports)
    return tuple(exports)


# --------------------------------------------------------------------------- Modbus (ch02#27)
@dataclass(frozen=True, slots=True)
class ModbusDeviceId:
    """The objects a Modbus "Read Device Identification" reply carries."""

    objects: Mapping[int, str] = field(default_factory=dict)

    @property
    def vendor(self) -> str | None:
        return self.objects.get(0)

    @property
    def product(self) -> str | None:
        return self.objects.get(1)

    @property
    def version(self) -> str | None:
        return self.objects.get(2)


def modbus_read_device_id(unit_id: int = 1, *, transaction_id: int = 1, code: int = 1) -> bytes:
    """MBAP + function 0x2B / MEI 0x0E "Read Device Identification" (read-only)."""
    pdu = bytes([0x2B, 0x0E, code, 0x00])
    header = struct.pack(">HHHB", transaction_id, 0, len(pdu) + 1, unit_id)
    return header + pdu


def parse_modbus_device_id(data: bytes) -> ModbusDeviceId | None:
    """Decode a Read Device Identification reply into its ASCII object map."""
    if len(data) < 9:
        return None
    try:
        reader = _ByteReader(data)
        reader.read_uint16()  # transaction
        reader.read_uint16()  # protocol
        length = reader.read_uint16()
        reader.read_uint8()  # unit id
        if length < 3:
            return None
        function = reader.read_uint8()
        if function & 0x80:  # exception response
            return None
        reader.read_uint8()  # MEI type
        reader.read_uint8()  # read device id code
        reader.read_uint8()  # conformity level
        reader.read_uint8()  # more follows
        reader.read_uint8()  # next object id
        objects: dict[int, str] = {}
        for _ in range(64):
            if reader.remaining < 2:
                break
            object_id = reader.read_uint8()
            size = reader.read_uint8()
            objects[object_id] = reader.read(size).decode("ascii", "replace")
    except ValueError:
        return None
    return ModbusDeviceId(objects=objects)


# --------------------------------------------------------------------------- BACnet (ch02#27)
@dataclass(frozen=True, slots=True)
class BacnetDevice:
    device_instance: int
    vendor_id: int


def bacnet_who_is() -> bytes:
    """A BACnet/IP Who-Is broadcast (unconfirmed service 0x10)."""
    return bytes([0x81, 0x0A, 0x00, 0x08, 0x01, 0x20, 0xFF, 0xFF, 0x00, 0xFF, 0x10, 0x08])


def parse_bacnet_i_am(data: bytes) -> BacnetDevice | None:
    """Decode an I-Am (unconfirmed service 0x00): BVLC + NPDU + the APDU fields M2 needs.

    APDU layout after the NPDU header (ASHRAE 135 §20.1.2):
    ``00`` (unconfirmed-request / I-Am) · ``C4`` object-identifier (4 bytes) ·
    ``21`` max-apdu-length-accepted (1) · ``91`` segmentation-supported (1) ·
    ``21`` vendor-id (1).
    """
    if len(data) < 18 or data[0] != 0x81:
        return None
    try:
        reader = _ByteReader(data)
        reader.read_uint8()  # BVLC type
        reader.read_uint8()  # BVLC function
        reader.read_uint16()  # BVLC length
        reader.read_uint8()  # NPDU version
        reader.read_uint8()  # NPDU control
        if reader.read_uint8() != 0x00:  # unconfirmed service: I-Am
            return None
        if reader.read_uint8() != 0xC4:  # object-identifier, context tag 0, 4 bytes
            return None
        identifier = reader.read_uint32()
        reader.read(2)  # max-apdu-length-accepted: tag + 1-byte value
        reader.read(2)  # segmentation-supported: tag + 1-byte value
        reader.read_uint8()  # vendor-id tag
        vendor = reader.read_uint8()
    except ValueError:
        return None
    return BacnetDevice(device_instance=identifier & 0x3FFFFF, vendor_id=vendor)


# --------------------------------------------------------------------------- S7comm (S29)
@dataclass(frozen=True, slots=True)
class S7Connection:
    """What an ISO-TSAP connection confirm tells us about an S7 endpoint.

    Only the handshake is decoded. This scanner deliberately implements **no** S7 read or write
    job: reading PLC memory is a state-touching capability, and the fact worth reporting —
    that a PLC's programming protocol answers from this network segment — is established by the
    connection alone (``REQ-DEPTH-006``).
    """

    source_tsap: bytes = b""
    destination_tsap: bytes = b""
    #: True when the peer answered with a COTP connection confirm (PDU type 0xD0).
    confirmed: bool = False


def s7_cotp_connection_request(*, source_ref: int = 0x0001, destination_ref: int = 0x0000) -> bytes:
    """TPKT + COTP Connection Request for ISO-TSAP (port 102), the S7 handshake's first step.

    TPKT: version 3, reserved 0, total length. COTP CR: PDU type ``0xE0`` (or ``0xE1`` with an
    explicit TPDU size), dst-ref, src-ref, class/options, then the ``C1``/``C2`` TSAP
    parameters a real client sends.
    """
    cotp = bytes([0x11, 0xE0]) + struct.pack(">HH", destination_ref, source_ref) + bytes([0x00])
    cotp += bytes([0xC1, 0x02, 0x01, 0x00])  # source TSAP (0x0100)
    cotp += bytes([0xC2, 0x02, 0x01, 0x02])  # destination TSAP (0x0102 = PG/PC)
    return bytes([0x03, 0x00]) + struct.pack(">H", 4 + len(cotp)) + cotp


def parse_s7_connection_confirm(data: bytes) -> S7Connection | None:
    """Decode a COTP Connection Confirm (PDU type ``0xD0``) from a TPKT frame."""
    if len(data) < 7 or data[0] != 0x03:
        return None
    try:
        reader = _ByteReader(data)
        reader.read_uint8()  # TPKT version
        reader.read_uint8()  # reserved
        length = reader.read_uint16()
        if length < 7 or length > len(data):
            return None
        reader.read_uint8()  # COTP header length
        pdu_type = reader.read_uint8()
        if pdu_type != 0xD0:  # not a connection confirm (0xE0 is a request, 0x80 a disconnect)
            return None
        reader.read_uint16()  # destination reference
        reader.read_uint16()  # source reference
        reader.read_uint8()  # class / options
        source_tsap = b""
        destination_tsap = b""
        while reader.remaining >= 2:
            parameter = reader.read_uint8()
            size = reader.read_uint8()
            value = reader.read(size) if size <= reader.remaining else b""
            if parameter == 0xC2:
                source_tsap = value
            elif parameter == 0xC1:
                destination_tsap = value
    except ValueError:
        return None
    return S7Connection(source_tsap=source_tsap, destination_tsap=destination_tsap, confirmed=True)


# --------------------------------------------------------------------------- DNP3 (S29)
#: DNP3 link-layer function codes (IEEE 1815 §5.2.1). Only the two *read-only* ones are
#: representable here: ``REQUEST_LINK_STATUS`` (9) asks for a status reply, and
#: ``RESET_LINK_STATES`` (0) *changes* the link state machine on the outstation, so this
#: scanner never sends it (``REQ-DEPTH-006``: read-only discovery).
DNP3_REQUEST_LINK_STATUS = 0x09
DNP3_LINK_STATUS = 0x0B


@dataclass(frozen=True, slots=True)
class Dnp3Link:
    """A DNP3 link-layer reply: the addresses it was addressed to and from, and its function."""

    destination: int
    source: int
    function: int

    @property
    def is_link_status(self) -> bool:
        return self.function == DNP3_LINK_STATUS


def dnp3_crc(data: bytes) -> int:
    """The DNP3 CRC-16 (polynomial 0x3D65, reflected, init 0, final XOR 0xFFFF).

    Implemented bitwise rather than from a 256-entry table: the frames this scanner builds are
    tens of bytes, so the table would be weight without benefit (and a table is one more thing
    to get wrong).
    """
    crc = 0x0000
    for byte in data:
        crc ^= byte
        for _ in range(8):
            if crc & 1:
                crc = (crc >> 1) ^ 0xA6BC  # the reflected 0x3D65 polynomial
            else:
                crc >>= 1
    return (~crc) & 0xFFFF


def dnp3_link_status_request(*, source: int = 3, destination: int = 1) -> bytes:
    """A DNP3 link-layer REQUEST_LINK_STATUS frame (read-only; no user data).

    ``05 64`` start · length ``05`` (control + destination + source, no user data) · control
    ``0xC9`` (DIR=1 master, PRM=1 from-primary, function 9) · destination · source · CRC.
    """
    header = bytes([0x05, 0x64, 0x05, 0xC9]) + struct.pack("<HH", destination, source)
    return header + struct.pack("<H", dnp3_crc(header))


def parse_dnp3_link(data: bytes) -> Dnp3Link | None:
    """Decode a DNP3 link-layer frame's header and verify its CRC."""
    if len(data) < 10 or data[0] != 0x05 or data[1] != 0x64:
        return None
    length = data[2]
    if length < 5 or len(data) < 3 + length + 2:
        return None
    header = data[: 3 + length]
    expected = int.from_bytes(data[3 + length : 3 + length + 2], "little")
    if dnp3_crc(header) != expected:
        return None
    control = data[3]
    destination = int.from_bytes(data[4:6], "little")
    source = int.from_bytes(data[6:8], "little")
    return Dnp3Link(destination=destination, source=source, function=control & 0x0F)


# --------------------------------------------------------------------------- SMB2 (ch02#16)
_SMB2_DIALECT = {
    0x0202: "SMB 2.0.2",
    0x0210: "SMB 2.1",
    0x0222: "SMB 2.2",
    0x0300: "SMB 3.0",
    0x0302: "SMB 3.0.2",
    0x0311: "SMB 3.1.1",
    0x02FF: "SMB 2.??",
}


@dataclass(frozen=True, slots=True)
class SmbNegotiate:
    """What an SMB2 NEGOTIATE response tells us."""

    dialect: str | None
    dialect_revision: int | None
    signing_required: bool = False
    signing_enabled: bool = False
    server_guid: str = ""
    smb1_supported: bool = False

    @property
    def dialect_name(self) -> str:
        return self.dialect or "unknown"


def smb1_negotiate() -> bytes:
    """A minimal SMB1 NEGOTIATE PROTOCOL REQUEST (dialect detection only)."""
    header = bytes([0xFF, b"SMB"[0], b"SMB"[1], b"SMB"[2]]) + b"\x72\x00\x00\x00\x00\x18\x53\xc8"
    header += b"\x00" * 12
    header += struct.pack("<H", 0)  # flags (no unicode)
    header += b"\x00" * 12
    body = struct.pack("<BHH", 0, 0, 2) + b"NT LM 0.12\x00\x02SMB 2.002\x00"
    payload = header + body
    return _netbios_session(payload)


def smb2_negotiate(*, dialects: Sequence[int] = (0x0311, 0x0302, 0x0300, 0x0210, 0x0202)) -> bytes:
    """An SMB2 NEGOTIATE request offering a modern dialect list."""
    # SMB2 header (64 bytes): protocol, structure size, credit charge, status, command, ...
    header = (
        b"\xfeSMB"
        + struct.pack("<H", 64)  # StructureSize
        + struct.pack("<H", 0)  # CreditCharge
        + struct.pack("<I", 0)  # Status
        + struct.pack("<H", 0)  # Command = NEGOTIATE
        + struct.pack("<H", 1)  # CreditRequest
        + struct.pack("<I", 1)  # Flags (SMB2_FLAGS_SERVER_TO_REDIR cleared)
        + struct.pack("<I", 0)  # NextCommand
        + struct.pack("<Q", 1)  # MessageId
        + struct.pack("<I", 0xFEFF)  # ProcessId
        + struct.pack("<I", 0)  # TreeId
        + struct.pack("<Q", 0)  # SessionId
        + b"\x00" * 16  # Signature
    )
    dialect_bytes = b"".join(struct.pack("<H", value) for value in dialects)
    guid = _random_bytes(16)
    body = (
        struct.pack("<H", 36)  # StructureSize
        + struct.pack("<H", len(dialects))
        + struct.pack("<H", 0x0001)  # SecurityMode: signing enabled
        + struct.pack("<I", 0)  # Capabilities
        + guid
        + struct.pack("<Q", 0)  # ClientStartTime
        + dialect_bytes
    )
    return _netbios_session(header + body)


def smb2_session_setup_anonymous(
    *, session_id: int = 0, message_id: int = 1, security_blob: bytes | None = None
) -> bytes:
    """An SMB2 SESSION_SETUP carrying an NTLMSSP *anonymous* negotiate token."""
    blob = security_blob if security_blob is not None else ntlmssp_anonymous_negotiate()
    header = (
        b"\xfeSMB"
        + struct.pack("<H", 64)
        + struct.pack("<H", 0)
        + struct.pack("<I", 0)
        + struct.pack("<H", 1)  # Command = SESSION_SETUP
        + struct.pack("<H", 1)
        + struct.pack("<I", 0)
        + struct.pack("<I", 0)
        + struct.pack("<Q", message_id)
        + struct.pack("<I", 0xFEFF)
        + struct.pack("<I", 0)
        + struct.pack("<Q", session_id)
        + b"\x00" * 16
    )
    offset = 64 + 24
    body = (
        struct.pack("<H", 25)  # StructureSize
        + bytes([0])  # Flags: binding cleared
        + bytes([1])  # SecurityMode
        + struct.pack("<I", 0)  # Capabilities
        + struct.pack("<I", 0)  # Channel
        + struct.pack("<H", offset)  # SecurityBufferOffset
        + struct.pack("<H", len(blob))  # SecurityBufferLength
        + struct.pack("<Q", 0)  # PreviousSessionId
        + blob
    )
    return _netbios_session(header + body)


def ntlmssp_anonymous_negotiate() -> bytes:
    """An NTLMSSP NEGOTIATE (type 1) message requesting anonymous authentication."""
    # NEGOTIATE_ANONYMOUS | NEGOTIATE_UNICODE | NEGOTIATE_NTLM | NEGOTIATE_OEM
    flags = 0x00000800 | 0x00000001 | 0x00000200 | 0x00000002
    return (
        b"NTLMSSP\x00" + struct.pack("<I", 1) + struct.pack("<I", flags) + b"\x00" * 8 + b"\x00" * 8
    )


def _netbios_session(payload: bytes) -> bytes:
    """Prefix an SMB payload with the NetBIOS session service header (RFC 1002 §4.3)."""
    return b"\x00" + len(payload).to_bytes(3, "big") + payload


def parse_smb2_negotiate(data: bytes) -> SmbNegotiate | None:
    """Decode an SMB2 NEGOTIATE response (or recognise an SMB1 one)."""
    if len(data) < 8:
        return None
    body = data[4:] if data[:1] in {b"\x00", b"\x80"} and len(data) > 4 else data
    if body[:4] == b"\xffSMB":
        return SmbNegotiate(dialect="SMB 1.0 (CIFS)", dialect_revision=1, smb1_supported=True)
    if body[:4] != b"\xfeSMB" or len(body) < 64:
        return None
    try:
        reader = _ByteReader(body)
        reader.read(4)  # protocol
        reader.read_le16()  # structure size
        reader.read_le16()  # credit charge
        status = reader.read_le32()
        command = reader.read_le16()
        if command != 0 or status != 0:
            return None
        reader.read_le16()  # credit response
        reader.read_le32()  # flags
        reader.read_le32()  # next command
        reader.read_le64()  # message id
        reader.read_le32()  # process id
        reader.read_le32()  # tree id
        reader.read_le64()  # session id
        reader.read(16)  # signature
        structure_size = reader.read_le16()
        if structure_size != 65:
            return None
        security_mode = reader.read_le16()
        reader.read_le16()  # reserved
        dialect_revision = reader.read_le16()
        reader.read(16)  # server guid
        reader.read_le32()  # capabilities
        reader.read_le32()  # max transact size
        reader.read_le32()  # max read size
        reader.read_le32()  # max write size
        reader.read_le64()  # system time
        reader.read_le64()  # server start time
        return SmbNegotiate(
            dialect=_SMB2_DIALECT.get(dialect_revision, "SMB 2.x/3.x"),
            dialect_revision=dialect_revision,
            signing_required=bool(security_mode & 0x0002),
            signing_enabled=bool(security_mode & 0x0001),
        )
    except ValueError:
        return None


#: NTSTATUS values that matter to the anonymous-session probe.
NT_STATUS = {
    0x00000000: "STATUS_SUCCESS",
    0xC0000016: "STATUS_MORE_PROCESSING_REQUIRED",
    0xC0000022: "STATUS_ACCESS_DENIED",
    0xC000006D: "STATUS_LOGON_FAILURE",
    0xC00000CC: "STATUS_BAD_NETWORK_NAME",
    0xC000015B: "STATUS_LOGON_TYPE_NOT_GRANTED",
}


def parse_nt_status(data: bytes) -> int | None:
    """The NTSTATUS field of an SMB2 (or SMB1) response header."""
    if len(data) < 12:
        return None
    body = data[4:] if data[:1] == b"\x00" and len(data) > 4 else data
    if body[:4] == b"\xfeSMB" and len(body) >= 12:
        return int(struct.unpack("<I", body[8:12])[0])
    if body[:4] == b"\xffSMB" and len(body) >= 9:
        return int(struct.unpack("<I", body[5:9])[0])
    return None


def nt_status_name(status: int) -> str:
    return NT_STATUS.get(status, f"0x{status:08X}")


# --------------------------------------------------------------------------- X.224 / RDP (ch02#25)
#: RDP protocol bitmask (MS-RDPBCGR §2.2.1.1.1).
RDP_PROTOCOL_SSL = 0x00000001
RDP_PROTOCOL_HYBRID = 0x00000002  # CredSSP / NLA
RDP_PROTOCOL_RDP = 0x00000000
RDP_PROTOCOL_HYBRID_EX = 0x00000008


def rdp_negociation_request(*, requested: int | None = None, cookie: bytes = b"arachne") -> bytes:
    """A TPKT/X.224 connection request carrying an RDP_NEG_REQ (NLA negotiation)."""
    protocols = (
        requested
        if requested is not None
        else (RDP_PROTOCOL_HYBRID | RDP_PROTOCOL_SSL | RDP_PROTOCOL_RDP)
    )
    neg = struct.pack("<BHI", 0x01, 0x00, 8) + struct.pack("<I", protocols)
    x224 = bytes([6 + len(neg) + len(cookie), 0xE0, 0, 0, 0, 0, 0])
    payload = x224 + cookie + b"\r\n" + neg
    return struct.pack(">BBH", 3, 0, len(payload) + 4) + payload


@dataclass(frozen=True, slots=True)
class X224Negociation:
    """The RDP negotiation response: which protocol the server selected."""

    selected: int
    failure_code: int | None = None

    @property
    def selected_name(self) -> str:
        return {
            RDP_PROTOCOL_RDP: "RDP (standard security)",
            RDP_PROTOCOL_SSL: "TLS",
            RDP_PROTOCOL_HYBRID: "CredSSP/NLA",
            RDP_PROTOCOL_HYBRID_EX: "CredSSP/NLA (extended)",
        }.get(self.selected, f"0x{self.selected:08x}")

    @property
    def nla_required(self) -> bool:
        return self.selected in {RDP_PROTOCOL_HYBRID, RDP_PROTOCOL_HYBRID_EX}


def parse_x224_negociation(data: bytes) -> X224Negociation | None:
    """Decode a TPKT/X.224 negotiation response (or a connection confirm)."""
    if len(data) < 11 or data[0] != 0x03:
        return None
    # TPKT header (4) + X.224 CR/CC header (7) → the RDP negotiation structure follows.
    offset = 11
    while offset + 8 <= len(data):
        neg_type = data[offset]
        if neg_type == 0x02:  # RDP_NEG_RSP
            selected = struct.unpack("<I", data[offset + 4 : offset + 8])[0]
            return X224Negociation(selected=selected)
        if neg_type == 0x03:  # RDP_NEG_FAILURE
            failure = struct.unpack("<I", data[offset + 4 : offset + 8])[0]
            return X224Negociation(selected=RDP_PROTOCOL_RDP, failure_code=failure)
        offset += 1
    return X224Negociation(selected=RDP_PROTOCOL_RDP)


# --------------------------------------------------------------------------- RFB / VNC (ch02#25)
@dataclass(frozen=True, slots=True)
class RfbSecurity:
    """Which authentication types a VNC server offers."""

    types: tuple[int, ...] = ()

    @property
    def no_authentication(self) -> bool:
        return 1 in self.types

    @property
    def vnc_authentication(self) -> bool:
        return 2 in self.types

    def describe(self) -> tuple[str, ...]:
        names = {
            0: "invalid",
            1: "None",
            2: "VNC password",
            5: "RA2",
            6: "RA2ne",
            16: "Tight",
            17: "Ultra",
            18: "TLS",
            19: "VeNCrypt",
            20: "GTK-VNC SASL",
            21: "MD5 hash",
            22: "Colin Dean xvp",
        }
        return tuple(names.get(item, f"type-{item}") for item in self.types)


def parse_rfb_version(banner: str) -> tuple[int, int] | None:
    """Parse the ``RFB 003.008`` protocol banner."""
    if not banner:
        return None
    line = banner.strip().splitlines()[0].strip() if banner.strip() else ""
    if not line.startswith("RFB "):
        return None
    parts = line[4:].strip().split(".")
    if len(parts) != 2:
        return None
    try:
        return int(parts[0]), int(parts[1])
    except ValueError:
        return None


def rfb_client_version(major: int = 3, minor: int = 8) -> bytes:
    """The client's protocol version, which makes the server answer with its security types."""
    return f"RFB {major:03d}.{minor:03d}\n".encode()


def parse_rfb_security(data: bytes) -> RfbSecurity | None:
    """Decode the security-type list the server sends after the version exchange."""
    if not data:
        return None
    if data[0] == 0 and len(data) >= 2:
        # Zero types followed by a reason string means the connection was refused.
        return None
    count = data[0]
    if count < 1 or count > 32 or len(data) < 1 + count:
        return None
    return RfbSecurity(types=tuple(data[1 : 1 + count]))


# --------------------------------------------------------------------------- DB handshakes
@dataclass(frozen=True, slots=True)
class MysqlGreeting:
    protocol_version: int
    server_version: str
    thread_id: int
    auth_plugin: str = ""

    @property
    def version(self) -> str:
        return self.server_version


def parse_mysql_greeting(data: bytes) -> MysqlGreeting | None:
    """Decode the MySQL initial handshake packet (research ch02#22).

    Accepts the packet either with or without its 3-byte length + sequence header, because a
    banner grab hands over the frame and a protocol driver hands over the payload.
    """
    if len(data) > 4 and data[0] not in {9, 10} and data[4] in {9, 10}:
        data = data[4:]
    if len(data) < 6 or data[0] == 0xFF:
        return None
    try:
        reader = _ByteReader(data)
        protocol_version = reader.read_uint8()
        if protocol_version not in {9, 10}:
            return None
        version = _read_cstring(reader, 64)
        reader.read_uint32()  # connection id
        reader.read(8)  # auth-plugin-data-part-1
        reader.read_uint8()  # filler
        capability_low = reader.read_uint16()
        if reader.remaining == 0 and not capability_low:
            return None
        auth_plugin = ""
        try:
            if reader.remaining > 0:
                reader.read_uint8()  # charset
                reader.read_uint16()  # status flags
                capability_high = reader.read_uint16()
                auth_len = reader.read_uint8()
                reader.read(10)  # reserved
                if capability_high & 0x8000:  # CLIENT_PLUGIN_AUTH
                    reader.read(max(13, auth_len - 8))
                    if reader.remaining > 1:
                        auth_plugin = _read_cstring(reader, 32)
        except ValueError:
            auth_plugin = ""
    except ValueError:
        return None
    return MysqlGreeting(
        protocol_version=protocol_version,
        server_version=version,
        thread_id=0,
        auth_plugin=auth_plugin,
    )


def _read_cstring(reader: _ByteReader, limit: int = 256) -> str:
    out = bytearray()
    for _ in range(limit):
        byte = reader.read_uint8()
        if byte == 0:
            return out.decode("utf-8", "replace")
        out.append(byte)
    return out.decode("utf-8", "replace")


def postgres_ssl_request() -> bytes:
    """The PostgreSQL SSLRequest (protocol 1234.5679) — answered ``S`` or ``N``."""
    return struct.pack(">II", 8, 80877103)


def postgres_startup(*, user: str = "arachne_probe", database: str = "postgres") -> bytes:
    """A PostgreSQL StartupMessage for an intentionally non-existent role."""
    body = struct.pack(">I", 196608)
    body += b"user\x00" + user.encode() + b"\x00"
    body += b"database\x00" + database.encode() + b"\x00\x00"
    return struct.pack(">I", len(body) + 4) + body


#: PostgreSQL ErrorResponse SQLSTATEs that prove the server is alive (RFC-less but stable).
POSTGRES_AUTH_FAILED = {"28P01", "28000"}
POSTGRES_UNSUPPORTED = {"0A000", "08P01", "3D000"}


@dataclass(frozen=True, slots=True)
class PostgresReply:
    """A decoded PostgreSQL message: type byte, severity, SQLSTATE and text."""

    type: str
    code: str = ""
    severity: str = ""
    message: str = ""


def parse_postgres_message(data: bytes) -> PostgresReply | None:
    """Decode one PostgreSQL backend message (ErrorResponse or Authentication*)."""
    if not data:
        return None
    message_type = chr(data[0])
    if message_type not in {"R", "E", "S", "N"}:
        return None
    if len(data) > 5:
        declared = int.from_bytes(data[1:5], "big")
        if declared and 4 <= declared <= len(data) - 1:
            data = data[: declared + 1]
    code = ""
    severity = ""
    message = ""
    if message_type == "E":
        offset = 5
        while offset + 2 <= len(data):
            field_type = chr(data[offset])
            offset += 1
            if field_type == "\x00":
                break
            end = data.find(b"\x00", offset)
            if end < 0:
                break
            text = data[offset:end].decode("utf-8", "replace")
            offset = end + 1
            if field_type == "C":
                code = text
            elif field_type == "S":
                severity = text
            elif field_type == "M":
                message = text
    elif message_type == "R" and len(data) >= 9:
        auth_type = int.from_bytes(data[5:9], "big")
        severity = "authentication"
        code = f"AUTH-{auth_type}"
        message = {
            0: "AuthenticationOk",
            3: "AuthenticationCleartextPassword",
            5: "AuthenticationMD5Password",
            10: "AuthenticationSASL",
        }.get(auth_type, f"AuthenticationType{auth_type}")
    return PostgresReply(type=message_type, code=code, severity=severity, message=message)


def parse_mssql_prelogin(data: bytes) -> dict[str, str] | None:
    """Decode the TDS PRELOGIN response: version, instance and encryption posture."""
    if len(data) < 8:
        return None
    try:
        reader = _ByteReader(data)
        packet_type = reader.read_uint8()
        if packet_type != 0x04:  # TABULAR_RESULT (PRELOGIN response)
            return None
        reader.read_uint8()  # status
        length = reader.read_le16()
        reader.read(2)  # spid
        reader.read_uint8()  # packet id
        reader.read_uint8()  # window
        if length and length > len(data):
            return None
        info: dict[str, str] = {}
        while reader.remaining >= 5:
            token = reader.read_uint8()
            offset = reader.read_le16()
            size = reader.read_le16()
            if token == 0xFF:
                break
            if offset <= 0 or offset >= len(data) or size == 0 or offset + size > len(data):
                continue
            value = data[offset : offset + size]
            if token == 0x00 and len(value) >= 6:  # VERSION
                major = value[0]
                minor = value[1]
                build = int.from_bytes(value[2:4], "big")
                info["version"] = f"{major}.{minor}.{build}"
            elif token == 0x01:  # ENCRYPTION
                info["encryption"] = {0: "off", 1: "on", 2: "not supported", 3: "required"}.get(
                    value[0], str(value[0])
                )
            elif token == 0x02:  # INSTOPT (instance name)
                info["instance"] = value.rstrip(b"\x00").decode("utf-8", "replace")
    except ValueError:
        return None
    return info


# --------------------------------------------------------------------------- data stores
def redis_command(*parts: str) -> bytes:
    """Encode a Redis command in the RESP array form (``PING``, ``INFO server``, ...)."""
    out = bytearray(f"*{len(parts)}\r\n".encode())
    for part in parts:
        encoded = part.encode()
        out.extend(f"${len(encoded)}\r\n".encode())
        out.extend(encoded)
        out.extend(b"\r\n")
    return bytes(out)


@dataclass(frozen=True, slots=True)
class RedisReply:
    kind: str
    value: str

    @property
    def ok(self) -> bool:
        return self.kind in {"+", ":"}

    @property
    def needs_auth(self) -> bool:
        return "NOAUTH" in self.value.upper() or "WRONGPASS" in self.value.upper()


def parse_redis_reply(data: bytes) -> RedisReply | None:
    """Parse a simple RESP reply (the leading byte is the type)."""
    if not data:
        return None
    kind = chr(data[0])
    body = data[1:].decode("utf-8", "replace")
    if kind in {"+", "-", ":"}:
        return RedisReply(kind=kind, value=body.strip())
    if kind == "$":
        lines = body.split("\r\n", 2)
        return RedisReply(kind=kind, value=lines[1] if len(lines) > 1 else "")
    if kind == "*":
        return RedisReply(kind=kind, value=body.strip())
    return None


def memcached_stats() -> bytes:
    """The memcached ``stats`` command (research ch02#23)."""
    return b"stats\r\n"


def memcached_values(text: str) -> dict[str, str]:
    """Parse a memcached ``stats`` reply into its ``STAT key value`` map."""
    values: dict[str, str] = {}
    for line in text.splitlines():
        parts = line.strip().split()
        if len(parts) >= 3 and parts[0].upper() == "STAT":
            values[parts[1]] = parts[2]
    return values


# --------------------------------------------------------------------------- BSON (MongoDB)
def bson_encode_document(document: Mapping[str, Any]) -> bytes:
    """Encode a flat document (int/float/bool/str only) as BSON."""
    elements = bytearray()
    for key, value in document.items():
        name = key.encode() + b"\x00"
        if isinstance(value, bool):
            elements.extend(b"\x08" + name + bytes([1 if value else 0]))
        elif isinstance(value, int):
            if -(2**31) <= value < 2**31:
                elements.extend(b"\x10" + name + struct.pack("<i", value))
            else:
                elements.extend(b"\x12" + name + struct.pack("<q", value))
        elif isinstance(value, float):
            elements.extend(b"\x01" + name + struct.pack("<d", value))
        elif isinstance(value, str):
            encoded = value.encode() + b"\x00"
            elements.extend(b"\x02" + name + struct.pack("<i", len(encoded)) + encoded)
        else:
            continue
    body = bytes(elements) + b"\x00"
    return struct.pack("<i", len(body) + 4) + body


def bson_decode_document(data: bytes) -> dict[str, Any] | None:
    """Decode a flat BSON document; ``None`` when the framing is wrong."""
    if len(data) < 5:
        return None
    size = struct.unpack("<i", data[:4])[0]
    if size < 5 or size > len(data):
        return None
    document: dict[str, Any] = {}
    reader = _ByteReader(data)
    reader.read(4)
    try:
        for _ in range(512):
            element_type = reader.read_uint8()
            if element_type == 0x00:
                break
            key = _read_cstring(reader, 128)
            if element_type == 0x01:
                document[key] = struct.unpack("<d", reader.read(8))[0]
            elif element_type == 0x02:
                length = struct.unpack("<i", reader.read(4))[0]
                document[key] = reader.read(max(0, length - 1)).decode("utf-8", "replace")
                reader.read(1)
            elif element_type == 0x08:
                document[key] = reader.read_uint8() != 0
            elif element_type == 0x10:
                document[key] = struct.unpack("<i", reader.read(4))[0]
            elif element_type == 0x12:
                document[key] = struct.unpack("<q", reader.read(8))[0]
            elif element_type in {0x03, 0x04}:  # embedded document/array: skipped whole
                length = struct.unpack("<i", reader.read(4))[0]
                reader.read(max(0, length - 4))
            else:
                return document
    except (ValueError, struct.error):
        return document
    return document


def mongo_ismaster_probe(*, request_id: int = 1) -> bytes:
    """A legacy OP_QUERY ``isMaster`` handshake (accepted by every MongoDB generation)."""
    document = bson_encode_document({"isMaster": 1})
    body = (
        struct.pack("<i", 0)  # flags
        + b"admin.$cmd\x00"
        + struct.pack("<ii", 0, -1)  # skip, return -1 (all)
        + document
    )
    return struct.pack("<iiii", 16 + len(body), request_id, 0, 2004) + body


@dataclass(frozen=True, slots=True)
class MongoHandshake:
    """What an ``isMaster`` reply reveals."""

    ok: bool
    fields: Mapping[str, Any] = field(default_factory=dict)
    auth_error: str | None = None

    @property
    def version(self) -> str | None:
        value = self.fields.get("version")
        return str(value) if value is not None else None

    @property
    def max_wire_version(self) -> int | None:
        value = self.fields.get("maxWireVersion")
        return int(value) if isinstance(value, int) else None


def parse_mongo_ismaster(data: bytes) -> MongoHandshake | None:
    """Decode an OP_REPLY (2004) or OP_MSG (2013) ``isMaster``/``hello`` reply."""
    if len(data) < 16:
        return None
    header_length, _, _, op_code = struct.unpack("<iiii", data[:16])
    if header_length > len(data):
        return None
    body = data[16:]
    if op_code == 2004:  # OP_REPLY
        if len(body) < 20:
            return None
        document_bytes = body[20:]
    elif op_code == 2013:  # OP_MSG
        if len(body) < 5:
            return None
        # flagBits (4) + section kind (1) + document
        document_bytes = body[5:]
    else:
        return None
    document = bson_decode_document(document_bytes)
    if document is None:
        return None
    if "ok" in document and not document["ok"]:
        text = str(document.get("errmsg", "authentication or authorization failed"))
        return MongoHandshake(ok=False, fields=document, auth_error=text)
    return MongoHandshake(ok=True, fields=document)


# --------------------------------------------------------------------------- Kerberos (ch02#19)
_KERBEROS_ETYPES = (18, 17, 23, 16)  # AES256/AES128/RC4/3DES


def _der_general_string(value: str) -> bytes:
    return ber_tlv(0x1B, value.encode())


def _der_generalized_time(moment: datetime) -> bytes:
    return ber_tlv(0x18, moment.astimezone(UTC).strftime("%Y%m%d%H%M%SZ").encode())


def kerberos_as_req(
    principal: str,
    realm: str,
    *,
    nonce: int | None = None,
    till_hours: int = 8,
) -> bytes:
    """A Kerberos AS-REQ (RFC 4120 §5.4.1).

    Only the fields a KDC needs to answer with a *user-exists / user-unknown* error are
    filled in: the reply's error code is the whole point, and the request deliberately
    carries no pre-authentication data (that is what makes the probe non-lockout by
    construction — see the check's pacing).
    """
    from datetime import timedelta

    moment = datetime.now(UTC)
    number = nonce if nonce is not None else _probe_id(31) or 1
    cname = ber_tlv(
        0xA1,
        ber_tlv(0xA0, ber_int(1))  # name-type: NT-PRINCIPAL
        + ber_tlv(0xA1, ber_tlv(0x1B, principal.encode())),  # name-string
    )
    sname = ber_tlv(
        0xA3,
        ber_tlv(0xA0, ber_int(2))  # NT-SRV-INST
        + ber_tlv(0xA1, ber_tlv(0x1B, b"krbtgt") + ber_tlv(0x1B, realm.encode())),
    )
    body = (
        ber_tlv(0xA0, ber_tlv(0x03, b"\x40\x81\x00\x00"))  # kdc-options: forwardable+renewable
        + cname
        + ber_tlv(0xA2, ber_tlv(0x1B, realm.encode()))  # realm
        + sname
        + ber_tlv(0xA5, _der_generalized_time(moment + timedelta(hours=till_hours)))  # till
        + ber_tlv(0xA7, ber_int(number))  # nonce
        + ber_tlv(0xA8, b"".join(ber_tlv(0x02, ber_int(value)) for value in _KERBEROS_ETYPES))
    )
    return ber_tlv(
        0x6A,  # [APPLICATION 10] AS-REQ
        ber_tlv(0xA1, ber_int(5))  # pvno
        + ber_tlv(0xA2, ber_int(10))  # msg-type: AS-REQ
        + ber_tlv(0xA4, body),  # req-body
    )


#: Kerberos error codes relevant to user enumeration (RFC 4120 §7.5.9).
KRB_ERRORS = {
    6: "KDC_ERR_C_PRINCIPAL_UNKNOWN",
    7: "KDC_ERR_S_PRINCIPAL_UNKNOWN",
    12: "KDC_ERR_POLICY",
    18: "KDC_ERR_CLIENT_REVOKED",
    24: "KDC_ERR_PREAUTH_REQUIRED",
    25: "KDC_ERR_PREAUTH_FAILED",
    32: "KRB_AP_ERR_TKT_EXPIRED",
    52: "KRB_ERR_RESPONSE_TOO_BIG",
    68: "KDC_ERR_WRONG_REALM",
}


def kerberos_error_code(data: bytes) -> int | None:
    """Extract ``error-code [6]`` from a KRB-ERROR ([APPLICATION 30]) reply."""
    if not data:
        return None
    try:
        reader = BerReader(data)
        tag, body = reader.read_tlv()
        if tag != 0x7E:  # [APPLICATION 30] KRB-ERROR
            # A KDC may also answer with a bare AS-REP ([APPLICATION 11]); no code then.
            return None
        inner = BerReader(body)
        for _ in range(16):
            if inner.eof:
                break
            item_tag, item_body = inner.read_tlv()
            if item_tag == 0x86:  # error-code [6] INTEGER
                return int.from_bytes(item_body, "big")
    except ValueError:
        return None
    return None


# --------------------------------------------------------------------------- TLS ClientHello
def tls_client_hello(
    *,
    server_name: str | None = None,
    version: int = 0x0303,
    random: bytes | None = None,
    include_tls13: bool = True,
) -> bytes:
    """A minimal TLS 1.2/1.3 ClientHello (used to identify TLS on a non-standard port).

    ``random`` overrides the 32-byte ClientHello random. It exists for S30's fuzzing grammars:
    a fuzz case has to be reproducible byte for byte, and a seed that changed on every call
    would make "this exact message produced that fault" unprovable. Callers that do not pass it
    get the unpredictable nonce they always got, so every existing probe is unchanged.

    ``include_tls13=False`` caps the offer at TLS 1.2 (both in ``supported_versions`` and in
    the cipher list). That is what the mutual-TLS observation needs: a server that negotiates
    TLS 1.3 encrypts its whole handshake flight, so the ``CertificateRequest`` it sends is not
    observable on the wire, while a TLS 1.2 server sends it in the clear — alongside
    ``Certificate`` and ``ServerHelloDone``, in the one flight
    :func:`parse_tls_server_flight` reads.
    """
    if random is not None and len(random) != 32:
        raise ValueError("a TLS ClientHello random must be exactly 32 bytes")
    extensions = b""
    if server_name:
        name = server_name.encode()
        server_name_list = b"\x00" + struct.pack(">H", len(name)) + name
        extensions += (
            struct.pack(">HH", 0x0000, len(server_name_list) + 2)
            + struct.pack(">H", len(server_name_list))
            + server_name_list
        )
    # supported_versions — TLS 1.3 first, then 1.2 (or 1.2 alone when capped). The extension
    # body is ``versions<2..254>``: a one-byte length, then the 2-byte versions.
    version_list = struct.pack(">H", 0x0303)
    if include_tls13:
        version_list = struct.pack(">H", 0x0304) + version_list
    versions = struct.pack(">B", len(version_list)) + version_list
    extensions += struct.pack(">HH", 0x002B, len(versions)) + versions
    # supported_groups, ec_point_formats and signature_algorithms. OpenSSL 3.x refuses an
    # ECDHE handshake without them (and requires signature_algorithms outright), so a hello
    # without these is answered with an alert rather than a ServerHello — which is what made
    # the raw probe unusable as anything but a "is this port TLS-ish" smoke test.
    groups = struct.pack(">H", 0x001D) + struct.pack(">H", 0x0017) + struct.pack(">H", 0x0018)
    extensions += (
        struct.pack(">HH", 0x000A, len(groups) + 2) + struct.pack(">H", len(groups)) + groups
    )
    extensions += struct.pack(">HH", 0x000B, 2) + b"\x01\x00"  # uncompressed only
    signatures = b"".join(
        struct.pack(">H", scheme) for scheme in (0x0403, 0x0804, 0x0401, 0x0805, 0x0806, 0x0201)
    )
    extensions += (
        struct.pack(">HH", 0x000D, len(signatures) + 2)
        + struct.pack(">H", len(signatures))
        + signatures
    )
    suites = (
        (0x1301, 0x1302, 0x1303, 0xC02F, 0xC030, 0x009C)
        if include_tls13
        else (
            0xC02F,
            0xC030,
            0x009C,
        )
    )
    cipher_suites = b"".join(struct.pack(">H", suite) for suite in suites)
    body = (
        struct.pack(">H", version)
        + (_random_bytes(32) if random is None else random)
        + b"\x00"  # session id length
        + struct.pack(">H", len(cipher_suites))
        + cipher_suites
        + b"\x01\x00"  # compression: null
        + struct.pack(">H", len(extensions))
        + extensions
    )
    handshake = b"\x01" + struct.pack(">I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack(">H", len(handshake)) + handshake


_TLS_CONTENT_TYPE = {
    0x14: "change_cipher_spec",
    0x15: "alert",
    0x16: "handshake",
    0x17: "application_data",
}
_TLS_VERSIONS = {
    0x0300: "SSLv3",
    0x0301: "TLSv1.0",
    0x0302: "TLSv1.1",
    0x0303: "TLSv1.2",
    0x0304: "TLSv1.3",
}


def parse_tls_server_hello(data: bytes) -> dict[str, Any] | None:
    """Recognise a TLS ServerHello and report the version it selected.

    The ServerHello's own version field is the *legacy* version (0x0303 even for TLS 1.3), so
    the extensions are walked for ``supported_versions`` (0x002b) when the handshake is long
    enough to contain them — which is what makes "this port speaks TLS 1.3" an observation
    rather than a reading of the compatibility field.
    """
    if len(data) < 6 or data[0] != 0x16:
        return None
    record_version = _TLS_VERSIONS.get(struct.unpack(">H", data[1:3])[0], "unknown")
    body = data[5:]
    if not body or body[0] != 0x02:  # not a ServerHello
        return {"content_type": "handshake", "record_version": record_version}
    max_offset = min(len(body), int.from_bytes(body[1:4], "big") + 4)
    info: dict[str, Any] = {
        "content_type": "handshake",
        "record_version": record_version,
        "legacy_version": _TLS_VERSIONS.get(struct.unpack(">H", body[4:6])[0], "unknown")
        if len(body) >= 6
        else "unknown",
    }
    try:
        reader = _ByteReader(body)
        reader.read(4)  # handshake type + length
        reader.read(2)  # legacy version
        reader.read(32)  # random
        session_id_length = reader.read_uint8()
        reader.read(session_id_length)
        selected = reader.read_uint16()
        reader.read_uint8()  # compression method
        extensions_length = reader.read_uint16()
        extensions = reader.read(extensions_length)
    except ValueError:
        info["selected_version"] = info["legacy_version"]
        return info
    del max_offset
    negotiated = _TLS_VERSIONS.get(selected, f"0x{selected:04x}")
    info["cipher_suite"] = f"0x{selected:04x}"
    extension_reader = _ByteReader(extensions)
    while extension_reader.remaining >= 4:
        try:
            extension_type = extension_reader.read_uint16()
            extension_length = extension_reader.read_uint16()
            payload = extension_reader.read(extension_length)
        except ValueError:
            break
        if extension_type == 0x002B and len(payload) >= 2:
            # supported_versions in a ServerHello carries exactly the selected version.
            negotiated = _TLS_VERSIONS.get(struct.unpack(">H", payload[:2])[0], negotiated)
    info["selected_version"] = negotiated
    return info


#: TLS handshake message types, by name, for evidence. Only the ones a mutual-TLS probe
#: reads are listed; an unknown type is reported by number.
TLS_HANDSHAKE_NAMES: dict[int, str] = {
    0: "hello_request",
    1: "client_hello",
    2: "server_hello",
    11: "certificate",
    12: "server_key_exchange",
    13: "certificate_request",
    14: "server_hello_done",
    15: "certificate_verify",
    16: "client_key_exchange",
    20: "finished",
}

#: Alert descriptions that mean "this peer refused the client certificate it was offered".
#: ``certificate_required`` (116) is the TLS 1.3 form of the same answer; ``unknown_ca`` and
#: ``bad_certificate`` are the TLS 1.2 forms a server sends when it cannot build a chain to a
#: trust anchor it knows.
CERTIFICATE_ALERTS: dict[int, str] = {
    40: "handshake_failure",
    42: "bad_certificate",
    43: "unsupported_certificate",
    44: "certificate_revoked",
    45: "certificate_expired",
    46: "certificate_unknown",
    48: "unknown_ca",
    49: "access_denied",
    116: "certificate_required",
}

#: Alert names for evidence. Only the ones a probe can provoke are listed; anything else is
#: reported by number, which is honest and stable.
TLS_ALERTS: dict[int, str] = {
    0: "close_notify",
    10: "unexpected_message",
    20: "bad_record_mac",
    22: "record_overflow",
    40: "handshake_failure",
    42: "bad_certificate",
    43: "unsupported_certificate",
    44: "certificate_revoked",
    45: "certificate_expired",
    46: "certificate_unknown",
    47: "illegal_parameter",
    48: "unknown_ca",
    49: "access_denied",
    50: "decode_error",
    51: "decrypt_error",
    70: "protocol_version",
    71: "insufficient_security",
    80: "internal_error",
    86: "inappropriate_fallback",
    90: "user_canceled",
    109: "missing_extension",
    112: "unrecognized_name",
    116: "certificate_required",
    120: "no_application_protocol",
}


def tls_client_certificate(certificate_der: bytes) -> bytes:
    """A TLS ``Certificate`` handshake message (with one certificate) as a handshake record.

    ``Certificate ::= struct { ASN.1Cert certificate_list<0..2^24-1> }`` and
    ``ASN.1Cert ::= opaque<1..2^24-1>``, so the body is two three-byte lengths and the DER.
    Only the TLS 1.2 form is built: the mutual-TLS observation offers TLS 1.2 (see
    :func:`tls_client_hello`) precisely so the server's own flight stays readable.
    """
    body = struct.pack(">I", len(certificate_der) + 3)[1:]
    body += struct.pack(">I", len(certificate_der))[1:]
    body += certificate_der
    handshake = b"\x0b" + struct.pack(">I", len(body))[1:] + body
    return b"\x16\x03\x03" + struct.pack(">H", len(handshake)) + handshake


def parse_tls_server_flight(data: bytes) -> dict[str, Any]:
    """Read a plaintext TLS server flight: what the server sent, in order.

    Returns a dictionary rather than a dataclass because it is evidence first and a value
    object second:

    ``handshake_types``
        the handshake message names observed, in order.
    ``certificate_request``
        ``True`` when the server sent a ``CertificateRequest`` (it is asking for a client
        certificate), ``False`` when the flight completed without one, ``None`` when the
        flight was not complete enough to say (an alert, a truncated read, or TLS 1.3, whose
        flight is encrypted).
    ``selected_version`` / ``alert`` / ``complete``
        the negotiated version, the first alert ``{level, description, name}`` if any, and
        whether ``ServerHelloDone`` closed the flight.

    A record layer that is not TLS at all yields ``{"handshake_types": [], ...}`` rather than
    an exception: "the port did not speak TLS" is an observation, not a crash.
    """
    info: dict[str, Any] = {
        "handshake_types": [],
        "certificate_request": None,
        "selected_version": None,
        "alert": None,
        "complete": False,
        "record_count": 0,
    }
    handshake_buffer = b""
    alerts: list[tuple[int, int]] = []
    index = 0
    while index + 5 <= len(data):
        content_type = data[index]
        length = int.from_bytes(data[index + 3 : index + 5], "big")
        body = data[index + 5 : index + 5 + length]
        if len(body) < length:
            break  # a truncated record: the rest never arrived
        index += 5 + length
        info["record_count"] = int(info["record_count"]) + 1
        if content_type == 0x16:
            handshake_buffer += body
        elif content_type == 0x15 and len(body) >= 2:
            alerts.append((body[0], body[1]))
    # Walk the handshake messages that were fully received.
    offset = 0
    while offset + 4 <= len(handshake_buffer):
        message_type = handshake_buffer[offset]
        message_length = int.from_bytes(handshake_buffer[offset + 1 : offset + 4], "big")
        end = offset + 4 + message_length
        if end > len(handshake_buffer):
            break
        info["handshake_types"].append(
            TLS_HANDSHAKE_NAMES.get(message_type, f"type-{message_type}")
        )
        if message_type == 2:
            hello = parse_tls_server_hello(
                b"\x16\x03\x03"
                + struct.pack(">H", 4 + message_length)
                + handshake_buffer[offset:end]
            )
            if hello is not None:
                info["selected_version"] = hello.get("selected_version")
        offset = end
    types = info["handshake_types"]
    if "certificate_request" in types:
        info["certificate_request"] = True
    elif "server_hello_done" in types:
        info["certificate_request"] = False
    info["complete"] = "server_hello_done" in types
    if alerts:
        level, description = alerts[0]
        info["alert"] = {
            "level": "fatal" if level == 2 else "warning",
            "description": description,
            "name": TLS_ALERTS.get(description, f"alert-{description}"),
            "certificate_related": description in CERTIFICATE_ALERTS,
        }
    return info


# --------------------------------------------------------------------- SMB NTLMv2 (ch02#16)
#
# Credentialed SMB authentication (REQ-CREDS-004). The check that uses this is opt-in and
# needs a credential from the vault; the *material* never appears here — the broker passes a
# username and a password into :func:`ntlmssp_authenticate` for the length of one call and
# drops them. What this module owns is the bytes: NTLMv2 as MS-NLMP defines it, computed with
# hashlib plus a small, test-vector-pinned MD4 (no crypto dependency; ADR-240.5).
#
# MD4 is only used for the NT hash — the one place the NTLM family still needs it, and the one
# hash `hashlib` does not guarantee (OpenSSL moved it to the legacy provider).


@dataclass(frozen=True, slots=True)
class NtlmChallenge:
    """The parts of an NTLMSSP CHALLENGE a client must answer."""

    flags: int
    server_challenge: bytes
    target_info: bytes = b""


@dataclass(frozen=True, slots=True)
class NtlmAuthenticate:
    """The parts of an NTLMSSP AUTHENTICATE a verifier needs."""

    nt_response: bytes
    domain: str = ""
    user: str = ""
    workstation: str = ""


_NTLMSSP_SIGNATURE = b"NTLMSSP\x00"
#: NEGOTIATE_UNICODE | NEGOTIATE_NTLM | NEGOTIATE_ALWAYS_SIGN | NEGOTIATE_EXTENDED_SESSIONSECURITY.
_NTLM_NEGOTIATE_FLAGS = 0x00000001 | 0x00000200 | 0x00008000 | 0x00080000


def md4(data: bytes) -> bytes:
    """MD4 (RFC 1320). Pinned by test vectors; used only for the NT password hash."""
    message = bytearray(data)
    bit_length = (8 * len(data)) & 0xFFFFFFFFFFFFFFFF
    message.append(0x80)
    while len(message) % 64 != 56:
        message.append(0x00)
    message += struct.pack("<Q", bit_length)
    state = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]

    def rol(value: int, shift: int) -> int:
        value &= 0xFFFFFFFF
        return ((value << shift) | (value >> (32 - shift))) & 0xFFFFFFFF

    def f(x: int, y: int, z: int) -> int:
        return (x & y) | (~x & z)

    def g(x: int, y: int, z: int) -> int:
        return (x & y) | (x & z) | (y & z)

    def h(x: int, y: int, z: int) -> int:
        return x ^ y ^ z

    for offset in range(0, len(message), 64):
        words = list(struct.unpack("<16I", bytes(message[offset : offset + 64])))
        a, b, c, d = state
        for i in range(4):
            a = rol(a + f(b, c, d) + words[i * 4], 3)
            d = rol(d + f(a, b, c) + words[i * 4 + 1], 7)
            c = rol(c + f(d, a, b) + words[i * 4 + 2], 11)
            b = rol(b + f(c, d, a) + words[i * 4 + 3], 19)
        for i in range(4):
            a = rol(a + g(b, c, d) + words[i] + 0x5A827999, 3)
            d = rol(d + g(a, b, c) + words[i + 4] + 0x5A827999, 5)
            c = rol(c + g(d, a, b) + words[i + 8] + 0x5A827999, 9)
            b = rol(b + g(c, d, a) + words[i + 12] + 0x5A827999, 13)
        for group in ((0, 8, 4, 12), (2, 10, 6, 14), (1, 9, 5, 13), (3, 11, 7, 15)):
            a = rol(a + h(b, c, d) + words[group[0]] + 0x6ED9EBA1, 3)
            d = rol(d + h(a, b, c) + words[group[1]] + 0x6ED9EBA1, 9)
            c = rol(c + h(d, a, b) + words[group[2]] + 0x6ED9EBA1, 11)
            b = rol(b + h(c, d, a) + words[group[3]] + 0x6ED9EBA1, 15)
        state = [
            (state[0] + a) & 0xFFFFFFFF,
            (state[1] + b) & 0xFFFFFFFF,
            (state[2] + c) & 0xFFFFFFFF,
            (state[3] + d) & 0xFFFFFFFF,
        ]
    return struct.pack("<4I", *state)


def nt_owf_v2(username: str, password: str, domain: str = "") -> bytes:
    """The NTLMv2 hash: HMAC-MD5 over ``UPPER(user) + domain`` keyed by MD4 of the password."""
    nt_hash = md4(password.encode("utf-16-le"))
    identity = (username.upper() + domain).encode("utf-16-le")
    return hmac.new(nt_hash, identity, hashlib.md5).digest()


def ntlm_v2_response(
    username: str,
    password: str,
    *,
    server_challenge: bytes,
    target_info: bytes = b"",
    domain: str = "",
    client_challenge: bytes | None = None,
    timestamp: bytes | None = None,
) -> tuple[bytes, bytes]:
    """``(nt_proof, nt_response_blob)`` for an NTLMv2 AUTHENTICATE (MS-NLMP §3.3.2).

    The blob is what travels in the message; the proof is HMAC-MD5 of the server challenge
    plus the blob, keyed with the NTLMv2 hash. A server verifies it by recomputing the same
    HMAC with the password it holds, which is exactly what the protocol lab does.
    """
    if len(server_challenge) != 8:
        msg = "an NTLM server challenge is 8 bytes"
        raise ValueError(msg)
    challenge = client_challenge if client_challenge is not None else _random_bytes(8)
    if len(challenge) != 8:
        msg = "an NTLM client challenge is 8 bytes"
        raise ValueError(msg)
    stamp = timestamp if timestamp is not None else b"\x00" * 8
    blob = (
        b"\x01\x01\x00\x00"  # RespType / HiRespType / reserved
        + b"\x00" * 4
        + stamp
        + challenge
        + b"\x00" * 4
        + target_info
        + b"\x00" * 4
    )
    key = nt_owf_v2(username, password, domain)
    proof = hmac.new(key, server_challenge + blob, hashlib.md5).digest()
    return proof, proof + blob


def ntlmssp_negotiate(*, domain: str = "", workstation: str = "") -> bytes:
    """An NTLMSSP NEGOTIATE (type 1) offering NTLM with extended session security."""
    domain_bytes = domain.encode("utf-16-le")
    workstation_bytes = workstation.encode("utf-16-le")
    payload_offset = 32 + 8 + 8
    message = (
        _NTLMSSP_SIGNATURE
        + struct.pack("<I", 1)
        + struct.pack("<I", _NTLM_NEGOTIATE_FLAGS)
        + struct.pack("<HHI", len(domain_bytes), len(domain_bytes), payload_offset)
        + struct.pack(
            "<HHI",
            len(workstation_bytes),
            len(workstation_bytes),
            payload_offset + len(domain_bytes),
        )
    )
    return message + domain_bytes + workstation_bytes


def parse_ntlmssp_challenge(blob: bytes) -> NtlmChallenge | None:
    """Decode an NTLMSSP CHALLENGE (type 2): the server challenge and target info."""
    if len(blob) < 32 or not blob.startswith(_NTLMSSP_SIGNATURE):
        return None
    if struct.unpack("<I", blob[8:12])[0] != 2:
        return None
    flags = struct.unpack("<I", blob[20:24])[0]
    server_challenge = blob[24:32]
    target_info = b""
    if len(blob) >= 48:
        info_len, _info_max, info_offset = struct.unpack("<HHI", blob[40:48])
        if info_len and info_offset + info_len <= len(blob):
            target_info = blob[info_offset : info_offset + info_len]
    return NtlmChallenge(flags=flags, server_challenge=server_challenge, target_info=target_info)


def ntlmssp_authenticate(
    *,
    username: str,
    password: str,
    server_challenge: bytes,
    target_info: bytes = b"",
    domain: str = "",
    workstation: str = "",
    client_challenge: bytes | None = None,
) -> bytes:
    """An NTLMSSP AUTHENTICATE (type 3) carrying an NTLMv2 response.

    Everything the peer needs to decide "these credentials are valid" and nothing else: the
    LM field carries the NTLMv2 response (as clients do when LM is disabled), and the domain,
    user and workstation go in UTF-16LE security buffers.
    """
    _proof, response = ntlm_v2_response(
        username,
        password,
        server_challenge=server_challenge,
        target_info=target_info,
        domain=domain,
        client_challenge=client_challenge,
    )
    domain_bytes = domain.encode("utf-16-le")
    user_bytes = username.encode("utf-16-le")
    workstation_bytes = workstation.encode("utf-16-le")
    lm_response = response
    header_size = 64
    offset = header_size
    fields: list[bytes] = []
    offsets: list[int] = []
    for value in (lm_response, response, domain_bytes, user_bytes, workstation_bytes):
        offsets.append(offset)
        fields.append(value)
        offset += len(value)
    body = (
        _NTLMSSP_SIGNATURE
        + struct.pack("<I", 3)
        + struct.pack("<HHI", len(lm_response), len(lm_response), offsets[0])
        + struct.pack("<HHI", len(response), len(response), offsets[1])
        + struct.pack("<HHI", len(domain_bytes), len(domain_bytes), offsets[2])
        + struct.pack("<HHI", len(user_bytes), len(user_bytes), offsets[3])
        + struct.pack("<HHI", len(workstation_bytes), len(workstation_bytes), offsets[4])
        + struct.pack("<HHI", 0, 0, offset)  # session key: absent
        + struct.pack("<I", _NTLM_NEGOTIATE_FLAGS)
    )
    return body + b"".join(fields)


def parse_ntlmssp_authenticate(blob: bytes) -> NtlmAuthenticate | None:
    """Decode an NTLMSSP AUTHENTICATE (type 3) — what the protocol lab verifies.

    Only the fields a verifier needs are extracted: the user, the domain and the NT response
    (whose first 16 bytes are the proof and the rest the NTLMv2 blob).
    """
    if len(blob) < 64 or not blob.startswith(_NTLMSSP_SIGNATURE):
        return None
    if struct.unpack("<I", blob[8:12])[0] != 3:
        return None

    def _field(spec_offset: int) -> bytes:
        length, _maximum, start = struct.unpack("<HHI", blob[spec_offset : spec_offset + 8])
        if not length or start + length > len(blob):
            return b""
        return blob[start : start + length]

    return NtlmAuthenticate(
        nt_response=_field(20),
        domain=_field(28).decode("utf-16-le", "replace"),
        user=_field(36).decode("utf-16-le", "replace"),
        workstation=_field(44).decode("utf-16-le", "replace"),
    )


def smb2_session_setup_ntlmssp(
    security_blob: bytes, *, session_id: int = 0, message_id: int = 1
) -> bytes:
    """An SMB2 SESSION_SETUP carrying ``security_blob`` (an NTLMSSP message)."""
    return smb2_session_setup_anonymous(
        session_id=session_id, message_id=message_id, security_blob=security_blob
    )


def parse_smb2_session_setup(data: bytes) -> tuple[int, bytes] | None:
    """``(nt_status, security_blob)`` from an SMB2 SESSION_SETUP response.

    The blob is the peer's NTLMSSP CHALLENGE in the first round (status
    ``STATUS_MORE_PROCESSING_REQUIRED``) and empty in the second.
    """
    if len(data) < 4:
        return None
    body = data[4:] if data[:1] in {b"\x00", b"\x80"} else data
    if body[:4] != b"\xfeSMB" or len(body) < 64 + 8:
        return None
    status = int(struct.unpack("<I", body[8:12])[0])
    blob_offset, blob_length = struct.unpack("<HH", body[64 + 4 : 64 + 8])
    blob = b""
    # SecurityBufferOffset is measured from the start of the SMB2 header (MS-SMB2 §2.2.6),
    # so it already includes the 64-byte header — adding it again would read past the buffer.
    if blob_length and blob_offset + blob_length <= len(body):
        blob = body[blob_offset : blob_offset + blob_length]
    return status, blob
