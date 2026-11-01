"""The shipped M2 wire grammars (S30, area FUZZ, REQ-FUZZ-002).

Each grammar wraps a *real* builder from :mod:`arachne.modules.m2.wire` — the exact bytes the
shipped M2 checks send — and declares which ranges of that message are the operation code, the
length fields, the identifiers and the free text. The offsets are not guessed: they are derived
from the seed the builder produced and then **verified** by
:meth:`~arachne.fuzz.grammar.MessageGrammar.__post_init__`, which refuses a grammar whose
framing arithmetic does not describe its own seed and whose operation field does not hold a
read-only operation. A wrong offset in this file is an import error, not a fuzzer that quietly
mutates the wrong bytes.

Every seed is deterministic — explicit transaction ids, fixed nonces, a fixed ClientHello
random — because a fuzz case has to be replayable for its evidence to mean anything.

Two grammars deliberately carry ``verifier=None``: TCP and DNS/SNMP reads on a lab peer are
probed by shipped checks, but no shipped check can *prove* a signal from a raw Modbus reply, say,
and naming an unrelated check so that a candidate looks verifiable would be worse than saying
so. Such a candidate is recorded for manual triage and is not proposed as a hypothesis
(REQ-FUZZ-004 is honest about the difference).
"""

from __future__ import annotations

from typing import Any, Final

from arachne.fuzz.grammar import (
    ChecksumSpec,
    FieldKind,
    FieldSpec,
    FramingSpec,
    MessageGrammar,
    ResponseReading,
)
from arachne.modules.m2 import wire

__all__ = ["GRAMMARS", "GRAMMAR_NAMES", "get_grammar", "grammar_catalogue"]


def _no_answer(data: bytes) -> ResponseReading | None:
    """``unknown`` for an empty reply, else ``None`` so the caller's parser can have it."""
    return ResponseReading("unknown", "no response bytes") if not data else None


def _dns_reading(data: bytes) -> ResponseReading:
    """A DNS reply: NOERROR is an answer, any other RCODE is a well-formed refusal."""
    empty = _no_answer(data)
    if empty is not None:
        return empty
    message = wire.parse_dns_message(data)
    if message is None:
        return ResponseReading("unknown", "the reply does not parse as DNS")
    if not message.ok:
        return ResponseReading("refused", f"RCODE {message.rcodes}")
    return ResponseReading("ok", f"{message.answer_count} answer(s)")


def _snmp_reading(data: bytes) -> ResponseReading:
    """An SNMP reply: a GET-RESPONSE PDU parses, or the varbinds are empty (a refusal)."""
    empty = _no_answer(data)
    if empty is not None:
        return empty
    parsed = wire.parse_snmp_response(data)
    if parsed is None:
        return ResponseReading("unknown", "the reply does not parse as SNMP")
    request_id, varbinds = parsed
    if not varbinds:
        return ResponseReading("refused", "an empty varbind list")
    return ResponseReading("ok", f"{len(varbinds)} varbind(s) for request {request_id}")


def _modbus_reading(data: bytes) -> ResponseReading:
    """A Modbus reply: a device-identification map, or 0x2B+0x83 as the exception form."""
    empty = _no_answer(data)
    if empty is not None:
        return empty
    if len(data) >= 9 and data[7] == 0x2B and data[8] == 0x83:
        return ResponseReading("refused", f"Modbus exception {data[9]:#04x}")
    device = wire.parse_modbus_device_id(data)
    if device is None:
        return ResponseReading("unknown", "the reply does not parse as device identification")
    return ResponseReading("ok", f"vendor {device.vendor!r}")


def _s7_reading(data: bytes) -> ResponseReading:
    """A COTP reply: a Connection Confirm, or a COTP Disconnect/Reject."""
    empty = _no_answer(data)
    if empty is not None:
        return empty
    if len(data) >= 6 and data[5] in (0x80, 0x70):
        return ResponseReading("refused", f"COTP PDU {data[5]:#04x}")
    connection = wire.parse_s7_connection_confirm(data)
    if connection is None or not connection.confirmed:
        return ResponseReading("unknown", "the reply is not a COTP Connection Confirm")
    return ResponseReading("ok", f"destination TSAP {connection.destination_tsap.hex()}")


def _dnp3_reading(data: bytes) -> ResponseReading:
    """A DNP3 link reply: a CRC-verified frame, or an explicit CRC failure."""
    empty = _no_answer(data)
    if empty is not None:
        return empty
    link = wire.parse_dnp3_link(data)
    if link is None:
        return ResponseReading("unknown", "the reply is not a CRC-valid DNP3 link frame")
    return ResponseReading("ok", f"link function {link.function}")


def _rdp_reading(data: bytes) -> ResponseReading:
    """An X.224 reply: a negotiation response, or a failure code if the server refused."""
    empty = _no_answer(data)
    if empty is not None:
        return empty
    negotiation = wire.parse_x224_negociation(data)
    if negotiation is None:
        return ResponseReading("unknown", "the reply is not an X.224 negotiation response")
    if negotiation.failure_code:
        return ResponseReading("refused", f"negotiation failure {negotiation.failure_code:#010x}")
    return ResponseReading("ok", negotiation.selected_name)


def _ntlmssp_reading(data: bytes) -> ResponseReading:
    """An NTLMSSP reply: a CHALLENGE, or a well-formed non-challenge message."""
    empty = _no_answer(data)
    if empty is not None:
        return empty
    if not data.startswith(b"NTLMSSP\x00"):
        return ResponseReading("unknown", "the reply is not an NTLMSSP message")
    challenge = wire.parse_ntlmssp_challenge(data)
    if challenge is None:
        return ResponseReading("refused", "an NTLMSSP message that is not a type-2 CHALLENGE")
    return ResponseReading("ok", "server challenge present")


def _redis_reading(data: bytes) -> ResponseReading:
    """A RESP reply: a simple/bulk answer, or a ``-`` error line (a well-formed refusal)."""
    empty = _no_answer(data)
    if empty is not None:
        return empty
    reply = wire.parse_redis_reply(data)
    if reply is None:
        return ResponseReading("unknown", "the reply is not RESP")
    if reply.kind == "-":
        return ResponseReading("refused", reply.value[:120])
    return ResponseReading("ok", f"RESP {reply.kind}")


def _postgres_reading(data: bytes) -> ResponseReading:
    """A PostgreSQL reply: an ErrorResponse means the server answered; garbled bytes do not."""
    empty = _no_answer(data)
    if empty is not None:
        return empty
    reply = wire.parse_postgres_message(data)
    if reply is None:
        return ResponseReading("unknown", "the reply is not a PostgreSQL message")
    return ResponseReading("ok", f"{reply.type} ({reply.code or reply.message or 'no detail'})")


def _tls_reading(data: bytes) -> ResponseReading:
    """A TLS reply: a ServerHello, or an alert (which is a well-formed refusal)."""
    empty = _no_answer(data)
    if empty is not None:
        return empty
    if data[:1] == b"\x15":
        return ResponseReading("refused", "a TLS alert record")
    hello = wire.parse_tls_server_hello(data)
    if hello is None:
        return ResponseReading("unknown", "the reply is not a TLS ServerHello")
    return ResponseReading("ok", f"negotiated {hello.get('legacy_version', 'unknown')}")

#: Fixed values that make each seed reproducible. Not secrets: the point is that the same
#: grammar produces the same baseline on every run, so a report's differentials are meaningful.
_DNS_TXID: Final = 0x1234
_MODBUS_TXID: Final = 0x1234
_SNMP_REQUEST_ID: Final = 0x1234
_TLS_RANDOM: Final = bytes(range(32))
_SNMP_COMMUNITY: Final = "public"
_SNMP_OIDS: Final = ((1, 3, 6, 1, 2, 1, 1, 1, 0), (1, 3, 6, 1, 2, 1, 1, 2, 0))
_DNS_NAME: Final = "example.test"
_DNS_QTYPES: Final = (1, 2, 5, 6, 12, 15, 16, 28, 33, 255)
_DNS_QCLASSES: Final = (1, 3, 4, 255)


def _dns_query() -> MessageGrammar:
    def build() -> bytes:
        return wire.dns_query(_DNS_NAME, "A", txid=_DNS_TXID)

    seed = build()
    length = len(seed)
    return MessageGrammar(
        name="dns.query",
        protocol="dns",
        description=(
            "A recursive DNS query (UDP wire form): header counts, the encoded question name "
            "and the question type."
        ),
        builder=build,
        fields=(
            FieldSpec("transaction-id", 0, 2, FieldKind.ID, description="matches reply to query"),
            FieldSpec("flags", 2, 2, FieldKind.U16, description="QR/Opcode/RD/RA/RCODE"),
            FieldSpec("question-count", 4, 2, FieldKind.U16, description="QDCOUNT"),
            FieldSpec("answer-count", 6, 2, FieldKind.U16, description="ANCOUNT"),
            FieldSpec("authority-count", 8, 2, FieldKind.U16, description="NSCOUNT"),
            FieldSpec("additional-count", 10, 2, FieldKind.U16, description="ARCOUNT"),
            FieldSpec(
                "question-name",
                12,
                length - 16,
                FieldKind.OPAQUE,
                description="length-prefixed labels, terminated by a zero octet",
            ),
            FieldSpec(
                "question-type",
                length - 4,
                2,
                FieldKind.ENUM,
                values=_DNS_QTYPES,
                description="A/NS/CNAME/SOA/PTR/MX/TXT/AAAA/SRV/ANY",
            ),
            FieldSpec(
                "question-class",
                length - 2,
                2,
                FieldKind.ENUM,
                values=_DNS_QCLASSES,
                description="IN/CH/HS/ANY",
            ),
        ),
        classify=_dns_reading,
    )


def _snmp_get() -> MessageGrammar:
    def build() -> bytes:
        return wire.build_snmp_get(_SNMP_COMMUNITY, _SNMP_OIDS, request_id=_SNMP_REQUEST_ID)

    return MessageGrammar(
        name="snmp.get",
        protocol="snmp",
        description=(
            "An SNMPv2c GET-Request for two OIDs. Every length here is a BER definite length, "
            "which is where an SNMP parser's bugs live; the grammar declares no framing on "
            "purpose, so a mutation that makes a length inconsistent with its contents is "
            "reproduced rather than repaired."
        ),
        builder=build,
        fields=(
            FieldSpec("sequence-length", 1, 1, FieldKind.LENGTH, description="outer SEQUENCE"),
            FieldSpec(
                "community-tag",
                5,
                1,
                FieldKind.ENUM,
                values=(0x04,),
                description="OCTET STRING, the community's tag",
            ),
            FieldSpec("community-length", 6, 1, FieldKind.LENGTH),
            FieldSpec("community", 7, 6, FieldKind.TEXT, description="the v2c community"),
            FieldSpec(
                "pdu-tag",
                13,
                1,
                FieldKind.OPCODE,
                values=(0xA0, 0xA1, 0xA5),
                description="GetRequest/GetNextRequest/GetBulkRequest (read-only PDUs only)",
            ),
            FieldSpec("pdu-length", 14, 1, FieldKind.LENGTH),
            FieldSpec("request-id", 17, 2, FieldKind.ID, description="BER INTEGER body"),
            FieldSpec("error-status", 21, 1, FieldKind.U8),
            FieldSpec("error-index", 24, 1, FieldKind.U8),
            FieldSpec("varbind-list-length", 26, 1, FieldKind.LENGTH),
            FieldSpec(
                "oid",
                31,
                8,
                FieldKind.OPAQUE,
                description="the first requested OID's BER body",
            ),
        ),
        classify=_snmp_reading,
        verifier=None,
    )


def _modbus_read_device_id() -> MessageGrammar:
    def build() -> bytes:
        return wire.modbus_read_device_id(1, transaction_id=_MODBUS_TXID)

    return MessageGrammar(
        name="modbus.read-device-id",
        protocol="modbus",
        description=(
            "MBAP header plus function 0x2B / MEI 0x0E 'Read Device Identification' — the "
            "read-only Modbus request this program already sends. The MBAP length covers "
            "everything after the unit id, so the grammar can recompute it."
        ),
        builder=build,
        fields=(
            FieldSpec("transaction-id", 0, 2, FieldKind.ID),
            FieldSpec("protocol-id", 2, 2, FieldKind.ENUM, values=(0,)),
            FieldSpec(
                "length",
                4,
                2,
                FieldKind.LENGTH,
                description="bytes following the unit id",
            ),
            FieldSpec("unit-id", 6, 1, FieldKind.U8, description="the Modbus slave address"),
            FieldSpec(
                "function-code",
                7,
                1,
                FieldKind.OPCODE,
                values=(0x01, 0x02, 0x03, 0x04, 0x2B),
                description="read-only Modbus function codes only; the write family is refused",
            ),
            FieldSpec("mei-type", 8, 1, FieldKind.ENUM, values=(0x0E,)),
            FieldSpec(
                "read-device-id-code",
                9,
                1,
                FieldKind.ENUM,
                values=(1, 2, 3, 4),
                description="basic/extended/specific/individual access",
            ),
            FieldSpec("object-id", 10, 1, FieldKind.U8, description="MEI object identifier"),
        ),
        framings=(FramingSpec("length", start=6),),
        classify=_modbus_reading,
        verifier=None,
    )


def _s7_cotp_connect() -> MessageGrammar:
    def build() -> bytes:
        return wire.s7_cotp_connection_request(source_ref=0x0001, destination_ref=0x0000)

    return MessageGrammar(
        name="s7.cotp-connect",
        protocol="s7comm",
        description=(
            "TPKT + COTP Connection Request for ISO-TSAP (the S7 handshake's first step). The "
            "TPKT length covers everything after the four-byte TPKT header; the COTP length is "
            "a separate field the grammar mutates on its own terms."
        ),
        builder=build,
        fields=(
            FieldSpec("tpkt-version", 0, 1, FieldKind.ENUM, values=(3,)),
            FieldSpec("tpkt-reserved", 1, 1, FieldKind.U8),
            FieldSpec("tpkt-length", 2, 2, FieldKind.LENGTH, description="the whole TPKT frame"),
            FieldSpec(
                "cotp-length",
                4,
                1,
                FieldKind.LENGTH,
                description="the COTP PDU length as the builder states it",
            ),
            FieldSpec(
                "cotp-pdu-type",
                5,
                1,
                FieldKind.ENUM,
                values=(0xE0, 0xD0),
                description="Connection Request / Connection Confirm",
            ),
            FieldSpec("cotp-destination-ref", 6, 2, FieldKind.ID),
            FieldSpec("cotp-source-ref", 8, 2, FieldKind.ID),
            FieldSpec("cotp-class", 10, 1, FieldKind.U8),
            FieldSpec(
                "tsap-parameters",
                11,
                8,
                FieldKind.OPAQUE,
                description="the C1/C2 TSAP parameters",
            ),
        ),
        framings=(FramingSpec("tpkt-length", start=0),),
        classify=_s7_reading,
        verifier="m2.ot-protocol-probe",
    )


def _dnp3_link_status() -> MessageGrammar:
    def build() -> bytes:
        return wire.dnp3_link_status_request(source=3, destination=1)

    return MessageGrammar(
        name="dnp3.link-status",
        protocol="dnp3",
        description=(
            "A DNP3 link-layer REQUEST_LINK_STATUS frame — function 9, read-only, no user data. "
            "The link length covers control+destination+source, and the CRC over the first "
            "eight bytes is recomputed on every mutation so the target's link layer passes the "
            "frame to the parser instead of discarding it."
        ),
        builder=build,
        fields=(
            FieldSpec("start", 0, 2, FieldKind.ENUM, values=(0x0564,)),
            FieldSpec(
                "length",
                2,
                1,
                FieldKind.LENGTH,
                description="control + destination + source",
            ),
            FieldSpec(
                "control",
                3,
                1,
                FieldKind.U8,
                description="DIR/PRM/FCB/FCV + link function code (9 = REQUEST_LINK_STATUS)",
            ),
            FieldSpec("destination", 4, 2, FieldKind.ID, endian="little"),
            FieldSpec("source", 6, 2, FieldKind.ID, endian="little"),
            FieldSpec("crc", 8, 2, FieldKind.U16, endian="little"),
        ),
        framings=(FramingSpec("length", start=3, end=8),),
        checksums=(ChecksumSpec("crc", start=0, end=8, compute=wire.dnp3_crc, endian="little"),),
        classify=_dnp3_reading,
        verifier="m2.ot-protocol-probe",
    )


def _rdp_negotiation() -> MessageGrammar:
    def build() -> bytes:
        return wire.rdp_negociation_request()

    return MessageGrammar(
        name="rdp.negotiation",
        protocol="rdp",
        description=(
            "A TPKT/X.224 connection request carrying an RDP_NEG_REQ (NLA negotiation). The "
            "TPKT length covers the whole frame including its own four-byte header; the "
            "negotiation block is little-endian."
        ),
        builder=build,
        fields=(
            FieldSpec("tpkt-version", 0, 1, FieldKind.ENUM, values=(3,)),
            FieldSpec("tpkt-reserved", 1, 1, FieldKind.U8),
            FieldSpec(
                "tpkt-length",
                2,
                2,
                FieldKind.LENGTH,
                description="the whole TPKT frame, header included",
            ),
            FieldSpec("x224-length", 4, 1, FieldKind.U8, description="the X.224 CR length"),
            FieldSpec(
                "x224-pdu-type",
                5,
                1,
                FieldKind.ENUM,
                values=(0xE0, 0xD0),
                description="Connection Request / Connection Confirm",
            ),
            FieldSpec("x224-destination-ref", 6, 2, FieldKind.ID),
            FieldSpec("x224-source-ref", 8, 2, FieldKind.ID),
            FieldSpec("x224-class", 10, 1, FieldKind.U8),
            FieldSpec("cookie", 11, 7, FieldKind.TEXT, description="the mstshash cookie"),
            FieldSpec("neg-type", 20, 1, FieldKind.ENUM, values=(0x01, 0x02, 0x03)),
            FieldSpec("neg-flags", 21, 2, FieldKind.U16, endian="little"),
            FieldSpec("neg-length", 23, 4, FieldKind.U32, endian="little"),
            FieldSpec(
                "requested-protocols",
                27,
                4,
                FieldKind.ENUM,
                endian="little",
                values=(0, 1, 2, 3, 8, 11),
                description="RDP/SSL/HYBRID/HYBRID_EX combinations the client offers",
            ),
        ),
        framings=(FramingSpec("tpkt-length", start=0),),
        classify=_rdp_reading,
        verifier=None,
    )


def _ntlmssp_negotiate() -> MessageGrammar:
    def build() -> bytes:
        return wire.ntlmssp_negotiate()

    return MessageGrammar(
        name="ntlmssp.negotiate",
        protocol="ntlmssp",
        description=(
            "An NTLMSSP NEGOTIATE (type 1) message with empty domain and workstation security "
            "buffers. The two length fields claim zero bytes and their offsets point past the "
            "32-byte header — the shape a parser that trusts a security buffer has to get right."
        ),
        builder=build,
        fields=(
            FieldSpec(
                "signature",
                0,
                8,
                FieldKind.OPAQUE,
                description="'NTLMSSP\\0' — dropped to see whether it is checked at all",
            ),
            FieldSpec("message-type", 8, 4, FieldKind.ENUM, endian="little", values=(1, 2, 3)),
            FieldSpec("negotiate-flags", 12, 4, FieldKind.U32, endian="little"),
            FieldSpec("domain-length", 16, 2, FieldKind.LENGTH, endian="little"),
            FieldSpec("domain-max-length", 18, 2, FieldKind.U16, endian="little"),
            FieldSpec("domain-offset", 20, 4, FieldKind.ID, endian="little"),
            FieldSpec("workstation-length", 24, 2, FieldKind.LENGTH, endian="little"),
            FieldSpec("workstation-max-length", 26, 2, FieldKind.U16, endian="little"),
            FieldSpec("workstation-offset", 28, 4, FieldKind.ID, endian="little"),
        ),
        classify=_ntlmssp_reading,
        verifier=None,
    )


def _redis_ping() -> MessageGrammar:
    def build() -> bytes:
        return wire.redis_command("PING")

    return MessageGrammar(
        name="redis.ping",
        protocol="redis",
        description=(
            "A Redis PING in RESP array form. The counts and the bulk length are ASCII digits, "
            "so the numeric operators write binary values into them — a RESP parser that does "
            "not validate its digits is exactly the parser worth finding. The verb itself is a "
            "text field whose replacements are fixed boundary strings, none of which is a "
            "write verb, so this grammar cannot be made to issue one."
        ),
        builder=build,
        fields=(
            FieldSpec("array-marker", 0, 1, FieldKind.ENUM, values=(0x2A,)),
            FieldSpec("array-count", 1, 1, FieldKind.U8, description="RESP '*<n>' count digit"),
            FieldSpec("array-terminator", 2, 2, FieldKind.OPAQUE),
            FieldSpec("bulk-marker", 4, 1, FieldKind.ENUM, values=(0x24,)),
            FieldSpec("bulk-length", 5, 1, FieldKind.U8, description="RESP '$<n>' digit"),
            FieldSpec("bulk-terminator", 6, 2, FieldKind.OPAQUE),
            FieldSpec("command", 8, 4, FieldKind.TEXT, description="PING"),
            FieldSpec("command-terminator", 12, 2, FieldKind.OPAQUE),
        ),
        classify=_redis_reading,
        verifier=None,
    )


def _postgres_startup() -> MessageGrammar:
    def build() -> bytes:
        return wire.postgres_startup()

    return MessageGrammar(
        name="postgres.startup",
        protocol="postgres",
        description=(
            "A PostgreSQL StartupMessage for an intentionally non-existent role. The four-byte "
            "length covers the whole message including itself, and the two parameters are the "
            "free-text fields."
        ),
        builder=build,
        fields=(
            FieldSpec("length", 0, 4, FieldKind.LENGTH, description="the whole message"),
            FieldSpec(
                "protocol-version",
                4,
                4,
                FieldKind.ENUM,
                values=(196608, 80877102, 80877103),
                description="3.0, CancelRequest, SSLRequest",
            ),
            FieldSpec("user-parameter", 13, 13, FieldKind.TEXT, description="the user name"),
            FieldSpec(
                "database-parameter",
                36,
                8,
                FieldKind.TEXT,
                description="the database name",
            ),
        ),
        framings=(FramingSpec("length", start=0),),
        classify=_postgres_reading,
        verifier=None,
    )


def _tls_client_hello() -> MessageGrammar:
    def build() -> bytes:
        return wire.tls_client_hello(random=_TLS_RANDOM)

    seed = build()
    length = len(seed)
    return MessageGrammar(
        name="tls.client-hello",
        protocol="tls",
        description=(
            "A minimal TLS 1.2/1.3 ClientHello. Three nested length prefixes — record, "
            "handshake and extensions — each recomputed on a mutation of a field inside it, so "
            "the case is always a well-framed record whose *content* is wrong. The session id "
            "length claims zero bytes, which is the field a parser has to check before reading."
        ),
        builder=build,
        fields=(
            FieldSpec(
                "record-type",
                0,
                1,
                FieldKind.ENUM,
                values=(0x14, 0x15, 0x16),
                description="change_cipher_spec/alert/handshake",
            ),
            FieldSpec("record-version", 1, 2, FieldKind.ENUM, values=(0x0301, 0x0303)),
            FieldSpec("record-length", 3, 2, FieldKind.LENGTH, description="the handshake bytes"),
            FieldSpec(
                "handshake-type",
                5,
                1,
                FieldKind.ENUM,
                values=(0x01, 0x02, 0x0B),
                description="ClientHello/ServerHello/Certificate",
            ),
            FieldSpec("handshake-length", 6, 3, FieldKind.LENGTH, description="the body bytes"),
            FieldSpec("client-version", 9, 2, FieldKind.U16),
            FieldSpec("random", 11, 32, FieldKind.OPAQUE, description="the 32-byte nonce"),
            FieldSpec(
                "session-id-length",
                43,
                1,
                FieldKind.LENGTH,
                description="claims zero bytes of session id",
            ),
            FieldSpec(
                "cipher-suites-length",
                44,
                2,
                FieldKind.LENGTH,
                description="the cipher suite list length",
            ),
            FieldSpec("cipher-suites", 46, 12, FieldKind.OPAQUE),
            FieldSpec("compression-methods", 58, 2, FieldKind.OPAQUE),
            FieldSpec(
                "extensions-length",
                60,
                2,
                FieldKind.LENGTH,
                description="the extension block length",
            ),
            FieldSpec(
                "extensions",
                62,
                length - 62,
                FieldKind.OPAQUE,
                description="the supported_versions extension",
            ),
        ),
        framings=(
            FramingSpec("record-length", start=5, end=length),
            FramingSpec("handshake-length", start=9, end=length),
            FramingSpec("cipher-suites-length", start=46, end=58),
            FramingSpec("extensions-length", start=62, end=length),
        ),
        classify=_tls_reading,
        verifier=None,
    )


_FACTORIES: Final = {
    "dns.query": _dns_query,
    "snmp.get": _snmp_get,
    "modbus.read-device-id": _modbus_read_device_id,
    "s7.cotp-connect": _s7_cotp_connect,
    "dnp3.link-status": _dnp3_link_status,
    "rdp.negotiation": _rdp_negotiation,
    "ntlmssp.negotiate": _ntlmssp_negotiate,
    "redis.ping": _redis_ping,
    "postgres.startup": _postgres_startup,
    "tls.client-hello": _tls_client_hello,
}


def _build_grammars() -> dict[str, MessageGrammar]:
    """Construct every grammar once, at import.

    Construction validates each grammar against its own seed (framing arithmetic, checksum,
    operation allowlist), so this call is also the build's self-check: an offset that does not
    describe the real message raises here rather than producing a fuzzer that mutates the wrong
    byte.
    """
    return {name: factory() for name, factory in _FACTORIES.items()}


#: Every shipped grammar, by name.
GRAMMARS: Final[dict[str, MessageGrammar]] = _build_grammars()

#: The grammar names, in declaration order.
GRAMMAR_NAMES: Final[tuple[str, ...]] = tuple(_FACTORIES)


def get_grammar(name: str) -> MessageGrammar:
    """The grammar called ``name``; a ``KeyError`` if this build does not ship one."""
    try:
        return GRAMMARS[name]
    except KeyError as exc:
        known = ", ".join(sorted(GRAMMARS))
        msg = f"no fuzzing grammar named {name!r} (this build ships: {known})"
        raise KeyError(msg) from exc


def grammar_catalogue() -> tuple[dict[str, Any], ...]:
    """The grammars as a report renders them: protocol, field count, case count, verifier."""
    return tuple(GRAMMARS[name].to_dict() for name in GRAMMAR_NAMES)
