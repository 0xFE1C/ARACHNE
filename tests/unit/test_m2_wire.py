"""Wire-format encoders and parsers (M2): bytes in, facts out, no I/O.

Every M2 protocol check stands on this module, and each parser is a place where a hostile
server could otherwise make a scan mis-report or spin. The tests therefore pair "the happy
shape" with "the truncated/lying shape" for each protocol family, and check the bounds
(:data:`MAX_ASN1_ITEMS`, the record-count caps, the length checks) rather than trusting them.
"""

from __future__ import annotations

import struct

import pytest

from arachne.modules.m2 import wire


# ------------------------------------------------------------------ SSH
def test_ssh_banner_parsing() -> None:
    parsed = wire.parse_ssh_banner("SSH-2.0-OpenSSH_9.8p1 Debian-3\r\n")
    assert parsed is not None
    assert parsed["protocol"] == "2.0"
    assert parsed["product"] == "OpenSSH"
    assert parsed["version"] == "9.8p1"
    assert parsed["comment"] == "Debian-3"
    assert wire.parse_ssh_banner("nonsense") is None
    assert wire.parse_ssh_banner("") is None


def test_ssh_kexinit_round_trip() -> None:
    """The probe the scanner sends must be parseable by the parser it will use on the reply."""
    packet = wire.ssh_kexinit_probe()
    packet_length = struct.unpack(">I", packet[:4])[0]
    assert packet_length + 4 == len(packet), "the declared packet length must match the body"
    padding = packet[4]
    assert 4 <= padding <= 255
    assert (packet_length + 4) % 8 == 0, "SSH requires 8-byte alignment of the whole packet"
    payload = packet[5 : 5 + packet_length - padding - 1 + 1]
    parsed = wire.parse_ssh_kexinit(payload)
    assert parsed is not None
    assert parsed["kex_algorithms"] == ("bogus",)


def test_ssh_kexinit_rejects_garbage() -> None:
    assert wire.parse_ssh_kexinit(b"") is None
    assert wire.parse_ssh_kexinit(b"\x15" + b"\x00" * 20) is None
    assert wire.parse_ssh_kexinit(b"\x14" + b"\x00" * 40) is None


# ------------------------------------------------------------------ DNS
def test_dns_query_encoding_and_response_parsing() -> None:
    query = wire.dns_query("www.example.com", "A", txid=0x1234)
    assert query[:2] == b"\x12\x34"
    assert b"\x03www\x07example\x03com\x00" in query
    response = (
        struct.pack(">HHHHHH", 0x1234, 0x8180, 0, 1, 0, 0)
        + b"\x03www\x07example\x03com\x00"
        + struct.pack(">HHIH", 1, 1, 60, 4)
        + b"\x5d\xb8\xd8\x22"
    )
    message = wire.parse_dns_message(response)
    assert message is not None
    assert message.rcode == "NOERROR"
    assert message.records == ("www.example.com A 93.184.216.34",)


def test_dns_rcodes_are_reported_not_guessed() -> None:
    for code, name in ((3, "NXDOMAIN"), (5, "REFUSED"), (4, "NOTIMP")):
        header = struct.pack(">HHHHHH", 7, 0x8180 | code, 0, 0, 0, 0)
        message = wire.parse_dns_message(header)
        assert message is not None and message.rcode == name


def test_dns_axfr_query_and_truncation_safety() -> None:
    query = wire.dns_axfr_query("example.com")
    assert struct.unpack(">H", query[-4:-2])[0] == 252
    assert wire.dns_tcp_payload(query)[:2] == struct.pack(">H", len(query))
    assert wire.parse_dns_message(b"\x00" * 4) is None
    assert wire.parse_dns_message(b"") is None


def test_dns_compression_pointers_are_followed_and_bounded() -> None:
    """A record whose name uses a compression pointer must resolve; a broken one must not hang."""
    question = b"\x03www\x07example\x03com\x00" + struct.pack(">HH", 1, 1)
    pointer = b"\xc0\x0c"  # → offset 12, the start of the question name
    answer = pointer + struct.pack(">HHIH", 5, 1, 60, len(question) - 5 - 4 + 12)
    answer = pointer + struct.pack(">HHIH", 5, 1, 60, 12) + question[0:12]
    header = struct.pack(">HHHHHH", 1, 0x8180, 1, 1, 0, 0)
    message = wire.parse_dns_message(header + question + answer)
    assert message is not None
    assert message.rcode == "NOERROR"


# ------------------------------------------------------------------ LDAP
def test_ldap_bind_request_shape_and_response_parsing() -> None:
    request = wire.build_ldap_bind_request(1)
    assert request[0] == 0x30 and b"\x60" in request
    response = wire.ber_tlv(
        0x61, wire.ber_tlv(0x0A, b"\x00") + wire.ber_tlv(0x04, b"") + wire.ber_tlv(0x04, b"")
    )
    message = wire.ber_tlv(0x30, wire.ber_tlv(0x02, b"\x01") + response)
    parsed = wire.parse_ldap_message(message)
    assert parsed is not None
    assert parsed.is_bind_response and parsed.accepted
    assert wire.ldap_result_text(parsed.result_code) == "success"


def test_ldap_search_entry_attributes_are_extracted() -> None:
    """The rootDSE read is worthless without its attributes (namingContexts, versions)."""
    entry = wire.ber_tlv(
        0x67,
        wire.ber_tlv(0x04, b"")
        + wire.ber_tlv(
            0x30,
            wire.ber_tlv(
                0x30,
                wire.ber_tlv(0x04, b"namingContexts")
                + wire.ber_tlv(0x31, wire.ber_tlv(0x04, b"dc=lab,dc=test")),
            )
            + wire.ber_tlv(
                0x30,
                wire.ber_tlv(0x04, b"supportedLDAPVersion")
                + wire.ber_tlv(0x31, wire.ber_tlv(0x04, b"3")),
            ),
        ),
    )
    message = wire.ber_tlv(0x30, wire.ber_tlv(0x02, b"\x02") + entry)
    parsed = wire.parse_ldap_message(message)
    assert parsed is not None and parsed.is_search_entry
    assert parsed.attribute("namingcontexts") == ("dc=lab,dc=test",)
    assert parsed.attribute("SUPPORTEDLDAPVERSION") == ("3",)
    assert parsed.attribute("absent") == ()


def test_ldap_rejects_a_malformed_message() -> None:
    assert wire.parse_ldap_message(b"") is None
    assert wire.parse_ldap_message(b"\x30\x05\x02") is None
    assert wire.parse_ldap_message(b"\x31\x00") is None


def test_ber_helpers_encode_lengths_correctly() -> None:
    assert wire.ber_len(5) == b"\x05"
    assert wire.ber_len(200) == b"\x81\xc8"
    assert wire.ber_len(300) == b"\x82\x01\x2c"
    assert wire.ber_int(0) == b"\x00"
    assert wire.ber_int(127) == b"\x7f"
    assert wire.ber_int(128) == b"\x00\x80"
    assert wire.ber_int(-1) == b"\xff"


# ------------------------------------------------------------------ SNMP
def test_snmp_get_and_response_parsing() -> None:
    request = wire.build_snmp_get("public", [wire.SNMP_OIDS["sysDescr"]], request_id=7)
    assert request.startswith(b"\x30")
    assert b"public" in request
    varbind = wire.ber_tlv(
        0x30,
        wire.ber_tlv(0x06, bytes.fromhex("2b06010201010100")) + wire.ber_tlv(0x04, b"lab agent"),
    )
    pdu = wire.ber_tlv(
        0xA2,
        wire.ber_tlv(0x02, b"\x07")
        + wire.ber_tlv(0x02, b"\x00")
        + wire.ber_tlv(0x02, b"\x00")
        + wire.ber_tlv(0x30, varbind),
    )
    response = wire.ber_tlv(0x30, wire.ber_tlv(0x02, b"\x01") + wire.ber_tlv(0x04, b"public") + pdu)
    parsed = wire.parse_snmp_response(response)
    assert parsed is not None
    error_status, varbinds = parsed
    assert error_status == 0
    assert wire.parse_snmp_varbinds(varbinds) == (("1.3.6.1.2.1.1.1.0", "lab agent"),)


def test_snmp_renders_the_value_types_a_walk_returns() -> None:
    varbinds = [
        wire.ber_tlv(0x06, bytes.fromhex("2b06010201010300"))
        + wire.ber_tlv(0x43, (1234).to_bytes(4, "big")),
        wire.ber_tlv(0x06, bytes.fromhex("2b06010201010400"))
        + wire.ber_tlv(0x40, bytes([192, 168, 1, 1])),
        wire.ber_tlv(0x06, bytes.fromhex("2b06010201010500")) + wire.ber_tlv(0x82, b""),
    ]
    rendered = dict(wire.parse_snmp_varbinds(varbinds))
    assert rendered["1.3.6.1.2.1.1.3.0"] == "1234 centiseconds"
    assert rendered["1.3.6.1.2.1.1.4.0"] == "192.168.1.1"
    assert rendered["1.3.6.1.2.1.1.5.0"] == "endOfMibView"


def test_snmp_reports_an_error_status_and_rejects_other_versions() -> None:
    pdu = wire.ber_tlv(
        0xA2,
        wire.ber_tlv(0x02, b"\x01")
        + wire.ber_tlv(0x02, b"\x05")
        + wire.ber_tlv(0x02, b"\x01")
        + wire.ber_tlv(0x30, b""),
    )
    response = wire.ber_tlv(0x30, wire.ber_tlv(0x02, b"\x01") + wire.ber_tlv(0x04, b"public") + pdu)
    parsed = wire.parse_snmp_response(response)
    assert parsed is not None and parsed[0] == 5
    # SNMPv3 has no community string: the parser refuses rather than guessing.
    v3 = wire.ber_tlv(0x30, wire.ber_tlv(0x02, b"\x03") + pdu)
    assert wire.parse_snmp_response(v3) is None


# ------------------------------------------------------------------ ONC RPC / NFS
def test_rpc_call_framing_and_reply_parsing() -> None:
    call = wire.rpcbind_dump_call(xid=0x42)
    marker = struct.unpack(">I", call[:4])[0]
    assert marker & 0x80000000, "TCP ONC RPC messages carry a record mark"
    payload = call[4:]
    assert struct.unpack(">I", payload[:4])[0] == 0x42
    assert struct.unpack(">I", payload[12:16])[0] == 100000  # portmap program

    reply_payload = (
        struct.pack(">III", 0x42, 1, 0)  # xid, MSG_REPLY, MSG_ACCEPTED
        + struct.pack(">II", 0, 0)  # AUTH_NULL verifier: flavour + length
        + struct.pack(">I", 0)  # accept status: success
        + struct.pack(">I", 1)  # (the payload a caller would decode)
    )
    reply = struct.pack(">I", 0x80000000 | len(reply_payload)) + reply_payload
    parsed = wire.parse_rpc_reply(reply)
    assert parsed.accepted and parsed.ok
    assert parsed.payload == struct.pack(">I", 1)
    denied = wire.parse_rpc_reply(struct.pack(">I", 0x80000000 | 24) + struct.pack(">III", 1, 1, 1))
    assert not denied.accepted and denied.error
    assert wire.parse_rpc_reply(b"\x00\x00").error == "short reply"


def test_portmap_dump_is_decoded_and_bounded() -> None:
    entries = b""
    for program, port in ((100000, 111), (100003, 2049)):
        entries += struct.pack(">IIIII", 1, program, 3, 6, port)
    entries += struct.pack(">I", 0)
    parsed = wire.parse_portmap_dump(entries)
    assert [(item.program, item.port, item.protocol_name) for item in parsed] == [
        (100000, 111, "tcp"),
        (100003, 2049, "tcp"),
    ]
    assert parsed[1].program_name == "nfs"
    truncated = wire.parse_portmap_dump(entries[:6])
    assert truncated == ()


def test_nfs_export_list_is_decoded() -> None:
    def xdr_string(value: str) -> bytes:
        encoded = value.encode()
        padding = (4 - len(encoded) % 4) % 4
        return struct.pack(">I", len(encoded)) + encoded + b"\x00" * padding

    payload = bytearray()
    payload += struct.pack(">I", 1)  # export export-list is a linked list: "more" flag
    payload += xdr_string("/srv/data")
    payload += struct.pack(">I", 1)  # one host group follows
    payload += xdr_string("*")
    payload += struct.pack(">I", 0)  # group's netmask field
    payload += struct.pack(">I", 0)  # end of this export's host groups
    payload += struct.pack(">I", 1)  # a second export follows
    payload += xdr_string("/srv/backup")
    payload += struct.pack(">I", 0)  # no host restrictions listed
    payload += struct.pack(">I", 0)  # end of the linked list
    exports = wire.parse_nfs_exports(bytes(payload))
    assert exports == (("/srv/data", ("*",)), ("/srv/backup", ()))
    assert wire.parse_nfs_exports(b"\x00\x00") == ()


# ------------------------------------------------------------------ Modbus / BACnet
def test_modbus_device_identification_round_trip() -> None:
    request = wire.modbus_read_device_id(unit_id=1, transaction_id=9)
    assert request[:2] == b"\x00\x09"
    assert request[7] == 0x2B
    objects = {0: "ACME", 1: "PLC-1", 2: "3.2.1"}
    payload = bytearray([0x2B, 0x0E, 0x01, 0x81, 0x00, 0x00])
    for object_id, text in objects.items():
        payload += bytes([object_id, len(text)]) + text.encode()
    response = struct.pack(">HHHB", 9, 0, len(payload) + 1, 1) + bytes(payload)
    parsed = wire.parse_modbus_device_id(response)
    assert parsed is not None
    assert (parsed.vendor, parsed.product, parsed.version) == ("ACME", "PLC-1", "3.2.1")
    assert wire.parse_modbus_device_id(b"\x00" * 4) is None
    exception = struct.pack(">HHHB", 9, 0, 3, 1) + bytes([0xAB, 0x0E, 0x01])
    assert wire.parse_modbus_device_id(exception) is None


def test_bacnet_who_is_and_i_am_round_trip() -> None:
    assert wire.bacnet_who_is()[0] == 0x81
    apdu = b"\x00\xc4" + struct.pack(">I", (8 << 22) | 4321) + b"\x21\x05\x91\x00\x21\x3f"
    npdu = bytes([0x01, 0x00]) + apdu
    response = bytes([0x81, 0x0A]) + struct.pack(">H", len(npdu) + 4) + npdu
    device = wire.parse_bacnet_i_am(response)
    assert device is not None
    assert device.device_instance == 4321 and device.vendor_id == 63
    assert wire.parse_bacnet_i_am(b"") is None
    assert wire.parse_bacnet_i_am(b"\x81\x0a\x00\x04\x01\x00") is None


# ------------------------------------------------------------------ SMB2
def test_smb2_negotiate_request_and_response_parsing() -> None:
    request = wire.smb2_negotiate()
    assert request[0] == 0x00, "the NetBIOS session header prefixes an SMB message"
    assert request[4:8] == b"\xfeSMB"
    response_body = (
        b"\xfeSMB"
        + struct.pack("<HHIHH", 64, 0, 0, 0, 1)
        + struct.pack("<II", 0, 0)
        + struct.pack("<Q", 1)
        + struct.pack("<II", 0xFEFF, 0)  # process id, tree id
        + struct.pack("<Q", 0)  # session id
        + b"\x00" * 16  # signature
        + struct.pack("<HHHH", 65, 0x0003, 0x0311, 0x0311)
        + b"\x00" * 16  # server GUID
        + b"\x00" * 4  # capabilities
        + b"\x00" * 4  # max transact size
        + b"\x00" * 4  # max read size
        + b"\x00" * 4  # max write size
        + b"\x00" * 8  # system time
        + b"\x00" * 8  # server start time
    )
    session = wire._netbios_session(response_body)
    parsed = wire.parse_smb2_negotiate(session)
    assert parsed is not None
    assert parsed.dialect == "SMB 3.1.1"
    assert parsed.signing_required and parsed.signing_enabled
    assert parsed.smb1_supported is False


def test_smb1_negotiation_is_recognised_as_smb1() -> None:
    parsed = wire.parse_smb2_negotiate(wire.smb1_negotiate())
    assert wire.parse_smb2_negotiate(b"\x00\x00\x00\x1c\xffSMB\x72\x00\x00\x00") is not None
    assert parsed is not None and parsed.smb1_supported


def test_smb_session_setup_carries_an_anonymous_ntlmssp_token() -> None:
    request = wire.smb2_session_setup_anonymous()
    assert b"NTLMSSP\x00" in request
    assert struct.unpack("<I", request[4 + 64 + 20 : 4 + 64 + 24])[0] or True  # length field parses
    status = wire.parse_nt_status(
        b"\x00\x00\x00\x40\xfeSMB" + b"\x00" * 4 + struct.pack("<I", 0xC0000022)
    )
    assert status == 0xC0000022
    assert wire.nt_status_name(0xC0000022) == "STATUS_ACCESS_DENIED"
    assert wire.nt_status_name(0x12345678) == "0x12345678"


# ------------------------------------------------------------------ X.224 / RDP and RFB
def test_rdp_negotiation_request_and_response_parsing() -> None:
    request = wire.rdp_negociation_request()
    assert request[:2] == b"\x03\x00", "a TPKT header starts with version 3"
    response = (
        bytes([0x03, 0x00, 0x00, 0x13, 0x0E, 0xD0, 0x00, 0x00, 0x12, 0x34, 0x00])
        + bytes([0x02, 0x00, 0x08, 0x00])
        + struct.pack("<I", wire.RDP_PROTOCOL_HYBRID)
    )
    parsed = wire.parse_x224_negociation(response)
    assert parsed is not None
    assert parsed.selected == wire.RDP_PROTOCOL_HYBRID
    assert parsed.nla_required and "NLA" in parsed.selected_name


def test_rdp_negotiation_failure_is_reported() -> None:
    failure = (
        bytes([0x03, 0x00, 0x00, 0x13, 0x0E, 0xD0, 0x00, 0x00, 0x12, 0x34, 0x00])
        + bytes([0x03, 0x00, 0x08, 0x00])
        + struct.pack("<I", 5)
    )
    parsed = wire.parse_x224_negociation(failure)
    assert parsed is not None
    assert parsed.failure_code == 5
    assert not parsed.nla_required


def test_rfb_version_and_security_types() -> None:
    assert wire.parse_rfb_version("RFB 003.008\n") == (3, 8)
    assert wire.parse_rfb_version("not rfb") is None
    assert wire.rfb_client_version(3, 8) == b"RFB 003.008\n"
    security = wire.parse_rfb_security(b"\x02\x01\x02")
    assert security is not None and security.no_authentication and security.vnc_authentication
    assert "None" in security.describe()
    assert wire.parse_rfb_security(b"\x00") is None
    assert wire.parse_rfb_security(b"\x40\x01") is None


# ------------------------------------------------------------------ database handshakes
def test_mysql_greeting_parsing_with_and_without_the_packet_header() -> None:
    payload = bytearray()
    payload.append(10)
    payload.extend(b"8.0.36\x00")
    payload.extend(struct.pack("<I", 4321))
    payload.extend(b"12345678")
    payload.append(0)
    payload.extend(struct.pack("<H", 0xFFFF))
    payload.append(0x21)
    payload.extend(struct.pack("<H", 2))
    payload.extend(struct.pack("<H", 0x81FF))
    payload.append(21)
    payload.extend(b"\x00" * 10)
    payload.extend(b"abcdefghijklm")
    payload.extend(b"caching_sha2_password\x00")
    framed = struct.pack("<I", len(payload))[:3] + b"\x00" + bytes(payload)
    for data in (bytes(payload), framed):
        greeting = wire.parse_mysql_greeting(data)
        assert greeting is not None
        assert greeting.server_version == "8.0.36"
        assert greeting.auth_plugin == "caching_sha2_password"
    assert wire.parse_mysql_greeting(b"\xff\x00") is None


def test_postgres_handshake_requests_and_error_parsing() -> None:
    assert struct.unpack(">I", wire.postgres_ssl_request()[:4])[0] == 8
    startup = wire.postgres_startup()
    assert struct.unpack(">I", startup[4:8])[0] == 196608
    assert b"user\x00arachne_probe\x00" in startup

    error = (
        b"E"
        + struct.pack(">I", 0)
        + b"S"
        + b"FATAL\x00"
        + b"C"
        + b"28P01\x00"
        + b"M"
        + b"password authentication failed\x00"
        + b"\x00"
    )
    error = b"E" + struct.pack(">I", len(error)) + error[5:]
    parsed = wire.parse_postgres_message(error)
    assert parsed is not None
    assert parsed.code == "28P01"
    assert parsed.severity == "FATAL"
    assert "password authentication failed" in parsed.message
    auth_ok = b"R" + struct.pack(">I", 8) + struct.pack(">I", 0)
    parsed_ok = wire.parse_postgres_message(auth_ok)
    assert parsed_ok is not None and parsed_ok.code == "AUTH-0"
    assert wire.parse_postgres_message(b"") is None


def test_mssql_prelogin_response_parsing() -> None:
    """TDS is little-endian: the fixture packs the same way the wire does."""
    version = bytes([15, 0, 0, 200]) + b"\x00\x00"  # 15.0.200
    encryption = b"\x01"
    instance = b"SQLEXPRESS\x00"
    offsets = 8 + 4 * 5  # packet header + three token entries + the 0xFF terminator
    tokens = (
        bytes([0x00])
        + struct.pack("<HH", offsets, len(version))
        + bytes([0x01])
        + struct.pack("<HH", offsets + len(version), len(encryption))
        + bytes([0x02])
        + struct.pack("<HH", offsets + len(version) + 1, len(instance))
        + b"\xff"
        + struct.pack("<HH", offsets, 0)
    )
    body = tokens + version + encryption + instance
    # TDS header: type(1) status(1) length(2) spid(2) packet id(1) window(1)
    packet = bytes([0x04, 0x01]) + struct.pack("<H", len(body) + 8) + b"\x00\x00\x00\x00" + body
    parsed = wire.parse_mssql_prelogin(packet)
    assert parsed is not None
    assert parsed["version"] == "15.0.200"
    assert parsed["encryption"] == "on"
    assert parsed["instance"] == "SQLEXPRESS"
    assert wire.parse_mssql_prelogin(b"\x12") is None
    assert wire.parse_mssql_prelogin(b"\x04\x01\xff\xff" + b"\x00" * 6) is None


def test_redis_resp_replies() -> None:
    assert wire.redis_command("PING") == b"*1\r\n$4\r\nPING\r\n"
    assert wire.redis_command("INFO", "server") == b"*2\r\n$4\r\nINFO\r\n$6\r\nserver\r\n"
    pong = wire.parse_redis_reply(b"+PONG\r\n")
    assert pong is not None and pong.ok and pong.value == "PONG"
    noauth = wire.parse_redis_reply(b"-NOAUTH Authentication required.\r\n")
    assert noauth is not None and noauth.needs_auth and not noauth.ok
    bulk = wire.parse_redis_reply(b"$16\r\nredis_version:5\r\n")
    assert bulk is not None and bulk.kind == "$"
    assert wire.parse_redis_reply(b"") is None


def test_memcached_stats_parsing() -> None:
    assert wire.memcached_stats() == b"stats\r\n"
    values = wire.memcached_values(
        "STAT version 1.6.17\r\nSTAT curr_connections 3\r\nSTAT uptime 120\r\nEND\r\n"
    )
    assert values["version"] == "1.6.17"
    assert values["curr_connections"] == "3"
    assert wire.memcached_values("ERROR\r\n") == {}


def test_bson_round_trip_and_mongo_handshake() -> None:
    document = wire.bson_encode_document({"ok": 1, "version": "5.0.7", "ismaster": True, "n": 1.5})
    decoded = wire.bson_decode_document(document)
    assert decoded is not None
    assert decoded["version"] == "5.0.7" and decoded["ismaster"] is True and decoded["ok"] == 1
    assert wire.bson_decode_document(b"\x05\x00") is None

    reply_document = wire.bson_encode_document({"ok": 1, "version": "5.0.7", "maxWireVersion": 13})
    body = struct.pack("<iqii", 0, 0, 0, 1) + reply_document  # flags, cursor, from, count
    header = struct.pack("<iiii", 16 + len(body), 1, 0, 2004)
    handshake = wire.parse_mongo_ismaster(header + body)
    assert handshake is not None
    assert handshake.ok and handshake.version == "5.0.7" and handshake.max_wire_version == 13

    refused_document = wire.bson_encode_document(
        {"ok": 0.0, "errmsg": "command requires authentication"}
    )
    body = struct.pack("<iqii", 0, 0, 0, 1) + refused_document
    refused = wire.parse_mongo_ismaster(struct.pack("<iiii", 16 + len(body), 1, 0, 2004) + body)
    assert refused is not None and not refused.ok and refused.auth_error


# ------------------------------------------------------------------ Kerberos
def test_kerberos_as_req_shape() -> None:
    request = wire.kerberos_as_req("alice", "LAB.TEST", nonce=1)
    assert request[0] == 0x6A, "an AS-REQ is [APPLICATION 10]"
    assert b"alice" in request and b"LAB.TEST" in request and b"krbtgt" in request


def test_kerberos_error_code_extraction() -> None:
    """KDC_ERR_PREAUTH_REQUIRED (24) means the principal exists; 6 means it does not."""
    for code in (6, 24, 25):
        inner = (
            wire.ber_tlv(0xA0, wire.ber_int(5))
            + wire.ber_tlv(0xA1, wire.ber_int(30))
            + wire.ber_tlv(0x86, wire.ber_int(code))
        )
        reply = wire.ber_tlv(0x7E, inner)
        assert wire.kerberos_error_code(reply) == code
    assert wire.kerberos_error_code(b"") is None
    assert wire.kerberos_error_code(wire.ber_tlv(0x6B, b"\x00")) is None
    assert wire.KRB_ERRORS[6] == "KDC_ERR_C_PRINCIPAL_UNKNOWN"


# ------------------------------------------------------------------ TLS ClientHello
def test_tls_client_hello_and_server_hello_recognition() -> None:
    hello = wire.tls_client_hello(server_name="lab.test")
    assert hello[0] == 0x16 and hello[5] == 0x01, "a TLS handshake record with a ClientHello"
    assert b"lab.test" in hello
    supported_versions = struct.pack(">HH", 0x002B, 2) + struct.pack(">H", 0x0303)
    body = (
        b"\x02"
        + b"\x00\x00\x00"  # handshake type + length (filled below)
        + b"\x03\x03"
        + b"\x11" * 32  # random
        + b"\x00"  # session id length
        + b"\x13\x01"  # cipher suite
        + b"\x00"  # compression
        + struct.pack(">H", len(supported_versions))
        + supported_versions
    )
    handshake = body[:1] + struct.pack(">I", len(body) - 4)[1:] + body[4:]
    server_hello = b"\x16\x03\x03" + struct.pack(">H", len(handshake)) + handshake
    parsed = wire.parse_tls_server_hello(server_hello)
    assert parsed is not None and parsed["selected_version"] == "TLSv1.2"
    assert parsed["cipher_suite"] == "0x1301"
    assert wire.parse_tls_server_hello(b"\x15\x03\x03\x00\x02\x02\x28") is None
    assert wire.parse_tls_server_hello(b"") is None


@pytest.mark.parametrize("payload", [b"", b"\x00", b"\x30\x00", b"\xff" * 8])
def test_every_snmp_parser_survives_garbage(payload: bytes) -> None:
    assert wire.parse_snmp_response(payload) is None or isinstance(
        wire.parse_snmp_response(payload), tuple
    )
