"""A stdlib-only vulnerable lab: real sockets on loopback, no Docker required.

 wants the integration layer to run against a Docker compose lab (DVWA,
Juice Shop, a misconfigured Nginx, a weak-TLS endpoint), and that fixture now exists
(``docker/docker-compose.yml``, ``docker/lab/``). But M2's checks talk raw TCP, UDP and TLS —
and proving *those* paths work needs real sockets, real banners and a real handshake, not a
mock. Requiring a container runtime for that would make the S4 integration suite unrunnable in
most CI environments, so this module starts a mini lab in-process:

===================================  ==============================================
service                              what it plants
===================================  ==============================================
``ssh``                              ``OpenSSH_8.5p1`` banner + a KEXINIT offering the
                                     deprecated ``ssh-rsa``/``group1-sha1`` algorithms
``http``                             ``nginx/1.18.0`` (a version with known CVEs)
``tls``                              a TLS endpoint with TLS 1.0 enabled and an **expired,
                                     self-signed** certificate, serving the same Nginx
``mysql``                            a MySQL 5.5.62 greeting (old version → CVE)
``redis``                            an unauthenticated Redis 5.0.7 (PING → +PONG, INFO)
``vnc``                              RFB 003.008 offering security type 1 (no auth)
``smtp``                             Postfix 3.4.14 that answers VRFY
``dns``                              a nameserver that permits AXFR and resolves a few names
``ldap``                             a directory that accepts an anonymous bind
``snmp`` (UDP, opt-in)                an agent that answers community ``public``
``modbus``                           a Modbus/TCP device identification response
===================================  ==============================================

Everything binds to ``127.0.0.1`` on ephemeral ports and is torn down by the context
manager, so a test can run in parallel with another copy of itself. The servers speak
*deliberately minimal but wire-correct* versions of their protocols: enough that ARACHNE's
own parsers accept the answers, which is the point — the assertion is "our client and parser
handle a real peer", not "our fixture is a full implementation of SSH".
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import os
import secrets
import socket
import ssl
import struct
import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from tests.lab import grpc_lab

from arachne.modules.m2 import wire

__all__ = [
    "LabFixture",
    "LabService",
    "start_m2_lab",
]

#: Bumped when the fixture's service set changes: the S29 additions (S7, DNP3 and the three
#: gRPC services) are recorded here so a stale cached fixture is spotted rather than trusted.
LAB_VERSION = "2.0"

CERT_DIR = Path(__file__).resolve().parents[1] / "fixtures" / "lab"

#: The Nginx version the lab reports — chosen because it is in the offline CVE index.
LAB_NGINX_VERSION = "1.18.0"
#: The OpenSSH version the lab reports (affected by CVE-2024-6387).
LAB_SSH_VERSION = "8.5p1"
#: The MySQL version the lab reports (affected by CVE-2017-3599 / CVE-2020-14750 range).
LAB_MYSQL_VERSION = "5.5.62"
#: The Redis version the lab reports (affected by CVE-2022-0543).
LAB_REDIS_VERSION = "5.0.7"
#: The DNS zone the lab serves.
LAB_ZONE = "lab.arachne.test"

Handler = Callable[[socket.socket], None]


@dataclass
class LabService:
    """One running fixture service."""

    name: str
    port: int
    protocol: str = "tcp"
    #: Stop the accept loop / close the socket.
    _stop: Callable[[], None] = lambda: None

    def stop(self) -> None:
        self._stop()


@dataclass
class LabFixture:
    """The whole lab: every service, plus the target definition fragments to scan it."""

    host: str = "127.0.0.1"
    services: dict[str, LabService] = field(default_factory=dict)

    def port(self, name: str) -> int:
        return self.services[name].port

    @property
    def ports(self) -> dict[str, int]:
        return {name: service.port for name, service in self.services.items()}

    @property
    def max_port(self) -> int:
        return max((service.port for service in self.services.values()), default=0)

    def stop(self) -> None:
        for service in self.services.values():
            service.stop()
        self.services.clear()


# --------------------------------------------------------------------------- plumbing
class _TcpServer:
    """A threaded TCP server: one thread per connection, bounded reads, clean shutdown."""

    def __init__(self, handler: Handler, *, name: str) -> None:
        self.handler = handler
        self.name = name
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(("127.0.0.1", 0))
        self.socket.listen(64)
        self.socket.settimeout(0.2)
        self.port = int(self.socket.getsockname()[1])
        self._running = True
        self._thread = threading.Thread(target=self._serve, name=f"lab-{name}", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def _serve(self) -> None:
        while self._running:
            try:
                connection, _ = self.socket.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            threading.Thread(
                target=self._handle, args=(connection,), daemon=True, name=f"lab-{self.name}-conn"
            ).start()

    def _handle(self, connection: socket.socket) -> None:
        try:
            connection.settimeout(5.0)
            self.handler(connection)
        except Exception:  # a fixture must never fail a test by raising in its thread
            return
        finally:
            with contextlib.suppress(OSError):
                connection.shutdown(socket.SHUT_RDWR)
            connection.close()

    def stop(self) -> None:
        self._running = False
        with contextlib.suppress(OSError):
            self.socket.close()


def _read(connection: socket.socket, size: int = 4096) -> bytes:
    """Read up to ``size`` bytes, tolerating a peer that sends nothing."""
    try:
        return connection.recv(size)
    except (TimeoutError, OSError):
        return b""


def _read_until_idle(connection: socket.socket, *, total: int = 8192) -> bytes:
    """Read until the peer goes quiet (or the cap is reached) — a full request buffer."""
    chunks: list[bytes] = []
    received = 0
    while received < total:
        chunk = _read(connection, total - received)
        if not chunk:
            break
        chunks.append(chunk)
        received += len(chunk)
    return b"".join(chunks)


# --------------------------------------------------------------------------- handlers
def _ssh(connection: socket.socket) -> None:
    connection.sendall(f"SSH-2.0-OpenSSH_{LAB_SSH_VERSION} Debian-3\r\n".encode())
    request = _read(connection, 512)
    if not request:
        return
    connection.sendall(_ssh_server_kexinit())


def _ssh_server_kexinit() -> bytes:
    """A server KEXINIT listing the deprecated algorithms the check must flag."""
    name_lists = (
        b"diffie-hellman-group1-sha1,diffie-hellman-group14-sha1,curve25519-sha256",
        b"ssh-rsa,rsa-sha2-256,ssh-ed25519",
        b"aes128-ctr,3des-cbc",
        b"aes128-ctr,3des-cbc",
        b"hmac-sha1,hmac-md5",
        b"hmac-sha1,hmac-md5",
        b"none",
        b"none",
        b"",
        b"",
    )
    body = b"".join(struct.pack(">I", len(item)) + item for item in name_lists)
    payload = b"\x14" + os.urandom(16) + body
    padding = 8 - ((len(payload) + 5) % 8)
    padding = padding if padding >= 4 else padding + 8
    return struct.pack(">IB", len(payload) + 1 + padding, padding) + payload + bytes(padding)


def _http_body(title: str = "ARACHNE lab target") -> bytes:
    return (
        "<!doctype html><html><head><title>"
        + title
        + "</title></head><body><h1>lab</h1></body></html>"
    ).encode()


def _http(connection: socket.socket) -> None:
    request = _read(connection, 4096)
    if not request:
        return
    body = _http_body()
    connection.sendall(
        b"HTTP/1.1 200 OK\r\n"
        + f"Server: nginx/{LAB_NGINX_VERSION}\r\n".encode()
        + b"Content-Type: text/html\r\n"
        + f"Content-Length: {len(body)}\r\n".encode()
        + b"Connection: close\r\n\r\n"
        + body
    )


def _tls_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(CERT_DIR / "expired.crt", CERT_DIR / "expired.key")
    with _suppress_deprecation():
        context.minimum_version = ssl.TLSVersion.TLSv1
        context.maximum_version = ssl.TLSVersion.TLSv1_2
    # SECLEVEL=0 keeps the legacy CBC suites available, which is the point of the fixture.
    context.set_ciphers("ALL:@SECLEVEL=0")
    return context


@contextmanager
def _suppress_deprecation() -> Iterator[None]:
    """Silence the ``ssl.TLSVersion.TLSv1`` deprecation (the test suite escalates it)."""
    import warnings

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        yield


def _tls_handler(context: ssl.SSLContext | None = None) -> Handler:
    def handler(connection: socket.socket) -> None:
        active = context or _tls_context()
        try:
            with _suppress_deprecation():
                wrapped = active.wrap_socket(connection, server_side=True)
        except (ssl.SSLError, OSError):
            return
        try:
            request = wrapped.recv(4096)
            if not request:
                return
            body = _http_body()
            wrapped.sendall(
                b"HTTP/1.1 200 OK\r\n"
                + f"Server: nginx/{LAB_NGINX_VERSION}\r\n".encode()
                + b"Content-Type: text/html\r\n"
                + f"Content-Length: {len(body)}\r\n".encode()
                + b"Connection: close\r\n\r\n"
                + body
            )
        finally:
            with contextlib.suppress(OSError):
                wrapped.close()

    return handler


def _mysql(connection: socket.socket) -> None:
    """A MySQL 5.5-era initial handshake packet."""
    capabilities_low = 0xFFFF
    capabilities_high = 0x81FF
    payload = bytearray()
    payload.append(10)  # protocol version
    payload.extend(LAB_MYSQL_VERSION.encode() + b"\x00")
    payload.extend(struct.pack("<I", 1234))  # connection id
    payload.extend(b"12345678")  # auth-plugin-data-part-1
    payload.append(0)  # filler
    payload.extend(struct.pack("<H", capabilities_low))
    payload.append(0x21)  # charset utf8_general_ci
    payload.extend(struct.pack("<H", 0x0002))  # status flags
    payload.extend(struct.pack("<H", capabilities_high))
    payload.append(21)  # auth plugin data length
    payload.extend(b"\x00" * 10)  # reserved
    payload.extend(b"abcdefghijklm")  # auth-plugin-data-part-2 (13 bytes)
    payload.extend(b"mysql_native_password\x00")
    header = struct.pack("<I", len(payload))[:3] + b"\x00"
    connection.sendall(bytes(header) + bytes(payload))


def _redis(connection: socket.socket) -> None:
    """An unauthenticated Redis: PING → +PONG, INFO → a bulk string with the version."""
    request = _read(connection, 4096)
    if not request:
        return
    upper = request.upper()
    if b"PING" in upper:
        connection.sendall(b"+PONG\r\n")
        return
    if b"INFO" in upper:
        info = (
            f"# Server\r\nredis_version:{LAB_REDIS_VERSION}\r\nredis_mode:standalone\r\n"
            "os:Linux\r\n# Clients\r\nconnected_clients:1\r\n"
        ).encode()
        connection.sendall(b"$" + str(len(info)).encode() + b"\r\n" + info + b"\r\n")
        return
    connection.sendall(b"-ERR unknown command\r\n")


def _vnc(connection: socket.socket) -> None:
    """RFB 3.8 offering exactly one security type: 1 (None) — the passwordless case."""
    connection.sendall(b"RFB 003.008\n")
    _read(connection, 64)
    connection.sendall(b"\x01\x01")


def _smtp(connection: socket.socket) -> None:
    connection.sendall(b"220 lab.arachne.test ESMTP Postfix 3.4.14\r\n")
    for _ in range(8):
        request = _read(connection, 1024)
        if not request:
            return
        command = request.split(b"\r\n", 1)[0].upper()
        if command.startswith(b"EHLO"):
            connection.sendall(
                b"250-lab.arachne.test\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n"
                b"250-VRFY\r\n250-EXPN\r\n250 HELP\r\n"
            )
        elif command.startswith(b"VRFY"):
            connection.sendall(b"252 2.0.0 cannot VRFY user, will accept\r\n")
        elif command.startswith(b"EXPN"):
            connection.sendall(b"250 2.1.5 <postmaster@lab.arachne.test>\r\n")
        elif command.startswith(b"MAIL FROM"):
            connection.sendall(b"250 2.1.0 Ok\r\n")
        elif command.startswith(b"RCPT TO"):
            connection.sendall(b"250 2.1.5 Ok\r\n")
        elif command.startswith(b"RSET"):
            connection.sendall(b"250 2.0.0 Ok\r\n")
        elif command.startswith(b"QUIT"):
            connection.sendall(b"221 2.0.0 Bye\r\n")
            return
        else:
            connection.sendall(b"502 5.5.2 Error: command not recognized\r\n")


#: Names the lab's DNS server resolves (the rest of the dictionary gets NXDOMAIN).
LAB_DNS_ANSWERS: dict[str, str] = {
    LAB_ZONE: "127.0.0.1",
    f"www.{LAB_ZONE}": "127.0.0.1",
    f"git.{LAB_ZONE}": "127.0.0.1",
    f"dev.{LAB_ZONE}": "127.0.0.1",
    f"staging.{LAB_ZONE}": "127.0.0.1",
    f"admin.{LAB_ZONE}": "127.0.0.1",
}


def _dns(connection: socket.socket) -> None:
    """A TCP DNS server: AXFR is permitted, and a few dictionary names resolve."""
    header = _read(connection, 2)
    if len(header) < 2:
        return
    length = struct.unpack(">H", header)[0]
    message = _read(connection, max(length, 512))
    if len(message) < 12:
        return
    transaction = message[:2]
    name, offset = _dns_name(message, 12)
    if offset + 4 > len(message):
        return
    qtype = struct.unpack(">H", message[offset : offset + 2])[0]
    question = message[12 : offset + 4]
    connection.sendall(_dns_response(transaction, question, name, qtype))


def _dns_name(message: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    while offset < len(message):
        length = message[offset]
        offset += 1
        if length == 0:
            break
        labels.append(message[offset : offset + length].decode("ascii", "replace"))
        offset += length
    return ".".join(labels), offset


def _dns_response(transaction: bytes, question: bytes, name: str, qtype: int) -> bytes:
    if qtype == 252:  # AXFR: hand over the whole (small) zone
        records = list(LAB_DNS_ANSWERS.items())
        rcode = 0
    else:
        address = LAB_DNS_ANSWERS.get(name.lower())
        records = [(name, address)] if address else []
        rcode = 0 if address else 3  # NXDOMAIN for everything else
    answers = bytearray()
    for fqdn, address in records:
        answers.extend(_encode_dns_name(fqdn))
        answers.extend(struct.pack(">HHIH", 1, 1, 60, 4))
        answers.extend(socket.inet_aton(address))
    header = transaction + struct.pack(">HHHHH", 0x8400 | rcode, 1, len(records), 0, 0)
    body = header + question + bytes(answers)
    return struct.pack(">H", len(body)) + body


def _encode_dns_name(name: str) -> bytes:
    out = bytearray()
    for label in name.strip(".").split("."):
        out.append(len(label))
        out.extend(label.encode())
    out.append(0)
    return bytes(out)


def _ldap(connection: socket.socket) -> None:
    """An LDAP server that accepts an anonymous bind and answers a rootDSE read."""
    request = _read(connection, 4096)
    if not request:
        return
    if b"\x60" in request[:16]:  # BindRequest → success
        connection.sendall(_ldap_message(1, _ldap_bind_response()))
        return
    # searchRequest → a searchResEntry carrying the rootDSE attributes
    connection.sendall(_ldap_message(2, _ldap_search_entry()))


def _ldap_message(message_id: int, body: bytes) -> bytes:
    return _ber(0x30, _ber(0x02, _ber_int_bytes(message_id)) + body)


def _ber(tag: int, value: bytes) -> bytes:
    if len(value) < 0x80:
        return bytes([tag, len(value)]) + value
    encoded = len(value).to_bytes((len(value).bit_length() + 7) // 8, "big")
    return bytes([tag, 0x80 | len(encoded)]) + encoded + value


def _ber_int_bytes(value: int) -> bytes:
    return value.to_bytes(max(1, (value.bit_length() + 7) // 8), "big")


def _ber_int(value: int) -> bytes:
    return _ber(0x02, _ber_int_bytes(value))


def _ber_str(value: str) -> bytes:
    return _ber(0x04, value.encode())


def _ldap_bind_response() -> bytes:
    return _ber(0x61, _ber_int(0) + _ber_str("") + _ber_str(""))


def _ldap_search_entry() -> bytes:
    attributes = _ber(
        0x30,
        _ber_str("namingContexts") + _ber(0x31, _ber_str("dc=lab,dc=arachne,dc=test")),
    ) + _ber(
        0x30,
        _ber_str("supportedLDAPVersion") + _ber(0x31, _ber_str("3")),
    )
    return _ber(
        0x67,
        _ber_str("") + _ber(0x30, attributes),
    )


# --------------------------------------------------------------------------- UDP services
class _UdpServer:
    """A datagram server with a request→response handler."""

    def __init__(self, handler: Callable[[bytes], bytes | None], *, name: str) -> None:
        self.handler = handler
        self.name = name
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.bind(("127.0.0.1", 0))
        self.socket.settimeout(0.2)
        self.port = int(self.socket.getsockname()[1])
        self._running = True
        self._thread = threading.Thread(target=self._serve, name=f"lab-{name}", daemon=True)

    def start(self) -> None:
        self._thread.start()

    def _serve(self) -> None:
        while self._running:
            try:
                payload, address = self.socket.recvfrom(8192)
            except TimeoutError:
                continue
            except OSError:
                return
            try:
                response = self.handler(payload)
            except Exception:  # a malformed probe is data, not a fixture failure
                response = None
            if response:
                with contextlib.suppress(OSError):
                    self.socket.sendto(response, address)

    def stop(self) -> None:
        self._running = False
        with contextlib.suppress(OSError):
            self.socket.close()


def _snmp_handler(request: bytes) -> bytes | None:
    """Answer an SNMPv2c GET for any community, echoing the requested OIDs with values."""
    if not request.startswith(b"\x30"):
        return None
    community_start = request.find(b"\x04")
    if community_start < 0:
        return None
    length = request[community_start + 1]
    community = request[community_start + 2 : community_start + 2 + length]
    request_id_offset = request.find(b"\xa0")
    if request_id_offset < 0:
        return None
    request_id = request[request_id_offset + 4]
    # Rebuild a GetResponse with a fixed set of system-group values, whatever was asked.
    values = {
        (1, 3, 6, 1, 2, 1, 1, 1, 0): "ARACHNE lab SNMP agent (fixture)",
        (1, 3, 6, 1, 2, 1, 1, 5, 0): "lab-agent",
        (1, 3, 6, 1, 2, 1, 1, 6, 0): "lab rack 1",
        (1, 3, 6, 1, 2, 1, 1, 4, 0): "ops@lab.arachne.test",
    }
    varbinds = b""
    for oid, text in values.items():
        varbinds += _ber(
            0x30,
            _ber(0x06, _snmp_oid(oid)) + _ber(0x04, text.encode()),
        )
    pdu = _ber(
        0xA2,
        _ber_int(request_id)
        + _ber_int(0)  # error-status
        + _ber_int(0)  # error-index
        + _ber(0x30, varbinds),
    )
    return _ber(0x30, _ber_int(1) + _ber(0x04, community) + pdu)


def _snmp_oid(oid: tuple[int, ...]) -> bytes:
    body = bytearray([oid[0] * 40 + oid[1]])
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


def _wait_for_mbap(connection: socket.socket) -> bytes:
    """Read one MBAP frame: 6-byte header (with the length) + the PDU it declares."""
    header = _read(connection, 6)
    if len(header) < 6:
        return b""
    declared = struct.unpack(">H", header[4:6])[0]
    return header + _read(connection, max(declared, 1))


def _bacnet_handler(request: bytes) -> bytes | None:
    """Answer a BACnet/IP Who-Is with an I-Am for device 1234 (vendor 63)."""
    if len(request) < 4 or request[0] != 0x81:
        return None
    apdu = (
        b"\x00"  # unconfirmed request: I-Am
        b"\xc4"  # object-identifier: context tag 0, 4 bytes
        + struct.pack(">I", (8 << 22) | 1234)  # object type 8 = device, instance 1234
        + b"\x21\x05"  # max-apdu-length-accepted
        + b"\x91\x00"  # segmentation-supported
        + b"\x21\x3f"  # vendor-id (63)
    )
    npdu = bytes([0x01, 0x00]) + apdu  # NPDU version 1, control 0
    return bytes([0x81, 0x0A]) + struct.pack(">H", len(npdu) + 4) + npdu


def _modbus_handler(request: bytes) -> bytes | None:
    if len(request) < 8:
        return None
    transaction = request[:2]
    unit = request[6:7]
    objects = {0: "ARACHNE Lab", 1: "Virtual PLC 200", 2: "1.4.2"}
    payload = bytearray([0x2B, 0x0E, 0x01, 0x81, 0x00, 0x00])
    for object_id, text in objects.items():
        payload.append(object_id)
        payload.append(len(text))
        payload.extend(text.encode())
    header = transaction + struct.pack(">H", 0) + struct.pack(">H", len(payload) + 1) + unit
    return bytes(header) + bytes(payload)


# ------------------------------------------------------------------- S7comm / DNP3 (S29)
def _s7_handler(connection: socket.socket) -> None:
    """Answer an ISO-TSAP COTP connection request with a connection confirm.

    A real S7 endpoint's *first* exchange, and the only one this fixture implements: the lab
    refuses to pretend to be a PLC that would answer read/write jobs, because the scanner has
    no business sending them (``REQ-DEPTH-006``). The TSAPs it reports are the standard
    PG/PC pair, which is what a check decodes.
    """
    request = connection.recv(4096)
    if len(request) < 7 or request[0] != 0x03 or request[5] != 0xE0:
        return  # not a COTP connection request: stay silent, like a filtered port
    cotp = bytes([0x11, 0xD0, 0x00, 0x01, 0x00, 0x01, 0x00])
    cotp += bytes([0xC1, 0x02, 0x01, 0x00])
    cotp += bytes([0xC2, 0x02, 0x01, 0x02])
    connection.sendall(bytes([0x03, 0x00]) + struct.pack(">H", 4 + len(cotp)) + cotp)


def _dnp3_handler(connection: socket.socket) -> None:
    """Answer a DNP3 link-layer status request with a link status reply (CRC-correct)."""
    request = connection.recv(4096)
    if len(request) < 10 or request[0] != 0x05 or request[1] != 0x64:
        return
    if (request[3] & 0x0F) != 0x09:  # only REQUEST_LINK_STATUS is answered
        return
    destination = request[4:6]
    source = request[6:8]
    # A reply swaps the addresses and sets DIR=0, PRM=1 with the link-status function.
    header = bytes([0x05, 0x64, 0x05, 0xC0 | 0x0B]) + bytes(source) + bytes(destination)
    connection.sendall(header + struct.pack("<H", _dnp3_crc(header)))


def _dnp3_crc(data: bytes) -> int:
    """The DNP3 CRC-16, computed independently of the scanner's implementation."""
    crc = 0x0000
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA6BC if crc & 1 else crc >> 1
    return (~crc) & 0xFFFF


# --------------------------------------------------------------------------- SMB (S19)
#: The lab's SMB account and the password it accepts. A credentialed check (``m2.smb-auth``)
#: authenticates with NTLMv2 against this service, so the accept criterion "protocol-lab test
#: with valid and invalid credentials" is a real exchange, not a scripted reply.
LAB_SMB_USER = "svc-backup"
LAB_SMB_PASSWORD = "svc-backup-lab-password"
LAB_SMB_DOMAIN = "LAB"
LAB_SMB_DIALECT = 0x0302

#: The server challenge the lab last issued. The net client opens one connection per probe
#: (``ScopedNetClient.tcp`` is request/response), so an SMB2 session setup arrives in two
#: separate connections; the fixture remembers the challenge between them. Two SMB
#: conversations must not interleave in one test — the protocol-lab form used here is
#: sequential by construction (ADR-240.6).
_SMB_STATE: dict[str, Any] = {"challenge": None}
_SMB_LOCK = threading.Lock()


def _smb2_header(status: int, command: int, *, message_id: int = 1, session_id: int = 0) -> bytes:
    return (
        b"\xfeSMB"
        + struct.pack("<H", 64)     # StructureSize
        + struct.pack("<H", 1)      # CreditCharge
        + struct.pack("<I", status)
        + struct.pack("<H", command)
        + struct.pack("<H", 1)      # CreditResponse
        + struct.pack("<I", 1)      # Flags: SMB2_FLAGS_SERVER_TO_REDIR
        + struct.pack("<I", 0)      # NextCommand
        + struct.pack("<Q", message_id)
        + struct.pack("<I", 0xFEFF)  # ProcessId
        + struct.pack("<I", 0)       # TreeId
        + struct.pack("<Q", session_id)
        + b"\x00" * 16
    )


def _smb2_negotiate_response() -> bytes:
    # MS-SMB2 §2.2.4 field order: StructureSize, SecurityMode, Reserved, DialectRevision,
    # ServerGuid, Capabilities, MaxTransactSize, MaxReadSize, MaxWriteSize, SystemTime,
    # ServerStartTime, SecurityBufferOffset/Length.
    body = (
        struct.pack("<H", 65)        # StructureSize
        + struct.pack("<H", 0x0001)  # SecurityMode: signing enabled, not required
        + struct.pack("<H", 0)       # Reserved
        + struct.pack("<H", LAB_SMB_DIALECT)
        + b"\x11" * 16               # ServerGuid
        + struct.pack("<I", 0x00000001)  # Capabilities
        + struct.pack("<I", 1 << 20)     # MaxTransactSize
        + struct.pack("<I", 1 << 20)     # MaxReadSize
        + struct.pack("<I", 1 << 20)     # MaxWriteSize
        + struct.pack("<Q", 0)           # SystemTime
        + struct.pack("<Q", 0)           # ServerStartTime
        + struct.pack("<H", 0)           # SecurityBufferOffset
        + struct.pack("<H", 0)           # SecurityBufferLength
    )
    payload = _smb2_header(0x00000000, 0) + body
    return b"\x00" + len(payload).to_bytes(3, "big") + payload


def _smb2_session_setup_response(status: int, blob: bytes, *, session_id: int) -> bytes:
    offset = 64 + 8
    body = (
        struct.pack("<H", 9)    # StructureSize
        + struct.pack("<H", 0)  # SessionFlags
        + struct.pack("<H", offset)
        + struct.pack("<H", len(blob))
        + blob
    )
    payload = _smb2_header(status, 1, session_id=session_id) + body
    return b"\x00" + len(payload).to_bytes(3, "big") + payload


def _ntlmssp_challenge(server_challenge: bytes, target_info: bytes) -> bytes:
    return (
        b"NTLMSSP\x00"
        + struct.pack("<I", 2)
        + struct.pack("<HHI", 0, 0, 48)          # target name: absent
        + struct.pack("<I", 0x00080001)          # UNICODE | NTLM | EXTENDED_SESSIONSECURITY
        + server_challenge
        + b"\x00" * 8
        + struct.pack("<HHI", len(target_info), len(target_info), 48)
        + target_info
    )


def _smb2_payload(request: bytes) -> tuple[int, bytes] | None:
    """``(command, security_blob)`` from a NetBIOS-framed SMB2 request."""
    body = request[4:] if request[:1] in {b"\x00", b"\x80"} else request
    if body[:4] != b"\xfeSMB" or len(body) < 64:
        return None
    command = struct.unpack("<H", body[12:14])[0]
    blob = b""
    if command == 1 and len(body) >= 64 + 24:
        # SESSION_SETUP *request* layout (MS-SMB2 §2.2.5): StructureSize(2), Flags(1),
        # SecurityMode(1), Capabilities(4), Channel(4), then the security-buffer offset and
        # length at header+76..80.
        offset, length = struct.unpack("<HH", body[76:80])
        # The offset is header-relative (MS-SMB2 §2.2.6), so it already counts the header.
        if length and offset + length <= len(body):
            blob = body[offset : offset + length]
    return command, blob


def _verify_ntlmv2(blob: bytes) -> bool:
    """Verify an NTLMv2 AUTHENTICATE the way a server does: recompute the HMAC."""
    parsed = wire.parse_ntlmssp_authenticate(blob)
    if parsed is None or parsed.user != LAB_SMB_USER:
        return False
    with _SMB_LOCK:
        challenge = _SMB_STATE.get("challenge")
    if not isinstance(challenge, bytes) or len(challenge) != 8:
        return False
    if len(parsed.nt_response) <= 16:
        return False
    proof, response_blob = parsed.nt_response[:16], parsed.nt_response[16:]
    key = wire.nt_owf_v2(LAB_SMB_USER, LAB_SMB_PASSWORD, parsed.domain or LAB_SMB_DOMAIN)
    expected = hmac.new(key, challenge + response_blob, hashlib.md5).digest()
    return hmac.compare_digest(expected, proof)


def _smb(connection: socket.socket) -> None:
    """A minimal but wire-correct SMB2 server: NEGOTIATE, then NTLMv2 SESSION_SETUP."""
    request = _read(connection, 4096)
    if not request:
        return
    parsed = _smb2_payload(request)
    if parsed is None:
        return
    command, blob = parsed
    if command == 0:  # NEGOTIATE
        connection.sendall(_smb2_negotiate_response())
        return
    if command != 1:  # only the authentication exchange is modelled
        connection.sendall(_smb2_session_setup_response(0xC00000BB, b"", session_id=0))
        return
    message_type = struct.unpack("<I", blob[8:12])[0] if len(blob) >= 12 else 0
    if message_type == 1:  # NEGOTIATE (type 1) -> challenge
        challenge = secrets.token_bytes(8)
        with _SMB_LOCK:
            _SMB_STATE["challenge"] = challenge
        target_info = struct.pack("<HH", 2, 0) + b"\x00" * 4  # one MsvAv terminator
        connection.sendall(
            _smb2_session_setup_response(
                0xC0000016,  # STATUS_MORE_PROCESSING_REQUIRED
                _ntlmssp_challenge(challenge, target_info),
                session_id=0x4000,
            )
        )
        return
    if message_type == 3:  # AUTHENTICATE (type 3)
        status = 0x00000000 if _verify_ntlmv2(blob) else 0xC000006D  # SUCCESS / LOGON_FAILURE
        connection.sendall(_smb2_session_setup_response(status, b"", session_id=0x4000))
        return
    connection.sendall(_smb2_session_setup_response(0xC000000D, b"", session_id=0))


# --------------------------------------------------------------------------- the fixture
def start_m2_lab(*, include_udp: bool = True) -> LabFixture:
    """Start the lab and return a fixture whose ``ports`` map names to real ports."""
    fixture = LabFixture()
    servers: list[Any] = []

    tcp_services: tuple[tuple[str, Handler], ...] = (
        ("ssh", _ssh),
        ("http", _http),
        ("tls", _tls_handler()),
        ("mysql", _mysql),
        ("redis", _redis),
        ("vnc", _vnc),
        ("smtp", _smtp),
        ("dns", _dns),
        ("ldap", _ldap),
        ("smb", _smb),
        (
            "modbus",
            lambda connection: connection.sendall(
                _modbus_handler(_wait_for_mbap(connection)) or b""
            ),
        ),
        # S29 (REQ-DEPTH-006): the OT/ICS read-only protocol fixtures. S7comm and DNP3 are
        # separate services so a check has to find the right one by port and by protocol, the
        # way it must in an estate.
        ("s7", _s7_handler),
        ("dnp3", _dnp3_handler),
        # S29 (REQ-DEPTH-003): three gRPC services — the vulnerable deployment, an
        # application-hardened one that still speaks cleartext HTTP/2, and a TLS-only one that
        # refuses the plaintext preface.
        (
            "grpc",
            lambda connection: grpc_lab.handle_connection(connection, grpc_lab.VULNERABLE),
        ),
        (
            "grpc-hardened",
            lambda connection: grpc_lab.handle_connection(connection, grpc_lab.HARDENED),
        ),
        (
            "grpc-tls-only",
            lambda connection: grpc_lab.handle_connection(connection, grpc_lab.TLS_ONLY),
        ),
    )
    for name, handler in tcp_services:
        server = _TcpServer(handler, name=name)
        server.start()
        servers.append(server)
        fixture.services[name] = LabService(
            name=name, port=server.port, protocol="tcp", _stop=server.stop
        )

    if include_udp:
        for name, handler in (("snmp", _snmp_handler), ("bacnet", _bacnet_handler)):
            udp_server = _UdpServer(handler, name=name)
            udp_server.start()
            servers.append(udp_server)
            fixture.services[name] = LabService(
                name=name, port=udp_server.port, protocol="udp", _stop=udp_server.stop
            )
    return fixture


@contextmanager
def m2_lab(*, include_udp: bool = True) -> Iterator[LabFixture]:
    """Context-manager form of :func:`start_m2_lab` (stops every service on exit)."""
    fixture = start_m2_lab(include_udp=include_udp)
    try:
        yield fixture
    finally:
        fixture.stop()
