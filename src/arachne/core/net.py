"""The scoped, rate-limited, audited **network** client (S4/M2, F-01-07/08, F-08-03).

M2 talks to targets with TCP, UDP and TLS — not HTTP — so the shared HTTP client cannot be
the only egress path. Rather than let every check open sockets, this module is the exact
structural counterpart of :mod:`arachne.core.http`: one object that, for **every** probe,

1. **authorizes** — the host is checked against the compiled ``Scope`` (F-01-02) and every
   address it resolves to is checked against the same private/loopback/link-local policy the
   HTTP path uses (F-08-03). A refusal is audited as ``scope.rejected`` / ``net.blocked``
   and *no packet is sent*.
2. **throttles** — the per-host and global token buckets of F-01-07. M2 probes are far
   cheaper than HTTP requests, so fifty ports on one host is one logical interaction, but
   the per-host budget still applies to each probe.
3. **probes** — through an injectable :class:`NetTransport` (``SocketTransport`` in
   production, a scripted transport in tests), with per-connection timeouts and a bounded
   read.
4. **audits** — one ``net.probe`` line per attempt with host, port, protocol, outcome and
   duration, so "which packets did this scan send?" is answerable from the audit trail
   (F-01-08).

Two deliberate boundaries:

* **No HTTP.** ``httpx`` stays confined to :mod:`arachne.core.http` (ADR-05); this module
  uses ``asyncio``/``ssl``/``socket`` only, and ``tests/unit/test_http_hygiene.py`` keeps it
  that way.
* **No detection.** This layer reports *states* (open/closed/filtered, a banner, a
  certificate); deciding that "OpenSSH 8.5p1 is CVE-2024-6387" is M2's job, in
  ``arachne.modules.m2``. Keeping the split means the egress path stays small enough to
  audit by reading it.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import os
import socket
import ssl
import struct
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final, Literal, Protocol

from arachne.core.airgap import AirgapError, build_airgap_policy
from arachne.core.audit import AuditAction, Auditor, AuditOutcome
from arachne.core.config import NetSettings, Settings, get_settings
from arachne.core.errors import NetProbeError, OutOfScopeError, SafetyError
from arachne.core.logging import get_logger
from arachne.core.ratelimit import HostRateLimiter
from arachne.core.safety import (
    HostResolver,
    Scope,
    SocketResolver,
    UrlSafetyPolicy,
    classify_ip,
    normalize_host,
)

__all__ = [
    "LEGACY_TLS_VERSIONS",
    "PINNABLE_TLS_VERSIONS",
    "TLS_VERSION_NUMBERS",
    "TLS_VERSION_ORDER",
    "WEAK_CIPHER_CANDIDATES",
    "IcmpExchange",
    "IcmpState",
    "NetSettings",
    "NetTransport",
    "PortState",
    "ProbeOutcome",
    "ScopedNetClient",
    "ScriptedNetTransport",
    "SocketTransport",
    "TcpExchange",
    "TlsExchange",
    "TlsProfile",
    "TlsVersionProbe",
    "UdpExchange",
    "UdpState",
    "legacy_version_cap_options",
]

_logger = get_logger("core.net")

#: Connection outcome for a TCP probe. ``filtered`` means "no answer" (a drop or a timeout,
#: the classic firewall signature of research ch02#4); ``closed`` means an RST.
PortState = Literal["open", "closed", "filtered", "error"]

#: Outcome of a UDP probe. UDP has no handshake, so silence is ambiguous by construction
#: and is reported as ``open-filtered`` rather than guessed (research ch02#6).
UdpState = Literal["open", "closed", "open-filtered", "error"]

#: Outcome of an ICMP echo probe: a reply, silence, or "this process cannot send ICMP".
IcmpState = Literal["reply", "timeout", "error", "unavailable"]

#: TLS protocol names in the order a report should read them, oldest first.
#:
#: **SSLv3 is deliberately absent.** A Python 3.11+ client cannot negotiate SSLv3 at all
#: (OpenSSL 3 builds it out), so probing it would report "not supported" for every endpoint —
#: a false negative presented as a fact, which is worse than not asking. Detecting SSLv3 needs
#: a stack that still speaks it, which is what ``ARACHNE_NET_TLS_TOOL`` (testssl.sh/sslscan)
#: is for; its ``ssl3`` topic maps onto the ``sslv3-supported`` signal of the offline index.
TLS_VERSION_ORDER: Final[tuple[str, ...]] = (
    "TLSv1.0",
    "TLSv1.1",
    "TLSv1.2",
    "TLSv1.3",
)

#: Versions the stdlib can be *pinned* to directly. ``ssl.TLSVersion.TLSv1``/``TLSv1_1`` are
#: deprecated members, and the interpreter refuses the assignment outright when deprecations
#: are errors (which the project's own test suite arranges) — so TLS 1.0/1.1 support is
#: established a different way: cap the client *below* TLS 1.2 and read which version the
#: server then negotiates (see :func:`legacy_version_cap_options`).
PINNABLE_TLS_VERSIONS: Final[tuple[str, ...]] = ("TLSv1.2", "TLSv1.3")

#: Versions that can only be observed through the legacy cap.
LEGACY_TLS_VERSIONS: Final[tuple[str, ...]] = ("TLSv1.0", "TLSv1.1")

#: Cipher suites probed one at a time, weakest first. A handshake is attempted with the
#: suite pinned, so "the server accepted RC4-SHA" is an observation rather than a political
#: guess about server cipher ordering. The list is deliberately short: the stdlib probe is
#: the bounded, offline-capable pass, and ``ARACHNE_NET_TLS_TOOL`` exists for operators who
#: want a full testssl.sh/sslscan matrix.
WEAK_CIPHER_CANDIDATES: Final[tuple[str, ...]] = (
    "NULL-SHA",
    "NULL-MD5",
    "RC4-SHA",
    "RC4-MD5",
    "EXP-RC4-MD5",
    "DES-CBC-SHA",
    "DES-CBC3-SHA",
    "ECDHE-RSA-DES-CBC3-SHA",
    "ADH-AES128-SHA",
    "AECDH-AES128-SHA",
    "AES128-SHA",
    "AES256-SHA",
    "ECDHE-RSA-AES128-SHA",
    "AES128-GCM-SHA256",
    "ECDHE-RSA-AES128-GCM-SHA256",
    "ECDHE-RSA-AES256-GCM-SHA384",
    "ECDHE-RSA-CHACHA20-POLY1305",
    "TLS_AES_128_GCM_SHA256",
)


@dataclass(frozen=True, slots=True)
class TcpExchange:
    """One TCP interaction: how the connection ended and what came back."""

    state: PortState
    chunks: tuple[bytes, ...] = ()
    elapsed_ms: float = 0.0
    addresses: tuple[str, ...] = ()
    error: str | None = None

    @property
    def is_open(self) -> bool:
        return self.state == "open"

    @property
    def banner(self) -> bytes:
        """Everything read, concatenated (bounded by ``max_read_bytes`` per read)."""
        return b"".join(self.chunks)

    def banner_text(self, *, limit: int = 0) -> str:
        """The banner decoded as text; control characters kept so a parser can rely on CRLF."""
        text = self.banner.decode("utf-8", errors="replace")
        return text[:limit] if limit else text


@dataclass(frozen=True, slots=True)
class UdpExchange:
    """One UDP interaction (research ch02#6: silence is ``open-filtered``, not a guess)."""

    state: UdpState
    payload: bytes | None = None
    elapsed_ms: float = 0.0
    error: str | None = None

    @property
    def replied(self) -> bool:
        return self.state == "open" and self.payload is not None


@dataclass(frozen=True, slots=True)
class IcmpExchange:
    """The result of an ICMP echo probe (research ch02#1), including the reply TTL.

    ``state="unavailable"`` is a first-class answer: an unprivileged process on a host whose
    kernel does not allow ping sockets cannot send ICMP at all, and M2 reports that instead
    of silently degrading to "the host is down" (which is what dropping it would mean).
    """

    state: IcmpState
    ttl: int | None = None
    rtt_ms: float | None = None
    error: str | None = None

    @property
    def replied(self) -> bool:
        return self.state == "reply"

    @property
    def unavailable(self) -> bool:
        return self.state == "unavailable"


@dataclass(frozen=True, slots=True)
class TlsExchange:
    """One TLS handshake attempt with a specific version/cipher/trust configuration."""

    ok: bool
    version: str | None = None
    cipher: str | None = None
    cipher_bits: int | None = None
    certificate_der: bytes | None = None
    #: Set when a *verifying* handshake failed ("self-signed certificate", "certificate
    #: has expired", ...). Empty/None means the certificate chain validated.
    verify_error: str | None = None
    error: str | None = None
    elapsed_ms: float = 0.0


@dataclass(frozen=True, slots=True)
class TlsVersionProbe:
    """Whether one protocol version could be negotiated, and with which cipher.

    ``supported`` is tri-state: ``True`` (observed), ``False`` (the endpoint refused it), or
    ``None`` (**undetermined**) for a version the probe could not isolate — a server that
    negotiates TLS 1.1 under a legacy cap need not also accept TLS 1.0, and claiming either
    way would be a guess.
    """

    version: str
    supported: bool | None
    cipher: str | None = None


@dataclass(frozen=True, slots=True)
class TlsProfile:
    """The stdlib TLS profile of one endpoint (protocols, ciphers, certificate, trust).

    Produced by ``arachne.modules.m2.tls``; declared here because it is the shape every
    TLS-related consumer (the M2 check, the report, a later re-verification pass) agrees on.
    """

    host: str
    port: int
    versions: tuple[TlsVersionProbe, ...] = ()
    ciphers: tuple[str, ...] = ()
    #: Certificates that a *verifying* handshake rejected, with the reason.
    trust_error: str | None = None
    negotiated: TlsExchange | None = None
    error: str | None = None

    @property
    def supported_versions(self) -> tuple[str, ...]:
        return tuple(item.version for item in self.versions if item.supported is True)

    @property
    def undetermined_versions(self) -> tuple[str, ...]:
        return tuple(item.version for item in self.versions if item.supported is None)


@dataclass(frozen=True, slots=True)
class ProbeOutcome:
    """What a check gets back from :meth:`ScopedNetClient.probe_ports`, per port."""

    host: str
    port: int
    protocol: str
    state: str
    banner: str = ""
    elapsed_ms: float = 0.0
    error: str | None = None

    @property
    def open(self) -> bool:
        return self.state == "open"


class NetTransport(Protocol):
    """The byte-level seam. ``SocketTransport`` in production, scripted in tests."""

    async def tcp(
        self,
        host: str,
        port: int,
        *,
        payload: bytes | None,
        reads: int,
        connect_timeout: float,
        read_timeout: float,
        max_bytes: int,
    ) -> TcpExchange: ...

    async def udp(
        self,
        host: str,
        port: int,
        *,
        payload: bytes,
        io_timeout: float,
        max_bytes: int,
    ) -> UdpExchange: ...

    async def tls(
        self,
        host: str,
        port: int,
        *,
        min_version: str | None,
        max_version: str | None,
        ciphers: str | None,
        options: int,
        server_hostname: str | None,
        verify: bool,
        connect_timeout: float,
        read_timeout: float,
    ) -> TlsExchange: ...

    async def icmp(self, host: str, *, identifier: int, io_timeout: float) -> IcmpExchange: ...


#: Wire values of the TLS protocol versions, as ``ssl.TLSVersion`` numbers them (they are the
#: protocol numbers from the TLS record layer, so they do not drift between OpenSSL builds).
#: The *named* attributes (``ssl.TLSVersion.TLSv1``, ``.TLSv1_1``) are deprecated and reading
#: them raises ``DeprecationWarning`` — which the test suite turns into an error for this
#: package, and which a scan must never let become a failure. Constructing the enum from its
#: integer avoids the deprecated paths entirely.
TLS_VERSION_NUMBERS: Final[Mapping[str, int]] = {
    "TLSv1.2": 0x0303,
    "TLSv1.3": 0x0304,
}


def _tls_versions() -> dict[str, Any]:
    """``{name: ssl.TLSVersion}`` for the versions this build can be told to use."""
    table: dict[str, Any] = {}
    for name, number in TLS_VERSION_NUMBERS.items():
        try:
            table[name] = ssl.TLSVersion(number)
        except ValueError:  # pragma: no cover - a build that does not know the value
            continue
    return table


def legacy_version_cap_options() -> int:
    """SSL options that stop the client offering TLS 1.2 or later.

    ``OP_NO_TLSv1_2``/``OP_NO_TLSv1_3`` are still supported (unlike the ``OP_NO_TLSv1`` /
    ``OP_NO_TLSv1_1`` pair, which is deprecated alongside the version members). Using the cap
    is what makes a legacy-protocol observation possible on a modern interpreter: the
    handshake then negotiates the best version *below* 1.2 that the server still offers, and
    the negotiated version is read back from the connection.
    """
    options = 0
    for name in ("OP_NO_TLSv1_2", "OP_NO_TLSv1_3"):
        options |= int(getattr(ssl, name, 0))
    return options


class SocketTransport:
    """The real transport: ``asyncio`` sockets and the stdlib ``ssl`` module."""

    async def tcp(
        self,
        host: str,
        port: int,
        *,
        payload: bytes | None,
        reads: int,
        connect_timeout: float,
        read_timeout: float,
        max_bytes: int,
    ) -> TcpExchange:
        started = time.monotonic()
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port), connect_timeout
            )
        except TimeoutError:
            # No answer at all: the signature of a filtered port (research ch02#4).
            return TcpExchange(state="filtered", elapsed_ms=_ms(started))
        except ConnectionRefusedError:
            return TcpExchange(state="closed", elapsed_ms=_ms(started))
        except OSError as exc:
            return TcpExchange(state="error", elapsed_ms=_ms(started), error=_describe(exc))

        chunks: list[bytes] = []
        error: str | None = None
        try:
            if payload:
                writer.write(payload)
                await asyncio.wait_for(writer.drain(), connect_timeout)
            for _ in range(max(1, reads)):
                try:
                    data = await asyncio.wait_for(reader.read(max_bytes), read_timeout)
                except TimeoutError:
                    break
                except OSError as exc:  # a reset after a completed handshake
                    error = _describe(exc)
                    break
                if not data:
                    break
                chunks.append(data)
        except OSError as exc:
            error = _describe(exc)
        finally:
            _close_writer(writer)
        # The connection *was* established: a later read error does not un-open the port.
        return TcpExchange(state="open", chunks=tuple(chunks), elapsed_ms=_ms(started), error=error)

    async def udp(
        self,
        host: str,
        port: int,
        *,
        payload: bytes,
        io_timeout: float,
        max_bytes: int,
    ) -> UdpExchange:
        started = time.monotonic()
        loop = asyncio.get_running_loop()
        family = socket.AF_INET6 if _is_ipv6(host) else socket.AF_INET
        sock = socket.socket(family, socket.SOCK_DGRAM)
        sock.setblocking(False)
        try:
            # ``connect`` on a datagram socket sends nothing; it is what lets the kernel
            # surface an ICMP port-unreachable as ECONNREFUSED on the next operation,
            # which is the only reliable "closed" signal UDP offers.
            sock.connect((host, port))
            await loop.sock_sendall(sock, payload)
            try:
                data = await asyncio.wait_for(loop.sock_recv(sock, max_bytes), io_timeout)
            except TimeoutError:
                return UdpExchange(state="open-filtered", elapsed_ms=_ms(started))
            except ConnectionRefusedError:
                return UdpExchange(state="closed", elapsed_ms=_ms(started))
            except OSError as exc:
                return UdpExchange(state="error", elapsed_ms=_ms(started), error=_describe(exc))
            return UdpExchange(state="open", payload=data, elapsed_ms=_ms(started))
        except OSError as exc:
            return UdpExchange(state="error", elapsed_ms=_ms(started), error=_describe(exc))
        finally:
            sock.close()

    async def icmp(self, host: str, *, identifier: int, io_timeout: float) -> IcmpExchange:
        """One ICMP echo request, run off the event loop (the socket API is blocking here)."""
        return await asyncio.to_thread(_icmp_echo, host, identifier, io_timeout)

    async def tls(
        self,
        host: str,
        port: int,
        *,
        min_version: str | None,
        max_version: str | None,
        ciphers: str | None,
        options: int,
        server_hostname: str | None,
        verify: bool,
        connect_timeout: float,
        read_timeout: float,
    ) -> TlsExchange:
        started = time.monotonic()
        try:
            context = _client_context(
                min_version=min_version,
                max_version=max_version,
                ciphers=ciphers,
                options=options,
                verify=verify,
            )
        except (ssl.SSLError, OSError, ValueError) as exc:
            # An unknown cipher name or an unavailable protocol version is a fact about
            # this build, not about the server.
            return TlsExchange(ok=False, error=_describe(exc), elapsed_ms=_ms(started))
        try:
            _reader, writer = await asyncio.wait_for(
                asyncio.open_connection(
                    host, port, ssl=context, server_hostname=server_hostname or host
                ),
                connect_timeout + read_timeout,
            )
        except ssl.SSLCertVerificationError as exc:
            return TlsExchange(
                ok=False,
                verify_error=_describe(exc),
                error=_describe(exc),
                elapsed_ms=_ms(started),
            )
        except ssl.SSLError as exc:
            return TlsExchange(ok=False, error=_describe(exc), elapsed_ms=_ms(started))
        except TimeoutError:
            return TlsExchange(ok=False, error="timeout", elapsed_ms=_ms(started))
        except OSError as exc:
            return TlsExchange(ok=False, error=_describe(exc), elapsed_ms=_ms(started))
        try:
            ssl_object = writer.get_extra_info("ssl_object")
            cipher = ssl_object.cipher() if ssl_object is not None else None
            der = ssl_object.getpeercert(binary_form=True) if ssl_object is not None else None
            return TlsExchange(
                ok=True,
                version=getattr(ssl_object, "version", lambda: None)() if ssl_object else None,
                cipher=cipher[0] if cipher else None,
                cipher_bits=cipher[2] if cipher else None,
                certificate_der=der,
                elapsed_ms=_ms(started),
            )
        finally:
            _close_writer(writer)


def _icmp_echo(host: str, identifier: int, io_timeout: float) -> IcmpExchange:
    """Blocking ICMP echo probe (called through ``asyncio.to_thread``).

    Tries an unprivileged ping socket first (``SOCK_DGRAM`` + ``IPPROTO_ICMP``, which Linux
    allows when ``net.ipv4.ping_group_range`` permits it) and falls back to a raw socket.
    A reply from a raw socket carries the IPv4 header, so the reply is verified to be an
    echo *reply* with *our* identifier before it is believed — otherwise any unrelated
    packet on the socket would read as a live host.
    """
    started = time.monotonic()
    sock: socket.socket | None = None
    raw = False
    for kind in (socket.SOCK_DGRAM, socket.SOCK_RAW):
        try:
            candidate = socket.socket(socket.AF_INET, kind, socket.IPPROTO_ICMP)
        except OSError:
            continue
        with contextlib.suppress(OSError, AttributeError):
            candidate.setsockopt(socket.IPPROTO_IP, getattr(socket, "IP_RECVTTL", 12), 1)
        sock = candidate
        raw = kind == socket.SOCK_RAW
        break
    if sock is None:
        return IcmpExchange(
            state="unavailable",
            error="ICMP requires a ping socket or CAP_NET_RAW; this process has neither",
        )
    try:
        sock.settimeout(io_timeout)
        sock.sendto(_icmp_packet(identifier, 1), (host, 0))
        for _ in range(8):  # a raw socket may see other traffic before our reply
            data, ancillary = sock.recvmsg(1024, 512)[:2]
            if raw:
                if len(data) < 28:
                    continue
                icmp = data[20:]
                if icmp[0] != 0 or int.from_bytes(icmp[4:6], "big") != identifier & 0xFFFF:
                    continue
            return IcmpExchange(
                state="reply",
                ttl=_ttl_from_ancillary(list(ancillary)),
                rtt_ms=_ms(started),
            )
        return IcmpExchange(state="timeout", rtt_ms=_ms(started))
    except TimeoutError:
        return IcmpExchange(state="timeout", rtt_ms=_ms(started))
    except OSError as exc:
        return IcmpExchange(state="error", error=_describe(exc), rtt_ms=_ms(started))
    finally:
        sock.close()


def _icmp_packet(identifier: int, sequence: int) -> bytes:
    """An ICMPv4 echo request (type 8, code 0) with a checksum the kernel can accept."""
    header = struct.pack(">BBHHH", 8, 0, 0, identifier & 0xFFFF, sequence & 0xFFFF)
    body = b"arachne-probe"
    packet = header + body
    checksum = _checksum(packet)
    return struct.pack(">BBHHH", 8, 0, checksum, identifier & 0xFFFF, sequence & 0xFFFF) + body


def _checksum(payload: bytes) -> int:
    if len(payload) % 2:
        payload += b"\x00"
    total = 0
    for index in range(0, len(payload), 2):
        total += (payload[index] << 8) + payload[index + 1]
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return ~total & 0xFFFF


#: ``IP_TTL`` is not exposed by every Python build's ``socket`` module; the constant is
#: stable across the platforms that do report it (Linux 2, macOS 4, BSD 4).
_IP_TTL: Final = getattr(socket, "IP_TTL", 2)


def _ttl_from_ancillary(ancillary: list[tuple[int, int, bytes]]) -> int | None:
    """Extract IP_TTL from ``recvmsg`` ancillary data (Linux/macOS report it this way)."""
    for level, kind, data in ancillary:
        if level == socket.IPPROTO_IP and kind == _IP_TTL:
            try:
                return int(struct.unpack("i", data[:4])[0])
            except struct.error:
                return None
    return None


def _client_context(
    *,
    min_version: str | None,
    max_version: str | None,
    ciphers: str | None,
    options: int = 0,
    verify: bool,
) -> ssl.SSLContext:
    """Build the client context for one TLS probe.

    A probing context deliberately does **not** trust the target — the point is to read the
    certificate and negotiate the ciphers, so ``CERT_NONE`` and no hostname check are
    correct here. Trust is a *separate* observation, made by a second handshake with
    ``verify=True``, which is the only way to learn "the chain does not validate" without
    aborting the profile.
    """
    # The security-profile changes below are *deliberate*: probing TLS 1.0/1.1 and legacy
    # cipher suites is the whole point of a TLS posture scan, so this context is built to be
    # as permissive as the local OpenSSL allows.
    if verify:
        context = ssl.create_default_context()
        context.check_hostname = False
    else:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    table = _tls_versions()
    if min_version and min_version in table:
        context.minimum_version = table[min_version]
    if max_version and max_version in table:
        context.maximum_version = table[max_version]
    if ciphers:
        context.set_ciphers(ciphers)
    if options:
        context.options |= options
    return context


def _close_writer(writer: Any) -> None:
    """Close a stream writer, tolerating an already-broken connection."""
    try:
        writer.close()
    except Exception:  # a closed/broken transport must not mask the probe result
        return


def _ms(started: float) -> float:
    return round((time.monotonic() - started) * 1000.0, 3)


def _describe(exc: BaseException) -> str:
    return f"{exc.__class__.__name__}: {exc}"


def _is_ipv6(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).version == 6
    except ValueError:
        return False


class ScriptedNetTransport:
    """A transport that answers from a table instead of a network (tests, replay).

    Keys are ``("tcp", host, port)`` / ``("udp", host, port)`` / ``("tls", host, port)``;
    a value may be an exchange object, a bare ``bytes`` banner (shorthand for an open TCP
    port), a callable taking the request payload, or a ``list``/``dict`` of scripted replies
    consumed in order (so a check that makes two probes can script both).

    Unscripted ports answer ``closed`` — the honest answer for a lab fixture that only
    planted the services a test cares about — and every probe is recorded in
    :attr:`calls`, which is how a test asserts "this check did not touch that port".
    """

    def __init__(self, routes: dict[tuple[str, str, int], Any] | None = None) -> None:
        self.routes: dict[tuple[str, str, int], Any] = dict(routes or {})
        self.calls: list[tuple[str, str, int]] = []

    def _next(self, key: tuple[str, str, int], default: Any) -> Any:
        self.calls.append(key)
        route = self.routes.get(key)
        if route is None:
            return default
        if isinstance(route, list):
            return route.pop(0) if route else default
        return route

    async def tcp(
        self,
        host: str,
        port: int,
        *,
        payload: bytes | None,
        reads: int,
        connect_timeout: float,
        read_timeout: float,
        max_bytes: int,
    ) -> TcpExchange:
        route = self._next(("tcp", host, port), TcpExchange(state="closed"))
        if callable(route):
            route = route(payload)
        if isinstance(route, (bytes, bytearray)):
            return TcpExchange(state="open", chunks=(bytes(route),))
        if isinstance(route, str):
            return TcpExchange(state="open", chunks=(route.encode(),))
        assert isinstance(route, TcpExchange)
        return route

    async def icmp(self, host: str, *, identifier: int, io_timeout: float) -> IcmpExchange:
        route = self._next(("icmp", host, 0), IcmpExchange(state="timeout"))
        if callable(route):
            route = route(identifier)
        if isinstance(route, int):
            return IcmpExchange(state="reply", ttl=route)
        assert isinstance(route, IcmpExchange)
        return route

    async def udp(
        self,
        host: str,
        port: int,
        *,
        payload: bytes,
        io_timeout: float,
        max_bytes: int,
    ) -> UdpExchange:
        route = self._next(("udp", host, port), UdpExchange(state="open-filtered"))
        if callable(route):
            route = route(payload)
        if isinstance(route, (bytes, bytearray)):
            return UdpExchange(state="open", payload=bytes(route))
        assert isinstance(route, UdpExchange)
        return route

    async def tls(
        self,
        host: str,
        port: int,
        *,
        min_version: str | None,
        max_version: str | None,
        ciphers: str | None,
        options: int,
        server_hostname: str | None,
        verify: bool,
        connect_timeout: float,
        read_timeout: float,
    ) -> TlsExchange:
        key = ("tls", host, port)
        route = self._next(key, TlsExchange(ok=False, error="no TLS listener in the script"))
        if callable(route):
            route = route(
                {
                    "min_version": min_version,
                    "max_version": max_version,
                    "ciphers": ciphers,
                    "options": options,
                    "verify": verify,
                }
            )
        if isinstance(route, dict):
            # A scripted TLS server. Contract:
            #   supported:    versions the endpoint offers (a pinned probe for one of them
            #                 succeeds; anything else fails as "unsupported")
            #   legacy:       the version it negotiates when the client is capped below TLS 1.2
            #                 (``options`` set), i.e. what the legacy-protocol probe observes
            #   verify_error: the trust probe's failure message (the chain does not validate)
            #   cipher/der:   the negotiated suite and the certificate DER
            wanted = max_version or min_version
            if verify:
                if route.get("verify_error"):
                    return TlsExchange(ok=False, verify_error=str(route["verify_error"]))
                return TlsExchange(ok=True, version=wanted, cipher=route.get("cipher"))
            if options:
                legacy = route.get("legacy")
                if not legacy:
                    return TlsExchange(ok=False, error="alert: no legacy protocol offered")
                return TlsExchange(
                    ok=True,
                    version=str(legacy),
                    cipher=route.get("cipher"),
                    certificate_der=route.get("der"),
                )
            if wanted:
                supported = bool(route.get(wanted, False))
                return TlsExchange(
                    ok=supported,
                    version=wanted if supported else None,
                    cipher=route.get("cipher") if supported else None,
                    certificate_der=route.get("der"),
                )
            # An unpinned probe: the scripted server selects its best offered version.
            offered = tuple(route.get("supported") or ())
            best = offered[0] if offered else None
            return TlsExchange(
                ok=best is not None,
                version=best,
                cipher=route.get("cipher") if best else None,
                certificate_der=route.get("der") if best else None,
            )
        assert isinstance(route, TlsExchange)
        return route


class ScopedNetClient:
    """The single non-HTTP egress point: scoped, rate-limited, audited probes (S4/M2)."""

    def __init__(
        self,
        *,
        settings: Settings | None = None,
        scope: Scope | None = None,
        policy: UrlSafetyPolicy | None = None,
        resolver: HostResolver | None = None,
        limiter: HostRateLimiter | None = None,
        auditor: Auditor | None = None,
        transport: NetTransport | None = None,
    ) -> None:
        self.settings = settings or get_settings()
        safety = self.settings.safety
        self.scope = scope if scope is not None else safety.scope
        self.policy = policy if policy is not None else safety.policy
        self.net_settings: NetSettings = self.settings.net
        self.resolver: HostResolver = resolver or SocketResolver()
        self.limiter = limiter or HostRateLimiter(self.settings.rate_limit)
        self.transport: NetTransport = transport or SocketTransport()
        self.auditor = auditor or Auditor(actor=self.settings.actor)
        #: Bound on simultaneous probes; a scan must not turn a /24 into a SYN storm.
        self._semaphore = asyncio.Semaphore(self.net_settings.concurrency)
        #: Every probe this client made, for step statistics and tests.
        self.probes = 0
        #: The air-gapped egress allowlist (S25, REQ-RESIL-001); inert unless enabled.
        self._airgap = build_airgap_policy(self.settings)
        self._airgap_scope_hosts: tuple[str, ...] = tuple(safety.scope.allowed_hosts) + tuple(
            safety.scope.allowed_domains
        )

    async def __aenter__(self) -> ScopedNetClient:
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        """Nothing to release today; the seam exists so a caller treats both clients alike."""

    # ------------------------------------------------------------------ primitives
    async def tcp(
        self,
        host: str,
        port: int,
        *,
        payload: bytes | None = None,
        reads: int = 1,
        read_timeout: float | None = None,
    ) -> TcpExchange:
        """Connect to ``host:port``, optionally send ``payload``, read up to ``reads`` chunks."""
        addresses = await self._authorize(host, port, protocol="tcp")
        # An unprompted banner gets the short banner window; a probe that sends a payload gets
        # the full read timeout, because the peer is expected to answer. (Waiting the full
        # timeout on every open port is what makes a 100-port scan take minutes.)
        if read_timeout is not None:
            effective_read = read_timeout
        elif payload is None and reads > 0:
            effective_read = self.net_settings.banner_wait_s
        else:
            effective_read = self.net_settings.read_timeout_s
        async with self._semaphore:
            await self.limiter.acquire(f"{host}:{port}")
            exchange = await self.transport.tcp(
                addresses[0],
                port,
                payload=payload,
                reads=reads,
                connect_timeout=self.net_settings.connect_timeout_s,
                read_timeout=effective_read,
                max_bytes=self.net_settings.max_read_bytes,
            )
        self._audit(
            action=AuditAction.NET_PROBE,
            host=host,
            port=port,
            protocol="tcp",
            outcome=AuditOutcome.ALLOWED,
            meta={
                "state": exchange.state,
                "bytes_read": len(exchange.banner),
                "elapsed_ms": exchange.elapsed_ms,
                "addresses": list(addresses),
                "error": exchange.error,
            },
        )
        self.probes += 1
        return TcpExchange(
            state=exchange.state,
            chunks=exchange.chunks,
            elapsed_ms=exchange.elapsed_ms,
            addresses=addresses,
            error=exchange.error,
        )

    async def udp(
        self,
        host: str,
        port: int,
        payload: bytes,
        *,
        io_timeout: float | None = None,
    ) -> UdpExchange:
        """Send one UDP datagram and read one reply (opt-in: ``net.allow_udp``)."""
        addresses = await self._authorize(host, port, protocol="udp")
        async with self._semaphore:
            await self.limiter.acquire(f"{host}:{port}")
            exchange = await self.transport.udp(
                addresses[0],
                port,
                payload=payload,
                io_timeout=(
                    io_timeout if io_timeout is not None else self.net_settings.read_timeout_s
                ),
                max_bytes=self.net_settings.max_read_bytes,
            )
        self._audit(
            action=AuditAction.NET_PROBE,
            host=host,
            port=port,
            protocol="udp",
            outcome=AuditOutcome.ALLOWED,
            meta={
                "state": exchange.state,
                "bytes_read": len(exchange.payload or b""),
                "elapsed_ms": exchange.elapsed_ms,
                "addresses": list(addresses),
                "error": exchange.error,
            },
        )
        self.probes += 1
        return exchange

    async def tls(
        self,
        host: str,
        port: int,
        *,
        min_version: str | None = None,
        max_version: str | None = None,
        ciphers: str | None = None,
        options: int = 0,
        server_hostname: str | None = None,
        verify: bool = False,
    ) -> TlsExchange:
        """Attempt one TLS handshake with a specific version/cipher/trust configuration."""
        addresses = await self._authorize(host, port, protocol="tls")
        async with self._semaphore:
            await self.limiter.acquire(f"{host}:{port}")
            exchange = await self.transport.tls(
                addresses[0],
                port,
                min_version=min_version,
                max_version=max_version,
                ciphers=ciphers,
                options=options,
                server_hostname=server_hostname,
                verify=verify,
                connect_timeout=self.net_settings.connect_timeout_s,
                read_timeout=self.net_settings.read_timeout_s,
            )
        self._audit(
            action=AuditAction.NET_PROBE,
            host=host,
            port=port,
            protocol="tls",
            outcome=AuditOutcome.ALLOWED,
            meta={
                "state": "open" if exchange.ok else "refused",
                "version": exchange.version,
                "cipher": exchange.cipher,
                "verify_error": exchange.verify_error,
                "elapsed_ms": exchange.elapsed_ms,
                "addresses": list(addresses),
                "error": exchange.error,
            },
        )
        self.probes += 1
        return exchange

    async def icmp(self, host: str, *, io_timeout: float | None = None) -> IcmpExchange:
        """Send one ICMP echo request and report the reply's TTL when the platform allows it.

        A liveness probe, nothing more: research ch02#1 is explicit that "ICMP is filtered"
        does not mean "the host is down", so a timeout here is a data point and never a
        conclusion — :meth:`ScopedNetClient.tcp` is what decides liveness for M2.
        """
        addresses = await self._authorize(host, 0, protocol="icmp")
        async with self._semaphore:
            await self.limiter.acquire(f"{host}:icmp")
            exchange = await self.transport.icmp(
                addresses[0],
                identifier=int.from_bytes(os.urandom(2), "big"),
                io_timeout=(
                    io_timeout if io_timeout is not None else self.net_settings.connect_timeout_s
                ),
            )
        self._audit(
            action=AuditAction.NET_PROBE,
            host=host,
            port=0,
            protocol="icmp",
            outcome=(AuditOutcome.ALLOWED if exchange.state != "error" else AuditOutcome.ERROR),
            meta={
                "state": exchange.state,
                "ttl": exchange.ttl,
                "elapsed_ms": exchange.rtt_ms,
                "error": exchange.error,
            },
        )
        self.probes += 1
        return exchange

    async def resolve_addresses(self, host: str, port: int) -> tuple[str, ...]:
        """Resolve a name through the client's resolver (used for evidence, no packets)."""
        return await self._resolve(host, port)

    # ------------------------------------------------------------------ conveniences
    async def probe_ports(
        self,
        host: str,
        ports: Sequence[int],
        *,
        payload: bytes | None = None,
        reads: int = 1,
    ) -> list[ProbeOutcome]:
        """Probe several ports on one host concurrently, returning results in port order.

        Concurrency is bounded by the client's semaphore and every probe still passes the
        per-probe gate, so this is a scheduling convenience, never a bypass.
        """

        async def one(port: int) -> ProbeOutcome:
            try:
                exchange = await self.tcp(host, port, payload=payload, reads=reads)
            except (SafetyError, NetProbeError, OSError) as exc:
                # A refused or unresolvable target is an outcome for that port, not a reason
                # to abandon the rest of the host's ports (a single dead name must not fail a
                # whole sweep).
                return ProbeOutcome(
                    host=host,
                    port=port,
                    protocol="tcp",
                    state="blocked",
                    error=getattr(exc, "reason", None) or str(exc),
                )
            return ProbeOutcome(
                host=host,
                port=port,
                protocol="tcp",
                state=exchange.state,
                banner=exchange.banner_text(limit=self.net_settings.max_read_bytes),
                elapsed_ms=exchange.elapsed_ms,
                error=exchange.error,
            )

        return list(await asyncio.gather(*(one(port) for port in ports)))

    async def resolve(self, host: str, port: int) -> tuple[str, ...]:
        """Resolve ``host`` through the client's resolver (no packet to the target)."""
        return await self._resolve(host, port)

    # ------------------------------------------------------------------ internals
    async def _authorize(self, host: str, port: int, *, protocol: str) -> tuple[str, ...]:
        """Scope + address-policy gate; returns the pinned addresses to dial.

        Order follows the HTTP path (ADR-050.1): an IP literal is classified *before* the
        scope check so the operator always sees the specific reason, and a name is resolved
        only *after* it is known to be in scope, so an out-of-scope host cannot even cause
        a DNS query.
        """
        normalized = normalize_host(host)
        if not normalized:
            self._block("missing host", host=host, port=port, protocol=protocol, reason="missing")
            raise OutOfScopeError("empty host", reason="missing-host")

        scope_decision = self.scope.check(normalized)
        if not scope_decision.allowed:
            self._block(
                scope_decision.reason,
                host=host,
                port=port,
                protocol=protocol,
                reason=scope_decision.reason,
                action=AuditAction.SCOPE_REJECTED,
            )
            raise OutOfScopeError(
                f"host {host!r} is not in scope: {scope_decision.reason}",
                reason=scope_decision.reason,
            )

        # S25 (REQ-RESIL-001): the air-gapped allowlist is a second, stricter gate on the
        # non-HTTP egress path, so a probe to an external host is refused here as it is in
        # the HTTP client. Inert unless the deployment runs air-gapped.
        refusal = self._airgap.refusal(normalized, scope_hosts=self._airgap_scope_hosts)
        if refusal is not None:
            self._block(
                refusal,
                host=host,
                port=port,
                protocol=protocol,
                reason="airgapped",
                action=AuditAction.AIRGAP_BLOCKED,
            )
            raise AirgapError(refusal)

        if not _is_ip(normalized):
            try:
                addresses = await self._resolve(normalized, port)
            except OSError as exc:
                self._block(
                    _describe(exc),
                    host=host,
                    port=port,
                    protocol=protocol,
                    reason="dns-failure",
                )
                raise NetProbeError(f"cannot resolve {host!r}: {_describe(exc)}") from exc
            if not addresses:
                self._block(
                    "resolved to no addresses",
                    host=host,
                    port=port,
                    protocol=protocol,
                    reason="dns-empty",
                )
                raise NetProbeError(f"host {host!r} resolved to no addresses")
        else:
            addresses = (normalized,)

        for address in addresses:
            reason = classify_ip(address, self.policy)
            if reason is not None:
                self._block(
                    f"address {address} is out of policy ({reason})",
                    host=host,
                    port=port,
                    protocol=protocol,
                    reason=reason,
                )
                raise SafetyError(f"address {address} is out of policy ({reason})", reason=reason)
        return addresses

    async def _resolve(self, host: str, port: int) -> tuple[str, ...]:
        return await self.resolver.resolve(host, port)

    def _block(
        self,
        message: str,
        *,
        host: str,
        port: int,
        protocol: str,
        reason: str,
        action: AuditAction = AuditAction.NET_BLOCKED,
    ) -> None:
        self.audit_record(
            action,
            outcome=AuditOutcome.BLOCKED,
            host=host,
            port=port,
            protocol=protocol,
            reason=reason,
            meta={"requested": f"{host}:{port}"},
        )
        _logger.warning(
            "network probe blocked by safety gate",
            extra={
                "event": "net.blocked",
                "host": host,
                "port": port,
                "protocol": protocol,
                "reason": reason,
            },
        )

    def _audit(
        self,
        *,
        action: AuditAction,
        host: str,
        port: int,
        protocol: str,
        outcome: AuditOutcome,
        meta: dict[str, Any],
    ) -> None:
        self.audit_record(
            action, outcome=outcome, host=host, port=port, protocol=protocol, meta=meta
        )

    def audit_record(
        self,
        action: AuditAction,
        *,
        outcome: AuditOutcome = AuditOutcome.ALLOWED,
        host: str,
        port: int,
        protocol: str,
        reason: str | None = None,
        meta: dict[str, Any] | None = None,
    ) -> None:
        """Write one audit line for a probe (F-01-08)."""
        self.auditor.record(
            action,
            outcome=outcome,
            target=f"{protocol}://{host}:{port}",
            reason=reason,
            meta={"host": host, "port": port, "protocol": protocol, **dict(meta or {})},
        )


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True
