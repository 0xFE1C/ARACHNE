"""Service identification: banners, version strings and a bounded probe suite (ch02#9).

Research method 9 is "service version detection & banner grabbing", and its whole value is
the ``(product, version)`` triple that CVE correlation consumes. Two design choices follow
from that:

* **A port number is a hint, never a conclusion.** The catalogue (``templates/m2/ports.yaml``)
  says "port 6379 is usually Redis", which is why the lab binding Redis to 56379 still gets
  identified: the hinted probe is tried first, and a generic suite follows when the hint does
  not answer. An inventory that trusted port numbers would report a CVE for whatever usually
  runs on 6379 rather than for what actually answered.
* **Identify, do not enumerate.** Every probe here is the *cheapest* exchange that names the
  protocol — a banner, an HTTP ``GET /``, a TLS ClientHello, a Redis ``PING`` — because the
  expensive, protocol-specific enumeration belongs to the check that owns that protocol
  (``m2.smtp-enum`` speaks SMTP verbs, ``m2.smb-enum`` speaks SMB2). The fingerprinter's
  output is what those checks use to decide whether a port is theirs.

Every probe is bounded by :data:`MAX_PROBES_PER_PORT`, so an unidentified open port costs a
known number of packets instead of "however many protocols we know".
"""

from __future__ import annotations

import re
import struct
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from arachne.core.net import ScopedNetClient, TcpExchange, TlsExchange
from arachne.modules.m2 import wire
from arachne.modules.m2.inventory import ServiceIdentity

__all__ = [
    "BANNER_RULES",
    "MAX_PROBES_PER_PORT",
    "BannerRule",
    "Identification",
    "identify",
    "parse_http_response",
    "product_from_banner",
]

#: Upper bound on probes one unidentified port may cost.
MAX_PROBES_PER_PORT = 6


@dataclass(frozen=True, slots=True)
class BannerRule:
    """A banner shape that names a protocol (and, when the banner carries one, a version)."""

    name: str
    pattern: re.Pattern[str]
    protocol: str
    product: str | None = None
    #: Regex group names to take the product/version from, when the banner has them.
    product_group: str | None = None
    version_group: str | None = None
    confidence: float = 0.7


#: Ordered rules: the first match wins, so the most specific banner shapes come first.
BANNER_RULES: tuple[BannerRule, ...] = (
    BannerRule(
        "ssh",
        re.compile(r"^SSH-(?P<proto>[12]\.\d+)-(?P<software>[A-Za-z0-9._\-]+)"),
        protocol="ssh",
        product_group="software",
        confidence=0.9,
    ),
    BannerRule(
        "http",
        re.compile(r"^HTTP/\d\.\d\s+\d{3}"),
        protocol="http",
        confidence=0.95,
    ),
    BannerRule(
        "smtp",
        re.compile(r"^220[\s\-].*", re.MULTILINE),
        protocol="smtp",
        confidence=0.7,
    ),
    BannerRule("pop3", re.compile(r"^\+OK"), protocol="pop3", confidence=0.8),
    BannerRule("imap", re.compile(r"^\*\s+OK"), protocol="imap", confidence=0.8),
    BannerRule(
        "ftp",
        re.compile(r"^220[\s\-].*(?:FTP|ftp)"),
        protocol="ftp",
        confidence=0.75,
    ),
    BannerRule(
        "vnc",
        re.compile(r"^RFB\s+(?P<version>\d{3}\.\d{3})"),
        protocol="vnc",
        product="vnc",
        version_group="version",
        confidence=0.9,
    ),
    BannerRule(
        "telnet",
        re.compile(r"^\xff[\xfb-\xfe]"),
        protocol="telnet",
        confidence=0.6,
    ),
    BannerRule(
        "memcached",
        re.compile(r"^STAT\s+\w+\s"),
        protocol="memcached",
        confidence=0.85,
    ),
    BannerRule(
        "redis-error",
        re.compile(r"^-(ERR|NOAUTH|WRONGPASS|DENIED)"),
        protocol="redis",
        product="redis",
        confidence=0.75,
    ),
    BannerRule(
        "redis-pong",
        re.compile(r"^\+PONG"),
        protocol="redis",
        product="redis",
        confidence=0.9,
    ),
    BannerRule(
        "rsync",
        re.compile(r"^@RSYNCD:"),
        protocol="rsync",
        product="rsync",
        confidence=0.9,
    ),
    BannerRule(
        "mysql-binary",
        re.compile(r"^\x00\x00\x00."),
        protocol="mysql",
        product="mysql",
        confidence=0.4,
    ),
)


def product_from_banner(banner: str) -> ServiceIdentity | None:
    """Classify an unprompted banner (the cheapest identification there is)."""
    if not banner:
        return None
    for rule in BANNER_RULES:
        match = rule.pattern.search(banner)
        if match is None:
            continue
        product = rule.product
        version: str | None = None
        groups = match.groupdict()
        if rule.product_group and groups.get(rule.product_group):
            software = str(groups[rule.product_group])
            product, _, tail = software.partition("_")
            product = product.lower()
            version = tail or None
        elif rule.version_group and groups.get(rule.version_group):
            version = str(groups[rule.version_group])
        if rule.protocol == "http":
            # An HTTP response's banner is the start line; the product lives in the headers,
            # which the caller (``identify``) parses from the same buffer.
            product, version = None, None
        return ServiceIdentity(
            protocol=rule.protocol,
            product=product,
            version=version,
            banner=_first_line(banner),
            confidence=rule.confidence,
            extra={"rule": rule.name},
        )
    return None


def _first_line(text: str, *, limit: int = 256) -> str:
    line = text.split("\r\n", 1)[0].split("\n", 1)[0]
    return line.strip()[:limit]


def parse_http_response(text: str) -> dict[str, Any] | None:
    """Parse an HTTP response's status line and headers (no body handling worth the name)."""
    if not text.startswith("HTTP/"):
        return None
    head, _, body = text.partition("\r\n\r\n")
    if not body:
        head, _, body = text.partition("\n\n")
    lines = head.splitlines()
    if not lines:
        return None
    parts = lines[0].split(None, 2)
    if len(parts) < 2:
        return None
    try:
        status = int(parts[1])
    except ValueError:
        return None
    headers: dict[str, str] = {}
    for line in lines[1:]:
        name, separator, value = line.partition(":")
        if separator:
            headers[name.strip().lower()] = value.strip()
    return {
        "status": status,
        "reason": parts[2] if len(parts) > 2 else "",
        "headers": headers,
        "body": body[:2048],
    }


_SERVER_PRODUCT = re.compile(
    r"^(?P<product>[A-Za-z][A-Za-z0-9._\-]*?)(?:/(?P<version>[0-9][0-9A-Za-z._\-]*))?(?:\s|$|\(|;)"
)

#: Vendors whose `Server` header names a whole stack rather than a product.
_SERVER_ALIASES = {
    "microsoft-iis": "Microsoft IIS",
    "gws": "Google Web Server",
    "nginx": "nginx",
    "apache": "Apache httpd",
    "httpd": "Apache httpd",
    "cloudflare": "cloudflare",
    "awselb": "AWS Elastic Load Balancer",
    "openresty": "OpenResty",
    "jetty": "Jetty",
    "gunicorn": "gunicorn",
    "uvicorn": "uvicorn",
    "werkzeug": "Werkzeug",
    "lighttpd": "lighttpd",
    "caddy": "Caddy",
    "tomcat": "Apache Tomcat",
    "wildfly": "WildFly",
    "jboss": "JBoss",
    "iis": "Microsoft IIS",
}


def product_from_server_header(value: str) -> tuple[str | None, str | None]:
    """``(product, version)`` from a ``Server:``/``X-Powered-By:`` value."""
    if not value:
        return None, None
    match = _SERVER_PRODUCT.match(value.strip())
    if match is None:
        return None, None
    raw_product = (match.group("product") or "").lower()
    product = _SERVER_ALIASES.get(raw_product, match.group("product"))
    return (product or None), (match.group("version") or None)


@dataclass(frozen=True, slots=True)
class Probe:
    """One identification exchange: bytes to send, and how many times to read."""

    name: str
    payload: bytes | None
    reads: int = 1
    #: A second exchange where the protocol needs one (the server speaks first for VNC, and
    #: PostgreSQL answers the SSLRequest before the StartupMessage). Unused today: the
    #: protocol checks (not the fingerprinter) do the multi-step conversations.
    repeat: bool = False


@dataclass
class Identification:
    """The outcome of identifying one port."""

    identity: ServiceIdentity | None = None
    probes: list[str] = field(default_factory=list)
    notes: dict[str, Any] = field(default_factory=dict)

    @property
    def protocol(self) -> str:
        return self.identity.protocol if self.identity else "unknown"


def _http_probe(server_name: str) -> Probe:
    host = server_name or "localhost"
    payload = (
        f"GET / HTTP/1.1\r\nHost: {host}\r\n"
        "User-Agent: ARACHNE/0.1 (+https://localhost/arachne) defensive-security-scanner\r\n"
        "Accept: */*\r\nConnection: close\r\n\r\n"
    ).encode()
    return Probe(name="http-get", payload=payload, reads=1)


#: The hinted probes, keyed by the catalogue's ``probe`` vocabulary.
_HINTED: Mapping[str, Callable[[str], Probe]] = {
    "ssh": lambda _host: Probe(name="ssh-banner", payload=None, reads=1),
    "http": lambda host: _http_probe(host),
    "tls": lambda host: Probe(
        name="tls-clienthello", payload=wire.tls_client_hello(server_name=host), reads=1
    ),
    "ftp": lambda _host: Probe(name="ftp-banner", payload=None, reads=1),
    "telnet": lambda _host: Probe(name="telnet-banner", payload=None, reads=1),
    "smtp": lambda _host: Probe(name="smtp-banner", payload=None, reads=1),
    "pop3": lambda _host: Probe(name="pop3-banner", payload=None, reads=1),
    "imap": lambda _host: Probe(name="imap-banner", payload=None, reads=1),
    "dns": lambda _host: Probe(name="dns-banner", payload=None, reads=1),
    "smb": lambda _host: Probe(name="smb2-negotiate", payload=wire.smb2_negotiate(), reads=1),
    "rpcbind": lambda _host: Probe(name="rpcbind-dump", payload=wire.rpcbind_dump_call(), reads=1),
    "ldap": lambda _host: Probe(name="ldap-bind", payload=wire.build_ldap_bind_request(1), reads=1),
    "vnc": lambda _host: Probe(name="vnc-banner", payload=None, reads=1),
    "rdp": lambda _host: Probe(name="rdp-x224", payload=wire.rdp_negociation_request(), reads=1),
    "mysql": lambda _host: Probe(name="mysql-greeting", payload=None, reads=1),
    "postgres": lambda _host: Probe(
        name="postgres-sslrequest", payload=wire.postgres_ssl_request(), reads=1
    ),
    "mssql": lambda _host: Probe(name="mssql-prelogin", payload=_tds_prelogin(), reads=1),
    "redis": lambda _host: Probe(name="redis-ping", payload=wire.redis_command("PING"), reads=1),
    "memcached": lambda _host: Probe(
        name="memcached-stats", payload=wire.memcached_stats(), reads=1
    ),
    "mongodb": lambda _host: Probe(
        name="mongodb-ismaster", payload=wire.mongo_ismaster_probe(), reads=1
    ),
    "modbus": lambda _host: Probe(
        name="modbus-device-id", payload=wire.modbus_read_device_id(), reads=1
    ),
    "kerberos": lambda _host: Probe(name="kerberos-banner", payload=None, reads=1),
    "unknown": lambda _host: Probe(name="connect", payload=None, reads=1),
}

#: The generic suite, tried in order when the hint did not identify the service.
_GENERIC_SUITE: tuple[str, ...] = ("http", "tls", "redis", "memcached", "mongodb", "smtp")


def _tds_prelogin() -> bytes:
    """A minimal, well-formed TDS PRELOGIN request (MS-TDS §2.2.6.5).

    Only the option table and its default data are needed: sending VERSION, ENCRYPTION,
    INSTOPT, THREADID and MARS with neutral values is enough for SQL Server to answer with
    its own PRELOGIN, which is what names the product and build.
    """
    # (token, length) in table order; the data follows the table.
    options = ((0x00, 6), (0x01, 1), (0x02, 1), (0x03, 4), (0x04, 1))
    header_size = 8
    table_size = 5 * len(options) + 5  # + the 0xFF terminator entry
    data_offset = header_size + table_size
    table = bytearray()
    default_data = bytearray()
    cursor = data_offset
    for token, size in options:
        table += bytes([token]) + struct.pack("<HH", cursor, size)
        default_data += b"\x00" * size
        cursor += size
    table += b"\xff" + struct.pack("<HH", table_size, 0)
    # VERSION = 0.0.0.0 is an honest "no preference"; ENCRYPTION = off, MARS = off.
    payload = bytes(table) + bytes(default_data)
    header = bytes([0x12, 0x01]) + struct.pack("<H", len(payload) + header_size)
    header += b"\x00\x00\x00\x00"
    return header + payload


async def identify(
    client: ScopedNetClient,
    *,
    host: str,
    port: int,
    probe_hint: str | None = None,
    banner: str = "",
    server_name: str | None = None,
    max_probes: int = MAX_PROBES_PER_PORT,
) -> Identification:
    """Identify the service on ``host:port``; costs at most ``max_probes`` exchanges.

    The order is: classify what the port already said → try the hinted probe → try the
    generic suite. Whatever answered is returned with the raw evidence, so a report can show
    *why* a product and version were claimed.
    """
    result = Identification()
    existing = product_from_banner(banner)
    if existing is not None:
        if existing.protocol == "http":
            parsed = parse_http_response(banner)
            if parsed is not None:
                result.identity = _identity_from_http(parsed, banner)
                result.probes.append("http-banner")
                return result
        result.identity = existing
        result.probes.append("banner")
        if existing.product and not existing.version and existing.protocol == "ssh":
            # A banner without a version still tells us the protocol; the version is missing
            # and must stay missing (a guessed version would produce a guessed CVE).
            result.notes["version_missing"] = True
        return result

    tried: list[str] = []
    order: list[str] = []
    if probe_hint and probe_hint in _HINTED:
        order.append(probe_hint)
    order.extend(name for name in _GENERIC_SUITE if name not in order)

    for name in order:
        if len(tried) >= max_probes:
            break
        probe = _HINTED[name](server_name or host)
        tried.append(probe.name)
        if name == "tls":
            # A TLS probe is a *handshake*, not a payload: use the client's TLS path (which
            # goes through the same scope, rate-limit and audit machinery) and only fall back
            # to a raw ClientHello when the strict handshake is refused (a server that wants
            # an older protocol, or rejects our context's requirements).
            handshake = await client.tls(host, port, server_hostname=server_name)
            if handshake.ok:
                result.identity = _identity_from_tls(handshake)
                result.probes = tried
                return result
            exchange = await client.tcp(host, port, payload=probe.payload, reads=probe.reads)
            if not exchange.is_open:
                continue
            identity = _interpret(name, exchange, banner=banner, server_name=server_name or host)
            if identity is not None:
                result.identity = identity
                result.probes = tried
                return result
            continue
        exchange = await client.tcp(host, port, payload=probe.payload, reads=probe.reads)
        if not exchange.is_open:
            continue
        identity = _interpret(name, exchange, banner=banner, server_name=server_name or host)
        if identity is not None:
            result.identity = identity
            result.probes = tried
            return result
    result.probes = tried
    return result


def _identity_from_tls(handshake: TlsExchange) -> ServiceIdentity:
    """An identity from a completed TLS handshake (protocol proven, product not guessed)."""
    version = handshake.version or "unknown"
    return ServiceIdentity(
        protocol="tls",
        product=None,
        version=None,
        banner=f"TLS {version} ({handshake.cipher or 'cipher unknown'})",
        confidence=0.85,
        extra={
            "tls": {
                "version": version,
                "cipher": handshake.cipher,
                "certificate_presented": handshake.certificate_der is not None,
            }
        },
    )


def _interpret(
    family: str, exchange: TcpExchange, *, banner: str, server_name: str
) -> ServiceIdentity | None:
    """Turn one probe's response into an identity, or ``None`` when it did not answer.

    ``family`` is the probe *family* from :data:`_HINTED` (``http``, ``mysql``, ...), not the
    display name of the exchange that was sent: one family may send several exchanges and the
    decoder is chosen per family.
    """
    text = exchange.banner_text(limit=8192)
    identity = product_from_banner(text)
    if identity is not None and identity.protocol != "http":
        return identity

    if family == "http":
        parsed = parse_http_response(text)
        if parsed is not None:
            return _identity_from_http(parsed, text)
        return None
    if family == "tls":
        hello = wire.parse_tls_server_hello(exchange.banner)
        if hello is not None:
            return ServiceIdentity(
                protocol="tls",
                product=None,
                version=hello.get("selected_version") or hello.get("record_version"),
                banner=f"TLS {hello.get('record_version', '')}".strip(),
                confidence=0.85,
                extra={"tls": hello},
            )
        return None
    if family == "smb":
        smb = wire.parse_smb2_negotiate(exchange.banner)
        if smb is not None:
            return ServiceIdentity(
                protocol="smb",
                product="smb1" if smb.dialect_revision == 1 else "windows smb",
                version=smb.dialect,
                banner=smb.dialect_name,
                confidence=0.9,
                extra={"dialect": smb.dialect, "signing_required": smb.signing_required},
            )
        return None
    if family == "rpcbind":
        rpc_reply = wire.parse_rpc_reply(exchange.banner)
        if rpc_reply.accepted:
            entries = wire.parse_portmap_dump(rpc_reply.payload)
            return ServiceIdentity(
                protocol="rpcbind",
                product="rpcbind/portmapper",
                banner=f"rpcbind ({len(entries)} registration(s))",
                confidence=0.9,
                extra={"registrations": len(entries)},
            )
        return None
    if family == "ldap":
        ldap = wire.parse_ldap_message(exchange.banner)
        if ldap is not None and ldap.is_bind_response:
            return ServiceIdentity(
                protocol="ldap",
                product="ldap",
                banner=f"LDAP bind result {ldap.result_code}",
                confidence=0.85,
                extra={"result_code": ldap.result_code},
            )
        return None
    if family == "rdp":
        x224 = wire.parse_x224_negociation(exchange.banner)
        if x224 is not None:
            return ServiceIdentity(
                protocol="rdp",
                product="rdp",
                banner=f"RDP {x224.selected_name}",
                confidence=0.85,
                extra={"selected_protocol": x224.selected},
            )
        return None
    if family == "mysql":
        greeting = wire.parse_mysql_greeting(exchange.banner)
        if greeting is not None:
            return ServiceIdentity(
                protocol="mysql",
                product="mysql",
                version=greeting.version,
                banner=f"MySQL {greeting.version}",
                confidence=0.9,
                extra={"auth_plugin": greeting.auth_plugin},
            )
        if text.startswith("mysql_native_password") or "MariaDB" in text:
            return ServiceIdentity(
                protocol="mysql",
                product="mariadb" if "MariaDB" in text else "mysql",
                banner=_first_line(text),
                confidence=0.5,
            )
        return None
    if family == "postgres":
        if exchange.banner[:1] in {b"S", b"N"}:
            if exchange.banner[:1] == b"S":
                return ServiceIdentity(
                    protocol="postgres",
                    product="postgresql",
                    banner="PostgreSQL (TLS supported)",
                    confidence=0.8,
                    extra={"tls_available": True},
                )
            return ServiceIdentity(
                protocol="postgres",
                product="postgresql",
                banner="PostgreSQL (no TLS)",
                confidence=0.8,
                extra={"tls_available": False},
            )
        return None
    if family == "mssql":
        prelogin = wire.parse_mssql_prelogin(exchange.banner)
        if prelogin is not None:
            return ServiceIdentity(
                protocol="mssql",
                product="microsoft sql server",
                version=prelogin.get("version"),
                banner=f"TDS {prelogin.get('version', '')}".strip(),
                confidence=0.9,
                extra=dict(prelogin),
            )
        return None
    if family == "redis":
        redis_reply = wire.parse_redis_reply(exchange.banner)
        if redis_reply is not None and (redis_reply.ok or redis_reply.needs_auth):
            return ServiceIdentity(
                protocol="redis",
                product="redis",
                banner=redis_reply.value[:120],
                confidence=0.9,
                extra={"needs_auth": redis_reply.needs_auth},
            )
        return None
    if family == "memcached":
        stats = wire.memcached_values(text)
        if stats:
            return ServiceIdentity(
                protocol="memcached",
                product="memcached",
                version=stats.get("version"),
                banner=f"memcached {stats.get('version', '')}".strip(),
                confidence=0.9,
                extra={"curr_connections": stats.get("curr_connections")},
            )
        return None
    if family == "mongodb":
        handshake = wire.parse_mongo_ismaster(exchange.banner)
        if handshake is not None:
            return ServiceIdentity(
                protocol="mongodb",
                product="mongodb",
                version=handshake.version,
                banner="MongoDB isMaster handshake",
                confidence=0.9,
                extra={
                    "auth_required": handshake.auth_error is not None,
                    "max_wire_version": handshake.max_wire_version,
                },
            )
        return None
    if family == "modbus":
        device = wire.parse_modbus_device_id(exchange.banner)
        if device is not None:
            return ServiceIdentity(
                protocol="modbus",
                product=device.product or "modbus",
                version=device.version,
                banner=f"Modbus {device.vendor or ''}".strip(),
                confidence=0.9,
                extra={str(key): value for key, value in device.objects.items()},
            )
        return None
    if family == "kerberos":
        # Kerberos is a binary UDP/TCP protocol with no banner; only an AS-REQ answer proves it.
        return None
    if text:
        return product_from_banner(text)
    del server_name
    return None


def _identity_from_http(parsed: Mapping[str, Any], raw: str) -> ServiceIdentity:
    headers = dict(parsed.get("headers") or {})
    server = str(headers.get("server", ""))
    product, version = product_from_server_header(server)
    if product is None:
        powered = str(headers.get("x-powered-by", ""))
        product, version = product_from_server_header(powered)
    extra: dict[str, Any] = {
        "status": parsed.get("status"),
        "server": server or None,
        "title": _html_title(str(parsed.get("body", ""))),
        "headers": {
            key: headers[key]
            for key in ("content-type", "x-powered-by", "strict-transport-security", "location")
            if key in headers
        },
    }
    return ServiceIdentity(
        protocol="http",
        product=product,
        version=version,
        banner=f"{server or 'HTTP'} {parsed.get('status')}".strip(),
        confidence=0.85 if product else 0.6,
        extra=extra,
    )


_HTML_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def _html_title(body: str) -> str | None:
    match = _HTML_TITLE.search(body)
    if match is None:
        return None
    title = " ".join(match.group(1).split())
    return title[:200] or None


def probe_names() -> Sequence[str]:
    """The probe vocabulary (used by tests and by reporting of unsupported hints)."""
    return tuple(sorted(_HINTED))
