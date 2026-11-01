"""Hardening and legacy-exposure checks for M2 (research ch02#12/#13/#21/#26, ch04#22).

Five checks that sit between "we know the port is open" and "we know what it is", each
answering a question the fingerprinter deliberately does not:

* ``m2.http-fingerprint`` (ch02#12) reads the HTTP(S) response itself — ``Server``,
  ``X-Powered-By``, ``X-AspNet-Version``, ``X-Generator``, the framework cookies and the
  HTML ``<title>``/generator meta — to name the stack behind a web endpoint. A version
  string in a banner is reported as a low-confidence candidate because it is exactly the
  input a CVE correlation wants.
* ``m2.favicon-hash`` (ch02#13) fetches ``/favicon.ico`` and digests the bytes (SHA-256,
  plus the MurmurHash3-32 Shodan uses when ``mmh3`` is importable), matching a small table
  of well-known default icons. The favicon is an *artifact*, never an asset.
* ``m2.ftp-anonymous`` (ch02#21) reads the FTP banner and completes an ``anonymous`` login,
  read-only: ``USER anonymous`` / ``PASS anonymous@`` and a ``230`` is the finding.
* ``m2.ssdp-discovery`` (ch02#26) sends one SSDP ``M-SEARCH`` over UDP 1900 and parses the
  ``200 OK``/``NOTIFY`` answer for the UPnP ``SERVER`` header and ``LOCATION`` URL. UDP needs
  the deployment-level opt-in (``ARACHNE_NET_ALLOW_UDP``), on top of the active-check gate.
* ``m2.legacy-services`` (ch04#22) detects legacy services left on their defaults: Telnet
  (via the IAC negotiation bytes), and the cleartext legacy protocols rlogin (513), finger
  (79) and a read-only TFTP ``RRQ`` (69).

**Safety.** The three active checks set ``requires_active_checks=True`` and ``safe=True``:
they read, they never write. The FTP check stops at a successful anonymous login, and the
TFTP probe requests a single small path. Nothing here uploads, deletes or authenticates
with a victim credential.
"""

from __future__ import annotations

import hashlib
import importlib
import re
from collections.abc import AsyncIterator, Sequence
from typing import Any
from urllib.parse import urlsplit

from arachne.core.results import CheckResult, Evidence
from arachne.core.target import TargetKind
from arachne.modules.base import CheckMetadata, Module
from arachne.modules.context import CheckContext
from arachne.modules.m2.inventory import ServiceRecord
from arachne.modules.m2.support import (
    NetworkCheck,
    addresses_for_asset,
    catalog_ports_for_probe,
    inventory_or_skip,
    net_or_skip,
    services_of,
)

__all__ = [
    "DEFAULT_FAVICONS",
    "DEFAULT_FAVICON_MMH3",
    "FaviconHash",
    "FtpAnonymous",
    "HttpFingerprint",
    "LegacyServices",
    "SsdpDiscovery",
    "favicon_digest",
]

_HTTP_KINDS = (TargetKind.IP, TargetKind.DOMAIN, TargetKind.URL)
_NETWORK_KINDS = (TargetKind.IP, TargetKind.CIDR)

#: Upper bound on how many HTTP endpoints one fingerprint run may touch.
_MAX_HTTP_ENDPOINTS = 8

#: Ports an HTTP(S) endpoint plausibly lives on when the inventory already named the service
#: (the scheme matters: a favicon fetched over TLS cannot use the raw-byte TCP path).
_HTTP_SCHEME_PORTS: dict[int, str] = {
    80: "http",
    8000: "http",
    8080: "http",
    8888: "http",
    3000: "http",
    5000: "http",
    8081: "http",
    443: "https",
    8443: "https",
    9443: "https",
}
_HTTP_SERVICE_NAMES: frozenset[str] = frozenset(
    {"http", "http-alt", "https", "http-proxy", "webcache", "docker"}
)

#: A banner that names a product *and* a version is what the CVE correlation wants, so it is
#: reported as a low-confidence candidate rather than buried in the informational summary.
_VERSION_BANNER = re.compile(
    r"(?i)\b("
    r"apache|nginx|php|openssl|iis|microsoft-iis|tomcat|jetty|lighttpd|caddy|gunicorn|"
    r"uvicorn|werkzeug|openresty|express|asp\.?net|python|ruby|mongoose|thttpd"
    r")[\s/]+(\d[\w.\-]*)"
)

#: Session cookie names that name a framework (the cookie is set before any body arrives, which
#: is why it is such a reliable fingerprint).
_FRAMEWORK_COOKIES: dict[str, str] = {
    "jsessionid": "Java Servlet (JSESSIONID)",
    "phpsessid": "PHP (PHPSESSID)",
    "phpbb3": "phpBB (phpbb3_...)",
    "asp.net_sessionid": "ASP.NET (ASP.NET_SessionId)",
    "aspnetsessionid": "ASP.NET",
    "aspsessionid": "Classic ASP (ASPSESSIONID)",
    "xsrf-token": "Laravel / Angular (XSRF-TOKEN)",
    "laravel_session": "Laravel (laravel_session)",
    "csrftoken": "Django (csrftoken)",
    "sessionid": "Django (sessionid)",
    "_session_id": "Ruby on Rails (_session_id)",
    "_rails_session": "Ruby on Rails",
    "connect.sid": "Express (connect.sid)",
    "cfid": "ColdFusion (CFID)",
    "jsessionid3": "Java Servlet",
}

_HTML_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_HTML_GENERATOR = re.compile(
    r"""<meta[^>]+name=["']generator["'][^>]*content=["']([^"']+)""", re.IGNORECASE
)

#: Well-known default favicons, keyed by the SHA-256 of their bytes. The 0-byte icon is a
#: surprisingly common server default (a blank ``favicon.ico``) and the two 1x1 placeholders
#: are the generic "no real icon" files. The named vendor digests are the published defaults
#: of the FoxIO/Shodan favicon corpus; keeping the table small is deliberate — a wrong hash
#: would attribute an unrelated site's identity.
DEFAULT_FAVICONS: dict[str, str] = {
    # 0-byte favicon.
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": (
        "empty favicon (0-byte default icon)"
    ),
    # 1x1 transparent GIF (43 bytes, the smallest valid GIF).
    "693d949d8c3fdc7fd4ace7c340b5f177a9f0c5be7bafee8bc93a7d88b7523d75": (
        "1x1 transparent GIF placeholder"
    ),
}

#: MurmurHash3-32 of the same default icons (the value Shodan and FOFA index by). Only used
#: when the optional ``mmh3`` package is importable; the entries mirror :data:`DEFAULT_FAVICONS`.
DEFAULT_FAVICON_MMH3: dict[int, str] = {
    # mmh3.hash(b"") == 0 for the 32-bit signed variant.
    0: "empty favicon (0-byte default icon)",
}

#: ASCII magic that marks an FTP banner as a known cleartext server, mapped to a product label.
_FTP_PRODUCTS: tuple[tuple[str, str], ...] = (
    ("vsftpd", "vsftpd"),
    ("proftpd", "ProFTPD"),
    ("filezilla", "FileZilla Server"),
    ("microsoft ftp", "Microsoft FTP Service"),
    ("pure-ftpd", "Pure-FTPd"),
    ("wu-ftpd", "wu-ftpd"),
    ("serv-u", "Serv-U"),
    ("ncftp", "NcFTPd"),
)

#: Legacy cleartext services (research ch04#22): canonical port, family and catalogue names.
_LEGACY_TCP: tuple[tuple[int, str, tuple[str, ...]], ...] = (
    (23, "telnet", ("telnet", "telnetd")),
    (513, "rlogin", ("rlogin", "login", "shell", "exec")),
    (79, "finger", ("finger",)),
)

#: The shortest read that proves a Telnet server: the IAC (0xFF) negotiation byte.
_TELNET_IAC = b"\xff"
_TELNET_PROMPTS = ("login:", "password:", "telnet", "busybox")

_SSDP_MULTICAST = "239.255.255.250"
_SSDP_PORT = 1900
_SSDP_M_SEARCH = (
    b"M-SEARCH * HTTP/1.1\r\n"
    b"HOST: 239.255.255.250:1900\r\n"
    b'MAN: "ssdp:discover"\r\n'
    b"MX: 1\r\n"
    b"ST: ssdp:all\r\n"
    b"\r\n"
)


# --------------------------------------------------------------------------- shared helpers
def _probe_hosts(ctx: CheckContext) -> tuple[str, ...]:
    """The addresses of this asset the inventory already knows, else the asset's own."""
    addresses = addresses_for_asset(ctx.asset, max_hosts=ctx.config.max_hosts)
    inventory = ctx.inventory
    if inventory is None:
        return addresses
    known = [record.address for record in inventory.iter_hosts()]
    if not known:
        return addresses
    wanted = set(addresses)
    known_set = tuple(address for address in known if address in wanted)
    return known_set or addresses


def _split_endpoint(url: str) -> tuple[str, str, int]:
    """``(scheme, host, port)`` for an endpoint URL (defaults to plain HTTP)."""
    parts = urlsplit(url if "://" in url else f"http://{url}")
    scheme = (parts.scheme or "http").lower()
    host = parts.hostname or ""
    port = parts.port or (443 if scheme == "https" else 80)
    return scheme, host, port


def _http_endpoints(ctx: CheckContext) -> tuple[str, ...]:
    """The HTTP(S) base URLs worth probing for this asset (bounded, no packet sent)."""
    asset = ctx.asset
    if asset.kind == "url":
        return (asset.value,)[:_MAX_HTTP_ENDPOINTS]
    inventory = ctx.inventory
    services = services_of(inventory, asset) if inventory is not None else ()
    urls: list[str] = []
    for service in services:
        if service.protocol != "tcp":
            continue
        name = service.effective_service.lower()
        if name not in _HTTP_SERVICE_NAMES and service.port not in _HTTP_SCHEME_PORTS:
            continue
        scheme = _HTTP_SCHEME_PORTS.get(service.port, "https" if name == "https" else "http")
        urls.append(f"{scheme}://{service.host}:{service.port}/")
    if not urls:
        urls = [f"http://{host}/" for host in _probe_hosts(ctx)[:_MAX_HTTP_ENDPOINTS]]
    return tuple(dict.fromkeys(urls))[:_MAX_HTTP_ENDPOINTS]


def _html_title(body: str) -> str | None:
    match = _HTML_TITLE.search(body or "")
    if match is None:
        return None
    return " ".join(match.group(1).split())[:200] or None


def _html_generator(body: str) -> str | None:
    match = _HTML_GENERATOR.search(body or "")
    if match is None:
        return None
    return match.group(1).strip()[:120] or None


def _framework_from_cookies(cookies: Any) -> tuple[str, ...]:
    found: list[str] = []
    for cookie in cookies or ():
        name = str(getattr(cookie, "name", "")).lower()
        label = _FRAMEWORK_COOKIES.get(name)
        if label is not None:
            found.append(label)
    return tuple(dict.fromkeys(found))


def _headers_lower(response: Any) -> dict[str, str]:
    return {
        str(key).lower(): str(value) for key, value in (response.response_headers or {}).items()
    }


def _murmur3_32(data: bytes) -> int | None:
    """The Shodan-style MurmurHash3-32 of ``data``, or ``None`` when ``mmh3`` is absent."""
    try:
        module: Any = importlib.import_module("mmh3")
    except ImportError:
        return None
    try:
        return int(module.hash(data))
    except Exception:  # a broken install must not fail the scan
        return None


def favicon_digest(data: bytes) -> tuple[str, int | None]:
    """``(sha256_hex, mmh3_32_or_None)`` for the favicon bytes."""
    return hashlib.sha256(data).hexdigest(), _murmur3_32(data)


# =========================================================================== checks
class HttpFingerprint(NetworkCheck, Module):
    """``m2.http-fingerprint`` — name the HTTP(S) stack from one response (ch02#12)."""

    metadata = CheckMetadata(
        id="m2.http-fingerprint",
        module="M2",
        name="http-fingerprint",
        version="1.0",
        title="HTTP(S) fingerprinting",
        description=(
            "Reads one HTTP(S) response and names the server stack from its Server, "
            "X-Powered-By, X-AspNet-Version and X-Generator headers, its framework session "
            "cookies (JSESSIONID, PHPSESSID, ASP.NET_SessionId, XSRF-TOKEN, csrftoken, "
            "_session_id) and the HTML <title>/generator meta. A banner that discloses a "
            "product version is raised as a low-confidence candidate for the CVE correlation."
        ),
        research_ref="ch02#12",
        cwe="CWE-200",
        target_kinds=_HTTP_KINDS,
        severity_hint="low",
        type="hybrid",
        safe=True,
        verifiable=True,
        estimated_requests=8,
        runs_on_discovered=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        http = ctx.http
        if http is None:
            yield ctx.skipped(
                "no HTTP client in this run: HTTP fingerprinting needs a live scan "
                "(a dry run sends nothing — F-01-10)"
            )
            return
        endpoints = _http_endpoints(ctx)
        if not endpoints:
            yield ctx.skipped(f"no HTTP(S) endpoint to fingerprint for asset {ctx.asset.key}")
            return

        identified = False
        for url in endpoints:
            try:
                response = await http.get(url)
            except Exception as exc:  # a refused endpoint is data, not a crash
                yield ctx.info(
                    f"HTTP fingerprint of {url} did not answer ({exc.__class__.__name__})",
                    evidence=[
                        ctx.evidence("note", {"url": url, "error": str(exc)[:200]}, source=url)
                    ],
                    confidence=0.2,
                )
                continue
            identified = True
            facts = _fingerprint_response(response)
            evidence = [
                ctx.evidence(
                    "http_response",
                    {
                        "url": response.url,
                        "status_code": response.status_code,
                        "headers": response.response_headers,
                        "body": response.body[:2048],
                    },
                    source=response.url,
                ),
                ctx.evidence("note", facts, source=response.url),
            ]
            stack = facts["stack"]
            yield ctx.info(
                f"HTTP stack on {url}: {facts['summary'] or 'no identifying banner'}",
                detail=("; ".join(stack) or "The response carried no product banner."),
                evidence=evidence,
                confidence=0.85 if stack else 0.4,
            )
            banners = facts["version_banners"]
            if banners:
                yield ctx.candidate(
                    f"HTTP banner on {url} discloses a product version",
                    detail=(
                        "The response advertises: " + "; ".join(banners) + ". A versioned "
                        "banner lets a client correlate the stack against known CVEs without "
                        "probing further (research ch02#12)."
                    ),
                    confidence=0.4,
                    evidence=evidence,
                )
        if not identified:
            yield ctx.clean(
                f"no HTTP(S) endpoint answered for {ctx.asset.key}",
                detail=f"{len(endpoints)} endpoint(s) were attempted without a response.",
                confidence=0.4,
            )


def _fingerprint_response(response: Any) -> dict[str, Any]:
    headers = _headers_lower(response)
    server = headers.get("server")
    powered = headers.get("x-powered-by")
    aspnet = headers.get("x-aspnet-version") or headers.get("x-aspnetmvc-version")
    generator = headers.get("x-generator")
    body = response.body or ""
    title = _html_title(body)
    meta_generator = _html_generator(body)
    frameworks = _framework_from_cookies(response.cookies)

    stack: list[str] = []
    if server:
        stack.append(f"Server: {server}")
    if powered:
        stack.append(f"X-Powered-By: {powered}")
    if aspnet:
        stack.append(f"ASP.NET: {aspnet}")
    if generator:
        stack.append(f"X-Generator: {generator}")
    if meta_generator:
        stack.append(f"generator meta: {meta_generator}")
    if title:
        stack.append(f"title: {title}")
    stack.extend(f"framework cookie: {item}" for item in frameworks)

    banner_sources = " ".join(
        part for part in (server, powered, aspnet, generator, meta_generator, title) if part
    )
    version_banners = sorted({match.group(0) for match in _VERSION_BANNER.finditer(banner_sources)})
    summary = server or powered or generator or meta_generator or (title or "")
    return {
        "status": response.status_code,
        "server": server,
        "powered_by": powered,
        "aspnet_version": aspnet,
        "generator": generator,
        "meta_generator": meta_generator,
        "title": title,
        "frameworks": list(frameworks),
        "stack": stack,
        "summary": summary,
        "version_banners": version_banners,
    }


class FaviconHash(NetworkCheck, Module):
    """``m2.favicon-hash`` — hash ``/favicon.ico`` and match default icons (ch02#13)."""

    metadata = CheckMetadata(
        id="m2.favicon-hash",
        module="M2",
        name="favicon-hash",
        version="1.0",
        title="Favicon hash identification",
        description=(
            "Fetches /favicon.ico, records its SHA-256 (and the MurmurHash3-32 Shodan uses "
            "when the optional mmh3 package is importable) as an artifact, and matches it "
            "against a small table of well-known default favicons. A default icon is the "
            "same-favicon pivot an OSINT correlation is built on."
        ),
        research_ref="ch02#13",
        cwe="CWE-200",
        target_kinds=_HTTP_KINDS,
        severity_hint="info",
        type="hybrid",
        safe=True,
        verifiable=True,
        estimated_requests=1,
        runs_on_discovered=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        endpoints = _http_endpoints(ctx)
        if not endpoints:
            yield ctx.skipped(f"no HTTP(S) endpoint to fetch a favicon from for {ctx.asset.key}")
            return
        base = endpoints[0]
        _scheme, host, _port = _split_endpoint(base)
        favicon_url = f"{base.rstrip('/')}/favicon.ico"
        # The favicon is fetched through the shared HTTP client even for a plain-HTTP endpoint,
        # so a replayed/offline scan (fixtures) never has to open a raw socket for it.
        http = ctx.http
        if http is None:
            yield ctx.skipped(f"no HTTP client in this run: cannot fetch the favicon of {base}")
            return
        try:
            response = await http.get(favicon_url)
        except Exception as exc:  # a refused endpoint is data, not a crash
            yield ctx.clean(
                f"favicon request to {favicon_url} failed ({exc.__class__.__name__})",
                evidence=[ctx.evidence("note", {"url": favicon_url}, source=favicon_url)],
                confidence=0.3,
            )
            return
        status, headers = response.status_code, _headers_lower(response)
        binary = response.body_is_binary
        body = b"" if binary else response.body.encode("utf-8", "replace")
        source = response.url

        if status != 200 or (not body and not binary):
            yield ctx.clean(
                f"no favicon served on {base}",
                detail=f"GET /favicon.ico returned HTTP {status} with {len(body)} byte(s).",
                evidence=[
                    ctx.evidence(
                        "note",
                        {"url": favicon_url, "status": status, "size": len(body)},
                        source=source,
                    )
                ],
                confidence=0.6,
            )
            return

        if binary:
            # The shared client summarises a binary body (it is not decoded), so there are no
            # bytes to hash. Record the observation and stop — hashing the placeholder would
            # match the "empty favicon" default and invent a false positive for every target.
            yield ctx.info(
                f"favicon for {host} is a binary image (not digested)",
                detail=(
                    "The favicon is served as binary content, which the shared HTTP client "
                    "summarises rather than decodes; the digest is skipped to avoid a false "
                    "match (research ch02#13)."
                ),
                evidence=[
                    ctx.evidence(
                        "note",
                        {
                            "url": source,
                            "status": status,
                            "content_type": headers.get("content-type"),
                        },
                        source=source,
                    )
                ],
                confidence=0.4,
            )
            return

        sha256, mmh3_value = favicon_digest(body)
        product = DEFAULT_FAVICONS.get(sha256)
        if product is None and mmh3_value is not None:
            product = DEFAULT_FAVICON_MMH3.get(mmh3_value)
        facts: dict[str, Any] = {
            "url": source,
            "status": status,
            "size": len(body),
            "sha256": sha256,
            "mmh3": mmh3_value,
            "content_type": headers.get("content-type"),
            "known_default": product,
        }
        evidence = [ctx.evidence("artifact", facts, source=source)]
        yield ctx.info(
            f"favicon SHA-256 {sha256[:16]}... for {host}",
            detail=(
                f"{len(body)} byte(s)"
                + (f", mmh3 {mmh3_value}" if mmh3_value is not None else "")
                + (f", matches {product}" if product else ", no known default icon match")
            ),
            evidence=evidence,
            confidence=0.7,
        )
        if product:
            yield ctx.candidate(
                f"favicon on {host} is a known default icon ({product})",
                detail=(
                    f"The favicon matches the shipped default ({product}). A vendor-default "
                    "icon is a same-instance pivot: every deployment that never replaced it "
                    "shares this hash, which is exactly how favicon clustering works "
                    "(research ch02#13)."
                ),
                confidence=0.6,
                evidence=evidence,
            )


class FtpAnonymous(NetworkCheck, Module):
    """``m2.ftp-anonymous`` — anonymous FTP login and cleartext banner (ch02#21)."""

    metadata = CheckMetadata(
        id="m2.ftp-anonymous",
        module="M2",
        name="ftp-anonymous",
        version="1.0",
        title="FTP anonymous access",
        description=(
            "Reads the FTP banner, then attempts a read-only anonymous login (USER "
            "anonymous / PASS anonymous@): a 230 response is anonymous access. Also reports "
            "a cleartext FTP banner (vsftpd, ProFTPD, FileZilla, Microsoft FTP). Nothing is "
            "uploaded, downloaded or deleted."
        ),
        research_ref="ch02#21",
        cwe="CWE-287",
        target_kinds=_NETWORK_KINDS,
        severity_hint="high",
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

        catalog = catalog_ports_for_probe(ctx, "ftp") or (21,)
        services = _services_for(ctx, ("ftp",), catalog)
        if not services:
            yield ctx.skipped(
                f"no FTP service recorded for asset {ctx.asset.key} "
                "(m2.port-scan and m2.service-fingerprint establish them first)"
            )
            return

        for service in services:
            greeting = await client.tcp(service.host, service.port)
            service.probes += 1
            banner = greeting.banner_text(limit=1024).strip()
            if not greeting.is_open or not banner:
                yield ctx.clean(
                    f"no FTP greeting from {service.key}",
                    detail=f"The port answered {greeting.state!r} without a banner.",
                    evidence=[_port_evidence(ctx, service, banner[:256])],
                    confidence=0.4,
                )
                continue

            product, version = _ftp_product(banner)
            code = _ftp_code(banner)
            evidence = [
                ctx.evidence(
                    "banner",
                    {
                        "host": service.host,
                        "port": service.port,
                        "greeting": banner[:256],
                        "product": product,
                        "version": version,
                    },
                    source=service.key,
                )
            ]
            yield ctx.info(
                f"FTP on {service.key}: {product or 'unknown server'}",
                detail=(
                    f"cleartext banner {banner[:80]!r} (FTP carries credentials and data "
                    "unencrypted; prefer FTPS/SFTP)"
                ),
                evidence=evidence,
                confidence=0.85 if product else 0.6,
            )

            if code != "220":
                continue
            logged_in, transcript = await _ftp_anonymous(ctx, client, service)
            service.probes += 1
            if logged_in:
                yield ctx.candidate(
                    f"FTP on {service.key} allows anonymous access",
                    detail=(
                        "USER anonymous / PASS anonymous@ completed with a 230 login, so the "
                        "server grants an unauthenticated session — a classic exposure from "
                        "research ch02#21. The probe read the greeting and logged in only; no "
                        "file was listed, uploaded or deleted."
                    ),
                    confidence=0.95,
                    evidence=[
                        *evidence,
                        ctx.evidence("artifact", {"transcript": transcript}, source=service.key),
                    ],
                )
            else:
                yield ctx.info(
                    f"FTP on {service.key} refused anonymous access",
                    detail=f"anonymous login reply: {transcript[-1] if transcript else 'none'}",
                    evidence=evidence,
                    confidence=0.7,
                )


async def _ftp_anonymous(
    ctx: CheckContext, client: Any, service: ServiceRecord
) -> tuple[bool, list[str]]:
    """``USER anonymous`` / ``PASS anonymous@``; ``(logged_in, transcript)``."""
    transcript: list[str] = []
    user = await client.tcp(service.host, service.port, payload=b"USER anonymous\r\n", reads=1)
    service.probes += 1
    user_reply = user.banner_text(limit=512).strip()
    transcript.append(f"USER → {user_reply}")
    if _ftp_code(user_reply) == "230":
        return True, transcript
    if _ftp_code(user_reply) != "331":
        return False, transcript
    await _pace(ctx)
    password = await client.tcp(service.host, service.port, payload=b"PASS anonymous@\r\n", reads=1)
    service.probes += 1
    pass_reply = password.banner_text(limit=512).strip()
    transcript.append(f"PASS → {pass_reply}")
    return _ftp_code(pass_reply) == "230", transcript


class SsdpDiscovery(NetworkCheck, Module):
    """``m2.ssdp-discovery`` — UPnP/SSDP multicast discovery (ch02#26). UDP opt-in."""

    metadata = CheckMetadata(
        id="m2.ssdp-discovery",
        module="M2",
        name="ssdp-discovery",
        version="1.0",
        title="SSDP/UPnP discovery",
        description=(
            "Sends an SSDP M-SEARCH over UDP 1900 and parses the 200 OK / NOTIFY answers for "
            "the UPnP SERVER header and the LOCATION device-description URL. UDP probing "
            "requires ARACHNE_NET_ALLOW_UDP in addition to this check's active-check opt-in."
        ),
        research_ref="ch02#26",
        cwe="CWE-200",
        target_kinds=_NETWORK_KINDS,
        severity_hint="medium",
        type="active",
        safe=True,
        verifiable=True,
        estimated_requests=2,
        requires_active_checks=True,
        runs_on_discovered=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        if not ctx.config.net_allow_udp:
            yield ctx.skipped(
                "UDP probing is disabled: set ARACHNE_NET_ALLOW_UDP=true to send the SSDP "
                "M-SEARCH (multicast discovery is a UDP opt-in, F-01-09)"
            )
            return
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

        hosts = _probe_hosts(ctx)
        if not hosts:
            yield ctx.skipped(f"no probed host for asset {ctx.asset.key}")
            return

        found = False
        for host in hosts:
            exchange = await client.udp(host, _SSDP_PORT, _SSDP_M_SEARCH)
            parsed = _parse_ssdp(exchange.payload) if exchange.payload else None
            if parsed is None:
                continue
            found = True
            server = parsed.get("server")
            location = parsed.get("location")
            evidence = [
                ctx.evidence(
                    "note",
                    {"host": host, "port": _SSDP_PORT, **parsed},
                    source=f"{host}:{_SSDP_PORT}/udp",
                )
            ]
            yield ctx.info(
                f"SSDP responder on {host}: {server or 'unknown device'}",
                detail=(
                    f"ST {parsed.get('st') or 'unknown'}; LOCATION {location or 'not advertised'}"
                ),
                evidence=evidence,
                confidence=0.85,
            )
            yield ctx.candidate(
                f"UPnP/SSDP service exposed on {host}",
                detail=(
                    "A UPnP device answered the SSDP M-SEARCH"
                    + (f" as {server}" if server else "")
                    + (f"; its device-description document is at {location}" if location else "")
                    + ". UPnP exposes device control over the local segment and is a common "
                    "pivot for NAT/firewall manipulation (research ch02#26)."
                ),
                confidence=0.7,
                evidence=evidence,
            )
        if not found:
            yield ctx.clean(
                f"no SSDP responder on {len(hosts)} host(s)",
                detail=(
                    "The M-SEARCH drew no answer. Silence on UDP is ambiguous (a responder "
                    "may be filtered or on another segment), so this is not evidence that "
                    "UPnP is absent."
                ),
                evidence=[
                    ctx.evidence(
                        "note",
                        {"hosts": list(hosts), "port": _SSDP_PORT},
                        source=ctx.asset.key,
                    )
                ],
                confidence=0.4,
            )


def _parse_ssdp(payload: bytes) -> dict[str, Any] | None:
    """Parse an SSDP ``200 OK``/``NOTIFY`` datagram's headers, or ``None`` if it is neither."""
    text = payload.decode("latin-1", errors="replace")
    lines = text.replace("\r\n", "\n").splitlines()
    if not lines:
        return None
    start = lines[0].strip().upper()
    if not start.startswith(("HTTP/1.1 200", "NOTIFY")):
        return None
    headers: dict[str, str] = {}
    for line in lines[1:]:
        name, separator, value = line.partition(":")
        if separator and name.strip():
            headers[name.strip().lower()] = value.strip()
    return {
        "start_line": lines[0].strip()[:80],
        "server": headers.get("server"),
        "location": headers.get("location"),
        "st": headers.get("st"),
        "usn": headers.get("usn"),
    }


class LegacyServices(NetworkCheck, Module):
    """``m2.legacy-services`` — Telnet and cleartext legacy services (ch04#22)."""

    metadata = CheckMetadata(
        id="m2.legacy-services",
        module="M2",
        name="legacy-services",
        version="1.0",
        title="Legacy network services",
        description=(
            "Detects legacy services left enabled with their defaults: a Telnet service "
            "(recognised by its IAC negotiation bytes) and the cleartext legacy protocols "
            "rlogin (513) and finger (79). When UDP is enabled it also sends a single "
            "read-only TFTP RRQ (69) for a small path. Any reachable service is a "
            "cleartext-management exposure."
        ),
        research_ref="ch04#22",
        cwe="CWE-521",
        target_kinds=_NETWORK_KINDS,
        severity_hint="high",
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

        hosts = _probe_hosts(ctx)
        if not hosts:
            yield ctx.skipped(f"no probed host for asset {ctx.asset.key}")
            return

        services = services_of(inventory, ctx.asset)
        found = False
        for host in hosts:
            for port, family, names in _LEGACY_TCP:
                for candidate_port in _legacy_ports(ctx, services, host, family, names, port):
                    async for result in self._probe_tcp(ctx, client, host, candidate_port, family):
                        found = found or result.is_finding
                        yield result
            if ctx.config.net_allow_udp:
                for port in _legacy_ports(
                    ctx, services, host, "tftp", ("tftp",), 69, protocol="udp"
                ):
                    result = await self._probe_tftp(ctx, client, host, port)
                    found = found or result.is_finding
                    yield result

        if not found:
            yield ctx.clean(
                f"no legacy cleartext service answered on {len(hosts)} host(s)",
                detail=(
                    "Telnet (23), rlogin (513) and finger (79) were probed"
                    + (" and a TFTP RRQ was sent" if ctx.config.net_allow_udp else "")
                    + ". None answered as a cleartext legacy service."
                ),
                evidence=[
                    ctx.evidence(
                        "note",
                        {
                            "hosts": list(hosts),
                            "tcp_ports": [entry[0] for entry in _LEGACY_TCP],
                            "udp_enabled": ctx.config.net_allow_udp,
                        },
                        source=ctx.asset.key,
                    )
                ],
                confidence=0.5,
            )

    async def _probe_tcp(
        self, ctx: CheckContext, client: Any, host: str, port: int, family: str
    ) -> AsyncIterator[CheckResult]:
        payload = b"\r\n" if family == "finger" else None
        exchange = await client.tcp(host, port, payload=payload, reads=1)
        if not exchange.is_open:
            yield ctx.clean(
                f"no {family} service on {host}:{port}",
                detail="The port did not accept the probe.",
                confidence=0.5,
            )
            return
        banner = exchange.banner
        text = exchange.banner_text(limit=1024).strip()
        source = f"{host}:{port}/tcp"
        if family == "telnet":
            if not _looks_like_telnet(banner, text):
                yield ctx.info(
                    f"port {port} on {host} is open but did not speak Telnet",
                    detail=f"banner: {text[:120] or banner[:32].hex()}",
                    evidence=[
                        ctx.evidence(
                            "banner",
                            {"host": host, "port": port, "banner": text[:256]},
                            source=source,
                        )
                    ],
                    confidence=0.3,
                )
                return
            yield ctx.candidate(
                f"Telnet service reachable on {host}:{port}",
                detail=(
                    "The service advertised Telnet negotiation"
                    + (f" ({text[:80]!r})" if text else "")
                    + ". Telnet transmits credentials and the whole session in cleartext, and "
                    "is a legacy default still found on network gear and embedded devices "
                    "(research ch04#22)."
                ),
                confidence=0.85,
                evidence=[
                    ctx.evidence(
                        "banner",
                        {
                            "host": host,
                            "port": port,
                            "banner": text[:256],
                            "iac": _TELNET_IAC in banner,
                        },
                        source=source,
                    )
                ],
            )
            return
        yield ctx.candidate(
            f"cleartext {family} service reachable on {host}:{port}",
            detail=(
                f"The {family} port accepted a connection"
                + (f" and answered {text[:80]!r}" if text else "")
                + ". rlogin, finger and friends are unauthenticated, cleartext legacy "
                "services that should not be reachable (research ch04#22)."
            ),
            confidence=0.6,
            evidence=[
                ctx.evidence(
                    "banner", {"host": host, "port": port, "banner": text[:256]}, source=source
                )
            ],
        )

    async def _probe_tftp(
        self, ctx: CheckContext, client: Any, host: str, port: int
    ) -> CheckResult:
        rrq = b"\x00\x01" + b"index.html" + b"\x00" + b"octet" + b"\x00"
        exchange = await client.udp(host, port, rrq)
        source = f"{host}:{port}/udp"
        if exchange.state != "open" or not exchange.payload:
            return ctx.clean(
                f"no TFTP responder on {host}:{port}/udp",
                detail="The read-only RRQ drew no answer.",
                confidence=0.5,
            )
        opcode = int.from_bytes(exchange.payload[:2], "big") if len(exchange.payload) >= 2 else -1
        if opcode == 3:  # DATA
            return ctx.candidate(
                f"TFTP server on {host}:{port}/udp answered a read-only RRQ",
                detail=(
                    "A TFTP server returned DATA for 'index.html' without any authentication. "
                    "TFTP has no authentication and no encryption, so any file it exposes is "
                    "world-readable (research ch04#22)."
                ),
                confidence=0.75,
                evidence=[
                    ctx.evidence(
                        "note", {"host": host, "port": port, "opcode": opcode}, source=source
                    )
                ],
            )
        return ctx.info(
            f"TFTP responder on {host}:{port}/udp",
            detail=f"the RRQ was answered with opcode {opcode} (no DATA returned)",
            evidence=[
                ctx.evidence("note", {"host": host, "port": port, "opcode": opcode}, source=source)
            ],
            confidence=0.5,
        )


# --------------------------------------------------------------------------- ftp / legacy helpers
def _services_for(
    ctx: CheckContext, protocols: Sequence[str], ports: Sequence[int]
) -> tuple[ServiceRecord, ...]:
    """Services matching a protocol identity or one of ``ports`` (a fingerprinted hint wins)."""
    wanted_ports = set(ports)
    wanted_names = {name.lower() for name in protocols}
    matches: list[ServiceRecord] = []
    for service in services_of(ctx.inventory, ctx.asset):
        if service.protocol != "tcp":
            continue
        if service.effective_service.lower() in wanted_names:
            matches.append(service)
            continue
        if service.port in wanted_ports and service.identity is None:
            matches.append(service)
    return tuple(matches)


def _legacy_ports(
    ctx: CheckContext,
    services: Sequence[ServiceRecord],
    host: str,
    family: str,
    names: Sequence[str],
    canonical: int,
    *,
    protocol: str = "tcp",
) -> tuple[int, ...]:
    """Ports to probe for a legacy family: the inventory's matches, else the canonical port."""
    wanted_names = {name.lower() for name in names}
    ports: list[int] = []
    for service in services:
        if service.host != host or service.protocol != protocol:
            continue
        if service.effective_service.lower() in wanted_names or service.port == canonical:
            ports.append(service.port)
    if not ports:
        ports = [canonical]
    del ctx, family
    return tuple(dict.fromkeys(ports))[:2]


def _ftp_code(reply: str) -> str:
    stripped = reply.strip()
    return stripped[:3] if stripped[:3].isdigit() else ""


def _ftp_product(banner: str) -> tuple[str | None, str | None]:
    lowered = banner.lower()
    for needle, product in _FTP_PRODUCTS:
        if needle in lowered:
            match = re.search(rf"{re.escape(needle)}[\s/]*([\d][\w.\-]*)", lowered)
            return product, (match.group(1) if match else None)
    return None, None


def _looks_like_telnet(banner: bytes, text: str) -> bool:
    if not banner:
        return False
    if _TELNET_IAC in banner:
        return True
    low = text.lower()
    return any(prompt in low for prompt in _TELNET_PROMPTS)


async def _pace(ctx: CheckContext) -> None:
    """A tiny inter-step pause so an FTP server does not see a machine-gun login.

    Mirrors SMTP's pacing discipline; the value is the same anti-automation knob, since a
    deployment that wants to slow one login flow wants the same for the other.
    """
    import asyncio

    await asyncio.sleep(min(ctx.config.smtp_pacing_s, 0.5))


def _port_evidence(ctx: CheckContext, service: ServiceRecord, banner: str) -> Evidence:
    return ctx.evidence(
        "banner",
        {"host": service.host, "port": service.port, "response": banner},
        source=service.key,
    )
