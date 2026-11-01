"""Third-party endpoint builders and parsers, one pair per provider.

Separating "build the URL" and "parse the body" from "decide what it means" is what makes
the M1 checks short enough to read: the check owns the *decision* (which hosts are new,
which paths look sensitive) and this module owns the *wire format* of crt.sh, the Wayback
CDX API, the Common Crawl index, Shodan InternetDB, CIRCL passive DNS, a search API and
GitHub code search.

Parsing is total: a body that does not look like what the provider documents yields an empty
result rather than an exception, because a provider changing its shape is a normal event and
must degrade to "nothing found" instead of failing the check (— errors are
data, and so is an unparseable body).
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, urlencode

from arachne.core.safety import normalize_host

__all__ = [
    "COMMONCRAWL_DEFAULT_INDEX",
    "Breach",
    "CensysHost",
    "CensysService",
    "CirclRecords",
    "CrtshCertificate",
    "CrtshResult",
    "CtIssuance",
    "InternetDbRecord",
    "RdapDomain",
    "SearchHit",
    "ShodanHost",
    "censys_host_url",
    "certspotter_url",
    "circl_url",
    "commoncrawl_url",
    "crtsh_url",
    "dns_txt_url",
    "github_code_search_url",
    "hibp_breaches_url",
    "internetdb_url",
    "parse_censys_host",
    "parse_certspotter",
    "parse_circl",
    "parse_commoncrawl_jsonl",
    "parse_crtsh",
    "parse_doh_txt",
    "parse_github_code_search",
    "parse_hibp_breaches",
    "parse_internetdb",
    "parse_rdap",
    "parse_search_results",
    "parse_shodan_host",
    "parse_wayback_cdx",
    "rdap_url_for",
    "search_url_for",
    "shodan_display_url",
    "shodan_host_url",
    "urls_from_rows",
    "wayback_cdx_url",
]

#: A pinned Common Crawl crawl. Pinned, not "latest", so a scan is reproducible and a
#: recorded fixture is meaningful (F-09-03: correlation data is offline-friendly).
COMMONCRAWL_DEFAULT_INDEX = "CC-MAIN-2024-51"


# --------------------------------------------------------------------------- crt.sh
def crtsh_url(domain: str) -> str:
    """crt.sh JSON endpoint for every certificate naming ``domain`` or a subdomain."""
    query = quote(f"%.{normalize_host(domain)}", safe="")
    return f"https://crt.sh/?q={query}&output=json"


# --------------------------------------------------------------------------- DNS over HTTPS
def dns_txt_url(name: str) -> str:
    """A DNS-over-HTTPS TXT query for ``name`` (the SPF/DKIM/DMARC source, S7)."""
    return f"https://dns.google/resolve?name={quote(name, safe='')}&type=TXT"


def parse_doh_txt(payload: Any) -> tuple[str, ...]:
    """TXT record values from a DoH JSON answer, in server order.

    DoH splits a long TXT record into several character-strings inside one answer's
    ``data`` value (``"v=spf1 ..." "all"``); they are concatenated, because a check that
    reads half a record would misjudge the policy. ``Status != 0`` and a malformed answer
    both yield ``()`` — "no record" is the only safe reading.
    """
    if not isinstance(payload, Mapping):
        return ()
    if payload.get("Status") not in (0, None):
        return ()
    answers = payload.get("Answer")
    if not isinstance(answers, (list, tuple)):
        return ()
    records: list[str] = []
    for answer in answers:
        if not isinstance(answer, Mapping) or answer.get("type") not in (16, "TXT"):
            continue
        data = answer.get("data")
        if not isinstance(data, str) or not data.strip():
            continue
        records.append(_join_txt_strings(data))
    return tuple(item for item in records if item)


def _join_txt_strings(data: str) -> str:
    """Concatenate the quoted character-strings of one TXT rdata value."""
    text = data.strip()
    if not text.startswith('"'):
        return text
    parts: list[str] = []
    current: list[str] = []
    index = 0
    while index < len(text):
        character = text[index]
        if character == '"':
            index += 1
            current = []
            while index < len(text) and text[index] != '"':
                if text[index] == "\\" and index + 1 < len(text):
                    index += 1
                current.append(text[index])
                index += 1
            parts.append("".join(current))
            index += 1
            continue
        index += 1
    return "".join(parts) if parts else text


@dataclass(frozen=True, slots=True)
class CrtshCertificate:
    """One certificate as crt.sh reports it."""

    name_value: str
    issuer: str | None = None
    not_before: str | None = None
    not_after: str | None = None
    logged_at: str | None = None


@dataclass(frozen=True, slots=True)
class CrtshResult:
    """Parsed crt.sh answer: every certificate plus the flattened host set."""

    certificates: tuple[CrtshCertificate, ...] = ()
    issuers: tuple[str, ...] = ()

    @property
    def hosts(self) -> tuple[str, ...]:
        """Every distinct hostname named in any certificate's SANs."""
        seen: dict[str, None] = {}
        for certificate in self.certificates:
            for name in certificate.name_value.splitlines():
                host = normalize_host(name.strip().lstrip("*."))
                if host:
                    seen.setdefault(host, None)
        return tuple(seen)


def parse_crtsh(payload: Any, *, domain: str | None = None) -> CrtshResult:
    """Parse the crt.sh JSON body (a list of certificate objects)."""
    if not isinstance(payload, list):
        return CrtshResult()
    certificates: list[CrtshCertificate] = []
    issuers: dict[str, None] = {}
    for entry in payload:
        if not isinstance(entry, Mapping):
            continue
        # crt.sh exposes either name_value or common_name depending on the endpoint/version.
        names = entry.get("name_value") or entry.get("common_name") or ""
        if not isinstance(names, str) or not names.strip():
            continue
        issuer = entry.get("issuer_name") or entry.get("issuer_ca_id")
        if issuer is not None:
            issuers.setdefault(str(issuer), None)
        certificates.append(
            CrtshCertificate(
                name_value=names,
                issuer=str(issuer) if issuer is not None else None,
                not_before=_opt_str(entry.get("not_before")),
                not_after=_opt_str(entry.get("not_after")),
                logged_at=_opt_str(entry.get("entry_timestamp")),
            )
        )
    result = CrtshResult(certificates=tuple(certificates), issuers=tuple(issuers))
    if domain is None:
        return result
    # Keep only names under the queried domain: crt.sh's ``%.`` query is exact, but a
    # recorded fixture (or a future endpoint) must not be able to smuggle in unrelated names.
    base = normalize_host(domain)
    return CrtshResult(
        certificates=tuple(
            certificate
            for certificate in result.certificates
            if any(
                normalize_host(name.strip().lstrip("*.")) == base
                or normalize_host(name.strip().lstrip("*.")).endswith(f".{base}")
                for name in certificate.name_value.splitlines()
            )
        ),
        issuers=result.issuers,
    )


# --------------------------------------------------------------------------- Wayback CDX
def wayback_cdx_url(host: str, *, limit: int = 100) -> str:
    """Wayback CDX query for every archived URL of ``host`` (one collapsed row per URL)."""
    params = urlencode(
        {
            "url": f"{normalize_host(host)}/*",
            "output": "json",
            "fl": "original,timestamp,statuscode,mimetype",
            "collapse": "urlkey",
            "limit": str(limit),
        }
    )
    return f"https://web.archive.org/cdx/search/cdx?{params}"


def parse_wayback_cdx(payload: Any, *, limit: int = 100) -> tuple[dict[str, str], ...]:
    """Parse a CDX JSON body: a header row followed by rows of values."""
    if not isinstance(payload, list) or not payload:
        return ()
    header = [str(item) for item in payload[0]] if isinstance(payload[0], list) else []
    if not header:
        return ()
    rows: list[dict[str, str]] = []
    for raw in payload[1:]:
        if not isinstance(raw, list):
            continue
        row = {name: str(value) for name, value in zip(header, raw, strict=False)}
        rows.append(row)
        if len(rows) >= limit:
            break
    return tuple(rows)


# --------------------------------------------------------------------------- Common Crawl
def commoncrawl_url(host: str, *, index: str = COMMONCRAWL_DEFAULT_INDEX, limit: int = 100) -> str:
    """Common Crawl columnar-index query for ``host`` (JSONL response)."""
    params = urlencode({"url": f"*.{normalize_host(host)}", "output": "json", "limit": str(limit)})
    return f"https://index.commoncrawl.org/{index}-index?{params}"


def parse_commoncrawl_jsonl(text: str, *, limit: int = 100) -> tuple[dict[str, str], ...]:
    """Parse the Common Crawl JSONL body into per-URL records."""
    rows: list[dict[str, str]] = []
    for line in text.splitlines():
        candidate = line.strip()
        if not candidate:
            continue
        try:
            document = json.loads(candidate)
        except json.JSONDecodeError:
            # The index returns a human-readable line when the crawl/URL matches nothing.
            continue
        if not isinstance(document, Mapping):
            continue
        rows.append({str(key): str(value) for key, value in document.items()})
        if len(rows) >= limit:
            break
    return tuple(rows)


# --------------------------------------------------------------------------- InternetDB
def internetdb_url(address: str) -> str:
    """Shodan InternetDB lookup for one IP (keyless, free for non-commercial use)."""
    return f"https://internetdb.shodan.io/{quote(address, safe='')}"


@dataclass(frozen=True, slots=True)
class InternetDbRecord:
    """One InternetDB answer."""

    address: str
    ports: tuple[int, ...] = ()
    hostnames: tuple[str, ...] = ()
    cpes: tuple[str, ...] = ()
    tags: tuple[str, ...] = ()
    vulns: tuple[str, ...] = ()
    found: bool = True

    @property
    def is_empty(self) -> bool:
        return not (self.ports or self.hostnames or self.cpes or self.tags or self.vulns)


def parse_internetdb(payload: Any, *, address: str) -> InternetDbRecord:
    """Parse an InternetDB body; a 404 body (``{"detail":"No information available"}``)
    means "no data for this address", which is a result, not an error."""
    if not isinstance(payload, Mapping):
        return InternetDbRecord(address=address, found=False)
    if "detail" in payload and len(payload) == 1:
        return InternetDbRecord(address=address, found=False)
    return InternetDbRecord(
        address=address,
        ports=tuple(_int_list(payload.get("ports"))),
        hostnames=tuple(_str_list(payload.get("hostnames"))),
        cpes=tuple(_str_list(payload.get("cpes"))),
        tags=tuple(_str_list(payload.get("tags"))),
        vulns=tuple(_str_list(payload.get("vulns"))),
    )


# --------------------------------------------------------------------------- CIRCL pDNS
def circl_url(domain: str) -> str:
    """CIRCL passive-DNS query for one domain (JSONL response, no key required)."""
    return f"https://www.circl.lu/pdns/query/{quote(normalize_host(domain), safe='')}"


@dataclass(frozen=True, slots=True)
class CirclRecords:
    """Parsed passive-DNS records, split by the answer type a check cares about."""

    addresses: tuple[str, ...] = ()
    hostnames: tuple[str, ...] = ()
    mail_servers: tuple[str, ...] = ()
    name_servers: tuple[str, ...] = ()
    rrsets: tuple[str, ...] = ()
    first_seen: str | None = None
    last_seen: str | None = None

    @property
    def is_empty(self) -> bool:
        return not (self.addresses or self.hostnames or self.mail_servers or self.name_servers)


def parse_circl(text: str, *, limit: int = 500) -> CirclRecords:
    """Parse CIRCL's JSONL pDNS answer into typed buckets."""
    addresses: dict[str, None] = {}
    hostnames: dict[str, None] = {}
    mail: dict[str, None] = {}
    nameservers: dict[str, None] = {}
    rrsets: dict[str, None] = {}
    first_seen: str | None = None
    last_seen: str | None = None
    count = 0
    for line in text.splitlines():
        candidate = line.strip()
        if not candidate:
            continue
        try:
            document = json.loads(candidate)
        except json.JSONDecodeError:
            continue
        if not isinstance(document, Mapping):
            continue
        count += 1
        if count > limit:
            break
        rrtype = str(document.get("rrtype", "")).upper()
        raw_rdata = str(document.get("rdata", "")).strip()
        rdata = normalize_host(raw_rdata)
        rrset = f"{rrtype} {document.get('rrname', '')}".strip()
        rrsets.setdefault(rrset, None)
        if rrtype in {"A", "AAAA"} and rdata:
            addresses.setdefault(raw_rdata, None)
        elif rrtype == "CNAME" and rdata:
            hostnames.setdefault(rdata, None)
        elif rrtype == "MX":
            # MX rdata carries a preference ("10 mail.example.com"); only the host is a name.
            exchange = normalize_host(raw_rdata.split()[-1]) if raw_rdata else ""
            if exchange:
                mail.setdefault(exchange, None)
        elif rrtype == "NS" and rdata:
            nameservers.setdefault(rdata, None)
        first_seen = str(document.get("time_first", first_seen))
        last_seen = str(document.get("time_last", last_seen))
    return CirclRecords(
        addresses=tuple(addresses),
        hostnames=tuple(hostnames),
        mail_servers=tuple(mail),
        name_servers=tuple(nameservers),
        rrsets=tuple(rrsets),
        first_seen=first_seen,
        last_seen=last_seen,
    )


# --------------------------------------------------------------------------- search API
def search_url_for(base_url: str, query: str, *, limit: int = 20) -> str:
    """Build a query URL for a configured search endpoint.

    The template is data (``ARACHNE_OSINT_SEARCH_URL``): a deployment points it at a
    self-hosted SearxNG or any endpoint that returns ``{"results": [{"url", "title", ...}]}``.
    ``{query}`` and ``{limit}`` are substituted; without a ``{query}`` placeholder the query
    is appended as a ``q`` parameter.
    """
    base = base_url.strip()
    if "{query}" in base or "{limit}" in base:
        return base.replace("{query}", quote(query, safe="")).replace("{limit}", str(limit))
    separator = "&" if "?" in base else "?"
    return f"{base}{separator}{urlencode({'q': query, 'limit': limit, 'format': 'json'})}"


@dataclass(frozen=True, slots=True)
class SearchHit:
    """One search result."""

    url: str
    title: str = ""
    snippet: str = ""

    def to_dict(self) -> dict[str, str]:
        return {"url": self.url, "title": self.title, "snippet": self.snippet}


def parse_search_results(payload: Any, *, limit: int = 20) -> tuple[SearchHit, ...]:
    """Parse a SearxNG-style search answer into hits.

    Accepts ``{"results": [...]}`` (SearxNG and most metasearch JSON APIs). Result objects
    may spell the snippet ``snippet``, ``content`` or ``description``; a missing title or
    snippet is tolerated, a missing URL means the entry is skipped.
    """
    if not isinstance(payload, Mapping):
        return ()
    raw = payload.get("results")
    if not isinstance(raw, list):
        return ()
    hits: list[SearchHit] = []
    for entry in raw:
        if not isinstance(entry, Mapping):
            continue
        url = str(entry.get("url") or entry.get("link") or "").strip()
        if not url:
            continue
        hits.append(
            SearchHit(
                url=url,
                title=str(entry.get("title") or ""),
                snippet=str(
                    entry.get("snippet") or entry.get("content") or entry.get("description") or ""
                ),
            )
        )
        if len(hits) >= limit:
            break
    return tuple(hits)


# --------------------------------------------------------------------------- GitHub
def github_code_search_url(query: str, *, per_page: int = 20) -> str:
    """GitHub code-search API URL (requires a token: unauthenticated search is rate-less)."""
    params = urlencode({"q": query, "per_page": min(max(per_page, 1), 100)})
    return f"https://api.github.com/search/code?{params}"


def parse_github_code_search(payload: Any, *, limit: int = 20) -> tuple[dict[str, str], ...]:
    """Parse GitHub's code-search answer into per-match records."""
    if not isinstance(payload, Mapping):
        return ()
    items = payload.get("items")
    if not isinstance(items, list):
        return ()
    matches: list[dict[str, str]] = []
    for entry in items:
        if not isinstance(entry, Mapping):
            continue
        repository = entry.get("repository")
        repo_name = ""
        if isinstance(repository, Mapping):
            repo_name = str(repository.get("full_name") or "")
        matches.append(
            {
                "html_url": str(entry.get("html_url") or ""),
                "path": str(entry.get("path") or ""),
                "repository": repo_name,
                "name": str(entry.get("name") or ""),
            }
        )
        if len(matches) >= limit:
            break
    return tuple(matches)


# --------------------------------------------------------------------------- helpers
def _str_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, Iterable):
        return [str(item) for item in value]
    return []


def _int_list(value: Any) -> list[int]:
    out: list[int] = []
    for item in _str_list(value):
        try:
            out.append(int(item))
        except ValueError:
            continue
    return out


def _opt_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def urls_from_rows(
    rows: Sequence[Mapping[str, str]], *, keys: Sequence[str] = ("original", "url")
) -> tuple[str, ...]:
    """Pull distinct URLs out of CDX/Common Crawl rows."""
    seen: dict[str, None] = {}
    for row in rows:
        for key in keys:
            value = row.get(key)
            if value:
                seen.setdefault(value.strip(), None)
                break
    return tuple(seen)


# --------------------------------------------------------------------------- Shodan (S18)
def shodan_host_url(address: str, *, api_key: str | None = None) -> str:
    """Shodan host lookup for one IP.

    Shodan's REST API takes its key as a **query parameter** — there is no header form. That
    makes the URL a credential carrier, which is why everything that records a provider URL
    (:class:`~arachne.modules.providers.OsintAccess`, the audit trail, the evidence capture)
    redacts ``key=`` before storing it, and why a check uses :func:`shodan_display_url` for its
    own evidence rather than this URL.
    """
    query: dict[str, str] = {}
    if api_key:
        query["key"] = api_key
    suffix = f"?{urlencode(query)}" if query else ""
    return f"https://api.shodan.io/shodan/host/{quote(address, safe='')}{suffix}"


def shodan_display_url(address: str) -> str:
    """The key-free form of :func:`shodan_host_url`, safe for evidence and prose."""
    return f"https://api.shodan.io/shodan/host/{quote(address, safe='')}"


@dataclass(frozen=True, slots=True)
class ShodanHost:
    """One Shodan host record: what the internet thinks is listening on an address."""

    address: str
    ports: tuple[int, ...] = ()
    hostnames: tuple[str, ...] = ()
    domains: tuple[str, ...] = ()
    org: str | None = None
    isp: str | None = None
    os: str | None = None
    country_code: str | None = None
    last_update: str | None = None
    tags: tuple[str, ...] = ()
    cpes: tuple[str, ...] = ()
    vulns: tuple[str, ...] = ()
    found: bool = True

    @property
    def is_empty(self) -> bool:
        return not (self.ports or self.hostnames or self.cpes or self.vulns)

    def to_dict(self) -> dict[str, Any]:
        return {
            "address": self.address,
            "ports": list(self.ports),
            "hostnames": list(self.hostnames),
            "domains": list(self.domains),
            "org": self.org,
            "isp": self.isp,
            "os": self.os,
            "country_code": self.country_code,
            "last_update": self.last_update,
            "tags": list(self.tags),
            "cpes": list(self.cpes),
            "vulns": list(self.vulns),
            "found": self.found,
        }


def parse_shodan_host(payload: Any, *, address: str) -> ShodanHost:
    """Parse a Shodan host answer; its 404 (``{"error": "No information available"}``) is a
    result ("nothing is known about this address"), not an error."""
    if not isinstance(payload, Mapping):
        return ShodanHost(address=address, found=False)
    if payload.get("error") and not payload.get("ports"):
        return ShodanHost(address=address, found=False)
    return ShodanHost(
        address=str(payload.get("ip_str") or address),
        ports=tuple(_int_list(payload.get("ports"))),
        hostnames=tuple(_str_list(payload.get("hostnames"))),
        domains=tuple(_str_list(payload.get("domains"))),
        org=_opt_str(payload.get("org")),
        isp=_opt_str(payload.get("isp")),
        os=_opt_str(payload.get("os")),
        country_code=_opt_str(payload.get("country_code")),
        last_update=_opt_str(payload.get("last_update")),
        tags=tuple(_str_list(payload.get("tags"))),
        cpes=tuple(_str_list(payload.get("cpes"))),
        vulns=tuple(_str_list(payload.get("vulns"))),
    )


# --------------------------------------------------------------------------- Censys (S18)
def censys_host_url(address: str) -> str:
    """Censys Platform API v2 host lookup (basic auth carries the identifier/secret)."""
    return f"https://search.censys.io/api/v2/hosts/{quote(address, safe='')}"


@dataclass(frozen=True, slots=True)
class CensysService:
    """One service Censys observed on an address."""

    port: int
    service_name: str = ""
    transport: str = ""
    products: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "port": self.port,
            "service_name": self.service_name,
            "transport": self.transport,
            "products": list(self.products),
        }


@dataclass(frozen=True, slots=True)
class CensysHost:
    """A Censys host record (services only — enough for drift, no banner bodies)."""

    address: str
    services: tuple[CensysService, ...] = ()
    labels: tuple[str, ...] = ()
    last_updated: str | None = None
    found: bool = True

    @property
    def ports(self) -> tuple[int, ...]:
        return tuple(service.port for service in self.services)


def parse_censys_host(payload: Any, *, address: str) -> CensysHost:
    """Parse a Censys v2 host answer; an error body means "not indexed", which is a result."""
    if not isinstance(payload, Mapping):
        return CensysHost(address=address, found=False)
    if payload.get("error") or payload.get("code") not in (None, 200):
        return CensysHost(address=address, found=False)
    result = payload.get("result")
    if not isinstance(result, Mapping):
        return CensysHost(address=address, found=False)
    services: list[CensysService] = []
    for item in result.get("services") or ():
        if not isinstance(item, Mapping):
            continue
        port = _int_list([item.get("port")])
        if not port:
            continue
        products: list[str] = []
        for software in item.get("software") or ():
            if isinstance(software, Mapping):
                product = str(software.get("product") or "").strip()
                version = str(software.get("version") or "").strip()
                if product:
                    products.append(f"{product} {version}".strip())
        services.append(
            CensysService(
                port=port[0],
                service_name=str(item.get("service_name") or ""),
                transport=str(item.get("transport_protocol") or ""),
                products=tuple(products),
            )
        )
    return CensysHost(
        address=str(result.get("ip") or address),
        services=tuple(services),
        labels=tuple(_str_list(result.get("labels"))),
        last_updated=_opt_str(result.get("last_updated_at")),
    )


# --------------------------------------------------------------------------- Cert Spotter
def certspotter_url(
    domain: str, *, include_subdomains: bool = True, expand: str = "dns_names"
) -> str:
    """Cert Spotter issuances for ``domain`` (a second, independent CT view beside crt.sh)."""
    params = urlencode(
        {
            "domain": normalize_host(domain),
            "include_subdomains": "true" if include_subdomains else "false",
            "expand": expand,
        }
    )
    return f"https://api.certspotter.com/v1/issuances?{params}"


@dataclass(frozen=True, slots=True)
class CtIssuance:
    """One certificate issuance as a CT log aggregator reports it."""

    id: str
    dns_names: tuple[str, ...] = ()
    issuer: str | None = None
    not_before: str | None = None
    not_after: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "dns_names": list(self.dns_names),
            "issuer": self.issuer,
            "not_before": self.not_before,
            "not_after": self.not_after,
        }


def parse_certspotter(payload: Any, *, domain: str | None = None) -> tuple[CtIssuance, ...]:
    """Parse Cert Spotter's issuance list (``not_before``/``not_after`` are RFC 3339)."""
    if not isinstance(payload, list):
        return ()
    base = normalize_host(domain) if domain else ""
    issuances: list[CtIssuance] = []
    for entry in payload:
        if not isinstance(entry, Mapping):
            continue
        certificate = entry.get("tbs_certificate")
        names = entry.get("dns_names")
        if not isinstance(names, list) and isinstance(certificate, Mapping):
            names = certificate.get("dns_names")
        dns_names = tuple(
            sorted(
                {
                    normalize_host(str(name).strip().lstrip("*."))
                    for name in (names or ())
                    if str(name).strip()
                    and (
                        not base
                        or normalize_host(str(name).strip().lstrip("*.")) == base
                        or normalize_host(str(name).strip().lstrip("*.")).endswith(f".{base}")
                    )
                }
            )
        )
        if base and not dns_names:
            # An issuance that names only unrelated hosts is not this domain's business.
            continue
        issuer = None
        if isinstance(certificate, Mapping):
            issuer_block = certificate.get("issuer")
            if isinstance(issuer_block, Mapping):
                issuer = _opt_str(issuer_block.get("friendly_name")) or _opt_str(
                    issuer_block.get("common_name")
                )
        not_before = _opt_str(entry.get("not_before"))
        not_after = _opt_str(entry.get("not_after"))
        if isinstance(certificate, Mapping):
            not_before = not_before or _opt_str(certificate.get("not_before"))
            not_after = not_after or _opt_str(certificate.get("not_after"))
        issuances.append(
            CtIssuance(
                id=str(entry.get("id") or ""),
                dns_names=dns_names,
                issuer=issuer,
                not_before=not_before,
                not_after=not_after,
            )
        )
    return tuple(issuances)


# --------------------------------------------------------------------------- HIBP
def hibp_breaches_url(domain: str) -> str:
    """The breaches HIBP has recorded for ``domain`` (a key is required for this endpoint)."""
    params = urlencode({"domain": normalize_host(domain)})
    return f"https://haveibeenpwned.com/api/v3/breaches?{params}"


@dataclass(frozen=True, slots=True)
class Breach:
    """One breach HIBP knows about, reduced to what a summary needs."""

    name: str
    title: str = ""
    domain: str | None = None
    breach_date: str | None = None
    added_date: str | None = None
    pwn_count: int = 0
    data_classes: tuple[str, ...] = ()
    is_verified: bool = False
    is_sensitive: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "title": self.title,
            "domain": self.domain,
            "breach_date": self.breach_date,
            "added_date": self.added_date,
            "pwn_count": self.pwn_count,
            "data_classes": list(self.data_classes),
            "is_verified": self.is_verified,
            "is_sensitive": self.is_sensitive,
        }


def parse_hibp_breaches(payload: Any) -> tuple[Breach, ...]:
    """Parse HIBP's breach list. A 404 (no breaches for the domain) is an empty tuple."""
    if not isinstance(payload, list):
        return ()
    breaches: list[Breach] = []
    for entry in payload:
        if not isinstance(entry, Mapping):
            continue
        name = _opt_str(entry.get("Name")) or _opt_str(entry.get("name"))
        if not name:
            continue
        pwn = entry.get("PwnCount", entry.get("pwn_count"))
        breaches.append(
            Breach(
                name=name,
                title=_opt_str(entry.get("Title")) or _opt_str(entry.get("title")) or "",
                domain=_opt_str(entry.get("Domain")) or _opt_str(entry.get("domain")),
                breach_date=_opt_str(entry.get("BreachDate")),
                added_date=_opt_str(entry.get("AddedDate")),
                pwn_count=int(pwn) if isinstance(pwn, int) else 0,
                data_classes=tuple(_str_list(entry.get("DataClasses"))),
                is_verified=bool(entry.get("IsVerified")),
                is_sensitive=bool(entry.get("IsSensitive")),
            )
        )
    return tuple(breaches)


# --------------------------------------------------------------------------- WHOIS / RDAP
def rdap_url_for(base_url: str, name: str) -> str:
    """Build an RDAP domain URL from the deployment's template.

    ``{query}`` is substituted with the registrable name. Without a placeholder the name is
    appended as the last path segment, which is the shape every RDAP server uses
    (``/domain/example.com``).
    """
    base = base_url.strip()
    query = quote(normalize_host(name), safe="")
    if "{query}" in base:
        return base.replace("{query}", query)
    return f"{base.rstrip('/')}/{query}"


@dataclass(frozen=True, slots=True)
class RdapDomain:
    """Registration facts for one domain (RDAP's answer to ``whois example.com``)."""

    handle: str = ""
    ldh_name: str = ""
    statuses: tuple[str, ...] = ()
    registrar: str | None = None
    created: str | None = None
    updated: str | None = None
    expires: str | None = None
    nameservers: tuple[str, ...] = ()
    registrant_org: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "handle": self.handle,
            "ldh_name": self.ldh_name,
            "statuses": list(self.statuses),
            "registrar": self.registrar,
            "created": self.created,
            "updated": self.updated,
            "expires": self.expires,
            "nameservers": list(self.nameservers),
            "registrant_org": self.registrant_org,
        }


def parse_rdap(payload: Any) -> RdapDomain:
    """Parse an RDAP domain object.

    Only the fields a posture summary needs are read: status codes, the registration/expiry
    events, the nameservers, and the registrar/registrant names extracted from the ``vCard``
    entity blocks (RDAP's entity model is general; ``fn`` is the readable name).
    """
    if not isinstance(payload, Mapping):
        return RdapDomain()
    events: dict[str, str] = {}
    for event in payload.get("events") or ():
        if isinstance(event, Mapping):
            action = _opt_str(event.get("eventAction"))
            date = _opt_str(event.get("eventDate"))
            if action and date:
                events[action.lower()] = date
    nameservers: list[str] = []
    for server in payload.get("nameservers") or ():
        if isinstance(server, Mapping):
            name = _opt_str(server.get("ldhName"))
            if name:
                nameservers.append(normalize_host(name))
    registrar: str | None = None
    registrant_org: str | None = None
    for entity in payload.get("entities") or ():
        if not isinstance(entity, Mapping):
            continue
        roles = {str(role).lower() for role in entity.get("roles") or ()}
        name = _vcard_name(entity.get("vcardArray"))
        if "registrar" in roles and registrar is None:
            registrar = name
        elif roles & {"registrant", "administrative"} and registrant_org is None:
            registrant_org = name
    return RdapDomain(
        handle=_opt_str(payload.get("handle")) or "",
        ldh_name=_opt_str(payload.get("ldhName")) or "",
        statuses=tuple(_str_list(payload.get("status"))),
        registrar=registrar,
        created=events.get("registration"),
        updated=events.get("last changed") or events.get("last update of rdap database"),
        expires=events.get("expiration"),
        nameservers=tuple(sorted(set(nameservers))),
        registrant_org=registrant_org,
    )


def _vcard_name(vcard: Any) -> str | None:
    """The ``fn`` (formatted name) of a jCard ``vcardArray``."""
    if not isinstance(vcard, list) or len(vcard) < 2 or not isinstance(vcard[1], list):
        return None
    for field in vcard[1]:
        if isinstance(field, list) and len(field) >= 4 and str(field[0]).lower() == "fn":
            value = _opt_str(field[3])
            if value:
                return value
    return None
