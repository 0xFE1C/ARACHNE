"""WP-34 · reconnaissance breadth (REQ-DET-027).

Eight read-only recon checks that widen the *enumerating* half of M1 rather than the exposure
half. Four read a third party's answer about the target's names (DNS and RDAP), two read the
certificate-transparency log, and two read the crawl the checks step already built:

``m1.nameserver-inventory``         ch01#6    the domain's delegation set (DoH NS)
``m1.mail-infrastructure-inventory`` ch01#6   the domain's mail exchangers (DoH MX)
``m1.certificate-inventory``        ch01#24   the distinct certificates and their issuers (crt.sh)
``m1.certificate-expiry``           ch01#24   certificates that are expired or expiring soon
``m1.asn-network-attribution``      ch01#27   the network an address is allocated from (RDAP)
``m1.reverse-ip-cluster``           ch01#12   hostnames co-located on one address (InternetDB)
``m1.technology-inventory``         ch02#10   the stack the application publishes (from the crawl)
``m1.vhost-discovery``              ch02#12   alternate names the same address serves (a Host probe)

**A fingerprint is a signal, not a finding.** The pitfall is explicit: a technology guess is not
a finding until it is corroborated. This family therefore splits its output the way M1 already
does — an *inventory* (a delegation set, a mail-exchanger list, a certificate set, an
attributed network, a technology list, a virtual-host list) is emitted as an ``info`` result,
because "this name resolves" and "this header says nginx" establish nothing by themselves.
Only two checks raise a candidate, and each rests on a fact the target's own data states:
:class:`CertificateExpiry` reports a certificate whose own ``not_after`` has passed (or is
about to), and :class:`VhostDiscovery` reports an alternate name whose *response body differs*
from the origin's — a corroborated alternate application, not a guess from a banner.

**Read-only, and no payload anywhere.** Every request is a plain ``GET``: the DNS checks read a
DoH resolver, the certificate checks read crt.sh, the address checks read RDAP and InternetDB,
and the crawl readers issue no request at all (``estimated_requests = 0``). The one check that
sends a header (:class:`VhostDiscovery`) sends the ``Host`` header a browser sends — no body, no
verb beyond ``GET``, nothing written anywhere.
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator, Mapping
from dataclasses import dataclass
from datetime import date
from typing import Any
from urllib.parse import quote, urlsplit

from arachne.core.config import DEFAULT_WHOIS_RDAP_URL
from arachne.core.errors import OsintError
from arachne.core.results import CheckResult, sha256_of
from arachne.core.safety import normalize_host
from arachne.core.target import TargetKind
from arachne.modules.base import Asset, CheckMetadata, Module
from arachne.modules.context import CheckContext, require_osint
from arachne.modules.extract import extract_urls
from arachne.modules.m3.inventory import normalize_body
from arachne.modules.providers.sources import (
    crtsh_url,
    internetdb_url,
    parse_crtsh,
    parse_internetdb,
)

__all__ = [
    "RECON_BREADTH_CHECKS",
    "AsnNetworkAttribution",
    "CertificateExpiry",
    "CertificateInventory",
    "MailInfrastructureInventory",
    "NameserverInventory",
    "ReverseIpCluster",
    "TechnologyInventory",
    "VhostDiscovery",
]

_DOMAIN_KINDS = (TargetKind.DOMAIN, TargetKind.DOMAIN_PATTERN)
_ADDRESS_KINDS = (TargetKind.IP,)
_URL_KINDS = (TargetKind.URL,)

#: DoH record types this family reads, by name (the resolver's ``type`` parameter).
_NS_TYPE: int = 2
_MX_TYPE: int = 15
#: The bound on how many certificate entries a check will consider — crt.sh can return
#: thousands for a large domain, and "the expiry picture" does not need all of them.
_CERT_LIMIT: int = 200
#: The window (days) inside which a certificate counts as "expiring soon".
_EXPIRY_WINDOW_DAYS: int = 30
#: The bound on virtual-host candidates probed for one origin.
_VHOST_CANDIDATE_LIMIT: int = 5


def _doh_url(name: str, record_type: str) -> str:
    """A DNS-over-HTTPS query for one record class (dns.google's JSON form)."""
    return f"https://dns.google/resolve?name={quote(name, safe='')}&type={record_type}"


def _doh_records(payload: Any, record_type: int) -> tuple[str, ...]:
    """The ``data`` values of one record class in a DoH JSON answer, de-duplicated in order."""
    if not isinstance(payload, Mapping):
        return ()
    if payload.get("Status") not in (0, None):
        # NXDOMAIN / SERVFAIL: "no record" is the only safe reading.
        return ()
    answers = payload.get("Answer")
    if not isinstance(answers, (list, tuple)):
        return ()
    values: list[str] = []
    for answer in answers:
        if not isinstance(answer, Mapping):
            continue
        if answer.get("type") not in (record_type, str(record_type)):
            continue
        data = answer.get("data")
        if isinstance(data, str) and data.strip():
            values.append(data.strip().rstrip("."))
    return tuple(dict.fromkeys(values))


def _rdap_ip_url(base: str, address: str) -> str | None:
    """The RDAP address object for ``address``, on the deployment's configured RDAP host.

    The configured base names the *domain* path (``https://rdap.org/domain/{query}``); an
    address object lives under ``/ip/`` on the same server. Building the URL from the configured
    host rather than a literal keeps the provider scope honest: a deployment that pointed
    ``whois`` at its own registry never has this check reach out to the public one.
    """
    parts = urlsplit(base)
    if not parts.scheme or not parts.netloc:
        return None
    return f"{parts.scheme}://{parts.netloc}/ip/{quote(address, safe='')}"


@dataclass(frozen=True, slots=True)
class _NetworkRecord:
    """The allocation facts an RDAP address object states."""

    handle: str = ""
    name: str = ""
    start: str = ""
    end: str = ""
    kind: str = ""
    country: str = ""

    @property
    def attributed(self) -> bool:
        return bool(self.handle or self.name)

    def to_dict(self) -> dict[str, Any]:
        return {
            "handle": self.handle,
            "name": self.name,
            "start_address": self.start,
            "end_address": self.end,
            "type": self.kind,
            "country": self.country,
        }


def _network_record(payload: Any) -> _NetworkRecord:
    if not isinstance(payload, Mapping):
        return _NetworkRecord()
    return _NetworkRecord(
        handle=str(payload.get("handle") or ""),
        name=str(payload.get("name") or ""),
        start=str(payload.get("startAddress") or ""),
        end=str(payload.get("endAddress") or ""),
        kind=str(payload.get("type") or ""),
        country=str(payload.get("country") or ""),
    )


#: The technology markers this family recognises, as ``(technology, marker)`` pairs searched
#: case-insensitively in a page's headers and body. A closed table on purpose: a fingerprint is
#: a *signal*, and a check that guessed from a loose substring would be the pitfall itself.
_TECH_MARKERS: tuple[tuple[str, str], ...] = (
    ("nginx", "server: nginx"),
    ("apache", "server: apache"),
    ("iis", "server: microsoft-iis"),
    ("caddy", "server: caddy"),
    ("php", "x-powered-by: php"),
    ("asp.net", "x-powered-by: asp.net"),
    ("express", "x-powered-by: express"),
    ("wordpress", "wp-content"),
    ("drupal", "drupal"),
    ("joomla", "joomla"),
    ("tomcat", "tomcat"),
    ("spring", "spring"),
    ("react", "react"),
    ("vue.js", "vue.js"),
    ("angular", "ng-version"),
    ("jquery", "jquery"),
    ("bootstrap", "bootstrap"),
)

#: ``nginx/1.18.0``, ``PHP/8.1.2`` — a version a page publishes next to its product name.
_TECH_VERSION_RE = r"(?i)({tech})[/ ]v?(\d+\.\d+(?:\.\d+)?)"


def _page_text(page: Any) -> str:
    """A page's headers and body as one lower-cased blob, bounded."""
    headers = " ".join(f"{name}: {value}" for name, value in page.headers.items())
    return f"{headers}\n{page.body[:65536]}"


def _technology_signals(page: Any) -> tuple[tuple[str, str], ...]:
    """``(technology, disclosed version or "")`` for every marker this page carries."""
    text = _page_text(page)
    lowered = text.lower()
    found: list[tuple[str, str]] = []
    for technology, marker in _TECH_MARKERS:
        if marker not in lowered:
            continue
        version = ""
        match = re.search(_TECH_VERSION_RE.format(tech=re.escape(technology)), text)
        if match:
            version = match.group(2)
        found.append((technology, version))
    return tuple(found)


def _certificates(payload: Any, domain: str) -> tuple[Any, ...]:
    """The certificate entries of a crt.sh answer, restricted to the queried domain."""
    return parse_crtsh(payload, domain=domain).certificates[:_CERT_LIMIT]


# --------------------------------------------------------------------------- DNS enumeration
class NameserverInventory(Module):
    """``m1.nameserver-inventory`` — the domain's delegation set (research ch01#6)."""

    metadata = CheckMetadata(
        id="m1.nameserver-inventory",
        module="M1",
        name="nameserver-inventory",
        version="1.0",
        title="Nameserver delegation inventory",
        description=(
            "Reads the domain's NS records through a DNS-over-HTTPS resolver and reports the "
            "delegation set it publishes. The set names the providers the domain's resolution "
            "depends on — the first fact an enumeration wants and the input to the zone's "
            "shape. It is an inventory, not a finding: a delegation set that resolves proves "
            "nothing on its own. Read-only: one resolver query."
        ),
        research_ref="ch01#6",
        framework=("WSTG-INFO-04", "CWE-200"),
        cwe="CWE-200",
        target_kinds=_DOMAIN_KINDS,
        severity_hint="info",
        type="passive",
        verifiable=True,
        estimated_requests=1,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        name = ctx.asset.query_name
        if not name:
            yield ctx.skipped(f"asset {ctx.asset.key} has no queryable name")
            return
        osint, skip = require_osint(ctx, "dns")
        if skip is not None:
            yield skip
            return
        assert osint is not None
        url = _doh_url(name, "NS")
        try:
            response = await osint.fetch("dns", url)
        except OsintError as exc:
            yield ctx.error(exc)
            return
        servers = _doh_records(response.json(), _NS_TYPE)
        if not servers:
            yield ctx.clean(
                f"no nameserver delegation for {name}",
                detail="the resolver returned no NS record for this name",
                evidence=[ctx.evidence("note", response.evidence_payload(), source=url)],
                confidence=0.6,
            )
            return
        yield ctx.info(
            f"nameserver delegation for {name}: {len(servers)} server(s)",
            detail=", ".join(servers[:8]),
            confidence=0.9,
            evidence=[
                ctx.evidence(
                    "artifact",
                    {
                        "signal": "nameserver-inventory",
                        "domain": name,
                        "nameservers": list(servers[:32]),
                        **response.evidence_payload(),
                    },
                    source=url,
                )
            ],
        )


class MailInfrastructureInventory(Module):
    """``m1.mail-infrastructure-inventory`` — the domain's mail exchangers (research ch01#6)."""

    metadata = CheckMetadata(
        id="m1.mail-infrastructure-inventory",
        module="M1",
        name="mail-infrastructure-inventory",
        version="1.0",
        title="Mail-exchanger inventory",
        description=(
            "Reads the domain's MX records through a DNS-over-HTTPS resolver and reports the "
            "mail exchangers it publishes, in the resolver's preference order. The set names "
            "the mail estate (and, through it, the provider the organisation uses) — a "
            "different record class from the delegation set, and an inventory rather than a "
            "finding. Read-only: one resolver query."
        ),
        research_ref="ch01#6",
        framework=("WSTG-INFO-10", "CWE-200"),
        cwe="CWE-200",
        target_kinds=_DOMAIN_KINDS,
        severity_hint="info",
        type="passive",
        verifiable=True,
        estimated_requests=1,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        name = ctx.asset.query_name
        if not name:
            yield ctx.skipped(f"asset {ctx.asset.key} has no queryable name")
            return
        osint, skip = require_osint(ctx, "dns")
        if skip is not None:
            yield skip
            return
        assert osint is not None
        url = _doh_url(name, "MX")
        try:
            response = await osint.fetch("dns", url)
        except OsintError as exc:
            yield ctx.error(exc)
            return
        exchanges = _doh_records(response.json(), _MX_TYPE)
        if not exchanges:
            yield ctx.clean(
                f"no mail exchangers published for {name}",
                detail="the resolver returned no MX record for this name",
                evidence=[ctx.evidence("note", response.evidence_payload(), source=url)],
                confidence=0.6,
            )
            return
        yield ctx.info(
            f"mail exchangers for {name}: {len(exchanges)} record(s)",
            detail=", ".join(exchanges[:8]),
            confidence=0.9,
            evidence=[
                ctx.evidence(
                    "artifact",
                    {
                        "signal": "mail-infrastructure-inventory",
                        "domain": name,
                        "mail_exchangers": list(exchanges[:32]),
                        **response.evidence_payload(),
                    },
                    source=url,
                )
            ],
        )


# --------------------------------------------------------------------------- CT enumeration
class CertificateInventory(Module):
    """``m1.certificate-inventory`` — the distinct certificates and their issuers (ch01#24)."""

    metadata = CheckMetadata(
        id="m1.certificate-inventory",
        module="M1",
        name="certificate-inventory",
        version="1.0",
        title="Certificate-issuance inventory",
        description=(
            "Reads the certificate-transparency log for the declared domain and reports the "
            "distinct certificates that name it: their issuers, their validity windows and "
            "their count. It is the certificate *fingerprinting* view — which authorities "
            "issue for this name, and over what period — and it is an inventory, not a "
            "finding. A different claim from ``m1.ct-lookup``, which records the *hostnames* "
            "the same log exposes. Read-only: one log query."
        ),
        research_ref="ch01#24",
        framework=("WSTG-INFO-04", "CWE-200"),
        cwe="CWE-200",
        target_kinds=_DOMAIN_KINDS,
        severity_hint="info",
        type="passive",
        verifiable=True,
        estimated_requests=1,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        name = ctx.asset.query_name
        if not name:
            yield ctx.skipped(f"asset {ctx.asset.key} has no queryable name")
            return
        osint, skip = require_osint(ctx, "crtsh")
        if skip is not None:
            yield skip
            return
        assert osint is not None
        url = crtsh_url(name)
        try:
            response = await osint.fetch("crtsh", url)
        except OsintError as exc:
            yield ctx.error(exc)
            return
        parsed = parse_crtsh(response.json(), domain=name)
        certificates = parsed.certificates[:_CERT_LIMIT]
        if not certificates:
            yield ctx.clean(
                f"no certificates logged for {name}",
                detail="the transparency log returned no certificate naming this domain",
                evidence=[ctx.evidence("note", response.evidence_payload(), source=url)],
                confidence=0.6,
            )
            return
        windows = sorted(
            certificate.not_after for certificate in certificates if certificate.not_after
        )
        yield ctx.info(
            f"{len(certificates)} certificate(s) logged for {name} from "
            f"{len(parsed.issuers)} issuer(s)",
            detail=(
                f"issuers: {', '.join(parsed.issuers[:5]) or 'unspecified'}; "
                f"latest expiry {windows[-1] if windows else 'unknown'}"
            ),
            confidence=0.9,
            evidence=[
                ctx.evidence(
                    "artifact",
                    {
                        "signal": "certificate-inventory",
                        "domain": name,
                        "certificate_count": len(certificates),
                        "issuers": list(parsed.issuers[:16]),
                        "latest_expiry": windows[-1] if windows else None,
                        **response.evidence_payload(),
                    },
                    source=url,
                )
            ],
        )


class CertificateExpiry(Module):
    """``m1.certificate-expiry`` — expired or soon-expiring certificates (research ch01#24)."""

    metadata = CheckMetadata(
        id="m1.certificate-expiry",
        module="M1",
        name="certificate-expiry",
        version="1.0",
        title="Certificate expiry review",
        description=(
            "Reads the certificate-transparency log for the declared domain and reports the "
            "certificates whose own ``not_after`` has passed or falls inside the next 30 days. "
            "Unlike the inventory beside it this raises a candidate, because the finding rests "
            "on a date the certificate itself states rather than on a fingerprint: an expired "
            "certificate is still being served somewhere, and an expiring one is an operational "
            "cliff. Read-only: one log query; the certificate is not fetched or re-validated."
        ),
        research_ref="ch01#24",
        framework=("WSTG-INFO-04", "CWE-295"),
        cwe="CWE-295",
        target_kinds=_DOMAIN_KINDS,
        severity_hint="low",
        type="passive",
        verifiable=True,
        estimated_requests=1,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        name = ctx.asset.query_name
        if not name:
            yield ctx.skipped(f"asset {ctx.asset.key} has no queryable name")
            return
        osint, skip = require_osint(ctx, "crtsh")
        if skip is not None:
            yield skip
            return
        assert osint is not None
        url = crtsh_url(name)
        try:
            response = await osint.fetch("crtsh", url)
        except OsintError as exc:
            yield ctx.error(exc)
            return
        certificates = _certificates(response.json(), name)
        if not certificates:
            yield ctx.clean(
                f"no certificate expiry data for {name}",
                detail="the transparency log returned no certificate naming this domain",
                evidence=[ctx.evidence("note", response.evidence_payload(), source=url)],
                confidence=0.6,
            )
            return
        today = ctx.now().date()
        expired: list[Any] = []
        expiring: list[Any] = []
        for certificate in certificates:
            expiry = _parse_date(certificate.not_after)
            if expiry is None:
                continue
            if expiry < today:
                expired.append(certificate)
            elif (expiry - today).days <= _EXPIRY_WINDOW_DAYS:
                expiring.append(certificate)
        if not expired and not expiring:
            yield ctx.clean(
                f"no expired or expiring certificate for {name}",
                detail=(
                    f"{len(certificates)} certificate(s) reviewed; every logged expiry is more "
                    f"than {_EXPIRY_WINDOW_DAYS} days away"
                ),
                evidence=[ctx.evidence("note", response.evidence_payload(), source=url)],
                confidence=0.7,
            )
            return
        if expired:
            yield ctx.candidate(
                f"{len(expired)} expired certificate(s) logged for {name}",
                detail=(
                    "the transparency log holds certificates naming this domain whose own "
                    f"not_after date has passed (earliest {expired[0].not_after}); begin at "
                    f"{expired[0].issuer or 'an unspecified issuer'}"
                ),
                confidence=0.7,
                evidence=[
                    ctx.evidence(
                        "artifact",
                        {
                            "signal": "certificate-expiry",
                            "state": "expired",
                            "domain": name,
                            "count": len(expired),
                            "not_after": [certificate.not_after for certificate in expired[:16]],
                            **response.evidence_payload(),
                        },
                        source=url,
                    )
                ],
            )
        if expiring:
            yield ctx.candidate(
                f"{len(expiring)} certificate(s) expiring within {_EXPIRY_WINDOW_DAYS} days for "
                f"{name}",
                detail=(
                    "renewal is due inside the review window; the earliest expiry is "
                    f"{min(certificate.not_after or '' for certificate in expiring)}"
                ),
                confidence=0.6,
                evidence=[
                    ctx.evidence(
                        "artifact",
                        {
                            "signal": "certificate-expiry",
                            "state": "expiring",
                            "domain": name,
                            "count": len(expiring),
                            "not_after": [certificate.not_after for certificate in expiring[:16]],
                            **response.evidence_payload(),
                        },
                        source=url,
                    )
                ],
            )


def _parse_date(value: str | None) -> date | None:
    """The date part of a crt.sh timestamp, or ``None`` when it is not a date."""
    if not value:
        return None
    try:
        return date.fromisoformat(value[:10])
    except ValueError:
        return None


# --------------------------------------------------------------------------- address enumeration
class AsnNetworkAttribution(Module):
    """``m1.asn-network-attribution`` — the network an address is allocated from (ch01#27)."""

    metadata = CheckMetadata(
        id="m1.asn-network-attribution",
        module="M1",
        name="asn-network-attribution",
        version="1.0",
        title="Network (ASN) attribution of an address",
        description=(
            "Reads the registration-data (RDAP) address object for the declared address and "
            "reports the network it is allocated from: the registry handle and name, the "
            "address range and the country. The range is what an ASN-level enumeration works "
            "from — the owning network's own statement, not a guess from a reverse lookup. It "
            "is an inventory, so it emits an info result. Read-only: one registry query through "
            "the opt-in ``whois`` provider."
        ),
        research_ref="ch01#27",
        framework=("WSTG-INFO-01", "CWE-200"),
        cwe="CWE-200",
        target_kinds=_ADDRESS_KINDS,
        severity_hint="info",
        type="passive",
        verifiable=True,
        estimated_requests=1,
    )

    def supports(self, asset: Asset) -> bool:
        """Only an address literal can be attributed to a network."""
        return Module.supports(self, asset) and _is_ip_literal(asset.value)

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        address = _address_of(ctx)
        if address is None:
            yield ctx.skipped(f"asset {ctx.asset.key} names no address to attribute")
            return
        osint, skip = require_osint(ctx, "whois")
        if skip is not None:
            yield skip
            return
        assert osint is not None
        base = ctx.config.whois_url or DEFAULT_WHOIS_RDAP_URL
        url = _rdap_ip_url(base, address)
        if url is None:
            yield ctx.clean(
                f"the configured RDAP base names no host for {address}",
                detail="set ARACHNE_OSINT_WHOIS_URL to an RDAP server to attribute addresses",
            )
            return
        try:
            response = await osint.fetch("whois", url)
        except OsintError as exc:
            yield ctx.error(exc)
            return
        record = _network_record(response.json())
        if not record.attributed:
            yield ctx.clean(
                f"no network registration for {address}",
                detail="the registry returned no network object for this address",
                evidence=[ctx.evidence("note", response.evidence_payload(), source=url)],
                confidence=0.6,
            )
            return
        yield ctx.info(
            f"{address} is allocated from {record.name or record.handle}",
            detail=(
                f"range {record.start or '?'}-{record.end or '?'}"
                + (f"; {record.country}" if record.country else "")
            ),
            confidence=0.85,
            evidence=[
                ctx.evidence(
                    "artifact",
                    {
                        "signal": "asn-network-attribution",
                        "address": address,
                        **record.to_dict(),
                        **response.evidence_payload(),
                    },
                    source=url,
                )
            ],
        )


class ReverseIpCluster(Module):
    """``m1.reverse-ip-cluster`` — hostnames co-located on one address (research ch01#12)."""

    metadata = CheckMetadata(
        id="m1.reverse-ip-cluster",
        module="M1",
        name="reverse-ip-cluster",
        version="1.0",
        title="Reverse-IP host clustering",
        description=(
            "Reads the third-party index entry for the declared address and reports the "
            "hostnames it records as resolving there, recording each as a scoped asset. The "
            "co-tenancy view is how an enumeration finds the siblings of a name — the input to "
            "reverse-IP clustering — and it is an inventory, not a finding. A different claim "
            "from ``m1.internetdb-triage``, which reports the *services and CVEs* of one "
            "address; this reports the names beside it. Read-only: one index query."
        ),
        research_ref="ch01#12",
        framework=("WSTG-INFO-04", "CWE-200"),
        cwe="CWE-200",
        target_kinds=_ADDRESS_KINDS,
        severity_hint="info",
        type="passive",
        verifiable=True,
        estimated_requests=1,
    )

    def supports(self, asset: Asset) -> bool:
        """Only an address literal can be clustered with its co-tenants."""
        return Module.supports(self, asset) and _is_ip_literal(asset.value)

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        address = _address_of(ctx)
        if address is None:
            yield ctx.skipped(f"asset {ctx.asset.key} names no address to cluster")
            return
        osint, skip = require_osint(ctx, "internetdb")
        if skip is not None:
            yield skip
            return
        assert osint is not None
        url = internetdb_url(address)
        try:
            response = await osint.fetch("internetdb", url)
        except OsintError as exc:
            yield ctx.error(exc)
            return
        record = parse_internetdb(response.json(), address=address)
        # The address's own name is not a co-tenant: only *other* names are the cluster.
        hosts = tuple(
            host
            for host in record.hostnames
            if normalize_host(host) and normalize_host(host) != normalize_host(address)
        )
        if not hosts:
            yield ctx.clean(
                f"no co-located hostnames recorded for {address}",
                detail="the index records no other name resolving to this address",
                evidence=[ctx.evidence("note", response.evidence_payload(), source=url)],
                confidence=0.6,
            )
            return
        recorded = 0
        for host in hosts[: ctx.config.max_assets]:
            if await ctx.record_host(host, source="reverse-ip-cluster"):
                recorded += 1
        yield ctx.info(
            f"{len(hosts)} hostname(s) co-located on {address}",
            detail=f"{recorded} new host asset(s) recorded; first: {', '.join(hosts[:5])}",
            confidence=0.8,
            evidence=[
                ctx.evidence(
                    "artifact",
                    {
                        "signal": "reverse-ip-cluster",
                        "address": address,
                        "hostnames": list(hosts[:64]),
                        "recorded": recorded,
                        **response.evidence_payload(),
                    },
                    source=url,
                )
            ],
        )


def _is_ip_literal(value: str) -> bool:
    """True when ``value`` is an IPv4/IPv6 literal (the only thing RDAP can attribute)."""
    import ipaddress

    try:
        ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    return True


def _address_of(ctx: CheckContext) -> str | None:
    """The IP literal this asset names, or ``None`` when it names no address."""
    value = ctx.asset.value.strip()
    if _is_ip_literal(value):
        return value
    parts = urlsplit(value if "://" in value else f"//{value}")
    candidate = parts.hostname or value
    return candidate if _is_ip_literal(candidate) else None


# --------------------------------------------------------------------------- crawl readers
class TechnologyInventory(Module):
    """``m1.technology-inventory`` — the stack the application publishes (research ch02#10)."""

    metadata = CheckMetadata(
        id="m1.technology-inventory",
        module="M1",
        name="technology-inventory",
        version="1.0",
        title="Published-technology inventory",
        description=(
            "Reads the crawl the checks step already built and reports the technologies the "
            "application itself publishes — its server header, its powered-by header, its "
            "generator meta and its framework markers — with the version each one discloses. "
            "It is fingerprint breadth as an inventory: a technology name is a signal that "
            "steers the next step, and only a version the application states about itself is "
            "reported, never a guess from a loose substring. Reads the crawl only; it issues no "
            "request of its own (estimated_requests = 0). Distinct from ``m2.http-fingerprint``, "
            "which reads a socket banner."
        ),
        research_ref="ch02#10",
        framework=("WSTG-INFO-02", "CWE-200"),
        cwe="CWE-200",
        target_kinds=_URL_KINDS,
        severity_hint="info",
        type="passive",
        verifiable=True,
        estimated_requests=0,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        inventory = ctx.web
        if inventory is None:
            yield ctx.skipped(
                "no web inventory for this step: the checks step crawls the endpoints (S6/M3)"
            )
            return
        found: dict[str, str] = {}
        sources: dict[str, str] = {}
        for url in inventory.order:
            page = inventory.pages[url]
            for technology, version in _technology_signals(page):
                found.setdefault(technology, version)
                sources.setdefault(technology, page.url)
        if not found:
            yield ctx.clean(
                "the application publishes no technology fingerprint",
                detail=f"{inventory.visited} crawled page(s) carry no recognised marker",
                confidence=0.5,
            )
            return
        disclosed = {name: version for name, version in found.items() if version}
        yield ctx.info(
            f"{len(found)} published technology signal(s); {len(disclosed)} with a version",
            detail=", ".join(
                f"{name} {version}".strip() for name, version in sorted(found.items())[:8]
            ),
            confidence=0.7,
            evidence=[
                ctx.evidence(
                    "artifact",
                    {
                        "signal": "technology-inventory",
                        "technologies": dict(sorted(found.items())),
                        "versions_disclosed": dict(sorted(disclosed.items())),
                        "sources": dict(sorted(sources.items())),
                        "requests_issued": 0,
                    },
                    source=ctx.asset.value,
                )
            ],
        )


class VhostDiscovery(Module):
    """``m1.vhost-discovery`` — alternate names the same address serves (research ch02#12)."""

    metadata = CheckMetadata(
        id="m1.vhost-discovery",
        module="M1",
        name="vhost-discovery",
        version="1.0",
        title="Virtual-host discovery",
        description=(
            "Takes the other hostnames the crawl's pages name, asks the declared origin for "
            "each one with that name in the Host header, and reports the names whose answer is "
            "a *different, successful* application than the origin's own — a corroborated "
            "virtual host, not a banner guess. Only the Host header a browser would send is "
            "added to a plain GET: no body, no other verb, nothing written. The candidate set "
            "is bounded and comes from the target's own content."
        ),
        research_ref="ch02#12",
        framework=("WSTG-INFO-04", "CWE-200"),
        cwe="CWE-200",
        target_kinds=_URL_KINDS,
        severity_hint="info",
        type="hybrid",
        verifiable=True,
        estimated_requests=1 + _VHOST_CANDIDATE_LIMIT,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        inventory = ctx.web
        if inventory is None:
            yield ctx.skipped(
                "no web inventory for this step: the checks step crawls the endpoints (S6/M3)"
            )
            return
        if ctx.http is None:
            yield ctx.skipped(
                "no HTTP client in this run: the virtual-host probe needs a live scan "
                "(a dry run sends nothing — F-01-10)"
            )
            return
        origin = ctx.asset.value
        parts = urlsplit(origin)
        origin_host = normalize_host(parts.hostname or "")
        if not origin_host:
            yield ctx.clean("the declared asset names no origin to probe")
            return
        baseline_fingerprint = _origin_fingerprint(inventory, origin_host)
        candidates = _vhost_candidates(inventory, origin_host)
        if not candidates:
            yield ctx.clean(
                "no alternate hostname to test against this origin",
                detail="the crawl names no other host that could be a virtual host",
            )
            return
        findings = 0
        for candidate in candidates:
            try:
                exchange = await ctx.http.get(origin, headers={"Host": candidate})
            except Exception:  # noqa: S112 - a refused probe is data, not a crash
                continue
            if not exchange.ok:
                continue
            if sha256_of(normalize_body(exchange.body)) == baseline_fingerprint:
                continue
            findings += 1
            yield ctx.candidate(
                f"Virtual host served at this address: {candidate}",
                detail=(
                    f"a GET of {origin} with Host: {candidate} returned HTTP "
                    f"{exchange.status_code} with a body that differs from the origin's own "
                    "answer, so the address serves a second application for that name"
                ),
                confidence=0.7,
                evidence=[
                    ctx.evidence(
                        "artifact",
                        {
                            "signal": "vhost-discovery",
                            "origin": origin,
                            "virtual_host": candidate,
                            "status": exchange.status_code,
                            "body_split": 2,
                        },
                        source=origin,
                    )
                ],
            )
        if not findings:
            yield ctx.clean(
                f"no virtual host among {len(candidates)} candidate name(s)",
                detail=(
                    "every candidate answered the origin's own application (or refused), so "
                    "the address serves no alternate name"
                ),
            )


def _origin_fingerprint(inventory: Any, origin_host: str) -> str | None:
    """The body fingerprint of the crawled page that is the origin's own answer.

    A page's ``host`` carries the port (``127.0.0.1:8000``) while ``origin_host`` is the bare
    name, so the comparison is on the *hostname* of each page's URL.
    """
    for url in inventory.order:
        page = inventory.pages[url]
        hostname = normalize_host(urlsplit(page.url).hostname or "")
        if hostname == origin_host and urlsplit(page.url).path in {"", "/"}:
            return str(page.body_fingerprint)
    for url in inventory.order:
        page = inventory.pages[url]
        if normalize_host(urlsplit(page.url).hostname or "") == origin_host:
            return str(page.body_fingerprint)
    return None


def _vhost_candidates(inventory: Any, origin_host: str) -> tuple[str, ...]:
    """Other hostnames the crawl's pages name, in first-seen order, bounded."""
    seen: dict[str, None] = {}
    for url in inventory.order:
        page = inventory.pages[url]
        for candidate in extract_urls(page.body, limit=200):
            host = normalize_host(urlsplit(candidate).hostname or "")
            if not host or host == origin_host:
                continue
            seen.setdefault(host, None)
            if len(seen) >= _VHOST_CANDIDATE_LIMIT:
                return tuple(seen)
    return tuple(seen)


#: Every check the WP-34 reconnaissance family registers, in the order they appear above.
RECON_BREADTH_CHECKS: tuple[type[Module], ...] = (
    NameserverInventory,
    MailInfrastructureInventory,
    CertificateInventory,
    CertificateExpiry,
    AsnNetworkAttribution,
    ReverseIpCluster,
    TechnologyInventory,
    VhostDiscovery,
)
