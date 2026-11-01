"""M1 inventory checks: expand the asset inventory from third-party indexes (ch01).

These four checks answer "what exists under this name?" from sources that never touch the
target: certificate transparency logs (research ch01 method 8), passive DNS (11), the
passive-aggregator pattern (13) and web archives (14-16). They emit **info** results (an
asset discovered is not a finding) and route every discovered host or URL through
:meth:`~arachne.modules.context.CheckContext.record_asset`, so the scope guard of F-01-02
decides what may be kept — a CNAME pointing at a cloud provider is discarded and audited
rather than quietly entering the inventory.

The one place an inventory check raises a *candidate* is
:class:`WebArchiveHarvest`, when archived URLs match the sensitive-path table: a `.env` that
was public last year is an exposure signal, and confirming it is analysis (ADR-02).
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from urllib.parse import urlsplit

from arachne.core.errors import OsintError
from arachne.core.results import CheckResult, Evidence
from arachne.core.safety import normalize_host
from arachne.core.target import TargetKind
from arachne.modules.base import CheckMetadata, Module
from arachne.modules.context import CheckContext, require_osint
from arachne.modules.extract import internal_hostname_hints, match_sensitive_paths
from arachne.modules.providers import ProviderResponse
from arachne.modules.providers.sources import (
    COMMONCRAWL_DEFAULT_INDEX,
    circl_url,
    commoncrawl_url,
    crtsh_url,
    parse_circl,
    parse_commoncrawl_jsonl,
    parse_crtsh,
    parse_wayback_cdx,
    urls_from_rows,
    wayback_cdx_url,
)

__all__ = [
    "CtLookup",
    "PassiveDns",
    "SubdomainPassive",
    "WebArchiveHarvest",
]

_DOMAIN_KINDS = (TargetKind.DOMAIN, TargetKind.DOMAIN_PATTERN)
#: A source's answer → the hostnames it names.
Extractor = Callable[[ProviderResponse], "set[str]"]


class CtLookup(Module):
    """``m1.ct-lookup`` — certificate transparency hostnames (research ch01#8)."""

    metadata = CheckMetadata(
        id="m1.ct-lookup",
        module="M1",
        name="ct-lookup",
        version="1.0",
        title="Certificate Transparency lookup",
        description=(
            "Queries crt.sh for every certificate naming the declared domain and records the "
            "hostnames its SANs expose."
        ),
        research_ref="ch01#8",
        target_kinds=_DOMAIN_KINDS,
        severity_hint="info",
        type="passive",
        verifiable=True,
        estimated_requests=1,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        osint, skip = require_osint(ctx, "crtsh")
        if skip is not None:
            yield skip
            return
        assert osint is not None
        name = ctx.asset.query_name
        if not name:
            yield ctx.skipped(f"asset {ctx.asset.key} has no queryable name")
            return

        url = crtsh_url(name)
        try:
            response = await osint.fetch("crtsh", url)
        except OsintError as exc:
            yield ctx.error(exc)
            return
        if not response.ok:
            yield ctx.info(
                f"Certificate Transparency lookup for {name} returned HTTP {response.status}",
                detail="the index answered with a status that carries no certificate data",
                evidence=[ctx.evidence("note", response.evidence_payload(), source=url)],
            )
            return

        parsed = parse_crtsh(response.json(), domain=name)
        hosts = parsed.hosts
        if not hosts:
            yield ctx.clean(
                f"no certificate-transparency hostnames for {name}",
                detail="crt.sh returned no certificate naming this domain",
                evidence=[ctx.evidence("note", response.evidence_payload(), source=url)],
                confidence=0.6,
            )
            return

        recorded = 0
        for host in hosts[: ctx.config.max_assets]:
            if await ctx.record_host(host, source="ct-lookup"):
                recorded += 1
        non_production = {host: hints for host in hosts if (hints := internal_hostname_hints(host))}
        evidence = [
            ctx.evidence(
                "note",
                {
                    **response.evidence_payload(),
                    "hosts": list(hosts[:100]),
                    "certificate_count": len(parsed.certificates),
                    "issuers": list(parsed.issuers[:10]),
                    "non_production_hosts": {
                        k: list(v) for k, v in list(non_production.items())[:50]
                    },
                },
                source=url,
            )
        ]
        yield ctx.info(
            f"certificate transparency exposed {len(hosts)} hostname(s) for {name}",
            detail=(
                f"{len(parsed.certificates)} certificate(s) from "
                f"{len(parsed.issuers)} issuer(s); {recorded} new host asset(s) recorded"
            ),
            evidence=evidence,
            confidence=0.9,
        )


class PassiveDns(Module):
    """``m1.passive-dns`` — historical resolutions (research ch01#11)."""

    metadata = CheckMetadata(
        id="m1.passive-dns",
        module="M1",
        name="passive-dns",
        version="1.0",
        title="Passive DNS history",
        description=(
            "Queries a passive-DNS database for the addresses, CNAMEs, mail servers and name "
            "servers the declared name has ever resolved to."
        ),
        research_ref="ch01#11",
        target_kinds=_DOMAIN_KINDS,
        severity_hint="info",
        type="passive",
        verifiable=True,
        estimated_requests=1,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        osint, skip = require_osint(ctx, "circl")
        if skip is not None:
            yield skip
            return
        assert osint is not None
        name = ctx.asset.query_name
        if not name:
            yield ctx.skipped(f"asset {ctx.asset.key} has no queryable name")
            return

        url = circl_url(name)
        try:
            response = await osint.fetch("circl", url)
        except OsintError as exc:
            yield ctx.error(exc)
            return
        if not response.ok:
            yield ctx.info(
                f"passive DNS lookup for {name} returned HTTP {response.status}",
                evidence=[ctx.evidence("note", response.evidence_payload(), source=url)],
            )
            return

        records = parse_circl(response.text, limit=ctx.config.max_results)
        if records.is_empty:
            yield ctx.clean(
                f"no passive-DNS history for {name}",
                detail="the passive-DNS source returned no records",
                evidence=[ctx.evidence("note", response.evidence_payload(), source=url)],
                confidence=0.5,
            )
            return

        for host in records.hostnames[: ctx.config.max_assets]:
            # A CNAME target is usually hosted elsewhere (a CDN, a SaaS) and is therefore
            # out of scope: record_asset discards it with an audit line (F-01-02).
            await ctx.record_host(host, source="passive-dns")
        yield ctx.info(
            f"passive DNS history for {name}: {len(records.addresses)} address(es), "
            f"{len(records.hostnames)} CNAME target(s)",
            detail=(
                f"{len(records.rrsets)} record set(s)"
                + (
                    f"; first seen {records.first_seen}, last seen {records.last_seen}"
                    if records.first_seen
                    else ""
                )
            ),
            evidence=[
                ctx.evidence(
                    "note",
                    {
                        **response.evidence_payload(),
                        "addresses": list(records.addresses[:50]),
                        "cname_targets": list(records.hostnames[:50]),
                        "mail_servers": list(records.mail_servers[:20]),
                        "name_servers": list(records.name_servers[:20]),
                    },
                    source=url,
                )
            ],
            confidence=0.8,
        )


class SubdomainPassive(Module):
    """``m1.subdomain-passive`` — merge passive sources (research ch01#13)."""

    metadata = CheckMetadata(
        id="m1.subdomain-passive",
        module="M1",
        name="subdomain-passive",
        version="1.0",
        title="Passive subdomain aggregation",
        description=(
            "Merges and de-duplicates subdomains observed by several passive sources "
            "(certificate transparency, passive DNS, web archives) into one host set."
        ),
        research_ref="ch01#13",
        target_kinds=_DOMAIN_KINDS,
        severity_hint="info",
        type="passive",
        verifiable=True,
        estimated_requests=3,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        name = ctx.asset.query_name
        if not name:
            yield ctx.skipped(f"asset {ctx.asset.key} has no queryable name")
            return
        if ctx.osint is None:
            yield ctx.skipped(
                "OSINT access is disabled for this scan "
                "(set ARACHNE_OSINT_ENABLED=true to query third-party passive sources)"
            )
            return

        observed: dict[str, set[str]] = {}
        consulted: list[str] = []
        evidence: list[Evidence] = []
        failures: list[str] = []

        extractors: tuple[tuple[str, str, Extractor], ...] = (
            ("crtsh", crtsh_url(name), _hosts_from_crtsh),
            ("circl", circl_url(name), _hosts_from_circl),
            (
                "wayback",
                wayback_cdx_url(name, limit=ctx.config.max_results),
                _hosts_from_cdx,
            ),
        )
        for provider, url, extract in extractors:
            if not ctx.osint.available(provider):
                continue
            try:
                response = await ctx.osint.fetch(provider, url)
            except OsintError as exc:
                failures.append(f"{provider}: {exc}")
                continue
            if not response.ok:
                failures.append(f"{provider}: HTTP {response.status}")
                continue
            consulted.append(provider)
            evidence.append(ctx.evidence("note", response.evidence_payload(), source=url))
            for host in extract(response):
                if host == name or host.endswith(f".{name}"):
                    observed.setdefault(host, set()).add(provider)

        if not consulted:
            reason = "; ".join(failures) or "no passive source is enabled for this scan"
            yield ctx.skipped(f"no passive source answered for {name}: {reason}")
            return

        # Only subdomains: the apex is already an asset from the target definition.
        subdomains = {host: sources for host, sources in observed.items() if host != name}
        recorded = 0
        for host in sorted(subdomains)[: ctx.config.max_assets]:
            if await ctx.record_host(host, source="subdomain-passive"):
                recorded += 1
        multi_source = {host: sorted(src) for host, src in subdomains.items() if len(src) > 1}
        yield ctx.info(
            f"passive subdomain aggregation found {len(subdomains)} subdomain(s) for {name}",
            detail=(
                f"sources consulted: {', '.join(consulted)}; {recorded} new host asset(s); "
                f"{len(multi_source)} host(s) seen by more than one source"
                + (f"; failures: {'; '.join(failures)}" if failures else "")
            ),
            evidence=[
                *evidence,
                ctx.evidence(
                    "artifact",
                    {
                        "subdomains": sorted(subdomains)[:200],
                        "sources": {
                            host: sorted(src) for host, src in list(subdomains.items())[:200]
                        },
                        "multi_source": multi_source,
                    },
                    source=name,
                ),
            ],
            confidence=0.85,
        )


class WebArchiveHarvest(Module):
    """``m1.webarchive-harvest`` — archived URLs (research ch01#14-16)."""

    metadata = CheckMetadata(
        id="m1.webarchive-harvest",
        module="M1",
        name="webarchive-harvest",
        version="1.0",
        title="Web archive URL harvesting",
        description=(
            "Harvests historical URLs for the declared host from the Wayback Machine CDX "
            "index and the Common Crawl index, and flags archived paths that match the "
            "sensitive-path table."
        ),
        research_ref="ch01#14-16",
        cwe="CWE-200",
        # Domain-scoped on purpose: a URL target already belongs to a declared host, so
        # letting the check run against both would harvest the same archive twice and raise
        # the same candidate twice. Merging duplicates is the correlation engine's job
        # (F-05-03), not a reason to do the work twice.
        target_kinds=_DOMAIN_KINDS,
        severity_hint="low",
        type="passive",
        verifiable=True,
        estimated_requests=2,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        name = ctx.asset.query_name
        if not name:
            yield ctx.skipped(f"asset {ctx.asset.key} has no queryable name")
            return
        if ctx.osint is None:
            yield ctx.skipped(
                "OSINT access is disabled for this scan "
                "(set ARACHNE_OSINT_ENABLED=true to query third-party passive sources)"
            )
            return

        sources: dict[str, tuple[str, ...]] = {}
        evidence: list[Evidence] = []
        failures: list[str] = []

        if ctx.osint.available("wayback"):
            url = wayback_cdx_url(name, limit=ctx.config.max_results)
            try:
                response = await ctx.osint.fetch("wayback", url)
            except OsintError as exc:
                failures.append(f"wayback: {exc}")
            else:
                if response.ok:
                    rows = parse_wayback_cdx(response.json(), limit=ctx.config.max_results)
                    sources["wayback"] = urls_from_rows(rows)
                    evidence.append(ctx.evidence("note", response.evidence_payload(), source=url))
                else:
                    failures.append(f"wayback: HTTP {response.status}")

        if ctx.osint.available("commoncrawl"):
            index = ctx.config.commoncrawl_index or COMMONCRAWL_DEFAULT_INDEX
            url = commoncrawl_url(name, index=index, limit=ctx.config.max_results)
            try:
                response = await ctx.osint.fetch("commoncrawl", url)
            except OsintError as exc:
                failures.append(f"commoncrawl: {exc}")
            else:
                if response.ok:
                    rows = parse_commoncrawl_jsonl(response.text, limit=ctx.config.max_results)
                    sources["commoncrawl"] = urls_from_rows(rows)
                    evidence.append(ctx.evidence("note", response.evidence_payload(), source=url))
                else:
                    failures.append(f"commoncrawl: HTTP {response.status}")

        if not sources:
            yield ctx.skipped(
                f"no web archive answered for {name}: "
                + ("; ".join(failures) or "no archive provider is enabled")
            )
            return

        urls: dict[str, None] = {}
        for found in sources.values():
            for url in found:
                urls.setdefault(url, None)
        all_urls = tuple(urls)
        recorded = 0
        for url in all_urls[: ctx.config.max_assets]:
            if await ctx.record_asset(
                "url", url, meta={"discovered_by": "webarchive"}, source="webarchive-harvest"
            ):
                recorded += 1

        hits: dict[tuple[str, str], list[str]] = {}
        for url in all_urls:
            for hit in match_sensitive_paths(url):
                hits.setdefault(hit, []).append(url)

        yield ctx.info(
            f"web archives exposed {len(all_urls)} URL(s) for {name}",
            detail=(
                f"{', '.join(f'{source}: {len(found)}' for source, found in sources.items())}; "
                f"{recorded} URL asset(s) recorded"
                + (f"; failures: {'; '.join(failures)}" if failures else "")
            ),
            evidence=[
                *evidence,
                ctx.evidence(
                    "artifact",
                    {
                        "urls": list(all_urls[:200]),
                        "by_source": {key: list(value[:100]) for key, value in sources.items()},
                    },
                    source=name,
                ),
            ],
            confidence=0.8,
        )

        if hits:
            yield ctx.candidate(
                f"archived URLs for {name} match {len(hits)} sensitive path pattern(s)",
                detail=(
                    "Archived copies are historical, not proof of live exposure, but "
                    "removed-but-indexed paths (research ch01 §14/§28) are worth verifying: "
                    + "; ".join(
                        f"{label} ({len(found)} url(s), e.g. {found[0]})"
                        for (needle, label), found in list(hits.items())[:10]
                    )
                ),
                evidence=[
                    ctx.evidence(
                        "artifact",
                        {
                            "matches": [
                                {"pattern": needle, "label": label, "urls": found[:10]}
                                for (needle, label), found in list(hits.items())[:50]
                            ]
                        },
                        source=name,
                    )
                ],
                confidence=0.4,
            )


def _hosts_from_crtsh(response: ProviderResponse) -> set[str]:
    return set(parse_crtsh(response.json()).hosts)


def _hosts_from_circl(response: ProviderResponse) -> set[str]:
    records = parse_circl(response.text)
    return {*records.hostnames, *records.name_servers, *records.mail_servers}


def _hosts_from_cdx(response: ProviderResponse) -> set[str]:
    hosts: set[str] = set()
    for url in urls_from_rows(parse_wayback_cdx(response.json())):
        host = _host_of(url)
        if host:
            hosts.add(host)
    return hosts


def _host_of(url: str) -> str | None:
    return normalize_host(urlsplit(url).hostname or "") or None
