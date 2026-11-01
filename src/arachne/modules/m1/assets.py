"""M1 per-asset checks: inspect one URL or one address range (ch01).

* :class:`JsAssetScan` — fetch a web asset, follow its JavaScript bundles and extract API
  endpoints plus hardcoded credentials (research ch01 method 26). This is the one M1 check
  that is *hybrid*: it reads the target's own public content (read-only HTTP, rate limited,
  inside the target scope) and cross-references what it finds with the client-side key
  patterns the corpus describes.
* :class:`InternetDbTriage` — keyless Shodan InternetDB lookups over the declared
  addresses (method 5) to triage ports, CPEs and CVEs before any active work.

Both are bounded: a page yields at most ``max_assets`` bundles and ``max_results`` findings,
and the address walk is capped, so a wide range or a hostile page cannot turn one check into
an unbounded scan.
"""

from __future__ import annotations

import ipaddress
from collections.abc import AsyncIterator
from urllib.parse import urljoin, urlsplit

from arachne.core.errors import OsintError, RequestError, SafetyError
from arachne.core.results import CheckResult
from arachne.core.safety import normalize_host
from arachne.core.target import TargetKind
from arachne.modules.base import CheckMetadata, Module
from arachne.modules.context import CheckContext, require_osint
from arachne.modules.extract import (
    dom_sink_signals,
    extract_named_assets,
    extract_script_sources,
    scan_text,
)
from arachne.modules.providers.sources import internetdb_url, parse_internetdb

__all__ = ["InternetDbTriage", "JsAssetScan"]

#: Bundles fetched per page. A real site can list hundreds; the first handful carry the
#: application code, and the cap keeps the check's request count honest (F-01-07).
MAX_SCRIPTS_PER_PAGE = 10


class JsAssetScan(Module):
    """``m1.js-asset-scan`` — endpoints and secrets in client-side assets (ch01#26)."""

    metadata = CheckMetadata(
        id="m1.js-asset-scan",
        module="M1",
        name="js-asset-scan",
        version="1.0",
        title="JavaScript asset scan",
        description=(
            "Fetches the page and its JavaScript bundles and extracts API endpoints, "
            "referenced assets and hardcoded credentials (reported masked)."
        ),
        research_ref="ch01#26",
        cwe="CWE-200",
        target_kinds=(TargetKind.URL,),
        severity_hint="medium",
        type="hybrid",
        safe=True,
        verifiable=True,
        estimated_requests=3,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        if ctx.http is None:
            yield ctx.skipped("no HTTP client is available in this mode (dry run)")
            return
        page_url = ctx.asset.value
        try:
            page = await ctx.http.get(page_url)
        except (SafetyError, RequestError) as exc:
            yield ctx.error(exc)
            return
        request_evidence, response_evidence = ctx.evidence_from_exchange(page)
        page_signals = scan_text(page.body, source=page_url, emails=False)

        sources = [
            urljoin(page_url, source)
            for source in extract_script_sources(page.body, limit=MAX_SCRIPTS_PER_PAGE)
        ]
        analysed: list[str] = []
        endpoints: dict[str, None] = {}
        assets: dict[str, None] = {}
        # Credentials are reported by *kind*: the body a check receives has already been
        # redacted at capture (F-08-04), so `secret_kinds` — the detectors that fired — is
        # both the only and the safest way to know a bundle hardcodes a key.
        secret_sources: dict[str, set[str]] = {}
        #: The DOM sink/source shapes per analysed body (S29, REQ-DEPTH-004). Static: this
        #: stage runs no JavaScript engine (ADR-100.4), so the reading is textual and the
        #: finding says so.
        dom_sinks: dict[str, dict[str, list[str]]] = {}
        evidence = [request_evidence, response_evidence]
        failures: list[str] = []

        for endpoint in page_signals.endpoints:
            endpoints.setdefault(endpoint, None)
        for asset_url in extract_named_assets(page.body):
            assets.setdefault(asset_url, None)
        _remember_secrets(secret_sources, page.secret_kinds, page_url)
        _remember_dom(dom_sinks, page.body, page_url)

        for script_url in sources:
            try:
                script = await ctx.http.get(script_url)
            except (SafetyError, RequestError) as exc:
                failures.append(f"{script_url}: {exc.__class__.__name__}")
                continue
            analysed.append(script_url)
            found = scan_text(script.body, source=script_url, emails=False)
            for endpoint in found.endpoints:
                endpoints.setdefault(endpoint, None)
            _remember_secrets(secret_sources, script.secret_kinds, script_url)
            _remember_dom(dom_sinks, script.body, script_url)
            if script.secret_kinds:
                script_request, script_response = ctx.evidence_from_exchange(script)
                evidence.extend([script_request, script_response])

        for endpoint in list(endpoints)[: ctx.config.max_assets]:
            # A same-origin route is a URL asset in the target's own scope; anything
            # absolute and external is discarded by the scope guard (F-01-02).
            candidate = urljoin(page_url, endpoint)
            if urlsplit(candidate).hostname and normalize_host(
                str(urlsplit(candidate).hostname)
            ) == normalize_host(str(urlsplit(page_url).hostname)):
                await ctx.record_asset(
                    "url",
                    candidate,
                    meta={"discovered_by": "js-asset-scan"},
                    source="js-asset-scan",
                )

        summary = ctx.evidence(
            "artifact",
            {
                "page": page_url,
                "scripts_analysed": analysed,
                "script_failures": failures,
                "endpoints": list(endpoints)[:200],
                "referenced_assets": list(assets)[:100],
                "matched_patterns": {
                    kind: sorted(urls)[:10] for kind, urls in secret_sources.items()
                },
                "dom_sinks": {
                    source: {
                        "sinks": shapes["sinks"],
                        "sources": shapes["sources"],
                        "source_fed": shapes["source_fed"],
                    }
                    for source, shapes in sorted(dom_sinks.items())
                },
                "dom_analysis": "static text scan; no JavaScript engine ran (ADR-100.4)",
            },
            source=page_url,
        )
        evidence.append(summary)

        if not analysed and not endpoints:
            yield ctx.clean(
                f"no JavaScript assets analysed at {page_url}",
                detail=(
                    "the page referenced no script this check could fetch"
                    + (f"; failures: {'; '.join(failures)}" if failures else "")
                ),
                evidence=evidence,
                confidence=0.4,
            )
            return

        yield ctx.info(
            f"JavaScript analysis of {page_url} found {len(endpoints)} endpoint(s)",
            detail=(
                f"{len(analysed)} script(s) analysed"
                + (f"; {len(assets)} referenced asset(s)" if assets else "")
                + (f"; failures: {'; '.join(failures)}" if failures else "")
            ),
            evidence=evidence,
            confidence=0.8,
        )

        if secret_sources:
            yield ctx.candidate(
                f"{len(secret_sources)} credential pattern(s) matched in client-side assets "
                f"at {page_url}",
                detail=(
                    "Values are redacted at capture time and reported as detector names "
                    "(F-08-04): a client-side credential is only exploitable if the backend "
                    "accepts it, which is analysis (research ch01 §26). kinds: "
                    + ", ".join(sorted(secret_sources))
                    + "; sources: "
                    + ", ".join(
                        sorted({url for urls in secret_sources.values() for url in urls})[:5]
                    )
                ),
                evidence=evidence,
                confidence=0.5,
            )

        source_fed = {
            source: shapes["source_fed"]
            for source, shapes in dom_sinks.items()
            if shapes["source_fed"]
        }
        if source_fed:
            yield ctx.candidate(
                f"client-side DOM sink fed from an input source at {page_url}",
                detail=(
                    "a served bundle carries a dangerous DOM sink ("
                    + ", ".join(sorted({name for names in source_fed.values() for name in names}))
                    + ") in code that also reads an attacker-influenceable source ("
                    + ", ".join(
                        sorted(
                            {
                                name
                                for source in source_fed
                                for name in dom_sinks[source]["sources"]
                            }
                        )
                    )
                    + "). This is the *static* precondition of a DOM-XSS path: the bundle was "
                    "read as text and no JavaScript ran, so it establishes where to look, not "
                    "that a payload executes (ADR-100.4). sources: "
                    + ", ".join(sorted(source_fed)[:5])
                ),
                evidence=evidence,
                confidence=0.4,
            )


def _remember_dom(
    target: dict[str, dict[str, list[str]]], body: str, source: str
) -> None:
    """Record the DOM sink/source shapes of one body (only when it has a sink at all)."""
    signals = dom_sink_signals(body)
    if not signals.sinks:
        return
    target[source] = {
        "sinks": list(signals.sinks),
        "sources": list(signals.sources),
        "source_fed": list(signals.reachable),
    }


class InternetDbTriage(Module):
    """``m1.internetdb-triage`` — keyless per-address triage (research ch01#5)."""

    metadata = CheckMetadata(
        id="m1.internetdb-triage",
        module="M1",
        name="internetdb-triage",
        version="1.0",
        title="InternetDB address triage",
        description=(
            "Looks up every declared address in Shodan InternetDB (keyless) for open ports, "
            "CPE fingerprints and known CVEs, before any active service scan."
        ),
        research_ref="ch01#5",
        cwe="CWE-1035",
        target_kinds=(TargetKind.IP, TargetKind.CIDR),
        severity_hint="medium",
        type="passive",
        verifiable=True,
        estimated_requests=1,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        osint, skip = require_osint(ctx, "internetdb")
        if skip is not None:
            yield skip
            return
        assert osint is not None

        addresses = list(_addresses_of(ctx.asset.value, ctx.config.max_hosts_per_network))
        if not addresses:
            yield ctx.skipped(f"asset {ctx.asset.key} contains no usable address")
            return

        lookups = 0
        records = []
        failures: list[str] = []
        for address in addresses:
            if not osint.can_spend():
                failures.append(f"budget exhausted after {lookups} lookup(s)")
                break
            try:
                response = await osint.fetch("internetdb", internetdb_url(address))
            except OsintError as exc:
                failures.append(f"{address}: {exc}")
                continue
            lookups += 1
            if response.status not in (200, 404):
                failures.append(f"{address}: HTTP {response.status}")
                continue
            record = parse_internetdb(response.json(), address=address)
            if record.found and not record.is_empty:
                records.append((address, record, response))

        if not records:
            yield ctx.clean(
                f"no InternetDB data for {len(addresses)} address(es) of {ctx.asset.value}",
                detail=(
                    f"{lookups} lookup(s) returned no indexed service"
                    + (f"; failures: {'; '.join(failures)}" if failures else "")
                ),
                confidence=0.5,
            )
            return

        for address, record, _ in records:
            await ctx.record_asset(
                "host",
                address,
                meta={
                    "discovered_by": "internetdb",
                    "ports": list(record.ports),
                    "cpes": list(record.cpes),
                    "tags": list(record.tags),
                },
                source="internetdb-triage",
            )

        with_cves = [
            (address, record, response) for address, record, response in records if record.vulns
        ]
        yield ctx.info(
            f"InternetDB triage of {ctx.asset.value}: "
            f"{len(records)} address(es) with indexed services",
            detail=(
                f"{lookups} lookup(s); "
                + (
                    f"{len(with_cves)} address(es) carry CVE identifiers"
                    if with_cves
                    else "no CVE identifiers"
                )
                + (f"; failures: {'; '.join(failures)}" if failures else "")
            ),
            evidence=[
                ctx.evidence(
                    "artifact",
                    {
                        "addresses": {
                            address: {
                                "ports": list(record.ports),
                                "cpes": list(record.cpes),
                                "tags": list(record.tags),
                                "hostnames": list(record.hostnames),
                                "vulns": list(record.vulns),
                            }
                            for address, record, _ in records[:50]
                        },
                        "lookups": lookups,
                    },
                    source=ctx.asset.value,
                ),
                *[
                    ctx.evidence("note", response.evidence_payload(), source=url)
                    for _, _, response in records[:5]
                    for url in (response.url,)
                ],
            ],
            confidence=0.7,
        )

        for address, record, response in with_cves[: ctx.config.max_results]:
            yield ctx.candidate(
                f"{len(record.vulns)} known CVE(s) indexed for {address}",
                detail=(
                    f"InternetDB reports {', '.join(record.vulns[:10])} against "
                    f"{', '.join(record.cpes[:5]) or 'unnamed services'} on ports "
                    f"{', '.join(str(port) for port in record.ports[:10])}. "
                    "The index is passive evidence from a third-party weekly crawl; "
                    "confirming the version actively is M2's job (F-02-03)."
                ),
                evidence=[
                    ctx.evidence("note", response.evidence_payload(), source=response.url),
                    ctx.evidence(
                        "artifact",
                        {
                            "address": address,
                            "vulns": list(record.vulns),
                            "cpes": list(record.cpes),
                            "ports": list(record.ports),
                            "tags": list(record.tags),
                        },
                        source=address,
                    ),
                ],
                confidence=0.6,
            )


def _remember_secrets(target: dict[str, set[str]], kinds: tuple[str, ...], source: str) -> None:
    """Record which secret detectors fired on ``source`` (the values are already redacted)."""
    for kind in kinds:
        target.setdefault(kind, set()).add(source)


def _addresses_of(value: str, cap: int) -> tuple[str, ...]:
    """Enumerate the addresses a ``host``/``network`` asset covers (never a default route)."""
    try:
        network = ipaddress.ip_network(value, strict=False)
    except ValueError:
        try:
            return (str(ipaddress.ip_address(value)),)
        except ValueError:
            return ()
    # An IPv4 subnet's network and broadcast addresses are not usable hosts; every other
    # range (including IPv6) is enumerated in full.
    usable = network.version == 4 and network.prefixlen <= 30
    hosts = network.hosts() if usable else iter(network)
    out: list[str] = []
    for address in hosts:
        out.append(str(address))
        if len(out) >= cap:
            break
    return tuple(out)
