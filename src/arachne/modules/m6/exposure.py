"""Exploit-readiness and local-privesc correlation over the estate (research ch06#7 and #16).

Two estate-level checks that answer "what do we already know about, and how exploitable is
it?" from data the scan already has, without touching the network:

``m6.cve-epss-correlation``
    Matches the OS/service fingerprints M2 recorded (plus an operator version export and the
    web server banner) against the offline CVE index, then ranks each hit by FIRST EPSS and
    CISA KEV — the exploit-readiness view of ch06#7. The PHP2SHELL pair is the canonical
    example: high EPSS, KEV-listed, with a patch-to-exploit window measured in hours.
``m6.lpe-discovery``
    Matches the same fingerprints against the local-privilege-escalation index (kernel, sudo,
    polkit, glibc) — the "which of our hosts has a local root path?" view of ch06#16.

Both read the discovery step's persisted inventory sample (``m6.support.resolved_services``)
and are owner-gated so a multi-target scan reports the estate once. Neither makes a request.
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator
from typing import Any

from arachne.core.results import CheckResult
from arachne.core.target import TargetKind
from arachne.modules.base import Asset, CheckMetadata, Module
from arachne.modules.context import CheckContext
from arachne.modules.m2.catalog import CveEntry, normalize_product, version_matches
from arachne.modules.m2.support import cve_index_for
from arachne.modules.m6.feeds import load_epss, load_lpe_index
from arachne.modules.m6.support import (
    estate_owner,
    finding_cap,
    m6_candidate,
    resolved_services,
    skip,
)

__all__ = ["CveEpssCorrelation", "LpeDiscovery"]

_ESTATE_KINDS = (
    TargetKind.URL,
    TargetKind.IP,
    TargetKind.DOMAIN,
    TargetKind.CIDR,
    TargetKind.CLOUD,
)


def _fingerprints(ctx: CheckContext) -> tuple[dict[str, Any], ...]:
    """Product/version rows for the estate, deduplicated (fingerprint rows + banner rows)."""
    rows: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for row in resolved_services(ctx):
        product = row.get("product") or row.get("service") or row.get("name")
        version = row.get("version")
        if not product or not version:
            continue
        host = str(row.get("host") or row.get("asset") or "")
        key = (str(product).lower(), str(version), host)
        if key in seen:
            continue
        seen.add(key)
        rows.append(
            {
                "product": str(product),
                "version": str(version),
                "host": host,
                "port": row.get("port"),
                "source": "fingerprint",
            }
        )
    for row in _banner_rows(ctx):
        key = (row["product"].lower(), row["version"], row["host"])
        if key in seen:
            continue
        seen.add(key)
        rows.append(row)
    return tuple(rows)


def _banner_rows(ctx: CheckContext) -> tuple[dict[str, Any], ...]:
    """Web server products/versions from the crawl's ``Server`` header (ch02#12/ch06#7)."""
    inventory = ctx.web
    if inventory is None:
        return ()
    out: list[dict[str, Any]] = []
    for page in inventory.pages.values():
        server = page.header("server")
        if not server:
            continue
        product, version = _split_banner(server)
        if not product:
            continue
        out.append(
            {
                "product": product,
                "version": version or "",
                "host": page.host,
                "port": None,
                "source": "web-server",
            }
        )
    return tuple(out)


def _split_banner(server: str) -> tuple[str | None, str | None]:
    match = re.match(r"\s*([A-Za-z][A-Za-z0-9._\-]*)/([0-9][0-9A-Za-z.\-]*)", server)
    if match:
        return match.group(1), match.group(2)
    token = server.strip().split()[0] if server.strip() else ""
    return (token, None) if token else (None, None)


def _match_index(
    rows: tuple[dict[str, Any], ...], entries: tuple[CveEntry, ...]
) -> tuple[tuple[dict[str, Any], CveEntry], ...]:
    by_product: dict[str, list[CveEntry]] = {}
    for entry in entries:
        for name in entry.product_names():
            by_product.setdefault(normalize_product(name), []).append(entry)
    matches: list[tuple[dict[str, Any], CveEntry]] = []
    for row in rows:
        candidates = by_product.get(normalize_product(row["product"]), [])
        for entry in candidates:
            if not row["version"]:
                continue
            if version_matches(row["version"], entry.constraints):
                matches.append((row, entry))
    return tuple(matches)


def _fixed_at(entry: CveEntry) -> str | None:
    """The lowest upper-bound version in ``affected`` — where the fix lands, if written."""
    upper: list[str] = []
    for constraint in entry.constraints:
        if constraint.op in {"<", "<="}:
            upper.append(constraint.version)
    return min(upper) if upper else None


# --------------------------------------------------------------------------- CVE/EPSS
class CveEpssCorrelation(Module):
    """``m6.cve-epss-correlation`` — patch-gap analysis ranked by EPSS/KEV (ch06#7)."""

    metadata = CheckMetadata(
        id="m6.cve-epss-correlation",
        version="1.0",
        title="CVE/EPSS correlation and patch-gap analysis",
        description=(
            "Correlates the estate's fingerprinted products and versions with the offline CVE "
            "index, then ranks each hit by FIRST EPSS exploit likelihood and CISA KEV status to "
            "produce a patch-gap view (research ch06#7). Offline-first: the shipped EPSS "
            "snapshot is used unless ARACHNE_M6_EPSS_FEED / ARACHNE_M6_KEV_FEED point at a "
            "refreshed feed. Zero requests."
        ),
        module="M6",
        name="cve-epss-correlation",
        research_ref="ch06#7",
        framework=("WSTG-CONF-01", "CWE-1035"),
        compliance=(
            "CIS-16.2",
            "CIS-16.6",
            "CIS-7.1",
            "CIS-7.2",
            "CIS-7.6",
            "CIS-7.7",
            "ISO-A.5.7",
            "ISO-A.8.8",
            "CSF-DE.AE-03",
            "CSF-DE.AE-07",
            "CSF-ID.RA-01",
            "CSF-ID.RA-02",
            "CSF-ID.RA-04",
            "CSF-ID.RA-05",
            "CSF-ID.RA-06",
            "PCI-11",
        ),
        cwe="CWE-1035",
        target_kinds=_ESTATE_KINDS,
        severity_hint="high",
        type="passive",
        safe=True,
        verifiable=False,
        estimated_requests=0,
    )

    def supports(self, asset: Asset) -> bool:
        if not Module.supports(self, asset):
            return False
        return asset.kind in {"url", "domain", "host", "network", "cloud"}

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        if not estate_owner(ctx):
            yield skip(ctx, "estate check: it runs once per scan, on the estate's owner asset")
            return
        index = cve_index_for(ctx)
        snapshot = load_epss(ctx.config.m6.epss_feed, kev_path=ctx.config.m6.kev_feed)
        rows = _fingerprints(ctx)
        if not rows:
            yield skip(
                ctx,
                "no fingerprinted product/version on the estate: M2 ran no version detection "
                "and no ARACHNE_M6_RESOLVED_VERSIONS export was configured",
            )
            return
        matches = _match_index(rows, index.entries)
        if not matches:
            yield ctx.clean(
                f"{len(rows)} fingerprinted product(s) with no CVE match in the offline index",
                detail="the offline index has no affected range for these versions",
            )
            return
        cap = finding_cap(ctx)
        for position, (row, entry) in enumerate(
            sorted(matches, key=lambda item: -snapshot.rank(item[1].cve)), start=1
        ):
            epss_entry = snapshot.get(entry.cve)
            yield m6_candidate(
                ctx,
                f"{entry.cve}: {entry.title}",
                artifact={
                    "signal": "epss-correlated",
                    "family": "patch-gap",
                    "cve": entry.cve,
                    "product": row["product"],
                    "version": row["version"],
                    "asset": row["host"],
                    "port": row.get("port"),
                    "source": row.get("source"),
                    "epss": epss_entry.epss if epss_entry else entry.epss,
                    "percentile": epss_entry.percentile if epss_entry else None,
                    "kev": bool(epss_entry.kev) if epss_entry else False,
                    "patch_gap": True,
                    "fixed_at": _fixed_at(entry),
                    "cvss": entry.cvss,
                },
                cwe=entry.cwe or "CWE-1035",
                confidence=0.75,
                detail=(
                    f"{row['product']} {row['version']} on {row['host'] or 'the estate'} is in "
                    f"the affected range of {entry.cve} "
                    f"(EPSS {epss_entry.epss if epss_entry else entry.epss}, "
                    f"KEV {bool(epss_entry.kev) if epss_entry else False})"
                ),
                source=row["host"] or row["product"],
            )
            if position >= cap:
                return


# --------------------------------------------------------------------------- LPE
class LpeDiscovery(Module):
    """``m6.lpe-discovery`` — version-based local privilege-escalation matching (ch06#16)."""

    metadata = CheckMetadata(
        id="m6.lpe-discovery",
        version="1.0",
        title="Local privilege-escalation CVE matching",
        description=(
            "Matches the estate's fingerprinted OS/service versions (kernel, sudo, polkit, "
            "glibc) against the offline local-privilege-escalation index to surface known "
            "unprivileged-to-root paths a defender must patch before an attacker enumerates "
            "them (research ch06#16). Offline-first and read-only: it reads fingerprints and "
            "the shipped index, and never runs a privesc check on a host."
        ),
        module="M6",
        name="lpe-discovery",
        research_ref="ch06#16",
        framework=("WSTG-CONF-01", "WSTG-ATHZ-03", "CWE-269"),
        cwe="CWE-269",
        target_kinds=_ESTATE_KINDS,
        severity_hint="high",
        type="passive",
        safe=True,
        verifiable=False,
        estimated_requests=0,
    )

    def supports(self, asset: Asset) -> bool:
        if not Module.supports(self, asset):
            return False
        return asset.kind in {"url", "domain", "host", "network", "cloud"}

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        if not estate_owner(ctx):
            yield skip(ctx, "estate check: it runs once per scan, on the estate's owner asset")
            return
        index = load_lpe_index(ctx.config.m6.lpe_index)
        rows = _fingerprints(ctx)
        if not rows:
            yield skip(
                ctx,
                "no fingerprinted OS/service version to match against the LPE index",
            )
            return
        matches = _match_index(rows, index.entries)
        if not matches:
            yield ctx.clean(
                f"{len(rows)} fingerprinted product(s) with no LPE match",
                detail="the offline LPE index has no affected range for these versions",
            )
            return
        cap = finding_cap(ctx)
        for position, (row, entry) in enumerate(matches, start=1):
            yield m6_candidate(
                ctx,
                f"Local privesc CVE: {entry.cve} — {entry.title}",
                artifact={
                    "signal": "lpe-cve",
                    "family": "lpe",
                    "cve": entry.cve,
                    "product": row["product"],
                    "version": row["version"],
                    "asset": row["host"],
                    "source": row.get("source"),
                    "epss": entry.epss,
                    "fixed_at": _fixed_at(entry),
                    "cvss": entry.cvss,
                },
                cwe=entry.cwe or "CWE-269",
                confidence=0.7,
                detail=(
                    f"{row['product']} {row['version']} on {row['host'] or 'the estate'} is in "
                    f"the affected range of {entry.cve} (a local privilege-escalation path)"
                ),
                source=row["host"] or row["product"],
            )
            if position >= cap:
                return
