"""M3 subdomain takeover: dangling-alias fingerprint matching (ch03#34).

Research ch03#34's takeover pipeline is *enumerate subdomains → read the CNAME → match the
service's unclaimed-name error page*. A scanner that never claims a live alias can still do the
last two steps safely, and that is what this check does:

* it matches the **service fingerprint page** among the hosts the crawl already reached — the
  "There isn't a GitHub Pages site here" / "NoSuchBucket" / "No such app" body is the evidence,
  and a page carrying it means the alias points at a service that does not own it any more;
* when OSINT is enabled and a ``dns`` provider is selected it also reads the CNAME chain, and a
  CNAME into a fingerprint service raises the confidence.

It never registers, claims or configures anything: the finding is the dangling record plus the
service's own not-found page (research ch03#34: "safe when the researcher only confirms the
dangling record's existence and error fingerprint").
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from urllib.parse import quote, urlsplit

from arachne.core.results import CheckResult
from arachne.core.target import TargetKind
from arachne.modules.base import CheckMetadata, Module
from arachne.modules.context import CheckContext, require_osint
from arachne.modules.m3.inventory import WebInventory
from arachne.modules.m3.support import (
    WebCheck,
    http_or_skip,
    owns_origin,
    payloads_for,
    skip,
    web_candidate,
    web_or_skip,
)

__all__ = ["SubdomainTakeover"]


class SubdomainTakeover(WebCheck, Module):
    """``m3.subdomain-takeover`` — dangling-CNAME service fingerprint (ch03#34)."""

    metadata = CheckMetadata(
        id="m3.subdomain-takeover",
        module="M3",
        name="subdomain-takeover",
        version="1.0",
        title="Subdomain takeover of a web-facing alias",
        description=(
            "Matches the can-i-take-over-xyz service fingerprints (GitHub Pages, Heroku, S3, "
            "Shopify, Fastly, ...) against the hosts the crawl reached: a page carrying the "
            "service's own 'this name is not configured' body means the alias points at a service "
            "that no longer owns it. When OSINT is enabled the CNAME chain is read too and a CNAME "
            "into a fingerprint service raises the confidence. Nothing is claimed or registered."
        ),
        research_ref="ch03#34",
        framework=("WSTG-CONF-10", "CWE-350"),
        cwe="CWE-350",
        target_kinds=(TargetKind.URL, TargetKind.DOMAIN, TargetKind.DOMAIN_PATTERN),
        severity_hint="high",
        type="hybrid",
        safe=True,
        verifiable=False,
        estimated_requests=2,
        runs_on_discovered=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        _client, skipped = http_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        if not owns_origin(ctx):
            yield skip(ctx, "another URL asset on this origin owns the M3 crawl for it")
            return
        inventory, skipped = web_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        assert isinstance(inventory, WebInventory)
        payloads = payloads_for(ctx)
        fingerprints = payloads.entries("takeover", "fingerprints")
        if not fingerprints:
            yield skip(ctx, "the M3 corpus ships no takeover fingerprints")
            return
        cnames = await self._cnames(ctx)
        findings = 0
        for page in inventory.pages.values():
            host = urlsplit(page.url).hostname or ""
            for entry in fingerprints:
                markers = [str(item) for item in entry.get("markers") or ()]
                service = str(entry.get("service", "unknown"))
                cname_suffix = str(entry.get("cname", ""))
                matched = next(
                    (marker for marker in markers if marker.lower() in page.body.lower()), None
                )
                if matched is None:
                    continue
                cname = cnames.get(host)
                cname_match = bool(cname and cname_suffix and cname_suffix in cname)
                findings += 1
                yield web_candidate(
                    ctx,
                    f"Possible subdomain takeover: {host} ({service})",
                    artifact={
                        "signal": "subdomain-takeover",
                        "family": "subdomain-takeover",
                        "host": host,
                        "url": page.url,
                        "service": service,
                        "marker": matched,
                        "cname": cname,
                        "cname_matches_service": cname_match,
                    },
                    exchanges=(),
                    cwe="CWE-350",
                    confidence=0.8 if cname_match else 0.65,
                    detail=(
                        f"{page.url} served the {service} 'name not configured' fingerprint"
                        + (
                            f"; its CNAME ({cname}) points into {cname_suffix}"
                            if cname_match
                            else ""
                        )
                    ),
                    source=page.url,
                )
                break
        if not findings:
            yield ctx.clean(
                "no dangling service fingerprint observed",
                detail=(
                    f"matched {len(fingerprints)} service fingerprint(s) over "
                    f"{len(inventory.pages)} page(s)"
                ),
            )

    async def _cnames(self, ctx: CheckContext) -> dict[str, str]:
        """``{host: cname}`` from the dns OSINT provider, or ``{}`` when it is unavailable."""
        access, _skipped = require_osint(ctx, "dns")
        if access is None:
            return {}
        result: dict[str, str] = {}
        hosts: dict[str, None] = {}
        inventory = ctx.web
        if isinstance(inventory, WebInventory):
            for page in inventory.pages.values():
                host = urlsplit(page.url).hostname
                if host:
                    hosts.setdefault(host, None)
        for host in list(hosts)[: ctx.config.web.takeover_max_names]:
            try:
                payload = await access.get_json(
                    "dns", f"https://dns.google/resolve?name={quote(host, safe='')}&type=CNAME"
                )
            except Exception:  # noqa: S112 - a provider failure is data, not a check failure
                continue
            cname = _extract_cname(payload)
            if cname:
                result[host] = cname
        return result


def _extract_cname(payload: object) -> str | None:
    """A CNAME target from a DNS-over-HTTPS answer, whatever shape the provider returns."""
    if isinstance(payload, dict):
        answer = payload.get("Answer") or payload.get("answer")
        if isinstance(answer, list):
            for record in answer:
                if isinstance(record, dict) and str(record.get("type")) in {"CNAME", "5"}:
                    data = record.get("data") or record.get("target")
                    if data:
                        return str(data).rstrip(".")
        cname = payload.get("cname")
        if cname:
            return str(cname).rstrip(".")
    return None
