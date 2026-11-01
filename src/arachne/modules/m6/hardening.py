"""M6 hardening checks: template matching, offline exploit matching and configuration-surface
credential hunting (research ch06#3, #5 and #17).

All three read what the scan already has or ships as managed data, and none performs an
exploitation action :

``m6.template-scan``
    A minimal, offline, *strictly a matcher* pass over the served origin: it loads simple
    path + body-marker templates from the managed corpus, requests each template's path(s)
    against the asset origin, and flags a body whose markers match (ch06#3). There is no
    templating engine and no code execution.
``m6.exploit-match``
    Matches the estate's observed software banners / CVE ids against a compact offline
    ExploitDB-style N-day index and reports the *mapped exploit/PoC reference* as a candidate
    when a banner matches (ch06#5). Matching only; nothing is exploited.
``m6.credential-hunt``
    Hunts credentials in reachable configuration surfaces — the crawled pages/inventory plus a
    bounded set of ``.env``-style paths — reusing the shared secret detectors and reporting
    the detector *name* and a masked fingerprint, never a raw value (ch06#17).
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator, Mapping
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

from arachne.core.errors import ConfigurationError
from arachne.core.redaction import mask_secret
from arachne.core.results import CheckResult
from arachne.core.target import TargetKind
from arachne.modules.base import Asset, CheckMetadata, Module
from arachne.modules.context import CheckContext
from arachne.modules.m2.catalog import VersionConstraint, normalize_product, version_matches
from arachne.modules.m5.support import (
    endpoint_base,
    fetch_page,
    http_or_skip,
    text_contains_any,
)
from arachne.modules.m6.corpus import M6Corpus, Signature, TemplateSpec
from arachne.modules.m6.support import (
    corpus_for,
    finding_cap,
    m6_candidate,
    resolved_services,
    skip,
)

__all__ = [
    "CredentialHunt",
    "ExploitEntry",
    "ExploitMatch",
    "TemplateScan",
    "load_exploit_index",
]

#: Bundled exploit index resource (relative to ``templates/``).
_EXPLOIT_RESOURCE: tuple[str, ...] = ("m6", "exploit-index.yaml")

#: How many configuration paths ``m6.credential-hunt`` probes (read-only GET).
_MAX_SURFACE_PROBES = 4

#: How many banner fetches ``m6.exploit-match`` may make when nothing is in context.
_MAX_BANNER_FETCHES = 2


# --------------------------------------------------------------------------- template scan
class TemplateScan(Module):
    """``m6.template-scan`` — path + marker matcher over the served origin (ch06#3)."""

    metadata = CheckMetadata(
        id="m6.template-scan",
        module="M6",
        name="template-scan",
        version="1.0",
        title="Template-driven exposure match",
        description=(
            "A minimal, offline matcher: loads simple path + body-marker templates from the "
            "managed corpus, requests each template's path(s) against the asset origin and "
            "flags a response whose status and body markers match (research ch06#3). Strictly "
            "a matcher — no templating engine, no code execution, GET only."
        ),
        research_ref="ch06#3",
        cwe="CWE-200",
        target_kinds=(TargetKind.URL,),
        severity_hint="medium",
        type="hybrid",
        safe=True,
        verifiable=True,
        estimated_requests=10,
        runs_on_discovered=True,
    )

    def supports(self, asset: Asset) -> bool:
        if not Module.supports(self, asset):
            return False
        return asset.kind == "url" and asset.value.lower().startswith(("http://", "https://"))

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        _client, skipped = http_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        corpus = corpus_for(ctx)
        templates = corpus.matcher_templates()
        if not templates:
            yield skip(ctx, "no matcher templates in the M6 corpus")
            return
        base = endpoint_base(ctx)
        if base is None:
            yield skip(ctx, "no origin to match templates against (declare a URL asset)")
            return
        findings = 0
        for template in templates:
            hit = await self._match_template(ctx, template, base)
            if hit is None:
                continue
            findings += 1
            title, artifact, confidence, detail, source = hit
            yield m6_candidate(
                ctx,
                title,
                artifact=artifact,
                exchanges=(),
                cwe="CWE-200",
                confidence=confidence,
                detail=detail,
                source=source,
            )
            if findings >= finding_cap(ctx):
                return
        if not findings:
            yield ctx.clean(
                f"no template matched ({len(templates)} template(s) tried)",
                detail="no served path carried a template's status and body markers",
            )

    async def _match_template(
        self, ctx: CheckContext, template: TemplateSpec, base: str
    ) -> tuple[str, dict[str, Any], float, str, str] | None:
        markers = tuple(marker.lower() for marker in template.markers)
        status = set(template.status) if template.status else {200}
        for path in template.paths:
            url = base.rstrip("/") + path
            page = await fetch_page(ctx, url)
            if page is None or page.status not in status:
                continue
            if not markers:
                continue
            lowered = page.body.lower()
            if template.match == "all":
                matched = all(marker in lowered for marker in markers)
                marker = markers[0] if matched else None
            else:
                marker = text_contains_any(page.body, markers)
                matched = marker is not None
            if not matched:
                continue
            artifact = {
                "signal": "template-match",
                "family": "template",
                "template": template.id,
                "severity_hint": template.severity,
                "endpoint": url,
                "path": path,
                "status": page.status,
                "marker": marker,
                "reference": template.reference,
            }
            detail = template.hint or f"template {template.id} matched the served response"
            return (
                f"Template '{template.id}' matched at {path}",
                artifact,
                0.8,
                f"{url}: {detail}",
                url,
            )
        return None


# --------------------------------------------------------------------------- exploit match
@dataclass(frozen=True, slots=True)
class ExploitEntry:
    """One row of the offline exploit index (a product/CVE mapped to a public exploit)."""

    product: str
    aliases: tuple[str, ...]
    constraints: tuple[VersionConstraint, ...]
    cve: str | None
    exploit_ref: str
    severity: str
    cwe: str | None
    title: str
    references: tuple[str, ...]

    def product_names(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys([self.product, *self.aliases]))


def _read_exploit_text(name: str | None) -> tuple[str, str]:
    filename = name or _EXPLOIT_RESOURCE[-1]
    candidate = Path(filename).expanduser()
    if candidate.is_file():
        return candidate.read_text(encoding="utf-8"), str(candidate)
    node = files("arachne.templates")
    for part in (*_EXPLOIT_RESOURCE[:-1], filename):
        node = node.joinpath(part)
    try:
        return node.read_text(encoding="utf-8"), f"bundled {filename}"
    except (FileNotFoundError, OSError) as exc:  # pragma: no cover - packaging failure
        raise ConfigurationError(f"bundled exploit index is missing ({filename}): {exc}") from exc


def _exploit_constraints(affected: Any) -> tuple[VersionConstraint, ...]:
    parsed: list[VersionConstraint] = []
    if not isinstance(affected, (list, tuple)):
        return ()
    for item in affected:
        if isinstance(item, str):
            text = item.strip()
            parsed.append(
                VersionConstraint(op="all")
                if text == "all"
                else VersionConstraint(op="==", version=text)
            )
            continue
        if not isinstance(item, Mapping):
            continue
        op = str(item.get("op", "")).strip()
        version = str(item.get("version", "")).strip()
        if op == "all":
            parsed.append(VersionConstraint(op="all"))
            continue
        if op == "=":
            op = "=="
        if not op or not version:
            continue
        parsed.append(VersionConstraint(op=op, version=version))
    return tuple(parsed)


def load_exploit_index(name: str | None = None) -> tuple[ExploitEntry, ...]:
    """Load the offline exploit index (a bundled file, or an operator file when it exists)."""
    text, source = _read_exploit_text(name)
    try:
        data = yaml.safe_load(text)  # F-08-06: safe_load only
    except yaml.YAMLError as exc:
        raise ConfigurationError(f"{source}: not valid YAML: {exc}") from exc
    if not isinstance(data, Mapping):
        raise ConfigurationError(f"{source}: expected a mapping at the top level")
    entries: list[ExploitEntry] = []
    for raw in data.get("entries") or ():
        if not isinstance(raw, Mapping) or not raw.get("product"):
            continue
        exploit_ref = str(raw.get("exploit_ref") or raw.get("exploit") or "").strip()
        if not exploit_ref:
            continue
        entries.append(
            ExploitEntry(
                product=str(raw["product"]),
                aliases=tuple(str(item) for item in raw.get("aliases") or ()),
                constraints=_exploit_constraints(raw.get("affected")),
                cve=str(raw["cve"]).upper() if raw.get("cve") else None,
                exploit_ref=exploit_ref,
                severity=str(raw.get("severity", "medium")),
                cwe=str(raw["cwe"]) if raw.get("cwe") else None,
                title=str(raw.get("title", raw["product"])),
                references=tuple(str(item) for item in raw.get("references") or ()),
            )
        )
    return tuple(entries)


class ExploitMatch(Module):
    """``m6.exploit-match`` — offline N-day exploit matching (ch06#5)."""

    metadata = CheckMetadata(
        id="m6.exploit-match",
        module="M6",
        name="exploit-match",
        version="1.0",
        title="Known N-day exploit matches observed software",
        description=(
            "Matches the estate's observed software banners and CVE ids — from the network and "
            "web crawl already in the step context, or a bounded banner fetch — against a "
            "compact offline ExploitDB-style N-day index, and reports the mapped exploit/PoC "
            "reference as a candidate (research ch06#5). Matching only: no exploitation is "
            "performed."
        ),
        research_ref="ch06#5",
        cwe="CWE-1104",
        target_kinds=(TargetKind.URL, TargetKind.DOMAIN, TargetKind.IP),
        severity_hint="high",
        type="hybrid",
        safe=True,
        verifiable=False,
        estimated_requests=2,
        runs_on_discovered=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        corpus = corpus_for(ctx)
        index = load_exploit_index(corpus.exploit_index_resource())
        rows = await self._rows(ctx)
        if not rows:
            yield skip(
                ctx,
                "no software banner or version to match: M2 ran no version detection and no "
                "ARACHNE_M6_RESOLVED_VERSIONS export was configured",
            )
            return
        matches: list[tuple[dict[str, Any], ExploitEntry]] = []
        for row in rows:
            for entry in index:
                if not _entry_matches(entry, row):
                    continue
                matches.append((row, entry))
                break
        if not matches:
            yield ctx.info(
                "No N-day exploit match in the offline index",
                detail=f"{len(rows)} observed product(s)/version(s) matched no exploit entry",
            )
            return
        for position, (row, entry) in enumerate(matches, start=1):
            yield m6_candidate(
                ctx,
                f"{entry.exploit_ref}: {entry.title}",
                artifact={
                    "signal": "exploit-match",
                    "family": "exploit",
                    "exploit_ref": entry.exploit_ref,
                    "cve": entry.cve,
                    "product": row.get("product"),
                    "version": row.get("version"),
                    "asset": row.get("host"),
                    "source": row.get("source"),
                    "severity_hint": entry.severity,
                    "references": list(entry.references),
                },
                cwe=entry.cwe or "CWE-1104",
                confidence=0.7,
                detail=(
                    f"{row.get('product') or row.get('cve')} "
                    f"{row.get('version') or ''} on {row.get('host') or 'the estate'} maps to "
                    f"{entry.exploit_ref} ({entry.cve or 'no CVE'}) — matching only"
                ),
                source=str(row.get("host") or row.get("product") or ""),
            )
            if position >= finding_cap(ctx):
                return

    async def _rows(self, ctx: CheckContext) -> tuple[dict[str, Any], ...]:
        rows: list[dict[str, Any]] = []
        seen: set[tuple[str, str, str, str]] = set()
        host = ctx.asset.host
        for source_row in resolved_services(ctx):
            product = (
                source_row.get("product") or source_row.get("service") or source_row.get("name")
            )
            version = source_row.get("version")
            cve = source_row.get("cve")
            if not product and not cve:
                continue
            row_host = str(source_row.get("host") or source_row.get("asset") or "")
            if not _host_matches(row_host, host):
                continue
            key = (str(product or "").lower(), str(version or ""), row_host, str(cve or ""))
            if key in seen:
                continue
            seen.add(key)
            rows.append(
                {
                    "product": str(product) if product else "",
                    "version": str(version) if version else "",
                    "host": row_host,
                    "cve": str(cve).upper() if cve else None,
                    "source": "fingerprint",
                }
            )
        inventory = ctx.web
        if inventory is not None:
            for page in inventory.pages.values():
                if host and urlsplit(page.url).hostname != host:
                    continue
                server = page.header("server")
                if not server:
                    continue
                product, version = _split_banner(server)
                if not product:
                    continue
                key = (product.lower(), version or "", page.host, "")
                if key in seen:
                    continue
                seen.add(key)
                rows.append(
                    {
                        "product": product,
                        "version": version or "",
                        "host": page.host,
                        "cve": None,
                        "source": "web-server",
                    }
                )
        if not rows and ctx.http is not None:
            for row in await self._banner_fetch(ctx):
                rows.append(row)
        return tuple(rows)

    async def _banner_fetch(self, ctx: CheckContext) -> tuple[dict[str, Any], ...]:
        base = endpoint_base(ctx)
        if base is None:
            return ()
        out: list[dict[str, Any]] = []
        for url in (base, base.rstrip("/") + "/"):
            if len(out) >= _MAX_BANNER_FETCHES:
                break
            page = await fetch_page(ctx, url)
            if page is None:
                continue
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
                    "cve": None,
                    "source": "banner-fetch",
                }
            )
            break
        return tuple(out)


# --------------------------------------------------------------------------- credential hunt
class CredentialHunt(Module):
    """``m6.credential-hunt`` — credentials in reachable configuration surfaces (ch06#17)."""

    metadata = CheckMetadata(
        id="m6.credential-hunt",
        module="M6",
        name="credential-hunt",
        version="1.0",
        title="Credentials in reachable configuration surfaces",
        description=(
            "Hunts credentials in reachable configuration surfaces: the crawled pages/inventory "
            "the step already has plus a bounded set of .env-style paths (web.config, "
            "appsettings.json, docker-compose.yml, application.properties, shell rc files, "
            "backups), reusing the shared secret detectors and reporting the detector name and "
            "a masked fingerprint — never a raw value (research ch06#17). GET only."
        ),
        research_ref="ch06#17",
        cwe="CWE-798",
        target_kinds=(TargetKind.URL,),
        severity_hint="high",
        type="hybrid",
        safe=True,
        verifiable=True,
        estimated_requests=4,
        runs_on_discovered=True,
    )

    def supports(self, asset: Asset) -> bool:
        if not Module.supports(self, asset):
            return False
        return asset.kind == "url" and asset.value.lower().startswith(("http://", "https://"))

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        if ctx.http is None and ctx.web is None:
            yield skip(
                ctx,
                "no HTTP client or web inventory in this run: the credential hunt needs the "
                "crawl or a live scan (a dry run sends nothing — F-01-10)",
            )
            return
        corpus = corpus_for(ctx)
        detectors = corpus.secret_detectors()
        surfaces = await self._surfaces(ctx, corpus)
        if not surfaces:
            yield skip(ctx, "no configuration surface could be reached or crawled")
            return
        findings = 0
        for label, text in surfaces:
            hits = _scan_credentials(text, detectors)
            if not hits:
                continue
            findings += 1
            yield m6_candidate(
                ctx,
                f"Credentials in configuration surface: {label}",
                artifact={
                    "signal": "config-credential",
                    "family": "credentials",
                    "location": label,
                    "detectors": [kind for kind, _masked in hits],
                    "masked": [masked for _kind, masked in hits],
                },
                cwe="CWE-798",
                confidence=0.8,
                detail=(
                    f"{label} exposes credential-shaped values ({', '.join(k for k, _ in hits)}); "
                    "values are masked"
                ),
                source=label,
            )
            if findings >= finding_cap(ctx):
                return
        if not findings:
            yield ctx.clean(
                f"no credential found in {len(surfaces)} configuration surface(s)",
                detail="the shared detectors matched nothing in the crawled or probed configs",
            )

    async def _surfaces(self, ctx: CheckContext, corpus: M6Corpus) -> tuple[tuple[str, str], ...]:
        surfaces: list[tuple[str, str]] = []
        seen: set[str] = set()
        host = ctx.asset.host
        inventory = ctx.web
        if inventory is not None:
            for page in inventory.pages.values():
                if host and urlsplit(page.url).hostname != host:
                    continue
                if page.url in seen:
                    continue
                seen.add(page.url)
                surfaces.append((page.url, page.body))
        base = endpoint_base(ctx)
        if base is not None and ctx.http is not None:
            probed = 0
            for path in corpus.credential_surface_paths():
                if probed >= _MAX_SURFACE_PROBES:
                    break
                url = base.rstrip("/") + path
                if url in seen:
                    continue
                seen.add(url)
                probed += 1
                page = await fetch_page(ctx, url)
                if page is None or page.status != 200:
                    continue
                surfaces.append((url, page.body))
        return tuple(surfaces)


# --------------------------------------------------------------------------- helpers
def _host_matches(row_host: str, asset_host: str | None) -> bool:
    if not row_host or not asset_host:
        return True
    lowered = row_host.lower()
    wanted = asset_host.lower()
    return lowered == wanted or lowered.startswith(wanted + ":")


def _entry_matches(entry: ExploitEntry, row: Mapping[str, Any]) -> bool:
    cve = row.get("cve")
    if cve and entry.cve and str(cve).upper() == entry.cve:
        return True
    product = row.get("product")
    if not product:
        return False
    names = {normalize_product(name) for name in entry.product_names()}
    if normalize_product(str(product)) not in names:
        return False
    version = str(row.get("version") or "")
    if version:
        return version_matches(version, entry.constraints, accept_all=False)
    return any(constraint.op == "all" for constraint in entry.constraints)


def _split_banner(server: str) -> tuple[str | None, str | None]:
    match = re.match(r"\s*([A-Za-z][A-Za-z0-9._\-]*)/([0-9][0-9A-Za-z.\-]*)", server)
    if match:
        return match.group(1), match.group(2)
    token = server.strip().split()[0] if server.strip() else ""
    return (token, None) if token else (None, None)


def _scan_credentials(text: str, detectors: tuple[Signature, ...]) -> tuple[tuple[str, str], ...]:
    """``((detector kind, masked fingerprint), ...)`` — deduped per kind, first hit only."""
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for signature in detectors:
        kind = signature.kind or signature.id
        if kind in seen:
            continue
        match = signature.regex.search(text)
        if match is None:
            continue
        value = match.group(1) if match.groups() else match.group(0)
        seen.add(kind)
        out.append((kind, mask_secret(value)))
    return tuple(out)
