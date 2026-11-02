"""M1 exposure checks: search the indexes for what should not be public (ch01).

Three checks that query a search surface *about* an organization rather than a target host:

* :class:`DorkSweep` — a versioned dork corpus (research ch01 method 1) run against a
  configured search API, diffed into the asset/exposure ledger.
* :class:`CodeSecretMining` — committed credentials in public code hosts (method 2). Opt-in
  and budgeted, because it needs a token and can fan out.
* :class:`EmailHarvest` — employee addresses and the organization's naming pattern
  (method 17), the input to credential-reuse and phishing-risk scoring.

All three emit candidates rather than pronouncements: "a search index returned a `.env`
document" is a lead, and the analyzer decides what it means (ADR-02).
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator, Mapping, Sequence
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path
from typing import Any

import yaml

from arachne.core.errors import ConfigurationError, OsintError
from arachne.core.results import CheckResult
from arachne.core.target import TargetKind
from arachne.modules.base import CheckMetadata, Module
from arachne.modules.context import CheckContext, require_osint
from arachne.modules.extract import detect_secrets, extract_emails
from arachne.modules.providers.sources import (
    SearchHit,
    github_code_search_url,
    parse_github_code_search,
    parse_search_results,
    search_url_for,
)

__all__ = ["CodeSecretMining", "DorkEntry", "DorkSweep", "EmailHarvest", "load_dork_corpus"]

_DOMAIN_KINDS = (TargetKind.DOMAIN, TargetKind.DOMAIN_PATTERN)

#: Location of the shipped dork corpus, relative to the ``arachne.templates`` package.
DEFAULT_DORK_RESOURCE = ("dorks", "m1-dorks.yaml")

_PATTERN_LABEL = re.compile(r"^[a-z][a-z0-9_.-]*$")


@dataclass(frozen=True, slots=True)
class DorkEntry:
    """One dork: a query template (``{domain}`` is substituted) and what it is looking for."""

    id: str
    category: str
    query: str
    description: str = ""
    #: True when a hit means "this should not have been indexed" rather than "mention found".
    exposure: bool = False


def _parse_dork_corpus(data: Any, *, source: str) -> tuple[str, tuple[DorkEntry, ...]]:
    if not isinstance(data, Mapping):
        msg = f"{source}: expected a mapping at the top level"
        raise ConfigurationError(msg)
    version = str(data.get("corpus_version") or "1.0")
    raw = data.get("dorks")
    if not isinstance(raw, list) or not raw:
        msg = f"{source}: 'dorks' must be a non-empty list"
        raise ConfigurationError(msg)
    entries: list[DorkEntry] = []
    seen: set[str] = set()
    for index, item in enumerate(raw):
        if not isinstance(item, Mapping):
            msg = f"{source}: dork {index} is not a mapping"
            raise ConfigurationError(msg)
        try:
            entry = DorkEntry(
                id=str(item["id"]),
                category=str(item["category"]),
                query=str(item["query"]),
                description=str(item.get("description") or ""),
                exposure=bool(item.get("exposure", False)),
            )
        except KeyError as exc:
            msg = f"{source}: dork {index} is missing {exc.args[0]!r}"
            raise ConfigurationError(msg) from exc
        if not _PATTERN_LABEL.match(entry.id):
            msg = f"{source}: dork id {entry.id!r} is not a kebab-case identifier"
            raise ConfigurationError(msg)
        if "{domain}" not in entry.query:
            msg = f"{source}: dork {entry.id!r} must contain the '{{domain}}' placeholder"
            raise ConfigurationError(msg)
        if entry.id in seen:
            msg = f"{source}: duplicate dork id {entry.id!r}"
            raise ConfigurationError(msg)
        seen.add(entry.id)
        entries.append(entry)
    return version, tuple(entries)


def load_dork_corpus(path: str | Path | None = None) -> tuple[str, tuple[DorkEntry, ...]]:
    """Load the dork corpus: a project file when configured, else the shipped corpus."""
    if path is None:
        resource = files("arachne.templates")
        for part in DEFAULT_DORK_RESOURCE:
            resource = resource.joinpath(part)
        try:
            text = resource.read_text(encoding="utf-8")
        except (FileNotFoundError, OSError) as exc:  # pragma: no cover - packaging failure
            msg = f"bundled dork corpus is missing ({'/'.join(DEFAULT_DORK_RESOURCE)}): {exc}"
            raise ConfigurationError(msg) from exc
        source = "bundled dork corpus"
    else:
        resolved = Path(path).expanduser()
        if not resolved.is_file():
            msg = f"dork corpus {resolved} does not exist or is not a file"
            raise ConfigurationError(msg)
        try:
            text = resolved.read_text(encoding="utf-8")
        except OSError as exc:
            raise ConfigurationError(f"cannot read dork corpus {resolved}: {exc}") from exc
        source = str(resolved)
    try:
        data = yaml.safe_load(text)  # F-08-06: safe_load only
    except yaml.YAMLError as exc:
        raise ConfigurationError(f"{source}: not valid YAML: {exc}") from exc
    return _parse_dork_corpus(data, source=source)


class DorkSweep(Module):
    """``m1.dork-sweep`` — run the dork corpus against a search API (research ch01#1)."""

    metadata = CheckMetadata(
        id="m1.dork-sweep",
        module="M1",
        name="dork-sweep",
        version="1.0",
        title="Search-engine dork sweep",
        description=(
            "Runs the versioned dork corpus (GHDB-aligned) against the configured search API "
            "and records which queries surface indexed material for the target."
        ),
        research_ref="ch01#1",
        framework=("WSTG-INFO-01", "CWE-200"),
        cwe="CWE-200",
        target_kinds=_DOMAIN_KINDS,
        severity_hint="low",
        type="passive",
        verifiable=True,
        estimated_requests=4,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        name = ctx.asset.query_name
        if not name:
            yield ctx.skipped(f"asset {ctx.asset.key} has no queryable name")
            return
        osint, skip = require_osint(ctx, "search")
        if skip is not None:
            yield skip
            return
        assert osint is not None
        search_url = ctx.config.search_url
        if not search_url:
            yield ctx.skipped(
                "no search endpoint is configured "
                "(set ARACHNE_OSINT_SEARCH_URL to a search API that returns JSON results)"
            )
            return

        try:
            corpus_version, entries = load_dork_corpus(ctx.config.dork_corpus)
        except ConfigurationError as exc:
            yield ctx.error(exc)
            return

        hits_by_dork: dict[DorkEntry, tuple[SearchHit, ...]] = {}
        failures: list[str] = []
        queried = 0
        for entry in entries:
            if not osint.can_spend():
                break
            url = search_url_for(
                search_url,
                entry.query.format(domain=name),
                limit=ctx.config.max_results,
            )
            try:
                response = await osint.fetch("search", url)
            except OsintError as exc:
                failures.append(f"{entry.id}: {exc}")
                continue
            queried += 1
            if not response.ok:
                failures.append(f"{entry.id}: HTTP {response.status}")
                continue
            hits = parse_search_results(response.json(), limit=ctx.config.max_results)
            if hits:
                hits_by_dork[entry] = hits

        exposure_hits = {entry: hits for entry, hits in hits_by_dork.items() if entry.exposure}
        if not hits_by_dork:
            yield ctx.clean(
                f"the dork sweep found nothing indexed for {name}",
                detail=(
                    f"{queried} dork(s) from corpus {corpus_version} returned no results"
                    + (f"; failures: {'; '.join(failures)}" if failures else "")
                ),
                confidence=0.5,
            )
            return

        recorded = 0
        for hits in hits_by_dork.values():
            for hit in hits[: ctx.config.max_assets]:
                if await ctx.record_asset(
                    "url", hit.url, meta={"discovered_by": "dork-sweep"}, source="dork-sweep"
                ):
                    recorded += 1

        yield ctx.info(
            f"the dork sweep matched {len(hits_by_dork)} dork(s) for {name}",
            detail=(
                f"{queried} dork(s) from corpus {corpus_version}; {recorded} URL asset(s) "
                f"recorded; matched: {', '.join(entry.id for entry in list(hits_by_dork)[:20])}"
                + (f"; failures: {'; '.join(failures)}" if failures else "")
            ),
            evidence=[
                ctx.evidence(
                    "artifact",
                    {
                        "corpus_version": corpus_version,
                        "queries": [entry.query.format(domain=name) for entry in hits_by_dork],
                        "matches": {
                            entry.id: [hit.to_dict() for hit in hits[:10]]
                            for entry, hits in list(hits_by_dork.items())[:50]
                        },
                    },
                    source=name,
                )
            ],
            confidence=0.7,
        )

        for entry, hits in exposure_hits.items():
            yield ctx.candidate(
                f"search index exposes {entry.description} for {name}",
                detail=(
                    f"dork {entry.id!r} ({entry.query.format(domain=name)}) returned "
                    f"{len(hits)} result(s): " + ", ".join(hit.url for hit in hits[:5])
                ),
                evidence=[
                    ctx.evidence(
                        "artifact",
                        {
                            "dork": entry.id,
                            "category": entry.category,
                            "query": entry.query.format(domain=name),
                            "results": [hit.to_dict() for hit in hits[:20]],
                        },
                        source=name,
                    )
                ],
                confidence=0.5,
            )


class CodeSecretMining(Module):
    """``m1.code-secret-mining`` — committed credentials (research ch01#2)."""

    metadata = CheckMetadata(
        id="m1.code-secret-mining",
        module="M1",
        name="code-secret-mining",
        version="1.0",
        title="Public code-host secret mining",
        description=(
            "Queries a code-search API for configuration files and credentials referencing the "
            "target domain. Opt-in and token budgeted."
        ),
        research_ref="ch01#2",
        framework=("WSTG-INFO-01", "CWE-798"),
        cwe="CWE-798",
        target_kinds=(*_DOMAIN_KINDS, TargetKind.GIT),
        severity_hint="high",
        type="passive",
        verifiable=True,
        enabled_by_default=False,
        estimated_requests=3,
        requires_credentials=("github_token",),
    )

    #: What the search is looking for, in the vocabulary a code host understands.
    QUERY_TEMPLATES: tuple[tuple[str, str], ...] = (
        ("config-files", '"{domain}" filename:.env'),
        ("credentials", '"{domain}" (password OR api_key OR secret)'),
        ("private-keys", '"{domain}" filename:id_rsa'),
        ("cloud-keys", '"{domain}" (AKIA OR "aws_secret_access_key")'),
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        name = ctx.asset.query_name
        if not name:
            yield ctx.skipped(f"asset {ctx.asset.key} has no queryable name")
            return
        if ctx.config.github_token is None:
            yield ctx.skipped(
                "code search needs a token in ARACHNE_GITHUB_TOKEN (opt-in check: F-02-09, F-08-01)"
            )
            return
        osint, skip = require_osint(ctx, "github")
        if skip is not None:
            yield skip
            return
        assert osint is not None
        headers = {"authorization": f"Bearer {ctx.config.github_token.get_secret_value()}"}

        per_query: dict[str, tuple[dict[str, str], ...]] = {}
        failures: list[str] = []
        for label, template in self.QUERY_TEMPLATES:
            if not osint.can_spend():
                failures.append("request budget exhausted")
                break
            query = template.format(domain=name)
            url = github_code_search_url(query, per_page=ctx.config.max_results)
            try:
                response = await osint.fetch("github", url, headers=headers)
            except OsintError as exc:
                failures.append(f"{label}: {exc}")
                continue
            if not response.ok:
                failures.append(f"{label}: HTTP {response.status}")
                continue
            matches = parse_github_code_search(response.json(), limit=ctx.config.max_results)
            if matches:
                per_query[label] = matches

        if not per_query:
            yield ctx.clean(
                f"no committed material referencing {name} found in public code search",
                detail=(
                    f"{len(self.QUERY_TEMPLATES)} query class(es) returned nothing"
                    + (f"; failures: {'; '.join(failures)}" if failures else "")
                ),
                confidence=0.4,
            )
            return

        for label, matches in per_query.items():
            # The search API returns paths, not file bodies, so the candidate is "this file
            # is committed and reachable" — extracting the value itself is a separate,
            # deeper step (secret scan at scale).
            secrets = [
                found for match in matches for found in detect_secrets(" ".join(match.values()))
            ]
            yield ctx.candidate(
                f"public code search matched {len(matches)} file(s) for {name} ({label})",
                detail=(
                    "Files matching the query class are indexed in a public code host; "
                    "each one needs review before it is treated as a live credential. "
                    + "; ".join(
                        f"{match.get('repository')}/{match.get('path')}" for match in matches[:5]
                    )
                ),
                evidence=[
                    ctx.evidence(
                        "artifact",
                        {
                            "query_class": label,
                            "matches": [dict(match) for match in matches[:20]],
                            "path_patterns": [s.to_dict() for s in secrets[:10]],
                        },
                        source=name,
                    )
                ],
                confidence=0.55 if label in {"config-files", "credentials"} else 0.5,
            )


class EmailHarvest(Module):
    """``m1.email-harvest`` — employee addresses and naming pattern (research ch01#17)."""

    metadata = CheckMetadata(
        id="m1.email-harvest",
        module="M1",
        name="email-harvest",
        version="1.0",
        title="Organization email harvesting",
        description=(
            "Searches the configured search API for addresses at the target domain and infers "
            "the organization's address-generation pattern."
        ),
        research_ref="ch01#17",
        framework=("WSTG-INFO-01",),
        target_kinds=_DOMAIN_KINDS,
        severity_hint="info",
        type="passive",
        verifiable=True,
        estimated_requests=3,
    )

    QUERY_TEMPLATES: tuple[str, ...] = (
        '"{domain}" email',
        '"@{domain}"',
        'site:pastebin.com "{domain}"',
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        name = ctx.asset.query_name
        if not name:
            yield ctx.skipped(f"asset {ctx.asset.key} has no queryable name")
            return
        osint, skip = require_osint(ctx, "search")
        if skip is not None:
            yield skip
            return
        assert osint is not None
        search_url = ctx.config.search_url
        if not search_url:
            yield ctx.skipped(
                "no search endpoint is configured "
                "(set ARACHNE_OSINT_SEARCH_URL to a search API that returns JSON results)"
            )
            return

        addresses: dict[str, None] = {}
        failures: list[str] = []
        for template in self.QUERY_TEMPLATES:
            if not osint.can_spend():
                break
            url = search_url_for(
                search_url,
                template.format(domain=name),
                limit=ctx.config.max_results,
            )
            try:
                response = await osint.fetch("search", url)
            except OsintError as exc:
                failures.append(f"{template}: {exc}")
                continue
            if not response.ok:
                failures.append(f"{template}: HTTP {response.status}")
                continue
            for hit in parse_search_results(response.json(), limit=ctx.config.max_results):
                for address in extract_emails(f"{hit.title}\n{hit.snippet}\n{hit.url}"):
                    addresses.setdefault(address, None)

        on_domain = [address for address in addresses if address.endswith(f"@{name}")]
        third_party = [address for address in addresses if not address.endswith(f"@{name}")]
        if not addresses:
            yield ctx.clean(
                f"no employee addresses found for {name}",
                detail=(
                    "the configured search API returned no address at this domain"
                    + (f"; failures: {'; '.join(failures)}" if failures else "")
                ),
                confidence=0.5,
            )
            return

        pattern = _infer_pattern(on_domain)
        yield ctx.info(
            f"email harvesting found {len(on_domain)} address(es) at {name}",
            detail=(
                f"{len(third_party)} unrelated address(es) seen in the same results"
                + (f"; inferred pattern: {pattern}" if pattern else "")
                + (f"; failures: {'; '.join(failures)}" if failures else "")
            ),
            evidence=[
                ctx.evidence(
                    "artifact",
                    {
                        "addresses": sorted(on_domain)[:200],
                        "third_party_addresses": sorted(third_party)[:100],
                        "inferred_pattern": pattern,
                    },
                    source=name,
                )
            ],
            confidence=0.75,
        )
        if on_domain:
            yield ctx.candidate(
                f"employee address pattern for {name} is publicly inferable",
                detail=(
                    f"{len(on_domain)} address(es) were harvestable from public sources"
                    + (f" and follow the pattern {pattern}" if pattern else "")
                    + "; harvested addresses feed credential-reuse and phishing risk (ch01 §17)"
                ),
                evidence=[
                    ctx.evidence(
                        "artifact",
                        {"addresses": sorted(on_domain)[:50], "pattern": pattern},
                        source=name,
                    )
                ],
                confidence=0.4,
            )


def _infer_pattern(addresses: Sequence[str]) -> str | None:
    """Infer the local-part shape shared by most addresses (``first.last``, ``f.last``).

    Each run of letters collapses to a single placeholder, so ``jane.doe`` and ``john.smith``
    are the same shape; a shape needs at least two samples before it is called a pattern,
    because one address is a sample, not an address-generation scheme.
    """
    shapes: dict[str, int] = {}
    for address in addresses:
        local = address.split("@", 1)[0].lower()
        shape = re.sub(r"\d+", "d", re.sub(r"[a-z]+", "x", local))
        shapes[shape] = shapes.get(shape, 0) + 1
    if not shapes:
        return None
    shape, count = max(shapes.items(), key=lambda item: item[1])
    if count < 2:
        return None
    named = {
        "x.x": "first.last",
        "x_x": "first_last",
        "x-x": "first-last",
        "xx": "firstinitiallastname",
        "x": "firstname",
        "x.d": "name.sequence",
        "x.xd": "name.sequence",
    }
    return named.get(shape, shape)
