"""M4 file-exposure checks: env files, VCS metadata, backups, source maps, key material.

Five families, one method: request a path that should not be reachable, then decide
whether the answer *is* the file rather than the application's own not-found page. The
decision is made on three independent signals, because each one alone has a failure mode:

* a **marker** in the body (``APP_KEY=``, ``ref: refs/``, ``Index of``) — precise, but a
  soft-404 page that echoes the path can contain it;
* the **detector names** the HTTP client's redactor reports (``aws-access-key-id``,
  ``private-key``) — proof that credential material was present, without the value;
* the **shape** (binary payload, SQL dump signature, a JSON source map) — content only the
  real artifact has.

Every finding cites the exchange plus the not-found reference it was compared against, and
the artifact carries only names, counts and fingerprints. No secret value ever reaches a
check: the client redacted it before ``Page`` was built (F-08-04).
"""

from __future__ import annotations

import json
import re
from collections.abc import AsyncIterator
from urllib.parse import urljoin

from arachne.core.results import CheckResult
from arachne.core.target import TargetKind
from arachne.modules.base import CheckMetadata, Module
from arachne.modules.context import CheckContext
from arachne.modules.m3.inventory import Page, WebInventory, origin_of
from arachne.modules.m3.support import web_or_skip
from arachne.modules.m4.corpus import BackupSignature
from arachne.modules.m4.support import (
    UrlCheck,
    asset_origin,
    corpus_for,
    exchange_from_page,
    fetch_page,
    finding_cap,
    http_or_skip,
    is_catchall_page,
    looks_like_not_found,
    m4_candidate,
    not_found_for,
    owns_origin,
    probe_paths,
    secrets_in,
    skip,
    text_contains_any,
    wordlist,
)

__all__ = [
    "BackupFileHunt",
    "EnvFileProbe",
    "KeyExposure",
    "SourceMapExposure",
    "VcsExposure",
]


def _assignment_keys(body: str, assignment: re.Pattern[str] | None) -> tuple[str, ...]:
    """The ``KEY=`` names in a (redacted) env-style body — names only, never values."""
    if assignment is None:
        return ()
    found: dict[str, None] = {}
    for line in body.splitlines():
        stripped = line.strip()
        if assignment.search(stripped):
            name = stripped.split("=", 1)[0].strip()
            if name:
                found.setdefault(name, None)
    return tuple(found)


class EnvFileProbe(UrlCheck, Module):
    """``m4.env-file-probe`` — exposed ``.env``/configuration files (ch04#1)."""

    metadata = CheckMetadata(
        id="m4.env-file-probe",
        module="M4",
        name="env-file-probe",
        version="1.0",
        title="Exposed environment or configuration file",
        description=(
            "Requests the well-known environment and configuration paths (.env and its "
            "variants, wp-config.php, application.properties, config.yml, ...) and reports "
            "the ones that return a file instead of a not-found page. A hit is confirmed by "
            "credential-bearing key=value lines and by the redactor's detector names; the "
            "values themselves are redacted at capture time and never reach the check."
        ),
        research_ref="ch04#1",
        cwe="CWE-200",
        target_kinds=(TargetKind.URL,),
        severity_hint="high",
        type="hybrid",
        safe=True,
        verifiable=True,
        estimated_requests=8,
        runs_on_discovered=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        _client, skipped = http_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        if not owns_origin(ctx):
            yield skip(ctx, "another URL asset on this origin owns the M4 probes for it")
            return
        corpus = corpus_for(ctx)
        origin = asset_origin(ctx)
        not_found = await not_found_for(ctx, origin)
        paths = corpus.env_paths()
        if not paths:
            yield skip(ctx, "the M4 corpus names no environment-file paths")
            return
        assignment = corpus.env_assignment_regex()
        cap = finding_cap(ctx)
        findings = 0
        for probe in await probe_paths(ctx, origin, paths, not_found=not_found):
            page = probe.page
            if page is None or page.status >= 400:
                continue
            if looks_like_not_found(page, not_found):
                continue
            keys = _assignment_keys(page.body, assignment)
            detectors = secrets_in(page)
            marker = text_contains_any(page.body, corpus.env_markers())
            if not (marker or len(keys) >= 2 or (keys and detectors)):
                continue
            if page.body_length < corpus.env_min_bytes() and not marker:
                continue
            findings += 1
            yield m4_candidate(
                ctx,
                f"Environment file exposed: {probe.path}",
                artifact={
                    "signal": "exposed-env-file",
                    "family": "env",
                    "path": probe.path,
                    "status": page.status,
                    "content_type": page.content_type,
                    "bytes": page.body_length,
                    "marker": marker,
                    "assignment_count": len(keys),
                    "assignment_keys": list(keys[:10]),
                    "detectors": list(detectors),
                    "origin": origin,
                    "not_found_status": None if not_found is None else not_found.status,
                },
                exchanges=(
                    exchange_from_page(page),
                    None if not_found is None else exchange_from_page(not_found),
                ),
                confidence=0.95 if detectors else (0.85 if marker else 0.7),
                detail=(
                    f"{probe.url} returned HTTP {page.status} with "
                    f"{len(keys)} credential-style assignment(s)"
                    + (f"; detectors: {', '.join(detectors)}" if detectors else "")
                ),
                source=probe.url,
            )
            if findings >= cap:
                break
        if not findings:
            yield ctx.clean(
                "no exposed configuration file found",
                detail=f"probed {len(paths)} environment/config paths on {origin}",
            )


class VcsExposure(UrlCheck, Module):
    """``m4.vcs-exposure`` — served ``.git``/``.svn``/``.hg`` metadata (ch04#2)."""

    metadata = CheckMetadata(
        id="m4.vcs-exposure",
        module="M4",
        name="vcs-exposure",
        version="1.0",
        title="Exposed version-control metadata",
        description=(
            "Probes /.git/HEAD, /.git/config, /.svn/entries, /.svn/wc.db and /.hg/requires "
            "and confirms the answer by its repository markers (a ref line, a [core] block, "
            "an SVN XML/entries body, a SQLite payload). It reports the exposure only; it "
            "does not download objects or reconstruct history."
        ),
        research_ref="ch04#2",
        cwe="CWE-538",
        target_kinds=(TargetKind.URL,),
        severity_hint="high",
        type="hybrid",
        safe=True,
        verifiable=True,
        estimated_requests=5,
        runs_on_discovered=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        _client, skipped = http_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        if not owns_origin(ctx):
            yield skip(ctx, "another URL asset on this origin owns the M4 probes for it")
            return
        corpus = corpus_for(ctx)
        origin = asset_origin(ctx)
        not_found = await not_found_for(ctx, origin)
        probes = corpus.vcs_probes()
        if not probes:
            yield skip(ctx, "the M4 corpus names no version-control probes")
            return
        cap = finding_cap(ctx)
        findings = 0
        for probe in await probe_paths(
            ctx, origin, [entry.path for entry in probes], not_found=not_found
        ):
            page = probe.page
            if page is None or page.status != 200:
                continue
            if looks_like_not_found(page, not_found):
                continue
            definition = next((item for item in probes if item.path == probe.path), None)
            markers = () if definition is None else definition.markers
            family = "vcs" if definition is None else definition.family
            marker = text_contains_any(page.body, markers)
            binary = page.body.startswith("[binary payload")
            # A VCS artifact is text with a marker, or a binary object (wc.db, pack file);
            # a plain HTML 200 without either is a soft-404 that slipped through.
            if not marker and not (binary and corpus.vcs_binary_exposed()):
                continue
            if not marker and page.content_type.startswith("text/html"):
                continue
            findings += 1
            yield m4_candidate(
                ctx,
                f"Version-control metadata exposed: {probe.path}",
                artifact={
                    "signal": "vcs-exposure",
                    "family": family,
                    "path": probe.path,
                    "status": page.status,
                    "content_type": page.content_type,
                    "bytes": page.body_length,
                    "marker": marker,
                    "binary": binary,
                    "origin": origin,
                    "history_mining": False,
                },
                exchanges=(
                    exchange_from_page(page),
                    None if not_found is None else exchange_from_page(not_found),
                ),
                confidence=0.95,
                detail=(
                    f"{probe.url} served {family} metadata"
                    + (f" (marker: {marker!r})" if marker else " (binary payload)")
                ),
                source=probe.url,
            )
            if findings >= cap:
                break
        if not findings:
            yield ctx.clean(
                "no version-control metadata exposed",
                detail=f"probed {len(probes)} VCS paths on {origin}",
            )


class BackupFileHunt(UrlCheck, Module):
    """``m4.backup-file-hunt`` — backup, dump and editor artifacts (ch04#3)."""

    metadata = CheckMetadata(
        id="m4.backup-file-hunt",
        module="M4",
        name="backup-file-hunt",
        version="1.0",
        title="Downloadable backup or dump file",
        description=(
            "Combines a bounded name list with backup/dump extensions under the usual "
            "backup directories and reports the artifacts that download. A hit is confirmed "
            "by the content's own signature (SQL statements, a dotenv body, source code), by "
            "an archive/database content type, or by a binary payload where the extension is "
            "binary by nature."
        ),
        research_ref="ch04#3",
        cwe="CWE-530",
        target_kinds=(TargetKind.URL,),
        severity_hint="high",
        type="hybrid",
        safe=True,
        verifiable=True,
        estimated_requests=20,
        runs_on_discovered=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        _client, skipped = http_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        if not owns_origin(ctx):
            yield skip(ctx, "another URL asset on this origin owns the M4 probes for it")
            return
        corpus = corpus_for(ctx)
        origin = asset_origin(ctx)
        not_found = await not_found_for(ctx, origin)
        candidates = _backup_candidates(ctx)
        if not candidates:
            yield skip(ctx, "the M4 corpus names no backup names or extensions")
            return
        signatures = corpus.backup_signatures()
        binary_extensions = corpus.backup_binary_extensions()
        cap = finding_cap(ctx)
        findings = 0
        for probe in await probe_paths(ctx, origin, candidates, not_found=not_found):
            page = probe.page
            if page is None or page.status >= 400:
                continue
            if looks_like_not_found(page, not_found):
                continue
            if is_catchall_page(page, not_found=not_found, root=_root_of(ctx, origin)):
                continue
            family, marker = _backup_family(page, signatures)
            extension = _extension_of(probe.path)
            binary = page.body.startswith("[binary payload")
            archive_type = page.content_type.lower().startswith(
                (
                    "application/zip",
                    "application/gzip",
                    "application/x-gzip",
                    "application/sql",
                    "application/x-sqlite3",
                    "application/octet-stream",
                )
            )
            if not (
                marker or family or (binary and extension in binary_extensions) or archive_type
            ):
                continue
            if page.body_length < corpus.backup_min_bytes() and not binary:
                continue
            findings += 1
            yield m4_candidate(
                ctx,
                f"Backup artifact downloadable: {probe.path.lstrip('/')}",
                artifact={
                    "signal": "backup-download",
                    "family": "backup",
                    "path": probe.path,
                    "extension": extension,
                    "content_family": family,
                    "marker": marker,
                    "status": page.status,
                    "content_type": page.content_type,
                    "bytes": page.body_length,
                    "binary": binary,
                    "detectors": list(secrets_in(page)),
                    "origin": origin,
                },
                exchanges=(
                    exchange_from_page(page),
                    None if not_found is None else exchange_from_page(not_found),
                ),
                confidence=0.9 if (marker or family) else 0.75,
                detail=(
                    f"{probe.url} returned HTTP {page.status} "
                    f"({page.content_type or 'unknown type'}, {page.body_length} bytes)"
                    + (f"; signature: {marker!r}" if marker else "")
                ),
                source=probe.url,
            )
            if findings >= cap:
                break
        if not findings:
            yield ctx.clean(
                "no downloadable backup artifact found",
                detail=f"probed {len(candidates)} backup-name candidates on {origin}",
            )


class SourceMapExposure(UrlCheck, Module):
    """``m4.sourcemap-exposure`` — JavaScript source maps (ch04#4)."""

    metadata = CheckMetadata(
        id="m4.sourcemap-exposure",
        module="M4",
        name="sourcemap-exposure",
        version="1.0",
        title="JavaScript source map exposed",
        description=(
            "Follows the sourceMappingURL reference of every JavaScript/CSS asset the crawl "
            "fetched, requests the map, and reports it when the document carries sources or "
            "sourcesContent. Recovered original sources and any secrets the redactor "
            "detected are reported by name, never by value."
        ),
        research_ref="ch04#4",
        cwe="CWE-540",
        target_kinds=(TargetKind.URL,),
        severity_hint="medium",
        type="hybrid",
        safe=True,
        verifiable=True,
        estimated_requests=6,
        runs_on_discovered=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        _client, skipped = http_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        inventory, skipped = web_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        assert isinstance(inventory, WebInventory)
        corpus = corpus_for(ctx)
        reference = corpus.sourcemap_reference_regex()
        if reference is None:
            yield skip(ctx, "the M4 corpus has no sourceMappingURL pattern")
            return
        origin = asset_origin(ctx)
        script_pages = [
            page
            for page in inventory.pages.values()
            if origin_of(page.url) == origin
            and page.url.split("?")[0].endswith((".js", ".mjs", ".css"))
        ]
        if not script_pages:
            yield skip(ctx, "the crawl fetched no JavaScript or CSS asset to inspect")
            return
        keys = corpus.sourcemap_document_keys()
        disclose = corpus.sourcemap_disclose_keys()
        cap = finding_cap(ctx)
        findings = 0
        for page in script_pages[:8]:
            match = reference.search(page.body)
            if match is None:
                continue
            map_url = urljoin(page.url, match.group(1).strip().strip("'\""))
            map_page = await fetch_page(ctx, map_url)
            if map_page is None or map_page.status != 200:
                continue
            try:
                document = json.loads(map_page.body)
            except (json.JSONDecodeError, ValueError):
                document = None
            if not isinstance(document, dict) or not any(key in document for key in keys):
                continue
            sources = document.get("sources")
            source_count = len(sources) if isinstance(sources, list) else 0
            has_content = any(key in document for key in disclose)
            findings += 1
            await ctx.record_asset("url", map_page.url, source=self.metadata.id)
            yield m4_candidate(
                ctx,
                f"JavaScript source map served: {map_url.rsplit('/', 1)[-1]}",
                artifact={
                    "signal": "sourcemap-exposure",
                    "family": "sourcemap",
                    "script": page.url,
                    "map_url": map_page.url,
                    "status": map_page.status,
                    "source_count": source_count,
                    "sources_content": has_content,
                    "detectors": list(secrets_in(map_page)),
                    "bytes": map_page.body_length,
                },
                exchanges=(exchange_from_page(page), exchange_from_page(map_page)),
                confidence=0.9 if has_content else 0.75,
                detail=(
                    f"{map_url} is a source map with {source_count} source(s)"
                    + (" including sourcesContent" if has_content else "")
                ),
                source=map_page.url,
            )
            if findings >= cap:
                break
        if not findings:
            yield ctx.clean(
                "no exposed source map found",
                detail=f"inspected {min(len(script_pages), 8)} script/style asset(s) on {origin}",
            )


class KeyExposure(UrlCheck, Module):
    """``m4.key-exposure`` — private keys and keystores on the web root (ch04#15)."""

    metadata = CheckMetadata(
        id="m4.key-exposure",
        module="M4",
        name="key-exposure",
        version="1.0",
        title="Private key material exposed",
        description=(
            "Probes the well-known private-key and keystore paths and reports a reachable "
            "one when the response is PEM key material (the redactor's private-key detector "
            "fired), carries a PEM header, or is served with a key-file extension and a "
            "non-HTML content type. The key's contents never enter evidence."
        ),
        research_ref="ch04#15",
        cwe="CWE-321",
        target_kinds=(TargetKind.URL,),
        severity_hint="critical",
        type="hybrid",
        safe=True,
        verifiable=True,
        estimated_requests=8,
        runs_on_discovered=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        _client, skipped = http_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        if not owns_origin(ctx):
            yield skip(ctx, "another URL asset on this origin owns the M4 probes for it")
            return
        corpus = corpus_for(ctx)
        origin = asset_origin(ctx)
        not_found = await not_found_for(ctx, origin)
        paths = corpus.key_paths()
        if not paths:
            yield skip(ctx, "the M4 corpus names no key-material paths")
            return
        key_kind = corpus.key_secret_kind()
        pem_marker = corpus.key_pem_marker()
        extensions = tuple(ext.lower() for ext in corpus.key_extensions())
        cap = finding_cap(ctx)
        findings = 0
        for probe in await probe_paths(ctx, origin, paths, not_found=not_found):
            page = probe.page
            if page is None or page.status >= 400:
                continue
            if looks_like_not_found(page, not_found):
                continue
            detectors = secrets_in(page)
            pem = pem_marker in page.body
            extension = _extension_of(probe.path)
            key_extension = extension in extensions
            html = page.content_type.lower().startswith("text/html")
            if key_kind not in detectors and not pem and not (key_extension and not html):
                continue
            if not (key_kind in detectors or pem or key_extension) or (html and not pem):
                continue
            findings += 1
            yield m4_candidate(
                ctx,
                f"Private key served: {probe.path.lstrip('/')}",
                artifact={
                    "signal": "key-material",
                    "family": "key-material",
                    "path": probe.path,
                    "extension": extension,
                    "status": page.status,
                    "content_type": page.content_type,
                    "bytes": page.body_length,
                    "pem_present": pem,
                    "detectors": list(detectors),
                    "origin": origin,
                },
                exchanges=(
                    exchange_from_page(page),
                    None if not_found is None else exchange_from_page(not_found),
                ),
                confidence=0.95 if (key_kind in detectors or pem) else 0.7,
                detail=(
                    f"{probe.url} returned HTTP {page.status} "
                    f"({page.content_type or 'unknown type'})"
                    + ("; the response carried PEM private-key material" if pem else "")
                ),
                source=probe.url,
            )
            if findings >= cap:
                break
        if not findings:
            yield ctx.clean(
                "no private key material served",
                detail=f"probed {len(paths)} key-material paths on {origin}",
            )


# --------------------------------------------------------------------------- helpers
def _root_of(ctx: CheckContext, origin: str) -> Page | None:
    inventory = ctx.web
    if not isinstance(inventory, WebInventory):
        return None
    for page in inventory.pages.values():
        if origin_of(page.url) == origin:
            return page
    return None


def _extension_of(path: str) -> str:
    lowered = path.split("?")[0].lower()
    for candidate in (".tar.gz", ".sql.gz", ".sqlite", ".tgz"):
        if lowered.endswith(candidate):
            return candidate
    _, dot, extension = lowered.rpartition(".")
    return "" if not dot else f".{extension}"


def _backup_candidates(ctx: CheckContext) -> tuple[str, ...]:
    """Name x extension x directory candidates, interleaved so every directory is probed.

    The iteration order is deliberate: the first ``max_paths`` entries must cover the
    interesting names *and* the backup directories, not exhaust the root directory first.
    A ``db.sql`` candidate is therefore tried as ``db.sql``, ``backup/db.sql``,
    ``db/db.sql`` … before the second name is considered.
    """
    corpus = corpus_for(ctx)
    extensions = corpus.backup_extensions()
    directories = corpus.backup_directories() or ("",)
    names = wordlist(ctx, corpus.backup_names_wordlist(), limit=12)
    candidates: list[str] = []
    seen: set[str] = set()

    def _add(value: str) -> None:
        normalized = "/" + value.lstrip("/")
        if normalized not in seen:
            seen.add(normalized)
            candidates.append(normalized)

    # 1. The priority list: what an exposed web root actually leaks.
    for candidate in corpus.backup_priority():
        _add(candidate)
    # 2. The systematic expansion, directory-major inside a name so every backup
    #    directory is reached before the cap bites.
    for name in names:
        for directory in directories:
            for extension in extensions:
                _add(f"{directory}{name}{extension}")
    return tuple(candidates[: ctx.config.m4.max_paths])


def _backup_family(
    page: Page, signatures: tuple[BackupSignature, ...]
) -> tuple[str | None, str | None]:
    """The content family and the marker that proves it (see ``backup.signatures``)."""
    lowered = page.body.lower()
    for signature in signatures:
        for marker in signature.markers:
            if marker.lower() in lowered:
                return signature.family, marker
    return None, None
