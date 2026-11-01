"""Shared M4 check plumbing: applicability, probes, classification and evidence.

M4's checks are a family of *probes for things that should not be reachable*: an exposed
configuration file, version-control metadata, a backup dump, a debug console, a dashboard,
a public bucket. They share almost all of their machinery — one bounded GET/HEAD path
probe, one learned "what does this application's 404 look like?" reference, one candidate
shape whose artifact carries the detector facts a heuristic rule reads — so that
machinery lives here and the checks read as a catalogue of mistakes.

Three rules this module exists to enforce:

* **Read-only.** Every M4 request is a GET, HEAD or (for the verb check) OPTIONS/
  PROPFIND/TRACE; the only POST is ``m4.default-credentials``, which is inert unless three
  separate switches are on. Nothing is uploaded, deleted or modified.
* **Nothing is sent in a dry run.** ``ctx.http is None`` turns every probe into a
  ``skipped`` result (F-01-10), exactly as in M3.
* **Secrets are never values.** The HTTP client redacts at capture time and reports which
  detectors fired; a check reads ``Page.secret_kinds`` and passes *names* into the
  artifact. The operator's encrypted ledger is fed by the client, not by a check
  (F-08-04, ADR-120.6).
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from functools import lru_cache
from typing import Any
from urllib.parse import urlsplit

from arachne.core.http import HttpExchange
from arachne.core.results import CheckResult
from arachne.modules.base import Asset
from arachne.modules.context import CheckContext
from arachne.modules.m3.inventory import (
    Page,
    WebInventory,
    normalize_body,
    origin_of,
    page_from_exchange,
)
from arachne.modules.m3.support import (
    artifact_evidence,
    exchange_from_page,
    http_or_skip,
    is_catchall,
    is_probably_not_found,
    nonce,
    owns_origin,
    safe_fetch,
    skip,
    text_ratio,
    web_candidate,
    web_or_skip,
)
from arachne.modules.m4.corpus import M4Corpus, load_corpus, load_wordlist

__all__ = [
    "BucketCheck",
    "M4Check",
    "Probe",
    "UrlCheck",
    "artifact_evidence",
    "asset_origin",
    "body_prefix",
    "corpus_for",
    "exchange_from_page",
    "fetch_page",
    "finding_cap",
    "host_of",
    "http_or_skip",
    "is_catchall_page",
    "is_denied",
    "is_not_found",
    "listing_entries",
    "looks_like_not_found",
    "not_found_for",
    "owns_origin",
    "pages_of_origin",
    "path_url",
    "probe_paths",
    "safe_fetch",
    "secrets_in",
    "similarity",
    "skip",
    "text_contains_any",
    "web_or_skip",
    "wordlist",
]

#: ``<a href="...">`` entries a directory listing publishes.
_LISTING_ENTRY_RE = re.compile(r"""<a\s+href=["\']([^"\'?#][^"\']*)["\']""", re.IGNORECASE)


# --------------------------------------------------------------------------- applicability
class UrlCheck:
    """M4's default applicability: one ``http(s)`` URL asset."""

    def supports(self, asset: Asset) -> bool:
        if not super().supports(asset):  # type: ignore[misc]
            return False
        return asset.kind == "url" and asset.value.lower().startswith(("http://", "https://"))


class BucketCheck:
    """A URL, cloud or bucket asset (the storage check derives a bucket from any of them)."""

    def supports(self, asset: Asset) -> bool:
        if not super().supports(asset):  # type: ignore[misc]
            return False
        if asset.kind in {"bucket", "cloud"}:
            return True
        return asset.kind == "url"


#: Kept as an alias so a check may mix in either name with the same meaning.
M4Check = UrlCheck


# --------------------------------------------------------------------------- corpus access
@lru_cache(maxsize=4)
def _corpus_cached(path: str | None) -> M4Corpus:
    return load_corpus(path)


def corpus_for(ctx: CheckContext) -> M4Corpus:
    """The M4 probe corpus (cached per path: parsing YAML per check would be wasteful)."""
    return _corpus_cached(ctx.config.m4_probes)


def wordlist(ctx: CheckContext, name: str, *, limit: int | None = None) -> tuple[str, ...]:
    """An M4 wordlist: the operator's directory wins over the packaged file (F-09-04)."""
    return load_wordlist(
        name,
        override_dir=ctx.config.m4_probes,
        limit=limit if limit is not None else ctx.config.m4.max_paths,
    )


# --------------------------------------------------------------------------- probe model
@dataclass(frozen=True, slots=True)
class Probe:
    """One path probe: what was requested, and what came back (``page is None`` = refused)."""

    path: str
    url: str
    page: Page | None

    @property
    def status(self) -> int | None:
        return None if self.page is None else self.page.status

    @property
    def reachable(self) -> bool:
        return self.page is not None and self.page.status < 400


def path_url(origin: str, path: str) -> str:
    """Join ``origin`` and ``path`` without doubling or dropping the separating slash."""
    if not path:
        return origin.rstrip("/") + "/"
    if path.startswith(("http://", "https://")):
        return path
    return origin.rstrip("/") + "/" + path.lstrip("/")


def host_of(value: str) -> str:
    parts = urlsplit(value)
    if parts.hostname:
        return parts.hostname.lower()
    return value.strip().lower()


def asset_origin(ctx: CheckContext) -> str:
    return origin_of(ctx.asset.value)


def pages_of_origin(inventory: WebInventory, origin: str) -> tuple[Page, ...]:
    return tuple(page for page in inventory.pages.values() if origin_of(page.url) == origin)


# --------------------------------------------------------------------------- requests
async def fetch_page(
    ctx: CheckContext,
    url: str,
    *,
    method: str = "GET",
    headers: Mapping[str, str] | None = None,
    content: bytes | str | None = None,
    session: bool = True,
    follow_redirects: bool | None = False,
) -> Page | None:
    """One bounded probe as a :class:`Page`, or ``None`` when it was refused/failed.

    ``content`` is the request body for the two M4 checks that POST (user enumeration and
    the opt-in default-credential verification); a GET probe leaves it ``None``.
    """
    exchange = await safe_fetch(
        ctx,
        url,
        method=method,
        headers=headers,
        content=content,
        session=session,
        follow_redirects=follow_redirects,
    )
    return None if exchange is None else page_from_exchange(exchange)


async def not_found_for(ctx: CheckContext, origin: str) -> Page | None:
    """The application's own not-found answer for ``origin`` (learned once per step)."""
    inventory = ctx.web
    if isinstance(inventory, WebInventory):
        cached = inventory.not_found_by_origin.get(origin)
        if cached is not None:
            return cached
        if inventory.not_found is not None and origin_of(inventory.not_found.url) == origin:
            inventory.not_found_by_origin[origin] = inventory.not_found
            return inventory.not_found
    page = await fetch_page(ctx, path_url(origin, f"{nonce()}-not-a-real-path"))
    if page is not None and isinstance(inventory, WebInventory):
        inventory.not_found_by_origin[origin] = page
    return page


def is_denied(page: Page | None) -> bool:
    return page is not None and page.status in {401, 403, 405, 501}


def is_not_found(page: Page, reference: Page | None) -> bool:
    """True when ``page`` is the application's own 404 (status + rendering)."""
    return is_probably_not_found(page, reference)


# --------------------------------------------------------------------------- classification
def text_contains_any(body: str, markers: Iterable[str]) -> str | None:
    """The first marker present in ``body`` (case-insensitive), or ``None``."""
    lowered = body.lower()
    for marker in markers:
        if marker and marker.lower() in lowered:
            return marker
    return None


def secrets_in(page: Page) -> tuple[str, ...]:
    """Which secret detectors fired on this page's raw body (never the values)."""
    return tuple(page.secret_kinds)


def listing_entries(body: str, *, limit: int = 20) -> tuple[str, ...]:
    """The entry names a directory listing publishes (bounded, deduplicated)."""
    found: dict[str, None] = {}
    for match in _LISTING_ENTRY_RE.finditer(body):
        entry = match.group(1).strip()
        if not entry or entry.startswith(("http://", "https://", "../")):
            continue
        found.setdefault(entry, None)
        if len(found) >= limit:
            break
    return tuple(found)


def similarity(page: Page, reference: Page | None) -> float:
    return 1.0 if reference is None else text_ratio(page.body, reference.body)


def is_catchall_page(page: Page, *, not_found: Page | None, root: Page | None) -> bool:
    return is_catchall(page, not_found=not_found, root=root)


# --------------------------------------------------------------------------- results
def finding_cap(ctx: CheckContext) -> int:
    return max(1, ctx.config.m4.max_findings_per_check)


def m4_candidate(
    ctx: CheckContext,
    title: str,
    *,
    artifact: Mapping[str, Any],
    exchanges: Iterable[HttpExchange | None] = (),
    cwe: str | None = None,
    confidence: float = 0.5,
    detail: str | None = None,
    source: str | None = None,
) -> CheckResult:
    """M4's candidate shape: the proving exchanges plus one machine-readable artifact.

    Reuses M3's :func:`web_candidate` so the evidence layout — request, response, and one
    ``artifact`` the rules read — is identical across the two modules, which is what lets a
    single rule corpus cover both.
    """
    return web_candidate(
        ctx,
        title,
        artifact=artifact,
        exchanges=exchanges,
        cwe=cwe,
        confidence=confidence,
        detail=detail,
        source=source,
    )


async def probe_paths(
    ctx: CheckContext,
    origin: str,
    paths: Sequence[str],
    *,
    limit: int | None = None,
    not_found: Page | None = None,
    method: str = "GET",
) -> list[Probe]:
    """Fetch ``paths`` under ``origin`` in order, bounded by ``limit``.

    A path whose answer is indistinguishable from the application's not-found page is
    returned as a probe with ``page`` set anyway: the *caller* decides what "exists" means
    for its family (a debug console, a listing, an env file), and hiding the page here would
    make a check unable to say why it rejected a candidate.
    """
    cap = limit if limit is not None else ctx.config.m4.max_paths
    probes: list[Probe] = []
    for entry in list(paths)[:cap]:
        url = path_url(origin, entry)
        page = await fetch_page(ctx, url, method=method)
        probes.append(Probe(path=entry, url=url, page=page))
    return probes


def listing_entries_default(body: str) -> tuple[str, ...]:
    return listing_entries(body)


def _norm(text: str) -> str:
    return normalize_body(text)


def body_prefix(page: Page, limit: int = 400) -> str:
    """A bounded, whitespace-normalized prefix used for fingerprints and artifacts."""
    return _norm(page.body)[:limit]


def looks_like_not_found(page: Page, reference: Page | None, *, threshold: float = 0.9) -> bool:
    if reference is None:
        return False
    if page.status != reference.status:
        return False
    return similarity(page, reference) >= threshold
