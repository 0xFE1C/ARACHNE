"""Shared M6 check plumbing: applicability, corpus access, artifact/state helpers, evidence.

M6's checks read three kinds of input, and this module gives each a single shape:

* **local artifacts** — a web root, a repository clone (working tree + git objects), a CI log
  directory, a BloodHound export, a honeytoken trigger log. Read with the M5 ``RepoCheck``
  helpers (``local_root``/``iter_repo_files``/``read_text``), never written.
* **the shared state earlier steps produced** — the web crawl (``ctx.web``) for served
  content and the discovery step's persisted inventory sample for service versions. No M6
  check ever builds its own inventory or network client.
* **managed feeds** — the EPSS/KEV snapshot, the LPE index and the Sigma rules, loaded through
  :mod:`arachne.modules.m6.feeds`.

The one non-obvious helper is :func:`estate_owner`: the patch-gap and log-hunting checks speak
about the *estate*, not about one asset, so a scan that declares five targets must not produce
five identical estate findings. ``estate_owner`` is true for exactly one declared asset per
scan (the lexicographically first), which makes the estate checks run once and their findings
deterministic.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from functools import lru_cache
from pathlib import Path
from typing import Any, Final

from arachne.core.planner import ScanStep
from arachne.core.results import CheckResult
from arachne.modules.base import Asset
from arachne.modules.context import CheckContext
from arachne.modules.m3.support import exchange_from_page, safe_fetch, web_candidate
from arachne.modules.m5.support import (
    EndpointCheck,
    RepoCheck,
    UrlCheck,
    artifact_evidence,
    iter_repo_files,
    local_root,
    read_text,
    skip,
)
from arachne.modules.m6.corpus import M6Corpus, load_corpus, load_wordlist

__all__ = [
    "EndpointCheck",
    "RepoCheck",
    "UrlCheck",
    "artifact_evidence",
    "corpus_for",
    "declared_assets",
    "estate_owner",
    "exchange_from_page",
    "finding_cap",
    "iter_repo_files",
    "local_root",
    "m6_candidate",
    "read_json",
    "read_text",
    "resolved_services",
    "safe_fetch",
    "skip",
    "wordlist",
]

#: Extension-less files a webshell check must still read when they sit in a web root.
_JSON_LIMIT: Final = 4 * 1024 * 1024


@lru_cache(maxsize=4)
def _corpus_cached(path: str | None) -> M6Corpus:
    return load_corpus(path)


def corpus_for(ctx: CheckContext) -> M6Corpus:
    """The M6 probe corpus (cached per path: parsing YAML per check would be wasteful)."""
    return _corpus_cached(ctx.config.m6_probes)


def wordlist(ctx: CheckContext, name: str, *, limit: int | None = None) -> tuple[str, ...]:
    """An M6 wordlist: the operator's directory wins over the packaged file (F-09-04)."""
    return load_wordlist(
        name,
        override_dir=ctx.config.m6_probes,
        limit=limit if limit is not None else ctx.config.m6.max_paths,
    )


def finding_cap(ctx: CheckContext) -> int:
    return max(1, ctx.config.m6.max_findings_per_check)


# --------------------------------------------------------------------------- estate helpers
def declared_assets(ctx: CheckContext) -> tuple[Asset, ...]:
    """The assets the target definition declared, as :class:`Asset` objects (best effort)."""
    try:
        records = ctx.step.store.list_assets(ctx.scan_id)
    except Exception:  # a store hiccup must not stop a check from running
        return ()
    return tuple(
        Asset.from_meta(record.kind, record.value, dict(record.meta))
        for record in records
        if record.meta.get("declared")
    )


def estate_owner(ctx: CheckContext) -> bool:
    """True for exactly one declared asset per scan — the estate checks' run gate.

    The patch-gap and log-hunting checks speak about the estate, so running them once per
    declared asset would duplicate identical findings. The owner is the lexicographically
    first declared asset of the scan (deterministic, no shared mutable state).
    """
    assets = declared_assets(ctx)
    if not assets:
        return True
    declared = sorted((asset.kind, asset.value) for asset in assets)
    current = (ctx.asset.kind, ctx.asset.value)
    if current not in declared:
        return False
    return current == declared[0]


def resolved_services(ctx: CheckContext) -> tuple[Mapping[str, Any], ...]:
    """Product/version rows for the estate: the discovery inventory plus an optional export.

    ``m2``'s discovery step persists a bounded ``identified_sample`` of the services it
    fingerprinted; that is the version source the patch-gap and LPE checks correlate against.
    When ``ARACHNE_M6_RESOLVED_VERSIONS`` names an export, its rows are added, so an operator
    can feed a richer asset/version inventory without M2 having fingerprinted it.
    """
    rows: list[Mapping[str, Any]] = []
    try:
        record = ctx.step.store.get_scan(ctx.scan_id)
    except Exception:
        record = None
    if record is not None:
        for step in record.steps:
            if step.step is not ScanStep.DISCOVERY:
                continue
            inventory = (step.stats or {}).get("inventory") or {}
            for item in inventory.get("identified_sample") or ():
                if isinstance(item, Mapping):
                    rows.append(item)
    for item in _export_rows(ctx.config.m6.resolved_versions):
        rows.append(item)
    return tuple(rows)


def _export_rows(path: str | None) -> tuple[Mapping[str, Any], ...]:
    if not path:
        return ()
    resolved = Path(path).expanduser()
    if not resolved.is_file():
        return ()
    try:
        data = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return ()
    if isinstance(data, Mapping):
        items: Any = data.get("assets") or data.get("services") or data.get("entries") or ()
    elif isinstance(data, list):
        items = data
    else:
        items = ()
    return tuple(item for item in items if isinstance(item, Mapping))


# --------------------------------------------------------------------------- local artifacts
def read_json(path: Path, *, limit: int = _JSON_LIMIT) -> Any:
    """Read and parse a JSON file, bounded; ``None`` when unreadable or not JSON."""
    try:
        text = path.read_text(encoding="utf-8")[:limit]
    except OSError:  # pragma: no cover - unreadable
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


# --------------------------------------------------------------------------- results
def m6_candidate(
    ctx: CheckContext,
    title: str,
    *,
    artifact: Mapping[str, Any],
    exchanges: Any = (),
    cwe: str | None = None,
    confidence: float = 0.5,
    detail: str | None = None,
    source: str | None = None,
) -> CheckResult:
    """M6's candidate shape: the proving exchanges plus one machine-readable artifact."""
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
