"""Shared M5 check plumbing: applicability, corpus access, endpoint/file helpers, evidence.

M5's checks fall into two families with very different mechanics:

* **Endpoint checks** probe something reachable over HTTP (a bucket, a kubelet, a Docker
  daemon, a registry, a Firebase/Supabase project, a metadata service). They share M3/M4's
  request policy: one scoped, rate-limited, redacted, audited client, ``None`` in dry-run, and
  a candidate whose evidence is the request/response pair plus one machine-readable artifact.
* **Artifact checks** read a *local* clone or file (a workflow, a ``.tfstate``, a lockfile, a
  Dockerfile, an IAM policy). They never touch the network, so they run with no client at all.

Both need the same things from this module: the typed corpus (``corpus_for``), the candidate
shape the rules read (``m5_candidate``), and one place for the applicability rules
(``UrlCheck``/``EndpointCheck``/``RepoCheck``) so a check's ``supports`` cannot drift from its
metadata.
"""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Iterable, Mapping
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from arachne.core.http import HttpExchange
from arachne.core.results import CheckResult
from arachne.modules.base import Asset
from arachne.modules.context import CheckContext
from arachne.modules.m3.inventory import Page, page_from_exchange
from arachne.modules.m3.support import (
    artifact_evidence,
    exchange_from_page,
    http_or_skip,
    safe_fetch,
    skip,
    web_candidate,
)
from arachne.modules.m5.corpus import M5Corpus, load_corpus, load_wordlist

__all__ = [
    "EndpointCheck",
    "RepoCheck",
    "UrlCheck",
    "artifact_evidence",
    "corpus_for",
    "endpoint_base",
    "exchange_from_page",
    "fetch_page",
    "finding_cap",
    "http_or_skip",
    "is_local_path",
    "iter_matching",
    "iter_repo_files",
    "local_root",
    "m5_candidate",
    "provider_reference",
    "read_text",
    "safe_fetch",
    "skip",
    "skip_bytes",
    "text_contains_any",
    "wordlist",
]

#: Provider labels that name an HTTP endpoint directly (``endpoint:http://...``) or a daemon
#: whose URL is built from the reference (``registry:host:5000``).
_BARE_ENDPOINT_PROVIDERS = frozenset(
    {
        "endpoint",
        "http",
        "https",
        "minio",
        "localstack",
        "registry",
        "docker",
        "kubelet",
        "kube",
        "k8s",
    }
)


# --------------------------------------------------------------------------- applicability
class UrlCheck:
    """M5's URL-asset applicability: one ``http(s)`` URL (usually the SSRF/endpoint case)."""

    def supports(self, asset: Asset) -> bool:
        if not super().supports(asset):  # type: ignore[misc]
            return False
        return asset.kind == "url" and asset.value.lower().startswith(("http://", "https://"))


class EndpointCheck:
    """A URL, cloud or bucket asset — the shape every endpoint probe accepts."""

    def supports(self, asset: Asset) -> bool:
        if not super().supports(asset):  # type: ignore[misc]
            return False
        if asset.kind in {"bucket", "cloud"}:
            return True
        return asset.kind == "url"


class RepoCheck:
    """A git or cloud asset that names a *local* repository artifact (a clone or a file).

    ``repo:<path>`` / ``file://<path>`` / a bare filesystem path all resolve through
    :func:`local_root`; a remote git URL has no local clone in a scan, so the check reports
    itself skipped rather than cloning (docs/spec/05- M5: "runs on local clones only").
    """

    def supports(self, asset: Asset) -> bool:
        if not super().supports(asset):  # type: ignore[misc]
            return False
        return asset.kind in {"git", "cloud"}


# --------------------------------------------------------------------------- corpus access
@lru_cache(maxsize=4)
def _corpus_cached(path: str | None) -> M5Corpus:
    return load_corpus(path)


def corpus_for(ctx: CheckContext) -> M5Corpus:
    """The M5 probe corpus (cached per path: parsing YAML per check would be wasteful)."""
    return _corpus_cached(ctx.config.m5_probes)


def wordlist(ctx: CheckContext, name: str, *, limit: int | None = None) -> tuple[str, ...]:
    """An M5 wordlist: the operator's directory wins over the packaged file (F-09-04)."""
    return load_wordlist(
        name,
        override_dir=ctx.config.m5_probes,
        limit=limit if limit is not None else ctx.config.m5.max_paths,
    )


def finding_cap(ctx: CheckContext) -> int:
    return max(1, ctx.config.m5.max_findings_per_check)


# --------------------------------------------------------------------------- endpoints
def provider_reference(value: str) -> tuple[str, str] | None:
    """Split ``provider:reference`` for a cloud/bucket asset, or ``None``."""
    provider, separator, reference = value.partition(":")
    if not separator:
        return None
    return provider.lower(), reference


def endpoint_base(ctx: CheckContext) -> str | None:
    """The HTTP base URL this asset names, or ``None`` when it names no endpoint.

    ``https://host/path`` (a URL asset), ``endpoint:https://host/path`` and the
    daemon/provider spellings (``registry:host:5000``, ``kubelet:host:10255``) all resolve to
    a base URL a probe joins a path onto.
    """
    value = ctx.asset.value
    if value.lower().startswith(("http://", "https://")):
        return value
    parts = provider_reference(value)
    if parts is None:
        return None
    provider, reference = parts
    if provider in _BARE_ENDPOINT_PROVIDERS:
        if "://" in reference:
            return reference
        return (
            f"https://{reference}"
            if not reference.startswith("127.0.0.1")
            else f"http://{reference}"
        )
    if provider in {"registry", "docker", "kubelet"}:
        return f"http://{reference}"
    return None


def text_contains_any(body: str, markers: Iterable[str]) -> str | None:
    lowered = body.lower()
    for marker in markers:
        if marker and marker.lower() in lowered:
            return marker
    return None


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
    """One bounded probe as a :class:`Page`, or ``None`` when it was refused/failed."""
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


# --------------------------------------------------------------------------- local artifacts
def is_local_path(value: str) -> bool:
    """True when ``value`` names a filesystem path rather than a remote reference."""
    if value.startswith("file://"):
        return True
    if "://" in value:
        return False
    parts = provider_reference(value)
    if parts is not None:
        return parts[0] in {"repo", "path", "file", "dir", "local"}
    return value.startswith(("/", "./", "../", "~"))


def local_root(ctx: CheckContext) -> Path | None:
    """The local directory a repo/file asset points at, or ``None`` (a remote reference).

    A scan never clones: a ``repo:/path``, ``file:///path`` or bare path resolves; a
    ``git@host:org/repo`` or ``https://github.com/...`` reference does not, and the check
    reports itself skipped.
    """
    value = ctx.asset.value.strip()
    parts = provider_reference(value)
    if parts is not None and parts[0] in {"repo", "path", "file", "dir", "local"}:
        value = parts[1]
    elif parts is not None and "://" not in value and not value.startswith("/"):
        return None
    if value.startswith("file://"):
        value = urlsplit(value).path
    if "://" in value or re.match(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+:", value):
        return None
    root = Path(value).expanduser()
    return root if root.exists() else None


def iter_repo_files(
    root: Path,
    globs: Iterable[str],
    *,
    max_files: int = 4000,
    max_bytes: int = 262144,
) -> list[Path]:
    """Files under ``root`` matching any of ``globs`` (bounded; skips huge/binary files)."""
    if not root.exists():
        return []
    patterns = tuple(globs)
    if not patterns:
        patterns = ("*",)
    found: list[Path] = []
    if root.is_file():
        return [root]
    for path in sorted(root.rglob("*")):
        if len(found) >= max_files:
            break
        if not path.is_file():
            continue
        relative = path.relative_to(root).as_posix()
        if not any(
            fnmatch.fnmatch(relative, pattern) or fnmatch.fnmatch(path.name, pattern)
            for pattern in patterns
        ):
            continue
        try:
            if path.stat().st_size > max_bytes:
                continue
        except OSError:  # pragma: no cover - unreadable
            continue
        found.append(path)
    return found


def iter_matching(root: Path, names: Iterable[str]) -> list[Path]:
    """Files under ``root`` whose *name* matches one of ``names`` (glob names allowed)."""
    wanted = tuple(names)
    matches: list[Path] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if any(fnmatch.fnmatch(path.name, name) for name in wanted):
            matches.append(path)
    return matches


def read_text(path: Path, *, limit: int = 262144) -> str | None:
    """Read a text file, bounded; ``None`` when it is binary or unreadable."""
    try:
        data = path.read_bytes()[:limit]
    except OSError:  # pragma: no cover - unreadable
        return None
    if b"\x00" in data[:1024]:
        return None
    return data.decode("utf-8", "replace")


def skip_bytes(limit: int, *, what: str = "artifact") -> int:
    """Clamp a caller-supplied read limit to a sane positive value."""
    return max(1, min(limit, 4 * 1024 * 1024)) if limit else 262144


# --------------------------------------------------------------------------- results
def m5_candidate(
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
    """M5's candidate shape: the proving exchanges plus one machine-readable artifact.

    Reuses M3's :func:`web_candidate` so the evidence layout — request, response, and one
    ``artifact`` the rules read — is identical across the modules, which is what lets a single
    rule corpus cover all of them.
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
