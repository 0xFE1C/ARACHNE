"""Secret scanning at scale and CI-log leakage (research ch06#8 and ch06#23).

``m6.secret-scan-at-scale``
    A gitleaks-class sweep of a repository clone — its working tree, its reflog/config, and
    its *git history* (loose objects are zlib-decompressed read-only, so a secret committed
    and later "removed" is still found). The corpus's credential detectors cover the cloud,
    VCS, SaaS and generic key shapes an attacker mines public code for (ch06#8).
``m6.ci-secret-leak``
    The CI-log half of ch06#23: a pipeline that echoes an environment variable, misses an
    ``::add-mask::``, or dumps a debug trace leaks the same credentials into a log artifact
    that lives far longer than the build. This check reads exported CI logs and artifacts
    shipped in the clone (or a configured log directory) and reports each leaked value.

Both are read-only and mask every value before it can reach evidence: the check reports the
credential *kind* and location, never the secret.
"""

from __future__ import annotations

import fnmatch
import re
import zlib
from collections.abc import AsyncIterator, Iterable
from pathlib import Path

from arachne.core.redaction import mask_secret
from arachne.core.results import CheckResult
from arachne.core.target import TargetKind
from arachne.modules.base import Asset, CheckMetadata, Module
from arachne.modules.context import CheckContext
from arachne.modules.m6.corpus import M6Corpus, Signature
from arachne.modules.m6.support import (
    corpus_for,
    finding_cap,
    iter_repo_files,
    local_root,
    m6_candidate,
    read_text,
    skip,
)

__all__ = ["CiSecretLeak", "SecretScanAtScale"]

#: A git loose object lives at ``.git/objects/<2 hex>/<38 hex>``.
_LOOSE_OBJECT_RE = re.compile(r"^[0-9a-f]{2}$")


def _first_match(signature: Signature, text: str) -> str | None:
    match = signature.regex.search(text)
    if match is None:
        return None
    value = match.group(1) if match.groups() else match.group(0)
    return mask_secret(value)


def _scan_text(text: str, detectors: tuple[Signature, ...]) -> tuple[tuple[str, str], ...]:
    """``((kind, masked), ...)`` — deduped per kind, first hit only (a file has enough)."""
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for signature in detectors:
        kind = signature.kind or signature.id
        if kind in seen:
            continue
        masked = _first_match(signature, text)
        if masked is None:
            continue
        seen.add(kind)
        out.append((kind, masked))
    return tuple(out)


class SecretScanAtScale(Module):
    """``m6.secret-scan-at-scale`` — repository + git-history secret scan (ch06#8)."""

    metadata = CheckMetadata(
        id="m6.secret-scan-at-scale",
        version="1.0",
        title="Repository and history secret scan",
        description=(
            "Scans a local repository clone for committed credentials — the working tree, the "
            "reflog/config, and git history (loose objects are decompressed read-only) — with "
            "the corpus detectors (AWS/GCP/Azure keys, GitHub/GitLab/Slack/Stripe tokens, PEM "
            "keys, connection strings, generic secrets), reporting the credential kind and "
            "location with the value masked (research ch06#8). Read-only; no clone, no network."
        ),
        module="M6",
        name="secret-scan-at-scale",
        research_ref="ch06#8",
        framework=("WSTG-INFO-05", "CWE-798"),
        compliance=("CSF-PR.PS-06",),
        cwe="CWE-798",
        target_kinds=(TargetKind.GIT, TargetKind.CLOUD, TargetKind.URL),
        severity_hint="high",
        type="passive",
        safe=True,
        verifiable=False,
        estimated_requests=0,
    )

    def supports(self, asset: Asset) -> bool:
        if not Module.supports(self, asset):
            return False
        return asset.kind in {"git", "cloud", "url"}

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        corpus = corpus_for(ctx)
        detectors = corpus.secret_detectors()
        root = local_root(ctx) if ctx.asset.kind in {"git", "cloud"} else None
        if root is None or not root.exists():
            yield skip(
                ctx,
                "no local repository to scan: declare a repo:/path or file:// target "
                "(a remote git URL is never cloned — )",
            )
            return
        produced = 0
        skip_globs = corpus.secret_skip_globs()
        for path in iter_repo_files(
            root,
            ("*",),
            max_files=ctx.config.m6.max_repo_files,
            max_bytes=ctx.config.m6.max_file_bytes,
        ):
            if _skipped(path, root, skip_globs):
                continue
            text = read_text(path, limit=ctx.config.m6.max_file_bytes)
            if text is None:
                continue
            relative = _relative(path, root)
            for kind, masked in _scan_text(text, detectors):
                produced += 1
                yield m6_candidate(
                    ctx,
                    f"Committed secret ({kind}) in {relative}",
                    artifact={
                        "signal": "repo-secret",
                        "family": "secrets",
                        "kind": kind,
                        "location": relative,
                        "masked": masked,
                        "in_history": False,
                    },
                    cwe="CWE-798",
                    confidence=0.75,
                    detail=f"{relative}: a {kind}-shaped credential is committed (value masked)",
                    source=relative,
                )
                if produced >= finding_cap(ctx):
                    return
        for path, relative in _history_files(corpus, root):
            text = read_text(path)
            if text is None:
                continue
            for kind, masked in _scan_text(text, detectors):
                produced += 1
                yield m6_candidate(
                    ctx,
                    f"Secret ({kind}) in git metadata {relative}",
                    artifact={
                        "signal": "repo-secret",
                        "family": "secrets",
                        "kind": kind,
                        "location": relative,
                        "masked": masked,
                        "in_history": True,
                    },
                    cwe="CWE-798",
                    confidence=0.6,
                    detail=f"{relative}: a {kind}-shaped value is recorded in git metadata",
                    source=relative,
                )
                if produced >= finding_cap(ctx):
                    return
        async for result in self._scan_objects(ctx, corpus, root, detectors, produced):
            produced += 1
            yield result
            if produced >= finding_cap(ctx):
                return
        if not produced:
            yield ctx.clean(
                "no committed secret in the working tree, git metadata or history",
                detail="the corpus detectors found no credential-shaped value",
            )

    async def _scan_objects(
        self,
        ctx: CheckContext,
        corpus: M6Corpus,
        root: Path,
        detectors: tuple[Signature, ...],
        already: int,
    ) -> AsyncIterator[CheckResult]:
        objects = root / ".git" / "objects"
        if not objects.is_dir():
            return
        budget = ctx.config.m6.max_git_objects
        scanned = 0
        for bucket in sorted(objects.iterdir()):
            if not bucket.is_dir() or not _LOOSE_OBJECT_RE.match(bucket.name):
                continue
            for item in sorted(bucket.iterdir()):
                if scanned >= budget:
                    return
                scanned += 1
                text = _read_loose_object(item)
                if text is None:
                    continue
                relative = f".git/objects/{bucket.name}/{item.name}"
                for kind, masked in _scan_text(text, detectors):
                    yield m6_candidate(
                        ctx,
                        f"Secret ({kind}) in git history {relative}",
                        artifact={
                            "signal": "repo-secret",
                            "family": "secrets",
                            "kind": kind,
                            "location": relative,
                            "masked": masked,
                            "in_history": True,
                        },
                        cwe="CWE-798",
                        confidence=0.65,
                        detail=(
                            f"{relative}: a {kind}-shaped value is present in a git object "
                            "(history), though it may be absent from the working tree"
                        ),
                        source=relative,
                    )


class CiSecretLeak(Module):
    """``m6.ci-secret-leak`` — credentials leaked into CI logs and artifacts (ch06#23)."""

    metadata = CheckMetadata(
        id="m6.ci-secret-leak",
        version="1.0",
        title="CI log/artifact secret leakage",
        description=(
            "Reads exported CI logs and build artifacts (from a repository clone or a "
            "configured log directory) for leaked credentials: a token a workflow echoed, an "
            "unmasked secret, a debug trace of an environment variable (research ch06#23). The "
            "same detectors as the repository scan plus CI-specific markers (::add-mask::, "
            "GITHUB_TOKEN, printenv, set -x). Values are masked; nothing is fetched."
        ),
        module="M6",
        name="ci-secret-leak",
        research_ref="ch06#23",
        framework=("WSTG-INFO-05", "CWE-532"),
        cwe="CWE-532",
        target_kinds=(TargetKind.GIT, TargetKind.CLOUD, TargetKind.URL),
        severity_hint="medium",
        type="passive",
        safe=True,
        verifiable=False,
        estimated_requests=0,
    )

    def supports(self, asset: Asset) -> bool:
        if not Module.supports(self, asset):
            return False
        return asset.kind in {"git", "cloud", "url"}

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        corpus = corpus_for(ctx)
        detectors = corpus.secret_detectors()
        markers = tuple(marker.lower() for marker in corpus.ci_markers())
        produced = 0
        candidates = list(_ci_log_paths(ctx, corpus))
        if not candidates:
            yield skip(
                ctx,
                "no CI logs to read: declare a repo with exported logs, or set "
                "ARACHNE_M6_LOG_PATHS to a log directory",
            )
            return
        for path, label in candidates:
            text = read_text(path, limit=ctx.config.m6.max_file_bytes)
            if text is None:
                continue
            lowered = text.lower()
            hits = [marker for marker in markers if marker in lowered]
            secrets = _scan_text(text, detectors)
            if not secrets and not hits:
                continue
            for kind, masked in secrets:
                produced += 1
                yield m6_candidate(
                    ctx,
                    f"CI log leak ({kind}) in {label}",
                    artifact={
                        "signal": "ci-secret-leak",
                        "family": "ci",
                        "kind": kind,
                        "location": label,
                        "masked": masked,
                        "markers": hits,
                    },
                    cwe="CWE-532",
                    confidence=0.7,
                    detail=f"{label}: a {kind}-shaped credential appears in a CI log/artifact",
                    source=label,
                )
                if produced >= finding_cap(ctx):
                    return
            if not secrets and hits:
                produced += 1
                yield m6_candidate(
                    ctx,
                    f"CI log leakage markers in {label}",
                    artifact={
                        "signal": "ci-secret-leak",
                        "family": "ci",
                        "kind": "marker",
                        "location": label,
                        "markers": hits,
                    },
                    cwe="CWE-532",
                    confidence=0.5,
                    detail=(f"{label}: CI log carries unmasked-token markers ({', '.join(hits)})"),
                    source=label,
                )
                if produced >= finding_cap(ctx):
                    return
        if not produced:
            yield ctx.clean(
                f"no credential leak in {len(candidates)} CI log/artifact file(s)",
                detail="the corpus detectors and CI markers both came back clean",
            )


# --------------------------------------------------------------------------- helpers
def _skipped(path: Path, root: Path, globs: tuple[str, ...]) -> bool:
    relative = _relative(path, root)
    return any(
        fnmatch.fnmatch(relative, pattern) or fnmatch.fnmatch(path.name, pattern)
        for pattern in globs
    )


def _relative(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:  # pragma: no cover - a path outside the root
        return path.as_posix()


def _history_files(corpus: M6Corpus, root: Path) -> tuple[tuple[Path, str], ...]:
    out: list[tuple[Path, str]] = []
    for relative in corpus.secret_history_files():
        candidate = root / relative
        if candidate.is_file():
            out.append((candidate, relative))
    return tuple(out)


def _read_loose_object(path: Path) -> str | None:
    """Decompress a git loose object (read-only) into text, bounded; ``None`` when unreadable.

    A git object is ``<type> <size>\\x00<content>``, so the leading NUL is the header
    delimiter, not a binary marker: the header is dropped and the content decoded.
    """
    try:
        blob = zlib.decompress(path.read_bytes()[: 1024 * 1024])
    except (OSError, zlib.error):
        return None
    _, separator, content = blob.partition(b"\x00")
    body = content if separator else blob
    if b"\x00" in body[:1024]:
        return None
    return body.decode("utf-8", "replace")


def _ci_log_paths(ctx: CheckContext, corpus: M6Corpus) -> Iterable[tuple[Path, str]]:
    """CI log/artifact files: globs under a repo target, plus the configured log paths."""
    out: list[tuple[Path, str]] = []
    seen: set[Path] = set()
    roots: list[Path] = []
    root = local_root(ctx) if ctx.asset.kind in {"git", "cloud"} else None
    if root is not None and root.exists():
        roots.append(root)
    for configured in ctx.config.m6.log_paths:
        path = Path(configured).expanduser()
        if path.is_file():
            out.append((path, path.name))
            seen.add(path)
        elif path.is_dir():
            roots.append(path)
    globs = corpus.ci_log_globs()
    for base in roots:
        for path in iter_repo_files(base, globs, max_files=ctx.config.m6.max_repo_files):
            if path in seen:
                continue
            seen.add(path)
            out.append((path, _relative(path, base)))
    return tuple(out)
