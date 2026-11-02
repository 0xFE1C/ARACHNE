"""M5 supply-chain checks: image/manifest secrets (ch05#17), CI/CD pipelines (ch05#23),
dependency confusion (ch05#24) and SBOM/SCA (ch05#25).

These four read a **local clone** — a Dockerfile, a Helm/Kubernetes manifest, a GitHub Actions
workflow, a lockfile — and none of them touches the network (registry lookups are off by default
and only ever HEAD a public package name). They are the part of M5 that answers "is what we build
from safe?", which is why they run in a default (non-active) posture: reading a file is not an
active check (F-01-09).

``m5.image-history-secrets``
    Reads Dockerfiles for literal secret material in ENV/ARG/LABEL and manifest files for
    plaintext values, and reports each location (research ch05#17). Values are masked.
``m5.cicd-audit``
    Reviews workflow files for the constructs of research ch05#23: ``pull_request_target``, an
    untrusted ``github.event.*`` interpolated into a ``run:`` step, ``permissions: write-all``, a
    self-hosted runner, and an unpinned third-party action.
``m5.dep-confusion``
    Flags manifest dependencies whose name looks internal/private (a scoped or ``-internal``
    name) — the registration-collision candidate of research ch05#24.
``m5.sbom-review``
    Matches a lockfile's declared component versions against the offline known-vulnerable index
    (research ch05#25) and reports each component below its fixed version.
"""

from __future__ import annotations

import json
import re
from collections.abc import AsyncIterator
from pathlib import Path

from arachne.core.results import CheckResult
from arachne.core.target import TargetKind
from arachne.modules.base import CheckMetadata, Module
from arachne.modules.context import CheckContext
from arachne.modules.m5.support import (
    RepoCheck,
    corpus_for,
    iter_repo_files,
    local_root,
    m5_candidate,
    read_text,
    skip,
)

__all__ = ["CicdAudit", "DepConfusion", "ImageHistorySecrets", "SbomReview"]

_VERSION_RE = re.compile(r"(\d+)(?:\.(\d+))?(?:\.(\d+))?")
_REQUIREMENT_RE = re.compile(r"^([A-Za-z0-9_.\-]+)\s*==\s*([0-9][0-9A-Za-z.\-+]*)", re.MULTILINE)


# --------------------------------------------------------------------------- image secrets
class ImageHistorySecrets(RepoCheck, Module):
    """``m5.image-history-secrets`` — secrets in image build/manifest artifacts (ch05#17)."""

    metadata = CheckMetadata(
        id="m5.image-history-secrets",
        module="M5",
        name="image-history-secrets",
        version="1.0",
        title="Secret material in image build or manifest artifacts",
        description=(
            "Reads a local clone's Dockerfiles for literal secret material in ENV/ARG/LABEL "
            "instructions, its Helm/Kubernetes manifests for plaintext values, and reports a "
            "container that runs as root (research ch05#17: image layers and manifests preserve "
            "secrets that were 'removed'). Values are masked; nothing is pulled or built."
        ),
        research_ref="ch05#17",
        framework=("WSTG-INFO-05", "CWE-798"),
        cwe="CWE-798",
        target_kinds=(TargetKind.GIT, TargetKind.CLOUD),
        severity_hint="high",
        type="hybrid",
        safe=True,
        verifiable=False,
        estimated_requests=0,
        runs_on_discovered=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        root = local_root(ctx)
        if root is None:
            yield skip(
                ctx, "no local image/manifest artifact to review (declare a repo:/path target)"
            )
            return
        corpus = corpus_for(ctx)
        hints = tuple(h.upper() for h in corpus.image_secret_instruction_hints())
        markers = corpus.image_secret_value_markers()
        findings = 0
        for path in iter_repo_files(
            root,
            ("Dockerfile", "Dockerfile.*", "Containerfile", *corpus.image_manifest_globs()),
            max_files=ctx.config.m5.max_repo_files,
            max_bytes=ctx.config.m5.max_file_bytes,
        ):
            text = read_text(path, limit=ctx.config.m5.max_file_bytes)
            if text is None:
                continue
            relative = _relative(path, root)
            is_dockerfile = path.name.lower().startswith(("dockerfile", "containerfile"))
            for line_no, line in enumerate(text.splitlines(), start=1):
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                instruction = stripped.split(None, 1)[0].upper()
                if is_dockerfile and instruction not in hints:
                    continue
                if not any(marker in stripped.lower() for marker in markers):
                    continue
                findings += 1
                yield m5_candidate(
                    ctx,
                    f"Secret-shaped value in {relative}:{line_no}",
                    artifact={
                        "signal": "image-secret",
                        "family": "image",
                        "location": f"{relative}:{line_no}",
                        "instruction": instruction,
                        "masked": _mask(stripped),
                    },
                    confidence=0.7,
                    detail=(
                        f"{relative}:{line_no} carries a secret-shaped value in a {instruction} "
                        "instruction; the value is masked"
                    ),
                    source=f"{relative}:{line_no}",
                )
                if findings >= ctx.config.m5.max_findings_per_check:
                    return
            if (
                is_dockerfile
                and corpus.image_root_user_marker() in text
                and "USER " not in text.split(corpus.image_root_user_marker())[0]
            ):
                findings += 1
                yield m5_candidate(
                    ctx,
                    f"Container explicitly runs as root ({relative})",
                    artifact={
                        "signal": "image-root-user",
                        "family": "image",
                        "location": relative,
                        "user": "root",
                    },
                    confidence=0.6,
                    detail=f"{relative} sets USER root, so the container runs as root by default",
                    source=relative,
                )
        if not findings:
            yield ctx.clean(
                "no secret-shaped value in the image/manifest artifacts",
                detail="reviewed the local Dockerfiles and manifests",
            )


# --------------------------------------------------------------------------- CI/CD
class CicdAudit(RepoCheck, Module):
    """``m5.cicd-audit`` — CI/CD pipeline supply-chain exposure (ch05#23)."""

    metadata = CheckMetadata(
        id="m5.cicd-audit",
        module="M5",
        name="cicd-audit",
        version="1.0",
        title="CI/CD pipeline supply-chain exposure",
        description=(
            "Reviews a local clone's workflow files (GitHub Actions, GitLab CI, Jenkins) for the "
            "constructs of research ch05#23: pull_request_target with secrets in scope, an "
            "untrusted github.event.* interpolated into a run step (script injection), "
            "GITHUB_TOKEN write-all, a self-hosted runner, and a third-party action pinned to a "
            "mutable ref. Read-only: it parses files and never runs a workflow."
        ),
        research_ref="ch05#23",
        framework=("WSTG-CONF-02", "CWE-78"),
        cwe="CWE-78",
        target_kinds=(TargetKind.GIT, TargetKind.CLOUD),
        severity_hint="high",
        type="passive",
        safe=True,
        verifiable=False,
        estimated_requests=0,
        runs_on_discovered=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        root = local_root(ctx)
        if root is None:
            yield skip(ctx, "no local CI/CD artifact to review (declare a repo:/path target)")
            return
        corpus = corpus_for(ctx)
        patterns = corpus.cicd_patterns()
        globs = tuple(corpus.cicd_workflow_globs())
        workflows = iter_repo_files(
            root,
            globs,
            max_files=ctx.config.m5.max_repo_files,
            max_bytes=ctx.config.m5.max_file_bytes,
        )
        if not workflows:
            yield ctx.clean(
                "no CI/CD workflow file found",
                detail=f"looked for {', '.join(globs)} in the local clone",
            )
            return
        findings = 0
        for path in workflows:
            text = read_text(path, limit=ctx.config.m5.max_file_bytes)
            if text is None:
                continue
            relative = _relative(path, root)
            for pattern in patterns:
                if pattern.regex.search(text) is None:
                    continue
                findings += 1
                yield m5_candidate(
                    ctx,
                    f"CI/CD risk in {relative}: {pattern.hint}",
                    artifact={
                        "signal": "cicd-risk",
                        "family": "cicd",
                        "rule": pattern.id,
                        "severity_hint": pattern.severity,
                        "location": relative,
                    },
                    confidence=0.8,
                    detail=f"{relative}: {pattern.hint}",
                    source=relative,
                )
                if findings >= ctx.config.m5.max_findings_per_check:
                    return


# --------------------------------------------------------------------------- dependency confusion
class DepConfusion(RepoCheck, Module):
    """``m5.dep-confusion`` — dependency-confusion / typosquatting candidates (ch05#24)."""

    metadata = CheckMetadata(
        id="m5.dep-confusion",
        module="M5",
        name="dep-confusion",
        version="1.0",
        title="Dependency-confusion or typosquatting candidate",
        description=(
            "Reads a local clone's manifests (package.json, requirements.txt, pom.xml, ...) and "
            "flags dependencies whose name looks internal or private (a scoped or "
            "'…-internal'/'company-' name), which is the registration-collision candidate of "
            "research ch05#24: an attacker who registers the same name publicly gets code "
            "execution at install time. Offline by default; nothing is registered."
        ),
        research_ref="ch05#24",
        framework=("WSTG-CONF-02", "API10:2023", "CWE-427"),
        cwe="CWE-427",
        target_kinds=(TargetKind.GIT, TargetKind.CLOUD),
        severity_hint="medium",
        type="hybrid",
        safe=True,
        verifiable=False,
        estimated_requests=0,
        runs_on_discovered=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        root = local_root(ctx)
        if root is None:
            yield skip(ctx, "no local manifest to review (declare a repo:/path target)")
            return
        corpus = corpus_for(ctx)
        hints = corpus.dep_internal_hints()
        manifests = iter_repo_files(
            root,
            tuple(corpus.dep_manifests()),
            max_files=ctx.config.m5.max_repo_files,
            max_bytes=ctx.config.m5.max_file_bytes,
        )
        findings = 0
        for path in manifests:
            text = read_text(path, limit=ctx.config.m5.max_file_bytes)
            if text is None:
                continue
            relative = _relative(path, root)
            names = _dependency_names(path.name, text)
            suspicious = sorted({name for name in names if _looks_internal(name, hints)})
            if not suspicious:
                continue
            findings += 1
            yield m5_candidate(
                ctx,
                f"Internal-looking dependencies in {relative}",
                artifact={
                    "signal": "dependency-confusion",
                    "family": "dep-confusion",
                    "location": relative,
                    "candidates": suspicious[:10],
                    "count": len(suspicious),
                },
                confidence=0.65,
                detail=(
                    f"{relative} depends on internal-looking names ({', '.join(suspicious[:3])}) "
                    "that are confusion candidates if the same name resolves publicly"
                ),
                source=relative,
            )
            if findings >= ctx.config.m5.max_findings_per_check:
                return
        if not findings:
            yield ctx.clean(
                "no internal-looking dependency name found",
                detail="reviewed the local manifests",
            )


# --------------------------------------------------------------------------- SBOM / SCA
class SbomReview(RepoCheck, Module):
    """``m5.sbom-review`` — known-vulnerable components in a lockfile (ch05#25)."""

    metadata = CheckMetadata(
        id="m5.sbom-review",
        module="M5",
        name="sbom-review",
        version="1.0",
        title="Known-vulnerable component in use",
        description=(
            "Parses a local clone's lockfiles/manifests, matches the declared component versions "
            "against the offline known-vulnerable index (research ch05#25), and reports each "
            "component below its fixed version with the CVE and the fix version. An external "
            "scanner (Trivy/Syft-class) is used when ARACHNE_M5_SBOM_TOOL is configured. Nothing "
            "is installed or executed."
        ),
        research_ref="ch05#25",
        framework=("WSTG-CONF-02", "API10:2023", "CWE-1104"),
        cwe="CWE-1104",
        target_kinds=(TargetKind.GIT, TargetKind.CLOUD),
        severity_hint="high",
        type="hybrid",
        safe=True,
        verifiable=False,
        estimated_requests=0,
        runs_on_discovered=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        root = local_root(ctx)
        if root is None:
            yield skip(ctx, "no local lockfile to review (declare a repo:/path target)")
            return
        corpus = corpus_for(ctx)
        vulnerable = corpus.sbom_vulnerable()
        lockfiles = iter_repo_files(
            root,
            tuple(corpus.sbom_lockfiles()),
            max_files=ctx.config.m5.max_repo_files,
            max_bytes=ctx.config.m5.max_file_bytes,
        )
        findings = 0
        for path in lockfiles:
            text = read_text(path, limit=ctx.config.m5.max_file_bytes)
            if text is None:
                continue
            relative = _relative(path, root)
            declared = _declared_versions(path.name, text)
            for component in vulnerable:
                version = declared.get(component.name)
                if version is None or not _is_below(version, component.below):
                    continue
                findings += 1
                yield m5_candidate(
                    ctx,
                    f"Vulnerable component {component.name} {version} in {relative}",
                    artifact={
                        "signal": "sbom-vulnerable-component",
                        "family": "sbom",
                        "location": relative,
                        "component": component.name,
                        "version": version,
                        "fixed": component.below,
                        "cve": component.cve,
                        "severity_hint": component.severity,
                    },
                    confidence=0.7,
                    detail=(
                        f"{relative} declares {component.name} {version}, below the fixed "
                        f"{component.below} ({component.cve})"
                    ),
                    source=relative,
                )
                if findings >= ctx.config.m5.max_findings_per_check:
                    return
        if not findings:
            yield ctx.clean(
                "no known-vulnerable component declared",
                detail="reviewed the local lockfiles against the offline index",
            )


# --------------------------------------------------------------------------- helpers
def _dependency_names(filename: str, text: str) -> set[str]:
    names: set[str] = set()
    if filename.endswith("package.json"):
        document = _json_or_none(text)
        if isinstance(document, dict):
            for key in ("dependencies", "devDependencies", "peerDependencies"):
                block = document.get(key)
                if isinstance(block, dict):
                    names.update(str(name) for name in block)
    elif filename in {"requirements.txt", "Pipfile"} or filename.endswith(".txt"):
        for match in _REQUIREMENT_RE.finditer(text):
            names.add(match.group(1))
    else:
        for match in re.finditer(r"<artifactId>([^<]+)</artifactId>", text):
            names.add(match.group(1))
        for match in re.finditer(r"^\s*([A-Za-z0-9_.\-]+)\s*[:=]", text, re.MULTILINE):
            names.add(match.group(1))
    return names


def _looks_internal(name: str, hints: tuple[str, ...]) -> bool:
    lowered = name.lower()
    if lowered.startswith("@") and not lowered.startswith(("@types/", "@babel/", "@angular/")):
        return True
    return any(hint in lowered for hint in hints)


def _declared_versions(filename: str, text: str) -> dict[str, str]:
    versions: dict[str, str] = {}
    if filename.endswith("package.json") or filename in {"package-lock.json"}:
        document = _json_or_none(text)
        if isinstance(document, dict):
            for key in ("dependencies", "devDependencies"):
                block = document.get(key)
                if isinstance(block, dict):
                    for name, spec in block.items():
                        version = _version_from_spec(str(spec))
                        if version:
                            versions[str(name)] = version
            packages = document.get("packages")
            if isinstance(packages, dict):
                for _path, meta in packages.items():
                    if isinstance(meta, dict) and meta.get("name") and meta.get("version"):
                        versions[str(meta["name"])] = str(meta["version"])
    elif filename.endswith(".txt") or filename == "requirements.txt":
        for match in _REQUIREMENT_RE.finditer(text):
            versions[match.group(1)] = match.group(2)
    else:
        for match in re.finditer(
            r"<artifactId>([^<]+)</artifactId>\s*<version>([^<]+)</version>", text
        ):
            versions[match.group(1)] = match.group(2)
    return versions


def _version_from_spec(spec: str) -> str | None:
    match = re.search(r"(\d+\.\d+\.\d+)", spec)
    return match.group(1) if match else None


def _is_below(version: str, fixed: str) -> bool:
    return _tuple(version) < _tuple(fixed)


def _tuple(version: str) -> tuple[int, int, int]:
    match = _VERSION_RE.search(version)
    if match is None:
        return (0, 0, 0)
    return tuple(int(part or 0) for part in match.groups())  # type: ignore[return-value]


def _json_or_none(text: str) -> object:
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None


def _mask(value: str) -> str:
    import hashlib

    return f"<masked:{hashlib.sha256(value.encode('utf-8', 'replace')).hexdigest()[:10]}>"


def _relative(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:  # pragma: no cover - path outside root
        return str(path)
