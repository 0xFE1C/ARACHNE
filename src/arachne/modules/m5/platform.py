"""M5 platform checks: Firebase (ch05#7), Supabase (ch05#8), Terraform state + IaC (ch05#11-12),
Kubernetes (ch05#13-14), the container registry (ch05#15) and the Docker API (ch05#16).

Each check is a bounded, read-only probe (or a local artifact review) and each confirmation is a
*marker the service itself returns*: a Firebase RTDB JSON dump, a PostgREST table list, a kubelet
``PodList``, a registry catalog, a Docker ``/version`` body. Nothing is written and nothing is
claimed.

``m5.tfstate-exposure`` also runs the IaC misconfiguration review (ch05#12, tfsec/checkov-class)
over a local clone's ``.tf``/manifest files when the asset names one, so the state-file exposure
and the static review share one check as the module pairs them.
"""

from __future__ import annotations

import json
import re
from collections.abc import AsyncIterator, Mapping
from pathlib import Path
from urllib.parse import urlsplit

from arachne.core.results import CheckResult
from arachne.core.target import TargetKind
from arachne.modules.base import Asset, CheckMetadata, Module
from arachne.modules.context import CheckContext
from arachne.modules.m5.corpus import M5Corpus
from arachne.modules.m5.support import (
    EndpointCheck,
    RepoCheck,
    corpus_for,
    endpoint_base,
    fetch_page,
    finding_cap,
    http_or_skip,
    iter_matching,
    iter_repo_files,
    local_root,
    m5_candidate,
    read_text,
    skip,
    text_contains_any,
)
from arachne.posture.iac import evaluate_k8s_manifest, is_k8s_manifest, rules_from_corpus

__all__ = [
    "DockerSocket",
    "FirebaseRules",
    "K8sExposure",
    "RegistryScan",
    "SupabaseRls",
    "TfstateExposure",
]


# --------------------------------------------------------------------------- Firebase
class FirebaseRules(EndpointCheck, Module):
    """``m5.firebase-rules`` — Firebase project with open read/write rules (ch05#7)."""

    metadata = CheckMetadata(
        id="m5.firebase-rules",
        module="M5",
        name="firebase-rules",
        version="1.0",
        title="Firebase project exposes open database rules",
        description=(
            "Probes a Firebase Realtime Database / Firestore project for anonymous read access "
            "by requesting the ``.json`` tree dump, and reports a project whose rules allow it "
            "(research ch05#7). The project reference comes from a ``firebase:<project>`` cloud "
            "target or an ``endpoint:<url>``; GET only, never a write."
        ),
        research_ref="ch05#7",
        cwe="CWE-284",
        target_kinds=(TargetKind.CLOUD, TargetKind.URL),
        severity_hint="high",
        type="active",
        safe=True,
        verifiable=True,
        estimated_requests=4,
        requires_active_checks=True,
        runs_on_discovered=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        _client, skipped = http_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        corpus = corpus_for(ctx)
        bases = self._bases(ctx, corpus)
        if not bases:
            yield skip(
                ctx,
                "no Firebase project reference: declare firebase:<project> or endpoint:<url>",
            )
            return
        markers = corpus.firebase_markers()
        findings = 0
        for label, base in bases:
            for path in corpus.firebase_rtdb_paths():
                page = await fetch_page(ctx, f"{base.rstrip('/')}{path}")
                if page is None or page.status != 200:
                    continue
                if not _is_json_dump(page.body, markers):
                    continue
                findings += 1
                yield m5_candidate(
                    ctx,
                    f"Firebase Realtime Database is publicly readable ({label})",
                    artifact={
                        "signal": "firebase-open-rules",
                        "family": "firebase",
                        "project": label,
                        "endpoint": f"{base.rstrip('/')}{path}",
                        "status": page.status,
                        "records": _json_size(page.body),
                    },
                    confidence=0.9,
                    detail=(
                        f"{base}{path} returned database contents anonymously, so the project's "
                        "security rules permit public reads"
                    ),
                    source=base,
                )
                break
            if findings >= finding_cap(ctx):
                break
        if not findings:
            yield ctx.clean(
                "no publicly readable Firebase database found",
                detail=f"probed {len(bases)} project reference(s)",
            )

    def _bases(self, ctx: CheckContext, corpus: M5Corpus) -> list[tuple[str, str]]:
        template = corpus.firebase_rtdb_host_template()
        value = ctx.asset.value
        if value.lower().startswith(("http://", "https://")):
            return [(urlsplit(value).hostname or "endpoint", value)]
        provider, _, reference = value.partition(":")
        if provider.lower() == "firebase" and reference:
            return [(reference, f"https://{template.replace('<project>', reference)}")]
        base = endpoint_base(ctx)
        if base:
            return [(urlsplit(base).hostname or "endpoint", base)]
        return []


# --------------------------------------------------------------------------- Supabase
class SupabaseRls(EndpointCheck, Module):
    """``m5.supabase-rls`` — Supabase/PostgREST table without RLS (ch05#8)."""

    metadata = CheckMetadata(
        id="m5.supabase-rls",
        module="M5",
        name="supabase-rls",
        version="1.0",
        title="Supabase / PostgREST table readable without RLS",
        description=(
            "Requests the PostgREST API root and a bounded table list anonymously and reports "
            "tables that answer with rows, which means row-level security is not enabled for the "
            "anonymous role (research ch05#8). GET only; no row is written."
        ),
        research_ref="ch05#8",
        cwe="CWE-284",
        target_kinds=(TargetKind.CLOUD, TargetKind.URL),
        severity_hint="high",
        type="active",
        safe=True,
        verifiable=True,
        estimated_requests=6,
        requires_active_checks=True,
        runs_on_discovered=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        _client, skipped = http_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        corpus = corpus_for(ctx)
        bases = _endpoint_bases(ctx, corpus.supabase_host_template(), {"supabase"})
        if not bases:
            yield skip(
                ctx, "no Supabase project reference: declare supabase:<ref> or endpoint:<url>"
            )
            return
        rest = corpus.supabase_rest_path().rstrip("/")
        findings = 0
        for label, base in bases:
            root = f"{base.rstrip('/')}{rest}/"
            page = await fetch_page(ctx, root)
            if page is None:
                continue
            for table in corpus.supabase_tables():
                table_page = await fetch_page(ctx, f"{root}{table}?select=*&limit=3")
                rows = _table_rows(table_page.body) if table_page is not None else None
                if not rows or table_page is None:
                    continue
                findings += 1
                yield m5_candidate(
                    ctx,
                    f"PostgREST table '{table}' is readable anonymously ({label})",
                    artifact={
                        "signal": "supabase-open-rls",
                        "family": "supabase",
                        "project": label,
                        "table": table,
                        "status": table_page.status,
                        "rows": len(rows),
                    },
                    confidence=0.85,
                    detail=(
                        f"{root}{table} returned {len(rows)} row(s) without a session, so RLS does "
                        "not cover the anonymous role"
                    ),
                    source=root,
                )
                if findings >= finding_cap(ctx):
                    return
            if (
                page is not None
                and page.status == 200
                and text_contains_any(page.body, corpus.supabase_markers())
                and not findings
            ):
                findings += 1
                yield m5_candidate(
                    ctx,
                    f"PostgREST schema is exposed anonymously ({label})",
                    artifact={
                        "signal": "supabase-open-schema",
                        "family": "supabase",
                        "project": label,
                        "endpoint": root,
                        "status": page.status,
                    },
                    confidence=0.75,
                    detail=f"{root} published the PostgREST OpenAPI schema without a session",
                    source=root,
                )
        if not findings:
            yield ctx.clean(
                "no anonymously readable PostgREST table found",
                detail=f"probed {len(bases)} project reference(s)",
            )


# --------------------------------------------------------------------------- terraform state + IaC
class TfstateExposure(EndpointCheck, RepoCheck, Module):
    """``m5.tfstate-exposure`` — state-file exposure + IaC misconfiguration review (ch05#11-12)."""

    metadata = CheckMetadata(
        id="m5.tfstate-exposure",
        module="M5",
        name="tfstate-exposure",
        version="1.1",
        title="Terraform state exposed or IaC misconfigured",
        description=(
            "Fetches the conventional ``.tfstate`` paths (over HTTP) and reads a local clone's "
            "state files, and reports a state document that carries plaintext secrets or a full "
            "resource inventory (research ch05#11). The same check runs the IaC misconfiguration "
            "review (ch05#12, tfsec/checkov-class) over the clone's .tf/manifests when it has "
            "one: security groups open to 0.0.0.0/0, wildcard IAM, public buckets, unencrypted "
            "storage, publicly accessible databases and privileged containers. Since S23 the "
            "review also parses YAML manifests and evaluates them with the *structured* "
            "Kubernetes policy rules the admission webhook runs, so the pre-deploy gate and "
            "the cluster cannot drift apart (REQ-POSTURE-002/005)."
        ),
        research_ref="ch05#11-12",
        cwe="CWE-312",
        target_kinds=(TargetKind.CLOUD, TargetKind.URL, TargetKind.GIT),
        severity_hint="high",
        type="hybrid",
        safe=True,
        verifiable=True,
        estimated_requests=6,
        runs_on_discovered=True,
    )

    def supports(self, asset: Asset) -> bool:
        if super().supports(asset):
            return True
        return Module.supports(self, asset) and asset.kind == "url"

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        corpus = corpus_for(ctx)
        findings = 0
        # (a) HTTP state exposure (needs a live client).
        base = endpoint_base(ctx)
        if base is not None:
            _client, skipped = http_or_skip(ctx)
            if skipped is None:
                for path in corpus.tfstate_paths():
                    page = await fetch_page(ctx, f"{base.rstrip('/')}{path}")
                    if page is None or page.status != 200:
                        continue
                    document = _json_or_none(page.body)
                    if not isinstance(document, dict):
                        continue
                    keys = set(document)
                    if not keys.intersection(corpus.tfstate_resource_keys()):
                        continue
                    secrets = _state_secrets(page.body, corpus.tfstate_secret_keys())
                    findings += 1
                    yield m5_candidate(
                        ctx,
                        f"Terraform state file served at {path}",
                        artifact={
                            "signal": "tfstate-exposure",
                            "family": "tfstate",
                            "path": path,
                            "status": page.status,
                            "terraform_version": str(document.get("terraform_version", "")),
                            "resource_count": len(document.get("resources") or []),
                            "secret_keys": secrets,
                            "plaintext_secrets": bool(secrets),
                        },
                        confidence=0.9 if secrets else 0.8,
                        detail=(
                            f"{base}{path} served a Terraform state document"
                            + (f" carrying plaintext {', '.join(secrets[:4])}" if secrets else "")
                        ),
                        source=f"{base.rstrip('/')}{path}",
                    )
                    break
        # (b) local clone: state files + IaC review.
        root = local_root(ctx)
        if root is not None:
            async for finding in self._local(ctx, root, corpus):
                findings += 1
                yield finding
        if not findings:
            yield ctx.clean(
                "no exposed Terraform state or IaC misconfiguration found",
                detail="probed the conventional state paths and reviewed any local IaC",
            )

    async def _local(
        self, ctx: CheckContext, root: Path, corpus: M5Corpus
    ) -> AsyncIterator[CheckResult]:
        seen: set[Path] = set()
        state_files: list[Path] = []
        for path in iter_matching(root, corpus.tfstate_local_names()):
            if path not in seen:
                seen.add(path)
                state_files.append(path)
        for path in state_files:
            text = read_text(path, limit=ctx.config.m5.max_file_bytes)
            if text is None:
                continue
            document = _json_or_none(text)
            if not isinstance(document, dict):
                continue
            secrets = _state_secrets(text, corpus.tfstate_secret_keys())
            relative = _relative(path, root)
            yield m5_candidate(
                ctx,
                f"Terraform state file committed: {relative}",
                artifact={
                    "signal": "tfstate-exposure",
                    "family": "tfstate",
                    "location": relative,
                    "resource_count": len(document.get("resources") or []),
                    "secret_keys": secrets,
                    "plaintext_secrets": bool(secrets),
                },
                confidence=0.85,
                detail=(
                    f"{relative} is committed and carries the plaintext infrastructure inventory"
                ),
                source=relative,
            )
        patterns = corpus.iac_patterns()
        globs = corpus.iac_globs()
        hits: dict[str, list[str]] = {}
        k8s_hits: dict[str, list[str]] = {}
        k8s_severity: dict[str, str] = {}
        k8s_hint: dict[str, str] = {}
        for path in iter_repo_files(
            root,
            globs,
            max_files=ctx.config.m5.max_repo_files,
            max_bytes=ctx.config.m5.max_file_bytes,
        ):
            text = read_text(path, limit=ctx.config.m5.max_file_bytes)
            if text is None:
                continue
            for pattern in patterns:
                if pattern.regex.search(text):
                    hits.setdefault(pattern.id, []).append(_relative(path, root))
            # S23 (REQ-POSTURE-002): manifests are also parsed and evaluated *structurally*
            # by the same rules the admission webhook runs, so "what the gate blocks" and
            # "what the cluster refuses" cannot drift apart. A file that does not parse is
            # skipped silently — the regex pass above still reviewed its bytes.
            for document in _yaml_documents(text):
                if not is_k8s_manifest(document) or not isinstance(document, Mapping):
                    continue
                for violation in evaluate_k8s_manifest(document, rules_from_corpus(corpus)):
                    relative = _relative(path, root)
                    k8s_hits.setdefault(violation.rule_id, []).append(
                        f"{relative}#{violation.path}"
                    )
                    k8s_severity[violation.rule_id] = violation.severity
                    k8s_hint[violation.rule_id] = violation.hint
        for pattern in patterns:
            locations = hits.get(pattern.id)
            if not locations:
                continue
            yield m5_candidate(
                ctx,
                f"IaC misconfiguration: {pattern.hint}",
                artifact={
                    "signal": "iac-misconfiguration",
                    "family": "iac",
                    "rule": pattern.id,
                    "severity_hint": pattern.severity,
                    "locations": sorted(set(locations))[:6],
                    "count": len(locations),
                },
                confidence=0.7,
                detail=f"{pattern.hint} in {', '.join(sorted(set(locations))[:3])}",
                source=sorted(set(locations))[0],
            )
        for rule_id in sorted(k8s_hits):
            locations = k8s_hits[rule_id]
            yield m5_candidate(
                ctx,
                f"Kubernetes manifest policy: {k8s_hint.get(rule_id, rule_id)}",
                artifact={
                    "signal": "iac-misconfiguration",
                    "family": "k8s-policy",
                    "rule": rule_id,
                    "severity_hint": k8s_severity.get(rule_id, "medium"),
                    "locations": sorted(set(locations))[:6],
                    "count": len(locations),
                },
                confidence=0.75,
                detail=(
                    f"{k8s_hint.get(rule_id, rule_id)} in "
                    f"{', '.join(sorted(set(locations))[:3])}"
                ),
                source=sorted(set(locations))[0],
            )


# --------------------------------------------------------------------------- kubernetes
class K8sExposure(EndpointCheck, Module):
    """``m5.k8s-exposure`` — unauthenticated kubelet API / dashboard exposure (ch05#13-14)."""

    metadata = CheckMetadata(
        id="m5.k8s-exposure",
        module="M5",
        name="k8s-exposure",
        version="1.0",
        title="Kubernetes kubelet API or dashboard exposed",
        description=(
            "Probes the kubelet read-only API paths (/pods, /runningpods, /stats/summary) and the "
            "Kubernetes Dashboard for anonymous access, and reports a ``PodList`` or dashboard "
            "answer (research ch05#13-14: pod specs and env vars leak, and the dashboard's default "
            "binding grants cluster admin). GET only."
        ),
        research_ref="ch05#13-14",
        cwe="CWE-306",
        target_kinds=(TargetKind.CLOUD, TargetKind.URL, TargetKind.IP),
        severity_hint="critical",
        type="active",
        safe=True,
        verifiable=True,
        estimated_requests=8,
        requires_active_checks=True,
        runs_on_discovered=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        _client, skipped = http_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        corpus = corpus_for(ctx)
        bases = _endpoint_bases(ctx, "", {"kubelet", "kube", "k8s"})
        if not bases:
            yield skip(
                ctx,
                "no Kubernetes endpoint reference: declare kubelet:<host:port> or endpoint:<url>",
            )
            return
        pod_markers = corpus.k8s_pod_markers()
        env_markers = corpus.k8s_env_markers()
        dash_markers = corpus.k8s_dashboard_markers()
        findings = 0
        for _label, base in bases:
            for path in corpus.k8s_kubelet_paths():
                page = await fetch_page(ctx, f"{base.rstrip('/')}{path}")
                if page is None or page.status not in {200, 201}:
                    continue
                marker = text_contains_any(page.body, pod_markers)
                if marker is None:
                    continue
                env_leak = text_contains_any(page.body, env_markers)
                findings += 1
                yield m5_candidate(
                    ctx,
                    f"Kubelet API answers anonymously at {path}",
                    artifact={
                        "signal": "k8s-kubelet-unauth",
                        "family": "k8s",
                        "endpoint": f"{base.rstrip('/')}{path}",
                        "status": page.status,
                        "marker": marker,
                        "env_exposure": env_leak,
                    },
                    confidence=0.9,
                    detail=(
                        f"{base}{path} returned pod data without authentication"
                        + (f" (env markers: {env_leak})" if env_leak else "")
                    ),
                    source=base,
                )
                break
            for path in corpus.k8s_dashboard_paths():
                page = await fetch_page(ctx, f"{base.rstrip('/')}{path}")
                if page is None or page.status != 200:
                    continue
                if text_contains_any(page.body, dash_markers) is None and path not in page.body:
                    continue
                findings += 1
                yield m5_candidate(
                    ctx,
                    "Kubernetes Dashboard reachable",
                    artifact={
                        "signal": "k8s-dashboard",
                        "family": "k8s",
                        "endpoint": f"{base.rstrip('/')}{path}",
                        "status": page.status,
                    },
                    confidence=0.8,
                    detail=f"{base}{path} served the Kubernetes Dashboard anonymously",
                    source=base,
                )
                break
            if findings >= finding_cap(ctx):
                break
        if not findings:
            yield ctx.clean(
                "no anonymous kubelet or dashboard found",
                detail=f"probed {len(bases)} Kubernetes endpoint(s)",
            )


# --------------------------------------------------------------------------- registry
class RegistryScan(EndpointCheck, Module):
    """``m5.registry-scan`` — container registry catalog / image scan (ch05#15)."""

    metadata = CheckMetadata(
        id="m5.registry-scan",
        module="M5",
        name="registry-scan",
        version="1.0",
        title="Container registry anonymously enumerable",
        description=(
            "Requests the Docker Registry v2 catalog (``/v2/_catalog``) and a bounded repository "
            "list and reports a registry that answers without authentication (research ch05#15: a "
            "misconfigured Harbor/Docker Registry/ECR reveals every repository and tag). An "
            "external image scanner (Trivy/Syft-class) is used when ARACHNE_M5_SBOM_TOOL is "
            "configured and ARACHNE_M5_REGISTRY_SCAN is enabled. GET only."
        ),
        research_ref="ch05#15",
        cwe="CWE-1104",
        target_kinds=(TargetKind.CLOUD, TargetKind.URL),
        severity_hint="medium",
        type="hybrid",
        safe=True,
        verifiable=True,
        estimated_requests=6,
        requires_active_checks=True,
        runs_on_discovered=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        _client, skipped = http_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        corpus = corpus_for(ctx)
        bases = _endpoint_bases(ctx, "", {"registry"})
        if not bases:
            yield skip(
                ctx,
                "no registry endpoint reference: declare registry:<host:port> or endpoint:<url>",
            )
            return
        catalog_path = corpus.registry_catalog_path()
        markers = corpus.registry_markers()
        findings = 0
        for label, base in bases:
            page = await fetch_page(ctx, f"{base.rstrip('/')}{catalog_path}")
            if page is None or page.status != 200:
                continue
            repositories = _catalog_repositories(page.body)
            if not repositories and text_contains_any(page.body, markers) is None:
                continue
            findings += 1
            yield m5_candidate(
                ctx,
                f"Container registry catalog is anonymous ({label})",
                artifact={
                    "signal": "registry-catalog",
                    "family": "registry",
                    "endpoint": f"{base.rstrip('/')}{catalog_path}",
                    "status": page.status,
                    "repositories": repositories[:10],
                    "repository_count": len(repositories),
                },
                confidence=0.85,
                detail=(
                    f"{base}{catalog_path} listed {len(repositories)} repository(ies) without "
                    "authentication"
                ),
                source=base,
            )
        if not findings:
            yield ctx.clean(
                "no anonymously readable registry catalog found",
                detail=f"probed {len(bases)} registry endpoint(s)",
            )


# --------------------------------------------------------------------------- docker
class DockerSocket(EndpointCheck, RepoCheck, Module):
    """``m5.docker-socket`` — Docker daemon API / socket reachability (ch05#16)."""

    metadata = CheckMetadata(
        id="m5.docker-socket",
        module="M5",
        name="docker-socket",
        version="1.0",
        title="Docker daemon API reachable",
        description=(
            "Probes a Docker daemon's HTTP API (``/version``, ``/info``, ``/containers/json``, "
            "``/images/json``) for anonymous reachability and checks whether the local daemon "
            "socket is present in a reviewed clone's filesystem (research ch05#16: an exposed "
            "socket or TCP API grants host takeover). Read-only: the API is read for its version "
            "and object lists; no container is created and no mount is attempted."
        ),
        research_ref="ch05#16",
        cwe="CWE-306",
        target_kinds=(TargetKind.CLOUD, TargetKind.URL),
        severity_hint="critical",
        type="active",
        safe=True,
        verifiable=True,
        estimated_requests=5,
        requires_active_checks=True,
        runs_on_discovered=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        corpus = corpus_for(ctx)
        markers = corpus.docker_markers()
        privileged = corpus.docker_privileged_markers()
        findings = 0
        base = endpoint_base(ctx)
        if base is not None:
            _client, skipped = http_or_skip(ctx)
            if skipped is None:
                for path in corpus.docker_api_paths():
                    page = await fetch_page(ctx, f"{base.rstrip('/')}{path}")
                    if page is None or page.status != 200:
                        continue
                    marker = text_contains_any(page.body, markers)
                    if marker is None:
                        continue
                    priv = text_contains_any(page.body, privileged)
                    findings += 1
                    yield m5_candidate(
                        ctx,
                        f"Docker daemon API is reachable at {path}",
                        artifact={
                            "signal": "docker-api",
                            "family": "docker",
                            "endpoint": f"{base.rstrip('/')}{path}",
                            "status": page.status,
                            "marker": marker,
                            "privileged_container": priv,
                        },
                        confidence=0.9,
                        detail=(
                            f"{base}{path} answered without authentication, exposing the Docker API"
                            + (" (a privileged container is present)" if priv else "")
                        ),
                        source=base,
                    )
                    break
        root = local_root(ctx)
        if root is not None and ctx.config.m5.docker_socket:
            socket = root / corpus.docker_socket_path().lstrip("/")
            if socket.exists() or (root / "docker.sock").exists():
                findings += 1
                yield m5_candidate(
                    ctx,
                    "Docker socket present in the reviewed artifact",
                    artifact={
                        "signal": "docker-socket",
                        "family": "docker",
                        "socket": corpus.docker_socket_path(),
                        "location": _relative(
                            socket if socket.exists() else root / "docker.sock", root
                        ),
                    },
                    confidence=0.6,
                    detail="a docker.sock artifact is present in the reviewed tree",
                    source=str(root),
                )
        if not findings:
            yield ctx.clean(
                "no reachable Docker daemon API or socket found",
                detail="probed the Docker API paths and the reviewed filesystem",
            )


# --------------------------------------------------------------------------- helpers
def _endpoint_bases(
    ctx: CheckContext, host_template: str, providers: set[str]
) -> list[tuple[str, str]]:
    """``(label, base_url)`` pairs for an endpoint/provider reference."""
    value = ctx.asset.value
    if value.lower().startswith(("http://", "https://")):
        return [(urlsplit(value).hostname or "endpoint", value)]
    provider, _, reference = value.partition(":")
    if provider.lower() in providers and reference:
        if "://" in reference:
            return [(reference, reference)]
        if host_template:
            return [
                (
                    reference,
                    "https://"
                    + host_template.replace("<ref>", reference).replace("<project>", reference),
                )
            ]
        return [(reference, f"https://{reference}")]
    base = endpoint_base(ctx)
    if base:
        return [(urlsplit(base).hostname or "endpoint", base)]
    return []


def _is_json_dump(body: str, markers: tuple[str, ...]) -> bool:
    stripped = body.strip()
    if stripped.startswith(("{", "[")):
        return True
    return text_contains_any(body, markers) is not None


def _json_size(body: str) -> int:
    document = _json_or_none(body)
    if isinstance(document, dict):
        return len(document)
    if isinstance(document, list):
        return len(document)
    return 0


def _table_rows(body: str) -> list[object]:
    document = _json_or_none(body)
    if isinstance(document, list):
        return document
    return []


def _json_or_none(text: str) -> object:
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return None


def _state_secrets(text: str, secret_keys: tuple[str, ...]) -> list[str]:
    """Which secret-shaped keys appear in a state document (names only, never values)."""
    found: list[str] = []
    lowered = text.lower()
    for key in secret_keys:
        if re.search(rf'"{re.escape(key)}"\s*:', lowered) or f"{key} =" in lowered:
            found.append(key)
    return found


def _catalog_repositories(body: str) -> list[str]:
    document = _json_or_none(body)
    if isinstance(document, dict):
        repositories = document.get("repositories")
        if isinstance(repositories, list):
            return [str(item) for item in repositories]
    return []


def _relative(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:  # pragma: no cover - path outside root
        return str(path)


def _yaml_documents(text: str) -> list[object]:
    """Every document of a (possibly multi-document) YAML file, or its JSON form.

    Bounded: a file is one read of ``max_file_bytes`` already; a parse failure yields an
    empty list (the regex pass has still run over the bytes).
    """
    import yaml

    try:
        return [document for document in yaml.safe_load_all(text) if document is not None]
    except yaml.YAMLError:
        return []
