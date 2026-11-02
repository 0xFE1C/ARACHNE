"""``m6.attack-surface-genai`` — the GenAI attack surface, read passively (research ch06#14-15).

Prompt injection is the fastest-growing web flaw class (HackerOne's 2025 report measured a 540%
surge in valid findings), and the surface it lives on — model endpoints, agent tool configs,
leaked model keys and exposed system prompts — is visible from things a scan already has: the
shared web crawl and, when the target declares one, a repository clone. This check therefore
reads *only* those; it never sends an injection payload at a model endpoint
("Safety": nothing M6 does is an active exploitation of the AI itself).

Four signals, each a separate artifact so the rules can reason about them:

``genai-endpoint``
    An LLM/agent API path (``/v1/chat/completions``, ``/api/generate``, ...) answers 2xx to a
    plain GET — an exposed model endpoint (LLM01/LLM10 territory).
``genai-key``
    A hosted-provider API key reached the client or a served document (the HTTP client has
    already redacted it; this reports the *kind*).
``genai-prompt-surface``
    Served content exposes a system prompt or carries the prompt-injection markers of an
    instructions field.
``genai-agent-config``
    A repository ships an agent/assistant configuration (MCP, Claude/Cursor, AGENTS.md) that
    grants tool or secret access — the agent-poisoning surface of ch06#15.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from pathlib import Path
from urllib.parse import urlsplit

from arachne.core.results import CheckResult
from arachne.core.target import TargetKind
from arachne.modules.base import Asset, CheckMetadata, Module
from arachne.modules.context import CheckContext
from arachne.modules.m3.support import owns_origin
from arachne.modules.m6.corpus import M6Corpus
from arachne.modules.m6.support import (
    corpus_for,
    finding_cap,
    iter_repo_files,
    local_root,
    m6_candidate,
    read_text,
    skip,
)

__all__ = ["AttackSurfaceGenai"]


class AttackSurfaceGenai(Module):
    """``m6.attack-surface-genai`` — exposed model endpoints, prompt hygiene, agent configs."""

    metadata = CheckMetadata(
        id="m6.attack-surface-genai",
        version="1.0",
        title="Generative-AI attack surface",
        description=(
            "Reviews the crawled surface and a declared repository for the GenAI attack "
            "surface: an exposed LLM/agent API endpoint answering 2xx, a hosted-model API key "
            "reaching a client or served document, a served system prompt or prompt-injection "
            "marker, and an agent/tool configuration that grants secret or command access "
            "(research ch06#14-15). Passive: it reads the crawl and local files and never sends "
            "a prompt or injection payload."
        ),
        module="M6",
        name="attack-surface-genai",
        research_ref="ch06#14-15",
        framework=(
            "WSTG-INFO-06",
            "LLM01:2025",
            "LLM02:2025",
            "LLM07:2025",
            "LLM10:2025",
            "ASI02:2026",
            "ASI03:2026",
            "CWE-1426",
        ),
        cwe="CWE-1426",
        target_kinds=(TargetKind.URL, TargetKind.DOMAIN, TargetKind.GIT, TargetKind.CLOUD),
        severity_hint="medium",
        type="passive",
        safe=True,
        verifiable=False,
        estimated_requests=0,
    )

    def supports(self, asset: Asset) -> bool:
        if not Module.supports(self, asset):
            return False
        return asset.kind in {"url", "domain", "git", "cloud"}

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        corpus = corpus_for(ctx)
        produced = 0
        if ctx.asset.kind in {"git", "cloud"}:
            root = local_root(ctx)
            if root is None or not root.exists():
                yield skip(ctx, "no local repository to review for agent configurations")
                return
            async for result in self._scan_repo(ctx, corpus, root):
                produced += 1
                yield result
        else:
            async for result in self._scan_web(ctx, corpus):
                produced += 1
                yield result
        if not produced:
            yield ctx.clean(
                "no GenAI attack surface observed",
                detail="no exposed model endpoint, agent config, leaked model key or system prompt",
            )

    # ------------------------------------------------------------------ served surface
    async def _scan_web(self, ctx: CheckContext, corpus: M6Corpus) -> AsyncIterator[CheckResult]:
        inventory = ctx.web
        if inventory is None:
            yield skip(
                ctx,
                "no web inventory for this step: the checks step crawls the endpoints (S6/M3)",
            )
            return
        slug: str | None = urlsplit(ctx.asset.value).hostname if ctx.asset.kind == "url" else None
        if slug is not None and not owns_origin(ctx):
            return
        endpoints = {path.lower() for path in corpus.genai_endpoint_paths()}
        key_patterns = corpus.genai_key_patterns()
        prompt_markers = corpus.genai_prompt_surface_markers()
        produced = 0

        for page in inventory.pages.values():
            if slug is not None and urlsplit(page.url).hostname != slug:
                continue
            path = urlsplit(page.url).path.lower()
            if (
                any(path.endswith(candidate) for candidate in endpoints)
                and 200 <= page.status < 300
            ):
                produced += 1
                yield m6_candidate(
                    ctx,
                    f"Exposed LLM/agent endpoint: {page.url}",
                    artifact={
                        "signal": "genai-endpoint",
                        "family": "genai",
                        "location": page.url,
                        "http_status": page.status,
                        "content_type": page.content_type,
                    },
                    cwe="CWE-1426",
                    confidence=0.6,
                    detail=(
                        f"{page.url} answers {page.status} on an LLM/agent API path without a "
                        "recorded auth challenge"
                    ),
                    source=page.url,
                )
                if produced >= finding_cap(ctx):
                    return
            body = page.body
            lowered = body.lower()
            for signature in key_patterns:
                if signature.regex.search(body):
                    produced += 1
                    yield m6_candidate(
                        ctx,
                        f"Hosted-model API key exposed ({signature.kind})",
                        artifact={
                            "signal": "genai-key",
                            "family": "genai",
                            "location": page.url,
                            "kind": signature.kind,
                        },
                        cwe="CWE-1426",
                        confidence=0.7,
                        detail=f"{page.url}: a {signature.kind} shaped key is present (masked)",
                        source=page.url,
                    )
                    break
            if any(marker in lowered for marker in prompt_markers):
                produced += 1
                yield m6_candidate(
                    ctx,
                    f"Prompt surface exposed at {page.url}",
                    artifact={
                        "signal": "genai-prompt-surface",
                        "family": "genai",
                        "location": page.url,
                    },
                    cwe="CWE-1426",
                    confidence=0.5,
                    detail=(
                        f"{page.url}: served content exposes a system prompt or instruction field"
                    ),
                    source=page.url,
                )
            if produced >= finding_cap(ctx):
                return

    # ------------------------------------------------------------------ repository
    async def _scan_repo(
        self, ctx: CheckContext, corpus: M6Corpus, root: Path
    ) -> AsyncIterator[CheckResult]:
        risk_markers = corpus.genai_agent_risk_markers()
        produced = 0
        for path in iter_repo_files(
            root,
            corpus.genai_agent_config_globs(),
            max_files=ctx.config.m6.max_repo_files,
            max_bytes=ctx.config.m6.max_file_bytes,
        ):
            text = read_text(path, limit=ctx.config.m6.max_file_bytes)
            if text is None:
                continue
            lowered = text.lower()
            hits = [marker for marker in risk_markers if marker in lowered]
            relative = path.relative_to(root).as_posix()
            produced += 1
            yield m6_candidate(
                ctx,
                f"Agent/tool configuration present: {relative}",
                artifact={
                    "signal": "genai-agent-config",
                    "family": "genai",
                    "location": relative,
                    "risk_markers": hits,
                },
                cwe="CWE-1426",
                confidence=0.5 if hits else 0.35,
                detail=(
                    f"{relative}: an agent/assistant configuration "
                    + (f"referencing {', '.join(hits)}" if hits else "with no obvious tool grant")
                ),
                source=relative,
            )
            if produced >= finding_cap(ctx):
                return
