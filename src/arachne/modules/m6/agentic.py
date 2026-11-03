"""``m6.agentic-*`` — the OWASP Agentic Top 10 surface, read passive (REQ-DET-013).

The OWASP Top 10 for Agentic Applications (2026) names ASI01..ASI10. Four of the six items
the requirement prioritises are decidable from *documents the target already publishes*, with
one anonymous ``GET`` each and nothing sent to the agent:

``m6.agentic-tool-manifest`` (ASI02, tool misuse and exploitation)
    An agent/MCP tool manifest that is readable by an unauthenticated caller and enumerates
    tools whose declared capability is destructive (command execution, file mutation,
    credential access, outbound fetch). The tool surface is not merely present — it is
    published to anyone, so a caller with no identity can drive it.
``m6.agentic-memory-store`` (ASI06, memory and context poisoning)
    A memory/vector/context store that answers an unauthenticated read with a collection
    listing. A store reachable without a credential on the same surface a write would use is
    the context-poisoning condition: the agent's long-term context is not integrity-protected.
    ARACHNE reads and stops — it never writes a document into a memory store.
``m6.agentic-human-trust`` (ASI09, human-agent trust exploitation)
    A published agent policy that declares autonomous execution with no human confirmation.
    A human consuming the agent's output has no intervention point, so the trust the human
    extends to that output is not backed by a gate.
``m6.agentic-rogue-runtime`` (ASI10, rogue agents)
    An agent runtime that answers unauthenticated callers with its model, tools and status.
    Nothing binds an operator to the process and nothing binds the caller, so anyone can
    reach and drive an agent the estate has no way to attribute.

**Safety.** Every request in this module is a ``GET`` to a path on the target's own origin,
with no request body and no ``Authorization`` header. Nothing here prompts, instructs, starts
or writes to an agent — the checks read what the target publishes about itself and report the
*condition* it discloses. ``tests/test_agentic_safety.py`` asserts both halves: the source
shape (no non-GET verb, no authorization literal) and the wire (every request the checks issue
is a GET without credentials).
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator, Mapping, Sequence
from typing import Any
from urllib.parse import urlsplit

from arachne.core.results import CheckResult, Evidence
from arachne.core.target import TargetKind
from arachne.modules.base import Asset, CheckMetadata, Module
from arachne.modules.context import CheckContext
from arachne.modules.m5.support import endpoint_base
from arachne.modules.m6.support import m6_candidate, safe_fetch, skip

__all__ = [
    "AGENTIC_CHECKS",
    "AGENTIC_PROBE_PATHS",
    "AgenticHumanTrust",
    "AgenticMemoryStore",
    "AgenticRogueRuntime",
    "AgenticToolManifest",
]

#: The paths each check reads, per concern. Bounded and declarative, so the plan's request
#: estimate is exactly the number of GETs the check can issue.
AGENTIC_PROBE_PATHS: Mapping[str, tuple[str, ...]] = {
    "tool-manifest": (
        "/.well-known/mcp.json",
        "/.well-known/agent.json",
        "/.well-known/ai-plugin.json",
        "/mcp/tools",
        "/api/agent/tools",
    ),
    "memory-store": (
        "/api/memory",
        "/v1/memory",
        "/api/context",
        "/v1/collections",
        "/collections",
    ),
    "human-trust": (
        "/.well-known/agent-policy.json",
        "/.well-known/ai-policy.json",
        "/agent/config",
        "/api/agent/config",
        "/mcp/config",
    ),
    "rogue-runtime": (
        "/agent/status",
        "/api/agent/status",
        "/agent",
        "/api/agent",
        "/assistant",
    ),
}

#: Capability classes that make a tool dangerous to publish unauthenticated, with the markers
#: that name them in a tool's name or description. Ordered: the first class a tool matches is
#: the one reported, so one tool contributes one capability.
_DANGEROUS_CAPABILITIES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("command-execution", ("shell", "exec", "command", "cmd", "bash", "subprocess", "terminal")),
    ("file-mutation", ("write_file", "write-file", "delete", "remove", "unlink", "overwrite")),
    ("code-execution", ("eval", "python", "script", "run_code")),
    ("sql-execution", ("sql", "query", "database", "db_")),
    ("credential-access", ("credential", "secret", "token", "password", "apikey", "api_key")),
    ("outbound-fetch", ("fetch", "http", "url", "webhook", "download")),
    ("sensitive-egress", ("email", "sms", "publish", "deploy", "transfer")),
)

#: Keys a document uses to list the tools an agent may call.
_TOOL_LIST_KEYS: tuple[str, ...] = ("tools", "toolset", "functions", "capabilities", "actions")

#: Keys that identify a document as a *memory/context store* rather than some other JSON.
_MEMORY_STORE_KEYS: tuple[str, ...] = (
    "collections",
    "memories",
    "memory",
    "documents",
    "embeddings",
    "vectors",
    "chunks",
    "contexts",
)

#: Keys that identify a document as an *agent runtime* self-description.
_RUNTIME_KEYS: tuple[str, ...] = (
    "model",
    "tools",
    "runtime",
    "system_prompt",
    "system_prompt_hash",
    "capabilities",
    "framework",
    "uptime",
)

#: ``key`` markers that remove the human confirmation step, and the values that activate them.
#: Both directions are needed: ``auto_approve: true`` and ``requires_confirmation: false`` are
#: the same declaration written two ways.
_RELAXING_TRUE_KEYS: tuple[str, ...] = (
    "auto_approve",
    "autoapprove",
    "auto_execute",
    "autonomous",
    "unattended",
    "yolo",
    "bypass_confirmation",
    "skip_approval",
)
_RELAXING_FALSE_KEYS: tuple[str, ...] = (
    "human_in_the_loop",
    "humanintheloop",
    "requires_confirmation",
    "require_confirmation",
    "requires_approval",
    "require_approval",
    "confirm",
    "needs_approval",
    "guardrails",
    "supervised",
)
#: A policy that removes the gate by naming the mode rather than by a boolean.
_NONE_VALUES: frozenset[str] = frozenset({"none", "off", "disabled", "false", "never"})
_MODE_KEYS: tuple[str, ...] = ("approval_mode", "confirmation", "approval", "guardrail_mode")


def _origin(ctx: CheckContext) -> str | None:
    """``scheme://host[:port]`` for this asset, or ``None`` when it names no endpoint."""
    base = endpoint_base(ctx)
    if base is None:
        return None
    parts = urlsplit(base)
    if not parts.scheme or not parts.netloc:
        return None
    return f"{parts.scheme}://{parts.netloc}"


def _supports_url(asset: Asset) -> bool:
    return asset.kind == "url" and asset.value.lower().startswith(("http://", "https://"))


def _unauthenticated_ok(exchange: Any) -> bool:
    """True when the response is a 2xx *served without an authentication challenge*.

    A 2xx that carries ``WWW-Authenticate`` is a challenge a caller is expected to answer, so
    the document is not "published to anyone"; that is the decoy every one of these checks has
    to stay silent on.
    """
    return bool(exchange.ok) and exchange.header("WWW-Authenticate") is None


async def _published(
    ctx: CheckContext, paths: Sequence[str]
) -> tuple[list[tuple[str, Any, Any]], tuple[Evidence, ...]]:
    """``([(url, document, exchange)], evidence)`` for every path that served JSON 2xx anon.

    Only 2xx-without-challenge responses are returned as *documents*; every exchange is
    returned as evidence (as redacted request/response pairs) so a clean result can still cite
    what it read.
    """
    origin = _origin(ctx)
    if origin is None:
        return [], ()
    documents: list[tuple[str, Any, Any]] = []
    cited: list[Evidence] = []
    for path in paths:
        url = f"{origin}{path}"
        exchange = await safe_fetch(ctx, url, anonymous=True)
        if exchange is None:
            continue
        cited.extend(exchange.to_evidence())
        if not _unauthenticated_ok(exchange):
            continue
        document = exchange.json_body()
        if document is None:
            continue
        documents.append((url, document, exchange))
    return documents, tuple(cited)


def _no_origin(ctx: CheckContext) -> CheckResult:
    return skip(ctx, "no HTTP origin on this asset: declare a URL target")


# --------------------------------------------------------------------------- ASI02
def _tool_entries(document: Any) -> tuple[Mapping[str, Any], ...]:
    """Every tool object a manifest lists, wherever the manifest nests its list."""
    found: list[Mapping[str, Any]] = []

    def visit(node: Any, depth: int) -> None:
        if depth > 4 or not isinstance(node, Mapping):
            return
        for key in _TOOL_LIST_KEYS:
            value = node.get(key)
            if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
                found.extend(item for item in value if isinstance(item, Mapping))
            elif isinstance(value, Mapping):
                # A dict-of-tools (``{"tools": {"search": {...}}}``) names each key.
                found.extend(
                    {**item, "name": item.get("name") or key}
                    for key, item in value.items()
                    if isinstance(item, Mapping)
                )
        for value in node.values():
            if isinstance(value, Mapping):
                visit(value, depth + 1)

    visit(document, 0)
    return tuple(found)


def _tool_capability(tool: Mapping[str, Any]) -> str | None:
    """The dangerous capability a tool declares, or ``None`` when it declares none."""
    text = " ".join(
        str(tool.get(key) or "") for key in ("name", "title", "description", "summary")
    ).lower()
    if not text:
        return None
    for capability, markers in _DANGEROUS_CAPABILITIES:
        if any(marker in text for marker in markers):
            return capability
    return None


class AgenticToolManifest(Module):
    """``m6.agentic-tool-manifest`` — high-impact tools published to unauthenticated callers."""

    metadata = CheckMetadata(
        id="m6.agentic-tool-manifest",
        module="M6",
        name="agentic-tool-manifest",
        version="1.0",
        title="Agent tool manifest publishes high-impact tools without an authorization gate",
        description=(
            "Reads the agent/MCP tool manifests a target publishes with one anonymous GET per "
            "path and reports a manifest that answers without an authentication challenge while "
            "it enumerates tools whose declared capability is destructive (command execution, "
            "file mutation, credential access, outbound fetch). The condition is the missing "
            "authorization gate on the tool surface, not the tools themselves. Read-only: the "
            "documents are parsed and no tool is ever invoked."
        ),
        research_ref="ch06#15",
        framework=("API5:2023", "LLM06:2025", "ASI02:2026", "CWE-269"),
        cwe="CWE-269",
        target_kinds=(TargetKind.URL,),
        severity_hint="high",
        type="hybrid",
        safe=True,
        verifiable=True,
        estimated_requests=len(AGENTIC_PROBE_PATHS["tool-manifest"]),
    )

    def supports(self, asset: Asset) -> bool:
        return Module.supports(self, asset) and _supports_url(asset)

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        if _origin(ctx) is None:
            yield _no_origin(ctx)
            return
        documents, cited = await _published(ctx, AGENTIC_PROBE_PATHS["tool-manifest"])
        if not documents:
            yield ctx.clean(
                "no unauthenticated agent tool manifest is published",
                detail="every tool-manifest path was absent, not JSON, or behind a challenge",
                evidence=list(cited),
            )
            return
        findings = 0
        for url, document, exchange in documents:
            tools = _tool_entries(document)
            dangerous = [
                (str(tool.get("name") or tool.get("title") or "unnamed"), capability)
                for tool in tools
                if (capability := _tool_capability(tool)) is not None
            ]
            if not dangerous:
                continue
            findings += 1
            names = ", ".join(name for name, _ in dangerous)
            capabilities = sorted({capability for _, capability in dangerous})
            yield m6_candidate(
                ctx,
                "Agent tool manifest publishes high-impact tools to unauthenticated callers",
                artifact={
                    "signal": "agentic-tool-manifest",
                    "family": "agentic",
                    "asi_item": "ASI02:2026",
                    "endpoint": url,
                    "tools": [
                        {"name": name, "capability": capability} for name, capability in dangerous
                    ],
                    "capabilities": capabilities,
                    "authenticated": False,
                    "severity_hint": "high",
                },
                exchanges=(exchange,),
                cwe="CWE-269",
                confidence=0.6,
                detail=(
                    f"{url} answers an unauthenticated GET and enumerates {len(dangerous)} "
                    f"high-impact tool(s) ({names}) covering {', '.join(capabilities)}; the tool "
                    "surface has no authorization gate, which is the tool-misuse condition "
                    "(ASI02). ARACHNE did not invoke any tool."
                ),
                source=url,
            )
        if not findings:
            yield ctx.clean(
                "the published tool manifests list no high-impact tool",
                detail=(
                    f"{len(documents)} manifest(s) reviewed; every tool declares a benign "
                    "capability"
                ),
                evidence=list(cited),
            )


# --------------------------------------------------------------------------- ASI06
def _memory_document(document: Any) -> bool:
    """True when a JSON document reads as a memory/context collection listing."""
    if isinstance(document, Sequence) and not isinstance(document, (str, bytes)):
        return all(isinstance(item, Mapping) for item in document) and bool(document)
    if not isinstance(document, Mapping):
        return False
    for key in _MEMORY_STORE_KEYS:
        value = document.get(key)
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes)) and value:
            return True
    return any(key in document for key in ("count", "size", "total")) and any(
        key in document for key in _MEMORY_STORE_KEYS
    )


class AgenticMemoryStore(Module):
    """``m6.agentic-memory-store`` — the agent's context store readable without a credential."""

    metadata = CheckMetadata(
        id="m6.agentic-memory-store",
        module="M6",
        name="agentic-memory-store",
        version="1.0",
        title="Agent memory store is readable without authentication",
        description=(
            "Reads the memory/vector/context endpoints a target publishes with one anonymous GET "
            "per path and reports one that answers 2xx without an authentication challenge with a "
            "collection listing. A context store reachable with no credential on the same surface "
            "a write would use is the context-poisoning condition (ASI06): the agent's long-term "
            "context is not integrity-protected. Read-only: ARACHNE reads and writes nothing."
        ),
        research_ref="ch06#15",
        framework=(
            "WSTG-ATHN-04",
            "API2:2023",
            "LLM04:2025",
            "LLM08:2025",
            "ASI06:2026",
            "CWE-345",
        ),
        cwe="CWE-345",
        target_kinds=(TargetKind.URL,),
        severity_hint="high",
        type="hybrid",
        safe=True,
        verifiable=True,
        estimated_requests=len(AGENTIC_PROBE_PATHS["memory-store"]),
    )

    def supports(self, asset: Asset) -> bool:
        return Module.supports(self, asset) and _supports_url(asset)

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        if _origin(ctx) is None:
            yield _no_origin(ctx)
            return
        documents, cited = await _published(ctx, AGENTIC_PROBE_PATHS["memory-store"])
        if not documents:
            yield ctx.clean(
                "no unauthenticated agent memory store is published",
                detail="every memory/context path was absent, not JSON, or behind a challenge",
                evidence=list(cited),
            )
            return
        findings = 0
        for url, document, exchange in documents:
            if not _memory_document(document):
                continue
            findings += 1
            yield m6_candidate(
                ctx,
                "Agent memory store answers an unauthenticated read",
                artifact={
                    "signal": "agentic-memory-exposure",
                    "family": "agentic",
                    "asi_item": "ASI06:2026",
                    "endpoint": url,
                    "root": sorted(str(key) for key in document)[:16]
                    if isinstance(document, Mapping)
                    else ["<list>"],
                    "authenticated": False,
                    "severity_hint": "high",
                },
                exchanges=(exchange,),
                cwe="CWE-345",
                confidence=0.6,
                detail=(
                    f"{url} returns a context/collection listing to an unauthenticated GET and "
                    "presents no authentication challenge; a store reachable this way offers no "
                    "integrity boundary for the entries an agent later treats as context, which is "
                    "the memory-poisoning condition (ASI06). ARACHNE read the listing and wrote "
                    "nothing — no entry was added, changed or deleted."
                ),
                source=url,
            )
        if not findings:
            yield ctx.clean(
                "the published documents read as something other than a memory store",
                detail=f"{len(documents)} document(s) reviewed; none lists memories or collections",
                evidence=list(cited),
            )


# --------------------------------------------------------------------------- ASI09
def _confirmation_removed(document: Any) -> tuple[str, str] | None:
    """``(key, value)`` for the first declaration that removes the human confirmation step.

    Recursive over nested objects, bounded in depth, so a policy that nests its guardrail
    block under ``agent`` or ``guardrails`` is read the same way as a flat one.
    """
    found: list[tuple[str, str]] = []

    def visit(node: Any, depth: int) -> None:
        if depth > 4 or not isinstance(node, Mapping):
            return
        for key, value in node.items():
            lowered = str(key).lower()
            if lowered in _RELAXING_TRUE_KEYS and value is True:
                found.append((str(key), "true"))
            elif lowered in _RELAXING_FALSE_KEYS and value is False:
                found.append((str(key), "false"))
            elif lowered in _MODE_KEYS and isinstance(value, str):
                if value.strip().lower() in _NONE_VALUES:
                    found.append((str(key), value.strip()))
            elif isinstance(value, Mapping):
                visit(value, depth + 1)
        return

    visit(document, 0)
    return found[0] if found else None


def _guardrail_present(document: Any) -> bool:
    """True when the document declares an *active* human confirmation step (the decoy)."""
    active = ("true", "required", "on", "enabled", "always", "manual", "strict")

    def visit(node: Any, depth: int) -> bool:
        if depth > 4 or not isinstance(node, Mapping):
            return False
        for key, value in node.items():
            lowered = str(key).lower()
            if lowered in _RELAXING_TRUE_KEYS and value is False:
                return True
            if lowered in _RELAXING_FALSE_KEYS and value is True:
                return True
            if lowered in _MODE_KEYS and isinstance(value, str) and value.strip().lower() in active:
                return True
            if isinstance(value, Mapping) and visit(value, depth + 1):
                return True
        return False

    return visit(document, 0)


class AgenticHumanTrust(Module):
    """``m6.agentic-human-trust`` — a published policy that removes the human gate."""

    metadata = CheckMetadata(
        id="m6.agentic-human-trust",
        module="M6",
        name="agentic-human-trust",
        version="1.0",
        title="Agent policy declares autonomous execution without human confirmation",
        description=(
            "Reads the agent policy documents a target publishes with one anonymous GET per path "
            "and reports a policy that declares its actions run without human confirmation "
            "(`auto_approve`, `requires_confirmation: false`, `approval_mode: none`). With no "
            "confirmation step a human has no intervention point, so the trust they extend to the "
            "agent's output is not backed by a control — the human-agent trust condition (ASI09). "
            "Read-only: the published document is parsed and no instruction is sent to the agent."
        ),
        research_ref="ch06#15",
        framework=("WSTG-BUSL-06", "API5:2023", "LLM06:2025", "ASI09:2026", "CWE-863"),
        cwe="CWE-863",
        target_kinds=(TargetKind.URL,),
        severity_hint="medium",
        type="hybrid",
        safe=True,
        verifiable=True,
        estimated_requests=len(AGENTIC_PROBE_PATHS["human-trust"]),
    )

    def supports(self, asset: Asset) -> bool:
        return Module.supports(self, asset) and _supports_url(asset)

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        if _origin(ctx) is None:
            yield _no_origin(ctx)
            return
        documents, cited = await _published(ctx, AGENTIC_PROBE_PATHS["human-trust"])
        if not documents:
            yield ctx.clean(
                "no unauthenticated agent policy document is published",
                detail="every policy path was absent, not JSON, or behind a challenge",
                evidence=list(cited),
            )
            return
        findings = 0
        for url, document, exchange in documents:
            declared = _confirmation_removed(document)
            if declared is None or _guardrail_present(document):
                continue
            key, value = declared
            findings += 1
            yield m6_candidate(
                ctx,
                "Agent policy removes the human confirmation step",
                artifact={
                    "signal": "agentic-human-trust",
                    "family": "agentic",
                    "asi_item": "ASI09:2026",
                    "endpoint": url,
                    "declaration": {key: value},
                    "authenticated": False,
                    "severity_hint": "medium",
                },
                exchanges=(exchange,),
                cwe="CWE-863",
                confidence=0.55,
                detail=(
                    f"{url} declares `{key}: {value}`, so the deployment runs the agent's actions "
                    "without a human confirmation step; a human reading the agent's output has no "
                    "intervention point, which is the human-agent trust condition (ASI09). "
                    "ARACHNE read the published policy only."
                ),
                source=url,
            )
        if not findings:
            yield ctx.clean(
                "no published agent policy removes the human confirmation step",
                detail=f"{len(documents)} document(s) reviewed; each keeps a confirmation gate",
                evidence=list(cited),
            )


# --------------------------------------------------------------------------- ASI10
def _runtime_description(document: Any) -> tuple[str, ...]:
    """The self-describing keys an agent runtime publishes (``model``, ``tools``, ...)."""
    if not isinstance(document, Mapping):
        return ()
    lowered = {str(key).lower() for key in document}
    return tuple(sorted(key for key in _RUNTIME_KEYS if key in lowered))


class AgenticRogueRuntime(Module):
    """``m6.agentic-rogue-runtime`` — an unauthenticated, unmanaged agent runtime."""

    metadata = CheckMetadata(
        id="m6.agentic-rogue-runtime",
        module="M6",
        name="agentic-rogue-runtime",
        version="1.0",
        title="Agent runtime answers unauthenticated callers with its own configuration",
        description=(
            "Reads the agent runtime endpoints a target publishes with one anonymous GET per path "
            "and reports one that answers 2xx without an authentication challenge while "
            "self-describing (its model, tools, framework or uptime). Nothing binds an operator to "
            "the process and nothing binds the caller, so any reachable host can drive an agent "
            "the estate cannot attribute — the unmanaged/rogue-agent condition (ASI10). Read-only: "
            "the description is parsed and no agent action is requested."
        ),
        research_ref="ch06#15",
        framework=("API2:2023", "ASI10:2026", "CWE-306"),
        cwe="CWE-306",
        target_kinds=(TargetKind.URL,),
        severity_hint="high",
        type="hybrid",
        safe=True,
        verifiable=True,
        estimated_requests=len(AGENTIC_PROBE_PATHS["rogue-runtime"]),
    )

    def supports(self, asset: Asset) -> bool:
        return Module.supports(self, asset) and _supports_url(asset)

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        if _origin(ctx) is None:
            yield _no_origin(ctx)
            return
        documents, cited = await _published(ctx, AGENTIC_PROBE_PATHS["rogue-runtime"])
        if not documents:
            yield ctx.clean(
                "no unauthenticated agent runtime is published",
                detail="every runtime path was absent, not JSON, or behind a challenge",
                evidence=list(cited),
            )
            return
        findings = 0
        for url, document, exchange in documents:
            declared = _runtime_description(document)
            if len(declared) < 2:
                continue
            findings += 1
            yield m6_candidate(
                ctx,
                "Agent runtime self-describes to unauthenticated callers",
                artifact={
                    "signal": "agentic-rogue-runtime",
                    "family": "agentic",
                    "asi_item": "ASI10:2026",
                    "endpoint": url,
                    "fields": list(declared),
                    "authenticated": False,
                    "severity_hint": "high",
                },
                exchanges=(exchange,),
                cwe="CWE-306",
                confidence=0.55,
                detail=(
                    f"{url} answers an unauthenticated GET with the runtime's own configuration "
                    f"({', '.join(declared)}) and presents no authentication challenge; with no "
                    "credential binding an operator or a caller to the process, this is the "
                    "unmanaged-agent condition (ASI10) — the estate cannot attribute or constrain "
                    "who drives it. ARACHNE read the description and requested no action."
                ),
                source=url,
            )
        if not findings:
            yield ctx.clean(
                "the published documents do not describe an agent runtime",
                detail=(
                    f"{len(documents)} document(s) reviewed; none names a model, a tool, a "
                    "framework or a runtime"
                ),
                evidence=list(cited),
            )


#: Every ASI check this module registers, so the safety suite can enumerate the family.
AGENTIC_CHECKS: tuple[type[Module], ...] = (
    AgenticToolManifest,
    AgenticMemoryStore,
    AgenticHumanTrust,
    AgenticRogueRuntime,
)

#: The ASI items this module's checks map to (REQ-DET-013). Named here so the ledger's tally
#: and the requirement's six-item list cannot drift apart.
_ASI_ITEMS: tuple[str, ...] = tuple(
    item
    for check in AGENTIC_CHECKS
    for item in check.metadata.framework
    if re.match(r"^ASI\d{2}:2026$", item)
)


def asi_items() -> tuple[str, ...]:
    """The ``ASI<N>:2026`` items this module maps, in canonical order."""
    return tuple(sorted(set(_ASI_ITEMS)))
