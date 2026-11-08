"""``m6.ai-*`` — the AI-era serving surface: inference, vector stores, agent frameworks, notebooks.

The AI-era stack is a family of servers that a default deployment leaves answering anyone who
can route to it: an inference server (Ollama, vLLM, Triton, LM Studio), a vector database
(Qdrant, Weaviate, Chroma), an agent/workflow framework (Flowise, n8n, Dify, Airflow,
Langflow) and a notebook server (Jupyter, Zeppelin). Each of them publishes a *status or
metadata document* — a model list, a collection list, a flow list, a kernel list — that a
caller needs no credential to read on a bare installation.

**The claim is the exposure, and only the exposure.** Every check here issues a single
anonymous ``GET`` of one status document and reports it when the service's own fields come
back with no authentication challenge. Nothing else is asked of the service:

* **No prompt, no instruction, no payload reaches a model endpoint.** The check shape has no
  request *body* at all (each request is a bare ``GET`` with no content), and the probe paths
  are validated at import against :data:`INFERENCE_PATH_SEGMENTS`: a check whose declared path
  names an inference operation (``/generate``, ``/completions``, ``/embeddings``,
  ``/predict``, ``/invoke`` …) cannot be *defined*, so "ARACHNE sent an instruction to a model"
  is unrepresentable rather than merely untested. That is the difference between detecting an
  exposed endpoint (this family) and exercising it (permanently out of scope).
* **Nothing is written, listed or executed.** The Ollama and Triton checks read a *model index*
  (names and states), never a model; the vector-database checks read a *collection listing*,
  never a vector; the notebook checks read the *kernel list*, never run a cell; and no check
  issues anything but a read request — the module contains no state-changing verb at all.
* **A service that answers is not a service that is exposed.** A ``2xx`` carrying a
  ``WWW-Authenticate`` challenge, a ``401``/``403``, a network-restricted deployment (a
  fronting proxy that refuses the path) and a document that is not the service's own are all
  *non-findings*: that is the requirement's decoy ("authenticated or network-restricted
  deployments") and the reason a marker — a field of the service's own document — is required
  before anything is reported.

**No duplicate claim.** ``m3.api-surface`` reports a *published API document* (OpenAPI/Swagger)
and ``m6.attack-surface-genai`` reports a served *model endpoint* or system prompt from the
crawl. This family reports a different fact on different paths: the serving products' own
status and index documents (``/api/tags`` rather than ``/v1/chat/completions``), and it never
probes an inference route at all.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Mapping
from typing import Any, ClassVar, Final, cast
from urllib.parse import urlsplit

from arachne.core.proof import ProofLevel
from arachne.core.results import CheckResult
from arachne.core.target import TargetKind
from arachne.modules.base import Asset, CheckMetadata, Module, SeverityHint
from arachne.modules.context import CheckContext
from arachne.modules.m5.support import endpoint_base
from arachne.modules.m6.support import m6_candidate, safe_fetch, skip

__all__ = [
    "AI_SURFACE_CHECKS",
    "INFERENCE_PATH_SEGMENTS",
    "SERVICE_OF_CHECK",
    "SURFACE_AREAS",
    "AiSurfaceCheck",
    "AiSurfaceError",
    "ai_surface_metadata",
    "probe_paths_of",
]

#: Path *segments* that name an inference operation. A declared probe path containing one is
#: refused at import: the family reads status and index documents only, and a check that wanted
#: to call ``/generate`` or ``/completions`` cannot be declared. This is the structural control
#: behind the requirement's "no prompt, instruction or payload to a model endpoint" — the
#: vocabulary in which such a request would be written does not exist in this module.
INFERENCE_PATH_SEGMENTS: Final[frozenset[str]] = frozenset(
    {
        "generate",
        "generation",
        "completion",
        "completions",
        "chat",
        "embed",
        "embedding",
        "embeddings",
        "predict",
        "prediction",
        "invoke",
        "invocations",
        "rerank",
        "inference",
        "responses",
        "prompt",
        "prompts",
    }
)

#: The compliance controls every member bears on. Reused from WP-30/33, which validated the
#: ids against the pinned inventories: authentication/authorization and data exposure.
_COMPLIANCE: Final[tuple[str, ...]] = ("CIS-4.7", "ISO-A.5.15", "ISO-A.8.2", "PCI-7")
#: Data-exposure controls, for the members whose finding is a data surface (an index listing)
#: rather than a control plane.
_COMPLIANCE_DATA: Final[tuple[str, ...]] = ("CIS-4.7", "ISO-A.5.15", "ISO-A.8.12", "PCI-7")

_AUTH_STATUSES: Final[frozenset[int]] = frozenset({401, 403})


class AiSurfaceError(ValueError):
    """A check declares a probe this family does not permit."""


def _path_segments(path: str) -> tuple[str, ...]:
    """The non-empty segments of a URL path, lower-cased and stripped of a file extension."""
    segments: list[str] = []
    for raw in path.split("/"):
        segment = raw.strip().lower()
        if not segment:
            continue
        segment = segment.split(".", 1)[0]
        segment = segment.split("?", 1)[0]
        if segment:
            segments.append(segment)
    return tuple(segments)


def _assert_status_path(path: str) -> None:
    """Refuse a probe path that names an inference operation (unrepresentable by construction)."""
    if not path.startswith("/"):
        msg = f"ai-surface probe path {path!r} must be absolute"
        raise AiSurfaceError(msg)
    offenders = sorted(set(_path_segments(path)) & INFERENCE_PATH_SEGMENTS)
    if offenders:
        msg = (
            f"ai-surface probe path {path!r} names an inference operation {offenders}: this "
            "family reads status and index documents only and never calls a model endpoint"
        )
        raise AiSurfaceError(msg)


def ai_surface_metadata(
    *,
    name: str,
    title: str,
    description: str,
    research_ref: str,
    cwe: str,
    framework: tuple[str, ...],
    compliance: tuple[str, ...],
    severity: SeverityHint,
    estimated_requests: int,
) -> CheckMetadata:
    """One family check's metadata: L1, safe, hybrid (a read of the target's own origin).

    The family's contract is uniform — an anonymous GET of a status document on the asset's own
    origin — so no member declares a credentials requirement, a state-change attestation or an
    active-check opt-in: the request is a plain read of a URL the target already serves.
    """
    return CheckMetadata(
        id=f"m6.{name}",
        module="M6",
        name=name,
        version="1.0",
        title=title,
        description=description,
        research_ref=research_ref,
        cwe=cwe,
        framework=framework,
        compliance=compliance,
        severity_hint=severity,
        type="hybrid",
        safe=True,
        verifiable=True,
        enabled_by_default=True,
        proof=ProofLevel.L1,
        estimated_requests=estimated_requests,
        target_kinds=(TargetKind.URL,),
    )


# --------------------------------------------------------------------------- matching
def _has_key(node: Any, key: str, *, depth: int = 0) -> bool:
    """True when ``key`` appears as a mapping key anywhere in ``node`` (bounded walk)."""
    if depth > 6:
        return False
    if isinstance(node, Mapping):
        if key in node:
            return True
        return any(_has_key(value, key, depth=depth + 1) for value in node.values())
    if isinstance(node, (list, tuple)):
        return any(_has_key(item, key, depth=depth + 1) for item in node)
    return False


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


# --------------------------------------------------------------------------- the base check
class AiSurfaceCheck:
    """The family's shared shape: read the declared status documents, classify, report.

    A concrete check is declared ``class X(AiSurfaceCheck, Module)`` and sets ``probe_paths``
    (the status/index documents it reads), ``document_keys`` (the fields that prove the answer
    is that product's own document) and its metadata. The class declares no request method and
    no body: every request is the shared client's anonymous ``GET``.
    """

    metadata: ClassVar[CheckMetadata]
    #: The status/index paths this check reads. Validated at import: none may name an inference
    #: operation (:data:`INFERENCE_PATH_SEGMENTS`).
    probe_paths: ClassVar[tuple[str, ...]] = ()
    #: The fields of the product's own document that confirm the answer. All are searched; the
    #: first match is the marker the finding cites.
    document_keys: ClassVar[tuple[str, ...]] = ()
    #: The service this check covers (the requirement's scope area), for the fixture matrix.
    service: ClassVar[str] = ""
    finding_title: ClassVar[str] = "AI-era service answers without authentication ({target})"
    signal: ClassVar[str] = "ai-service-exposure"

    def __init_subclass__(cls, **kwargs: Any) -> None:
        super().__init_subclass__(**kwargs)
        if not getattr(cls, "probe_paths", ()):  # the abstract base and the mixin
            return
        for path in cls.probe_paths:
            _assert_status_path(path)

    def supports(self, asset: Asset) -> bool:
        # The mixin is declared before ``Module`` in every concrete check, so ``self`` *is* a
        # :class:`Module` at run time; the cast states that to the type checker.
        return Module.supports(cast("Module", self), asset) and _supports_url(asset)

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        origin = _origin(ctx)
        if origin is None:
            yield skip(ctx, "no HTTP origin on this asset: declare a URL target")
            return
        cited: list[Any] = []
        hits: list[tuple[str, str, Any]] = []
        for path in self.probe_paths:
            url = f"{origin}{path}"
            exchange = await safe_fetch(ctx, url, anonymous=True)
            if exchange is None:
                continue
            cited.extend(exchange.to_evidence())
            marker = self._marker(exchange)
            if marker is not None:
                hits.append((url, marker, exchange))

        if not hits:
            yield ctx.clean(
                f"no unauthenticated {self.service or 'AI-era'} service found",
                detail=(
                    f"read {len(self.probe_paths)} status path(s) on {origin}; every answer was "
                    "a challenge, an error, a restricted answer or another document"
                ),
                evidence=cited,
            )
            return
        for url, marker, exchange in hits:
            yield self._candidate(ctx, url, marker, exchange)

    def _marker(self, exchange: Any) -> str | None:
        """The product's own document field this answer carries, or ``None``.

        A challenge (``WWW-Authenticate``), an auth status or a non-2xx is never an exposure,
        and a document that does not carry one of the product's own fields is not this service's
        document — a different product, a proxy page or a soft 404.
        """
        if int(exchange.status_code) in _AUTH_STATUSES:
            return None
        if not exchange.ok or exchange.header("WWW-Authenticate") is not None:
            return None
        document = exchange.json_body()
        if document is None:
            return None
        return next((key for key in self.document_keys if _has_key(document, key)), None)

    def _candidate(self, ctx: CheckContext, url: str, marker: str, exchange: Any) -> CheckResult:
        return m6_candidate(
            ctx,
            self.finding_title.format(target=url),
            artifact={
                "signal": self.signal,
                "family": "ai-surface",
                "service": self.service,
                "endpoint": url,
                "marker": marker,
                "anonymous": True,
                "read_only": True,
                "command_issued": False,
                "state_changed": False,
            },
            exchanges=(exchange,),
            cwe=self.metadata.cwe,
            confidence=0.85,
            detail=(
                f"{url} returned HTTP {int(exchange.status_code)} with {self.service}'s own "
                f"document (marker {marker!r}) and no credential; nothing was sent to a model "
                "endpoint and nothing was written"
            ),
            source=url,
        )


def _probe_paths_of(check: type[Module]) -> tuple[str, ...]:
    paths = getattr(check, "probe_paths", ())
    if not isinstance(paths, tuple):  # pragma: no cover - a declaration defect
        msg = f"{check.metadata.id} declares no probe_paths tuple"
        raise TypeError(msg)
    return paths


def probe_paths_of(check: type[Module]) -> tuple[str, ...]:
    """The status paths a family check declares (the acceptance test's own control table)."""
    return _probe_paths_of(check)


# --------------------------------------------------------------------------- inference servers
class OllamaModelList(AiSurfaceCheck, Module):
    """``m6.ollama-model-list`` — an Ollama server's local model index, unauthenticated."""

    service = "ollama"
    probe_paths = ("/api/tags",)
    document_keys = ("models",)
    finding_title = "Ollama model index served without authentication ({target})"
    metadata = ai_surface_metadata(
        name="ollama-model-list",
        title="Ollama model index readable without authentication",
        description=(
            "Reads Ollama's own local-model index with one anonymous GET and reports it when "
            "the server answers with its model list and no authentication challenge. The list "
            "names every model the host carries and its digest, which is both an inventory "
            "disclosure and the supply-chain surface of an inference host that anyone can "
            "reach. Read-only: a model index is parsed, never loaded, and no generation "
            "endpoint is named or called."
        ),
        research_ref="ch06#14",
        cwe="CWE-306",
        framework=("WSTG-CONF-05", "API8:2023", "LLM02:2025", "LLM03:2025", "CWE-306"),
        compliance=_COMPLIANCE,
        severity="high",
        estimated_requests=1,
    )


class OllamaVersion(AiSurfaceCheck, Module):
    """``m6.ollama-version`` — an Ollama server's version endpoint, unauthenticated."""

    service = "ollama"
    probe_paths = ("/api/version",)
    document_keys = ("version",)
    finding_title = "Ollama version endpoint served without authentication ({target})"
    metadata = ai_surface_metadata(
        name="ollama-version",
        title="Ollama server version disclosed without authentication",
        description=(
            "Reads Ollama's version document with one anonymous GET and reports it when the "
            "server answers its own version field without a challenge. A disclosed server "
            "version is a patch-level signal — it is never a finding on its own, and this "
            "check reports the *exposure* of the version endpoint, not a vulnerability in that "
            "version. Read-only. This is a different claim from the model-index check: a "
            "deployment can publish its version and refuse its index."
        ),
        research_ref="ch06#14",
        cwe="CWE-200",
        framework=("WSTG-CONF-05", "CWE-200", "LLM02:2025"),
        compliance=_COMPLIANCE_DATA,
        severity="medium",
        estimated_requests=1,
    )


class VllmModelList(AiSurfaceCheck, Module):
    """``m6.vllm-model-list`` — a vLLM server's served-model index, unauthenticated."""

    service = "vllm"
    probe_paths = ("/v1/models",)
    document_keys = ("data",)
    finding_title = "vLLM served-model index readable without authentication ({target})"
    metadata = ai_surface_metadata(
        name="vllm-model-list",
        title="vLLM served-model index readable without authentication",
        description=(
            "Reads the OpenAI-compatible model index a vLLM server publishes and reports it "
            "when the server answers its own model list with no authentication challenge. An "
            "unauthenticated inference server is unbounded consumption: anyone who can route "
            "to it can spend the host's compute. Read-only GET of the index; no completion, "
            "chat or embedding route is named or called."
        ),
        research_ref="ch06#14",
        cwe="CWE-306",
        framework=("WSTG-CONF-05", "API8:2023", "LLM03:2025", "LLM10:2025", "CWE-306"),
        compliance=_COMPLIANCE,
        severity="high",
        estimated_requests=1,
    )


class TritonServerMetadata(AiSurfaceCheck, Module):
    """``m6.triton-server-metadata`` — a Triton inference server's metadata document."""

    service = "triton"
    probe_paths = ("/v2",)
    document_keys = ("name", "version")
    finding_title = "Triton inference server metadata served without authentication ({target})"
    metadata = ai_surface_metadata(
        name="triton-server-metadata",
        title="Triton inference server metadata readable without authentication",
        description=(
            "Reads the server-metadata document a Triton inference server publishes at its API "
            "root and reports it when the server answers its own name and version fields with "
            "no challenge. The document confirms the server is an unauthenticated inference "
            "endpoint. Read-only GET of the metadata document; no model is loaded, invoked or "
            "inferred from."
        ),
        research_ref="ch06#14",
        cwe="CWE-200",
        framework=("WSTG-CONF-05", "CWE-200", "LLM02:2025"),
        compliance=_COMPLIANCE_DATA,
        severity="low",
        estimated_requests=1,
    )


class TritonModelRepository(AiSurfaceCheck, Module):
    """``m6.triton-model-repository`` — a Triton model repository's index, unauthenticated."""

    service = "triton"
    probe_paths = ("/v2/repository/index",)
    document_keys = ("state", "name")
    finding_title = "Triton model repository index readable without authentication ({target})"
    metadata = ai_surface_metadata(
        name="triton-model-repository",
        title="Triton model repository index readable without authentication",
        description=(
            "Reads the repository index a Triton server publishes and reports it when the "
            "server answers the models it serves, their versions and their load state with no "
            "challenge. It is a second, independent claim from the server metadata: a "
            "deployment can hide its metadata document and still publish its repository, and "
            "the repository is the model supply-chain surface. Read-only GET of the index; the "
            "check never asks the server to load or unload a model."
        ),
        research_ref="ch06#14",
        cwe="CWE-306",
        framework=("WSTG-CONF-05", "API8:2023", "LLM03:2025", "CWE-306"),
        compliance=_COMPLIANCE,
        severity="medium",
        estimated_requests=1,
    )


class LmStudioModelList(AiSurfaceCheck, Module):
    """``m6.lmstudio-model-list`` — an LM Studio server's model index, unauthenticated."""

    service = "lmstudio"
    probe_paths = ("/api/v0/models",)
    document_keys = ("data", "models")
    finding_title = "LM Studio model index readable without authentication ({target})"
    metadata = ai_surface_metadata(
        name="lmstudio-model-list",
        title="LM Studio model index readable without authentication",
        description=(
            "Reads the local-model index an LM Studio server publishes and reports it when the "
            "server answers its own model list with no authentication challenge. The index "
            "names the models a desktop host has loaded, which is both a disclosure and an "
            "unauthenticated inference surface. Read-only GET of the index; no chat, "
            "completion or embedding route is named or called."
        ),
        research_ref="ch06#14",
        cwe="CWE-306",
        framework=("WSTG-CONF-05", "API8:2023", "LLM02:2025", "LLM03:2025", "CWE-306"),
        compliance=_COMPLIANCE,
        severity="high",
        estimated_requests=1,
    )


# --------------------------------------------------------------------------- vector databases
class QdrantCollections(AiSurfaceCheck, Module):
    """``m6.qdrant-collections`` — a Qdrant collection listing, unauthenticated."""

    service = "qdrant"
    probe_paths = ("/collections",)
    document_keys = ("collections",)
    finding_title = "Qdrant collection listing served without authentication ({target})"
    metadata = ai_surface_metadata(
        name="qdrant-collections",
        title="Qdrant collection listing readable without authentication",
        description=(
            "Reads the collection listing a Qdrant vector database publishes and reports it "
            "when the server answers the collections it holds with no challenge. A vector "
            "store reachable without a credential is the embedding-weakness surface: the "
            "collections are the retrieval corpus an agent grounds its answers on. Read-only "
            "GET of the listing; no vector, point or payload is ever read and nothing is "
            "written."
        ),
        research_ref="ch06#14",
        cwe="CWE-306",
        framework=("WSTG-CONF-05", "API8:2023", "LLM08:2025", "CWE-306"),
        compliance=_COMPLIANCE,
        severity="high",
        estimated_requests=1,
    )


class QdrantCluster(AiSurfaceCheck, Module):
    """``m6.qdrant-cluster`` — a Qdrant cluster status document, unauthenticated."""

    service = "qdrant"
    probe_paths = ("/cluster",)
    document_keys = ("result",)
    finding_title = "Qdrant cluster status served without authentication ({target})"
    metadata = ai_surface_metadata(
        name="qdrant-cluster",
        title="Qdrant cluster status readable without authentication",
        description=(
            "Reads the cluster-status document a Qdrant node publishes and reports it when the "
            "node answers its own peer and consensus state with no challenge. It is a "
            "different claim from the collection listing — a deployment can refuse the "
            "collections and still publish its topology — and it maps the store's peers and "
            "shard layout. Read-only GET of the status document."
        ),
        research_ref="ch06#14",
        cwe="CWE-200",
        framework=("WSTG-CONF-05", "CWE-200", "LLM08:2025"),
        compliance=_COMPLIANCE_DATA,
        severity="low",
        estimated_requests=1,
    )


class WeaviateMeta(AiSurfaceCheck, Module):
    """``m6.weaviate-meta`` — a Weaviate server's metadata document, unauthenticated."""

    service = "weaviate"
    probe_paths = ("/v1/meta",)
    document_keys = ("version", "modules")
    finding_title = "Weaviate metadata served without authentication ({target})"
    metadata = ai_surface_metadata(
        name="weaviate-meta",
        title="Weaviate server metadata readable without authentication",
        description=(
            "Reads the metadata document a Weaviate vector database publishes and reports it "
            "when the server answers its own version and loaded-module fields with no "
            "challenge. The module list names the vectorizer and generative integrations the "
            "store is wired to, which is the embedding pipeline's shape. Read-only GET of the "
            "metadata document."
        ),
        research_ref="ch06#14",
        cwe="CWE-200",
        framework=("WSTG-CONF-05", "API8:2023", "LLM08:2025", "CWE-200"),
        compliance=_COMPLIANCE_DATA,
        severity="medium",
        estimated_requests=1,
    )


class WeaviateSchema(AiSurfaceCheck, Module):
    """``m6.weaviate-schema`` — a Weaviate schema, unauthenticated."""

    service = "weaviate"
    probe_paths = ("/v1/schema",)
    document_keys = ("classes",)
    finding_title = "Weaviate schema served without authentication ({target})"
    metadata = ai_surface_metadata(
        name="weaviate-schema",
        title="Weaviate schema (class inventory) readable without authentication",
        description=(
            "Reads the schema document a Weaviate store publishes and reports it when the "
            "server answers its classes, their properties and their vectorizer settings with "
            "no challenge. A second, independent claim from the metadata document: the schema "
            "is the retrieval model an agent's grounding depends on. Read-only GET of the "
            "schema; no object, vector or tenant is read and nothing is written."
        ),
        research_ref="ch06#14",
        cwe="CWE-306",
        framework=("WSTG-CONF-05", "API8:2023", "LLM08:2025", "CWE-306"),
        compliance=_COMPLIANCE,
        severity="high",
        estimated_requests=1,
    )


class ChromaHeartbeat(AiSurfaceCheck, Module):
    """``m6.chroma-heartbeat`` — a Chroma server's heartbeat document, unauthenticated."""

    service = "chroma"
    probe_paths = ("/api/v1/heartbeat",)
    document_keys = ("nanosecond heartbeat",)
    finding_title = "Chroma heartbeat served without authentication ({target})"
    metadata = ai_surface_metadata(
        name="chroma-heartbeat",
        title="Chroma server heartbeat readable without authentication",
        description=(
            "Reads the heartbeat document a Chroma vector database publishes and reports it "
            "when the server answers its own liveness field with no challenge. The heartbeat "
            "confirms an unauthenticated vector store is reachable. Read-only GET of the "
            "liveness document; no collection, embedding or document is read."
        ),
        research_ref="ch06#14",
        cwe="CWE-200",
        framework=("WSTG-CONF-05", "CWE-200", "LLM08:2025"),
        compliance=_COMPLIANCE_DATA,
        severity="low",
        estimated_requests=1,
    )


class ChromaTenants(AiSurfaceCheck, Module):
    """``m6.chroma-tenants`` — a Chroma server's tenant listing, unauthenticated."""

    service = "chroma"
    probe_paths = ("/api/v2/tenants",)
    document_keys = ("name", "tenants")
    finding_title = "Chroma tenant listing served without authentication ({target})"
    metadata = ai_surface_metadata(
        name="chroma-tenants",
        title="Chroma tenant listing readable without authentication",
        description=(
            "Reads the tenant listing a Chroma server publishes and reports it when the server "
            "answers the tenants it holds with no challenge. It is a different claim from the "
            "heartbeat: a deployment can answer a liveness probe and still expose the "
            "multi-tenant namespace inventory. Read-only GET of the listing; no collection or "
            "embedding is read and nothing is written."
        ),
        research_ref="ch06#14",
        cwe="CWE-306",
        framework=("WSTG-CONF-05", "API8:2023", "LLM08:2025", "CWE-306"),
        compliance=_COMPLIANCE,
        severity="medium",
        estimated_requests=1,
    )


# --------------------------------------------------------------------------- agent frameworks
class FlowiseChatflows(AiSurfaceCheck, Module):
    """``m6.flowise-chatflows`` — a Flowise chatflow listing, unauthenticated."""

    service = "flowise"
    probe_paths = ("/api/v1/chatflows",)
    document_keys = ("flowData", "name")
    finding_title = "Flowise chatflow listing served without authentication ({target})"
    metadata = ai_surface_metadata(
        name="flowise-chatflows",
        title="Flowise chatflow listing readable without authentication",
        description=(
            "Reads the chatflow listing a Flowise agent platform publishes and reports it when "
            "the server answers the flows it holds with no challenge. A chatflow document "
            "carries the flow's own configuration — its prompt, its tools and its model — so "
            "publishing it is the system-prompt-leakage and agentic-supply-chain condition. "
            "Read-only GET of the listing; the check never drives a flow, sends a chat turn or "
            "invokes a tool."
        ),
        research_ref="ch06#14",
        cwe="CWE-306",
        framework=("WSTG-CONF-05", "API8:2023", "LLM07:2025", "ASI04:2026", "CWE-306"),
        compliance=_COMPLIANCE,
        severity="high",
        estimated_requests=1,
    )


class N8nWorkflows(AiSurfaceCheck, Module):
    """``m6.n8n-workflows`` — an n8n workflow listing, unauthenticated."""

    service = "n8n"
    probe_paths = ("/rest/workflows",)
    document_keys = ("nodes", "data")
    finding_title = "n8n workflow listing served without authentication ({target})"
    metadata = ai_surface_metadata(
        name="n8n-workflows",
        title="n8n workflow listing readable without authentication",
        description=(
            "Reads the workflow listing an n8n automation platform publishes and reports it "
            "when the server answers the workflows it holds — their nodes, their connections "
            "and their credential references — with no challenge. The workflow definitions are "
            "the automation supply chain, and a caller with no identity can read them. "
            "Read-only GET of the listing; no workflow is started, executed or published."
        ),
        research_ref="ch06#14",
        cwe="CWE-306",
        framework=("WSTG-CONF-05", "API8:2023", "LLM06:2025", "ASI04:2026", "CWE-306"),
        compliance=_COMPLIANCE,
        severity="high",
        estimated_requests=1,
    )


class DifyAppParameters(AiSurfaceCheck, Module):
    """``m6.dify-app-parameters`` — a Dify application's parameter document, unauthenticated."""

    service = "dify"
    probe_paths = ("/api/v1/parameters",)
    document_keys = ("user_input_form", "system_parameters", "opening_statement")
    finding_title = "Dify application parameters served without authentication ({target})"
    metadata = ai_surface_metadata(
        name="dify-app-parameters",
        title="Dify application parameters readable without authentication",
        description=(
            "Reads the parameter document a Dify LLM application publishes and reports it when "
            "the app answers its input form, its system-parameter block and its opening "
            "statement with no challenge. The document describes the application's prompt "
            "surface and its model configuration — the system-prompt-leakage and agentic "
            "supply-chain condition. Read-only GET of the parameter document; the check never "
            "sends a message or runs the app."
        ),
        research_ref="ch06#14",
        cwe="CWE-306",
        framework=("WSTG-CONF-05", "API8:2023", "LLM07:2025", "ASI04:2026", "CWE-306"),
        compliance=_COMPLIANCE,
        severity="medium",
        estimated_requests=1,
    )


class AirflowDags(AiSurfaceCheck, Module):
    """``m6.airflow-dags`` — an Airflow DAG listing, unauthenticated."""

    service = "airflow"
    probe_paths = ("/api/v1/dags",)
    document_keys = ("dags", "total_entries")
    finding_title = "Airflow DAG listing served without authentication ({target})"
    metadata = ai_surface_metadata(
        name="airflow-dags",
        title="Airflow DAG listing readable without authentication",
        description=(
            "Reads the DAG listing an Airflow orchestration API publishes and reports it when "
            "the API answers the pipelines it holds, their schedules and their tags, with no "
            "challenge. An unauthenticated orchestrator is the automation supply chain exposed "
            "and the excessive-agency surface: the estate's automated actions are readable by "
            "anyone who can route to the API. Read-only GET of the listing; no DAG is "
            "triggered, paused or modified."
        ),
        research_ref="ch06#14",
        cwe="CWE-306",
        framework=("WSTG-CONF-05", "API8:2023", "LLM06:2025", "ASI04:2026", "CWE-306"),
        compliance=_COMPLIANCE,
        severity="medium",
        estimated_requests=1,
    )


class AirflowConfig(AiSurfaceCheck, Module):
    """``m6.airflow-config`` — an Airflow configuration document, unauthenticated."""

    service = "airflow"
    probe_paths = ("/api/v1/config",)
    document_keys = ("sections",)
    finding_title = "Airflow configuration served without authentication ({target})"
    metadata = ai_surface_metadata(
        name="airflow-config",
        title="Airflow configuration readable without authentication",
        description=(
            "Reads the configuration document an Airflow API publishes and reports it when the "
            "API answers its configuration sections — connection settings, executor, secrets "
            "backend — with no challenge. It is a different claim from the DAG listing: a "
            "deployment can refuse its pipelines and still expose its configuration. The "
            "document is reported, never a secret value in it (the client redacts credentials "
            "at capture time). Read-only GET of the configuration document."
        ),
        research_ref="ch06#14",
        cwe="CWE-200",
        framework=("WSTG-CONF-05", "CWE-200", "LLM02:2025"),
        compliance=_COMPLIANCE_DATA,
        severity="medium",
        estimated_requests=1,
    )


class LangflowFlows(AiSurfaceCheck, Module):
    """``m6.langflow-flows`` — a Langflow flow listing, unauthenticated."""

    service = "langflow"
    probe_paths = ("/api/v1/flows/",)
    document_keys = ("flows",)
    finding_title = "Langflow flow listing served without authentication ({target})"
    metadata = ai_surface_metadata(
        name="langflow-flows",
        title="Langflow flow listing readable without authentication",
        description=(
            "Reads the flow listing a Langflow agent platform publishes and reports it when "
            "the server answers the flows it holds with no challenge. A flow document is an "
            "executable agent graph — its components, its tools and its model wiring — so "
            "publishing it is the agentic-supply-chain and unexpected-code-execution "
            "condition. Read-only GET of the listing; the check never builds or runs a flow."
        ),
        research_ref="ch06#14",
        cwe="CWE-306",
        framework=("WSTG-CONF-05", "API8:2023", "ASI04:2026", "ASI05:2026", "CWE-306"),
        compliance=_COMPLIANCE,
        severity="high",
        estimated_requests=1,
    )


# --------------------------------------------------------------------------- notebook servers
class JupyterStatus(AiSurfaceCheck, Module):
    """``m6.jupyter-status`` — a Jupyter server's status document, unauthenticated."""

    service = "jupyter"
    probe_paths = ("/api/status",)
    document_keys = ("kernels", "connections")
    finding_title = "Jupyter server status served without authentication ({target})"
    metadata = ai_surface_metadata(
        name="jupyter-status",
        title="Jupyter server status readable without authentication",
        description=(
            "Reads the status document a Jupyter server publishes and reports it when the "
            "server answers its kernel and connection counters with no challenge. The counters "
            "disclose the server's execution surface, and an unauthenticated notebook server "
            "is a code-execution surface — the exposure is the finding. Read-only GET of the "
            "status document; the check never opens a notebook or runs a cell."
        ),
        research_ref="ch06#14",
        cwe="CWE-306",
        framework=("WSTG-CONF-05", "API8:2023", "LLM02:2025", "ASI05:2026", "CWE-306"),
        compliance=_COMPLIANCE,
        severity="medium",
        estimated_requests=1,
    )


class JupyterKernels(AiSurfaceCheck, Module):
    """``m6.jupyter-kernels`` — a Jupyter server's kernel listing, unauthenticated."""

    service = "jupyter"
    probe_paths = ("/api/kernels",)
    document_keys = ("last_activity", "execution_state")
    finding_title = "Jupyter kernel listing served without authentication ({target})"
    metadata = ai_surface_metadata(
        name="jupyter-kernels",
        title="Jupyter kernel listing readable without authentication",
        description=(
            "Reads the kernel listing a Jupyter server publishes and reports it when the "
            "server answers its live kernels, their state and their last activity with no "
            "challenge. It is a stronger, independent claim than the status counters: the "
            "listing names the execution sessions themselves. The exposure of an "
            "unauthenticated execution surface is the finding; the check never attaches to a "
            "kernel, opens a websocket or runs a cell. Read-only GET of the listing."
        ),
        research_ref="ch06#14",
        cwe="CWE-306",
        framework=("WSTG-CONF-05", "API8:2023", "ASI05:2026", "CWE-306"),
        compliance=_COMPLIANCE,
        severity="high",
        estimated_requests=1,
    )


class ZeppelinNotebooks(AiSurfaceCheck, Module):
    """``m6.zeppelin-notebooks`` — an Apache Zeppelin notebook listing, unauthenticated."""

    service = "zeppelin"
    probe_paths = ("/api/notebook",)
    document_keys = ("body", "status")
    finding_title = "Zeppelin notebook listing served without authentication ({target})"
    metadata = ai_surface_metadata(
        name="zeppelin-notebooks",
        title="Zeppelin notebook listing readable without authentication",
        description=(
            "Reads the notebook listing an Apache Zeppelin server publishes and reports it "
            "when the server answers its notebooks and their paragraphs with no challenge. An "
            "unauthenticated notebook server is a code-execution surface, and the notebook "
            "list is the analyst work product itself. Read-only GET of the listing; no "
            "paragraph is run, no note is created and no interpreter is started."
        ),
        research_ref="ch06#14",
        cwe="CWE-306",
        framework=("WSTG-CONF-05", "API8:2023", "ASI05:2026", "CWE-306"),
        compliance=_COMPLIANCE,
        severity="high",
        estimated_requests=1,
    )


#: Every check the WP-34 AI-era family registers, in the order the services appear above.
AI_SURFACE_CHECKS: tuple[type[Module], ...] = (
    OllamaModelList,
    OllamaVersion,
    VllmModelList,
    TritonServerMetadata,
    TritonModelRepository,
    LmStudioModelList,
    QdrantCollections,
    QdrantCluster,
    WeaviateMeta,
    WeaviateSchema,
    ChromaHeartbeat,
    ChromaTenants,
    FlowiseChatflows,
    N8nWorkflows,
    DifyAppParameters,
    AirflowDags,
    AirflowConfig,
    LangflowFlows,
    JupyterStatus,
    JupyterKernels,
    ZeppelinNotebooks,
)

#: Check id → the service (the requirement's scope area) it covers.
SERVICE_OF_CHECK: dict[str, str] = {
    check.metadata.id: str(getattr(check, "service", "")) for check in AI_SURFACE_CHECKS
}

#: The services the requirement's scope names, in the order they appear above.
SURFACE_AREAS: tuple[str, ...] = tuple(dict.fromkeys(SERVICE_OF_CHECK.values()))
