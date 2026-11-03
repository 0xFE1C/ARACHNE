"""The capability-scoped tool contract of the AI layer (REQ-AGENT-011).

``INV-6`` forbids arbitrary command APIs for checks, and an AI stage must not become the back
door that rule closed. So the AI layer's reachable surface is *enumerated*: every tool is
declared here, once, with a pydantic argument model, a capability from a closed vocabulary and a
handler that reads and returns data. There is no shell tool, no HTTP tool and no filesystem tool
— not "none registered today", but no such capability existing in
:class:`ToolCapability`, which is what makes the absence structural rather than a review habit.
``ai.capability`` asserts the same property statically, over the package's own imports.

Three decisions worth stating:

* **A handler returns data; it never mutates.** Every declared tool is a *view* over facts the
  scan already produced (the check catalogue, the candidate's evidence). A tool that changed
  state would be a proof-ladder decision, and those are made by the executor's gate, not by a
  model's request (REQ-AGENT-005).
* **Undeclared means refused, and refusal is audited.** :meth:`ToolRegistry.invoke` raises
  :class:`ToolNotDeclaredError` and records ``ai.tool`` with ``outcome=blocked`` before it does
  anything else, so "the model asked for something that does not exist" is a trail line rather
  than a stack trace.
* **The arguments are validated, not coerced.** A tool call arrives as a mapping (a model's JSON)
  and is validated against the declared model; a wrong type is a typed
  :class:`ToolArgumentError`, never a silent reinterpretation.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Final, Generic, TypeVar

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from arachne.ai.types import AiError
from arachne.analyzer.model import SEVERITY_ORDER

__all__ = [
    "CAPABILITIES",
    "DEFAULT_TOOL_NAMES",
    "AnalysisContext",
    "ToolArgumentError",
    "ToolCallResult",
    "ToolCapability",
    "ToolError",
    "ToolNotDeclaredError",
    "ToolRegistry",
    "ToolSpec",
    "build_tool_registry",
]

_MODEL = ConfigDict(frozen=True, extra="forbid")


class ToolCapability(StrEnum):
    """The closed vocabulary of what an AI tool is allowed to be.

    There is deliberately no ``process``, ``network`` or ``filesystem`` member: a capability
    that does not exist cannot be registered, so the refusal of shell execution, arbitrary HTTP
    and filesystem writes is a property of the type rather than of the current tool list.
    """

    #: Read what the scan already observed and recorded.
    ANALYSIS_CONTEXT = "analysis_context"
    #: Read the shipped check catalogue (ids, modules, titles, CWEs, proof levels).
    CATALOGUE = "catalogue"


CAPABILITIES: Final[frozenset[str]] = frozenset(member.value for member in ToolCapability)


class ToolError(AiError):
    """Base class for a refused tool call."""


class ToolNotDeclaredError(ToolError):
    """The requested tool is not in the registry (REQ-AGENT-011)."""


class ToolArgumentError(ToolError):
    """The arguments did not match the tool's declared typed schema."""


# --------------------------------------------------------------------------- argument models


class ListChecksArgs(BaseModel):
    """``catalogue.list_checks`` — the catalogue, filtered by module."""

    model_config = _MODEL

    module: str = Field(default="", max_length=32)
    limit: int = Field(default=200, ge=1, le=500)


class CheckDetailsArgs(BaseModel):
    """``catalogue.check_details`` — one catalogued check."""

    model_config = _MODEL

    check_id: str = Field(min_length=1, max_length=128)


class EvidenceArgs(BaseModel):
    """``analysis.evidence`` — one of the current candidate's evidence facts."""

    model_config = _MODEL

    evidence_id: str = Field(min_length=1, max_length=64)


class NoArgs(BaseModel):
    """A tool that takes no arguments (declared explicitly, so the schema exists)."""

    model_config = _MODEL


# --------------------------------------------------------------------------- context


@dataclass(frozen=True, slots=True)
class CheckView:
    """One check the model may name or ask about — read-only, no executable handle."""

    check_id: str
    module: str = ""
    title: str = ""
    cwe: str | None = None
    proof: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "module": self.module,
            "title": self.title,
            "cwe": self.cwe,
            "proof": self.proof,
        }


@dataclass(frozen=True, slots=True)
class EvidenceView:
    """One evidence fact of the current candidate (payload already redacted at capture)."""

    evidence_id: str
    kind: str
    source: str | None = None
    sha256: str | None = None
    summary: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "kind": self.kind,
            "source": self.source,
            "sha256": self.sha256,
            "summary": dict(self.summary),
        }


@dataclass(frozen=True, slots=True)
class AnalysisContext:
    """Everything the tools may read: the catalogue and the candidate's own evidence."""

    checks: tuple[CheckView, ...] = ()
    evidence: tuple[EvidenceView, ...] = ()

    def with_evidence(self, evidence: Iterable[EvidenceView]) -> AnalysisContext:
        return AnalysisContext(checks=self.checks, evidence=tuple(evidence))


# --------------------------------------------------------------------------- specs


ArgsT = TypeVar("ArgsT", bound=BaseModel)


@dataclass(frozen=True, slots=True)
class ToolSpec(Generic[ArgsT]):
    """One declared tool: its name, capability, typed arguments and read-only handler."""

    name: str
    capability: ToolCapability
    description: str
    arguments: type[ArgsT]
    handler: Callable[[ArgsT], Mapping[str, Any]]

    def invoke(self, arguments: Mapping[str, Any]) -> Mapping[str, Any]:
        """Validate ``arguments`` against the declared schema and call the handler."""
        try:
            typed = self.arguments.model_validate(dict(arguments))
        except ValidationError as exc:
            msg = f"tool {self.name!r}: invalid arguments: {_summarize(exc)}"
            raise ToolArgumentError(msg) from exc
        return dict(self.handler(typed))


@dataclass(frozen=True, slots=True)
class ToolCallResult:
    """One tool call, as it is recorded (REQ-AGENT-011: an undeclared call is audited)."""

    tool: str
    ok: bool
    detail: str = ""
    value: Mapping[str, Any] = field(default_factory=dict)


#: The tools every registry declares (the candidate-scoped one adds the same names over data).
DEFAULT_TOOL_NAMES: Final[tuple[str, ...]] = (
    "analysis.evidence",
    "analysis.severity_scale",
    "catalogue.check_details",
    "catalogue.list_checks",
)


def build_tool_registry(
    context: AnalysisContext | None = None,
    *,
    auditor: Any | None = None,
) -> ToolRegistry:
    """Build the registry over ``context`` (empty context: the catalogue reads answer "none")."""
    scope = context or AnalysisContext()

    def list_checks(arguments: ListChecksArgs) -> Mapping[str, Any]:
        rows = [
            check.to_dict()
            for check in scope.checks
            if not arguments.module or check.module.lower() == arguments.module.lower()
        ]
        rows.sort(key=lambda item: str(item["check_id"]))
        return {"check_ids": [row["check_id"] for row in rows[: arguments.limit]]}

    def check_details(arguments: CheckDetailsArgs) -> Mapping[str, Any]:
        for check in scope.checks:
            if check.check_id == arguments.check_id:
                return {"found": True, "check": check.to_dict()}
        return {"found": False, "check": None}

    def evidence(arguments: EvidenceArgs) -> Mapping[str, Any]:
        for fact in scope.evidence:
            if fact.evidence_id == arguments.evidence_id:
                return {"found": True, "evidence": fact.to_dict()}
        return {"found": False, "evidence": None}

    def severity_scale(_arguments: NoArgs) -> Mapping[str, Any]:
        return {"severities": list(SEVERITY_ORDER)}

    specs: tuple[ToolSpec[Any], ...] = (
        _spec(
            name="catalogue.list_checks",
            capability=ToolCapability.CATALOGUE,
            description="List the registered check ids, optionally filtered by module.",
            arguments=ListChecksArgs,
            handler=list_checks,
        ),
        _spec(
            name="catalogue.check_details",
            capability=ToolCapability.CATALOGUE,
            description="Read one registered check's module, title, CWE and proof level.",
            arguments=CheckDetailsArgs,
            handler=check_details,
        ),
        _spec(
            name="analysis.evidence",
            capability=ToolCapability.ANALYSIS_CONTEXT,
            description="Read one evidence fact of the current finding, by its evidence id.",
            arguments=EvidenceArgs,
            handler=evidence,
        ),
        _spec(
            name="analysis.severity_scale",
            capability=ToolCapability.ANALYSIS_CONTEXT,
            description="The severity vocabulary, in ascending order.",
            arguments=NoArgs,
            handler=severity_scale,
        ),
    )
    return ToolRegistry(specs, auditor=auditor)


def _spec(
    *,
    name: str,
    capability: ToolCapability,
    description: str,
    arguments: type[BaseModel],
    handler: Callable[[Any], Mapping[str, Any]],
) -> ToolSpec[Any]:
    """Build one spec, erasing the argument model to the registry's ``ToolSpec[Any]``.

    The erasure happens exactly here, at the one place a registry is assembled: ``invoke``
    validates the caller's mapping against ``arguments`` (the concrete model) before calling
    ``handler``, so the ``Any`` never reaches a tool's own body — a handler receives the model
    its signature names, or it is never called.
    """
    return ToolSpec(
        name=name,
        capability=capability,
        description=description,
        arguments=arguments,
        handler=handler,
    )


class ToolRegistry:
    """The enumerated tool surface one engine may call (REQ-AGENT-011)."""

    def __init__(
        self,
        tools: Iterable[ToolSpec[Any]] = (),
        *,
        auditor: Any | None = None,
        validate_capabilities: bool = True,
    ) -> None:
        declared: dict[str, ToolSpec[Any]] = {}
        for spec in tools:
            if not spec.name or "." not in spec.name:
                msg = f"tool name {spec.name!r} must be '<namespace>.<verb>'"
                raise ToolArgumentError(msg)
            if validate_capabilities and spec.capability.value not in CAPABILITIES:
                msg = (
                    f"tool {spec.name!r} declares capability {spec.capability.value!r}, which is "
                    f"outside the closed set {sorted(CAPABILITIES)}"
                )
                raise ToolArgumentError(msg)
            if spec.name in declared:
                msg = f"two tools claim the name {spec.name!r}"
                raise ToolArgumentError(msg)
            declared[spec.name] = spec
        self._tools = declared
        self._auditor = auditor
        self.calls: list[ToolCallResult] = []

    # ------------------------------------------------------------------ interface
    def names(self) -> tuple[str, ...]:
        """The declared tool names, sorted (the whole surface, in one call)."""
        return tuple(sorted(self._tools))

    def spec(self, name: str) -> ToolSpec[Any] | None:
        return self._tools.get(name)

    def invoke(self, name: str, arguments: Mapping[str, Any] | None = None) -> Mapping[str, Any]:
        """Call a declared tool, or refuse and audit (REQ-AGENT-011).

        An undeclared name is not a 404: it is a *blocked* call, recorded on the audit trail
        before the error is raised, because "an AI stage asked for a capability ARACHNE does not
        have" is exactly the event an operator wants to see.
        """
        spec = self._tools.get(name)
        if spec is None:
            self._record(ToolCallResult(tool=name, ok=False, detail="not_declared"))
            self._audit(name, "blocked", "not_declared")
            msg = f"tool {name!r} is not declared; the AI layer may only call {list(self.names())}"
            raise ToolNotDeclaredError(msg)
        try:
            value = spec.invoke(arguments or {})
        except ToolArgumentError as exc:
            self._record(ToolCallResult(tool=name, ok=False, detail=str(exc)[:300]))
            self._audit(name, "blocked", "invalid_arguments")
            raise
        self._record(ToolCallResult(tool=name, ok=True, value=dict(value)))
        self._audit(name, "allowed", spec.capability.value)
        return value

    def snapshot(self) -> dict[str, Any]:
        """What this registry is and what it did, for a plan line or a test."""
        return {
            "tools": list(self.names()),
            "capabilities": sorted({spec.capability.value for spec in self._tools.values()}),
            "calls": len(self.calls),
            "blocked": sum(1 for call in self.calls if not call.ok),
        }

    # ------------------------------------------------------------------ internals
    def _record(self, result: ToolCallResult) -> None:
        self.calls.append(result)

    def _audit(self, name: str, outcome: str, reason: str) -> None:
        if self._auditor is None:
            return
        from arachne.core.audit import AuditAction, AuditOutcome

        self._auditor.record(
            AuditAction.AI_TOOL,
            outcome=AuditOutcome.ALLOWED if outcome == "allowed" else AuditOutcome.BLOCKED,
            target=f"ai.tool:{name}",
            reason=None if outcome == "allowed" else reason,
            # ``meta["outcome"]`` belongs to the audit layer (ALLOWED/BLOCKED), so this module's
            # own verdict word travels under a different key rather than fighting it.
            meta={"tool": name, "result": outcome, "capability": self._capability_of(name)},
        )

    def _capability_of(self, name: str) -> str:
        spec = self._tools.get(name)
        return spec.capability.value if spec is not None else ""


def _summarize(exc: ValidationError) -> str:
    return "; ".join(
        f"{'.'.join(str(part) for part in error['loc']) or '<root>'}: {error['msg']}"
        for error in exc.errors()
    )
