"""The capability-scoped tool contract (REQ-AGENT-011, G5 clause 5).

Two halves, and both have to hold for the claim to mean anything:

* **the surface is enumerated and typed** — every tool is declared once, with a pydantic argument
  model, a capability from a closed vocabulary, and a read-only handler; an undeclared name is
  refused with a typed error *and* audited, because "an AI stage asked for a capability ARACHNE
  does not have" is the event that precedes capability creep;
* **the tool is actually used** — the shipped caller is the agentic ``hypothesize`` stage, which
  reads its closed list of check ids through ``catalogue.list_checks`` rather than reaching into
  the index, so the contract is a code path and not a decoration.

The closed vocabulary is the load-bearing part: there is no ``process``, ``socket`` or
``filesystem`` capability, so a tool that needed one could not be declared. ``test_ai_capability``
asserts the other half of that property over the package's own imports.
"""

from __future__ import annotations

import asyncio

import pytest
from pydantic import BaseModel
from tests.helpers.agentic import lab_index
from tests.helpers.ai import make_engine

from arachne.ai.tools import (
    CAPABILITIES,
    DEFAULT_TOOL_NAMES,
    AnalysisContext,
    CheckView,
    EvidenceView,
    NoArgs,
    ToolArgumentError,
    ToolCapability,
    ToolNotDeclaredError,
    ToolRegistry,
    build_tool_registry,
)
from arachne.core.audit import AuditAction, Auditor, AuditOutcome, MemoryAuditSink


@pytest.fixture
def registry() -> ToolRegistry:
    return build_tool_registry(
        AnalysisContext(
            checks=(
                CheckView(
                    check_id="m4.env-file-probe", module="M4", title="Env file", cwe="CWE-200"
                ),
                CheckView(check_id="m2.smb-enum", module="M2", title="SMBv1", cwe="CWE-200"),
            ),
            evidence=(
                EvidenceView(evidence_id="12", kind="http_response", summary={"status_code": 200}),
            ),
        )
    )


# ------------------------------------------------------------------ the declared surface


def test_the_registry_declares_the_documented_tools_with_typed_arguments(
    registry: ToolRegistry,
) -> None:
    assert registry.names() == DEFAULT_TOOL_NAMES
    for name in registry.names():
        spec = registry.spec(name)
        assert spec is not None
        assert issubclass(spec.arguments, BaseModel), f"{name} has no typed argument model"
        assert spec.arguments.model_json_schema()["type"] == "object"
        assert spec.description
        assert "." in name, "a tool name is '<namespace>.<verb>'"


def test_no_capability_can_execute_a_process_open_a_socket_or_write_a_file() -> None:
    """The closed vocabulary is what makes those three impossible to *declare*, not unused."""
    forbidden = {"process", "socket", "network", "filesystem", "shell", "exec"}
    assert not (set(CAPABILITIES) & forbidden)
    assert {member.value for member in ToolCapability} == set(CAPABILITIES)


def test_a_capability_outside_the_closed_set_is_refused_at_registration() -> None:
    """The guard is real, even though the enum makes the case unreachable by ordinary means.

    ``ToolCapability`` cannot express "process", so the only way to build such a spec is to put a
    foreign value there by hand — which is exactly what a future adapter of this module might do
    by mistake, and what the registry's allowlist check exists to catch.
    """
    from dataclasses import replace

    from arachne.ai.tools import ToolSpec

    def handler(_arguments: NoArgs) -> dict[str, object]:
        return {}

    spec = ToolSpec(
        name="analysis.severity_scale",
        capability=ToolCapability.ANALYSIS_CONTEXT,
        description="x",
        arguments=NoArgs,
        handler=handler,
    )
    sneaky = replace(spec, capability=_FakeCapability())  # type: ignore[arg-type]
    with pytest.raises(ToolArgumentError) as raised:
        ToolRegistry([sneaky])
    assert "outside the closed set" in str(raised.value)


class _FakeCapability:
    """A duck-typed capability naming a primitive ARACHNE refuses to have."""

    value = "process"


def test_a_malformed_or_duplicated_tool_name_is_refused() -> None:
    from arachne.ai.tools import ToolSpec

    def handler(_arguments: NoArgs) -> dict[str, object]:
        return {}

    with pytest.raises(ToolArgumentError):
        ToolRegistry(
            [
                ToolSpec(
                    name="noseparator",
                    capability=ToolCapability.CATALOGUE,
                    description="x",
                    arguments=NoArgs,
                    handler=handler,
                )
            ]
        )
    with pytest.raises(ToolArgumentError):
        ToolRegistry(
            [
                ToolSpec(
                    name="catalogue.a",
                    capability=ToolCapability.CATALOGUE,
                    description="x",
                    arguments=NoArgs,
                    handler=handler,
                ),
                ToolSpec(
                    name="catalogue.a",
                    capability=ToolCapability.CATALOGUE,
                    description="y",
                    arguments=NoArgs,
                    handler=handler,
                ),
            ]
        )


# ------------------------------------------------------------------ calling


def test_the_catalogue_and_evidence_tools_return_typed_data(registry: ToolRegistry) -> None:
    listing = registry.invoke("catalogue.list_checks", {"limit": 10})
    assert listing["check_ids"] == ["m2.smb-enum", "m4.env-file-probe"]
    filtered = registry.invoke("catalogue.list_checks", {"module": "M4"})
    assert filtered["check_ids"] == ["m4.env-file-probe"]
    details = registry.invoke("catalogue.check_details", {"check_id": "m4.env-file-probe"})
    assert details["found"] is True
    assert details["check"]["cwe"] == "CWE-200"  # type: ignore[index]
    missing = registry.invoke("catalogue.check_details", {"check_id": "nope"})
    assert missing["found"] is False
    evidence = registry.invoke("analysis.evidence", {"evidence_id": "12"})
    assert evidence["found"] is True and evidence["evidence"]["kind"] == "http_response"  # type: ignore[index]
    assert registry.invoke("analysis.severity_scale")["severities"] == [
        "info",
        "low",
        "medium",
        "high",
        "critical",
    ]


def test_a_tool_reports_nothing_rather_than_inventing_it() -> None:
    """An empty context answers "none", which is what a stage must be able to tell apart."""
    empty = build_tool_registry()
    assert empty.invoke("catalogue.list_checks")["check_ids"] == []
    assert empty.invoke("analysis.evidence", {"evidence_id": "12"})["found"] is False


def test_bad_arguments_are_a_typed_error_not_a_coercion(registry: ToolRegistry) -> None:
    with pytest.raises(ToolArgumentError) as raised:
        registry.invoke("catalogue.list_checks", {"limit": "many"})
    assert "invalid arguments" in str(raised.value)
    # A refused call is recorded too: an argument error is a bug or a misbehaving model.
    assert registry.calls[-1].ok is False


def test_an_undeclared_tool_is_refused_and_audited(registry: ToolRegistry) -> None:
    sink = MemoryAuditSink()
    audited = build_tool_registry(auditor=Auditor(sink, actor="pytest"))
    with pytest.raises(ToolNotDeclaredError) as raised:
        audited.invoke("shell.exec", {"command": "id"})
    assert "not declared" in str(raised.value)
    assert list(audited.names()) == list(DEFAULT_TOOL_NAMES)
    events = [event for event in sink.events if event.action == AuditAction.AI_TOOL]
    assert events, "a refused call must appear on the audit trail"
    assert events[-1].outcome == AuditOutcome.BLOCKED
    assert events[-1].meta["tool"] == "shell.exec"
    # ``reason`` carries the refusal the caller raised; ``meta.result`` is this module's own
    # verdict word, kept distinct from the audit layer's ALLOWED/BLOCKED.
    assert events[-1].reason == "not_declared"
    assert events[-1].meta["result"] == "blocked"
    assert audited.calls[-1].ok is False
    assert audited.snapshot()["blocked"] == 1


def test_a_declared_call_is_audited_as_allowed(registry: ToolRegistry) -> None:
    sink = MemoryAuditSink()
    audited = build_tool_registry(AnalysisContext(), auditor=Auditor(sink, actor="pytest"))
    audited.invoke("analysis.severity_scale")
    events = [event for event in sink.events if event.action == AuditAction.AI_TOOL]
    assert events and events[0].outcome == AuditOutcome.ALLOWED
    assert events[0].target == "ai.tool:analysis.severity_scale"
    assert events[0].reason is None
    assert events[0].meta["result"] == "allowed"
    assert events[0].meta["capability"] == "analysis_context"


# ------------------------------------------------------------------ the shipped caller


def test_the_hypothesize_stage_reads_its_vocabulary_through_the_tool(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The registry is a code path, not a decoration: the agentic stage's only way in."""
    from arachne.ai.engine import AiEngine
    from arachne.ai.tools import ToolRegistry as Registry
    from arachne.reasoning.ai import AiHypothesisEngine
    from arachne.reasoning.model import HypothesisInput

    engine, provider = make_engine(stages=("hypothesize",))
    assert isinstance(engine, AiEngine)
    sink = MemoryAuditSink()
    engine.auditor = Auditor(sink, actor="pytest")  # type: ignore[assignment]

    seen: list[tuple[str, dict[str, object]]] = []
    original = Registry.invoke

    def spy(self: Registry, name: str, arguments: object = None) -> object:
        seen.append((name, dict(arguments or {})))  # type: ignore[arg-type]
        return original(self, name, arguments)  # type: ignore[arg-type]

    monkeypatch.setattr(Registry, "invoke", spy)
    index = lab_index()
    reasoner = AiHypothesisEngine(engine)
    input_state = HypothesisInput(scan_id=1, findings=("m4.env-file-probe|host|high|80|analyzed",))
    proposal = asyncio.run(reasoner.propose_async(input_state, index))
    del proposal, provider

    assert ("catalogue.list_checks", {"limit": 200}) in seen
    events = [event for event in sink.events if event.action == AuditAction.AI_TOOL]
    assert any(event.target == "ai.tool:catalogue.list_checks" for event in events)
