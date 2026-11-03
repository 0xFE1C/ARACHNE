"""The Agentic Top 10 decision tables, with no socket (REQ-DET-013).

``tests/test_asi_safety.py`` proves the family's read-only boundary on the wire. This suite
drives the *parsers* the four checks are built on: which tool a manifest exposes, whether a
served JSON document reads as a memory store, which declaration removes the human gate, and
whether a document describes an agent runtime. Each is a pure function, so the false-positive
cases — the ones that would make the family noisy — are pinned here rather than discovered in
the field.
"""

from __future__ import annotations

from arachne.modules.m6.agentic import (
    AGENTIC_CHECKS,
    AgenticHumanTrust,
    AgenticMemoryStore,
    AgenticRogueRuntime,
    AgenticToolManifest,
    _confirmation_removed,
    _guardrail_present,
    _memory_document,
    _runtime_description,
    _tool_capability,
    _tool_entries,
)


# ------------------------------------------------------------------ ASI02: tool manifests
def test_a_tool_list_is_read_from_either_shape() -> None:
    assert len(_tool_entries({"tools": [{"name": "a"}, {"name": "b"}]})) == 2
    named = _tool_entries({"tools": {"search": {"description": "find things"}}})
    assert [tool["name"] for tool in named] == ["search"]


def test_a_nested_tool_list_is_read_too() -> None:
    document = {"agent": {"capabilities": [{"name": "fetch_url", "description": "retrieve"}]}}
    assert [tool["name"] for tool in _tool_entries(document)] == ["fetch_url"]


def test_each_dangerous_capability_class_is_recognised() -> None:
    cases = {
        "run_shell": "command-execution",
        "delete_file": "file-mutation",
        "evaluate_script": "code-execution",
        "run_sql_query": "sql-execution",
        "read_credential": "credential-access",
        "fetch_url": "outbound-fetch",
        "send_email": "sensitive-egress",
    }
    for name, expected in cases.items():
        assert _tool_capability({"name": name}) == expected, name


def test_a_benign_tool_declares_no_capability() -> None:
    assert _tool_capability({"name": "get_customer", "description": "look up a record"}) is None
    assert _tool_capability({"name": "get_weather"}) is None


def test_a_description_can_name_the_capability() -> None:
    assert _tool_capability({"name": "helper", "description": "runs a shell command"}) == (
        "command-execution"
    )


# ------------------------------------------------------------------ ASI06: memory stores
def test_a_collection_listing_reads_as_a_memory_store() -> None:
    assert _memory_document({"collections": ["a", "b"], "size": 2})
    assert _memory_document([{"id": 1}, {"id": 2}])


def test_a_document_without_memories_does_not() -> None:
    assert not _memory_document({"status": "ok", "collections": []})
    assert not _memory_document({"status": "ok"})
    assert not _memory_document([])
    assert not _memory_document("not json")


# ------------------------------------------------------------------ ASI09: the human gate
def test_both_spellings_of_the_removed_gate_are_read() -> None:
    assert _confirmation_removed({"auto_approve": True}) == ("auto_approve", "true")
    assert _confirmation_removed({"requires_confirmation": False}) == (
        "requires_confirmation",
        "false",
    )
    assert _confirmation_removed({"approval_mode": "none"}) == ("approval_mode", "none")


def test_a_nested_policy_is_read_like_a_flat_one() -> None:
    document = {"agent": {"guardrails": {"human_in_the_loop": False}}}
    assert _confirmation_removed(document) == ("human_in_the_loop", "false")


def test_a_policy_that_keeps_its_gate_reports_nothing() -> None:
    assert _confirmation_removed({"requires_confirmation": True}) is None
    assert _confirmation_removed({"approval_mode": "manual"}) is None
    assert _confirmation_removed({"auto_approve": False}) is None


def test_a_declared_gate_is_recognised_as_the_decoy() -> None:
    assert _guardrail_present({"requires_confirmation": True})
    assert _guardrail_present({"human_in_the_loop": True})
    assert _guardrail_present({"confirmation": "required"})
    assert not _guardrail_present({"auto_approve": True})


# ------------------------------------------------------------------ ASI10: runtimes
def test_a_runtime_description_needs_the_keys_that_identify_one() -> None:
    assert _runtime_description({"model": "m", "tools": ["a"], "uptime": 1}) == (
        "model",
        "tools",
        "uptime",
    )
    assert _runtime_description({"some": "thing"}) == ()
    assert _runtime_description([]) == ()


# ------------------------------------------------------------------ the family's identities
def test_each_check_maps_exactly_one_asi_item() -> None:
    expected = {
        AgenticToolManifest: "ASI02:2026",
        AgenticMemoryStore: "ASI06:2026",
        AgenticHumanTrust: "ASI09:2026",
        AgenticRogueRuntime: "ASI10:2026",
    }
    assert set(expected) == set(AGENTIC_CHECKS)
    for check, item in expected.items():
        assert item in check.metadata.framework, check.metadata.id


def test_each_check_is_a_read_only_get_probe() -> None:
    for check in AGENTIC_CHECKS:
        assert check.metadata.type == "hybrid"
        assert check.metadata.safe is True
        assert check.metadata.verifiable is True
        assert check.metadata.target_kinds == (check.metadata.target_kinds[0],)


def test_every_check_declares_a_cwe_in_its_framework_mapping() -> None:
    for check in AGENTIC_CHECKS:
        assert check.metadata.cwe in check.metadata.framework, check.metadata.id
