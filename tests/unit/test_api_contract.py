"""Contract: every documented operation is tested, and a breaking change fails the build.

REQ-UIX-003's acceptance criteria are exactly these two properties, so they are what is
asserted:

* the suite **enumerates the operations from the OpenAPI document** and fails if one has no
  contract test (``test_every_documented_operation_has_a_contract_test`` — it prints
  ``n/n operations covered``);
* **removing a required response property fails** and **adding an optional property passes**
  (the last two tests), which is what makes the snapshot a gate rather than a document.

The document is read through ``arachne.tools.sdkgen.load_spec`` — the same
``create_app().openapi()`` the generated clients are built from — so the contract test and
the clients can never disagree about what the API is.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest
from tests.helpers.api_contract import breaks, describe, operation_keys

from arachne.tools.sdkgen import load_spec

SNAPSHOT = Path(__file__).resolve().parents[1] / "fixtures" / "api-contract.json"

#: The operation count the delivery plan states for this API. A floor, not a ceiling: the
#: contract test's real gate is that the snapshot covers every operation the document
#: publishes, so an API that grows must grow this snapshot with it.
DOCUMENTED_OPERATIONS = 74


@pytest.fixture(scope="module")
def spec() -> dict[str, Any]:
    return dict(load_spec())


@pytest.fixture(scope="module")
def snapshot() -> dict[str, Any]:
    if not SNAPSHOT.exists():
        if os.environ.get("ARACHNE_UPDATE_API_CONTRACT") == "1":
            SNAPSHOT.write_text(
                json.dumps(describe(load_spec()), indent=1, sort_keys=True) + "\n", encoding="utf-8"
            )
        else:
            pytest.fail(
                f"the contract snapshot {SNAPSHOT} is missing; create it with "
                "ARACHNE_UPDATE_API_CONTRACT=1 python -m pytest tests/unit/test_api_contract.py -q"
            )
    return json.loads(SNAPSHOT.read_text(encoding="utf-8"))


def test_every_documented_operation_has_a_contract_test(
    spec: dict[str, Any], snapshot: dict[str, Any]
) -> None:
    """Enumerate the document; fail naming any operation the snapshot does not cover."""
    wanted = set(operation_keys(spec))
    covered = set(snapshot)
    missing = sorted(wanted - covered)
    stale = sorted(covered - wanted)
    assert not missing, f"operations with no contract test: {missing}"
    assert not stale, (
        f"the contract snapshot names operations the document no longer publishes: {stale}; "
        "regenerate it with ARACHNE_UPDATE_API_CONTRACT=1"
    )
    assert len(wanted) >= DOCUMENTED_OPERATIONS, (
        f"the document publishes {len(wanted)} operations, fewer than the "
        f"{DOCUMENTED_OPERATIONS} the delivery plan states"
    )
    print(f"\n{len(covered)}/{len(wanted)} operations covered by a contract test")


def test_no_required_response_property_was_removed(
    snapshot: dict[str, Any], spec: dict[str, Any]
) -> None:
    """A released operation keeps every required response property it promised."""
    found = breaks(snapshot, describe(spec))
    assert not found, "breaking API changes:\n" + "\n".join(found)


def test_the_snapshot_is_current(snapshot: dict[str, Any], spec: dict[str, Any]) -> None:
    """The recorded contract equals the live one (an optional addition changes neither)."""
    live = describe(spec)
    if os.environ.get("ARACHNE_UPDATE_API_CONTRACT") == "1":
        SNAPSHOT.write_text(json.dumps(live, indent=1, sort_keys=True) + "\n", encoding="utf-8")
        return
    assert live == snapshot, (
        "the API contract moved; inspect the diff and regenerate with "
        "ARACHNE_UPDATE_API_CONTRACT=1 python -m pytest tests/unit/test_api_contract.py -q"
    )


def test_removing_a_required_response_property_fails_the_build(spec: dict[str, Any]) -> None:
    document = json.loads(json.dumps(spec))
    method, path, property_name = _a_required_response_property(document)
    target = _response_object_schema(document["paths"][path][method]["responses"], document)
    assert target is not None, f"{method} {path} has no object response schema to break"
    target["required"] = [name for name in target["required"] if name != property_name]

    found = breaks(describe(spec), describe(document))
    assert any(property_name in message for message in found), found


def test_adding_an_optional_response_property_passes_the_build(spec: dict[str, Any]) -> None:
    document = json.loads(json.dumps(spec))
    method, path, _ = _a_required_response_property(document)
    target = _response_object_schema(document["paths"][path][method]["responses"], document)
    assert target is not None
    properties = target.setdefault("properties", {})
    properties["a_new_optional_field"] = {"type": "string"}

    assert breaks(describe(spec), describe(document)) == []


# --------------------------------------------------------------------------- helpers
def _response_object_schema(responses: Any, document: dict[str, Any]) -> dict[str, Any] | None:
    """The object schema of the lowest 2xx JSON response, resolving ``$ref``/arrays."""
    for code in sorted((c for c in responses if str(c).startswith("2")), key=str):
        content = responses[code].get("content")
        if not isinstance(content, dict) or "application/json" not in content:
            continue
        node = content["application/json"].get("schema")
        node = _deref(node, document)
        if node is not None and node.get("type") == "array":
            node = _deref(node.get("items"), document)
        if isinstance(node, dict) and "required" in node:
            return node
    return None


def _deref(node: Any, document: dict[str, Any]) -> dict[str, Any] | None:
    if not isinstance(node, dict):
        return None
    if "$ref" in node:
        return _deref(document["components"]["schemas"][node["$ref"].rsplit("/", 1)[-1]], document)
    return node


def _a_required_response_property(document: dict[str, Any]) -> tuple[str, str, str]:
    """Some operation and one of its required response properties, for the synthetic tests."""
    for path, item in document["paths"].items():
        for method in ("get", "post", "put", "patch", "delete"):
            if method not in item:
                continue
            target = _response_object_schema(item[method]["responses"], document)
            if target and target.get("required"):
                return method, path, str(target["required"][0])
    raise AssertionError("no operation with a required response property")
