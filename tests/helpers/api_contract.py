"""The API contract snapshot: which operation promises what (REQ-UIX-003).

The contract is small on purpose. For every operation the OpenAPI document
publishes it records only the things a *breaking change* would move:

* the required properties of the success response (the item's own properties when the
  response is an array);
* the required properties of the JSON request body;
* the parameter names, by location.

Adding an optional property changes none of them, so it does not fail the build. Removing a
required property, or a parameter, does — and the failure names the operation and the
property, so the diff is diagnosable without opening the document.

The snapshot lives in ``tests/fixtures/api-contract.json``; ``describe`` derives it from the
live document (``arachne.tools.sdkgen.load_spec``), and ``breaks`` compares two descriptions.
Regenerate the file after an *intentional* contract change::

    ARACHNE_UPDATE_API_CONTRACT=1 python -m pytest tests/unit/test_api_contract.py -q
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

__all__ = ["HTTP_METHODS", "breaks", "describe", "operation_keys"]

HTTP_METHODS: tuple[str, ...] = ("get", "post", "put", "patch", "delete")


def operation_keys(spec: Mapping[str, Any]) -> list[str]:
    """Every documented operation as ``METHOD /path``, sorted."""
    keys: list[str] = []
    for path, item in spec.get("paths", {}).items():
        for method in HTTP_METHODS:
            if method in item:
                keys.append(f"{method.upper()} {path}")
    return sorted(keys)


def _resolve(ref: str, spec: Mapping[str, Any]) -> Any:
    node: Any = spec
    for part in ref.lstrip("#/").split("/"):
        if not isinstance(node, Mapping) or part not in node:
            return None
        node = node[part]
    return node


def _required_names(schema: Any, spec: Mapping[str, Any]) -> list[str]:
    """The required property names a schema promises, following ``$ref`` and containers."""
    if not isinstance(schema, Mapping):
        return []
    ref = schema.get("$ref")
    if isinstance(ref, str):
        return _required_names(_resolve(ref, spec), spec)
    if schema.get("type") == "array":
        return _required_names(schema.get("items"), spec)
    for key in ("anyOf", "oneOf", "allOf"):
        branches = schema.get(key)
        if isinstance(branches, list):
            names: set[str] = set()
            for branch in branches:
                names.update(_required_names(branch, spec))
            return sorted(names)
    required = schema.get("required")
    if isinstance(required, list):
        return sorted(str(name) for name in required)
    return []


def _success_schema(operation: Mapping[str, Any]) -> Any:
    responses = operation.get("responses")
    if not isinstance(responses, Mapping):
        return None
    for code in sorted((c for c in responses if str(c).startswith("2")), key=str):
        content = responses[code].get("content") if isinstance(responses[code], Mapping) else None
        if isinstance(content, Mapping) and "application/json" in content:
            return content["application/json"].get("schema")
    return None


def _body_schema(operation: Mapping[str, Any]) -> Any:
    body = operation.get("requestBody")
    if not isinstance(body, Mapping):
        return None
    content = body.get("content")
    if isinstance(content, Mapping) and "application/json" in content:
        return content["application/json"].get("schema")
    return None


def _parameters(operation: Mapping[str, Any], spec: Mapping[str, Any]) -> list[str]:
    out: list[str] = []
    for parameter in operation.get("parameters") or []:
        node: Any = parameter
        ref = node.get("$ref") if isinstance(node, Mapping) else None
        if isinstance(ref, str):
            node = _resolve(ref, spec)
        if isinstance(node, Mapping) and node.get("name"):
            out.append(f"{node.get('in')}:{node['name']}")
    return sorted(out)


def describe(spec: Mapping[str, Any]) -> dict[str, dict[str, list[str]]]:
    """The contract of every operation: required response/body properties and parameters."""
    described: dict[str, dict[str, list[str]]] = {}
    for path, item in spec.get("paths", {}).items():
        for method in HTTP_METHODS:
            operation = item.get(method)
            if not isinstance(operation, Mapping):
                continue
            described[f"{method.upper()} {path}"] = {
                "response_required": _required_names(_success_schema(operation), spec),
                "body_required": _required_names(_body_schema(operation), spec),
                "parameters": _parameters(operation, spec),
            }
    return described


def breaks(before: Mapping[str, Mapping[str, list[str]]], after: Mapping[str, Any]) -> list[str]:
    """The breaking changes moving from ``before`` to ``after``; empty means compatible.

    Removing an operation, a required response/body property or a parameter is a break.
    Adding an operation, a property or a parameter is not.
    """
    found: list[str] = []
    for key, old in before.items():
        new = after.get(key)
        if new is None:
            found.append(f"{key}: operation removed")
            continue
        for field, label in (
            ("response_required", "required response property"),
            ("body_required", "required request property"),
            ("parameters", "parameter"),
        ):
            lost = sorted(set(old.get(field, ())) - set(new.get(field, ())))
            for name in lost:
                found.append(f"{key}: {label} {name!r} removed")
    return found
