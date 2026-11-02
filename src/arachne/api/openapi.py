"""The published OpenAPI document, with the pagination contract documented once (REQ-UIX-001).

FastAPI renders a query parameter inline on every operation that declares it, so the
``cursor`` parameter would be repeated on all eight collection endpoints. The requirement is
that it is documented **once, via a shared component**, so this module rewrites the generated
document:

* the first ``cursor`` parameter becomes ``components.parameters.Cursor``;
* every operation that carried one is rewritten to a ``$ref`` to it;
* those operations are tagged ``x-arachne-paginated: true``, which is the machine-readable
  marker the client generator reads (``arachne.tools.sdkgen``) and the contract test asserts.

Everything else in the document is left byte-for-byte as FastAPI produced it.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from fastapi import FastAPI
from fastapi.openapi.utils import get_openapi

__all__ = ["CURSOR_COMPONENT", "build_openapi", "paginated_operations"]

#: The name of the shared parameter component.
CURSOR_COMPONENT = "Cursor"

#: The one description every collection endpoint shares.
CURSOR_DESCRIPTION = (
    "Opaque pagination cursor. Take it from the `next` (or `prev`) `Link` header — or the "
    "`X-Next-Cursor` / `X-Prev-Cursor` header — of the previous page; do not construct one. "
    "A malformed cursor is a 400."
)

_HTTP_METHODS = ("get", "post", "put", "patch", "delete", "options", "head", "trace")


def paginated_operations(schema: dict[str, Any]) -> list[str]:
    """The ``METHOD /path`` keys of every operation the marker was applied to."""
    found: list[str] = []
    for path, item in schema.get("paths", {}).items():
        for method, operation in item.items():
            if method not in _HTTP_METHODS or not isinstance(operation, dict):
                continue
            if operation.get("x-arachne-paginated"):
                found.append(f"{method.upper()} {path}")
    return sorted(found)


def build_openapi(app: FastAPI) -> dict[str, Any]:
    """The app's OpenAPI document, cached on the app like FastAPI's own builder."""
    cached = getattr(app, "openapi_schema", None)
    if isinstance(cached, dict):
        return cached
    schema: dict[str, Any] = get_openapi(
        title=app.title,
        version=app.version,
        summary=app.summary,
        description=app.description,
        routes=app.routes,
    )
    _share_cursor_parameter(schema)
    app.openapi_schema = schema
    return schema


def _share_cursor_parameter(schema: dict[str, Any]) -> None:
    """Hoist the ``cursor`` query parameter into one shared component and tag the operations."""
    template: dict[str, Any] | None = None
    for item in schema.get("paths", {}).values():
        for method, operation in item.items():
            if method not in _HTTP_METHODS or not isinstance(operation, dict):
                continue
            parameters = operation.get("parameters")
            if not parameters:
                continue
            cursor = next(
                (
                    parameter
                    for parameter in parameters
                    if parameter.get("in") == "query" and parameter.get("name") == "cursor"
                ),
                None,
            )
            if cursor is None:
                continue
            if template is None:
                template = deepcopy(cursor)
                template["description"] = CURSOR_DESCRIPTION
            operation["x-arachne-paginated"] = True
            operation["parameters"] = [
                {"$ref": f"#/components/parameters/{CURSOR_COMPONENT}"} if p is cursor else p
                for p in parameters
            ]
    if template is None:
        return
    components = schema.setdefault("components", {})
    parameters = components.setdefault("parameters", {})
    parameters[CURSOR_COMPONENT] = template
