"""A tiny GraphQL engine for the lab's ``/graphql`` and ``/graphql-safe`` routes.

The scanner's GraphQL checks are differential oracles: they send a query and read the shape of
the answer. A fixture that pattern-matches on substrings would therefore be a mirror of the
check rather than a ground truth for it — the check would "pass" against a lab that only
implements the check's own assumptions. This module implements just enough of the language to
be a *server* instead:

* a real (small) parser for operation selection sets, aliases and nesting, so the depth and
  alias counts the checks rely on are genuinely derived from the query text;
* a schema with a **cycle** (``Query.product → Product.vendor → Vendor.products → Product``), so
  an unbounded depth is actually reachable and not an artefact of a name list;
* three independent controls that each hardened route can enforce: a maximum depth, a maximum
  alias count, and authentication for sensitive-named fields.

``/graphql`` enforces none of them (the planted-vulnerable route); ``/graphql-safe`` enforces
all three and disables introspection. Because the controls are enforced by an engine that
parses the query, a check cannot pass the ``-safe`` route by accident: it has to receive real
data back.

Only the query operation is implemented — no mutation, no subscription, no execution of any
resolver. The "data" it returns is a fixed ``__typename`` description, which is exactly what
the scanner's probe asks for and all it can ask for.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "AUTH_FIELDS",
    "SEE_ALSO",
    "FieldRef",
    "Limits",
    "count_aliases",
    "depth_of",
    "execute",
    "introspection_body",
    "parse_query",
    "query_from_body",
    "schema_types",
]

#: Query fields the schema declares as requiring a credential. A hardened route returns an
#: authorization error for these; the vulnerable route answers them like any other field.
AUTH_FIELDS: frozenset[str] = frozenset(
    {"viewer", "adminUsers", "invoices", "orders", "secretConfig", "paymentMethods"}
)

#: The suggestion a wrong field name produces (the S10 field-suggestion leak).
SEE_ALSO: dict[str, str] = {
    "arachnenonexistentfield": "product",
    "user": "viewer",
    "adminuser": "adminUsers",
}

#: Object type each query field returns (used to build both the schema and the fake data).
_QUERY_FIELDS: dict[str, str] = {
    "product": "Product",
    "products": "Product",
    "vendor": "Vendor",
    "viewer": "User",
    "adminUsers": "User",
    "invoices": "Invoice",
    "orders": "Order",
    "secretConfig": "Config",
    "paymentMethods": "PaymentMethod",
}

#: Fields of each object type that return another object — the graph the depth probe walks.
_OBJECT_FIELDS: dict[str, dict[str, str]] = {
    "Product": {"vendor": "Vendor", "primaryInvoice": "Invoice"},
    "Vendor": {"products": "Product", "contact": "User"},
    "User": {"organization": "Vendor", "primaryOrder": "Order"},
    "Invoice": {"vendor": "Vendor", "payment": "PaymentMethod"},
    "Order": {"product": "Product", "invoice": "Invoice"},
    "Config": {"owner": "User"},
    "PaymentMethod": {"owner": "User"},
}


def schema_types() -> list[dict[str, Any]]:
    """The ``__schema.types`` array an introspection response carries.

    Built from the same tables the engine resolves against, so the schema the scanner reads is
    the schema that answers it — a fixture whose introspection response disagreed with its own
    behaviour would make every check built on it meaningless.
    """
    query_fields = [
        {
            "name": name,
            "type": {
                "name": None,
                "kind": "NON_NULL",
                "ofType": {"name": type_name, "kind": "OBJECT", "ofType": None},
            },
        }
        for name, type_name in _QUERY_FIELDS.items()
    ]
    types: list[dict[str, Any]] = [
        {"name": "Query", "kind": "OBJECT", "fields": query_fields},
        {
            "name": "String",
            "kind": "SCALAR",
            "fields": None,
        },
        {
            "name": "SecretNote",
            "kind": "SCALAR",
            "fields": None,
        },
    ]
    for type_name, object_fields in _OBJECT_FIELDS.items():
        fields: list[dict[str, Any]] = [
            {
                "name": name,
                "type": {"name": target, "kind": "OBJECT", "ofType": None},
            }
            for name, target in object_fields.items()
        ]
        types.append({"name": type_name, "kind": "OBJECT", "fields": fields})
    return types


def query_from_body(body: str) -> str:
    """The GraphQL query text in a request body.

    A GraphQL endpoint accepts ``application/json`` (``{"query": "..."}``) and
    ``application/graphql`` (the query text alone). The distinction matters for the fixture:
    the engine must parse the *query*, not the envelope that carries it, or every probe but
    introspection would look like a syntax error.
    """
    text = body.strip()
    if not text:
        return ""
    try:
        parsed = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        return text
    if isinstance(parsed, dict):
        query = parsed.get("query")
        return query if isinstance(query, str) else ""
    return text


def introspection_body() -> str:
    """A complete introspection response for the lab schema."""
    return json.dumps(
        {
            "data": {
                "__schema": {
                    "queryType": {"name": "Query"},
                    "types": schema_types(),
                }
            }
        }
    )


# --------------------------------------------------------------------------- parsing
class QuerySyntaxError(ValueError):
    """The query text is not a selection set this engine can read."""


@dataclass(frozen=True, slots=True)
class FieldRef:
    """One selected field: its response key (an alias, when given) and its field name."""

    key: str
    name: str
    children: tuple[FieldRef, ...] = ()


_WHITESPACE = " \t\r\n,"
_NAME_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")


def _skip_ignorable(text: str, index: int) -> int:
    while index < len(text):
        char = text[index]
        if char in _WHITESPACE:
            index += 1
            continue
        if char == "#":  # a comment runs to the end of the line
            newline = text.find("\n", index)
            index = len(text) if newline < 0 else newline + 1
            continue
        break
    return index


def _read_name(text: str, index: int) -> tuple[str, int]:
    start = index
    while index < len(text) and text[index] in _NAME_CHARS:
        index += 1
    if index == start:
        raise QuerySyntaxError(f"expected a field name at offset {start}")
    return text[start:index], index


def _skip_parens(text: str, index: int) -> int:
    """Skip a balanced ``(...)`` argument or directive block (arguments are not evaluated)."""
    depth = 0
    while index < len(text):
        char = text[index]
        if char in "\"'":
            closing = char
            index += 1
            while index < len(text) and text[index] != closing:
                index += 2 if text[index] == "\\" else 1
        elif char == "(":
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                return index + 1
        elif char == "{":
            return index  # a selection set: the caller must not treat it as an argument
        index += 1
    return index


def _parse_selection_set(text: str, index: int, depth: int = 0) -> tuple[tuple[FieldRef, ...], int]:
    if depth > 64:  # a hostile query must not recurse the parser without bound
        raise QuerySyntaxError("selection set nested too deeply for this engine")
    if index >= len(text) or text[index] != "{":
        raise QuerySyntaxError(f"expected '{{' at offset {index}")
    index += 1
    fields: list[FieldRef] = []
    while True:
        index = _skip_ignorable(text, index)
        if index >= len(text):
            raise QuerySyntaxError("unterminated selection set")
        if text[index] == "}":
            return tuple(fields), index + 1
        name, index = _read_name(text, index)
        index = _skip_ignorable(text, index)
        key = name
        if index < len(text) and text[index] == ":":
            alias, index = name, _skip_ignorable(text, index + 1)
            name, index = _read_name(text, index)
            key = alias
            index = _skip_ignorable(text, index)
        if index < len(text) and text[index] == "(":
            index = _skip_ignorable(text, _skip_parens(text, index))
        while index < len(text) and text[index] == "@":
            index += 1
            _, index = _read_name(text, index)
            index = _skip_ignorable(text, index)
            if index < len(text) and text[index] == "(":
                index = _skip_ignorable(text, _skip_parens(text, index))
        children: tuple[FieldRef, ...] = ()
        if index < len(text) and text[index] == "{":
            children, index = _parse_selection_set(text, index, depth + 1)
        fields.append(FieldRef(key=key, name=name, children=children))
        index = _skip_ignorable(text, index)


def parse_query(text: str) -> tuple[FieldRef, ...]:
    """Parse a query operation into its root selection set.

    An operation keyword (``query Name``), its variable definitions and its directives are
    accepted and ignored: this engine evaluates nothing, so there is nothing for them to bind.
    """
    index = _skip_ignorable(text, 0)
    if index >= len(text):
        raise QuerySyntaxError("empty query")
    if text[index] != "{":
        # ``query <Name>($vars) @dir { ... }`` — skip to the first brace that opens the set.
        while index < len(text) and text[index] not in "{(":
            index += 1
        if index < len(text) and text[index] == "(":
            index = _skip_ignorable(text, _skip_parens(text, index))
            while index < len(text) and text[index] == "@":
                index += 1
                _, index = _read_name(text, index)
                index = _skip_ignorable(text, index)
                if index < len(text) and text[index] == "(":
                    index = _skip_ignorable(text, _skip_parens(text, index))
        if index >= len(text) or text[index] != "{":
            raise QuerySyntaxError("no selection set found")
    root, _ = _parse_selection_set(text, index)
    return root


def depth_of(fields: tuple[FieldRef, ...], level: int = 1) -> int:
    """The deepest selection level in ``fields`` (a root selection set is level 1)."""
    deepest = level
    for item in fields:
        if item.children:
            deepest = max(deepest, depth_of(item.children, level + 1))
    return deepest


def count_aliases(fields: tuple[FieldRef, ...]) -> int:
    """How many selected fields carry an alias (the amplification the cost probe measures)."""
    total = 0
    for item in fields:
        if item.key != item.name:
            total += 1
        total += count_aliases(item.children)
    return total


# --------------------------------------------------------------------------- execution
@dataclass(frozen=True, slots=True)
class Limits:
    """The controls a route enforces. Every field ``None``/``False`` means "not enforced"."""

    max_depth: int | None = None
    max_aliases: int | None = None
    require_auth: bool = False
    introspection_enabled: bool = True
    #: The response fields a resolver actually produces (unused by the probes, kept so the
    #: fixture can show a compliant route answering real content).
    data_fields: frozenset[str] = field(default_factory=frozenset)


#: ``/graphql`` — the planted-vulnerable route: no depth limit, no cost limit, no auth.
VULNERABLE = Limits()

#: ``/graphql-safe`` — the hardened route: every control on, introspection off.
SAFE = Limits(max_depth=5, max_aliases=16, require_auth=True, introspection_enabled=False)


def _error(message: str) -> tuple[int, str]:
    return 200, json.dumps({"errors": [{"message": message}]})


def _typename_of(field_name: str) -> str:
    return _QUERY_FIELDS.get(field_name, "Query")


def _resolve(fields: tuple[FieldRef, ...], typename: str = "Query") -> dict[str, Any]:
    out: dict[str, Any] = {}
    for item in fields:
        if item.name == "__typename":
            out[item.key] = typename
        elif item.children:
            out[item.key] = _resolve(item.children, _typename_of(item.name))
        else:
            out[item.key] = _typename_of(item.name)
    return out


def execute(
    query: str,
    *,
    limits: Limits,
    auth_present: bool,
) -> tuple[int, str]:
    """Run one query against the engine and return ``(status, body)``.

    The order of the checks is the order a hardened server applies them: introspection
    policy, then the depth and cost limits, then authorization, then field resolution.
    """
    lowered = query.lower()
    if "__schema" in lowered:
        if not limits.introspection_enabled:
            return _error("introspection is disabled on this endpoint")
        return 200, introspection_body()
    try:
        fields = parse_query(query)
    except QuerySyntaxError as exc:
        return _error(f"Cannot query field: syntax error ({exc})")
    if limits.max_depth is not None and depth_of(fields) > limits.max_depth:
        return _error(
            f"MAX_DEPTH exceeded: query depth {depth_of(fields)} exceeds maximum {limits.max_depth}"
        )
    aliases = count_aliases(fields)
    if limits.max_aliases is not None and aliases > limits.max_aliases:
        return _error(
            f"query too complex: {aliases} aliases is too many aliases (limit {limits.max_aliases})"
        )
    unknown = sorted(
        {
            item.name
            for item in fields
            if item.name != "__typename" and item.name not in _QUERY_FIELDS
        }
    )
    if unknown:
        name = unknown[0]
        suggestion = SEE_ALSO.get(name.lower())
        message = f"Cannot query field '{name}'"
        if suggestion:
            message += f". Did you mean '{suggestion}'?"
        return _error(message)
    if limits.require_auth and not auth_present:
        protected = sorted({item.name for item in fields if item.name in AUTH_FIELDS})
        if protected:
            return _error(f"not authorized: authentication required to query '{protected[0]}'")
    return 200, json.dumps({"data": _resolve(fields)})
