"""M3 GraphQL depth expansion (research ch03#32, REQ-DEPTH-001).

The S10 ``m3.graphql-audit`` answers one question: *is the schema published?* This module
adds the two depth facets the requirement names, and one property they share is what makes
them safe:

**Every probe in this module selects only the introspection meta-field ``__typename``.**
``{ adminUsers { __typename } }`` makes the server run the ``adminUsers`` resolver and
describe the object it produced — it never asks for a document field, so no user record, no
token and no config value ever crosses the wire. That is the difference between proving
"a resolver answers an anonymous caller" and exfiltrating the data behind it, and the
non-goals (``01-`` §2.2) draw exactly that line.

``m3.graphql-depth-abuse``
    Two bounded amplification probes. The *depth* probe walks the introspected type graph to
    a real cycle (``product → vendor → products → vendor → …``) and nests the selection
    ``max_depth`` levels deep — far below anything that could be called resource exhaustion —
    asking for ``__typename`` at the leaf. The *cost* probe sends one operation carrying
    ``alias_probe_size`` aliases of ``__typename``. A server with a depth or cost limit
    refuses both with a recognisable error; a response that is *data* has neither. The two are
    reported separately because they are separate controls.
``m3.graphql-resolver-auth``
    Asks each schema query field whose *name* suggests an authenticated resource
    (``viewer``, ``adminUsers``, ``invoices``, ...) for its ``__typename`` with no credential,
    with a query for a field that cannot exist as the control. Data from the first and an
    error from the second is the auth-bypass pattern: the resolver runs for a caller who
    presented nothing.

Both checks are opt-in twice over: the check itself is outside the default set, and the
deployment switch ``ARACHNE_WEB_GRAPHQL_PROBE`` must be on. They keep the M3 active-checks
and attestation gates, send no mutation, and bound their own request count.

A note on the ladder: both are **L1** (active read-only) and *declare* it. Neither reaches
for ``ctx.proof``'s L2/L3 grants — a GraphQL probe needs no callback and no state change — so
the registry's proof-consistency gate holds them to exactly the level they claim.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from arachne.core.results import CheckResult
from arachne.core.target import TargetKind
from arachne.modules.base import CheckMetadata, Module
from arachne.modules.context import CheckContext
from arachne.modules.m3.inventory import WebInventory, origin_of
from arachne.modules.m3.payloads import WebPayloads
from arachne.modules.m3.support import (
    WebCheck,
    http_or_skip,
    json_post,
    owns_origin,
    payloads_for,
    skip,
    web_candidate,
    web_or_skip,
)

__all__ = ["GraphQLDepthAbuse", "GraphQLResolverAuth"]

#: The introspection meta-field. Selecting it proves a resolver produced an object without
#: asking for any of that object's content (see the module docstring).
_TYPENAME = "__typename"

#: A field name that cannot exist in any schema: the "the server does error" control.
_ABSENT_FIELD = "arachneNonexistentField"

#: How far the type-graph walk will look for a nesting cycle. A schema with no object-typed
#: field chain simply yields no depth probe (the check says so rather than guessing a name).
_MAX_WALK = 24


# --------------------------------------------------------------------------- schema reading
@dataclass(frozen=True, slots=True)
class Field:
    """One introspected field: its name and the *named* type it returns."""

    name: str
    type_name: str | None


@dataclass(frozen=True, slots=True)
class Schema:
    """The parts of an introspected schema these probes need."""

    query_type: str
    #: Object type name → its object-typed fields (the only ones that can be nested).
    objects: Mapping[str, tuple[Field, ...]] = field(default_factory=dict)
    #: Query field name → the named type it returns.
    query_fields: Mapping[str, str | None] = field(default_factory=dict)

    @property
    def readable(self) -> bool:
        return bool(self.query_fields)


def _named_type(type_ref: Any) -> str | None:
    """The underlying named type of a (possibly wrapped) introspection type reference."""
    seen = 0
    while isinstance(type_ref, dict) and seen < 8:
        seen += 1
        if type_ref.get("name"):
            return str(type_ref["name"])
        type_ref = type_ref.get("ofType")
    return None


def read_schema(exchange: Any) -> Schema | None:
    """The schema an introspection response describes, or ``None`` if it is not one."""
    try:
        body = json.loads(exchange.body)
    except (json.JSONDecodeError, ValueError, TypeError):
        return None
    if not isinstance(body, dict):
        return None
    data = body.get("data")
    schema = data.get("__schema") if isinstance(data, dict) else None
    if not isinstance(schema, dict):
        return None
    types = schema.get("types")
    if not isinstance(types, list):
        return None
    query_type = schema.get("queryType")
    query_name = str(query_type.get("name")) if isinstance(query_type, dict) else "Query"
    kinds: dict[str, str] = {}
    raw_fields: dict[str, list[tuple[str, str | None]]] = {}
    for entry in types:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        if not isinstance(name, str):
            continue
        kinds[name] = str(entry.get("kind") or "")
        fields = entry.get("fields")
        if not isinstance(fields, list):
            continue
        collected: list[tuple[str, str | None]] = []
        for item in fields:
            if not isinstance(item, dict):
                continue
            field_name = item.get("name")
            if not isinstance(field_name, str) or not field_name.isidentifier():
                continue
            if field_name.startswith("__"):
                continue
            collected.append((field_name, _named_type(item.get("type"))))
        raw_fields[name] = collected

    def _is_object(type_name: str | None) -> bool:
        return type_name is not None and kinds.get(type_name) in {"OBJECT", "INTERFACE"}

    objects = {
        name: tuple(Field(n, t) for n, t in fields if _is_object(t))
        for name, fields in raw_fields.items()
    }
    query_fields = {
        name: type_name
        for name, type_name in raw_fields.get(query_name, [])
        if type_name is not None
    }
    return Schema(query_type=query_name, objects=objects, query_fields=query_fields)


def object_query_fields(schema: Schema, *, name_hints: tuple[str, ...] = ()) -> tuple[str, ...]:
    """Query fields that return an object, optionally filtered by name hints.

    Only object-typed fields qualify: a scalar-typed field (``secretToken: String``) would
    have to be requested by name, which would return its *content* — the line this module does
    not cross.
    """
    out: list[str] = []
    for name, type_name in schema.query_fields.items():
        if schema.objects.get(type_name or "") is None:
            continue
        if name_hints and not any(hint in name.lower() for hint in name_hints):
            continue
        out.append(name)
    return tuple(out)


def depth_path(schema: Schema, start: str, depth: int) -> tuple[str, ...]:
    """A selection path of ``depth`` object fields starting at query field ``start``.

    The walk follows the schema, never guessing a name, and prefers a field whose return type
    is already on the path (a genuine cycle such as ``product → vendor → products``) because
    that is what makes an unbounded depth reachable at all. An empty tuple means the schema
    offers no such path, and the depth probe then reports that it could not test the limit.
    """
    if depth < 2 or start not in schema.query_fields:
        return ()
    path = [start]
    seen = [schema.query_fields.get(start)]
    current = schema.query_fields.get(start)
    for _ in range(depth - 1):
        options = schema.objects.get(current or "")
        if not options:
            return ()
        chosen: Field | None = None
        for candidate in options:
            if candidate.type_name in seen:
                chosen = candidate
                break
        if chosen is None:
            chosen = options[0]
        path.append(chosen.name)
        seen.append(chosen.type_name)
        current = chosen.type_name
        if len(path) >= _MAX_WALK:
            break
    return tuple(path) if len(path) >= depth else ()


def nested_query(path: tuple[str, ...]) -> str:
    """``{ a { b { c { __typename } } } }`` — the meta-field under ``len(path)`` levels."""
    opened = " { ".join(path)
    return "{ " + opened + " { " + _TYPENAME + " " + "} " * len(path) + "}"


def alias_query(size: int, template: str) -> str:
    """One operation carrying ``size`` aliases of ``__typename`` (the cost probe)."""
    aliases = " ".join(template.format(i=index) for index in range(max(1, size)))
    return "{ " + aliases + " }"


# --------------------------------------------------------------------------- response reading
def _data_of(exchange: Any) -> Mapping[str, Any]:
    """The ``data`` object of a GraphQL response, or an empty mapping."""
    try:
        body = json.loads(exchange.body)
    except (json.JSONDecodeError, ValueError, TypeError):
        return {}
    if not isinstance(body, dict):
        return {}
    data = body.get("data")
    return data if isinstance(data, dict) else {}


def _refusal(body: str, markers: Iterable[str]) -> str | None:
    """The refusal marker the body carries, if any (a depth/cost/auth refusal, not data)."""
    lowered = body.lower()
    for marker in markers:
        if marker.lower() in lowered:
            return marker
    return None


async def _graphql_post(ctx: CheckContext, url: str, query: str) -> Any:
    """One GraphQL request, issued **anonymously**.

    Every probe in this module is a question about what a caller who presents nothing can
    reach, so the request goes out on the client's cookie-less path: no operator session
    header and no cookie the crawl (or a credentialed broker's login) established. A single
    helper, so no probe can be written that forgets it.
    """
    return await json_post(ctx, url, {"query": query}, session=False, anonymous=True)


def _endpoints(ctx: CheckContext, inventory: WebInventory) -> list[str]:
    """The GraphQL endpoints to probe: crawled hits first, then the path hints themselves."""
    payloads = payloads_for(ctx)
    origin = origin_of(ctx.asset.value)
    hints = [hint.lower() for hint in payloads.strings("graphql", "endpoint_hints")]
    found = [
        url
        for url in inventory.endpoints
        if origin_of(url) == origin and any(hint in url.lower() for hint in hints)
    ]
    if not found:
        found = [f"{origin}{path}" for path in payloads.strings("graphql", "endpoint_hints")[:3]]
    return [url.split("?")[0] for url in found[:3]]


def _introspection_query(payloads: WebPayloads) -> str:
    return payloads.string(
        "graphql",
        "introspection_query",
        default=(
            "query IntrospectionQuery { __schema { queryType { name } types { name kind "
            "fields { name type { name kind ofType { name kind ofType { name kind } } } } } } }"
        ),
    )


# --------------------------------------------------------------------------- depth & cost
class GraphQLDepthAbuse(WebCheck, Module):
    """``m3.graphql-depth-abuse`` — missing depth/cost limits (ch03#32). Opt-in."""

    metadata = CheckMetadata(
        id="m3.graphql-depth-abuse",
        module="M3",
        name="graphql-depth-abuse",
        version="1.0",
        title="GraphQL depth and cost limit audit",
        description=(
            "Sends two bounded amplification probes at the GraphQL endpoints the crawl found: a "
            "selection nested to a configured (modest) depth along a real cycle in the "
            "introspected type graph, and one operation carrying a configured number of "
            "aliases. A server with a depth or cost limit refuses them; a response carrying "
            "data means the limit is absent. Every probe selects only the introspection "
            "meta-field __typename, so no document content is requested; no mutation is sent."
        ),
        research_ref="ch03#32",
        framework=("WSTG-APIT-01", "API4:2023", "CWE-770"),
        cwe="CWE-770",
        target_kinds=(TargetKind.URL,),
        severity_hint="low",
        type="active",
        safe=True,
        verifiable=True,
        enabled_by_default=False,
        estimated_requests=9,
        requires_active_checks=True,
        runs_on_discovered=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        _client, skipped = http_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        if not ctx.config.web.graphql_probe:
            yield skip(
                ctx,
                "the GraphQL depth/cost probe is off: set ARACHNE_WEB_GRAPHQL_PROBE=true to "
                "enable it (it asks a server to do amplification-shaped work)",
            )
            return
        if not owns_origin(ctx):
            yield skip(ctx, "another URL asset on this origin owns the M3 crawl for it")
            return
        inventory, skipped = web_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        assert isinstance(inventory, WebInventory)
        payloads = payloads_for(ctx)
        markers = tuple(payloads.strings("graphql", "refusal_markers"))
        depth = int(payloads.number("graphql", "max_depth", default=12))
        alias_template = payloads.string("graphql", "alias_template", default="{i}: __typename")
        probe_size = int(payloads.number("graphql", "alias_probe_size", default=32))
        threshold = int(payloads.number("graphql", "alias_abuse_threshold", default=24))
        findings = 0
        probed = 0
        depth_untestable: list[str] = []
        for url in _endpoints(ctx, inventory):
            schema_exchange = await _graphql_post(ctx, url, _introspection_query(payloads))
            if schema_exchange is None:
                continue
            schema = read_schema(schema_exchange)
            probed += 1

            # --- depth -----------------------------------------------------------------
            path: tuple[str, ...] = ()
            if schema is not None:
                for start in object_query_fields(schema):
                    candidate = depth_path(schema, start, depth)
                    if candidate:
                        path = candidate
                        break
            if not path:
                depth_untestable.append(url)
            else:
                exchange = await _graphql_post(ctx, url, nested_query(path))
                if (
                    exchange is not None
                    and _refusal(exchange.body, markers) is None
                    and _data_of(exchange)
                ):
                    findings += 1
                    yield web_candidate(
                        ctx,
                        f"GraphQL endpoint {url} answered a {len(path)}-level nested query",
                        artifact={
                            "signal": "graphql",
                            "family": "graphql",
                            "facet": "depth-limit",
                            "endpoint": url,
                            "depth": len(path),
                            "nesting_path": list(path),
                            "limit_refused": False,
                            "content_requested": False,
                        },
                        exchanges=(exchange,),
                        cwe="CWE-770",
                        confidence=0.7,
                        detail=(
                            f"the selection {' → '.join(path)} nested {len(path)} levels deep "
                            "returned data, and no level asked for a document field (only "
                            "__typename). Without a depth limit one request can be made to "
                            "consume unbounded resolver work (research ch03#32)."
                        ),
                        source=url,
                    )

            # --- cost (aliases) --------------------------------------------------------
            alias_exchange = await _graphql_post(ctx, url, alias_query(probe_size, alias_template))
            if alias_exchange is not None and _refusal(alias_exchange.body, markers) is None:
                data = _data_of(alias_exchange)
                if len(data) >= threshold:
                    findings += 1
                    yield web_candidate(
                        ctx,
                        f"GraphQL endpoint {url} accepted {len(data)} aliases in one operation",
                        artifact={
                            "signal": "graphql",
                            "family": "graphql",
                            "facet": "cost-limit",
                            "endpoint": url,
                            "aliases_accepted": len(data),
                            "aliases_sent": probe_size,
                            "threshold": threshold,
                            "limit_refused": False,
                        },
                        exchanges=(alias_exchange,),
                        cwe="CWE-770",
                        confidence=0.6,
                        detail=(
                            f"one operation carrying {probe_size} aliases of the meta-field "
                            f"returned {len(data)} results with no complexity error, so the "
                            "endpoint applies no cost limit to a query's shape "
                            "(research ch03#32)."
                        ),
                        source=url,
                    )
        if not findings:
            detail = (
                f"probed {probed} endpoint(s); every nested or aliased selection was refused, "
                "errored or returned no data"
            )
            if depth_untestable:
                detail += (
                    "; the depth limit could not be tested at "
                    + ", ".join(depth_untestable[:3])
                    + " (no introspectable cycle to nest along)"
                )
            yield ctx.clean(
                "GraphQL depth and cost probes found no missing limit",
                detail=detail,
                confidence=0.6,
            )


# --------------------------------------------------------------------------- resolver auth
class GraphQLResolverAuth(WebCheck, Module):
    """``m3.graphql-resolver-auth`` — anonymous access to authenticated resolvers. Opt-in."""

    metadata = CheckMetadata(
        id="m3.graphql-resolver-auth",
        module="M3",
        name="graphql-resolver-auth",
        version="1.0",
        title="GraphQL resolver authorization audit",
        description=(
            "Reads the schema and asks each query field whose name suggests an authenticated "
            "resource for its __typename with no credential presented, with a query for a "
            "field that cannot exist as the control. Data from the first and an error from the "
            "second is the anonymous-resolver-access pattern. Only the introspection meta-field "
            "is selected, so no document content is requested."
        ),
        research_ref="ch03#32",
        framework=("WSTG-APIT-01", "API5:2023", "CWE-862"),
        cwe="CWE-862",
        target_kinds=(TargetKind.URL,),
        severity_hint="high",
        type="active",
        safe=True,
        verifiable=True,
        enabled_by_default=False,
        estimated_requests=10,
        requires_active_checks=True,
        runs_on_discovered=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        _client, skipped = http_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        if not ctx.config.web.graphql_probe:
            yield skip(
                ctx,
                "the GraphQL authorization probe is off: set ARACHNE_WEB_GRAPHQL_PROBE=true "
                "to enable it (it asks sensitive-named resolvers for an object description)",
            )
            return
        if not owns_origin(ctx):
            yield skip(ctx, "another URL asset on this origin owns the M3 crawl for it")
            return
        inventory, skipped = web_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        assert isinstance(inventory, WebInventory)
        payloads = payloads_for(ctx)
        markers = tuple(payloads.strings("graphql", "refusal_markers"))
        hints = tuple(hint.lower() for hint in payloads.strings("graphql", "sensitive_field_hints"))
        findings = 0
        for url in _endpoints(ctx, inventory):
            schema_exchange = await _graphql_post(ctx, url, _introspection_query(payloads))
            if schema_exchange is None:
                continue
            schema = read_schema(schema_exchange)
            if schema is None or not schema.readable:
                continue
            # The control: a field that cannot exist must produce an error. If it does not,
            # this endpoint answers everything and a "bypass" reading would be meaningless.
            control = await _graphql_post(ctx, url, f"{{ {_ABSENT_FIELD} {{ {_TYPENAME} }} }}")
            if control is None or _data_of(control):
                continue
            for field_name in object_query_fields(schema, name_hints=hints)[:6]:
                exchange = await _graphql_post(ctx, url, f"{{ {field_name} {{ {_TYPENAME} }} }}")
                if exchange is None:
                    continue
                data = _data_of(exchange)
                if not data or _refusal(exchange.body, markers) is not None:
                    continue
                findings += 1
                value = data.get(field_name)
                returned = (
                    str(value.get(_TYPENAME))
                    if isinstance(value, dict)
                    else type(value).__name__
                    if value is not None
                    else "null"
                )
                yield web_candidate(
                    ctx,
                    f"GraphQL resolver '{field_name}' answered an anonymous caller at {url}",
                    artifact={
                        "signal": "graphql",
                        "family": "graphql",
                        "facet": "resolver-auth",
                        "endpoint": url,
                        "field": field_name,
                        "anonymous_request": True,
                        "content_requested": False,
                        "returned_typename": returned,
                    },
                    exchanges=(exchange, control),
                    cwe="CWE-862",
                    confidence=0.7,
                    detail=(
                        f"asking for '{field_name} {{ __typename }}' with no credential "
                        "returned an object description, while a query for a field that cannot "
                        f"exist ('{_ABSENT_FIELD}') errored as expected — so the resolver, not "
                        "the transport, is what answered. No document field was requested: this "
                        "proves the authorization gap without reading the data behind it "
                        "(research ch03#32)."
                    ),
                    source=url,
                )
        if not findings:
            yield ctx.clean(
                "no anonymously reachable sensitive GraphQL resolver observed",
                detail=(
                    "either introspection is disabled, the sensitive-named resolvers refused "
                    "the anonymous query, or no such field exists in the schema"
                ),
                confidence=0.5,
            )
