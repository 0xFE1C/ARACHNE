"""M3 extended API/client families: mass assignment (ch03#26), prototype pollution (ch03#27),
GraphQL (ch03#32), WebSocket (ch03#33) and business logic (ch03#30).

Five families that all live above the injection layer: they abuse a *legitimate* mechanism —
object binding, a JSON merge, a GraphQL query, a WebSocket handshake, a workflow's own fields —
reading an over-permissive behaviour rather than an exploitable defect. Every confirmation is a
measured difference (a reflected injected property, an introspected schema, an accepted
cross-origin handshake, an accepted edge value) and none of them writes durable state:

``m3.mass-assign-audit``
    Adds sensitive property names (role, is_admin, balance, ...) to an API body and reports the
    one the response reflects back — the property-level binding gap of research ch03#26.
``m3.proto-pollution``
    Injects a benign prototype key through a JSON body the server merges and reports the marker
    the server echoed (the server-side pollution oracle). A headless-browser DOM-sink check is
    out of scope (ADR-S10-6).
``m3.graphql-audit``
    Runs the introspection query and a field-suggestion probe against the GraphQL endpoints the
    crawl found (research ch03#32).
``m3.websocket-audit``
    Attempts the upgrade handshake with a reserved attacker Origin and reports an accepted
    handshake — the cross-site WebSocket hijacking precondition of research ch03#33.
``m3.business-logic-audit``
    Sends the edge values of research ch03#30 (negative/zero/huge quantities) at the fields that
    drive a workflow and reports one the application accepted where its constraints should have
    refused it.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any

from arachne.core.results import CheckResult
from arachne.core.target import TargetKind
from arachne.modules.base import CheckMetadata, Module
from arachne.modules.context import CheckContext
from arachne.modules.m3.inventory import WebInventory, origin_of
from arachne.modules.m3.support import (
    WebCheck,
    http_or_skip,
    json_post,
    owns_origin,
    payloads_for,
    probe_url,
    safe_fetch,
    skip,
    text_ratio,
    web_candidate,
    web_or_skip,
)

__all__ = [
    "BusinessLogicAudit",
    "GraphQLAudit",
    "MassAssignmentAudit",
    "PrototypePollution",
    "WebSocketAudit",
]


# --------------------------------------------------------------------------- mass assignment
class MassAssignmentAudit(WebCheck, Module):
    """``m3.mass-assign-audit`` — object property over-binding (ch03#26)."""

    metadata = CheckMetadata(
        id="m3.mass-assign-audit",
        module="M3",
        name="mass-assign-audit",
        version="1.0",
        title="Mass assignment (property-level binding) audit",
        description=(
            "Adds sensitive property names (role, is_admin, balance, verified, ...) to an API body "
            "the crawl found binding to an object, and reports the property whose injected value "
            "the response reflects back — the object-property over-binding gap of research "
            "ch03#26. Detection-only: the property is read from the response, never relied upon, "
            "and no durable state is created."
        ),
        research_ref="ch03#26",
        cwe="CWE-915",
        target_kinds=(TargetKind.URL,),
        severity_hint="high",
        type="active",
        safe=True,
        verifiable=False,
        estimated_requests=8,
        requires_active_checks=True,
        runs_on_discovered=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        _client, skipped = http_or_skip(ctx)
        if skipped is not None:
            yield skipped
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
        fields = payloads.entries("mass_assign", "fields")
        hints = [hint.lower() for hint in payloads.strings("mass_assign", "path_hints")]
        origin = origin_of(ctx.asset.value)
        endpoints = [
            url
            for url in inventory.endpoints
            if origin_of(url) == origin and any(h in url.lower() for h in hints)
        ]
        origin_of(ctx.asset.value)
        candidates: list[str] = list(dict.fromkeys([*endpoints]))
        if not candidates:
            yield ctx.clean(
                "no object-binding endpoint to test",
                detail=(
                    "the crawl found no API endpoint whose path suggests a "
                    "profile/registration form"
                ),
            )
            return
        findings = 0
        for url in candidates[:2]:
            baseline = await safe_fetch(ctx, url, session=False, follow_redirects=False)
            injected = {str(item.get("name")): item.get("value") for item in fields}
            payload = {"username": "arachne-probe", **injected}
            exchange = await json_post(ctx, url, payload, session=False)
            if exchange is None:
                continue
            matched = [
                name
                for name, value in injected.items()
                if value is not None
                and f'"{name}"'.lower() in exchange.body.lower()
                and str(value).lower() in exchange.body.lower()
            ]
            if not matched:
                continue
            findings += 1
            yield web_candidate(
                ctx,
                f"API binds extra properties on {url}",
                artifact={
                    "signal": "mass-assignment",
                    "family": "mass-assignment",
                    "endpoint": url,
                    "bound_fields": matched,
                    "injected": injected,
                    "baseline_status": None if baseline is None else baseline.status_code,
                },
                exchanges=(exchange,) if baseline is None else (baseline, exchange),
                cwe="CWE-915",
                confidence=0.7,
                detail=(
                    f"{url} reflected the injected propert(ies) {matched}, so the request body is "
                    "bound to the object without an allowlist"
                ),
                source=url,
            )
        if not findings:
            yield ctx.clean(
                "no extra property bound",
                detail=f"posted over-posting probes to {min(len(candidates), 2)} endpoint(s)",
            )


# --------------------------------------------------------------------------- prototype pollution
class PrototypePollution(WebCheck, Module):
    """``m3.proto-pollution`` — server-side JSON merge pollution oracle (ch03#27)."""

    metadata = CheckMetadata(
        id="m3.proto-pollution",
        module="M3",
        name="proto-pollution",
        version="1.0",
        title="Prototype pollution oracle (server-observable)",
        description=(
            "Injects a benign prototype key (__proto__ / constructor.prototype) carrying a unique "
            "marker through a JSON body the server merges, and reports the marker the server "
            "echoed back — the server-observable pollution oracle of research ch03#27. A "
            "headless-browser DOM-sink check is out of scope for this stage (ADR-S10-6); the check "
            "never attempts to chain the pollution to a sink."
        ),
        research_ref="ch03#27",
        cwe="CWE-1321",
        target_kinds=(TargetKind.URL,),
        severity_hint="medium",
        type="active",
        safe=True,
        verifiable=False,
        estimated_requests=8,
        requires_active_checks=True,
        runs_on_discovered=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        _client, skipped = http_or_skip(ctx)
        if skipped is not None:
            yield skipped
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
        keys = payloads.strings("proto_pollution", "keys") or ("__proto__",)
        marker_key = payloads.string("proto_pollution", "marker_key", default="arachne_polluted")
        marker_value = payloads.string("proto_pollution", "marker_value", default="ar9x")
        hints = [hint.lower() for hint in payloads.strings("proto_pollution", "param_hints")]
        origin = origin_of(ctx.asset.value)
        endpoints = [
            url
            for url in inventory.endpoints
            if origin_of(url) == origin and any(h in url.lower() for h in hints)
        ]
        if not endpoints:
            yield ctx.clean(
                "no JSON-merge endpoint to probe",
                detail="the crawl found no endpoint whose path suggests a config/filter merge",
            )
            return
        findings = 0
        for url in endpoints[:2]:
            for key in keys[:2]:
                body: dict[str, Any] = {key: {marker_key: marker_value}}
                exchange = await json_post(ctx, url, body, session=False)
                if exchange is None:
                    continue
                if marker_value not in exchange.body:
                    continue
                findings += 1
                yield web_candidate(
                    ctx,
                    f"JSON merge inherited the '{key}' prototype key at {url}",
                    artifact={
                        "signal": "prototype-pollution",
                        "family": "proto-pollution",
                        "endpoint": url,
                        "key": key,
                        "marker": marker_key,
                        "observed": marker_value,
                        "status": exchange.status_code,
                    },
                    exchanges=(exchange,),
                    cwe="CWE-1321",
                    confidence=0.7,
                    detail=(
                        f"{url} echoed the injected prototype marker, so a recursive JSON merge "
                        "does not filter prototype keys"
                    ),
                    source=url,
                )
                break
        if not findings:
            yield ctx.clean(
                "no prototype key accepted",
                detail=f"posted prototype-key probes to {min(len(endpoints), 2)} endpoint(s)",
            )


# --------------------------------------------------------------------------- GraphQL
class GraphQLAudit(WebCheck, Module):
    """``m3.graphql-audit`` — introspection and field-suggestion disclosure (ch03#32)."""

    metadata = CheckMetadata(
        id="m3.graphql-audit",
        module="M3",
        name="graphql-audit",
        version="1.0",
        title="GraphQL introspection and schema disclosure",
        description=(
            "Runs the introspection query and a wrong-field suggestion probe against the GraphQL "
            "endpoints the crawl found, and reports an enabled introspection (full schema "
            "disclosure) or a field-suggestion leak (research ch03#32). Read-only queries only; "
            "no mutation is sent and no batching amplification is attempted beyond a bounded alias "
            "probe."
        ),
        research_ref="ch03#32",
        cwe="CWE-200",
        target_kinds=(TargetKind.URL,),
        severity_hint="medium",
        type="active",
        safe=True,
        verifiable=False,
        estimated_requests=8,
        requires_active_checks=True,
        runs_on_discovered=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        _client, skipped = http_or_skip(ctx)
        if skipped is not None:
            yield skipped
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
        origin = origin_of(ctx.asset.value)
        hints = [hint.lower() for hint in payloads.strings("graphql", "endpoint_hints")]
        endpoints = [
            url
            for url in inventory.endpoints
            if origin_of(url) == origin and any(h in url.lower() for h in hints)
        ]
        if not endpoints:
            endpoints = [
                f"{origin}{path}" for path in payloads.strings("graphql", "endpoint_hints")[:3]
            ]
        introspection = payloads.string("graphql", "introspection_query")
        suggestion = payloads.string("graphql", "suggestion_query")
        suggestion_markers = payloads.strings("graphql", "suggestion_markers")
        findings = 0
        for url in endpoints[:3]:
            exchange = await json_post(ctx, url.split("?")[0], {"query": introspection})
            if exchange is None:
                continue
            if "__schema" not in exchange.body and '"types"' not in exchange.body:
                continue
            probe = await json_post(ctx, url.split("?")[0], {"query": suggestion})
            suggested = probe is not None and any(
                marker.lower() in probe.body.lower() for marker in suggestion_markers
            )
            findings += 1
            yield web_candidate(
                ctx,
                f"GraphQL introspection is enabled at {url}",
                artifact={
                    "signal": "graphql",
                    "family": "graphql",
                    "endpoint": url,
                    "introspection_enabled": True,
                    "suggestion_leak": bool(suggested),
                    "status": exchange.status_code,
                },
                exchanges=(exchange,) if probe is None else (exchange, probe),
                cwe="CWE-200",
                confidence=0.8,
                detail=(
                    f"{url} answered the introspection query with the schema"
                    + ("; a wrong field name leaks suggestions" if suggested else "")
                ),
                source=url,
            )
            break
        if not findings:
            yield ctx.clean(
                "GraphQL introspection disabled or absent",
                detail=f"probed {min(len(endpoints), 3)} candidate endpoint(s)",
            )


# --------------------------------------------------------------------------- WebSocket
class WebSocketAudit(WebCheck, Module):
    """``m3.websocket-audit`` — cross-origin handshake acceptance (ch03#33)."""

    metadata = CheckMetadata(
        id="m3.websocket-audit",
        module="M3",
        name="websocket-audit",
        version="1.0",
        title="WebSocket handshake origin validation audit",
        description=(
            "Attempts the WebSocket upgrade handshake against the endpoints the crawl found, with "
            "a reserved attacker Origin, and reports an accepted handshake — the cross-site "
            "WebSocket hijacking precondition of research ch03#33. Read-only: the handshake is "
            "attempted (a GET with the upgrade headers) and abandoned at once; no frame is sent "
            "and no message is injected."
        ),
        research_ref="ch03#33",
        cwe="CWE-1385",
        target_kinds=(TargetKind.URL,),
        severity_hint="medium",
        type="active",
        safe=True,
        verifiable=False,
        estimated_requests=6,
        requires_active_checks=True,
        runs_on_discovered=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        _client, skipped = http_or_skip(ctx)
        if skipped is not None:
            yield skipped
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
        origin = origin_of(ctx.asset.value)
        hints = [hint.lower() for hint in payloads.strings("websocket", "path_hints")]
        endpoints = [
            url
            for url in inventory.endpoints
            if origin_of(url) == origin and any(h in url.lower() for h in hints)
        ]
        if not endpoints:
            endpoints = [
                f"{origin}{path}" for path in payloads.strings("websocket", "path_hints")[:2]
            ]
        headers = dict(payloads.mapping("websocket", "upgrade_headers"))
        attacker_origin = (
            payloads.strings("websocket", "origins") or ["https://arachne-ws.invalid"]
        )[0]
        findings = 0
        for url in endpoints[:2]:
            exchange = await safe_fetch(
                ctx,
                url,
                headers={**headers, "Origin": attacker_origin},
                session=False,
                follow_redirects=False,
            )
            if exchange is None:
                continue
            accepted = exchange.status_code == 101 or (
                exchange.status_code == 200 and exchange.header("sec-websocket-accept") is not None
            )
            if not accepted:
                continue
            findings += 1
            yield web_candidate(
                ctx,
                "WebSocket handshake accepted for a cross-origin request",
                artifact={
                    "signal": "websocket",
                    "family": "websocket",
                    "endpoint": url,
                    "origin": attacker_origin,
                    "status": exchange.status_code,
                    "origin_validated": False,
                },
                exchanges=(exchange,),
                cwe="CWE-1385",
                confidence=0.7,
                detail=(
                    f"{url} proceeded with the upgrade handshake for Origin: {attacker_origin}, so "
                    "the endpoint does not validate the origin"
                ),
                source=url,
            )
            break
        if not findings:
            yield ctx.clean(
                "no cross-origin WebSocket handshake accepted",
                detail=f"attempted the handshake at {min(len(endpoints), 2)} endpoint(s)",
            )


# --------------------------------------------------------------------------- business logic
class BusinessLogicAudit(WebCheck, Module):
    """``m3.business-logic-audit`` — client-authoritative value / constraint bypass (ch03#30)."""

    metadata = CheckMetadata(
        id="m3.business-logic-audit",
        module="M3",
        name="business-logic-audit",
        version="1.0",
        title="Business-logic invariant audit",
        description=(
            "Sends the edge values of research ch03#30 (a negative, zero or huge quantity / a "
            "client-supplied price) at the fields that drive a workflow, and reports one the "
            "application accepted where its own constraints should have refused it (a success "
            "response for a value the flow cannot honour). Detection-only: no order is created and "
            "no state is modified."
        ),
        research_ref="ch03#30",
        cwe="CWE-840",
        target_kinds=(TargetKind.URL,),
        severity_hint="medium",
        type="hybrid",
        safe=True,
        verifiable=False,
        estimated_requests=8,
        requires_active_checks=True,
        runs_on_discovered=True,
    )

    def __init__(self) -> None:
        self._markers: tuple[str, ...] = (
            "success",
            "placed",
            "accepted",
            "confirmed",
            "ok",
            "created",
            "saved",
        )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        _client, skipped = http_or_skip(ctx)
        if skipped is not None:
            yield skipped
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
        quantity = {name.lower() for name in payloads.strings("business_logic", "quantity_fields")}
        edges = payloads.strings("business_logic", "edge_values") or ["-1", "0"]
        origin = origin_of(ctx.asset.value)
        targets = [
            (url, param)
            for url, param in inventory.parameter_targets(names=quantity)
            if origin_of(url) == origin
        ][: ctx.config.web.max_params_per_check]
        if not targets:
            yield ctx.clean(
                "no quantity/price field to test",
                detail="the crawl found no parameter whose name suggests a quantity or a price",
            )
            return
        findings = 0
        for url, param in targets:
            benign = await safe_fetch(
                ctx, probe_url(url, param, "1"), session=False, follow_redirects=False
            )
            if benign is None:
                continue
            for edge in edges:
                exchange = await safe_fetch(
                    ctx, probe_url(url, param, edge), session=False, follow_redirects=False
                )
                if exchange is None:
                    continue
                accepted = any(marker in exchange.body.lower() for marker in self._markers)
                rejected = any(
                    marker in exchange.body.lower()
                    for marker in ("invalid", "error", "must be", "positive", "denied")
                )
                if not accepted or rejected:
                    continue
                findings += 1
                yield web_candidate(
                    ctx,
                    f"Business invariant not enforced for '{param}' (edge value {edge})",
                    artifact={
                        "signal": "business-logic",
                        "family": "business-logic",
                        "endpoint": url,
                        "parameter": param,
                        "edge_value": edge,
                        "accepted": True,
                        "baseline_ratio": round(text_ratio(benign.body, exchange.body), 4),
                    },
                    exchanges=(benign, exchange),
                    cwe="CWE-840",
                    confidence=0.55,
                    detail=(
                        f"{url} accepted the edge value {edge!r} for '{param}' "
                        "with a success response where its constraints should refuse it"
                    ),
                    source=url,
                )
                break
        if not findings:
            yield ctx.clean(
                "edge values were refused",
                detail=f"tested {len(targets)} quantity/price parameter(s)",
            )
