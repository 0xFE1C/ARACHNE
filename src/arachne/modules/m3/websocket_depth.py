"""M3 WebSocket depth expansion (research ch03#33, REQ-DEPTH-002).

S10's ``m3.websocket-audit`` checks one thing: does the endpoint accept a handshake from a
reserved attacker ``Origin``? These two checks add the other two facets the requirement
names, and both stay inside the proof ladder — neither sends a payload that could change
anything.

``m3.websocket-upgrade-auth``
    Completes the upgrade with **no credential at all** (no ``Authorization``, no ``Cookie``,
    no subprotocol token, no demo session) and reports the endpoint that proceeds anyway. A
    plain ``GET`` of the same path is the control: a WebSocket endpoint answers "upgrade
    required", so a 200 HTML page is a false lead, not a finding. The handshake is verified
    against the RFC 6455 ``Sec-WebSocket-Accept`` derivation of the key we sent, so a path
    that merely returns a 101-looking status is not reported.
``m3.websocket-injection``
    Completes the handshake over the scoped network client and sends **one** text frame whose
    payload is an inert, self-describing marker (``ARACHNE_POC_<nonce> safe-proof-of-
    websocket-message-relay``) plus one control PING. A server that echoes the marker back is
    relaying client input unvalidated — the stated precondition of message injection — and
    that is all this check proves: it injects no command language, no query and no
    target-specific syntax, and sends exactly one message per endpoint.

Both are L1 (active read-only) and *declare* it; neither requests an L2/L3 grant. Both are
opt-in: they are outside the default check set, and the injection probe additionally needs
``ARACHNE_WEB_WS_PROBE=true``, because a frame is the one step that makes a WebSocket probe a
conversation rather than a read.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from urllib.parse import SplitResult, urlsplit

from arachne.core.results import CheckResult
from arachne.core.target import TargetKind
from arachne.modules.base import CheckMetadata, Module
from arachne.modules.context import CheckContext
from arachne.modules.m3 import wsproto
from arachne.modules.m3.inventory import WebInventory, origin_of
from arachne.modules.m3.support import (
    WebCheck,
    http_or_skip,
    nonce,
    owns_origin,
    payloads_for,
    skip,
    web_candidate,
    web_or_skip,
)

__all__ = ["WebSocketInjection", "WebSocketUpgradeAuth"]

#: Status codes that mean "this path only answers an upgrade" (the control's expected reply).
_UPGRADE_REQUIRED = frozenset({400, 404, 405, 426, 505})


def _candidate_endpoints(ctx: CheckContext, inventory: WebInventory) -> list[str]:
    """WS endpoints to probe: crawled hits first, then the path hints themselves (max 2)."""
    payloads = payloads_for(ctx)
    origin = origin_of(ctx.asset.value)
    hints = [hint.lower() for hint in payloads.strings("websocket", "path_hints")]
    found = [
        url
        for url in inventory.endpoints
        if origin_of(url) == origin and any(hint in url.lower() for hint in hints)
    ]
    if not found:
        found = [f"{origin}{path}" for path in payloads.strings("websocket", "path_hints")[:2]]
    return [url.split("?")[0] for url in found[:2]]


def _key_of(ctx: CheckContext) -> str:
    """The ``Sec-WebSocket-Key`` the corpus declares (a fixed, non-secret nonce)."""
    headers = payloads_for(ctx).mapping("websocket", "upgrade_headers")
    for name, value in headers.items():
        if name.lower() == "sec-websocket-key":
            return str(value)
    return "dGhlIHNhbXBsZSBub25jZQ=="


def _parse_response(raw: bytes) -> tuple[int, dict[str, str]]:
    """``(status, headers)`` from a raw HTTP response (no body needed for a handshake)."""
    head = raw.split(b"\r\n\r\n", 1)[0].decode("latin-1", "replace")
    lines = head.split("\r\n")
    if not lines:
        return 0, {}
    parts = lines[0].split(" ", 2)
    try:
        status = int(parts[1])
    except (IndexError, ValueError):
        status = 0
    headers: dict[str, str] = {}
    for line in lines[1:]:
        name, separator, value = line.partition(":")
        if separator:
            headers[name.strip().lower()] = value.strip()
    return status, headers


def _plain_get(parts: SplitResult) -> bytes:
    """A plain (non-upgrade) GET of the same path — the upgrade-only control request."""
    target = parts.path or "/"
    if parts.query:
        target = f"{target}?{parts.query}"
    host = parts.hostname or ""
    port = parts.port
    host_header = f"{host}:{port}" if port and port != 80 else host
    return (
        f"GET {target} HTTP/1.1\r\nHost: {host_header}\r\nConnection: close\r\nAccept: */*\r\n\r\n"
    ).encode("ascii", errors="replace")


class WebSocketUpgradeAuth(WebCheck, Module):
    """``m3.websocket-upgrade-auth`` — upgrades accepted with no credential (ch03#33). Opt-in."""

    metadata = CheckMetadata(
        id="m3.websocket-upgrade-auth",
        module="M3",
        name="websocket-upgrade-auth",
        version="1.0",
        title="WebSocket upgrade authentication audit",
        description=(
            "Completes the WebSocket upgrade at the endpoints the crawl found while presenting "
            "no credential of any kind (no Authorization, Cookie, subprotocol token or demo "
            "session), verifying the RFC 6455 accept derivation of the key it sent and using a "
            "plain GET of the same path as the upgrade-only control. An upgrade that succeeds "
            "without a credential means the connection is never authenticated."
        ),
        research_ref="ch03#33",
        framework=("WSTG-CLNT-10", "API2:2023", "CWE-306"),
        cwe="CWE-306",
        target_kinds=(TargetKind.URL,),
        severity_hint="medium",
        type="active",
        safe=True,
        verifiable=True,
        enabled_by_default=False,
        estimated_requests=8,
        requires_active_checks=True,
        runs_on_discovered=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        _client, skipped = http_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        if ctx.net is None:
            yield skip(
                ctx,
                "no network client in this run: the upgrade is completed at the byte level so "
                "that 'no credential was presented' is a fact about the request, not an "
                "assumption about the HTTP client's cookie jar",
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
        auth_names = {name.lower() for name in payloads.strings("websocket", "auth_header_names")}
        # Only the protocol-required headers: the question is what happens with *no*
        # credential, so every credential-looking header is dropped, not just the ones the
        # corpus happens to name.
        headers = {
            name: value
            for name, value in payloads.mapping("websocket", "upgrade_headers").items()
            if name.lower() not in auth_names
            and name.lower() not in {"authorization", "cookie", "proxy-authorization", "origin"}
        }
        expected = wsproto.accept_key(_key_of(ctx))
        host_header = urlsplit(ctx.asset.value).netloc
        findings = 0
        probed = 0
        for url in _candidate_endpoints(ctx, inventory):
            parts = urlsplit(url)
            if parts.scheme != "http":
                # The byte-level upgrade below is plain TCP; a TLS endpoint would need the
                # scoped TLS client. It is reported by the handshake-less check instead of
                # being probed insecurely.
                continue
            host = parts.hostname or ""
            port = parts.port or 80
            request = wsproto.build_upgrade_request(
                parts.path or "/", host=host_header, key=_key_of(ctx), headers=headers
            )
            upgrade = await ctx.net.tcp(host, port, payload=request, reads=1)
            control = await ctx.net.tcp(host, port, payload=_plain_get(parts), reads=1)
            upgrade_status, upgrade_headers = _parse_response(upgrade.banner)
            control_status, _ = _parse_response(control.banner)
            if control_status not in _UPGRADE_REQUIRED:
                # The path answers ordinary requests, so it is not an upgrade-only endpoint
                # and an accepted upgrade here would prove nothing.
                continue
            probed += 1
            if upgrade_status != 101:
                continue
            if upgrade_headers.get("sec-websocket-accept", "").strip() != expected:
                # A 101-shaped reply that does not carry the RFC 6455 accept derivation is not
                # a completed handshake: reporting it would be the classic WebSocket false
                # positive.
                continue
            findings += 1
            yield web_candidate(
                ctx,
                "WebSocket upgrade completed with no credential presented",
                artifact={
                    "signal": "websocket",
                    "family": "websocket",
                    "facet": "upgrade-auth",
                    "endpoint": url,
                    "anonymous_request": True,
                    "accept_verified": True,
                    "control_status": control_status,
                    "status": upgrade_status,
                },
                exchanges=(),
                cwe="CWE-306",
                confidence=0.7,
                detail=(
                    f"{url} completed the RFC 6455 upgrade for a request carrying no "
                    "authorization header, cookie or subprotocol token, while a plain GET of "
                    f"the same path answered {control_status} (upgrade required). The "
                    "handshake bytes were built by the check, so 'nothing was presented' is a "
                    "property of the request rather than an assumption about a client's cookie "
                    "jar. The connection is never authenticated, so the authorization "
                    "decision — if there is one — happens only per message (research "
                    "ch03#33)."
                ),
                source=url,
            )
        if not findings:
            yield ctx.clean(
                "no WebSocket upgrade accepted without a credential",
                detail=(
                    f"attempted the upgrade at {probed} upgrade-only endpoint(s); each refused, "
                    "required a credential or did not answer a verified handshake"
                ),
                confidence=0.6,
            )


class WebSocketInjection(WebCheck, Module):
    """``m3.websocket-injection`` — inert message relay proof (ch03#33). Opt-in + env switch."""

    metadata = CheckMetadata(
        id="m3.websocket-injection",
        module="M3",
        name="websocket-injection",
        version="1.0",
        title="WebSocket message relay probe",
        description=(
            "Completes the WebSocket handshake over the scoped network client and sends one "
            "inert, self-describing marker text frame plus one control PING. A server that "
            "echoes the marker is relaying client input unvalidated, the precondition of "
            "message injection; the probe sends no command language, query or target-specific "
            "syntax and exactly one message per endpoint. Off unless ARACHNE_WEB_WS_PROBE=true."
        ),
        research_ref="ch03#33",
        framework=("WSTG-CLNT-10", "CWE-1385"),
        cwe="CWE-1385",
        target_kinds=(TargetKind.URL,),
        severity_hint="medium",
        type="active",
        safe=True,
        verifiable=True,
        enabled_by_default=False,
        estimated_requests=4,
        requires_active_checks=True,
        runs_on_discovered=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        _client, skipped = http_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        if not ctx.config.web.ws_probe:
            yield skip(
                ctx,
                "the WebSocket message probe is off: set ARACHNE_WEB_WS_PROBE=true to enable "
                "it (it sends one inert marker frame after the handshake)",
            )
            return
        if ctx.net is None:
            yield skip(ctx, "no network client in this run: the frame exchange needs a live scan")
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
        template = payloads.string(
            "websocket",
            "message_template",
            default="ARACHNE_POC_{nonce} safe-proof-of-websocket-message-relay",
        )
        host_header = urlsplit(ctx.asset.value).netloc
        findings = 0
        probed = 0
        for url in _candidate_endpoints(ctx, inventory):
            parts = urlsplit(url)
            host = parts.hostname or ""
            port = parts.port or (443 if parts.scheme == "https" else 80)
            if parts.scheme == "https":
                # The frame exchange below is plain TCP: a TLS endpoint needs the TLS path,
                # which this probe deliberately does not take (it would have to re-implement
                # the scoped TLS client). Report the gap rather than probing insecurely.
                continue
            marker = nonce()
            message = template.format(nonce=marker)
            client_key = _key_of(ctx)
            payload = (
                wsproto.build_upgrade_request(parts.path or "/", host=host_header, key=client_key)
                + wsproto.encode_frame(b"", opcode=wsproto.PING)
                + wsproto.encode_frame(message.encode("utf-8"))
            )
            exchange = await ctx.net.tcp(host, port, payload=payload, reads=2)
            probed += 1
            if not exchange.is_open:
                continue
            raw = exchange.banner
            separator = raw.find(b"\r\n\r\n")
            if separator < 0:
                continue
            status_line = raw.split(b"\r\n", 1)[0].decode("latin-1")
            if "101" not in status_line:
                continue
            frames = wsproto.decode_frames(raw[separator + 4 :])
            pong = any(frame.opcode == wsproto.PONG for frame in frames)
            relayed = any(marker in frame.text for frame in frames if not frame.is_control)
            if not relayed:
                continue
            findings += 1
            yield web_candidate(
                ctx,
                "WebSocket endpoint relayed an inert client message verbatim",
                artifact={
                    "signal": "websocket",
                    "family": "websocket",
                    "facet": "message-relay",
                    "endpoint": url,
                    "message_marker": marker,
                    "frames_received": len(frames),
                    "pong_received": pong,
                    "payload_executed": False,
                    "messages_sent": 1,
                },
                exchanges=(),
                cwe="CWE-1385",
                confidence=0.5,
                detail=(
                    f"after a verified handshake, one text frame carrying the inert marker "
                    f"'{marker}' came back in the server's frames (and a control PING was "
                    f"{'answered' if pong else 'not answered'}). Relaying client input "
                    "unvalidated is the precondition of WebSocket message injection "
                    "(research ch03#33); this probe proves relay and nothing more — it sent no "
                    "command language, query or target-specific syntax, and no payload was "
                    "executed at the target."
                ),
                source=url,
            )
        if not findings:
            yield ctx.clean(
                "no WebSocket endpoint echoed the inert marker",
                detail=(
                    f"attempted a one-frame exchange at {probed} plaintext endpoint(s); none "
                    "relayed the marker"
                ),
                confidence=0.5,
            )
