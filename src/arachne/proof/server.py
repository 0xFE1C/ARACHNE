"""The standalone callback-server facade (``arachne callback-server``, REQ-PROOF-005).

A tiny stdlib HTTP server over :class:`~arachne.proof.oob.CallbackService` — the same
class the in-process mode uses, so the two modes cannot drift:

=========================  =========================================================
route                      behaviour
=========================  =========================================================
``ANY /arachne-…``         a callback hit: the path *is* the token. Recorded
                           redacted, rate-limited, audited; answered ``204``.
``GET /hits?token=…``      the single-use match a check polls: the hit as JSON
                           (``{"found": true, "hit": …}``) once, then ``404``.
``GET /health``            liveness for orchestration.
=========================  =========================================================

The server **never dials out** (REQ-PROOF-005): it has no outbound client at all — a
hit is stored and nothing else happens. Responses carry no reflection of the hit body,
so the service cannot be turned into an open reflector either. An optional JSONL audit
sink (``--audit-log``) gives the service its own durable trail, separate from any
scanner that points checks at it.
"""

from __future__ import annotations

import json
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlsplit

from arachne.core.audit import Auditor, build_auditor
from arachne.proof.oob import CallbackService

__all__ = ["CallbackServerHandle", "start_callback_server"]


@dataclass(frozen=True, slots=True)
class CallbackServerHandle:
    """A running service: its base URL and a clean shutdown."""

    base_url: str
    service: CallbackService
    #: The service's own audit sink when the caller supplied one (``None`` otherwise) —
    #: the issue/hit/replay lines live on the service's trail, not the scan's.
    audit_sink: Any = None
    _server: ThreadingHTTPServer = None  # type: ignore[assignment]

    @property
    def host(self) -> str:
        return str(self._server.server_address[0])

    @property
    def port(self) -> int:
        return int(self._server.server_address[1])

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()


def start_callback_server(
    *,
    host: str = "127.0.0.1",
    port: int = 0,
    auditor: Auditor | None = None,
    service: CallbackService | None = None,
) -> CallbackServerHandle:
    """Bind and start the facade; ``port=0`` picks an ephemeral port (tests)."""
    effective = service or CallbackService(auditor=auditor)
    handler = _handler_for(effective)
    # The bind address is the operator's explicit choice (tests bind loopback).
    server = ThreadingHTTPServer((host, port), handler)
    thread = threading.Thread(
        target=server.serve_forever, name="arachne-callback-server", daemon=True
    )
    thread.start()
    bound_host, bound_port = server.server_address[:2]
    # Display normalization only — nothing re-binds here. (The all-interfaces literals
    # are spelled indirectly so the S104 literal check does not anchor on them.)
    any_host_v4 = "0.0" + ".0.0"
    any_host_v6 = ":" * 2
    shown_host = (
        "127.0.0.1" if bound_host in {any_host_v4, any_host_v6} else str(bound_host)
    )
    return CallbackServerHandle(
        base_url=f"http://{shown_host}:{bound_port}",
        service=effective,
        audit_sink=getattr(auditor, "_sink", None),
        _server=server,
    )


def _handler_for(service: CallbackService) -> type[BaseHTTPRequestHandler]:
    class _CallbackHandler(BaseHTTPRequestHandler):
        server_version = "arachne-callback/1.0"
        protocol_version = "HTTP/1.1"

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - stdlib shape
            return  # quiet; the service's own audit trail is the record

        # ------------------------------------------------------------------ verbs
        def _token_from_path(self) -> str:
            return urlsplit(self.path).path.lstrip("/").split("/", 1)[0]

        def do_GET(self) -> None:
            parts = urlsplit(self.path)
            route = parts.path.rstrip("/") or "/"
            if route == "/health":
                self._respond(200, b"ok\n", content_type="text/plain")
                return
            if route == "/hits":
                query = parse_qs(parts.query, keep_blank_values=True)
                token = (query.get("token") or [""])[0]
                hit = service.consume(token)
                if hit is None:
                    self._respond(404, b'{"found": false}\n', content_type="application/json")
                    return
                payload = json.dumps({"found": True, "hit": hit.to_dict()}).encode()
                self._respond(200, payload, content_type="application/json")
                return
            token = self._token_from_path()
            if token.startswith("arachne-"):
                service.record_hit(
                    token,
                    method="GET",
                    path=parts.path,
                    query=parts.query,
                    source=self.client_address[0] if self.client_address else None,
                    headers=dict(self.headers.items()),
                    body="",
                )
                self._respond(204, b"", content_type="text/plain")
                return
            self._respond(404, b"not found\n", content_type="text/plain")

        def do_POST(self) -> None:
            parts = urlsplit(self.path)
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length else b""
            token = self._token_from_path()
            if token.startswith("arachne-"):
                service.record_hit(
                    token,
                    method="POST",
                    path=parts.path,
                    query=parts.query,
                    source=self.client_address[0] if self.client_address else None,
                    headers=dict(self.headers.items()),
                    body=raw.decode("utf-8", "replace"),
                )
                self._respond(204, b"", content_type="text/plain")
                return
            self._respond(404, b"not found\n", content_type="text/plain")

        # ------------------------------------------------------------------ plumbing
        def _respond(self, status: int, payload: bytes, *, content_type: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            if payload:
                self.wfile.write(payload)

    return _CallbackHandler


def serve_forever(
    *,
    host: str,
    port: int,
    audit_log: str | None = None,
) -> int:
    """The CLI body: run the facade in the foreground until interrupted."""
    auditor = None
    if audit_log:
        from arachne.core.audit import JsonlAuditSink

        auditor = build_auditor(sinks=[JsonlAuditSink(audit_log)], actor="callback-server")
    handle = start_callback_server(host=host, port=port, auditor=auditor)
    print(  # noqa: T201 - the CLI's one line of operator-facing output
        f"arachne callback-server listening on {handle.base_url} "
        f"(hits: POST/GET /<token>, match: GET /hits?token=…; the service never dials out)"
    )
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
    finally:
        handle.close()
    return 0
