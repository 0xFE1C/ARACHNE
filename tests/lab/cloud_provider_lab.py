"""A loopback DigitalOcean API fixture for the read-only posture check (WP-12, REQ-DET-017).

Two account prefixes live on one server: ``/risky`` carries the four posture conditions the
check looks for, ``/safe`` carries the hardened counterparts (the decoy case). Every request
must present the bearer token, so the test also proves the credential path is real and that a
missing token is refused rather than treated as an empty account.

The fixture records every request line, which is what the operation-allowlist test asserts
against: the check may only issue the GET operations declared in
:data:`arachne.modules.cloud_providers.CLOUD_PROVIDER_MATRIX`.
"""

from __future__ import annotations

import json
import threading
import urllib.parse
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

__all__ = [
    "DIGITALOCEAN_TOKEN",
    "DigitalOceanLab",
    "start_digitalocean_lab",
]

#: The bearer token the fixture accepts. It is a lab value, never a real credential.
DIGITALOCEAN_TOKEN = "do-lab-token-not-a-real-credential"

RISKY: dict[str, Any] = {
    "/v2/droplets": {
        "droplets": [
            {"id": 1, "name": "web-1", "region": {"slug": "nyc1"}},
            {"id": 2, "name": "worker-1", "region": {"slug": "nyc1"}},
        ]
    },
    "/v2/databases": {
        "databases": [
            {
                "id": "db-1",
                "name": "orders",
                "engine": "pg",
                "private_network_uuid": None,
                "trusted_sources": [],
            }
        ]
    },
    "/v2/load_balancers": {
        "load_balancers": [
            {
                "id": "lb-1",
                "name": "web",
                "redirect_http_to_https": False,
                "forwarding_rules": [
                    {
                        "entry_protocol": "http",
                        "target_protocol": "http",
                        "entry_port": 80,
                        "target_port": 8080,
                    }
                ],
            }
        ]
    },
    "/v2/firewalls": {
        "firewalls": [
            {
                "id": "fw-1",
                "name": "ssh-open",
                "inbound_rules": [
                    {
                        "protocol": "tcp",
                        "ports": "22",
                        "sources": {"addresses": ["0.0.0.0/0"], "droplet_ids": []},
                    }
                ],
            }
        ]
    },
}

SAFE: dict[str, Any] = {
    "/v2/droplets": {"droplets": [{"id": 3, "name": "web-safe", "region": {"slug": "nyc3"}}]},
    "/v2/databases": {
        "databases": [
            {
                "id": "db-2",
                "name": "orders-safe",
                "engine": "pg",
                "private_network_uuid": "b8f0a4c0-private",
                "trusted_sources": ["10.0.0.0/8"],
            }
        ]
    },
    "/v2/load_balancers": {
        "load_balancers": [
            {
                "id": "lb-2",
                "name": "web-safe",
                "redirect_http_to_https": True,
                "forwarding_rules": [
                    {"entry_protocol": "https", "target_protocol": "http", "entry_port": 443}
                ],
            }
        ]
    },
    "/v2/firewalls": {
        "firewalls": [
            {
                "id": "fw-2",
                "name": "ssh-restricted",
                "inbound_rules": [
                    {
                        "protocol": "tcp",
                        "ports": "22",
                        "sources": {"addresses": ["10.0.0.0/8"]},
                    }
                ],
            }
        ]
    },
}


@dataclass
class DigitalOceanLab:
    """A running fixture: its loopback base, the two account prefixes and its requests."""

    port: int = 0
    base_url: str = ""
    requests: list[str] = field(default_factory=list)

    def endpoint(self, account: str) -> str:
        """``endpoint:<base>`` value for one account prefix (``risky`` or ``safe``)."""
        return f"{self.base_url.rstrip('/')}/{account.lstrip('/')}"


class _Handler(BaseHTTPRequestHandler):
    server_version = "arachne-do-lab/1.0"
    protocol_version = "HTTP/1.1"
    # TCP_NODELAY: the same Nagle/delayed-ACK stall as tests/lab/web_lab.py (42 ms → 0.8 ms per
    # request on loopback).
    disable_nagle_algorithm = True
    lab: DigitalOceanLab

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - stdlib signature
        return

    def _respond(self, status: int, body: str) -> None:
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def do_GET(self) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        self.lab.requests.append(f"GET {parsed.path}")
        if self.headers.get("Authorization") != f"Bearer {DIGITALOCEAN_TOKEN}":
            self._respond(401, json.dumps({"id": "unauthorized", "message": "not authenticated"}))
            return
        for account, data in (("risky", RISKY), ("safe", SAFE)):
            prefix = f"/{account}"
            if parsed.path == prefix or parsed.path.startswith(prefix + "/"):
                resource = parsed.path[len(prefix) :]
                if resource in data:
                    self._respond(200, json.dumps(data[resource]))
                    return
        self._respond(404, json.dumps({"id": "not_found", "message": "no such route"}))

    def do_POST(self) -> None:
        self.lab.requests.append(f"POST {urllib.parse.urlsplit(self.path).path}")
        self._respond(405, json.dumps({"id": "method_not_allowed"}))

    def do_PUT(self) -> None:
        self.do_POST()

    def do_PATCH(self) -> None:
        self.do_POST()

    def do_DELETE(self) -> None:
        self.do_POST()


@contextmanager
def start_digitalocean_lab() -> Iterator[DigitalOceanLab]:
    """Start the fixture on loopback and yield its handle; tear it down on exit."""
    lab = DigitalOceanLab()
    handler = type("_BoundDigitalOceanHandler", (_Handler,), {"lab": lab})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    server.daemon_threads = True
    port = server.server_address[1]
    lab.port = port
    lab.base_url = f"http://127.0.0.1:{port}/"
    thread = threading.Thread(
        target=server.serve_forever, args=(0.05,), name="arachne-do-lab", daemon=True
    )
    thread.start()
    try:
        yield lab
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
