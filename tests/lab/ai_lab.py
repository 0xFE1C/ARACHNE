"""The AI-era serving lab (WP-34, REQ-DET-027).

The requirement's decoy is "authenticated or network-restricted deployments", and this fixture
implements exactly that as a *mode* over one route table:

``bare``
    the positive: every covered service answers its own status/index document, 200, no
    authentication, on the lab's single origin.
``hardened``
    **the requirement's decoy**: the same routes answer ``401`` with a ``WWW-Authenticate``
    challenge, which is what an authenticated deployment looks like to an unauthenticated
    caller.
``restricted``
    the network-restricted half of the decoy: every route answers ``403``, the shape a fronting
    proxy's allowlist produces.
``soft404``
    the pitfall's own trap: every route answers ``200`` with a short body that echoes the
    requested path, so a check whose marker is a substring of the path it probes fires here.

A lab may serve only one service (``only="ollama"``), which is how the acceptance test measures
the cross-service decoys: every check is run against every service's own installation, and only
the checks covering that service may report anything.

Nothing in this file writes, invokes or executes anything: every route is a static document, the
hardened answers are a challenge, and no route exists for any inference operation (there is no
``/generate``, ``/completions`` or ``/embeddings`` path to probe in the first place).
"""

from __future__ import annotations

import json
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

from arachne.modules.m6.ai_surface import AI_SURFACE_CHECKS, SERVICE_OF_CHECK

__all__ = [
    "MODES",
    "ROUTES",
    "SERVICES",
    "AiLab",
    "published_paths",
    "service_routes",
    "start_ai_lab",
]

#: The three decoy-shaped modes beside the positive.
MODES: tuple[str, ...] = ("bare", "hardened", "restricted", "soft404")

#: The services the family covers, in the family's own order.
SERVICES: tuple[str, ...] = tuple(dict.fromkeys(SERVICE_OF_CHECK.values()))

#: One route table per service: ``{path: (status, body, content_type)}``. Every body is the
#: product's own document shape, so a check's marker is a real field rather than a word the
#: fixture was written to contain.
ROUTES: Mapping[str, Mapping[str, tuple[int, str, str]]] = {
    "ollama": {
        "/api/tags": (
            200,
            json.dumps(
                {
                    "models": [
                        {
                            "name": "llama3:8b",
                            "model": "llama3:8b",
                            "size": 4661224676,
                            "digest": (
                                "sha256:365c0bd3c000a25d28ddbf732fe1c6add4bfb03d2d51fea0d2b0ecef4b2b1a1f"
                            ),
                        }
                    ]
                }
            ),
            "application/json",
        ),
        "/api/version": (200, json.dumps({"version": "0.1.32"}), "application/json"),
    },
    "vllm": {
        "/v1/models": (
            200,
            json.dumps(
                {
                    "object": "list",
                    "data": [
                        {
                            "id": "meta-llama/Meta-Llama-3-8B-Instruct",
                            "object": "model",
                            "created": 1710000000,
                            "owned_by": "vllm",
                        }
                    ],
                }
            ),
            "application/json",
        )
    },
    "triton": {
        "/v2": (
            200,
            json.dumps({"name": "triton", "version": "2.40.0", "extensions": ["http", "grpc"]}),
            "application/json",
        ),
        "/v2/repository/index": (
            200,
            json.dumps([{"name": "resnet50", "version": 1, "state": "READY", "reason": ""}]),
            "application/json",
        ),
    },
    "lmstudio": {
        "/api/v0/models": (
            200,
            json.dumps(
                {
                    "data": [
                        {
                            "id": "lmstudio-community/Meta-Llama-3-8B-Instruct-GGUF",
                            "object": "model",
                            "state": "loaded",
                            "max_context_length": 8192,
                        }
                    ]
                }
            ),
            "application/json",
        )
    },
    "qdrant": {
        "/collections": (
            200,
            json.dumps(
                {
                    "result": {"collections": [{"name": "documents"}, {"name": "faq"}]},
                    "status": "ok",
                    "time": 0.0001,
                }
            ),
            "application/json",
        ),
        "/cluster": (
            200,
            json.dumps(
                {
                    "result": {
                        "status": "enabled",
                        "peer_id": 1,
                        "peers": {"1": {"uri": "http://10.0.0.1:6335"}},
                    },
                    "status": "ok",
                }
            ),
            "application/json",
        ),
    },
    "weaviate": {
        "/v1/meta": (
            200,
            json.dumps(
                {
                    "version": "1.24.1",
                    "hostname": "http://[::]:8080",
                    "modules": {"text2vec-openai": {"documentationHref": "https://example.test"}},
                }
            ),
            "application/json",
        ),
        "/v1/schema": (
            200,
            json.dumps(
                {
                    "classes": [
                        {
                            "class": "Document",
                            "vectorizer": "text2vec-openai",
                            "properties": [{"name": "content", "dataType": ["text"]}],
                        }
                    ]
                }
            ),
            "application/json",
        ),
    },
    "chroma": {
        "/api/v1/heartbeat": (
            200,
            json.dumps({"nanosecond heartbeat": 1731000000000000000}),
            "application/json",
        ),
        "/api/v2/tenants": (
            200,
            json.dumps([{"name": "default_tenant"}]),
            "application/json",
        ),
    },
    "flowise": {
        "/api/v1/chatflows": (
            200,
            json.dumps(
                [
                    {
                        "id": "8f2a",
                        "name": "support-agent",
                        "type": "CHATFLOW",
                        "flowData": json.dumps({"nodes": [{"id": "llm", "type": "chatOpenAI"}]}),
                    }
                ]
            ),
            "application/json",
        )
    },
    "n8n": {
        "/rest/workflows": (
            200,
            json.dumps(
                {
                    "data": [
                        {
                            "id": "1",
                            "name": "Nightly sync",
                            "active": True,
                            "nodes": [{"name": "Cron", "type": "n8n-nodes-base.cron"}],
                        }
                    ]
                }
            ),
            "application/json",
        )
    },
    "dify": {
        "/api/v1/parameters": (
            200,
            json.dumps(
                {
                    "opening_statement": "Hello, how can I help?",
                    "system_parameters": {"file_size_limit": 15},
                    "user_input_form": [{"text-input": {"variable": "query"}}],
                }
            ),
            "application/json",
        )
    },
    "airflow": {
        "/api/v1/dags": (
            200,
            json.dumps(
                {
                    "dags": [
                        {
                            "dag_id": "etl",
                            "is_paused": False,
                            "schedule_interval": "@daily",
                            "tags": [{"name": "prod"}],
                        }
                    ],
                    "total_entries": 1,
                }
            ),
            "application/json",
        ),
        "/api/v1/config": (
            200,
            json.dumps(
                {
                    "sections": [
                        {
                            "name": "core",
                            "options": [{"key": "executor", "value": "LocalExecutor"}],
                        }
                    ]
                }
            ),
            "application/json",
        ),
    },
    "langflow": {
        "/api/v1/flows/": (
            200,
            json.dumps({"flows": [{"id": "f1", "name": "rag-agent", "data": {"nodes": []}}]}),
            "application/json",
        )
    },
    "jupyter": {
        "/api/status": (200, json.dumps({"connections": 0, "kernels": 0}), "application/json"),
        "/api/kernels": (
            200,
            json.dumps(
                [
                    {
                        "id": "k1",
                        "name": "python3",
                        "execution_state": "idle",
                        "last_activity": "2026-01-01T00:00:00Z",
                    }
                ]
            ),
            "application/json",
        ),
    },
    "zeppelin": {
        "/api/notebook": (
            200,
            json.dumps(
                {"status": "OK", "body": [{"id": "2ABC", "name": "analysis", "paragraphs": []}]}
            ),
            "application/json",
        )
    },
}

#: The challenge a hardened installation answers every published path with.
_CHALLENGE_BODY = (
    "<!DOCTYPE html><html><head><title>401 Unauthorized</title></head><body>"
    "<h1>Unauthorized</h1></body></html>"
)
#: The body a network-restricted installation answers with (a fronting proxy's refusal).
_RESTRICTED_BODY = "403 Forbidden: this path is not permitted from your network\n"


def service_routes(service: str) -> Mapping[str, tuple[int, str, str]]:
    """The routes one service publishes."""
    return ROUTES[service]


def published_paths(service: str) -> tuple[str, ...]:
    """The paths one service's checks read (the acceptance test's control table)."""
    return tuple(ROUTES[service])


@dataclass
class AiLab:
    """A running AI-era lab: its base URL, the services it serves and what it answered."""

    base_url: str
    port: int
    mode: str
    only: str | None
    #: Every request line the lab answered (``GET /path``), in order.
    requests: list[str] = field(default_factory=list)

    @property
    def host(self) -> str:
        return f"127.0.0.1:{self.port}"

    def served_services(self) -> tuple[str, ...]:
        return (self.only,) if self.only else SERVICES


class _Handler(BaseHTTPRequestHandler):
    """The lab: a route table over one origin, with the mode applied to every answer."""

    server_version = "arachne-ai-lab/1.0"
    protocol_version = "HTTP/1.1"
    disable_nagle_algorithm = True
    lab: AiLab  # injected by the factory below

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - stdlib signature
        return  # quiet: the scanner's audit log is the record

    def _respond(self, status: int, body: str, content_type: str, **headers: str) -> None:
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        for name, value in headers.items():
            self.send_header(name.replace("_", "-"), value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def do_GET(self) -> None:
        self._serve()

    def do_HEAD(self) -> None:
        self._serve()

    def _serve(self) -> None:
        path = self.path.split("?", 1)[0]
        self.lab.requests.append(f"{self.command} {path}")
        routes = {_normalize(route): entry for route, entry in _routes_for(self.lab).items()}
        entry = routes.get(_normalize(path))
        if entry is None:
            self._respond(404, f"Not found: {path}\n", "text/plain")
            return
        if self.lab.mode == "hardened":
            self._respond(
                401,
                _CHALLENGE_BODY,
                "text/html",
                www_authenticate='Basic realm="management"',
            )
            return
        if self.lab.mode == "restricted":
            self._respond(403, _RESTRICTED_BODY, "text/plain")
            return
        if self.lab.mode == "soft404":
            self._respond(200, f"Not found: {path}\n", "text/plain")
            return
        status, body, content_type = entry
        self._respond(status, body, content_type)


def _normalize(path: str) -> str:
    """A path with its trailing slash removed (``/api/v1/flows/`` → ``/api/v1/flows``)."""
    stripped = path.rstrip("/")
    return stripped or "/"


def _routes_for(lab: AiLab) -> Mapping[str, tuple[int, str, str]]:
    merged: dict[str, tuple[int, str, str]] = {}
    for service in lab.served_services():
        merged.update(ROUTES[service])
    return merged


@contextmanager
def start_ai_lab(*, mode: str = "bare", only: str | None = None) -> Iterator[AiLab]:
    """Start the lab on an ephemeral loopback port and tear it down on exit."""
    if mode not in MODES:
        raise ValueError(f"unknown mode {mode!r}; expected one of {MODES}")
    if only is not None and only not in SERVICES:
        raise ValueError(f"unknown service {only!r}; expected one of {SERVICES}")
    lab = AiLab(base_url="", port=0, mode=mode, only=only)
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    server.daemon_threads = True
    _Handler.lab = lab
    lab.port = int(server.server_address[1])
    lab.base_url = f"http://127.0.0.1:{lab.port}"
    import threading

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield lab
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


#: The checks that cover one service (used by the acceptance test's own grouping).
def checks_for(service: str) -> tuple[Any, ...]:
    return tuple(
        check for check in AI_SURFACE_CHECKS if SERVICE_OF_CHECK[check.metadata.id] == service
    )
