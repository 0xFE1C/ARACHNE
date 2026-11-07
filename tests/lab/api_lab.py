"""The API and modern-web lab: six surfaces, each served in three modes (WP-28, REQ-DET-021).

The requirement's acceptance needs a **positive fixture** and a **decoy** per surface, and names
the decoy: "decoys are conformant deployments that publish their documentation deliberately
behind authentication". This module serves each of the six surfaces the family covers from its
own origin, in three modes:

``vulnerable``
    A deployment publishing exactly the artefacts the family's checks establish: the OpenAPI and
    Swagger documents, the Swagger UI and ReDoc interfaces, the resource index and a declared
    operation that answers anonymously; a GraphQL endpoint with introspection, suggestions, an
    IDE and a mutation inventory; the browser-facing gRPC method and its CORS preflight; three
    WebSocket routes, each trusting one *different* wrong origin; a Netlify function, a Vercel
    function route, a Cloud Functions invocation, an OpenFaaS gateway and a published bundle
    source map; and a CORS policy that reflects a sibling subdomain, a suffix-spoofed origin and
    a wide-open preflight.
``production``
    The conformant deployment. Every path the family probes answers the installation's own
    refusal — ``401`` with the deployment's own challenge for the documentation surface (the
    requirement's decoy: documentation published *deliberately, behind authentication*),
    ``403`` for the WebSocket routes whose origins are validated, and a conformant CORS policy
    that names only the site's own origin and authorizes only ``GET`` and ``content-type``. The
    production homepage names the platform and carries none of its markup, which is what makes
    it a fair trap for the marker guard.
``waf``
    The production deployment behind a web application firewall: the homepage is the production
    one, and every other path — document, IDE, handshake, function route, source map and CORS
    endpoint alike — is answered with the WAF's ``403`` block page, which *echoes the requested
    path* and *names the platform*. That is the "block page that contains the payload" archetype
    of the decoy catalogue (``docs/plugin-developer-guide.md`` §2.1): a check that matched on
    body content, or on a status code, rather than on the artefact's own structure plus a
    distinct answer, would fire on it.

Three of the surfaces carry an internal trap of their own, so a check that over-claims is caught
by the fixture rather than by a reviewer:

* the OpenAPI surface declares ``/api/orders`` as well as ``/api/users``, and only the second
  answers anonymously — the ``401`` on the first is the control for the unauthenticated
  invocation check;
* the three WebSocket routes each trust exactly one wrong origin, so each of the three
  origin checks fires on its own route and is refused by the other two;
* the GraphQL surface serves introspection to an anonymous caller but refuses the same query
  when the request carries a session cookie, so a check that "found" the schema list by
  ignoring the answer's shape is not what passes here.

**No credential values and no state change.** No route authenticates anything, no route accepts
a body, and no route accepts anything but ``GET``/``HEAD``/``OPTIONS``. Every fixture body
declares identifiers and never a secret. No GraphQL mutation is implemented at all: the fixture
cannot be made to change state even by a caller that tries.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import threading
import urllib.parse
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

__all__ = ["MODES", "SURFACES", "ApiLab", "start_api_lab"]

#: The RFC 6455 handshake GUID. RFC 6455 §1.3 mandates that ``Sec-WebSocket-Accept`` be the
#: base64 SHA-1 of the client key plus this constant, so SHA-1 here is the protocol's own
#: definition and protects nothing — it is a handshake nonce, not a signature. (A scanner
#: fixture, not a service: no data is protected by it.)
_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

#: The six surfaces the family covers (REQ-DET-021).
SURFACES: tuple[str, ...] = (
    "openapi",
    "graphql",
    "grpc",
    "websocket",
    "serverless",
    "cors",
)

#: The modes a lab can serve. ``vulnerable`` is the positive fixture; the other two are decoys.
MODES: tuple[str, ...] = ("vulnerable", "production", "waf")

#: The name each fixture publishes about itself.
_SURFACE_NAMES: Mapping[str, str] = {
    "openapi": "OpenAPI",
    "graphql": "GraphQL",
    "grpc": "gRPC-Web",
    "websocket": "WebSocket",
    "serverless": "Serverless edge platform",
    "cors": "Cross-origin API",
}

#: A not-found page that names no platform and carries no marker (every mode's own 404).
_NOT_FOUND = (
    "<html><head><title>Not found</title></head><body><h1>Not found</h1>"
    "<p>The requested resource was not found on this server.</p></body></html>"
)

#: The refusal a conformant deployment answers for a documentation path: published
#: deliberately, behind authentication (the requirement's own decoy).
_AUTH_REFUSAL = (
    "<html><head><title>401 Unauthorized</title></head><body>"
    "<h1>HTTP Status 401 - Unauthorized</h1>"
    "<p>Documentation for this deployment is published behind authentication.</p>"
    "</body></html>"
)

#: The WAF block page. It *does* name the platform and echo the requested path — that is the
#: trap — and it carries none of the platforms' own markup.
_WAF_BLOCK = (
    "<!DOCTYPE html><html><head><title>Request blocked</title></head><body>"
    "<h1>Request blocked</h1>"
    "<p>Your request to <code>{path}</code> was blocked by the web application firewall. "
    "This site publishes {surface} documentation; API, debugging and function routes are "
    "protected.</p>"
    "<p>If you believe this is an error, contact the site operator and quote reference "
    "{nonce}.</p></body></html>"
)


@dataclass
class ApiLab:
    """A running fixture: which surface, which mode, its origin and what it answered."""

    surface: str
    mode: str
    base_url: str = ""
    port: int = 0
    requests: list[str] = field(default_factory=list)

    @property
    def origin(self) -> str:
        return self.base_url.rstrip("/")

    @property
    def host(self) -> str:
        return f"127.0.0.1:{self.port}"

    @property
    def hostname(self) -> str:
        """The bare host name, as a check derives it from the asset's origin."""
        return "127.0.0.1"


@dataclass(frozen=True, slots=True)
class _Response:
    status: int
    body: str
    content_type: str = "text/html; charset=utf-8"
    headers: tuple[tuple[str, str], ...] = ()


def _not_found() -> _Response:
    return _Response(404, _NOT_FOUND)


def _json_response(document: object, *, status: int = 200) -> _Response:
    return _Response(status, json.dumps(document), "application/json; charset=utf-8")


def _unauthorized() -> _Response:
    return _Response(
        401,
        _AUTH_REFUSAL,
        headers=(("WWW-Authenticate", 'Basic realm="api-docs"'),),
    )


def _homepage(surface: str, lab: ApiLab) -> str:
    """A stock homepage that names the surface and links its own artefacts."""
    links = {
        "openapi": ["/openapi.json", "/swagger.json", "/swagger-ui/index.html", "/docs/"],
        "graphql": ["/graphql", "/graphiql"],
        "grpc": ["/grpc.health.v1.Health/Check"],
        "websocket": ["/ws", "/socket.io/", "/realtime"],
        "serverless": ["/.netlify/functions/hello", "/api/hello", "/system/functions"],
        "cors": ["/api/config"],
    }[surface]
    anchors = "".join(f'<li><a href="{href}">{href}</a></li>' for href in links)
    return (
        '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8" />'
        f"<title>Arachne API Lab — {_SURFACE_NAMES[surface]}</title></head><body>"
        "<h1>Arachne API and Modern Web Lab</h1>"
        f"<p>{_SURFACE_NAMES[surface]} surface served here in its deployed configuration.</p>"
        f"<ul>{anchors}</ul></body></html>"
    )


def _production_homepage(surface: str) -> str:
    """The production homepage: the site itself, and nothing a scanner can inventory."""
    return (
        '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8" />'
        "<title>Arachne API Lab — site</title></head><body>"
        "<h1>Arachne API and Modern Web Lab</h1>"
        f"<p>{_SURFACE_NAMES[surface]} is served here in its production configuration and "
        "publishes nothing else.</p></body></html>"
    )


# --------------------------------------------------------------------------- OpenAPI / Swagger
_OPENAPI_V3: Mapping[str, object] = {
    "openapi": "3.0.3",
    "info": {"title": "Arachne Lab API", "version": "1.0.0"},
    "servers": [{"url": "/"}],
    "paths": {
        "/api/users": {
            "get": {"summary": "List users", "responses": {"200": {"description": "ok"}}}
        },
        "/api/orders": {
            "get": {"summary": "List orders", "responses": {"401": {"description": "auth"}}}
        },
    },
}

_SWAGGER_V2: Mapping[str, object] = {
    "swagger": "2.0",
    "info": {"title": "Arachne Lab API", "version": "1.0.0"},
    "basePath": "/",
    "paths": {"/v1/items": {"get": {"summary": "List items", "responses": {"200": {}}}}},
}

_SWAGGER_UI = (
    '<!DOCTYPE html><html lang="en"><head><title>Swagger UI</title>'
    '<link rel="stylesheet" href="/swagger-ui/swagger-ui.css" /></head><body>'
    '<div id="swagger-ui"></div>'
    '<script src="/swagger-ui/swagger-ui-bundle.js"></script>'
    "<script>window.onload = function() { SwaggerUIBundle({url: '/openapi.json'}); };</script>"
    "</body></html>"
)

_REDOC = (
    '<!DOCTYPE html><html lang="en"><head><title>ReDoc — Arachne Lab API</title>'
    '<script src="/redoc/redoc.standalone.js"></script></head><body>'
    '<redoc spec-url="/openapi.json"></redoc>'
    "<script>Redoc.init('/openapi.json');</script>"
    "</body></html>"
)


def _openapi(path: str, query: Mapping[str, list[str]]) -> _Response:
    if path in {"/openapi.json", "/v3/api-docs", "/api-docs"}:
        return _json_response(_OPENAPI_V3)
    if path in {"/swagger.json", "/v2/api-docs", "/swagger/v1/swagger.json"}:
        return _json_response(_SWAGGER_V2)
    if path in {"/swagger-ui/index.html", "/swagger-ui.html"}:
        return _Response(200, _SWAGGER_UI)
    if path in {"/docs", "/redoc", "/redoc.html"}:
        return _Response(200, _REDOC)
    if path == "/swagger-resources":
        return _json_response(
            [{"name": "default", "url": "/v3/api-docs", "location": "/v3/api-docs"}]
        )
    if path == "/api/users":
        # The operation the document declares, answering an anonymous client: the finding.
        return _json_response({"users": [{"id": 1, "name": "demo"}]})
    if path == "/api/orders":
        # Also declared, but it requires authentication: the control for the invocation check.
        return _unauthorized()
    return _not_found()


# --------------------------------------------------------------------------- GraphQL
_GRAPHIQL = (
    '<!DOCTYPE html><html lang="en"><head><title>GraphiQL</title>'
    '<link rel="stylesheet" href="//cdn.jsdelivr.net/npm/graphiql/graphiql.min.css" />'
    '</head><body><div id="graphiql">Loading GraphiQL...</div>'
    "<script>ReactDOM.render(React.createElement(GraphiQL), document.body);</script>"
    "</body></html>"
)

_SCHEMA_TYPES = [
    {"name": "Query", "kind": "OBJECT"},
    {"name": "Mutation", "kind": "OBJECT"},
    {"name": "User", "kind": "OBJECT"},
    {"name": "String", "kind": "SCALAR"},
]

_MUTATION_FIELDS = [
    {"name": "createUser"},
    {"name": "updateProfile"},
    {"name": "deleteAccount"},
]


def _graphql(path: str, query: Mapping[str, list[str]], *, authenticated: bool) -> _Response:
    if path in {"/graphiql"}:
        return _Response(200, _GRAPHIQL)
    if path != "/graphql":
        return _not_found()
    if authenticated:
        # Introspection is disabled for a session-bearing caller: the control that keeps a
        # check from "finding" the schema by ignoring whether it actually got one.
        return _json_response({"errors": [{"message": "introspection is disabled"}]}, status=400)
    operation = (query.get("query") or [""])[0]
    lowered = operation.lower()
    if "arachneprobenonexistentfield" in lowered:
        return _json_response(
            {
                "errors": [
                    {
                        "message": (
                            'Cannot query field "arachneProbeNonexistentField" on type '
                            '"Query". Did you mean "arachneProbeExistingField"?'
                        ),
                        "locations": [{"line": 1, "column": 15}],
                    }
                ]
            }
        )
    if "mutationtype" in lowered:
        return _json_response(
            {
                "data": {
                    "__schema": {
                        "mutationType": {
                            "name": "Mutation",
                            "fields": _MUTATION_FIELDS,
                        }
                    }
                }
            }
        )
    if "__schema" in lowered or operation == "":
        if operation == "":
            # No query at all: the endpoint's own browsing interface.
            return _Response(200, _GRAPHIQL)
        return _json_response(
            {
                "data": {
                    "__schema": {
                        "queryType": {"name": "Query"},
                        "mutationType": {"name": "Mutation"},
                        "types": _SCHEMA_TYPES,
                    }
                }
            }
        )
    return _not_found()


# --------------------------------------------------------------------------- gRPC / Connect
def _grpc(path: str, query: Mapping[str, list[str]], *, method: str) -> _Response:
    if path == "/grpc.health.v1.Health/Check":
        if method == "OPTIONS":
            # The browser-facing deployment's preflight: it reflects an arbitrary origin and
            # authorizes the gRPC-Web request headers. No call is made.
            return _Response(
                204,
                "",
                content_type="text/plain",
                headers=(
                    ("Access-Control-Allow-Origin", "*"),
                    ("Access-Control-Allow-Methods", "POST, OPTIONS"),
                    ("Access-Control-Allow-Headers", "content-type,x-grpc-web,grpc-timeout"),
                ),
            )
        if query.get("encoding") == ["json"]:
            return _json_response({"status": "SERVING"})
        return _not_found()
    return _not_found()


# --------------------------------------------------------------------------- WebSocket
def _websocket(path: str, origin: str, *, key: str, host: str, scheme: str) -> _Response | None:
    """The upgrade answer for ``origin``: ``None`` means "complete the handshake".

    Each route trusts exactly one wrong origin, in the target's own scheme — so the three
    fixtures are decoys for one another's checks and each check's signal is origin-specific.
    """
    trusted = {
        "/ws": "null",
        # ``_normalise`` drops the trailing slash, so the route key is the bare form.
        "/socket.io": f"{scheme}://arachne-sibling.{host}",
        "/realtime": f"{scheme}://{host}.arachne-suffix.invalid",
    }
    if path not in trusted:
        return _not_found()
    if origin != trusted[path] or not key:
        return _Response(403, "origin rejected", content_type="text/plain")
    return None


# --------------------------------------------------------------------------- serverless / edge
def _serverless(path: str) -> _Response:
    if path == "/.netlify/functions/hello":
        return _Response(
            200,
            json.dumps({"message": "hello from the function"}),
            "application/json; charset=utf-8",
            headers=(("X-Nf-Request-Id", "01HQ8Z9"),),
        )
    if path == "/api/hello":
        return _Response(
            200,
            json.dumps({"message": "hello from the edge route"}),
            "application/json; charset=utf-8",
            headers=(("X-Vercel-Id", "fra1::arachne-lab"),),
        )
    if path == "/hello":
        return _Response(
            200,
            json.dumps({"message": "hello from the function runtime"}),
            "application/json; charset=utf-8",
            headers=(("Function-Execution-Id", "arachne-lab-0001"),),
        )
    if path == "/system/functions":
        return _json_response(
            [
                {
                    "name": "figlet",
                    "image": "ghcr.io/openfaas/figlet:latest",
                    "replicas": 1,
                },
                {
                    "name": "nodeinfo",
                    "image": "ghcr.io/openfaas/nodeinfo:latest",
                    "replicas": 1,
                },
            ]
        )
    if path == "/app.js":
        return _Response(
            200,
            "export default function handler(req) { return new Response('ok'); }\n"
            "//# sourceMappingURL=app.js.map\n",
            "application/javascript; charset=utf-8",
        )
    if path == "/app.js.map":
        return _json_response(
            {
                "version": 3,
                "file": "app.js",
                "sources": ["functions/index.ts", "../src/handler.ts"],
                "mappings": "AAAA,IAAM",
            }
        )
    return _not_found()


# --------------------------------------------------------------------------- CORS
def _cors(path: str, origin: str | None, *, method: str, host: str, scheme: str) -> _Response:
    if path not in {"/api/config", "/api/v1/config"}:
        return _not_found()
    if method == "OPTIONS":
        # The preflight: it reflects an arbitrary origin and authorizes write verbs and any
        # request header. No state-changing request is ever sent.
        return _Response(
            204,
            "",
            content_type="text/plain",
            headers=(
                ("Access-Control-Allow-Origin", origin or "*"),
                ("Access-Control-Allow-Credentials", "true"),
                ("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE"),
                ("Access-Control-Allow-Headers", "authorization, content-type, *"),
            ),
        )
    return _Response(
        200,
        json.dumps({"config": {"region": "eu-central-1", "features": ["a", "b"]}}),
        "application/json; charset=utf-8",
        headers=(
            ("Access-Control-Allow-Origin", origin or f"{scheme}://{host}"),
            ("Access-Control-Allow-Credentials", "true"),
        ),
    )


def _cors_production(path: str, host: str, scheme: str) -> _Response:
    """The conformant policy: the site's own origin only, ``GET`` and ``content-type`` only."""
    if path not in {"/api/config", "/api/v1/config"}:
        return _not_found()
    return _Response(
        200,
        json.dumps({"config": {"region": "eu-central-1"}}),
        "application/json; charset=utf-8",
        headers=(
            ("Access-Control-Allow-Origin", f"{scheme}://{host}"),
            ("Access-Control-Allow-Methods", "GET"),
            ("Access-Control-Allow-Headers", "content-type"),
        ),
    )


def _normalise(path: str) -> str:
    """The route key for a request path: no trailing slash, ``"/"`` for the root."""
    stripped = path.rstrip("/")
    return stripped or "/"


class _Handler(BaseHTTPRequestHandler):
    """One fixture: one route table per surface, differing by the lab's mode."""

    server_version = "arachne-api-lab/1.0"
    protocol_version = "HTTP/1.1"
    # Loopback Nagle/delayed-ACK stall removal, as in the shared web lab.
    disable_nagle_algorithm = True
    lab: ApiLab

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - stdlib signature
        return  # the fixture is quiet; the scanner's audit log is the record

    # ------------------------------------------------------------------ plumbing
    def _send(self, response: _Response) -> None:
        payload = response.body.encode("utf-8")
        self.send_response(response.status)
        self.send_header("Content-Type", response.content_type)
        self.send_header("Content-Length", str(len(payload)))
        for name, value in response.headers:
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def _complete_handshake(self) -> None:
        """Write an RFC 6455 ``101`` by hand: an upgrade carries no content length or body."""
        key = self.headers.get("Sec-WebSocket-Key", "")
        accept = base64.b64encode(
            hashlib.sha1((key + _WS_GUID).encode("ascii")).digest()  # noqa: S324 - RFC 6455
        ).decode("ascii")
        self.close_connection = True
        self.send_response(101, "Switching Protocols")
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept)
        self.end_headers()

    # ------------------------------------------------------------------ routing
    def _route(self, path: str, query: Mapping[str, list[str]]) -> _Response | None:
        """The answer for this request. ``None`` means "complete the WebSocket handshake"."""
        lab = self.lab
        key = _normalise(path)
        scheme, host = "http", lab.host
        if lab.mode == "waf" and (key != "/" or query):
            return _Response(
                403,
                _WAF_BLOCK.format(
                    path=self.path,
                    surface=_SURFACE_NAMES[lab.surface],
                    nonce=secrets.token_hex(4),
                ),
                headers=(("Server", "arachne-waf-lab"),),
            )
        if key == "/":
            if lab.mode == "vulnerable":
                return _Response(200, _homepage(lab.surface, lab))
            return _Response(200, _production_homepage(lab.surface))
        if lab.mode in {"production", "waf"}:
            # The conformant deployment. The documentation surface refuses with its own
            # challenge; the WebSocket routes validate their origin; the CORS surface names
            # only its own origin; everything else is the installation's own 404.
            if lab.surface in {"openapi", "graphql", "grpc", "serverless"}:
                return _unauthorized()
            if lab.surface == "websocket":
                return _Response(403, "origin rejected", content_type="text/plain")
            if lab.surface == "cors":
                return _cors_production(key, host, scheme)
            return _not_found()
        if lab.surface == "openapi":
            return _openapi(key, query)
        if lab.surface == "graphql":
            return _graphql(key, query, authenticated=bool(self.headers.get("Cookie")))
        if lab.surface == "grpc":
            return _grpc(key, query, method=self.command)
        if lab.surface == "websocket":
            if self.command == "OPTIONS":
                return _Response(405, "", headers=(("Allow", "GET, HEAD, OPTIONS"),))
            return _websocket(
                key,
                self.headers.get("Origin", ""),
                key=self.headers.get("Sec-WebSocket-Key", ""),
                host=lab.hostname,
                scheme=scheme,
            )
        if lab.surface == "serverless":
            return _serverless(key)
        if lab.surface == "cors":
            return _cors(
                key,
                self.headers.get("Origin"),
                method=self.command,
                host=host,
                scheme=scheme,
            )
        return _not_found()

    def _handle(self) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        self.lab.requests.append(f"{self.command} {self.path}")
        response = self._route(parsed.path, query)
        if response is None:
            self._complete_handshake()
            return
        self._send(response)

    # ------------------------------------------------------------------ verbs
    def do_GET(self) -> None:
        self._handle()

    def do_HEAD(self) -> None:
        self._handle()

    def do_OPTIONS(self) -> None:
        # OPTIONS is a safe method (RFC 9110 §9.3.7) and the only non-GET verb this family
        # sends. The surface decides: a preflight policy or a plain refusal.
        self._handle()

    def do_POST(self) -> None:
        self.lab.requests.append(f"POST {self.path}")
        # No route in this fixture accepts a POST: no login, no console action and no GraphQL
        # mutation is possible against it, which is what makes the *surface* the only thing a
        # check can report.
        self._send(_Response(405, _NOT_FOUND, headers=(("Allow", "GET, HEAD, OPTIONS"),)))


@contextmanager
def start_api_lab(surface: str, mode: str = "vulnerable") -> Iterator[ApiLab]:
    """Start one surface fixture on loopback in ``mode`` and yield its handle."""
    if surface not in SURFACES:
        raise ValueError(f"unknown surface {surface!r}; expected one of {SURFACES}")
    if mode not in MODES:
        raise ValueError(f"unknown api-lab mode {mode!r}; expected one of {MODES}")
    lab = ApiLab(surface=surface, mode=mode)
    handler: Any = type("_BoundHandler", (_Handler,), {"lab": lab})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    server.daemon_threads = True
    port = server.server_address[1]
    lab.port = port
    lab.base_url = f"http://127.0.0.1:{port}/"
    thread = threading.Thread(
        target=server.serve_forever,
        args=(0.05,),
        name=f"arachne-api-lab-{surface}-{mode}",
        daemon=True,
    )
    thread.start()
    try:
        yield lab
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
