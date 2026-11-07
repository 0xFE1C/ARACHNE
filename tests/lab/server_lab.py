"""The server, platform and runtime-configuration lab (WP-30, REQ-DET-023).

The requirement's decoy is explicit — "one hardened server per family" — so this fixture
serves each of the nine scope areas the requirement names from its own origin, in four modes:

``vulnerable``
    A deployment left at its defaults, serving exactly the artefacts its area's checks
    establish: the nginx welcome page, the ``stub_status`` counters and a served
    ``nginx.conf``; Apache's default page, ``httpd.conf`` and the ``.htpasswd`` store; the
    IIS welcome page and ``applicationHost.config``; Caddy's admin-API configuration and a
    ``Caddyfile``; a JSON and an XML auto-index; the Docker and Podman version documents; the
    Kubernetes Dashboard behind the API-server proxy, the kubelet pod list, the registry
    catalogue and a registry dashboard's system document; the ActiveMQ console, the NATS
    monitoring document and the EMQX console; and — for the header family — a ``Server``
    banner naming a version, the stack headers and a session response a shared cache may
    store.
``hardened``
    **The requirement's decoy.** The installation serves its own application and answers
    *every* management path with ``401`` and a challenge: the artefact is there but a caller
    who has not authenticated cannot read it. It sends a generic ``Server`` banner with no
    version, no stack headers and a ``Cache-Control: no-store``. A check that fired on a
    status code, on a path that merely exists, or on any header it reads blindly would report
    this installation as vulnerable.
``error-page``
    The same installation with a broken backend: every path answers a generic ``500`` that
    names nothing.
``echo-404``
    The pitfall's own trap, and this fixture's sharpest: every path answers ``200 OK`` with a
    *short* body that echoes the requested path — short enough that it is **not** similar to
    the not-found reference, so the family's not-found comparison does not suppress it and the
    content markers are the only thing standing between the trap and a false positive. A check
    whose marker is a substring of the path it probes fires here.

**The cross-area decoy.** The nine ``vulnerable`` installations are decoys for one another's
checks. Each plants only the signals *its own* area's checks claim: the Apache installation
does not send an nginx banner and the nginx installation does not serve a registry catalogue,
so a check that fired there would be reporting something that installation never published.

**No credential, and nothing executed.** The ``.htpasswd`` entry is *assembled at import*
(:func:`_derive`) rather than written as a literal, the way the WP-29 artifact lab assembles
its planted values: it is digest output over a fixed string, so it authenticates nothing, and
a served password *hash* is the finding rather than a leaked secret. No route authenticates,
no route accepts a body, no verb but ``GET``/``HEAD`` is answered, and nothing is started,
stopped, loaded or changed anywhere in this file — a container daemon's version endpoint is
*read* and nothing else is asked of it.
"""

from __future__ import annotations

import hashlib
import json
import threading
import urllib.parse
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

__all__ = [
    "AREAS",
    "MODES",
    "PATHS_BY_AREA",
    "ServerLab",
    "start_server_lab",
]

#: The nine scope areas the requirement names. Each owns the checks of one platform family.
AREAS: tuple[str, ...] = (
    "nginx",
    "apache",
    "iis",
    "caddy",
    "directory-index",
    "container-runtime",
    "orchestration-registry",
    "message-broker",
    "header-defaults",
)

#: The four modes. The first is the positive fixture, the second the requirement's decoy, the
#: third a broken backend, the fourth the echoing soft-404 the pitfalls warn about.
MODES: tuple[str, ...] = ("vulnerable", "hardened", "error-page", "echo-404")

#: The ``Server`` banner the header family's vulnerable installation discloses, and the
#: generic banner every other installation sends. The lab's own default (``BaseHTTP/0.6
#: Python/3.x``) would disclose a version on every installation, including the decoys — which
#: is precisely the false positive the version check must not produce — so the handler
#: overrides ``version_string`` for every response.
_PLATFORM_BANNER: str = "nginx/1.24.0"
_GENERIC_BANNER: str = "arachne-server-lab"


def _derive(label: str, *, length: int) -> str:
    """A deterministic fixture value: digest output, never a credential."""
    digest = hashlib.sha256(f"arachne-wp30-lab:{label}".encode()).hexdigest()
    return digest[:length]


#: The password file's two entries, assembled here so this file carries no credential-shaped
#: literal. A ``crypt``-style hash is a *hash*: it proves the file is a password store (which
#: is the finding) and authenticates nothing.
_HTPASSWD: str = (
    "$apr1$" + _derive("htpasswd-salt", length=8) + "$" + _derive("htpasswd-hash", length=22)
)


@dataclass
class ServerLab:
    """A running fixture: which area, which mode, its origin and what it answered."""

    area: str
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


@dataclass(frozen=True, slots=True)
class _Response:
    status: int
    body: bytes
    content_type: str = "text/html; charset=utf-8"
    headers: tuple[tuple[str, str], ...] = ()


def _text(status: int, body: str, content_type: str = "text/html; charset=utf-8") -> _Response:
    return _Response(status, body.encode("utf-8"), content_type)


def _json(document: object, *, status: int = 200) -> _Response:
    return _Response(
        status,
        json.dumps(document, indent=1).encode("utf-8"),
        "application/json; charset=utf-8",
    )


# --------------------------------------------------------------------------- the bodies
_SITE = (
    '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8" />'
    "<title>Arachne server, platform and runtime lab</title></head><body>"
    "<h1>Server, platform and runtime configuration lab</h1>"
    "<p>This installation serves its own application and protects its management "
    "surfaces.</p></body></html>"
)

_NGINX_WELCOME = (
    "<!DOCTYPE html><html><head><title>Welcome to nginx!</title></head><body>"
    "<h1>Welcome to nginx!</h1>"
    "<p>If you see this page, the nginx web server is successfully installed and working. "
    "Further configuration is required.</p>"
    "<p>Thank you for using nginx.</p></body></html>"
)

_NGINX_STATUS = (
    "Active connections: 291 \n"
    "server accepts handled requests\n"
    " 16630948 16630948 31070465 \n"
    "Reading: 6 Writing: 179 Waiting: 106 \n"
)

_NGINX_CONF = (
    "user  nginx;\n"
    "worker_processes  auto;\n"
    "error_log  /var/log/nginx/error.log notice;\n"
    "pid        /var/run/nginx.pid;\n"
    "events {\n"
    "    worker_connections  1024;\n"
    "}\n"
    "http {\n"
    "    include       /etc/nginx/mime.types;\n"
    "    default_type  application/octet-stream;\n"
    "    server {\n"
    "        listen       80;\n"
    "        server_name  _;\n"
    "    }\n"
    "}\n"
)

_APACHE_WELCOME = (
    "<!DOCTYPE html><html><head><title>Apache2 Debian Default Page: It works</title>"
    "</head><body>"
    "<h1>Apache2 Debian Default Page</h1>"
    "<p>It works!</p>"
    "<p>This is the default welcome page used to test the correct operation of the "
    "Apache2 server after installation on Debian systems.</p></body></html>"
)

_APACHE_CONF = (
    'ServerRoot "/etc/apache2"\n'
    "LoadModule mpm_event_module /usr/lib/apache2/modules/mod_mpm_event.so\n"
    "LoadModule auth_basic_module /usr/lib/apache2/modules/mod_auth_basic.so\n"
    'DocumentRoot "/var/www/html"\n'
    '<Directory "/var/www/html">\n'
    "    Options Indexes FollowSymLinks\n"
    "    AllowOverride None\n"
    "    Require all granted\n"
    "</Directory>\n"
)

_HTPASSWD_BODY = f"admin:${_HTPASSWD}\ndeployer:$2y$10${_derive('bcrypt-hash', length=53)}\n"

_IIS_WELCOME = (
    '<!DOCTYPE html><html><head><meta charset="utf-8" />'
    "<title>IIS Windows Server</title></head><body>"
    "<h1>Internet Information Services</h1>"
    "<p>Welcome to the IIS Windows Server default page. This page is served by the "
    "web server's default site.</p></body></html>"
)

_IIS_CONFIG = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    "<configuration>\n"
    "  <system.applicationHost>\n"
    "    <applicationPools>\n"
    '      <add name="DefaultAppPool" managedRuntimeVersion="v4.0" />\n'
    "    </applicationPools>\n"
    "    <sites>\n"
    "      <siteDefaults>\n"
    '        <limits maxBandwidth="4294967295" maxConnections="4294967295" />\n'
    "      </siteDefaults>\n"
    '      <site name="Default Web Site" id="1" serverAutoStart="true">\n'
    '        <application path="/" applicationPool="DefaultAppPool" />\n'
    "      </site>\n"
    "    </sites>\n"
    "  </system.applicationHost>\n"
    "</configuration>\n"
)

_CADDY_CONFIG = {
    "admin": {"disabled": False, "listen": ":2019"},
    "logging": {"logs": {}},
    "storage": {"module": "file_system", "root": "/var/lib/caddy"},
    "automatic_https": {"disable": False, "disable_redirects": False},
    "storage_clean_interval": "1m0s",
}

_CADDY_SERVERS = {
    "servers": {
        "srv0": {
            "listen": [":443"],
            "routes": [
                {
                    "handle": [
                        {
                            "handler": "reverse_proxy",
                            "upstreams": [{"dial": "127.0.0.1:8080"}],
                        }
                    ]
                }
            ],
        }
    }
}

_CADDYFILE = (
    "{\n"
    "\temail admin@acme.test\n"
    "}\n"
    "\n"
    "acme.test {\n"
    "\tencode gzip\n"
    "\tfile_server\n"
    "\treverse_proxy 127.0.0.1:8080\n"
    "}\n"
)

_AUTOINDEX_JSON = [
    {"name": "..", "type": "directory", "mtime": "2026-01-01T00:00:00Z"},
    {"name": "app.css", "type": "file", "mtime": "2026-01-01T00:00:00Z", "size": 1234},
    {"name": "app.js", "type": "file", "mtime": "2026-01-01T00:00:00Z", "size": 5678},
]

_AUTOINDEX_XML = (
    '<?xml version="1.0"?>\n'
    "<listing>\n"
    '<directory mtime="2026-01-01T00:00:00Z"><name>..</name></directory>\n'
    '<file mtime="2026-01-01T00:00:00Z"><name>report.pdf</name><size>1234</size></file>\n'
    "</listing>\n"
)

_DOCKER_VERSION = {
    "Platform": {"Name": "Docker Engine - Community"},
    "Components": [
        {
            "Name": "Engine",
            "Version": "25.0.3",
            "Details": {
                "ApiVersion": "1.44",
                "Arch": "amd64",
                "BuildTime": "2024-03-19T00:00:00.000000000+00:00",
                "Experimental": "false",
                "GitCommit": "f417435",
                "GoVersion": "go1.21.6",
                "KernelVersion": "6.6.0",
                "MinAPIVersion": "1.12",
                "Os": "linux",
            },
        }
    ],
    "Version": "25.0.3",
    "ApiVersion": "1.44",
    "MinAPIVersion": "1.12",
    "GitCommit": "f417435",
    "GoVersion": "go1.21.6",
    "Os": "linux",
    "Arch": "amd64",
    "KernelVersion": "6.6.0",
    "BuildTime": "2024-03-19T00:00:00.000000000+00:00",
}

_PODMAN_VERSION = {
    "Version": "4.9.4",
    "GoVersion": "go1.21.6",
    "GitCommit": "9f5bc3d8f9",
    "Built": 1700000000,
    "OsArch": "linux/amd64",
}

_K8S_DASHBOARD = (
    '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8" />'
    "<title>Kubernetes Dashboard</title></head><body>"
    '<app-root class="k8sDashboard"><h1>Kubernetes Dashboard</h1></app-root>'
    "</body></html>"
)

_KUBELET_PODS = {
    "kind": "PodList",
    "apiVersion": "v1",
    "metadata": {},
    "items": [
        {
            "metadata": {"name": "acme-app-0", "namespace": "default"},
            "spec": {
                "nodeName": "worker-1",
                "containers": [{"name": "app", "image": "acme/app:1.4.2"}],
            },
        }
    ],
}

_REGISTRY_CATALOG = {
    "repositories": ["library/nginx", "library/postgres", "acme/app", "acme/internal-tools"]
}

_HARBOR_SYSTEMINFO = {
    "harbor_version": "v2.10.2",
    "registry_storage_provider_name": "filesystem",
    "auth_mode": "db_auth",
    "with_notary": True,
}

_NEXUS_STATUS = {
    "version": "3.61.0-02",
    "edition": "PRO",
    "distribution": "nexus-repository-manager",
}

_ACTIVEMQ_CONSOLE = (
    "<!DOCTYPE html><html><head><title>ActiveMQ Console</title></head><body>"
    "<h1>Apache ActiveMQ</h1>"
    "<p>Welcome to the ActiveMQ Console. Queues and topics are listed below.</p>"
    "</body></html>"
)

_NATS_VARZ = {
    "server_id": "NDFIXTURE0000000000000000000000",
    "server_name": "nats-1",
    "version": "2.10.7",
    "proto": 1,
    "go": "go1.21.6",
    "host": "0.0.0.0",
    "port": 4222,
    "max_connections": 65536,
    "in_msgs": 123456,
    "out_msgs": 123000,
    "subscriptions": 42,
}

_EMQX_CONSOLE = (
    '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8" />'
    "<title>EMQX Dashboard</title></head><body>"
    "<h1>EMQX Dashboard</h1></body></html>"
)

_NOT_FOUND = (
    "<!DOCTYPE html><html><head><title>404 Not Found</title></head><body>"
    "<h1>Not Found</h1>"
    "<p>The requested resource was not found on this server.</p></body></html>"
)

_ERROR_PAGE = (
    "<!DOCTYPE html><html><head><title>500 Internal Server Error</title></head><body>"
    "<h1>Internal Server Error</h1>"
    "<p>The server encountered an internal error and was unable to complete your "
    "request.</p></body></html>"
)

#: The challenge a hardened server answers a management path with. It names no artefact.
_CHALLENGE = (
    "<!DOCTYPE html><html><head><title>401 Unauthorized</title></head><body>"
    "<h1>Unauthorized</h1>"
    "<p>Authentication is required to view this resource.</p></body></html>"
)

#: The echoing soft-404. Deliberately **short**: the body is not similar to the not-found
#: reference, so the family's not-found comparison does not suppress it and the content
#: markers are the only thing standing between the trap and a false positive. A marker that
#: is a substring of the path it probes fires here.
_ECHO_404 = "Not found: {path}\n"


def _area_routes() -> dict[str, dict[str, _Response]]:
    """Each area's planted routes, keyed by the *normalised* request path.

    Only the paths a check needs to find are published; every other path in the corpus
    answers the installation's own refusal, which is what makes the other checks silent.
    """
    dashboard = "/api/v1/namespaces/kubernetes-dashboard/services/https:kubernetes-dashboard:/proxy"
    return {
        "nginx": {
            "/": _text(200, _NGINX_WELCOME),
            "/index.nginx-debian.html": _text(200, _NGINX_WELCOME),
            "/nginx_status": _text(200, _NGINX_STATUS, "text/plain; charset=utf-8"),
            "/nginx.conf": _text(200, _NGINX_CONF, "text/plain; charset=utf-8"),
        },
        "apache": {
            "/": _text(200, _APACHE_WELCOME),
            "/index.html": _text(200, _APACHE_WELCOME),
            "/apache2.conf": _text(200, _APACHE_CONF, "text/plain; charset=utf-8"),
            "/.htpasswd": _text(200, _HTPASSWD_BODY, "text/plain; charset=utf-8"),
        },
        "iis": {
            "/": _text(200, _IIS_WELCOME),
            "/iisstart.htm": _text(200, _IIS_WELCOME),
            "/applicationHost.config": _text(200, _IIS_CONFIG, "application/xml; charset=utf-8"),
        },
        "caddy": {
            "/config": _json(_CADDY_CONFIG),
            "/config/apps/http": _json(_CADDY_SERVERS),
            "/Caddyfile": _text(200, _CADDYFILE, "text/plain; charset=utf-8"),
        },
        "directory-index": {
            "/static": _json(_AUTOINDEX_JSON),
            "/media": _json(_AUTOINDEX_JSON),
            "/files": _text(200, _AUTOINDEX_XML, "application/xml; charset=utf-8"),
            "/downloads": _text(200, _AUTOINDEX_XML, "application/xml; charset=utf-8"),
        },
        "container-runtime": {
            "/version": _json(_DOCKER_VERSION),
            "/v1.44/version": _json(_DOCKER_VERSION),
            "/libpod/version": _json(_PODMAN_VERSION),
            "/v4.9.0/libpod/version": _json(_PODMAN_VERSION),
        },
        "orchestration-registry": {
            dashboard: _text(200, _K8S_DASHBOARD),
            "/pods": _json(_KUBELET_PODS),
            "/v2/_catalog": _json(_REGISTRY_CATALOG),
            "/api/v2.0/systeminfo": _json(_HARBOR_SYSTEMINFO),
            "/service/rest/v1/status": _json(_NEXUS_STATUS),
        },
        "message-broker": {
            "/admin": _text(200, _ACTIVEMQ_CONSOLE),
            "/admin/index.jsp": _text(200, _ACTIVEMQ_CONSOLE),
            "/varz": _json(_NATS_VARZ),
            "/connz": _json(_NATS_VARZ),
            "/emqx": _text(200, _EMQX_CONSOLE),
        },
        "header-defaults": {},
    }


#: Every area's published routes, keyed by area.
_AREA_ROUTES: Mapping[str, Mapping[str, _Response]] = _area_routes()

#: The published paths per area (normalised: no trailing slash), for the acceptance test's own
#: controls. A finding's path is compared with the trailing slash folded away.
PATHS_BY_AREA: Mapping[str, tuple[str, ...]] = {
    area: tuple(sorted(routes)) for area, routes in _AREA_ROUTES.items()
}


def _normalise(path: str) -> str:
    """The route key for a request path: no trailing slash, ``"/"`` for the root."""
    stripped = path.rstrip("/")
    return stripped or "/"


class _Handler(BaseHTTPRequestHandler):
    """One fixture: one route table per area, differing by the lab's mode."""

    server_version = "arachne-server-lab"
    sys_version = ""
    protocol_version = "HTTP/1.1"
    disable_nagle_algorithm = True
    lab: ServerLab

    def version_string(self) -> str:
        """The single ``Server`` header, which is the one thing every answer discloses.

        The lab's own default would name ``BaseHTTP/x.y`` on *every* installation, decoys
        included — the exact false positive ``m4.server-version-disclosure`` must not
        produce. So exactly one installation (the header family's vulnerable mode) discloses
        a product version, and every other answer is generic.
        """
        return _PLATFORM_BANNER if self._discloses() else _GENERIC_BANNER

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - stdlib signature
        return  # the fixture is quiet; the scanner's audit log is the record

    def _discloses(self) -> bool:
        return self.lab.area == "header-defaults" and self.lab.mode == "vulnerable"

    def _send(self, response: _Response, *, path: str) -> None:
        self.send_response(response.status)
        self.send_header("Content-Type", response.content_type)
        self.send_header("Content-Length", str(len(response.body)))
        # The hardening default every installation sends, disclosing installation removed.
        if self._discloses() and path == "/":
            self.send_header("Cache-Control", "public, max-age=600")
            self.send_header("X-Powered-By", "PHP/8.2.1")
            self.send_header("X-AspNet-Version", "4.0.30319")
            self.send_header("Set-Cookie", f"PHPSESSID={_derive('session', length=26)}; Path=/")
        else:
            self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        for name, value in response.headers:
            self.send_header(name, value)
        self.end_headers()
        if self.command == "HEAD":
            return
        try:
            self.wfile.write(response.body)
        except (BrokenPipeError, ConnectionResetError):
            self.close_connection = True

    def _route(self, path: str) -> _Response:
        lab = self.lab
        key = _normalise(path)
        if key == "/":
            # The site itself: every mode serves a working application at the root. Only the
            # three server-default-page families answer it with the package's stock page, and
            # only in the vulnerable mode.
            published = _AREA_ROUTES[lab.area].get("/")
            if lab.mode == "vulnerable" and published is not None:
                return published
            return _text(200, _SITE)
        if lab.mode == "hardened":
            # The artefact exists but is behind a challenge: a caller who has not
            # authenticated cannot read it, so a check that reported this would be reporting
            # an exposure that is not one.
            if key in _AREA_ROUTES[lab.area]:
                return _Response(
                    401,
                    _CHALLENGE.encode("utf-8"),
                    headers=(("WWW-Authenticate", 'Basic realm="management"'),),
                )
            return _text(404, _NOT_FOUND)
        if lab.mode == "error-page":
            return _text(500, _ERROR_PAGE)
        if lab.mode == "echo-404":
            return _text(200, _ECHO_404.format(path=self.path))
        published = _AREA_ROUTES[lab.area].get(key)
        if published is not None:
            return published
        return _text(404, _NOT_FOUND)

    def _handle(self) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        response = self._route(parsed.path)
        # The log records the answer's status too: "what could a reader actually reach on
        # this installation?" is a question about the 2xx answers, not the requests.
        self.lab.requests.append(f"{self.command} {parsed.path} {response.status}")
        self._send(response, path=_normalise(parsed.path))

    def do_GET(self) -> None:
        self._handle()

    def do_HEAD(self) -> None:
        self._handle()

    def do_OPTIONS(self) -> None:
        self.lab.requests.append(f"OPTIONS {self.path} 405")
        self._send(_Response(405, b"", headers=(("Allow", "GET, HEAD"),)), path="/")

    def do_POST(self) -> None:
        self.lab.requests.append(f"POST {self.path} 405")
        # No route in this fixture accepts a body: nothing can be uploaded, changed or
        # authenticated against it.
        self._send(_Response(405, b"", headers=(("Allow", "GET, HEAD"),)), path="/")


@contextmanager
def start_server_lab(area: str, mode: str = "vulnerable") -> Iterator[ServerLab]:
    """Start one area fixture on loopback in ``mode`` and yield its handle."""
    if area not in AREAS:
        raise ValueError(f"unknown area {area!r}; expected one of {AREAS}")
    if mode not in MODES:
        raise ValueError(f"unknown server-lab mode {mode!r}; expected one of {MODES}")
    lab = ServerLab(area=area, mode=mode)
    handler: Any = type("_BoundHandler", (_Handler,), {"lab": lab})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    server.daemon_threads = True
    port = server.server_address[1]
    lab.port = port
    lab.base_url = f"http://127.0.0.1:{port}/"
    thread = threading.Thread(
        target=server.serve_forever,
        args=(0.05,),
        name=f"arachne-server-lab-{area}-{mode}",
        daemon=True,
    )
    thread.start()
    try:
        yield lab
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
