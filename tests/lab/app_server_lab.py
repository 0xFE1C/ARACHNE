"""The application-server lab: nine frameworks, each served in three modes (WP-27, REQ-DET-020).

The requirement's acceptance needs a **positive fixture** and a **decoy** per framework, and
names the decoy: "each framework ships a production-configured decoy". This module serves each
of the nine frameworks the family covers (Spring Boot, Django, Rails, Laravel, Tomcat, JBoss,
WebLogic, ColdFusion and IIS) from its own origin, in three modes:

``vulnerable``
    A development/stock installation publishing the artefacts the family's checks establish:
    the Spring Boot actuator index, configuration surfaces and heap dump, the Django debug and
    media paths, the Rails info controller, the Laravel debug page and Ignition endpoints, the
    Tomcat manager/host-manager and default webapps, the JBoss consoles, the WebLogic console
    family, the ColdFusion administrator and CFIDE tree, and the IIS short-name, trace-viewer
    and legacy password surfaces.
``production``
    The same framework after a production configuration: every non-root path answers the
    installation's own 404, so a check that matched on a status code or a path alone finds
    nothing. **The production homepage names the framework and carries none of its markup**,
    which is what makes it a fair trap for the marker guard.
``waf``
    The production configuration behind a web application firewall: the homepage is the
    production one, and every other path — actuator, debug, manager, console, CFIDE and IIS
    alike — is answered with the WAF's ``403`` block page, which *echoes the requested path* and
    *names the framework*. That is the "block page that contains the payload" archetype of the
    decoy catalogue (``docs/plugin-developer-guide.md`` §2.1): a check that matched on body
    content, or on a status code, rather than on the framework's own markup plus a successful
    answer, would fire on it.

The fixture is deliberately a *server*, not a mirror of the checks: it renders the artefacts
each framework actually ships (Spring's ``_links`` actuator index and ``propertySources``
document, HPROF's ``JAVA PROFILE`` magic, Django's technical page and ``Directory listing for``
renderer, ``Rails version``/``Ruby version`` properties, Ignition's ``APP_DEBUG`` page and
``can_execute_commands`` health payload, Tomcat's ``WWW-Authenticate`` realm, JBoss's
``JMX Agent View``, WebLogic's ``j_security_check`` form, ColdFusion's ``CFIDE`` tree and the
ASP.NET trace viewer's ``Requests to this Application`` heading), so a check that passes here
has read something the real installation produces rather than something this module invented.

**No credential values and no state change.** No route authenticates anything, none accepts a
body, and none accepts anything but ``GET``/``HEAD``/``OPTIONS`` — which is what makes the
management-console *surface* the only thing a check can report against it. Every fixture body
declares identifiers and never a secret.
"""

from __future__ import annotations

import json
import secrets
import threading
import urllib.parse
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

__all__ = ["FRAMEWORKS", "MODES", "AppServerLab", "start_app_server_lab"]

#: The nine frameworks the family covers (REQ-DET-020).
FRAMEWORKS: tuple[str, ...] = (
    "spring_boot",
    "django",
    "rails",
    "laravel",
    "tomcat",
    "jboss",
    "weblogic",
    "coldfusion",
    "iis",
)

#: The modes a lab can serve. ``vulnerable`` is the positive fixture; the other two are decoys.
MODES: tuple[str, ...] = ("vulnerable", "production", "waf")

#: The version each vulnerable fixture publishes (a version *signal*, never a severity).
CORE_VERSIONS: Mapping[str, str] = {
    "spring_boot": "3.2.4",
    "django": "5.0.3",
    "rails": "7.1.3",
    "laravel": "10.48.4",
    "tomcat": "10.1.19",
    "jboss": "7.4.13",
    "weblogic": "14.1.1.0.0",
    "coldfusion": "2023",
    "iis": "10.0",
}

#: The name each fixture publishes about itself.
_FRAMEWORK_NAMES: Mapping[str, str] = {
    "spring_boot": "Spring Boot",
    "django": "Django",
    "rails": "Rails",
    "laravel": "Laravel",
    "tomcat": "Apache Tomcat",
    "jboss": "JBoss",
    "weblogic": "Oracle WebLogic Server",
    "coldfusion": "Adobe ColdFusion",
    "iis": "Internet Information Services",
}

#: A not-found page that names no framework and carries no marker (every mode's own 404).
_NOT_FOUND = (
    "<html><head><title>Not found</title></head><body><h1>Not found</h1>"
    "<p>The requested resource was not found on this server.</p></body></html>"
)

#: The WAF block page. It *does* name the framework and echo the requested path — that is the
#: trap — and it carries none of the frameworks' markup.
_WAF_BLOCK = (
    "<!DOCTYPE html><html><head><title>Request blocked</title></head><body>"
    "<h1>Request blocked</h1>"
    "<p>Your request to <code>{path}</code> was blocked by the web application firewall. "
    "This site runs {framework}; administrative and diagnostic paths are protected.</p>"
    "<p>If you believe this is an error, contact the site operator and quote reference "
    "{nonce}.</p></body></html>"
)


@dataclass
class AppServerLab:
    """A running fixture: which framework, which mode, its origin and what it answered."""

    framework: str
    mode: str
    base_url: str = ""
    port: int = 0
    requests: list[str] = field(default_factory=list)

    @property
    def origin(self) -> str:
        return self.base_url.rstrip("/")


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


def _homepage(framework: str, origin: str) -> str:
    """A stock homepage that names the framework and publishes nothing else this family reads."""
    return (
        '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8" />'
        f"<title>Arachne App Lab — {_FRAMEWORK_NAMES[framework]}</title>"
        "</head><body>"
        f"<h1>Arachne Application Server Lab</h1><p>{_FRAMEWORK_NAMES[framework]} "
        f"{CORE_VERSIONS[framework]} is running here.</p>"
        f'<p><a href="{origin}/">Home</a></p>'
        "</body></html>"
    )


def _production_homepage(framework: str) -> str:
    """The production homepage: the site itself, and nothing a scanner can inventory."""
    return (
        '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8" />'
        "<title>Arachne App Lab — site</title>"
        "</head><body><h1>Arachne Application Server Lab</h1>"
        f"<p>{_FRAMEWORK_NAMES[framework]} is served here in its production configuration and "
        "publishes nothing else.</p></body></html>"
    )


# --------------------------------------------------------------------------- Spring Boot
def _spring_boot(path: str, origin: str) -> _Response:
    links = {
        name: {"href": f"{origin}/actuator/{name}", "templated": False}
        for name in ("self", "health", "env", "configprops", "heapdump")
    }
    if path in {"/actuator", "/actuator/"}:
        return _json_response({"_links": links})
    if path == "/actuator/health":
        return _json_response({"status": "UP"})
    if path == "/actuator/env":
        return _json_response(
            {
                "activeProfiles": ["production"],
                "propertySources": [
                    {"name": "server.ports"},
                    {"name": "systemProperties"},
                    {"name": "applicationConfig: [classpath:/application.properties]"},
                ],
            }
        )
    if path == "/actuator/configprops":
        return _json_response(
            {
                "contexts": {
                    "application": {
                        "beans": {
                            "server-org.springframework.boot.autoconfigure.web.ServerProperties": {
                                "prefix": "server",
                                "properties": {"port": "8080"},
                            }
                        }
                    }
                }
            }
        )
    if path == "/actuator/heapdump":
        return _Response(
            200,
            "JAVA PROFILE 1.0.2\0" + "\0" * 512,
            "application/octet-stream",
        )
    return _not_found()


# --------------------------------------------------------------------------- Django
_DJANGO_TECHNICAL_404 = (
    '<!DOCTYPE html><html lang="en"><head><title>Page not found at /</title></head><body>'
    "<h1>Page not found <span>(404)</span></h1>"
    "<p>Using the URLconf defined in <code>settings.urls</code>, Django tried these URL "
    "patterns, in this order:</p>"
    "<ol><li><code>admin/</code></li><li><code>media/</code></li></ol>"
    "<p>You're seeing this error because you have <code>DEBUG = True</code> in your Django "
    "settings file. Change that to <code>False</code>, and Django will display a standard 404 "
    "page.</p></body></html>"
)


def _django_listing(path: str) -> str:
    return (
        f'<!DOCTYPE html><html lang="en"><head><title>Index of {path}</title></head><body>'
        f"<h1>Directory listing for {path}</h1><ul>"
        '<li><a href="uploads/">uploads/</a></li>'
        '<li><a href="images/">images/</a></li>'
        "</ul><hr></body></html>"
    )


def _django(path: str, origin: str) -> _Response:
    if path.startswith(("/media", "/static")):
        return _Response(200, _django_listing(path + "/"))
    if path in {"/__debug__", "/__debug__/"}:
        return _Response(
            200,
            "<!DOCTYPE html><html><head><title>Django Debug Toolbar</title></head><body>"
            '<div id="djDebug" class="djDebug" data-store-id="djdt">'
            "<p>Django Debug Toolbar</p></div></body></html>",
        )
    if path in {"/__debug__/render_panel", "/__debug__/render_panel/"}:
        return _json_response({"__debug__": "render_panel", "djdt": True, "panels": ["SQL"]})
    if path in {"/__debug__/history_sidebar", "/__debug__/history_sidebar/"}:
        return _Response(
            200,
            '<div id="djDebug" class="djDebug"><p>Django Debug Toolbar history</p></div>',
        )
    # Everything else is an unmatched URL: with DEBUG on, Django renders its technical page.
    return _Response(404, _DJANGO_TECHNICAL_404)


# --------------------------------------------------------------------------- Rails
def _rails(path: str, origin: str) -> _Response:
    if path == "/rails/info/properties":
        return _Response(
            200,
            "<!DOCTYPE html><html><head><title>Rails Environment Properties</title></head>"
            "<body><h1>Rails Environment Properties</h1><table>"
            "<tr><td>Rails version</td><td>{version}</td></tr>"
            "<tr><td>Ruby version</td><td>3.2.2</td></tr>"
            "<tr><td>Application root</td><td>/srv/app</td></tr>"
            "<tr><td>Rails env</td><td>development</td></tr></table>"
            "<p>Rendered by Rails::InfoController.</p></body></html>".format(
                version=CORE_VERSIONS["rails"]
            ),
        )
    if path == "/rails/info":
        return _Response(
            200,
            "<!DOCTYPE html><html><head><title>Rails Info</title></head><body>"
            "<h1>Rails version</h1><p>Ruby version 3.2.2</p>"
            '<p><a href="/rails/info/properties">properties</a></p></body></html>',
        )
    if path == "/rails/info/routes":
        return _Response(
            200,
            "<!DOCTYPE html><html><head><title>Routes</title></head><body>"
            "<h1>Routes</h1><table><tr><th>Prefix</th><th>Verb</th><th>URI Pattern</th>"
            "<th>Controller#Action</th></tr>"
            "<tr><td>root</td><td>GET</td><td>/</td><td>home#index</td></tr>"
            "<tr><td>health</td><td>GET</td><td>/up</td><td>rails/health#show</td></tr>"
            "</table><p>Rails 7 routes.</p></body></html>",
        )
    return _not_found()


# --------------------------------------------------------------------------- Laravel
_LARAVEL_DEBUG_404 = (
    '<!DOCTYPE html><html lang="en"><head><title>Route [x] not defined.</title></head><body>'
    "<h1>Whoops, looks like something went wrong.</h1>"
    "<p>The route was not defined. Ignition error page rendered because APP_DEBUG is enabled."
    "</p><pre>Laravel 10.48.4 · PHP 8.3</pre>"
    "<script>window.ignition = {routeList: []};</script></body></html>"
)


def _laravel(path: str, origin: str) -> _Response:
    if path in {"/_ignition/health-check", "/_ignition/health-check/"}:
        return _json_response({"can_execute_commands": False, "ignition": "1.16.0", "status": "ok"})
    if path in {"/_ignition", "/_ignition/"}:
        return _Response(
            200,
            "<!DOCTYPE html><html><head><title>Ignition</title></head><body>"
            "<h1>Ignition</h1><p>Laravel's Ignition debug component is enabled.</p>"
            "</body></html>",
        )
    # Everything else is an unmatched route: with debug on, Laravel renders Ignition's page.
    return _Response(404, _LARAVEL_DEBUG_404)


# --------------------------------------------------------------------------- Tomcat
_TOMCAT_401 = (
    "<!DOCTYPE html><html><head><title>401 Unauthorized</title></head><body>"
    "<h1>HTTP Status 401 - Unauthorized</h1>"
    "<p>This request requires HTTP authentication (Apache Tomcat Manager).</p>"
    "</body></html>"
)


def _tomcat(path: str, origin: str) -> _Response:
    if path.startswith("/manager"):
        return _Response(
            401,
            _TOMCAT_401,
            headers=(("WWW-Authenticate", 'Basic realm="Tomcat Manager Application"'),),
        )
    if path.startswith("/host-manager"):
        return _Response(
            401,
            "<!DOCTYPE html><html><head><title>401 Unauthorized</title></head><body>"
            "<h1>HTTP Status 401 - Unauthorized</h1>"
            "<p>This request requires HTTP authentication (Tomcat Host Manager Application)."
            "</p></body></html>",
            headers=(("WWW-Authenticate", 'Basic realm="Tomcat Host Manager Application"'),),
        )
    if path in {"/examples", "/examples/", "/examples/servlets", "/examples/servlets/"}:
        return _Response(
            200,
            "<!DOCTYPE html><html><head><title>Servlet and JSP Examples</title></head><body>"
            "<h1>Apache Tomcat — Servlet and JSP Examples</h1>"
            "<p>These examples are shipped with Apache Tomcat {version}.</p>"
            "</body></html>".format(version=CORE_VERSIONS["tomcat"]),
        )
    if path in {"/docs", "/docs/"}:
        return _Response(
            200,
            "<!DOCTYPE html><html><head><title>Documentation Index</title></head><body>"
            "<h1>Apache Tomcat Documentation Index</h1>"
            "<p>Apache Tomcat {version} documentation.</p></body></html>".format(
                version=CORE_VERSIONS["tomcat"]
            ),
        )
    return _not_found()


# --------------------------------------------------------------------------- JBoss
def _jboss(path: str, origin: str) -> _Response:
    if path.startswith("/jmx-console"):
        return _Response(
            200,
            "<!DOCTYPE html><html><head><title>JBoss JMX Agent View</title></head><body>"
            "<h1>JBoss JMX Agent View</h1>"
            "<p>Agent View of the JBoss MBean server. HtmlAdaptor is serving this page.</p>"
            "</body></html>",
        )
    if path.startswith("/web-console"):
        return _Response(
            200,
            "<!DOCTYPE html><html><head><title>JBoss Web Console</title></head><body>"
            "<h1>JBoss Web Console</h1>"
            '<p><a href="ServerInfo.jsp">ServerInfo</a> — the deployment inventory.</p>'
            "</body></html>",
        )
    if path.startswith("/admin-console"):
        return _Response(
            200,
            "<!DOCTYPE html><html><head><title>JBoss Administrator Console</title></head>"
            "<body><h1>JBoss Administrator Console</h1>"
            '<form action="j_security_check" method="post" class="login.seam">'
            "<p>Log in to the management console.</p></form></body></html>",
        )
    return _not_found()


# --------------------------------------------------------------------------- WebLogic
def _weblogic(path: str, origin: str) -> _Response:
    if path.startswith("/console"):
        return _Response(
            200,
            "<!DOCTYPE html><html><head><title>Oracle WebLogic Server Administration Console"
            "</title></head><body><h1>Oracle WebLogic Server Administration Console</h1>"
            '<form method="POST" action="j_security_check" name="LoginForm">'
            '<input name="j_username" type="text" /><input name="j_password" type="password" />'
            "<p>LoginForm.jsp</p></form></body></html>",
        )
    if path.startswith("/uddiexplorer"):
        return _Response(
            200,
            "<!DOCTYPE html><html><head><title>WebLogic UDDI Explorer</title></head><body>"
            "<h1>UDDI Explorer</h1>"
            '<p><a href="SearchPublicRegistries.jsp">Search Public Registries</a></p>'
            "<p>Oracle WebLogic Server UDDI registry browser.</p></body></html>",
        )
    if path.startswith("/wls-wsat"):
        return _Response(
            200,
            "<!DOCTYPE html><html><head><title>WLS-WSAT</title></head><body>"
            "<h1>WebLogic WLS-WSAT</h1>"
            "<p>Web Services Atomic Transaction: CoordinatorPortType is deployed.</p>"
            "</body></html>",
        )
    return _not_found()


# --------------------------------------------------------------------------- ColdFusion
def _coldfusion(path: str, origin: str) -> _Response:
    if path.startswith("/CFIDE/administrator"):
        return _Response(
            200,
            "<!DOCTYPE html><html><head><title>ColdFusion Administrator</title></head><body>"
            "<h1>Adobe ColdFusion Administrator</h1>"
            "<p>ColdFusion Administrator version {version} — the CFIDE console login.</p>"
            "</body></html>".format(version=CORE_VERSIONS["coldfusion"]),
        )
    if path in {"/CFIDE/scripts", "/CFIDE/scripts/"}:
        return _Response(
            200,
            "<!DOCTYPE html><html><head><title>Index of /CFIDE/scripts</title></head>"
            "<body><h1>Index of /CFIDE/scripts</h1><ul>"
            '<li><a href="ajax/">ajax/</a></li>'
            '<li><a href="cfide-scripts.js">cfide-scripts.js</a></li></ul></body></html>',
        )
    if path.startswith("/CFIDE/scripts"):
        return _Response(
            200,
            "<!DOCTYPE html><html><head><title>FCKeditor file manager</title></head><body>"
            "<h1>FCKeditor</h1><p>Bundled with the ColdFusion CFIDE/scripts tree.</p>"
            "</body></html>",
        )
    return _not_found()


# --------------------------------------------------------------------------- IIS
_IIS_400 = (
    "<!DOCTYPE html><html><head><title>400 - Bad Request</title></head><body>"
    "<h1>HTTP Error 400. The request is badly formed.</h1>"
    "<p>Internet Information Services</p></body></html>"
)


def _iis(path: str, origin: str) -> _Response:
    if "~" in path:
        # The 8.3 short-name behaviour: a tilde request is refused with IIS's own 400 page.
        return _Response(
            400, _IIS_400, headers=(("Server", f"Microsoft-IIS/{CORE_VERSIONS['iis']}"),)
        )
    if path.lower() == "/trace.axd":
        return _Response(
            200,
            "<!DOCTYPE html><html><head><title>Application Trace</title></head><body>"
            "<h1>Application Trace</h1>"
            "<h2>Requests to this Application</h2>"
            "<h2>Trace Information</h2>"
            "<p>Microsoft .NET Framework / ASP.NET trace viewer.</p></body></html>",
        )
    if path.startswith(("/iisadmpwd", "/scripts/iisadmin")):
        return _Response(
            200,
            "<!DOCTYPE html><html><head><title>Internet Services Administrator</title></head>"
            "<body><h1>Internet Services Administrator</h1>"
            "<p>Password Administrator — iisadmpwd.</p></body></html>",
        )
    return _not_found()


_ROUTES: Mapping[str, Callable[[str, str], _Response]] = {
    "spring_boot": _spring_boot,
    "django": _django,
    "rails": _rails,
    "laravel": _laravel,
    "tomcat": _tomcat,
    "jboss": _jboss,
    "weblogic": _weblogic,
    "coldfusion": _coldfusion,
    "iis": _iis,
}


def _normalise(path: str) -> str:
    """The route key for a request path: no trailing slash, ``"/"`` for the root."""
    stripped = path.rstrip("/")
    return stripped or "/"


class _Handler(BaseHTTPRequestHandler):
    """One fixture: one route table per framework, differing by the lab's mode."""

    server_version = "arachne-app-lab/1.0"
    protocol_version = "HTTP/1.1"
    # Loopback Nagle/delayed-ACK stall removal, as in the shared web lab.
    disable_nagle_algorithm = True
    lab: AppServerLab

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

    def _route(self, path: str, query: Mapping[str, list[str]]) -> _Response:
        lab = self.lab
        self.lab.requests.append(f"{self.command} {self.path}")
        key = _normalise(path)
        if lab.mode == "waf" and (key != "/" or query):
            # The edge filter blocks every non-root path — actuator, debug, manager, console,
            # CFIDE and IIS alike — and its block page echoes the request and names the
            # framework, so a status-code or body-content oracle fires on it.
            return _Response(
                403,
                _WAF_BLOCK.format(
                    path=self.path,
                    framework=_FRAMEWORK_NAMES[lab.framework],
                    nonce=secrets.token_hex(4),
                ),
                headers=(("Server", "arachne-waf-lab"),),
            )
        if key == "/":
            if lab.mode == "vulnerable":
                return _Response(200, _homepage(lab.framework, lab.origin))
            return _Response(200, _production_homepage(lab.framework))
        if lab.mode in {"production", "waf"}:
            return _not_found()
        return _ROUTES[lab.framework](key, lab.origin)

    # ------------------------------------------------------------------ verbs
    def do_GET(self) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        self._send(self._route(parsed.path, query))

    def do_HEAD(self) -> None:
        self.do_GET()

    def do_OPTIONS(self) -> None:
        self.lab.requests.append(f"OPTIONS {self.path}")
        # Nothing in this fixture is reachable by any verb but GET: the family is read-only and
        # the decoys must stay unreachable by a check that tries anything else.
        self._send(_Response(405, "", headers=(("Allow", "GET, HEAD, OPTIONS"),)))

    def do_POST(self) -> None:
        self.lab.requests.append(f"POST {self.path}")
        # No route in this fixture accepts a POST: no login and no console action is possible
        # against it, which is what makes the management *surface* the only thing a check can
        # report.
        self._send(_Response(405, _NOT_FOUND, headers=(("Allow", "GET, HEAD, OPTIONS"),)))


@contextmanager
def start_app_server_lab(framework: str, mode: str = "vulnerable") -> Iterator[AppServerLab]:
    """Start one framework fixture on loopback in ``mode`` and yield its handle."""
    if framework not in FRAMEWORKS:
        raise ValueError(f"unknown framework {framework!r}; expected one of {FRAMEWORKS}")
    if mode not in MODES:
        raise ValueError(f"unknown app-lab mode {mode!r}; expected one of {MODES}")
    lab = AppServerLab(framework=framework, mode=mode)
    handler: Any = type("_BoundHandler", (_Handler,), {"lab": lab})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    server.daemon_threads = True
    port = server.server_address[1]
    lab.port = port
    lab.base_url = f"http://127.0.0.1:{port}/"
    thread = threading.Thread(
        target=server.serve_forever,
        args=(0.05,),
        name=f"arachne-app-lab-{framework}-{mode}",
        daemon=True,
    )
    thread.start()
    try:
        yield lab
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
