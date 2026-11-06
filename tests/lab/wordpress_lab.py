"""The WordPress lab: one installation served in three modes (WP-25, REQ-DET-018).

The family's acceptance needs a **positive fixture** and two **decoys**, and the requirement
names them: a stock WordPress installation, a stock *hardened* one, and one behind a web
application firewall. This module serves all three from the same route table by mode:

``vulnerable``
    A stock installation: ``readme.html`` publishes the version, ``xmlrpc.php`` answers, the
    REST API exposes the user route, ``wp-config.php.bak`` is readable, the uploads/plugins/
    themes directories are indexed, ``debug.log`` is served, the installer and the upgrade
    script answer, ``?author=N`` redirects to the login-name archive, registration is open
    and ``/wp-admin/authorize-application.php`` answers without a session.
``hardened``
    The same installation after the hardening checklist: the markup editor spill file is gone,
    XML-RPC is blocked with ``403``, the REST API answers ``401`` to anonymous callers (with
    the real ``rest_cannot_access`` error shape), the uploads/plugins/themes directories have
    indexing off, the debug log is removed, ``?author=N`` no longer redirects (author archives
    are disabled), the registration form is not served, and the installer, upgrade script and
    application-password page redirect to the login screen.
``waf``
    A **hardened** installation behind a web application firewall: the homepage carries no
    version query, and every WordPress path — and every query form of the surface
    (``?author=N``, ``?rest_route=…``) — is answered with the WAF's ``403`` block page, which
    *echoes the requested path* and the platform's name. That makes the WAF decoy the "block
    page that contains the payload" archetype of the decoy catalogue (see
    ``docs/plugin-developer-guide.md`` §2.1): a check that matched on body content rather than
    on a successful answer would fire on it.

The fixture is deliberately a *server*, not a mirror of the checks: it renders the artefacts
WordPress actually ships (the ``XML-RPC server accepts POST requests only`` notice, an RSD
document, a REST user array, an Apache ``Index of /`` page, a readme with a version line, a
``readme.txt`` with a ``Stable tag:`` header), so a check that passes here has read something
the real installation produces rather than something this module invented.

**No credential values.** The ``wp-config`` fixture declares the configuration *identifiers*
with obvious placeholder values, exactly as ``wp-config-sample.php`` does; the checks report
the identifiers, never a value, and nothing here is a usable secret.
"""

from __future__ import annotations

import json
import secrets
import threading
import urllib.parse
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

__all__ = ["WordPressLab", "start_wordpress_lab"]

#: The modes a lab can serve. ``vulnerable`` is the positive fixture; the other two are the
#: requirement's decoys.
MODES: tuple[str, ...] = ("vulnerable", "hardened", "waf")

#: The core version the vulnerable fixture publishes (a version *signal*, never a severity).
CORE_VERSION = "6.4.2"

_NOT_FOUND = (
    "<html><head><title>Nothing found</title></head><body><h1>Nothing found</h1>"
    "<p>The requested page does not exist.</p></body></html>"
)

#: The placeholder values the wp-config fixture declares. They are the sample file's own
#: placeholders, not credentials: no real secret appears anywhere in this repository.
_WP_CONFIG_SOURCE = """<?php
/**
 * The base configuration for WordPress (a lab fixture).
 *
 * @package WordPress
 */

// ** Database settings ** //
define( 'DB_NAME', 'wordpress_lab' );
define( 'DB_USER', 'wordpress_lab' );
define( 'DB_PASSWORD', 'put-your-password-here' );
define( 'DB_HOST', 'localhost' );
define( 'DB_CHARSET', 'utf8mb4' );
define( 'DB_COLLATE', '' );

define( 'AUTH_KEY',         'put your unique phrase here' );
define( 'SECURE_AUTH_KEY',  'put your unique phrase here' );
define( 'LOGGED_IN_KEY',    'put your unique phrase here' );

$table_prefix = 'wp_';

if ( ! defined( 'ABSPATH' ) ) {
\tdefine( 'ABSPATH', __DIR__ . '/' );
}
"""

_RSD = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<rsd version="1.0" xmlns="http://archipelago.phrasewise.com/rsd">\n'
    "  <service>\n"
    "    <engineName>WordPress</engineName>\n"
    "    <engineLink>https://wordpress.org/</engineLink>\n"
    "    <homePageLink>{origin}/</homePageLink>\n"
    "    <apis>\n"
    '      <api name="WordPress" blogID="1" preferred="true" '
    'apiLink="{origin}/xmlrpc.php" />\n'
    "    </apis>\n"
    "  </service>\n"
    "</rsd>\n"
)

_REST_INDEX = {
    "name": "Arachne Lab",
    "description": "A WordPress lab fixture",
    "url": "{origin}",
    "home": "{origin}",
    "gmt_offset": 0,
    "namespaces": ["oembed/1.0", "wp/v2", "wp-site-health/v1"],
    "routes": {
        "/": {"methods": ["GET"]},
        "/wp/v2/users": {"methods": ["GET"]},
        "/wp/v2/settings": {"methods": ["GET", "POST"]},
    },
}

_REST_USERS = [
    {"id": 1, "name": "Lab Administrator", "slug": "labadmin", "url": "{origin}/author/labadmin/"},
    {"id": 2, "name": "Lab Editor", "slug": "labeditor", "url": "{origin}/author/labeditor/"},
]

_REST_SETTINGS = {
    "title": "Arachne Lab",
    "description": "A WordPress lab fixture",
    "url": "{origin}",
    "email": "operator@example.test",
    "timezone": "UTC",
    "date_format": "F j, Y",
    "posts_per_page": 10,
}

_REST_APP_PASSWORDS = [
    {
        "uuid": "00000000-0000-4000-8000-0000000000a1",
        "app_id": "00000000-0000-4000-8000-0000000000b1",
        "name": "Lab deployment",
        "created": "2026-01-01T00:00:00",
        "last_used": None,
    },
]

_PLUGIN_READMES: dict[str, str] = {
    "akismet": (
        "=== Akismet Anti-spam ===\n"
        "Contributors: automattic\n"
        "Tags: spam, antispam\n"
        "Requires at least: 5.8\n"
        "Tested up to: 6.4\n"
        "Stable tag: 5.3\n\n"
        "Used by millions, Akismet is quite possibly the best way in the world to protect "
        "your blog from spam.\n"
    ),
    "contact-form-7": (
        "=== Contact Form 7 ===\n"
        "Contributors: rocklobster\n"
        "Requires at least: 6.2\n"
        "Tested up to: 6.4\n"
        "Stable tag: 5.8.4\n\n"
        "Just another contact form plugin.\n"
    ),
}

_THEME_STYLES: dict[str, str] = {
    "twentytwentyfour": (
        "/*\n"
        "Theme Name: Twenty Twenty-Four\n"
        "Theme URI: https://wordpress.org/themes/twentytwentyfour/\n"
        "Version: 1.0\n"
        "Text Domain: twentytwentyfour\n"
        "*/\n"
    ),
}

_DEBUG_LOG = (
    "[01-Jan-2026 00:00:01 UTC] PHP Notice: Function wp_enqueue_script was called "
    "incorrectly. Scripts and styles should not be registered or enqueued until the "
    "wp_enqueue_scripts hook. in /var/www/html/wp-content/themes/lab/functions.php on line 41\n"
    '[01-Jan-2026 00:00:02 UTC] PHP Warning: Undefined array key "utm_source" in '
    "/var/www/html/wp-content/plugins/lab-tools/lab-tools.php on line 88\n"
    "[01-Jan-2026 00:00:03 UTC] PHP Fatal error: Uncaught Error: Call to undefined function "
    "lab_missing() in /var/www/html/wp-content/themes/lab/inc/setup.php:12\n"
)

_HOMEPAGE = (
    '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8" />'
    "<title>Arachne Lab — WordPress</title>"
    '<meta name="generator" content="WordPress {version}" />'
    '<link rel="https://api.w.org/" href="{origin}/wp-json/" />'
    '<link rel="alternate" type="application/json" href="{origin}/wp-json/wp/v2/pages/2" />'
    '<link rel="EditURI" type="application/rsd+xml" title="RSD" href="{origin}/xmlrpc.php?rsd" />'
    '<link rel="wlwmanifest" type="application/wlwmanifest+xml" '
    'href="{origin}/wp-includes/wlwmanifest.xml" />'
    '<link rel="pingback" href="{origin}/xmlrpc.php" />'
    "</head><body>"
    "<h1>Arachne Lab</h1>"
    '<script src="{origin}/wp-includes/js/jquery/jquery.min.js?ver={version}"></script>'
    '<script src="{origin}/wp-content/plugins/lab-tools/js/tools.js?ver=1.4.1"></script>'
    '<link rel="stylesheet" href="{origin}/wp-content/themes/twentytwentyfour/style.css?ver=1.0" />'
    '<p><a href="{origin}/wp-login.php?action=register">Register</a></p>'
    "</body></html>"
)

_HARDENED_HOMEPAGE = (
    '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8" />'
    "<title>Arachne Lab — site</title>"
    "</head><body><h1>Arachne Lab</h1>"
    "<p>Nothing is published here beyond the site itself.</p>"
    "</body></html>"
)

_LOGIN_FORM = (
    "<!DOCTYPE html><html><head><title>Log In &lsaquo; Arachne Lab</title></head><body>"
    '<form name="loginform" id="loginform" action="{origin}/wp-login.php" method="post">'
    '<p><label for="user_login">Username or Email Address</label>'
    '<input type="text" name="log" id="user_login" /></p>'
    '<p><label for="user_pass">Password</label>'
    '<input type="password" name="pwd" id="user_pass" /></p>'
    '<p class="submit"><input type="submit" name="wp-submit" value="Log In" /></p>'
    "</form></body></html>"
)

_REGISTRATION_FORM = (
    "<!DOCTYPE html><html><head><title>Registration &lsaquo; Arachne Lab</title></head><body>"
    '<form name="registerform" id="registerform" '
    'action="{origin}/wp-login.php?action=register" method="post">'
    '<p><label for="user_login">Username</label>'
    '<input type="text" name="user_login" id="user_login" /></p>'
    '<p><label for="user_email">Email</label>'
    '<input type="email" name="user_email" id="user_email" /></p>'
    '<input type="hidden" name="action" value="register" />'
    '<p class="submit"><input type="submit" name="wp-submit" value="Register" /></p>'
    "</form></body></html>"
)

_AUTHORIZE_APPLICATION = (
    "<!DOCTYPE html><html><head><title>Authorize Application &lsaquo; Arachne Lab</title></head>"
    "<body><h1>Authorize Application</h1>"
    "<p>An application would like to connect to your account.</p>"
    '<form action="{origin}/wp-admin/authorize-application.php" method="post">'
    '<input type="text" name="app_name" id="app_name" value="Lab deployment" />'
    "<p>New Application Password Name</p>"
    '<input type="submit" name="authorize" value="Yes, I approve of this connection" />'
    "</form></body></html>"
)

_INSTALLER = (
    "<!DOCTYPE html><html><head><title>Installation &rsaquo; Arachne Lab</title></head><body>"
    "<h1>Already Installed</h1>"
    "<p>You appear to have already installed WordPress. To reinstall please clear your old "
    "database tables.</p></body></html>"
)

_UPGRADE = (
    "<!DOCTYPE html><html><head><title>Update &rsaquo; Arachne Lab</title></head><body>"
    "<h1>Database Update Required</h1>"
    "<p>WordPress has been updated! Before we send you on your way, we need to update your "
    "database to the newest version.</p></body></html>"
)

_README_HTML = (
    "<!DOCTYPE html><html><head><title>WordPress &rsaquo; ReadMe</title></head><body>"
    '<h1 id="logo">WordPress</h1>'
    "<br /> Version {version}"
    "<p>Semantic Personal Publishing Platform</p></body></html>"
)

_WAF_BLOCK = (
    "<!DOCTYPE html><html><head><title>Request blocked</title></head><body>"
    "<h1>Request blocked</h1>"
    "<p>Your request to <code>{path}</code> was blocked by the web application firewall. "
    "This site runs WordPress; administrative and content paths are protected.</p>"
    "<p>If you believe this is an error, contact the site operator and quote reference "
    "{nonce}.</p></body></html>"
)


@dataclass
class WordPressLab:
    """A running WordPress fixture: its origin, its mode and the requests it answered."""

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


def _json_response(document: object, *, status: int = 200) -> _Response:
    return _Response(status, json.dumps(document), "application/json; charset=utf-8")


def _listing(title: str, entries: tuple[str, ...]) -> _Response:
    rows = "".join(f'<li><a href="{entry}">{entry}</a></li>' for entry in entries)
    return _Response(
        200,
        f"<!DOCTYPE html><html><head><title>Index of {title}</title></head><body>"
        f"<h1>Index of {title}</h1><ul>{rows}</ul></body></html>",
    )


class _Handler(BaseHTTPRequestHandler):
    """The installation: one route table, differing by the lab's mode."""

    server_version = "arachne-wp-lab/1.0"
    protocol_version = "HTTP/1.1"
    # Loopback Nagle/delayed-ACK stall removal, as in the shared web lab.
    disable_nagle_algorithm = True
    lab: WordPressLab

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

    def _route(self, path: str, query: dict[str, list[str]]) -> _Response:
        lab = self.lab
        origin = lab.origin
        self.lab.requests.append(f"{self.command} {self.path}")
        if lab.mode == "waf" and (path != "/" or query):
            # The edge filter blocks every WordPress path *and* every query form of the
            # surface (?author=N, ?rest_route=...), and its block page echoes the request so
            # a check that matched on body content rather than on a successful answer fires.
            return _Response(
                403,
                _WAF_BLOCK.format(path=self.path, nonce=secrets.token_hex(4)),
                headers=(("Server", "arachne-waf-lab"),),
            )
        if lab.mode in {"hardened", "waf"}:
            return _hardened(path, query, origin)
        return _vulnerable(path, query, origin)

    # ------------------------------------------------------------------ verbs
    def do_GET(self) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        self._send(self._route(parsed.path.rstrip("/") or "/", query))

    def do_HEAD(self) -> None:
        self.do_GET()

    def do_OPTIONS(self) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        path = parsed.path.rstrip("/") or "/"
        self.lab.requests.append(f"OPTIONS {self.path}")
        if path == "/wp-cron.php":
            if self.lab.mode == "vulnerable":
                # A served cron endpoint advertises the methods it accepts. The fixture
                # answers OPTIONS without running anything, which is what makes the check's
                # probe side-effect-free against this installation.
                self._send(_Response(200, "", headers=(("Allow", "GET, POST, OPTIONS"),)))
            else:
                # Both decoys block the endpoint, which is what the check reports as clean.
                self._send(_Response(403, "<html><body><h1>Forbidden</h1></body></html>"))
            return
        self._send(_Response(405, "", headers=(("Allow", "GET, HEAD, OPTIONS"),)))

    def do_POST(self) -> None:
        self.lab.requests.append(f"POST {self.path}")
        # Nothing in this fixture accepts a POST: the family is read-only, and the decoys
        # must not be reachable by a check that tries to change state.
        self._send(_Response(405, _NOT_FOUND, headers=(("Allow", "GET, HEAD, OPTIONS"),)))


def _vulnerable(path: str, query: dict[str, list[str]], origin: str) -> _Response:
    """The stock installation: every artefact the family's checks establish."""
    if path == "/" and query.get("author"):
        slug = "labadmin" if query["author"][0] == "1" else "labeditor"
        return _Response(302, "", headers=(("Location", f"{origin}/author/{slug}/"),))
    if path == "/" and "rest_route" in query:
        if query["rest_route"] == ["/wp/v2/users"]:
            return _json_response(json.loads(json.dumps(_REST_USERS).replace("{origin}", origin)))
        return _Response(404, _NOT_FOUND)
    if path in {"/", ""}:
        return _Response(200, _HOMEPAGE.format(origin=origin, version=CORE_VERSION))
    if path == "/wp-config.php" or path == "/wp-config.txt":
        return _Response(200, _WP_CONFIG_SOURCE, "text/plain; charset=utf-8")
    if path.startswith("/wp-config") and path.endswith(
        (".bak", "~", ".save", ".old", ".orig", ".txt", ".bkp", ".disabled")
    ):
        return _Response(200, _WP_CONFIG_SOURCE, "application/octet-stream")
    if path == "/xmlrpc.php":
        if "rsd" in query:
            return _Response(200, _RSD.format(origin=origin), "application/rsd+xml; charset=utf-8")
        return _Response(405, "XML-RPC server accepts POST requests only.")
    if path == "/wp-json":
        return _json_response(json.loads(json.dumps(_REST_INDEX).replace("{origin}", origin)))
    if path == "/wp-json/wp/v2/users":
        return _json_response(json.loads(json.dumps(_REST_USERS).replace("{origin}", origin)))
    if path == "/wp-json/wp/v2/users/1":
        return _json_response(
            {
                "id": 1,
                "name": "Lab Administrator",
                "slug": "labadmin",
                "url": f"{origin}/author/labadmin/",
            }
        )
    if path == "/wp-json/wp/v2/settings":
        return _json_response(json.loads(json.dumps(_REST_SETTINGS).replace("{origin}", origin)))
    if path == "/wp-json/wp/v2/users/1/application-passwords":
        return _json_response(_REST_APP_PASSWORDS)
    if path == "/wp-content/uploads":
        return _listing("/wp-content/uploads", ("2026/", "2025/", "arachne-probe.txt"))
    if path == "/wp-content/plugins":
        return _listing("/wp-content/plugins", ("akismet/", "contact-form-7/", "lab-tools/"))
    if path == "/wp-content/themes":
        return _listing("/wp-content/themes", ("twentytwentyfour/", "lab-theme/"))
    if path.startswith("/wp-content/plugins/") and path.endswith("/readme.txt"):
        slug = path.split("/")[3]
        readme = _PLUGIN_READMES.get(slug)
        if readme is not None:
            return _Response(200, readme, "text/plain; charset=utf-8")
    if path.startswith("/wp-content/themes/") and path.endswith("/style.css"):
        slug = path.split("/")[3]
        style = _THEME_STYLES.get(slug)
        if style is not None:
            return _Response(200, style, "text/css; charset=utf-8")
    if path == "/readme.html":
        return _Response(200, _README_HTML.format(version=CORE_VERSION))
    if path == "/wp-content/debug.log":
        return _Response(200, _DEBUG_LOG, "text/plain; charset=utf-8")
    if path == "/wp-admin/install.php":
        return _Response(200, _INSTALLER)
    if path == "/wp-admin/upgrade.php":
        return _Response(200, _UPGRADE)
    if path == "/wp-admin/admin-ajax.php":
        return _json_response({"actions": ["heartbeat", "lab_public_stats"], "nopriv": True})
    if path == "/wp-login.php":
        if query.get("action") == ["register"]:
            return _Response(200, _REGISTRATION_FORM.format(origin=origin))
        return _Response(200, _LOGIN_FORM.format(origin=origin))
    if path == "/wp-admin/authorize-application.php":
        return _Response(200, _AUTHORIZE_APPLICATION.format(origin=origin))
    if path == "/wp-sitemap-users-1.xml":
        return _Response(
            200,
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
            f"<url><loc>{origin}/author/labadmin/</loc></url>"
            f"<url><loc>{origin}/author/labeditor/</loc></url>"
            "</urlset>",
            "application/xml; charset=utf-8",
        )
    if path == "/wp-cron.php":
        # A GET would run due jobs; the fixture has none registered, and no check sends one.
        return _Response(200, "")
    return _Response(404, _NOT_FOUND)


def _hardened(path: str, _query: dict[str, list[str]], origin: str) -> _Response:
    """The hardened installation: the same paths, none of the signals."""
    if path in {"/", ""}:
        return _Response(200, _HARDENED_HOMEPAGE)
    if path.startswith("/wp-config") or path == "/wp-content/debug.log":
        return _Response(403, "<html><body><h1>Forbidden</h1></body></html>")
    if path in {"/xmlrpc.php"}:
        return _Response(403, "<html><body><h1>XML-RPC services are disabled.</h1></body></html>")
    if path == "/wp-cron.php":
        return _Response(403, "<html><body><h1>Forbidden</h1></body></html>")
    if path.startswith("/wp-json"):
        # The real WordPress shape for an anonymous caller the REST API refuses.
        return _Response(
            401,
            json.dumps(
                {
                    "code": "rest_cannot_access",
                    "message": "Only authenticated users can access the REST API.",
                    "data": {"status": 401},
                }
            ),
            "application/json; charset=utf-8",
        )
    if path.startswith(("/wp-content/uploads", "/wp-content/plugins", "/wp-content/themes")):
        return _Response(403, "<html><body><h1>Forbidden</h1></body></html>")
    if path in {"/readme.html", "/readme.txt", "/wp-sitemap-users-1.xml"}:
        return _Response(404, _NOT_FOUND)
    if path in {"/wp-admin/install.php", "/wp-admin/upgrade.php"}:
        return _Response(302, "", headers=(("Location", f"{origin}/wp-login.php"),))
    if path == "/wp-admin/authorize-application.php":
        return _Response(302, "", headers=(("Location", f"{origin}/wp-login.php"),))
    if path == "/wp-admin/admin-ajax.php":
        return _Response(400, "0", "text/plain; charset=utf-8")
    if path == "/wp-login.php":
        # Registration is closed: the login form is served and the register action is not.
        return _Response(200, _LOGIN_FORM.format(origin=origin))
    # ``/?author=N`` and ``/?rest_route=...`` reach the root branch above, which answers the
    # hardened homepage and the REST refusal respectively — no author redirect, no user list.
    return _Response(404, _NOT_FOUND)


@contextmanager
def start_wordpress_lab(mode: str = "vulnerable") -> Iterator[WordPressLab]:
    """Start one WordPress fixture on loopback in ``mode`` and yield its handle."""
    if mode not in MODES:
        raise ValueError(f"unknown WordPress lab mode {mode!r}; expected one of {MODES}")
    lab = WordPressLab(mode=mode)
    handler: Any = type("_BoundHandler", (_Handler,), {"lab": lab})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    server.daemon_threads = True
    port = server.server_address[1]
    lab.port = port
    lab.base_url = f"http://127.0.0.1:{port}/"
    thread = threading.Thread(
        target=server.serve_forever,
        args=(0.05,),
        name=f"arachne-wp-lab-{mode}",
        daemon=True,
    )
    thread.start()
    try:
        yield lab
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
