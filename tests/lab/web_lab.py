"""A stdlib-only vulnerable *web* lab: real HTTP on loopback, no Docker required.

 wants the integration layer to run against the Docker compose lab (DVWA,
OWASP Juice Shop, a misconfigured Nginx). That fixture exists (``docker/docker-compose.yml``,
``docker/lab/``), but the S6 acceptance criteria — "find ≥ 60% of the planted vulnerabilities,
false-positive rate ≤ 15%" — need a lab whose *planted set is known and checkable*, and a
container runtime is not available in every environment. So this module starts a small
vulnerable-by-design application in-process, modelled on the DVWA / Juice Shop patterns the M3
tables name, and publishes the ground truth beside it.

===============================  ============================================
route                             what it plants
===============================  ============================================
``/search?q=``                    reflected XSS (raw echo in HTML body)
``/profile?name=``                reflected XSS (raw echo inside an attribute)
``/product?category=``            SQL injection (MySQL error text + boolean delta)
``/download?file=``               path traversal (``/etc/passwd`` header lines)
``/upload``                       unrestricted upload (.php accepted, then served)
``/redirect?next=``               open redirect (Location reflects any host)
``/api/user?id=``                 IDOR (sequential ids, unauthenticated JSON records)
``/account/settings``             CSRF (POST form, no token, no SameSite cookie)
``/api/config``                   permissive CORS (origin reflected + credentials)
``/login``                        HTTP login form; user enumeration differential
``/login-fast``                   (control) throttles: 429 after two requests
``/admin/``                       hidden endpoint (200, not linked anywhere)
``/``                             cookies without flags; headers absent
===============================  ============================================

**Controls** (the false-positive traps) live on the same origin: an HTML-escaped search, a
traversal-hardened download, a relative-only redirect, a fixed CORS allowlist, a token-bearing
form, an extension-allowlisted upload, an authenticated user API, and an SPA catch-all
(``/api/v1`` answers the application shell with 200) — every one of which a naive check would
report and a precise one must not.

Everything binds to ``127.0.0.1`` on an ephemeral port and is torn down by the context
manager, so the suite can run in parallel with itself.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import threading
import urllib.parse
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from tests.lab import graphql_lab

#: RFC 6455's handshake GUID and the frame opcodes the WebSocket fixtures use. The lab
#: implements its own framing (rather than importing the scanner's) so a change in the
#: scanner's encoder cannot silently redefine what the fixture answers.
_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
_WS_TEXT, _WS_BINARY, _WS_CLOSE, _WS_PING, _WS_PONG = 0x1, 0x2, 0x8, 0x9, 0xA
_WS_MAX_FRAME = 65536


#: The planted web root the M6 webshell scan reads on disk (a clone we can see) — the same
#: content one of the lab routes serves, so both halves of ``m6.webshell-yara`` share a seed.
WEBROOT_FIXTURE: Path = Path(__file__).resolve().parents[1] / "fixtures" / "webroot"

__all__ = [
    "DEPTH_FALSE_POSITIVE_TRAPS",
    "DEPTH_GROUND_TRUTH",
    "FALSE_POSITIVE_TRAPS",
    "GROUND_TRUTH",
    "M3X_FALSE_POSITIVE_TRAPS",
    "M3X_GROUND_TRUTH",
    "M4_FALSE_POSITIVE_TRAPS",
    "M4_GROUND_TRUTH",
    "M6_FALSE_POSITIVE_TRAPS",
    "M6_GROUND_TRUTH",
    "STORAGE_PREFIX",
    "WebLab",
    "start_web_lab",
]

#: Documented planted vulnerabilities: ``(check id, marker)`` where the marker must appear in
#: the candidate's endpoint/parameter/origin evidence for the detection to count as a true
#: positive. A single route may plant more than one family (``/login`` carries the transport
#: finding, the enumeration differential *and* a token-less POST form), which is why this is a
#: list of expectations rather than of routes. It is deliberately explicit rather than derived
#: from the routes: the acceptance number means nothing if the ground truth is inferred from
#: whatever the scanner happened to report.
GROUND_TRUTH: tuple[tuple[str, str], ...] = (
    ("m3.sqli-oracle", "/product"),
    ("m3.xss-oracle", "/search"),
    ("m3.xss-oracle", "/profile"),
    ("m3.traversal-oracle", "/download"),
    ("m3.upload-audit", "/upload"),
    ("m3.open-redirect", "/redirect"),
    ("m3.idor-oracle", "/api/user?"),
    # Every POST form in the lab is token-less and the session cookie has no SameSite policy,
    # which is the two-part CSRF condition of research ch03#4 — including login CSRF.
    ("m3.csrf-audit", "/account/settings"),
    ("m3.csrf-audit", "/login"),
    ("m3.csrf-audit", "/upload"),
    ("m3.cors-audit", "/api/config"),
    ("m3.rate-limit-audit", "/login"),
    ("m3.auth-session-audit", "/login"),
    ("m3.auth-session-audit", "127.0.0.1:"),
    ("m3.security-headers", "127.0.0.1:"),
    ("m3.api-surface", "/admin"),
    # S19: the authenticated area. These only exist for a credentialed scan: the surface
    # itself, and the logout that leaves the server-side session alive (/logout-soft).
    ("m3.authenticated-surface", "/portal/admin"),
    ("m3.session-logout", "/logout-soft"),
)

#: (check id, marker) pairs that must **not** appear: the hardened counterparts. A candidate
#: matching one of these is a false positive.
FALSE_POSITIVE_TRAPS: tuple[tuple[str, str], ...] = (
    ("m3.xss-oracle", "/safe-search"),
    ("m3.xss-oracle", "/product"),
    ("m3.traversal-oracle", "/hardened-download"),
    ("m3.open-redirect", "/api/safe-redirect"),
    ("m3.cors-audit", "/api/config-fixed"),
    ("m3.csrf-audit", "/notes-fixed"),
    ("m3.upload-audit", "/upload-hardened"),
    ("m3.idor-oracle", "/api/user-fixed"),
    ("m3.rate-limit-audit", "/login-fast"),
    ("m3.api-surface", "/api/v1"),
)

#: The S7 planted set (see ``docs/adr/120-stage-7-m4-misconfiguration-exposure.md``). Same
#: shape as :data:`GROUND_TRUTH`: ``(check id, marker)`` where the marker must appear in the
#: candidate's evidence. The lab mixes the misconfigured-Nginx fixture's exposures (a
#: deployed ``.env``, ``.git`` metadata, a backup dump, directory listing, an unauthenticated
#: Jenkins, an S3-shaped bucket) with the transport checks of the same module.
M4_GROUND_TRUTH: tuple[tuple[str, str], ...] = (
    ("m4.env-file-probe", "/.env"),
    ("m4.vcs-exposure", "/.git/HEAD"),
    ("m4.vcs-exposure", "/.git/config"),
    ("m4.vcs-exposure", "/.git/packed-refs"),
    ("m4.backup-file-hunt", "/backup/db.sql"),
    ("m4.backup-file-hunt", "/backup/site.zip"),
    ("m4.backup-file-hunt", "/index.php.bak"),
    ("m4.directory-listing", "/files"),
    ("m4.dashboard-exposure", "/jenkins"),
    ("m4.dashboard-exposure", "/grafana"),
    ("m4.dashboard-exposure", "/phpmyadmin"),
    ("m4.bucket-exposure", "/storage/backup"),
    ("m4.api-doc-exposure", "/swagger.json"),
    ("m4.sourcemap-exposure", "/app.js.map"),
    ("m4.key-exposure", "/id_rsa"),
    ("m4.debug-endpoints", "/phpinfo.php"),
    ("m4.debug-endpoints", "/actuator/env"),
    ("m4.actuator-exposure", "/actuator/env"),
    ("m4.alias-traversal", "/download"),
    ("m4.client-secrets", "/app.js"),
    ("m4.unauth-api-audit", "/api/internal/users"),
    ("m4.staging-exposure", "/staging"),
    ("m4.webdav-verbs", "/dav"),
    ("m4.security-header-review", "127.0.0.1:"),
    ("m4.cookie-flag-audit", "127.0.0.1:"),
    ("m4.cors-config-review", "/api/config"),
    ("m4.user-enumeration", "/login"),
    # A route can legitimately be reported by two families (hidden-endpoint discovery and
    # the staging check both see /staging); each is its own expectation.
    ("m4.hidden-endpoint-hunt", "/admin"),
    ("m4.hidden-endpoint-hunt", "/staging"),
)

#: The M4 hardened counterparts: a candidate matching one of these is a false positive.
M4_FALSE_POSITIVE_TRAPS: tuple[tuple[str, str], ...] = (
    ("m4.env-file-probe", "/.env.local"),
    ("m4.env-file-probe", "/.env.production"),
    ("m4.backup-file-hunt", "/backup/safe.sql"),
    ("m4.directory-listing", "/files-hardened"),
    ("m4.dashboard-exposure", "/kibana"),
    ("m4.bucket-exposure", "/storage/private"),
    ("m4.debug-endpoints", "/health"),
    ("m4.key-exposure", "/id_rsa-hardened"),
    ("m4.sourcemap-exposure", "/app-hardened.js"),
    ("m4.webdav-verbs", "/dav-hardened"),
    ("m4.unauth-api-audit", "/api/orders"),
    ("m4.cors-config-review", "/api/config-fixed"),
)

#: The path prefix the bucket fixture lives under. A declared ``cloud`` target of the form
#: ``endpoint:http://<host>/storage/backup`` makes ``m4.bucket-exposure`` probe it.
STORAGE_PREFIX = "/storage"

#: The S10 (M3 extended) planted set (see ``docs/adr/150-stage-10-m3-extended-m5.md``). Same
#: ``(check id, marker)`` shape as :data:`GROUND_TRUTH`: the marker must appear in the
#: candidate's evidence. The routes model the Juice-Shop-class advanced scenarios the stage
#: names — template injection, XXE, command injection, deserialization, smuggling, cache
#: poisoning, JWT/OAuth/SAML, HPP, mass assignment, prototype pollution, GraphQL, WebSocket,
#: business logic, race and subdomain takeover.
M3X_GROUND_TRUTH: tuple[tuple[str, str], ...] = (
    ("m3.ssti-oracle", "ssti"),
    ("m3.xxe-oracle", "xxe"),
    ("m3.cmdi-oracle", "command-injection"),
    ("m3.deser-audit", "deserialization"),
    ("m3.smuggling-oracle", "request-smuggling"),
    ("m3.cache-poison-audit", "cache-poisoning"),
    ("m3.hpp-oracle", "http-parameter-pollution"),
    ("m3.mass-assign-audit", "mass-assignment"),
    ("m3.proto-pollution", "prototype-pollution"),
    ("m3.graphql-audit", "graphql"),
    ("m3.websocket-audit", "websocket"),
    ("m3.business-logic-audit", "business-logic"),
    ("m3.race-oracle", "race-condition"),
    ("m3.oauth-flow-audit", "oauth"),
    ("m3.saml-audit", "saml"),
    ("m3.jwt-audit", "jwt"),
    ("m3.subdomain-takeover", "subdomain-takeover"),
)

#: The M3-extended hardened counterparts: a candidate matching one of these is a false positive.
M3X_FALSE_POSITIVE_TRAPS: tuple[tuple[str, str], ...] = (
    ("m3.ssti-oracle", "/safe-template"),
    ("m3.xxe-oracle", "/safe-xml"),
    ("m3.cmdi-oracle", "/safe-ping"),
    ("m3.smuggling-oracle", "/smuggle-safe"),
    ("m3.cache-poison-audit", "/cache-safe"),
    ("m3.graphql-audit", "/graphql-safe"),
    ("m3.websocket-audit", "/ws-safe"),
    ("m3.business-logic-audit", "/checkout-safe"),
    ("m3.oauth-flow-audit", "/oauth/authorize-safe"),
    ("m3.saml-audit", "/saml/acs-safe"),
)

#: S29 depth-expansion ground truth (REQ-DEPTH-001/002): ``(check id, marker)`` in the same
#: shape as :data:`M3X_GROUND_TRUTH`, but kept separate because every one of these checks is
#: opt-in twice over (outside the default set *and* behind a deployment switch), so the S10
#: acceptance suite — which runs the default switch state — must not be asked to report them.
#: The GraphQL engine at ``/graphql`` bounds neither depth nor aliases and answers
#: sensitive-named resolvers with no credential; ``/ws`` neither validates the Origin nor
#: requires a credential at the upgrade and echoes what it is sent.
DEPTH_GROUND_TRUTH: tuple[tuple[str, str], ...] = (
    ("m3.graphql-depth-abuse", "graphql"),
    ("m3.graphql-resolver-auth", "graphql"),
    ("m3.websocket-upgrade-auth", "websocket"),
    ("m3.websocket-injection", "websocket"),
)

#: The S29 hardened counterparts: a candidate matching one of these is a false positive.
#: ``/graphql-safe`` enforces a depth limit, an alias limit and authorization and disables
#: introspection; ``/ws-safe`` validates the Origin and demands a credential.
DEPTH_FALSE_POSITIVE_TRAPS: tuple[tuple[str, str], ...] = (
    ("m3.graphql-depth-abuse", "/graphql-safe"),
    ("m3.graphql-resolver-auth", "/graphql-safe"),
    ("m3.websocket-upgrade-auth", "/ws-safe"),
    ("m3.websocket-injection", "/ws-safe"),
)


#: M6 (S11) ground truth on the served surface: ``(check id, marker)``. The webshell is served
#: at ``/uploads/shell.php`` (the same content the on-disk web-root fixture holds); the GenAI
#: family is an exposed model endpoint and an exposed system prompt.
M6_GROUND_TRUTH: tuple[tuple[str, str], ...] = (
    ("m6.webshell-yara", "/uploads/shell.php"),
    ("m6.attack-surface-genai", "/v1/chat/completions"),
    ("m6.attack-surface-genai", "/assistant/system-prompt.txt"),
)

#: M6 controls: a benign script and a denied shell path must not be reported.
M6_FALSE_POSITIVE_TRAPS: tuple[tuple[str, str], ...] = (
    ("m6.webshell-yara", "/safe-shell.php"),
    ("m6.webshell-yara", "/uploads/denied.php"),
)


#: A JWT signed with the deliberately weak secret ``secret`` (HS256). The ``m3.jwt-audit``
#: check recovers the secret offline from the token in ``/app.js``.
def _weak_jwt() -> str:
    import base64
    import hashlib
    import hmac

    def enc(value: bytes) -> str:
        return base64.urlsafe_b64encode(value).rstrip(b"=").decode()

    header = enc(b'{"alg":"HS256","typ":"JWT"}')
    payload = enc(b'{"sub":"alice","role":"user"}')
    signing_input = f"{header}.{payload}"
    signature = enc(hmac.new(b"secret", signing_input.encode(), hashlib.sha256).digest())
    return f"{signing_input}.{signature}"


_WEAK_JWT = _weak_jwt()

_SSTI_PAGE = "<html><body><h1>Hello {name}</h1></body></html>"
_SAFE_TEMPLATE = "<html><body><h1>Hello guest</h1></body></html>"
_PASSWD = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin/nologin\n"
#: The GraphQL routes are served by a real (small) engine — see ``tests/lab/graphql_lab.py``.
_GITHUB_PAGES_TAKEOVER = (
    "<!doctype html><html><head><title>GitHub Pages</title></head><body>"
    "<h1>404</h1><p>There isn't a GitHub Pages site here.</p></body></html>"
)

_ENV_BODY = (
    "# deployed by mistake\n"
    "APP_ENV=production\n"
    "APP_KEY=base64:AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=\n"
    "DB_HOST=db.internal.arachne.test\n"
    "DB_DATABASE=arachne\n"
    "DB_USERNAME=arachne\n"
    "DB_PASSWORD=sup3rs3cr3t-db-password\n"
    "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
    "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
    "MAIL_PASSWORD=mailgun-not-really-a-password\n"
)

_PHP_CONFIG = (
    "<?php\n"
    "$db_host = 'db.internal.arachne.test';\n"
    "$db_user = 'arachne';\n"
    "$db_password = 'php-config-db-password';\n"
    "$api_secret = 'php-config-api-secret-value';\n"
    "?>\n"
)

_GIT_HEAD = "ref: refs/heads/main\n"
_GIT_CONFIG = (
    "[core]\n"
    "\trepositoryformatversion = 0\n"
    "\tfilemode = true\n"
    "\tbare = false\n"
    '[remote "origin"]\n'
    "\turl = git@github.com:arachne/vulnerable-lab.git\n"
)
_GIT_PACKED_REFS = "# pack-refs with: peeled fully-peeled sorted\nabc123 refs/heads/main\n"

_SQL_DUMP = (
    "-- MySQL dump 10.13  Distrib 5.7.44, for Linux (x86_64)\n"
    "--\n"
    "-- Host: db.internal    Database: arachne\n"
    "CREATE TABLE `users` (`id` int(11) NOT NULL, `email` varchar(255));\n"
    "INSERT INTO `users` VALUES (1,'alice@example.com'),(2,'bob@example.com');\n"
)

_PHP_BACKUP = (
    "<?php\n"
    "// old revision kept by the editor\n"
    "define('DB_PASSWORD', 'backup-file-db-password');\n"
    "function login($user, $pass) { return true; }\n"
)

_DIRECTORY_LISTING = (
    "<!doctype html><html><head><title>Index of /files</title></head><body>"
    "<h1>Index of /files</h1><pre>"
    "<a href='?C=N;O=D'>Name</a>"
    "<a href='/backup/'>backup/</a>"
    "<a href='dump.sql'>dump.sql</a>"
    "<a href='report.pdf'>report.pdf</a>"
    "<a href='users.csv'>users.csv</a>"
    "</pre></body></html>"
)

_JENKINS = (
    "<!doctype html><html><head><title>Dashboard [Jenkins]</title></head><body>"
    "<h1>Dashboard [Jenkins]</h1><p>Welcome to Jenkins</p>"
    "<a href='/jenkins/manage'>Manage Jenkins</a>"
    "<a href='/jenkins/script'>Script Console</a></body></html>"
)

_GRAFANA_LOGIN = (
    "<!doctype html><html><head><title>Grafana</title></head><body>"
    "<h1>Grafana</h1><form action='/grafana/login' method='post'>"
    "<input type='text' name='user'><input type='password' name='password'>"
    "<button>Sign in</button></form></body></html>"
)

_PHPMYADMIN = (
    "<!doctype html><html><head><title>phpMyAdmin</title></head><body>"
    "<h1>phpMyAdmin</h1><form method='post'>"
    "<input name='pma_username'><input type='password' name='pma_password'>"
    "</form></body></html>"
)

_PHPINFO = (
    "<!doctype html><html><head><title>phpinfo()</title></head><body>"
    "<h1>PHP Version 7.4.33</h1>"
    "<table><tr><td>phpinfo()</td></tr>"
    "<tr><td>DOCUMENT_ROOT</td><td>/var/www/html</td></tr>"
    "<tr><td>PHP Credits</td><td></td></tr></table></body></html>"
)

_SERVER_STATUS = (
    "<!doctype html><html><head><title>Apache Status</title></head><body>"
    "<h1>Apache Server Status for 127.0.0.1</h1>"
    "<p>Server uptime: 3 days</p>"
    "<p>2 requests currently being processed, 8 idle workers</p></body></html>"
)

_OPENAPI = json.dumps(
    {
        "openapi": "3.0.1",
        "info": {"title": "Arachne Lab API", "version": "1.0.0"},
        "paths": {
            "/api/orders": {"get": {"summary": "List orders"}},
            "/api/internal/users": {"get": {"summary": "Internal user directory"}},
            "/api/internal/metrics": {"get": {"summary": "Internal metrics"}},
        },
    }
)

_INTERNAL_USERS = json.dumps(
    {
        "users": [
            {"id": 1, "email": "alice@example.com", "role": "admin"},
            {"id": 2, "email": "bob@example.com", "role": "user"},
        ]
    }
)

_ORDERS_REQUIRES_AUTH = json.dumps({"error": "authentication required"})

_APP_JS = (
    "var apiBase = '/api';\n"
    "var config = {aws_access_key_id: 'AKIAIOSFODNN7EXAMPLE', region: 'eu-west-1'};\n"
    # S29 (REQ-DEPTH-004): the API routes this bundle calls. One answers anonymously
    # (/api/internal/users) and one requires a credential (/api/orders) — the two halves of
    # m3.client-secret-verify's control. Written as full literal paths, which is how a
    # bundler usually emits them and what a static route extractor can read.
    "var users = '/api/internal/users';\n"
    "var orders = '/api/orders';\n"
    # ...and the DOM sink/source shapes a static reading looks for: a query-string source fed
    # into an HTML sink, a hash source into document.write, and a dynamic-code sink fed a
    # variable. Nothing here executes in this scanner (ADR-100.4).
    "var params = new URLSearchParams(location.search);\n"
    "document.getElementById('out').innerHTML = params.get('q');\n"
    "var note = location.hash;\n"
    "document.write(note);\n"
    "var region = config.region;\n"
    "eval(region);\n"
    "//# sourceMappingURL=app.js.map\n"
)

_APP_MAP = json.dumps(
    {
        "version": 3,
        "file": "app.js",
        "sources": ["webpack:///./src/config.ts", "webpack:///./src/api.ts"],
        "sourcesContent": [
            "export const config = { apiKey: 'AIzaSyA-not-a-real-google-key-value-000' };",
            "export const base = '/api/internal/users';",
        ],
        "mappings": "AAAA",
    }
)

_APP_JS_HARDENED = "var apiBase = '/api';\n"

_RSA_KEY = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEowIBAAKCAQEAx7Vv3Zk8q1l0YQk9m2n5v8b1c4d7e0f3a6b9c2d5e8f1a4b7c0\n"
    "d3e6f9a2b5c8d1e4f7a0b3c6d9e2f5a8b1c4d7e0f3a6b9c2d5e8f1a4b7c0d3e6\n"
    "-----END RSA PRIVATE KEY-----\n"
)

_ACTUATOR_INDEX = json.dumps({"_links": {"self": {"href": "/actuator"}, "health": {}}})

_ACTUATOR_ENV = json.dumps(
    {
        "activeProfiles": ["prod"],
        "propertySources": [
            {
                "name": "systemEnvironment",
                "properties": {
                    "spring.datasource.password": {"value": "actuator-db-password"},
                    "spring.datasource.url": {"value": "jdbc:mysql://db:3306/app"},
                },
            }
        ],
    }
)

_STAGING_PAGE = (
    "<!doctype html><html><head><title>Arachne Lab (staging)</title></head><body>"
    "<h1>Staging environment</h1>"
    "<p>Not for production use. Debug logging is enabled.</p>"
    "</body></html>"
)

_BUCKET_LISTING = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    "<ListBucketResult><Name>backup</Name><IsTruncated>false</IsTruncated>"
    "<Contents><Key>dump.sql</Key><Size>2048</Size></Contents>"
    "<Contents><Key>users.csv</Key><Size>512</Size></Contents>"
    "</ListBucketResult>"
)

_BUCKET_ACL = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    "<AccessControlPolicy><Owner><ID>lab</ID></Owner>"
    "<AccessControlList><Grant><Grantee><ID>AllUsers</ID></Grantee>"
    "<Permission>READ</Permission></Grant></AccessControlList>"
    "</AccessControlPolicy>"
)

_IMDS_V1 = "ami-id\nami-launch-index\niam/\ninstance-id\nplacement/\n"

_ZIP_BYTES = b"PK\x03\x04\x14\x00\x00\x00\x00\x00" + bytes(64) + b"lab-backup-archive"

_HTML_SHELL = (
    "<!doctype html><html lang='en'><head><title>Arachne Lab</title>"
    "<meta name='generator' content='arachne-lab'>"
    "</head><body><h1>Vulnerable web lab</h1>"
    "<ul>"
    "<li><a href='/search?q=hello'>search</a></li>"
    "<li><a href='/profile?name=guest'>profile</a></li>"
    "<li><a href='/product?category=1'>products</a></li>"
    "<li><a href='/download?file=readme.txt'>download</a></li>"
    "<li><a href='/redirect?next=/home'>redirect</a></li>"
    "<li><a href='/api/user?id=1'>user</a></li>"
    "<li><a href='/api/config'>config</a></li>"
    "<li><a href='/safe-search?q=hello'>safe search</a></li>"
    "<li><a href='/hardened-download?file=readme.txt'>safe download</a></li>"
    "<li><a href='/api/safe-redirect?next=/home'>safe redirect</a></li>"
    "<li><a href='/api/config-fixed'>fixed cors</a></li>"
    "<li><a href='/api/user-fixed?id=1'>protected user</a></li>"
    "<li><a href='/login-fast'>throttled login api</a></li>"
    "<li><a href='/notes-fixed'>protected form</a></li>"
    # S7: the SSRF sink the metadata check looks for (a URL-fetching parameter).
    "<li><a href='/fetch?url=/home'>fetch</a></li>"
    "</ul>"
    # S7: a bundle the crawl must fetch so m4.client-secrets and
    # m4.sourcemap-exposure have something to read.
    "<script src='/app.js'></script>"
    # S10: the M3-extended surface, linked so the crawl reaches it (the oracles probe
    # parameters and forms the crawl records).
    "<ul>"
    "<li><a href='/ssti?name=guest'>template</a></li>"
    "<li><a href='/cache-me'>cache</a></li>"
    "<li><a href='/hpp?role=user'>pollution</a></li>"
    "<li><a href='/checkout?qty=1'>checkout</a></li>"
    "<li><a href='/oauth/authorize?redirect_uri=/home'>oauth</a></li>"
    "<li><a href='/redeem'>redeem</a></li>"
    "<li><a href='/takeover-alias'>alias</a></li>"
    "<li><a href='/ping?host=127.0.0.1'>ping</a></li>"
    "<li><a href='/rce-blind?host=127.0.0.1'>rce-blind</a></li>"
    "<li><a href='/graphql'>graphql</a></li>"
    "<li><a href='/ws'>websocket</a></li>"
    "<li><a href='/api/profile'>profile</a></li>"
    "<li><a href='/merge'>merge</a></li>"
    "<li><a href='/xxe'>xml</a></li>"
    "<li><a href='/deser'>deserialize</a></li>"
    "<li><a href='/api/me'>me</a></li>"
    # S19: the authenticated area. Anonymous clients are redirected to /login, so these links
    # give the anonymous crawl a 302 and the authenticated crawl the real pages — the
    # difference m3.authenticated-surface reports.
    "<li><a href='/portal'>account portal</a></li>"
    # S11: the GenAI surface, linked from the app's assistant nav.
    "<li><a href='/v1/chat/completions'>assistant</a></li>"
    "<li><a href='/assistant/system-prompt.txt'>assistant instructions</a></li>"
    "</ul>"
    "<form action='/upload' method='post' enctype='multipart/form-data'>"
    "<input type='file' name='file'><input type='submit' value='upload'></form>"
    "<form action='/upload-hardened' method='post' enctype='multipart/form-data'>"
    "<input type='hidden' name='csrf_token' value='token-def'>"
    "<input type='file' name='attachment'><input type='submit' value='upload'></form>"
    "<form action='/login' method='post'>"
    "<input type='text' name='username'><input type='password' name='password'>"
    "<input type='submit' value='Log in'></form>"
    "<form action='/account/settings' method='post'>"
    "<input type='text' name='email'><input type='text' name='display_name'>"
    "<input type='submit' value='Save'></form>"
    "<form action='/notes-fixed' method='post'>"
    "<input type='hidden' name='csrf_token' value='token-abc'>"
    "<input type='text' name='note'><input type='submit' value='Add'></form>"
    "<script>var api='/api/user?id=1';</script>"
    "</body></html>"
)

_NOT_FOUND = "<!doctype html><html><body><h1>404 Not Found</h1><p>No such page.</p></body></html>"

_SQL_ERROR = (
    "<!doctype html><html><body><h1>Database error</h1>"
    "<p>You have an error in your SQL syntax; check the manual that corresponds to your "
    "MySQL server version for the right syntax to use near ''' at line 1</p></body></html>"
)

_USERS: dict[str, dict[str, Any]] = {
    "1": {"id": 1, "username": "alice", "email": "alice@example.com", "role": "user"},
    "2": {"id": 2, "username": "bob", "email": "bob@example.com", "role": "user"},
    "3": {"id": 3, "username": "carol", "email": "carol@example.com", "role": "admin"},
    "4": {"id": 4, "username": "dave", "email": "dave@example.com", "role": "user"},
    "5": {"id": 5, "username": "erin", "email": "erin@example.com", "role": "user"},
}

#: The same users keyed by name — the authenticated area resolves a session to its record.
_USER_BY_NAME: dict[str, dict[str, Any]] = {item["username"]: item for item in _USERS.values()}

#: Privileged names whose login response differs from an unknown one (the enumeration trap).
#: Deliberately *not* lab accounts: a name here gets the "invalid password" page, which is the
#: S6 enumeration differential, and never a session.
_KNOWN_USERS = ("admin", "administrator", "root", "test", "user")

#: Real accounts for the S19 authenticated area (REQ-CREDS-001). A password here is a lab
#: credential: the scanner's vault holds the same value under a label, and the zero-occurrence
#: test asserts it never reaches a log, an evidence blob or a report.
LAB_PASSWORDS: dict[str, str] = {
    "alice": "alice-portal-password-1",
    "carol": "carol-admin-password-1",
}

#: The cookie the authenticated area sets. Deliberately **without** ``Secure`` and with only
#: ``SameSite=Lax``: the cookie-posture finding is part of what a credentialed scan reports.
AUTH_COOKIE = "AUTH_SID"


@dataclass
class WebLab:
    """A running lab: its base URL, its ground truth, and the requests it answered."""

    base_url: str
    port: int
    ground_truth: tuple[tuple[str, str], ...] = GROUND_TRUTH
    false_positives: tuple[tuple[str, str], ...] = FALSE_POSITIVE_TRAPS
    requests: list[str] = field(default_factory=list)
    uploads: dict[str, bytes] = field(default_factory=dict)
    throttles: dict[str, int] = field(default_factory=dict)
    #: Counters for the race-condition fixture (``/redeem-safe``).
    redeemed: dict[str, int] = field(default_factory=dict)
    # ------------------------------------------------------------------ S15 proof ladder
    #: The OOB callback service base on ARACHNE's side. When set, the simulated sinks that
    #: cannot carry the callback URL in their payload (the blind command sink's execution
    #: monitor) phone home here; the sinks whose payload carries the URL (SQLi, XXE, SSTI,
    #: SSRF) reach the callback through the payload alone.
    callback_base: str | None = None
    #: What the simulated command sink executed (the execution monitor's record).
    executed_commands: list[str] = field(default_factory=list)
    #: The lab's SQLite database (``arachne_poc`` + ``products``) behind ``/poc-sql`` —
    #: the L4 executor surface of the demo. Shared across handler threads under a lock.
    poc_db: Any = None
    db_lock: Any = field(default_factory=threading.Lock)
    #: ------------------------------------------------------------------ S19 authenticated area
    #: Server-side sessions: token → username. A logout removes the entry, which is what makes
    #: "did logout end the session?" answerable; ``/logout-soft`` deliberately does not.
    sessions: dict[str, str] = field(default_factory=dict)
    #: Requests the authenticated area has answered (the keep-alive expiry knob's clock).
    session_requests: int = 0
    #: When set, every session is dropped once this many authenticated requests have been
    #: answered — the mid-scan expiry that exercises re-authentication (REQ-CREDS-001).
    expire_after: int | None = None
    #: ------------------------------------------------------------------ S29 depth expansion
    #: The text messages the WebSocket fixtures received, in order (``/ws`` relays them; the
    #: probe's inert marker showing up here is the fixture's own record of the relay).
    ws_messages: list[str] = field(default_factory=list)

    def session_user(self, token: str | None) -> str | None:
        return self.sessions.get(token or "") if token else None

    def poc_rows(self, table: str) -> list[tuple[Any, ...]]:
        """Every row of ``table`` (the zero-residue assertion reads this)."""
        assert self.poc_db is not None
        with self.db_lock:
            # The table name is this fixture's own constant (a test helper).
            cursor = self.poc_db.execute(f"SELECT * FROM {table}")  # noqa: S608
            return list(cursor.fetchall())

    @property
    def host(self) -> str:
        return f"127.0.0.1:{self.port}"


class _Handler(BaseHTTPRequestHandler):
    """The lab application: a route table over one request handler."""

    server_version = "arachne-lab/1.0"
    protocol_version = "HTTP/1.1"
    lab: WebLab  # injected by the server factory below

    # ------------------------------------------------------------------ plumbing
    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - stdlib signature
        return  # the lab is quiet; the scanner's own audit log is the record

    def _record(self) -> tuple[urllib.parse.SplitResult, dict[str, list[str]]]:
        parsed = urllib.parse.urlsplit(self.path)
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        self.lab.requests.append(f"{self.command} {self.path}")
        return parsed, query

    def _respond(
        self,
        status: int,
        body: str | bytes,
        *,
        content_type: str = "text/html; charset=utf-8",
        headers: dict[str, str] | None = None,
        cookies: tuple[str, ...] = ("PHPSESSID=" + secrets.token_hex(8) + "; path=/",),
    ) -> None:
        payload = body.encode("utf-8") if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        for cookie in cookies:
            self.send_header("Set-Cookie", cookie)
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    # ------------------------------------------------------------------ verbs
    def do_GET(self) -> None:
        parsed, query = self._record()
        route = parsed.path.rstrip("/") or "/"
        handler = self._ROUTES.get(route)
        if handler is not None:
            handler(self, query)
            return
        self._respond(404, _NOT_FOUND)

    def do_HEAD(self) -> None:
        self.do_GET()

    def do_OPTIONS(self) -> None:
        parsed, _query = self._record()
        route = parsed.path.rstrip("/") or "/"
        if route.startswith("/dav") and "hardened" not in route:
            # An exposed WebDAV collection advertises the write verbs it accepts. Nothing
            # here is exercised by the scanner: the Allow header is the evidence.
            self._respond(
                200,
                "",
                headers={
                    "Allow": "GET, POST, OPTIONS, PROPFIND, PUT, DELETE, MOVE, TRACE, MKCOL",
                    "DAV": "1,2",
                },
                cookies=(),
            )
            return
        self._respond(
            200,
            "",
            headers={"Allow": "GET, POST, OPTIONS"},
            cookies=(),
        )

    def do_PROPFIND(self) -> None:
        parsed, _query = self._record()
        route = parsed.path.rstrip("/") or "/"
        if route.startswith("/dav") and "hardened" not in route:
            self._respond(
                207,
                '<?xml version="1.0"?><D:multistatus xmlns:D="DAV:">'
                "<D:response><D:href>/dav/</D:href></D:response></D:multistatus>",
                content_type="application/xml",
                headers={"DAV": "1,2"},
                cookies=(),
            )
            return
        self._respond(405, "", headers={"Allow": "GET, POST, OPTIONS"}, cookies=())

    def do_TRACE(self) -> None:
        parsed, _query = self._record()
        route = parsed.path.rstrip("/") or "/"
        if route.startswith("/dav") and "hardened" not in route:
            # Cross-site tracing: the server echoes the request line and headers back.
            echo = (
                f"TRACE {self.path} HTTP/1.1\r\nHost: {self.headers.get('Host', '')}\r\n"
                f"X-Echo: {self.headers.get('X-Echo', '')}\r\n"
            )
            self._respond(200, echo, content_type="message/http", cookies=())
            return
        self._respond(405, "", headers={"Allow": "GET, POST, OPTIONS"}, cookies=())

    def do_POST(self) -> None:
        parsed, query = self._record()
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        route = parsed.path.rstrip("/") or "/"
        handler = self._POST_ROUTES.get(route)
        if handler is not None:
            handler(self, query, body)
            return
        self._respond(404, _NOT_FOUND)

    # ------------------------------------------------------------------ S15 proof sinks
    def _extract_url(self, text: str) -> str | None:
        """The first http(s) URL in a payload — the OOB channel the DB/template reached."""
        match = re.search(r"https?://[^\s\]>'\"]+", text)
        return match.group(0) if match else None

    def _phone_home(self, url: str) -> None:
        """The simulated out-of-band channel: the sink reaches ARACHNE's callback.

        Loopback-only by construction (the whole lab is), and the URL arrives either in
        the payload itself (SQLi/XXE/SSTI/SSRF) or from the execution monitor's
        configuration (blind command injection).
        """
        if not url.startswith(("http://127.0.0.1", "http://localhost")):
            return
        import urllib.request

        try:
            with urllib.request.urlopen(url, timeout=2) as response:  # noqa: S310 - loopback only
                response.read()
        except OSError:
            return  # the callback's answer never influences the sink's response

    # ------------------------------------------------------------------ routes (GET)
    def _index(self, query: dict[str, list[str]]) -> None:
        self._respond(200, _HTML_SHELL)

    def _search(self, query: dict[str, list[str]]) -> None:
        term = query.get("q", [""])[0]
        # Reflected XSS: the term is echoed without encoding.
        self._respond(
            200, f"<html><body><h1>Results</h1><p>You searched for {term}</p></body></html>"
        )

    def _safe_search(self, query: dict[str, list[str]]) -> None:
        term = query.get("q", [""])[0]
        escaped = (
            term.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )
        self._respond(
            200, f"<html><body><h1>Results</h1><p>You searched for {escaped}</p></body></html>"
        )

    def _profile(self, query: dict[str, list[str]]) -> None:
        name = query.get("name", [""])[0]
        # Reflected XSS in *attribute* context: the value lands inside a single-quoted
        # attribute and the escaping encodes <, >, & and " but not the single quote — the
        # classic wrong-flag bug, and a different oracle branch from /search's raw echo.
        escaped = (
            name.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
        )
        self._respond(
            200,
            "<html><body><input type='text' name='display' value='"
            + escaped
            + "'><p>Profile</p></body></html>",
        )

    def _product(self, query: dict[str, list[str]]) -> None:
        category = query.get("category", ["1"])[0]
        if " OR 1=1" in category:
            # Simulated blind SQLi with an out-of-band DB channel: the predicate is true,
            # and the back-end "resolved" whatever the payload carried — including the
            # callback URL. The response is the ordinary true-predicate list (blind).
            url = self._extract_url(category)
            if url is not None:
                self._phone_home(url)
            self._respond(
                200,
                "<html><body><h1>Products</h1><ul>"
                "<li>Widget A - 19.99</li><li>Widget B - 24.99</li><li>Widget C - 9.99</li>"
                "</ul></body></html>",
            )
            return
        if "'" in category or '"' in category:
            self._respond(500, _SQL_ERROR)
            return
        if "1=2" in category or ">5" in category:
            self._respond(
                200, "<html><body><h1>Products</h1><p>No products found.</p></body></html>"
            )
            return
        self._respond(
            200,
            "<html><body><h1>Products</h1><ul>"
            "<li>Widget A - 19.99</li><li>Widget B - 24.99</li><li>Widget C - 9.99</li>"
            "</ul></body></html>",
        )

    def _download(self, query: dict[str, list[str]]) -> None:
        raw = query.get("file", [""])[0]
        name = _deep_unquote(raw)
        if "etc/passwd" in name:
            self._respond(
                200,
                "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n",
                content_type="text/plain",
            )
            return
        if "win.ini" in name.lower():
            self._respond(200, "[fonts]\n[extensions]\n", content_type="text/plain")
            return
        if name == "readme.txt":
            self._respond(200, "Arachne lab readme.\n", content_type="text/plain")
            return
        self._respond(404, _NOT_FOUND)

    def _hardened_download(self, query: dict[str, list[str]]) -> None:
        raw = _deep_unquote(query.get("file", [""])[0])
        if raw != "readme.txt":
            self._respond(403, "<html><body><h1>403 Forbidden</h1></body></html>")
            return
        self._respond(200, "Arachne lab readme.\n", content_type="text/plain")

    def _redirect(self, query: dict[str, list[str]]) -> None:
        target = query.get("next", ["/"])[0]
        self._respond(302, "", headers={"Location": target}, content_type="text/html")

    def _safe_redirect(self, query: dict[str, list[str]]) -> None:
        target = query.get("next", ["/"])[0]
        # Relative-only: anything that names a host is discarded, so nothing reflects.
        location = target if target.startswith("/") and not target.startswith("//") else "/"
        self._respond(302, "", headers={"Location": location}, content_type="text/html")

    def _api_user(self, query: dict[str, list[str]]) -> None:
        identifier = query.get("id", [""])[0]
        record = _USERS.get(identifier)
        if record is None:
            self._respond(404, json.dumps({"error": "not found"}), content_type="application/json")
            return
        self._respond(200, json.dumps(record), content_type="application/json")

    def _api_user_fixed(self, query: dict[str, list[str]]) -> None:
        # Requires a session; the lab never issues an authorized one, so every read is refused
        # with the same body (no differential for the IDOR oracle to find).
        self._respond(
            401,
            json.dumps({"error": "authentication required", "username": None, "email": None}),
            content_type="application/json",
        )

    def _api_config(self, query: dict[str, list[str]]) -> None:
        origin = self.headers.get("Origin")
        headers: dict[str, str] = {}
        if origin:
            # Permissive CORS: the request origin is reflected and credentials are allowed.
            headers["Access-Control-Allow-Origin"] = origin
            headers["Access-Control-Allow-Credentials"] = "true"
        self._respond(
            200,
            json.dumps({"feature": "beta", "region": "eu-west-1"}),
            content_type="application/json",
            headers=headers,
        )

    def _api_config_fixed(self, query: dict[str, list[str]]) -> None:
        self._respond(
            200,
            json.dumps({"feature": "stable"}),
            content_type="application/json",
            headers={
                "Access-Control-Allow-Origin": "https://app.example.com",
                "Vary": "Origin",
            },
        )

    def _admin(self, query: dict[str, list[str]]) -> None:
        self._respond(200, "<html><body><h1>Admin console</h1><p>Manage users.</p></body></html>")

    def _api_v1_catchall(self, query: dict[str, list[str]]) -> None:
        # A single-page-application catch-all: 200 with the application shell for any path.
        self._respond(200, _HTML_SHELL)

    def _login_fast(self, query: dict[str, list[str]]) -> None:
        client = self.client_address[0]
        count = self.lab.throttles.get(client, 0) + 1
        self.lab.throttles[client] = count
        if count > 2:
            self._respond(
                429, json.dumps({"error": "too many requests"}), content_type="application/json"
            )
            return
        self._respond(200, json.dumps({"token": "none"}), content_type="application/json")

    def _not_found_route(self, query: dict[str, list[str]]) -> None:
        self._respond(404, _NOT_FOUND)

    def _login_page(self, query: dict[str, list[str]]) -> None:
        # S19: a signed-in client is not offered the form again. That is both what a real
        # application does and the signal an undeclared (detected) login flow is verified
        # with — "the login page no longer carries a password input" (arachne.creds.session).
        if self.lab.session_user(self._auth_cookie()) is not None:
            self._respond(
                302,
                "<html><body><p>Already signed in.</p></body></html>",
                headers={"Location": "/portal"},
                cookies=(),
            )
            return
        self._respond(
            200,
            "<html><body><h1>Log in</h1>"
            "<form action='/login' method='post'>"
            "<input type='text' name='username'><input type='password' name='password'>"
            "<input type='submit'></form></body></html>",
        )

    def _notes_fixed(self, query: dict[str, list[str]]) -> None:
        self._respond(200, "<html><body><p>Notes.</p></body></html>")

    # ------------------------------------------------------------------ routes (M4, S7)
    def _env_file(self, query: dict[str, list[str]]) -> None:
        self._respond(200, _ENV_BODY, content_type="text/plain")

    def _denied(self, query: dict[str, list[str]]) -> None:
        self._respond(403, "403 Forbidden", content_type="text/plain")

    def _git_head(self, query: dict[str, list[str]]) -> None:
        self._respond(200, _GIT_HEAD, content_type="text/plain")

    def _git_config(self, query: dict[str, list[str]]) -> None:
        self._respond(200, _GIT_CONFIG, content_type="text/plain")

    def _git_packed_refs(self, query: dict[str, list[str]]) -> None:
        self._respond(200, _GIT_PACKED_REFS, content_type="text/plain")

    def _sql_dump(self, query: dict[str, list[str]]) -> None:
        self._respond(200, _SQL_DUMP, content_type="application/sql")

    def _zip_backup(self, query: dict[str, list[str]]) -> None:
        self._respond(200, _ZIP_BYTES, content_type="application/zip")

    def _php_backup(self, query: dict[str, list[str]]) -> None:
        self._respond(200, _PHP_BACKUP, content_type="text/plain")

    def _directory_listing(self, query: dict[str, list[str]]) -> None:
        self._respond(200, _DIRECTORY_LISTING)

    def _files_hardened(self, query: dict[str, list[str]]) -> None:
        self._respond(
            200, "<html><body><h1>Files</h1><p>No directory listings here.</p></body></html>"
        )

    def _jenkins(self, query: dict[str, list[str]]) -> None:
        self._respond(200, _JENKINS)

    def _grafana(self, query: dict[str, list[str]]) -> None:
        self._respond(200, _GRAFANA_LOGIN)

    def _phpmyadmin(self, query: dict[str, list[str]]) -> None:
        self._respond(200, _PHPMYADMIN)

    def _phpinfo(self, query: dict[str, list[str]]) -> None:
        self._respond(200, _PHPINFO)

    def _openapi(self, query: dict[str, list[str]]) -> None:
        self._respond(200, _OPENAPI, content_type="application/json")

    def _internal_users(self, query: dict[str, list[str]]) -> None:
        self._respond(200, _INTERNAL_USERS, content_type="application/json")

    def _orders(self, query: dict[str, list[str]]) -> None:
        # A protected API route: the control for m4.unauth-api-audit.
        self._respond(401, _ORDERS_REQUIRES_AUTH, content_type="application/json")

    def _app_js(self, query: dict[str, list[str]]) -> None:
        # The S10 jwt fixture: a client-side token signed with the weak secret "secret"; the
        # jwt-audit check recovers it offline from this bundle.
        self._respond(
            200,
            _APP_JS + f"var sessionToken = '{_WEAK_JWT}';\n",
            content_type="application/javascript",
        )

    def _app_js_hardened(self, query: dict[str, list[str]]) -> None:
        self._respond(200, _APP_JS_HARDENED, content_type="application/javascript")

    def _app_map(self, query: dict[str, list[str]]) -> None:
        self._respond(200, _APP_MAP, content_type="application/json")

    def _rsa_key(self, query: dict[str, list[str]]) -> None:
        self._respond(200, _RSA_KEY, content_type="application/x-pem-file")

    def _actuator_env(self, query: dict[str, list[str]]) -> None:
        self._respond(200, _ACTUATOR_ENV, content_type="application/json")

    def _staging(self, query: dict[str, list[str]]) -> None:
        self._respond(200, _STAGING_PAGE)

    def _dav(self, query: dict[str, list[str]]) -> None:
        self._respond(200, "<html><body><h1>WebDAV collection</h1></body></html>")

    def _dav_hardened(self, query: dict[str, list[str]]) -> None:
        self._respond(200, "<html><body><p>Static files only.</p></body></html>")

    def _fetch_sink(self, query: dict[str, list[str]]) -> None:
        """A server-side fetch sink: the SSRF vector m4.metadata-ssrf needs."""
        target = query.get("url", [""])[0]
        if "metadata/instance" in target:
            self._respond(
                200,
                json.dumps({"compute": {"azEnvironment": "AzurePublicCloud", "name": "lab-vm"}}),
                content_type="application/json",
            )
            return
        if "metadata/identity" in target:
            self._respond(
                200,
                json.dumps({"access_token": "not-a-real-token", "token_type": "Bearer"}),
                content_type="application/json",
            )
            return
        if "computeMetadata" in target or "service-accounts" in target:
            self._respond(
                200,
                json.dumps({"access_token": "not-a-real-token", "token_type": "Bearer"}),
                content_type="application/json",
            )
            return
        if "169.254.169.254" in target or "metadata.google.internal" in target:
            self._respond(200, _IMDS_V1, content_type="text/plain")
            return
        self._respond(400, "unsupported url", content_type="text/plain")

    def _storage(self, query: dict[str, list[str]]) -> None:
        """An S3-shaped bucket endpoint: /storage/<name> with S3 query parameters."""
        parts = urllib.parse.urlsplit(self.path)
        name = parts.path.rstrip("/").rsplit("/", 1)[-1]
        params = parts.query
        if name == "private":
            self._respond(
                403,
                '<?xml version="1.0"?><Error><Code>AccessDenied</Code></Error>',
                content_type="application/xml",
            )
            return
        if name == "backup":
            if "acl" in params:
                self._respond(200, _BUCKET_ACL, content_type="application/xml")
                return
            if "list-type" in params:
                self._respond(200, _BUCKET_LISTING, content_type="application/xml")
                return
        self._respond(
            404,
            '<?xml version="1.0"?><Error><Code>NoSuchBucket</Code></Error>',
            content_type="application/xml",
        )

    _ROUTES: dict[str, Any] = {}
    _POST_ROUTES: dict[str, Any] = {}

    # ------------------------------------------------------------------ routes (POST)
    def _upload(self, query: dict[str, list[str]], body: bytes) -> None:
        filename = _multipart_filename(body)
        if not filename:
            self._respond(400, "<html><body>no file submitted</body></html>")
            return
        if not re.search(r"\.(php5?|phtml|jsp|aspx?)$", filename, re.IGNORECASE):
            self._respond(200, "<html><body>invalid file type</body></html>")
            return
        self.lab.uploads[filename] = b""
        self._respond(
            200, f"<html><body>uploaded successfully to /uploads/{filename}</body></html>"
        )

    def _upload_hardened(self, query: dict[str, list[str]], body: bytes) -> None:
        filename = _multipart_filename(body)
        if filename and filename.lower().endswith((".txt", ".png", ".jpg")):
            self._respond(200, "<html><body>uploaded successfully</body></html>")
            return
        self._respond(200, "<html><body>invalid file type</body></html>")

    def _login_submit(self, query: dict[str, list[str]], body: bytes) -> None:
        fields = urllib.parse.parse_qs(body.decode("utf-8", "replace"))
        username = (fields.get("username") or [""])[0]
        password = (fields.get("password") or [""])[0]
        # S19: a real account with the right password gets a real session (REQ-CREDS-001).
        expected = LAB_PASSWORDS.get(username)
        if expected is not None:
            if secrets.compare_digest(password, expected):
                self._login_lab_account(username, password)
                return
            # One generic refusal for a real account: no enumeration signal for these.
            self._respond(
                401,
                "<html><body><h1>Log in</h1><p>Invalid username or password.</p></body></html>",
            )
            return
        # The S6 enumeration trap: a *privileged-looking* name that is not an account.
        if username in _KNOWN_USERS:
            self._respond(
                200,
                f"<html><body><h1>Log in</h1><p>Invalid password for {username}.</p>"
                "<p>Please try again.</p></body></html>",
            )
            return
        self._respond(401, "<html><body><h1>Unknown user.</h1></body></html>")

    def _account_settings(self, query: dict[str, list[str]], body: bytes) -> None:
        self._respond(200, "<html><body><p>Settings saved.</p></body></html>")

    def _notes_fixed_post(self, query: dict[str, list[str]], body: bytes) -> None:
        self._respond(200, "<html><body><p>Note added.</p></body></html>")

    # ------------------------------------------------------------------ routes (M3 extended, S10)
    def _ssti(self, query: dict[str, list[str]]) -> None:
        name = query.get("name", ["guest"])[0]
        evaluated = (
            name.replace("{{7*7}}", "49").replace("${7*7}", "49").replace("<%= 7*7 %>", "49")
        )
        if "{{" in name and "}}" in name:
            # Simulated template engine with the SSTI→SSRF primitive: an evaluated
            # template may reference a URL, which the renderer then fetches.
            url = self._extract_url(name)
            if url is not None:
                self._phone_home(url)
        self._respond(200, f"<html><body><h1>Hello {evaluated}</h1></body></html>")

    def _safe_template(self, query: dict[str, list[str]]) -> None:
        self._respond(200, _SAFE_TEMPLATE)

    def _cache_me(self, query: dict[str, list[str]]) -> None:
        forwarded = self.headers.get("X-Forwarded-Host", "")
        self._respond(
            200,
            f"<html><body><p>asset host: {forwarded}</p></body></html>",
            headers={"X-Cache": "HIT", "Cache-Control": "public, max-age=600"},
        )

    def _cache_safe(self, query: dict[str, list[str]]) -> None:
        self._respond(200, "<html><body><p>static asset</p></body></html>")

    def _hpp(self, query: dict[str, list[str]]) -> None:
        values = query.get("role", [])
        winner = values[0] if values else "user"
        self._respond(200, f"<html><body><p>role={winner}</p></body></html>")

    def _graphql(self, query: dict[str, list[str]], body: bytes = b"") -> None:
        """The planted-vulnerable GraphQL route (S29): a real engine, no controls enforced."""
        raw = graphql_lab.query_from_body(body.decode("utf-8", "replace") if body else "")
        status, payload = graphql_lab.execute(
            raw,
            limits=graphql_lab.VULNERABLE,
            auth_present=bool(self.headers.get("Authorization") or self.headers.get("Cookie")),
        )
        self._respond(status, payload, content_type="application/json")

    def _graphql_safe(self, query: dict[str, list[str]], body: bytes = b"") -> None:
        """The hardened route (S29): depth, alias and auth controls on, introspection off."""
        raw = graphql_lab.query_from_body(body.decode("utf-8", "replace") if body else "")
        status, payload = graphql_lab.execute(
            raw,
            limits=graphql_lab.SAFE,
            auth_present=bool(self.headers.get("Authorization") or self.headers.get("Cookie")),
        )
        self._respond(status, payload, content_type="application/json")

    # ------------------------------------------------------------------ WebSocket (RFC 6455)
    def _ws_handshake(self, *, origin_ok: bool, auth_required: bool) -> bool:
        """Complete (or refuse) an RFC 6455 upgrade on this connection.

        Returns ``True`` when the handshake completed and the caller may read frames. The
        ``101`` is written by hand rather than through :meth:`_respond`: an upgrade carries no
        content length and no body, and the connection is no longer an HTTP one afterwards.
        """
        key = self.headers.get("Sec-WebSocket-Key", "")
        if not key or self.headers.get("Upgrade", "").lower() != "websocket":
            self._respond(426, "upgrade required", content_type="text/plain", cookies=())
            return False
        # An upgrade attempt means the peer is (or will be) speaking frames, not HTTP: the
        # connection must not be returned to the request loop, even when the handshake is
        # refused — a client that sends frames before reading the refusal would otherwise have
        # them parsed as a request line.
        self.close_connection = True
        if not origin_ok:
            self._respond(403, "origin rejected", content_type="text/plain", cookies=())
            return False
        if auth_required:
            credential = (
                self.headers.get("Authorization")
                or self.headers.get("Cookie")
                or self.headers.get("Sec-WebSocket-Protocol")
            )
            if not credential:
                self._respond(401, "unauthorized", content_type="text/plain", cookies=())
                return False
        accept = base64.b64encode(
            hashlib.sha1((key + _WS_GUID).encode("ascii")).digest()  # noqa: S324 - RFC 6455
        ).decode("ascii")
        self.send_response(101, "Switching Protocols")
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept)
        self.end_headers()
        return True

    def _ws_converse(self, *, relay: bool) -> None:
        """Read the client's frames and answer them in one write: PING→PONG, text→echo.

        Both replies are batched into a single write so the peer sees them in one chunk —
        which is what makes the frame exchange a deterministic fixture rather than a race.
        """
        out = bytearray()
        frame = _read_ws_frame(self.rfile)
        if frame is None:
            return
        opcode, payload = frame
        if opcode == _WS_PING:
            out.extend(_ws_frame(payload, opcode=_WS_PONG))
            frame = _read_ws_frame(self.rfile)
            if frame is None:
                self.wfile.write(bytes(out))
                self.wfile.flush()
                return
            opcode, payload = frame
        if opcode in {_WS_TEXT, _WS_BINARY}:
            self.lab.ws_messages.append(payload.decode("utf-8", "replace"))
            if relay:
                out.extend(_ws_frame(payload, opcode=opcode))
        if out:
            self.wfile.write(bytes(out))
            self.wfile.flush()

    def _ws_upgrade(self, query: dict[str, list[str]]) -> None:
        """``/ws`` — accepts any Origin, needs no credential, and relays what it is sent."""
        if not self._ws_handshake(origin_ok=True, auth_required=False):
            return
        self._ws_converse(relay=True)

    def _ws_safe(self, query: dict[str, list[str]]) -> None:
        """``/ws-safe`` — validates the Origin *and* requires a credential at the upgrade."""
        origin = self.headers.get("Origin", "")
        if "arachne-ws.invalid" in origin or origin == "null":
            self._respond(403, "origin rejected", content_type="text/plain", cookies=())
            return
        if not self._ws_handshake(origin_ok=True, auth_required=True):
            return
        # Authenticated and same-origin: the endpoint answers PINGs but does not echo an
        # arbitrary client payload back.
        self._ws_converse(relay=False)

    def _checkout(self, query: dict[str, list[str]]) -> None:
        qty = query.get("qty", ["1"])[0]
        try:
            value = float(qty)
        except ValueError:
            value = 1.0
        total = round(19.99 * value, 2)
        self._respond(200, f"<html><body><p>order placed total={total}</p></body></html>")

    def _checkout_safe(self, query: dict[str, list[str]]) -> None:
        qty = query.get("qty", ["1"])[0]
        try:
            value = float(qty)
        except ValueError:
            value = 0.0
        if value <= 0 or value > 1000:
            self._respond(200, "<html><body><p>invalid quantity</p></body></html>")
            return
        self._respond(
            200, f"<html><body><p>order placed total={round(19.99 * value, 2)}</p></body></html>"
        )

    def _oauth_authorize(self, query: dict[str, list[str]]) -> None:
        redirect = query.get("redirect_uri", ["/"])[0]
        off_origin = (
            redirect.endswith("/evil")
            or ".evil.invalid" in redirect
            or redirect.startswith("//")
            or "@evil.invalid" in redirect
        )
        self._respond(
            302, "", headers={"Location": redirect if off_origin else "/"}, content_type="text/html"
        )

    def _oauth_authorize_safe(self, query: dict[str, list[str]]) -> None:
        self._respond(302, "", headers={"Location": "/"}, content_type="text/html")

    def _redeem(self, query: dict[str, list[str]]) -> None:
        # Non-atomic: every concurrent request is told it succeeded.
        self._respond(200, "<html><body><p>success: coupon redeemed</p></body></html>")

    def _redeem_safe(self, query: dict[str, list[str]]) -> None:
        used = self.lab.redeemed.get("coupon", 0)
        self.lab.redeemed["coupon"] = used + 1
        if used == 0:
            self._respond(200, "<html><body><p>success: coupon redeemed</p></body></html>")
            return
        self._respond(200, "<html><body><p>already used</p></body></html>")

    def _takeover_alias(self, query: dict[str, list[str]]) -> None:
        self._respond(200, _GITHUB_PAGES_TAKEOVER)

    def _ping(self, query: dict[str, list[str]]) -> None:
        host = query.get("host", [""])[0]
        if "echo " in host:
            token = host.split("echo ", 1)[1].strip().split()[0]
            self._respond(200, f"<html><body><pre>{token}</pre></body></html>")
            return
        self._respond(200, "<html><body><pre>pong</pre></body></html>")

    def _safe_ping(self, query: dict[str, list[str]]) -> None:
        host = query.get("host", [""])[0]
        if any(separator in host for separator in (";", "|", "&&", "`", "$(")):
            self._respond(400, "invalid host", content_type="text/plain")
            return
        self._respond(200, "<html><body><pre>pong</pre></body></html>")

    def _rce_blind(self, query: dict[str, list[str]]) -> None:
        """A blind command sink with an execution monitor (S15): output is never echoed.

        The injected command after the separator is "executed" (simulated: the lab
        interprets the allowlisted echo only — no shell) and the monitor reports the
        marker to the configured callback base. The response is always the same, so only
        the out-of-band hit can prove execution.
        """
        host = query.get("host", [""])[0]
        match = re.search(r"[;|&]\s*echo\s+(\S+)", host)
        if match is not None:
            marker = match.group(1)
            self.lab.executed_commands.append(f"echo {marker}")
            base = self.lab.callback_base
            if base and marker.startswith("arachne-"):
                self._phone_home(f"{base.rstrip('/')}/{marker}")
        self._respond(200, "<html><body><pre>pinged</pre></body></html>")

    def _poc_sql_page(self, query: dict[str, list[str]]) -> None:
        """The sink's GET page (a real deployment documents its proof surface too)."""
        self._respond(
            200,
            "<html><body><h1>SQL proof sink</h1>"
            "<p>POST sql=&lt;statement&gt; and params=&lt;json array&gt;.</p></body></html>",
        )

    def _poc_sql(self, query: dict[str, list[str]], body: bytes) -> None:
        """The L4 SQL proof sink (S15): one statement, JSON parameters, on the lab's DB.

        The statement and its parameters arrive as form fields; the lab executes the
        statement on its own SQLite database and returns the rows as text. This is the
        deployment surface the ``SqlProof`` helper drives — the ladder's policy lives in
        ARACHNE, the sink is deliberately dumb.
        """
        fields = urllib.parse.parse_qs(body.decode("utf-8", "replace"))
        sql = (fields.get("sql") or [""])[0]
        try:
            params = json.loads((fields.get("params") or ["[]"])[0])
        except ValueError:
            params = []
        if not sql or self.lab.poc_db is None:
            self._respond(500, "no statement", content_type="text/plain")
            return
        try:
            with self.lab.db_lock:
                cursor = self.lab.poc_db.execute(sql, tuple(params))
                if cursor.description is None:
                    self.lab.poc_db.commit()
                    self._respond(200, "ok", content_type="text/plain")
                    return
                rows = cursor.fetchall()
        except Exception as exc:
            self._respond(500, f"SQL error: {exc}", content_type="text/plain")
            return
        rendered = "\n".join(
            "|".join("" if cell is None else str(cell) for cell in row) for row in rows
        )
        self._respond(200, rendered or "(no rows)", content_type="text/plain")

    def _smuggle(self, query: dict[str, list[str]]) -> None:
        # A proxy hop in front of the origin: the two-parser boundary a desync requires.
        headers = {"Via": "1.1 arachne-edge", "X-Backend-Server": "app-node-1"}
        te = self.headers.get("Transfer-Encoding", "")
        if te and ("," in te or te != te.strip()):
            self._respond(
                200, "SMUGGLING_ACCEPTED", content_type="text/plain", headers=headers, cookies=()
            )
            return
        self._respond(200, "ok", content_type="text/plain", headers=headers, cookies=())

    def _smuggle_safe(self, query: dict[str, list[str]]) -> None:
        te = self.headers.get("Transfer-Encoding", "")
        if te.strip().lower() != "chunked":
            self._respond(400, "bad framing", content_type="text/plain", cookies=())
            return
        self._respond(200, "ok", content_type="text/plain", cookies=())

    def _api_me(self, query: dict[str, list[str]]) -> None:
        auth = self.headers.get("Authorization", "")
        token = auth.split(" ", 1)[1] if auth.lower().startswith("bearer ") else ""
        if not token:
            self._respond(
                401, json.dumps({"error": "unauthenticated"}), content_type="application/json"
            )
            return
        import base64

        try:
            header = json.loads(base64.urlsafe_b64decode(token.split(".")[0] + "=="))
        except Exception:
            header = {}
        if token == _WEAK_JWT or str(header.get("alg", "")).lower() == "none":
            self._respond(
                200,
                json.dumps({"username": "alice", "role": "user"}),
                content_type="application/json",
            )
            return
        self._respond(401, json.dumps({"error": "invalid token"}), content_type="application/json")

    def _fetch_sink_ssrf(self, query: dict[str, list[str]]) -> None:
        target = query.get("url", [""])[0]
        if "metadata/instance" in target:
            self._respond(
                200,
                json.dumps({"compute": {"azEnvironment": "AzurePublicCloud", "name": "lab-vm"}}),
                content_type="application/json",
            )
            return
        if "metadata/identity" in target:
            self._respond(
                200,
                json.dumps({"access_token": "not-a-real-token", "token_type": "Bearer"}),
                content_type="application/json",
            )
            return
        if "computeMetadata" in target or "service-accounts" in target:
            self._respond(
                200,
                json.dumps({"access_token": "not-a-real-token", "token_type": "Bearer"}),
                content_type="application/json",
            )
            return
        if "169.254.169.254" in target or "metadata.google.internal" in target:
            self._respond(200, _IMDS_V1, content_type="text/plain")
            return
        if target.startswith(("http://127.0.0.1", "http://localhost")):
            # A real (loopback) server-side fetch — the SSRF vector the probe confirms via out-
            # of-band callback or an in-band reflection of the callback's body.
            import urllib.request

            try:
                with urllib.request.urlopen(target, timeout=2) as response:  # noqa: S310 - loopback only
                    self._respond(
                        200, response.read().decode("utf-8", "replace"), content_type="text/plain"
                    )
            except Exception:
                self._respond(502, "fetch failed", content_type="text/plain")
            return
        self._respond(400, "unsupported url", content_type="text/plain")

    def _xxe_page(self, query: dict[str, list[str]]) -> None:
        self._respond(
            200,
            "<html><body><form action='/xxe' method='post'>"
            "<textarea name='xml'></textarea></form></body></html>",
        )

    def _deser_page(self, query: dict[str, list[str]]) -> None:
        self._respond(
            200,
            "<html><body><form action='/deser' method='post'>"
            "<input type='hidden' name='data' value=''><input type='submit'></form></body></html>",
        )

    def _checkout_page(self, query: dict[str, list[str]]) -> None:
        self._respond(200, "<html><body><p>checkout</p></body></html>")

    def _api_profile(self, query: dict[str, list[str]], body: bytes = b"") -> None:
        if self.command == "POST":
            raw = body.decode("utf-8", "replace") if body else "{}"
            try:
                parsed = json.loads(raw)
            except (json.JSONDecodeError, ValueError):
                parsed = {}
            record = {"username": "guest", "role": "user"}
            if isinstance(parsed, dict):
                record.update(parsed)
            self._respond(200, json.dumps(record), content_type="application/json")
            return
        self._respond(
            200, json.dumps({"username": "guest", "role": "user"}), content_type="application/json"
        )

    def _merge(self, query: dict[str, list[str]], body: bytes = b"") -> None:
        if self.command == "POST":
            raw = body.decode("utf-8", "replace") if body else "{}"
            try:
                parsed = json.loads(raw)
            except (json.JSONDecodeError, ValueError):
                parsed = {}
            record: dict[str, Any] = {"username": "guest"}
            if isinstance(parsed, dict):
                # The classic naive recursive merge: prototype keys are not filtered.
                record.update(parsed)
            self._respond(200, json.dumps(record), content_type="application/json")
            return
        self._respond(200, "<html><body><p>merge endpoint</p></body></html>")

    # ------------------------------------------------------------------ routes (POST, M3 extended)
    def _xxe_post(self, query: dict[str, list[str]], body: bytes) -> None:
        text = body.decode("utf-8", "replace")
        if "<!ENTITY" in text and ("file:///etc/passwd" in text or "%p;" in text):
            self._respond(200, _PASSWD, content_type="text/plain")
            return
        if "<!ENTITY" in text and "SYSTEM" in text:
            # Simulated parser with *network* entity resolution (file entities above are
            # the in-band case): a SYSTEM entity pointing at a URL is fetched.
            match = re.search(r'SYSTEM\s+"(https?://[^"]+)"', text)
            if match is not None:
                self._phone_home(match.group(1))
                self._respond(200, "entity resolved", content_type="text/plain")
                return
        self._respond(400, "no entity resolved", content_type="text/plain")

    def _deser_post(self, query: dict[str, list[str]], body: bytes) -> None:
        fields = urllib.parse.parse_qs(body.decode("utf-8", "replace"))
        data = (fields.get("data") or [""])[0]
        if data.startswith("a:"):
            self._respond(200, "<html><body><p>object restored</p></body></html>")
            return
        self._respond(500, "<html><body><p>unserialize(): error at offset 0</p></body></html>")

    def _saml_acs(self, query: dict[str, list[str]], body: bytes) -> None:
        fields = urllib.parse.parse_qs(body.decode("utf-8", "replace"))
        assertion = (fields.get("SAMLResponse") or [""])[0]
        import base64

        try:
            decoded = base64.b64decode(assertion + "===").decode("utf-8", "replace")
        except Exception:
            decoded = ""
        if assertion and "Signature" not in decoded:
            self._respond(200, "<html><body><p>authenticated</p></body></html>")
            return
        self._respond(400, "<html><body><p>invalid signature</p></body></html>")

    def _saml_acs_safe(self, query: dict[str, list[str]], body: bytes) -> None:
        self._respond(400, "<html><body><p>invalid signature</p></body></html>")

    # ------------------------------------------------------------------ routes (POST, M4/S7)
    def _jenkins_login(self, query: dict[str, list[str]], body: bytes) -> None:
        fields = urllib.parse.parse_qs(body.decode("utf-8", "replace"))
        user = (fields.get("j_username") or [""])[0]
        password = (fields.get("j_password") or [""])[0]
        if user == "admin" and password == "admin":
            # The vendor default is accepted: the S7 acceptance scan must find this only
            # when the operator opted in.
            self._respond(200, _JENKINS)
            return
        self._respond(401, "<html><body><h1>Invalid login</h1></body></html>")

    # ------------------------------------------------------------------ routes (GET, M6/S11)
    def _served_shell(self, query: dict[str, list[str]]) -> None:
        """Serve the planted obfuscated webshell (the on-disk web-root fixture's content)."""
        try:
            body = (WEBROOT_FIXTURE / "uploads" / "shell.php").read_text(encoding="utf-8")
        except OSError:  # pragma: no cover - the fixture ships with the suite
            self._respond(404, _NOT_FOUND)
            return
        self._respond(200, body, content_type="text/html; charset=utf-8")

    def _safe_shell(self, query: dict[str, list[str]]) -> None:
        """A control: a benign PHP script served at a shell-looking path."""
        try:
            body = (WEBROOT_FIXTURE / "cache" / "clean.php").read_text(encoding="utf-8")
        except OSError:  # pragma: no cover
            body = "<?php echo 'ok';"
        self._respond(200, body, content_type="text/html; charset=utf-8")

    def _llm_endpoint(self, query: dict[str, list[str]]) -> None:
        """An exposed, unauthenticated LLM chat endpoint (GenAI surface, ch06#14)."""
        self._respond(
            200,
            json.dumps({"choices": [{"message": {"role": "assistant", "content": "hi"}}]}),
            content_type="application/json",
        )

    def _system_prompt(self, query: dict[str, list[str]]) -> None:
        """A served system prompt — the prompt-injection surface of ch06#14."""
        self._respond(
            200,
            "You are a helpful assistant. Ignore previous instructions only when told to."
            " Always answer as the support agent.",
            content_type="text/plain; charset=utf-8",
        )

    # ------------------------------------------------------------------ S19 authenticated area
    def _auth_cookie(self) -> str | None:
        """The session token from the request's Cookie header (``AUTH_SID=<token>``)."""
        header = self.headers.get("Cookie") or ""
        for chunk in header.split(";"):
            name, separator, value = chunk.strip().partition("=")
            if separator and name == AUTH_COOKIE and value:
                return value
        return None

    def _portal_user(self) -> str | None:
        """The authenticated user for this request, or ``None``.

        Also the session-expiry clock: with ``lab.expire_after`` set, the lab drops every
        session once that many authenticated requests have been answered, which is how a test
        proves the scanner re-authenticates instead of silently going anonymous.
        """
        token = self._auth_cookie()
        user = self.lab.session_user(token)
        if user is not None:
            self.lab.session_requests += 1
            limit = self.lab.expire_after
            if limit is not None and self.lab.session_requests > limit:
                # Fire once: this models a server-side session flush mid-scan. Leaving the
                # knob set would drop every re-established session too, which models a target
                # that cannot be scanned at all rather than an expiring one.
                self.lab.expire_after = None
                self.lab.sessions.clear()
                return None
        return user

    def _require_session(self, *, api: bool = False) -> str | None:
        """The user, or a refusal already sent (302 to /login, or 401 for the JSON surface)."""
        user = self._portal_user()
        if user is not None:
            return user
        if api:
            self._respond(
                401,
                json.dumps({"error": "authentication required"}),
                content_type="application/json",
            )
            return None
        self._respond(
            302,
            "<html><body><p>Redirecting to the login page.</p></body></html>",
            headers={"Location": "/login"},
        )
        return None

    def _portal(self, query: dict[str, list[str]]) -> None:
        user = self._require_session()
        if user is None:
            return
        term = query.get("q", [""])[0]
        # Reflected, unencoded — reachable only with a session, so `m3.xss-oracle` finds this
        # parameter on a credentialed scan and not on an anonymous one.
        self._respond(
            200,
            "<!doctype html><html><body><h1>Account portal</h1>"
            f"<p>Signed in as {user} ({_USER_BY_NAME[user]['email']}).</p>"
            f"<p>Recent activity for {term}</p>"
            "<ul>"
            "<li><a href='/portal/admin'>administration</a></li>"
            "<li><a href='/portal/api/notes'>notes api</a></li>"
            "<li><a href='/portal/keep-alive'>session status</a></li>"
            "<li><a href='/logout-soft'>sign out</a></li>"
            "</ul></body></html>",
        )

    def _portal_admin(self, query: dict[str, list[str]]) -> None:
        user = self._require_session()
        if user is None:
            return
        if _USER_BY_NAME[user]["role"] != "admin":
            self._respond(403, "<html><body><h1>Forbidden</h1></body></html>")
            return
        rows = "".join(
            f"<tr><td>{item['username']}</td><td>{item['email']}</td><td>{item['role']}</td></tr>"
            for item in _USERS.values()
        )
        self._respond(
            200,
            "<!doctype html><html><body><h1>Administration</h1>"
            "<p>user-directory-export</p>"
            f"<table><tr><th>user</th><th>email</th><th>role</th></tr>{rows}</table>"
            "</body></html>",
        )

    def _portal_notes(self, query: dict[str, list[str]]) -> None:
        user = self._require_session(api=True)
        if user is None:
            return
        self._respond(
            200,
            json.dumps(
                {
                    "user": user,
                    "notes": [
                        {"id": 1, "title": "Quarterly plan", "body": "portal-notes-body"},
                        {"id": 2, "title": "Onboarding", "body": "portal-notes-body"},
                    ],
                }
            ),
            content_type="application/json",
        )

    def _portal_keep_alive(self, query: dict[str, list[str]]) -> None:
        user = self._require_session(api=True)
        if user is None:
            return
        self._respond(
            200,
            json.dumps({"authenticated": True, "user": user}),
            content_type="application/json",
        )

    def _api_login(self, query: dict[str, list[str]], body: bytes) -> None:
        """A JSON login flow (S19): the same accounts, ``application/json`` in and out.

        Some applications have no login form at all; the credential broker supports both
        encodings, and this endpoint is what proves the JSON one end to end.
        """
        try:
            fields = json.loads(body.decode("utf-8", "replace") or "{}")
        except ValueError:
            self._respond(400, json.dumps({"error": "bad json"}), content_type="application/json")
            return
        if not isinstance(fields, dict):
            self._respond(400, json.dumps({"error": "bad json"}), content_type="application/json")
            return
        username = str(fields.get("username") or "")
        password = str(fields.get("password") or "")
        expected = LAB_PASSWORDS.get(username)
        if expected is not None and secrets.compare_digest(password, expected):
            token = secrets.token_hex(16)
            self.lab.sessions[token] = username
            self._respond(
                200,
                json.dumps({"authenticated": True, "user": username}),
                content_type="application/json",
                cookies=(
                    f"{AUTH_COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax",
                    "PHPSESSID=" + secrets.token_hex(8) + "; path=/",
                ),
            )
            return
        self._respond(
            401,
            json.dumps({"authenticated": False, "error": "invalid credentials"}),
            content_type="application/json",
        )

    def _login_lab_account(self, username: str, password: str) -> None:
        """A real login for a lab account: a server-side session and a Set-Cookie."""
        token = secrets.token_hex(16)
        self.lab.sessions[token] = username
        self._respond(
            302,
            "<html><body><p>Signed in, redirecting.</p></body></html>",
            headers={"Location": "/portal"},
            cookies=(
                f"{AUTH_COOKIE}={token}; Path=/; HttpOnly; SameSite=Lax",
                "PHPSESSID=" + secrets.token_hex(8) + "; path=/",
            ),
        )

    def _logout(self, query: dict[str, list[str]]) -> None:
        """A logout that really ends the session (the hardened counterpart)."""
        token = self._auth_cookie()
        if token:
            self.lab.sessions.pop(token, None)
        self._respond(
            302,
            "<html><body><p>Signed out.</p></body></html>",
            headers={"Location": "/login"},
            cookies=(f"{AUTH_COOKIE}=; Path=/; Max-Age=0",),
        )

    def _logout_soft(self, query: dict[str, list[str]]) -> None:
        """**The planted CWE-613:** logout that changes nothing.

        The page says the user signed out and the response is a plain success, but neither the
        cookie nor the server-side session is touched — so the session that was just "ended"
        keeps working. That is the finding ``m3.session-logout`` reports, and it is why the
        check re-probes after the logout instead of trusting the response.
        """
        self._respond(
            200,
            "<html><body><h1>Signed out</h1><p>You have been signed out.</p></body></html>",
        )

    def _logout_post(self, query: dict[str, list[str]], body: bytes) -> None:
        self._logout(query)

    def _logout_soft_post(self, query: dict[str, list[str]], body: bytes) -> None:

        self._logout_soft(query)


_Handler._ROUTES = {
    "/": _Handler._index,
    "/search": _Handler._search,
    "/safe-search": _Handler._safe_search,
    "/profile": _Handler._profile,
    "/product": _Handler._product,
    "/download": _Handler._download,
    "/hardened-download": _Handler._hardened_download,
    "/redirect": _Handler._redirect,
    "/api/safe-redirect": _Handler._safe_redirect,
    "/api/user": _Handler._api_user,
    "/api/user-fixed": _Handler._api_user_fixed,
    "/api/config": _Handler._api_config,
    "/api/config-fixed": _Handler._api_config_fixed,
    "/api/v1": _Handler._api_v1_catchall,
    "/admin": _Handler._admin,
    "/login": _Handler._login_page,
    "/login-fast": _Handler._login_fast,
    "/notes-fixed": _Handler._notes_fixed,
    "/uploads": _Handler._not_found_route,
    "/health": _Handler._not_found_route,
    # ------------------------------------------------------------------ M4 (S7) routes
    "/.env": _Handler._env_file,
    "/.env.local": _Handler._denied,
    "/.env.production": _Handler._denied,
    "/.git/HEAD": _Handler._git_head,
    "/.git/config": _Handler._git_config,
    "/.git/packed-refs": _Handler._git_packed_refs,
    "/backup/db.sql": _Handler._sql_dump,
    "/backup/site.zip": _Handler._zip_backup,
    "/index.php.bak": _Handler._php_backup,
    "/files": _Handler._directory_listing,
    "/files-hardened": _Handler._files_hardened,
    "/jenkins": _Handler._jenkins,
    "/grafana": _Handler._grafana,
    "/phpmyadmin": _Handler._phpmyadmin,
    "/phpinfo.php": _Handler._phpinfo,
    "/swagger.json": _Handler._openapi,
    "/api/internal/users": _Handler._internal_users,
    "/api/orders": _Handler._orders,
    "/app.js": _Handler._app_js,
    "/app.js.map": _Handler._app_map,
    "/app-hardened.js": _Handler._app_js_hardened,
    "/id_rsa": _Handler._rsa_key,
    "/actuator/env": _Handler._actuator_env,
    "/staging": _Handler._staging,
    "/dav": _Handler._dav,
    "/dav-hardened": _Handler._dav_hardened,
    "/fetch": _Handler._fetch_sink_ssrf,
    "/storage/backup": _Handler._storage,
    "/storage/private": _Handler._storage,
    # ------------------------------------------------------------------ M3 extended (S10)
    "/ssti": _Handler._ssti,
    "/safe-template": _Handler._safe_template,
    "/cache-me": _Handler._cache_me,
    "/cache-safe": _Handler._cache_safe,
    "/hpp": _Handler._hpp,
    "/graphql": _Handler._graphql,
    "/graphql-safe": _Handler._graphql_safe,
    "/ws": _Handler._ws_upgrade,
    "/ws-safe": _Handler._ws_safe,
    "/checkout": _Handler._checkout,
    "/checkout-safe": _Handler._checkout_safe,
    "/oauth/authorize": _Handler._oauth_authorize,
    "/oauth/authorize-safe": _Handler._oauth_authorize_safe,
    "/redeem": _Handler._redeem,
    "/redeem-safe": _Handler._redeem_safe,
    "/takeover-alias": _Handler._takeover_alias,
    "/ping": _Handler._ping,
    "/safe-ping": _Handler._safe_ping,
    "/rce-blind": _Handler._rce_blind,
    "/poc-sql": _Handler._poc_sql_page,
    # ------------------------------------------------------------------ S19 authenticated area
    "/portal": _Handler._portal,
    "/portal/admin": _Handler._portal_admin,
    "/portal/api/notes": _Handler._portal_notes,
    "/portal/keep-alive": _Handler._portal_keep_alive,
    # A real logout (invalidates the session) and the planted soft one (does not).
    "/logout": _Handler._logout,
    "/logout-soft": _Handler._logout_soft,
    "/smuggle": _Handler._smuggle,
    "/smuggle-safe": _Handler._smuggle_safe,
    "/api/me": _Handler._api_me,
    "/api/profile": _Handler._api_profile,
    "/merge": _Handler._merge,
    "/xxe": _Handler._xxe_page,
    "/deser": _Handler._deser_page,
    # ------------------------------------------------------------------ M6 (S11) routes
    "/uploads/shell.php": _Handler._served_shell,
    "/uploads/denied.php": _Handler._denied,
    "/safe-shell.php": _Handler._safe_shell,
    "/v1/chat/completions": _Handler._llm_endpoint,
    "/assistant/system-prompt.txt": _Handler._system_prompt,
}
_Handler._POST_ROUTES = {
    "/upload": _Handler._upload,
    "/upload-hardened": _Handler._upload_hardened,
    "/login": _Handler._login_submit,
    "/account/settings": _Handler._account_settings,
    "/notes-fixed": _Handler._notes_fixed_post,
    "/jenkins/j_acegi_security_check": _Handler._jenkins_login,
    # ------------------------------------------------------------------ M3 extended (S10)
    "/xxe": _Handler._xxe_post,
    "/deser": _Handler._deser_post,
    "/saml/acs": _Handler._saml_acs,
    "/saml/acs-safe": _Handler._saml_acs_safe,
    "/api/profile": _Handler._api_profile,
    "/merge": _Handler._merge,
    "/graphql": _Handler._graphql,
    "/graphql-safe": _Handler._graphql_safe,
    # ------------------------------------------------------------------ S15 proof sinks
    "/poc-sql": _Handler._poc_sql,
    # ------------------------------------------------------------------ S19 authenticated area
    "/api/login": _Handler._api_login,
    "/logout": _Handler._logout_post,
    "/logout-soft": _Handler._logout_soft_post,
}


def _deep_unquote(value: str) -> str:
    """Decode percent-encoding twice, the way a path-join bug usually exposes it."""
    once = urllib.parse.unquote(value)
    return urllib.parse.unquote(once)


def _multipart_filename(body: bytes) -> str | None:
    match = re.search(rb'filename="([^"]+)"', body)
    return match.group(1).decode("utf-8", "replace") if match else None


# ------------------------------------------------------------------- RFC 6455 framing (S29)
def _ws_frame(payload: bytes, *, opcode: int = _WS_TEXT) -> bytes:
    """One unmasked server→client frame (a server never masks, RFC 6455 §5.1)."""
    out = bytearray([0x80 | (opcode & 0x0F)])
    length = len(payload)
    if length < 126:
        out.append(length)
    elif length < 65536:
        out.append(126)
        out.extend(length.to_bytes(2, "big"))
    else:
        out.append(127)
        out.extend(length.to_bytes(8, "big"))
    out.extend(payload)
    return bytes(out)


def _read_ws_frame(stream: Any) -> tuple[int, bytes] | None:
    """Read one client→server frame; ``None`` when the stream ends or the frame is invalid."""
    header = stream.read(2)
    if len(header) < 2:
        return None
    opcode = header[0] & 0x0F
    masked = bool(header[1] & 0x80)
    length = header[1] & 0x7F
    if length == 126:
        length = int.from_bytes(stream.read(2), "big")
    elif length == 127:
        length = int.from_bytes(stream.read(8), "big")
    if length > _WS_MAX_FRAME:
        return None
    key = stream.read(4) if masked else b""
    if masked and len(key) < 4:
        return None
    data = stream.read(length) if length else b""
    if len(data) < length:
        return None
    if masked:
        data = bytes(byte ^ key[index % 4] for index, byte in enumerate(data))
    return opcode, data


@contextmanager
def start_web_lab(*, callback_base: str | None = None) -> Iterator[WebLab]:
    """Start the lab on loopback and yield its handle; tear it down on exit.

    ``callback_base`` is ARACHNE's OOB callback service (S15): when set, the simulated
    execution monitor of the blind command sink phones hits home to it. The sinks whose
    payload carries the callback URL (SQLi, XXE, SSTI, SSRF) need no configuration.
    """
    import sqlite3

    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.execute("CREATE TABLE arachne_poc (marker TEXT PRIMARY KEY, note TEXT, created_by TEXT)")
    db.execute("CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, price REAL)")
    db.execute("INSERT INTO products VALUES (1, 'anchor-product', 19.99)")
    db.commit()
    lab = WebLab(
        base_url="",
        port=0,
        callback_base=callback_base,
        poc_db=db,
        db_lock=threading.Lock(),
    )
    handler = type("_BoundHandler", (_Handler,), {"lab": lab})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    server.daemon_threads = True
    port = server.server_address[1]
    lab.port = port
    lab.base_url = f"http://127.0.0.1:{port}/"
    thread = threading.Thread(target=server.serve_forever, name="arachne-web-lab", daemon=True)
    thread.start()
    try:
        yield lab
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        db.close()
