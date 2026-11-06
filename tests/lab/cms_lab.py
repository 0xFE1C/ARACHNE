"""The CMS family B lab: five installations, each served in three modes (WP-26, REQ-DET-019).

The requirement's acceptance needs a **positive fixture** and a **decoy** per system, and names
the decoy: "one hardened instance per CMS". This module serves each of the five systems the
family covers from its own origin, in three modes:

``vulnerable``
    A stock installation publishing the artefacts the family's checks establish: the
    configuration file served as source and a backup name beside it, the administrative login
    page, the platform's own version artefact, the web installer, and the published API route.
``hardened``
    The same installation after hardening: the administrative and configuration trees are
    blocked (``403``) and the version, installer and API artefacts are gone (``404``). **The
    decoy names no platform and carries none of the platform's markers**, which is what makes
    it clean for every check — including the other four systems' checks.
``waf``
    A **hardened** installation behind a web application firewall: the homepage is the hardened
    one, and every other path — administrative, configuration, version, installer and API alike
    — is answered with the WAF's ``403`` block page, which *echoes the requested path* and *names
    the platform*. That is the "block page that contains the payload" archetype of the decoy
    catalogue (``docs/plugin-developer-guide.md`` §2.1): a check that matched on body content,
    or on a status code, rather than on the platform's own markup plus a successful answer,
    would fire on it.

The fixture is deliberately a *server*, not a mirror of the checks: it renders the artefacts
each platform actually ships (Joomla's ``joomla.xml`` manifest and its ``com_login`` form,
Drupal's ``$databases`` settings and its ``user_login_form``, Moodle's ``$CFG`` config and its
``logintoken``, PrestaShop's ``_DB_NAME_`` constants and its ``login_form``, Magento's
``env.php`` and its ``adminhtml-auth-login`` body class), so a check that passes here has read
something the real installation produces rather than something this module invented.

**No credential values.** Every configuration fixture declares the configuration's
*identifiers* and nothing else: the identifiers the family's checks report are present, and the
settings that would carry a secret are declared without a value or omit that key entirely, so
no literal credential of any kind appears in this repository. No route in this module
authenticates anything, and no route accepts anything but ``GET``/``HEAD`` — which is what makes
the default-credential *surface* the only thing a check can report against it.
"""

from __future__ import annotations

import json
import secrets
import threading
import urllib.parse
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

__all__ = ["CMS_PLATFORMS", "MODES", "CmsLab", "start_cms_lab"]

#: The five systems the family covers (REQ-DET-019).
CMS_PLATFORMS: tuple[str, ...] = ("joomla", "drupal", "moodle", "prestashop", "magento")

#: The modes a lab can serve. ``vulnerable`` is the positive fixture; the other two are decoys.
MODES: tuple[str, ...] = ("vulnerable", "hardened", "waf")

#: The version each vulnerable fixture publishes (a version *signal*, never a severity).
CORE_VERSIONS: Mapping[str, str] = {
    "joomla": "4.4.1",
    "drupal": "10.2.4",
    "moodle": "4.3.2",
    "prestashop": "8.1.2",
    "magento": "2.4.6",
}

#: A not-found page that names no platform and carries no marker (the decoys' own 404).
_NOT_FOUND = (
    "<html><head><title>Not found</title></head><body><h1>Not found</h1>"
    "<p>The requested resource was not found on this server.</p></body></html>"
)

#: The hardened refusal page: the same discipline — no platform name, no marker.
_FORBIDDEN = (
    "<html><head><title>Forbidden</title></head><body><h1>Forbidden</h1>"
    "<p>Access to this resource is not permitted.</p></body></html>"
)

#: The WAF block page. It *does* name the platform and echo the requested path — that is the
#: trap — and it carries none of the platforms' markup.
_WAF_BLOCK = (
    "<!DOCTYPE html><html><head><title>Request blocked</title></head><body>"
    "<h1>Request blocked</h1>"
    "<p>Your request to <code>{path}</code> was blocked by the web application firewall. "
    "This site runs {platform}; administrative and content paths are protected.</p>"
    "<p>If you believe this is an error, contact the site operator and quote reference "
    "{nonce}.</p></body></html>"
)

#: The platform name each fixture publishes about itself.
_PLATFORM_NAMES: Mapping[str, str] = {
    "joomla": "Joomla",
    "drupal": "Drupal",
    "moodle": "Moodle",
    "prestashop": "PrestaShop",
    "magento": "Magento",
}

#: The hardened instance blocks these trees (a web-server rule): the configuration and the
#: administrative surface are refused rather than removed.
_HARDENED_BLOCKED = (
    "/administrator",
    "/admin",
    "/admin-dev",
    "/admin1",
    "/configuration.php",
    "/login",
    "/user",
    "/installation",
    "/install",
    "/install-dev",
    "/setup",
    "/downloader",
    "/config",
    "/sites/default",
    "/app/etc",
    "/app/config",
)

#: The hardened instance has removed these artefacts entirely (the module is disabled or the
#: file was deleted), so they answer the installation's own not-found page.
_HARDENED_REMOVED = (
    "/core",
    "/sites",
    "/app",
    "/lib",
    "/language",
    "/docs",
    "/api",
    "/rest",
    "/jsonapi",
    "/webservice",
    "/magento_version",
    "/RELEASE_NOTES.txt",
    "/README.md",
    "/README.txt",
    "/INSTALL.txt",
)


# --------------------------------------------------------------------------- fixtures
# Joomla's configuration file. The two settings that would carry a secret are *declared* and
# deliberately not assigned: the family's check reports the identifiers it finds, and this
# fixture carries no value for any of them.
_JOOMLA_CONFIG = (
    "<?php\n"
    "/**\n"
    " * The Joomla configuration file (a lab fixture).\n"
    " *\n"
    " * Only the configuration's identifiers appear here. The settings that would carry a\n"
    " * secret are declared without a value, exactly so that nothing in this repository is\n"
    " * a usable credential.\n"
    " */\n"
    "class JConfig {\n"
    "    public $sitename = 'Arachne CMS Lab';\n"
    "    public $dbtype = 'mysqli';\n"
    "    public $host = 'localhost';\n"
    "    public $user = 'joomla_lab';\n"
    "    public $password;\n"
    "    public $db = 'joomla_lab';\n"
    "    public $dbprefix = 'jos_';\n"
    "    public $secret;\n"
    "    public $log_path = '/var/www/administrator/logs';\n"
    "}\n"
)

#: Drupal's settings file. The database password key is absent rather than set.
_DRUPAL_SETTINGS = (
    "<?php\n"
    "/**\n"
    " * The Drupal site settings (a lab fixture).\n"
    " *\n"
    " * Only the configuration's identifiers appear here; nothing in this file is a\n"
    " * credential.\n"
    " */\n"
    "$databases = [];\n"
    "$databases['default']['default'] = [\n"
    "  'database' => 'drupal_lab',\n"
    "  'username' => 'drupal_lab',\n"
    "  'host' => 'localhost',\n"
    "  'port' => '3306',\n"
    "  'driver' => 'mysql',\n"
    "  'prefix' => '',\n"
    "];\n"
    "$settings['hash_salt'] = 'lab-fixture-placeholder';\n"
    "$settings['update_free_access'] = FALSE;\n"
)

#: Moodle's config file. The database password setting is absent rather than set.
_MOODLE_CONFIG = (
    "<?php\n"
    "/**\n"
    " * The Moodle configuration (a lab fixture).\n"
    " *\n"
    " * Only the configuration's identifiers appear here; nothing in this file is a\n"
    " * credential.\n"
    " */\n"
    "unset($CFG);\n"
    "global $CFG;\n"
    "$CFG = new stdClass();\n"
    "$CFG->dbtype    = 'mariadb';\n"
    "$CFG->dblibrary = 'native';\n"
    "$CFG->dbhost    = 'localhost';\n"
    "$CFG->dbname    = 'moodle_lab';\n"
    "$CFG->dbuser    = 'moodle_lab';\n"
    "$CFG->wwwroot   = '{origin}';\n"
    "$CFG->dataroot  = '/var/moodledata';\n"
    "$CFG->admin     = 'admin';\n"
)

#: PrestaShop 1.6's settings file. The password and cookie-key constants are absent.
_PRESTASHOP_SETTINGS = (
    "<?php\n"
    "/**\n"
    " * PrestaShop settings (a lab fixture).\n"
    " *\n"
    " * Only the configuration's identifiers appear here; nothing in this file is a\n"
    " * credential.\n"
    " */\n"
    "define('_DB_SERVER_', 'localhost');\n"
    "define('_DB_NAME_', 'prestashop_lab');\n"
    "define('_DB_USER_', 'prestashop_lab');\n"
    "define('_DB_PREFIX_', 'ps_');\n"
    "define('_MYSQL_ENGINE_', 'InnoDB');\n"
    "define('_PS_CACHING_SYSTEM_', 'CacheMemcache');\n"
)

#: PrestaShop 1.7+'s parameters file. The password and cookie-key parameters are absent.
_PRESTASHOP_PARAMETERS = (
    "<?php\n"
    "/**\n"
    " * PrestaShop parameters (a lab fixture).\n"
    " *\n"
    " * Only the configuration's identifiers appear here; nothing in this file is a\n"
    " * credential.\n"
    " */\n"
    "return [\n"
    "    'parameters' => [\n"
    "        'database_host' => 'localhost',\n"
    "        'database_name' => 'prestashop_lab',\n"
    "        'database_user' => 'prestashop_lab',\n"
    "        'database_prefix' => 'ps_',\n"
    "        'database_port' => '3306',\n"
    "        'database_engine' => 'InnoDB',\n"
    "    ],\n"
    "];\n"
)

#: Magento 2's env.php. The crypt node is present but empty: the installer writes the
#: deployment's encryption key there, and this fixture carries none.
_MAGENTO_ENV = (
    "<?php\n"
    "/**\n"
    " * Magento deployment configuration (a lab fixture).\n"
    " *\n"
    " * Only the configuration's identifiers appear here; nothing in this file is a\n"
    " * credential.\n"
    " */\n"
    "return [\n"
    "    'backend' => ['frontName' => 'admin'],\n"
    "    'db' => [\n"
    "        'table_prefix' => 'mage_',\n"
    "        'connection' => [\n"
    "            'default' => [\n"
    "                'host' => 'localhost',\n"
    "                'dbname' => 'magento_lab',\n"
    "                'username' => 'magento_lab',\n"
    "                'active' => '1',\n"
    "            ],\n"
    "        ],\n"
    "    ],\n"
    "    'crypt' => [],\n"
    "    'session' => ['save' => 'files'],\n"
    "];\n"
)

#: Magento 1's local.xml. The password element is absent rather than set.
_MAGENTO_LOCAL_XML = (
    '<?xml version="1.0"?>\n'
    "<!-- Magento 1 local.xml (a lab fixture): identifiers only, no credential. -->\n"
    "<config>\n"
    "  <global>\n"
    "    <resources>\n"
    "      <db>\n"
    "        <table_prefix>mage_</table_prefix>\n"
    "        <connection>\n"
    "          <host>localhost</host>\n"
    "          <username>magento_lab</username>\n"
    "          <dbname>magento_lab</dbname>\n"
    "          <active>1</active>\n"
    "        </connection>\n"
    "      </db>\n"
    "    </resources>\n"
    "  </global>\n"
    "</config>\n"
)


def _homepage(cms: str, origin: str) -> str:
    """A stock homepage that names the platform and publishes nothing else this family reads."""
    version = CORE_VERSIONS[cms]
    return (
        '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8" />'
        f"<title>Arachne CMS Lab — {_PLATFORM_NAMES[cms]}</title>"
        f'<meta name="generator" content="{_PLATFORM_NAMES[cms]} {version}" />'
        "</head><body>"
        f"<h1>Arachne CMS Lab</h1><p>Powered by {_PLATFORM_NAMES[cms]}.</p>"
        f'<p><a href="{origin}/">Home</a></p>'
        "</body></html>"
    )


def _hardened_homepage(cms: str) -> str:
    """The hardened homepage: the site itself, and nothing a scanner can inventory."""
    return (
        '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8" />'
        "<title>Arachne CMS Lab — site</title>"
        "</head><body><h1>Arachne CMS Lab</h1>"
        f"<p>{_PLATFORM_NAMES[cms]} is installed here and publishes nothing else.</p>"
        "</body></html>"
    )


# --------------------------------------------------------------------------- route tables
def _joomla(path: str, origin: str) -> _Response:
    """The stock Joomla installation: every artefact this family's Joomla checks establish."""
    if path in {"/configuration.php", "/configuration.php.txt"}:
        return _Response(200, _JOOMLA_CONFIG, "text/plain; charset=utf-8")
    if path.startswith("/configuration.php.") or path.endswith("/configuration.php~"):
        return _Response(200, _JOOMLA_CONFIG, "application/octet-stream")
    if path in {"/administrator", "/administrator/index.php"}:
        return _Response(
            200,
            "<!DOCTYPE html><html><head><title>Administrator &lsaquo; Arachne CMS Lab</title>"
            '<meta name="generator" content="Joomla! 4.4.1" /></head><body>'
            "<h1>Joomla! Administrator</h1>"
            f'<form action="{origin}/administrator/index.php" method="post" id="form-login" '
            'name="form-login" class="form-login">'
            '<input type="hidden" name="option" value="com_login" />'
            '<input type="hidden" name="task" value="login" />'
            '<label for="mod-login-username">Username</label>'
            '<input name="username" id="mod-login-username" type="text" />'
            '<label for="mod-login-password">Password</label>'
            '<input name="passwd" id="mod-login-password" type="password" />'
            '<button type="submit">Log in</button></form>'
            "</body></html>",
        )
    if path == "/administrator/manifests/files/joomla.xml":
        return _Response(
            200,
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<extension type="file" method="upgrade">\n'
            "  <name>files_joomla</name>\n"
            "  <author>Joomla! Project</author>\n"
            f"  <version>{CORE_VERSIONS['joomla']}</version>\n"
            "  <creationDate>2024-02</creationDate>\n"
            "</extension>\n",
            "application/xml; charset=utf-8",
        )
    if path == "/language/en-GB/en-GB.xml":
        return _Response(
            200,
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<metafile version="4.4" client="site" '
            'xmlns:joomla="http://www.joomla.org">\n'
            "  <name>English (en-GB)</name>\n"
            f"  <version>{CORE_VERSIONS['joomla']}</version>\n"
            "</metafile>\n",
            "application/xml; charset=utf-8",
        )
    if path == "/README.txt":
        return _Response(
            200,
            f"Joomla! {CORE_VERSIONS['joomla']}\n"
            "Joomla is an open source content management system.\n",
            "text/plain; charset=utf-8",
        )
    if path in {"/installation", "/installation/index.php"}:
        return _Response(
            200,
            "<!DOCTYPE html><html><head><title>Joomla! Installation</title></head><body>"
            "<h1>Joomla! Installation</h1>"
            "<p>Select a language and press Continue to start the Joomla installer.</p>"
            "</body></html>",
        )
    if path in {"/api", "/api/index.php/v1", "/api/index.php/v1/users"}:
        return _Response(
            401,
            json.dumps(
                {
                    "errors": [
                        {
                            "title": "Unauthorised",
                            "code": 401,
                            "message": "The webservice route requires an authenticated request.",
                        }
                    ]
                }
            ),
            "application/json; charset=utf-8",
        )
    return _not_found()


def _drupal(path: str, origin: str) -> _Response:
    """The stock Drupal installation."""
    if path in {"/sites/default/settings.php", "/sites/default/settings.php.txt"}:
        return _Response(200, _DRUPAL_SETTINGS, "text/plain; charset=utf-8")
    if path == "/sites/default/default.settings.php":
        return _Response(200, _DRUPAL_SETTINGS, "application/octet-stream")
    if path.startswith("/sites/default/settings.php.") or path.endswith(
        "/sites/default/settings.php~"
    ):
        return _Response(200, _DRUPAL_SETTINGS, "application/octet-stream")
    if path == "/user/login":
        return _Response(
            200,
            "<!DOCTYPE html><html><head><title>Log in | Arachne CMS Lab</title>"
            '<meta name="Generator" content="Drupal 10 (https://www.drupal.org)" />'
            "</head><body><h1>Log in</h1>"
            '<form class="user-login-form" data-drupal-selector="user-login-form" '
            f'action="{origin}/user/login" method="post" id="user-login-form">'
            '<input data-drupal-selector="edit-name" type="text" id="edit-name" '
            'name="name" class="form-text" />'
            '<input data-drupal-selector="edit-pass" type="password" id="edit-pass" '
            'name="pass" class="form-text" />'
            '<input type="hidden" name="form_id" value="user_login_form" />'
            '<input type="submit" name="op" value="Log in" />'
            "</form></body></html>",
        )
    if path == "/admin":
        return _Response(302, "", headers=(("Location", f"{origin}/user/login"),))
    if path == "/core/CHANGELOG.txt":
        return _Response(
            200,
            f"Drupal {CORE_VERSIONS['drupal']}, 2024-01-17\n"
            "----------------------------\n"
            "- Fixed a cache invalidation issue.\n",
            "text/plain; charset=utf-8",
        )
    if path == "/core/COPYRIGHT.txt":
        return _Response(
            200,
            f"Drupal {CORE_VERSIONS['drupal']} copyright notice.\n"
            "Copyright (c) Dries Buytaert and contributors.\n",
            "text/plain; charset=utf-8",
        )
    if path == "/core/install.php":
        return _Response(
            200,
            "<!DOCTYPE html><html><head><title>Drupal installation</title></head><body>"
            "<h1>Drupal is already installed</h1>"
            "<p>To reinstall Drupal, remove the site configuration and try again.</p>"
            "</body></html>",
        )
    if path == "/jsonapi":
        return _Response(
            200,
            json.dumps(
                {
                    "jsonapi": {"version": "1.0", "meta": {"links": {"self": "/jsonapi"}}},
                    "data": [],
                    "links": {"self": f"{origin}/jsonapi"},
                }
            ),
            "application/vnd.api+json",
        )
    return _not_found()


def _moodle(path: str, origin: str) -> _Response:
    """The stock Moodle installation."""
    config = _MOODLE_CONFIG.format(origin=origin)
    if path in {"/config.php", "/config.php.txt"}:
        return _Response(200, config, "text/plain; charset=utf-8")
    if path.startswith("/config.php.") or path.endswith("/config.php~"):
        return _Response(200, config, "application/octet-stream")
    if path in {"/login", "/login/index.php"}:
        return _Response(
            200,
            "<!DOCTYPE html><html><head><title>Arachne CMS Lab: Log in to the site</title>"
            '<meta name="keywords" content="moodle, Arachne CMS Lab" /></head><body>'
            "<h1>Log in to Arachne CMS Lab</h1>"
            f'<form class="mform" action="{origin}/login/index.php" method="post" '
            'id="login" autocomplete="on">'
            '<label for="username">Username</label>'
            '<input type="text" name="username" id="username" />'
            '<label for="password">Password</label>'
            '<input type="password" name="password" id="password" />'
            '<input type="hidden" name="logintoken" value="lab-login-token" />'
            '<div class="loginform"><button type="submit">Log in</button></div>'
            "</form></body></html>",
        )
    if path == "/lib/upgrade.txt":
        return _Response(
            200,
            "This file describes API changes in core libraries and APIs.\n\n"
            f"=== {CORE_VERSIONS['moodle']} ===\n"
            "* A new core_system_health helper was added.\n\n"
            "=== 4.2 ===\n* Nothing notable.\n",
            "text/plain; charset=utf-8",
        )
    if path == "/admin/environment.xml":
        return _Response(
            200,
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<MOODLE version="{CORE_VERSIONS["moodle"]}">\n'
            '  <PHP version="8.0.0" /></MOODLE>\n',
            "application/xml; charset=utf-8",
        )
    if path in {"/install.php", "/admin/install.php"}:
        return _Response(
            200,
            "<!DOCTYPE html><html><head><title>Moodle installation</title></head><body>"
            "<h1>Moodle installation</h1>"
            "<p>Moodle is already installed: the installer has nothing left to do here.</p>"
            "</body></html>",
        )
    if path == "/webservice/rest/server.php":
        return _Response(
            200,
            '<?xml version="1.0" encoding="UTF-8"?>\n'
            '<EXCEPTION class="webservice_access_exception">\n'
            "  <ERRORCODE>accessexception</ERRORCODE>\n"
            "  <MESSAGE>Access control exception</MESSAGE>\n"
            "  <DEBUGINFO>The Moodle webservice server requires a token.</DEBUGINFO>\n"
            "</EXCEPTION>\n",
            "text/xml; charset=utf-8",
        )
    if path == "/login/token.php":
        return _Response(
            200,
            json.dumps({"error": "Missing required parameter(s)", "errorcode": "missingparam"}),
            "application/json; charset=utf-8",
        )
    return _not_found()


def _prestashop(path: str, origin: str) -> _Response:
    """The stock PrestaShop installation."""
    if path in {"/config/settings.inc.php", "/config/settings.inc.php.txt"}:
        return _Response(200, _PRESTASHOP_SETTINGS, "text/plain; charset=utf-8")
    if path.startswith("/config/settings.inc.php.") or path.endswith("/config/settings.inc.php~"):
        return _Response(200, _PRESTASHOP_SETTINGS, "application/octet-stream")
    if path == "/app/config/parameters.php":
        return _Response(200, _PRESTASHOP_PARAMETERS, "text/plain; charset=utf-8")
    if path.startswith("/app/config/parameters.php.") or path.endswith(
        "/app/config/parameters.php~"
    ):
        return _Response(200, _PRESTASHOP_PARAMETERS, "application/octet-stream")
    if path in {"/admin-dev", "/admin-dev/index.php"}:
        return _Response(
            200,
            "<!DOCTYPE html><html><head><title>Arachne CMS Lab — PrestaShop back office</title>"
            "</head><body><h1>PrestaShop</h1>"
            f'<form id="login_form" name="login_form" action="{origin}/admin-dev/index.php" '
            'method="post" class="defaultForm form-horizontal">'
            '<input id="email" name="email" type="text" class="form-control" />'
            '<input id="passwd" name="passwd" type="password" class="form-control" />'
            '<button id="submit_login" name="submitLogin" type="submit" class="btn">'
            "Log in</button></form></body></html>",
        )
    if path == "/README.md":
        return _Response(
            200,
            f"# PrestaShop {CORE_VERSIONS['prestashop']}\n\n"
            "PrestaShop is an open source e-commerce platform.\n",
            "text/plain; charset=utf-8",
        )
    if path == "/docs/CHANGELOG.txt":
        return _Response(
            200,
            f"PrestaShop {CORE_VERSIONS['prestashop']}\n"
            "=======================\n"
            "- Release notes for this version.\n",
            "text/plain; charset=utf-8",
        )
    if path == "/INSTALL.txt":
        return _Response(
            200,
            f"PrestaShop {CORE_VERSIONS['prestashop']} installation notes.\n"
            "Upload the release archive and run the installer.\n",
            "text/plain; charset=utf-8",
        )
    if path in {"/install", "/install/index.php"}:
        return _Response(
            200,
            "<!DOCTYPE html><html><head><title>PrestaShop installation</title></head><body>"
            "<h1>PrestaShop installation</h1>"
            "<p>Installation wizard — choose your language to continue.</p>"
            "</body></html>",
        )
    if path in {"/install-dev", "/install-dev/index.php"}:
        return _Response(
            200,
            "<!DOCTYPE html><html><head><title>PrestaShop installation</title></head><body>"
            "<h1>PrestaShop installation (development)</h1></body></html>",
        )
    if path in {"/api", "/api/products"}:
        # The webservice's own Basic challenge: the endpoint advertising that it is served.
        return _Response(
            401,
            "<html><head><title>Unauthorized</title></head><body>"
            "<h1>Unauthorized</h1></body></html>",
            "text/html; charset=utf-8",
            headers=(("WWW-Authenticate", 'Basic realm="PrestaShop Webservice"'),),
        )
    return _not_found()


def _magento(path: str, origin: str) -> _Response:
    """The stock Magento installation."""
    if path in {"/app/etc/env.php", "/app/etc/env.php.txt"}:
        return _Response(200, _MAGENTO_ENV, "text/plain; charset=utf-8")
    if path.startswith("/app/etc/env.php.") or path.endswith("/app/etc/env.php~"):
        return _Response(200, _MAGENTO_ENV, "application/octet-stream")
    if path == "/app/etc/local.xml":
        return _Response(200, _MAGENTO_LOCAL_XML, "text/plain; charset=utf-8")
    if path.startswith("/app/etc/local.xml.") or path.endswith("/app/etc/local.xml~"):
        return _Response(200, _MAGENTO_LOCAL_XML, "application/octet-stream")
    if path in {"/admin", "/admin/index.php"}:
        return _Response(
            200,
            "<!DOCTYPE html><html><head><title>Magento Admin</title></head>"
            '<body data-container="body" class="adminhtml-auth-login page-layout-admin-login">'
            "<h1>Magento</h1>"
            f'<form method="post" action="{origin}/admin/index/index" id="login-form">'
            '<input id="username" name="login[username]" type="text" />'
            '<input id="login" name="login[password]" type="password" />'
            '<button type="submit" class="action-login">Sign in</button>'
            "</form></body></html>",
        )
    if path == "/magento_version":
        return _Response(
            200,
            f"Magento/{CORE_VERSIONS['magento']} (Community)\n",
            "text/plain; charset=utf-8",
        )
    if path == "/RELEASE_NOTES.txt":
        return _Response(
            200,
            f"Magento {CORE_VERSIONS['magento']} release notes\nOpen Source edition.\n",
            "text/plain; charset=utf-8",
        )
    if path in {"/setup", "/setup/index.php"}:
        return _Response(
            200,
            "<!DOCTYPE html><html><head><title>Magento Setup Wizard</title></head><body>"
            "<h1>Magento Setup Wizard</h1>"
            "<p>Welcome to the Magento setup wizard. Choose a language to continue.</p>"
            "</body></html>",
        )
    if path == "/rest/V1/store/storeViews":
        return _Response(
            200,
            json.dumps(
                [
                    {
                        "id": 1,
                        "code": "default",
                        "name": "Default Store View",
                        "website_id": 1,
                        "store_group_id": 1,
                        "is_active": True,
                    }
                ]
            ),
            "application/json; charset=utf-8",
        )
    if path == "/rest/V1/store/storeConfigs":
        return _Response(
            200,
            json.dumps({"default": {"general": {"locale": {"code": "en_US"}}}}),
            "application/json; charset=utf-8",
        )
    return _not_found()


_ROUTES: Mapping[str, Any] = {
    "joomla": _joomla,
    "drupal": _drupal,
    "moodle": _moodle,
    "prestashop": _prestashop,
    "magento": _magento,
}


@dataclass
class CmsLab:
    """A running CMS fixture: which system, which mode, its origin and what it answered."""

    cms: str
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


def _normalise(path: str) -> str:
    """The route key for a request path: no trailing slash, ``"/"`` for the root."""
    stripped = path.rstrip("/")
    return stripped or "/"


def _matches(path: str, prefix: str) -> bool:
    """True when ``path`` is ``prefix``, sits below it, or is a spill name beside it."""
    return path == prefix or path.startswith((prefix + "/", prefix + ".")) or path == prefix + "~"


def _hardened(path: str) -> _Response:
    """The hardened instance: the administrative and configuration trees are blocked."""
    if any(_matches(path, prefix) for prefix in _HARDENED_BLOCKED):
        return _Response(403, _FORBIDDEN)
    return _not_found()


class _Handler(BaseHTTPRequestHandler):
    """One installation: one route table per system, differing by the lab's mode."""

    server_version = "arachne-cms-lab/1.0"
    protocol_version = "HTTP/1.1"
    # Loopback Nagle/delayed-ACK stall removal, as in the shared web lab.
    disable_nagle_algorithm = True
    lab: CmsLab

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
            # The edge filter blocks every non-root path — configuration, administrative,
            # version, installer and API alike — and its block page echoes the request and
            # names the platform, so a status-code or body-content oracle fires on it.
            return _Response(
                403,
                _WAF_BLOCK.format(
                    path=self.path,
                    platform=_PLATFORM_NAMES[lab.cms],
                    nonce=secrets.token_hex(4),
                ),
                headers=(("Server", "arachne-waf-lab"),),
            )
        if key == "/":
            if lab.mode == "vulnerable":
                return _Response(200, _homepage(lab.cms, lab.origin))
            return _Response(200, _hardened_homepage(lab.cms))
        if lab.mode in {"hardened", "waf"}:
            return _hardened(key)
        return _ROUTES[lab.cms](key, lab.origin)

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
        # No route in this fixture accepts a POST: no login is possible against it, which is
        # what makes the default-credential *surface* the only thing a check can report.
        self._send(_Response(405, _NOT_FOUND, headers=(("Allow", "GET, HEAD, OPTIONS"),)))


@contextmanager
def start_cms_lab(cms: str, mode: str = "vulnerable") -> Iterator[CmsLab]:
    """Start one CMS fixture on loopback in ``mode`` and yield its handle."""
    if cms not in CMS_PLATFORMS:
        raise ValueError(f"unknown CMS {cms!r}; expected one of {CMS_PLATFORMS}")
    if mode not in MODES:
        raise ValueError(f"unknown CMS lab mode {mode!r}; expected one of {MODES}")
    lab = CmsLab(cms=cms, mode=mode)
    handler: Any = type("_BoundHandler", (_Handler,), {"lab": lab})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    server.daemon_threads = True
    port = server.server_address[1]
    lab.port = port
    lab.base_url = f"http://127.0.0.1:{port}/"
    thread = threading.Thread(
        target=server.serve_forever,
        args=(0.05,),
        name=f"arachne-cms-lab-{cms}-{mode}",
        daemon=True,
    )
    thread.start()
    try:
        yield lab
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
