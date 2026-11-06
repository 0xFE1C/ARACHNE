"""WP-26 · the CMS family B — Joomla, Drupal, Moodle, PrestaShop and Magento (REQ-DET-019).

Thirty read-only L1 checks — six per content-management system — that inventory what each
installation publishes to an unauthenticated client, over the axes the requirement names:

* **configuration exposure** — the installation's configuration file served as source
  (``configuration.php``, ``settings.php``, ``config.php``, ``settings.inc.php``/``parameters.php``,
  ``app/etc/env.php``/``local.xml``) and the backup/spill names a text editor, a deployment
  rollback or a backup plugin leaves beside it;
* **administrative surface reachability** — the system's own login entry point
  (``/administrator/``, ``/user/login``, ``/login/index.php``, the renamed PrestaShop admin
  directory, ``/admin/``) served to an anonymous client. This is also the family's
  **default-credential surface** check: it reports *where* the platform's documented default
  administrator account would be used, as a configuration observation, and it **never** sends a
  credential or attempts a login (see "Default credentials" below);
* **version disclosure** — the system's own version artefact (Joomla's ``joomla.xml``, Drupal's
  and PrestaShop's ``CHANGELOG.txt``, Moodle's ``upgrade.txt``, Magento's ``magento_version``);
* **installation and upgrade residue** — the web installer or setup wizard the installation
  window leaves behind (``/installation/``, ``/core/install.php``, ``/install.php``,
  ``/install/``, ``/setup/``);
* **API route exposure** — the platform's published API entry point (the Joomla Webservices
  route, Drupal's JSON:API index, Moodle's REST webservice endpoint, PrestaShop's webservice,
  Magento's REST store routes).

**Read-only.** Every request is a ``GET``. No check sends a body, a credential or a
state-changing verb; none stores anything, and none reaches above L1. A check that could only
be decided by a login attempt is not written at all.

**Default credentials.** The requirement names "default-credential surfaces" and the task's
pitfall is explicit: report the **surface**, never test a credential. Attempting a login is
out of scope at L1, so the administrative-surface check reports the reachable login *surface*
(``"credential_test_sent": false``) and names the platform's own login marker it matched. The
claim is a configuration claim about reachability; nothing about a password is claimed.

**A version or banner match is never ``high`` on its own** (FP-3): every version check carries
``severity_hint="low"`` and reports a *signal*, not a vulnerability. The configuration checks
name the exposed *identifiers* a file declares (``$databases``, ``$CFG->dbname``, ``_DB_NAME_``)
and never a value.

**The decoy rule, enforced twice.** Two guards keep one system's checks off the others' and off
a block page:

1. every signal requires the *platform's own structural marker* (``com_login``, ``$databases``,
   ``_DB_NAME_``, ``magento_version``, ...), never a bare status code or a body word;
2. every signal additionally requires the body to **name its own platform**, so a check cannot
   fire on another CMS's installation — the five installations are decoys for one another — nor
   on a WAF block page that names the platform while carrying none of its markup. The two checks
   whose evidence is a protocol artefact rather than a body (the PrestaShop ``WWW-Authenticate``
   realm, the JSON API documents) carry their own platform-specific shape instead.

**Decoys.** One hardened instance per system, plus a WAF-fronted one per system
(``tests/lab/cms_lab.py``), the same trap design WP-25 used: the block page echoes the requested
path and names the platform, so a check that matched on body content would fire on it.
"""

from __future__ import annotations

import json
import re
from collections.abc import AsyncIterator, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, ClassVar
from urllib.parse import urlsplit

from arachne.core.proof import ProofLevel
from arachne.core.results import CheckResult
from arachne.core.target import TargetKind
from arachne.modules.base import CheckMetadata, Module, SeverityHint
from arachne.modules.context import CheckContext
from arachne.modules.m3.inventory import Page, WebInventory, origin_of, page_from_exchange
from arachne.modules.m3.support import (
    WebCheck,
    exchange_from_page,
    http_or_skip,
    nonce,
    owns_origin,
    payloads_for,
    safe_fetch,
    skip,
    text_ratio,
    web_candidate,
)

__all__ = [
    "CmsFamilyBChecks",
    "DrupalAdminSurface",
    "DrupalApiSurface",
    "DrupalConfigBackup",
    "DrupalConfigSource",
    "DrupalInstallerResidue",
    "DrupalVersionDisclosure",
    "JoomlaAdminSurface",
    "JoomlaApiSurface",
    "JoomlaConfigBackup",
    "JoomlaConfigSource",
    "JoomlaInstallerResidue",
    "JoomlaVersionDisclosure",
    "MagentoAdminSurface",
    "MagentoApiSurface",
    "MagentoConfigBackup",
    "MagentoConfigSource",
    "MagentoInstallerResidue",
    "MagentoVersionDisclosure",
    "MoodleAdminSurface",
    "MoodleApiSurface",
    "MoodleConfigBackup",
    "MoodleConfigSource",
    "MoodleInstallerResidue",
    "MoodleVersionDisclosure",
    "PrestaShopAdminSurface",
    "PrestaShopApiSurface",
    "PrestaShopConfigBackup",
    "PrestaShopConfigSource",
    "PrestaShopInstallerResidue",
    "PrestaShopVersionDisclosure",
]

#: The family tag every artifact carries, so one heuristic rule can cover the whole set.
FAMILY = "cms-family-b"

#: The name each installation publishes about itself (lowercase: matching is case-insensitive).
#: Used as the second decoy guard — see the module docstring.
_CMS_NAMES: Mapping[str, tuple[str, ...]] = {
    "joomla": ("joomla",),
    "drupal": ("drupal",),
    "moodle": ("moodle",),
    "prestashop": ("prestashop",),
    "magento": ("magento",),
}


# --------------------------------------------------------------------------- plumbing
@dataclass(frozen=True, slots=True)
class _Hit:
    """One confirmed signal: what it is, the facts behind it, and how much to trust it."""

    signal: str
    facts: Mapping[str, Any] = field(default_factory=dict)
    confidence: float = 0.75


def _meta(
    cms: str,
    name: str,
    title: str,
    description: str,
    *,
    research_ref: str,
    cwe: str,
    framework: tuple[str, ...],
    severity: SeverityHint,
    estimated_requests: int,
    compliance: tuple[str, ...] = (),
) -> CheckMetadata:
    """Build one check's metadata: L1, hybrid, safe, default-on, URL-scoped (WP-26 contract)."""
    return CheckMetadata(
        id=f"m3.{cms}-{name}",
        module="M3",
        name=f"{cms}-{name}",
        version="1.0",
        title=title,
        description=description,
        research_ref=research_ref,
        cwe=cwe,
        framework=framework,
        compliance=compliance,
        severity_hint=severity,
        type="hybrid",
        safe=True,
        verifiable=False,
        enabled_by_default=True,
        proof=ProofLevel.L1,
        estimated_requests=estimated_requests,
        runs_on_discovered=True,
        target_kinds=(TargetKind.URL,),
    )


def _paths(ctx: CheckContext, cms: str, key: str, default: Sequence[str] = ()) -> tuple[str, ...]:
    """A path inventory from the payload corpus, else the check's own default."""
    configured = payloads_for(ctx).strings(cms, key)
    return configured or tuple(default)


def _markers(ctx: CheckContext, cms: str, key: str, default: Sequence[str] = ()) -> tuple[str, ...]:
    """A lowercase marker list from the payload corpus, else the check's own default."""
    configured = payloads_for(ctx).strings(cms, key) or tuple(default)
    return tuple(marker.lower() for marker in configured)


def _full_url(origin: str, path: str) -> str:
    """Join ``origin`` and a path without doubling or dropping the separator."""
    if path.startswith(("http://", "https://")):
        return path
    return origin.rstrip("/") + "/" + path.lstrip("/")


def _first(pattern: str, text: str, *, flags: int = 0) -> str | None:
    match = re.search(pattern, text, flags)
    return None if match is None else match.group(1)


def _contains_any(body: str, markers: Sequence[str]) -> str | None:
    """The first marker present in ``body`` (case-insensitive), or ``None``."""
    lowered = body.lower()
    for marker in markers:
        if marker and marker in lowered:
            return marker
    return None


def _markers_found(body: str, markers: Sequence[str]) -> list[str]:
    """Every marker ``body`` carries (case-insensitive), in the list's order."""
    lowered = body.lower()
    return [marker for marker in markers if marker and marker in lowered]


def _json_of(page: Page) -> Any:
    """The page body parsed as JSON, or ``None`` when it is not JSON."""
    try:
        return json.loads(page.body)
    except (json.JSONDecodeError, ValueError):
        return None


class _CmsProbe:
    """The shared shape of the family: bounded path probes on the asset's origin.

    A concrete check is declared ``class X(_CmsProbe, WebCheck, Module)`` and sets its
    ``metadata`` plus the class attributes below. Every request goes through the shared scoped
    client (ADR-05); a response the server refuses, blocks or answers with its own not-found
    rendering is skipped, so a check only fires on a *distinct, successful* answer carrying both
    the platform's own marker and the platform's name.

    This is a plain mixin rather than a :class:`~arachne.modules.base.Module` subclass: the base
    refuses to be created without metadata, and a family base has none of its own.
    """

    #: Declared here so the shared ``run`` can read it; every concrete check supplies it.
    metadata: ClassVar[CheckMetadata]

    #: The payload-corpus section for this installation (``joomla``, ``drupal``, ...).
    cms: ClassVar[str] = ""
    #: The platform's own name, lowercase; the body must carry it before a signal is read.
    cms_names: ClassVar[tuple[str, ...]] = ()
    #: False for the two checks whose evidence is a protocol artefact, not the platform's markup.
    body_must_name_cms: ClassVar[bool] = True
    #: The ``<cms>:`` key holding this check's path list in the payload corpus.
    paths_key: ClassVar[str] = ""
    #: Fallback paths when the corpus key is absent (an operator-supplied corpus).
    default_paths: ClassVar[tuple[str, ...]] = ()
    #: Non-2xx statuses this check still evaluates: the platform's own answer to an anonymous
    #: API caller. Every other 4xx/5xx is a refusal, a block or a missing path.
    ok_statuses: ClassVar[tuple[int, ...]] = ()
    #: How many findings one run reports (one root cause, bounded output).
    max_findings: ClassVar[int] = 3
    #: The candidate title; ``{path}`` is the probed path.
    finding_title: ClassVar[str] = "CMS surface exposed ({path})"

    def paths(self, ctx: CheckContext) -> tuple[str, ...]:
        return _paths(ctx, self.cms, self.paths_key, self.default_paths)

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        """The signal this response carries, or ``None`` when it carries none."""
        raise NotImplementedError

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        _client, skipped = http_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        if not owns_origin(ctx):
            yield skip(ctx, "another URL asset on this origin owns the M3 crawl for it")
            return
        origin = origin_of(ctx.asset.value)
        paths = self.paths(ctx)
        if not paths:
            yield ctx.clean(
                "no CMS path inventory configured",
                detail="the payload corpus names no probe path for this check",
            )
            return
        not_found = await _not_found(ctx, origin)
        findings = 0
        refused = 0
        for path in paths:
            if findings >= self.max_findings:
                break
            url = _full_url(origin, path)
            page = await _fetch(ctx, url)
            if page is None:
                continue
            if page.status >= 400 and page.status not in self.ok_statuses:
                refused += 1
                continue
            if _looks_like_not_found(page, not_found):
                continue
            if self.body_must_name_cms and _contains_any(page.body, self.cms_names) is None:
                # Another platform's installation (or a block page naming it): not this one.
                continue
            hit = self.signal(path, page, ctx)
            if hit is None:
                continue
            findings += 1
            yield web_candidate(
                ctx,
                self.finding_title.format(path=path),
                artifact={
                    "signal": hit.signal,
                    "family": FAMILY,
                    "cms": self.cms,
                    "check": self.metadata.name,
                    "path": path,
                    "status": page.status,
                    "content_type": page.content_type,
                    "bytes": page.body_length,
                    "origin": origin,
                    "secret_kinds": list(page.secret_kinds),
                    **dict(hit.facts),
                },
                exchanges=(exchange_from_page(page),),
                confidence=hit.confidence,
                detail=f"{url} answered HTTP {page.status} with a {hit.signal} signal",
                source=url,
            )
        if not findings:
            yield ctx.clean(
                f"no {self.cms} {self.metadata.name.split('-', 1)[-1].replace('-', ' ')} found",
                detail=(
                    f"probed {len(paths)} {self.cms} path(s) on {origin}"
                    + (f"; {refused} refused or blocked" if refused else "")
                ),
            )


async def _fetch(ctx: CheckContext, url: str) -> Page | None:
    """One bounded GET probe as a :class:`Page` (``None`` when refused or failed)."""
    exchange = await safe_fetch(ctx, url, method="GET")
    return None if exchange is None else page_from_exchange(exchange)


async def _not_found(ctx: CheckContext, origin: str) -> Page | None:
    """The installation's own not-found answer for ``origin``, learned once per step."""
    inventory = ctx.web
    if isinstance(inventory, WebInventory):
        cached = inventory.not_found_by_origin.get(origin)
        if cached is not None:
            return cached
        if inventory.not_found is not None and origin_of(inventory.not_found.url) == origin:
            inventory.not_found_by_origin[origin] = inventory.not_found
            return inventory.not_found
    page = await _fetch(ctx, _full_url(origin, f"{nonce()}-not-a-real-path"))
    if page is not None and isinstance(inventory, WebInventory):
        inventory.not_found_by_origin[origin] = page
    return page


def _looks_like_not_found(page: Page, reference: Page | None) -> bool:
    """True when ``page`` is the installation's own not-found rendering (status + body)."""
    if reference is None:
        return False
    if page.status != reference.status:
        return False
    return text_ratio(page.body, reference.body) >= 0.9


# --------------------------------------------------------------------------- shared signals
def _source_signal(page: Page, ctx: CheckContext, cms: str, *, backup: bool) -> _Hit | None:
    """A configuration file served as *source*: the platform's own declarations are readable."""
    if _contains_any(page.body, _markers(ctx, cms, "source_markers", ("<?php",))) is None:
        return None
    declarations = _markers_found(page.body, _markers(ctx, cms, "config_markers"))
    if not declarations:
        return None
    return _Hit(
        "configuration-backup-readable" if backup else "configuration-source-disclosed",
        {
            "declares": declarations,
            "configuration_source": True,
            "reports": "identifiers, never a value",
        },
        confidence=0.85,
    )


def _admin_signal(page: Page, ctx: CheckContext, cms: str) -> _Hit | None:
    """The platform's own administrative login form is served to an anonymous client."""
    markers = _markers_found(page.body, _markers(ctx, cms, "admin_markers"))
    if not markers:
        return None
    return _Hit(
        "administrative-login-surface",
        {
            "markers": markers,
            # The surface is reported as configuration. No credential is sent, and the check
            # makes no claim about any account: see the module docstring.
            "default_credential_surface": True,
            "credential_test_sent": False,
        },
        confidence=0.75,
    )


def _version_signal(page: Page, ctx: CheckContext, cms: str, default: str) -> _Hit | None:
    """The platform's own version artefact publishes a version (a signal, never a severity)."""
    if _contains_any(page.body, _markers(ctx, cms, "version_markers")) is None:
        return None
    pattern = payloads_for(ctx).string(cms, "version_regex", default=default) or default
    version = _first(pattern, page.body, flags=re.IGNORECASE)
    if version is None:
        return None
    return _Hit("version-disclosed", {"version": version}, confidence=0.7)


def _installer_signal(page: Page, ctx: CheckContext, cms: str) -> _Hit | None:
    """The installation or upgrade entry point answers an anonymous client."""
    markers = _markers_found(page.body, _markers(ctx, cms, "installer_markers"))
    if not markers:
        return None
    return _Hit("installer-residue-reachable", {"markers": markers}, confidence=0.75)


def _path_segment(path: str, index: int) -> str:
    """One segment of a probe path (``-1`` is the last segment of the URL path)."""
    segments = [segment for segment in urlsplit(path).path.split("/") if segment]
    try:
        return segments[index]
    except IndexError:
        return ""


# --------------------------------------------------------------------------- Joomla (m3.joomla-*)
class JoomlaConfigSource(_CmsProbe, WebCheck, Module):
    """``m3.joomla-config-source`` — configuration.php served as source (ch03#31, CWE-540)."""

    cms = "joomla"
    cms_names = _CMS_NAMES[cms]
    metadata = _meta(
        cms,
        "config-source",
        "Joomla configuration served as source",
        "Reports when configuration.php (or a .txt copy of it) answers with the PHP source of "
        "the Joomla configuration instead of executing it: the response carries the PHP open "
        "tag and the configuration's own public property declarations ($user, $password, $db, "
        "$secret). A correctly served configuration.php outputs nothing. The finding names "
        "the identifiers, never a value. Read-only GET probes.",
        research_ref="ch03#31",
        cwe="CWE-540",
        framework=("WSTG-CONF-03", "WSTG-CONF-02", "ATT&CK-T1552", "CWE-540"),
        severity="medium",
        estimated_requests=4,
    )

    paths_key = "config_source_paths"
    default_paths = ("/configuration.php", "/configuration.php.txt")
    finding_title = "Joomla configuration source disclosed ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        return _source_signal(page, ctx, self.cms, backup=False)


class JoomlaConfigBackup(_CmsProbe, WebCheck, Module):
    """``m3.joomla-config-backup`` — a configuration.php backup is served (ch03#31, CWE-530)."""

    cms = "joomla"
    cms_names = _CMS_NAMES[cms]
    metadata = _meta(
        cms,
        "config-backup",
        "Joomla configuration backup file exposed",
        "Probes the backup and editor-spill names Joomla deployments leave beside "
        "configuration.php (.bak, ~, .save, .old, .orig, .bkp, .php.bak) and reports one that "
        "is served as configuration source. The finding names the configuration identifiers "
        "the file declares ($user, $password, $db, $secret), never a value. Read-only GET "
        "probes.",
        research_ref="ch03#31",
        cwe="CWE-530",
        framework=("WSTG-CONF-04", "WSTG-CONF-03", "ATT&CK-T1552", "CWE-530"),
        compliance=("ISO-A.8.12", "CSF-ID.AM-02"),
        severity="medium",
        estimated_requests=9,
    )

    paths_key = "config_backup_paths"
    finding_title = "Joomla configuration backup readable ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        return _source_signal(page, ctx, self.cms, backup=True)


class JoomlaAdminSurface(_CmsProbe, WebCheck, Module):
    """``m3.joomla-admin-surface`` — the administrator login is served (ch03#19, CWE-200)."""

    cms = "joomla"
    cms_names = _CMS_NAMES[cms]
    metadata = _meta(
        cms,
        "admin-surface",
        "Joomla administrator login surface reachable",
        "Reports when the Joomla administrator entry point (/administrator/) answers an "
        "anonymous GET with the platform's own login form (the com_login component, the "
        "mod-login module or the task=login form action). This is the installation's "
        "default-credential surface: the finding reports that the surface is reachable, as a "
        "configuration observation, and the check sends no credential and attempts no login. "
        "Read-only GET probes.",
        research_ref="ch03#19",
        cwe="CWE-200",
        framework=("WSTG-CONF-05", "WSTG-IDNT-04", "ATT&CK-T1592.002", "CWE-200"),
        severity="low",
        estimated_requests=4,
    )

    paths_key = "admin_paths"
    default_paths = ("/administrator/", "/administrator/index.php")
    max_findings = 2
    finding_title = "Joomla administrator login reachable ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        return _admin_signal(page, ctx, self.cms)


class JoomlaVersionDisclosure(_CmsProbe, WebCheck, Module):
    """``m3.joomla-version-disclosure`` — the core version is published (ch03#31, CWE-200)."""

    cms = "joomla"
    cms_names = _CMS_NAMES[cms]
    metadata = _meta(
        cms,
        "version-disclosure",
        "Joomla core version disclosed",
        "Reports when the Joomla version manifest (/administrator/manifests/files/joomla.xml) "
        "or a language manifest publishes the core version. A version is a fingerprint and is "
        "never a severity on its own (FP-3): the check reports the version and leaves the CVE "
        "correlation to the intelligence stage. Read-only GET probes.",
        research_ref="ch03#31",
        cwe="CWE-200",
        framework=("WSTG-INFO-08", "WSTG-INFO-09", "ATT&CK-T1592.002", "CWE-200"),
        severity="low",
        estimated_requests=5,
    )

    paths_key = "version_paths"
    default_paths = (
        "/administrator/manifests/files/joomla.xml",
        "/language/en-GB/en-GB.xml",
        "/README.txt",
    )
    finding_title = "Joomla core version disclosed ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        return _version_signal(page, ctx, self.cms, r"<version>\s*([0-9][\w.\-]*)\s*</version>")


class JoomlaInstallerResidue(_CmsProbe, WebCheck, Module):
    """``m3.joomla-installer-residue`` — the installation directory is served (ch03#31)."""

    cms = "joomla"
    cms_names = _CMS_NAMES[cms]
    metadata = _meta(
        cms,
        "installer-residue",
        "Joomla installation directory reachable",
        "Reports when the Joomla web installer (/installation/) is reachable by an "
        "unauthenticated client and answers with its own installation page. The installation "
        "directory belongs to the installation window; a running site removes it. Read-only "
        "GET probes.",
        research_ref="ch03#31",
        cwe="CWE-200",
        framework=("WSTG-CONF-05", "WSTG-CONF-02", "CWE-200"),
        severity="low",
        estimated_requests=4,
    )

    paths_key = "installer_paths"
    default_paths = ("/installation/index.php", "/installation/")
    finding_title = "Joomla installer reachable ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        return _installer_signal(page, ctx, self.cms)


class JoomlaApiSurface(_CmsProbe, WebCheck, Module):
    """``m3.joomla-api-surface`` — the Webservices API route is served (ch03#31)."""

    cms = "joomla"
    cms_names = _CMS_NAMES[cms]
    body_must_name_cms = False
    metadata = _meta(
        cms,
        "api-surface",
        "Joomla Webservices API route published",
        "Reports when the Joomla Webservices API route (/api/index.php/v1/) answers an "
        'anonymous GET with the API\'s own JSON error envelope ({"errors": [...]}) instead of '
        "a generic 404. The claim is that the API plugin is enabled and the route is served "
        "— the anonymous caller is refused, and the envelope is that refusal's record — not "
        "that any resource is readable. Read-only GET probes.",
        research_ref="ch03#31",
        cwe="CWE-200",
        framework=("WSTG-INFO-06", "API9:2023", "CWE-200"),
        severity="low",
        estimated_requests=4,
    )

    paths_key = "api_paths"
    default_paths = ("/api/index.php/v1/", "/api/index.php/v1/users")
    # The Joomla API answers an anonymous caller with 401 and its own error envelope: that is
    # the detection, not a refusal.
    ok_statuses = (401,)
    max_findings = 2
    finding_title = "Joomla API route served ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        if "api" not in path or "index.php" not in path:
            return None
        document = _json_of(page)
        if not isinstance(document, Mapping):
            return None
        errors = document.get("errors")
        if not isinstance(errors, list) or not errors:
            return None
        return _Hit(
            "webservices-api-route-served",
            {"status": page.status, "error_records": len(errors)},
            confidence=0.7,
        )


# --------------------------------------------------------------------------- Drupal (m3.drupal-*)
class DrupalConfigSource(_CmsProbe, WebCheck, Module):
    """``m3.drupal-config-source`` — settings.php served as source (ch03#31, CWE-540)."""

    cms = "drupal"
    cms_names = _CMS_NAMES[cms]
    metadata = _meta(
        cms,
        "config-source",
        "Drupal settings served as source",
        "Reports when sites/default/settings.php answers with the PHP source of the Drupal "
        "configuration instead of executing it: the response carries the PHP open tag and the "
        "configuration's own $databases and $settings declarations. A correctly served "
        "settings.php outputs nothing. The finding names the identifiers, never a value. "
        "Read-only GET probes.",
        research_ref="ch03#31",
        cwe="CWE-540",
        framework=("WSTG-CONF-03", "WSTG-CONF-02", "ATT&CK-T1552", "CWE-540"),
        severity="medium",
        estimated_requests=4,
    )

    paths_key = "config_source_paths"
    default_paths = ("/sites/default/settings.php", "/sites/default/settings.php.txt")
    finding_title = "Drupal settings source disclosed ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        return _source_signal(page, ctx, self.cms, backup=False)


class DrupalConfigBackup(_CmsProbe, WebCheck, Module):
    """``m3.drupal-config-backup`` — a settings backup is served (ch03#31, CWE-530)."""

    cms = "drupal"
    cms_names = _CMS_NAMES[cms]
    metadata = _meta(
        cms,
        "config-backup",
        "Drupal settings backup file exposed",
        "Probes the backup, editor-spill and shipped-template names Drupal deployments leave "
        "beside settings.php (.bak, ~, .save, .old, .orig, .bkp, default.settings.php) and "
        "reports one that is served as configuration source. The finding names the "
        "configuration identifiers the file declares ($databases, $settings, hash_salt), "
        "never a value. Read-only GET probes.",
        research_ref="ch03#31",
        cwe="CWE-530",
        framework=("WSTG-CONF-04", "WSTG-CONF-03", "ATT&CK-T1552", "CWE-530"),
        compliance=("ISO-A.8.12", "CSF-ID.AM-02"),
        severity="medium",
        estimated_requests=9,
    )

    paths_key = "config_backup_paths"
    finding_title = "Drupal settings backup readable ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        return _source_signal(page, ctx, self.cms, backup=True)


class DrupalAdminSurface(_CmsProbe, WebCheck, Module):
    """``m3.drupal-admin-surface`` — the user login form is served (ch03#19, CWE-200)."""

    cms = "drupal"
    cms_names = _CMS_NAMES[cms]
    metadata = _meta(
        cms,
        "admin-surface",
        "Drupal administrative login surface reachable",
        "Reports when the Drupal login entry point (/user/login, or /admin, which redirects "
        "there) answers an anonymous GET with the platform's own login form (the "
        "user_login_form form id and its edit-name/edit-pass fields). This is the "
        "installation's default-credential surface: the finding reports that the surface is "
        "reachable, as a configuration observation, and the check sends no credential and "
        "attempts no login. Read-only GET probes.",
        research_ref="ch03#19",
        cwe="CWE-200",
        framework=("WSTG-CONF-05", "WSTG-IDNT-04", "ATT&CK-T1592.002", "CWE-200"),
        severity="low",
        estimated_requests=5,
    )

    paths_key = "admin_paths"
    default_paths = ("/user/login", "/admin")
    max_findings = 2
    finding_title = "Drupal login reachable ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        return _admin_signal(page, ctx, self.cms)


class DrupalVersionDisclosure(_CmsProbe, WebCheck, Module):
    """``m3.drupal-version-disclosure`` — the core version is published (ch03#31, CWE-200)."""

    cms = "drupal"
    cms_names = _CMS_NAMES[cms]
    metadata = _meta(
        cms,
        "version-disclosure",
        "Drupal core version disclosed",
        "Reports when the Drupal changelog (/core/CHANGELOG.txt, or its pre-8 location) "
        "publishes the core version in its own header line. A version is a fingerprint and is "
        "never a severity on its own (FP-3). Read-only GET probes.",
        research_ref="ch03#31",
        cwe="CWE-200",
        framework=("WSTG-INFO-08", "WSTG-INFO-09", "ATT&CK-T1592.002", "CWE-200"),
        severity="low",
        estimated_requests=5,
    )

    paths_key = "version_paths"
    default_paths = ("/core/CHANGELOG.txt", "/CHANGELOG.txt", "/core/COPYRIGHT.txt")
    finding_title = "Drupal core version disclosed ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        return _version_signal(page, ctx, self.cms, r"Drupal\s+([0-9][\w.\-]*)")


class DrupalInstallerResidue(_CmsProbe, WebCheck, Module):
    """``m3.drupal-installer-residue`` — the install script is served (ch03#31)."""

    cms = "drupal"
    cms_names = _CMS_NAMES[cms]
    metadata = _meta(
        cms,
        "installer-residue",
        "Drupal installation entry point reachable",
        "Reports when Drupal's install script (/core/install.php, or its pre-8 location) "
        "answers an anonymous client with its own installation page instead of being removed "
        "or blocked. The install entry point belongs to the installation window. Read-only "
        "GET probes.",
        research_ref="ch03#31",
        cwe="CWE-200",
        framework=("WSTG-CONF-05", "WSTG-CONF-02", "CWE-200"),
        severity="low",
        estimated_requests=5,
    )

    paths_key = "installer_paths"
    default_paths = ("/core/install.php", "/install.php", "/core/authorize.php")
    finding_title = "Drupal installer reachable ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        return _installer_signal(page, ctx, self.cms)


class DrupalApiSurface(_CmsProbe, WebCheck, Module):
    """``m3.drupal-api-surface`` — the JSON:API index is served (ch03#31, API9:2023)."""

    cms = "drupal"
    cms_names = _CMS_NAMES[cms]
    body_must_name_cms = False
    metadata = _meta(
        cms,
        "api-surface",
        "Drupal JSON:API index published",
        "Reports when Drupal's JSON:API index (/jsonapi) answers an anonymous GET with the "
        "JSON:API document that names every resource type the installation publishes. The "
        "index is the API's own inventory document; site building may also expose content "
        "through it. Read-only GET probes.",
        research_ref="ch03#31",
        cwe="CWE-200",
        framework=("WSTG-INFO-06", "API9:2023", "CWE-200"),
        severity="low",
        estimated_requests=4,
    )

    paths_key = "api_paths"
    default_paths = ("/jsonapi", "/jsonapi/")
    max_findings = 2
    finding_title = "Drupal JSON:API index served ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        if "jsonapi" not in path:
            return None
        document = _json_of(page)
        if not isinstance(document, Mapping) or "jsonapi" not in document:
            return None
        version = document.get("jsonapi")
        published = version.get("version") if isinstance(version, Mapping) else None
        return _Hit(
            "jsonapi-index-published",
            {"jsonapi_version": published, "links": len(document.get("links") or {})},
            confidence=0.8,
        )


# --------------------------------------------------------------------------- Moodle (m3.moodle-*)
class MoodleConfigSource(_CmsProbe, WebCheck, Module):
    """``m3.moodle-config-source`` — config.php served as source (ch03#31, CWE-540)."""

    cms = "moodle"
    cms_names = _CMS_NAMES[cms]
    metadata = _meta(
        cms,
        "config-source",
        "Moodle configuration served as source",
        "Reports when config.php answers with the PHP source of the Moodle configuration "
        "instead of executing it: the response carries the PHP open tag and the $CFG "
        "declarations (dbtype, dbname, wwwroot). A correctly served config.php outputs "
        "nothing. The finding names the identifiers, never a value. Read-only GET probes.",
        research_ref="ch03#31",
        cwe="CWE-540",
        framework=("WSTG-CONF-03", "WSTG-CONF-02", "ATT&CK-T1552", "CWE-540"),
        severity="medium",
        estimated_requests=4,
    )

    paths_key = "config_source_paths"
    default_paths = ("/config.php", "/config.php.txt")
    finding_title = "Moodle configuration source disclosed ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        return _source_signal(page, ctx, self.cms, backup=False)


class MoodleConfigBackup(_CmsProbe, WebCheck, Module):
    """``m3.moodle-config-backup`` — a config.php backup is served (ch03#31, CWE-530)."""

    cms = "moodle"
    cms_names = _CMS_NAMES[cms]
    metadata = _meta(
        cms,
        "config-backup",
        "Moodle configuration backup file exposed",
        "Probes the backup, editor-spill and superseded names Moodle deployments leave beside "
        "config.php (.bak, ~, .save, .old, .orig, .bkp, config.php.disabled) and reports one "
        "that is served as configuration source. The finding names the $CFG identifiers the "
        "file declares, never a value. Read-only GET probes.",
        research_ref="ch03#31",
        cwe="CWE-530",
        framework=("WSTG-CONF-04", "WSTG-CONF-03", "ATT&CK-T1552", "CWE-530"),
        compliance=("ISO-A.8.12", "CSF-ID.AM-02"),
        severity="medium",
        estimated_requests=9,
    )

    paths_key = "config_backup_paths"
    finding_title = "Moodle configuration backup readable ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        return _source_signal(page, ctx, self.cms, backup=True)


class MoodleAdminSurface(_CmsProbe, WebCheck, Module):
    """``m3.moodle-admin-surface`` — the login form is served (ch03#19, CWE-200)."""

    cms = "moodle"
    cms_names = _CMS_NAMES[cms]
    metadata = _meta(
        cms,
        "admin-surface",
        "Moodle login surface reachable",
        "Reports when the Moodle login entry point (/login/index.php) answers an anonymous "
        "GET with the platform's own login form (the loginform form id and its logintoken "
        "field). This is the installation's default-credential surface: the finding reports "
        "that the surface is reachable, as a configuration observation, and the check sends "
        "no credential and attempts no login. Read-only GET probes.",
        research_ref="ch03#19",
        cwe="CWE-200",
        framework=("WSTG-CONF-05", "WSTG-IDNT-04", "ATT&CK-T1592.002", "CWE-200"),
        severity="low",
        estimated_requests=4,
    )

    paths_key = "admin_paths"
    default_paths = ("/login/index.php", "/login/")
    max_findings = 2
    finding_title = "Moodle login reachable ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        return _admin_signal(page, ctx, self.cms)


class MoodleVersionDisclosure(_CmsProbe, WebCheck, Module):
    """``m3.moodle-version-disclosure`` — the release is published (ch03#31, CWE-200)."""

    cms = "moodle"
    cms_names = _CMS_NAMES[cms]
    metadata = _meta(
        cms,
        "version-disclosure",
        "Moodle release version disclosed",
        "Reports when the Moodle upgrade history (/lib/upgrade.txt) or the environment "
        "manifest (/admin/environment.xml) publishes the release version in its own header. "
        "A version is a fingerprint and is never a severity on its own (FP-3). Read-only GET "
        "probes.",
        research_ref="ch03#31",
        cwe="CWE-200",
        framework=("WSTG-INFO-08", "WSTG-INFO-09", "ATT&CK-T1592.002", "CWE-200"),
        severity="low",
        estimated_requests=5,
    )

    paths_key = "version_paths"
    default_paths = ("/lib/upgrade.txt", "/admin/environment.xml")
    finding_title = "Moodle release version disclosed ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        return _version_signal(
            page, ctx, self.cms, r"(?:===\s*|<MOODLE[^>]*\bversion=\")([0-9][\w.\-]*)"
        )


class MoodleInstallerResidue(_CmsProbe, WebCheck, Module):
    """``m3.moodle-installer-residue`` — the install script is served (ch03#31)."""

    cms = "moodle"
    cms_names = _CMS_NAMES[cms]
    metadata = _meta(
        cms,
        "installer-residue",
        "Moodle installation script reachable",
        "Reports when Moodle's web installer (/install.php) answers an anonymous client with "
        "its own installation page instead of being removed or blocked. The install script "
        "belongs to the installation window. Read-only GET probes.",
        research_ref="ch03#31",
        cwe="CWE-200",
        framework=("WSTG-CONF-05", "WSTG-CONF-02", "CWE-200"),
        severity="low",
        estimated_requests=4,
    )

    paths_key = "installer_paths"
    default_paths = ("/install.php", "/admin/install.php")
    finding_title = "Moodle installer reachable ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        return _installer_signal(page, ctx, self.cms)


class MoodleApiSurface(_CmsProbe, WebCheck, Module):
    """``m3.moodle-api-surface`` — the REST webservice is served (ch03#31, API9:2023)."""

    cms = "moodle"
    cms_names = _CMS_NAMES[cms]
    body_must_name_cms = False
    metadata = _meta(
        cms,
        "api-surface",
        "Moodle REST webservice endpoint published",
        "Reports when Moodle's webservice endpoint (/webservice/rest/server.php) answers an "
        "anonymous GET with the platform's own webservice exception document "
        '(<EXCEPTION class="webservice_access_exception">) instead of a generic 404. The '
        "claim is that the webservice endpoint is enabled and served — the anonymous caller "
        "is refused by the platform's own envelope — not that any function is callable. "
        "Read-only GET probes.",
        research_ref="ch03#31",
        cwe="CWE-200",
        framework=("WSTG-INFO-06", "API9:2023", "CWE-200"),
        severity="low",
        estimated_requests=4,
    )

    paths_key = "api_paths"
    default_paths = ("/webservice/rest/server.php", "/login/token.php")
    max_findings = 2
    finding_title = "Moodle webservice endpoint served ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        if "webservice" not in path and "token" not in path:
            return None
        lowered = page.body.lower()
        webservice = "webservice" in lowered and "<exception" in lowered
        token = '"errorcode"' in lowered or "'errorcode'" in lowered
        if not (webservice or token):
            return None
        return _Hit(
            "webservice-endpoint-served",
            {"status": page.status, "content_type": page.content_type},
            confidence=0.7,
        )


# --------------------------------------------------------------------------- PrestaShop
class PrestaShopConfigSource(_CmsProbe, WebCheck, Module):
    """``m3.prestashop-config-source`` — the configuration is served as source (ch03#31)."""

    cms = "prestashop"
    cms_names = _CMS_NAMES[cms]
    metadata = _meta(
        cms,
        "config-source",
        "PrestaShop configuration served as source",
        "Reports when a PrestaShop configuration file (config/settings.inc.php for 1.6, "
        "app/config/parameters.php for 1.7+) answers with the PHP source of the configuration "
        "instead of executing it: the response carries the PHP open tag and the file's own "
        "declarations (_DB_NAME_, _COOKIE_KEY_, database_host/database_password). A correctly "
        "served configuration writes nothing. The finding names the identifiers, never a "
        "value. Read-only GET probes.",
        research_ref="ch03#31",
        cwe="CWE-540",
        framework=("WSTG-CONF-03", "WSTG-CONF-02", "ATT&CK-T1552", "CWE-540"),
        severity="medium",
        estimated_requests=5,
    )

    paths_key = "config_source_paths"
    default_paths = (
        "/config/settings.inc.php",
        "/app/config/parameters.php",
        "/config/settings.inc.php.txt",
    )
    finding_title = "PrestaShop configuration source disclosed ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        return _source_signal(page, ctx, self.cms, backup=False)


class PrestaShopConfigBackup(_CmsProbe, WebCheck, Module):
    """``m3.prestashop-config-backup`` — a configuration backup is served (ch03#31, CWE-530)."""

    cms = "prestashop"
    cms_names = _CMS_NAMES[cms]
    metadata = _meta(
        cms,
        "config-backup",
        "PrestaShop configuration backup file exposed",
        "Probes the backup and editor-spill names PrestaShop deployments leave beside the "
        "configuration (settings.inc.php.bak, parameters.php.bak, their ~/.save/.old/.orig "
        "variants) and reports one that is served as configuration source. The finding names "
        "the identifiers the file declares, never a value. Read-only GET probes.",
        research_ref="ch03#31",
        cwe="CWE-530",
        framework=("WSTG-CONF-04", "WSTG-CONF-03", "ATT&CK-T1552", "CWE-530"),
        compliance=("ISO-A.8.12", "CSF-ID.AM-02"),
        severity="medium",
        estimated_requests=11,
    )

    paths_key = "config_backup_paths"
    finding_title = "PrestaShop configuration backup readable ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        return _source_signal(page, ctx, self.cms, backup=True)


class PrestaShopAdminSurface(_CmsProbe, WebCheck, Module):
    """``m3.prestashop-admin-surface`` — the back office login is served (ch03#19)."""

    cms = "prestashop"
    cms_names = _CMS_NAMES[cms]
    metadata = _meta(
        cms,
        "admin-surface",
        "PrestaShop back office login surface reachable",
        "Reports when the PrestaShop back office answers an anonymous GET with the platform's "
        "own employee login form (the login_form form id and its submitLogin control). The "
        "back-office directory is renamed at install time, so the check probes a bounded list "
        "of candidate directory names (the operator's list, from the payload corpus). This is "
        "the installation's default-credential surface: the finding reports that the surface "
        "is reachable, as a configuration observation, and the check sends no credential and "
        "attempts no login. Read-only GET probes.",
        research_ref="ch03#19",
        cwe="CWE-200",
        framework=("WSTG-CONF-05", "WSTG-IDNT-04", "ATT&CK-T1592.002", "CWE-200"),
        severity="low",
        estimated_requests=6,
    )

    paths_key = "admin_paths"
    max_findings = 2
    finding_title = "PrestaShop back office login reachable ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        hit = _admin_signal(page, ctx, self.cms)
        if hit is None:
            return None
        return _Hit(hit.signal, {**dict(hit.facts), "admin_directory": _path_segment(path, 0)})


class PrestaShopVersionDisclosure(_CmsProbe, WebCheck, Module):
    """``m3.prestashop-version-disclosure`` — the release is published (ch03#31, CWE-200)."""

    cms = "prestashop"
    cms_names = _CMS_NAMES[cms]
    metadata = _meta(
        cms,
        "version-disclosure",
        "PrestaShop release version disclosed",
        "Reports when a PrestaShop release document (README.md, docs/CHANGELOG.txt, "
        "INSTALL.txt) publishes the version in its own header. A version is a fingerprint and "
        "is never a severity on its own (FP-3). Read-only GET probes.",
        research_ref="ch03#31",
        cwe="CWE-200",
        framework=("WSTG-INFO-08", "WSTG-INFO-09", "ATT&CK-T1592.002", "CWE-200"),
        severity="low",
        estimated_requests=5,
    )

    paths_key = "version_paths"
    default_paths = ("/README.md", "/docs/CHANGELOG.txt", "/INSTALL.txt")
    finding_title = "PrestaShop release version disclosed ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        return _version_signal(page, ctx, self.cms, r"PrestaShop\s+v?([0-9][\w.\-]*)")


class PrestaShopInstallerResidue(_CmsProbe, WebCheck, Module):
    """``m3.prestashop-installer-residue`` — the web installer is served (ch03#31)."""

    cms = "prestashop"
    cms_names = _CMS_NAMES[cms]
    metadata = _meta(
        cms,
        "installer-residue",
        "PrestaShop installation wizard reachable",
        "Reports when the PrestaShop web installer (/install/, or the 1.6 install-dev "
        "directory) answers an anonymous client with its own installation wizard instead of "
        "being removed or blocked. The installer belongs to the installation window. "
        "Read-only GET probes.",
        research_ref="ch03#31",
        cwe="CWE-200",
        framework=("WSTG-CONF-05", "WSTG-CONF-02", "CWE-200"),
        severity="low",
        estimated_requests=5,
    )

    paths_key = "installer_paths"
    default_paths = ("/install/index.php", "/install/", "/install-dev/index.php")
    finding_title = "PrestaShop installer reachable ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        return _installer_signal(page, ctx, self.cms)


class PrestaShopApiSurface(_CmsProbe, WebCheck, Module):
    """``m3.prestashop-api-surface`` — the webservice realm is served (ch03#31, API9:2023)."""

    cms = "prestashop"
    cms_names = _CMS_NAMES[cms]
    body_must_name_cms = False
    metadata = _meta(
        cms,
        "api-surface",
        "PrestaShop webservice endpoint published",
        "Reports when the PrestaShop webservice (/api/) answers an anonymous GET with the "
        "platform's own Basic authentication challenge (WWW-Authenticate: Basic "
        'realm="PrestaShop Webservice"), which is the endpoint\'s own advertisement that it '
        "is served. The finding reports the realm and the status; the check sends no "
        "credential and attempts no authentication. Read-only GET probes.",
        research_ref="ch03#31",
        cwe="CWE-200",
        framework=("WSTG-INFO-06", "API9:2023", "ATT&CK-T1592.002", "CWE-200"),
        severity="low",
        estimated_requests=4,
    )

    paths_key = "api_paths"
    default_paths = ("/api/", "/api/products")
    # The webservice answers an anonymous caller with 401 and its own Basic realm: that is
    # the detection, not a refusal.
    ok_statuses = (401,)
    max_findings = 2
    finding_title = "PrestaShop webservice reachable ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        if "/api" not in path:
            return None
        challenge = page.header("www-authenticate") or ""
        if "prestashop" not in challenge.lower():
            return None
        return _Hit(
            "webservice-realm-published",
            {"status": page.status, "realm": challenge, "credential_test_sent": False},
            confidence=0.8,
        )


# --------------------------------------------------------------------------- Magento (m3.magento-*)
class MagentoConfigSource(_CmsProbe, WebCheck, Module):
    """``m3.magento-config-source`` — env.php/local.xml served as source (ch03#31)."""

    cms = "magento"
    cms_names = _CMS_NAMES[cms]
    metadata = _meta(
        cms,
        "config-source",
        "Magento configuration served as source",
        "Reports when a Magento configuration file (app/etc/env.php for 2.x, app/etc/local.xml "
        "for 1.x) answers with the file's source instead of executing it: the PHP file carries "
        "its own 'db'/crypt declarations and the XML file its host/username elements. A "
        "correctly served configuration writes nothing over HTTP. The finding names the "
        "identifiers, never a value. Read-only GET probes.",
        research_ref="ch03#31",
        cwe="CWE-540",
        framework=("WSTG-CONF-03", "WSTG-CONF-02", "ATT&CK-T1552", "CWE-540"),
        severity="medium",
        estimated_requests=4,
    )

    paths_key = "config_source_paths"
    default_paths = ("/app/etc/env.php", "/app/etc/local.xml", "/app/etc/env.php.txt")
    finding_title = "Magento configuration source disclosed ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        return _source_signal(page, ctx, self.cms, backup=False)


class MagentoConfigBackup(_CmsProbe, WebCheck, Module):
    """``m3.magento-config-backup`` — a configuration backup is served (ch03#31, CWE-530)."""

    cms = "magento"
    cms_names = _CMS_NAMES[cms]
    metadata = _meta(
        cms,
        "config-backup",
        "Magento configuration backup file exposed",
        "Probes the backup and editor-spill names Magento deployments leave beside app/etc "
        "(env.php.bak, local.xml.bak, their ~/.save/.old/.orig variants) and reports one that "
        "is served as configuration source. The database credential and the encryption key "
        "live in these files. The finding names the identifiers, never a value. Read-only GET "
        "probes.",
        research_ref="ch03#31",
        cwe="CWE-530",
        framework=("WSTG-CONF-04", "WSTG-CONF-03", "ATT&CK-T1552", "CWE-530"),
        compliance=("ISO-A.8.12", "CSF-ID.AM-02"),
        severity="medium",
        estimated_requests=11,
    )

    paths_key = "config_backup_paths"
    finding_title = "Magento configuration backup readable ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        return _source_signal(page, ctx, self.cms, backup=True)


class MagentoAdminSurface(_CmsProbe, WebCheck, Module):
    """``m3.magento-admin-surface`` — the admin login is served (ch03#19, CWE-200)."""

    cms = "magento"
    cms_names = _CMS_NAMES[cms]
    metadata = _meta(
        cms,
        "admin-surface",
        "Magento admin login surface reachable",
        "Reports when the Magento admin answers an anonymous GET with the platform's own "
        "backend login page (the adminhtml-auth-login body class and the "
        "login[username]/login[password] field names). The admin path is configurable, so the "
        "check probes the operator's bounded candidate list. This is the installation's "
        "default-credential surface: the finding reports that the surface is reachable, as a "
        "configuration observation, and the check sends no credential and attempts no login. "
        "Read-only GET probes.",
        research_ref="ch03#19",
        cwe="CWE-200",
        framework=("WSTG-CONF-05", "WSTG-IDNT-04", "ATT&CK-T1592.002", "CWE-200"),
        severity="low",
        estimated_requests=5,
    )

    paths_key = "admin_paths"
    default_paths = ("/admin/", "/admin")
    max_findings = 2
    finding_title = "Magento admin login reachable ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        return _admin_signal(page, ctx, self.cms)


class MagentoVersionDisclosure(_CmsProbe, WebCheck, Module):
    """``m3.magento-version-disclosure`` — the edition/version is published (ch03#31)."""

    cms = "magento"
    cms_names = _CMS_NAMES[cms]
    metadata = _meta(
        cms,
        "version-disclosure",
        "Magento version and edition disclosed",
        "Reports when the Magento version endpoint (/magento_version) or a release document "
        "(RELEASE_NOTES.txt) publishes the version and edition in the platform's own form. A "
        "version is a fingerprint and is never a severity on its own (FP-3). Read-only GET "
        "probes.",
        research_ref="ch03#31",
        cwe="CWE-200",
        framework=("WSTG-INFO-08", "WSTG-INFO-09", "ATT&CK-T1592.002", "CWE-200"),
        severity="low",
        estimated_requests=5,
    )

    paths_key = "version_paths"
    default_paths = ("/magento_version", "/RELEASE_NOTES.txt")
    finding_title = "Magento version disclosed ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        return _version_signal(page, ctx, self.cms, r"(?:Magento/|Magento\s+v?)([0-9][\w.\-]*)")


class MagentoInstallerResidue(_CmsProbe, WebCheck, Module):
    """``m3.magento-installer-residue`` — the setup wizard is served (ch03#31, CWE-200)."""

    cms = "magento"
    cms_names = _CMS_NAMES[cms]
    metadata = _meta(
        cms,
        "installer-residue",
        "Magento setup wizard reachable",
        "Reports when the Magento setup wizard (/setup/) or the 1.x Connect Manager "
        "(/downloader/) answers an anonymous client with its own installation page instead of "
        "being removed or blocked. The setup wizard belongs to the installation window. "
        "Read-only GET probes.",
        research_ref="ch03#31",
        cwe="CWE-200",
        framework=("WSTG-CONF-05", "WSTG-CONF-02", "CWE-200"),
        severity="low",
        estimated_requests=5,
    )

    paths_key = "installer_paths"
    default_paths = ("/setup/", "/setup/index.php", "/downloader/")
    finding_title = "Magento setup wizard reachable ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        return _installer_signal(page, ctx, self.cms)


class MagentoApiSurface(_CmsProbe, WebCheck, Module):
    """``m3.magento-api-surface`` — the anonymous REST store routes are served (ch03#31)."""

    cms = "magento"
    cms_names = _CMS_NAMES[cms]
    body_must_name_cms = False
    metadata = _meta(
        cms,
        "api-surface",
        "Magento REST API store routes published",
        "Reports when a Magento REST route that the platform marks anonymously accessible "
        "(/rest/V1/store/storeViews, /rest/V1/store/storeConfigs) answers with the platform's "
        "own store records: a JSON array of store or website objects. The finding reports the "
        "route and the record count; it claims nothing about the authenticated half of the "
        "API. Read-only GET probes.",
        research_ref="ch03#31",
        cwe="CWE-200",
        framework=("WSTG-INFO-06", "API9:2023", "CWE-200"),
        severity="low",
        estimated_requests=4,
    )

    paths_key = "api_paths"
    default_paths = ("/rest/V1/store/storeViews", "/rest/V1/store/storeConfigs")
    max_findings = 2
    finding_title = "Magento REST store route served ({path})"

    def signal(self, path: str, page: Page, ctx: CheckContext) -> _Hit | None:
        if "/rest/v1/" not in path.lower() or "store" not in path.lower():
            return None
        document = _json_of(page)
        if not isinstance(document, list):
            return None
        shaped = [
            item
            for item in document
            if isinstance(item, Mapping) and "code" in item and "name" in item
        ]
        if not shaped:
            return None
        return _Hit(
            "rest-store-route-published",
            {"records": len(shaped), "status": page.status},
            confidence=0.7,
        )


#: Every check of the family, in run order (grouped per platform, cheapest and most specific
#: first).
CmsFamilyBChecks: tuple[type[Module], ...] = (
    JoomlaConfigSource,
    JoomlaConfigBackup,
    JoomlaAdminSurface,
    JoomlaVersionDisclosure,
    JoomlaInstallerResidue,
    JoomlaApiSurface,
    DrupalConfigSource,
    DrupalConfigBackup,
    DrupalAdminSurface,
    DrupalVersionDisclosure,
    DrupalInstallerResidue,
    DrupalApiSurface,
    MoodleConfigSource,
    MoodleConfigBackup,
    MoodleAdminSurface,
    MoodleVersionDisclosure,
    MoodleInstallerResidue,
    MoodleApiSurface,
    PrestaShopConfigSource,
    PrestaShopConfigBackup,
    PrestaShopAdminSurface,
    PrestaShopVersionDisclosure,
    PrestaShopInstallerResidue,
    PrestaShopApiSurface,
    MagentoConfigSource,
    MagentoConfigBackup,
    MagentoAdminSurface,
    MagentoVersionDisclosure,
    MagentoInstallerResidue,
    MagentoApiSurface,
)
