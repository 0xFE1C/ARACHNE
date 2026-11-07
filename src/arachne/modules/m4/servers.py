"""WP-30 · Server, platform and runtime configuration (REQ-DET-023).

Twenty-four read-only L1 checks over the defaults a server, a platform or a runtime leaves
reachable. The requirement's scope names nine areas and this module covers each:

* **nginx** (3) — the stock welcome page, the ``stub_status`` counters and a served
  ``nginx.conf``;
* **Apache** (3) — the stock default/test page, a served ``httpd.conf``/``apache2.conf`` and the
  basic-auth password file (``.htpasswd``);
* **IIS** (2) — the ``iisstart`` welcome page and the served ``applicationHost.config`` /
  ``administration.config``;
* **Caddy** (2) — the **admin API** (``/config/...``, read-only) and a served ``Caddyfile``;
* **directory indexing** (2) — the **machine-readable** auto-index forms (``autoindex_format
  json`` and ``xml``). The shipped ``m4.directory-listing`` already claims the HTML auto-index,
  so this family claims the data-document forms it does not;
* **container runtimes** (2) — the Docker Engine API and Podman's libpod API answered to a
  **version query only** (see the pitfall note below);
* **orchestration and registries** (4) — the Kubernetes Dashboard behind the API-server proxy,
  the kubelet's unauthenticated read-only endpoint, the registry ``_catalog`` and the registry
  dashboards (Harbor, Nexus, Artifactory, Portainer);
* **message-broker consoles** (3) — ActiveMQ (console and Jolokia), the NATS monitoring
  endpoints, and the consoles the dashboard corpus does not name (EMQX, RocketMQ, Kafka UI,
  Pulsar Manager). RabbitMQ is deliberately absent: ``m4.dashboard-exposure`` already
  fingerprints it, and a second claim on the same product would be a duplicate;
* **header, cookie and caching defaults** (3) — a ``Server`` banner that names a version, the
  stack headers (``X-Powered-By``, ``X-AspNet-Version``, ...) and a session response a shared
  cache may store.

**Read-only, and nothing else.** Every request is a ``GET``: no verb but ``GET`` appears
anywhere in this module, asserted structurally by ``tests/integration/test_wp30_scan.py``.
Nothing is uploaded, deleted, started, stopped, decoded or reconstructed. A served file is
read at most ``body_limit`` bytes and its claim is the *disclosure*, not its content.

**A container daemon that answers a version query is a finding; a command through it never
is.** The pitfall is explicit, and it is the one place this family could overstep: a Docker or
Podman socket is a remote-control interface, and "list the containers", "start a container",
"read a secret" are all one endpoint away. This module therefore names **version endpoints
only** — ``/version`` and ``/libpod/version`` — and records ``command_issued: false`` in the
evidence. Reading a version proves the daemon is reachable from the scanning position, which
is the whole claim; nothing else about the daemon is asked of it, ever.

**A default page is not automatically a finding.** The decoy is one hardened installation per
family, and the pitfall cuts the other way too: a stock page that is behind a challenge, or
that is the site's actual front page, discloses nothing. Every check in this family therefore
requires (1) a ``2xx`` answer, (2) content that is the artefact's *own* — a marker, not a
status code — and (3) silence from the installation's own not-found rendering, its catch-all
page and the ``401`` challenge a hardened server answers with. ``tests/integration/
test_wp30_scan.py`` drives all twenty-four checks against every installation in all four modes
and asserts each positive is found and every decoy is silent, including the soft-404 that
answers ``200`` and echoes the requested path.

**FP-3 governs the two banner checks.** A product/version in a header is a *signal*, never a
severity claim on its own: ``m4.server-version-disclosure`` and ``m4.stack-header-disclosure``
ship at ``low``, report the header line they read, and say in their evidence that no
vulnerability is claimed and no CVE is correlated. Neither fires on a banner with no version
(``Server: Caddy``) or a generic one (``Server: webserver``).
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Any, ClassVar

from arachne.core.proof import ProofLevel
from arachne.core.results import CheckResult
from arachne.core.target import TargetKind
from arachne.modules.base import CheckMetadata, Module, SeverityHint
from arachne.modules.context import CheckContext
from arachne.modules.m3.inventory import Page, WebInventory
from arachne.modules.m4.corpus import ArtifactProbe, M4Corpus
from arachne.modules.m4.support import (
    UrlCheck,
    asset_origin,
    corpus_for,
    exchange_from_page,
    finding_cap,
    http_or_skip,
    is_catchall_page,
    looks_like_not_found,
    m4_candidate,
    not_found_for,
    owns_origin,
    pages_of_origin,
    probe_paths,
    skip,
    text_contains_any,
    web_or_skip,
)

__all__ = [
    "AREAS",
    "AREA_OF_CHECK",
    "AREA_OF_GROUP",
    "GROUPS_BY_AREA",
    "HEADER_CHECK_NAMES",
    "PROBE_CHECK_NAMES",
    "ActiveMqConsoleExposed",
    "ApacheConfigFileExposed",
    "ApacheDefaultPage",
    "ApacheHtpasswdExposed",
    "AutoindexJsonExposed",
    "AutoindexXmlExposed",
    "BrokerConsoleExposed",
    "CacheableSessionResponse",
    "CaddyAdminApiExposed",
    "CaddyConfigFileExposed",
    "DockerApiExposed",
    "IisApplicationHostExposed",
    "IisDefaultPage",
    "KubeletReadonlyExposed",
    "KubernetesDashboardExposed",
    "NatsMonitoringExposed",
    "NginxConfigFileExposed",
    "NginxDefaultPage",
    "NginxStubStatusExposed",
    "PodmanApiExposed",
    "RegistryCatalogExposed",
    "RegistryDashboardExposed",
    "ServerChecks",
    "ServerVersionDisclosure",
    "StackHeaderDisclosure",
]

#: The family tag every finding carries, so one heuristic rule can cover the whole set.
FAMILY = "server-platform"

#: The signal name a probe finding carries (the rules key on it, the way ``artifact-exposure``
#: covers WP-29's family and ``dashboard-exposure`` covers the shipped dashboard check).
SIGNAL = "server-config-exposure"

#: The signal name the header/cookie/caching findings carry.
HEADER_SIGNAL = "server-default-disclosure"

#: Severity of the two banner checks: FP-3 — a version in a header is a signal, not a finding
#: of its own, so it is reported at the lowest level that still carries the claim.
_BANNER_SEVERITY: SeverityHint = "low"


def _meta(
    *,
    name: str,
    title: str,
    description: str,
    research_ref: str,
    cwe: str,
    framework: tuple[str, ...],
    severity: SeverityHint,
    estimated_requests: int,
    compliance: tuple[str, ...] = (),
) -> CheckMetadata:
    """Build one check's metadata: L1, safe, read-only, default-on, URL-scoped.

    The family's contract is ``files.py``'s: an anonymous ``GET`` sweep of a bounded path
    inventory, decided against the installation's own not-found rendering. Every member is
    ``hybrid`` (it probes the origin and classifies the answer), no member sets
    ``requires_active_checks``, and none requires a state-change attestation.

    The arguments are keyword-only on purpose: the research-coverage scanner
    (``modules/coverage.py``) attributes a ``research_ref`` to the nearest preceding
    ``id=``/``name=`` literal, so a factory whose check name is a *positional* argument hides
    it from the matrix — the defect WP-25 ... WP-28 recorded. Every call site writes ``name=``,
    which is the convention WP-29 established for a factory-based family.
    """
    return CheckMetadata(
        id=f"m4.{name}",
        module="M4",
        name=name,
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
        verifiable=True,
        enabled_by_default=True,
        proof=ProofLevel.L1,
        estimated_requests=estimated_requests,
        runs_on_discovered=True,
        target_kinds=(TargetKind.URL,),
    )


class _ServerCheck:
    """The shared shape: a bounded ``GET`` sweep of one group, decided on the artefact's own
    content.

    A concrete check is declared ``class X(_ServerCheck, UrlCheck, Module)`` and sets its
    ``metadata`` plus the class attributes below. This is a plain mixin rather than a
    :class:`~arachne.modules.base.Module` subclass, for the same reason WP-29's
    ``_ArtifactCheck`` is: the base refuses to be created without metadata and a family base
    has none of its own.
    """

    metadata: ClassVar[CheckMetadata]
    #: The corpus group this check sweeps (``servers.groups.<group>``).
    group: ClassVar[str] = ""
    #: The candidate title; ``{path}`` is the probed path.
    finding_title: ClassVar[str] = "Server configuration or default page served ({path})"

    def probes(self, ctx: CheckContext) -> tuple[ArtifactProbe, ...]:
        return corpus_for(ctx).server_probes(self.group)

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        client, skipped = http_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        if not owns_origin(ctx):
            yield skip(ctx, "another URL asset on this origin owns the M4 probes for it")
            return
        corpus = corpus_for(ctx)
        origin = asset_origin(ctx)
        probes = self.probes(ctx)
        if not probes:
            yield skip(ctx, f"the M4 corpus names no server paths for group {self.group!r}")
            return
        not_found = await not_found_for(ctx, origin)
        min_bytes = corpus.server_min_bytes()
        cap = finding_cap(ctx)
        findings = 0
        for probe in await probe_paths(
            ctx, origin, [item.path for item in probes], not_found=not_found
        ):
            page = probe.page
            # A challenge (``401``/``403``) is not an exposure: the artefact is there but a
            # caller who has not authenticated cannot read it. Only a 2xx is considered, and
            # the *content* still has to be the artefact's own.
            if page is None or not 200 <= page.status < 300:
                continue
            if looks_like_not_found(page, not_found):
                continue
            if is_catchall_page(page, not_found=not_found, root=None):
                continue
            definition = next((item for item in probes if item.path == probe.path), None)
            markers = () if definition is None else definition.markers
            family = self.group if definition is None else definition.family
            marker = text_contains_any(page.body, markers)
            if marker is None:
                continue
            if page.body_length < min_bytes:
                continue
            findings += 1
            artifact: dict[str, Any] = {
                "signal": SIGNAL,
                "family": FAMILY,
                "group": self.group,
                "platform_family": family,
                "path": probe.path,
                "status": page.status,
                "content_type": page.content_type,
                "marker": marker,
                "bytes": page.body_length,
                "body_limit": client.body_limit,
                "truncated": page.truncated,
                "origin": origin,
                # The finding is the *disclosure*; nothing is executed, started or changed.
                "anonymous": True,
                "command_issued": False,
            }
            yield m4_candidate(
                ctx,
                self.finding_title.format(path=probe.path),
                artifact=artifact,
                exchanges=(
                    exchange_from_page(page),
                    None if not_found is None else exchange_from_page(not_found),
                ),
                confidence=0.9,
                detail=(
                    f"{probe.url} returned HTTP {page.status} "
                    f"({page.content_type or 'unknown type'}, {page.body_length} bytes)"
                    f"; marker: {marker!r}"
                ),
                source=probe.url,
            )
            if findings >= cap:
                break
        if not findings:
            yield ctx.clean(
                f"no {self.metadata.name.replace('-', ' ')} found",
                detail=f"probed {len(probes)} path(s) on {origin}",
            )


# --------------------------------------------------------------------------- nginx
class NginxDefaultPage(_ServerCheck, UrlCheck, Module):
    """``m4.nginx-default-page`` — the stock nginx welcome page (ch04#22)."""

    group = "nginx_default_page"
    finding_title = "Stock server default page served ({path})"
    metadata = _meta(
        name="nginx-default-page",
        title="Stock nginx default page served",
        description="Requests the welcome page a freshly installed nginx serves and reports it "
        "when the site itself answers with it. The page is confirmed by its own text, so a "
        "404, an error page or a hardened site's front page is never the finding. Its "
        "presence discloses that the virtual host was never configured — the deployment "
        "is serving the package's default document root — and it names the server "
        "product. Read-only GET probes.",
        research_ref="ch04#22",
        cwe="CWE-200",
        framework=("WSTG-INFO-02", "WSTG-CONF-02", "CWE-200"),
        compliance=("CIS-16.8", "ISO-A.8.9"),
        severity="low",
        estimated_requests=5,
    )


class NginxStubStatusExposed(_ServerCheck, UrlCheck, Module):
    """``m4.nginx-stub-status-exposed`` — the unauthenticated ``stub_status`` counters."""

    group = "nginx_stub_status"
    finding_title = "nginx status endpoint served without authentication ({path})"
    metadata = _meta(
        name="nginx-stub-status-exposed",
        title="nginx stub_status endpoint reachable without authentication",
        description="Requests the locations nginx's stub_status module is commonly mounted at "
        "and reports one whose own counters are served. The answer is confirmed by the "
        "module's output (its connection counters and request line), never by a status "
        "code. The counters disclose live traffic volume, the number of connections and "
        "the server's operating state to an unauthenticated caller. Read-only GET probes.",
        research_ref="ch04#7",
        cwe="CWE-306",
        framework=("WSTG-CONF-05", "WSTG-INFO-02", "CWE-306"),
        compliance=("CIS-4.7", "ISO-A.5.15", "ISO-A.8.9"),
        severity="low",
        estimated_requests=6,
    )


class NginxConfigFileExposed(_ServerCheck, UrlCheck, Module):
    """``m4.nginx-config-file-exposed`` — a served ``nginx.conf`` (ch04#22)."""

    group = "nginx_config_file"
    finding_title = "Web-server configuration file served ({path})"
    metadata = _meta(
        name="nginx-config-file-exposed",
        title="nginx configuration file served",
        description="Requests the nginx configuration file at the locations a misconfigured "
        "document root or an alias exposes and reports one that is served. The file is "
        "confirmed by its own directives (the worker and event configuration beside the "
        "http block), so a refusal page is never mistaken for it. A served configuration "
        "names the virtual hosts, the upstreams, the include paths and often the "
        "credential a proxy sets. Read-only GET probes.",
        research_ref="ch04#22",
        cwe="CWE-538",
        framework=("WSTG-CONF-02", "WSTG-INFO-05", "CWE-538"),
        compliance=("CIS-16.8", "ISO-A.8.9", "ISO-A.8.12"),
        severity="medium",
        estimated_requests=6,
    )


# --------------------------------------------------------------------------- Apache
class ApacheDefaultPage(_ServerCheck, UrlCheck, Module):
    """``m4.apache-default-page`` — Apache's stock default/test page (ch04#22)."""

    group = "apache_default_page"
    finding_title = "Stock server default page served ({path})"
    metadata = _meta(
        name="apache-default-page",
        title="Stock Apache default page served",
        description="Requests the default page the distribution's Apache package installs and "
        "reports it when it is the site's own answer. The page is confirmed by its own "
        "text (the distribution's welcome wording), which is what tells it apart from the "
        "server's refusal pages. It discloses an unconfigured virtual host and the exact "
        "distribution of the server. Read-only GET probes.",
        research_ref="ch04#22",
        cwe="CWE-200",
        framework=("WSTG-INFO-02", "WSTG-CONF-02", "CWE-200"),
        compliance=("CIS-16.8", "ISO-A.8.9"),
        severity="low",
        estimated_requests=6,
    )


class ApacheConfigFileExposed(_ServerCheck, UrlCheck, Module):
    """``m4.apache-config-file-exposed`` — a served ``httpd.conf``/``apache2.conf``."""

    group = "apache_config_file"
    finding_title = "Web-server configuration file served ({path})"
    metadata = _meta(
        name="apache-config-file-exposed",
        title="Apache configuration file served",
        description="Requests the Apache configuration file at the locations a misconfigured "
        "document root exposes and reports one that is served. It is confirmed by its own "
        "directives (the server root, the loaded modules and the document root), which is "
        "what a refusal page cannot imitate. A served configuration names the virtual "
        "hosts, the enabled modules and the directories the server will serve. Read-only "
        "GET probes.",
        research_ref="ch04#22",
        cwe="CWE-538",
        framework=("WSTG-CONF-02", "WSTG-INFO-05", "CWE-538"),
        compliance=("CIS-16.8", "ISO-A.8.9", "ISO-A.8.12"),
        severity="medium",
        estimated_requests=6,
    )


class ApacheHtpasswdExposed(_ServerCheck, UrlCheck, Module):
    """``m4.apache-htpasswd-exposed`` — the served basic-auth password file (ch04#22)."""

    group = "apache_htpasswd_exposed"
    finding_title = "Basic-auth password file served ({path})"
    metadata = _meta(
        name="apache-htpasswd-exposed",
        title="Apache basic-auth password file served",
        description="Requests the password file an Apache realm authenticates against and "
        "reports one that is served. A password entry is confirmed by the hash format "
        "itself (an Apache MD5, SHA or bcrypt entry), never by the file name alone. The "
        "file names the accounts of the realm and carries the salted digests of their "
        "passwords, which is the whole credential store for that realm. This is a "
        "different claim from ``m4.authorization-file-exposed``, which reports a served "
        "``.htaccess`` rule file. Read-only GET probes.",
        research_ref="ch04#22",
        cwe="CWE-522",
        framework=("WSTG-ATHN-02", "WSTG-CONF-04", "CWE-522"),
        compliance=("CIS-16.8", "ISO-A.5.17", "ISO-A.8.12"),
        severity="high",
        estimated_requests=6,
    )


# --------------------------------------------------------------------------- IIS
class IisDefaultPage(_ServerCheck, UrlCheck, Module):
    """``m4.iis-default-page`` — the IIS welcome page (ch04#22)."""

    group = "iis_default_page"
    finding_title = "Stock server default page served ({path})"
    metadata = _meta(
        name="iis-default-page",
        title="Stock IIS default page served",
        description="Requests the welcome page a default IIS installation serves and reports it "
        "when the site's own answer is that page. It is confirmed by its own wording "
        "(the Windows Server welcome text and the Internet Information Services "
        "product name). It discloses an unconfigured site and the server family. "
        "Read-only GET probes.",
        research_ref="ch04#22",
        cwe="CWE-200",
        framework=("WSTG-INFO-02", "WSTG-CONF-02", "CWE-200"),
        compliance=("CIS-16.8", "ISO-A.8.9"),
        severity="low",
        estimated_requests=4,
    )


class IisApplicationHostExposed(_ServerCheck, UrlCheck, Module):
    """``m4.iis-applicationhost-exposed`` — the served IIS ``applicationHost.config``."""

    group = "iis_applicationhost_config"
    finding_title = "IIS server configuration file served ({path})"
    metadata = _meta(
        name="iis-applicationhost-exposed",
        title="IIS server configuration file served",
        description="Requests the IIS server configuration and administration files and reports "
        "the ones served. Each is confirmed by its own XML elements (the application-host "
        "and pool sections, the module providers), so an ASP.NET application's own "
        "``web.config`` — a different file with a different claim — is not reported here. "
        "The server configuration lists every site, application pool, binding and module "
        "the server runs. Read-only GET probes.",
        research_ref="ch04#22",
        cwe="CWE-538",
        framework=("WSTG-CONF-02", "WSTG-INFO-05", "CWE-538"),
        compliance=("CIS-16.8", "ISO-A.8.9", "ISO-A.8.12"),
        severity="high",
        estimated_requests=6,
    )


# --------------------------------------------------------------------------- Caddy
class CaddyAdminApiExposed(_ServerCheck, UrlCheck, Module):
    """``m4.caddy-admin-api-exposed`` — the Caddy admin API read as configuration."""

    group = "caddy_admin_api_exposed"
    finding_title = "Caddy admin API served without authentication ({path})"
    metadata = _meta(
        name="caddy-admin-api-exposed",
        title="Caddy admin API reachable without authentication",
        description="Performs a read-only GET of Caddy's admin API configuration endpoints and "
        "reports one that returns the running configuration. The answer is confirmed by "
        "the configuration document's own keys (the automatic-HTTPS and storage settings, "
        "the server list), never by a status code. The admin API is Caddy's control "
        "plane: a caller who can read the configuration learns every listener, proxy "
        "target and TLS policy. Only GET is issued — nothing is loaded, changed or "
        "reloaded. Read-only GET probes.",
        research_ref="ch04#11",
        cwe="CWE-306",
        framework=("WSTG-CONF-05", "WSTG-CONF-02", "CWE-306"),
        compliance=("CIS-4.7", "ISO-A.5.15", "ISO-A.8.2"),
        severity="high",
        estimated_requests=5,
    )


class CaddyConfigFileExposed(_ServerCheck, UrlCheck, Module):
    """``m4.caddy-config-file-exposed`` — a served ``Caddyfile``."""

    group = "caddy_config_file_exposed"
    finding_title = "Web-server configuration file served ({path})"
    metadata = _meta(
        name="caddy-config-file-exposed",
        title="Caddy configuration file served",
        description="Requests the Caddyfile at the locations a misconfigured document root or "
        "alias exposes and reports one that is served. It is confirmed by its own "
        "directives (the reverse-proxy and file-server directives, the encoding rule), "
        "which is what a refusal page cannot imitate. A served Caddyfile names the "
        "upstreams, the static roots and the TLS settings of every site the server "
        "publishes. Read-only GET probes.",
        research_ref="ch04#22",
        cwe="CWE-538",
        framework=("WSTG-CONF-02", "WSTG-INFO-05", "CWE-538"),
        compliance=("CIS-16.8", "ISO-A.8.9", "ISO-A.8.12"),
        severity="medium",
        estimated_requests=5,
    )


# --------------------------------------------------------------------------- directory indexing
class AutoindexJsonExposed(_ServerCheck, UrlCheck, Module):
    """``m4.autoindex-json-exposed`` — a directory published as a JSON index."""

    group = "autoindex_json_exposed"
    finding_title = "Directory index published as a data document ({path})"
    metadata = _meta(
        name="autoindex-json-exposed",
        title="Directory published as a machine-readable JSON index",
        description="Requests directories that are commonly auto-indexed and reports one whose "
        "answer is a listing in the JSON form of the index (nginx's autoindex_format "
        "json, or an equivalent). The answer is confirmed by the document's own entry "
        "records, not by a status code. It is a different claim from "
        "``m4.directory-listing``, which reports the HTML auto-index: a data document is "
        "the listing a script consumes, so it survives an operator's attempt to hide the "
        "browsable page. Read-only GET probes.",
        research_ref="ch04#9",
        cwe="CWE-548",
        framework=("WSTG-CONF-02", "WSTG-INFO-05", "CWE-548"),
        compliance=("CIS-16.8", "ISO-A.8.12"),
        severity="medium",
        estimated_requests=4,
    )


class AutoindexXmlExposed(_ServerCheck, UrlCheck, Module):
    """``m4.autoindex-xml-exposed`` — a directory published as an XML index."""

    group = "autoindex_xml_exposed"
    finding_title = "Directory index published as a data document ({path})"
    metadata = _meta(
        name="autoindex-xml-exposed",
        title="Directory published as a machine-readable XML index",
        description="Requests directories that are commonly auto-indexed and reports one whose "
        "answer is a listing in the XML form of the index. The answer is confirmed by the "
        "listing document's own elements (its listing root and per-entry directory "
        "records with their modification times), not by a status code. As with the JSON "
        "form, the claim is the data-document index rather than the browsable page. "
        "Read-only GET probes.",
        research_ref="ch04#9",
        cwe="CWE-548",
        framework=("WSTG-CONF-02", "WSTG-INFO-05", "CWE-548"),
        compliance=("CIS-16.8", "ISO-A.8.12"),
        severity="medium",
        estimated_requests=4,
    )


# --------------------------------------------------------------------------- container runtimes
class DockerApiExposed(_ServerCheck, UrlCheck, Module):
    """``m4.docker-api-exposed`` — the Docker Engine API answers a version query."""

    group = "docker_api_exposed"
    finding_title = "Container daemon API answers without authentication ({path})"
    metadata = _meta(
        name="docker-api-exposed",
        title="Container daemon API reachable without authentication (version query)",
        description="Issues a single read-only GET of the Docker Engine API's version endpoint "
        "and reports it when the daemon answers with its own version document. Nothing "
        "else is ever asked of the daemon: no container is listed, started, stopped or "
        "inspected, and no command is issued through it (the evidence records "
        "``command_issued: false``). That a remote caller can read the version at all is "
        "the finding, and it is the whole finding — an unauthenticated daemon socket is "
        "a remote-control interface, and this check deliberately stops at the door. "
        "Read-only GET probe.",
        research_ref="ch04#12",
        cwe="CWE-306",
        framework=("WSTG-CONF-05", "WSTG-CONF-01", "CWE-306"),
        compliance=("CIS-4.7", "CIS-5.2", "ISO-A.5.15", "ISO-A.8.2", "PCI-7"),
        severity="high",
        estimated_requests=7,
    )


class PodmanApiExposed(_ServerCheck, UrlCheck, Module):
    """``m4.podman-api-exposed`` — Podman's libpod API answers a version query."""

    group = "podman_api_exposed"
    finding_title = "Container daemon API answers without authentication ({path})"
    metadata = _meta(
        name="podman-api-exposed",
        title="Podman libpod API reachable without authentication (version query)",
        description="Issues a single read-only GET of Podman's libpod version endpoint and "
        "reports it when the daemon answers with its own version document (confirmed by "
        "that document's own fields, not by a status code). As with the Docker Engine "
        "API, no other endpoint is named and no command is issued: the claim is that the "
        "libpod service is reachable from the scanning position without authentication. "
        "Read-only GET probe.",
        research_ref="ch04#12",
        cwe="CWE-306",
        framework=("WSTG-CONF-05", "WSTG-CONF-01", "CWE-306"),
        compliance=("CIS-4.7", "CIS-5.2", "ISO-A.5.15", "ISO-A.8.2", "PCI-7"),
        severity="high",
        estimated_requests=6,
    )


# ------------------------------------------------------------------ orchestration & registries
class KubernetesDashboardExposed(_ServerCheck, UrlCheck, Module):
    """``m4.kubernetes-dashboard-exposed`` — the dashboard behind the API-server proxy."""

    group = "kubernetes_dashboard_exposed"
    finding_title = "Kubernetes Dashboard reachable ({path})"
    metadata = _meta(
        name="kubernetes-dashboard-exposed",
        title="Kubernetes Dashboard reachable behind the API-server proxy",
        description="Requests the API-server proxy paths that publish the Kubernetes Dashboard "
        "and reports one that answers with the dashboard itself, confirmed by its own "
        "title and application markers. The proxy path is reachable from wherever the "
        "API server is; when it answers without a credential the dashboard's views — "
        "workloads, secrets, logs — are one click away for a caller who should not have "
        "them. Read-only GET probes.",
        research_ref="ch04#11",
        cwe="CWE-306",
        framework=("WSTG-CONF-05", "WSTG-CONF-01", "CWE-306"),
        compliance=("CIS-4.7", "CIS-5.4", "ISO-A.5.15", "ISO-A.8.2", "CSF-PR.AA-05", "PCI-7"),
        severity="high",
        estimated_requests=4,
    )


class KubeletReadonlyExposed(_ServerCheck, UrlCheck, Module):
    """``m4.kubelet-readonly-exposed`` — the kubelet's unauthenticated read-only endpoint."""

    group = "kubelet_readonly_exposed"
    finding_title = "Kubelet read-only endpoint served without authentication ({path})"
    metadata = _meta(
        name="kubelet-readonly-exposed",
        title="Kubelet read-only endpoint reachable without authentication",
        description="Requests the kubelet's historically unauthenticated read-only endpoint and "
        "reports one that returns the node's own pod list or its kubelet "
        "configuration. The answer is confirmed by the document's own kind and fields, "
        "never by a status code. The read-only port publishes every pod on the node "
        "with its spec, images and host paths, which is a complete map of the workload "
        "for a caller who never authenticated. Read-only GET probes.",
        research_ref="ch04#12",
        cwe="CWE-306",
        framework=("WSTG-CONF-05", "WSTG-CONF-01", "CWE-306"),
        compliance=("CIS-4.7", "CIS-5.4", "ISO-A.5.15", "ISO-A.8.2", "PCI-7"),
        severity="high",
        estimated_requests=5,
    )


class RegistryCatalogExposed(_ServerCheck, UrlCheck, Module):
    """``m4.registry-catalog-exposed`` — the container registry's ``_catalog``."""

    group = "registry_catalog_exposed"
    finding_title = "Container registry catalogue served without authentication ({path})"
    metadata = _meta(
        name="registry-catalog-exposed",
        title="Container registry catalogue reachable without authentication",
        description="Requests the registry API's catalogue endpoint and reports it when the "
        "registry answers with its repository list, confirmed by that document's own "
        "key. Listing the catalogue is a read: no manifest is pulled and no blob is "
        "fetched. It discloses every repository the registry holds, which is the "
        "supply-chain inventory — including the internal images an operator never "
        "published. Read-only GET probes.",
        research_ref="ch04#12",
        cwe="CWE-306",
        framework=("WSTG-CONF-05", "WSTG-CONF-01", "CWE-306"),
        compliance=("CIS-4.7", "ISO-A.5.15", "ISO-A.8.2", "ISO-A.8.28"),
        severity="medium",
        estimated_requests=3,
    )


class RegistryDashboardExposed(_ServerCheck, UrlCheck, Module):
    """``m4.registry-dashboard-exposed`` — the registry products' system APIs."""

    group = "registry_dashboard_exposed"
    finding_title = "Registry dashboard reachable without authentication ({path})"
    metadata = _meta(
        name="registry-dashboard-exposed",
        title="Container registry dashboard reachable without authentication",
        description="Requests the system endpoints of the registry products a deployment "
        "publishes — Harbor, Nexus Repository, Artifactory and Portainer — and reports "
        "one that answers unauthenticated, confirmed by that product's own system "
        "document. Each endpoint is a read: it reports the product's version and status "
        "and exposes the interface a reader would then browse. Read-only GET probes.",
        research_ref="ch04#11",
        cwe="CWE-306",
        framework=("WSTG-CONF-05", "WSTG-CONF-01", "CWE-306"),
        compliance=("CIS-4.7", "CIS-6.5", "ISO-A.5.15", "ISO-A.8.2", "PCI-7"),
        severity="medium",
        estimated_requests=5,
    )


# --------------------------------------------------------------------------- message brokers
class ActiveMqConsoleExposed(_ServerCheck, UrlCheck, Module):
    """``m4.activemq-console-exposed`` — the ActiveMQ console and Jolokia."""

    group = "activemq_console_exposed"
    finding_title = "Message-broker console reachable ({path})"
    metadata = _meta(
        name="activemq-console-exposed",
        title="ActiveMQ console or Jolokia endpoint reachable without authentication",
        description="Requests the ActiveMQ web console and its Jolokia management endpoint and "
        "reports the ones that answer unauthenticated, each confirmed by its own content "
        "(the console's own title, or Jolokia's agent and protocol document). Jolokia "
        "publishes the broker's configuration attribute by attribute; the console "
        "publishes its queues and their message counts. RabbitMQ is deliberately not "
        "covered here — ``m4.dashboard-exposure`` already fingerprints it. Read-only "
        "GET probes.",
        research_ref="ch04#12",
        cwe="CWE-306",
        framework=("WSTG-CONF-05", "WSTG-CONF-01", "CWE-306"),
        compliance=("CIS-4.7", "CIS-6.5", "ISO-A.5.15", "ISO-A.8.2", "PCI-7"),
        severity="medium",
        estimated_requests=5,
    )


class NatsMonitoringExposed(_ServerCheck, UrlCheck, Module):
    """``m4.nats-monitoring-exposed`` — the NATS monitoring endpoints."""

    group = "nats_monitoring_exposed"
    finding_title = "Message-broker monitoring endpoint served ({path})"
    metadata = _meta(
        name="nats-monitoring-exposed",
        title="Message-broker monitoring endpoint reachable without authentication",
        description="Requests the NATS server's monitoring endpoints and reports the ones that "
        "answer unauthenticated, each confirmed by that document's own fields (the server "
        "identifier and connection counters, the connection and subscription listings). "
        "The listings name the clients connected to the broker and the subjects they "
        "subscribe to. Read-only GET probes.",
        research_ref="ch04#12",
        cwe="CWE-306",
        framework=("WSTG-CONF-05", "WSTG-CONF-01", "CWE-306"),
        compliance=("CIS-4.7", "ISO-A.5.15", "ISO-A.8.2", "PCI-7"),
        severity="medium",
        estimated_requests=6,
    )


class BrokerConsoleExposed(_ServerCheck, UrlCheck, Module):
    """``m4.broker-console-exposed`` — the brokers other than RabbitMQ and ActiveMQ."""

    group = "broker_console_exposed"
    finding_title = "Message-broker console reachable ({path})"
    metadata = _meta(
        name="broker-console-exposed",
        title="Message-broker console reachable without authentication",
        description="Requests the management consoles of the message brokers the shipped "
        "dashboard corpus does not name — EMQX, the RocketMQ console, Kafka UI and "
        "Pulsar Manager — and reports the ones that answer unauthenticated, each "
        "confirmed by that product's own rendered title. A broker console lists the "
        "topics, queues and consumers and usually publishes a test-publish form, which "
        "is why an exposed one is reported rather than dismissed as a monitoring "
        "page. Read-only GET probes.",
        research_ref="ch04#11",
        cwe="CWE-306",
        framework=("WSTG-CONF-05", "WSTG-CONF-01", "CWE-306"),
        compliance=("CIS-4.7", "CIS-6.5", "ISO-A.5.15", "ISO-A.8.2", "PCI-7"),
        severity="medium",
        estimated_requests=5,
    )


# --------------------------------------------------------------------------- header defaults
class ServerVersionDisclosure(UrlCheck, Module):
    """``m4.server-version-disclosure`` — a ``Server`` header that names a version."""

    metadata = _meta(
        name="server-version-disclosure",
        title="Server product and version disclosed in a response header",
        description="Reads the Server response header of every crawled page and reports one "
        "that names a product *and* a version. Per FP-3 a version banner is a signal, "
        "not a severity claim: the finding states which header disclosed what and "
        "correlates no CVE. A banner with no version (Server: Caddy) or a generic one "
        "(Server: webserver) is not reported, because it discloses no version to "
        "fingerprint. No new request is made — the header is read from the crawl. "
        "Read-only.",
        research_ref="ch04#16",
        cwe="CWE-200",
        framework=("WSTG-INFO-02", "WSTG-INFO-08", "CWE-200"),
        compliance=("CIS-16.8", "ISO-A.8.9", "ISO-A.8.12"),
        severity=_BANNER_SEVERITY,
        estimated_requests=0,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        _client, skipped = http_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        if not owns_origin(ctx):
            yield skip(ctx, "another URL asset on this origin owns the M4 review for it")
            return
        inventory, skipped = web_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        assert isinstance(inventory, WebInventory)
        corpus = corpus_for(ctx)
        origin = asset_origin(ctx)
        header_name = corpus.server_header_name()
        pattern = corpus.server_version_regex()
        if pattern is None:
            yield skip(ctx, "the M4 corpus names no server version pattern")
            return
        pages = pages_of_origin(inventory, origin)
        if not pages:
            yield ctx.clean(
                "no page was fetched for this origin",
                detail="the crawl reached no page here",
            )
            return
        reported: set[str] = set()
        findings = 0
        for page in pages:
            value = page.header(header_name)
            if not value:
                continue
            match = pattern.search(value)
            if match is None or match.group(0).lower() in reported:
                continue
            reported.add(match.group(0).lower())
            findings += 1
            yield m4_candidate(
                ctx,
                f"Server version disclosed in the {header_name.title()} header",
                artifact={
                    "signal": HEADER_SIGNAL,
                    "family": FAMILY,
                    "kind": "server-banner",
                    "header": header_name,
                    "value": value[:120],
                    "product_version": match.group(0),
                    "url": page.url,
                    "origin": origin,
                    # FP-3: a banner is a signal. No vulnerability and no CVE is claimed.
                    "version_claim": False,
                },
                exchanges=(exchange_from_page(page),),
                confidence=0.85,
                detail=f"{page.url} answered with {header_name}: {value[:120]}",
                source=page.url,
            )
        if not findings:
            yield ctx.clean(
                "no version-bearing server banner",
                detail=f"read the {header_name} header of {len(pages)} page(s) on {origin}",
            )


class StackHeaderDisclosure(UrlCheck, Module):
    """``m4.stack-header-disclosure`` — ``X-Powered-By`` and the ASP.NET version headers."""

    metadata = _meta(
        name="stack-header-disclosure",
        title="Application stack and version disclosed in a response header",
        description="Reads the response headers of every crawled page and reports the ones that "
        "disclose the stack running behind the server — X-Powered-By, the ASP.NET and "
        "ASP.NET MVC version headers, a generator header. Per FP-3 this is a signal, not "
        "a severity claim: the finding names the header and the value it carried and "
        "correlates no CVE. The IIS and PHP defaults are the reason this is a *platform* "
        "default rather than an application bug. No new request is made. Read-only.",
        research_ref="ch04#16",
        cwe="CWE-200",
        framework=("WSTG-INFO-02", "WSTG-INFO-08", "CWE-200"),
        compliance=("CIS-16.8", "ISO-A.8.9", "ISO-A.8.12"),
        severity=_BANNER_SEVERITY,
        estimated_requests=0,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        _client, skipped = http_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        if not owns_origin(ctx):
            yield skip(ctx, "another URL asset on this origin owns the M4 review for it")
            return
        inventory, skipped = web_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        assert isinstance(inventory, WebInventory)
        corpus = corpus_for(ctx)
        origin = asset_origin(ctx)
        names = corpus.stack_headers()
        if not names:
            yield skip(ctx, "the M4 corpus names no stack-disclosure headers")
            return
        pages = pages_of_origin(inventory, origin)
        if not pages:
            yield ctx.clean(
                "no page was fetched for this origin",
                detail="the crawl reached no page here",
            )
            return
        findings = 0
        seen: set[str] = set()
        for page in pages:
            for raw_name, value in page.headers.items():
                name = raw_name.lower()
                if name not in names or name in seen:
                    continue
                seen.add(name)
                findings += 1
                yield m4_candidate(
                    ctx,
                    f"Application stack disclosed in the {raw_name} header",
                    artifact={
                        "signal": HEADER_SIGNAL,
                        "family": FAMILY,
                        "kind": "stack-banner",
                        "header": name,
                        "value": str(value)[:120],
                        "url": page.url,
                        "origin": origin,
                        "version_claim": False,
                    },
                    exchanges=(exchange_from_page(page),),
                    confidence=0.85,
                    detail=f"{page.url} answered with {raw_name}: {str(value)[:120]}",
                    source=page.url,
                )
        if not findings:
            yield ctx.clean(
                "no stack-disclosure header",
                detail=f"read {len(pages)} page(s) on {origin} for {', '.join(names)}",
            )


class CacheableSessionResponse(UrlCheck, Module):
    """``m4.cacheable-session-response`` — a session response a shared cache may store."""

    metadata = _meta(
        name="cacheable-session-response",
        title="Response establishing a session is cacheable by a shared cache",
        description="Reads the structural cookie projection of every crawled page and reports a "
        "response that establishes session state (it sets a session-like cookie) while its "
        "own Cache-Control *tells a shared cache to store it* — a public, max-age or "
        "s-maxage directive, or an Expires date, with no no-store/no-cache/private "
        "beside it. That combination is what lets a cache in front of the application "
        "hand one caller's session page to the next. A response that merely omits "
        "Cache-Control is deliberately **not** reported: absent headers are the common "
        "case on any dynamic page, and the first draft of this check measured a 42 % "
        "false-positive rate on the shared M4 lab for exactly that reason (see the "
        "WP-30 handoff). The cookie's *name* is read; its value was dropped at capture "
        "and never reaches the check. This is the caching default of a server family, "
        "distinct from m4.cookie-flag-audit, which reports the missing Secure/HttpOnly/"
        "SameSite attributes on the cookie itself. No new request is made. Read-only.",
        research_ref="ch04#18",
        cwe="CWE-524",
        framework=("WSTG-SESS-02", "WSTG-CONF-02", "CWE-524"),
        compliance=("CIS-16.7", "ISO-A.8.9", "CSF-PR.DS-01", "PCI-6"),
        severity="medium",
        estimated_requests=0,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        _client, skipped = http_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        if not owns_origin(ctx):
            yield skip(ctx, "another URL asset on this origin owns the M4 review for it")
            return
        inventory, skipped = web_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        assert isinstance(inventory, WebInventory)
        corpus = corpus_for(ctx)
        origin = asset_origin(ctx)
        pages = pages_of_origin(inventory, origin)
        if not pages:
            yield ctx.clean(
                "no page was fetched for this origin",
                detail="the crawl reached no page here",
            )
            return
        findings = 0
        for page in pages:
            cookies = _session_cookies(page, corpus)
            if not cookies:
                continue
            if not _shared_cache_allowed(page, corpus):
                continue
            findings += 1
            yield m4_candidate(
                ctx,
                "Session response is cacheable by a shared cache",
                artifact={
                    "signal": HEADER_SIGNAL,
                    "family": FAMILY,
                    "kind": "cacheable-session",
                    "url": page.url,
                    "cookie_names": list(cookies),
                    "cache_control": page.header(corpus.cache_control_header()) or "",
                    "expires": page.header(corpus.expires_header()) or "",
                    "status": page.status,
                    "origin": origin,
                    "shared_cache_allowed": True,
                },
                exchanges=(exchange_from_page(page),),
                confidence=0.7,
                detail=(
                    f"{page.url} set {', '.join(cookies)} beside a "
                    f"{corpus.cache_control_header()} that a shared cache may store"
                ),
                source=page.url,
            )
        if not findings:
            yield ctx.clean(
                "no cacheable session response",
                detail=f"reviewed {len(pages)} page(s) on {origin}",
            )


def _session_cookies(page: Page, corpus: M4Corpus) -> tuple[str, ...]:
    """The names of the session-like cookies this response set (never their values)."""
    names = corpus.server_session_cookie_names()
    tokens = corpus.server_session_cookie_tokens()
    found: list[str] = []
    for cookie in page.cookies:
        lowered = cookie.name.lower()
        if lowered in names or any(token in lowered for token in tokens):
            found.append(cookie.name)
    return tuple(found)


def _shared_cache_allowed(page: Page, corpus: M4Corpus) -> bool:
    """True when the response's own headers entitle a shared cache to store it.

    The check requires *positive* evidence: a public/max-age/s-maxage directive or an Expires
    date, with no directive that privatises the response beside it. A response that simply
    says nothing about caching is not reported — that is the overwhelmingly common case, and
    treating "no header" as "cacheable" is what the first draft did before the shared M4 lab
    measured it at a 42 % false-positive rate.
    """
    if any(
        marker in _directive(page, corpus).lower() for marker in corpus.cache_private_directives()
    ):
        return False
    if page.header(corpus.expires_header()):
        return True
    return any(
        marker in _directive(page, corpus).lower()
        for marker in corpus.server_shared_cache_directives()
    )


def _directive(page: Page, corpus: M4Corpus) -> str:
    return page.header(corpus.cache_control_header()) or ""


#: Every WP-30 check, in the order the families appear above.
ServerChecks: tuple[type[Module], ...] = (
    NginxDefaultPage,
    NginxStubStatusExposed,
    NginxConfigFileExposed,
    ApacheDefaultPage,
    ApacheConfigFileExposed,
    ApacheHtpasswdExposed,
    IisDefaultPage,
    IisApplicationHostExposed,
    CaddyAdminApiExposed,
    CaddyConfigFileExposed,
    AutoindexJsonExposed,
    AutoindexXmlExposed,
    DockerApiExposed,
    PodmanApiExposed,
    KubernetesDashboardExposed,
    KubeletReadonlyExposed,
    RegistryCatalogExposed,
    RegistryDashboardExposed,
    ActiveMqConsoleExposed,
    NatsMonitoringExposed,
    BrokerConsoleExposed,
    ServerVersionDisclosure,
    StackHeaderDisclosure,
    CacheableSessionResponse,
)

#: The nine scope areas the requirement names. The first eight each own one or more corpus
#: groups; the ninth (``header-defaults``) is the three checks that classify response headers
#: and carry no path inventory at all, so it has no group. Used by the acceptance test to
#: assert the family actually spans the requirement's scope — and to prove that the three
#: header checks are the only ones whose claim is read from the crawl rather than a probe.
GROUPS_BY_AREA: dict[str, tuple[str, ...]] = {
    "nginx": ("nginx_default_page", "nginx_stub_status", "nginx_config_file"),
    "apache": ("apache_default_page", "apache_config_file", "apache_htpasswd_exposed"),
    "iis": ("iis_default_page", "iis_applicationhost_config"),
    "caddy": ("caddy_admin_api_exposed", "caddy_config_file_exposed"),
    "directory-index": ("autoindex_json_exposed", "autoindex_xml_exposed"),
    "container-runtime": ("docker_api_exposed", "podman_api_exposed"),
    "orchestration-registry": (
        "kubernetes_dashboard_exposed",
        "kubelet_readonly_exposed",
        "registry_catalog_exposed",
        "registry_dashboard_exposed",
    ),
    "message-broker": (
        "activemq_console_exposed",
        "nats_monitoring_exposed",
        "broker_console_exposed",
    ),
    "header-defaults": (),
}

#: The three checks of the ``header-defaults`` area, by name. They read the headers of the
#: crawl the scan already made, so they name no path inventory and own no group.
HEADER_CHECK_NAMES: tuple[str, ...] = (
    "server-version-disclosure",
    "stack-header-disclosure",
    "cacheable-session-response",
)

#: The nine scope areas in the order the requirement names them.
AREAS: tuple[str, ...] = tuple(GROUPS_BY_AREA)

#: Every corpus group the family sweeps → the area that owns it.
AREA_OF_GROUP: dict[str, str] = {
    group: area for area, groups in GROUPS_BY_AREA.items() for group in groups
}

#: Every check name → the scope area it covers (the module's own declaration, which the
#: acceptance test reads so "which positive is this?" has one answer in one place). The three
#: header checks carry no corpus group — they read the crawl — so they are mapped by name.
AREA_OF_CHECK: dict[str, str] = {
    check.metadata.name: AREA_OF_GROUP[group]
    for check in ServerChecks
    if (group := getattr(check, "group", "")) in AREA_OF_GROUP
} | dict.fromkeys(HEADER_CHECK_NAMES, "header-defaults")

#: The names of the checks whose group the corpus actually defines, so a test can assert that
#: the eight probe areas and only they carry a path inventory.
PROBE_CHECK_NAMES: tuple[str, ...] = tuple(
    name for name, area in AREA_OF_CHECK.items() if area != "header-defaults"
)
