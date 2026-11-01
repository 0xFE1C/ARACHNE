"""M4 · Misconfiguration & Exposure (docs/spec/05- M4, research ch. 04).

Misconfiguration is the largest root-cause category in real breaches, and it is also the
cheapest to detect: each method is a finite set of GET requests, a marker, and a
comparison against what the application answers for a path it does not own. M4 is the
module that asks the questions an attacker asks first.

========================================  ==========  ==========================================
check                                      ref         what it establishes
========================================  ==========  ==========================================
``m4.security-header-review``              ch04#16     hardening header/CSP baseline
``m4.cookie-flag-audit``                   ch04#18     Secure/HttpOnly/SameSite
``m4.client-secrets``                      ch04#14     detectors that fired in JS/HTML
``m4.env-file-probe``                      ch04#1      .env/config files served
``m4.vcs-exposure``                        ch04#2      .git/.svn/.hg metadata served
``m4.backup-file-hunt``                    ch04#3      .sql/.bak/.zip artifacts served
``m4.key-exposure``                        ch04#15     private keys served
``m4.sourcemap-exposure``                  ch04#4      JavaScript source maps
``m4.api-doc-exposure``                    ch04#5      Swagger/OpenAPI documents + routes
``m4.debug-endpoints``                     ch04#7      phpinfo/status/Actuator/debug
``m4.directory-listing``                   ch04#9      auto-indexed directories
``m4.dashboard-exposure``                  ch04#11     Jenkins/Grafana/Kibana/... reachable
``m4.hidden-endpoint-hunt``                ch04#24     unlinked sensitive paths
``m4.staging-exposure``                    ch04#25     dev/staging surfaces
``m4.unauth-api-audit``                    ch04#29     documented/internal routes without auth
``m4.bucket-exposure``                     ch04#13     public S3/GCS/Azure bucket listing/ACL
``m4.cors-config-review``                  ch04#19     origin matrix against API endpoints
``m4.tls-config-review``                   ch04#17     protocols/ciphers/certificate
``m4.email-auth-review``                   ch04#20     SPF/DKIM/DMARC posture (OSINT)
``m4.webdav-verbs``                        ch04#21     OPTIONS/PROPFIND/TRACE (opt-in)
``m4.user-enumeration``                    ch04#28     login response differential (opt-in)
``m4.metadata-ssrf``                       ch04#26     metadata posture via a sink (opt-in)
``m4.default-credentials``                 ch04#10     vendor-default existence check (opt-in)
``m4.verbose-errors``                      ch04#6      stack-trace/framework error pages
``m4.actuator-exposure``                   ch04#8      Spring Boot Actuator reachable
``m4.datastore-surface``                   ch04#12     Elasticsearch/CouchDB/... over HTTP
``m4.robots-sitemap``                      ch04#23     robots/sitemap name sensitive paths
``m4.wordpress-surface``                   ch04#27     WordPress users/XML-RPC/REST root
``m4.alias-traversal``                     ch04#30     static-alias path traversal
========================================  ==========  ==========================================

**Numbering.** As for M1/M2/M3, ``research_ref`` values are the canonical method numbers of
``docs/research/04-`` (the universe G-01 counts); the check **ids** are docs/spec/05-'s.
The spec table's refs drift from the corpus from ``debug-endpoints`` onwards; ADR-120.3
records the reconciliation.

**Safety.** M4 is GET/HEAD nearly everywhere. Three checks are ``active`` and therefore
need ``--active-checks`` *and* an authorized attestation: ``cors-config-review`` (an origin
matrix), ``webdav-verbs`` (OPTIONS/PROPFIND/TRACE — read-only, no PUT), and
``user-enumeration`` (a login POST with a dummy password). Two more are opt-in *on top* of
that gate: ``metadata-ssrf`` (``ARACHNE_M4_METADATA_SSRF``) and ``default-credentials``
(``ARACHNE_M4_DEFAULT_CREDENTIALS``), and both must also be named explicitly because they
are ``enabled_by_default=False``. Nothing M4 does is destructive: no upload, no write verb,
no brute-force, no history reconstruction.

**Secrets.** The HTTP client redacts at capture time and reports which detectors fired;
M4's checks pass only the detector *names* into evidence. The operator's sidecar manifest
(``core.secrets``) is fed by the client and encrypted at rest (F-08-04, ADR-120.6).
"""

from __future__ import annotations

from arachne.modules.base import Module
from arachne.modules.m4.client import ClientSecrets
from arachne.modules.m4.cloud import BucketExposure, MetadataSsrf
from arachne.modules.m4.files import (
    BackupFileHunt,
    EnvFileProbe,
    KeyExposure,
    SourceMapExposure,
    VcsExposure,
)
from arachne.modules.m4.hardening import (
    ActuatorExposure,
    AliasTraversal,
    DatastoreSurface,
    RobotsSitemap,
    VerboseErrors,
    WordpressSurface,
)
from arachne.modules.m4.identity import DefaultCredentials, UnauthApiAudit, UserEnumeration
from arachne.modules.m4.surfaces import (
    ApiDocExposure,
    DashboardExposure,
    DebugEndpoints,
    DirectoryListing,
    HiddenEndpointHunt,
    StagingExposure,
    WebdavVerbs,
)
from arachne.modules.m4.transport import (
    CookieFlagAudit,
    CorsConfigReview,
    EmailAuthReview,
    SecurityHeaderReview,
    TlsConfigReview,
)
from arachne.modules.registry import ModuleGroup

__all__ = ["M4", "M4_CHECKS"]

#: Every M4 check, in run order. Inventory producers first (``api-doc-exposure`` publishes
#: routes into the shared crawl, which M3's ``api-surface`` then replays), then the read-only
#: reviews, then the probes, then the three active checks and the two opt-in ones — so a
#: scan's default result is useful before the expensive families run.
M4_CHECKS: tuple[type[Module], ...] = (
    SecurityHeaderReview,
    CookieFlagAudit,
    ClientSecrets,
    EnvFileProbe,
    VcsExposure,
    BackupFileHunt,
    KeyExposure,
    SourceMapExposure,
    ApiDocExposure,
    DebugEndpoints,
    DirectoryListing,
    DashboardExposure,
    HiddenEndpointHunt,
    StagingExposure,
    UnauthApiAudit,
    BucketExposure,
    CorsConfigReview,
    TlsConfigReview,
    EmailAuthReview,
    WebdavVerbs,
    UserEnumeration,
    MetadataSsrf,
    DefaultCredentials,
    VerboseErrors,
    ActuatorExposure,
    DatastoreSurface,
    RobotsSitemap,
    WordpressSurface,
    AliasTraversal,
)

#: The M4 module group (docs/spec/02- §2.2). Bump the version when the set or a check's
#: behaviour changes: scan reports record it (F-02-10).
M4 = ModuleGroup(
    id="M4",
    title="Misconfiguration & Exposure",
    description=(
        "Leaky configuration and exposed components over the crawled web surface and any "
        "declared cloud reference: exposed dotenv/VCS/backup/key material, source maps, API "
        "documents, debug surfaces, directory listings, admin dashboards, staging "
        "environments, stalking-horse routes, public object-store buckets, header/TLS/cookie/"
        "CORS/email-authentication posture, unsafe verbs, user enumeration, anonymous APIs, "
        "cloud-metadata reachability and vendor-default credentials."
    ),
    version="1.0.0",
    research_chapter="ch04",
    checks=M4_CHECKS,
)
