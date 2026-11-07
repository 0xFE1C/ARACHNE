"""M3 · Web Application .

M3 tests web endpoints for the vulnerability families of the corpus using the
**differential-oracle methodology**: it confirms that a class is present by measuring a
difference a benign probe caused, and never exploits the condition it found. The checks
of this stage are the *core* set of the roadmap's Phase 1 plus the extended M3 families
(NoSQL/SSTI/XXE/command injection/deserialization/LFI/header injection/smuggling/cache/JWT/
OAuth/SAML/HPP/mass-assignment/prototype-pollution/race/business-logic/GraphQL/WebSocket/
subdomain-takeover).

======================================  ==========  ==========================================
check                                    ref         what it establishes
======================================  ==========  ==========================================
``m3.sqli-oracle``                       ch03#1      error/boolean/time differentials
``m3.xss-oracle``                        ch03#3      inert-marker reflection context
``m3.csrf-audit``                        ch03#4      state-changing forms without token/SameSite
``m3.upload-audit``                      ch03#10     upload validation matrix (opt-in)
``m3.traversal-oracle``                  ch03#11     encoding matrix vs a content marker
``m3.open-redirect``                     ch03#14     Location reflection of an arbitrary host
``m3.idor-oracle``                       ch03#18     object-id enumeration / cross-account
``m3.auth-session-audit``                ch03#19     cookie flags, transport, enumeration
``m3.authenticated-surface``             ch03#19     pages only a session reaches (S19)
``m3.cors-audit``                        ch03#23     origin reflection and credential policy
``m3.security-headers``                  ch03#24     header and cookie hardening baseline
``m3.api-surface``                       ch03#31     hidden endpoint inventory
``m3.rate-limit-audit``                  ch03#35     bounded anti-automation profile
``m3.session-logout``                    ch03#19     logout invalidation (S19)
======================================  ==========  ==========================================

**The numbering deviation** S3 recorded for M1 and S4 for M2 applies again: ``research_ref``
values are the canonical method numbers in ``docs/research/03-web-application-testing.md``
(the universe the G-01 coverage matrix counts), while the check **ids** are the corpus's.
See ADR-100.3.

**Safety.** The active checks (everything except ``security-headers``, ``csrf-audit`` and
``api-surface``) need ``--active-checks`` *and* an attestation that authorizes active checks
(F-01-09). On top of that gate: probes are detection-only (single-character deltas, inert
reflection markers, a reserved non-resolving redirect host, ``1=1``/``1=2`` predicate pairs);
nothing is stored or exploited; the traversal marker set is world-readable and non-secret; and
``upload-audit`` stores its single inert marker only when ``ARACHNE_WEB_UPLOAD_PROBE`` is set,
because the M3 safety rules forbid stored payloads by default. Every request goes through the
shared scoped, rate-limited, redacted, audited client (ADR-05).

**Credentialed scanning** (S19, area CREDS, REQ-CREDS-001). When a scan names a credential
(``options.credentials``) the checks step authenticates through the credential broker, crawls
again as the authenticated user, and the two checks below report what a session adds
(``m3.authenticated-surface``) and whether logout ends it (``m3.session-logout``). Both are
opt-in and never handle the credential: the session lives in the HTTP client's cookie jar and
the findings carry redacted exchanges only. This is the half of ch03#19 that S6 recorded as
blocked on "a successful login, which would mean supplying real credentials" — ADR-240.1.

**The WordPress ecosystem family** (WP-25, REQ-DET-018) is the twenty-six checks in
``m3/wordpress.py``: the CMS surface a stock installation publishes to an unauthenticated
client — the ``wp-config.php`` source and the backup names beside it, the XML-RPC endpoint and
its RSD document, the REST route index and user/settings/application-password routes, the
uploads/plugins/themes directory listings, plugin and theme readiness artefacts, ``readme.html``
and ``?ver=``-carrying asset URLs, the debug log, installer and upgrade residue, the
unauthenticated AJAX entry point, the publicly reachable cron endpoint, author-archive and
user-sitemap enumeration, self-registration and the application-password page. Every one is an
L1 read-only probe (one ``OPTIONS`` for the cron endpoint, which cannot trigger the job it
reports as reachable), every one names a ``WSTG-*`` mapping, and the whole family is silent on
its two decoys — a hardened installation and a WAF-fronted one
(``tests/lab/wordpress_lab.py``). The count is carried by the generator: see
``coverage_matrix.md`` and ``python -m arachne.tools.counts``.

**The CMS family B** (WP-26, REQ-DET-019) is the thirty checks in ``m3/cms_family_b.py``: the
same CMS surface for Joomla, Drupal, Moodle, PrestaShop and Magento — the configuration file
served as source and the backup names beside it, the administrative login surface (which is also
the installation's *default-credential* surface, reported as a reachable configuration and never
tested: no check sends a credential or attempts a login), the platform's version artefact, the
installation/upgrade residue the installation window leaves behind, and the published API route.
Every one is an L1 read-only ``GET`` probe, every one names a ``WSTG-*`` mapping, and the whole
family is silent on its decoys — one hardened installation per system plus a WAF-fronted one
(``tests/lab/cms_lab.py``). Two guards carry that: each signal needs the platform's own
structural marker, and it needs the body to name its own platform, so the five installations are
decoys for one another. The count is carried by the generator: see ``coverage_matrix.md`` and
``python -m arachne.tools.counts``.

**The application-server and framework family** (WP-27, REQ-DET-020) is the twenty-five checks
in ``m3/app_servers.py``: the Spring Boot actuator index, configuration surfaces and heap dump;
the Django debug page, debug toolbar and development media listing; the Rails info controller;
the Laravel debug page and Ignition endpoints; the Tomcat manager, host-manager and default
webapps; the JBoss JMX, web and administration consoles; the WebLogic administration console,
UDDI explorer and ``wls-wsat`` component; the ColdFusion administrator, ``CFIDE`` scripts tree
and version disclosure; and the IIS short-name behaviour, ASP.NET trace viewer and legacy
``iisadmpwd`` surface. Every one is an L1 read-only ``GET`` probe, every one names a ``WSTG-*``
mapping, and the management-console checks report a reachable *surface* — they send no
credential and attempt no login. The whole family is silent on its decoys: one
production-configured instance per framework plus a WAF-fronted one, and each framework's
installation is a decoy for the other eight's checks. The count is carried by the generator:
see ``coverage_matrix.md`` and ``python -m arachne.tools.counts``.

**What this stage does not do** (recorded rather than implied): POST-body injection, DOM-sink
verification in a browser, session fixation, and the families deferred to S10. See
ADR-100.4-100.7.

**The API and modern-web surface family** (WP-28, REQ-DET-021) is the twenty-four checks in
``m3/api_surfaces.py``: the OpenAPI 3 and Swagger 2.0 documents a deployment publishes without
authentication, the Swagger UI and ReDoc interfaces, the documentation resource index, and an
operation the published document declares answering an *anonymous* GET; GraphQL introspection
over GET, field-suggestion disclosure, the GraphiQL/Playground IDE and the mutation inventory
the schema advertises; the browser-facing gRPC surface (the Connect protocol's GET form of a
service method and the gRPC-Web preflight); WebSocket origin handling (the ``null`` origin, a
sibling subdomain of the target's own host, and a host-suffix spoof); the serverless and
edge-function endpoints (a Netlify function, a Vercel function route, a Cloud Functions
invocation, an unauthenticated OpenFaaS gateway and a published bundle source map); and the CORS
surface (sibling-subdomain trust, suffix spoof, and the two preflight readings: the methods and
the request headers the policy authorizes). Every one is an L1 read-only probe on the client's
anonymous path — ``GET`` everywhere but the three ``OPTIONS`` preflight rows, which are
opt-in-active exactly as ``m3.wp-cron-surface`` is (F-01-09) — and every one is silent on its
decoys: a conformant deployment that publishes its documentation deliberately *behind
authentication* (the requirement's own decoy), a WAF-fronted one, and the five other surfaces'
vulnerable installations. No check sends a credential, a body or a mutation. The count is
carried by the generator: see ``coverage_matrix.md`` and ``python -m arachne.tools.counts``.
"""

from __future__ import annotations

from arachne.modules.base import Module
from arachne.modules.m3.advanced_api import (
    BusinessLogicAudit,
    GraphQLAudit,
    MassAssignmentAudit,
    PrototypePollution,
    WebSocketAudit,
)
from arachne.modules.m3.advanced_identity import JwtAudit, OAuthFlowAudit, SamlAudit
from arachne.modules.m3.advanced_injection import (
    CmdInjectionOracle,
    DeserializationAudit,
    SstiOracle,
    XxeOracle,
)
from arachne.modules.m3.advanced_protocol import (
    CachePoisonAudit,
    HppOracle,
    RaceOracle,
    RequestSmugglingOracle,
    SsrfProbe,
)
from arachne.modules.m3.api_surfaces import ApiSurfaceChecks
from arachne.modules.m3.app_servers import AppServerChecks
from arachne.modules.m3.authenticated import AuthenticatedSurface, SessionLogout
from arachne.modules.m3.client import XssOracle
from arachne.modules.m3.client_secret import ClientSecretVerify
from arachne.modules.m3.cms_family_b import CmsFamilyBChecks
from arachne.modules.m3.dom_xss import DomSinkCheck
from arachne.modules.m3.exposure import ApiSurface, SecurityHeaders
from arachne.modules.m3.files import TraversalOracle, UploadAudit
from arachne.modules.m3.graphql_depth import GraphQLDepthAbuse, GraphQLResolverAuth
from arachne.modules.m3.hardening import (
    CrlfInjection,
    DirectoryTraversal,
    FileInclusion,
    NosqlOracle,
)
from arachne.modules.m3.identity import AuthSessionAudit, CsrfAudit, IdorOracle
from arachne.modules.m3.injection import SqliOracle
from arachne.modules.m3.injection_families import (
    ArgumentInjectionOracle,
    CodeInjectionOracle,
    LdapInjectionOracle,
    XpathInjectionOracle,
)
from arachne.modules.m3.proof_ladder import (
    CmdiOobProbe,
    RceEchoProof,
    SqliOobProbe,
    SstiOobProbe,
    StateMarkerProof,
    XxeOobProbe,
)
from arachne.modules.m3.surface_families import (
    AuthzBypass,
    CacheDeception,
    EmailHeaderInjection,
    HostHeaderInjection,
    InputValidationAudit,
)
from arachne.modules.m3.takeover import SubdomainTakeover
from arachne.modules.m3.transport import CorsAudit, OpenRedirect, RateLimitAudit
from arachne.modules.m3.websocket_depth import WebSocketInjection, WebSocketUpgradeAuth
from arachne.modules.m3.wordpress import WordPressChecks
from arachne.modules.registry import ModuleGroup

__all__ = ["M3", "M3_CHECKS"]

#: Every M3 check class, in the order the table above lists them. The registry selects checks
#: in this order, so the tuple is the order the checks step runs them in; it also happens to be
#: roughly cheapest-first, which keeps a scan's early output useful while the slow oracles run.
#: S10 appends the extended families (SSRF, SSTI, XXE, command injection, deserialization,
#: smuggling, cache poisoning, JWT, OAuth, SAML, HPP, mass assignment, prototype pollution,
#: race, business logic, GraphQL, WebSocket, subdomain takeover) after the core set.
M3_CHECKS: tuple[type[Module], ...] = (
    SecurityHeaders,
    ApiSurface,
    SubdomainTakeover,
    CsrfAudit,
    DeserializationAudit,
    SqliOracle,
    SstiOracle,
    XxeOracle,
    CmdInjectionOracle,
    XssOracle,
    TraversalOracle,
    # WP-11 browser crawling (REQ-DET-015): the DOM-sink half of ch03#3, reachable only
    # through JavaScript execution — behind the optional `browser` extra and the
    # ARACHNE_WEB_BROWSER_CRAWL opt-in.
    DomSinkCheck,
    OpenRedirect,
    CorsAudit,
    CachePoisonAudit,
    HppOracle,
    IdorOracle,
    AuthSessionAudit,
    JwtAudit,
    OAuthFlowAudit,
    SamlAudit,
    MassAssignmentAudit,
    PrototypePollution,
    GraphQLAudit,
    WebSocketAudit,
    BusinessLogicAudit,
    RaceOracle,
    RequestSmugglingOracle,
    RateLimitAudit,
    UploadAudit,
    SsrfProbe,
    # S10 hardening family (research ch03#2/#12/#13/#15): NoSQL injection, directory traversal,
    # file inclusion (LFI/RFI) and CRLF/HTTP header injection.
    NosqlOracle,
    DirectoryTraversal,
    FileInclusion,
    CrlfInjection,
    # S19 authenticated scanning (area CREDS, research ch03#19): the checks that need a real
    # login — the authenticated-only surface and logout invalidation. Opt-in, and skipped with
    # a reason on a scan that names no credential.
    AuthenticatedSurface,
    SessionLogout,
    # S15 proof ladder (area PROOF): the L2 variants and the attested L3/L4 proofs.
    SqliOobProbe,
    XxeOobProbe,
    CmdiOobProbe,
    SstiOobProbe,
    RceEchoProof,
    StateMarkerProof,
    # S29 detection depth expansion (area DEPTH, REQ-DEPTH-001/002): the GraphQL depth/cost
    # and resolver-authorization probes, and the WebSocket upgrade-auth and inert-message
    # probes. All are opt-in (per-check, and by env switch for the crafted probes).
    GraphQLDepthAbuse,
    GraphQLResolverAuth,
    WebSocketUpgradeAuth,
    WebSocketInjection,
    # REQ-DEPTH-004: the dynamic half of client-side analysis — an L2 check that verifies the
    # *impact* of a statically-found credential (anonymous access + the ladder's OOB token).
    ClientSecretVerify,
    # WP-08 breadth (REQ-DET-004, REQ-DET-009): the four CWE Top 25 emitters and the five
    # missing injection families. Every one is L1 and read-only.
    LdapInjectionOracle,
    XpathInjectionOracle,
    CodeInjectionOracle,
    ArgumentInjectionOracle,
    HostHeaderInjection,
    EmailHeaderInjection,
    CacheDeception,
    AuthzBypass,
    InputValidationAudit,
    # WP-25 CMS family A (REQ-DET-018): the WordPress ecosystem surface — configuration and
    # backup exposure, XML-RPC and the REST API surface, user/author/sitemap enumeration,
    # plugin and theme inventory, the debug log, installer residue, the cron endpoint, the
    # registration and application-password surfaces. Every one is L1 and read-only.
    *WordPressChecks,
    # WP-26 CMS family B (REQ-DET-019): the Joomla, Drupal, Moodle, PrestaShop and Magento
    # surface — configuration source and backup exposure, the administrative login surface
    # (the default-credential surface, reported as configuration and never tested), version
    # disclosure, installation and upgrade residue and the published API route. Every one is
    # L1 and read-only.
    *CmsFamilyBChecks,
    # WP-27 application servers and web frameworks (REQ-DET-020): the Spring Boot actuator and
    # heap-dump surface, the Django debug and media paths, the Rails and Laravel debug surfaces,
    # the Tomcat manager and host-manager, the JBoss console family, the WebLogic console family,
    # the ColdFusion administrator and the IIS family of extensions and short-name behaviour.
    # Every one is an L1 read-only GET probe; the console checks report a reachable surface and
    # never send a credential.
    *AppServerChecks,
    # WP-28 API and modern web surfaces (REQ-DET-021): the OpenAPI/Swagger document surface and
    # an operation declared by a published document answering an anonymous GET, the GraphQL
    # introspection/suggestion/IDE surface and the mutation inventory its schema publishes, the
    # browser-facing gRPC surface (the Connect method's GET form and the gRPC-Web preflight),
    # WebSocket origin handling (null, sibling subdomain, suffix spoof), the serverless and
    # edge-function endpoints (Netlify, Vercel, Cloud Functions, an OpenFaaS gateway and a
    # published bundle source map) and the CORS surface (sibling trust, suffix spoof and the two
    # preflight readings). Every one is L1; the three OPTIONS preflight rows are opt-in-active.
    *ApiSurfaceChecks,
)

#: The M3 module group . Bump the version when the check set or a check's
#: behaviour changes: scan reports record it (F-02-10).
M3 = ModuleGroup(
    id="M3",
    title="Web Application",
    description=(
        "Web-application vulnerability families over the crawled endpoint surface, using "
        "differential oracles that confirm presence without exploiting it: SQL injection, "
        "cross-site scripting, template injection, XXE, command injection, deserialization, "
        "CSRF, upload validation, path traversal, open redirect, SSRF (out-of-band), request "
        "smuggling, cache poisoning, HPP, IDOR, authentication/session posture, JWT/OAuth/SAML "
        "token handling, CORS, security headers, hidden endpoint discovery, mass assignment, "
        "prototype pollution, GraphQL, WebSocket, business logic, race conditions, subdomain "
        "takeover, rate-limit posture, and authenticated surface reachable only with a "
        "configured credential (S19), plus the S29 depth-expansion families: GraphQL "
        "depth/cost and resolver-authorization probes and the WebSocket upgrade-auth and "
        "inert-message-relay probes, plus the WP-08 breadth families: LDAP, XPath, code and "
        "command-argument injection, host- and email-header injection, web cache deception, "
        "authorization-schema bypass and numeric input validation, plus the WP-25 WordPress "
        "ecosystem family: wp-config and backup exposure, the XML-RPC and REST API surface, "
        "user/author/sitemap enumeration, plugin and theme inventory, the debug log, installer "
        "residue, the cron endpoint and the registration and application-password surfaces, "
        "plus the WP-26 CMS family B: the Joomla, Drupal, Moodle, PrestaShop and Magento "
        "configuration, backup, administrative-login, version, installer-residue and API-route "
        "surfaces, plus the WP-27 application-server and framework family: the Spring Boot "
        "actuator and heap-dump surface, the Django debug and media paths, the Rails and Laravel "
        "debug surfaces, the Tomcat manager and host-manager, the JBoss, WebLogic and ColdFusion "
        "consoles and the IIS extension and short-name surfaces, plus the WP-28 API and "
        "modern-web surface family: the OpenAPI/Swagger document surface and an operation a "
        "published document declares answering an anonymous GET, the GraphQL introspection, "
        "suggestion, IDE and mutation-inventory surface, the browser-facing gRPC surface (the "
        "Connect method's GET form and the gRPC-Web preflight), WebSocket origin handling, the "
        "serverless and edge-function endpoints and the CORS surface with its preflight readings."
    ),
    version="2.8.0",
    research_chapter="ch03",
    checks=M3_CHECKS,
)
