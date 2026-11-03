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

**What this stage does not do** (recorded rather than implied): POST-body injection, DOM-sink
verification in a browser, session fixation, and the families deferred to S10. See
ADR-100.4-100.7.
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
from arachne.modules.m3.authenticated import AuthenticatedSurface, SessionLogout
from arachne.modules.m3.client import XssOracle
from arachne.modules.m3.client_secret import ClientSecretVerify
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
        "authorization-schema bypass and numeric input validation."
    ),
    version="2.4.0",
    research_chapter="ch03",
    checks=M3_CHECKS,
)
