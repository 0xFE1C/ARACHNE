"""M1 · Recon & Attack Surface .

M1 maps the target's surface from third-party and read-only sources *before* any active
contact, and feeds the asset inventory the other modules attach to. Its checks are
the ones listed for this stage plus the three S18 intel checks (each strictly
opt-in, because each one asks somebody else's service about the target):

======================================  ==========  =====================================
check                                    ref         what it does
======================================  ==========  =====================================
``m1.dork-sweep``                        ch01#1      run the versioned dork corpus
``m1.code-secret-mining``                ch01#2      public code-host secret mining (opt-in)
``m1.internetdb-triage``                 ch01#5      keyless Shodan InternetDB over addresses
``m1.ct-lookup``                         ch01#8      certificate transparency hostnames
``m1.passive-dns``                       ch01#11     historical resolutions
``m1.subdomain-passive``                 ch01#13     merged passive subdomain aggregation
``m1.webarchive-harvest``                ch01#14-16  Wayback / Common Crawl URL harvesting
``m1.email-harvest``                     ch01#17     employee addresses + naming pattern
``m1.doc-metadata``                      ch01#22     PDF /Info and image EXIF metadata
``m1.favicon-hash``                      ch01#23     favicon fingerprint matching
``m1.dns-txt-mining``                    ch01#25     SPF/DKIM/DMARC records (passive)
``m1.js-asset-scan``                     ch01#26     JS endpoints and hardcoded credentials
``m1.bucket-hunt``                       ch01#30     public cloud-storage listings
``m1.service-exposure-drift``            ch01#3-4    provider vs. scan view (opt-in, keyed)
``m1.ct-surprise``                       ch01#8-9    new certs + out-of-scope CT names (opt-in)
``m1.breach-exposure``                    ch01#18     HIBP breach summary (opt-in, keyed)
``m1.nameserver-inventory``              ch01#6      DNS delegation set (WP-34)
``m1.mail-infrastructure-inventory``     ch01#6      mail exchangers (WP-34)
``m1.certificate-inventory``             ch01#24     certificate issuers and windows (WP-34)
``m1.certificate-expiry``                ch01#24     expired/expiring certificates (WP-34)
``m1.asn-network-attribution``           ch01#27     the network an address is allocated from
``m1.reverse-ip-cluster``                ch01#12     hostnames co-located on one address
``m1.technology-inventory``              ch02#10     published-technology breadth (from the crawl)
``m1.vhost-discovery``                   ch02#12     alternate names the address serves
======================================  ==========  =====================================

A note on the ``research_ref`` values: the M1 table lists a reference number per
check, and several of those numbers are off by one or two against the method numbering in
``docs/research/01-reconnaissance-and-osint.md`` (its ``ch01#7`` is FOFA, while CT log
mining is method 8, and so on). The reference stored here is the **canonical method number in
the research chapter** — the corpus is what the coverage matrix of G-01 counts, and a
reference that points at the wrong method would make that count wrong. The deviation is
recorded in ADR-070.3.
"""

from __future__ import annotations

from arachne.modules.base import Module
from arachne.modules.m1.assets import InternetDbTriage, JsAssetScan
from arachne.modules.m1.exposure import CodeSecretMining, DorkSweep, EmailHarvest
from arachne.modules.m1.hardening import (
    BucketHunt,
    DnsTxtMining,
    DocMetadata,
    FaviconHash,
)
from arachne.modules.m1.intel import (
    BreachExposure,
    CertificateSurprise,
    ServiceExposureDrift,
)
from arachne.modules.m1.inventory import (
    CtLookup,
    PassiveDns,
    SubdomainPassive,
    WebArchiveHarvest,
)
from arachne.modules.m1.mobile import MobileArtifactScan
from arachne.modules.m1.recon_breadth import RECON_BREADTH_CHECKS
from arachne.modules.registry import ModuleGroup

__all__ = ["M1", "M1_CHECKS"]

#: Every M1 check class, in the order the module lists them.
M1_CHECKS: tuple[type[Module], ...] = (
    DorkSweep,
    CodeSecretMining,
    InternetDbTriage,
    CtLookup,
    PassiveDns,
    SubdomainPassive,
    WebArchiveHarvest,
    EmailHarvest,
    JsAssetScan,
    DnsTxtMining,
    FaviconHash,
    BucketHunt,
    DocMetadata,
    ServiceExposureDrift,
    CertificateSurprise,
    BreachExposure,
    # S29 detection depth expansion (REQ-DEPTH-005): offline APK/IPA analysis. Passive (L0 —
    # it contacts nothing), opt-in, and gated by a scope dimension of its own.
    MobileArtifactScan,
    # WP-34 reconnaissance breadth (REQ-DET-027): DNS/RDAP/CT enumeration, ASN attribution,
    # reverse-IP clustering and the two crawl readers (technology breadth, virtual hosts).
    *RECON_BREADTH_CHECKS,
)

#: The M1 module group . Its version is the module's own: bump it when
#: the set of checks or their behaviour changes, and the scan report records it (F-02-10).
M1 = ModuleGroup(
    id="M1",
    title="Recon & Attack Surface",
    description=(
        "Passive reconnaissance and OSINT: map the target's surface from third-party and "
        "read-only sources before any active contact, and feed the asset inventory."
    ),
    version="1.3.0",
    research_chapter="ch01",
    checks=M1_CHECKS,
)
