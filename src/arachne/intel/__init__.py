"""Live threat intelligence and passive OSINT (S18, area INTEL).

Three concerns, kept apart on purpose:

* :mod:`arachne.intel.sources` — what a feed is: URL builders and total parsers for NVD
  API 2.0, the CISA KEV catalogue and FIRST's EPSS scores.
* :mod:`arachne.intel.verify` — why a feed can be trusted: SHA-256 pinning and detached
  RSA signature verification, both fail-closed (REQ-INTEL-002).
* :mod:`arachne.intel.sync` — the service that ties them together behind one scope-pinned
  HTTP path, incrementally and versionedly (REQ-INTEL-001).

:mod:`arachne.intel.freshness` turns what the store holds into the freshness snapshot a
report carries, and :mod:`arachne.intel.index_builder` regenerates the shipped CVE-index
baseline from the synced corpus (the curated overlay stays hand-written).

The *passive OSINT providers* (Shodan, Censys, WHOIS/RDAP, CT logs, HIBP) are deliberately
**not** here: they extend the existing provider layer
(:mod:`arachne.modules.providers`), so they inherit its deny-by-default allowlist, budget,
cache and audit behaviour instead of growing a second, subtly different one.
"""

from __future__ import annotations

from arachne.intel.freshness import (
    FeedObservation,
    intel_snapshot,
    observations_from_store,
)
from arachne.intel.index_builder import BaselineIndex, ProductMap, build_baseline
from arachne.intel.sources import SOURCES, FeedDocument, FeedSource, parse_source, source_for
from arachne.intel.sync import (
    FeedSyncService,
    FixtureFeedTransport,
    ScopedFeedTransport,
    SyncOutcome,
    build_feed_transport,
    build_sync_service,
)
from arachne.intel.verify import (
    VerificationPolicy,
    VerificationResult,
    digest_of,
    verify_payload,
)

__all__ = [
    "SOURCES",
    "BaselineIndex",
    "FeedDocument",
    "FeedObservation",
    "FeedSource",
    "FeedSyncService",
    "FixtureFeedTransport",
    "ProductMap",
    "ScopedFeedTransport",
    "SyncOutcome",
    "VerificationPolicy",
    "VerificationResult",
    "build_baseline",
    "build_feed_transport",
    "build_sync_service",
    "digest_of",
    "intel_snapshot",
    "observations_from_store",
    "parse_source",
    "source_for",
    "verify_payload",
]
