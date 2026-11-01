# Chapter 1 — Passive Reconnaissance and OSINT

The M1 surface. Every method here is either passive (reads a third-party index) or active
against the target's own nameservice; none of them writes, and none of them needs a proof
level above L1. The `research_ref` on each M1 check cites one of the numbered methods below,
and `arachne coverage` reports which of them have no implementing check.

## Methods

### 1. Search-engine dork sweeping

Structured queries against public search indexes to surface exposed documents, panels and
parameterised URLs. Passive: the query goes to the search engine, never to the target.

### 2. Code-hosting repository secret mining

Searching public code-hosting for organisation-owned repositories, then for credential-shaped
strings in their history. Passive and read-only against the host's search API.

### 3. Provider-indexed service exposure drift

Comparing what a provider's index (Shodan, Censys, InternetDB) says is exposed at an address
against what the scan itself observes, to surface services that are internet-visible without
being in the target's own inventory.

### 4. Provider scan-view comparison

Diffing two providers' views of the same address to detect services that appear in one index
and not another, which is where stale or unreconciled exposure hides.

### 5. InternetDB triage of an address

A one-call, key-free triage of an IP: open ports, hostnames, CPEs and known vulnerabilities.
Used to decide whether an address deserves a full scan.

### 6. WHOIS and registration archaeology

Registrar, registrant and name-server history, plus the creation and expiry dates that
distinguish a long-lived estate from a freshly registered look-alike.

### 7. FOFA and alternative search engines

The asset-search engines outside the two the M1 provider layer talks to (Shodan, Censys):
FOFA, ZoomEye and their regional equivalents, which index a different slice of the internet
and answer a different operator question. Not implemented: two provider integrations are the
supported breadth for this release, and the vocabulary is already general enough to add a
third without touching a check.

### 8. Certificate Transparency log lookup

Enumerating every hostname a domain has ever been issued a certificate for, which is the
single highest-yield passive subdomain source.

### 9. Certificate Transparency surprise-host detection

Filtering the CT stream for names that should not exist: expired wildcard leaves, names from
a decommissioned acquisition, a hostname leaked by a pre-release environment.

### 10. Search-engine cache and snippet reuse

Mining cached copies and result snippets for content the live site no longer serves, including
the parameters that used to exist.

### 11. Passive DNS resolution history

Querying passive-DNS providers for the historical A/AAAA/CNAME answer for a name, which
surfaces infrastructure that has since moved.

### 12. Reverse-IP hosted-domain clustering

Enumerating the other names that share an address, to find sibling services and
co-tenants of the same infrastructure.

### 13. Passive subdomain enumeration

Aggregating subdomain candidates from passive sources only (CT, passive DNS, provider
indexes), without sending a query to the target's nameservice.

### 14. Wayback Machine snapshot harvesting

Enumerating archived snapshots of a host across the public web archives, including the
snapshots taken before a redesign.

### 15. Archived parameter and endpoint recovery

Parsing archived snapshots for query parameters, form fields and endpoint paths that the live
application has since removed but which may still be routed.

### 16. Obsolete asset discovery in web archives

Comparing the archived URL set with the live one to name assets, scripts and pages that were
once public and may still be reachable by direct path.

### 17. Email and mailbox harvesting

Building a mailbox list from public sources (CT organisation fields, document metadata, code
commits) for use in an authorised phishing-resilience or credential-exposure review.

### 18. Breach and credential-leak lookups

Checking whether an organisation's addresses appear in a known breach corpus, to prioritise
the accounts an attacker already has a password for.

### 19. Paste-site and forum monitoring

Watching public paste and forum surfaces for organisation identifiers and credential-shaped
strings.

### 20. Social-media and employee enumeration

Collecting publicly posted role, team and technology information that shortens the guesswork
in an authorised engagement.

### 21. Mobile application store listings

Enumerating an organisation's published mobile applications, their package ids and their
declared backend endpoints.

### 22. Public document metadata extraction

Reading author, software and path metadata out of published PDFs and Office documents, which
routinely leaks internal hostnames and user names.

### 23. Favicon hashing for asset correlation

Hashing the served favicon and matching it against provider indexes, which identifies a
technology or a deployment without a single fingerprinting request.

### 24. TLS certificate expiry monitoring

Tracking the expiry dates of internet-facing certificates, because an expired certificate is
an availability finding, not a security one, and belongs in a different queue.

### 25. DNS TXT record mining

Reading TXT records for the third-party verification, policy and configuration records that
disclose the vendors an organisation depends on.

### 26. JavaScript asset and bundle analysis

Collecting the scripts a page loads and extracting from them the internal endpoints, feature
flags and client-side secrets that minified bundles routinely retain.

### 27. Cloud IP-range attribution

Mapping observed addresses into the published AWS/Azure/GCP ranges, which distinguishes
first-party infrastructure from a hosted service.

### 28. Third-party DNS history services

Querying the commercial DNS-history providers whose retention exceeds the free passive-DNS
sources, for names that only ever resolved briefly.

### 29. Domain-similarity and typosquat listing

Enumerating registered names that resemble the target's, which is defensive: the same list
is what an impersonation-monitoring programme consumes.

### 30. Derived cloud-storage bucket name probing

Deriving candidate object-storage bucket names from the organisation's naming conventions and
testing them for anonymous listing. Active and opt-in: it touches third-party provider hosts,
so it needs an authorizing attestation.
