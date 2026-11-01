# ADR-230 — S18: live threat intel & passive OSINT

Status: accepted (S18, program Phase 3)

This stage makes the scanner's *knowledge* as current as its probes: NVD/KEV/EPSS arrive by
sync instead of by hand, the CVE index is generated from that corpus and corrected by an
operator's overlay, and five third-party indexes (Shodan, Censys, Cert Spotter, HIBP, RDAP)
become usable through the same allowlist that already governs crt.sh. It implements capability
area `INTEL` (REQ-INTEL-001...005) under the standing rules: deny by default, verified data or
none, every refusal audited, credentials never recorded, no new runtime dependency.

---

## 230.1 — The sync is opt-in, and it writes through the existing feed store

`arachne.intel` is a new package, but it adds **no new storage**. A synced feed is imported
through `FeedStore` exactly like an operator's file: the same `feeds`/`feed_entries` rows, the
same normalised artefact under `ARACHNE_FEEDS_DIR`, the same `arachne feeds` verbs and the same
M6 correlation paths. That is what makes "sync once, the next scan uses it" true without a
second wiring, and it keeps the offline import workflow of S14 intact.

Two additions were needed and both are additive:

* `FeedStore.import_entries(...)` — the sync parses and verifies once, then hands over
  normalised rows (a paginated feed is several documents; re-parsing a concatenation would be
  wrong);
* a `nvd` feed kind — the same one-row-per-CVE shape as `cve`, carrying what the NVD corpus
  knows (CVSS, CWE, references and **CPE version ranges**), which is what the index generator
  reads. Everything the sync learns about provenance (pinned digest, verification result,
  resume cursor, upstream publication date) rides in the existing `meta_json`, so no migration
  was needed.

`ARACHNE_INTEL_ENABLED` is the master switch and defaults to off: with it off no sync service
is constructed, so a deployment that never opts in keeps the S14 posture (an operator brings a
file; nothing leaves the process).

## 230.2 — Verification is fail-closed, and "no pin" is a refusal

REQ-INTEL-002 says feeds must be verified before import. The design question is what happens
when there is nothing to verify *against*, and the only safe answer is: refuse.

* **Checksum mode** (default) compares the payload's SHA-256 with a digest the deployment
  pinned (`ARACHNE_INTEL_FEED_CHECKSUMS` inline, or a manifest). A source with no pin is
  refused — never "imported unverified".
* **Signature mode** verifies a detached RSASSA-PKCS1-v1_5 (SHA-256) signature against a
  pinned RSA public key. The verifier reuses the S17 construction (modular exponentiation via
  `pow`, a small DER reader for SPKI/PKCS#1 keys) rather than adding a crypto dependency, and
  refuses anything it cannot check (Ed25519, GPG, a malformed key).
* There is **no "none" mode**. A deployment that cannot verify a feed should import it by hand
  (`arachne feeds import`), where the trust decision is visibly the operator's.

**The digest is over the bytes, and over what an operator would pin.** A single-request source
(KEV's one document, an incremental NVD/EPSS window that fits one page) is verified over its
raw body, so its pin is exactly `sha256sum <file>`. A paginated source is verified over the
length-prefixed concatenation of its pages, which is what `--pin` records; a window that
outgrows a page needs a re-pin. That trade-off is deliberate: the common case stays obvious,
the paginated case stays sound.

**`--pin` is the one trust-on-first-use act, and it is explicit.** It fetches, records the
digests it saw, and then runs the *normal* verify-and-import pass against the manifest it just
wrote — audited as `intel.checksums_pinned`. There is no ambient "accept whatever arrives"
mode; pinning is a sentence an operator writes, once, after establishing out of band which
mirror is theirs.

A rejected payload writes nothing (no rows, no artefact) and is audited as
`intel.feed_rejected` with both digests, because "the mirror served something else" is a
security event rather than a parsing detail.

## 230.3 — The second (and last) verbatim-read exemption

Two instance-level knobs on `ScopedHttpClient` exist for exactly two call sites, and
`tests/unit/test_http_hygiene.py` asserts that set:

| call site | `redaction_enabled=False` | raised `max_body_bytes` | why |
|---|---|---|---|
| `api/oidc.py` (S17) | yes | no | the token exchange must read the credential back |
| `intel/sync.py` (S18) | yes | yes | a feed is integrity-verified on its exact bytes |

For the feed client the reason is narrower than "we want the raw body": a redaction pass would
*edit* the payload, so the digest computed over it would no longer match the pinned one, and
the import would be refused for the wrong reason — or, worse, a feed whose content merely
looked like a secret would be silently altered before it reached vulnerability correlation. The
64 KiB default body cap would truncate a 2,000-record NVD page, so the cap is raised; a body
that is *still* truncated (or binary) is **refused** rather than verified.

The compensating controls: the client is scope-pinned to the feed hosts, the response is parsed
structurally and never logged or persisted (the audit line carries source, status, byte count
and digest), and the artefact that is written is operator data in the same store S14 already
owns.

## 230.4 — The CVE index is a generated baseline plus a curated overlay

The shipped index was ~15 hand-researched entries. That does not scale with feeds, and it is
not what an operator should be maintaining. The index a scan reads is now two layers:

* **baseline** — `templates/m2/cve-index-baseline.yaml`, marked `GENERATED FILE`, produced by
  `arachne intel build-index` from the synced NVD corpus. It is data, not judgement: a row
  exists because the upstream record says the CPE range covers a version M2 can read
  (`templates/m2/cve-index-products.yaml` maps CPE `(vendor, product)` onto the product names
  the fingerprinter emits, and a CVE whose CPEs map to nothing is dropped).
* **overlay** — `templates/m2/cve-index.yaml`, unchanged in shape, still hand-maintained: the
  impact/remediation prose, the priority calls and the signal-triggered entries (SMBv1, SSLv3)
  that no CPE range can express.

`load_cve_index` merges them with the **overlay winning** on a repeated
`(normalized product, cve)` pair. That gives operators a correction mechanism that is one entry
wide, lets the baseline grow without anyone rewriting the table, and keeps the Loader strict
(unknown fields still fail). The merged index reports both versions (`baseline+overlay`), so a
report can say which data produced a match.

The generator is deterministic — sorted output, no timestamp inside entries, provenance in the
header — and a test regenerates the committed file from the recorded corpus and compares it
byte for byte, so a diff always means the corpus changed. Entries gained a `kev` flag (CISA
known-exploited); the M2 correlation now says so in the finding, because that is the signal an
operator acts on first.

## 230.5 — Freshness is a scan-time snapshot, not a render-time lookup

A report is evidence: it must not change because someone re-read the database later. So
freshness is captured **when the scan is admitted** — `build_orchestrator` injects an
`intel_snapshot` callable (the composition root is where the feed store and settings meet,
`core` stays free of the data layer) — and stored in `scans.stats["intel"]`. The report builder
reads that key exactly as it already reads `stats["proof"]` and `stats["requested_by"]`.

The snapshot distinguishes three states, because they call for different action:

* **fresh** — ingested and inside its configured TTL;
* **stale** — ingested and past it (the report leads with it);
* **not ingested** — no artefact of that kind (`missing`), which is *not* the same statement
  as "matched nothing". A report that silently omits it would let a reader over-trust an
  absence of findings.

Report schema **1.3 → 1.4** adds the top-level `intel` block and appendix §G; HTML/PDF are
unchanged (they do not render the proof state-changes table either — the freshness table is an
evidence artefact, carried by Markdown and JSON).

## 230.6 — Providers extend the existing allowlist; opt-in is two declarations

The five new providers are not a second framework. They are rows in the tables that already
exist — `OSINT_PROVIDER_HOSTS` (the deployment allowlist), `PROVIDER_HOSTS`/`SPECS` (the client
the checks talk to) — plus three fields on `ProviderSpec` that make the S18 requirements
explicit rather than conventional:

* `credentials` — every field a provider needs (Censys needs a pair, so the single `credential`
  string was not enough);
* `opt_in` — the provider is never enabled implicitly;
* `rate_limit_rps` — applied by `OsintAccess` on top of the shared client's per-host limiter.

Three structural guarantees follow, and each has a test:

1. **No opt-in, no call.** None of the five is in `DEFAULT_OSINT_PROVIDERS`. Naming one in
   `ARACHNE_OSINT_PROVIDERS` is the opt-in; the *check* is opt-in too (`enabled_by_default
   = False`), so two declarations stand between a deployment and a provider call.
2. **No credential, no host.** `build_osint_access(usable=...)` drops an unusable provider from
   `enabled` *and* from the scope, and remembers why, so a half-configured provider produces a
   skip naming the missing variable and an `intel.provider_blocked` audit line — never an
   unauthenticated request. Missing credentials therefore degrade to the previous behaviour
   (REQ-INTEL-005), and the socket-armed safety test asserts zero requests.
3. **Pacing is per provider.** These are somebody else's tiers; a scan is not their only
   consumer. A deliberate wait is audited (`intel.rate_limited`).

**Keys are never recorded.** Credentials are `SecretStr` from the environment and build a
header (Censys basic auth, HIBP `hibp-api-key`) or, for Shodan, a query parameter — its REST
API has no header form. Every record of a URL therefore goes through `redact_url(...)`: the
audit target, the log field, the `ProviderResponse` (whose `url` *is* the redacted form) and
hence the finding's evidence. `tests/test_safety.py` scans the log stream, the audit trail, the
events and the evidence of a run that really used the key.

**WHOIS is RDAP.** Port-43 WHOIS cannot pass through `ScopedHttpClient`, and adding a second
egress path for a nice-to-have would be a bad trade. RDAP is the IETF's HTTPS replacement, so
the provider is RDAP over the same client, with the base URL from
`ARACHNE_OSINT_WHOIS_URL`. A referral to an authoritative RDAP server is an out-of-scope hop
and is refused unless the deployment names that host (`ARACHNE_OSINT_EXTRA_HOSTS`) or points
the provider at its own mirror — the same rule as everywhere else, and the guide says so.

## 230.7 — What the three checks report, and what they refuse to claim

`m1.service-exposure-drift` compares what a provider observes on an address with the scan's own
view. M1 runs *before* discovery, so the scan's view is usually its port **coverage** (the
catalogue), and the check says so in its evidence: "the provider sees :31337, this scan will
never look at it". When an inventory *is* available (a check run beside discovery, or on a
discovered asset) the comparison is two-sided and reports both directions.

`m1.ct-surprise` flags certificates issued inside the window
(`ARACHNE_OSINT_CT_WINDOW_DAYS`) and — the actionable half — CT names the scan's scope does not
cover, with RDAP registration facts as context.

`m1.breach-exposure` summarises HIBP's breaches for the domain. It is exposure of the domain's
*users*, not a vulnerability in the target, and the finding says exactly that.

All three are passive (they never touch the target), all three are opt-in, and all three report
"not run" with the reason when their provider is unavailable. None of them invents a severity:
they raise candidates and the analyzer decides (ADR-02).

## 230.8 — Deviations recorded for change control

1. `templates/plan/check_catalog.yaml` **1.6 → 1.7**: three opt-in M1 rows
   (`service-exposure-drift`, `ct-surprise`, `breach-exposure`), so the shipped set is
   129 + 6 (S15) + 3 (S18) = 138 checks, of which 20 are opt-in.
2. `M1.version` **1.0.0 → 1.1.0** (the module's own version tracks its check set, F-02-10).
3. Report schema **1.3 → 1.4** (`report-schema-1.4.json`): the top-level `intel` block. The
   S15/S17 report tests assert `REPORT_SCHEMA_VERSION`, so they followed the bump.
4. Coverage matrix: the three checks map four previously unmapped research methods
   (ch01 #3 Shodan, #4 Censys, #9 WHOIS/RDAP, #18 breach lookups), 144 → 148 of 175. The
   `coverage_matrix.md` artefact is regenerated by `arachne coverage --write coverage_matrix.md`
   in a checkout that carries the research corpus.
5. `FeedStore` gained the `nvd` kind and `import_entries` (additive); `Feed.meta_json` carries
   the sync provenance so no migration was required.
6. `IntelSettings` is new; `OsintSettings` gained the five providers' credentials, the per
   provider pacing table and `ct_window_days`. All defaults preserve S17 behaviour.
7. `ScopedHttpClient` gained `max_body_bytes` (per-instance cap) alongside the existing
   `redaction_enabled`; both exemptions are now pinned by the HTTP-hygiene test.
8. REQ-INTEL-004 is a SHOULD and is implemented as three checks; REQ-INTEL-001/002/003/005 are
   MUSTs and each has its named verification (see the S18 acceptance record).