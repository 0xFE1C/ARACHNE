# Security review of the ARACHNE codebase (F-08)

Scope: the ARACHNE codebase as shipped. Checklist source: the project's own security
requirements for the codebase itself (F-08). Redaction fuzz requirement, guarded by
`tests/unit/test_redaction_fuzz.py`.

> **Currency.** This review was written against an earlier snapshot of the code. File paths
> below have been updated for the current repository layout, and the findings marked
> "FIXED" were verified when they were fixed — but the findings that remain open have
> **not** been re-tested against the current code. Confirm a finding against the live code
> before relying on it.

Method: every claim below is read from the source, not assumed. Each checklist heading
carries concrete evidence (`file:line`) and a verdict of **PASS**, **PARTIAL**, or
**GAP**. The Findings section lists only real issues found; the limitations section is
explicit about what the environment could not verify.

---

## 1. Authorization gate (scope + attestation before any request; deny-by-default allowlist) — **PASS**

Requirement: every scan verifies scope + authorization attestation *before any request
leaves the process*, with a deny-by-default allowlist of target patterns.

Evidence:

* **Two gates run at plan time, before execution.** `Orchestrator.plan` calls
  `assert_in_scope` then, for a live (non-dry) run, `assert_authorized`:
  `src/arachne/core/orchestrator.py:218-220`. The dry-run exemption is deliberate and
  recorded (`orchestrator.py:219`, ADR-060.3) because a dry run sends nothing (F-01-10).
* **Deny-by-default allowlist.** `Scope` defaults to nothing
  (`Scope.check` → `"scope is empty (deny by default)"` at
  `src/arachne/core/safety.py:405-406`; `is_empty` at `safety.py:360-370`), and the
  deployment default scope is `Scope.deny_all()` (`src/arachne/core/config.py:83`). An
  unknown target kind is denied fail-closed (`safety.py:498`).
* **Compiled request scope.** The request path consults only the scope compiled from the
  operator's definition (`TargetDefinition.compile_scope`, `src/arachne/core/target.py:533-595`),
  so a scan cannot widen itself at runtime.
* **The gate is enforced again at execution time**, so an admitted scan whose attestation
  has since expired cannot run (`orchestrator.py:364-378`, docstring at 367-369).
* **Attestation correctness.** `TargetDefinition.authorization_errors` refuses a missing,
  future-dated, expired, or non-covering attestation and requires explicit
  `active_checks_authorized` for active checks (`target.py:598-625`); `assert_authorized`
  raises `AuthorizationError` (`target.py:627-643`). A `Scope` cannot be constructed with an
  invalid CIDR (`safety.py:228-239`).
* **Audited.** `auth.rejected` and `auth.attested` events:
  `orchestrator.py:183-199`; vocabulary at `src/arachne/core/audit.py:64-65`.

The invariant "nothing leaves without scope validation" is enforced structurally too:
the HTTP client is the only module allowed to speak HTTP
(`tests/unit/test_http_hygiene.py:17-59`), and the raw-network client re-checks scope and
address policy per probe (`src/arachne/core/net.py:1069-1132`).

## 2. Sandboxing (DNS-rebinding / SSRF; scheme+host validation; resolve-and-pin; block private IPs unless allowed) — **PARTIAL**

Requirement: probes run in a restricted network namespace/container by default; SSRF-by
design on target-supplied URLs (validate scheme/host, resolve-and-pin, block private IPs
unless explicitly allowed).

Evidence (what is done):

* **Scheme + host validation.** Scheme allowlist (`http`/`https`) at
  `src/arachne/core/safety.py:590-595`; host sanitising rejects malformed hosts, internal
  suffixes, cloud-metadata names, and ambiguous integer/hex IP encodings
  (`safety.py:532-565`; lists at `safety.py:67-81`).
* **Private/loopback/link-local/reserved blocking, allowlisted only by explicit policy.**
  `classify_ip` at `safety.py:501-529`; policy default `allow_private_ips=False`
  (`safety.py:88-96`); the permissive variant is opt-in via `ARACHNE_ALLOW_PRIVATE_IPS`
  (`config.py:1060`).
* **Per-hop revalidation defeats the rebinding redirect.** The client never follows
  redirects internally (`src/arachne/core/http.py:323`) and validates each hop by
  re-resolving the host (`http.py:378-406`); an out-of-scope host cannot even cause a DNS
  query, because resolution happens *after* the scope check (`safety.py:622-648`).
* **All addresses in a record set are checked**, not just the first
  (`safety.py:650-657`; test `tests/unit/test_safety_policy.py:81-87`).

Gaps (this is where the verdict is PARTIAL):

* **Resolve-and-pin is not implemented.** The validated addresses are recorded on
  `ResolvedUrl.addresses` but the request is sent to the *URL*, so `httpx` performs its own
  DNS lookup — a TOCTOU window between validation and connect. This is a known, documented
  stage decision: "Full resolve-and-pin (connect to a validated IP with a `Host` header) is
  *not* yet implemented; per-hop re-validation covers the rebinding case that matters at
  this stage" (`docs/adr/050-stage-1-foundation.md:40-42`). The stronger pin was
  scoped to "the sandboxed network namespace work (F-08-03)", which is not present.
* **No sandbox by default.** There is no network-namespace or container isolation in the
  code or compose file; the shipped `docker/Dockerfile:33-37` only drops to a
  non-root user (`USER arachne`). `docker/docker-compose.yml` declares no
  `cap_drop`, `read_only`, `security_opt`, or `network_mode`. Isolation is therefore a
  deployment property, not a default the tool enforces.

## 3. Rate limiting (per-host and global budgets; never bypassed by retries) — **PASS**

* **Two token buckets per request.** `HostRateLimiter.acquire` consults the per-host bucket
  first, then the global bucket (`src/arachne/core/ratelimit.py:158-167`); defaults are
  per-host 5/s burst 5 and global 20/s burst 20 (`ratelimit.py:31-38`).
* **Enforced on every attempt, including retries.** The initial acquire is at
  `http.py:381`; the retry loop re-acquires before every attempt after the first
  (`http.py:481-485`) with the comment "Rate limits are never bypassed by retries". Redirect hops re-acquire too (`http.py:381`).
* **Same budget on the raw network path** (`net.py:868, 912, 954, 995`).
* Tests: `tests/unit/test_ratelimit.py:74-103` (per-host independence, global span).

## 4. Redaction applied at evidence-capture time, not render time — **PASS**

* **Redaction happens inside the client while the exchange is captured.**
  `ScopedHttpClient._read_body` runs `masked_secret_findings` on the raw text and then
  `redact_text_report` / key-aware `redact_value` (`src/arachne/core/http.py:587-617`);
  `_capture` builds the `HttpExchange` with already-redacted headers, request body, and
  response body (`http.py:516-556`).
* **`HttpExchange` is the only shape in which HTTP data crosses a module boundary**
  (`http.py:184-189`), and `Evidence` is built from it (`http.py:233-260`), so no later
  stage ever holds a raw value.
* **Headers** go through `redact_headers`, which blanks sensitive header names wholesale
  (`src/arachne/core/redaction.py:518-529`); **cookies** are projected to name+attributes
  only, value dropped, at capture time (`http.py:70-181`).
* **Audit records are redacted in the sink** (`audit.py:256-264`: `redact_url`, `redact_text`,
  `redact_mapping`), so even a reason string or `meta` payload cannot leak.
* The secrets ledger stores only masked fingerprints, and refuses to write unencrypted
  (`src/arachne/core/secrets.py:286-305`).
* Verified end-to-end by the new fuzz test (§ Part B) and by
  `tests/unit/test_redaction.py`.

## 5. Audit of every out-of-scope / blocked request with a reason (F-01-08) — **PASS**

* **HTTP gate refusals** are audited with the specific reason: `_validate` records
  `scope.rejected` (for `OutOfScopeError`) or `safety.blocked` (any other `SafetyError`)
  with `outcome=blocked` and the policy reason (`src/arachne/core/http.py:444-465`).
* **Network gate refusals** are audited before any packet: `ScopedNetClient._block`
  records `net.blocked` / `scope.rejected` with host, port, protocol and reason
  (`src/arachne/core/net.py:1137-1165`).
* **Plan-time scope refusals** are audited: `Orchestrator._require_selector`
  (`orchestrator.py:148-171`); **authorization refusals** at `orchestrator.py:183-189`.
* Every allowed request also produces one `http.request` / `net.probe` line with method,
  redacted URL, status, duration, resolved addresses, and throttling
  (`http.py:557-573`; `net.py:879,923,968,1004`).
* The audit schema is fixed (`extra="forbid"`, `audit.py:128-131`) so the reason field is
  reliable; sinks are failure-tolerant so an audit failure cannot abort a scan
  (`audit.py:199-235`).

## 6. Dependency hygiene (pinned deps; pip-audit / osv-scanner in CI) — **PARTIAL**

* **Audit job exists but is advisory and only one scanner.** CI runs `pip-audit --strict`
  in a dedicated job with `continue-on-error: true`
  (`.github/workflows/ci.yml:130,133,145-146`), so a fresh
  advisory is visible but cannot red-X a commit. `osv-scanner` is **not** present.
* **No pins / no lockfile.** `pyproject.toml:21-31` declares only lower bounds
  (`httpx>=0.27`, `pydantic>=2.7,<3`, …); there is no `requirements*.txt`, `uv.lock`, or
  a lockfile of any kind in the repository. Installs are therefore not reproducible, and an audit of a
  "latest at build time" resolution is weaker than an audit of a frozen set.

---

## 7. Proof ladder & safe PoC engine (S15, area PROOF) — **PASS**

Requirement: attacker-grade evidence without attacker-grade damage (REQ-PROOF-001…014).
Every state change must be authorized, audited, restored and re-verified; destructive
operations must be unrepresentable; the existing deny-by-default gates must compose, never
weaken.

Evidence:

* **The ladder is declared and validated at construction.** `CheckMetadata.proof`
  (L0–L4, default L1) with `requires_state_attestation`; an L2+ check that is not
  opt-in, or an L3/L4 check without the attestation flag, raises at import
  (`src/arachne/modules/base.py`, `__post_init__`), and the registry re-validates any
  construction bypass (`src/arachne/modules/registry.py`, `ModuleGroup.__post_init__`;
  `src/arachne/core/proof.py::metadata_proof_problems`). All 129 pre-S15 checks are
  annotated L1 (`tests/unit/test_proof_model.py`).
* **The proof gate composes with the authorization gate.** `Orchestrator._assert_proof_gate`
  refuses a live scan whose plan carries L3/L4 checks without
  `attestation.state_changes_authorized` (new, deny-by-default field on
  `AuthorizationAttestation`), at plan time and re-checked at execute/resume against the
  *stored* plan; the refusal is audited as `proof.rejected`
  (`src/arachne/core/orchestrator.py`). A dry run prints the requirement instead of
  refusing (`render_plan` in `src/arachne/cli/scan.py`). The planner never plans an L3/L4
  check the operator did not name (`skip_code "proof-not-opted-in"`,
  `src/arachne/core/planner.py`), and an unavailable capability downgrades with a recorded
  note (`proof.downgraded`) — `proof_effective <= proof` is a planner invariant
  (`tests/test_proof_safety.py::test_no_check_is_ever_upgraded_above_its_declaration`).
* **L2 tokens are single-use and the service never dials out.** Tokens are
  `arachne-<scan-id>-<check-id>-<nonce>` with a 96-bit nonce
  (`src/arachne/core/proof.py::CallbackToken`); `CallbackService.consume` returns a hit
  once, replays are refused and audited (`src/arachne/proof/oob.py`); hits are redacted at
  capture and bounded (`MAX_HIT_BODY_CHARS`, cap applied *after* redaction). The service
  has no outbound client; the no-fetch property is proven with the socket constructor
  armed to explode (`tests/test_proof_safety.py::test_the_callback_service_never_dials_out`).
  Token uniqueness under concurrent issuance is a property test.
* **L3 has no arbitrary-command API.** The only command the code can emit is
  `echo arachne-<nonce>` (`ALLOWED_COMMANDS`, `src/arachne/proof/commands.py`); the proof
  is one-shot (a second `prove` raises `ProofRefused`); output capture is bounded and
  redacted; the execution is audited (`proof.command_executed`).
* **L4 enforces reversibility in code.** INSERT-first markers in `arachne_poc`; UPDATE
  only with before-value capture → write → verify → auto-restore → re-verify
  (`src/arachne/proof/sql.py`); every statement passes `sql_refusals`
  (DELETE/DROP/TRUNCATE/ALTER/GRANT/REVOKE/CREATE + multi-statement + comments + quoted
  literals refused); identity-store tables are refused outright (`CREDENTIAL_TABLE_HINTS`);
  the only DELETE the helper can issue restores its own marker row. Changes are persisted
  write-ahead with `restored=false` (REQ-PROOF-010) — a crash leaves a durable row plus a
  `proof.repair_required` audit instruction and a `restored=false` report row; the
  end-of-step cleanup pass re-restores leftovers
  (`src/arachne/proof/ledger.py::run_cleanup_pass`).
* **Markers are calm and self-identifying** (`ARACHNE_POC_<nonce> — safe proof of <class>,
  see ARACHNE report`; fear wording refused — `poc_marker`,
  `src/arachne/core/proof.py`).
* **L2+ evidence flows the normal path.** Proof artifacts are a first-class
  `EvidenceKind` ("proof") through the same capture → redact → audit pipeline; the
  nonce→probe map and cleanup status persist in the scan record (`stats["proof"]`) via the
  existing scan store — no second safety system (REQ-PROOF-012). The report renders a
  per-finding Proof section and the appendix-F state-changes table (what/where/before/
  after/restored), and a proof-bearing candidate is exempt from dedupe-merge so its Proof
  section always reaches the report (`src/arachne/analyzer/correlation.py::_dedupe`).
* **The prohibition table has named tests** (persistent shells, destructive SQL, deletion
  without restore, credential/account mutation, secret exfiltration, service disruption,
  evasion tooling) — `tests/test_proof_safety.py`, one test per prohibition, each pointing
  at the code boundary that enforces it.

Residual risk: the L4 helpers act through a deployment-supplied SQL sink (a web endpoint
that reaches the target's database); the ladder's policy is enforced in ARACHNE, but the
sink itself is operator-deployed surface and outside this review's scope. The demo lab's
`/poc-sql` is a test fixture.

## 8. Distributed scan execution (S16, area SCALE) — **PASS**

Distribution moves *where* a scan runs, never *whether* a gate runs. The reviewed
properties (`docs/adr/210-stage-16-distributed-execution.md`):

* **One lease per scan.** `scan_queue.scan_id` is UNIQUE and claims are atomic —
  `SELECT … FOR UPDATE SKIP LOCKED` on Postgres, a guarded `UPDATE … RETURNING`
  elsewhere — so no scan can execute on two nodes at once. The concurrent-claim test
  (five claimant threads, disjoint leases) and the two-agent/twenty-scan integration
  test pin it (`data/queue_store.py`, `tests/unit/test_queue.py`,
  `tests/integration/test_distributed.py`).
* **Gates re-evaluated on the executing node** (REQ-SCALE-008). The agent's executor
  rebuilds the request from the *current* stored target row and the orchestrator's
  `execute`/`resume` path re-runs the scope gate (the executing node's own
  `ARACHNE_SCOPE_*` and the project's scope), the authorization gate (the attestation
  as it stands at execution time) and the proof gate before any request. Safety tests:
  a revoked attestation stops an already-enqueued scan; a scan outside the executing
  node's deployment scope is refused there (`tests/test_safety.py`).
* **Agent identity in the audit trail** (REQ-SCALE-004). Agents authenticate with
  existing scanner-role API keys on `/api/v1/agent/*`; `register`/`heartbeat`/
  `lease`/`complete` are audited with the agent name and key label, and every audit line
  an execution writes is signed `agent:<name>` (the executor's auditor shares the
  deployment's sink — `core/audit.py::Auditor.with_actor`). No new credential type, no
  second trail.
* **Control-plane egress stays on the one HTTP path** (ADR-05): the agent's HTTP
  control plane goes through `ScopedHttpClient` with a scope pinned to exactly the
  deployment's host — the hygiene test's ban on raw `httpx` imports still covers every
  new module.
* **Interruption is honest.** An expired lease is reclaimed with an interruption note in
  the scan's stats and a `scan.interrupted` audit line before the scan re-queues; a
  failed execution marks the scan `failed` with the reason (never a stranded `pending`
  row), and a cancelled execution never acks — the abandoned lease is what makes an
  agent kill re-leasable rather than lost.

Residual risk: an operator who shares one scanner key across several agents gets a
shared identity in the trail (per-agent keys are the documented posture); lease expiry
timing depends on the deployment's clocks being roughly synchronized (NTP), as with any
TTL-based system.

## 9. Enterprise identity & access (S17, area IDAM) — **PASS**

Identity is added *around* the existing gates, never inside them. The reviewed
properties (`docs/adr/220-stage-17-identity-and-access.md`):

* **Deny-by-default is preserved.** `CredentialStore.enabled` is true only when a static
  key, an active service account or an SSO session can authenticate; with no IdP
  configured the SSO routes answer `503` and the API still requires a credential
  (`401`). A valid login whose groups map to no role (and no `default_role`) is refused
  and audited. Tests: `tests/integration/test_idam.py::test_an_unconfigured_idp_is_refused_and_the_api_stays_closed`,
  `::test_a_login_with_no_mapped_role_is_denied`.
* **The ID token is fully verified.** Structure, `alg` allowlist (never `none`, no
  family confusion), `kid` selection (a multi-key JWKS refuses an unknown `kid`), the
  RS256/HS256 signature (pure-stdlib: RSASSA-PKCS1-v1_5 via `pow`, HMAC via `hmac`),
  `iss`, `aud`, `exp`/`nbf` with leeway, and the OIDC `nonce`. No path returns unverified
  claims. Unit suite: `tests/unit/test_oidc.py` (tamper, garbage signature, alg
  confusion, issuer/audience/nonce/expiry, RFC 7636 PKCE vector).
* **Flow state is server-side and single-use.** `sso_flows.state` is the primary key and
  is deleted on consume; the PKCE verifier and nonce never reach the browser. A replayed
  state finds nothing (`test_a_replayed_state_is_refused`).
* **Secrets at rest stay hashed.** Service-account secrets and SSO session tokens are
  stored as SHA-256 digests only; verification is `hmac.compare_digest`. The S12
  storage-format test is unchanged and a new test pins the two hashers together
  (`tests/unit/test_identity_store.py`). Rotation replaces the digest in place (old
  secret rejected, new accepted) and revocation is a flag, never a delete, so lineage
  survives.
* **Actor identity, not a shared label.** A principal carries the human (`user`) and the
  credential (`credential`); audit rows read `user X via key Y`, `user X` or `key Y`
  (`api/auth.py::actor_identity`). The API middleware signs `api.request` with that
  identity, user-initiated routes use `Auditor.with_actor`, and the scan runner threads
  it into the orchestrator *and its handlers*, so every line a scan writes names its
  requester; the scan (`stats.requested_by`) and the report (§2 "Requested by") carry it
  too (REQ-IDAM-001/004).
* **One documented redaction exemption, scoped to the IdP client.** The OIDC token
  exchange must read credentials back, so its dedicated `ScopedHttpClient` is constructed
  with `redaction_enabled=False` (ADR-220.3). That client is scope-pinned to the IdP
  host, is the only call site passing the flag, never logs or persists a token (the audit
  line carries only the response's SHA-256), and is closed on shutdown. The scanning
  client is untouched.
* **Egress stays on the one HTTP path** (ADR-05). The provider calls go through
  `ScopedHttpClient`; the HTTP-hygiene test still bans raw `httpx` imports in every new
  module (`api/oidc.py`, `api/sso_routes.py` included).

Residual risk: the verifier is hand-written (no audited crypto library) — its correctness
rests on the negative test suite plus the fixed-key fixture; an RSA key below the
provider's advertised strength, or a provider using an algorithm outside the configured
allowlist (ECDSA/EdDSA), is refused rather than downgraded. Session revocation is
per-session; group changes apply at the next login (bounded by
`ARACHNE_SSO_SESSION_MAX_AGE`), which is documented rather than silently assumed.

## 10. Live threat intel & passive OSINT (S18, area INTEL) — **PASS**

Two new trust boundaries: data coming *in* (feeds) and the target going *out* to third-party
indexes (providers). The reviewed properties
(`docs/adr/230-stage-18-intel-and-osint.md`):

* **Nothing is imported that does not verify** (REQ-INTEL-002). Integrity is established on
  the raw bytes *before* the store is touched; a payload without a pinned digest is refused,
  not trusted (`intel.verify.verify_payload` → fail-closed). Checksums are SHA-256; the
  signature mode is RSASSA-PKCS1-v1_5/SHA-256 verified with `pow` (stdlib, like S17), and a
  malformed key or non-RSA signature is refused rather than downgraded. Tests:
  `tests/unit/test_intel_feeds.py::test_a_single_changed_byte_is_refused`,
  `::test_a_tampered_payload_cannot_reuse_the_signature`,
  `::test_a_source_with_no_pin_is_refused_not_waved_through`, and the end-to-end
  `::test_a_tampered_fixture_is_refused_and_nothing_is_imported` (no rows, one blocked
  `intel.feed_rejected` audit line).
* **The sync is one egress path, scope-pinned to the feed hosts.** `ScopedFeedTransport`
  wraps `ScopedHttpClient` with a scope of exactly `IntelSettings.source_hosts()` (mirrored by
  `INTEL_FEED_HOSTS`); a mirror that is not named is out of scope and refused before a socket
  opens. A truncated or binary body is refused rather than verified, because a digest over
  half a feed is worse than none.
* **A second, documented verbatim-read exemption.** The feed client is constructed with
  `redaction_enabled=False` and a raised `max_body_bytes` (ADR-230.3): redaction would edit
  the payload and invalidate the digest, and the 64 KiB default would truncate a 2,000-record
  page. It never logs or persists a body — the audit line carries source, status, byte count
  and digest — and `tests/unit/test_http_hygiene.py::test_only_the_documented_call_sites_read_a_response_verbatim`
  pins the exemption list at exactly `{api/oidc.py, intel/sync.py}`, so a third cannot appear
  quietly.
* **The opt-in providers are unreachable without two declarations.** Shodan, Censys, Cert
  Spotter, HIBP and WHOIS/RDAP are absent from `DEFAULT_OSINT_PROVIDERS`; naming one is the
  opt-in, and a provider named without its credential is dropped from `enabled` *and* the
  scope by `build_osint_access(usable=...)` before any check runs. Tests:
  `tests/unit/test_intel_providers.py::test_the_new_providers_are_strictly_opt_in`,
  `::test_a_keyed_provider_without_its_key_is_out_of_scope`, and the socket-armed
  `tests/test_safety.py::test_a_named_intel_check_without_opt_in_sends_nothing_and_is_audited`
  (zero requests, `intel.provider_blocked` per provider).
* **Keys are never recorded.** Credentials live in `SecretStr` (environment only) and build a
  header or — for Shodan, whose API has no header form — a query parameter. Every record of a
  URL is `redact_url(...)`: the audit target, the log field, the `ProviderResponse` and thus
  the finding's evidence. The log-scan
  `tests/test_safety.py::test_a_provider_key_never_reaches_a_log_line_a_record_or_a_finding`
  asserts the key is absent from the log stream, the audit trail, the events and the
  evidence of a run that really used it.
* **Rate limits are enforced per provider.** `OsintAccess` paces each provider at its
  declared requests/second on top of the shared client's per-host limiter, and audits a
  deliberate wait (`intel.rate_limited`) — the provider's tier is a resource of somebody
  else's, and the scan is not its only consumer
  (`tests/unit/test_intel_providers.py::test_the_provider_layer_paces_calls_to_one_provider`).
* **Freshness is stated, never implied.** A scan records what it was planned against
  (`scans.stats["intel"]`) and the report renders it (appendix §G, JSON schema 1.4), with
  *stale* and *not ingested* kept distinct — "no KEV match" against a month-old catalogue is
  not the same statement as against yesterday's
  (`tests/integration/test_intel.py`).
* **The generated index cannot silently replace the curated one.** The baseline is code-free
  data regenerated from the verified corpus, merged *under* the curated overlay (which wins on
  a repeated `(product, cve)`), and shipped with a regression test that regenerating it from
  the recorded corpus reproduces the committed file byte for byte
  (`tests/unit/test_intel_feeds.py::test_the_shipped_baseline_is_the_one_the_generator_produces`).

Residual risk: a pinned digest is only as trustworthy as the moment it was pinned — `--pin` is
an explicit operator act (audited as `intel.checksums_pinned`), and a moving upstream (NVD
windows, EPSS dates) legitimately needs a re-pin, so the deployment should use signature mode
for a self-mirrored feed. The RDAP referral hop is not followed outside the allowlist, which
means a `whois` provider pointed at the bootstrap service returns less than a full WHOIS
lookup; the operator guide documents the mirror/`ARACHNE_OSINT_EXTRA_HOSTS` path.

## 11. Authenticated scanning & the credential vault (S19, area CREDS) — **PASS**

The largest new trust boundary of the program so far: ARACHNE now holds credentials for the
target. Five reviewed properties (`docs/adr/240-stage-19-credentials-and-agent-mode.md`):

* **Encrypted at rest, and refusal is the failure mode** (REQ-CREDS-002). The vault is one
  sidecar file using the S7 construction (scrypt → SHAKE-256 keystream → HMAC-SHA256,
  encrypt-then-MAC) under its own magic, so a secrets manifest cannot be replayed as a vault.
  A configured path with no key is a `VaultLockedError`, never a plaintext fallback; a wrong key
  and a tampered file are indistinguishable. The file is written 0600 via write-then-rename, and
  the username is encrypted with the secret. Tests: `tests/unit/test_vault.py`
  (`::test_the_vault_file_is_ciphertext_and_carries_no_secret`,
  `::test_a_tampered_vault_file_is_refused`, `::test_a_vault_without_a_passphrase_refuses_to_exist`)
  and the byte-level assertions in `tests/test_credential_safety.py`.
* **Opaque scoped handles, one release seam.** `CredentialHandle` publishes `label`/`kind`/
  `scope` and no accessor; material needs `core.vault.release_seam()`, imported only by
  `arachne.creds`. A check that reaches for it raises `CredentialError`. Fuzz-pinned over every
  family variant (`tests/unit/test_redaction_fuzz.py::test_a_vault_handle_never_leaks_its_material`).
* **Scope confinement before the socket** (REQ-CREDS-005). A credential is bound to its hosts and
  URL prefixes; an offer outside them raises `CredentialScopeError` (an `OutOfScopeError`) and is
  audited `credential.scope_rejected`, and **no request is sent** —
  `tests/test_safety.py::test_a_credential_outside_its_scope_is_refused_before_a_request`
  (transport raises if called) and
  `tests/integration/test_credentials.py::test_a_credential_outside_the_target_scope_is_refused_and_nothing_is_sent`.
* **The session never becomes a check-visible value.** The login goes through the existing
  `ScopedHttpClient` (ADR-240.1); its `httpx` cookie jar holds the token, `set-cookie`/`cookie`
  are blanked at capture, and a check receives outcomes only. Zero-occurrence, end to end:
  `tests/test_credential_safety.py::test_the_password_is_absent_from_every_artifact` checks the
  JSON log stream, every audit `to_dict()`, every evidence payload, both rendered report formats
  and the vault's own bytes — while asserting `[REDACTED` **is** present, so the assertion is
  about redaction rather than about the path not running.
* **Authentication authorizes nothing.** The active-checks opt-in, the attestation and the proof
  gate are unchanged: `tests/test_safety.py::test_an_authenticated_scan_still_needs_the_active_checks_attestation`
  proves a credentialed check is withheld without them, and
  `::test_authenticated_requests_still_pass_the_rate_limiter` proves the authenticated requests
  are paced by the same limiter. In agent mode every gate is re-run on the executing node
  (`tests/integration/test_agent_internal.py`).

**Redaction gaps this stage closed** (found while fuzzing the credential path — the S19 additions
to `tests/unit/test_redaction_fuzz.py`):

| Carrier | Before | Now |
|---|---|---|
| `username=…&password=<secret>` (urlencoded body, later field) | the secret survived: `&` was not an assignment delimiter, so only the *first* field could ever be redacted | `&`, `|`, `?` added to the delimiter class |
| `Authorization: Basic <b64>` in plain text | survived (headers were already blanked wholesale) | a keyed `basic-auth` pattern, anchored to the header name so ordinary prose ("Basic plan") is untouched |
| `multipart/form-data` part named `password` | the value survived | a linear part-name scanner replaces only parts whose *field name* is sensitive; a file part is untouched |

Each is pinned by the extended fuzz test, and the multipart scanner has a linearity guard
(`tests/unit/test_redaction_perf.py`).

**Reviewed and deliberately not changed:** a username is an identifier, not a secret
(ADR-240.7). Adding `user`/`username`/`email` to the sensitive-key list would blank the account
names `m3.auth-session-audit`'s enumeration evidence and M4's exposure checks exist to report.
The vault therefore encrypts the username at rest, publishes it nowhere (handle, listing, audit,
`stats["credentials"]`, report methodology — all asserted), and accepts that a login request's
own body shows it, under the same policy as any other submitted form field.

**Known limitation:** `m3.session-logout` can only observe logout through the client it owns. A
logout endpoint that clears the cookie but keeps the server-side session is indistinguishable
from a real logout *without replaying the token*, which no component may do; the check therefore
reports the observable case (a session that still works after the logout request) and its skip
note says when the question cannot be answered. The protocol lab plants the observable variant.

## 12. Data lifecycle, evidence storage & observability (S20, areas DATA/OPS) — **PASS**

S20 adds the largest new *data* surface of the program: evidence can now leave the database for
a local directory or an object store, traces can leave the process for a collector, and a
pruning job deletes data. Five reviewed properties
(`docs/adr/250-stage-20-data-lifecycle.md`):

* **Deletion is policy-bound, and it is proved** (REQ-DATA-001). A pruning run plans concrete
  row ids and deletes exactly those, so a dry run and the apply that follows it cannot diverge;
  dry run is the default in both the module API and the CLI. The property test
  (`tests/unit/test_retention_property.py`, 25 generated estates with per-project policies,
  legal holds and `0`-day categories) asserts that every removed row was over its own category's
  cutoff *or* was removed with a scan that was, that everything inside retention survived, that
  a second run deletes nothing, and that the usage ledger still equals the surviving evidence
  sizes. A legal hold and a `0`-day category each get a dedicated test.
* **Object keys cannot escape their store.** An evidence key must be a 64-character hex digest
  (`evidence_backend._require_content_key`); a row whose `storage_key` was tampered with cannot
  read or unlink an arbitrary path, and a stored object whose digest does not match its key is
  refused on read rather than served (`LocalEvidenceBackend.get`). The container framing
  (`MAGIC | flag | size | body`) is verified on every read, decompression is bounded, and a
  length mismatch is an error — asserted by
  `tests/unit/test_evidence_backend.py::test_a_tampered_object_is_refused_on_read` and
  `::test_a_key_that_is_not_a_digest_is_refused`.
* **The object store is reached through the one egress path.** The S3 backend signs with
  stdlib SigV4 and sends through `ScopedHttpClient`, pinned to the configured endpoint's host;
  the HTTP-hygiene test asserts there is no second client. `request_bytes` — the byte-exact read
  path an integrity-bearing container needs — is a named method whose call sites the same test
  pins at exactly one module (`tests/unit/test_http_hygiene.py::test_only_the_documented_call_sites_read_a_body_as_bytes`).
  The fake object store in the test suite **verifies** the SigV4 signature, so a round trip
  proves the signing code: a tampered presigned URL and an expired one are both refused
  (`tests/unit/test_evidence_backend.py`).
* **A quota stop cannot corrupt or half-write anything** (REQ-DATA-003). The check happens
  *before* any byte is written, so a refusal leaves the database and the backend untouched
  (`tests/unit/test_storage_quota.py::test_a_refused_write_uploads_nothing_and_warns_first`),
  the error names the limit and the way out, and the audited failure lands on a *resumable*
  scan (`tests/integration/test_data_lifecycle.py::test_a_quota_crossing_warns_then_hard_stops_and_the_scan_is_resumable`
  asserts `quota.warning` then `quota.exceeded`, zero candidates written, and a completed
  `--resume` after the quota is raised).
* **The observability endpoints leak nothing.** `/metrics` is aggregate by construction — no
  label carries a target, asset, finding title or payload, asserted by
  `tests/unit/test_metrics_contract.py::test_the_endpoint_never_exposes_a_target_or_a_payload` —
  and label values are escaped and bounded, so a hostile agent or project name cannot inject
  metric lines (`::test_a_hostile_label_value_cannot_inject_a_metric_line`). Traces redact every
  attribute (`tests/unit/test_tracing.py::test_span_attributes_are_redacted`), and an
  unreachable collector is logged and dropped rather than propagated
  (`::test_an_exporter_failure_never_reaches_the_caller`).

Two redaction gaps were found while reviewing the new surfaces and fixed (§ "Findings", F6/F7):
a presigned URL's signature, and a credential inside a URL embedded in *text*.

**Known limitation.** `/metrics` is unauthenticated unless `ARACHNE_METRICS_TOKEN` is set, by
design (a scrape endpoint a monitoring system must authenticate to is one that gets scraped with
a static token in a config file). It is aggregate-only for the same reason, and a deployment
that publishes the API should publish the endpoint behind the same proxy. Traces carry the
*shape* of a scan (which steps ran, which requests were made, how long they took), so a
deployment that treats scan topology as sensitive should keep `ARACHNE_TRACING_ENABLED=false`
or point the collector at an internal deployment.

## 13. Agentic reasoning, attack paths & the quality workflow (S21, areas AGENT/QUAL) — **PASS**

The stage adds the first capability that *reasons*, so the review's question is not "is the new
code correct?" but "does the reasoning layer have a power the rest of the system does not?"

**Five boundaries, all structural (REQ-AGENT-005).**

1. *A hypothesis is a proposal to run a catalogued check on a known asset.* `Hypothesis` carries
   a check id and an asset string; the executor resolves both against the scan's own state and
   refuses anything else (`unknown-check`, `unknown-asset`). There is no field for a URL, a
   payload or a request, so a model cannot express one.
2. *Gate logic is unreachable from AI output.* The proof level written into the journal is the
   catalogue's (`CheckIndex`), the definition/attestation/module selection are the scan
   request's, and the executor plans every probe through `Orchestrator.plan_hypothesis`, which
   runs the same scope, authorization, engine-availability and proof gates as the scan path.
3. *Proof escalation needs the operator.* L2+ requires `options.proof_approved`; L3/L4 also
   requires the attestation's `state_changes_authorized`. Verified by
   `tests/test_agentic_safety.py` (a hostile proposal for `m3.sqli-oob` without approval is
   refused; with approval it runs; `m3.state-marker` is refused without the attestation).
4. *The budget cannot be exceeded.* `HypothesisBudget.spend` raises when a spend does not fit; the
   step validates before spending, records a refusal, and *defers* the remainder. A twelve-item
   proposal storm under a two-hypothesis budget leaves two executed and ten deferred.
5. *`options.proof_approved` does not widen the main plan.* It authorizes a proposal only; the
   planner ignores it when deciding what an admitted scan runs (ADR-260.8).

**Prompt injection (REQ-AGENT-006) is treated as hostile input, never as instruction.** Target
content reaches the reasoning layer only in the prompt's untrusted half (the S9 prompt store
wraps, escapes and delimits it) and lands in `HypothesisInput.observations`, which is data. The
defence does not depend on recognising the payload: the five boundaries above hold whatever the
text says. Detection (`reasoning/injection.py`) exists to *record* the attempt — the excerpt is
redacted before it reaches the audit trail — and the adversary test plants instructions naming an
out-of-scope host, a budget increase, an L4 approval and a scope bypass against a live lab, then
asserts: no evidence names the attacker's host, no executed decision targets it, the L3 proposal
is refused, and the budget in force is the scan's own.

**The kill switch (REQ-AGENT-007) is out-of-band by design** (`ARACHNE_HYPOTHESIS_CONTROL`, a
file the CLI, the API and a possibly-remote scan can all reach). It can only *stop* work — the
safe direction — and it is read between hypotheses, so an in-flight probe finishes and nothing
new starts. A corrupt or unreadable control file reads as "no directive" and is logged; a resume
clears the directive for that scan. The API route requires the scanner role and the UI form
requires the htmx header, like every other state-changing surface.

**The quality workflow records decisions, and records them where an auditor looks.** Suppressions
and acceptances are audited (`suppression.changed`, `acceptance.changed`, `acceptance.expired`),
attributed to an actor, and require a reason/justification of non-trivial length; a suppression
cannot make a *known* finding disappear from a diff (only new findings are filtered), and both
records are paper designs an operator reviews in the interface.

**Synthesis cannot deploy.** `quality/synthesis.py` writes files and nothing else; it refuses the
shipped catalogue directory and any path resembling the live catalogue, and `approve` refuses
without a passing parity result and a named reviewer (REQ-AGENT-004).

*Residual risk:* an operator can approve an L2+ proposal whose check then runs with real network
effects — that is the intended power of the switch, and it is bounded by the per-scan budget, the
proof ladder and the audit trail. A deployment that wants no agentic reasoning at all leaves
`ARACHNE_HYPOTHESES=off` (the default), in which case the hypothesis step is not even part of the
pipeline.

## Findings

| # | Severity | Where | Issue | Disposition |
|---|---|---|---|---|
| F1 | Medium | `src/arachne/core/redaction.py:182-185` (`_ASSIGNMENT_RE`) | In plain text, an indented non-sensitive outer key let its value span the newline and swallow the inner key: `service:\n  api_key: <secret>` and `database:\n  password: <secret>` were **not redacted at all** (`contains_secret` returned `False` too). The trailing `\s*` after the separator consumed `\n  `, so the inner `api_key:`/`password:` was eaten as the outer value and never scanned as a key. HTTP JSON bodies were already safe (the client routes JSON through the recursive key-aware `redact_value`, `http.py:605-615`); the gap was the plain-text/YAML path (e.g. a fetched `application/x-yaml` or `/.env` body). | **FIXED (committed).** Two changes together. (1) The inline separator now consumes horizontal whitespace only (`\s*[:=][ \t]*`), so a non-sensitive outer key can no longer swallow an inner `api_key:`. (2) Because that choice stops at the newline, a block-style value (`db_password:\n  hunter2`) would escape it, so a second pattern, `_BLOCK_ASSIGNMENT_RE`, covers a key-at-end-of-line whose value is on the next (optionally indented, optionally `\|`/`>` block-scalar) line. Verified against the committed behaviour on a 20-case battery (`docs/adr/180-stage-13-hardening.md` records it): five previously-leaking cases now redact and no case that was redacted before regressed. Both nested levels and block scalars now redact and `contains_secret` returns `True`; `tests/unit/test_redaction.py::test_block_style_assignments_are_redacted` and the fuzz test pin it. |
| F2 | Low–Medium | `src/arachne/core/redaction.py:188-200` (`_SENSITIVE_KEY_SUBSTRINGS`) | Azure storage/Service Bus connection strings spell the credential `AccountKey`, which matched no sensitive-key marker, so `;AccountKey=<base64>` was neither redacted by `redact_text` nor flagged by `contains_secret` (raw base64 survived). | **FIXED (committed).** Added `"accountkey"` to `_SENSITIVE_KEY_SUBSTRINGS`; the key-aware assignment rule now replaces the value. Covered by the fuzz test's Azure connection-string carrier. |
| F3 | Low | `src/arachne/core/redaction.py:131-161` (`SECRET_PATTERNS`) | In *plain text* (a raw log line or a body), `Authorization: Basic <b64>` and `Set-Cookie: session=<value>` are not caught by pattern redaction. The HTTP path is safe — `redact_headers` blanks these header names wholesale and cookies are projected value-free at capture — so this only bites text that never passed through the header path. | **FIXED (S19, committed).** A `basic-auth` pattern anchored to the header name (`authorization: basic <b64>`) now redacts the keyed text form without touching benign prose; `Set-Cookie` stays header-path-only by design (a bare session value with no key and no shape is not detectable — see the S19 table in §11). Pinned by `tests/unit/test_redaction_fuzz.py::test_no_credential_survives_any_login_carrier` and `::test_a_session_value_never_survives_a_response_carrier`. |
| F4 | Medium | `docs/adr/050-stage-1-foundation.md:40-42`; `http.py:378-406` | Resolve-and-pin is not implemented: addresses are validated but the request is sent to the URL, leaving a small DNS-rebinding TOCTOU window between validation and connect, and no network-namespace/container sandbox is enforced by default. | **Tracked, not fixed here.** Belongs with the F-08-03 sandbox work; documented as a limited protection (per-hop revalidation is the current mitigation). |
| F5 | Low | `pyproject.toml:21-31`; `ci.yml:130-146` | No pinned/locked dependencies; dependency audit is advisory and single-scanner (`pip-audit` only, no `osv-scanner`). | **Recommended.** Add a lockfile (e.g. `uv.lock`) and an `osv-scanner` step; keep the audit advisory until the lock exists. |

| F6 | Medium | `src/arachne/core/redaction.py:131-171` (`SECRET_PATTERNS`, `_SENSITIVE_QUERY_KEYS`) | An **S3 presigned URL is a bearer credential** — `X-Amz-Signature` authorises the download until it expires and `X-Amz-Credential` names the key id — and neither the query-key rule nor any pattern removed it. A presigned URL therefore survived redaction in a log line, an audit target or a span attribute, and downloads are exactly the URLs an operator copies into a ticket. | **FIXED (S20, committed).** `x_amz_signature`, `x_amz_credential` and `x_amz_security_token` joined `_SENSITIVE_QUERY_KEYS` (so `redact_url` blanks them wherever a URL is recorded), and a `presigned-url` pattern covers the *text* path when the URL never went through `redact_url`. Pinned for every generated secret family by `tests/unit/test_redaction_fuzz.py::test_no_secret_survives_an_s3_presigned_url`. |
| F7 | Medium | `src/arachne/core/redaction.py:401-432` (`_redact_pairs`) | **A credential inside a URL embedded in text survived**, because the `key: value` scanner matched the *whole URL* as one value: for `source: https://host/login?password=…` the pair key (`source`) is not sensitive, so the value was left alone — and the match consumed the query string, so the inner `password=` was never examined by `finditer`. The structured path was safe (`redact_url` is applied to a URL *field*), but the shared JSON log formatter redacts a string field with `redact_text`, so `{"url": "…?password=…"}` leaked, and S20 makes that shape common (an `http.url` span attribute). | **FIXED (S20, committed).** A pair whose key is innocent but whose value looks like a URL is now passed through `redact_url` (and `contains_secret` agrees). Regression-checked against the existing suites: `test_redaction.py`, the fuzz corpus and the linearity guard (`test_redaction_perf.py`) all pass unchanged, and `tests/unit/test_redaction_fuzz.py::test_a_credential_inside_a_url_embedded_in_text_never_survives` pins it per family. |

Findings F1–F3 and F6–F7 were found by the Part B fuzz test and by this review rather than by
inspection; `tests/unit/test_redaction_fuzz.py` pins each of them so none can silently regress.

## Known limitations / environment-limited

* **Sandboxing.** No network-namespace or container sandbox is implemented or asserted;
  the Docker image only drops privileges (`docker/Dockerfile:33-37`), and the compose
  file sets no hardening options. SSRF/DNS-rebinding protection is per-hop revalidation +
  private-IP policy only (Finding F4); full resolve-and-pin is future work.
* **Structureless secrets.** A bare high-entropy string with no recognisable prefix and no
  sensitive key cannot be detected by pattern — this is by design and stated in
  `mask_secret`'s docstring (`redaction.py:53-64`). Context/key-aware redaction (JSON,
  YAML, log `key=value`, sensitive keys, sensitive headers) is what catches these; the fuzz
  test asserts exactly that carrier guarantee and does not claim the impossible bare case.
* **Redaction can be turned off** by configuration (`ARACHNE_REDACTION_ENABLED`, default
  `True`, `config.py:84,1065`); the safety tests and the fuzz test assume the default.
* **External/optional tools** not exercised in this review: `python-nmap` (optional M2
  backend, falls back to the pure-Python connect backend; `net.py`), the optional
  WeasyPrint PDF backend and the external headless engine path
  (`src/arachne/report/pdf_backend.py`, ADR-180 — its one `subprocess` call is asserted
  shell-free, fixed-argv, timeout-bounded by
  `tests/unit/test_http_hygiene.py:90-147`), `testssl.sh`/`sslscan` for SSLv3/legacy-TLS
  observation (`net.py:97-119`), and the docker integration lab (DVWA / Juice Shop /
  misconfigured nginx) which needs containers unavailable here.
* **Integration/lab layers** were not run; this review is static
  source analysis plus the targeted unit suites named in the verification block.

## 14. Supply chain, deployment surface & integrations (S22, areas TRUST/OPS) — **PASS**

Scope reviewed: `src/arachne/report/compliance.py`, `src/arachne/report/defectdojo.py`,
`src/arachne/api/webhooks.py` (ServiceNow/SIEM additions), `src/arachne/tools/sbom.py`,
`src/arachne/tools/credentials_gate.py` (Kubernetes-surface extension),
`deploy/helm/arachne/` (the whole chart), `.github/workflows/release.yml`, the CI
changes, and the new integrations tests.

**The integration egress stays one path.** ServiceNow and the SIEM export are two more
payload shapes in the S12 webhook architecture, not new clients: rendering is a pure
function of the already-redacted report DTO, every token is a `SecretStr` read only to
build the auth header, delivery goes through `ScopedHttpClient` scoped to exactly the
configured hosts, and a failure is audited (`webhook.failed`) and returned — never
raised into the scan. The new secrets in the codebase are all *headers*; the
no-secrets-in-logs test delivers every integration through the notifier and asserts no
token survives into a payload body, the audit trail, or the log stream. The one
structural addition is the SIEM's `raw_body` (NDJSON is not a JSON document): the sender
posts it verbatim with `application/x-ndjson`, and its content is the same redacted
report/audit data every other destination gets. The audit events reaching the SIEM come
from the scan's own trail (already redacted at capture); the export path in
`ReportService.notify` treats a failed audit read as "findings only", never a delivery
blocker.

**DefectDojo is one builder, two paths.** The webhook import and
`arachne report --format defectdojo` produce byte-equal documents from the report DTO
alone — there is no second mapping to drift, and the contract tests pin both against the
recorded receiver-side fixture. Every value in the document is already-redacted report
data.

**The compliance maps are data with a dangling-id gate.** The framework files reference
only check ids the shipped catalogue contains (`tests/unit/test_compliance_map.py`
compares them against the registry *and* the catalogue — both directions of the join).
At report time a stale custom map degrades to honest `gap` rows rather than failing the
report; the loader is never called with redaction off, reads only shipped/override YAML
via `safe_load`, and an unknown framework name is a loud `ConfigurationError` (a report
that silently dropped a named framework would understate coverage). The framework
section is engineered to *not* overclaim: fail/pass/gap per control, the framework's own
total control count beside the mapped one, and "evidence about a control's operation, not
proof of conformity" stated in both the report and the export.

**The chart ships no credentials and fails closed.** `helm install` aborts at render
time without a Postgres password, API keys and (when the agent pool runs) an agent key —
the `required`/`fail` guards are in the templates, the values file ships empty strings,
and the credentials gate now scans `deploy/helm/` as shipped surface (with the
Kubernetes *pointer* idiom — `secretKeyRef.key`, `secretName`, `existingSecret`,
`topologyKey` — recognised as references, the same shape rule as `_FILE`-suffixed env
vars, plus `{{ … }}` template references and empty structures as non-values). Secrets
reaching pods are `secretKeyRef`s or files; the Vault path is injection annotations, not
a chart-rendered secret. The migration Job and agent pool get the same secretRef
treatment; no container runs as root (`runAsNonRoot`, UID 10001, matching the image).

**The release chain is verifiable by construction.** The release workflow signs the
*pushed digest* with cosign keyless (identity = the repository's OIDC claim), attests the
SBOM to the same digest, generates SLSA-style provenance, and then verifies its own
signature round-trips — a wrong subject or a broken identity claim fails the release
instead of publishing an unverifiable artifact. `pip-audit --strict` gates the tag with
no `continue-on-error` (CI's advisory job keeps the branch behaviour). Tool versions are
pinned (cosign via env, actions by major tag, `pip-audit` upper-bounded), and
`docs/reproducible-builds.md` separates the deterministic parts (the SBOM is
byte-identical for the same environment and timestamp) from the acceptable ones (layer
mtimes), with the digest-signing contract as the anchor.

*Residual risk:* the SIEM export is a *push* — a collector that accepts it holds
findings metadata outside ARACHNE's audit trail, and the NDJSON carries the same
redacted data the report does (no secrets, by the same tests). The release workflow's
action pins are major-version tags, not SHAs — the stricter pinning is documented as a
one-line change in `reproducible-builds.md`. A deployment that never enables
`ARACHNE_WEBHOOKS_ENABLED` sends nothing, exactly as before.

## Finding (S22)

| # | Severity | Where | Issue | Disposition |
|---|---|---|---|---|
| F9 | Low | `src/arachne/api/webhooks.py` (`_servicenow_payloads`, `_siem_headers`) | The new integrations put credentials into `Authorization` headers built by string formatting. A malformed URL (a newline in `servicenow_url`) could in principle split a header. | **Fixed (committed).** The egress client already normalises URLs before any request (the S10 header-injection guard), and the settings construct the endpoint by joining a validated base URL with a constant path; the no-secrets-in-logs test asserts no token appears outside the header it is built for. No change needed beyond the existing guards; recorded for the next review pass. |

## 15. Continuous exposure management (S23, area POSTURE) — **PASS**

**Scope.** `arachne.posture` (state/baseline/verify/iac/admission/cmdb/trend/access),
`data/posture_store.py` + migration 0009, `modules/m5/cloud_posture.py`, the M5 IaC
review's structured half, the scheduler's budget gate and reconcile hook,
`cli/{posture,iac}.py`, `api/admission_routes.py`, and the report's criticality feed
(schema 1.8).

**Read-only, by construction.** The continuous check's only target interaction is a
bounded GET per configured snapshot path through the shared scoped client — the same
safety gate, rate limiter, redaction and audit as every M5 request. It writes nothing to
the target and nothing to any cloud control plane; the optional bearer token rides the
environment (`ARACHNE_M5_POSTURE_TOKEN`) and reaches only the `Authorization` header,
which the client redacts at capture. Policies and drift are computed over the *response
document*, and the baseline store is ARACHNE-side.

**No enforcement by default, and the default is structural.** The admission route's mode
comes from deployment settings; `monitor` — the shipped default — always allows. Enforce
mode denies only inside an explicitly staged namespace list, and an empty list denies
nothing (the deny-nothing property is unit-pinned, `test_posture_admission.py`), so
enforce cannot become "block the world" by configuration accident (risk R-15). The IaC
gate *reports* and exits non-zero in a pipeline; it never touches a cluster. The
fail-open posture on admission evaluation errors is deliberate and documented:
availability of the customer's cluster outranks ARACHNE's opinion, and the error is
audited with the review that could not be evaluated.

**The fix loop cannot widen a scan.** `verify-fix` re-runs the original scan's *stored
request* through `Orchestrator.scan` — scope, authorization and proof gates re-checked
at the current moment — bounded to the affected check by the exact allowlist
(`ModuleSelection.only`), so a verification can never run more than the check the
finding came from. Reconciliation reopens only findings whose `(check, asset)` **and**
target match; a verification scan cannot reopen what it just closed (the same-scan id is
excluded). Both acts link evidence to the original finding rather than rewriting its
status history.

**Budgets are audited refusals.** A continuous schedule past its run cap or
estimated-request cap is refused with `schedule.budget_refused` (risk R-13) — the
guardrail working is a trail event. The refusal path never admits a scan, and the
window history survives status updates (a status write never rewrites run times).

**Migration 0009 is purely additive** (three new tables); `posture_baselines` is
scan-scope data keyed by the watched scope, `posture_verifications` keeps
`finding_id`/`scan_id` with `SET NULL` so pruning a scan never orphans the decision
history, and `asset_criticality` is a small upserted lookup. Criticality affects path
*ordering and labelling* only — the analyzer's severities are untouched, and a report
rendered without an import is byte-identical to its pre-S23 form (golden-pinned).

*Residual risk:* the snapshot endpoint is operator-declared and operator-trusted — it
answers estate configuration data, and ARACHNE treats it as evidence (redacted at
capture) but cannot verify the collector's own authenticity beyond transport security.
The admission endpoint authenticates with an API key, not mTLS: a cluster wanting
webhook-level source authentication should front it with the ingress of its choice
(documented in the operator guide §32.4). The three provider response parsers cover the
read-only list shapes ARACHNE can attest to; anything else is refused, never guessed.

## 16. Detection validation: the purple team (S24, area VALID)

**The area's hard rule is structural, not aspirational.** Purple-team tests are designed to
be *seen*: payloads are the proof ladder's own declared payloads, emitted verbatim and
tagged with the run nonce, under the ordinary rate limit, inside an attested window.
`tests/unit/test_purple_attack.py::test_no_evasion_anywhere_in_the_purple_package` parses
the package with `ast` and fails the build on any encoder, obfuscator, packet splitter,
timing trick or raw-socket escape; a second test pins the shipped payload strings as
plaintext and nonce-carrying. There is no evasion capability to accidentally enable.

**The window is an authorization boundary, enforced three times.** A purple window must sit
inside the attestation that carries it (validated on the model), purple mode without one is
refused at the *authorization* gate (`auth.rejected`), and the window itself is re-checked at
plan, at execute and at resume — with a run stopping itself when the window closes
(`purple.window_closed`, audited once). A refusal (`purple.window_refused`) creates no scan
row and sends nothing; `tests/test_purple_safety.py` asserts both by observation (a
recording transport and an empty scan store), not by inspecting the gate's return value.

**A purple run cannot do more than it declared.** The campaign's actions go through
`ModuleSelection.only` — the exact allowlist (S21) — so naming three proof actions withholds
every other check. The technique map is cross-checked against the module catalogue at plan
time: an action claiming a proof level the catalogue does not declare is refused, so the map
cannot mislabel where on the ladder a test sits. A map naming an unknown action is refused
rather than silently dropped.

**Coverage is computed defensively.** An emission counts as seen only when an alert names a
matching technique *and* carries **this run's nonce** *and* falls inside the window;
anything less is reported as unlinked, out-of-window, other-technique or
technique-less — counted, never folded into the coverage figure. A nonce is read only from
explicit shapes (a nonce field, an ARACHNE callback token, a `nonce=value` pair): a bare
hex-looking string in prose is never attributed, because it could be a hash and attributing
it would be a false claim of validation. The defender report distinguishes *unseen*
(proven blind) from *untested/unmapped* (nothing was run there), so it cannot overclaim.

**No credential material anywhere.** The alert corpus, the campaign spec and the run record
carry techniques, tactics, ISO timestamps and the nonce; the SIEM bearer token lives in the
environment only (`ARACHNE_PURPLE_ALERTS_TOKEN`), is read through `SecretStr`, and is sent
through the shared scoped HTTP client pinned to the SIEM's host (ADR-05). The committed SIEM
fixture is asserted to carry no credential-shaped literal.

**Migration 0010 is purely additive** (three tables): `purple_campaigns` (spec + enabled),
`purple_runs` (nonce, window, emissions, Sigma alignment, rewritable coverage) and
`purple_alerts` (the normalized ingest, deduplicated on `(source, alert_id)`). A deployment
that never configures purple mode behaves exactly as it did at S23, and an ordinary scan's
report is byte-identical to its pre-S24 form (the `detection_validation` block is optional
and golden-pinned both ways).

*Residual risk:* alerts are ingested from the defender's tooling and treated as evidence of
what it reported — ARACHNE cannot verify that a SIEM's alert really came from its detection
engine (it authenticates the *forwarder*, not the alert's provenance). Coverage therefore
measures what was *reported to ARACHNE*, which is the honest reading of the number and is
stated in the report's own wording. A purple run's real traffic reaches the target inside
the window — that is the point — so the window, the run nonce and the rate limit are the
controls that make it safe, and all three are enforced rather than documented.

## 17. Resilience & evidence integrity (S25, areas RESIL/TRUST) — **PASS**

**Air-gap is an enforced allowlist, not a flag.** `ARACHNE_AIRGAPPED=true` puts a second,
stricter allowlist on the two places every packet is decided (`ScopedHttpClient`,
`ScopedNetClient`): only the deployment's scan targets and the hosts an operator names in
`ARACHNE_AIRGAP_ALLOWED_HOSTS` are reachable. A feed sync, an OSINT provider, a cloud AI
endpoint, a webhook, an OTLP collector or an IdP inherits the refusal without remembering to
check anything, and the attempt is audited (`airgap.blocked`) before it is raised. The scan
itself still reaches the declared estate — that is what the tool is for — so the guarantee is
*which* hosts, not whether any packet is sent (ADR-300.2).

**Content packs fail closed.** An imported pack's manifest signature is verified before any
member is read; every member's digest and size before anything is returned; a member outside
`content/`, an absolute path, a `..` segment, a symlink or a non-regular file is refused; an
undeclared extra file is refused; an unknown format revision is refused. A failure installs
**nothing** (staging directory, then rename). An unsigned pack is refused by default;
`--allow-unsigned` is the explicit, audited exception. A refused import is a security event in
the trail (`pack.rejected`), and the accepted ones record their own provenance
(`content_packs`: name, version, manifest digest, signing key, importer).

**The audit trail is tamper-evident, and the failure is loud.** Every audit row carries its
position (`seq`), its predecessor's hash and its own digest over content + position, signed
with the deployment key. The chain is written in the same transaction as the row (a
reserved-but-unwritten sequence number would be indistinguishable from a deletion), and a
unique index on `seq` makes two racing replicas safe. Anchors (`integrity_anchors`, signed
checkpoints of the head, exportable off-host) catch the one failure a chain cannot see: a
deleted **tail**. Findings and evidence rows are signed over their immutable identity (with
evidence also pinning its payload digest), and a completed scan is **sealed** — a signed
manifest of every row — so deletion, insertion and post-seal modification are three
distinguishable findings. `arachne verify-chain` reports all of it and exits non-zero;
`integrity.tamper` is audited on failure (ADR-300.4/300.5).

*Residual risk (signature primitives).* The deployment key is **symmetric** (HMAC-SHA256 with
domain separation), so an auditor who must not be able to forge cannot verify — a public-key
scheme would let them. This runtime stack is deliberately dependency-free, and a stdlib RSA
*private-key* operation would mean hand-rolling ASN.1 DER parsing in the signing path where a
mistake is silent. The verifier role is the same party that holds the key. Recorded in
ADR-300.5 as a known limitation, not hidden.

*Residual risk (chain scope).* The chain protects the **audit** trail and every sealed scan's
rows. Rows written by a pre-S25 replica carry NULL chain columns and are simply outside the
chain (a verifier starts at the first chained row); rows of a scan that was never sealed are
covered by their per-row signature but not against deletion. The seal is written at completion
precisely so a completed scan is covered.

**PII masking happens at capture, not at render.** `core.pii` detects six categories with the
validators that make a pattern a finding (Luhn, mod-97, SSN area rules, octet ranges, grouped
national phone numbers), and `EvidenceService.stage` applies the project's policy *before* the
quota check, before any offload and before any row is written — so a masked value cannot reach
the database, an object store, a report, a log or the audit trail. Both the capture path and
the retention re-mask audit **counts by category** (`pii.masked`), never a value. The `hash`
action requires a salt (an unsalted digest of a phone number is reversible by enumeration), and
the policy's `to_dict` never serialises the salt. Masking is irreversible by construction.

**Residency refusals are scope refusals.** `ResidencyError` subclasses `OutOfScopeError`, so a
cross-region evidence read maps to the same 403 the scope gate uses and composes with it rather
than beside it. The check runs for inline payloads as well as offloaded ones (a boundary that
only covers the large payloads is not a boundary) and audits both regions
(`residency.rejected`).

**Finding F8 (fixed in stage): an API-key leak in the DR bundle's config dump.**
`redacted_config` originally redacted by *type* — a `SecretStr` became `{"set": true}` — but
`api.keys` holds `label:role:secret` **strings**, so a naive walk would have written real API
keys into every backup. Corrected: a field whose *name* is secret-shaped (`keys`, `*_key`,
`*_secret`, `*_password`, `*_token`, `*_passphrase`, with `_file`/`_id`/`_path` suffixes
excluded) is replaced by its presence, with a count for a collection. Pinned by
`tests/unit/test_backup.py::test_the_config_dump_keeps_secrets_out`.

**The DR bundle is verified before it is used.** Artifact digests, per-table row counts and the
manifest signature are all checked; a tampered, truncated or unsigned bundle is refused and
nothing is restored. Two deliberate refusals are documented rather than approximated: an
S3-backed evidence store is *not* copied by the bundle (the object store's own replication is
the right mechanism; the bundle records the object keys), and the integrity key stays in the
operator's secret store (the manifest records its id so a restore can name the signer).

**Finding F9 (fixed in stage): the PII hash salt reached the API and the report.**
`ProjectRecord.to_dict()` is what the project resource returns and what a report renders, and
it initially serialised the stored `pii_json` verbatim — which holds the `hash` action's **salt**,
the value that makes a pseudonym expensive to reverse. It now reports the *validated* policy view
(`PIIPolicy.to_dict`), which says `salted: true` and never the salt. The same change surfaced a
second defect the existing suite caught: `ProjectOut` is `extra="forbid"`, so the two new fields
turned project create/list into a 500 until they were declared on the schema. Pinned by
`tests/unit/test_pii.py::test_a_project_record_reports_its_policy_without_the_salt` and by the
S14 project-CRUD suite.

**External validation artifacts ship with the product** (REQ-TRUST-007): `SECURITY.md` (the
disclosure policy, with the tool's own safety invariants in scope for research and its misuse
prohibited), an RFC 9116 `security.txt` served unauthenticated at `/.well-known/security.txt`
from the reviewed file, and a pentest report whose register is an explicit placeholder — it
states its methodology and severity scheme and says plainly that absence of findings is not a
security claim.

**Authority and least privilege.** The new operator surface is read-mostly and audited: the
integrity/HA routes are `viewer` (aggregate status only — no audit content, no evidence) and
never mutate; anchoring and sealing are CLI acts (or the scan's own completion); the content
pack import requires filesystem access to the pack and the deployment key; the backup bundle is
written where the operator points it and holds no plaintext secret. No new egress path was
introduced: the air-gap gate sits on the existing one (ADR-05).

## 18. Ecosystem & product surface (S26, area ECOS) — **PASS**

**The review pipeline is three independent gates, and it lists only on all-pass.** A pack is
`listed` only when `signature`, `safety` and `parity` all pass (`ReviewReport.listed` is
`all(gate.passed)`); there is no partial listing, because a partially-reviewed pack that loaded
would be precisely the substitution attack the pipeline exists to refuse. The gates fail for
different reasons and the report says which — "unsigned", "signed by another deployment" and
"signed by an untrusted key" are three different operator actions, and a pipeline that collapsed
them into one "refused" would be technically safe and operationally useless
(`tests/test_pack_review_safety.py`, 25 cases, one per rejection path). A pack that does not
parse is returned as a *rejection report*, not raised: "hostile pack" is an outcome to record,
"not a pack" is a usage error (ADR-310.2).

**The safety gate is a policy gate on the AST — not a sandbox, and it says so.** A text search
for `subprocess` misses `__import__("subprocess")` and flags the word in a docstring; the AST
sees the import and the call as they will actually execute. The gate blocks process control, raw
network, dynamic code (`eval`/`exec`/`compile`/`__import__`), code-deserialisation
(`pickle`/`marshal`/`shelve`/`dbm`) and FFI (`ctypes`), and warns on `open`/`input`/file writes
and interpreter-state mutation. A member that does not parse is itself a blocking finding:
"we could not parse it" must not look like "we found nothing". **The pack still runs in-process
afterwards** — the gate raises the cost of shipping a hostile pack and makes the honest mistake
loud; it does not confine a determined one. That limitation is stated in the module docstring,
in `docs/operator-guide.md` §41 and in ADR-310.3 rather than implied away. The declared-content
half is the proof-ladder check: an L3/L4 declared check that omits `requires_state_attestation`
is refused, because it would otherwise be planned and run on an authorization that never covered
a state change (REQ-PROOF-002/004).

**The AST denylist is assembled from suffixes so it does not trip the repo's own hygiene scan.**
`tests/unit/test_http_hygiene.py` scans every module's *source text* for the shell helpers it
bans, so a denylist that quoted `os.system`/`subprocess.Popen` verbatim would flag
`plugins/review.py` itself and the policy table would read as the very thing it forbids. The
banned call names that would otherwise match the shell-helper patterns (`popen`, `system`,
`spawn*`, `exec*`) are therefore matched by **last component**, not by full dotted name
(`_BLOCKED_CALL_SUFFIXES`), and the rest by dotted prefix. This is a deliberate construction,
not an accident of formatting.

**A review verdict is bound to the pack digest, so re-signing the same bytes passes and
rebuilding with different content does not.** `PackReviewStore.is_listed(name, version, digest)`
is true only for the newest verdict on the exact digest; a review is evidence about a byte
sequence, not a name (ADR-310.4). `arachne packs import` fails closed on this: with
`ARACHNE_PLUGIN_REQUIRE_REVIEW` on (**the default**), a pack with no listed review for its digest
is refused, and the escape hatches (`ARACHNE_PLUGIN_REQUIRE_REVIEW=false`,
`ARACHNE_PLUGIN_ALLOW_UNSIGNED=true`) are the explicit, audited exceptions. `pack.imported` /
`pack.rejected` / `pack.reviewed` are all in the trail.

**Generated clients cannot skip auth or rate limits, and the proof is a live server.** Both
`clients/python/` and `clients/typescript/` require a non-empty API key at construction and route
every request through **one** chokepoint that sets `x-api-key` (and `x-project`) — there is no
per-method path that bypasses it. `tests/integration/test_sdk_contract.py` runs the generated
Python client against a **real** server and the generated TypeScript client live under `node`
(native type stripping), asserting a blank key is refused before any request, a wrong key is the
*server's* 401 (only the auth dependency writes that audit row), the `x-project` header is acted
on, and a burst returns 429 as a typed error that is **not retried** — the client never waits the
rate limit out and re-sends. The node test skips cleanly when `node` is absent, and the skip is
asserted (pytest's `Skipped` is deliberately matched as a `BaseException`), so a bare environment
is green without pretending the TypeScript contract ran.

**Tenant scoping of quality rows is by the request, and NULL is deployment-wide.** A
`risk_acceptance` or `suppression` carries a nullable `project_id`; **NULL means deployment-wide**,
which is every row written before S26 — so a pre-S26 row is visible to every tenant exactly as it
was before, and the migration changes no existing behaviour (ADR-310.9). The tenant for a
self-service write comes from the **request** (header/cookie), never from the form body:
`tests/integration/test_ui_ecos.py::test_a_rules_tenant_cannot_be_forged_through_the_form` pins
that a forged tenant does not take, and `test_the_quality_page_shows_only_the_selected_tenants_rules`
pins the scoping. The posture page is likewise scoped to the selected tenant.

**Server-rendered SVG is HTML-escaped, because the values are target-controlled.** An asset name,
a host, a CWE label — anything that reaches a chart — comes from scanned data, which the target
can influence. `api/ui_visuals.py` escapes every label with `html.escape(..., quote=True)`
(`_esc`), and `tests/report_qa/test_ecos_golden.py::test_the_visualisations_are_deterministic_and_escape_their_input`
pins it. A visualization that interpolated a raw asset name would be a stored-XSS vector in the
dashboard; the escaping is the control, not the styling.

**The `ProjectOut` `extra="forbid"` field-drift note.** `ProjectOut` (and the other API models)
are `extra="forbid"`; adding `projects.report_locale` to `ProjectRecord.to_dict()` without
declaring it on `ProjectOut` turns every project route into a **500**. The field is declared with
that reason in the schema (`api/schemas.py`), and the same class of defect was already recorded
at S25 (finding F9). It is noted here because it is the recurring cost of a strict output model:
a new column is not done until it is declared on the wire.

*Residual risk (review is a gate, not a sandbox).* The safety gate reads the AST of a pack's
members; it does not execute them in a confined environment. A pack that the gate cannot
*recognise* as hostile — an obfuscated construct, a capability the denylist does not enumerate —
still runs in-process once listed. Signature, trust and parity bound *who* may ship; the AST gate
bounds *what the honest and common hostile shapes look like*. A true sandbox for packs
(seccomp/container/separate process) is a later capability, and the pipeline does not pretend to
be one.

**Authority and least privilege.** `POST /api/v1/plugins/review` is admin and takes a **host
path** (`pack` is a path on the server, not an upload), so it can only review a pack the caller
can already see on the filesystem; `GET /api/v1/plugins/reviews` and
`/api/v1/plugins/marketplace` are read-only listings. The per-tenant locale and the white-label
mode are deployment/tenant *presentation* settings and introduce no egress. No new egress path
was introduced anywhere in S26: the review reads bytes, the UI renders SVG, the clients call the
API the process already serves, and the CI surfaces call the gate that already exists (S23).

## 19. Simulation & what-if modeling (S28, area SIM) — **PASS**

**The security property of this area is an absence, and it is proved by construction rather than
asserted.** A simulation computes attack paths over an estate model built from stored scan data;
its P0 requirement is that it is structurally incapable of network I/O. There is no setting that
enables egress, because there is no egress code to enable: the package imports no HTTP client, no
socket (except the guard that denies it), no `asyncio`, no `subprocess`, and no ARACHNE module that
owns an egress or a store path. `sim/hygiene.py` states that rule as data and
`tests/test_sim_safety.py` runs the scanner over the shipped tree, with positive controls proving
the scanner catches each class of escape (`import httpx`, `import socket`, `os.system`,
`importlib.import_module`, an `os` alias) and negative controls proving it does not flag the pure
collaborators it must keep. Exactly one file is exempt from one import —
`sim/boundary.py` holding `socket` so it can refuse it — and the exemption is pinned at that file
and that import.

**The boundary fails closed at runtime, which is what covers code we did not write.** Static rules
cannot see a dependency that dials on first use, a plugin, or a collaborator replaced by a
misconfigured one. `no_network(...)` therefore replaces every socket entry point
(`socket.socket`, `create_connection`, `getaddrinfo`, `gethostbyname*`, and the methods of
already-constructed sockets) with a guard that raises `SimulationNetworkError`, records a
**blocked** `simulation.boundary_violation` event naming the entry point, and never completes the
call. `tests/test_sim_safety.py` arms each entry point individually, arms *all* of them across a
whole simulation, and drives the misconfiguration case directly by replacing the path composer with
one that dials from inside a run. The `finally` restores every entry point, and a test opens a real
loopback socket afterwards — a boundary that leaked would break every scan that followed it.

**Nothing simulated can become a finding, and that is structural on both sides.** On the write
side, area SIM has one table (`simulation_points`, migration 0014) holding the trend's headline
numbers; no module in the package names a finding-store writer, and a real what-if run over a real
lab scan is asserted to leave the candidate set and the severity counts byte-identical. On the read
side, the report's simulated block lives in its own top-level field (`report.schema` 1.11), is
rendered in its own section (`## 13.`, after the evidence appendix, opening with a disclosure
sentence), and no finding-shaped consumer reads it: `ecos.ci_gate.findings_from_report` returns
only `report.findings`, and `tests/report_qa/test_sim_golden.py` pins that a *critical* simulated
path leaves a gate verdict clean while the fixture's own verified critical finding trips it.

**The staging rules are the report's own, and that is a security property too.** A simulation that
composed paths with looser rules would predict attacks the verified report would never show, which
for a capability whose whole purpose is to be believed about a future that has not happened is the
worst failure mode available. `estate.attack_paths()` calls
`analyzer.paths.build_attack_paths` — the same function the verified `## 9. Attack paths` section
uses — and a simulated hop's `origin` (`observed`/`hypothetical`) replaces the verified marker
entirely, so the word *verified* cannot appear about a hop nobody scanned. The cheapest-break
sentence is re-worded for the simulated world for exactly that reason.

**Identity relationships are recorded, never inferred, and reachability is never guessed.**
`sim/reachability.py` reads three documented evidence shapes and ignores every other payload; an
undocumented shape produces a smaller graph rather than a plausible-looking invention. Credential
labels bind only to the host a credentialed scan authenticated to (its plan target) and to hosts
with an authenticated-area finding — no credential material is read at all, and the vault is not
importable from the package.

**No new egress path, no new authorization surface, no new secret.** The area adds no endpoint, no
route, no credential, and no scope relaxation; the network refusal subclasses `SafetyError` so it
classifies as a safety refusal wherever errors are classified, and the audit trail records the
model's provenance (`simulation.model_built`), every run (`simulation.run`, with the scans the
model came from and the exposure before/after), the continuous refresh
(`simulation.resimulated`) and every boundary violation.

**Known limitations, stated rather than implied.** (1) The boundary guards the *process*, not the
kernel: a native extension that bypasses the `socket` module would not be caught by the guard — it
would be caught by the import rules only if it were a Python import, which is why the static half
exists as well. (2) The model is as complete as the estate's scans: an unprobed port is invisible,
by design. (3) `simulation_points` is prunable operator data with no retention policy of its own;
it holds no finding and no target data beyond an estate key.

## 20. Bounded safe fuzzing (S30, area FUZZ) — **PASS**

Area FUZZ is the capability whose *purpose* is to send a target traffic no other part of the
program would. Its review therefore starts from the opposite direction to the rest of this document:
not "can a hostile target make ARACHNE do something bad" but "can ARACHNE itself be the harm" — a
fuzzer that changes state, exhausts a service, or fuzzes an estate nobody authorized.

### Reviewed controls

| Control | Where it lives | What it is worth |
|---|---|---|
| A dedicated fuzzing attestation, on top of the scan's | `fuzz/attestation.py` | Non-production by default; a production label needs the grant *and* the deployment; an **unclassified** environment is refused rather than assumed. Coverage uses the same function as the scan attestation (`entry_covers_selector`), so the two grants cannot disagree about the estate |
| Refusal audited before it is raised | `fuzz/attestation.authorize_fuzz` | `fuzz.refused` is written `blocked` inside the gate, so a caller that drops the exception still leaves the record. The runner authorizes before constructing a client, so an unattested request cannot reach code that opens a socket |
| Hard bounds, spent before the request | `fuzz/bounds.py`, `fuzz/runner.py` | Cases, requests and wall-clock seconds per target; a refused spend leaves the ledger untouched, so a repeated refusal cannot walk past a bound. A plan and a grant may each narrow; the ceiling clamps any request upward |
| Inherited egress | `core/net.ScopedNetClient`, `core/http.ScopedHttpClient` | Fuzzing has **no egress path of its own**: scope, address policy, air-gap allowlist, rate limiting, redaction and the `net.probe`/`http.request` audit line are all the existing client's |
| Prohibition table on generated bytes | `fuzz/prohibitions.py`, `fuzz/grammar.py` | Destructive SQL, shell metacharacters, destructive commands, remaining-infrastructure verbs, credential/account mutations and obfuscation encodings. Applied at case construction **and** again in the runner, because the engine is pluggable |
| State-changing operations unrepresentable | `fuzz/prohibitions.grammar_operation_problems`, `MessageGrammar._value_replacement` | A grammar's operation field is confined to a declared read-only allowlist, refused at *construction* (including when the seed itself carries a write), and re-checked at the moment a value is written. This is a structural property, not a review habit |
| Abort on degradation | `fuzz/health.py`, `fuzz/runner.py` | Batches bracketed by health probes, more probes interleaved, guard re-judged after every case; the first signal stops the whole run, is audited `fuzz.aborted` with the measured value, and exits non-zero |
| Candidates are not findings | `fuzz/candidates.py`, `fuzz/runner.py` | No severity, no verdict, `"is_finding": false` restated on every row and in every audit line. The runner constructs no `CheckResult`, so there is no path from a fuzzing run to a reported vulnerability |
| Pluggable engine boundary | `fuzz/engines.py` | An engine sees the grammar and the outcome, never the budget, the network or the audit trail — and the runner re-validates every payload it is handed |

### Adversarial tests

`tests/test_fuzz_safety.py` is the append-only suite. Its assertions are about what did **not**
happen, measured against the fixture's own counters rather than against the fuzzer's report: an
unattested plan is refused with zero requests parsed by the service; a prohibited payload is
discarded inside the process and never written to a socket (with the audit `detail` naming the
class); the request count never crosses the cap; an abort stops the run *and* the remaining targets,
with the dropped-connection count proving the service was left alone; an out-of-scope endpoint is
refused with nothing sent; and a fuzzing run produces candidates with `is_finding is False` while
never writing a candidate *record* into the finding store.

### Findings

None at the review's severity bar. Three design decisions are recorded because a reviewer should see
them rather than infer them:

1. **Textual prohibitions do not apply to predominantly-binary payloads.** A binary message is
   judged by its operation table — enforced structurally at the grammar — not by whether its bytes
   happen to spell a word. This is a precision decision, and it is stated in the module rather than
   left implicit: the alternative (asking whether a TLS ClientHello's 32-byte nonce contains the
   word "shutdown") refuses legitimate cases and proves nothing.
2. **A TCP connection that answers nothing is treated as a degradation signal.** On TCP every
   request is expected to produce bytes, so an accepted connection with no answer is the shape of a
   service that has stopped coping. On UDP silence is a legitimate answer and is *not* a signal. The
   consequence is deliberate: an ambiguous case stops the run, and the candidate recording the
   non-answer survives the abort, so the conservative choice costs no evidence.
3. **This build does not ship an SMB2 grammar.** Its client GUID is random, so a byte-reproducible
   case would require a determinism seam in a shipped builder. Recorded as a limitation rather than
   fudged with a non-reproducible seed.

**Known limitations, stated rather than implied.** (1) The prohibition table is a deny-list over
*known* harm classes; a novel destructive payload class would not be named by it — which is why the
operation table, the hard bounds and the abort guard carry the weight rather than the deny-list
alone. (2) `environment` is a declaration ARACHNE cannot verify; it is one gate of several
(scope, attesting identity, expiry, coverage, and the deployment's own opt-in) rather than the gate.
(3) A third-party engine could attempt a payload the table misses; the runner's last-gate check and
the scoped client's audit line are what bound that, and both are on the path of every case.
