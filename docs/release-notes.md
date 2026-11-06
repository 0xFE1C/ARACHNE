# Release notes

> **Owner:** ARACHNE programme · **Last verified:** 2026-11-05 · **Review interval:** 180 days

*One section per release, newest first. The per-release change entries are **generated** from
[`CHANGELOG.md`](../CHANGELOG.md) — the single source for what changed — and this file carries
no second copy of them. Every number here is reproducible with the command that produced it;
where a capability is partial, this file says so.*

<!-- BEGIN GENERATED: changelog -->

<!-- Generated from CHANGELOG.md by `python -m arachne.tools.changelog --write`;
     edit the source, not this block. -->

## Change index

The authoritative change entries live in [`CHANGELOG.md`](../CHANGELOG.md). This index is generated from them, so the two cannot drift.

| Version | Date | Status | Added | Changed | Deprecated | Removed | Fixed | Security |
|---|---|---|---:|---:|---:|---:|---:|---:|
| Unreleased | — | unreleased | 0 | 0 | 0 | 0 | 0 | 0 |
| 0.1.0 | 2026-11-05 | development snapshot (unreleased) | 14 | 3 | 0 | 0 | 3 | 3 |

### Unreleased

No entries.

### 0.1.0 — 2026-11-05 — development snapshot (unreleased)

**Added**

- **Detection across six modules** — reconnaissance and OSINT, network and service checks,
- **A graduated safe proof ladder (L0–L4)** with verification records: a finding states how it
- **Evidence custody that survives deletion** — evidence is content-addressed inside its
- **An API and web UI** with key-based authentication, per-tenant isolation over every
- **A report engine** producing Markdown, HTML, JSON, SARIF and PDF from one model, versioned
- **Two analysis engines** — a deterministic heuristic engine that needs no network or API key,
- **Identity and access management** — roles, service accounts, sessions, project-scoped API
- **Operational surfaces** — service-level objectives with generated burn alerts, a rehearsal
- **A software-supply-chain story** — signed releases with SLSA v1.2 Build L3 provenance, an
- **Trust primitives** — Ed25519 signing and verification with the public key alone, a
- **Compliance maps generated from check metadata** for CIS, ISO/IEC 27001, NIST CSF and
- **A purple-team catalogue** of ATT&CK v20 techniques with replayable, declared-safe proof
- **Bounded fuzzing of protocol surfaces** behind a grant and an attestation, with a case,
- **A documentation surface** with an owner and a last-verified date on every page, a link and

**Changed**

- **Numeric claims in documentation are generated or test-checked**, so a count that moves in
- **The compliance maps and the coverage ledger are artefacts of the check registry**, not
- **Release notes are generated from this file** rather than typed twice.

**Fixed**

- **Five cross-tenant isolation defects** found by the generative tenancy suite — an evidence
- **Deduplicated evidence could be destroyed by one finding's delete**, and a tenant could be
- **A dangling-reference class in the documentation** — citations to paths and commits that do

**Security**

- **Proof levels are refusals, not warnings**: an L3 or L4 action without the corresponding
- **Scope is deny-by-default** and evaluated before resolution, with an out-of-scope host
- **Redaction happens at capture**, so a credential's value never enters evidence, a report or

<!-- END GENERATED: changelog -->

---

## 0.1.0 — development snapshot (unreleased)

**ARACHNE is a defensive vulnerability scanner.** It inspects targets you are authorized to
test, proves what it finds through a graduated safe proof ladder, reports it with evidence,
and cleans up after itself. It runs on a deterministic heuristic engine, a pluggable AI
engine, or both.

This snapshot is feature-complete against its own specification but **not yet released**. It
is published here so that an operator can evaluate it and a contributor can work on it. Read
the [Known limitations](#known-limitations) section before deploying it anywhere that
matters.

### What is in this snapshot

**Detection — 175 registered checks across six modules**

| Module | Checks | Surface |
|---|---:|---|
| M1 Reconnaissance & OSINT | 17 | dork sweeps, subdomain enumeration, certificate transparency, breach exposure, provider drift |
| M2 Network & services | 31 | ports, fingerprints, TLS, mTLS and X.509, DNS and AXFR, SMB, databases, OT protocols, SMTP transport, HTTP/3, read-only AD CS enumeration, CVE correlation |
| M3 Web application | 57 | injection, access control, session and identity, request smuggling, cache poisoning, GraphQL, WebSocket, gRPC, client-side code, DOM-XSS in a headless browser (optional extra), mobile artifacts |
| M4 Misconfiguration & exposure | 29 | exposed `.env`/`.git`, backups, debug endpoints, headers, cookies, default credentials |
| M5 Cloud, container & supply chain | 22 | instance metadata, buckets, Kubernetes, registries, native container-image scanning, CI/CD, dependency confusion, IAM posture, DigitalOcean posture |
| M6 Automation & AI-era | 19 | webshell signatures, secret scanning, local privilege escalation, AD paths, GenAI surface, MCP and Agentic Top 10 surface, Sigma hunts |

Checks and their payloads are data, not code: payloads, wordlists, protocol tables and rule
corpora live in `src/arachne/templates/` and can be replaced by an operator.

Three capabilities are **optional extras**, so the default and air-gapped installs never carry
them: `arachne[quic]` (HTTP/3 probing), `arachne[browser]` (the headless-browser DOM-XSS crawl)
and `arachne[postgres]`. Each degrades to a check that reports itself skipped, naming the extra
to install; `pip install arachne[browser]` also needs `ARACHNE_WEB_BROWSER_CRAWL=true`, because
a browser engine inside the scanner is a new attack surface and the operator opts into it.

**Analysis — a dual engine with a parity guarantee**

- A **heuristic engine** of 127 rules in a restricted expression language. It has no code
  execution, it is deterministic, and it works with no network and no API key.
- An **AI engine** with seven provider adapters (OpenAI, OpenAI-compatible, Anthropic,
  Gemini, Ollama, Mistral, custom). It annotates the heuristic verdict; it never owns it.
- A **parity suite** proves both engines reach the same finding set on the ground-truth
  fixtures, so a report cannot tell which engine ran except through its provenance field.

**AI provenance and evaluation — the "how do you know?" layer (WP-15)**

- **Every AI contribution is traceable, and AI changes are gateable.** Each analysis row persists
  a provenance record — origin (`ai`/`heuristic`), provider, model, prompt-template hash, prompt
  and completion tokens, the evidence ids the model cited, and the change it made — in its own
  `analysis_log.provenance` column, so an AI row is distinguishable from a heuristic one without
  reading a log. `arachne ai provenance --scan N` (or `--project P`) exports it, and
  `arachne compliance export` carries the same block: which provider received how many tokens for
  this scan.
- **An AI row cannot exist without a cited evidence id.** The provenance record refuses to be
  built without one, the engine treats an uncited answer as a *failed stage*, and the store
  refuses to persist a payload that claims AI without a citation. The prompt offers the model the
  closed list of ids it may cite, and every citing stage's schema requires it to cite at least one.
- **A held-out offline evaluation suite measures AI changes.** 240 labelled cases in a versioned
  corpus (`tests/eval/fixtures/ai-eval-cases-v1.jsonl`), run through the shipped engine with a
  scripted provider — no network, no API key, deterministic across runs — scored **per stage**
  (precision, recall and accuracy for `triage`, `correlate` and `narrative`). The baseline is
  committed alongside the corpus digest, a regression beyond two percentage points fails the gate,
  and a deliberately degraded prompt corpus is caught by a self-test in the same suite.
- **A dated provider parity matrix measures all seven adapters.** `docs/ai-provider-matrix.md`
  records, per adapter and per stage, the structured-output mechanism each one chose
  (`json_schema`, `tool_use`, `response_schema`, `format_schema`, `custom`), whether that mechanism
  constrains decoding at the provider or only asks for JSON, the suite's scores, and what an
  operator must supply — including the `custom` adapter's refusal to plan anything without a
  user-defined request template.
- **The AI layer's tool surface is enumerated and typed.** `ai.tools` declares the
  capability-scoped tools an AI stage may call (`analysis.*`, `catalogue.*`), each with a typed
  argument model; an undeclared name is a typed error and an audited `ai.tool` refusal. There is
  no process, socket or filesystem capability in the vocabulary, and a static-analysis test asserts
  that no module of `arachne.ai` imports such a primitive.

**Safety architecture — the part that does not change between releases**

- **Scope is deny-by-default.** An empty scope authorizes nothing. Hosts are resolved and
  validated *before* each request, and every redirect hop is re-validated.
- **Authorization is a typed, expiring, audited attestation.** A live scan without one never
  leaves the process.
- **The proof ladder runs L0 to L4:** passive, active read-only, out-of-band, one-shot
  command, minimal reversible state change. Every check declares the level it needs; L2 and
  above are opt-in; L3 and L4 require a state-change attestation. State changes are captured,
  restored and re-verified by a cleanup pass.
- **The audit trail is hash-chained and tamper-evident.** `arachne verify-chain` detects an
  edited, deleted, reordered or truncated trail, and verifies signed rows and per-scan seals.
- **Every finding carries its verification record.** The proof level, the method, the
  observations, a reproducibility token, when it was verified and which version of the check did
  it — required by report schema 1.12 (WP-13, REQ-PROOF-015). A finding reported without one is
  forced to `info` and marked `unverified`. `arachne verify-finding <id>` re-runs that finding's
  own check against the same asset and reports `still-verified` / `no-longer-verified` /
  `inconclusive` / `refused`, re-checking scope **and** attestation before any request and never
  raising the proof level (REQ-PROOF-016).
- **The injection families share one differential oracle.** Two boolean rules, a query rule and a
  content-marker rule live in `modules/m3/oracle.py` and are exercised by one conformance suite:
  the same payload set must produce the same verdict across families, and a page that answers 200
  identically to every input produces zero positives in all of them (REQ-PROOF-020).
- **Secrets and PII are redacted at capture**, never at render.
- **Every scan emits a residue attestation.** One artefact per scan enumerates each state
  change it authorized — asset, action, before-value *hash*, restore outcome, timestamp — with
  the verdict: zero residue, or the unrestored list and its repair instructions. It is signed
  with the deployment key when one is configured and **marked unsigned** when not, its hash is
  linked into the audit chain, and a scan with residue is not reported as clean (WP-14,
  REQ-PROOF-017).
- **Evidence has a chain of custody.** Every stored blob's content hash is recorded in the audit
  chain as it is captured, and `arachne verify-chain` reports `evidence.mismatch` — naming the
  evidence id — when a stored payload is edited behind the store's back, and a deletion for a
  blob whose scan still exists (WP-14, REQ-PROOF-018).
- **Out-of-band callbacks are authenticated per scan.** A callback token carries an
  authenticator derived from the deployment key, single use is enforced with a bounded replay
  window, and callbacks for a scan that is not active or whose attestation has expired are
  refused and audited (WP-14, REQ-PROOF-019).
- **PII retention is implemented, not just documented.** `ARACHNE_PII_RETENTION_DAYS` is
  consumed by the retention pruner: a dry run reports counts by category without changing
  anything, the applied run masks older inline evidence under the project's policy and audits
  one event per blob, and a blob it cannot mask (an offloaded object) is reported explicitly.
  Re-masked rows are re-signed and their scans re-sealed, so `verify-chain` stays green
  (WP-14, REQ-DATA-005).

**Operation**

- A **CLI**, a **REST API** (74 documented operations, OpenAPI at `/docs`) and a **web UI**
  (14 screens, each with an explicit loading, empty, error, partial and refused state;
  server-rendered with progressive enhancement and no build step).
- Generated **Python and TypeScript API clients**, contract-tested against the live schema.
- A **scheduler** with diff reporting, and **distributed scan agents** on a Postgres lease
  queue.
- **Air-gapped mode**, enforced at the request boundary: an air-gapped deployment refuses its
  first outbound request and audits the refusal.
- **Helm chart** and **Terraform module**; Docker and compose files for a demo stack.
- **Service-level objectives as code**: availability, API latency and scan completion, each with
  a target, a window, a measurement query and fast and slow error-budget burn alerts. The alert
  rules are generated from the definitions, and a contract test resolves every metric, label and
  histogram bucket they name against the families `GET /metrics` actually exposes.
- **Upgrade safety**: every migration declares in its docstring whether it is reversible, and
  the declaration is tested by running the downgrade; `arachne db upgrade --dry-run` prints the
  SQL without touching the database; a migration that does not declare itself reversible is
  refused until `--allow-destructive` acknowledges it.
- **A rehearsed restore**: `arachne dr rehearse` backs a deployment up, restores it into a
  scratch database, compares row counts, verifies the restored audit chain, and records the
  measured RTO and RPO per run — failing with the stage named when a stage breaks.
- **Mutation testing over the safety core** (scope gate, proof ladder, audit chain, SQL proof
  helper) with a minimum score, a scored allowlist of equivalent mutants, and a bounded subset
  on a pull request and the full set nightly.
- Reports as **Markdown, HTML, JSON, PDF and SARIF**, with executive summary, OWASP mapping,
  evidence appendix and a diff against the previous scan.

**Trust, compliance and detection validation (WP-19)**

- **Ed25519 alongside HMAC.** A deployment can sign its audit chain, row signatures and seals
  with an asymmetric key (`ARACHNE_INTEGRITY_ALGORITHM=ed25519`), and an auditor who holds
  **only the public key** verifies them and *cannot* forge one — the limitation ADR-300.5
  recorded is closed (REQ-TRUST-008). The signature format is unchanged (still
  `<scheme>:<key id>:<hex>`; HMAC keeps its historical `v1` tag), so stored rows stay valid;
  `arachne verify-chain` verifies either scheme through one keyring, and a documented **dual
  period** lets a deployment switch without invalidating anything written before the cutover.
  The primitive is pure Python, replayed against the **RFC 8032 §7.1** test vectors and
  cross-checked against `cryptography` where that developer dependency happens to be installed.
- **Compliance maps are generated, not maintained.** Each check declares the compliance
  controls its evidence bears on, and `python -m arachne.tools.compliance` generates the four
  published maps from that metadata — `--check` fails when a committed map and the registry
  disagree (REQ-TRUST-009). The complete control inventories are vendored with their
  provenance, so reach is counted against the frameworks' own totals: **CIS 64/153, ISO/IEC
  27001 46/93, NIST CSF 42/106, PCI DSS 11/12**, and every control no check can speak to is
  named in `outside_assessed_set` with a reason instead of being omitted.
- **The purple catalogue covers 36 ATT&CK v20 techniques across 10 tactics** (41 replayable
  proof actions, up from 3 techniques), with the tactic vocabulary read from the pinned v20
  release — 15 tactics, including the split of Defense Evasion into **Stealth** and **Defense
  Impairment** (REQ-VALID-007). An action's technique must exist in the release and its tactic
  must be one the release assigns that technique; no action is filed under Stealth, because
  these tests are designed to be seen.
- **A reproducible public benchmark**: the committed result states the corpus version and its
  digest, the exact command, the environment and the **raw per-case rows** — with precision,
  recall and a per-case time-to-finding whose source is named — and fixture rotation is
  recorded with a review date a test enforces (REQ-TRUST-010).
- **SLSA v1.2 Build L3 provenance and a validated SBOM**: the release workflow generates the
  SBOM with the shipped tool and validates it against the vendored official CycloneDX 1.5
  schema, and GitHub's attestation provides the L3 platform, which the workflow verifies with
  cosign before the release completes (REQ-TRUST-011). A shipped offline tool emits the same
  in-toto statement for a self-hosted build and says plainly that it is not L3.

**Beyond scanning**

- **Detection validation**: nonce-tagged proof actions replayed against your SIEM's alerts,
  scored against your Sigma rules.
- **Bounded safe fuzzing**: its own attestation, hard budgets, a prohibition table, health
  probes with an abort guard, and ten wire grammars.
- **Remediation as code**: human-approved pull requests, with the change proved to be scoped
  to the finding.
- **Continuous exposure management**: scheduled cloud-config checks, an IaC/CI gate, a
  Kubernetes admission endpoint, and a fix-verification loop.
- **What-if simulation**: an estate model that cannot reach a target, used to answer
  "what changes if I fix these five things?"

### Verification

| What | Result |
|---|---|
| Tests | **5,622** tests collected (the scope CI runs: `pytest tests -m "not perf"`) |
| Primary safety suite | **59 tests** in `tests/test_safety.py`; **340** in the safety files |
| Ground-truth labs | web, cloud, GraphQL, gRPC, fuzzing, protocol and mobile fixtures with planted false-positive traps |
| Strict type checking | clean under `mypy --strict` across the **434** Python modules in `src/` |
| Lint | clean over the whole repository (the badge's scope is the tree, not `src/` and `tests/`) |
| Research coverage | **148/175 (84.6%)** of the corpus's numbered methods have an implementing check |

Every figure here is generated rather than typed: `python -m arachne.tools.counts --check`
fails the build when one of them drifts from the registry, the suite or the coverage tool.
Reproduce them with the commands in the [operator guide](operator-guide.md).

### Known limitations

These are real, verified against this snapshot, and listed here rather than left for you to
discover. Each is a candidate for a future release.

**Detection gaps**

1. **No JavaScript execution unless the optional browser extra is installed.** The headless
   browser crawl (`m3.dom-xss`, REQ-DET-015) reaches single-page-application routes and
   DOM-based sinks with a real engine, but it is an optional extra *and* an operator opt-in:
   `pip install arachne[browser]` plus `ARACHNE_WEB_BROWSER_CRAWL=true`. Without both, that
   half of client-side testing is still the largest gap against comparable tools, the check
   reports itself skipped, and the plan says so. Its crawl is bounded by a documented page and
   time budget, every navigation passes the scope gate before the request, and the browser
   reaches the network only through ARACHNE's scope-bound proxy — but a page whose bundle lives
   off-scope renders as an empty shell, because deny-by-default outranks rendering fidelity.
2. **No WSTG or OWASP API Top 10 identifiers** in check metadata. Coverage against those
   frameworks cannot be reported, only estimated.
3. **Four of the ten OWASP Agentic Top 10 items have no check**, and AD CS enumeration is
   partial. `ASI01`, `ASI04`, `ASI05` and `ASI08` are named as gaps in the generated coverage
   ledger ([`coverage_matrix.md`](../coverage_matrix.md), which every check's `research_ref`
   feeds); the six that ship are `ASI02`, `ASI03`, `ASI06`, `ASI07`, `ASI09` and `ASI10`. The
   AD CS check reports the template and CA conditions associated with the published ESC classes
   but cannot decide the ACL-based ESC4/ESC5/ESC7, the relay-based ESC8 or the mapping-based
   ESC9/ESC10 halves, which it names as not-assessed rather than omitting. MCP-server checks
   ship (three of them).
4. **Mutual TLS and client-certificate inspection ship**, as does SMTP transport-security
   assessment (STARTTLS enforcement, AUTH mechanisms, open relay). What they do not do is
   *require* a client certificate: a server that accepts an anonymous handshake is reported as
   accepting one, not as a failure, because whether mTLS is required is a deployment decision
   the scanner cannot read from outside.
5. **HTTP/3 probing ships as an optional extra** (`arachne[quic]`; with the extra absent the
   check reports itself skipped and names it). IPv6-only targets remain **under-scanned**: the
   address policy, scope comparison and connect path handle IPv6 (the IPv6 safety suite asserts
   the parity), but the port and service catalogue is IPv4-shaped, so a v6-only host yields
   fewer service findings than its v4 equivalent.
6. **`oracle`, `sip` and `opc-ua` are declared in the port catalogue without an implementing
   check.** An Oracle port currently produces a generic "port reachable" finding rather than
   a database finding.
7. **Container image scanning is native and on by default**, so it works air-gapped with
   nothing installed (REQ-DET-016). The external Trivy/Grype path is an opt-in import of a JSON
   report produced out of band, never a launcher. The shipped advisory index is small; replace
   it with `ARACHNE_M5_PROBES` for real coverage.
8. **Cloud posture covers AWS, Azure, GCP and DigitalOcean.** OCI and Alibaba Cloud are
   `not_supported`, each with its reason in the coverage ledger — their APIs need a request
   signing scheme this release does not implement, and a guessed one would misreport posture.
9. **Every in-scope CWE Top 25 weakness now has a check (18 of 18).** The four that were gaps in
   an earlier snapshot (CWE-94, CWE-863, CWE-20, CWE-77) have one. The residual limitation is
   the same shape as item 2: a weakness is covered through the *techniques* its checks
   exercise, so a CWE no non-destructive probe can reach would appear as a named gap in
   `coverage_matrix.md` rather than being silently omitted.

**Behaviour you should know about**

10. **PII re-masking in place is implemented for evidence stored in the database, and only
    reported for offloaded evidence.** The retention pruner masks inline payloads under the
    project's policy and **reports** a payload that was offloaded to an object store
    (`pii.remask_unsupported`, with the reason in the plan) instead of rewriting the blob:
    rewriting would mint a new content-addressed key and orphan the old object, and reference
    counting is the data-lifecycle package's (REQ-DATA-006, WP-21). A deployment with
    `ARACHNE_EVIDENCE_BACKEND` set therefore has a partial privacy control — and the largest
    payloads, where PII is most likely, are the ones it reports rather than rewrites.
11. **`arachne coverage` reports 148 of 175 methods (84.6%) mapped.** The remaining 27 are
    named gaps, each with the reason it is absent (see `docs/research/README.md`). Seven of
    them are absent because the technique would need a capability ARACHNE refuses; the rest
    are simply not built yet. The committed `coverage_matrix.md` is the same number, and a
    test fails when it goes stale.
12. **The reporting pipeline step is declared but has no handler.** Reports are generated out
    of band with `arachne report`; the plan output marks the step "not executable".
13. **A DNS-rebinding window remains** between address validation and connect. Per-hop
    revalidation is the current mitigation; a container or network-namespace sandbox is not
    implemented.
14. **An unsigned deployment verifies as intact.** With no integrity key configured,
    `verify-chain` passes unless you pass `--require-signatures`.
15. **15 registered checks are not referenced by id in the test suite** (M4, M5 and M6
    clusters), so a regression in them could go unnoticed.

**AI provenance and evaluation (WP-15) — what the new evidence does and does not cover**

19. **The evaluation suite measures the pipeline's information fidelity, not a model's
    quality.** It runs a *scripted* provider that answers from the rendered prompt, so a score
    drop means a prompt or merge change stopped conveying what a label depends on — which is the
    regression class a prompt edit causes. Whether a particular model is good enough for a stage
    is not what these numbers say, and they must not be read as an accuracy claim about one.
20. **The provider parity matrix is produced through each adapter's real request/response
    handling with a scripted responder, not against live endpoints.** It therefore measures
    whether an adapter can carry the stage contract (structured output plus a citation) and which
    mechanism it chooses — not a vendor's live behaviour, latency or quality. The `custom`
    adapter is measured only in its documented configuration; unconfigured, it is reported as
    unsupported for every stage.
21. **Two declared tools have no shipped caller yet.** `analysis.evidence` and
    `analysis.severity_scale` are declared, typed, capability-scoped and tested, but no shipped
    stage calls them (the per-candidate stages read their inputs through the prompt). The
    registry's shipped caller is the agentic `hypothesize` stage, which reads its check
    vocabulary through `catalogue.list_checks`.
22. **`hypothesize` contributions are not `analysis_log` rows.** They carry stage-level
    provenance (provider, model, prompt hash, template version) in the reasoning record instead,
    because a hypothesis is a proposal, not an analysis of a finding; the citation requirement
    applies to the five stages that produce analysis content.

**Trust, compliance and detection validation (WP-19) — the limits of the new evidence**

23. **PCI DSS requirement 9 is assessed by no check, and the map says so.** Eleven of the
    twelve requirements are reachable (REQ-TRUST-009 asks for twelve); requirement 9 restricts
    *physical* access to cardholder data — facility entry, visitor management, media handling,
    point-of-interaction tamper protection — and a network scanner produces no artefact for any
    of it. The control is listed in `outside_assessed_set` with that reason rather than mapped to
    something that would make an auditor believe it had been assessed. Closing it needs a
    physical/host-agent control, not another web check.
24. **The ISO/IEC 27001:2022 Annex A inventory is secondary-sourced.** The standard is
    paywalled, so the 93 ids and short titles come from a widely used open-source library,
    cross-checked against a second independent dataset (93/93 ids identical; five title spellings
    reconciled). The file records this. Diff it against a licensed copy before treating it as an
    audited denominator; CIS v8.1, NIST CSF 2.0 and PCI DSS v4.0 come from the standards bodies'
    own publications.
25. **The Ed25519 implementation is not constant-time.** It is pure Python (the runtime has no
    cryptography dependency), and scalar multiplication is square-and-multiply over Python
    integers. Correctness is pinned by the RFC 8032 test vectors and an independent
    implementation, but a local attacker who can time the signing process is out of scope of
    that mitigation: keep the seed off hosts you do not trust for that threat
    (`docs/adr/370-trust-hardening-and-purple-breadth.md`).
26. **The purple catalogue covers 36 of the 65 ATT&CK techniques the landscape analysis calls a
    scanner's honest in-scope denominator** (and 36 of MITRE's 706 Enterprise techniques). The
    remaining in-scope techniques are mostly ones where ARACHNE has no replayable action — a
    detection test needs a safe proof payload, not only a check.

**Developer experience**

16. **The full test suite takes about 29 minutes and its bar is 15.** Every test has a timeout
    (60 s by default, with reviewed per-test exceptions), so a stuck test fails rather than
    hangs — but the suite budget itself is **not** met, and the CI `tests` job's asserted 900 s
    ceiling is red by design until the probe volume comes down. This is the one known unmet
    quality requirement in this snapshot (REQ-QUAL-007).
17. **A documentation page can go stale by one review interval before anyone is told.** Every
    shipped page declares an owner, a `last-verified` date and a review interval
    (`python -m arachne.tools.docmeta --check` in the docs job); past one interval it warns,
    past two it fails the build. The mechanism is deliberately forgiving at one interval.
18. **Coverage and mutation floors are enforced, and lowering either needs an ADR.** The branch
    coverage floor is 82 % (`fail_under`, with the CI test job running `--cov`) and the safety
    core's mutation-score floor is 0.80. Repo-wide `ruff check .` and `ruff format --check .`
    are clean and cover the whole tree, not `src` and `tests` only.

### Reporting a problem

- A **vulnerability in ARACHNE itself**: see [SECURITY.md](../SECURITY.md). Do not open a
  public issue.
- A **false positive or a missed detection**: open an issue with the check id, the target
  shape (redacted), and the evidence the check produced. Never include a real secret or
  customer hostname.
- A **documentation error**: a pull request. See [CONTRIBUTING.md](../CONTRIBUTING.md).

### Upgrading

No migration is required for this snapshot: it is the first. Future releases will state the
migration and its reversibility here.

---

## How this file is maintained

- One section per release, newest first, with the date.
- Every capability claim names the module, check or command that implements it.
- Every limitation is listed while it is true, and removed when it stops being true — not
  silently dropped.
- Numbers come from a command that is written down, so anyone can reproduce them.
