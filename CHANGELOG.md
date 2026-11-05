# Changelog

> **Owner:** ARACHNE programme · **Last verified:** 2026-11-05 · **Review interval:** 180 days

**This file is the single source of release change entries.** Every other document that lists
what changed — the release notes at [`docs/release-notes.md`](docs/release-notes.md) most of
all — carries a *generated* index of what is below rather than a second hand-written copy
(REQ-DOC-004). Editing a change twice is how two documents start disagreeing about the same
release.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html); while the project is pre-release
the version below is its development snapshot, and a released version replaces it rather than
being appended to it.

`Added` · `Changed` · `Deprecated` · `Removed` · `Fixed` · `Security` are the only section
names; `python -m arachne.tools.changelog --check` refuses any other, and refuses a release
without a date and a status.

---

## [Unreleased]

Nothing yet.

## [0.1.0] — 2026-11-05 — development snapshot (unreleased)

### Added

- **Detection across six modules** — reconnaissance and OSINT, network and service checks,
  web-application families, misconfiguration and exposure, cloud/container/supply-chain, and
  automation/AI-era surface, with every check carrying metadata, a declared proof level and
  the framework controls its evidence bears on.
- **A graduated safe proof ladder (L0–L4)** with verification records: a finding states how it
  was established, and a re-verification that no longer confirms it downgrades the finding and
  says so.
- **Evidence custody that survives deletion** — evidence is content-addressed inside its
  tenant's namespace, identical payloads share one object with a reference ledger, and the last
  reference makes the object collectable rather than unlinking a shared one.
- **An API and web UI** with key-based authentication, per-tenant isolation over every
  id-taking route, generated client SDKs, and a documented pagination and filtering contract.
- **A report engine** producing Markdown, HTML, JSON, SARIF and PDF from one model, versioned
  by a published schema with a deprecation policy and a supported-version window.
- **Two analysis engines** — a deterministic heuristic engine that needs no network or API key,
  and a pluggable AI engine with per-row provenance (provider, model, prompt hash, tokens and
  the evidence ids the model cited) and a parity suite over ground-truth fixtures.
- **Identity and access management** — roles, service accounts, sessions, project-scoped API
  keys, SCIM 2.0 provisioning with joiner-mover-leaver deprovisioning that revokes sessions and
  service-account keys in one request, and an SSH credential path that verifies the host key
  before offering anything.
- **Operational surfaces** — service-level objectives with generated burn alerts, a rehearsal
  command that measures restore point and time against declared targets, reversible migrations
  with a dry run, and a mutation-testing gate over the safety core.
- **A software-supply-chain story** — signed releases with SLSA v1.2 Build L3 provenance, an
  SBOM validated against the vendored official schema, and a shipped tool that verifies a
  provenance document offline.
- **Trust primitives** — Ed25519 signing and verification with the public key alone, a
  tamper-evident audit chain, row signatures, scan seals and a residue attestation.
- **Compliance maps generated from check metadata** for CIS, ISO/IEC 27001, NIST CSF and
  PCI DSS, with every unassessed control named in `outside_assessed_set` rather than omitted.
- **A purple-team catalogue** of ATT&CK v20 techniques with replayable, declared-safe proof
  actions and a defender-side result for each.
- **Bounded fuzzing of protocol surfaces** behind a grant and an attestation, with a case,
  request and wall-clock budget, a health guard that stops at the first distress signal, and a
  prohibition table enforced on the exact bytes before a socket is written.
- **A documentation surface** with an owner and a last-verified date on every page, a link and
  path integrity gate, generated counts, and a quickstart that is executed in CI.

### Changed

- **Numeric claims in documentation are generated or test-checked**, so a count that moves in
  the code fails the build instead of drifting in prose.
- **The compliance maps and the coverage ledger are artefacts of the check registry**, not
  parallel hand-maintained tables.
- **Release notes are generated from this file** rather than typed twice.

### Fixed

- **Five cross-tenant isolation defects** found by the generative tenancy suite — an evidence
  download route with no tenant check, two suppression/acceptance revoke routes, a hypothesis
  kill switch that reached any scan, and the project routes, which let a bound key read,
  re-policy and delete another tenant. Each is now a refusal with an audit event.
- **Deduplicated evidence could be destroyed by one finding's delete**, and a tenant could be
  billed twice for one object; the ledger counts references and the quota counts physical bytes.
- **A dangling-reference class in the documentation** — citations to paths and commits that do
  not exist — is now a gate that fails on a new one, with a self-test proving it can fail.

### Security

- **Proof levels are refusals, not warnings**: an L3 or L4 action without the corresponding
  opt-in, attestation or proof is refused before a request is made.
- **Scope is deny-by-default** and evaluated before resolution, with an out-of-scope host
  reaching no socket — asserted with every socket entry point armed.
- **Redaction happens at capture**, so a credential's value never enters evidence, a report or
  an export.
