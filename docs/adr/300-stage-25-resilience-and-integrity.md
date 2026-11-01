# ADR-300 — Stage 25: resilience & evidence integrity (areas RESIL + TRUST)

- **Status:** accepted (S25)
- **Requirements:** REQ-RESIL-001…006, REQ-TRUST-005/006/007
- **Phase/gate:** P6, gate G6 (`historical` spec path `docs/03-delivery-plan.md` §8)
- **Supersedes:** nothing. **Extends:** ADR-210 (the queue is the broker), ADR-250 (evidence
  storage, retention), ADR-290 (the nonce seam), ADR-05 (one egress path).

## 300.1 Context

Phase 6 is the platform ceiling: run where enterprises actually run (including where nothing
may leave the building), never lose a scan, and prove the evidence is intact. Five
properties were missing:

1. an air-gapped mode that is a *guarantee*, not a feature-flag convention;
2. a control plane that survives losing a replica, and an upgrade path that does not need an
   outage;
3. a scan farm that scales on the only number that matters (queue depth), down to zero;
4. evidence that cannot leave its region, and a disaster-recovery path with an RPO/RTO;
5. tamper-evidence — a hash-chained audit trail, signed findings and evidence, and a command
   that detects **modification and deletion**.

PII masking (REQ-TRUST-006) and the external-validation artifacts (REQ-TRUST-007) ride along
because they belong to the same "is this platform trustworthy?" question.

## 300.2 Decision: air-gap is an allowlist on the one egress path

`ARACHNE_AIRGAPPED=true` installs a **second, stricter allowlist** at the two places every
packet is already decided — `ScopedHttpClient` and `ScopedNetClient`. In air-gapped mode the
only reachable hosts are the deployment's scan targets (the deployment scope) plus the hosts
an operator names in `ARACHNE_AIRGAP_ALLOWED_HOSTS` (an on-premises model server, an internal
feed mirror).

The alternative — turning each egress feature off in configuration — is a convention that the
next feature added forgets. Placing the gate on the shared path means a feed sync, an OSINT
provider, a cloud AI endpoint, a webhook target, an OTLP collector and an IdP all inherit the
guarantee *without remembering to check it*. The refusal is audited (`airgap.blocked`) before
it is raised: an attempt to reach the outside from an air-gapped estate is a security event.

Consequence: the mode is not "no network". The scan still talks to the customer's estate —
that is what it is for — and a deployment that wants zero egress entirely simply leaves the
deployment scope empty (`ARACHNE_AIRGAPPED=true` with no targets configured refuses
everything, including a scan).

## 300.3 Decision: content arrives as a signed pack, and the import fails closed

`arachne.resil.packs` defines the format: a gzipped tar with a canonical `manifest.json`, a
detached signature over that manifest's digest, and the content under `content/<kind>/…`.
`build_pack` is the connected-build half; `read_pack`/`install_pack` are the air-gapped half.

The strictness is deliberate and asymmetric:

- **Building** may be unsigned (a lab's convenience);
- **importing** requires a valid signature by default. `--allow-unsigned` exists, is
  off by default, and is recorded in the audit trail as the exception it is.
- The manifest is verified **before any member is read**, and every member's digest and size
  before anything is returned; a member outside `content/`, an absolute path, a `..` segment or
  a non-regular file is refused (the archive is untrusted input, even though `build_pack`
  could not produce such a name).
- A failure at any step returns *nothing* and installs *nothing*: files are written into a
  staging directory and renamed into place, so an interrupted import leaves the previous
  version or nothing — never a half-installed tree a later scan would load.

Provenance is recorded in `content_packs` (name, version, manifest digest, signing key,
contents, importer), so "what content is this estate running, and where did it come from?" is
answerable from the database rather than from a shell history.

## 300.4 Decision: the audit chain is written by the sink, and anchored

The hash chain is computed **in the same transaction that writes the row**
(`SqlAuditChain.append`), and that class *is* the durable audit sink. Reserving a sequence
number and writing the row separately would leave a reserved-but-unwritten position, which is
indistinguishable from a deleted row to a verifier. Each row carries `seq`, `prev_hash`,
`hash` (over position + predecessor + canonical content) and `signature` (the deployment key
over the hash).

Concurrency is handled by a **unique index on `seq`**: two replicas racing for the next
position cannot both win, and the loser retries with the new tail. A unique *index* rather
than a table constraint because the column is added to an existing table and SQLite cannot
ALTER a constraint in.

A chain alone cannot see its own **tail** being deleted — there is no later row to disagree.
`integrity_anchors` records signed checkpoints of the head; `verify-chain` reports a log that
no longer reaches the last anchor, and an operator can export an anchor off the host
(`arachne integrity anchor --export`), so a database-level rewrite cannot silently delete the
evidence of the deletion.

## 300.5 Decision: findings and evidence are signed by identity, and the scan is sealed

A per-row signature covers the row's **immutable identity**: for a finding, its id, scan,
check, asset, title and creation time; for evidence, its id, owner, kind, payload digest and
creation time. `severity`/`confidence`/`status` are deliberately excluded — the analyzer fills
the first two after the row exists and an operator moves the third, so signing them would make
every finding fail verification the moment it was analysed.

Those mutable fields are covered by the **scan seal** instead: a signed manifest of every
finding and evidence row in a completed scan, written when the scan finishes. Verification
recomputes the manifest and reports the three distinguishable failures — a row **deleted**
since sealing, a row **inserted** afterwards, a row **changed** afterwards — naming the row in
each case. That is what makes REQ-TRUST-005's "modification **and** deletion" true for
findings, not only for the audit log.

The signature primitive is HMAC-SHA256 under a deployment key, with the purpose of the
signature mixed into the message (domain separation), so an evidence signature can never be
replayed as a finding or audit signature. **Known limitation:** a symmetric key means an
auditor who must not be able to forge cannot verify, where a public key would let them. This
runtime stack is deliberately dependency-free (no `cryptography`), and a stdlib RSA
*private-key* operation would mean hand-rolling ASN.1 DER parsing in the signing path, where a
mistake is silent. The verifier role is the same party that holds the key, so an HMAC is the
honest primitive. Recorded in `docs/security-review.md` §17 as residual risk.

## 300.6 Decision: leadership is a database lease, and the schema is expand-only

`LeaderElector` gives one named singleton (the scheduler tick, later the retention prune and
the auto-anchor) to one replica. The lease lives in the shared database — the same "the
database is the broker" posture as the work queue (ADR-210.1) — and `leader_leases.token` is
the ORM's **version counter**, so every update carries `WHERE token = <the value this session
read>`: two replicas racing a free lease cannot both win, and the loser sees an unmatched
update rather than double-holding. Liveness is computed from `expires_at`, never stored, so a
SIGKILLed replica hands the lease on by simply not renewing it.

The scheduler is opt-in about it: `Scheduler.leader` is `None` unless a caller passes one (the
tick loop does, an explicit `--id` run does not). A scheduler *given* a lease is fail-closed:
it admits nothing until it holds one.

`arachne.resil.migrations` inspects the head migration's source and reports every operation a
rolling upgrade would not survive (drop/rename/type-narrow/`nullable=False`/opaque `execute`).
The S25 migration is expand-only by construction — nullable columns and new tables, nothing
dropped — so the old replica keeps running while the new one rolls out, which is what a
zero-downtime upgrade means. A contract phase (dropping the pre-S25 compatibility) is a later
release's job, once no replica runs the old code.

## 300.7 Decision: residency is a column, and the refusal is a scope refusal

`ARACHNE_REGION` declares the deployment's region; `projects.residency_region` pins a tenant's
evidence; `evidences.region` stamps every row written. A read or presign from a deployment
that does not serve the row's region is refused with `ResidencyError`, which subclasses
`OutOfScopeError` on purpose: a residency refusal *is* a scope refusal, so it maps to the same
403 at the API boundary rather than to a new status code, and it composes with the existing
scope gate instead of sitting beside it. Both region values being set is required for the check
to bite; `None` on either side is "not pinned", which is the pre-S25 behaviour.

## 300.8 Decision: PII masking is applied at capture, never at render

`core.pii` detects six categories with the validators that make a pattern a finding (Luhn for a
card, mod-97 for an IBAN, SSN area rules, an octet-range check for an IPv4, and "the national
phone form must be grouped and consistently punctuated"), and applies the project's policy
(`mask` / `hash` with a required salt / `drop`) inside `EvidenceService.stage` — *before* the
quota is checked, before anything is offloaded and before a row is written. Ordering is the
guarantee: a masked value cannot reach the database, an object store, a report, a log or an
audit line. Masking is irreversible on purpose; a deployment that could un-mask would have
kept the value.

The retention hook (`pii.retention_days`, REQ-DATA-001) belongs to the pruner, which re-masks
a row whose window has passed — the mechanism for "we decided to mask later than we started
scanning". Both paths audit **counts by category**, never a value.

## 300.9 Decision: the DR bundle is verified before it is used, and refuses a live target

`arachne.resil.backup` writes one directory: `database.json` (every table the schema owns,
encoded so datetimes round-trip), `evidence/` (the content-addressed object tree, each object
verified against its own name before it is trusted), `keys/` (the operator's *already
encrypted* sidecars), `config.json` (the non-secret settings) and a signed `manifest.json`.

Two refusals carry the honesty of the feature:

- The **config dump redacts secrets by name as well as by type**. `api.keys` holds
  `label:role:secret` strings rather than a `SecretStr`, so a walk that only knew about
  `SecretStr` would have written real API keys into every backup. Finding F8 in the security
  review; `redacted_config` now replaces a secret-named field with `{"set": true}`.
- **An S3-backed evidence store is not copied.** Its own lifecycle/replication is the right
  mechanism, and a half-copied bucket would be worse than a documented pointer. The bundle
  records the object keys and says so.

Restore inserts one table at a time in dependency order (computed from the foreign keys, not
taken from `MetaData.sorted_tables`, whose ordering let a child INSERT precede its parent), and
refuses a target that already holds the bundle's scans unless the operator says otherwise. The
RTO the restore actually took is measured and reported, so the documented number has evidence
behind it.

## 300.10 Alternatives considered

- **A public-key signature scheme** (ed25519/RSASSA via a bundled library) — rejected under
  the dependency-light constraint; see 300.5.
- **A coordination service (etcd/ZooKeeper) for leader election** — rejected: it is a second
  always-on component and a new failure mode, for one lease the database already provides.
- **Signing only the evidence payload digest** — rejected: a *deleted* row leaves no digest to
  check, which is why the seal exists.
- **Report-time PII masking** — rejected: the payload would already be in the database, the
  object store, the audit trail and the logs by then.
- **Blocking all sockets in air-gapped mode** — rejected: the scanner's purpose is to reach the
  customer's estate; the mode restricts *which* hosts, not whether any packet is sent.

## 300.11 Consequences

- Report schema stays **1.9**; catalogue and module versions are unchanged (S25 adds no
  checks). Migration **0011** is purely additive: four nullable columns on `audit_log`, one on
  `findings`, two on `evidences`, two on `projects`, and four new tables
  (`integrity_anchors`, `integrity_seals`, `leader_leases`, `content_packs`).
- Audit schema goes **1.1 → 1.2** (the four chain fields), and every sink records the same
  chained event.
- `SqlAuditChain` replaces `SqlAuditSink` as the durable audit sink in the composition root;
  `SqlAuditSink` remains for callers that want an unchained row (and for the pre-S25 tests).
- A deployment with no `ARACHNE_INTEGRITY_KEY` still chains and still detects an edit, but
  `verify-chain` says "unsigned" and `--require-signatures` refuses. Absence is a refusal, not
  a pass.
