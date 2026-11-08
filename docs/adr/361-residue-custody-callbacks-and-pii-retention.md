# ADR-361 · The residue attestation, evidence chain-of-custody, hardened callbacks, and a PII retention pass that exists

> **Owner:** ARACHNE architecture group · **Last verified:** 2026-11-05 · **Review interval:** 1825 days

| Field | Value |
|---|---|
| Status | accepted |
| Date | 2026-11-03 |
| Deciders | ARACHNE detection engineering, privacy owner, safety owner |
| Extends | ADR-250 (the audit chain and seals) with evidence custody; ADR-200 (the proof ladder) with its outcome; ADR-290 (the PII policy) with retention |
| Requirements | REQ-PROOF-017, REQ-PROOF-018, REQ-PROOF-019, REQ-DATA-005 |

## Context

Four gaps, one theme: a control that existed as machinery or as documentation rather than as
something an operator or an auditor could check.

1. **`INV-7` restored state and reported it, but the outcome was not an artefact.** The proof
   journal lived in `scans.stats.proof`, unsigned and unhashed. "Did this scan put everything
   back?" was answerable only by trusting the report the scanner wrote about itself.
2. **Evidence was redacted and stored, but a payload edited in place was invisible.** A row's
   signature covers its identity and payload digest, and the per-scan seal covers the manifest
   — both are checked only when a deployment **has** a key. On a keyless deployment nothing
   noticed an edit to `evidences.payload_json`.
3. **The OOB callback receiver accepted any well-formed token.** The 96-bit nonce *was* the
   authenticator, which means a token observed once could be replayed as a different scan's, a
   hit for a scan that no longer existed was matched, and there was no way to say "this token
   came from us" beyond "the nonce looks random".
4. **`ARACHNE_PII_RETENTION_DAYS` was documented and consumed nowhere.** `core/pii.py` said the
   retention pruner re-masked old evidence; `data/retention.py` had no re-mask code. A privacy
   control a customer reasonably believed was active was not — the most serious functional gap
   in the audit (`02-current-state.md` §4.6).

Gap 4 also hides a design problem that had to be solved before it could be implemented: a
re-mask **mutates a stored payload**, which is exactly what the tamper-evidence layer (ADR-250)
is built to detect. Implementing the privacy control naively would have made `verify-chain`
report every re-masked blob as tampering — two controls contradicting each other.

## Decision

**1. The residue attestation is a row value, signed or explicitly unsigned.**
Two nullable columns on `scans` (`residue_attestation`, `residue_hash`, migration `0016`) hold
one artefact per scan: the entries (asset, action, **hash** of the before-value, restore
outcome, timestamp), the verdict (`residue` count and `clean`), the statement and the
deployment signature when a key exists. It is built from the scan record's own proof journal in
the scan machine, for **every** terminal path — completed and failed — so a crash mid-scan
leaves a statement of what was left behind rather than nothing. Its hash is recorded as a
`proof.residue_attested` chain line, and non-zero residue is that line's `error` outcome. The
report reads the artefact from the row (never re-deriving it) and shows a warning; a scan with
no attestation is rendered as "not recorded", never as clean.

*Rejected:* putting it in `stats` only. It would satisfy the report, but the requirement asks
for an artefact a third party can check, and `residue_hash` as a queryable column is what lets a
later verifier or an API consumer name the thing it checked.

**2. Evidence custody is a chain line, not a column.**
At capture, `SqlFindingStore` records one `evidence.captured` line per stored blob carrying
`payload_digest(stored payload)` — the **redacted** bytes, because a digest of the pre-redaction
payload could never be recomputed. `verify-chain` walks those lines and recomputes the stored
digest, reporting `[evidence.mismatch]` naming the evidence id on an edit and
`[evidence.deleted]` when a recorded blob is gone while its scan survives. A blob whose scan was
pruned by retention is a **note**: policy, not tampering — the same distinction the seal
verifier already makes.

*Rejected:* (a) writing the digest into `evidences.sha256`. That column feeds the analyzer's
evidence dedup key `(kind, sha256, source)`; populating it for inline rows that had `None` would
split previously-merged evidence facts — a behaviour change in the analysis pipeline, for no
gain over a chain line. (b) Recording one line per *batch*. One event per blob is what makes
"which blob, when" answerable, and it is what the audit trail is for.

**3. The chain's latest statement about a blob wins.**
`evidence_hash_records` applies `evidence.captured` and `pii.remasked` in chain order, last one
wins. This is the composition decision that lets gap 4 be implemented at all: an authorized
mutation records its own line with the new digest, so the custody record follows the change
instead of contradicting it. A verifier that compared against the *first* record would report
every re-masked blob as tampered.

**4. The per-scan callback secret is derived from the deployment key.**
`per_scan_secret(signer, scan_id)` is `HMAC(deployment key, "arachne.oob" + scan_id)`. The
scanner (issuing in-process, or minting in `ProofAccess` for a standalone listener) and the
callback service (a different process) derive the same secret without it ever travelling. The
token carries a 16-hex authenticator after a `~` separator; the receiver requires it when it can
obtain a secret for the scan, refuses one it cannot verify (fail-closed), and records replays and
refusals as audit lines. A **keyless** deployment has no secret to derive: the nonce remains the
authenticator, exactly as before, and this is stated rather than papered over.

*Rejected:* (a) a random per-scan secret stored on the scan row. It would have to travel to the
receiver, and a secret in the same database the receiver reads is not a secret between those
parties. (b) A MAC appended to the nonce. Check ids contain dots (`m3.sqli-oob`) and a purple run
supplies the nonce verbatim (REQ-VALID-003), so a `~`-separated segment is the only shape that
keeps both properties.

**5. The re-mask is inline-only, and the limit is reported.**
The pruner selects evidence older than the window, scoped to the project and excluding rows the
same run will delete, and masks the payload under the **project's** policy. Offloaded payloads are
**not** re-masked: their bytes live in an object store, rewriting them would mint a new
content-addressed key and orphan the old object (reference counting is REQ-DATA-006), and a
partial control that says so is honest where a partial control that stays silent is
not. They are reported in the plan and in one `pii.remask_unsupported` line per run. A legal
hold freezes the re-mask with the deletion.

**6. The re-mask re-signs and re-seals.**
After masking, affected rows are re-signed and their scans re-sealed (`reason="pii-remask"`),
and each blob's `pii.remasked` line carries its new digest. `verify-chain` therefore stays green
after a re-mask: the mutation is authorized, recorded, and described by the artefacts that
claim to describe it. A refresh failure is logged, never raised — the privacy control has
already happened, and the chain will then report the blob, which is the honest outcome.

## Consequences

- A scan's residue is now a signed claim with a repair list, and a non-clean scan cannot be read
  as clean by any renderer or API consumer that checks the artefact.
- An evidence payload edited behind the store's back is detected with no deployment key at all.
- A forged callback for a scan a deployment has a key for cannot be minted from a leaked nonce.
- PII retention is implemented for the default (inline) store and *states* its limit for object
  stores; the doc test keeps the operator guide and the code in step.
- **Costs:** one audit line per evidence blob at capture (bounded by the number of findings), one
  per re-masked blob, and one re-seal per affected scan per pruning run. Two nullable columns on
  `scans`. The report schema moves to 1.13 (additive; every golden changed by one version line).
- **Not done here, deliberately:** re-masking object-store blobs (reference counting),
  and the web UI's Residue section (spec `06-ui-ux.md` §4.6) — the API field it reads
  (`GET /api/v1/scans/{id}` → `residue_attestation`) exists as of this ADR.
