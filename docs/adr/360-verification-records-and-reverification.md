# ADR-360 · Verification records as a persisted artefact, re-verification that cannot escalate, and a shared differential oracle

> **Owner:** ARACHNE architecture group · **Last verified:** 2026-11-05 · **Review interval:** 1825 days

| Field | Value |
|---|---|
| Status | accepted |
| Date | 2026-11-03 |
| Deciders | ARACHNE detection engineering, safety owner |
| Extends | ADR-200 (the proof ladder) with its persisted record; ADR-250 (the audit chain); ADR-110 (false-positive discipline) |
| Requirements | REQ-PROOF-015, REQ-PROOF-016, REQ-PROOF-020 |

## Context

The proof ladder (ADR-200) decides **how far** a check may go, and the L2/L3/L4 helpers record
what they did — but the *record of an act* was not a first-class artefact. It existed only as a
`proof` evidence payload a reader had to reconstruct, so a finding could not be asked "how was
this established, with which version of which check, and can it be re-established?". Three
consequences, in increasing order of severity:

1. **A proof that cannot be re-run is a claim.** Nothing in the product could answer "is this
   still true?" — the operator's only option was another full scan of the whole target.
2. **A finding without a record could not be told apart from a proven one.** The report had no
   required field to distinguish them.
3. **Nine injection families each carried their own answer to "did my input change the
   response?"** — five boolean thresholds, two count-based rules, a content-marker rule, a
   timing rule and a regex-only rule. Divergence between them is a silent false-positive source,
   and the divergence was invisible because each answer lived in its own file.

## Decision

**1. The verification record is a row, and the finding points at its current one.**
`finding_verifications` holds the record type from `05-detection-program.md` §3.3 — level,
method, observations, reproducibility token, `verified_at`, check version — plus the
re-verification fields (`status`, `outcome`, `parent_id`, `scan_id`). `findings.verification_id`
is the **one nullable column plus an index** the migration adds; it is a logical reference
rather than a database foreign key, because the reverse edge
(`finding_verifications.finding_id`, `ON DELETE CASCADE`) already carries the lifecycle and a
mutual constraint would force SQLite to rebuild `findings` for an otherwise additive
`ALTER TABLE ADD COLUMN`. The store writes the record in the same transaction as the finding it
belongs to, and derives it from the check's own `CheckResult` — the function's signature *is* the
AI guard (PD-8): an analysis is not a `CheckResult`, so no AI contribution can reach it.

**2. A finding with no record is downgraded, not distrusted wholesale.**
Report schema **1.12** makes `verification` required. `ReportFinding` enforces the rest at the
model: a finding that arrives without a record is marked `unverified` and forced to `info`,
whether it was built by the builder, constructed by hand in a test, or loaded from a document.
The rule is deliberately fail-safe — a lost record costs severity, never credibility — and it is
enforced in an `after` validator so an *invalid* severity remains a validation error rather than
being silently rewritten.

**3. Re-verification is a gated, targeted re-scan that can never escalate.**
`arachne verify-finding <id>` reads the admitted request the original scan stored, runs the
orchestrator's own `assert_in_scope` and `assert_authorized` **before constructing any client**,
and then re-runs the finding's check and nothing else. Four outcomes: `still-verified`,
`no-longer-verified`, `inconclusive` (the check skipped, failed, or left no audit line — "we
could not re-run it" is not "it is gone"), and `refused` (nothing was re-checked; the CLI exits
non-zero). The level is bounded twice: the check's *declared* level is compared with the
recorded one before anything runs, and the store refuses to persist a record whose level exceeds
its parent's (PD-7). Both audit lines are written — one on the parent record, one on the new one,
each naming the other.

**4. One differential oracle, and a conformance kit that can fail.**
`modules/m3/oracle.py` owns the decision: `boolean` (a true/false predicate pair), `query` (a
probe against a baseline, discounting a pure reflection) and `marker` (a canary the baseline
does not carry). SQLi, XPath, NoSQL and the traversal/LFI families call it. A family may add a
*conjunct* (`extra`) to make its own verdict stricter, never looser.
`tests/unit/test_oracle_conformance.py` drives the same payload set and the same scripted
responses through four families, asserts they agree, asserts an always-200 decoy yields zero
positives in every one of them, and asserts that a deliberately looser implementation of the
oracle is reported as a divergence.

## Consequences

- **Every golden report changed**, as the delivery plan predicted: four `tests/report_qa/golden`
  files gained a *Verification* block and the schema-version line moved 1.11 → 1.12. The diff is
  additive (one new block per finding plus the version line) and was reviewed before blessing.
- **The rendered DTO field is `reproducibility`, not `reproducibility_token`.** The report QA gate
  scans every rendered document with `core.redaction.contains_secret`, which treats any
  `<key containing "token">: <value>` as a credential assignment; a field literally named
  `reproducibility_token` makes every report *look* like it leaked a secret. The persisted column
  and the data-layer record keep the full name; only the JSON the report emits shortens it. The
  same reasoning applies to the observation lines, which are rendered through a fixed vocabulary
  rather than a key/value dump.
- **A re-verification whose outcome is not `still-verified` writes an `unverified` record**, and
  the report therefore forces that finding to `info`. That is intended: a proof that no longer
  holds is an observation, and an operator who wants the old severity should re-establish it.
- **A redacted token falls back to a content digest.** `Evidence.of` masks a `callback_token`
  key, so the ladder's single-use token arrives at the record builder as `[REDACTED:value]`. The
  builder treats a placeholder as absent and derives `sha256:<digest over the observation set>`,
  which is genuinely reproducible; a `nonce` key is not treated as secret by the redactor and
  survives verbatim.
- **XPath's pair test is marginally stricter than it was.** It used to require only that the two
  halves differ at all (`min_ratio_drop=0.0`); through the shared oracle it now uses the oracle's
  0.05 floor as well as its own record-count conjunct. The direction is deliberate — a family may
  add a conjunct to the shared rule, never drop below it — and it can only make this family
  quieter, never louder.
- **The escaped-character and error-signature oracles did not move.** They are a signature match
  plus a "not identical to the baseline" guard, not a differential decision; folding them into
  the oracle would have changed what they prove.
- **No safety control was relaxed.** Scope, attestation, the proof ladder, the audit chain and
  redaction are untouched; the new command re-uses the first two rather than re-implementing
  them.

## Alternatives considered

- **A JSON column on `findings` instead of a table.** Rejected: re-verification history is a
  chain, and a column can hold one record — the deliverable's "parent reference" and
  REQ-PROOF-016's per-finding history both require rows.
- **Making `verification` optional with a schema `if/then` on severity.** Rejected: it moves the
  invariant into the consumer. A required field plus a model validator is one rule in one place.
- **Having `verify-finding` re-run the whole scan.** Rejected: it would spend requests on checks
  the finding did not come from, and make the verdict depend on unrelated drift.
- **Letting a re-verification raise the level when the check has grown a stronger proof.**
  Rejected outright (PD-7): it would turn "is this still true?" into "is this now provable more
  strongly?" — a different question, and one an operator must authorize on its own.
- **Renaming the persisted `reproducibility_token` column to match the DTO.** Rejected: the
  storage layer is never rendered, so the redaction-shaped name is only a problem where a text
  scanner reads it.
