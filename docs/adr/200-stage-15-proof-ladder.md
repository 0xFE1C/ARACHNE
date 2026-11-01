# ADR-200 — S15: the proof ladder & safe PoC engine

Status: accepted (S15, program Phase 1)

This stage gives ARACHNE the ability to say *"an attacker could have done X — here is the
proof"* while leaving the target untouched or exactly restored (`01-introduction.md`
§2.3). It implements capability area `PROOF` (REQ-PROOF-001…014) as the foundation every
later proof-adjacent capability composes with: credentialed scanning (S19), agentic
hypotheses (S21), purple-team validation (S24), depth (S29) and bounded fuzzing (S30) all
inherit this ladder.

---

## 200.1 — One enum, four walls, one default

`ProofLevel` (L0–L4) lives in `core/proof.py` as a pure model: no I/O, no services, one
place that knows the semantics. The walls around it are structural, not procedural:

* **Construction.** `CheckMetadata.proof` + `requires_state_attestation` are validated in
  `__post_init__` (REQ-PROOF-001): an L2+ check that is not `enabled_by_default=False`, or
  an L3/L4 check without the attestation flag, cannot be constructed — and
  `dataclasses.replace` cannot produce one either. The registry re-validates
  (`ModuleGroup.__post_init__`) so even a hand-crafted metadata object that bypassed
  construction is fatal at registration (REQ-PROOF-002).
* **Planning.** The planner plans L3/L4 checks only when the operator *names* them
  (`skip_code "proof-not-opted-in"`) — planning is module-granular for L1 checks, but a
  state-changing proof is opted in per check, mirroring the runtime selection. The plan
  shows `proof` and `proof_effective`; the gap between them is always a downgrade, never
  an upgrade.
* **Orchestration.** `_assert_proof_gate` refuses a live scan whose plan carries L3/L4
  checks without `attestation.state_changes_authorized` (a new, default-False field on
  `AuthorizationAttestation` — deny-by-default composes with the existing attestation
  rather than adding a second authorization system). It runs at plan time and is
  re-checked at execute/resume against the stored plan; refusals are audited as
  `proof.rejected` (REQ-PROOF-003). A dry run prints the requirement (REQ-PROOF-004).
* **Capability boundary.** A check never touches the proof services directly: it gets
  `ctx.proof` (a `ProofAccess`) built from its own metadata, and every capability method
  (`oob_token`, `command_proof`, `sql`) refuses below the declared level — even a fully
  attested scan cannot upgrade a check (REQ-PROOF-011's enforcement point).

## 200.2 — Downgrade, never block; never upgrade

An L2 check without a configured callback service is *downgraded* to its in-band L1
behaviour with a recorded note — audited (`proof.downgraded`), printed in the plan
(`L1↓L2]`), and reported by the check itself as a skip that says why. Downgrade is the
only direction: `proof_effective <= proof` is a planner invariant with a named test. This
is what makes unavailability a quality problem, not a safety problem — and it is why the
shipped L2 variants are written so their in-band halves still work without the callback
service.

## 200.3 — OOB: the token is the authenticator

`arachne-<scan-id>-<check-id>-<nonce>` with a 96-bit random nonce. The service does **not**
pre-register tokens: the token shape is validated, the nonce is the authenticator, and
matching happens at consume time — exactly once (`proof.oob_replay` on a second consume).
This keeps the standalone `arachne callback-server` stateless across checks and makes
in-process tests use the same class. Each L2 sink gets its own token, so a hit names the
exact parameter that reached it (the Burp-Collaborator pattern). The service never dials
out — no outbound client exists; the no-fetch property is tested with the socket
constructor armed to explode. The callback host must be inside the scan's declared scope
because the check's token lookup goes through the scan's scoped client — OOB lookups get
no scope exemption.

## 200.4 — L4: write-ahead reversibility

State changes are persisted **before** they happen: `ProofLedger.record_state_change`
writes `restored=false` into the scan record's stats (`stats["proof"]`, the existing scan
store — no new table), then the helper writes, verifies, restores, re-verifies. A crash
between the write and its restore therefore leaves a durable `restored=false` row and a
derivable repair instruction (`proof.repair_required`, REQ-PROOF-010) even though the
crashing process wrote nothing. The end-of-step cleanup pass re-restores what any live
helper owns and reports orphans as repair instructions. Destructive SQL is refused at the
statement boundary (`sql_refusals`: DELETE/DROP/TRUNCATE/ALTER/GRANT/REVOKE/CREATE,
multi-statement, comments, quoted literals — statements are parameterized), and
identity-store tables are refused outright. The helper's *only* DELETE is the hard-coded
restore of its own marker row.

## 200.5 — Proofs survive the report's dedupe

The correlation engine's dedupe folds same-CWE/same-asset candidates into one owner. A
proof artifact is *distinct evidence of exploitability*, not a duplicate detection, so a
proof-bearing candidate is exempt from merging (`_carries_proof` in
`analyzer/correlation.py`) — its finding always reaches the report with its own Proof
section. The report gains `FindingProof` (level, method, cleanup) per finding and the
appendix-F state-changes table (what/where/before/after/restored) — report schema 1.2.

## 200.6 — The capability carriers

Six new opt-in checks in M3 carry the ladder's upper rungs: four L2 variants (blind SQLi,
XXE, blind command injection, template injection — the blind classes of REQ-PROOF-006)
plus `m3.rce-echo` (L3) and `m3.state-marker` (L4). All are `enabled_by_default=False` by
construction, all keep the heuristic engine fully functional (parity test: heuristic mode
never proposes escalation, REQ-PROOF-014), and the demo — `tests/integration/
test_proof_ladder.py` — scans the web lab L2→L4 with real callbacks and zero database
residue (gate G1's VM evidence).

## 200.7 — What this stage deliberately did not build

No shipped check modifies state outside the marker-row/one-shot-echo shapes; credentialed
L4 depth belongs to S19. The `arachne_poc` sink convention (`POST {origin}/poc-sql` with
`sql`/`params`) is a deployment contract documented in the operator guide, not a second
safety system: the ladder's policy lives in ARACHNE and the sink is the operator's own
surface. Hypothesis-driven proof selection (REQ-PROOF-014's first clause) arrives with the
AGENT area in S21, on top of the ceiling this stage enforces.
