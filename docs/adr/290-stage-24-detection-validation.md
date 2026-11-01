# ADR-290 — Stage 24: detection validation (purple team)

**Status:** accepted (S24, area VALID — REQ-VALID-001...006)
**Context:** `historical` spec paths: `docs/02-system-requirements.md` area VALID,
`docs/03-delivery-plan.md` §7 (G5) (`historical`),
`docs/04-verification-and-acceptance.md` §2 (`historical`)

## 290.1 The problem

ARACHNE can prove an attack is *possible* (the S15 proof ladder, L1–L4). The question an
enterprise actually cannot answer is the next one: **would our defenses have seen it?** A
proof finding says "this worked"; it says nothing about whether anybody noticed.

Purple-team exercises answer it, but they are the one security activity where the usual
instincts are inverted. Stealth is the *opposite* of the goal: the test exists to be
detected, and a test that cannot be distinguished from an attack is an attack. So the
design constraint is not "make it powerful" but "make it visible, bounded and honestly
measured".

## 290.2 Decisions

### 290.2.1 The detection window is an attestation class, not a parameter

The window lives on `AuthorizationAttestation.detection_window` (a `DetectionWindow`:
`starts_at`, `ends_at`, `coordinator`, optional `defender`/`reference`/`notes`). Three
consequences, each deliberate:

1. **A window must sit inside its own authorization** (validated on the model: it may not
   start before `attested_at` nor end after `expires_at`). A detection test cannot outlive
   the grant it rests on.
2. **Purple mode without a window is refused at the authorization gate**
   (`TargetDefinition.authorization_errors(purple=True)` → `auth.rejected`). There is no
   "untimed purple team" flag: the authorization class *is* the feature.
3. **The window is a boundary, re-checked at plan, execute and resume**, and enforced
   *during* the run (the checks step stops itself when it closes). Refusals are audited
   (`purple.window_refused`), the auto-stop once (`purple.window_closed`), and a refused
   plan creates no scan row and sends nothing.

`ScanOptions.purple` is a `PurpleRunOptions` (campaign, exact action list, optional nonce),
and `ScanOptions` refuses purple mode without `active_checks=True` — the operator's own
opt-in is one of the two switches of F-01-09 and cannot be implied by an attestation.

### 290.2.2 Replay is selection, not new checks

Purple mode replays the **existing** proof actions; it adds no offensive capability. The
campaign's action list goes through `ModuleSelection.only` (the exact allowlist primitive
S21 introduced), so a purple run executes precisely what the defender agreed to watch for
and nothing else.

What the actions *are* — which technique each exercises and what telemetry each produces —
is shipped data (`templates/purple/attck-map.yaml`). The map is cross-checked against the
module catalogue at plan time: an action claiming a proof level the catalogue does not
declare is refused, and an unknown action is refused rather than dropped. The map cannot lie
about the ladder.

### 290.2.3 The run nonce is the visible tag, and it comes from the proof layer

REQ-VALID-003 wants every emitted artifact visibly nonce-tagged. Rather than invent a second
tagging mechanism, `ProofAccess` gained an optional `run_nonce` (S24, additive): when set,
the marker text, the out-of-band token and the L3 payload all carry it verbatim. The
propagation points are `CallbackService.issue(..., nonce=...)` and
`CommandProof(..., nonce=...)`, both validated against the same alphabet, so a caller cannot
smuggle a payload-shaped "nonce". Default behaviour is unchanged (a fresh random tag per
artifact), which is why every S15 test still passes unmodified.

Findings the run emits additionally get a `purple` evidence entry (technique, tactic,
campaign, nonce, window) — the tag on the *artifact* rather than only in the traffic.

### 290.2.4 Coverage counts only what is provably this run

An emission is *seen* when an alert names a matching technique **and** carries the run's
nonce **and** falls inside the window. Everything else is reported in its own bucket rather
than folded into the number:

| Alert | Read as |
|---|---|
| technique + nonce + in window | seen |
| technique, wrong/absent nonce | unlinked |
| technique, outside the window | out of window |
| a technique nothing emitted | other techniques |
| no ATT&CK technique | without a technique |

A nonce is read only from explicit shapes (a nonce field, an ARACHNE callback token, a
`nonce=value` pair). A bare hex string in prose is never attributed: it could be a file
hash, and treating it as a nonce would be a false claim of validation. Technique matching
follows one rule, stated once: same id, or parent-and-sub-technique either way, but never
two siblings.

### 290.2.5 Sigma alignment is an evaluation, not an assertion

Each action's declared telemetry is fed to the same matcher M6 uses on ingested logs
(`match_event`), and the verdict is rule-hit/rule-miss against whatever library the
deployment has. The shipped library is small (six rules), so the report is expected to show
misses — `m3.state-marker` (T1565.001, stored data manipulation) is the demonstrated one,
and `REQ-VALID-004`'s acceptance test is exactly that miss. The alternative (curating the
map so everything hits) would have made the alignment decorative.

### 290.2.6 The defender report distinguishes "unseen" from "untested"

`report.py` annotates every attack-path hop with the technique its check exercises and a
verdict: *seen*, *unseen*, *untested* (a technique in the map that this campaign did not
run) or *unmapped* (a check with no technique at all). Only *unseen* counts towards "what an
attacker could do unseen". Blurring untested into unseen would be the easiest way to make a
defender report impressive and useless.

### 290.2.7 Coverage is rewritable; the trend is the campaign's

`purple_runs.coverage_json` is updated in place by `score`, because a defender's SIEM
reports *after* the window closes. Trends are per campaign (`purple_campaigns`), and a
technique seen in the previous run and unseen now is a regression
(`purple.coverage_regressed`). The scheduler reuses all of this: a schedule with
`purple_campaign` set delegates to the campaign service, so budgets, run history and the
window gate all apply, and a refused run is recorded rather than swallowed.

### 290.2.8 Report schema 1.8 → 1.9, catalogue unchanged

The scan report gains an optional `detection_validation` block (campaign, nonce, window,
per-action technique/tactic/Sigma verdict, rule-miss list) rendered as appendix I. It is
optional, so an ordinary scan's report is byte-identical to its pre-S24 form — golden-pinned
in both directions. No check is added or changed, so no module version, catalogue version or
check count moves.

### 290.2.9 Migration 0010 is purely additive

`purple_campaigns`, `purple_runs`, `purple_alerts`. A deployment that never configures
purple mode behaves exactly as it did at S23. `purple_runs.scan_id` is `SET NULL` on delete,
so pruning a scan never orphans the trend.

## 290.3 Alternatives considered

* **A fifth proof level ("detection proof")** — rejected: detection is not a *deeper* proof
  of exploitability, it is a different question about the same evidence. The window belongs
  on the attestation, not on the ladder.
* **Nonce tagging in a separate purple-only payload layer** — rejected: it would have meant
  two tagging mechanisms, and the S15 payloads are what actually reaches the target. The
  `run_nonce` seam is smaller and provably carries into the traffic.
* **Treating any technique-named alert as coverage** — rejected: it flatters the number with
  evidence that does not say what the report claims. The unlinked bucket exists precisely so
  the honest reading is available.
* **Re-scoring by re-running the scan after the alerts arrive** — rejected: the test fired
  once, at a moment; replaying it to make the numbers line up would be dishonest and would
  fire inside a window that has closed.

## 290.4 Consequences

* A purple run is a normal scan through every existing gate; nothing new can widen scope,
  authorization or proof.
* The purple package stays free of the data layer (`purple/__init__.py` documents it), so
  the window, coverage and telemetry rules are testable as pure functions.
* The rate limiter, the scope gate and the audit trail apply to purple traffic unchanged; the
  safety tests observe that rather than assert it structurally.
* Operationally: the runbook is `docs/operator-guide.md` §33, and the residual risk
  (ARACHNE authenticates the forwarder, not the alert's provenance) is recorded in
  `docs/security-review.md` §16.
