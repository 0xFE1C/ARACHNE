# 260 — Agentic reasoning, attack paths & self-improvement (S21, areas AGENT and QUAL)

**Status:** accepted · **Date:** 2026-10-30 · **Stage:** S21 · **Requirements:** REQ-AGENT-001...007,
REQ-QUAL-001...005

## 260.1 What this stage is for

Every stage before this one made ARACHNE *see* more: a proof ladder that proves exploitability
(S15), a fleet that scales (S16), identity (S17), live intel (S18), credentials (S19), a data
lifecycle (S20). S21 is the first stage that makes it *think* — and the first that has to answer
the question the whole program has been building towards: what stops a reasoning engine from
becoming an offensive one?

Two capability areas, one loop:

* **AGENT** — a hypothesis engine in dual mode that proposes and runs additional checks under a
  per-scan budget (REQ-AGENT-001/002), composed attack paths from verified findings
  (REQ-AGENT-003), feed-driven check synthesis that never auto-deploys (REQ-AGENT-004), the
  autonomy boundaries as *code* (REQ-AGENT-005/006), and an operator kill switch (REQ-AGENT-007).
* **QUAL** — the FP workflow that makes quality a process rather than a promise
  (REQ-QUAL-001...004) and a benchmark harness that proves the detection claims
  (REQ-QUAL-005).

## 260.2 The cage: five structural boundaries

REQ-AGENT-005 is a P0 hard rule, so it is implemented as five properties of the data model and
the call graph rather than as a list of checks in one function. Each boundary is one sentence,
and each sentence is a test in `tests/test_agentic_safety.py`.

1. **A hypothesis is a proposal to run a catalogued check, never an action.** It names a check id
   and an asset — no URL, no payload, no request. A model that names a check that does not exist
   produces a *refused decision* (`unknown-check`), because the only thing that turns a check id
   into work is the registry, and the registry is reached through the executor's gate.
2. **The agent cannot introduce a target.** The asset a proposal names must be an asset the scan
   already recorded, and the scope is re-checked anyway (`unknown-asset` then `out-of-scope`).
   This is what "no out-of-scope request" means structurally: there is no code path from a
   proposal's string to a request that has not been through `Scope`.
3. **Proof escalation needs the operator.** An L2+ proposal is refused unless the check id is in
   `options.proof_approved`; an L3/L4 proposal additionally needs the attestation's
   state-change authorization. Both are values on the *scan request*, not on the model's output —
   an AI cannot mint, extend or borrow an attestation because nothing in the agentic path accepts
   one.
4. **The budget is per scan and can only move down.** `HypothesisBudget.spend` raises when a
   spend does not fit, and a proposal that does not fit is recorded as *deferred*. A storm of
   twelve proposals under a two-hypothesis budget leaves two executed and ten deferred, all
   visible.
5. **Gate logic is ours, not the model's.** The proof level written into the journal is the
   catalogue's; the definition, the attestation and the module selection are the scan request's.
   A model's rationale cannot change any of them, however it is worded — and
   `test_ai_output_cannot_change_the_definition_or_the_proof_level` asserts exactly that.

The prompt-injection case (REQ-AGENT-006) is the same five boundaries seen from the attacker's
side. Target-derived content reaches the reasoning layer only in the *untrusted* half of the
prompt payload (`StageInput.target_data`, wrapped and delimited by the prompt store, S9's
mechanism), and the output it produces is a proposal that must pass all five boundaries. The
stage before that is grey on purpose: nothing tries to *prevent* injection by pattern matching,
because a boundary that depends on recognising hostile text is not a boundary. Detection
(`reasoning/injection.py`) exists to *record* the attempt (`hypothesis.injection_suspected`) and
to give the adversarial tests a signal that is independent of the outcome.

## 260.3 Dual mode and the degradation chain

The heuristic half is not a stub: it derives hypotheses from two deterministic sources the
analyzer already produces — the rule corpus (a rule whose family produced a finding but whose
sibling check never ran) and the correlation output (a group's next hop) — plus re-confirmation
of findings the analyzer is unsure about. It is a pure function of
`HypothesisInput`, so the same input yields the same proposals, which is what makes replay
meaningful.

The AI half is one new stage (`hypothesize`) in the S9 stage machinery: versioned prompt,
JSON schema, ledger, retries, cache, circuit breaker. It sees the *closed list of check ids* as
trusted context and the findings/groups/observations as untrusted target data. A stage that
cannot be attempted (no provider, no budget) or that fails returns a fallback marker, and the
reasoner falls back to the heuristic engine — the same "AI failure degrades quality, never
safety" contract as the analyzer.

Mode semantics are deliberately strict, so the adversarial tests can say "the model proposed
exactly this":

* `heuristic` — never calls a model;
* `ai` — the model's proposals, with heuristic fallback only on failure;
* `hybrid` — both, merged, model proposals first.

## 260.4 Every decision is recorded, and replay needs nothing

`scans.stats["hypotheses"]` holds a versioned journal: the input's hash, the proposals, one
decision per proposal (outcome, reason code, probes, produced findings, engine, fallback) and the
budget. `arachne reason replay` re-derives the run *offline*: it recomputes the input hash from
the recorded input document, checks that every decision corresponds to its proposal, and re-runs
the heuristic engine to confirm the proposals are reproducible. A tampered hash or a mismatched
decision is a failure, which is what makes the record trustworthy rather than merely present.

The append-only property matters for resumption (REQ-AGENT-007): decisions are persisted after
each proposal, and an existing journal is always *continued* rather than re-derived. Re-deriving
on resume would reset the cursor and the budget — executing a probe adds findings, so the input
genuinely changes mid-run; the journal's hash identifies what the run *started* from, and the
step notes that in the journal when it detects the drift.

## 260.5 Attack paths: honest by construction

`analyzer/paths.py` composes chains from **verified** findings only (verdict `analyzed`,
confidence at or above the threshold, evidence attached). Anything else is a *candidate* hop that
names the check which would verify it — the requirement's own wording, and the reason a path can
say "this chain is proven" or "this chain has an unproven link" without hedging.

Hops have a stage (exposure → credentials → access → execution → impact) derived from the
weakness class, falling back to the severity; a path is a strictly increasing sequence on one
*host* (a URL's hostname, so two findings on different paths of one application are steps of one
chain). The path's severity is the **terminal** hop's — what the chain achieves, not its worst
step. The cheapest breaking remediation is the hop whose fix costs least (its catalogued
remediation's step count), preferring an earlier, verified hop when the cost ties, because an
earlier fix removes every path through that point.

The report gains a numbered section (`## 9. Attack paths`, schema 1.6) with one block per path:
the chain, the terminal impact, every hop with its evidence refs and a verified/candidate marker,
and the cheapest break.

## 260.6 The quality workflow

Suppression and risk acceptance are deliberately different records, because conflating them is
how organisations lose track of their risk:

* a **suppression** says "this is not a finding" — versioned (one monotonic sequence), attributed
  and *commented* (a reason is required, minimum length, because a suppression without a reason
  is indistinguishable from hiding a finding). Re-scan diffs exclude suppressed *new* findings
  and state the count and the rule-set version explicitly (REQ-QUAL-002); a finding that was
  already known stays visible, because a rule did not fix it.
* a **risk acceptance** says "this is real and we own it until *date*" — owner, justification and
  expiry are all mandatory, and `reopen_expired()` re-opens the finding on the injected clock
  (REQ-QUAL-003). It is a pure decision the store applies, so the expiry test does not depend on a
  background job being on.

The FP tuner's marks (S5) are already the tuning dataset; S21 adds the *process* view on top of
it — per-check daily FP-rate trends with an alert when the recent window rises above the baseline
by more than a threshold (REQ-QUAL-004), computed from the same `fp_feedback` rows.

Both records are reachable from the API and the interface (REQ-QUAL-001): `POST/DELETE
/suppressions`, `POST/DELETE /acceptances`, `POST /acceptances/expire`, the `/ui/quality` page
with its forms, and a "mark false positive" action on a finding that writes the same
`fp_feedback` key the API writes (ADR-02: one learner).

## 260.7 The benchmark harness and what CI actually gates

`quality/benchmark.py` scores stored candidates against a versioned suite of cases
(`templates/benchmark/suites/*.yaml`): a `tp` case is a marker that must appear in a check's
evidence, an `fp` case is a hardened counterpart that must not be reported. Scoring is the
benchmark convention — only the suite's cases count, and a finding on a path the suite does not
describe is reported as *unscored* rather than being folded into the FP rate, because that would
measure the suite's exhaustiveness instead of the scanner's precision.

Results are version-committed under `benchmarks/<suite>/baseline.json`; `compare()` gates on
a detection drop or an FP-rate rise beyond a tolerance, and refuses to compare across suite
versions. The CI job (`benchmark`, `.github/workflows/ci.yml`) runs
`python -m arachne.tools.benchmark --gate --lab`, which measures the in-repo ground-truth lab and
compares it against the committed baseline.

**Deviation, recorded:** only the in-repo lab suite is *runnable* here. The three named targets
(OWASP Benchmark, Juice Shop, DVWA) ship as suites with `source: recorded` and
`required: false`, and their baselines are committed once an operator runs them against the
hosted target (`--suite X --target URL --write-baseline`; the exact command is in each suite
file). Until then the gate verifies what a recorded result can still prove — its internal
arithmetic — and reports the absence as a note rather than a failure. A recorded result that
flatters the scanner (a hand-edited detection rate) fails `consistency_problems`.

## 260.8 Decisions worth recording

1. **The hypothesis step is opt-in and outside the default pipeline.** `ScanStep.HYPOTHESIS` is
   appended by the orchestrator only when a scan (or the deployment) enables a mode, so a
   pre-S21 scan's step list is byte-for-byte unchanged, and no default scan gains a request or an
   audit line.
2. **`ModuleSelection.only` is an exact allowlist**, distinct from the S7 `checks` list which
   *adds*. Conflating them would let one hypothesis quietly run a whole module; the new
   `check-not-allowlisted` skip code makes the difference visible in every plan.
3. **`options.proof_approved` does not name a check for the main plan.** It authorizes a
   *proposal*; the proposal's own subset plan names it and still passes the proof gate. Naming it
   for the main plan would widen what an admitted scan does — the opposite of the point.
4. **The kill switch is a file**, both sides reachable (`ARACHNE_HYPOTHESIS_CONTROL`, default
   `.arachne/hypothesis-control.json`): a scan may be running on another node in another process.
   A pause/abort applies to one run and is cleared by the resume; `--all` sets a deployment-wide
   stop a resume does not clear.
5. **A probe runs through the same check engine as the checks step** (`run_checks`), with a
   one-check allowlist and a re-crawl when the probe needs the web surface. There is no second
   execution path.
6. **Attack paths group by host, not by URL.** Anything else makes a chain of findings on one
   application invisible, which is the case the feature exists for.
7. **Report schema 1.5 → 1.6** adds the `attack_paths` block; the reported diff gains
   `suppressed`/`suppression_version`; markdown section numbering shifted (`Attack paths` is 9,
   low-confidence 10, patch-gap 11, appendix 12).
8. **Migration 0008 is purely additive** (`suppressions`, `risk_acceptances`).
9. **Audit retention and the quality records interact**: a suppression or an acceptance is a
   *decision*, and the audit trail keeps `suppression.changed`/`acceptance.changed`/expired lines
   under the deployment's audit retention (S20's note stands: per-tenant audit retention needs an
   attribution decision first).
10. **`tools/benchmark.py` loads the lab dynamically.** A shipped tool must not depend statically
    on the test suite, so `--lab` uses `importlib` and reports one clear error when the
    repository's lab is not present.

## 260.9 What this stage deliberately does not do

* No autonomous change to a target: hypotheses run checks; checks obey the proof ladder; L3/L4
  needs the operator's approval *and* the attestation.
* No auto-deployment of synthesized checks: the synthesizer can only write files, refuses the
  live catalogue directory, and requires a passing parity result plus a named reviewer before a
  proposal is marked approved. A human merges the row and implements the check.
* No suppression of a *known* finding in a diff: only new findings are filtered, so a rule can
  never look like a fix.
* No "learn from the model": trend alerts and tuning thresholds come from operator decisions, not
  from AI output.
