# ADR-280: Stage 23 — Continuous exposure management

Date: 2026-10-31 · Status: accepted · Supersedes: none · Decisions: 280.1–280.9

## Context

Phase 5's first work package (REQ-POSTURE-001…006) turns ARACHNE from a point-in-time
scanner into a continuous one: cloud-config drift on schedules, pre-deploy IaC/CI
gating, a fix-verification loop, estate baselines with executive drift/trend reporting,
a Kubernetes admission mode, and an optional CMDB criticality feed. Hard rules: the
continuous mode obeys the same scope/proof gates and cost guardrails; cloud control
planes are read-only; nothing enforces by default. Risk R-13 (continuous-mode cost
explosion) and R-15 (admission enforce blocking legitimate deploys) are the named risks.

## Decisions

### 280.1 — State, baseline, drift as a pure core (`arachne.posture.state`)

Snapshots are normalized once (the normalized export is canonical; the AWS
`DescribeSecurityGroups` / Azure `List` / GCP `aggregatedList` read-only response shapes
parse directly), resource identity is `(provider, service, id)`, and change detection is
a config **hash** — reordering never fakes a change, re-serialization never hides one.
Deltas always carry `before`/`after` and the changed key names. The store layer only
persists what the pure diff computed.

### 280.2 — The baseline capability is a per-asset access object (`PostureAccess`)

Like `ctx.proof` (S15) and `ctx.evidence` (S20), the check gets a capability boundary,
not the store: one scope key (the asset's own value), a read verb, and one write verb —
`observe(snapshot)`, which diffs against the last baseline and then commits. The first
observation commits silently (an estate appearing wholesale is a baseline, not drift);
every later observation diffs first, then replaces. Commits are audited
(`posture.baseline_saved`, `posture.drift`). A step without the wiring degrades to
stateless with a recorded note — a plain scan never invents a baseline.

### 280.3 — The check is `m5.cloud-posture` (default-on, active, one GET per path)

Point-in-time policy findings and drift deltas share one check and one schema; policies
are corpus data (`posture.policies` — id, severity, config key, breaching value,
optional service family). The check is default-on because with no declared snapshot
endpoint it does nothing but report itself skipped; `runs_on_discovered` stays False so
only declared surfaces are watched. M5 1.0.0 → 1.1.0; catalogue 1.8 → 1.9 (142 checks).

### 280.4 — The pre-deploy gate *is* a scan (`arachne iac-gate`)

Rather than a second, thinner scanner, the gate runs the real orchestrator over a local
`repo:` reference (offline by construction) and reuses the F-07-05 exit-code policy
(0/1/2). The operator's invocation stands as the attestation ("local pre-deploy review;
no network requests"), recorded like any other — which keeps "every live scan carries an
attestation" true without a ceremony. The structured Kubernetes policy evaluation lives
in `posture.iac` and is shared with admission, so the gate's vocabulary and the
cluster's cannot drift apart. `m5.tfstate-exposure` 1.0 → 1.1 gains the structured
manifest pass beside its regex review.

### 280.5 — Posture artifacts are unmergeable, like proof artifacts

The analyzer's dedupe folds candidates sharing `(cwe, asset)` — but a drift delta names
*one resource* with its before/after, and folding it into a point-in-time owner would
erase exactly the evidence the requirement asks for. `_carries_posture_artifact`
extends the S15 proof-artifact exemption (ADR-200.5) to the `cloud-config-drift` and
`cloud-posture` signals. No existing ground-truth score changed.

### 280.6 — The fix loop is a service over the stored request (`posture.verify`)

Verification re-runs the original scan's *stored* request (`scans.request_json`, S16)
bounded to the affected check by the exact allowlist, through `Orchestrator.scan` —
every gate re-checked. Close on verified absence (status `closed`), keep open with the
act recorded otherwise, reopen on regression when a scan of the same target reports the
same `(check, asset)` again. Reconciliation runs after every scheduled scan (scheduler
hook) and on demand (`arachne posture reconcile`); a verification scan can never reopen
what it just closed. Every act writes `posture_verifications` and links evidence to the
**original** finding.

### 280.7 — Budgets are audited refusals in the scheduler (risk R-13)

`ScheduleSpec` gains `continuous` and an optional `budget` (runs per rolling 24h,
estimated requests per run); a continuous schedule without its own budget inherits the
deployment defaults. The refusal (`schedule.budget_refused`, outcome blocked) is a trail
event, and the run history feeding the window count lives in the scheduler state
document (`run_times`, pruned) and survives status updates.

### 280.8 — Admission: evaluate/decide separated, monitor structural

`posture.iac` only ever reports violations; `posture.admission` decides. Monitor — the
shipped default — allows everything and names the findings; enforce denies only inside
the staged namespace list at/above the configured severity (an empty list denies
nothing, unit-pinned); off refuses loudly. The route audits every review
(`admission.reviewed`) and fails open on evaluation errors (cluster availability
outranks ARACHNE's opinion, risk R-15), with the failure audited. `arachne posture
admission-check` rehearses the same decision locally for the staged rollout.

### 280.9 — Criticality ranks paths; it never re-scores findings

The CMDB import (`arachne posture cmdb import`, CSV/JSON, fail-closed on malformed
rows) fills `asset_criticality`; `build_attack_paths` takes the index and applies a
business floor (tier 1 ⇒ high, tier 2 ⇒ medium) to path *ranking and labelling* only.
Report schema 1.7 → 1.8 adds two optional fields; a report without an import is
byte-identical to its pre-S23 form (golden-pinned both ways).

## Consequences

- Migration 0009 adds three tables, purely additive; no existing table changes.
- The checks/c catalogue count assertions move 141 → 142 (registry, catalogue,
  proof-model L1 set 135 → 136).
- The estate trend report (`posture.trend`) is computed from stored rows only — it never
  re-scans — so its golden file is stable by construction.
- Provider authentication beyond a bearer token (e.g. AWS SigV4 for arbitrary read
  APIs) is not implemented; the operator's read-only collector endpoint or the lab path
  covers the acceptance surface, and unrecognised snapshot shapes are refused.
