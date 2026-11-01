# ADR-320 — Stage 28: simulation & what-if modeling (area SIM)

- **Status:** accepted (S28)
- **Requirements:** REQ-SIM-001...006
- **Phase/gate:** P7, gate G7 (`docs/03-delivery-plan.md` §9)
- **Supersedes:** nothing. **Extends:** ADR-05 (one HTTP egress path — this stage's guarantee is
  the mirror image of it), ADR-190 (attack-path composition, whose composer this stage reuses),
  ADR-160 (continuous exposure management, whose trend this stage feeds), ADR-200 (the proof
  ladder's audit and refusal conventions), ADR-310 (the "state the limitation in the module
  docstring and in the guide" convention this ADR repeats).

## 320.1 Context

Every capability built so far answers a question about the estate **as it is**: what is exposed,
what would a chain look like, is the fix verified, did the defender see the test. Phase 7's
second half adds the question a scanner category cannot answer at all — *what if?* — and the
requirement set that defines it is unusually specific about the danger:

- the model must be built **from scan data only** (nothing may be re-probed to fill gaps);
- the engine must be **structurally incapable** of network I/O, with violations failing closed;
- results must be **rendered distinctly** from verified findings and must **never** enter a finding
  store or a CI gate verdict;
- change simulation must produce before/after exposure deltas;
- continuous re-simulation must be event-driven and feed posture trends.

Read together, those are not five features but one property with five faces: **a simulation must
be impossible to mistake for an observation.** The design that follows is organised around that,
and the two most consequential decisions are negative ones — what the package may import, and
where its results may be read.

## 320.2 Decision: the zero-network guarantee is enforced statically *and* dynamically

The requirement's accept criterion is "the sim module cannot reach the network even if
misconfigured", and "even if misconfigured" is the hard half: ARACHNE does not own every
collaborator, cannot audit every dependency upgrade, and cannot see what a plugin does at
runtime. A single mechanism therefore cannot carry the guarantee, so there are two, and neither
trusts the other.

1. **Static (`sim/hygiene.py`).** The imports the package may not contain are *data*: the socket
   family, the HTTP clients, `asyncio`, `subprocess`, the process escape hatches, and every
   ARACHNE module that owns an egress or a store path. `violations_for_package()` scans the
   shipped tree with an AST walk, and `tests/test_sim_safety.py` runs it — so a future edit that
   adds `import httpx` to a simulation file fails CI rather than shipping. The rule ships in
   `src`, not in the test, because a deployment auditing its own build should be able to run the
   same check.
2. **Dynamic (`sim/boundary.py`).** `no_network(...)` wraps every public entry point. For its
   duration it replaces `socket.socket`, `create_connection`, `getaddrinfo`, `gethostbyname*`
   **and** the methods of already-constructed sockets with a guard that records a blocked
   `simulation.boundary_violation` audit event, raises `SimulationNetworkError`, and never
   completes the call. The `finally` restores every entry point exactly (the guard captures the
   real callables rather than re-importing them, so a nested guard restores the outer one).

The alternative considered and rejected was a taint/flow analysis of the package's data, or a
sentinel collaborator injected into the engine. Both are weaker: the engine has few collaborators
by design, so a test that only guards *those* would prove nothing about a dependency, and a
property enforced by convention is exactly what the requirement rules out. ADR-05 made one egress
path and tested it by scanning sources; this is the same technique pointed at an absence.

**The exemption is pinned rather than implied.** `sim/boundary.py` must hold `socket` in order to
deny it, so the scanner exempts exactly one file and exactly one import —
`GUARD_MODULE`/`GUARD_ALLOWED_IMPORTS` — and a test asserts the offenders equal that set. A rule
with an unstated hole is not a rule.

## 320.3 Decision: paths are composed by the verified report's composer, and a hop states its origin

`EstateGraph.attack_paths()` calls `arachne.analyzer.paths.build_attack_paths` — the function the
report's `## 9. Attack paths` section calls. Hypothetical states are injected as *synthetic
analyses* (`Hypothesis.as_analysis()` with check id `sim.<kind>.<id>`), so a what-if run walks the
real composer over a model that has grown one more weakness.

The tempting alternative — a parallel composer with the simulation's own staging rules — was
rejected for a reason that is behavioural, not aesthetic: a simulation whose rules were looser
than the report's would predict attacks the report would never show, and a capability whose entire
purpose is to be believed about a future that has not happened fails worst by over-claiming. Reuse
also buys determinism and one place to fix a staging bug.

The consequence is that a simulated hop's `verified` flag means what the composer's does ("the
analyzer accepted this"), which inside a simulated world would print the word *verified* in a
section whose whole point is that nothing was verified. So the report DTO for the simulated block
has **no `verified` field at all**: a hop carries `origin: observed | hypothetical` plus the
hypothesis id, and `SimulatedPath.cheapest_label` re-words the composer's cheapest-break sentence
for a hypothetical hop. The vocabulary is separated deliberately, because a reader skimming a
what-if section for "verified" must not find it.

## 320.4 Decision: `applied-fix` is a hypothesis kind, and closing a link changes a path

REQ-SIM-002 names three injection kinds (new exposure, compromised credential, new vuln).
REQ-SIM-005 needs a fourth that *subtracts*: without it a "before/after delta for a proposed
architecture change" could only ever measure additions. `applied-fix` closes an **observed**
weakness by its check id, and it refuses a weakness nobody observed, because "the fix removes
something we never found" is not a change anyone can measure.

It also drops the weakness's stored candidate row, not only its analysis, because a candidate whose
analysis disappeared would otherwise re-enter the composition as an unverified candidate edge and
leave the path standing — an `applied-fix` that visibly changed nothing.

**A delta therefore reports introduced *and* removed paths.** Closing one link of a three-hop chain
usually does not delete the path; it produces a *different* path (different hops, different id), so
the delta reads "one introduced, one removed". That is exact rather than a rounding artefact, and
the report renders both lists.

## 320.5 Decision: the simulated block is optional, the section is last, and no gate reads it

The report gains one optional top-level field (`simulation`, schema 1.11) and one section
(`## 13. Simulated scenarios (what-if)`), placed **after the evidence appendix**. Three
consequences, all deliberate:

- **A report that did not ask for a simulation is byte-identical to its pre-S28 form.** The field
  defaults to `None` and the section is not rendered, so no existing golden, hash or reader changes.
- **The verified body (§1–§12) does not move.** Numbering the annex *after* the appendix keeps a
  deployment that never simulates on exactly the numbering it had, and means a reader meets the
  hypothetical material only after everything the scan actually established.
- **Nothing finding-shaped can see it.** `ci_gate.findings_from_report` reads `report.findings`;
  the severity counts read the `findings` table; the trend writers read `scans`/`findings`. The
  simulated paths live in a field none of them reads, and a golden test pins that a *critical*
  simulated path leaves a gate verdict clean while the fixture's own verified critical finding
  trips it.

Markdown, HTML and JSON all render the block; the i18n keys are added to both catalogues (the
renderer-key completeness test scans them).

## 320.6 Decision: one table, one purpose, and no writes anywhere else

Area SIM persists exactly one thing: `simulation_points` (migration 0014), one row per
event-driven re-simulation, carrying the path counts, the exposure score and the severity mix —
*observations of a computation*, so the posture view can plot the outlook beside the exposure. It
has no foreign key to `findings` and no method that touches one; the store's docstring says so, an
AST-level test asserts no file in the package names a finding-store writer, and an integration test
runs a real what-if over a real lab scan and asserts the candidate set and severity counts are
unchanged.

The alternative — reusing `scans.stats` or a report artifact — was rejected: a what-if run has no
scan, no report and no lifecycle, and parking its output anywhere the finding pipeline reads would
have made the "never enters a store" requirement a convention instead of a property.

## 320.7 Decision: the trend is a separate series, and re-simulation is opt-in

`ARACHNE_SIM_RESIMULATE` (default false) subscribes the re-simulator to `scan.finished` and
`report.ready` — a model update is exactly "a scan stored new data". The points are passed to the
posture view as an **optional** parameter, so `render_estate_markdown(posture)` is unchanged for
every existing caller and golden, and the simulated series renders as its own labelled section
(`## Simulated outlook (what-if)`) and its own JSON key. Merging a computed point into the observed
trend would have made one line mean two different things.

Three properties make it safe to leave running: it is opt-in; a failure inside it is a counted
error and never a failed scan (the bus swallows a raising subscriber and the re-simulator converts
the failure to an error event); and a provider with nothing to model records **no** point, because
a trend line standing for "no data" would read as "no exposure".

## 320.8 Consequences and trade-offs

- **Reachability is as complete as the scan's evidence, and no more.** Three documented payload
  shapes are read; an undocumented shape contributes nothing. The model can therefore be smaller
  than the estate, and the graph summary shows it. Accepted: the alternative is inventing topology,
  which the requirement forbids.
- **Identity bindings are only as good as what a scan proved.** A credential label binds to the
  host the credentialed scan authenticated to and to hosts with authenticated-area findings. A
  deployment that knows more (an SSO group's reach, a directory relationship) can pass
  `identity_bindings` explicitly; ARACHNE does not guess them.
- **The guard's reach is the process, not the kernel.** A native extension bypassing the `socket`
  module would not be caught by the runtime half — only by the static half, if it were a Python
  import. Stated in `docs/security-review.md` §19 rather than implied away.
- **`simulation_points` has no retention policy of its own.** It is operator data with an estate
  key and no target content; if it grows, prune it like any table. Recorded as a limitation.
- **The simulated block is attached per report, not stored.** `arachne report --simulate` computes
  it on demand, so two reports of one scan can carry different hypotheticals. That is the point,
  and it is why the block is not written to `scans.stats`.
