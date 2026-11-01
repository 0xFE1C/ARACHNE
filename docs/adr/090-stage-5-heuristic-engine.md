# ADR-090 — Stage 5: The Heuristic Engine

Status: accepted (stage S5, roadmap Phase 1, F-03-01..05, F-05-01..07).

This records the decisions that shaped the analyzer and that later stages — especially S8
(report engine), S9 (AI integration) and S13 (FP tuning) — have to keep honouring. It follows
ADR-070/ADR-080: the spec's *what* is not restated, only the choices it left open and the
deviations a reviewer needs to know about.

---

## ADR-090.1 — A real expression language instead of `eval`

**Context.** §2.1 writes rule conditions as small expressions over evidence
(`"secrets_found and http_status == 200"`, `{evidence.x matches "…"}`, `in [200]`). The
shortest implementation is `eval`, and it is exactly what §5 and F-08-06
forbid: a rule file is data an operator (or a downloaded corpus) supplies.

**Decision.** `analyzer/conditions.py` implements a tokenizer, a recursive-descent parser and
an interpreter for one small grammar (boolean operators, comparisons, `in`/`not in`,
`matches`/`contains`/`startswith`/`endswith`, `present`/`missing`, list literals, dotted
fact paths). There is no attribute access, no call syntax and no `eval`/`exec` anywhere;
`tests/unit/test_no_eval_exec.py` keeps the whole tree that way. The **same** evaluator backs
nuclei `dsl` matchers and narrative-section `when` clauses, so there is one language to reason
about, one place to audit and one set of tests.

**Consequences.** A comparison over a multi-valued fact uses "any" semantics (three CVE
artifacts compare as "any of them"), and an *absent* fact satisfies nothing — a rule cannot
fire on data the candidate does not have. A rule author who wants the absent case writes
`path missing` or `not (...)`. Regexes are bounded in length (`MAX_PATTERN_LENGTH`) because a
pathological pattern in a corpus entry would otherwise be a CPU exhaustion primitive; the
patterns themselves come from trusted rule data, not from the target.

## ADR-090.2 — Both spec spellings, because the spec uses both

**Context.** §2.1 shows `severity_if: [- "cond -> high"]` *and*
`conditions: {file_exists: {evidence.http_status in [200]}}`. A YAML flow mapping whose key
contains `[200]` is not valid YAML when written plainly, and a *Python* dict literal for the
same shape puts `in` in the key and `200` in the value.

**Decision.** All three spellings parse to the same thing: the inline `"<expr> -> <value>"`
string; the explicit `{when, then}` mapping; and a single-key mapping whose key is either the
whole expression (`{"evidence.x in [200]": None}`) or an operator-prefixed path
(`{"evidence.x in": [200]}`). Clause values are validated **at load time** (a severity must be
a severity, a confidence a number), so a typo fails the scan that loads the corpus rather than
the rule that happened to fire.

**Consequences.** The shipped corpus uses the mapping shorthand where it reads like the spec
and the string form where YAML would need quoting; the rule docstring records both. A rule
that references an unknown remediation entry or narrative template fails
`tests/unit/test_rules.py`, which is what keeps the corpus honest.

## ADR-090.3 — The rule verdict wins; the score is the second opinion

**Context.** §2.1 says a rule assigns severity; §2.4 says the final severity is
the banded score. Both statements are in the spec, and they disagree whenever a rule author
rates a class higher or lower than its generic CVSS vector.

**Decision.** When a rule fires, its severity **is** the finding's severity (F-05-01: the rule
is the decision) and the score is reported next to it. When no rule fires, the severity is
`max(score band, the check's severity_hint)` — the hint is a floor, never a ceiling, because
it is the check author's statement about the class. `Analysis.score.derived_severity` always
carries the banded score, and a disagreement of **two or more bands** adds an explicit note to
`risk_notes`; one band is normal and silent.

**Consequences.** The correlation engine promotes from the contributors' *reported* severities
(what the report shows), not from their scores, so a compound finding is never weaker than the
findings it explains. S8 renders both numbers; the report must not hide the score when the
rule won, because "CVSS 7.5, rated high" is information.

## ADR-090.4 — Derived CVSS vectors are managed data

**Context.** The spec asks for a "CVSS-style base score per finding (attack vector, complexity,
privileges, impact from check metadata + evidence)". Every implementation choice in that
sentence (which vector a check implies) is a risk judgement an organisation may disagree with.

**Decision.** `templates/scoring/cvss-vectors.yaml` (F-09-04 managed data) holds the defaults
plus per-module, per-CWE and per-check layers; the engine merges them in that order and then
applies two evidence facts (a reachable asset is `AV:N`, a reproduced finding is `AC:L`). The
formula is the real CVSS v3.1 base formula, including the round-up step, and is checked
against published vectors in `tests/unit/test_scoring.py`.

**Consequences.** A deployment tunes its own risk function by editing a data file
(`ARACHNE_ANALYSIS_SCORING`), not by patching the engine. The table is deliberately
conservative for an unclassified finding (`AV:N/AC:H/…/C:L`) so an unknown finding is not
reported as severe on the strength of a guess.

## ADR-090.5 — Verification is I/O, so it lives in the handler, not the engine

**Context.** F-05-07 wants verifiable candidates re-requested before acceptance, and
 §2.1 insists the rule engine itself never touches the network.

**Decision.** `Analyzer.analyze(candidates, context)` stays **pure and synchronous**. The
`analysis` step handler runs the `Verifier` (an `HttpVerifier` over the scan's own scoped
client, or a `NullVerifier` in a dry run) and passes the outcomes in through
`ScanContext.verification`. The engine reads `analysis.verification_count` /
`analysis.reproducible` like any other fact.

**Consequences.** The engine is trivially testable and deterministic (ADR-090.7), and a
verification request is indistinguishable from any other request in the audit trail — no
privileged egress path (ADR-05). A contradiction **drops** the finding (status `fp`, reason
recorded) unless `ARACHNE_ANALYSIS_DROP_ON_CONTRADICTION=false`, because "we saw it, then we
did not" is data an operator needs. Replay mode (`ARACHNE_HTTP_FIXTURES`) makes verification
replay the recording: it proves determinism, not liveness, which the ADR for the lab fixtures
(S4) already noted.

## ADR-090.6 — `findings.confidence` is 0-100 everywhere

**Context.** The module layer writes a check's own confidence (a 0-1 fraction), while
 §2 defines the finding's confidence as 0-100. One column with two units is a
bug waiting to be read the wrong way.

**Decision.** `core.results.confidence_percent` converts at the **store boundary**, so every
row a scan writes carries the report's 0-100 scale regardless of which stage wrote it. The
analyzer's `Candidate.check_confidence` is therefore documented as a percentage too.

**Consequences.** `tests/unit/test_finding_store.py` asserts `70` instead of `0.7` for a check
that reported `0.7`. A reader of the database never has to know which stage wrote a row.

## ADR-090.7 — Determinism is a testable property, not a hope

**Context.** §4 promises "identical output every run" for the heuristic engine,
and G-05 builds the parity guarantee on top of it.

**Decision.** The engine takes every input explicitly (rules, scoring table, narratives,
remediation catalog, filters, signatures) and reads no clock, no environment and no database.
`tests/unit/test_engine.py::test_the_engine_is_deterministic` asserts two runs over the same
candidate are `==`; `tests/parity/test_parity.py` asserts the finding set (`check_id`, `asset`)
is stable and defines the comparison the AI engine will be held to in S9.

**Consequences.** The FP tuner is the one input that changes between runs, and it is read once
per analysis step from the persisted feedback (`fp_feedback`), so a given feedback state
produces a given result. `findings.confidence`/`severity` are written by the analysis step,
which is idempotent over the same rows, so a resumed scan converges rather than accumulating.

## ADR-090.8 — Dedupe and correlation are two passes, and the engine explains rather than replaces

**Context.** says findings with one root cause merge by CWE + asset, keeping
"the most specific module as owner"; §2.3 says correlation emits one compound
finding whose severity is upgraded. Both act on the same analysis list.

**Decision.** The correlation step runs dedupe first (merged findings become
`status="merged"` with `merged_into` recorded, contributors attached to the owner) and then
correlation over the survivors. A compound finding is **added**: the contributing findings stay
in the report with their own detail, and the compound carries `contributors`,
`merged_evidence_refs` and a shared remediation. Grouping is `asset`, `host` (a URL and the
bare host name of the same machine group together — `Candidate.asset_host`), `asset_kind` or
`module`; the threshold is `min_weak_signals`, and `upgrade_if` (first matching clause) beats
`upgrade_levels`. A correlation rule never *lowers* a contributor's severity, and
`max_severity` caps the promotion.

**Consequences.** `findings.status` gained a `merged` value beyond the spec's
`open/verified/fp/fixed`. The report (S8) must skip merged rows when counting findings and show
the owner instead; the analysis log names the owner. A compound has no `checks` row, so
`findings.check_id` is NULL and its identity (`correlation.<rule>`) lives in the analysis
record.

## ADR-090.9 — Operator FP feedback is a table, and the tuner is deliberately simple

**Context.** F-05-07 asks for an FP tuner that "learns per (check, asset-type, signature) and
adjusts rule confidence thresholds". Learning that a restart erases is not learning.

**Decision.** `fp_feedback` (migration `0003`) stores one row per operator decision, keyed
`check|asset-kind|signature`. The tuner aggregates a false-positive *rate* and raises the
confidence a finding from that key needs, capped at 25 points, so no check can be made
unreportable by history alone. It is deterministic for a given feedback state.

**Consequences.** The operator-facing "mark as fp" verb lands with S8's report engine / S12's
API; the storage and the aggregation are ready for it (`AnalysisStore.record_feedback`). The
second extension table beyond §2.4's nine (the first was S2's `scan_steps`),
recorded here so the schema drift is deliberate and visible.

## ADR-090.10 — The `Analyzer` interface, and what `hybrid` means before S9

**Context.** F-03-01 wants one interface with two swappable engines; F-03-03 wants AI to be
opt-in and explicit; F-03-04 wants a hybrid mode.

**Decision.** `analyzer.engine.Analyzer` is a `Protocol` (`name`, `analyze`). `select_engine`
resolves `heuristic` and `hybrid` to `HeuristicEngine` today — "hybrid with no provider" *is*
heuristic, which is F-03-04 read literally — and refuses `ai` with an actionable
`ConfigurationError` rather than silently degrading, because a report must not claim a
provenance it did not have. `Analysis.provenance` records the engine, rule ids and template
version, which is the one field the report may read to tell engines apart (F-03-05).

**Consequences.** S9 layers the AI engine on top of these results without changing the
`Analysis` shape; the parity harness in `tests/parity/` already names the comparison.

## ADR-090.11 — Signature templates participate in the verdict

**Context.** §2.2 wants the nuclei corpus importable. A template engine that
no decision ever consults would be dead code behind a test suite.

**Decision.** `SignatureLibrary` runs over each candidate's captured HTTP exchanges (and, for
native templates, named evidence payloads) *before* the rules. Matched signature ids appear in
the fact space as `signature.matched`, in `Analysis.signatures`, and in
`signature.matched contains "<id>"` conditions — which is how the shipped
`exposure.matched-signature` rule turns "this response is an exposed `.env`" into a severity
and an action. A nuclei template's declared `path` is honoured: a template for `/.env` cannot
be satisfied by the site's home page, and only the host placeholder in `{{BaseURL}}/…` is
treated as dynamic.

**Consequences.** The template engine performs no I/O (a template *describes* a request; the
check layer makes it), so importing a community corpus cannot make a scan touch a host no
check chose. The bundled corpus is three nuclei templates and two native signatures, enough to
exercise the format without pretending to be the community library.

## ADR-090.12 — Supplied narratives, and why the narrative cannot crash a scan

**Context.** §2.5 promises "AI-like" prose generated without a model, from
templates keyed to (severity, CWE, check class) with interpolated facts.

**Decision.** `narrative-templates.yaml` holds 41 templates ranked by specificity, with
conditional sections gated by the same expression language. Interpolation is a hand-written
`{path}` scanner — **not** `str.format`, which would allow `{0.__class__}` and would raise on
any unexpected key. An unresolvable reference drops its section, or (when the section is
`required`) makes the template step aside for the next one; the built-in synthesis always
renders last, so a finding is never reported without prose.

**Consequences.** Narrative quality is a data problem: a new class of finding needs a template,
not a code change. The justification sentence cites the rule trace and the research method, so
the prose is reproducible from the evidence rather than generated.

## ADR-090.13 — Superseded/deferred details

- **`Analysis.remediation` is a resolved object, not an id.** The rule writes the spec's
  `remediation-catalog/….yaml` reference; the catalog resolves it to summary/steps/references
  at analysis time so a report never has to join. S8 owns the full catalog and its QA gate.
- **`ARACHNE_ASSET_CRITICALITY` is a flat `pattern=level` list.** It is the OWASP impact input
  (F-05-04) today; S12's asset model can replace it without changing the engine
  (`ScanContext.asset_criticality` is already the boundary).
- **EPSS comes from evidence or from `ScanContext.epss`.** M2's CVE-correlation evidence
  already carries `epss` from the offline index, so the analyzer reads it there; an online
  feed (F-09-03) fills `ScanContext.epss` in a later stage.
- **The `analysis` and `correlation` steps are part of a scan.** `--dry-run` still plans them
  (0 requests) and reports them as executable, because their handler now exists; a scan with
  no candidates completes them with zero findings rather than skipping them.