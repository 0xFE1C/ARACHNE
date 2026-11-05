# ADR-070 — Stage 3: module framework + M1 recon & attack surface

> **Owner:** ARACHNE architecture group · **Last verified:** 2026-11-05 · **Review interval:** 1825 days

Scope of this stage: the plugin contract of §5 (F-02-01, F-09-01), the module
registry (F-02-09, F-02-10), the nine M1 checks of M1 (F-02-02) with
evidence-bearing candidates (F-02-08), candidate persistence, and the G-01 coverage tool.
Everything below is a decision that a later stage has to keep honouring, or that a reader of
the code would otherwise have to reverse-engineer.

## ADR-070.1 — One `Module` per check, with a separate module *group*

 §5 names the base class `Module` and gives it a *single* `research_ref`, a
`supports(asset)` predicate and a `run(ctx)` generator — i.e. it describes **one check**, not
a package of thirteen. §2.2 and, on the other hand, speak of
"M1..M6" as modules that contain checks.

Both readings are honoured, in the two places they belong:

* **`Module` is the check** (`modules/base.py`), exactly as §5 declares it: `name`, `version`,
  `description`, `research_ref`, `supports(asset)`, `run(ctx) -> AsyncIterator[CheckResult]`,
 plus a validated `CheckMetadata` that carries the common check metadata of.
* **`ModuleGroup` is M1..M6** (`modules/registry.py`): an id, a title, a description, its own
  version, the pipeline step its checks belong to, and its checks.

The registry discovers groups; the pipeline runs checks. A plan, a report and the coverage
matrix can therefore talk about "M1" and about `m1.ct-lookup` without either name being a
lie. A plugin that exports only checks is wrapped into a group for its module id, and a group
for an already-registered module is *merged* into it (adding one check to M1 must not mean
forking M1) — while a duplicate check id is fatal, because two implementations of one
identity would make a plan describe work that cannot run.

## ADR-070.2 — OSINT is a second scoped client behind a default-off switch

M1's whole value is querying *other people's* indexes, and those are not the target: forcing
crt.sh through the target scope would be wrong, and relaxing the target scope would be worse.
So the provider layer builds a **second** `ScopedHttpClient` whose scope is exactly the hosts
of the enabled providers (plus a configured search endpoint and any declared extra host).

Consequences:

* `core.config.OSINT_PROVIDER_HOSTS` is the single deployment allowlist, and
  `tests/unit/test_providers.py` fails the build if the provider table drifts from it.
* `ARACHNE_OSINT_ENABLED` is the master switch and defaults to **false**: a deployment that
  has not asked for OSINT contacts no third party, every M1 check reports a "not run" result
 with the reason, and a default live scan stays offline (.1).
* The OSINT client shares the scan's auditor, so a third-party query (`osint.query`), a
  refused one, and a spent budget (`budget.exhausted`) land in the same trail as every target
  request (F-01-08).
* Per-scan request budget, per-query result limit and per-check asset cap are configuration,
  not constants. A budget that runs out is *recorded* and the check stops — it is not an error
  and it does not abort the scan.
* Provider responses are cached per scan (keyed by provider+URL), which is what makes
  `m1.subdomain-passive` merging three sources cost three requests rather than six.

## ADR-070.3 — M1 `research_ref` values follow the corpus, not the spec table

's M1 table lists a reference per check, and several of those numbers do not
match the method numbering in `docs/research/01-reconnaissance-and-osint.md`: the spec calls
CT-log mining `ch01#7` where the corpus has FOFA at 7 and CT at 8, InternetDB `ch01#4` where
the corpus has Censys at 4 and InternetDB at 5, and so on (the same drift affects
passive-DNS, subdomain aggregation, email harvesting, JS analysis and BGP mapping).

The reference stored on each check is the **canonical method number in the research
chapter**, because:

* G-01 measures coverage against the 175 numbered corpus methods, and the coverage tool reads
  those numbers out of the chapter files; a reference pointing at the wrong method would make
  that measurement wrong;
* `tests/unit/test_module_contract.py` asserts that every M1 reference resolves to a method
  that exists in `research/01-`, which is only meaningful under the corpus numbering.

The check *ids* are exactly the spec's (`m1.ct-lookup`, `m1.webarchive-harvest`, ...), so
traceability from the spec table to the code is unaffected: only the number after the `#` is
corrected. This is a documented deviation, not a dropped requirement.

## ADR-070.4 — Redaction *reports* the patterns it fired

`redact_text` rewrites a body before any check sees it (F-08-04), which means a
pattern-based secret *detector* inside a check could only ever find placeholders. Rather than
give a check a "raw mode" (which would put live credentials back in the process), the
redactor now also returns **which detectors fired**:

* `core.redaction.redact_text_report(text) -> (redacted, kinds)`;
* `HttpExchange.secret_kinds` carries the names, and the serialized evidence key is
  `captured_patterns` — deliberately *not* containing the substring "secret", because the
  redactor's key-aware pass would otherwise blank the very list a report needs.

`m1.js-asset-scan` therefore reports "the bundle matched an AWS access key" (kind + source +
response hash), never a value. The redactor is the detector, there is one definition of "what
a secret looks like", and no path exists by which a live credential reaches a check, a log
line, a finding or a report. `tests/test_safety.py` asserts this end to end.

## ADR-070.5 — The catalogue and the registry are in parity by test

The planner reads a **data file** (`templates/plan/check_catalog.yaml`) so the dry run needs
no detection code; the registry is the executable truth. Two sources for one fact drift, so:

* the M1 rows of the catalogue are generated from the check metadata (formatting aside, byte
  for byte), and `tests/unit/test_registry.py::test_the_shipped_catalogue_and_the_registry_agree`
  fails the build when they disagree on `title`, `description`, `research_ref`, `cwe`,
  `target_kinds`, `estimated_requests` or `requires_active_checks`;
* `PlannedCheck.implemented` (from the registry) tells a plan which included checks this build
  can actually run, and `PlanStep.planned_only` counts them per step;
* a step is reported as *skipped* only when nothing will happen at runtime: no handler, no
  built-in offline work (recon seeding, endpoint discovery), or no implemented check. That is
  what keeps `arachne scan --dry-run` honest about M2-M6, which are planned but not built.

## ADR-070.6 — Candidates are persisted without a severity

`findings.severity` stays `NULL` and `status` stays `open` for everything a check emits: the
module layer does not score (ADR-02), and the S5/S9 analyzer fills severity, remediation and
status transitions. The candidate's `detail` and its provenance (check key, module, status,
confidence, asset) are stored as a `note` evidence row rather than as a new column, so:

* the schema remains the spec's §2.4 (no migration, no drift-gate risk);
* every candidate has at least one evidence row, which is F-02-08's requirement even when a
  check captured no request;
* the report engine can render "why was this reported, and from which research method" from
  the evidence store alone.

`data/finding_store.py` additionally upserts the registry's checks into the `checks` table
keyed on `(module, name, version)`, so a report can name the version that ran (F-02-10).

## ADR-070.7 — A check only runs on assets the target definition declared

`Asset.declared` is set from the seed metadata, and `modules.handlers` skips a check against
an asset it discovered itself unless the check sets `runs_on_discovered = True`. Without this
rule, one M1 check naming four subdomains would hand those subdomains to every other M1 check,
turning a plan's request estimate into fiction. Checks that feed on their own discoveries must
opt in, visibly, in their metadata.

## ADR-070.8 — Recorded-response replay is a first-class mode

Live network calls are optional, and the test suite must not need the internet. Both egress
paths therefore accept recordings (vcrpy-style, as plain JSON that reviews and diffs):

* `ARACHNE_OSINT_FIXTURES` for the provider client, `ARACHNE_HTTP_FIXTURES` for the
  target-scoped client;
* `core.http.fixture_transport` builds the transport (the one module allowed to import
  `httpx`, ADR-05), and `modules.providers.fixtures` loads the files without importing one;
* matching is exact `METHOD url` first, then `METHOD host+path` **only when that key is
  unique** — an ambiguous fallback would answer with the wrong body, and a fixture gap must be
  loud (a `501` with an explanatory body) rather than plausible;
* name resolution is stubbed in replay mode because nothing dials, but the *whole* safety
  pipeline (scheme, scope, IP policy, rate limit, redaction, audit) still runs.

This is also what makes the offline demonstration of.1 possible today, and
it is why the S2 "a live scan makes no request" tests were rewritten: the property that still
holds — and now has teeth — is "every request is a read-only GET inside the declared scope".

## ADR-070.9 — Small, deliberate extensions of earlier stages

* `core/config.py` gains `OsintSettings` and `Settings.http_fixtures`, and
  `migrations/env.py` is untouched.
* `core/audit.py` gains six actions (`check.started`, `check.skipped`, `modules.loaded`,
  `finding.candidate`, `osint.query`, `budget.exhausted`); the audit schema version stays 1.1
  because the *shape* did not change, only the vocabulary.
* `core/planner.py` gains `implemented_checks` as a parameter and two fields
  (`PlannedCheck.implemented`, `PlanStep.planned_only`, `PlanTotals.planned_only_checks`).
  All are additive, so a plan persisted by S2 still loads.
* `core/orchestrator.py` builds the module-backed handler set by default (S2 said
  `core.steps.default_handlers` was the injection point for exactly this) and takes an
  optional `registry`. `core/steps.py` keeps the module-free pair, which is what
  `core.steps.default_handlers()` still returns.
* `core/errors.py` gains `OsintError` and `BudgetExhaustedError`.
* `providers/fixtures.py` reports a non-UTF-8 recording as a fixture problem instead of
  leaking a codec traceback.

## ADR-070.10 — What is deliberately not here

* **M2-M6 are planned, not built.** They appear in the catalogue (so the plan can price them)
  and are marked `implemented: false`; the checks step reports itself skipped.
* **The analyzer does not exist yet.** Candidates are persisted without severity; nothing in
  `modules/` writes prose beyond an operator-facing description of what was observed.
* **`m1.favicon-hash`, `m1.doc-metadata`, `m1.bgp-asn-map` and `m1.breach-lookup`** from the
 M1 table are not implemented in this stage: the stage prompt names the nine
  checks that are, and the coverage matrix shows the rest of ch01 as unmapped rather than
  pretending otherwise.
