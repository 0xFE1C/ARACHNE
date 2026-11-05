# ADR 160 — Stage 11: M6 automation/AI-era/post-exploit + scheduler + diff

> **Owner:** ARACHNE architecture group · **Last verified:** 2026-11-05 · **Review interval:** 1825 days

- **Status:** accepted
- **Date:** 2026-10-29
- **Scope:** S11 (roadmap phase 3). Adds the M6 module (nine checks), a cron-like scan
  scheduler, and the completed diff/trend reporting half of F-06-05, with rules, narratives,
  remediation, CVSS vectors, the OWASP map, the planning catalogue, the coverage matrix and new
  lab fixtures.

## Context

Through S10 the scanner looked at the target's *surface* (recon, network, web, misconfiguration,
cloud). S11 adds the module that asks the two questions the others do not: "is something already
wrong inside what we host?" (a planted webshell, a committed credential, a leaked CI token) and
"what does the AI-era and exploit-readiness picture look like?" (GenAI endpoints, EPSS/KEV-ranked
patch gap, post-exploit telemetry). M6's evidence is mostly *files and logs*, not HTTP responses,
and it is the first module that must stay inert until an operator explicitly grants access to
telemetry. S11 also delivers the roadmap's other phase-3 items: a recurring-scan scheduler
(F-01-05) and the diff/trend reporting F-06-05 promised in S8.

## Decisions

### ADR-S11.1 — One check per spec id; M6 ships the nine the spec table names

The nine check ids are exactly M6's (`m6.webshell-yara`, `m6.attack-surface-genai`,
`m6.cve-epss-correlation`, `m6.secret-scan-at-scale`, `m6.ci-secret-leak`,
`m6.sigma-hunt-rules`, `m6.deception-listeners`, `m6.lpe-discovery`, `m6.ad-attack-path`), and
their `research_ref` values follow the spec table's corpus references. `m6.ci-secret-leak` and
`m6.sigma-hunt-rules` share `ch06#23` in the spec table; `ci-secret-leak` is the CI-log
application of that method and the sigma check is the log-hunting one (see ADR-S11.4).

### ADR-S11.2 — M6 is file-read-only, offline-first, and never post-exploits

Every M6 check obeys M6 "Safety":

- The **webshell scan** reads files and served content; the served half is GET-only and the
  local half never writes, renames or executes anything. The probe of served shell-path
  candidates is bounded by `ARACHNE_M6_WEBSHELL_PROBES` (default 12) and GET-only, so it is a
  `hybrid` check that does not need the active-checks gate (a plain read, like every M3/M4 GET).
- The **secret/CI/AD/GenAI** checks read local artifacts and never fetch: a remote git URL is
  skipped rather than cloned (the S10 rule), and the AD check parses an exported graph and never
  authenticates or binds to AD.
- The **telemetry checks** are the ones with a grant: `m6.sigma-hunt-rules` ingests nothing
  unless `ARACHNE_M6_LOG_ACCESS=true` (without it, it ships the rule set and reports skipped),
  and `m6.deception-listeners` and `m6.ad-attack-path` are `enabled_by_default=False` (the former
  also behind `ARACHNE_M6_DECEPTION`).
- Nothing in M6 performs a post-exploitation action; "post-exploit signals" means *detecting the
 artifacts and behaviours*.

### ADR-S11.3 — M6's webshell detection is signature **and** behaviour (the PHP2SHELL lesson)

The PHP2SHELL case study is explicit that the first exploitation of an embargoed RCE precedes any
CVE-specific signature, so `m6.webshell-yara` runs two halves: the corpus signature rules
(`eval($_POST[...]`, `assert($_REQUEST`, `eval(base64_decode(...))`, c99/r57/b374k markers, ...)
and behaviour heuristics (oversized single lines, encoded blocks, high entropy, eval density,
and — for local files — anomalous mtimes relative to their siblings). A signature match is
`critical`; behaviour alone, on a served document, is `high`; behaviour alone on a local file is
`medium`. This is the difference the acceptance fixture exercises: the S11 diff test escalates a
heuristics-only file into a signature-bearing one and the finding's severity rises, which is what
makes it a *regressed* finding rather than a recurring one.

### ADR-S11.4 — `m6.sigma-hunt-rules` cites a range because its rules encode the discovery methods

The spec gives the sigma check `ch06#23`; the rules it ships, however, encode the post-exploit
discovery behaviours of ch06#18 (Kerberoasting/AS-REP), #20 (ticket/hash abuse), #21 (lateral
movement) and #22 (persistence/C2), and the coverage matrix counts methods, not rules. The check
therefore declares `research_ref: ch06#18-23`, and ADR-S11.1 records that the range is the honest
description of what the rule corpus covers. `m6.ci-secret-leak` keeps `ch06#23` as well (the
CI-log application of log analysis); the two checks share the method, which the coverage matrix
handles (a method may be mapped by several checks).

### ADR-S11.5 — Offline-first feeds: EPSS/KEV, LPE index and Sigma rules are managed data

The patch-gap and LPE checks must work with no network (says so; the demo scan runs
offline). M6 therefore ships three managed-data snapshots — `templates/m6/epss-snapshot.yaml`
(CVE→EPSS/percentile/KEV), `templates/m6/lpe-index.yaml` (a `CveIndex` document, reusing the M2
model) and `templates/m6/sigma/*.yml` — and an operator may replace each
(`ARACHNE_M6_EPSS_FEED`, `ARACHNE_M6_KEV_FEED`, `ARACHNE_M6_LPE_INDEX`, `ARACHNE_M6_SIGMA_RULES`)
or add a version export the checks correlate against (`ARACHNE_M6_RESOLVED_VERSIONS`). The
estate-level checks (`cve-epss-correlation`, `lpe-discovery`, and the log-hunting check) are
*owner-gated*: they run once per scan on the lexicographically-first declared asset, so a
multi-target scan reports the estate once rather than once per asset.

### ADR-S11.6 — The Sigma evaluator is a bounded subset, and a rule it cannot honour is inert

`m6.sigma-hunt-rules` ships Sigma rules as data and, with log access, runs them over exported
JSON-lines telemetry with a small evaluator supporting `and`/`or`/`not`, `all of them`,
`any of them`, the `contains`/`startswith`/`endswith`/`re` field modifiers and list values. A
condition the evaluator cannot honour is *not* an error that aborts a scan: the rule is treated as
unmatched (the loader already validated the document shape). The point of the check is that the
rule set ships and is SIEM-queryable; the local ingest is a convenience, not a SIEM replacement.

### ADR-S11.7 — The scheduler is a file-backed coordinator over the real orchestrator

`arachne.scheduler` registers a schedule (a target fixture + a cron expression + optional scan
options), persists its state in a JSON document (`ARACHNE_SCHEDULER_STATE`), and, on a tick, runs
what is due through the **real** orchestrator. State is operational, not evidentiary, so it lives
in a file, not a table — which also keeps the evidence-store schema to the spec's tables. The
cron parser is dependency-free and evaluates five fields with the standard day rule (restricted
DOM and DOW are ORed). Change detection is the F-06-05 half: each run compares itself with the
previous run of the *same schedule* and persists a `scans_diff` row (the table has existed since
`0001`), which the report's trend section and `arachne report --diff-with` already read.

### ADR-S11.8 — The diff identity stays `(check_id, asset)`; the scheduler works within it

The S8 diff compares findings by `(check_id, asset)`. An M6 *local* check
reports every file against the one declared repository asset, so a repository scan yields one
identity per check, not one per file. S11 keeps that identity (changing it is a spec decision, not
a stage decision) and the acceptance test is written to exercise the change kinds the identity can
express: a whole check's signal appearing (new), disappearing (fixed), or rising in severity
(regressed). A future per-file identity (e.g. the artifact path as a sub-key) would be a spec
change and is out of scope.

### ADR-S11.9 — New CWEs ship with a vector, an OWASP entry and a remediation

The four new weakness classes — CWE-506 (embedded malicious code / webshell), CWE-1426 (GenAI
prompt/input weakness), CWE-532 (sensitive information in a log) and CWE-778 (insufficient
logging, for the telemetry findings) — each gained a CVSS vector (`templates/scoring/`), an OWASP
Top-10 mapping (`templates/report/owasp-map.yaml`) and a remediation entry
(`templates/remediation/`), so the S8 gates (`test_rules`, `test_report_remediation`) stay green.

### ADR-S11.10 — The deception artifact field is named `decoy`, not `token`

`Evidence.of` redacts any value under a key named `token` (the redaction key-substring rule). A
honeytoken is not a secret, but a field literally named `token` would be redacted at capture time
and the operator would lose *which* decoy fired. The check therefore emits the decoy's name under
`decoy` (and the source/time under `source`/`at`), so the trigger stays actionable while no real
credential could ever be stored there.

### ADR-S11.11 — The coverage matrix counts the corpus, so `ch06` is now a mapped chapter

`coverage_matrix.md` is regenerated (`arachne coverage --write coverage_matrix.md`). M6 maps
thirteen ch06 methods (7, 8, 14, 15, 16, 18, 19, 20, 21, 22, 23, 24, 25), moving the total from
`106/175 (60.6%)` to `119/175 (68.0%)`. The catalogue's planned-only M6 rows are replaced with
the nine implemented rows (catalog version 1.3), and `test_registry.py`'s "planned-only" gate
becomes the assertion that *every* catalogue row is implemented now that all six modules ship.

## Consequences

- The module count is six; the check count is 104 (95 + 9), with ten opt-in checks (eight from
  S7/S10 plus M6's two) and the same fifty-five active checks.
- M6 adds no `active` check: its only network use is GET-only served webshell probing, which is a
  read. The telemetry checks carry the log-access grant instead.
- The scheduler is exercised end to end by an acceptance test that scans a mutable local web
  root twice and asserts a `new`/`fixed`/`regressed` diff is persisted.
- No migration is needed: `scans_diff` already exists and the scheduler state is a file.
