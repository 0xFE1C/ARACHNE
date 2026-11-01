# ADR 130 — Stage 8: report engine v1 + remediation

Stage S8 implements (F-06-01…07): the report is the product, and every
format must be the same document. The decisions below record what S8 fixed and why.

## 130.1 One immutable `ReportData` DTO; renderers are pure functions of it

`arachne/report/model.py` defines the pydantic (frozen) `ReportData` document: cover,
executive summary, scope & methodology, asset inventory, findings (the §1 schema),
low-confidence observations, patch-gap, appendix and diff. The builder
(`report/builder.py`) is the **only** module that reads the store; `render_markdown` and
`render_json` only format the object they are handed. That is what makes "the Markdown and
the JSON cannot disagree" a structural property rather than a test. `render_report` is the
single format switch, and an unknown format raises `ReportError` (a new `reporting` error
category) instead of degrading.

## 130.2 Markdown (default) and JSON only in S8; HTML/PDF are S13

 lists four formats, but the roadmap places HTML/PDF in the hardening
stage. This build ships the two the stage prompt requires and refuses the others with an
actionable message. Adding a renderer later means one new module behind `render_report`; it
must not add a second assembly path.

## 130.3 Evidence kinds are mapped onto the §5 vocabulary

The internal `EvidenceKind` (`tls_certificate`, `file_path`, …) predates the report spec.
The projection maps onto §5 (`tls_cert`, `file_artifact`) and keeps `artifact` and `note` as
documented extensions: an `artifact` is a machine-readable fact bundle and a `note` is the
candidate's provenance — both are what makes a finding explainable, and neither is an HTTP
capture.

## 130.4 Redaction is re-applied at projection; bodies are truncated; QA scans the output

Evidence is redacted at capture time (ADR-050.3), but the report re-applies the idempotent
redactor to every payload and to request URLs. Bodies are truncated at
`ARACHNE_REPORT_EVIDENCE_LIMIT` (default 8 KB) with a `body_truncated` marker; the sha256 is
of the projected payload, and an existing capture hash is preserved. `tests/report_qa`
scans both rendered formats with the same detectors (`contains_secret`) and for the lab's
planted credentials. Redaction is a net, not a licence: a bare high-entropy string with no
recognisable shape is still not caught (ADR-050.3), which is why the lab test asserts the
*known* secrets.

## 130.5 A finding's verdict comes from `findings`; its explanation from `analysis_log`

`findings` holds severity/confidence/status/remediation id (written by the analyzer);
`analysis_log.output_json` holds the narrative, score breakdown, rule trace, provenance and
merged-evidence ids. The builder joins them by finding id. A candidate with no analysis is
still rendered (`info`, the check's confidence), and a compound finding's
`merged_evidence_refs` are resolved against the global evidence-id map so it cites its
contributors' captures. Status comes from the analysis when one exists, because an
in-memory store cannot write it back to the candidate row.

## 130.6 Dropped and merged findings are appendix material, never confirmed findings

`status in {fp, merged}` is excluded from the confirmed set: `fp` goes to appendix D with
the analyzer's drop reason, `merged` is the dedupe artefact and is counted there. The report
renders the deduplicated set the correlation step built; it does not re-dedupe (ADR-090.7,
ADR-120.12).

## 130.7 Low confidence is a report decision, separate from the analyzer's threshold

 puts the threshold at the report (`ARACHNE_REPORT_MIN_CONFIDENCE`,
default 55) while keeps the analyzer's own. They are deliberately
independent: the analyzer decides what a finding *is*; the report decides what it publishes
as confirmed. Below the threshold a finding is *moved*, never dropped, and the executive
summary reports the count separately. `ARACHNE_REPORT_LOW_CONFIDENCE=false` omits the
section but not the count.

## 130.8 The executive summary is template synthesis with a provenance label

In heuristic mode the section is rendered from
`templates/report/executive-summary.yaml` over the report's own counts/headlines/priority
order, using the same linear `{path}` scanner as the narrative engine (no `format`, no
`eval`). Every paragraph is gated on a boolean and dropped if a reference cannot resolve, so
"no findings" and "one critical finding" cannot emit the same sentence. The counts table is
structured data on `ExecutiveSummary`, always present; provenance (engine, template
version) is carried. S9's AI engine renders the same section shape through its prompts, so
the report cannot tell which engine wrote it.

## 130.9 Remediation is catalog data, now with verification-of-fix steps

 requires summary, numbered steps, **verification of fix**, and
references. S8 adds `verify` to `RemediationEntry` and `verification` to the resolved
`Remediation` DTO (carried through `analysis_log`). The shipped catalog grows to **58
entries / 43 CWEs** — the union of every CWE a shipped check or rule can emit, plus the
broader classes a report reader expects — and `tests/unit/test_report_remediation.py`
fails the build if an emitted CWE has no entry, or an entry lacks steps/verification/
references. An operator's entry without `verify` gets the documented fallback, so their
older catalog still loads.

## 130.10 The diff vocabulary is closed, and a severity decrease is `recurring`

F-06-05 names four words: `new`, `fixed`, `regressed`, `recurring`. Identity is
`(check_id, asset)`. A severity **increase** is `regressed`; a severity **decrease** is
`recurring` (the finding is still there) with the direction visible in `severity_trend`;
labeling a decrease "regressed" would make the word mean "changed". The full diff UI is S11;
S8 ships the comparison, the payload and the `scans_diff` writer.

## 130.11 `scans_diff` is written by upsert; no migration

`scans_diff` has been one of the spec's nine tables since `0001`. `SqlScanDiffStore.save`
updates an existing `(scan_a, scan_b)` row rather than appending, so re-running a comparison
does not grow the table. S8 adds no column and no table, so `alembic check` stays clean.

## 130.12 The JSON schema ships as data and is generated from the DTO

`templates/report/report-schema-1.0.json` is `ReportData.model_json_schema()` plus `$id`,
`title` and a pinned `schema_version` const. The report QA gate validates a rendered report
against it. `jsonschema` is a **dev** dependency only: the runtime renderer is stdlib
`json`. If the DTO changes, the schema file must be regenerated in the same commit and the
QA test is what notices.

## 130.13 The QA gate runs a real M3+M4 lab scan; M2 keeps its own acceptance

`tests/report_qa/test_report_qa.py` runs the shared stdlib web lab through the full pipeline
(M1 with OSINT off — its online checks report *skipped* while the hybrid js-asset-scan still
runs — plus M3 and M4 active checks, the analyzer and correlation) and asserts the five §10
properties on the *rendered* output, not just the DTO. M2 is network-only and has its own
acceptance suite (`tests/integration/test_m2_scan.py`); the report builder is
module-agnostic and the unit tests include M2/M1-shaped findings, so coverage of "S3–S7
checks" is not contingent on running two labs in one test. The SQL path (findings +
`analysis_log` + audit rows) is covered separately in `tests/unit/test_report_store.py`.

## 130.14 Two additive store fields, no schema change

`CandidateRecord.created_at` and `StoredAnalysis.log_id` are read-only projections of
columns that already exist (`findings.created_at`, `analysis_log.id`). They were added so
the report's `timestamps.first_seen` and `provenance.analysis_log_id` come from the store
rather than from guesswork. No migration, no change to the schema's shape.

## 130.15 The report CLI writes at most one row

`arachne report` reads; with `--diff-with` it writes one `scans_diff` row. It never updates a
finding, never re-analyses and never re-runs a check. `unrun_opt_in_checks` surfaces a
default-off check that produced nothing as **"not run (opt-in)"**, so a report does not
imply an opt-in check was clean (S7 gotcha #3).

## Consequences

- S9 must render the *same* `ReportData`, not a parallel one; its executive summary writes
  `ExecutiveSummary.paragraphs` and sets `provenance` to the model, leaving the counts
  table alone.
- S11 extends `report/diff.py` and `ReportDiff` (trend rendering, sparkline) without
  changing the four-word vocabulary.
- S12 maps `ReportData` onto the API's JSON and the UI's sections; `render_report` stays the
  single format entry point.
- S13 adds HTML/PDF renderers and their golden files to the QA gate.