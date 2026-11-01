# 250 — Data lifecycle, evidence storage & observability (S20, areas DATA and OPS)

**Status:** accepted · **Date:** 2026-10-30 · **Stage:** S20 · **Requirements:** REQ-DATA-001...004,
REQ-OPS-003, REQ-OPS-004, REQ-OPS-006

## 250.1 What this stage is for

Continuous scanning at estate scale produces three problems that no detection improvement
solves: the data grows without bound, it grows in the *database*, and nobody can see what the
fleet is doing. S20 answers all three — retention policies with a pruning job (REQ-DATA-001),
an evidence backend abstraction with S3 support (REQ-DATA-002), per-project quotas
(REQ-DATA-003), deduplication and compression (REQ-DATA-004), a Prometheus endpoint and
opt-in traces (REQ-OPS-003/004) — and removes the last shipped default credential
(REQ-OPS-006).

## 250.2 Retention: a policy, not a habit

A policy has four day counts (findings, evidence, scans, audit) and an `enabled` flag. It is
resolved per project (`projects.retention_json`) over the deployment defaults
(`ARACHNE_RETENTION_*`, migration 0007). Two values carry meaning that a bare number cannot:

* **`0` means keep for ever** for that category. A tenant with a seven-year audit obligation
  turns audit retention off without turning off evidence retention; the alternative (one
  global knob) forces every tenant onto the shortest policy anyone needs.
* **`enabled: false` is a legal hold.** The job plans nothing and deletes nothing for that
  project, and the plan says so (`(legal hold)` in `arachne retention status`).

**The plan is the contract.** `RetentionPruner.plan()` selects concrete row ids; `prune()`
deletes exactly those ids. That is what makes "dry run, then apply" trustworthy even though
the clock keeps moving between the two calls, and it is what the property test asserts
(`tests/unit/test_retention_property.py`, 25 generated estates): every removed row was over
its own category's cutoff *or* was removed with a scan that was, every row inside retention
survived, a second run deletes nothing, and the cached usage ledger still equals the sum of
the surviving evidence sizes afterwards.

**The cascade is declared, not hidden.** Deleting a scan takes its findings and evidence with
it (the foreign keys cascade). That is the *parent's* policy — a finding cannot outlive the
scan that produced it — so the plan reports those rows as `cascaded_rows` under `scans`
rather than pretending they were independently eligible.

**Audit has no project column.** `audit_log` rows carry an actor and an action, and an audit
line can name any tenant. Rather than adding a column and guessing at attribution, the audit
cutoff is the *smallest* non-zero `audit_days` among the configured policies: the tenant with
the shortest obligation wins. That is the only choice that cannot retain one tenant's audit
records longer than that tenant allows, and it is stated in the API/CLI output as
deployment-wide.

The job is bounded (`retention.batch_limit`, default 10 000 rows per category per run), so a
first prune on a years-old database is a series of repeatable batches rather than one enormous
transaction. Dry run is the default in both the CLI (`arachne retention prune`, `--apply` to
act) and the module API (`prune(dry_run=True)`).

## 250.3 Evidence storage: one abstraction, two backends

Evidence stays **inline in the `evidences` table** below `evidence.offload_threshold_bytes`
(16 KiB default) — that is what keeps the default deployment dependency-free and every existing
behaviour unchanged. Above it, the payload is written to the configured **backend** and the row
keeps a *stub*: every scalar field, every string truncated to `preview_chars` (2 KiB), plus the
object's `backend`, `key`, `sha256`, `size`. A report and the UI render the stub, so an
offloaded finding still reads correctly; the full object is one download away.

* **`LocalEvidenceBackend`** (default): `<evidence_dir>/ab/cd/<sha256>`, written atomically
  (temp file + `os.replace`), streamed chunk by chunk.
* **`S3EvidenceBackend`**: any S3-compatible store, SigV4-signed with stdlib `hmac`/`hashlib`
  (the same choice S17 made for JWT verification and S19 for NTLM), path-style or virtual-host
  addressing, multipart above `multipart_threshold`, and presigned GET URLs computed locally.
  The transport is the shared `ScopedHttpClient` — a second egress path was not an option.

**Dedup and compression are the same mechanism.** An object's key *is* the SHA-256 of its
logical bytes, so writing the same 64 KB response body a hundred times costs one object; the
container (`MAGIC | flag | size | zlib(body)`) makes every stored object self-describing and
verifiable, and both backends write the same bytes so a payload migrated between them still
verifies. `REQ-DATA-004`'s "dedup ratio assertion" is `tests/integration/test_data_lifecycle.py`
comparing logical against on-disk bytes and asserting that a repeated payload adds no object.

**A payload whose stub would be larger than itself is not offloaded.** The reference metadata
costs ~230 bytes, so a 100-byte payload would grow the database to shrink nothing. The guard
lives in `EvidenceService.stage` and is why `evidence.offload_threshold_bytes` below ~512 has
no effect: the rule is "offload when it saves space", and the threshold is the floor below
which it is never worth asking.

**Retrieval never hydrates a stub.** The download route (`GET /api/v1/evidence/{id}/download`)
streams the object, or — when the backend can mint one — answers `302` to a presigned URL, so
the browser fetches straight from the object store and ARACHNE never proxies the bytes. That is
what "presigned UI access" means here, and it is why the read path needs no network call: the
stub is self-describing and the full payload has its own route.

## 250.4 `request_bytes`: the one byte-exact read path

`ScopedHttpClient` returns an `HttpExchange` whose body is a *decoded, redacted string*. That
shape is wrong for exactly one payload class: an evidence object is a compressed container
whose digest is recorded with the finding, and a text decode plus a redaction pass would
corrupt it and change the digest. `request_bytes` is therefore a separate, deliberately-named
method — not a flag on `request` — that runs the same safety pipeline (scope validation, scope
refusal auditing, rate limiting, retries, the audit line with the response digest) and returns
raw bytes with a per-call cap. `tests/unit/test_http_hygiene.py` pins its call sites at one
module (`data/evidence_backend.py`), next to the two existing verbatim-read exemptions.

## 250.5 Quotas: warn, then stop, resumably

`projects.used_bytes` is a cached running total, incremented in the *same transaction* that
inserts the evidence rows it accounts for and recomputed from `SUM(size_bytes)` after a prune
and by `arachne retention status`. Above `quota_warn_ratio` (80%) of `projects.quota_bytes`
(or the deployment default) the deployment records one `quota.warning` per scan; at the limit
the write is **refused before it happens** — nothing is written, and the error names the
project, what is stored, what was refused, the limit, and the way out:

```
project 3 has exceeded its storage quota (scan 12): 1050 bytes stored, 900 more requested,
limit 1000 bytes. Nothing was written. Raise the quota (arachne retention quota --project
<slug> --bytes <n>) and resume the scan with `arachne scan --resume <id>`.
```

The checks step audits the refusal (`quota.exceeded`, with the check and asset) and re-raises,
so it reaches the scan machine, which marks the step and the scan `failed`. That is the state
`arachne scan --resume` continues from — a quota stop costs the operator the failed step, not
the whole scan. `_persist` re-raises `StorageQuotaError` explicitly rather than swallowing it
with the other store failures: a full disk is an operator decision, not a hiccup.

Overshoot is bounded by one candidate, not by a transaction: two scans writing concurrently can
each be admitted just under the limit. Documented rather than locked, because the alternative
is a cross-process lock held across every evidence write.

## 250.6 Observability

**Prometheus `/metrics` (REQ-OPS-003)** is hand-rendered. The exposition format is a page of
text, and a metrics client library would be a dependency in *every* deployment, including the
air-gapped one — the AI layer already renders Prometheus text the same way. Three properties
are asserted by `tests/unit/test_metrics_contract.py`:

* **The families are declared, never discovered** (`METRIC_FAMILIES`): a name, a type, a help
  string and its label names, covering each signal the requirement names — scan counts and
  durations, queue depth and leases, agent health, proof-level counters, API latency, feed
  freshness — plus the ones an operator needs to act on them (retention deletions, storage per
  project, evidence bytes and dedup hits).
* **Label values are escaped and bounded.** A label value reaches the format verbatim, so a
  value containing a quote or a newline would *inject* metric lines; `_escape_label` is a
  security function, asserted by a hostile-value test.
* **Nothing identifies a target.** No host, asset, finding title or payload reaches a label.
  The endpoint is scrapeable without an API key (`ARACHNE_METRICS_TOKEN` optionally requires
  one), so that is a privacy property, not a convention.

Counters are process-local — what this worker did — which is what a scrape target means. The
gauges (queue depth, agents, feeds, per-project storage, scan counts by status) are read from
the database at scrape time, so a scrape against any worker describes the whole deployment;
those families are cleared before each scrape so a retired agent or a deleted project stops
being reported. `/metrics` is exempt from the rate limiter and the per-request audit line
(scrapes are machine-generated and frequent); its own refusals are audited by the route.

**Traces (REQ-OPS-004)** are opt-in and sampled: `ARACHNE_TRACING_ENABLED` requires
`ARACHNE_OTLP_ENDPOINT`, and `ARACHNE_TRACING_SAMPLE_RATIO` decides what fraction of traces is
recorded, with the decision taken once at the root span so a partial trace is impossible. The
orchestrator opens one span per pipeline step (`scan.step.<step>`, with the scan id and the
attempt), the HTTP client opens one per request (`http.<METHOD>`, with the redacted URL and
status) nested under it, and the W3C `traceparent` header is propagated outbound. Attributes go
through the redactor, so a URL in a span cannot carry a credential; the exporter is best-effort
(an unreachable collector is logged and dropped, never propagated), and the spans are flushed
at scan end rather than left in a buffer a short-lived CLI process would drop.

Rendering is OTLP/HTTP with the JSON encoding (no protobuf, no code generator) over the shared
scoped client, pinned to the collector's host. A collector on a private address needs
`ARACHNE_OTLP_ALLOW_PRIVATE_IPS=true`, exactly as an internal agent deployment needs
`ARACHNE_ALLOW_PRIVATE_IPS`.

**Structured JSON logging with redaction** already existed (S1–S14); S20 extends it where the
new surfaces reach it. Two gaps were closed in `core/redaction.py`:

1. **Presigned URLs.** `X-Amz-Signature`, `X-Amz-Credential` and `X-Amz-Security-Token` are now
   sensitive query keys, and a `presigned-url` pattern removes the signature from the *text*
   path too. A presigned URL is a bearer credential until it expires.
2. **A URL embedded in text.** The `key: value` scanner consumed a whole URL as one value, so
   `source: https://host/login?password=…` — the shape the JSON log formatter produces for any
   string field, and the shape a trace attribute takes — hid the inner parameter from the
   scanner. A pair whose key is innocent but whose value is a URL is now passed through
   `redact_url`. `contains_secret` was extended to agree. The property is fuzz-pinned for every
   generated secret family (`tests/unit/test_redaction_fuzz.py`).

## 250.7 No default credentials (REQ-OPS-006)

The compose stack ships **no** credentials: `POSTGRES_PASSWORD` and `ARACHNE_API_KEYS` use
compose's required-variable syntax (`${VAR:?message}`), so a missing value is a startup error
with an explanation rather than a fallback everyone can read, and `docker/README.md` documents
generating both instead of publishing demo keys.

`python -m arachne.tools.credentials_gate` is the CI grep gate (its own workflow step, plus
`tests/test_no_default_credentials.py`), and it is designed so it cannot rot:

* A credential-named setting in a shipped file must be empty, a variable reference, or an
  obvious placeholder. Names that end in a *reference* suffix (`_FILE`, `_PATH`, `_ENV`,
  `_MAX`, `_KEY_LENGTH`, …) are pointers or bounds, not values; a bare number, a boolean, a
  path or a shell expansion is not a credential.
* Compose `${VAR:-default}` fallbacks are findings; so is an ARACHNE API key written down
  anywhere (`label:role:secret`).
* **Exemptions are proved, not trusted.** The vulnerable-by-design lab fixtures are exempted
  per service, and the gate re-reads the compose file to confirm every exempted service really
  is in the `profiles: ["lab"]` set — so an exemption can never cover a service the demo stack
  starts. The same credential under a non-lab service is a finding (asserted).
* It bites: the self-test runs the gate against a temporary tree containing the exact pre-S20
  compose defaults and requires a finding for each, so a gate that quietly stopped matching
  fails the suite instead of passing everything.

## 250.8 Deviations recorded

1. **Audit retention is deployment-wide, not per project** (250.2): `audit_log` has no project
   column, and the strictest-policy rule is the conservative reading. A per-project audit
   retention needs an attribution decision first (an audit line can name several tenants).
2. **The vault file is operator data, not scan data.** Retention never touches it; the S19
   acceptance note stands.
3. **Feeds are exempt from retention.** A feed is superseded, not stale: its artefacts are
   versioned reference data that the CVE index and past reports cite. `feed_store.delete` is
   the operator's verb. Recorded as a known limitation rather than a gate criterion.
4. **Quota accounting counts logical bytes** (250.5), not physical bytes after compression and
   dedup: the quota bounds what a tenant may accumulate, and a tenant whose payloads happen to
   compress well should not appear to have used less than it did. Storage efficiency is visible
   separately (`arachne_storage_used_bytes` versus the backend's `stored_bytes`).
5. **`request_bytes` is the third documented exception** to the "one redacted body shape" rule
   (250.4), pinned by the HTTP-hygiene test at exactly one call site.
6. **Counters are per worker.** A multi-worker deployment sums them in Prometheus, which is the
   standard scrape-target model; the gauges are database-derived for the same reason.
7. **Migration 0007 is purely additive** (six nullable columns and one index), so an existing
   database upgrades with no rewrite and no backfill, and the `alembic check` drift gate stays
   green.
