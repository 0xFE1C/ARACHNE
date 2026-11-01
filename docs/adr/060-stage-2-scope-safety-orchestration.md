# ADR-060 · Stage S2 decisions — scope, safety & scan orchestration

Status: accepted (S2)
Scope: the repository — what S2 had to decide because the spec left it open, plus the two places
it deliberately extends what S1 shipped. Same rule as S1: prefer the safer interpretation,
record the decision, move on (§1.5). Nothing here weakens a requirement;
the one addition to the spec's data model is recorded in ADR-060.2.

---

## ADR-060.1 — Two scope gates: the definition governs requests, the deployment governs declarations

**Context.** F-01-02 requires "an explicit scope" and a "deny-by-default allowlist of
target patterns"; F-01-01 makes the target definition (targets + exclusions + attestation)
that declaration. It was not obvious what an *empty* deployment scope (`ARACHNE_SCOPE_*`
unset) should mean once a definition exists — S1's `Scope` treats empty as "deny
everything", which would make every scan impossible.

**Decision.** Two scopes, checked at two different times:

* the **definition scope** (`TargetDefinition.compile_scope()`) is compiled from the
  declared targets and exclusions and is what the shared HTTP client enforces on every
  request, including every redirect hop;
* the **deployment scope** (`ARACHNE_SCOPE_*`) is an *additional* allowlist. When it is
  non-empty, `Orchestrator.assert_in_scope` requires every declared target to be allowed
  by it, and refuses the scan (audited as `scope.rejected`, outcome `blocked`) otherwise.
  When it is empty, there is no extra restriction: the audited definition is the
  declaration.

Deny-by-default is preserved at both ends: `Scope` with no dimension still contacts
nothing (unchanged from S1), and the orchestrator never builds a client without a compiled,
non-empty definition scope.

**Consequences.** `arachne scan --target fixture --dry-run` works out of the box, while a
deployment can still pin down what any scan on that host may even be defined over. The
plan prints both scopes, so an operator can always see which layer allowed what.

## ADR-060.2 — `scan_steps` is a new table (F-01-04 needs per-step persisted state)

**Context.** F-01-04 requires that "each step persists state; a crashed scan continues from
the last completed step". §2.4 lists nine core tables and none holds step
progress. The alternatives were stuffing progress into `scans.stats_json` or adding a
table.

**Decision.** Add `scan_steps` (migration `0002`): one row per `(scan_id, step)` with
status, attempts, start/finish timestamps, a redacted error summary and step stats.
`UNIQUE (scan_id, step)` makes a progress write an upsert keyed by pipeline position.
`src/arachne/data/schema.py` now separates `SPEC_TABLE_NAMES` from
`EXTENSION_TABLE_NAMES` so the traceability to §2.4 stays visible.

**Consequences.** Progress is queryable and inspectable (`F-01-04` says "resumable *and*
inspectable"), the resume rule is one predicate (`status in {completed, skipped}`), and a
JSON-blob read-modify-write race on `stats_json` is avoided. Cost: the CI `alembic check`
drift gate now also covers a tenth table, and the table list in the acceptance record differs
from the spec's "nine" — intentionally.

## ADR-060.3 — The attestation gate applies to live scans, not to dry runs

**Context.** F-01-09/F-08-05 require an authorization attestation before requests leave the
process. A dry run sends nothing (F-01-10), so requiring an attestation for it is a policy
choice, not a safety one.

**Decision.** `Orchestrator.plan(..., dry_run=True)` runs the scope gate for every target
(both layers, so an out-of-scope target is refused even in a dry run) but does **not**
require an attestation. It reports `live_ready` plus a warning instead. A live run
(`dry_run=False`, `scan`, `resume` of a non-completed scan) requires a complete, unexpired
attestation covering every declared target, and records it in the audit log
(`auth.attested`) or refuses (`auth.rejected`, outcome `blocked`).

**Consequences.** The dry run is usable as a pre-flight question — "what would this scan do,
and am I allowed to run it?" — which is the purpose of F-01-10. No request can leave the
process without an attestation, because `_run` is only reachable through a passed gate.
Resuming an *already completed* scan skips the attestation check for the same reason the
dry run does: there is nothing left to execute.

## ADR-060.4 — The repository boundary re-attaches UTC to database timestamps

**Context.** ADR-050.6: SQLite stores `DateTime(timezone=True)` as naive UTC, and S1 left
readers to remember that.

**Decision.** `arachne.data.scan_store.as_utc` converts on the way out of the store, so
everything above `data/` sees timezone-aware UTC. The column type is untouched, so the
`alembic check` drift gate is unaffected (the coercion happens in Python, not in the type).

**Consequences.** The lifecycle and planner can compare timestamps without a naive/aware
trap. `ScanRecord` and `StepState` are always aware. ADR-050.6 still describes the storage
behaviour.

## ADR-060.5 — `Scope` gained three dimensions rather than a second scope type

**Context.** F-01-01 targets include CIDR ranges, Git and cloud references; S1's `Scope`
knew only hosts, domains and excluded hosts. The alternatives were a richer scope object
for the orchestrator, or extending the one type the HTTP client already consults.

**Decision.** Extend `Scope` in place with `allowed_networks`, `url_prefixes`,
`allowed_refs` and their exclusion counterparts, plus `check_network`, `check_ref`,
`check_value(kind, value)` (the dispatcher used by both the plan-time gate and the
step-asset guard) and `describe()`. Dimension semantics:

* a URL is allowed when it sits under a declared URL prefix **or** its host matches a
  host/domain/network dimension — every dimension is one of the operator's declarations, so
  the allowlist is exactly what was declared;
* a CIDR target must sit *inside* a declared network; excluding one address inside a
  declared range is normal and still applies per request through `check()`;
* Git/cloud references have no host, so they need their own dimension (a deployment cannot
  otherwise express "this cloud account is allowed");
* an unknown target kind is denied — fail closed.

**Consequences.** One type, one implementation, consulted by both the request path and the
orchestrator, so the two cannot disagree. IP literals are still classified before the scope
check (ADR-050.1), so the reason in the audit log keeps its specificity. `Scope` remains a
frozen dataclass, so its CIDR strings are parsed and validated once, at construction, and a
typo fails at the boundary instead of silently allowing nothing.

## ADR-060.6 — Planning is a data file, and the planner never resolves anything

**Context.** F-01-10 wants a plan with estimated request counts; S3's module registry does
not exist yet, but a plan that lists no checks is not a plan.

**Decision.** Ship a versioned catalogue (`templates/plan/check_catalog.yaml`, ADR-04 data)
of the checks M1–M6 will implement, each with module, name, version, `research_ref`,
applicable `target_kinds`, `estimated_requests` and `requires_active_checks`. The planner
takes the catalogue as a parameter, so S3 can pass the real registry instead. Every
estimate is either declared in the catalogue or arithmetic over the target definition
(`ipaddress` for CIDR sizes, a configurable subdomain assumption for names); nothing
resolves a name, opens a socket, or imports a module. `handled_steps` tells the planner
which steps this build can execute, so a plan states plainly that the `checks` step is
planned but not executable until S3.

**Consequences.** The dry run is genuinely inert and testable as such (a test monkeypatches
`socket.getaddrinfo`, `socket.socket.connect`, `socket.create_connection`,
`ScopedHttpClient.request` and `httpx.AsyncClient.request`, and runs the CLI). Estimates
are honest about being estimates: assumed parameters appear as plan warnings. Active checks
are withheld unless the operator opts in *and* the attestation authorizes them (F-01-09),
and the reason is a structured `skip_code` rather than prose.

## ADR-060.7 — Events are redacted at emission and subscribers cannot break a scan

**Context.** §2.1 names five typed events as the foundation for the
scheduler, API and webhooks. A webhook that is down must not abort a scan
(§4, "errors are data"), and an event payload can contain target-derived
text.

**Decision.** `Event` is a frozen pydantic model with a fixed envelope and a per-type
factory that names the required fields; the payload is passed through `redact_value` when
the event is constructed (the same capture-time rule as evidence, F-08-04). `EventBus.publish`
awaits async handlers, catches and counts every exception, and keeps a bounded replayable
history so a late subscriber (the API/webhooks of S12) can drain what it missed.

**Consequences.** Redaction cannot be forgotten by a subscriber, because it never receives
unredacted data; a broken consumer costs a log line and a counter, not a scan. The bus is
in-process only — external delivery is S12's job.

## ADR-060.8 — `AuditEvent.scan_id` widened to `int | str`; audit schema 1.1

**Context.** S1 typed `AuditEvent.scan_id` as `str`. The evidence store keys scans by an
integer primary key, so every scan-scoped F-01-08 record would otherwise have had to
stringify an id, making the audit trail harder to join against `scans`.

**Decision.** Widen the field to `int | str | None` and bump `AUDIT_SCHEMA_VERSION` to
`1.1`. The change is additive (a string id is still valid) and no consumer exists yet
(the API/webhooks arrive in S12), but the version is bumped so a future consumer can tell
the two shapes apart.

**Consequences.** Audit rows carry the real scan key; the JSONL and `audit_log.meta_json`
representations stay JSON-safe either way.

## ADR-060.9 — `migrations/env.py` no longer disables existing loggers

**Context.** Alembic's `fileConfig(config.config_file_name)` defaults to
`disable_existing_loggers=True`, which disables every logger the config does not mention —
including `arachne.*`. `arachne db upgrade` exits immediately, so S1 never noticed, but a
long-lived host (the API of S12 migrating at startup) would silently lose its logs, and in
the test suite it made `caplog` assertions order-dependent.

**Decision.** Call `fileConfig(..., disable_existing_loggers=False)`. The Alembic logger
sections of `alembic.ini` still configure Alembic as intended. The test suite additionally
resets the `arachne` logger's handlers/level/propagate after every test
(`tests/conftest.py`), so no test can leave global logging state behind.

**Consequences.** ARACHNE keeps logging across an in-process migration, and the suite is
order-independent. Recorded as an S2 fix to S1 code; no requirement changed.

---

## Requirements touched by S2

| Requirement | Where |
|---|---|
| F-01-01 target definition (domains, CIDR, URLs, Git, cloud, exclusions, attestation) | `core/target.py` |
| F-01-02 explicit scope; out-of-scope discovery discarded, logged, never reported | `core/safety.py`, `core/orchestrator.py`, `core/lifecycle.py` |
| F-01-03 ordered pipeline (recon → discovery → checks → analysis → correlation → reporting) | `core/planner.py` (`ScanStep`, `DEFAULT_PIPELINE`), `core/lifecycle.py` |
| F-01-04 resumable and inspectable scans | `core/lifecycle.py`, `data/scan_store.py`, migration `0002` |
| F-01-08 audit log of every request and every blocked request | `core/audit.py` (actions, `build_auditor`), `core/http.py` (S1), `core/orchestrator.py`, `core/lifecycle.py` |
| F-01-09 safety gates: active-check opt-in + authorization | `core/target.py`, `core/orchestrator.py`, `core/planner.py` |
| F-01-10 dry-run/plan mode with estimated request counts | `core/planner.py`, `core/catalog.py`, `cli/scan.py` |
| F-08-05 authorization attestation (who/scope/when) in report and audit log | `core/target.py`, `core/orchestrator.py` |
| F-07-01 `arachne scan --target ... [--dry-run]` | `cli/scan.py`, `cli/main.py` |
| `02-` §2.1 Orchestrator + typed event bus | `core/orchestrator.py`, `core/events.py` |

Not in S2 (by design): the scheduler (F-01-05, S11), concurrency (F-01-06), the module
registry and M1 (F-02, S3), the analyzer (S5/S9), report rendering (S8), the REST API and
webhooks (S12). Nothing in S2 performs a network request: no detection module is
registered, so a live scan executes the offline `recon`/`discovery` handlers only.
