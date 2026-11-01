# ADR-170 — Stage 12: REST API, Web UI and Webhooks

Status: accepted (S12). Scope: `arachne.api` (new), `arachne.cli.serve`, `arachne.cli.ci`,
the `api`/`webhooks` settings, small additions to `arachne.report`, `arachne.data` and
`arachne.core.orchestrator`.

This stage implements F-07-02 (REST API with API-key auth and roles), F-07-03 (read-mostly
Web UI served by the same process), F-06-06 (webhooks: Slack/Teams/Jira/DefectDojo) and
F-07-05 (CI gate exit codes), under F-08-02 (authN/authZ, TLS by default, audit logging).

## ADR-170.1 — One process, two interfaces; the UI is never a dependency of the scanner

`create_app` builds the JSON API (`/api/v1`) and the web UI (`/ui`) into one ASGI app. The
dependency direction is strictly `api → core/data/report/modules`; nothing in the scanner
imports `arachne.api`, and `arachne.api.app.create_app` is imported lazily by
`arachne.cli.serve` and by tests. A scan run by the CLI or the scheduler therefore works with
no ASGI stack configured, which is 's "the UI is the primary human interface
but never the dependency of the scanner".

Both interfaces read through the same objects (the same `ScanStateStore`, `ApiQueryStore`,
`ReportService`, webhook notifier), so a page and a JSON response cannot disagree.

## ADR-170.2 — Authentication is one API-key scheme with three ordered roles

Keys are configured as `label:role:secret` entries in `ARACHNE_API_KEYS` (`;`-separated) or in
a file named by `ARACHNE_API_KEYS_FILE` (F-08-01: keep secrets out of the process environment
listing). The secret is SHA-256-hashed at load and compared with `hmac.compare_digest`; the
plaintext never lives in the key store.

Roles are ordered (`viewer < scanner < admin`) and a route declares the *minimum* it needs:
viewer reads, scanner also starts/stops scans and reviews findings, admin also manages targets
and deletes. **An empty key set closes the API** — the deny-by-default posture the scanner
applies to scope (F-01-02), applied to its own interface.

The digest is unsalted on purpose: the secret is a high-entropy random token, not a user
password, so a per-key salt would only complicate rotation without changing the attack.

## ADR-170.3 — The web session is the API key in an HttpOnly cookie; CSRF is the htmx marker

A browser cannot set an `X-API-Key` header on a navigation, so `/ui/login` verifies a key and
sets it in an `HttpOnly`, `SameSite=Strict` (and `Secure` when TLS is configured) cookie. The
UI's auth dependency accepts either the header or that cookie, so the capability model is
identical for a human and a script — there is no second token system.

Cookie auth exposes state-changing requests to CSRF, so UI writes require the `HX-Request:
true` header that htmx sets automatically (plus `SameSite=Strict`). A cross-site `<form>` POST
cannot set an arbitrary header, so a forged write is refused before it reaches a handler. The
login POST itself is exempt (it holds no session yet and only sets a credential).

## ADR-170.4 — Rate limiting is a non-blocking middleware in front of every route

The scanner's limiter *waits*; an API must answer `429` and stop. `ApiRateLimiter` is a
per-identity token bucket with an injectable clock and no sleeping, applied in middleware so it
also covers the `401` path. The identity is the presented key's digest when there is one,
otherwise the client address, so an unauthenticated flood is bounded too; the bucket table is
capped so spoofed identities cannot grow memory without limit. `/static` is exempt.

## ADR-170.5 — Async scans: admission is split from execution

A REST request must return before a scan that can take minutes finishes, so `Orchestrator`
gained two methods: `launch` (run every gate, persist the scan, return it `pending`) and
`execute` (run an admitted scan, re-checking scope and attestation). `ScanRunner` schedules
`execute` on the event loop and keeps an in-process task registry.

`stop` cancels the task and marks the scan `aborted` — an existing lifecycle status — so a
stopped scan is resumable from its last completed step, reusing S2's machinery rather than
inventing a cancellation protocol. The registry is in-process: a scan started by another
process is visible in the store but not cancellable through this API, which `is_running`
reports truthfully. A single-process API is the documented single-node deployment.

## ADR-170.6 — Webhook payloads are data-driven, delivered through the shared client, and never fail a scan

`render_payloads` is a pure function of the immutable `ReportData` DTO: it produces one
`WebhookPayload` per configured destination. Prose (Slack/Teams card text, Jira summary and
description) lives in `templates/webhooks/*.txt.j2` (ADR-04, F-09-04); the JSON envelopes are
built in Python so a target-derived title can never break out of the body.

Delivery goes through `ScopedHttpClient` (ADR-05) scoped to exactly the configured endpoint
hosts, so ARACHNE's own outbound integrations are rate-limited and audited like any other
request. A delivery failure is audited (`webhook.failed`) and returned, never raised: a broken
integration must not change a scan's outcome. Jira opens at most `webhooks.max_findings` issues
and only for findings at or above `webhooks.min_severity`.

## ADR-170.7 — The findings review verb records F-05-07 feedback

`PATCH /api/v1/findings/{id}` sets a finding's `status` (the F-05-07 review verb promised to
S12) and, for a false-positive decision, writes an `fp_feedback` row whose key matches
`analyzer.fp.feedback_key` (`check|asset-kind|signature`, dot check id). A decision taken in the
UI therefore adjusts the same confidence threshold a decision taken during a scan would. The
store's `severity`/`confidence` columns stay the analyzer's to write (ADR-02); the API only
transitions `status`.

## ADR-170.8 — Module configuration is read-only over the API

Deployment configuration is environment-driven (F-08-01), so `GET /api/v1/modules` and the UI's
module page *describe* the installed modules and this deployment's effective settings; no
endpoint mutates them. Changing module configuration means changing the environment and
restarting, which keeps one source of truth and no runtime configuration-write path to secure.

## ADR-170.9 — TLS by default at the bind, not just in the docs

`arachne serve` refuses to bind a non-loopback address without a certificate unless `--insecure`
is passed explicitly; loopback development is allowed without a certificate for convenience.
`uvicorn` receives the cert/key when configured, and the session cookie is marked `Secure` when
it is. F-08-02's "TLS by default" is enforced where the socket is opened.

## ADR-170.10 — The CI gate is a pure policy function

`cli.ci` maps a severity count map plus a threshold onto the documented exit codes (0 clean, 1
below threshold, 2 at-or-above) and is unit-tested in isolation. `arachne scan --fail-on NAME`
(or `ARACHNE_CI_FAIL_ON`) applies it after the run and adds a `severities` block to `--json`.
The default is `none` (gate disabled) so an interactive scan keeps its historical exit code; a
pipeline opts in. An `unanalysed` row (a candidate the analyzer has not touched) is not a
confirmed finding and does not trip the gate.

## ADR-170.11 — Interface-side SQL lives in `data/api_store.py`

The report layer may not own SQL, and neither may the API: the findings/target/check/trend
queries the API and the UI need live in `arachne.data.api_store` (`ApiQueryStore`) next to the
tables they read, returning plain row dataclasses. A router passes named filters and cannot
synthesize SQL, which keeps the query surface small and reviewable. `SqlTargetStore` gained
read methods (`list_targets`/`get_target`) and a `TargetRecord.to_definition`, so a stored
target is re-runnable without a schema change: the declared selectors are already in
`scope_json` and the attestation in `auth_attestation`.

No migration is required for S12 (`alembic check` stays clean): nothing was added to the schema.

## ADR-170.12 — The vendored htmx runtime

The UI uses htmx for progressive enhancement. The minified runtime is vendored at
`templates/web/static/htmx.min.js` rather than loaded from a CDN, so the interface works in an
air-gapped deployment (.1) and a page load never contacts a third party. There
is no Node build step; the CSS is one hand-written stylesheet.

## ADR-170.13 — Shared report helpers moved into the report package

`module_versions_for` and `not_run_checks` were `cli/report.py` privates; the API needs the same
two (the cover's module versions and the "opt-in check did not run" note), so they moved to
`arachne.report.builder` with thin aliases kept in the CLI. `ReportService` wraps
`build_report_for_scan` once for both interfaces, so `GET /scans/{id}/report` and
`arachne report` render the same bytes.

## Consequences / gotchas

* The rate limiter and the scan task registry are per-process; a multi-process deployment would
  need a shared store for both (S14's packaging concern).
* A UI write requires the `HX-Request` header; a non-htmx client must send it (the UI's own
  forms are htmx-driven, so this is invisible in normal use).
* The `docs/` spec tree was not modified.
