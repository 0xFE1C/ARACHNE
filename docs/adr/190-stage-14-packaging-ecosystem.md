# ADR-190 — Stage 14: packaging & ecosystem

> **Owner:** ARACHNE architecture group · **Last verified:** 2026-11-05 · **Review interval:** 1825 days

Status: accepted (S14, roadmap Phase 5 stretch)

This stage turns a working scanner into a deployable one and opens its extension points to
third parties. Five goals were in scope: container packaging (F-07-04), multi-tenancy
(F-07-06), CVE/EPSS ingestion (F-09-03), plugin installation for checks **and report
formats** (F-09-01), and white-label reporting for MSSPs.

---

## 190.1 — Three extension tables and two nullable columns

The migration `0004_projects_and_feeds` adds:

* `projects` — the tenant/workspace row (slug, name, description, `scope_json`,
  `branding_json`);
* `feeds` and `feed_entries` — an ingested artefact's provenance and its normalised rows;
* `targets.project_id` and `scans.project_id` — nullable FKs with `ON DELETE SET NULL`.

`NULL` is load-bearing: every row written before S14 reads as the implicit **default**
workspace, and deleting a project detaches its evidence instead of destroying it. A
single-tenant deployment therefore behaves exactly as it did before, and no data migration
is required (a migration that rewrote existing rows would be a much riskier change for a
stretch stage).

The two columns are added with `batch_alter_table` because SQLite cannot
`ALTER TABLE … ADD CONSTRAINT`; the same op emits a plain `ALTER TABLE` on Postgres, and
`alembic check` stays clean on both model and migration.

## 190.2 — Tenancy is one project per request, enforced by filtering

There is no "all projects" view. Every API/UI request resolves exactly one project:

* `X-Project` (or `?project=`) selects it; it defaults to `default`;
* an API key may be **bound** to a project with a fourth entry field
  (`label:role:secret:project`). A bound key cannot name another project (403), and
  `authenticate` returns the binding on the `Principal`, so no route can forget it;
* every list is filtered by it (`list_scans`, `list_targets`, `finding_rows`,
  `scan_trend`), and every single-resource route checks ownership. Another tenant's scan is
  **404**, never 403 — existence itself is information.

The scope gate is applied in layers, narrowest last: the target definition, the deployment
allowlist (`ARACHNE_SCOPE_*`), then the project's scope. A tenant can never widen what the
deployment allows; the deployment can never widen a tenant. The project gate is audited as
`scope.rejected` with `origin = "project scope"`, so a cross-tenant attempt is visible.

Known limit: schedules are deployment-wide (`ARACHNE_SCHEDULER_STATE` is one JSON file), so
a scheduled scan runs in the default workspace. Per-tenant scheduling is a natural next
step, not part of this stretch stage.

## 190.3 — Report formats are a registry, not an `if` chain

`REPORT_FORMATS` was a tuple and `render_report` an `if` chain: a third-party format meant
patching the core. S14 replaces both with `arachne.report.formats`:

* a `ReportFormat` is `name + renderer + media_type + binary + aliases + origin`;
* built-ins (`md`, `html`, `json`, `pdf`) are registered first;
* a plugin registers under the **`arachne.report_formats`** entry-point group;
* a duplicate name or alias is **refused**, never overridden — a report's format must not
  depend on which packages happen to be installed.

The renderer receives the same immutable `ReportData` DTO as the built-ins, so a plugin
cannot disagree with the core about a severity (ADR-06 still holds). A binary format
returns `bytes` and declares `binary=True`; the API sets the media type from the registry
and the CLI writes bytes. The API no longer restricts `?format=` with a regex — it asks the
registry and answers 400 listing what is installed.

`REPORT_FORMATS` is kept as the built-in tuple for compatibility; `report_formats()` returns
the resolved spellings.

## 190.4 — The plugin installer is the second asserted `subprocess` call site

Installing a plugin is running `pip`; there is no honest way around starting a process.
`arachne.plugins.installer` is therefore the second module allowed to import `subprocess`
(the first is `report/pdf_backend.py`, ADR-180), and
`tests/unit/test_http_hygiene.py` asserts the same four properties from the AST:

1. the executable is `sys.executable`, never a program named by input;
2. an argv sequence, never a command string;
3. no `shell=` keyword at all;
4. a timeout is always set.

Input validation is part of the contract: a source must be an existing package directory
(with `pyproject.toml`/`setup.py`), a wheel/sdist, or a git URL (`git+https://`,
`git+ssh://`, `git+file://`, scp-like `git@host:path.git`). Anything beginning with `-` is
refused, because pip would read it as an option. `--no-build-isolation` is exposed for an
offline host; the container image ships `hatchling`/`setuptools` so a local-path install
works with no network.

**API installation is off by default** (`ARACHNE_PLUGIN_INSTALL`): a remote admin should
not be able to mutate the running environment without a deployment decision. The CLI always
works — an operator at a shell has already made that decision. After installing, discovery
re-runs and the command reports what appeared; long-lived processes are told to restart,
because entry points are read at process start.

## 190.5 — The marketplace is data

`templates/marketplace/index.yaml` is a versioned catalogue (`ARACHNE_MARKETPLACE` points at
another one). It is read-only data: it names a source and the entry-point group and nothing
else. The `installed` flag is computed from installed **distribution** names (PEP 503
normalisation), which is the honest test; `arachne plugin list` remains authoritative for
what the process can actually see.

Both shipped entries are real packages in this repository, so the marketplace demo works
offline. Adding an entry is a data edit; no code changes.

## 190.6 — Feed ingestion normalises to what M6 already reads

`FeedStore` validates an EPSS CSV / CISA KEV JSON / CVE snapshot and writes a normalised
artefact whose shape is exactly what `ARACHNE_M6_EPSS_FEED` / `ARACHNE_M6_KEV_FEED` consume.
The rows are also persisted (`feed_entries`) so lookup and provenance do not re-read a
200k-line file.

The composition root closes the loop: `build_handlers(..., feeds=…)` resolves the newest
feed of each kind and passes its path into `ModuleConfig`, so an imported feed is used by the
next scan with **no environment change**. The module layer still reads a path, never the
data layer, and a broken feed store degrades to the configured path instead of stopping a
scan.

Ingestion makes **no network call**. A URL recorded as `source` is provenance only; fetching
is the operator's job (`curl`), which keeps the scanner's egress rules (ADR-05) intact and
the workflow usable on an air-gapped host. `feeds.max_entries` bounds one import.

## 190.7 — Branding rides on the DTO; the schema is 1.1

White-label presentation is a `Branding` value on `ReportData`, not a renderer argument, so
every format of one report carries the same branding. `REPORT_SCHEMA_VERSION` is bumped to
`1.1` and `templates/report/report-schema-1.1.json` is regenerated (the `1.0` file stays for
consumers of older documents).

The default `Branding()` renders **byte-identical** output to the pre-S14 renderers: the
Markdown/HTML additions are guarded by `is_customised()`, and the only unconditional change
is `product_name` (default `"ARACHNE"`) replacing a literal. Colours and the logo URL are
validated at construction (hex colour; `https`/`http`/`data:image`), so a stylesheet
injection through a colour is impossible. `merge_branding` treats pydantic defaults as
"unset", letting a project override a few fields over a deployment default.

## 190.8 — Docker: one image, three roles, an offline demo

`docker/Dockerfile` builds one image; compose selects the role with the command (`migrate`,
`api`, `worker`, `scan`). The demo stack brings up Postgres, migrates, runs a real
heuristic scan against the bundled recorded fixtures (`docker/demo/`, copied into the image)
and renders Markdown + HTML into the `reports` volume — so `docker compose up` proves an
end-to-end scan on a host with no outbound network.

`docker-compose.prod.yml` is the secrets overlay: `POSTGRES_PASSWORD_FILE` for the database
and `ARACHNE_API_KEYS_FILE` for the API, plus `ARACHNE_DATABASE_PASSWORD_FILE`, which the
settings layer reads and injects into the URL (a new, small feature: secret files were
already supported for API keys, not for the database). Neither value enters the environment
or `docker inspect`. TLS is required in the overlay; the demo passes `--insecure` explicitly
because it publishes a loopback port.

Postgres support is an extra (`.[postgres]` → `psycopg[binary]`); the image installs it, the
default SQLite install does not need it.

## 190.9 — Verification and its limits

* `pytest -m "not perf"`: all green (see the acceptance evidence for the count).
* The plugin-install proof is an **actual pip install** of real wheels built from
  `examples/plugins/`, into a temporary `--target`, followed by entry-point discovery and a
  render — no core change, no monkeypatching of discovery.
* The compose-equivalent scan is executed locally
  (`tests/integration/test_s14_e2e.py`) with a socket guard that fails the test on any real
  connection.
* **Docker itself could not be executed in this environment**: the client is installed but
  the daemon socket is not accessible to the build user and the compose plugin is absent.
  The compose files are validated structurally (services, volumes, secrets, loopback-only
  lab publication, health check, dependency order) and every command the demo runs is
  exercised outside Docker. This is an environment limitation, recorded rather than papered
  over; the Dockerfile's install path was also reproduced outside Docker in S1.

## 190.10 — What this stage deliberately does not do

* **No per-tenant scheduling.** The scheduler state is one JSON document; a `project` field
  on `ScheduleSpec` is the obvious follow-up.
* **No per-tenant API key management UI.** Keys are still environment/secret-file entries;
  the binding is a fourth field.
* **No feed download.** Ingestion is offline by design; fetching a feed is an operator
  action.
* **No report-format sandbox.** A plugin renders in-process, with the scanner's privileges.
  That is the same trust level as a check plugin, and is why installation is an explicit
  operator action.
* **No Postgres integration test.** SQLAlchemy models stay portable and the migration
  round-trips on SQLite; a live Postgres run belongs in the compose CI job, which this
  environment could not execute.
