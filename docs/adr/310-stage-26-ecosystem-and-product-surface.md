# ADR-310 — Stage 26: ecosystem & product surface (area ECOS)

> **Owner:** ARACHNE architecture group · **Last verified:** 2026-11-05 · **Review interval:** 1825 days

- **Status:** accepted (S26)
- **Requirements:** REQ-ECOS-001...006
- **Phase/gate:** P6, gate G6 (`historical` spec path `docs/03-delivery-plan.md` §8)
- **Supersedes:** nothing. **Extends:** ADR-190 (packaging & ecosystem), ADR-170 (the API/UI
  split), ADR-130 (one report DTO), ADR-300 (signed content packs, and the 0011 trade-off this
  migration repeats).

## 310.1 Context

Phase 6 is the platform ceiling. S25 made the platform survive (run anywhere, never lose a
scan, prove the evidence intact). S26 is the other half of the same ceiling — the product
other people extend and use. Four things were missing:

1. a marketplace where a third party ships checks, formats or providers as a **signed pack**
   that is reviewed before a deployment will list it, rather than a package an operator
   installs on trust;
2. a UI an executive and a tenant can actually use — the attack-path graph, an estate
   dashboard, and self-service quality — not just a report viewer;
3. a report that can be delivered in a second language and under the delivery partner's own
   name, per report and per tenant;
4. generated Python and TypeScript clients, so a consumer does not hand-write an HTTP client
   against a moving API.

REQ-ECOS-003 (the CI delivery surfaces) rides along: the gate already existed (S23), and S26
adds the surfaces that put its findings where a reviewer reads them.

## 310.2 Decision: the marketplace review is three independent gates, and lists only on all-pass

`arachne.plugins.review` runs three gates over a parsed pack and returns **one report**:

- **`signature`** — the pack's signature verifies against the deployment's content key
  (`ARACHNE_INTEGRITY_KEY`, via `core.signing.DeploymentSigner`), and — when the deployment
  names trusted key ids — against one of those. An unsigned pack is refused; so is one signed
  by another deployment's key; so is one whose key id is not trusted. A deployment with **no**
  key configured cannot verify, and therefore cannot list (ADR-300.5's "absence is a refusal,
  not a pass" carried to content).
- **`safety`** — every Python member is parsed and walked (see 310.3), and every declared check
  YAML is checked for proof-ladder consistency.
- **`parity`** — the pack says what it is and matches it.

The gates are independent on purpose: they fail for different reasons and an operator needs to
know which. A pack is `listed` only when **all three** pass (`ReviewReport.listed` is
`all(gate.passed)`); there is no partial listing, because a partially-reviewed pack that loaded
would be exactly the substitution attack the pipeline exists to refuse. A pack that does not
even parse is returned as a *rejection report* (`review_pack_bytes` → `_unparseable`), not
raised as an exception: "this pack is hostile" is an outcome to record, while "this file is not
a tar.gz" is a usage error, and only the first is a review.

The parity gate is the anti-substitution one. A pack declares `meta.kind` and
`meta.entry_point_group`, and the two must agree and be a group the platform owns
(`ENTRY_POINT_GROUPS`: `check`/`module` → `arachne.modules`, `report-format` →
`arachne.report_formats`, `provider` → the OSINT provider groups). A pack declaring
`m3.cmdi-oob` is not *adding* a check — it is *replacing* one, silently, with whatever it
likes; so a declared check id that collides with the built-in catalogue
(`templates/plan/check_catalog.yaml`) is refused, as is a declared report format that collides
with `BUILTIN_FORMAT_NAMES`, and a malformed `<module>.<name>` id.

## 310.3 Decision: the safety gate is a policy gate on the AST, not a sandbox

The scan is on the **AST**, not on the text: a text search for `subprocess` misses
`__import__("subprocess")` and flags the word in a docstring; the AST sees the import and the
call as they will actually execute. `scan_python_source` walks for:

- **blocked imports** — `subprocess`, `multiprocessing`, `ctypes`, `pty`, `socket`,
  `telnetlib`, `ftplib`, `smtplib`, `imaplib`, `poplib`, `pickle`, `marshal`, `shelve`, `dbm`,
  `http.client`, `urllib.request`, `urllib.error`, `requests`, `urllib3`, `aiohttp`, `httpx`,
  `paramiko`, `asyncio.subprocess`;
- **blocked calls** by dotted prefix (`subprocess.`, `multiprocessing.`, `ctypes.`,
  `pickle.load*`, `marshal.load*`, `os.remove`/`unlink`/`rmdir`/`removedirs`/`chmod`/`chown`/
  `setuid`/`setgid`, `shutil.rmtree`/`move`, `signal.`, `runpy.`) or by **last component**
  (`popen`, `system`, `spawn*`, `exec*`);
- **bare dynamic code** — `eval`, `exec`, `compile`, `__import__`;
- and **warnings** (non-blocking) for `open`/`input`/`breakpoint`, a write-looking file call,
  and a mutation of `sys.modules`/`sys.path`/`os.environ`.

Two deliberate construction choices:

- The suffix list (`popen`, `system`, `spawn`, …) is written as **last components**, not full
  dotted names, because `tests/unit/test_http_hygiene.py` scans every module's *source text*
  for the shell helpers it bans — a denylist that quoted them verbatim would trip that scan,
  and the policy table would read as the very thing it forbids.
- A file that does not parse is itself a blocking finding (`syntax_error`): "we could not parse
  it" must not look like "we found nothing".

**This is a policy gate, not a sandbox.** The pack still runs in-process afterwards. What the
gate does is raise the cost of shipping a hostile pack and make the honest mistake loud; it
does not confine a determined pack. `docs/security-review.md` §18 states this plainly rather
than implying the pipeline is a sandbox.

The **proof-ladder consistency** check is the declared-content half: a check that declares
`proof: L3` or `L4` (it changes state on a target) without setting
`requires_state_attestation: true` is refused, because it would otherwise be planned and *run*
on the strength of an authorization that never covered a state change (REQ-PROOF-002/004).
That is the "unsafe check" REQ-ECOS-001 names, and it is a property of the declared content,
not of the Python.

## 310.4 Decision: a review verdict is bound to the pack digest

`data/review_store.py` (`PackReviewStore`) records one row per reviewed pack in the
`pack_reviews` table (migration 0012): its identity, digest, signing key, decision and the
full gate report. `is_listed(name, version, digest)` is true only when the **newest review of
those exact bytes** says `listed`.

Binding to the digest is the point: **rebuilding a pack with different content does not
inherit the old verdict.** A review is evidence about a byte sequence, not about a name. That
is what makes "listed only after review" mean something rather than "this name was reviewed
once".

## 310.5 Decision: the load boundary fails closed, and the escape hatch is audited

`arachne packs import` refuses a pack that has no *listed* review for its digest when
`ARACHNE_PLUGIN_REQUIRE_REVIEW` is on — and it is on by default (`true`). The escape hatch for
a lab is `ARACHNE_PLUGIN_REQUIRE_REVIEW=false`, or `ARACHNE_PLUGIN_ALLOW_UNSIGNED=true`; both
are recorded. The same default-off convention S25 set for `--allow-unsigned` is carried here:
importing is the act that *trusts*, so it is the act that demands a review.

The CLI is `arachne plugin review <pack> [--publish] [--allow-unsigned] [--json]`, and its exit
code is **2** on a rejection so a CI job can gate on it; the API is `GET
/api/v1/plugins/reviews`, `POST /api/v1/plugins/review` (admin; `pack` is a host path, not an
upload), and `GET /api/v1/plugins/marketplace`, which now annotates each entry with its review
status. `arachne plugin marketplace` shows the same flag.

## 310.6 Decision: locale is per-report and per-tenant, and the catalogue is structural-only

The report's labels (the 12 numbered section headings, the 9 appendix sub-headings, the
severity names, the per-finding labels, the cover labels and the attack-path table headers) are
translatable, because they are a finite, reviewed vocabulary. `src/arachne/templates/i18n/fr.yaml`
sits beside `en.yaml` with the **same key set**, and a test fails the build if the sets diverge —
a missing key would fall back to English silently, which is the failure the test exists to
catch.

**Narrative prose is out of scope.** The executive-summary paragraphs and the explanatory
sentence under each section still ship in English. They are catalogue-able — it is a translation
pass, not a renderer change — but they are not translated in this release, and the release note
says so rather than implying a complete French product.

The selection is a three-level precedence, per report and never global: `report.locale` on the
DTO (`arachne report --locale fr`, `GET .../report?locale=fr`) wins, then the project's stored
`projects.report_locale`, then the deployment default `ARACHNE_REPORT_LOCALE`. An unknown locale
**falls back to English rather than failing** — a report that refuses to render because of a
language tag is worse than one in English with a note. The report schema is bumped **1.10** (the
top-level `locale` field), generated by `python -m arachne.tools.report_schema`; see 310.11.

Identifiers are never translated: check ids, CWE/CVE/CVSS values, asset names. The
executive-summary counts table is deliberately not translated either — its rows come from
`SeverityCounts.as_rows()`, the canonical vocabulary the machinery matches on, and translating
the row labels while the body computed off them would be two vocabularies for one number.

## 310.7 Decision: white-label is a mode applied by one resolver, not new branding data

`report.branding.resolve_branding(settings, override)` is the **single resolver** the CLI, the
API and the report builder all call: deployment default ⊕ per-tenant branding ⊕ white-label
mode. `white_label()` forces `show_arachne_branding=False` and, when the tenant has not named
its own product, falls the product name back to the tenant's `company_name`.

`ARACHNE_REPORT_WHITE_LABEL=true` is a **deployment** setting: a tenant cannot switch it back on,
which is what makes "our MSSP delivers under our name" a property of the deployed product rather
than a per-tenant suggestion. `Branding` gained **no field** — white-label is a mode applied to
the existing data, not a new set of data, and the pre-S26 per-tenant `projects.branding_json` is
unchanged.

The single-resolver choice also fixed a defect (310.11): `cli/report.py`'s diff-rebuild path had
dropped the branding argument, so a `--diff-with` report lost its white-label presentation. One
resolver means one place to get it right.

## 310.8 Decision: the UI's charts are server-rendered SVG, and the goldens are those SVG/HTML bytes

`api/ui_visuals.py` renders deterministic SVG by hand — no browser, no JS build:
`attack_path_svg` (one row per composed chain, kill-chain stages left→right, a filled node for a
verified hop, a hollow node naming its verifying check for a candidate, a thick ring on the
cheapest break), `posture_trend_svg` (stacked severity bars per scan, with a baseline tick for a
**clean** scan so "scanned and found nothing" is not rendered as "did not scan"), and
`coverage_bars_svg` (pass/fail/gap bands plus a hatched **unmapped** remainder — a framework's
unaddressed controls are the point of the chart). Every label is `html.escape`d: an asset value
is target-controlled.

New pages: `GET /ui/posture` (the executive dashboard) and
`GET /ui/scans/{id}/attack-paths`; `/ui/quality` becomes tenant self-service. The posture page's
control coverage comes from the **newest scan and is labelled with its id** — not averaged —
because coverage is a statement about which checks ran, and averaging it would state something
else.

The golden files under `tests/report_qa/golden/` are the visualization **SVG** and HTML page
snapshots. There is deliberately **no headless browser** in the suite: a pixel gate would add an
installation dependency and flake, and the value of the test is the diff, not a rasterized
comparison. The SVG *is* the screenshot — diffable and reviewable in a pull request. Re-bless
with `ARACHNE_GOLDEN_UPDATE=1 pytest ...`; the blessed run fails on purpose so a blessing never
passes silently.

## 310.9 Decision: quality rows are tenant-scoped, and NULL means deployment-wide

`suppressions.project_id` and `risk_acceptances.project_id` are nullable integers. `NULL` is a
**deployment-wide** row: every row written before S26 keeps NULL, and therefore stays visible to
every tenant — which is precisely why migration 0012 changes no existing behaviour. The store
takes `project_id`/`include_global`; the API gained `?all_projects=true`; the UI page is scoped
to the selected project with `?scope=all` for an MSSP audit view. The tenant always comes from
the **request** (header/cookie), never from the form body — a page that took the tenant from its
own form would let a user forge which tenant's rules they are editing.

These columns are indexed integers, **not** foreign keys (310.11).

## 310.10 Decision: the clients are generated from the live spec and committed

`tools/sdkgen.py` generates `clients/python/arachne_client/` and `clients/typescript/src/` from
the **running application's** OpenAPI document (`create_app().openapi()`), never from a
checked-in file, so the clients cannot describe an API the process does not serve.
`python -m arachne.tools.sdkgen --check` is the drift gate that runs in CI: regenerate and name
any file that differs. The generated clients are **committed**, so a consumer can read them
without running the generator, and CI enforces they match the spec.

Two hard rules are structural and tested:

- both clients require a **non-empty API key at construction**, and every request goes through
  **one** chokepoint that sets `x-api-key` (and `x-project`) — there is no per-method path that
  skips auth;
- a **429** is surfaced as a typed error honouring `Retry-After`, and is **never retried
  blindly**. Contract tests run the generated Python client against a real server and the
  generated TypeScript client live under `node` (native type stripping), asserting
  401-without-key, the happy path, and 429-under-burst; the node test skips cleanly when node is
  absent, and the skip is asserted rather than assumed.

Honest limitation: the generated **types** cover the spec partially. A free-form object, an
array without `items`, a non-string enum, or a `$ref` outside `components.schemas` becomes a
generic JSON type, marked in-source with `# generic JSON:` / `// generic JSON:` so a reader sees
where the type is a placeholder. Nothing is silently mistyped; some things are honestly typed as
"any JSON".

## 310.11 Alternatives considered

- **One combined review gate** — rejected: signature, safety and parity fail for different
  reasons and drive different operator actions; a single pass/fail hides which.
- **A text search for banned constructs** — rejected: it misses dynamic imports and flags
  docstrings; the AST is what executes.
- **A real sandbox for packs** (seccomp/container/separate process) — out of scope for this
  stage; the pipeline is a policy gate and says so (310.3). A sandbox is a stronger, later
  capability, not something to imply here.
- **Binding the review verdict to the pack name** — rejected: a rebuilt pack must not inherit a
  verdict for content it does not have (310.4).
- **Translating the executive-summary prose now** — rejected for this release: it needs a
  translation pass, and shipping machine prose under a language label would be worse than an
  honest English narrative with translated structure.
- **A headless-browser pixel gate over the UI** — rejected: an installation dependency and a
  flake source for a test whose value is the reviewable diff; the SVG is the screenshot.
- **A database-level foreign key on the new `project_id` columns** — rejected; see 310.12.

## 310.12 Consequences

- Report schema goes **1.9 → 1.10** (top-level `locale`); the registered check count, the
  catalogue and the module versions are unchanged (S26 adds no checks). Migration **0012** is
  expand-only, like 0011: three nullable columns (`projects.report_locale`,
  `suppressions.project_id`, `risk_acceptances.project_id`) and one new table (`pack_reviews`).
  An old replica keeps serving through the rollout.
- **The `project_id` columns are indexed integers, not foreign keys.** SQLite cannot ALTER a
  constraint into an existing table (it needs a copy-and-move batch), and the shipped migrations
  run on SQLite, so a DB-level FK would break `alembic upgrade` on the default dialect.
  `ProjectStore.delete` nulls the columns **in the same transaction**, which is where the
  `ON DELETE SET NULL` semantics live — the same trade-off 0011 records for the audit `seq`
  index and its unique index.
- **The report-schema file was regenerated from the model for the first time.** The committed
  `report-schema-*.json` had drifted by hand since roughly 1.8; `tools/report_schema.py` now
  generates it from `ReportData`, and a drift test keeps it honest. The novelty is the generator
  and the gate, not the schema.
- **Two latent defects were found and fixed in stage.** (a) `packs export`'s default content
  roots never resolved: `str(importlib.resources.files("arachne.templates"))` on a *namespace*
  package is a repr, not a path, so the default root was unusable; it is now resolved from the
  package's real location, and `tools/report_schema.py` uses the same fix. (b) `cli/report.py`'s
  diff-rebuild path dropped the branding argument, so a `--diff-with` report lost its
  white-label presentation; the single resolver (310.7) is why it is now correct.
- `Branding` gained no field (310.7): white-label is a mode, not data.
- A deployment that sets nothing new behaves exactly as it did at S25: no `report_locale` and no
  `--locale` renders English byte-identically, and every pre-S26 quality row (`NULL`) is visible
  to every tenant as before.
- **`packs export` gained the pack's self-declaration** (`--pack-kind`, `--entry-point-group`,
  `--check-id`, `--format-name`). This was not optional once the two halves were joined: the
  parity gate reads `manifest.meta`, and `packs export` wrote only `generator_version`, so a pack
  built by the operator's own CLI could never pass review — and with import now requiring a
  listed review, that is a broken supported path rather than a stylistic gap. Omitting the
  options still builds and signs a pack; it simply cannot be listed, which is the honest outcome
  for a pack that declares no provenance. `tests/test_pack_review_safety.py` drives the whole
  flow over the CLI (export → review --publish → import) so the two halves stay joined.
