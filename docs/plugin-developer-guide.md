# ARACHNE Plugin Developer Guide

> **Owner:** Ecosystem group · **Last verified:** 2026-11-05 · **Review interval:** 180 days

How to write, register, test and ship an ARACHNE **check** (a detection plugin). This is the
F-09-01 contract: the plugin API is a documented interface plus a discovery mechanism, not a
fork of the scanner.

> **Responsible use.** A plugin extends a scanner for **targets you own or are explicitly
> authorized to test**. A check detects and reports; it must never exploit, weaponize or
> maintain access. See the [README](../README.md) responsible-use statement.

See also: [Operator Guide](operator-guide.md) · [ADRs](adr/).

Two complete worked examples ship with the project:

* [`examples/plugins/arachne_example_plugin/`](../examples/plugins/arachne_example_plugin/) —
  a check plugin (`arachne.modules`);
* [`examples/plugins/arachne_example_report_plugin/`](../examples/plugins/arachne_example_report_plugin/)
  — a report-format plugin (`arachne.report_formats`, §11).

Both are real packages with their `pyproject.toml` entry-point wiring, and both are listed in
the bundled marketplace catalogue.

---

## 1. The model in one paragraph

A check is a `Module` subclass with **validated metadata** and one async generator,
`run(ctx)`, that inspects `ctx.asset` and yields `CheckResult`s. A **module group**
(`ModuleGroup`, ids `M1`..`M6`) is a titled bundle of checks with its own version. The
**registry** (`ModuleRegistry.discover`) loads the built-in groups plus everything installed
under the `arachne.modules` entry-point group. A plugin therefore adds a group (or a single
check class), and the scanner finds it without knowing the plugin exists.

Three rules the framework enforces, so a plugin cannot quietly break the scanner:

1. **Metadata is validated at class-definition time** (`CheckMetadata.__post_init__`). A bad
   id, an unknown target kind, a `research_ref` that is not `chNN#M`, or an `active` check
   that does not require the opt-in fails at import. The same is true of the proof ladder
   (S15): declare `proof="L0".."L4"` (default `L1`). An `L2`+ check must be opt-in
   (`enabled_by_default=False` — the constructor refuses otherwise), and an `L3`/`L4` check
   must additionally set `requires_state_attestation=True`. Capabilities above the declared
   level are refused at the `ctx.proof` boundary (`arachne.proof.access.ProofAccess`).
2. **A check detects; the analyzer decides** (ADR-02). A check yields *candidates* with
   evidence. `CheckResult` has no severity field — severity, confidence, CWE narrative and
   remediation are the analyzer's job.
3. **No check imports an HTTP library** (ADR-05). Every outbound request goes through
   `ctx.http`, `ctx.osint` or `ctx.net`. `tests/unit/test_http_hygiene.py` fails the build if
   any module imports `requests`, `httpx`, `urllib.request`, `urllib3`, `aiohttp` or
   `http.client`.

---

## 2. The fast path: `arachne plugin new-check` (REQ-ECOS-007)

Everything this guide describes is now generated. Read this section, run one command, and come
back only for the parts you actually need:

```bash
arachne plugin new-check m4.header-missing --out ./arachne-check-header-missing
```

It writes a complete, green plugin package:

```
pyproject.toml                              the entry point that registers it (arachne.modules)
src/arachne_check_header_missing/__init__.py the check (AuthorCheck + metadata)
tests/test_header_missing.py                its test: positive fires, decoy stays clean
fixtures/header-missing/positive.json       the recorded response that makes it fire
fixtures/header-missing/decoy.json          the false-positive trap it must stay silent on
mappings/header-missing.yaml                the framework-mapping entry (REQ-DET-002)
docs/header-missing.md                      the docs stub
conformance.yaml                            what `arachne plugin conform` reads
```

Then:

```bash
cd arachne-check-header-missing
python -m pytest tests -q          # 3 passed — before you edit anything
# 1. replace MARKERS with the claim your check actually establishes
# 2. record the response that made you write it as the positive fixture
# 3. keep the decoy a fair trap (a 200 that names the concept and carries no marker)
arachne plugin conform conformance.yaml
```

The generated output passes this repository's gates with **zero edits** — `ruff check`, `ruff
format --check`, `mypy --strict` and the generated test — and the suite asserts that from a
scaffolded tree, so a scaffold that needs fixing fails the build rather than you. Scaffolding
the same id twice is byte-identical, and the scaffold refuses to overwrite a tree it already
wrote unless you pass `--force`.

### 2.1 The conformance kit: the four refusals

`arachne plugin conform conformance.yaml` is what a reviewer runs. It **imports the candidate**,
so it scans the source *first* and refuses a check that uses a capability a plugin is not
granted (a process, a raw socket, dynamic code, FFI, unpickling) **without importing it at all**.
Then it reports one gate per property, and four defect classes are refusals rather than advice:

| Class | Refused when | What to do |
|---|---|---|
| `mapping` | no framework item, an id outside the pinned snapshot, or the mapping entry drifted from the metadata | name ≥1 WSTG/API/CWE/ATT&CK/LLM/ASI item in `check_framework` and regenerate the entry |
| `proof` | L2+ declared without its opt-in, or L3/L4 without the state-change attestation | declare the lowest level at which the claim is decidable; `author_metadata` derives the flags from the level |
| `decoy` | no decoy fixture, or the check fires on it | assign a fair trap and tighten the oracle — an exact token, not a word; not the payload you sent back |
| `evidence` | no finding, or a finding with no verification-relevant evidence | attach the captured exchange (or banner, certificate, artifact) a human could confirm by hand |

Three further defects come free once the check is loaded: a **collision** with a built-in check
id, a **fixture gap** (the check asked for a URL the fixture does not record), and a
**non-deterministic** verdict (two runs disagree). Every message says what to change. The exit
code is 2 for a refusal, so CI can gate on it.

### 2.2 Time from scaffold to a merged check

The target (`05-detection-program.md` §6.3) is **under a day, and ≤2 hours once the author has
done it twice**. What the SDK removes is the day of *reading*: nothing on this path requires
opening the registry, the metadata constraints, the proof model or the report scheme.

Measured on this repository, for a first check with no prior reading, the machinery is seconds
rather than hours — `scaffold_check` writes the tree in well under a second, and the gates over
its output (`ruff check`, `ruff format --check`, `mypy --strict`, the generated test suite) run
in about five seconds together, which is what `tests/unit/test_check_sdk_scaffold.py` asserts
rather than describes. What remains is the part no generator can do: implementing the claim,
recording the response that made you write the check, choosing a decoy that traps the oracle
instead of the author, and the review itself.

## 3. Worked example: a new M4 check

The example below is the real content of
`examples/plugins/arachne_example_plugin/src/arachne_example_plugin/__init__.py` (trimmed
comments; the file is the source of truth).

### 3.1 The check

```python
from __future__ import annotations

from collections.abc import AsyncIterator

from arachne.core.results import CheckResult
from arachne.core.target import TargetKind
from arachne.modules.base import CheckMetadata, Module
from arachne.modules.context import CheckContext

_DEBUG_MARKERS: tuple[str, ...] = ("server-status", "debug:", "x-debug-token")


class ExampleVersionBanner(Module):
    """m4.example-version-banner — reports a status path that leaks a debug banner."""

    metadata = CheckMetadata(
        id="m4.example-version-banner",
        module="M4",
        name="example-version-banner",
        version="1.0",
        title="Exposed debug/version banner",
        description=(
            "Requests /server-status and /debug and reports a response that exposes a debug "
            "banner. Read-only: it never changes state and never submits a payload."
        ),
        research_ref="ch04#7",
        proof="L1",  # the proof ladder: how far the check may go (L0..L4, S15)
        # REQ-DET-002: at least one framework item; the registry refuses a check without one.
        framework=("WSTG-CONF-05", "CWE-489"),
        cwe="CWE-489",
        target_kinds=(TargetKind.URL,),
        severity_hint="medium",
        type="hybrid",  # GET reads only, so no active-checks opt-in is needed
        safe=True,
        verifiable=True,
        estimated_requests=2,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        client = ctx.http
        if client is None:  # dry run: nothing may be sent
            yield ctx.skipped("no HTTP client (dry-run mode)")
            return

        origin = ctx.asset.value.rstrip("/")
        for path in ("/server-status", "/debug"):
            exchange = await client.get(origin + path)  # shared scoped client (ADR-05)
            if exchange.status_code >= 400:
                continue
            body = exchange.body.lower()
            marker = next((item for item in _DEBUG_MARKERS if item in body), None)
            if marker is None:
                continue
            yield ctx.candidate(  # a candidate, never a severity
                f"debug banner exposed at {path}",
                detail=f"HTTP {exchange.status_code} with marker {marker!r}",
                confidence=0.6,
                evidence=[ctx.evidence("http_response", exchange.to_dict(), source=ctx.asset.key)],
            )
```

### 3.2 The module group

A group's id must be one of `M1`..`M6`, and every check it contains must declare that same
`module`. Registering a group with an id that already exists **merges** into it (a plugin can
*extend* a built-in module); a duplicate *check* id is fatal.

```python
from arachne.modules.registry import ModuleGroup

PLUGIN_GROUP = ModuleGroup(
    id="M4",
    title="M4 (example plugin)",
    description="The example-version-banner check, supplied by the plugin guide.",
    version="0.1.0",
    checks=(ExampleVersionBanner,),
    research_chapter="ch04",
    origin="example-plugin",
)
```

### 3.3 The entry-point wiring

The only ARACHNE-specific line in the plugin's packaging is the entry point:

```toml
[project.entry-points."arachne.modules"]
example-version-banner = "arachne_example_plugin:PLUGIN_GROUP"
```

The value may resolve to a `ModuleGroup`, a single `Module` subclass, or a sequence of
either (the registry accepts all three). `ENTRY_POINT_GROUP`
(`arachne.modules.registry.ENTRY_POINT_GROUP`) is `"arachne.modules"`.

### 3.4 Install and confirm discovery

```bash
# In the same environment as ARACHNE. Either install it directly:
pip install -e examples/plugins/arachne_example_plugin

# ... or through ARACHNE's installer, which validates the source, runs pip and then
# re-runs discovery and prints what appeared (F-09-01):
arachne plugin install examples/plugins/arachne_example_plugin --no-build-isolation

arachne module list --module M4        # the check appears under M4
arachne module list --json             # origin and versions are machine-readable
arachne plugin list                    # the installed plugin, its origin and its checks
```

`ModuleRegistry.discover()` merges the plugin group into the built-in `M4` group and records
the merged `origin` (e.g. `builtin+example-version-banner`) so an operator can see where a
check came from. The dry run also lists it:

```bash
arachne scan --target examples/targets/lab-fixture.yaml --dry-run | grep example-version
```

---

## 4. How discovery works

`ModuleRegistry.discover(*, include_entry_points=True, extra_groups=())`
(`src/arachne/modules/registry.py`) does, in order:

1. collects the built-in groups (`M1`..`M6` from `arachne.modules.m1`..`m6`);
2. appends any `extra_groups` passed explicitly (used by tests);
3. loads every installed `arachne.modules` entry point (`importlib.metadata.entry_points`);
4. **merges** groups that share a module id (`_merge_by_module`), built-ins first;
5. sorts by module order and returns a registry.

Failure behaviour to rely on:

* A plugin that **fails to load** raises `ConfigurationError` naming the entry point and the
  exception; discovery does not silently skip it.
* A plugin object that resolves to the wrong type raises `ConfigurationError` ("must resolve
  to a ModuleGroup, a Module subclass, or a sequence of those").
* A **duplicate check id** (two implementations claiming one identity) or a group whose
  checks do not all declare its module id is fatal at registration.

### Selection (what actually runs)

`ModuleRegistry.select(selection, active_checks_allowed=..., check_ids=..., enabled_check_ids=...)`
applies, in order: the scan's module selection (`options.modules`), the check's own
`enabled_by_default` (an opt-in check needs an explicit `--check` mention), and the
active-checks switch (`requires_active_checks` checks are skipped unless the scan opted in
*and* the attestation authorized it).

### Everything is versioned

`ModuleRegistry.check_versions()` returns `{check id: version}` plus `{module id: module
version}`; scan reports record both (F-02-10, "version everything"). Bump a
version whenever a check's behaviour changes.

---

## 5. Check metadata: field rules and validation

`CheckMetadata` (`src/arachne/modules/base.py`) is validated on construction. Required
fields and the rules enforced:

| Field | Type / rule |
|---|---|
| `id` | **Must equal** `f"{module.lower()}.{name}"` (e.g. `m4.example-version-banner`). |
| `module` | `^M[1-6]$`. |
| `name` | kebab-case: `^[a-z0-9]+(?:-[a-z0-9]+)*$`. |
| `version` | free string; recorded in reports (`key` is `Module/name@version`). |
| `title`, `description` | non-empty; operator-facing prose. |
| `research_ref` | `^ch0[1-6]#\d{1,2}(?:-\d{1,2})?$` — a research-corpus method reference. |
| `framework` | **non-empty**, and every item must exist in the pinned snapshot: `WSTG-<CAT>-<NN>`, `API<N>:2023`, `CWE-<N>`, `ATT&CK-T<NNNN>[.<NNN>]`, `LLM<N>:2025` or `ASI<N>:2026`. The registry refuses a check with no mapping (`REQ-DET-002`). A check that sets `cwe` must list it here too. |
| `target_kinds` | non-empty; each a valid `TargetKind` (`domain`, `domain_pattern`, `url`, `ip`, `cidr`, `git`, `cloud`). |
| `cwe` | optional, `^CWE-\d{1,5}$`. |
| `cve` | optional, `^CVE-\d{4}-\d{4,7}$`. |
| `severity_hint` | `info|low|medium|high|critical` — a *hint* for the analyzer's default scoring, never a decision (ADR-02). |
| `type` | `passive|active|hybrid`. **An `active` check must set `requires_active_checks=True`.** |
| `safe` | read-only / no state change. `requires_active_checks=True` with `safe=False` is refused. |
| `verifiable` | whether the analyzer may re-request to confirm (F-05-07). |
| `enabled_by_default` | `False` makes the check opt-in (`--check <id>`). |
| `rate_cost` | `>= 0`; relative cost the planner uses. |
| `estimated_requests` | `>= 0`; the dry-run request estimate. |
| `requires_active_checks` | opt-in gate (F-01-09). |
| `requires_credentials` | Credentials the check needs. Either an env-only **name** (M1's `("github_token",)`, `("shodan_api_key",)`) or, from S19, a **kind** from the vault — `("web",)` / `("smb",)` / `("ssh",)`. A check that declares a vault kind gets its material only through `ctx.credentials` (see §5). |
| `runs_on_discovered` | `True` only if the check runs against its own discoveries (keeps the estimate honest). |

Derived properties: `key` = `module/name@version`; `is_opt_in` = `not enabled_by_default`;
`supports_kind(kind)`.

`Asset.supports(asset)` maps an asset's kind to a `TargetKind` (`Asset.selector_kind`) and
checks membership in `target_kinds`. A check that needs more (e.g. a URL that actually
serves JavaScript) overrides `supports`.

---

## 6. The context a check is given

`CheckContext` (`src/arachne/modules/context.py`) is the only thing a check receives. The
capabilities:

| Attribute | What it is |
|---|---|
| `ctx.http` | The target-scoped, rate-limited, audited client — or `None` in dry-run mode. |
| `ctx.osint` | A separately scoped client for third-party passive sources — or `None`. |
| `ctx.net` | The target-scoped raw TCP/UDP/TLS client (M2) — or `None` in dry-run. |
| `ctx.inventory` / `ctx.web` | Per-step network inventory (M2) and web crawl (M3/M4). |
| `ctx.config` | `ModuleConfig`, a frozen projection of `Settings` (corpus paths, bounds). |
| `ctx.scope` | The compiled scope. |
| `ctx.logger` | A structured logger namespaced to the check. |
| `ctx.asset` | The `Asset` under inspection. |
| `ctx.definition` / `ctx.options` | The target definition and scan options. |
| `ctx.credentials` | **S19:** the credential broker — or `None` when the step wired none. The only way to authenticate. |
| `ctx.web_session` / `ctx.web_baseline` | **S19:** the authenticated web session (or `None`) and the *anonymous* crawl the authenticated one is compared against. |

Result helpers (all produce a `CheckResult` tagged with the check's identity):

| Helper | Status | Use |
|---|---|---|
| `ctx.candidate(title, ...)` | `vulnerable` | A candidate finding; the analyzer scores it. |
| `ctx.clean(title, ...)` | `not_vulnerable` | Asked and found nothing. |
| `ctx.info(title, ...)` | `info` | A non-finding observation. |
| `ctx.skipped(reason)` | `info` (+ `note` evidence) | Could not run (provider off, no applicable asset). |
| `ctx.error(exc)` | `error` | Errors are data; the scan never crashes on a check. |
| `ctx.evidence(kind, payload, source=...)` | — | Redacted, hashed, timestamped evidence. |

Evidence kinds: `http_request`, `http_response`, `banner`, `file_path`, `artifact`,
`tls_certificate`, `note`, `proof`. `Evidence.of` redacts the payload at construction, so the value a
check passes is already safe — pass counts, names, fingerprints and detector names, never a
secret.

### Credentials (S19) — never in a check's hands

A check **never receives a credential**. It receives `ctx.credentials` (a
`CredentialBroker`) and asks it for an outcome:

```python
session = await ctx.credentials.login(client=ctx.http, inventory=ctx.web, url=ctx.asset.value)
if session is None or not session.authenticated:
    return ctx.skipped("no credential established a session")

# Or, for a raw protocol, supply an Authenticator and let the broker hold the secret:
result = await ctx.credentials.authenticate(SmbAuthenticator(ctx.net, service), host=..., port=...)
```

The broker checks the credential's scope against the target (an offer outside it raises
`CredentialScopeError` and sends nothing), reads the material, performs the exchange and drops
it. What comes back is derived state: `WebSession` (authenticated, re-authentications,
authenticated-only URLs, logout verdict) or `ProtocolAuthResult` (attempted, accepted, the
peer's status). The session cookie lives in the HTTP client's cookie jar and the material in
`arachne.creds`; neither is reachable from a check. Declare the kind you need in
`requires_credentials` and make the check opt-in (`enabled_by_default=False`) — a credentialed
check also needs the active-checks opt-in and an attestation.


Side effects: `ctx.record_asset(kind, value, meta=...)` / `ctx.record_host(host)` add a
discovered asset **through the scope guard** (out-of-scope discoveries are discarded and
audited as `scope.discarded`); `ctx.audit(action, ...)` and `ctx.emit(event)` write to the
audit trail and event bus.

For an OSINT check, `require_osint(ctx, provider)` is the single "may I call out to a third
party?" helper — it returns `(access, None)` or `(None, skipped_result)` so every check
reports a disabled source the same way.

---

## 7. Managed data: corpus, wordlists, prompts

Corpora, wordlists, rule/prompt/remediation templates and port/CVE tables are **data, not
code** (F-09-04, ADR-04). A check reads them from `src/arachne/templates/...` and an operator
can replace them with an `ARACHNE_*` override without touching a check:

| Data | Shipped location | Override |
|---|---|---|
| M4 probe corpus / wordlists | `templates/m4/` | `ARACHNE_M4_PROBES` |
| M3 payload corpus / wordlists | `templates/m3/` | `ARACHNE_WEB_PAYLOADS` |
| M2 port catalogue / CVE index / wordlists | `templates/m2/` | `ARACHNE_PORT_CATALOG`, `ARACHNE_CVE_INDEX`, `ARACHNE_WORDLISTS_DIR` |
| M2 CVE-index baseline (generated, S18) / product map | `templates/m2/cve-index-baseline.yaml`, `templates/m2/cve-index-products.yaml` | `ARACHNE_CVE_INDEX_BASELINE` (`off` disables the layer), `ARACHNE_CVE_INDEX_PRODUCTS` |
| M5 / M6 corpora | `templates/m5/`, `templates/m6/` | `ARACHNE_M5_PROBES`, `ARACHNE_M6_PROBES` |
| Dork corpus | `templates/dorks/` | `ARACHNE_OSINT_DORK_CORPUS` |
| Heuristic rules / correlation / narrative / scoring / remediation / FP filters | `templates/{rules,correlation,narrative,scoring,remediation,fp}/` | `ARACHNE_ANALYSIS_RULES`, `ARACHNE_ANALYSIS_CORRELATION`, `ARACHNE_ANALYSIS_NARRATIVE`, `ARACHNE_ANALYSIS_SCORING`, `ARACHNE_REMEDIATION_CATALOG`, `ARACHNE_FP_FILTERS` |
| Sigma rules / EPSS / KEV | `templates/m6/sigma/` etc. | `ARACHNE_M6_SIGMA_RULES`, `ARACHNE_M6_EPSS_FEED`, `ARACHNE_M6_KEV_FEED` |

Since S18 the CVE index a check reads is a **generated baseline merged under the curated
overlay** (`ARACHNE_CVE_INDEX`), the overlay winning on a repeated `(product, cve)`. A plugin
that reads `ctx.config.cve_index` through `m2.support.cve_index_for(ctx)` gets the merged
index unchanged — entries now also carry `kev` (CISA known-exploited) and the index carries
`source` (the feed version a generated layer came from).

The path is threaded from `Settings` → `ModuleConfig` (`ctx.config.m4_probes`,
`ctx.config.m6_probes`, ...). Keep markers and signatures in the corpus, not in the check
body, so a deployment can tune detection without a code change and the data is versioned with
the repository.

---

## 8. Writing tests

Check-level tests use the harness in
[`tests/helpers/checks.py`](../tests/helpers/checks.py): `run_check(module, asset, *, http=...,
osint=..., config=..., web=..., seed=...)` returns `(results, memory)` and wires real
framework machinery (store, bus, auditor, scope) around your check. Related helpers:
`asset_for(kind, value)`, `make_step_context(...)`, `make_osint(...)` (recorded OSINT),
`make_target_client(...)` and `make_m2_harness(...)` (scripted network). M4/M3 checks that
read a crawl use `tests/helpers/m4.py` / `tests/helpers/web.py`.

A focused unit test that runs the example check with **no network**:

```python
from arachne.core.audit import Auditor, MemoryAuditSink
from arachne.core.http import RecordedResponse, ScopedHttpClient, fixture_transport
from arachne.core.safety import Scope, StaticResolver, UrlSafetyPolicy

from arachne_example_plugin import ExampleVersionBanner
from tests.helpers.checks import asset_for, run_check


async def test_reports_a_debug_banner() -> None:
    client = ScopedHttpClient(
        scope=Scope(allowed_hosts=("example.com",)),
        policy=UrlSafetyPolicy(allow_private_ips=True),
        resolver=StaticResolver(("93.184.216.34",)),
        auditor=Auditor(MemoryAuditSink(), actor="pytest"),
        transport=fixture_transport(
            [
                RecordedResponse(
                    "GET",
                    "https://example.com/server-status",
                    200,
                    {},
                    "Server Status: debug: on",
                ),
            ]
        ),
    )
    results, _ = await run_check(
        ExampleVersionBanner, asset_for("url", "https://example.com"), http=client
    )
    candidates = [r for r in results if r.status == "vulnerable"]
    assert len(candidates) == 1
    assert candidates[0].check == "M4/example-version-banner@1.0"
```

`pytest-asyncio` runs in `asyncio_mode = "auto"` (see `pyproject.toml`), so no marker is
needed. Also worth asserting in a plugin's suite:

* the metadata validates and `key` is what you expect (a construction test);
* `ModuleRegistry.discover(extra_groups=(PLUGIN_GROUP,))` merges your checks in;
* an out-of-scope `ctx.record_asset` is discarded and audited as `scope.discarded`;
* a raising `run` becomes `status="error"`, never a crash.

The reusable conventions live in `tests/unit/test_module_contract.py`,
`tests/unit/test_registry.py` and `tests/unit/test_m4_checks.py`.

---

## 9. Rules you must not break

### ADR-02 — checks detect, the analyzer decides severity

A check yields candidates with **evidence**; it never sets severity (there is no severity
field on `CheckResult`) and never writes prose. The analyzer applies rules, scoring,
correlation and narrative, then writes severity back to the finding. This is what makes the
AI/heuristic parity guarantee structural: the finding set is the
deterministic one.

### ADR-05 — no HTTP library imports; use `ctx.http` / `ctx.osint` / `ctx.net`

Every request must flow through a shared scoped client so scope validation, SSRF protection,
rate limiting, redaction-at-capture and audit apply. `tests/unit/test_http_hygiene.py` parses
every source file and fails on `requests`, `httpx`, `urllib.request`, `urllib3`, `aiohttp` or
`http.client`. `ctx.http` and `ctx.net` are `None` in dry-run mode: turn that into a
`ctx.skipped(...)` result, not an error.

### Safe by default

* `active` checks must set `requires_active_checks=True`; F-01-09 gates them on the scan
  opt-in *and* an authorizing attestation.
* Anything beyond a plain GET (a payload, an authentication attempt, a non-GET verb, a
  third-party lookup) carries its own switch and a bound (`estimated_requests`, a pacing
  knob). Prefer differential/read-only oracles; never store a payload on the target (M3
  forbids it except the one opt-in marker) and never brute-force.
* Errors are data: raise nothing a caller must catch. If a check raises, the framework records
  `CheckResult(status="error")` and the scan continues.

---

## 10. Definition of Done checklist

Hold every plugin to this:

- [ ] **Maps to a requirement ID** (F-### / M#-### / a research method); the `research_ref`
      is set and the check appears in `arachne coverage`.
- [ ] **`arachne plugin conform conformance.yaml` passes** — the four refusal classes above, with
      a decoy the check is silent on and evidence a reviewer can confirm by hand.
- [ ] **Typed, reviewed, no `eval`/`exec`, no direct HTTP** outside the shared client
      (`mypy --strict` on `src/`, `tests/unit/test_http_hygiene.py` green,
      `tests/unit/test_no_eval_exec.py` green).
- [ ] **Unit + integration tests pass**; coverage target met (≥ 85% on `src/`, 100% of
      safety-critical paths).
- [ ] **Parity and safety tests still pass** if the check touches analysis.
- [ ] **Documented**: docstring, an example configuration, and the report example updated.
- [ ] **Prompts/templates versioned and committed as data**, not code.
- [ ] **Audit/observability hooks in place** (metrics + structured logs).
- [ ] **No secrets in code, logs or test fixtures.**

Also make sure:

- [ ] The check's `version` is bumped when behaviour changes (reports record it).
- [ ] `arachne module list` shows the check with the right flags (opt-in / active /
      credentials / discovered-assets).
- [ ] `arachne scan --dry-run` lists it and the `estimated_requests` is honest.

---

## 11. Packaging recap

```text
my_arachne_plugin/
├── pyproject.toml          # [project.entry-points."arachne.modules"]
└── src/
    └── my_arachne_plugin/
        ├── __init__.py     # Module subclasses + ModuleGroup
        └── corpus.yaml     # managed data, if any

[project.entry-points."arachne.modules"]
my-checks = "my_arachne_plugin:PLUGIN_GROUP"

[tool.hatch.build.targets.wheel]
packages = ["src/my_arachne_plugin"]
```

The `src/` layout is what the worked examples use: it keeps the importable package separate
from packaging files, so an editable install and a wheel build both behave.

Install it next to ARACHNE, then:

```bash
arachne module list --json      # discovery proof: your check, its version and origin
arachne scan --target <fixture> --dry-run
```

The worked example package is at
[`examples/plugins/arachne_example_plugin/`](../examples/plugins/arachne_example_plugin/).


---

## 12. Report-format plugins

A report format is an output renderer over the **same immutable DTO** the built-in formats
read. The contract is `arachne.report.formats.ReportFormat`:

| Field | Meaning |
|---|---|
| `name` | The CLI/API spelling (`example-csv`); must not collide with a built-in or another plugin. |
| `render` | `ReportData -> str \| bytes`. Consume the DTO; never re-read the store. |
| `media_type` | What the API sets as `Content-Type`. |
| `binary` | `True` for bytes (the API serves them, the CLI writes bytes); `False` for text. |
| `aliases` | Extra spellings (`csv`), also collision-checked. |
| `description` / `origin` | Operator-facing text; `origin` is stamped by discovery. |

The worked example is `examples/plugins/arachne_example_report_plugin/`:

```python
# examples/plugins/arachne_example_report_plugin/src/
#   arachne_example_report_plugin/__init__.py
from arachne.report.formats import ReportFormat
from arachne.report.model import ReportData


def render_csv(report: ReportData) -> str: ...


CSV_FORMAT = ReportFormat(
    name="example-csv",
    render=render_csv,
    media_type="text/csv; charset=utf-8",
    aliases=("csv",),
    description="One row per finding, for spreadsheets and ticket importers.",
    origin="example-report-plugin",
)
```

```toml
[project.entry-points."arachne.report_formats"]
example-csv = "arachne_example_report_plugin:CSV_FORMAT"
```

An entry point may resolve to a `ReportFormat`, a bare renderer callable (which becomes a
text format named after the entry point), or a sequence of either. Discovery merges it with
the built-ins (`md`, `html`, `json`, `pdf`); a duplicate name or alias is **refused**, so a
report's format never depends on installation order.

```bash
arachne plugin install examples/plugins/arachne_example_report_plugin --no-build-isolation
arachne plugin formats
arachne report --scan 7 --format example-csv --output findings.csv
curl -H 'X-API-Key: ...' 'http://127.0.0.1:8080/api/v1/scans/7/report?format=example-csv'
```

Rules that apply to a format plugin as much as a check:

* **No value is invented.** Format what is on the DTO; when a field is absent, say so.
* **Escape target-controlled text** (a finding title can contain a newline or a CSV quote).
* **No network and no subprocess** — `tests/unit/test_http_hygiene.py` enforces the first,
  and the only two `subprocess` call sites in the scanner are the PDF backend and the plugin
  installer.
* **Declare `binary=True`** if you return bytes, or the text façade will raise.
* **Keep it deterministic**: the DTO's ordering is stable, and no renderer may call `now()`.

### Testing a format plugin

```python
from arachne.report.formats import ReportFormatRegistry, ReportFormat
from arachne.report import render_report


def test_my_format_renders(synthetic_report):
    registry = ReportFormatRegistry.discover(extra=[MY_FORMAT])
    text = registry.require("my-format").to_text(synthetic_report)
    assert text.splitlines()[0] == "expected,header"
```

`tests/integration/test_plugin_install.py` is the end-to-end shape: it builds real wheels,
installs them through the production installer and asserts both a check and a format appear
without any core change.

---

## 13. Shipping a pack through the marketplace review pipeline (S26, REQ-ECOS-001)

Installing a wheel (§10, §11) is one delivery path. The other is a **content pack**: a signed
archive a deployment reviews and then accepts, and the only path into an air-gapped estate
(operator guide §34). S26 adds the review that stands between "someone built a pack" and "this
deployment lists it".

A pack reaches a running deployment through four steps: **build → verify → review → import**. The
first three happen on a connected build; the last happens in the estate, and it is the one that
trusts.

### 13.1 Build the content tree

A pack is a gzipped tar with a canonical `manifest.json`, a detached signature over that
manifest's digest, and the content under `content/<kind>/...`. The `<kind>` is the directory name
you pack under (``checks``, ``rules``, ``feeds``, ...), and it is what `manifest.files[].kind`
records. Lay your plugin's content out by kind:

```text
my-pack/
└── checks/
    ├── my_checks.py            # a Module subclass (the same contract as §2)
    └── my_checks.yaml          # the declared checks: name + proof level (+ requires_state_attestation)
```

### 13.2 Pack it, with the parity metadata the review reads

The manifest's `meta` is what the review's **parity** gate reads, so a pack that will be listed
must declare it. `meta` is a build-time argument of the pack builder,
`arachne.resil.packs.build_pack(roots, name=…, version=…, signer=…, meta=…)`:

```python
from arachne.core.config import get_settings
from arachne.core.signing import build_signer
from arachne.resil.packs import write_pack

settings = get_settings()
path, manifest = write_pack(
    "my-pack-1.0.0.tar.gz",
    {"checks": "my-pack/checks"},
    name="my-pack",
    version="1.0.0",
    signer=build_signer(settings),  # the deployment's ARACHNE_INTEGRITY_KEY
    meta={
        "kind": "check",  # or "module" | "report-format" | "provider"
        "entry_point_group": "arachne.modules",
        "checks": ["m4.example-added-check"],
        # "formats": ["example-csv"],     # a report-format pack declares its formats instead
    },
)
print(manifest.digest)
```

The `kind` and `entry_point_group` must **agree** and be a group the platform owns:

| `meta.kind` | allowed `meta.entry_point_group` |
|---|---|
| `check` / `module` | `arachne.modules` |
| `report-format` | `arachne.report_formats` |
| `provider` | `arachne.providers` · `arachne.osint_providers` |

`meta.checks` lists the check ids the pack *adds*, and `meta.formats` the report-format names it
adds. Both must be genuine additions.

> **Note on the CLI.** `arachne packs export` uses the same builder and takes the parity fields
> as options, so a third-party pack can be declared without a build script:
>
> ```bash
> arachne packs export --out my-pack-1.0.0.tar.gz \
>   --name my-pack --version 1.0.0 --content ./content \
>   --pack-kind check --entry-point-group arachne.modules \
>   --check-id m4.example-added-check
> ```
>
> `--pack-kind`, `--entry-point-group`, `--check-id` (repeatable) and `--format-name`
> (repeatable) land in the manifest's `meta`, which is exactly what the parity gate reads, and
> `--json` echoes them back under `declared` so you can confirm before you sign what the review
> will see. Omitting them is allowed — the pack is still built and signed — but it then cannot
> pass parity, so it can be neither listed nor imported. Using the library (`build_pack(...,
> meta=...)`) is equivalent if you prefer to generate the declaration from your own packaging
> metadata.

### 13.3 Verify, then review

```bash
# Does it verify? Installs nothing, so it is safe to run on any build.
arachne packs verify my-pack-1.0.0.tar.gz
# Run the three review gates and record the verdict for these exact bytes.
arachne plugin review my-pack-1.0.0.tar.gz --publish
```

`arachne plugin review` runs **signature**, **safety** and **parity** (operator guide §41) and
lists the pack only when all three pass. `--publish` writes the verdict to the `pack_reviews`
store, so the estate's `arachne packs import` finds a *listed* review bound to the pack's digest.
Exit code is `2` on a rejection, so a CI job can gate your pack the same way.

### 13.4 What the safety gate will refuse

The safety gate parses every `.py` member and walks the AST. **Blocking** (a pack that trips one
is rejected):

- imports of `subprocess`, `multiprocessing`, `ctypes`, `pty`, `socket`, `telnetlib`, `ftplib`,
  `smtplib`, `imaplib`, `poplib`, `pickle`, `marshal`, `shelve`, `dbm`, `http.client`,
  `urllib.request`, `urllib.error`, `requests`, `urllib3`, `aiohttp`, `httpx`, `paramiko`,
  `asyncio.subprocess`;
- calls whose dotted name starts with `subprocess.`, `multiprocessing.`, `ctypes.`,
  `pickle.load*`, `marshal.load*`, `os.remove`/`unlink`/`rmdir`/`removedirs`/`chmod`/`chown`/
  `setuid`/`setgid`, `shutil.rmtree`/`move`, `signal.`, `runpy.`, or whose last component is
  `popen`, `system`, `spawn*`, `exec*`;
- bare `eval`, `exec`, `compile`, `__import__`;
- a member that does not parse as Python.

**Warnings** (recorded, non-blocking): `open`/`input`/`breakpoint`, a write-looking file call, and
a mutation of `sys.modules`/`sys.path`/`os.environ`. A check that needs any of these is a check
that should be a pure reader; review why before you ship.

The same gate checks your **declared checks**: a check that declares `proof: L3` or `L4` must set
`requires_state_attestation: true`, or it is refused — an L3/L4 check changes state on the target,
and it must not be runnable on an authorization that never covered a state change.

**This is a policy gate, not a sandbox.** Your pack still runs in-process after it is listed. Do
not read "listed" as "confined".

### 13.5 Common rejection reasons, and the fix

| Gate finding | Why it fired | Fix |
|---|---|---|
| `signature.unsigned` | the pack carries no signature | sign with the deployment's `ARACHNE_INTEGRITY_KEY` (`--unsigned` is a lab-only exception) |
| `signature.no_key` | the deployment has no content key, so it cannot verify | set `ARACHNE_INTEGRITY_KEY` on the reviewing deployment |
| `signature.invalid` | the signature does not verify — another deployment signed it, or the manifest was edited | rebuild and sign with this deployment's key |
| `signature.untrusted_key` | the signing key id is not in this deployment's trusted list | sign with a trusted key, or add the key id to the trusted list |
| `import.blocked` / `call.blocked` / `call.dynamic_code` | a banned import, call, or `eval`/`exec`/`__import__` | reach the network through `ctx` (the shared client); a plugin does not start processes, unpickle, or use FFI |
| `syntax_error` | a `.py` member does not parse | fix the member; an unparseable pack is a rejection, not a pass |
| `content.state_change_without_attestation` | an L3/L4 declared check omits `requires_state_attestation` | declare it, or lower the proof level |
| `parity.kind_missing` / `parity.group_missing` | no `meta.kind` / `meta.entry_point_group` | declare both (see 12.2) |
| `parity.group_unknown` / `parity.group_mismatch` | the group is not platform-owned, or does not match the kind | use the group that matches the kind (table in 12.2) |
| `parity.check_id_collision` | a declared check id is already in the built-in catalogue | rename yours — a pack adds checks, never replaces one |
| `parity.check_id_malformed` | the id is not of the form `<module>.<name>` (`m4.my-check`) | rename it |
| `parity.format_collision` | a declared report-format name collides with a built-in | rename yours |

### 13.6 Import in the estate

```bash
arachne packs import my-pack-1.0.0.tar.gz     # refuses without a listed review for this digest
```

With `ARACHNE_PLUGIN_REQUIRE_REVIEW` on (the default), the import additionally requires a
**listed** verdict for the pack's exact digest — so rebuild-and-reship with different content does
not inherit an earlier pass. `ARACHNE_PLUGIN_REQUIRE_REVIEW=false` is the lab escape hatch and is
audited.
