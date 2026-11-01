# ADR-120 — Stage 7: M4 Misconfiguration & Exposure

> Scope: S7 implements roadmap Phase 1's M4 module (M4, `research/04-`):
> 23 checks across the exposure, hardening and identity families, the probe corpus they read,
> the encrypted operator secrets manifest, the rules / narratives / remediation entries that
> turn their candidates into analysed findings, and the acceptance harness that measures
> detection and false-positive rates against a lab with planted exposures.
> Decisions are numbered ADR-120.1 … ADR-120.14. Nothing under `docs/` was modified.

## 120.1 Check set, order and safety classification

All 23 checks of the stage prompt, in the order `M4_CHECKS` runs them:

| # | Check | Research | Type | Default | Opt-in | Active | CWE |
|---|---|---|---|---|---|---|---|
| 1 | `m4.security-header-review` | ch04#16 | hybrid | on | – | no | CWE-693 |
| 2 | `m4.cookie-flag-audit` | ch04#18 | hybrid | on | – | no | CWE-614 |
| 3 | `m4.client-secrets` | ch04#14 | passive | on | – | no | CWE-798 |
| 4 | `m4.env-file-probe` | ch04#1 | hybrid | on | – | no | CWE-200 |
| 5 | `m4.vcs-exposure` | ch04#2 | hybrid | on | – | no | CWE-538 |
| 6 | `m4.backup-file-hunt` | ch04#3 | hybrid | on | – | no | CWE-530 |
| 7 | `m4.key-exposure` | ch04#15 | hybrid | on | – | no | CWE-321 |
| 8 | `m4.sourcemap-exposure` | ch04#4 | hybrid | on | – | no | CWE-540 |
| 9 | `m4.api-doc-exposure` | ch04#5 | hybrid | on | – | no | CWE-200 |
| 10 | `m4.debug-endpoints` | ch04#7 | hybrid | on | – | no | CWE-489 |
| 11 | `m4.directory-listing` | ch04#9 | hybrid | on | – | no | CWE-548 |
| 12 | `m4.dashboard-exposure` | ch04#11 | hybrid | on | – | no | CWE-284 |
| 13 | `m4.hidden-endpoint-hunt` | ch04#24 | hybrid | on | – | no | CWE-200 |
| 14 | `m4.staging-exposure` | ch04#25 | hybrid | on | – | no | CWE-1188 |
| 15 | `m4.unauth-api-audit` | ch04#29 | hybrid | on | – | no | CWE-306 |
| 16 | `m4.bucket-exposure` | ch04#13 | hybrid | on | – | no | CWE-732 |
| 17 | `m4.cors-config-review` | ch04#19 | active | on | – | **yes** | CWE-942 |
| 18 | `m4.tls-config-review` | ch04#17 | active | on | – | **yes** | CWE-326 |
| 19 | `m4.email-auth-review` | ch04#20 | passive | on | – | no | CWE-290 |
| 20 | `m4.webdav-verbs` | ch04#21 | active | on | – | **yes** | CWE-650 |
| 21 | `m4.user-enumeration` | ch04#28 | active | on | – | **yes** | CWE-204 |
| 22 | `m4.metadata-ssrf` | ch04#26 | hybrid | **off** | **yes** | **yes** | CWE-918 |
| 23 | `m4.default-credentials` | ch04#10 | active | **off** | **yes** | **yes** | CWE-1392 |

**Why so few checks need `--active-checks`.** F-01-09 defines *active* as a non-GET
interaction, fuzzing, or credential verification. Path probing with GET is none of those, so
the fourteen "does this path exist?" checks are `hybrid` and run by default, exactly as M3's
`security-headers`/`api-surface` do (ADR-100.1). Five checks are declared active and gated:

* `cors-config-review` — sends an `Origin:` matrix (a probe header, not a read of the app).
* `tls-config-review` — opens its own TLS handshakes through `ctx.net` (M2's transport), not
  HTTP reads.
* `webdav-verbs` — OPTIONS/PROPFIND/TRACE. `PROPFIND` is a read verb, but it is a
  non-GET method and the check exists to prove which verbs a server accepts, so it is gated.
* `user-enumeration` — a login `POST` with a dummy password.
* `metadata-ssrf` / `default-credentials` — both active *and* `enabled_by_default=False`.

`m4.db-exposure` (spec ch04#10) is **not implemented as an M4 check**: an internet-reachable
database is an M2 network finding, and itself says "overlaps M2; dedupe by
CWE". Implementing it twice would create exactly the duplicate the dedupe rule exists to
remove. It stays M2's `m2.*-enum` family, and the coverage matrix counts ch04#12 through
those refs, not through a phantom M4 row.

## 120.2 `research_ref` numbering: the spec table drifts, the corpus does not

The M4 table in numbers its references against a different sequence than
`research/04-` from `debug-endpoints` onwards (`ch04#6` vs the corpus's method 7, and so on
through `staging-exposure`/`webdav-verbs`). As in ADR-070.3/080.3/100.3, the check **ids**
are exactly the spec's, and `research_ref` values are the **canonical corpus method
numbers** — the universe G-01's coverage matrix counts. S7 takes M4 from 0/30 to
**23/30 mapped** (70/175 overall, 40.0%), and the seven unmapped methods are named in the
matrix (`ch04#6`, `#8`, `#12`, `#22`, `#23`, `#27`, `#30`).

## 120.3 One shared crawl, one fetch policy, one evidence shape

M4 does not build a second crawler. The checks step already constructs a `WebInventory`
(ADR-100.2); M4 reads it through `modules/m4/support.py`, which re-exports M3's `safe_fetch`,
`exchange_from_page` and `owns_origin` rather than copying them. Every M4 probe therefore:

* goes through the shared scoped client (rate-limited, audited, scope-checked);
* is bounded by `M4Settings.max_paths` (60) per check;
* yields the same `CheckResult`/`Evidence` shape with one machine-readable `artifact`;
* respects `owns_origin` so a per-origin review runs once per origin, not once per URL.

`runs_on_discovered=True` for every M4 check, like M3: the endpoints the discovery step
derived *are* the surface M4 probes.

## 120.4 Existence is proven by a marker, never by a 200

A `200` on `/.env` proves nothing (SPAs answer 200 for every path). Each family has a
content predicate:

* `.env`: assignment lines (`KEY=value`) **and** at least one known secret-shaped key;
* VCS: `.git/HEAD` must read `ref: refs/`, `.git/config` must carry `[core]`;
* backups: a per-extension signature (SQL dump header, `PK\x03\x04` for zips, PHP/JSON shapes);
* keys: a PEM header (`-----BEGIN ... PRIVATE KEY-----`);
* source maps: `"mappings"`/`"sources"` JSON keys;
* API docs: a parseable OpenAPI/Swagger document (the endpoints are then *used*, 120.5);
* debug: a framework marker (`phpinfo()` body, Actuator `_links`, Werkzeug console);
* directory listing: an auto-index `<a href>` table with a parent link;
* dashboards: a body/header fingerprint pair per product;
* staging/hidden: an interest regex on the body, not merely a status.

`m4.hidden-endpoint-hunt` additionally dedupes by `(status, body fingerprint)` so `/admin`
and `/admin/` are one finding (ADR-100.11's lesson).

## 120.5 `m4.api-doc-exposure` is a real producer, not a reporter

The stage prompt requires the parsed OpenAPI document to feed `m3.api-surface`. Implemented
literally:

1. `ApiDocExposure` parses the document (OpenAPI 2/3 `paths`, plus `servers`), records each
   route into the shared `WebInventory` via `inventory.add_endpoint(..., source="api-doc")`,
   and emits each documented route as an asset candidate for the next steps.
2. `modules/handlers.py` sorts `INVENTORY_PRODUCERS` (`{"m4.api-doc-exposure"}`) first in
   the checks step, so a producer always runs before a consumer regardless of registry order.
3. `m3.api-surface` consumes `inventory.endpoints` where `source == "api-doc"` and marks its
   artifact `documented: true` — so the finding says *why* the route was tried.

This is the one cross-module data flow in S7, and it is one-directional (M4 → inventory →
M3), with no import from `m3` into `m4` beyond the support re-exports.

## 120.6 The operator's secrets manifest: masked-only, encrypted at rest

F-08-04 asks for two things at once: findings must not carry usable secrets, and the
operator must still get a usable ledger. The split:

* **Redaction stays the detector.** `core/http.py` masks at capture time, records *which*
  detector fired in `HttpExchange.secret_kinds`, and never hands the raw value to a module.
  M4 evidence carries detector names only.
* **The manifest is fed at the same moment.** `_read_body` calls
  `SecretsManifest.record(kind, masked, source, check)`. The value is masked *where the match
  is made* and the raw match is discarded — the manifest cannot contain a usable secret even
  if the file is stolen.
* **What remains is still sensitive** (which systems hold which credential shapes), so the
  file is encrypted: scrypt(passphrase, 16-byte salt) → 32-byte key; SHAKE-256 keystream with
  a 16-byte nonce; HMAC-SHA256 over magic‖salt‖nonce‖ciphertext (encrypt-then-MAC). Text
  format `ARACHNE-SM-1`, so an operator can see it is ciphertext. Written with
  write-then-rename and `chmod 0600`.
* **Off by default and fail-closed.** `ARACHNE_SECRETS_MANIFEST` unset writes nothing;
  setting a path without `ARACHNE_SECRETS_MANIFEST_KEY` raises
  `"refusing to write an unencrypted secrets manifest"` at startup, not at first secret.
* **Flush is not on the hot path.** `ScopedHttpClient.aclose()` flushes once, and a flush
  failure is logged and swallowed (a scan must not fail because a sidecar file could not be
  written), with the ledger still in memory.

Limit, stated plainly: this is a local sidecar, not a KMS. It protects a stolen file from a
reader without the passphrase; it does not protect against a compromised host while the scan
runs. ADR-050.3's warning still applies — redaction is a net, not a licence.

## 120.7 `POLICY_HEADERS`: one narrow exemption in header redaction

`m4.cors-config-review` must read `Access-Control-Allow-Origin` and
`Access-Control-Allow-Credentials` to judge a policy, but `redact_headers` masked the whole
`access-control-allow-*` family because the value can echo an attacker origin. The fix is a
**named policy exemption**, not a general loosening: `POLICY_HEADERS` (the
`access-control-*` family) keeps its value, and the artifact records it. Nothing else
changes — `set-cookie`, `authorization`, `x-api-key` and friends are still blanked.

Because the redactor blanks any artifact key containing `credential`, the CORS artifact key
is `allows_auth`, and `m3.transport`'s CORS artifact was renamed to match (one contract, two
modules). This is the second deliberate artifact-key rename after ADR-100.8's cookie
projection, and for the same reason: a rule needs the boolean.

## 120.8 Opt-in is three gates, and each one alone is enough to stop a request

`m4.metadata-ssrf` and `m4.default-credentials` are `enabled_by_default=False` **and**
`requires_active_checks=True` **and** behind a config switch. All three must be satisfied:

1. the check id is named (`--check m4.default-credentials`, i.e. `ModuleSelection.checks`);
2. the scan authorized active checks (`--active-checks` + attestation, F-01-09);
3. the deployment switch is on (`ARACHNE_M4_DEFAULT_CREDENTIALS=true` /
   `ARACHNE_M4_METADATA_SSRF=true`).

This required a small but real change to `ModuleRegistry.select`: it gained
`enabled_check_ids` (additive opt-in semantics — naming a check never excludes a default
one) and `modules/handlers.py` passes `options.modules.checks` through. Before S7 no caller
passed `check_ids` at all, which is why ADR-100.7 had to make `upload-audit` inert via config
instead of `enabled_by_default=False`. That pattern is now reachable, and
`tests/test_safety.py` asserts all three gates independently, including that a named but
switched-off check sends **no request at all**.

The two checks' behaviour when they do run:

* `default-credentials`: one paced attempt per detected product (pacing
  `default_credentials_pacing_s`, at most `default_credentials_max_attempts` products),
  against **vendor-default pairs only** (the corpus is data), and the verdict is
  *existence* — a response differential proves the default works, and the check stops. No
  spray, no retry, no user list.
* `metadata-ssrf`: sends the metadata GET only to the provider endpoints in the corpus and
  only through a sink parameter the crawl already exposed; the finding is a **posture**
  statement (IMDSv1-served vs IMDSv2-enforced), not a credential dump. With the switch off
  it reports the sinks it can see and sends nothing.

## 120.9 Bucket probing is wordlist-based and non-destructive

`m4.bucket-exposure` derives names from a declared domain (prefix/suffix combinations from
`wordlists/bucket-names.txt`, capped by `max_bucket_names`) and probes three provider shapes:
an operator-declared endpoint, S3 virtual-host style, GCS `storage.googleapis.com`, and Azure
Blob `*.blob.core.windows.net`. A finding needs a **listing** (a bucket XML/JSON body with
object entries) or an **ACL** read (`AllUsers`/`allUsers` grant), not a bare 200 or 403. The
`endpoint` provider exists so the lab fixture (and an operator's MinIO) can be tested without
touching a real cloud account.

## 120.10 Email authentication is OSINT, through the OSINT client

`m4.email-auth-review` is the only M4 check that does not touch the target's HTTP surface.
It reads TXT records through the OSINT provider layer (`dns` provider → dns.google DoH), which
is a separate scoped client bound to the provider allowlist — so a scan of `example.com`
does not accidentally send DNS queries from the target-scoped client. Artifacts are booleans
and summaries (`spf_permissive`, `dmarc_enforced`), never raw records. SPF `+all`/`?all`,
missing DMARC, and `p=none` are the reported conditions.

## 120.11 Rules, narratives and remediation: M4 candidates become findings

* **Rules**: 23 new M4 rules in `templates/rules/heuristic-rules.yaml`, one per signal, keyed
  on the artifact each check attaches (`evidence.artifact.family`, `.signal`, `.allows_auth`,
  …) rather than prose. The S5-era `web.missing-security-headers` rule was **extended** with
  `m4.security-header-review` in its `check_ref` (not duplicated) — both checks legitimately
  report the same header baseline from different surfaces.
* **Narratives**: 22 new templates with a top-level `rule:` pin so each one is reachable from
  exactly the rule it explains; `when` sections adapt to the artifact (e.g. the CORS template
  has separate branches for reflected-origin-with-credentials vs wildcard).
* **Remediation**: 9 new catalogue entries (directory listing, bucket exposure, private key,
  email authentication, unsafe verbs, metadata SSRF, unauth API, default credentials, staging)
  and `checks:` lists updated on 12 existing entries so every M4 finding has a fix. 48
  entries total.

The three parity tests (`test_rules.py`, `test_narrative.py`, `test_remediation.py`) enforce
that every rule's `check_ref` names a registered check, every narrative's `rule` exists, and
every check with a candidate has a remediation entry.

## 120.12 Dedupe against M2/M3: `(CWE, asset)`, M4 owns exposure

's Deduplication section and S5's correlation step define the key
`(CWE, asset_label)` with owner preference `[M4, M3, M6, M5, M2, M1]`. S7 verifies the
intended collisions rather than assuming them:

* `m4.security-header-review` vs `m3.security-headers` (both CWE-693) → one row, M4 owns it;
* `m4.cors-config-review` vs `m3.cors-audit` (both CWE-942) → one row, M4 owns it.

Two near-misses are deliberately **not** merged, and the CWEs are why: `m4.tls-config-review`
is CWE-326 (inadequate encryption strength) while `m2.tls-deep-scan` is CWE-327 (broken
algorithm) — different root causes, so two findings are correct; `m4.cookie-flag-audit` is
CWE-614 (sensitive cookie without `Secure`) while `m3.auth-session-audit` is CWE-287 (improper
authentication) — the M3 finding is about the session mechanism, the M4 one about the cookie
attribute. Dedupe is by CWE and asset, not by "sounds similar".

The merged rows keep the `drop_reason` "same CWE and asset…". The integration test groups by
`finding_id`, because both the analysis step and the correlation step write a row for a
finding and only the correlation row is the deduped one.

## 120.13 Acceptance: the stdlib lab, the ground truth, and the numbers

No container runtime is available (S1/S4/S6 notes record the same constraint), so the
acceptance fixture is `tests/lab/web_lab.py` extended with the M4 surface the DONE criteria
name — a planted `/.env`, `.git/{HEAD,config,packed-refs}`, `/backup/{db.sql,site.zip}`,
`/index.php.bak`, an auto-indexed `/files`, exposed Jenkins/Grafana/phpMyAdmin, a bucket
endpoint at `/storage/backup`, `/swagger.json`, `/app.js.map`, `/id_rsa`, `/phpinfo.php`,
`/actuator/env`, `/staging`, `/dav`, `/api/internal/users`, `/login` with a user differential,
`/fetch?url=` (SSRF sink) and `/api/config` with a reflecting CORS policy — plus **12
false-positive traps**: denied `.env.local`/`.env.production`, `/backup/safe.sql` (a real SQL
file that is not a backup), a hardened `/files-hardened`, a login-only `/kibana`, a
non-listable `/storage/private`, a healthy `/health`, a hardened key/source-map/WebDAV
surface, an authenticated `/api/orders` and a fixed-allowlist `/api/config-fixed`.

Measured through the real pipeline (`build_handlers` + lifecycle + analyzer), M4-only, active
checks authorized and opted in:

| Run | Detection | False positives |
|---|---|---|
| default tuning (both opt-in switches off) | **27/27 (100%)** | **0/12 traps, 0/27 candidates (0%)** |

The DONE threshold holds with margin. The number is honest about the harness: the lab's
behaviour is what the corpus was written against, so it demonstrates the *methodology* and
that the traps are not reported — not that a production estate yields 100%.

## 120.14 Deviations summary

* `m4.db-exposure` not implemented in M4 (it is M2's, per the spec's own dedupe note) — 120.1.
* `research_ref` uses corpus numbering, not the spec table's drifted refs — 120.2.
* `POLICY_HEADERS` exemption in header redaction, and the CORS artifact key renamed
  `allows_auth` (M3's too) — 120.7.
* `ModuleRegistry.select` gained `enabled_check_ids`; `--check` on the CLI — 120.8.
* `m4.webdav-verbs` and `m4.cors-config-review` declared active although they send only
  read verbs / a probe header — 120.1.
* The secrets manifest is dependency-free (scrypt + SHAKE-256 + HMAC) rather than a KMS — 120.6.
* The acceptance lab is stdlib rather than the Docker compose fixture — 120.13.
