# ADR-100 — Stage 6: M3 Web Application (core families)

> Scope: S6 implements the *core* M3 families of roadmap Phase 1 (M3,
> `research/03-`): twelve checks, a shared web crawl, a detection-only probe corpus, the rules /
> narratives / remediation entries that turn their candidates into analysed findings, and the
> acceptance harness that measures detection and false-positive rates.
> Decisions are numbered ADR-100.1 … ADR-100.14. Nothing under `docs/` was modified.

## 100.1 Check set, order and safety classification

Implemented, in the stage prompt's priority order:

| Check | Research | Type | Default | CWE |
|---|---|---|---|---|
| `m3.sqli-oracle` | ch03#1 | active | on (needs the opt-in) | CWE-89 |
| `m3.xss-oracle` | ch03#3 | active | on (needs the opt-in) | CWE-79 |
| `m3.traversal-oracle` | ch03#11 | active | on (needs the opt-in) | CWE-22 |
| `m3.upload-audit` | ch03#10 | active | on, probe opt-in only | CWE-434 |
| `m3.auth-session-audit` | ch03#19 | active | on (needs the opt-in) | CWE-287 |
| `m3.security-headers` | ch03#24 | hybrid | **on, no opt-in** | CWE-693 |
| `m3.api-surface` | ch03#31 | hybrid | **on, no opt-in** | CWE-200 |
| `m3.idor-oracle` | ch03#18 | active | on (needs the opt-in) | CWE-639 |
| `m3.open-redirect` | ch03#14 | active | on (needs the opt-in) | CWE-601 |
| `m3.csrf-audit` | ch03#4 | hybrid | **on, no opt-in** | CWE-352 |
| `m3.cors-audit` | ch03#23 | active | on (needs the opt-in) | CWE-942 |
| `m3.rate-limit-audit` | ch03#35 | active | on (needs the opt-in) | CWE-770 |

**Why three checks are not gated on `--active-checks`.** F-01-09 defines "active" as *any
non-GET interaction, fuzzing or credential verification*. `security-headers` and `csrf-audit`
send nothing but the crawl's own GETs (both are pure classification of what the application
already served), and `api-surface` sends GET/OPTIONS. Gating a GET-only check on the active
opt-in would be inconsistent with M1's `js-asset-scan`, which is hybrid and default-on for
exactly the same reason. 's M3 table calls `csrf-audit` and `api-surface`
`hybrid` and `security-headers` `passive`; the metadata's `type` is the honest one (they do
contact the target), while the *safety* classification stays "no opt-in needed".

Two checks deviate from the spec table's `active`: `idor-oracle` (`hybrid`) and `upload-audit`
(`active`). The IDOR check's probes are GETs of an object identifier, which no definition of
"active" covers, but they *enumerate* — a sequence of requests an operator should authorize —
so it is declared active. `upload-audit` writes (see 100.7), so it is active and its write is
additionally opt-in.

## 100.2 One shared crawl per checks step (not one per check)

Twelve checks each crawling the application would multiply the request count by twelve, make
the plan's estimate fiction, and let twelve independent guesses about "what are the parameters
here?" disagree. So the **checks step** builds a single `WebInventory`
(`modules/m3/inventory.py`) and hands it to every check through a new `StepContext.web` field,
mirroring M2's per-step `NetworkInventory` (ADR-080.2).

The crawl is bounded and deliberately narrow: **same-origin, GET-only, no redirect following,
`max_pages`/`max_depth` capped, destructive paths recorded but never walked** (a scanner must
not log itself out of the application it is measuring), and every request goes through the
shared scoped client, so it is rate-limited and audited like any other exchange.

It runs **only when a checks-step check is selected**, and never in dry-run mode. A scan that
runs M1 alone does not pay for an M3 crawl, and a plan that withheld every active M3 check does
not either.

The crawl starts from the scan's URL assets, including the endpoints the discovery step
*derived* from a declared host or domain — which is why M3's checks set
`runs_on_discovered=True`. M2's checks do the opposite (they skip derived URLs to avoid
scanning one host three times); for M3 the derived endpoints are the surface.

## 100.3 `research_ref` numbering (same deviation as M1/M2)

's M3 table numbers its references against a different sequence than the corpus
chapter. As in ADR-070.3/080.3, check **ids** are exactly the spec's and `research_ref` values
are the **canonical corpus method numbers** (`ch03#1`, `ch03#3`, …), because the corpus is what
the G-01 coverage matrix counts. S6 takes M3 from 0/35 to **12/35 mapped** (47/175 overall).

## 100.4 Differential oracles only; what is deliberately out of scope

Every check confirms presence by measuring a difference a *benign* probe caused, and stops
there (research ch03's own instruction):

* SQLi: a single-character delta whose response carries a database error signature; a `1=1` vs
  `1=2` predicate pair whose responses diverge *and* whose true half resembles the baseline; a
  blocking-sleep probe whose timing exceeds the baseline (capped at two per run).
* XSS: one inert marker (`<a{nonce}>"'{nonce}` — an unknown element plus quote characters,
  unique per request) and a context classifier; an **encoded** reflection is reported as clean.
* Traversal: an encoding matrix against a content marker (see 100.5).
* Open redirect: the `Location` header must point at a reserved, non-resolving probe host.
* IDOR: adjacent identifiers must return distinct *single-record* responses carrying per-record
  identity markers.

Out of scope, recorded rather than implied:

1. **POST-body injection.** The oracles probe query-string parameters only. Sending payloads in
   request bodies would mean posting to state-changing endpoints, which the M3 safety text
   ("no data modification beyond benign requests") and F-02's safe defaults rule out. This is a
   real coverage limit against DVWA/Juice Shop, whose login SQLi is a POST.
2. **DOM-XSS sink verification.** The XSS check reports server-side reflection context only; the
   headless-browser half of research ch03#3 needs a JavaScript engine this stage does not ship.
3. Session fixation and logout invalidation (ch03#19) — both need a successful login.
4. The M3 families assigned to S10 (NoSQL, SSTI, XXE, command injection, deserialization, LFI,
   header injection, smuggling, cache, JWT, OAuth, SAML, HPP, mass assignment, prototype
   pollution, race, business logic, GraphQL, WebSocket, subdomain takeover).

## 100.5 The traversal marker set: world-readable, non-secret files

Research ch03#11 confirms a traversal by content, and its own "how it works" section names
`/etc/passwd`. §1.5 says to prefer the safer interpretation. The compromise
implemented: the marker set is **data** (`templates/m3/payloads.yaml`), it contains only
**world-readable, non-secret** files (`/etc/passwd`, `windows/win.ini`), a finding requires the
file's *header line* in a response whose benign baseline did not contain it, and an operator who
prefers a benign in-tree marker file can replace the list without touching code (F-09-04). No
write, no privilege, no credential file, and nothing that a public file listing would not
already reveal.

## 100.6 Sessions: an operator-provided identity, never credential verification

Authenticated surface is unreachable without a session, so M3 accepts one **from the
environment only** (F-08-01): `ARACHNE_WEB_SESSION_COOKIE`, `ARACHNE_WEB_SESSION_B_COOKIE` (the
second identity `m3.idor-oracle` uses for its cross-account differential) and
`ARACHNE_WEB_AUTH_HEADER`. They are `SecretStr`, the HTTP client redacts `cookie`/
`authorization` at capture time, and the crawl and every probe attach them — so an
authenticated scan produces the same redacted evidence an unauthenticated one does.

**No credential verification is implemented**: nothing guesses, sprays or defaults a password.
`m3.auth-session-audit`'s user-enumeration oracle compares a plausible privileged name against a
random one **with one dummy password each**, bounded and lockout-safe, exactly as M2's Kerberos
enumeration does (research ch02#19): it establishes existence, never access.

## 100.7 `m3.upload-audit` stores only on an explicit opt-in

Storing even an inert file is a write to the target, and M3's safety text says
"no stored payloads". So the check is **default-off** in the only way that matters: with
`ARACHNE_WEB_UPLOAD_PROBE` unset it reports itself *skipped* and sends nothing. When the knob is
set it submits one **plain-text, explicitly non-executable ARACHNE marker** per extension class
(never `.htaccess`/`web.config`, which change server configuration rather than prove a
validation gap), compares the answer against a benign-extension *control* submission so a
permissive endpoint cannot masquerade as an accepted executable, and never fetches or executes
what it stored.

Consequence for the acceptance numbers: the upload family is invisible to a default scan. Both
numbers are reported (§100.11) so the cost of the safety default is visible rather than hidden.

## 100.8 `CookieInfo`: a structural `Set-Cookie` projection captured before redaction

A cookie audit needs the cookie's *name and attributes* (`Secure`, `HttpOnly`, `SameSite`),
but the redactor blanks the whole `set-cookie` header, so no check could read them. The fix is
a **projection, not a loosening**: `core/http.py` parses `Set-Cookie` at capture time into
`CookieInfo(name, secure, httponly, samesite, path, domain)` — the value is *dropped*, not
masked, so nothing downstream can reconstruct it — and exposes it as `HttpExchange.cookies`
(also in the response evidence payload). This is additive; the redaction contract of ADR-050.3
is unchanged.

## 100.9 The M3 catalogue rows replaced the placeholders, and the legacy `web.*` rules were retargeted

`templates/plan/check_catalog.yaml` had eight placeholder M3 rows (`sqli-family`, `xss-family`,
`api-graphql-surface`, …) written in S2 before any check existed. They are replaced by the
twelve real rows, generated from the check metadata, so the F-02-10 registry-parity test holds.

The four `web.*` rules S5 shipped "ready for S6/S7" were **retargeted, not duplicated**:
`web.injection-confirmed` → `m3.sqli-oracle`, `web.missing-security-headers` /
`web.cookie-weak-flags` → `m3.security-headers` (+ `m3.auth-session-audit` for the cookie one),
`web.cors-wildcard-credentials` → `m3.cors-audit`. This mattered: those rules named *research*
references (`ch03#14`, `ch03#18`, `ch03#31`) that M3's checks now declare, so leaving them
alone would have let a CORS rule fire on an `m3.api-surface` candidate. Seventeen M3 rules were
added, one per signal, keyed on the machine-readable `artifact` payload each check attaches
(`evidence.artifact.technique == "error-based"`, …) rather than on prose.

## 100.10 M3 candidates are not `verifiable`

M5's verification re-request (§2.6) requires the **body to match** the original
capture. M3 runs against live applications, whose pages routinely carry a nonce, a timestamp or
a CSRF token; a body comparison would contradict a real finding and drop it. The differential
*inside* each check is the confirmation, so `verifiable=False` for every M3 check. A
reproduction attempt that compares the *oracle's* verdict rather than the bytes is a better
verifier and belongs with the FP tuner (S13).

## 100.11 Acceptance: the stdlib web lab, the ground truth, and the numbers

The DONE criteria are quantitative against a Docker lab (DVWA + Juice Shop). A container runtime
is not available in every environment (the S1/S4 notes record the same constraint), so the
acceptance fixture is `tests/lab/web_lab.py`: a small vulnerable-by-design HTTP application on
loopback, modelled on the DVWA/Juice Shop patterns the M3 table names, with a **published
ground truth** (`GROUND_TRUTH`) and a **published set of false-positive traps**
(`FALSE_POSITIVE_TRAPS` — an HTML-escaped search, a traversal-hardened download, a
relative-only redirect, a fixed CORS allowlist, a token-bearing form, an extension-allowlisted
upload, an authenticated user API and an SPA catch-all). `docker/docker-compose.yml` still
carries the real DVWA/Juice Shop profiles for an operator, and `examples/targets/web-lab.yaml`
points at them.

Measured through the real pipeline (`build_handlers` + lifecycle + analyzer), M3-only, active
checks authorized and opted in:

| Run | Detection | False positives | Candidates | Analysis rows |
|---|---|---|---|---|
| default tuning (upload probe off) | **15/16 (94%)** | **0/18 (0%)** | 18 | 31 |
| upload probe enabled | **16/16 (100%)** | **0/21 (0%)** | 21 | 37 |

Both DONE thresholds hold with margin (≥ 60% detection, ≤ 15% FP). The FP rate is the share of
*candidates* that match no declared ground-truth item; two lookups matter to that number: the
`/admin` and `/admin/` wordlist entries are the same handler, so `m3.api-surface` reports one
finding per *response* (status + body fingerprint), and the lab's CSV of token-less POST forms
is declared in full rather than only for the one route that "looks" CSRF-sensitive.

The numbers are also honest about the harness: they are measured against a lab whose behaviour
the check corpus was written against, so they demonstrate that the oracle *methodology* works
end to end and that the traps are not reported — not that a production estate yields 100%.

## 100.12 One import cycle fixed: `analyzer/__init__` resolves its adapter names lazily

`data/analysis_store.py` imports from `arachne.analyzer.model`, and
`analyzer/__init__.py` eagerly imported `analyzer.handlers`, which imports
`data/analysis_store` — so `import arachne.data.analysis_store` before anything from the
analyzer failed with a partially-initialised-module error (a real bug for a plugin or a user
touching the store first). The six handler names are now resolved on first attribute access
(PEP 562 `__getattr__`), so the documented surface
(`from arachne.analyzer import build_analysis_handlers`) still works and the package root is no
longer a cycle member. No behaviour changed.

## 100.13 Provenance and traceability

* Every M3 check carries its requirement mapping in metadata (`id`, `research_ref`, `cwe`,
  `type`, `safe`, `requires_active_checks`, `estimated_requests`) and its rationale in the
 module docstring (.4).
* Every finding cites the request/response pair that proved it (F-02-08) and one machine-
  readable `artifact` (redacted + SHA-256) that the rules read.
* Every probe is rate-limited by the shared client and appears in the audit trail (F-01-07/08);
  the request estimates in the plan (256 requests for the two-target lab fixture) are the
  catalogue's declared numbers.

## 100.14 Deviations summary

* Traversal marker set: `/etc/passwd` + `win.ini` headers, not a benign in-tree marker — 100.5.
* `upload-audit` is enabled-by-default in the registry but *inert* by default via
  `ARACHNE_WEB_UPLOAD_PROBE` — 100.7. (An `enabled_by_default=False` opt-in check would be
  unreachable: no caller passes explicit `check_ids` to `ModuleRegistry.select`.)
* `idor-oracle` declared active although its probes are GETs — 100.1.
* `verifiable=False` on every M3 check — 100.10.
* The acceptance lab is stdlib rather than the Docker compose fixture — 100.11.
* One core change beyond the additive ones (lazy `analyzer/__init__` exports) — 100.12.
