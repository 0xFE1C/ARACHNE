# ADR-180 — Stage 13: Hardening & Polish

> **Owner:** ARACHNE architecture group · **Last verified:** 2026-11-05 · **Review interval:** 1825 days

Status: accepted (S13). Scope: `arachne.analyzer.fp` + `arachne.cli.fp` (the FP tuner,
F-05-07), `arachne.report.html_render`/`pdf`/`pdf_backend` (F-06-02), the remediation catalog
and OWASP map (data), `arachne.i18n` (new), 25 new detection checks across M1–M6, the perf
benchmark, the security review, and the operator/plugin guides.

This stage is where the final acceptance criteria of §9 and the success
metrics of §6 are meant to be met. Two of them are met only in part, and both
shortfalls are recorded below rather than papered over: **G-01 coverage** (ADR-180.1) and the
**security-review sandbox gaps** (ADR-180.6). Everything else is met and evidenced.

---

## ADR-180.1 — Coverage outcome (G-01 / F-05, §9 #5): 82.3%, not ≥ 90%

`arachne coverage` measured **119/175 (68.0%)** at the start of S13. This stage raises it to
**144/175 (82.3%)** by adding 25 checks. The target in the spec — ≥ 90 % — is **not met**, and
this is a deliberate, recorded shortfall, not an oversight.

Per chapter, after S13 (regenerate with `arachne coverage --write coverage_matrix.md`; the
committed `coverage_matrix.md` is current and a staleness test pins it):

| Chapter | Mapped | Total | % |
|---|---|---|---|
| ch01 Passive Recon & OSINT | 15 | 30 | 50.0 % |
| ch02 Active Scanning & Enum | 28 | 30 | 93.3 % |
| ch03 Web Application | 34 | 35 | 97.1 % |
| ch04 Misconfiguration & Exposure | 30 | 30 | 100.0 % |
| ch05 Cloud/Container/Supply-Chain | 21 | 25 | 84.0 % |
| ch06 Automation/Post-Exploit/AI-Era | 16 | 25 | 64.0 % |
| **total** | **144** | **175** | **82.3 %** |

### What S13 implemented (25 checks)

Each is a real, registered check with unit tests (positive + negative) and a catalogue row.

| Module | Check | Method |
|---|---|---|
| M1 | `m1.dns-txt-mining` | ch01#25 DNS TXT mining (SPF/DKIM/DMARC) via the existing `dns` provider |
| M1 | `m1.favicon-hash` | ch01#23 favicon hash matching |
| M1 | `m1.bucket-hunt` | ch01#30 cloud storage bucket exposure hunting |
| M1 | `m1.doc-metadata` | ch01#22 document/EXIF metadata extraction (PDF `/Info`, JPEG EXIF, stdlib only) |
| M2 | `m2.http-fingerprint` | ch02#12 HTTP(S) fingerprinting |
| M2 | `m2.favicon-hash` | ch02#13 favicon hash identification |
| M2 | `m2.ftp-anonymous` | ch02#21 FTP anonymous login (active) |
| M2 | `m2.ssdp-discovery` | ch02#26 UPnP/SSDP discovery (active, UDP opt-in) |
| M2 | `m2.legacy-services` | ch04#22 legacy network services with defaults (Telnet/cleartext, active) |
| M3 | `m3.nosql-oracle` | ch03#2 NoSQL injection (active) |
| M3 | `m3.directory-traversal` | ch03#12 path traversal (active) |
| M3 | `m3.file-inclusion` | ch03#13 LFI/RFI (active) |
| M3 | `m3.crlf-injection` | ch03#15 HTTP header injection / CRLF (active) |
| M4 | `m4.verbose-errors` | ch04#6 verbose error pages & stack traces |
| M4 | `m4.actuator-exposure` | ch04#8 Spring Boot Actuator exposure |
| M4 | `m4.datastore-surface` | ch04#12 internet-exposed databases & data stores |
| M4 | `m4.robots-sitemap` | ch04#23 robots.txt & sitemap information leaks |
| M4 | `m4.wordpress-surface` | ch04#27 XML-RPC & wp-json exposure |
| M4 | `m4.alias-traversal` | ch04#30 directory traversal via misconfigured aliases |
| M5 | `m5.serverless-functions` | ch05#9 unauthenticated cloud functions & Lambda URLs |
| M5 | `m5.managed-datastores` | ch05#20 publicly accessible managed databases |
| M5 | `m5.search-platform-exposure` | ch05#21 Elasticsearch/Kibana/OpenSearch exposure |
| M6 | `m6.template-scan` | ch06#3 nuclei-style template matcher (managed data, no engine/eval) |
| M6 | `m6.exploit-match` | ch06#5 ExploitDB-style N-day matching against an offline index |
| M6 | `m6.credential-hunt` | ch06#17 credential hunting in reachable configs |

They are grouped in one new `hardening.py` per module, wired into each `Mx_CHECKS` tuple, and
recorded in `templates/plan/check_catalog.yaml` (catalogue version bumped 1.3 → 1.4; the
registry↔catalogue drift gate and the count pins in `test_registry.py`/`test_module_contract.py`
were updated to the new totals — 129 built-in checks, 63 active, 11 opt-in).

**Safety-model conformance of the new checks (why they did not break the offline/scope gates).**
Three of the new checks first violated an existing safety invariant, and each was fixed in the
check rather than in the test:

* **`m1.bucket-hunt` derives third-party provider hosts** (S3/GCS/Azure) from the domain, so it is
  now `type="active"`, `requires_active_checks=True` **and** `enabled_by_default=False` — it never
  runs in a default/offline scan, exactly like the cloud module's `m5.bucket-enumerator`
  (ch05#2). A default scan therefore makes no out-of-scope request (the `m2`-scope and dry-run
  gates stay green).
* **`m2.favicon-hash` used a raw TCP GET for an `http://` endpoint**, which opened a real socket
  even in recorded-response (fixture) mode; it now fetches through the shared HTTP client for
  every scheme, so a replayed scan needs no socket.
* **`m1.favicon-hash` emitted a *candidate* for a stock favicon.** Recon identification is an
  *observation*: M1 now yields `info` (ADR-02 — the analyzer decides severity), which also keeps
  the AI/heuristic parity set identical.
* Separately, `m2.favicon-hash` no longer hashes the shared client's *binary-body placeholder*
  (which would have matched the shipped "empty favicon" default and invented a false positive for
  every target with a real image favicon); a binary favicon is recorded as an observation instead.

### What S13 deliberately excluded (31 methods) — and why

| Method(s) | Reason |
|---|---|
| ch01#3 Shodan, #4 Censys, #6 ZoomEye, #7 FOFA | Require a **paid, credentialed** scan-database API and a new OSINT provider + host allowlist. The keyless Shodan InternetDB path is already covered (ch01#5). |
| ch01#10 Reverse-WHOIS, #12 DNS-history, #18 breach data (HIBP/DeHashed/Intelligence X), #19 paste/dark-web | Paid/credentialed third-party feeds, and a legally/privacy-sensitive data class a defensive scanner should not silently ingest. |
| ch01#20 social/professional-network OSINT | People, not assets; outside a scoped asset scan and ToS-restricted. |
| ch01#21 OSINT collection frameworks (SpiderFoot/Maltego/recon-ng) | ARACHNE **is** the collection framework; re-implementing another tool is not a detection method. |
| ch01#24 BGP data analysis | Needs a BGP/RIPEstat provider; low signal for the asset model. |
| ch01#27 package-registry metadata OSINT | Needs a new npm/PyPI provider; deferred (feasible future work). |
| ch01#28 web-archive diffing | Could reuse the existing `wayback` provider; deferred (feasible future work). |
| ch01#29, ch05#22 APK/mobile-binary analysis | The target model has no mobile-binary asset kind. |
| ch02#11 masscan internet-scale scanning, ch06#2 mass-scanning pipelines | **Out of scope by design** — the responsible-use statement and the authorization gate forbid internet-scale mass scanning. |
| ch02#30 credential verification / password spraying | The spraying half is an authentication attack (out of scope); the default-credential half is already `m4.default-credentials` (ch04#10), opt-in and gated. |
| ch03#28 DOM clobbering | Needs client-side JS/DOM execution; a remote scanner cannot confirm it without a browser oracle. |
| ch05#10 SQS/SNS/Kinesis, ch05#19 cross-account trust | Need cloud credentials / signed API access to enumerate; no unauthenticated surface. |
| ch05#18 serverless env-var leakage | A variant of `m5.serverless-functions`; deferred. |
| ch06#1 automated recon/OSINT pipelines | ARACHNE's own pipeline + S11 scheduler **is** this method; a check would be circular. |
| ch06#4 Metasploit automation, #12 LLM fuzzing harnesses, #13 autonomous agentic hacking | **Out of scope by design** — "detects and reports, does not exploit" ( §8). |
| ch06#6 GHDB dorking automation | Already delivered by the M1 dork corpus (`m1.dork-sweep`, ch01#1) plus the S11 scheduler; a separate check would duplicate it. |
| ch06#9 threat-intel/MITRE ATT&CK mapping | **Analysis** (the analyzer's job, ADR-02), not a detection check; the ATT&CK/Sigma mapping ships via `m6.sigma-hunt-rules`. |
| ch06#10 DefectDojo triage/reporting | An integration/reporting concern, delivered by the S12 webhook/DefectDojo exporter. |
| ch06#11 AI-assisted static code analysis | The S9 AI analysis engine covers AI-assisted analysis; a SAST engine is a different product surface. |

### Why 90 % is not reachable honestly

Of the 31 exclusions, **10 are excluded by design** (offensive internet-scale / exploitation /
autonomous-hacking methods that the responsible-use statement forbids) and are not "not yet
done" — they will never be checks. The remaining 21 are paid-feed OSINT, credentialed cloud
enumeration, or methods that need a target-model or browser capability this build does not
have. Even implementing every "feasible" deferral above (ch01#9, #24, #27, #28, ch05#18) would
reach only **149/175 (85.1 %)**. A ≥ 90 % figure would require either buying into the paid
providers or writing checks for methods explicitly out of scope; neither is done. The metric is
therefore reported as **144/175 (82.3 %) with 31 documented exclusions**, per the stage's
"record the shortfall, do not lower the threshold" rule.

---

## ADR-180.2 — The FP tuner is operator feedback, not a filter that hides findings (F-05-07)

 §2.6 asks for three things, and `arachne.analyzer.fp` implements them in the
order an operator wants them:

1. **Verification** — a `verifiable` candidate is re-requested once; a contradiction (404 now,
   signal gone) is *dropped with its reason recorded*, never silently. The outcome is stored so
   a report can explain "we saw it, then we did not" (`analyzer/model.VerificationOutcome`).
2. **Context filters** — placeholder pages, WAF interstitials and login walls *penalise* rather
   than delete, except when the placeholder is the whole substance of the finding.
3. **The tuner** — operator `fp`/`--not-fp` marks become a per-`(check, asset kind, signature)`
   false-positive rate that raises the confidence a finding needs to be reported. The rate is
   read once per analysis run, so analysis stays deterministic for a given feedback state.

Design decisions:

* **Feedback is data with one key.** A mark writes the same `fp_feedback` row whether it comes
  from `arachne fp mark` or the S12 REST `PATCH /findings` (ADR-170.7), so the CLI and the API
  cannot disagree about what an operator said.
* **Thresholds are managed data.** `templates/fp/thresholds.yaml` (version 1.0, `default: 55`)
  ships with an empty `checks` map — a fresh deployment has no feedback and no reason to
  distrust a check. `arachne fp tune --write` suggests values once marks exist;
  `ARACHNE_FP_THRESHOLDS` points a deployment at its own file (F-09-04).
* **Nothing is deleted.** `mark` sets a status and appends feedback; the tuner reads the
  feedback, never the status. A low-confidence finding is a *low-confidence observation*, not a
  hidden one.

---

## ADR-180.3 — The PDF renderer is built in, and the external backend is the exception (F-06-02)

 §4: "generated from the HTML render via headless renderer; page numbers, cover".
`arachne.report.html_render` produces one self-contained HTML file (escaped, no external asset —
a report gets mailed and opened offline). `arachne.report.pdf` then *parses that same HTML back
into blocks* and lays them out two ways:

* **The built-in renderer (default)** is a small, deterministic, dependency-free A4 paginator:
  cover page, wrapped lines and table cells, "page N of M" on every sheet. It needs no browser,
  no system library and no network, so the PDF path works on an air-gapped host and in CI — and
  a golden-file test is possible at all.
* **External backends** (`ARACHNE_PDF_BACKEND=auto`) hand the same HTML to WeasyPrint, headless
  Chromium or headless Firefox for CSS-exact output. They are selected by presence, never
  required; `auto` falls back to the built-in renderer and says so in the returned
  `PdfResult`.

Both paths consume the same HTML, so the two formats cannot drift. `report/__init__.py` exposes
`report_bytes`/`media_type`/`render_report_bytes`, and `pdf` is now a real `ReportFormat`, so the
S1 test that expected an *unknown-format* error was updated to use `docx`, with a new test
asserting the `%PDF-1.4` magic bytes — a legitimate update, recorded here (the previous session
made the same call; the format set genuinely changed).

---

## ADR-180.4 — The remediation catalog covers 133 CWEs; the OWASP map follows it

`templates/remediation/remediation-catalog.yaml` grew to **135 unique CWEs** (176 entries; the
stage target was the top 120) and `templates/report/owasp-map.yaml` gained the matching
CWE→OWASP-2021 rows. The
catalog is keyed by CWE **and** by check id, so a specific check gets specific steps while an
unmapped CWE still resolves to the documented generic fallback. Two CWEs emitted by S13's new
checks (CWE-113 CRLF injection, CWE-497 diagnostic-endpoint exposure) were added in S13 with the
OWASP categories (A03 / A05); the `test_every_emitted_cwe_resolves_to_a_catalog_entry` test is the
gate that keeps a new check from shipping a CWE with no remediation.

---

## ADR-180.5 — Performance (G-06): 50 hosts / 200 endpoints in 27.1 s

`tests/perf/test_perf_scan.py` (marked `@pytest.mark.perf`) builds a synthetic **50-host ×
4-endpoint = 200-endpoint** fixture served entirely in-process (no sockets), runs a heuristic-mode
scan of the web-facing modules (M3 + M4) through the real `Orchestrator`, and measures wall-clock
time.

**Measured: 27.1 s** for 50 hosts / 200 endpoints in heuristic mode (the printed `PERF G-06:`
line). The G-06 budget is < 60 min (§6 #6), so the margin is ~130×.

Honesty about the number: this measures the **pipeline and analysis** cost. It excludes real
network latency (the fixture answers in-process), real target I/O, and rate-limit pacing (the
benchmark raises the rate limits so it measures throughput, not throttling). So 27.1 s is a
*lower bound* on a real scan of that shape, not a prediction of one; the assertion ceiling is a
generous 3600 s so an orders-of-magnitude regression fails while the benchmark stays meaningful.
CI runs `pytest -m "not perf"` so the 28 s benchmark does not slow every build
(`.github/workflows/ci.yml`); it is run on demand.

---

## ADR-180.6 — Security review of the codebase (§5): written, with gaps recorded

`docs/security-review.md` walks the six §5 headings with `file:line` evidence and PASS / PARTIAL /
GAP verdicts. Summary:

* **PASS** — authorization gate (deny-by-default scope + attestation, re-checked at execution),
  rate limiting (per-host + global, re-acquired on every retry and redirect hop), redaction at
  capture time (the HTTP client redacts before an `HttpExchange` exists, and the audit sink
  redacts again), audit of every blocked/out-of-scope request with a reason.
* **PARTIAL** — **sandboxing**: private-IP policy, scheme/host validation and per-hop
  re-validation defeat the rebinding *redirect*, but **resolve-and-pin is not implemented** (a
  small TOCTOU window) and **no network-namespace/container sandbox is enforced by default**
  (the Dockerfile only drops to a non-root user). This belongs to the F-08-03 sandbox work and is
  recorded, not silently fixed. **Dependency hygiene**: `pip-audit --strict` runs in CI (advisory,
  `continue-on-error`), but there is no lockfile and no `osv-scanner`.

### The one `subprocess` exemption, asserted rather than commented (F-08-03)

The PDF path legitimately drives an external headless engine. `tests/unit/test_http_hygiene.py`
is an import-level ban on `subprocess`/`os.system`/`os.popen` across `src/arachne/`; rather than
weaken it, S13 moved the call into **one** module, `src/arachne/report/pdf_backend.py`, and named
it as the sole exemption — exactly as `httpx` is permitted only in `core/http.py`. The test then
**asserts the call shape** from the AST: argv is a sequence built from a module-level template,
`shell` is never passed (so it defaults to `False`), a `timeout` is always set, the executable is
resolved with `shutil.which`, and no value from scanned content can name a program. The HTML is
passed **by file, never by argv**. A pure-Python fallback means a host with no backend binary
still renders a PDF — a scan never fails because an external tool is absent.

Findings from the review (F1–F5 in `docs/security-review.md`): **F1** (plain-text nested-key
redaction gap) and **F2** (Azure `AccountKey` not treated as sensitive) are **fixed**; **F3**
(`Authorization: Basic` / `Set-Cookie` in a *plain-text* body) is recommended-not-committed
(over-redaction risk); **F4** (resolve-and-pin/sandbox) and **F5** (lockfile/osv-scanner) are
tracked limitations.

---

## ADR-180.7 — Redaction fuzz, and the two-pattern assignment fix it forced

 §9 #3 asks for redaction fuzzed against many secret formats.
`tests/unit/test_redaction_fuzz.py` generates and asserts on: bare high-entropy strings,
key-prefixed tokens (AWS/GitHub/Stripe/Slack/Google/OpenAI/Twilio/SendGrid/npm/PyPI), PEM blocks,
JWTs, session cookies, cloud connection strings (Azure `AccountKey`), and `Authorization: Basic`,
each carried inside JSON/YAML/log/header/URL contexts. It asserts the raw secret never survives,
`contains_secret` sees it, and redaction stays linear.

The fuzz found a real gap (**F1**, ADR-180.6): in plain text, an indented non-sensitive outer key
swallowed the inner key (`service:\n  api_key: <secret>` was not redacted). The naive fix —
make the separator horizontal (`\s*[:=][ \t]*`) — fixes the nested case but **regresses
block-style values** (`db_password:\n  hunter2`), because the inline pattern then stops at the
newline. S13 therefore ships **two** patterns: the horizontal inline pattern, plus
`_BLOCK_ASSIGNMENT_RE` for a key at end-of-line whose value is on the next (optionally indented,
optionally `|`/`>` block-scalar) line. Both were verified against the committed behaviour on a
20-case battery: **five previously-leaking cases now redact, and no previously-redacting case
regressed**; `tests/unit/test_redaction.py::test_block_style_assignments_are_redacted` pins the
fixed cases so neither can silently regress.

---

## ADR-180.8 — Documentation: README, operator guide, plugin developer guide (§9 #8)

* `README.md` — refreshed: one-liner, the responsible-use statement (§8, verbatim),
  quickstart, architecture, test/CI summary, the coverage status, and links to the guides, spec
  and ADRs.
* `docs/operator-guide.md` — install, every `ARACHNE_*` variable grouped, dry-run/offline/
  AI scans, reading each report format, the API + web UI, the FP tuner, coverage, scheduling,
  webhooks, troubleshooting, and a copy-pasteable offline demo. Every command and variable in it
  was checked to exist in the code.
* `docs/plugin-developer-guide.md` (F-09-01) — the check contract, the metadata field rules,
  discovery, managed data, tests, the DoD checklist, and a **worked example plugin** shipped at
  `code/examples/plugins/arachne_example_plugin/` (a real `Module` + `ModuleGroup` +
  `[project.entry-points."arachne.modules"]`), verified to register through
  `ModuleRegistry.discover(extra_groups=...)`.

---

## ADR-180.9 — i18n skeleton, English first

`src/arachne/i18n/` adds a minimal, dependency-free externalization seam: a bundled English
catalog (`templates/i18n/en.yaml`, dotted keys), a `Translator` with English fallback, and
`translate(key, *, locale=None, **params)`. Locale resolves from an explicit argument →
`ARACHNE_LOCALE` → `en`; a missing key returns the key with params interpolated and never raises
on a scan path. S13 routes a small set of real report strings (section headings, the
Evidence/Description/Remediation labels) through it with **byte-identical English values**, so
`markdown.py` output is unchanged and every report golden test still passes. Scope is deliberately
narrow — HTML/PDF headings, JSON keys, narrative prose and CLI/API text remain inline — and the
package docstring says so.

---

## ADR-180.10 — Deviations from §9

| Criterion | Status | Note |
|---|---|---|
| #1 offline heuristic scan | met | `arachne scan --dry-run` and a full offline scan work with zero external calls (default scan is offline; ARACHNE_OSINT_ENABLED is off). |
| #2 AI mode (hosted + local OpenAI-compatible + one non-OpenAI) | environment-limited | adapter + parity tests are green with recorded fixtures; a *live* hosted-provider and local-Ollama run needs keys/a running Ollama that this environment does not have (recorded as environment-limited, never faked). |
| #3 report accepted by a security engineer | not runnable here | no human usability session available; the report QA / golden tests (md/html/pdf) pass. |
| #4 FP rate ≤ 15 % | unchanged from S8 | the lab-measured rate stands; S13 adds checks but re-measures only via the existing lab suites (no regression asserted). |
| #5 coverage ≥ 90 % (G-01) | **NOT met — 82.3 %** | 25 checks added; 31 methods excluded with per-method reasons (ADR-180.1). Recorded shortfall. |
| #6 safety tests green | met | `tests/test_safety.py` green; no new egress path. |
| #7 CI green | met | lint, type, unit, integration, parity, report-QA, dependency audit. |
| #8 documentation complete | met | ADR-180.8. |

`RESPONSIBLE USE` is unchanged: ARACHNE detects and reports; S13 added no exploitation, no
internet-scale scanning, and no new egress path.

### Verification (final tree)

* Full suite: **2092 passed, 1 skipped, 0 failed** in ~11.5 min. The one skip is
  `tests/integration/test_ai_live_local.py` (set `ARACHNE_LIVE_OLLAMA=1` to run it against a
  local Ollama).
* Fast gates: `ruff check .` clean, `ruff format --check .` (326 files), `mypy src` (strict,
  180 files), `alembic check` (no drift), `pip-audit --strict` (no known vulnerabilities).
* Perf benchmark (`-m perf`): 50 hosts / 200 endpoints in **27.1 s** (ADR-180.5).
* Coverage: **144/175 (82.3 %)**, committed matrix regenerated and pinned by a staleness test
  (ADR-180.1).
