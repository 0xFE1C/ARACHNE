# ADR 140 — Stage 9: the AI integration layer

> **Owner:** ARACHNE architecture group · **Last verified:** 2026-11-05 · **Review interval:** 1825 days

Stage S9 implements (F-04-01...09) and completes the cross-engine half of
 (G-05). The layer is optional, explicit and swappable; every capability it
adds already has a heuristic counterpart, and a scan never loses a finding because a model was
unreachable. The decisions below are the ones a later stage must not accidentally undo.

## 140.1 The AI engine is an *anchor*: the deterministic verdict is the one that ships

`AiEngine` (`ai/engine.py`) runs the heuristic engine first and then **enriches** its result:
narrative, remediation (only when no specific catalog entry matched), the model's reasoning and
explanations, a fix order. The finding set, severity, confidence, CWE, verdict and score stay
the heuristic ones unless a check is explicitly declared authoritative
(`ARACHNE_AI_AUTHORITATIVE_CHECKS`, empty by default).

This is what makes a structural property instead of a coincidence: the parity
test compares two engines' outputs for the same candidate and cannot fail because a model
"felt" differently today. An AI assessment that disagrees is *recorded* — in `risk_notes` and in
`analysis.ai.deviation` — so an operator sees it, and the report keeps a reproducible verdict.
For non-deterministic checks (M5/M6, novel combinations per) a deployment can
name the check and the AI verdict is adopted, including an `fp_likely` drop.

## 140.2 Provider egress is a second scope-bound `ScopedHttpClient`

`ai/transport.py` builds a client whose scope is exactly the hosts of the configured provider
`base_url`s (derived, not declared twice), so ADR-05's guarantees — URL validation, per-host and
global rate limits, capture-time redaction, one audit line per attempt — hold for provider
traffic too. `tests/unit/test_http_hygiene.py` still passes because no adapter imports `httpx`.

Loopback and private addresses are allowed **iff** some configured `base_url` is local: the
documented self-hosted path (Ollama, vLLM, LM Studio —) is unusable otherwise,
and deriving the policy from an explicit configuration entry is the same "declaration of intent"
rule the OSINT client uses (ADR-070.4). The target scan's policy is untouched.

## 140.3 Seven adapters, one `plan` → send → `interpret` seam

Every adapter is two functions: `plan(request)` produces the exact URL/headers/body and names
its structured-output mechanism, `interpret(data)` extracts text and usage. The transport is
injected, so a test asserts the bytes without a socket and a provider can be replaced by an
object with one method (`LLMProvider`). The four mechanisms of are selected
per adapter: `json_schema`/`json_object` (OpenAI family), `tool_use` (Anthropic),
`responseMimeType`/`responseSchema` (Gemini), `format` (Ollama) and `guided_json` (vLLM-style
constrained decoding). `custom` is a configuration-defined request template plus a dotted
response path — data, never code, so "support any format" does not become an arbitrary runner.

## 140.4 The JSON schema is derived from the pydantic model, and descriptions are stripped

`ai/structured.py` derives every stage's JSON schema from its pydantic model, so the schema a
provider is given and the validator that judges the answer cannot disagree ("all paths end with
the same validator", §6). `normalize_schema` adds `additionalProperties: false` (strict-mode
requirement) and drops `title`/`description`: a pydantic docstring is written for a maintainer,
our docstrings embed internal commentary, and every description is prompt tokens paid on every
call. Field meaning lives in the prompt template, which is versioned and hashed.

Parsing is tolerant (fences, leading prose, trailing commas, braces inside strings); validation
is not. A parse or validation failure gets the single repair attempt §5 allows, carrying the
validator's complaint, and then degrades the stage.

## 140.5 Prompts are data, and the *store* wraps untrusted content

`templates/ai/prompts/<stage>.yaml` (overridable with `ARACHNE_AI_PROMPTS`) holds the system and
user templates, the schema name, the response format and the untrusted-data limit. The store,
not the template, applies the policy: target content reaches a prompt only
through `[TARGET_DATA]` + `<delim>…</delim>`, with control characters neutralised, `&<>`
entity-escaped, the store's own section markers defanged, and over-limit content truncated with
an explicit marker. The injection instruction is appended verbatim if a template omits it, so a
template author cannot forget it. `prompt_hash` and `template_version` are recorded per analysis
and per audit line (F-03-05, F-04-04).

## 140.6 Token accounting needed one narrow redaction exemption

The capture-time redactor blanks any key containing `token` (ADR-050.3), which blanked every
provider's `usage.prompt_tokens` block — and the per-scan cost budget (F-04-07) cannot work
without those numbers. `redaction.ACCOUNTING_KEYS` exempts a **numeric** value under a fixed set
of accounting key names. A bare number cannot be a credential; pattern redaction of strings is
unchanged; the list is closed. This was found by the vcr cassette test, not by reasoning:
replaying a recorded exchange showed `usage` arriving as `[REDACTED:value]`.

## 140.7 Budget, cache, retries and a circuit breaker live below the engine

`BudgetLedger` enforces a per-scan token and cost cap **before** each call (0 disables either
gate), persists its snapshot in the analysis step's statistics, and exposes `low_water` (80%),
which makes the engine skip `explain`/`remediate`/`narrative` while keeping `triage`.
`RequestCache` is a bounded LRU keyed on stage + template version + model + rendered prompt, with
an optional JSON file so a second scan reuses the first one's answers; hits are never charged.
`RetryingProvider` retries only transient failures (`ProviderError.transient`), honours
`Retry-After`, paces with a per-provider token bucket, and opens a circuit breaker after
`failure_threshold` consecutive failures — without it a dead provider costs `attempts` timeouts
*per candidate*.

## 140.8 The degradation chain is data, not a code path

Every stage call returns a `StageOutcome`; a failed one leaves its part of the analysis at the
heuristic value. An analysis with no successful stage is `provenance.engine = "heuristic"` and
`fallback = "heuristic_fallback:<reason>"`; with some successful it is `engine = "ai"` and
`fallback = "partial:<stage>:<reason>"`. The reason vocabulary is closed
(`provider_error`, `budget_exhausted`, `structured_output_failed`, `privacy_refusal`,
`internal_error`), and each degradation also writes an `ai.degraded` audit line. A report can
therefore never present a degraded analysis as an AI one.

## 140.9 Privacy modes: `local-only` at build time, `redact` by default

`local-only` is enforced when the engine is built (and again per provider resolution), so an
external endpoint in that mode is a refusal, not a logged warning. `redact` tokenizes URLs,
hosts, IPv4 addresses, e-mails and credential shapes into stable `[U1]`/`[H2]`/`[K3]` tokens and
keeps the reverse mapping locally (`Redactor.mapping`, for a local report render); a final
`redact_text` pass catches anything left. The hostname pattern has lookarounds so the scanner's
own vocabulary (`m4.env-file-probe`, `CWE-200`) is not tokenized as a host — an over-tokenized
prompt is both useless and a hint that the rule is wrong. `default` sends evidence as captured
(already secret-redacted by the client) and only on explicit selection.

`assert_no_provider_secrets` refuses a prompt containing a configured credential. It is a hard
error: silently masking it would hide the bug that put it there.

## 140.10 Providers are configured by file, credentials by environment

's `ai:` block loads from `ARACHNE_AI_CONFIG`; each provider names
`api_key_env` and the key is read from the environment only (F-04-02/F-08-01). An inline
`api_key` in the file is rejected by schema validation (`extra="forbid"`). The environment can
override the default provider's `base_url`/`model`/`api_key_env` so a local demo needs no file.
With nothing configured the result is *unconfigured* (`AiConfig.configured is False`) and
`build_ai_engine` returns `None` — which is how F-03-03 stays true by construction.

`AiSettings.engine` and `.privacy` are `None` until the environment sets them: an env default
would otherwise silently override the config file (found when a file's `privacy: local-only` was
ignored in favour of the dataclass default).

## 140.11 Engine selection is per scan, and `ai` is refused at plan time

The analysis handler used to be built around one engine instance, which meant `--engine ai` was
only a label. `EngineResolver` now resolves the engine from `ctx.options.engine` per scan and
memoises it: `heuristic` always works, `hybrid` is the AI engine when one is configured and the
heuristic engine otherwise, `ai` without a provider raises.
`Orchestrator.plan` additionally refuses an explicit `ai` scan when no provider is configured, so
a misconfigured deployment does not spend a scan's requests before discovering it cannot analyse
them. `core` reaches `ai.config` through a function-local import (the same shape as the
module-handler import) to keep the module graph one-directional.

`select_engine("hybrid")` still returns the heuristic engine when no AI engine is passed, so the
S5 test that asserted the old semantics still holds; only its "not available in this build"
message assertion changed (S9 removed that state).

## 140.12 The two batch stages are wired where their inputs exist

`correlate` needs a group, so the correlation handler asks the AI engine for a title/reasoning
when a group reaches `ai.correlate_threshold`, and rewrites **only** the compound's title and
narrative. The compound's existence, contributors and severity remain the correlation engine's
decision, so the finding set is unaffected. `prioritize` needs the whole set, so it runs once
after the analysis pass and its output goes into the step statistics and audit metadata. The
four per-candidate stages (`triage`, `explain`, `remediate`, `narrative`) run in the configured
order (`ARACHNE_AI_STAGES`).

`Analysis.ai` carries the structured stage outputs plus `policy`/`privacy`/`fallback`/`skipped`/
`deviation`; `analysis_log.output_json` therefore holds the model's reasoning as data, which is
what S12's API/UI can render without a second call.

## 140.13 Tests: a scripted provider, a vcr cassette, a real local endpoint

* `tests/helpers/ai.py` — a `FakeProvider` implementing `LLMProvider` (answers per stage,
  identified by the output schema, can fail/garbage on demand) and the engine factory. The stage
  runner, prompt store, budget, cache and merge logic all run for real.
* `tests/fixtures/ai/openai-compatible-triage.yaml` — a **vcrpy cassette** recorded against the
  in-process endpoint and replayed through the real `ScopedHttpClient`; the recorded URI is
  normalised to `https://model.example` and the credential is filtered, so the cassette is
  portable and contains no key.
* `tests/helpers/ai_server.py` — a stdlib OpenAI-compatible endpoint on loopback, used by
  `tests/integration/test_ai_scan.py` (structured output validated and used; the endpoint killed
  mid-scan; the token cap enforced) and by the whole-scan parity test.
* `tests/integration/test_ai_live_local.py` — an optional live Ollama check, skipped unless
  `ARACHNE_LIVE_OLLAMA=1` and a model is installed. No test in the suite requires a model.

## 140.14 Everything the stage prompt asked for, and where it is proven

| DONE criterion | Where |
|---|---|
| 1. parity green | `tests/parity/test_parity.py` (8 cases, including a whole recorded scan in both modes) |
| 2. AI mode against a local OpenAI-compatible endpoint, structured output validated | `tests/integration/test_ai_scan.py::test_the_stored_analysis_carries_the_models_narrative_and_verdict`, `tests/unit/test_ai_providers.py::test_the_openai_adapter_replays_a_recorded_exchange` |
| 3. provider killed mid-scan → heuristic with provenance marked, scan completes | `::test_killing_the_endpoint_mid_scan_completes_with_provenance_marked`, `::test_a_provider_that_is_down_from_the_start_degrades_every_analysis`, `tests/unit/test_ai_engine.py` (engine level) |
| 4. per-scan cost/token cap enforced | `::test_the_per_scan_token_cap_is_enforced`, `tests/unit/test_ai_budget.py`, `tests/unit/test_ai_engine.py` |
| 5. all tests green | full suite, `ruff`, `mypy --strict`, `alembic check` |

## 140.15 Limitations and notes for S10+

1. **No schema change.** `analysis_log` already had `engine`/`model`/`template_version`/
   `prompt_hash`/`tokens_used`; the new facts live in `output_json` (`provenance.provider`,
   `provenance.fallback`, `ai`). `alembic check` stays clean. `tokens_used` is still written as
   0 — the per-scan ledger is the accounting record, and backfilling a per-row split would
   require a counter the engine does not have (one call can inform several rows).
2. **The AI cache key includes the redacted prompt**, so a second scan with a different token
   mapping misses. That is deliberate: tokens are per-scan, and a cache hit across differently
   tokenized prompts would return answers about `[U1]` from another scan's URL.
3. **Budget is per analysis step, not per process.** A resumed scan gets a fresh ledger; the
   step's statistics are the durable record.
4. **`AiEngine.analyze()` is a synchronous wrapper** for the `Analyzer` protocol. Inside a
   running loop it raises and tells the caller to await `analyze_async`; the step handler does.
5. **A provider that answers non-JSON with HTTP 200** (an HTML error page from a proxy) is a
   `ProviderError` with `transient = (status >= 500)`, so it retries only when it plausibly can
   succeed.
6. **`m4.env-file-probe` and friends stay deterministic.** Do not add M1–M4 checks to
   `ARACHNE_AI_AUTHORITATIVE_CHECKS` without also updating the parity expectation; the default
   empty list is what keeps G-05 true.
7. **The research-corpus coverage matrix is unchanged** (S9 adds no detection check).
