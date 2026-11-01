# ADR-050 · Stage S1 foundation decisions

Status: accepted (S1)
Scope: the repository — the decisions taken while implementing the foundation that later
stages must either honour or explicitly supersede. The architectural ADRs they depend
on are listed in §6 and are not repeated
here; this file records only what S1 had to decide because the spec left it open
(the spec's instruction: prefer the safer interpretation, record the decision, move on).

---

## ADR-050.1 — Scoped HTTP client validates IP literals before scope, and names after

**Context.** `validate_url` must enforce both the scope allowlist (F-01-02) and the
private-address policy (F-08-03). For a hostname these two checks compete: resolving the
name to classify its addresses sends a DNS query, which is itself an outbound act.

**Decision.** For an IP literal, classify the address *first* (so the audit log records
the specific reason — `private-address`, `loopback-address`, `link-local-address`) and
check scope second. For a hostname, check scope first and resolve only afterwards.

**Consequences.** Out-of-scope hostnames generate no DNS traffic, and private literals
are always reported with their specific reason rather than a generic "not in scope".
The cost is that an in-scope hostname that resolves to internal space is caught only at
resolution time — which is why every redirect hop is re-validated (see ADR-050.2).

## ADR-050.2 — Redirects are followed hop by hop, not by the transport

**Context.** `httpx` can follow redirects internally, but then the new URL never passes
through the safety gate: a target answering `302 Location: http://169.254.169.254/`
would pivot the scanner into cloud metadata.

**Decision.** The client sets `follow_redirects=False` on the underlying transport and
implements the redirect loop itself, validating (scheme, scope, addresses) and
rate-limiting every hop, recording the chain in the evidence.

**Consequences.** Every hop is audited and throttled, and the redirect budget
(`ARACHNE_HTTP_MAX_REDIRECTS`, default 5) is enforced. Cost: responses to redirects are
discarded rather than reused, and non-HTTP schemes in `Location` are refused outright.
Full resolve-and-pin (connect to a validated IP with a `Host` header) is *not* yet
implemented; per-hop re-validation covers the rebinding case that matters at this stage,
and the stronger pin belongs with the sandboxed network namespace work (F-08-03).

## ADR-050.3 — Redaction is pattern-based, applied at capture time, and must be linear

**Context.** F-08-04 requires redaction at evidence-capture time. Body text is
target-controlled, so a badly written detector is a denial-of-service vector against the
scanner itself.

**Decision.** Redaction runs when evidence is captured (HTTP client, audit `meta`, log
formatter) and never at render time. Detectors combine (a) fixed secret patterns
(prefixed keys, JWTs, PEM blocks, credentialed URLs, bearer tokens) and (b) a
key-sensitivity rule that redacts the value of any `key: value`/`key=value` pair whose
key contains a marker such as `secret`, `password`, `token`, `apikey`, `credential`,
`sessionid`. Sensitive-key matching is substring-based (`aws_secret_access_key` and
`X-Auth-Token` must both match), deliberately over-redacting where ambiguous.
Every detector is **linear in input length**: PEM blocks and assignments have dedicated
linear scanners, and the remaining regexes use bounded or atomic quantifiers.
`tests/unit/test_redaction_perf.py` fails if a pattern becomes superlinear on adversarial
input. Redaction is idempotent. JSON bodies get key-aware redaction in addition to
pattern redaction.

**Consequences.** Known limitation, recorded deliberately: a bare high-entropy string
with no recognisable form (e.g. an arbitrary base64 blob logged as a bare argument) is
not detectable by pattern. The operative rule stays "do not log secrets in the first
place" — redaction is a safety net, not a licence to pass secrets around. Bodies are
truncated (`ARACHNE_HTTP_MAX_BODY_BYTES`, default 64 KiB) and binary payloads are not
retained, which bounds the work.

## ADR-050.4 — Retries re-acquire rate-limit tokens

**Context.** forbids retries from bypassing the rate limit.

**Decision.** A retry is a fresh acquisition from both the per-host and the global token
bucket, exactly like a first attempt. Retries are bounded (default 1) and apply only to
transport errors and 502/503/504.

**Consequences.** A flaky target cannot be retried faster than its budget allows, so a
retry storm costs the same as the equivalent number of first attempts.

## ADR-050.5 — Scope guard in S1 is provisional; S2 owns the target model

**Context.** The S1 client must be scopable ("shared *scoped* HTTP client"), while the
full target definition, authorization attestation and dry-run planner are stage S2.

**Decision.** S1 ships a minimal, deny-by-default `Scope` (host allowlist, domain suffix
allowlist, exclusions) plus the `targets` table with `scope_json` and
`auth_attestation` columns. S2 replaces the in-process guard with the persisted target
model and the attestation gate; the `Scope` type stays as the compiled, checkable form.

## ADR-050.6 — SQLite timestamp round-trip is naive UTC

**Context.** The schema uses `DateTime(timezone=True)` (portable, and correct on
Postgres). SQLite has no timezone-aware storage type.

**Decision.** All timestamps are written as timezone-aware UTC values by Python; on
SQLite they read back as naive UTC. Tests compare instants, not `tzinfo`. Postgres keeps
the offset.

**Consequences.** Code that reads timestamps must treat naive values as UTC. A
`TypeDecorator` that coerces on load was considered and rejected for S1: it changes the
column type as seen by Alembic's `compare_type`, which would make the model-drift check
noisy. Revisit if a caller genuinely needs aware values from SQLite.

## ADR-050.7 — `uvicorn[standard]` is a declared dependency; no config file format

**Context.** lists "FastAPI + uvicorn"; the spec otherwise assumes
environment-driven configuration.

**Decision.** Depend on `uvicorn[standard]` (uvloop/httptools are available for the
supported interpreters) and read *all* configuration from environment variables via
`Settings.from_env`, with `.env.example` as documentation only. No config file is
parsed by ARACHNE itself, so no secret can be committed by accident and deployment stays
12-factor.

**Consequences.** Human-readable config files (e.g. `arachne.yaml`) would have to be
added deliberately in a later stage, with a redaction story for any secrets they carry.

## ADR-050.8 — Only `arachne/core/http.py` may import an HTTP library

**Context.** ADR-05 says every request flows through one client; a convention that is
not enforced decays.

**Decision.** `tests/unit/test_http_hygiene.py` parses the source AST and fails if any
module other than `core/http.py` imports `httpx`, `requests`, `urllib.request`,
`urllib3`, `aiohttp` or `http.client`. Companion tests ban `eval`/`exec`/`compile`/
`__import__` (F-08-06), `pickle`/`marshal`/`ctypes`, `subprocess`, and `yaml.load`.
