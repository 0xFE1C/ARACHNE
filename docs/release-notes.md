# Release notes

*One section per release, newest first. Every number here is reproducible with the command
that produced it; where a capability is partial, this file says so.*

---

## 0.1.0 — development snapshot (unreleased)

**ARACHNE is a defensive vulnerability scanner.** It inspects targets you are authorized to
test, proves what it finds through a graduated safe proof ladder, reports it with evidence,
and cleans up after itself. It runs on a deterministic heuristic engine, a pluggable AI
engine, or both.

This snapshot is feature-complete against its own specification but **not yet released**. It
is published here so that an operator can evaluate it and a contributor can work on it. Read
the [Known limitations](#known-limitations) section before deploying it anywhere that
matters.

### What is in this snapshot

**Detection — 152 registered checks across six modules**

| Module | Checks | Surface |
|---|---:|---|
| M1 Reconnaissance & OSINT | 17 | dork sweeps, subdomain enumeration, certificate transparency, breach exposure, provider drift |
| M2 Network & services | 27 | ports, fingerprints, TLS and X.509, DNS and AXFR, SMB, databases, OT protocols, CVE correlation |
| M3 Web application | 47 | injection, access control, session and identity, request smuggling, cache poisoning, GraphQL, WebSocket, gRPC, client-side code, mobile artifacts |
| M4 Misconfiguration & exposure | 29 | exposed `.env`/`.git`, backups, debug endpoints, headers, cookies, default credentials |
| M5 Cloud, container & supply chain | 20 | instance metadata, buckets, Kubernetes, registries, CI/CD, dependency confusion, IAM posture |
| M6 Automation & AI-era | 12 | webshell signatures, secret scanning, local privilege escalation, AD paths, GenAI surface, Sigma hunts |

Checks and their payloads are data, not code: payloads, wordlists, protocol tables and rule
corpora live in `src/arachne/templates/` and can be replaced by an operator.

**Analysis — a dual engine with a parity guarantee**

- A **heuristic engine** of 118 rules in a restricted expression language. It has no code
  execution, it is deterministic, and it works with no network and no API key.
- An **AI engine** with seven provider adapters (OpenAI, OpenAI-compatible, Anthropic,
  Gemini, Ollama, Mistral, custom). It annotates the heuristic verdict; it never owns it.
- A **parity suite** proves both engines reach the same finding set on the ground-truth
  fixtures, so a report cannot tell which engine ran except through its provenance field.

**Safety architecture — the part that does not change between releases**

- **Scope is deny-by-default.** An empty scope authorizes nothing. Hosts are resolved and
  validated *before* each request, and every redirect hop is re-validated.
- **Authorization is a typed, expiring, audited attestation.** A live scan without one never
  leaves the process.
- **The proof ladder runs L0 to L4:** passive, active read-only, out-of-band, one-shot
  command, minimal reversible state change. Every check declares the level it needs; L2 and
  above are opt-in; L3 and L4 require a state-change attestation. State changes are captured,
  restored and re-verified by a cleanup pass.
- **The audit trail is hash-chained and tamper-evident.** `arachne verify-chain` detects an
  edited, deleted, reordered or truncated trail, and verifies signed rows and per-scan seals.
- **Secrets and PII are redacted at capture**, never at render.

**Operation**

- A **CLI**, a **REST API** (74 documented operations, OpenAPI at `/docs`) and a **web UI**
  (13 screens, server-rendered with progressive enhancement).
- Generated **Python and TypeScript API clients**, contract-tested against the live schema.
- A **scheduler** with diff reporting, and **distributed scan agents** on a Postgres lease
  queue.
- **Air-gapped mode**, enforced at the request boundary: an air-gapped deployment refuses its
  first outbound request and audits the refusal.
- **Helm chart** and **Terraform module**; Docker and compose files for a demo stack.
- Reports as **Markdown, HTML, JSON, PDF and SARIF**, with executive summary, OWASP mapping,
  evidence appendix and a diff against the previous scan.

**Beyond scanning**

- **Detection validation**: nonce-tagged proof actions replayed against your SIEM's alerts,
  scored against your Sigma rules.
- **Bounded safe fuzzing**: its own attestation, hard budgets, a prohibition table, health
  probes with an abort guard, and ten wire grammars.
- **Remediation as code**: human-approved pull requests, with the change proved to be scoped
  to the finding.
- **Continuous exposure management**: scheduled cloud-config checks, an IaC/CI gate, a
  Kubernetes admission endpoint, and a fix-verification loop.
- **What-if simulation**: an estate model that cannot reach a target, used to answer
  "what changes if I fix these five things?"

### Verification

| What | Result |
|---|---|
| Tests | **4,023** tests collected (the scope CI runs: `pytest tests -m "not perf"`) |
| Primary safety suite | **59 tests** in `tests/test_safety.py`; **259** in the safety files |
| Ground-truth labs | web, cloud, GraphQL, gRPC, fuzzing, protocol and mobile fixtures with planted false-positive traps |
| Strict type checking | clean under `mypy --strict` across the **357** Python modules in `src/` |
| Lint | clean over `src/` and `tests/` |
| Research coverage | **148/175 (84.6%)** of the corpus's numbered methods have an implementing check |

Every figure here is generated rather than typed: `python -m arachne.tools.counts --check`
fails the build when one of them drifts from the registry, the suite or the coverage tool.
Reproduce them with the commands in the [operator guide](operator-guide.md).

### Known limitations

These are real, verified against this snapshot, and listed here rather than left for you to
discover. Each is a candidate for a future release.

**Detection gaps**

1. **No JavaScript execution.** There is no headless browser, so single-page application
   routes and DOM-based sinks are not reached. This is the largest gap against comparable
   tools.
2. **No WSTG or OWASP API Top 10 identifiers** in check metadata. Coverage against those
   frameworks cannot be reported, only estimated.
3. **No MCP-server checks, no OWASP Agentic Top 10 coverage, no ADCS enumeration.**
4. **No mutual-TLS or client-certificate check**, and no SMTP transport-security check
   (STARTTLS enforcement, AUTH, open relay).
5. **No HTTP/3 probing**, and IPv6-only targets are under-scanned.
6. **`oracle`, `sip` and `opc-ua` are declared in the port catalogue without an implementing
   check.** An Oracle port currently produces a generic "port reachable" finding rather than
   a database finding.
7. **Container registry scanning delegates to an external scanner and is off by default**, so
   it does not work in an air-gapped deployment.
8. **Cloud posture covers AWS, Azure and GCP only.**
9. **Four in-scope CWE Top 25 weaknesses have no check**: CWE-94, CWE-863, CWE-20 and CWE-77.

**Behaviour you should know about**

10. **The PII retention re-mask is configured and documented but not implemented.** The
    setting is accepted and no re-mask occurs. Treat evidence retention as manual until this
    is fixed. This is the most significant known defect in this snapshot.
11. **`arachne coverage` reports 148 of 175 methods (84.6%) mapped.** The remaining 27 are
    named gaps, each with the reason it is absent (see `docs/research/README.md`). Seven of
    them are absent because the technique would need a capability ARACHNE refuses; the rest
    are simply not built yet. The committed `coverage_matrix.md` is the same number, and a
    test fails when it goes stale.
12. **The reporting pipeline step is declared but has no handler.** Reports are generated out
    of band with `arachne report`; the plan output marks the step "not executable".
13. **A DNS-rebinding window remains** between address validation and connect. Per-hop
    revalidation is the current mitigation; a container or network-namespace sandbox is not
    implemented.
14. **An unsigned deployment verifies as intact.** With no integrity key configured,
    `verify-chain` passes unless you pass `--require-signatures`.
15. **15 registered checks are not referenced by id in the test suite** (M4, M5 and M6
    clusters), so a regression in them could go unnoticed.

**Developer experience**

16. **The integration test layer takes about 20 minutes** and there is no per-test timeout.
17. **Repo-wide lint reports one error outside the CI scope**, and 193 files would be
    reformatted. CI checks `src/` and `tests/` only.
18. **Coverage is configured but not enforced** — no `fail_under`, and CI does not run
    `pytest --cov`.

### Reporting a problem

- A **vulnerability in ARACHNE itself**: see [SECURITY.md](../SECURITY.md). Do not open a
  public issue.
- A **false positive or a missed detection**: open an issue with the check id, the target
  shape (redacted), and the evidence the check produced. Never include a real secret or
  customer hostname.
- A **documentation error**: a pull request. See [CONTRIBUTING.md](../CONTRIBUTING.md).

### Upgrading

No migration is required for this snapshot: it is the first. Future releases will state the
migration and its reversibility here.

---

## How this file is maintained

- One section per release, newest first, with the date.
- Every capability claim names the module, check or command that implements it.
- Every limitation is listed while it is true, and removed when it stops being true — not
  silently dropped.
- Numbers come from a command that is written down, so anyone can reproduce them.
