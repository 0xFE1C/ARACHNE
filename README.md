<p align="center"><img src="docs/assets/banner.svg" alt="ARACHNE — automated vulnerability detection and reporting" width="100%"></p>

<h3 align="center"><b>Automated vulnerability detection &amp; reporting — with AI, or without it.</b></h3>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-3b82f6" alt="License: MIT"></a>
  <img src="https://img.shields.io/badge/python-3.11%2B-3776AB?logo=python&logoColor=white" alt="Python 3.11+">
  <img src="https://img.shields.io/badge/checks-152-8b5cf6" alt="152 registered checks">
  <img src="https://img.shields.io/badge/tests-4,296-22c55e" alt="4,296 tests">
  <img src="https://img.shields.io/badge/engine-heuristic_%2B_AI-f59e0b" alt="Dual engine">
  <img src="https://img.shields.io/badge/proof_ladder-L0%E2%80%93L4-ef4444" alt="Proof ladder L0–L4">
  <img src="https://img.shields.io/badge/mypy-strict-0ea5e9" alt="mypy strict">
</p>

---

ARACHNE inspects targets you are **authorized** to test with attacker-grade methods,
proves what it finds through a graduated **safe proof ladder**, and produces
evidence-backed reports — then cleans up after itself. It runs on a **heuristic
engine** (deterministic, fully offline-capable), an **AI engine** (pluggable
providers), or both in parallel: a parity suite proves the two engines reach the same
findings on ground-truth labs.

> [!IMPORTANT]
> ARACHNE is a defensive tool. It detects and proves — it never exploits, persists, or
> destroys, and it is **refused by its own gates** unless every target is covered by an
> authorization attestation. Scanning systems you do not own is prohibited, by policy
> and by design.

## ✨ What makes it different

Most scanners stop at *"we think this is vulnerable."* ARACHNE is built to **prove**
it — safely — and to **show its work**:

| | Classic tools | ARACHNE |
|---|---|---|
| SQL injection | dumps the database | differential oracle + captured evidence, data stays yours |
| Blind RCE | drops a webshell | one-shot `echo arachne-<nonce>` proof — **nothing persists** |
| Findings | a list of alerts | **attack paths** with per-hop evidence and cheapest remediation |
| Trust | "trust the tool" | hash-chained audit, tamper-evident evidence, sealed integrity |
| State left behind | varies | a cleanup pass verifies **zero residue** |

## 📊 At a glance

| | |
|:---|:---|
| 🕷️ **152 registered checks** | 6 modules: recon/OSINT · network · web · misconfiguration · cloud/supply-chain · AI-era |
| 🪜 **Proof ladder L0–L4** | passive → read-only → out-of-band → one-shot command → minimal state change (auto-restored) |
| ⚙️ **Dual engine** | heuristic (118 rules, deterministic) + AI (7 provider adapters) — parity-guaranteed |
| 🖥️ **Run it your way** | CLI · REST API + web UI · scheduler · distributed agents · CI gate · air-gapped |
| 🧪 **4,296 tests** | incl. a 59-test safety suite and ground-truth labs with false-positive traps |
| 🔏 **Tamper-evident** | hash-chained audit trail; `arachne verify-chain` detects any modification |

## 🏗️ Architecture

```mermaid
flowchart LR
    subgraph entry["Entry points"]
        CLI["CLI"]
        API["REST API + Web UI"]
        SCH["Scheduler"]
        AGT["Agents"]
    end
    subgraph pipeline["Core pipeline"]
        PLAN["Planner<br/>readable plan · dry-run"]
        GATES["Safety gates<br/>scope · attestation · proof"]
        RUN["Scoped execution<br/>rate-limited · redacted · audited"]
    end
    subgraph modules["Detection — 152 checks, 6 modules"]
        M1["M1<br/>Recon/OSINT"]
        M2["M2<br/>Network"]
        M3["M3<br/>Web"]
        M4["M4<br/>Misconfig"]
        M5["M5<br/>Cloud/Supply"]
        M6["M6<br/>AI-era"]
    end
    subgraph engines["Analysis — dual engine"]
        HEUR["Heuristic<br/>118 rules"]
        AIE["AI<br/>7 providers"]
    end
    REP["Report engine<br/>MD · HTML · JSON · PDF"]
    DB[("Evidence store<br/>SQLite / Postgres")]

    CLI --> PLAN
    API --> PLAN
    SCH --> PLAN
    AGT --> PLAN
    PLAN --> GATES
    GATES --> RUN
    RUN --> modules
    modules --> engines
    engines --> REP
    RUN --> DB
    REP --> DB
```

Every request passes through the scoped, rate-limited, redacting, audited HTTP client —
checks cannot reach a host outside the compiled scope even by bug, because they only
ever receive a scope-bound client.

## 🪜 The safe proof ladder

Each check declares how far it may go; the engine always chooses the **lowest
sufficient level**:

```mermaid
flowchart TB
    L0["L0 · passive — no target interaction"] --> L1["L1 · active read-only — default for every check"]
    L1 --> L2["L2 · out-of-band callback — per-scan opt-in"]
    L2 --> L3["L3 · one-shot command proof — opt-in + attestation"]
    L3 --> L4["L4 · minimal state change — attestation + auto-restore"]
    L4 --> CLEAN["cleanup pass → zero residue, fully audited"]
```

Escalation is never implicit: L2+ needs a per-scan opt-in, L3/L4 need a typed,
expiring **authorization attestation**, and any state change is captured, restored and
re-verified with every step in the audit trail.

## 🚀 Quick start

Python 3.11+ required. From the repository root:

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"
arachne --version        # → 0.1.0
```

A fresh install starts with an **empty database** and a **closed API** — you set
everything up explicitly:

```bash
arachne db upgrade                       # create the schema (empty state)
arachne scan --target examples/targets/lab-fixture.yaml --dry-run
                                         # readable plan — ZERO requests
arachne scan --target examples/targets/lab-fixture.yaml
                                         # live scan (documentation-range lab)
arachne report --scan 1 --format md --output report.md
arachne serve --host 127.0.0.1 --port 8080
curl http://127.0.0.1:8080/health
```

> [!TIP]
> Always start with `--dry-run`: it prints the complete plan — scope, attestation,
> every check with its proof level, estimated request count — without touching the
> network.

The example target points at documentation ranges (example.com, RFC 5737) and carries
a complete authorization attestation — see
[`examples/targets/lab-fixture.yaml`](examples/targets/lab-fixture.yaml) to write your
own.

## 📦 The six detection modules

| Module | Checks | What it covers |
|---|:---:|---|
| **M1** Recon & OSINT | 17 | dork sweeps, subdomains, certificate transparency, breach exposure, provider drift (Shodan/Censys) |
| **M2** Network & Services | 27 | ports, fingerprints, TLS, DNS/AXFR, SMB auth, database & ICS probing, CVE correlation |
| **M3** Web Application | 47 | SQLi/XSS/SSRF/IDOR, command & template injection, XXE, smuggling, cache poisoning, GraphQL, JWT/OAuth/SAML |
| **M4** Misconfiguration | 29 | `.env`/`.git` exposure, backups, debug endpoints, headers, cookies, default credentials |
| **M5** Cloud & Supply Chain | 20 | IMDS/metadata, buckets, Kubernetes, registries, CI/CD, dependency confusion, IAM |
| **M6** AI-era & Post-Exploit | 12+ | webshell signatures, secret scanning, LPE, AD attack paths, GenAI surface, Sigma hunts |

*(+ distributed fuzzing, simulation, purple-team validation and remediation-as-code —
see [docs/architecture.md](docs/architecture.md))*

## 📚 Documentation

| Document | Purpose |
|---|---|
| 🟢 [docs/getting-started.md](docs/getting-started.md) | **Start here** — install → migrate → first scan → API, step by step |
| 🏗️ [docs/architecture.md](docs/architecture.md) | Pipeline, safety stack, proof ladder, dual engine, distributed mode — with diagrams |
| 📖 [docs/operator-guide.md](docs/operator-guide.md) | Deep reference: every variable, every command, runbooks |
| 🔌 [docs/plugin-developer-guide.md](docs/plugin-developer-guide.md) | Write your own checks, modules and report formats |
| 🔄 [docs/ci-integration.md](docs/ci-integration.md) | Use ARACHNE as a CI gate |
| 🔏 [docs/security-review.md](docs/security-review.md) | Security review of the codebase itself |
| 🗂️ [docs/README.md](docs/README.md) | Full documentation index |

<details>
<summary><b>🗂️ Repository layout</b></summary>

```
ARACHNE/
├── src/arachne/        # core, modules m1–m6, analyzer, ai/, api/, report/, data/
├── tests/              # unit · safety · integration · parity · report-QA · labs
├── docs/               # getting-started, architecture, operator guide, ADRs, security
├── migrations/         # Alembic schema migrations
├── docker/             # Dockerfile + compose (demo stack, offline scan)
├── deploy/             # Helm chart + Terraform
├── clients/            # generated Python/TS API clients
├── examples/           # commented target definitions, plugins
└── benchmarks/         # benchmark harness suites
```

</details>

## 🤝 Contributing

Issues and pull requests are welcome. Plugin authors: start with the
[plugin developer guide](docs/plugin-developer-guide.md) — new checks ride the same
registry, versioning and safety gates as the built-in 152, and the parity suite will
hold them to it.

## ⚖️ License

[MIT](LICENSE) © 2026 [0xFE1C (Felix)](https://github.com/0xFE1C). Third-party
components remain under their own licenses.

---

<p align="center">
  <sub><b>Red methods. Blue purpose. White evidence.</b> 🕷️<br>
  Scan only what you are authorized to test.</sub>
</p>
