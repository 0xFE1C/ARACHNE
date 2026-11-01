# Architecture

How ARACHNE works, with diagrams. For task-level instructions see
[getting-started.md](getting-started.md) and the
[operator guide](operator-guide.md); for the reasoning behind decisions see the
[ADRs](adr/).

## 1. System overview

```mermaid
flowchart TB
    subgraph entry["Entry points"]
        CLI["arachne CLI"]
        API["REST API + Web UI<br/>(hashed keys · roles · rate-limited)"]
        SCH["Scheduler<br/>(cron · diff reports)"]
        AGT["Scan agents<br/>(lease · heartbeat)"]
    end

    subgraph core["Core"]
        PLN["Planner<br/>checks × proof levels × request estimate"]
        ORC["Orchestrator<br/>three gates, re-checked at execute/resume"]
        HTTP["Scoped HTTP client<br/>rate-limit · redact-at-capture · audit"]
    end

    subgraph det["Detection modules — 152 checks"]
        M1["M1 Recon/OSINT (17)"]
        M2["M2 Network (27)"]
        M3["M3 Web (47)"]
        M4["M4 Misconfig (29)"]
        M5["M5 Cloud/Supply (20)"]
        M6["M6 AI-era (12)"]
    end

    subgraph ana["Analysis — dual engine"]
        HEUR["Heuristic engine<br/>118 rules · restricted expression language"]
        AIE["AI engine<br/>7 providers · budgets · cache · privacy modes"]
    end

    REP["Report engine<br/>MD · HTML · JSON · PDF · diff · OWASP mapping"]
    EVID[("Evidence store<br/>SQLite / Postgres · S3-compatible backend")]
    AUD[("Audit log<br/>hash-chained · tamper-evident")]

    CLI --> PLN
    API --> PLN
    SCH --> PLN
    AGT --> PLN
    PLN --> ORC
    ORC --> HTTP
    HTTP --> det
    det --> ana
    HEUR --> REP
    AIE --> REP
    REP --> EVID
    HTTP --> AUD
    ORC --> AUD
```

**The one-sentence version:** entry points produce a *plan*; the orchestrator admits it
through three gates; checks run only through a scope-bound HTTP client; findings are
analyzed by the dual engine; everything lands in an evidence store with a sealed audit
trail.

## 2. Scan pipeline

```mermaid
flowchart LR
    P["plan<br/>(dry-run: zero requests)"] --> G["gates<br/>scope · attestation · proof"]
    G --> R["recon"]
    R --> D["discovery"]
    D --> C["checks"]
    C --> A["analysis"]
    A --> K["correlation"]
    K --> RP["reporting"]
    G -.refused.-> X["audited refusal"]
    C -.crash.-> RES["resumable state<br/>(same or another node)"]
```

- The **plan** is a first-class artifact: `--dry-run` prints the complete check list
  with proof levels and request estimates without touching the network.
- The **gates** (scope, attestation, proof) are evaluated at plan time *and* re-checked
  at execute/resume — an admitted scan cannot escalate after its attestation expires.
- A crashed scan leaves a **resumable state**; in distributed mode the lease expires
  and another agent re-leases it.

## 3. The safety stack

Four structural layers, each independent of operator discipline:

| Layer | Mechanism |
|---|---|
| **Scope** | Deny-by-default allowlist (hosts, domains, networks, URLs, references) + exclusions; DNS resolved and validated *before* each request; every redirect hop re-validated |
| **Attestation** | Typed, expiring, audited authorization records — required for active checks (L2+), purple-team windows, fuzzing |
| **Proof ladder** | L0 passive → L1 read-only → L2 out-of-band → L3 one-shot command → L4 minimal state change; always the lowest sufficient level; destructive SQL refused in code |
| **Audit** | Every request, refusal, gate decision and state change captured, redacted, hash-chained; `arachne verify-chain` detects tampering |

```mermaid
flowchart TB
    REQ["check requests a fetch"] --> SC{"in scope?"}
    SC -- no --> REJ["refused + audited<br/>(proof.rejected / scope.rejected)"]
    SC -- yes --> LVL{"proof level<br/>authorized?"}
    LVL -- no --> REJ
    LVL -- yes --> RL{"rate limit ok?"}
    RL -- no --> WAIT["bounded wait"]
    RL -- yes --> RED["redact at capture"] --> AUD["audit entry"] --> OUT["response to check"]
```

## 4. Dual engine with parity

```mermaid
flowchart LR
    CAND["finding candidates"] --> H["Heuristic analyzer<br/>(anchor verdict)"]
    H --> Q{"AI engine<br/>configured & healthy?"}
    Q -- yes --> AI["AI stages<br/>triage · correlate · narrate<br/>(annotate the anchor)"]
    Q -- no | failed --> FB["degrade to heuristic<br/>(provenance recorded)"]
    AI --> OUT["findings + narrative"]
    FB --> OUT
```

The heuristic verdict is the anchor: the AI engine runs the heuristic first and
annotates, so an AI outage degrades quality — never the scan, never the safety. The
parity suite proves heuristic-only mode reaches the ground-truth labs' detection
thresholds.

## 5. Distributed mode

```mermaid
flowchart LR
    subgraph control["Control plane"]
        API2["API + UI"]
        Q[("Work queue<br/>Postgres SKIP LOCKED")]
        SCH2["Scheduler"]
    end
    subgraph farm["Scan farm (autoscaled)"]
        A1["Agent 1<br/>lease · heartbeat"]
        A2["Agent 2"]
        A3["Agent N"]
    end
    SCH2 --> Q
    API2 --> Q
    Q --> A1
    Q --> A2
    Q --> A3
    A1 -- "stream findings/evidence" --> E[("Central store")]
    A2 --> E
    A3 --> E
```

- One scan is leased by exactly one agent (`SKIP LOCKED`); a dead agent's lease
  expires and the scan is re-leased with an interruption note.
- Plans are deterministic: the same scan id produces the same plan on any node.
- Safety gates are evaluated on the **executing** node, not only at enqueue time.
- Air-gapped mode runs the full heuristic pipeline from signed offline content packs —
  zero external connectivity.

## 6. Where things live in code

```
src/arachne/
├── core/          # config, safety (Scope), http client, lifecycle, orchestrator,
│                  # planner, redaction, audit sink
├── modules/       # m1..m6 detection modules, registry (152 checks), handlers
├── analyzer/      # scoring, rules, correlation, FP tuning, narrative, remediation
├── ai/            # engine, stages, providers (7), budget, cache, privacy, reliability
├── report/        # builder, renderers (MD/HTML/JSON/PDF), diff, evidence, OWASP
├── api/           # FastAPI app, auth (hashed keys), rate limit, webhooks, UI
├── scheduler/     # cron parser, runner, store
├── data/          # SQLAlchemy stores: scans, findings, evidence, audit, feeds
└── plugins/       # entry-point plugin + content-pack installer
```

## 7. Design invariants

1. **Deny by default.** Empty scope authorizes nothing; every refusal is audited.
2. **Lowest sufficient proof.** Escalation is opt-in, attested, restored, audited.
3. **No exploitation.** No persistence, no destructive capability, no arbitrary
   command API for checks — enforced at code boundaries, not by convention.
4. **Heuristic independence.** The product runs fully without any AI provider (and
   fully offline in air-gapped mode).
5. **Everything is auditable and replayable.** AI decisions and proof actions are
   recorded; reports state what changed on a target and whether it was restored.
