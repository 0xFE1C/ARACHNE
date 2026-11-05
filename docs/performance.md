# Performance and precision: the published envelope

> **Owner:** Quality group · **Last verified:** 2026-11-05 · **Review interval:** 180 days

This page is the single place where ARACHNE states **measured** numbers: the API latency
envelope, scan throughput, the memory ceilings, and the false-positive rate on the in-repo
ground-truth corpus. Every figure here is produced by a shipped command and committed as
JSON under `benchmarks/`; none of it is an estimate.

If a number looks unflattering, it stays. The rule is a number plus a method, not a
flattering adjective.

---

## 1. The envelope at a glance

Measured **2026-11-04** by `python -m arachne.tools.envelope` on:
| | |
|---|---|
| CPU | AMD Ryzen 5 5600H with Radeon Graphics, 12 logical CPUs |
| RAM | 15,380 MiB |
| OS / Python | Linux 7.2.11-arch1-1 (x86_64) / CPython 3.14.9 |
| Database | SQLite, throwaway file created for the run |
| Engine | heuristic (no AI provider configured) |
| Modules scanned | M3, M4 |
| Dataset | 10 scans · 100 findings · 10 assets · 12 checks |
| Load | sequential client, one request in flight, **50 requests/second per endpoint**, 3 s each (150 samples) |

### API p95 latency per list endpoint

| Endpoint | p50 | **p95** | p99 | max | achieved rate |
|---|---:|---:|---:|---:|---:|
| `GET /api/v1/scans` | 18.16 ms | **20.60 ms** | 21.87 ms | 22.71 ms | 50.0/s |
| `GET /api/v1/findings` | 15.74 ms | **18.90 ms** | 22.13 ms | 26.71 ms | 50.0/s |
| `GET /api/v1/targets` | 10.90 ms | **12.58 ms** | 14.28 ms | 15.62 ms | 50.0/s |
| `GET /api/v1/modules` | 9.80 ms | **12.83 ms** | 15.81 ms | 16.02 ms | 50.0/s |

The documented budget is **p95 ≤ 500 ms** per endpoint at 50 req/s. All four are more than
an order of magnitude inside it.

### Scan throughput and memory

| Metric | Measured |
|---|---|
| Reference lab scan (heuristic, M3 + M4) | 43 checks in 29.40 s |
| Throughput | **87.8 checks per minute per agent** |
| Peak RSS growth during that scan | 14.6 MiB |
| Benchmark-process peak RSS | 145 MiB |
| Documented scan memory ceiling | 1,024 MiB |

### What the envelope deliberately excludes

Recorded in the committed JSON, so a reader is not left to guess:

- **AI inference** — the scan is heuristic mode.
- **M1 (OSINT) and M2 (network) modules** — on a synthetic estate their cost is the scripted
  network, not the scanner.
- **Multiple API workers/processes** and **TLS/proxy hops** — the client is in-process and
  loopback only.

The latency figures therefore measure the control plane's own work (routing, authentication,
query, serialization) with no network in between: the client is the app's ASGI callable,
driven directly, so there is not even a socket. A deployment behind a load balancer sees its
own p95 plus the network and TLS work; that is the operator's measurement to take, not this
one.

---

## 2. Reproduce it with one command

```bash
python -m arachne.tools.envelope --write benchmarks/envelope/envelope.json
```

That measures the four endpoints, runs the reference lab scan, and writes the envelope. To
run the CI gate against the committed envelope (p95 budget, plus a regression margin of
**1.5× the committed p95 + 10 ms per endpoint**, and the memory ceiling):

```bash
python -m arachne.tools.envelope --gate
```

Exit codes: `0` ok, `1` a breach, `2` a usage error. `--skip-scan` measures the API envelope
only; `--duration` and `--rate` override the load (a shorter run is what the test suite uses).

**Commit the envelope with every release.** The committed file
(`benchmarks/envelope/envelope.json`) is the baseline the gate compares against, and it
records its own hardware, dataset and configuration so a later reader knows what changed
when the numbers move.

---

## 3. Hot-path query budget

The report, analysis, reasoning, posture, fix and benchmark paths read a scan's candidates
and analyses. That read is **constant** in the number of findings (REQ-SCALE-012):

| Findings | Candidate queries | Analysis queries | Total |
|---:|---:|---:|---:|
| 1 | 5 | 2 | 7 |
| 10 | 5 | 2 | 7 |
| 100 | 5 | 2 | 7 |

Before WP-17 the same read was **3N+1**: one evidence query per finding, a *fresh session*
per finding for its asset identity, then one query each for the current verification record
and the whole history — plus a `Finding` lookup per analysis row. Measured with the same
counter at the same sizes: **6 / 51 / 501** candidate queries and **2 / 11 / 101** analysis
queries, i.e. **602 queries for a 100-finding scan+analysis read**. The fix batches them:

- findings (the caller's own query),
- one `IN` query for all evidence rows,
- one `IN` query for the assets those findings name,
- one `IN` query for the checks,
- one `IN` query for the verification records (current and history, which the same table
  holds).

The documented budget is **8** queries; the measured count is **7** at every size, and
`tests/perf/test_query_budget.py` fails if it grows with the finding count. No new public API
and no second caching layer was introduced, and every golden report is byte-identical.

---

## 4. Response-body memory: the limit is an allocation cap

`ARACHNE_HTTP_MAX_BODY_BYTES` (default 64 KiB) used to bound only *processing*: the client
read the whole body (`response.content`) and truncated afterwards, so a hostile endpoint could
allocate hundreds of megabytes before the cap applied. The client now reads the response as a
stream in 64 KiB chunks and stops as soon as it has one byte past the limit (REQ-SCALE-013).

| Measurement | Result |
|---|---|
| Body served by the fixture | 500 MiB |
| Configured limit | 1 MiB |
| Captured body | exactly 1 MiB, flagged `truncated` |
| Peak traced allocation | **≈3.5 MiB** (3.4–3.7 MiB across runs) |
| Documented bound | 16 MiB |

Peak memory is therefore `body_limit + one 64 KiB chunk + the decode/redaction copies` — a
constant. For a body under the limit the captured bytes and the truncated flag are unchanged
from the previous behaviour; the golden tests and the client suite pin that.

Local evidence reads and writes, and the three UI handlers that call synchronous stores or
the auditor (login, feed import, feed delete), now run their blocking work in a worker thread
(`asyncio.to_thread`) so they cannot stall the event loop. `tests/perf/test_event_loop.py`
parks the blocking call and proves the loop keeps running.

---

## 5. Soak: 100k findings stay inside the ceiling

`tests/perf/test_soak_findings.py` writes 1,000 / 10,000 / 100,000 findings through the real
store (`SqlFindingStore.record_candidate`, one transaction per finding) and samples the
process's resident set. The number that matters is the **growth over the baseline taken just
before each size's loop** — the absolute peak depends on what else the process has already
done, which is why it is not the figure quoted.

| Findings | Growth over the pre-loop baseline | Absolute peak RSS (isolated run) |
|---:|---:|---:|
| 1,000 | 2.0 MiB | 90.8 MiB |
| 10,000 | 0.24 MiB | 91.1 MiB |
| 100,000 | 2.0 MiB | 90.9 MiB |

Measured in an isolated process; the same test run inside the full `tests/perf` suite (after
the 500 MiB body fixture has already grown the process) reports ≤0.1 MiB of growth at every
size, because there the baseline is higher. Both readings say the same thing: the write path
holds nothing.

100-fold the findings added **0.09 MiB** (isolated) — the asserted figure is the 100k-to-1k
peak difference, and it is bounded by the documented slack. The two documented bounds:

- growth over the pre-loop baseline stays under **64 MiB** at every size;
- peak(100k) − peak(1k) stays under **32 MiB** — growth sub-linear in the finding count.

The property that makes this true is that the store opens a session and a transaction per
finding: the identity map is discarded with the session, so nothing accumulates. A failure
mid-stream therefore rolls back one finding, not the scan: the completed findings stay
committed and the store is immediately writable again (also asserted). The run takes about
4.7 minutes on an idle reference machine (252 s of it in the 100k pass), which is why the
module is marked `perf` and excluded from the default suite.

---

## 6. False-positive rate on the ground-truth corpus

**The number: 0 false positives out of 15 scored candidates = 0.0 %.**

| | |
|---|---|
| Definition | `false positives / (true positives + false positives)` over the suite's **scored** candidates |
| Denominator | **15** scored candidates (15 true positives + 0 false positives) in this measurement |
| Corpus | in-repo web lab, `tests/lab/web_lab.py`, scored by suite **`arachne-lab` version 1.0** |
| Corpus traps | 10 planted false-positive traps (the lab's documented *hardened* counterparts, e.g. `/safe-search`, `/hardened-download`, `/api/config-fixed`) |
| Planted true cases | 16 |
| Detection | 15/16 = 93.8 % (the miss is `m3.upload-audit:/upload`) |
| Excluded from the denominator | 14 candidates whose check id or marker matched no case ("unscored") |
| Measured | 2026-11-04 |
| Target | **≤ 2 %**; above it the release checklist fails |
| Command | `python -m arachne.tools.benchmark --lab --write-baseline` |
| Committed output | `benchmarks/arachne-lab/baseline.json` |
| Gate | `python -m arachne.tools.benchmark --lab --gate` |

**Why unscored candidates are not in the denominator.** The scoring rule is the benchmark
convention: a candidate is scored when its check matches a case and its evidence contains the
case's marker. A finding on a path the suite never describes is outside its ground truth — it
is the *suite's* blind spot, not a false alarm. Counting it as a false positive would make
this figure a measure of the corpus's exhaustiveness rather than of the scanner's precision.
The unscored count is published beside the rate so the blind spot stays visible.

**Read this number honestly.** 0/15 does not mean "no false positives". It means no false
positive among the 15 scored findings on this corpus. The rule-of-three upper 95 % bound for
zero events in 15 trials is about **20 %**, so the figure is consistent with a true rate
anywhere below that. It becomes informative as the corpus grows; the corpus version is
recorded in the committed result precisely because the rate is only meaningful against a
stated ground truth.

**The trend.** Every release re-runs the measurement and commits a new
`benchmarks/arachne-lab/baseline.json`. `--gate` fails when the rate rises by more than two
percentage points against the previous baseline, and an **absolute** ceiling of 2 % fails a
run that merely matches its own (bad) baseline. Raising a false-positive figure in the
release notes is expected; hiding it is not.

---

## 7. Read-replica failover and its consistency model

A deployment may configure `ARACHNE_DATABASE_REPLICA_URLS` (comma-separated). Reads for the
read-only catalogue/listing paths go to a healthy replica; writes always go to the primary.

- **Consistency model:** reads through a replica may lag the last write. That is why only
  endpoints that were already eventually consistent use the replica path; anything that must
  reflect a just-completed mutation reads the primary.
- **Failover:** a replica that cannot be reached is detected before a session is handed to
  the caller, the read falls back to the primary, and the degradation is logged
  (`db.read_replica_fallback`) and counted
  (`arachne_read_replica_failovers_total{replica=...}`). A dead replica is retried once per
  cooldown window (30 s), not once per request. A replica that answers again is put back into
  service (`db.replica_recovered`).

---

## 8. Release checklist (performance and precision)

A release is not cut unless all of these pass:

1. `python -m pytest tests/perf -q` — envelope, query budget, body memory, soak, replica
   failover and false-positive-rate tests all green.
2. `python -m arachne.tools.envelope --gate` — every list endpoint's p95 is inside the
   500 ms budget and inside 1.5× + 10 ms of the committed p95; peak RSS is under the ceiling.
3. `python -m arachne.tools.benchmark --lab --gate` — detection has not dropped by more than
   two points, the false-positive rate has not risen by more than two points, and it is
   **at or below 2 %** in absolute terms.
4. The new `benchmarks/envelope/envelope.json` and `benchmarks/arachne-lab/baseline.json` are
   committed with the hardware/dataset the run recorded.
5. `ruff check .`, `ruff format --check .` and `mypy` are clean (the Definition of Done).

A failure here blocks the release; it does not get re-baselined away.
