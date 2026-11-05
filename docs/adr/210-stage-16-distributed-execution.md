# ADR-210 — S16: distributed scan execution

> **Owner:** ARACHNE architecture group · **Last verified:** 2026-11-05 · **Review interval:** 1825 days

Status: accepted (S16, program Phase 2)

This stage removes the last single-process constraint the S14 baseline named
(`api/runner.py` owns scans in one process): one scan fleet, many nodes, no single
process owner. It implements capability area `SCALE` (REQ-SCALE-001…008) under three
hard rules — gates must not weaken under distribution, no scan may execute on two nodes
at once, and heuristic (single-node) mode is unchanged.

---

## 210.1 — The database is the broker

The work queue is two tables on the store ARACHNE already runs on
(`scan_queue`, `scan_agents`, migration `0005`). On Postgres the claim is the canonical
`SELECT … FOR UPDATE SKIP LOCKED` (the statement shape is pinned by a unit test);
concurrent agents lock disjoint rows and skip the locked ones, so nobody queues behind a
slow claimer and no scan is ever handed to two nodes. On the other supported dialect
(SQLite — single-node and tests) the claim is a single atomic `UPDATE … WHERE status =
'queued' … RETURNING` whose guard decides the win. Both paths satisfy the same
invariant, and the concurrent-claim test (five threads, disjoint leases) runs on the
portable path.

No message broker becomes a default dependency (REQ-SCALE-001): the queue needs only
what a distributed deployment already needs (Postgres, constraint C-01/A-01), and a
Redis adapter interface remains *reserved* — adding one later is a `WorkQueue`
implementation, not a redesign.

## 210.2 — Ownership: admit-then-execute, wherever the executor lives

Admission (gates, plan, `scans` row) already lives in `Orchestrator.launch`; execution
was the part welded to the admitting process. The seam now runs through the queue:

* **API**: `ScanRunner.start` admits, then either schedules `execute` on its own loop
  (single-node, the S12 behaviour byte-for-byte) or *enqueues* (distributed) —
  "enqueue-and-track" (REQ-SCALE-007). `is_running`/`stop` consult the queue row, so the
  API reports and cancels scans that other nodes run.
* **Scheduler**: in distributed mode `run_one` produces (`launch` + enqueue) instead of
  running. The F-06-05 diff rides on the queue row (`schedule_id`,
  `previous_scan_id`) and is computed by the agent's completion path — comparing a
  *queued* scan against an older one would be fiction. Single-node scheduling is
  unchanged.
* **Agent**: `AgentLoop` (register → lease → execute → heartbeat → ack) is the whole
  `arachne agent` role (REQ-SCALE-002). The control plane is four verbs
  (`/api/v1/agent/register|heartbeat|lease|complete`), each requiring an existing
  scanner-role API key — the agent is a `ScannerPrincipal`, not a new credential type
  (REQ-SCALE-004). The client half speaks HTTP through the one scoped HTTP client
  (ADR-05), scope pinned to the deployment's host.

## 210.3 — Cross-node determinism and resume are the same mechanism

The admitted request document (target + options exactly as gated) is persisted with the
scan (`scans.request_json`), next to the plan that was already stored. An agent rebuilds
the request from the stored target row (the *current* authorization state) plus the
stored options, and calls `execute` or `resume`: `resume` is what an interrupted scan
gets, and it skips completed steps by the persisted step rows — the S2 machinery, now
running across processes. The executing node therefore never re-plans: the same scan id
carries the same plan to every node (REQ-SCALE-006).

A lease that expires without a heartbeat is reclaimed by the *next claimant* (reaping is
a lease-time act, not a background daemon), which appends an interruption note to the
scan's stats and writes `scan.interrupted` before re-leasing (REQ-SCALE-003). A failed
execution is a terminal ack — no automatic retry hides a failure; a *cancellation*
never acks, which is exactly what makes an agent kill re-leasable.

## 210.4 — Gates on the executing node

REQ-SCALE-008 is structural: the agent's executor rebuilds the request and calls the
orchestrator, whose `execute`/`resume` path re-runs `assert_in_scope` (with *that*
node's deployment allowlist and the project's scope), `assert_authorized` (the
attestation as it stands *now*) and the proof gate before any handler runs. Two safety
tests pin it: a revoked attestation stops an already-enqueued scan at execution time,
and a scan outside the *executing* node's deployment scope is refused there with
`scope.rejected`. A refusal on the executing node marks the scan `failed` with the
reason — a gate refusal is data, never a stranded `pending` row.

## 210.5 — Streaming is a property of the executor, not a feature

Findings, evidence and assets are written by the handlers to the shared store as each
check finishes; the agent runs those handlers unchanged, so a second reader sees results
while the scan is running (REQ-SCALE-005, pinned by an integration test that reads a
committed finding from a second connection mid-scan). No bulk end-of-scan transfer
exists to remove — which is the point of running the real pipeline on the executing
node.

## 210.6 — Rejected alternatives

* **A broker (Redis/RabbitMQ) for the queue.** Violates C-01's dependency-light default;
  the DB queue does the job at fleet scale and keeps one transactional store.
* **The API relays scan state from agents (push/pull streaming endpoints).** Would make
  the API a data-plane bottleneck and duplicate the write path the handlers already
  have. Agents share the central store; only *control* traffic goes through HTTP.
* **Re-planning on the executing node.** Non-deterministic by construction (clock, node
  catalogue drift); the stored plan is the contract instead.
