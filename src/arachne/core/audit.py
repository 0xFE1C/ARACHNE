"""Audit log: fixed event schema and sinks (F-01-08, F-08-05).

Every request ARACHNE makes — and every request it *refuses* to make — produces one
:class:`AuditEvent`. The schema is fixed (extra fields are rejected) so downstream
consumers can rely on it; free-form detail goes in ``meta``. The audit trail is written
by sinks, which are deliberately failure-tolerant: an audit sink error is logged and
swallowed, because losing an audit line must never abort a scan.
"""

from __future__ import annotations

import json
import threading
import uuid
from collections.abc import Iterable, Mapping
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Final, Protocol

from pydantic import BaseModel, ConfigDict, Field, field_validator

from arachne.core.config import Settings, get_settings
from arachne.core.integrity import (
    AUDIT_DOMAIN,
    EVIDENCE_CAPTURED_ACTION,
    GENESIS_HASH,
    PII_REMASKED_ACTION,
    audit_payload,
    chain_digest,
)
from arachne.core.logging import get_logger
from arachne.core.redaction import redact_mapping, redact_text, redact_url
from arachne.core.signing import Signer

__all__ = [
    "AUDIT_SCHEMA_VERSION",
    "AuditAction",
    "AuditChain",
    "AuditEvent",
    "AuditOutcome",
    "AuditSink",
    "Auditor",
    "JsonlAuditSink",
    "LoggingAuditSink",
    "MemoryAuditChain",
    "MemoryAuditSink",
    "MultiAuditSink",
    "build_auditor",
]

#: Bumped whenever the audit event schema changes shape.
#:
#: 1.1 (S2): ``scan_id`` widened from ``str`` to ``int | str`` so it can carry the
#: evidence store's integer scan key; every scan-scoped action of F-01-08 now points at a
#: real scan row.
#: 1.2 (S25): the hash-chain fields (``seq``/``prev_hash``/``hash``/``signature``) so a
#: row's position and content digest are part of the stored event rather than a side
#: table — the trail a verifier walks (REQ-TRUST-005).
AUDIT_SCHEMA_VERSION: Final = "1.2"

_logger = get_logger("core.audit")


class AuditAction(StrEnum):
    """Fixed action vocabulary. Extend deliberately; never log free-form actions."""

    SCAN_CREATED = "scan.created"
    SCAN_STARTED = "scan.started"
    SCAN_FINISHED = "scan.finished"
    SCAN_FAILED = "scan.failed"
    SCAN_RESUMED = "scan.resumed"
    SCAN_PLANNED = "scan.planned"
    SCAN_STEP_STARTED = "scan.step_started"
    SCAN_STEP_COMPLETED = "scan.step_completed"
    SCAN_STEP_SKIPPED = "scan.step_skipped"
    TARGET_LOADED = "target.loaded"
    ATTESTATION_RECORDED = "auth.attested"
    AUTH_REJECTED = "auth.rejected"
    SCOPE_REJECTED = "scope.rejected"
    SCOPE_DISCARDED = "scope.discarded"
    SAFETY_BLOCKED = "safety.blocked"
    HTTP_REQUEST = "http.request"
    HTTP_REQUEST_BLOCKED = "http.request_blocked"
    CHECK_COMPLETED = "check.completed"
    CHECK_FAILED = "check.failed"
    #: S3: the module registry and the checks it runs. ``check.skipped`` is distinct from
    #: ``check.completed`` because "the source was not configured" is not "we looked".
    CHECK_STARTED = "check.started"
    CHECK_SKIPPED = "check.skipped"
    MODULES_LOADED = "modules.loaded"
    CANDIDATE_RECORDED = "finding.candidate"
    OSINT_QUERY = "osint.query"
    BUDGET_EXHAUSTED = "budget.exhausted"
    CONFIG_LOADED = "config.loaded"
    #: S4 (M2): raw network probes. ``net.probe`` is the non-HTTP counterpart of
    #: ``http.request`` — one line per TCP/UDP/TLS attempt, with host, port, protocol,
    #: outcome and duration — and ``net.blocked`` records a probe refused by the scope or
    #: address policy *before* any packet was sent (F-01-08).
    NET_PROBE = "net.probe"
    NET_BLOCKED = "net.blocked"
    #: S5 (analyzer): what the heuristic engine decided. ``analysis.dropped`` is the record of
    #: a candidate an FP filter (verification contradiction, placeholder page) rejected — the
    #: reason is kept because "we saw it, then we did not" is information .
    ANALYSIS_COMPLETED = "analysis.completed"
    ANALYSIS_DROPPED = "analysis.dropped"
    CORRELATION_COMPLETED = "correlation.completed"
    #: S9 (AI layer): one line per model stage call — stage, provider, model, mechanism, tokens,
    #: cost, prompt hash and outcome — so "what did the model see and cost?" is answerable from
    #: the audit trail alone. ``ai.degraded`` marks a stage that fell back to the heuristic
    #: result, which is the provenance half of the degradation chain .
    AI_REQUEST = "ai.request"
    AI_DEGRADED = "ai.degraded"
    #: WP-15 (area AGENT, REQ-AGENT-011): one line per capability-scoped tool call the AI layer
    #: makes. An *undeclared* tool is recorded with ``outcome=blocked`` and the name that was
    #: asked for, because "an AI stage requested a capability ARACHNE does not have" is the event
    #: that would precede capability creep, and it should be visible without reading a traceback.
    AI_TOOL = "ai.tool"
    #: S12 (API + webhooks): one line per HTTP request the API answers — method, path, status,
    #: the authenticated principal and the duration — so the interface layer is auditable too
    #: (F-08-02). ``api.denied`` marks a request refused before it reached a route (missing or
    #: invalid API key, insufficient role, rate limit): a distinct security event from a route
    #: that returned a 4xx of its own.
    API_REQUEST = "api.request"
    API_DENIED = "api.denied"
    #: Outbound webhook deliveries (F-06-06): ``webhook.delivered`` / ``webhook.failed`` carry
    #: the integration name, the scan and the HTTP status, so "did the ticket open?" is
    #: answerable from the audit trail. A failed delivery never fails a scan.
    WEBHOOK_DELIVERED = "webhook.delivered"
    WEBHOOK_FAILED = "webhook.failed"
    #: A background scan was cancelled by an operator through the API (S12). Distinct from
    #: ``scan.failed``: an abort is deliberate, and the scan is resumable from its last step.
    SCAN_ABORTED = "scan.aborted"
    #: An operator's decision on a finding through the API (F-05-07): the FP mark the tuner
    #: reads, and a status transition (``open``/``verified``/``fp``/``merged``).
    FINDING_REVIEWED = "finding.reviewed"
    #: A report was rendered on demand through the API/UI (F-06-02).
    REPORT_GENERATED = "report.generated"
    #: S14 (multi-tenancy, F-07-06): a project was created, updated or deleted. A tenant
    #: boundary change is an administrative action and belongs in the same trail as a scan.
    PROJECT_CHANGED = "project.changed"
    #: S14 (F-09-03): a CVE/EPSS artefact was ingested — kind, entry count and who imported
    #: it — so "which vulnerability data is this deployment correlating against?" is
    #: answerable from the audit trail.
    FEED_IMPORTED = "feed.imported"
    #: S14 (F-09-01): a plugin was installed through the API (the CLI has no audit sink by
    #: design — it is an operator at a shell). Records the source and what appeared.
    PLUGIN_INSTALLED = "plugin.installed"
    #: S15 (area PROOF): the proof ladder. ``proof.rejected`` is a refused L3/L4 plan
    #: (REQ-PROOF-003: every refusal is audited); ``proof.downgraded`` records a check
    #: running below its declared level because a capability (the OOB service) is
    #: unavailable — a downgrade is recorded, never silent, and never an upgrade.
    PROOF_REJECTED = "proof.rejected"
    PROOF_DOWNGRADED = "proof.downgraded"
    #: S15 OOB callbacks (REQ-PROOF-005): a token issued, a hit recorded, a replay
    #: attempt refused (single-use matching).
    PROOF_OOB_ISSUED = "proof.oob_issued"
    PROOF_OOB_HIT = "proof.oob_hit"
    PROOF_OOB_REPLAY = "proof.oob_replay"
    #: WP-14 (area PROOF, REQ-PROOF-019): a callback the receiver *refused* — a forged or
    #: missing per-scan secret MAC, a scan that is not active, or a token past its replay
    #: window. Distinct from ``proof.oob_hit`` (which also carries the malformed-token and
    #: rate-limit refusals that predate this package) so an operator can alert on
    #: "someone is trying to forge callbacks" separately from "the target is chatty".
    PROOF_OOB_REFUSED = "proof.oob_refused"
    #: WP-14 (area PROOF, REQ-PROOF-017): the per-scan residue attestation. One line per
    #: scan, carrying the attestation's hash (so the chain links it), the residue count and
    #: whether the deployment key signed it. A non-zero residue is also one
    #: ``proof.repair_required`` line per unrestored change (the pre-existing action).
    PROOF_RESIDUE_ATTESTED = "proof.residue_attested"
    #: S15 L3 one-shot command proof (REQ-PROOF-007): the single allowlisted echo.
    PROOF_COMMAND_EXECUTED = "proof.command_executed"
    #: S15 L4 state changes (REQ-PROOF-008/010): every write, every restore, the end-of-scan
    #: cleanup pass, and — when a crash left a change unrestored — the repair instruction
    #: an operator must follow.
    PROOF_STATE_CHANGED = "proof.state_changed"
    PROOF_STATE_RESTORED = "proof.state_restored"
    PROOF_CLEANUP_COMPLETED = "proof.cleanup_completed"
    PROOF_REPAIR_REQUIRED = "proof.repair_required"
    #: WP-13 (area PROOF, REQ-PROOF-015/016): the per-finding verification record.
    #: ``finding.verification_recorded`` names a record that now exists (the parent, when a
    #: re-verification writes its own); ``finding.reverified`` records a completed
    #: re-verification with its outcome; ``finding.reverify_refused`` a re-verification the
    #: gates refused — expired or non-covering attestation, out-of-scope asset, or a check
    #: whose declared proof level now sits above the record it would re-check (never an
    #: escalation). A refusal is audited *and* returned non-zero by the CLI.
    FINDING_VERIFICATION_RECORDED = "finding.verification_recorded"
    FINDING_REVERIFIED = "finding.reverified"
    FINDING_REVERIFY_REFUSED = "finding.reverify_refused"
    #: S16 (area SCALE): the distributed work queue. ``scan.enqueued`` is a producer
    # (API or scheduler) queueing an admitted scan; ``scan.leased``/``scan.released``
    # book-end one agent's execution of it (the agent's identity is in ``meta`` and in
    # the actor of every audit line its execution writes); ``scan.interrupted`` records
    # a lease that expired with the agent gone — the scan becomes re-leasable
    # (REQ-SCALE-003); ``agent.registered``/``agent.heartbeat`` are the agent role's
    # control-plane trail.
    SCAN_ENQUEUED = "scan.enqueued"
    SCAN_LEASED = "scan.leased"
    SCAN_RELEASED = "scan.released"
    SCAN_INTERRUPTED = "scan.interrupted"
    AGENT_REGISTERED = "agent.registered"
    AGENT_HEARTBEAT = "agent.heartbeat"
    #: S17 (area IDAM): enterprise identity. ``auth.sso_login`` records both the start of an
    #: authorization-code flow and the minted session (the ``reason`` distinguishes them);
    #: ``auth.sso_logout`` a revoked session. Refusals use ``api.denied`` (same trail as a
    #: wrong API key), and ``service_account.changed`` records a key created, rotated or
    #: revoked (REQ-IDAM-003) — an access change is an administrative event.
    AUTH_SSO_LOGIN = "auth.sso_login"
    AUTH_SSO_LOGOUT = "auth.sso_logout"
    SERVICE_ACCOUNT_CHANGED = "service_account.changed"
    #: S18 (area INTEL): live threat intel. ``intel.feed_fetched`` is one line per request to
    #: a feed source; ``intel.feed_verified`` / ``intel.feed_rejected`` record the integrity
    #: decision **before** an import (REQ-INTEL-002 — a tampered mirror is a security event,
    #: not a parsing detail); ``intel.feed_synced`` is one line per imported feed with its
    #: version and digest, so "which vulnerability data was this scan built on?" is
    #: answerable from the trail. ``intel.index_built`` records a regenerated CVE baseline and
    #: ``intel.checksums_pinned`` the explicit operator act of pinning a freshly trusted
    #: fetch. ``intel.provider_blocked`` marks a third-party provider call refused for want of
    #: opt-in or a key (REQ-INTEL-005), and ``intel.rate_limited`` a call the provider layer
    #: deliberately slowed down (REQ-INTEL-003).
    INTEL_FEED_FETCHED = "intel.feed_fetched"
    INTEL_FEED_VERIFIED = "intel.feed_verified"
    INTEL_FEED_REJECTED = "intel.feed_rejected"
    INTEL_FEED_SYNCED = "intel.feed_synced"
    INTEL_INDEX_BUILT = "intel.index_built"
    INTEL_CHECKSUMS_PINNED = "intel.checksums_pinned"
    INTEL_PROVIDER_BLOCKED = "intel.provider_blocked"
    INTEL_RATE_LIMITED = "intel.rate_limited"
    #: S19 (area CREDS): authenticated scanning. ``credential.stored``/``credential.revoked``
    #: are the operator's vault write actions (a label and a scope summary — never material);
    #: ``credential.released`` records that a credential was handed to an authenticated
    #: request for a covered target, and ``credential.scope_rejected`` a refusal because the
    #: credential is not scoped to the target or the target is not in the scan (REQ-CREDS-005).
    #: ``credential.unresolved`` is the internal-agent case: a scan named a label this node
    #: does not hold, so it runs **unauthenticated** rather than borrowing one from elsewhere
    #: (REQ-CREDS-003). ``auth.session_expired``/``auth.logout_observed`` record the session
    #: lifecycle findings (REQ-CREDS-001).
    CREDENTIAL_STORED = "credential.stored"
    CREDENTIAL_REVOKED = "credential.revoked"
    CREDENTIAL_RELEASED = "credential.released"
    CREDENTIAL_SCOPE_REJECTED = "credential.scope_rejected"
    CREDENTIAL_UNRESOLVED = "credential.unresolved"
    AUTH_SESSION_ESTABLISHED = "auth.session_established"
    AUTH_SESSION_EXPIRED = "auth.session_expired"
    AUTH_LOGOUT_OBSERVED = "auth.logout_observed"
    #: The agent's runtime mode (S19, REQ-CREDS-003): recorded once at registration so the
    #: trail says whether a node was deployed outside the target network or inside it.
    AGENT_MODE = "agent.mode"
    #: S20 (area DATA/OPS): the data lifecycle. ``retention.planned`` is the dry run — what
    #: would be deleted and why — and ``retention.pruned`` the applied run; both carry the
    #: per-category counts, so the trail answers "what did we delete and under whose
    #: policy". ``evidence.stored`` records that a payload was offloaded to a backend (key,
    #: digest and size — never the payload). ``quota.warning`` is the soft-threshold notice
    #: and ``quota.exceeded`` the hard stop that fails — and therefore makes resumable — the
    #: scan that crossed the limit (REQ-DATA-001/002/003).
    RETENTION_PLANNED = "retention.planned"
    RETENTION_PRUNED = "retention.pruned"
    EVIDENCE_STORED = "evidence.stored"
    #: WP-14 (area PROOF/DATA, REQ-PROOF-018): **every** evidence blob's content hash is
    #: recorded in the audit chain as it is captured (``evidence.captured``), so a later
    #: edit to a stored payload is detectable by ``arachne verify-chain`` even on a
    #: deployment whose rows carry no signature. ``pii.masked`` is the capture-time masking
    #: the evidence service already audits; ``pii.remasked`` (WP-14, REQ-DATA-005) is the
    #: retention pruner re-masking an **older** blob under a policy that arrived later — one
    #: line per masked blob, carrying the blob's *new* content hash, so the chain-of-custody
    #: record follows an authorized mutation instead of contradicting it.
    #: ``pii.remask_unsupported`` reports, once per run, the blobs a store could not
    #: re-mask (an offloaded object store, here) — reported rather than skipped in silence.
    #: The literals live in :mod:`arachne.core.integrity` (the module that has to
    #: recognise these events while walking the chain) and are bound here so the writer and
    #: the verifier cannot drift apart.
    EVIDENCE_CAPTURED = EVIDENCE_CAPTURED_ACTION
    PII_REMASKED = PII_REMASKED_ACTION
    PII_REMASK_UNSUPPORTED = "pii.remask_unsupported"
    QUOTA_WARNING = "quota.warning"
    QUOTA_EXCEEDED = "quota.exceeded"
    #: S21 (area AGENT): the agentic hypothesis loop. ``hypothesis.proposed`` is one line per
    #: reasoning pass (how many proposals, which engine, whether it degraded);
    #: ``hypothesis.executed``/``hypothesis.refused`` are per hypothesis, and every refusal
    #: carries its code — an AI output that tried to widen scope, invent a check, escalate
    #: proof or exceed the budget is *visible* in the trail, not silently dropped
    #: (REQ-AGENT-005). ``hypothesis.paused``/``aborted``/``resumed`` are the operator kill
    #: switch's trail (REQ-AGENT-007), and ``hypothesis.injection_suspected`` records hostile
    #: content found in a target's own output (REQ-AGENT-006) — detected, never obeyed.
    HYPOTHESIS_PROPOSED = "hypothesis.proposed"
    HYPOTHESIS_EXECUTED = "hypothesis.executed"
    HYPOTHESIS_REFUSED = "hypothesis.refused"
    HYPOTHESIS_PAUSED = "hypothesis.paused"
    HYPOTHESIS_ABORTED = "hypothesis.aborted"
    HYPOTHESIS_RESUMED = "hypothesis.resumed"
    HYPOTHESIS_COMPLETED = "hypothesis.completed"
    HYPOTHESIS_INJECTION_SUSPECTED = "hypothesis.injection_suspected"
    #: S21 (area QUAL): the quality workflow. ``suppression.changed`` records a suppression
    #: rule added, revoked or expired (versioned, attributed, commented — REQ-QUAL-002);
    #: ``acceptance.changed`` a risk acceptance recorded or withdrawn and
    #: ``acceptance.expired`` the automatic re-open of its finding (REQ-QUAL-003).
    #: ``benchmark.completed`` is one scored benchmark run and ``benchmark.regressed`` the
    #: gate-blocking comparison against the committed baseline (REQ-QUAL-005);
    #: ``synthesis.proposed`` a reviewable check artifact the self-improvement loop produced
    #: — never deployed (REQ-AGENT-004).
    SUPPRESSION_CHANGED = "suppression.changed"
    ACCEPTANCE_CHANGED = "acceptance.changed"
    ACCEPTANCE_EXPIRED = "acceptance.expired"
    BENCHMARK_COMPLETED = "benchmark.completed"
    BENCHMARK_REGRESSED = "benchmark.regressed"
    SYNTHESIS_PROPOSED = "synthesis.proposed"
    #: S23 (area POSTURE): continuous exposure management. ``posture.baseline_saved``
    #: records a continuous cloud-config run committing its state snapshot (the drift
    #: baseline, REQ-POSTURE-001) and ``posture.drift`` the delta findings a run emitted
    #: against the previous baseline. ``posture.fix_verified`` is an auto-close on
    #: verified absence, ``posture.fix_still_open`` a verification that found the finding
    #: still present and ``posture.fix_reopened`` an auto-reopen on regression — each with
    #: the linked evidence on the original finding (REQ-POSTURE-003).
    #: ``posture.cmdb_imported`` records a criticality import (REQ-POSTURE-006).
    POSTURE_BASELINE_SAVED = "posture.baseline_saved"
    POSTURE_DRIFT = "posture.drift"
    POSTURE_FIX_VERIFIED = "posture.fix_verified"
    POSTURE_FIX_STILL_OPEN = "posture.fix_still_open"
    POSTURE_FIX_REGRESSED = "posture.fix_reopened"
    POSTURE_CMDB_IMPORTED = "posture.cmdb_imported"
    #: S23: continuous-mode cost guardrails (risk R-13). ``schedule.budget_refused`` is a
    #: schedule whose budget (runs per window, estimated requests) stopped its run — the
    #: refusal is the guardrail working, so it is audited, not logged-and-forgotten.
    SCHEDULE_BUDGET_REFUSED = "schedule.budget_refused"
    #: S23 (REQ-POSTURE-005): one Kubernetes admission review evaluated. Monitor mode
    #: records the findings and allows; an enforce-mode denial carries
    #: ``outcome=blocked``. Never emitted by anything but the admission route.
    ADMISSION_REVIEWED = "admission.reviewed"
    #: S24 (area VALID): purple-team detection validation. ``purple.window_refused`` is a
    #: purple action refused because the coordinated detection window is not open (absent,
    #: not yet started, or already closed) — the window-enforcement refusal, always audited
    #: (REQ-VALID-001/003). ``purple.window_closed`` records the **auto-stop**: the window
    #: ended mid-run, so the remaining actions were skipped rather than fired.
    #: ``purple.action_emitted`` is one line per emitted test artifact, carrying the
    #: technique, tactic, campaign and run nonce — the visible-by-design tag
    #: (REQ-VALID-003). ``purple.alert_ingested`` is one ingested defender alert;
    #: ``purple.coverage_scored`` one scoring pass with its coverage and gap count; and
    #: ``purple.coverage_regressed`` a technique that was seen before and is unseen now
    #: (the campaign trend's regression alert, REQ-VALID-006).
    PURPLE_WINDOW_REFUSED = "purple.window_refused"
    PURPLE_WINDOW_CLOSED = "purple.window_closed"
    #: A purple run was admitted: the campaign, the run nonce and the window it will run
    #: inside — the line an operator correlates a defender's alert timeline against.
    PURPLE_RUN_STARTED = "purple.run_started"
    PURPLE_ACTION_EMITTED = "purple.action_emitted"
    PURPLE_ALERT_INGESTED = "purple.alert_ingested"
    PURPLE_COVERAGE_SCORED = "purple.coverage_scored"
    PURPLE_COVERAGE_REGRESSED = "purple.coverage_regressed"
    #: A purple campaign was created, updated or removed (an administrative act, like a
    #: project or a service-account change).
    PURPLE_CAMPAIGN_CHANGED = "purple.campaign_changed"
    #: S25 (areas RESIL + TRUST): the platform-ceiling work. ``integrity.anchored`` is a
    #: signed checkpoint of the audit chain's head and ``integrity.sealed`` the signed
    #: manifest of a completed scan's findings/evidence; ``integrity.verified`` records a
    #: verification run and its verdict, and ``integrity.tamper`` a **failed** one — the
    #: line an operator must find, so it is emitted with ``outcome=blocked`` and is never
    #: silent. ``airgap.blocked`` is an egress attempt refused because the deployment runs
    #: air-gapped (REQ-RESIL-001), and ``pii.masked`` counts the PII categories removed
    #: from an evidence payload under a project's policy — never the values
    #: (REQ-TRUST-006). ``pack.imported``/``pack.exported`` carry a content pack's digest
    #: and signer, and ``pack.rejected`` a refused one (REQ-RESIL-001). ``leader.acquired``
    #: /``leader.lost`` are the singleton-election transitions (REQ-RESIL-002), and
    #: ``residency.rejected`` a cross-region evidence access refused (REQ-RESIL-004).
    #: ``backup.created``/``backup.restored`` are the disaster-recovery acts
    #: (REQ-RESIL-005).
    INTEGRITY_ANCHORED = "integrity.anchored"
    INTEGRITY_SEALED = "integrity.sealed"
    INTEGRITY_VERIFIED = "integrity.verified"
    INTEGRITY_TAMPER = "integrity.tamper"
    AIRGAP_BLOCKED = "airgap.blocked"
    PII_MASKED = "pii.masked"
    PACK_IMPORTED = "pack.imported"
    PACK_EXPORTED = "pack.exported"
    PACK_REJECTED = "pack.rejected"
    PACK_REVIEWED = "pack.reviewed"
    LEADER_ACQUIRED = "leader.acquired"
    LEADER_LOST = "leader.lost"
    RESIDENCY_REJECTED = "residency.rejected"
    BACKUP_CREATED = "backup.created"
    BACKUP_RESTORED = "backup.restored"

    #: S27 (area FIX): remediation as code. Every act of a proposal's life is its own event,
    #: because the trail has to answer "who let this happen" at each step rather than only
    #: "a proposal existed": ``fix.proposal_created``/``fix.proposal_refused`` (the artifact,
    #: or the refusal and why), ``fix.proposal_approved``/``fix.proposal_rejected`` (the
    #: human gate, REQ-FIX-001), ``fix.tests_failed`` (a proposal that failed the
    #: repository's own suite — flagged, never submitted, risk R-18),
    #: ``fix.branch_created``/``fix.pr_opened`` (the arachne-fix-* branch and its PR
    #: artifact, REQ-FIX-002), ``fix.self_scan`` (the IaC self-scan verdict, REQ-FIX-004),
    #: ``fix.applied`` (a human says the fix landed) and
    #: ``fix.verified``/``fix.still_open`` (the loop's verdict, REQ-FIX-005).
    #: ``fix.ai_parity`` records a second engine's agreement or divergence (REQ-FIX-006),
    #: and ``fix.grant_refused`` a proposal against a repository no grant covers.
    FIX_PROPOSAL_CREATED = "fix.proposal_created"
    FIX_PROPOSAL_REFUSED = "fix.proposal_refused"
    FIX_PROPOSAL_APPROVED = "fix.proposal_approved"
    FIX_PROPOSAL_REJECTED = "fix.proposal_rejected"
    FIX_TESTS_FAILED = "fix.tests_failed"
    FIX_BRANCH_CREATED = "fix.branch_created"
    FIX_PR_OPENED = "fix.pr_opened"
    FIX_SELF_SCAN = "fix.self_scan"
    FIX_APPLIED = "fix.applied"
    FIX_VERIFIED = "fix.verified"
    FIX_STILL_OPEN = "fix.still_open"
    FIX_AI_PARITY = "fix.ai_parity"
    FIX_GRANT_REFUSED = "fix.grant_refused"

    #: S28 (area SIM): simulation and what-if modeling. ``simulation.model_built`` records
    #: the estate model a simulation was computed over (node/edge counts and the scans it
    #: was read from — never target interaction, because the model is built from stored scan
    #: data only, REQ-SIM-001); ``simulation.run`` a what-if or change simulation with its
    #: hypotheses and the paths it produced; ``simulation.resimulated`` an event-driven
    #: re-run feeding the posture trend (REQ-SIM-006); and
    #: ``simulation.boundary_violation`` **blocks** — it is the audit record of an attempted
    #: network call inside the zero-network boundary, which is a safety refusal and never a
    #: silent skip (REQ-SIM-003).
    SIMULATION_MODEL_BUILT = "simulation.model_built"
    SIMULATION_RUN = "simulation.run"
    SIMULATION_RESIMULATED = "simulation.resimulated"
    SIMULATION_BOUNDARY_VIOLATION = "simulation.boundary_violation"

    #: S30 (area FUZZ): bounded safe fuzzing. The vocabulary is deliberately split so the
    #: trail can answer the four questions a fuzzing run has to answer.
    #: ``fuzz.authorized``/``fuzz.refused`` are the attestation gate's two outcomes — a
    #: refusal is *blocked* and is recorded **before** anything is sent, which is what makes
    #: "unattested fuzzing never reached a socket" checkable from the trail.
    #: ``fuzz.health`` is one probe of the target's health (the baseline before a batch and
    #: the confirming probe after it), so "the service was healthy before and after" is
    #: evidence rather than an assertion. ``fuzz.candidate`` is a signal worth following up —
    #: always a *candidate*, never a finding, because only the proof ladder reports
    #: (REQ-FUZZ-003/004). There is deliberately no per-case action: every case already leaves
    #: a ``net.probe``/``http.request`` line from the egress client, and a second line saying
    #: the same thing would double the trail without adding an answer.
    #: ``fuzz.payload_refused`` records a prohibited payload the engine produced and that was
    #: discarded inside the process; ``fuzz.aborted`` is the degradation guard's stop, with
    #: the measured signal that stopped it (REQ-FUZZ-005); ``fuzz.budget_exhausted`` a hard
    #: bound being spent; ``fuzz.batch_complete`` and ``fuzz.finished`` close the run out.
    FUZZ_AUTHORIZED = "fuzz.authorized"
    FUZZ_REFUSED = "fuzz.refused"
    FUZZ_HEALTH = "fuzz.health"
    FUZZ_CANDIDATE = "fuzz.candidate"
    FUZZ_PAYLOAD_REFUSED = "fuzz.payload_refused"
    FUZZ_ABORTED = "fuzz.aborted"
    FUZZ_BUDGET_EXHAUSTED = "fuzz.budget_exhausted"
    FUZZ_BATCH_COMPLETE = "fuzz.batch_complete"
    FUZZ_FINISHED = "fuzz.finished"


class AuditOutcome(StrEnum):
    ALLOWED = "allowed"
    BLOCKED = "blocked"
    ERROR = "error"


class AuditEvent(BaseModel):
    """One audit record. Fixed schema; ``meta`` carries the detail.

    The four ``hash-chain`` fields (S25) are filled by the :class:`AuditChain` the
    :class:`Auditor` is attached to. They are ``None`` on a deployment with no chain
    (a dry run, an in-memory sink) and on rows written before S25 — a verifier starts at
    the first row that carries a ``seq``.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    schema_version: str = AUDIT_SCHEMA_VERSION
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    ts: datetime = Field(default_factory=lambda: datetime.now(UTC))
    actor: str = "system"
    action: AuditAction
    outcome: AuditOutcome = AuditOutcome.ALLOWED
    target: str | None = None
    reason: str | None = None
    scan_id: int | str | None = None
    meta: dict[str, Any] = Field(default_factory=dict)
    #: Position in the audit hash chain (S25, REQ-TRUST-005).
    seq: int | None = None
    #: The hash of the event before this one; the genesis constant when nothing was pruned.
    prev_hash: str | None = None
    #: This event's digest: content + position (``core.integrity.chain_digest``).
    hash: str | None = None
    #: ``v1:<key id>:<hex>`` — the deployment key's signature over :attr:`hash`.
    signature: str | None = None

    @field_validator("ts")
    @classmethod
    def _require_tz(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            msg = "audit timestamps must be timezone-aware (UTC)"
            raise ValueError(msg)
        return value.astimezone(UTC)

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe, redacted representation (used by every sink)."""
        return {
            "schema_version": self.schema_version,
            "id": self.id,
            "ts": self.ts.isoformat(),
            "actor": self.actor,
            "action": self.action.value,
            "outcome": self.outcome.value,
            "target": self.target,
            "reason": self.reason,
            "scan_id": self.scan_id,
            "meta": self.meta,
            "seq": self.seq,
            "prev_hash": self.prev_hash,
            "hash": self.hash,
            "signature": self.signature,
        }


class AuditSink(Protocol):
    """Destination for audit events."""

    def record(self, event: AuditEvent) -> None:
        """Persist one event. Implementations must not raise on I/O failure."""
        ...


class AuditChain(Protocol):
    """The tamper-evident position of one event (S25, REQ-TRUST-005).

    Called by :class:`Auditor` *before* any sink sees the event, so every sink records the
    same ``seq``/``prev_hash``/``hash``/``signature``. The implementation owns the
    serialisation that makes concurrent writers produce one chain (the database-backed one
    in ``arachne.data.integrity_store`` retries on a lost race); a caller never has to.
    """

    def append(self, payload: Mapping[str, Any]) -> tuple[int, str, str, str | None]:
        """``(seq, prev_hash, hash, signature)`` for the next link of ``payload``."""
        ...


class MemoryAuditSink:
    """In-memory sink for tests and dry runs."""

    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def record(self, event: AuditEvent) -> None:
        self.events.append(event)

    def actions(self) -> list[str]:
        return [event.action.value for event in self.events]

    def of_action(self, action: AuditAction) -> list[AuditEvent]:
        return [event for event in self.events if event.action is action]


class MemoryAuditChain:
    """An in-process chain (tests, dry runs, a single-node deployment without a database).

    Same arithmetic as the database-backed chain, so a test can assert the whole
    tamper-evidence story — modify a link, delete one, truncate the tail — without a
    database. Thread-safe: the ``Auditor`` may be shared by a scan's worker threads.
    """

    def __init__(self, *, signer: Signer | None = None, start_seq: int = 1) -> None:
        self.links: list[dict[str, Any]] = []
        self._signer = signer
        self._seq = start_seq
        self._prev = GENESIS_HASH
        self._lock = threading.Lock()

    def append(self, payload: Mapping[str, Any]) -> tuple[int, str, str, str | None]:
        with self._lock:
            seq, prev = self._seq, self._prev
            digest = chain_digest(seq, prev, payload)
            signature = (
                self._signer.sign(AUDIT_DOMAIN, digest.encode("ascii"))
                if self._signer is not None
                else None
            )
            self.links.append(
                {
                    "seq": seq,
                    "prev_hash": prev,
                    "hash": digest,
                    "signature": signature,
                    "payload": audit_payload(payload),
                }
            )
            self._seq, self._prev = seq + 1, digest
            return seq, prev, digest, signature


class JsonlAuditSink:
    """Append-only newline-delimited JSON file. Thread-safe within one process."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()

    def record(self, event: AuditEvent) -> None:
        line = json.dumps(event.to_dict(), default=str, ensure_ascii=False, sort_keys=True)
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self._lock, self.path.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")
        except OSError as exc:  # audit failure must not abort the scan
            _logger.error(
                "audit sink write failed", extra={"event": "audit.sink_error", "error": str(exc)}
            )


class LoggingAuditSink:
    """Mirror audit events into the structured logger."""

    def __init__(self, logger_name: str = "core.audit") -> None:
        self._logger = get_logger(logger_name)

    def record(self, event: AuditEvent) -> None:
        self._logger.info(event.action.value, extra={"event": "audit", **event.to_dict()})


class MultiAuditSink:
    """Fan out to several sinks."""

    def __init__(self, sinks: Iterable[AuditSink] = ()) -> None:
        self._sinks = list(sinks)

    def add(self, sink: AuditSink) -> None:
        self._sinks.append(sink)

    def record(self, event: AuditEvent) -> None:
        for sink in self._sinks:
            try:
                sink.record(event)
            except Exception:
                _logger.exception("audit sink raised", extra={"event": "audit.sink_error"})


class Auditor:
    """Facade used by the rest of the codebase to emit audit events."""

    def __init__(
        self,
        sink: AuditSink | None = None,
        *,
        actor: str = "system",
        chain: AuditChain | None = None,
    ) -> None:
        self._sink: AuditSink = sink or MultiAuditSink()
        self.actor = actor
        #: The tamper-evident position of every event this facade emits (S25). ``None``
        #: (the default) leaves the chain fields empty: a dry run and the CLI's ad-hoc
        #: auditors have no durable trail to chain, and pretending otherwise would be
        #: worse than saying so.
        self._chain = chain

    def with_actor(self, actor: str) -> Auditor:
        """A facade over the *same sink* that signs events as ``actor`` (S16).

        An agent executing a scan on a node writes every scan/step/check line with its
        own identity (``agent:<name>``), so the audit trail answers "which node ran
        this?" without a second trail. The sink — and the audit chain — are shared, never
        duplicated: a second chain would fork the very sequence the verifier walks.
        """
        return Auditor(self._sink, actor=actor, chain=self._chain)

    def record(
        self,
        action: AuditAction,
        *,
        outcome: AuditOutcome = AuditOutcome.ALLOWED,
        target: str | None = None,
        reason: str | None = None,
        scan_id: int | str | None = None,
        meta: dict[str, Any] | None = None,
    ) -> AuditEvent:
        """Build, redact, chain and emit one audit event."""
        event = AuditEvent(
            actor=self.actor,
            action=action,
            outcome=outcome,
            target=redact_url(target) if target else None,
            reason=redact_text(reason) if reason else None,
            scan_id=scan_id,
            meta=redact_mapping(meta or {}),
        )
        if self._chain is not None:
            # The chain is appended *before* the sinks see the event, so every sink
            # records one identical, already-chained row. The payload excludes the chain
            # fields by construction (``core.integrity.audit_payload`` strips them), so
            # the digest a verifier recomputes matches without a side table.
            seq, prev_hash, digest, signature = self._chain.append(event.to_dict())
            event = event.model_copy(
                update={
                    "seq": seq,
                    "prev_hash": prev_hash,
                    "hash": digest,
                    "signature": signature,
                }
            )
        self._sink.record(event)
        return event


def build_auditor(
    settings: Settings | None = None,
    *,
    sinks: Iterable[AuditSink] = (),
    actor: str | None = None,
    chain: AuditChain | None = None,
    logging_enabled: bool = True,
) -> Auditor:
    """Assemble the auditor a scan should use (F-01-08).

    Every deployment gets the structured-log sink (so an audit line is always visible),
    the JSONL sink when ``ARACHNE_AUDIT_LOG_PATH`` is set (the durable, greppable trail),
    and whatever additional sinks the caller supplies — the CLI adds the ``audit_log``
    table sink. Sinks are failure-tolerant (see :class:`MultiAuditSink`), so a store
    outage degrades the trail instead of aborting a scan.

    ``chain`` (S25) is the tamper-evident sequence the events are appended to. The
    composition root passes the database-backed chain; a caller that omits it gets an
    unchained trail, which ``arachne verify-chain`` reports as such rather than as intact.
    """
    effective = settings or get_settings()
    composite = MultiAuditSink()
    if logging_enabled:
        composite.add(LoggingAuditSink())
    if effective.audit_log_path:
        composite.add(JsonlAuditSink(effective.audit_log_path))
    for sink in sinks:
        composite.add(sink)
    return Auditor(composite, actor=actor or effective.actor, chain=chain)
