"""Core services: configuration, safety, audit, logging, HTTP client, results.

Stage S1 provides the foundation layer every later stage builds on; S2 adds the scan
orchestration on top of it:

==============================  ====================================================
Module                          Requirement
==============================  ====================================================
:mod:`~arachne.core.config`     env-only settings (F-08-01)
:mod:`~arachne.core.safety`     SSRF-by-design URL validation + scope (F-08-03, F-01-02)
:mod:`~arachne.core.http`       the single scoped HTTP client (ADR-05, F-01-07/08)
:mod:`~arachne.core.audit`      fixed audit event schema + sinks (F-01-08, F-08-05)
:mod:`~arachne.core.redaction`  secret redaction at capture time (F-08-01/04)
:mod:`~arachne.core.results`    ``CheckResult`` / ``Evidence`` + error model (F-02-08)
:mod:`~arachne.core.logging`    structured JSON logs with redaction
:mod:`~arachne.core.target`     target definition, exclusions, attestation (F-01-01/09)
:mod:`~arachne.core.catalog`    the planning catalogue of checks (F-01-10)
:mod:`~arachne.core.planner`    scan plan + dry-run estimation (F-01-03, F-01-10)
:mod:`~arachne.core.events`     typed event bus
:mod:`~arachne.core.lifecycle`  scan state machine + resumability (F-01-04)
:mod:`~arachne.core.orchestrator`  gates, wiring, plan/run/resume
==============================  ====================================================
"""

from __future__ import annotations

from arachne.core.audit import AuditAction, AuditEvent, Auditor, AuditOutcome, build_auditor
from arachne.core.catalog import PlanningCatalog, load_catalog
from arachne.core.config import Settings, get_settings
from arachne.core.errors import (
    ArachneError,
    AuthorizationError,
    ConfigurationError,
    ErrorInfo,
    OutOfScopeError,
    PlanningError,
    RequestError,
    SafetyError,
    ScanStateError,
    UnsafeUrlError,
)
from arachne.core.events import Event, EventBus, EventType
from arachne.core.http import HttpExchange, ScopedHttpClient
from arachne.core.lifecycle import (
    MemoryScanStateStore,
    ScanMachine,
    ScanRecord,
    ScanStatus,
    StepContext,
    StepOutcome,
    StepState,
    StepStatus,
)
from arachne.core.logging import configure_logging, get_logger
from arachne.core.orchestrator import Orchestrator, ScanSession
from arachne.core.planner import PlannedCheck, Planner, PlanStep, ScanPlan, ScanStep
from arachne.core.ratelimit import HostRateLimiter, RateLimitSettings, TokenBucket
from arachne.core.redaction import redact_mapping, redact_text, redact_url
from arachne.core.results import CheckResult, Evidence, guard_check
from arachne.core.safety import Scope, ScopeDecision, UrlSafetyPolicy, validate_url
from arachne.core.target import (
    AuthorizationAttestation,
    ScanOptions,
    ScanRequest,
    TargetDefinition,
    TargetKind,
    TargetSelector,
    load_scan_request,
)

__all__ = [
    "ArachneError",
    "AuditAction",
    "AuditEvent",
    "AuditOutcome",
    "Auditor",
    "AuthorizationAttestation",
    "AuthorizationError",
    "CheckResult",
    "ConfigurationError",
    "ErrorInfo",
    "Event",
    "EventBus",
    "EventType",
    "Evidence",
    "HostRateLimiter",
    "HttpExchange",
    "MemoryScanStateStore",
    "Orchestrator",
    "OutOfScopeError",
    "PlanStep",
    "PlannedCheck",
    "Planner",
    "PlanningCatalog",
    "PlanningError",
    "RateLimitSettings",
    "RequestError",
    "SafetyError",
    "ScanMachine",
    "ScanOptions",
    "ScanPlan",
    "ScanRecord",
    "ScanRequest",
    "ScanSession",
    "ScanStateError",
    "ScanStatus",
    "ScanStep",
    "Scope",
    "ScopeDecision",
    "ScopedHttpClient",
    "Settings",
    "StepContext",
    "StepOutcome",
    "StepState",
    "StepStatus",
    "TargetDefinition",
    "TargetKind",
    "TargetSelector",
    "TokenBucket",
    "UnsafeUrlError",
    "UrlSafetyPolicy",
    "build_auditor",
    "configure_logging",
    "get_logger",
    "get_settings",
    "guard_check",
    "load_catalog",
    "load_scan_request",
    "redact_mapping",
    "redact_text",
    "redact_url",
    "validate_url",
]
