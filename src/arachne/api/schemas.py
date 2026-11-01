"""Request/response models for the REST API (F-07-02, S12).

These are the shapes the OpenAPI document advertises. Two rules keep them honest:

* **Responses are built from the same dicts the UI renders**, so a field cannot appear in
  one interface and not the other. The models below are mostly a typed view over those
  dicts (``to_dict`` on the store rows), not a second source of truth.
* **Requests are validated before they reach business logic.** A scan start is either a
  full target definition (the fixture document) or a stored target id — never both, never
  neither — and a findings review is a status from the fixed vocabulary (F-05-07).
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

__all__ = [
    "AgentCompleteIn",
    "AgentHeartbeatIn",
    "AgentLeaseIn",
    "AgentRegisterIn",
    "BrandingIn",
    "FeedImport",
    "FindingOut",
    "FindingReview",
    "HealthOut",
    "ModuleOut",
    "PackReviewRequest",
    "PluginInstallRequest",
    "ProjectIn",
    "ProjectOut",
    "ScanDetail",
    "ScanSummary",
    "ScheduleIn",
    "ScheduleOut",
    "ServiceAccountIn",
    "StartScanRequest",
    "TargetIn",
    "TargetOut",
    "WebhookDeliveryOut",
]

_MODEL = ConfigDict(extra="forbid")


class HealthOut(BaseModel):
    """``GET /health`` — liveness and the interface build."""

    status: str = "ok"
    version: str
    database: str
    api_keys: int = 0
    docs: bool = True


class TargetIn(BaseModel):
    """A target definition as a client supplies it (the fixture document, F-01-01)."""

    model_config = _MODEL

    name: str = Field(min_length=1, max_length=255)
    targets: list[dict[str, Any]] = Field(min_length=1)
    exclusions: list[dict[str, Any]] = Field(default_factory=list)
    attestation: dict[str, Any] | None = None


class TargetOut(BaseModel):
    """A stored target as the API returns it."""

    model_config = _MODEL

    id: int
    name: str
    scope: dict[str, Any] = Field(default_factory=dict)
    attestation: dict[str, Any] | None = None
    created_at: str | None = None
    project_id: int | None = None


class StartScanRequest(BaseModel):
    """Start a scan: either a full target definition or a stored target id.

    ``options`` carries the same overrides a fixture's ``options`` block does
    (``engine``, ``active_checks``, ``modules``, ``notes``). ``dry_run`` plans without
    sending anything (F-01-10) and returns the plan instead of a scan id.
    """

    model_config = _MODEL

    target: dict[str, Any] | None = None
    target_id: int | None = None
    options: dict[str, Any] | None = None
    dry_run: bool = False

    @model_validator(mode="after")
    def _exactly_one_target(self) -> StartScanRequest:
        supplied = sum(item is not None for item in (self.target, self.target_id))
        if supplied == 0:
            msg = "provide either 'target' (a definition) or 'target_id' (a stored target)"
            raise ValueError(msg)
        if supplied == 2:
            msg = "'target' and 'target_id' are mutually exclusive"
            raise ValueError(msg)
        return self


class ScanSummary(BaseModel):
    """One row of ``GET /scans`` — the dashboard's data."""

    model_config = _MODEL

    id: int
    target_id: int | None = None
    target_name: str | None = None
    status: str
    engine: str
    created_at: str | None = None
    started_at: str | None = None
    finished_at: str | None = None
    counts: dict[str, int] = Field(default_factory=dict)
    total_findings: int = 0
    running: bool = False


class StepOut(BaseModel):
    model_config = _MODEL

    step: str
    status: str
    attempts: int = 0
    error: str | None = None
    stats: dict[str, Any] = Field(default_factory=dict)


class ScanDetail(ScanSummary):
    """``GET /scans/{id}`` — the summary plus the per-step progress."""

    model_config = _MODEL

    plan: dict[str, Any] = Field(default_factory=dict)
    stats: dict[str, Any] = Field(default_factory=dict)
    steps: list[StepOut] = Field(default_factory=list)
    assets: list[dict[str, Any]] = Field(default_factory=list)


class FindingOut(BaseModel):
    """A finding as the API/UI lists it (fields + the store ids)."""

    model_config = _MODEL

    id: int
    scan_id: int
    title: str
    severity: str | None = None
    confidence: float | None = None
    status: str = "open"
    module: str | None = None
    check_id: str | None = None
    cwe: str | None = None
    research_ref: str | None = None
    remediation_id: str | None = None
    asset: dict[str, Any] = Field(default_factory=dict)
    created_at: str | None = None


class RetentionIn(BaseModel):
    """A project's retention policy (S20, REQ-DATA-001). ``0`` keeps a category for ever."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    findings_days: int = Field(default=365, ge=0)
    evidence_days: int = Field(default=180, ge=0)
    scans_days: int = Field(default=90, ge=0)
    audit_days: int = Field(default=730, ge=0)


class QuotaIn(BaseModel):
    """A project's storage quota (S20, REQ-DATA-003); ``None`` removes the limit."""

    model_config = ConfigDict(extra="forbid")

    limit_bytes: int | None = Field(default=None, ge=0)


class FindingReview(BaseModel):
    """The F-05-07 review verb: a new status for one finding."""

    model_config = _MODEL

    status: Literal["open", "verified", "fp", "merged"]
    note: str | None = Field(default=None, max_length=2000)
    is_false_positive: bool | None = None


class SuppressionIn(BaseModel):
    """A suppression rule as an operator submits it (S21, REQ-QUAL-001/002)."""

    model_config = _MODEL

    kind: Literal["finding", "rule", "pattern"] = "rule"
    check_id: str | None = Field(default=None, max_length=128)
    asset_pattern: str | None = Field(default=None, max_length=512)
    finding_id: int | None = None
    #: Mandatory: a suppression without a reason is indistinguishable from hiding a finding.
    reason: str = Field(min_length=8, max_length=2000)
    expires_at: datetime | None = None


class SuppressionOut(BaseModel):
    """One stored suppression rule, with its version and attribution."""

    model_config = _MODEL

    id: int | None = None
    version: int
    kind: str
    check_id: str | None = None
    asset_pattern: str | None = None
    finding_id: int | None = None
    reason: str
    actor: str
    created_at: datetime
    expires_at: datetime | None = None
    active: bool


class AcceptanceIn(BaseModel):
    """A risk acceptance as an operator submits it (S21, REQ-QUAL-003)."""

    model_config = _MODEL

    finding_id: int | None = None
    check_id: str | None = Field(default=None, max_length=128)
    asset_pattern: str | None = Field(default=None, max_length=512)
    owner: str = Field(min_length=2, max_length=128)
    justification: str = Field(min_length=12, max_length=2000)
    #: Exactly one of ``expires_at`` (an explicit date) and ``ttl_days`` (a window) is needed:
    #: an acceptance without an end is a permanent hole in the process (REQ-QUAL-003).
    expires_at: datetime | None = None
    ttl_days: int | None = Field(default=None, ge=1, le=3650)

    @model_validator(mode="after")
    def _one_expiry(self) -> AcceptanceIn:
        if (self.expires_at is None) == (self.ttl_days is None):
            msg = "give exactly one of expires_at or ttl_days"
            raise ValueError(msg)
        return self


class AcceptanceOut(BaseModel):
    """One stored risk acceptance."""

    model_config = _MODEL

    id: int | None = None
    finding_id: int | None = None
    check_id: str | None = None
    asset_pattern: str | None = None
    owner: str
    justification: str
    accepted_at: datetime
    expires_at: datetime
    revoked_at: datetime | None = None
    reopened_at: datetime | None = None
    actor: str


class HypothesisControlIn(BaseModel):
    """The operator kill switch's directive (S21, REQ-AGENT-007)."""

    model_config = _MODEL

    directive: Literal["pause", "abort", "none"]


class ModuleOut(BaseModel):
    """One module group and its checks (the module-config view)."""

    model_config = _MODEL

    id: str
    title: str | None = None
    version: str
    step: str | None = None
    checks: list[dict[str, Any]] = Field(default_factory=list)
    read_only: bool = True


class ScheduleIn(BaseModel):
    """Register a recurring scan (F-01-05)."""

    model_config = _MODEL

    id: str
    target: str
    cron: str
    engine: str | None = None
    active_checks: bool | None = None
    modules: list[str] = Field(default_factory=list)
    checks: list[str] = Field(default_factory=list)
    enabled: bool = True


class ScheduleOut(BaseModel):
    model_config = _MODEL

    spec: dict[str, Any]
    state: dict[str, Any] = Field(default_factory=dict)


class WebhookDeliveryOut(BaseModel):
    """The result of one webhook delivery (F-06-06)."""

    model_config = _MODEL

    name: str
    ok: bool
    status_code: int | None = None
    error: str | None = None
    items: int = 0


class BrandingIn(BaseModel):
    """White-label report branding for a tenant (S14, MSSP use case).

    Validation lives on :class:`arachne.report.model.Branding`; this model is the request
    shape, so a bad colour or a non-http logo URL is a 422 before anything is stored.
    """

    model_config = _MODEL

    company_name: str = ""
    product_name: str = "ARACHNE"
    tagline: str = ""
    primary_color: str = "#1f4e79"
    accent_color: str = "#c00000"
    logo_url: str | None = None
    logo_text: str = ""
    footer_text: str = ""
    contact: str = ""
    classification: str = ""
    show_arachne_branding: bool = True


class ProjectIn(BaseModel):
    """Create a tenant/workspace (F-07-06)."""

    model_config = _MODEL

    slug: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    name: str | None = Field(default=None, max_length=255)
    description: str | None = Field(default=None, max_length=2000)
    #: Scope dimensions: hosts/domains/networks/url_prefixes/refs and their exclusions.
    scope: dict[str, Any] = Field(default_factory=dict)
    branding: BrandingIn | None = None
    #: The tenant's default report language (S26, REQ-ECOS-005). ``None`` inherits the
    #: deployment's ``ARACHNE_REPORT_LOCALE``.
    report_locale: str | None = Field(default=None, max_length=16)


class ProjectOut(BaseModel):
    """A tenant/workspace as the API returns it.

    ``retention``/``quota_bytes``/``used_bytes`` are S20's additions (REQ-DATA-001/003): a
    tenant's policy and its storage position belong to the resource an operator manages, and
    every list of projects can then show "which tenant is nearly full".

    ``pii`` and ``residency_region`` are S25's (REQ-TRUST-006, REQ-RESIL-004): the tenant's PII
    policy and its evidence residency pin are configuration an operator sets on the resource, so
    they are returned with it. ``pii`` is the *validated* view of the policy — a configured hash
    salt is reported as ``salted: true`` and never as a value.
    """

    model_config = _MODEL

    id: int
    slug: str
    name: str
    description: str | None = None
    scope: dict[str, Any] = Field(default_factory=dict)
    branding: dict[str, Any] = Field(default_factory=dict)
    created_at: str | None = None
    retention: dict[str, Any] | None = None
    quota_bytes: int | None = None
    used_bytes: int = 0
    pii: dict[str, Any] | None = None
    residency_region: str | None = None
    #: The tenant's default report language (S26, REQ-ECOS-005); ``None`` inherits the
    #: deployment's ``ARACHNE_REPORT_LOCALE``. Declared here because this model is
    #: ``extra="forbid"``: a field added to ``ProjectRecord.to_dict`` without a declaration
    #: turns every project route into a 500.
    report_locale: str | None = None


class FeedImport(BaseModel):
    """Upload a CVE/EPSS/KEV document for ingestion (F-09-03).

    ``content`` is the document text. A deployment with very large feeds should use the
    CLI against the operator's own file — this endpoint exists for the management UI and
    for a modest export.
    """

    model_config = _MODEL

    kind: Literal["epss", "kev", "cve"]
    name: str = Field(min_length=1, max_length=255)
    content: str = Field(min_length=1)
    source: str | None = Field(default=None, max_length=1024)


class PluginInstallRequest(BaseModel):
    """Install a plugin from a local path or a git URL (F-09-01)."""

    model_config = _MODEL

    source: str = Field(min_length=1, max_length=1024)
    target: str | None = Field(default=None, max_length=1024)
    dry_run: bool = False
    no_deps: bool = False
    no_build_isolation: bool = False


class PackReviewRequest(BaseModel):
    """Run the marketplace review pipeline over a content pack (S26, REQ-ECOS-001).

    ``pack`` is a path on the ARACHNE host, not an upload: the endpoint is admin-only and a
    pack is large. ``publish`` records the verdict in the provenance store; a caller that only
    wants an opinion passes ``publish=False``.
    """

    model_config = _MODEL

    pack: str = Field(min_length=1, max_length=1024)
    publish: bool = True
    allow_unsigned: bool = False


class AgentRegisterIn(BaseModel):
    """``POST /agent/register`` — an agent announces itself (S16, REQ-SCALE-002)."""

    model_config = _MODEL

    name: str = Field(min_length=1, max_length=128)
    node: str | None = Field(default=None, max_length=255)
    version: str | None = Field(default=None, max_length=64)
    #: The per-agent concurrency cap. ``None`` uses the deployment default (1).
    concurrency: int | None = Field(default=None, ge=1)


class AgentHeartbeatIn(BaseModel):
    """``POST /agent/heartbeat`` — liveness plus renewal of every held lease."""

    model_config = _MODEL

    name: str = Field(min_length=1, max_length=128)


class AgentLeaseIn(BaseModel):
    """``POST /agent/lease`` — claim up to ``cap`` queued scans for one heartbeat."""

    model_config = _MODEL

    name: str = Field(min_length=1, max_length=128)
    cap: int | None = Field(default=None, ge=1)
    ttl_s: float | None = Field(default=None, gt=0)


class AgentCompleteIn(BaseModel):
    """``POST /agent/complete`` — ack a finished (or failed) leased scan."""

    model_config = _MODEL

    name: str = Field(min_length=1, max_length=128)
    scan_id: int


class ServiceAccountIn(BaseModel):
    """``POST /service-accounts`` — mint a service-account API key (S17, REQ-IDAM-003).

    ``owner`` is the human the key acts for; when omitted it defaults to the creating SSO
    user, so a key made by a logged-in admin audits as "user X via key Y". ``expires_in_s``
    is optional — omitting it creates a non-expiring key. The secret is generated server
    side and returned exactly once; the caller never supplies it.
    """

    model_config = _MODEL

    label: str = Field(min_length=1, max_length=128, pattern=r"^[A-Za-z0-9_.:-]+$")
    role: Literal["viewer", "scanner", "admin"]
    project: str | None = Field(default=None, max_length=64)
    owner: str | None = Field(default=None, max_length=255)
    expires_in_s: int | None = Field(default=None, ge=60)
