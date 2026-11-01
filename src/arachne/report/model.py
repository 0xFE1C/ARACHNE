"""The report data model — one immutable DTO every renderer consumes (ADR-06, F-06-01).

``ReportData`` is the contract of the report. The heuristic engine, the AI
engine (S9) and every renderer (Markdown, JSON, later HTML/PDF) all speak this shape, so a
report can never be more (or less) than what the scan actually recorded. Three rules make
that true:

* **The DTO is data only.** It answers no questions, touches no store and has no methods
  that could re-derive a verdict. The builder (:mod:`arachne.report.builder`) is the one
  place that reads the evidence store; a renderer only formats what it is handed.
* **Every value a reader sees is in here.** A Markdown renderer that pulled a severity from
  the database would be able to disagree with the JSON renderer; keeping all input in one
  frozen object is what makes the two byte-for-byte derivable from the same source.
* **The schema is versioned** . ``schema_version`` is
  carried in the JSON document and in the shipped JSON Schema, so a consumer can validate
  a report written by an older build.

The field names follow the report contract literally (``check_id``, ``evidence_refs``,
``score.confidence``); where the spec's sample shows a nullable value (``cve``, ``epss``,
``verified_at``) the field is ``None`` rather than absent, so a consumer's validation is
uniform.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

__all__ = [
    "REPORT_SCHEMA_VERSION",
    "Appendix",
    "AssetEntry",
    "AssetRef",
    "AttackPathEntry",
    "AttackPathHop",
    "AuditHighlights",
    "Branding",
    "Classification",
    "ControlCoverage",
    "ExecutiveSummary",
    "FeedFreshness",
    "FindingProof",
    "FrameworkCoverage",
    "IntelFreshness",
    "RemediationPlan",
    "ReportCover",
    "ReportData",
    "ReportDiff",
    "ReportEvidence",
    "ReportFinding",
    "ScopeMethodology",
    "Score",
    "SeverityCounts",
    "SimulatedChange",
    "SimulatedHop",
    "SimulatedPathEntry",
    "SimulationBlock",
    "SimulationHypothesis",
    "StateChangeEntry",
    "Timestamps",
    "evidence_id",
    "finding_id",
]

#: Bumped whenever the serialized report changes shape. The contract.
#: 1.1 (S14) adds the optional ``branding`` block for white-labelled MSSP reports.
#: 1.2 (S15) adds the per-finding ``proof`` artifact and the report-level ``state_changes``
#: table (area PROOF, REQ-PROOF-013).
#: 1.3 (S17) adds the scope section's ``requested_by`` — the per-user principal that
#: requested the scan ("user X via key Y"), so accountability travels with the report
#: (area IDAM, REQ-IDAM-001/004).
#: 1.4 (S18) adds the top-level ``intel`` block: the threat-intel freshness snapshot a report
#: needs to be honest about its own data ("no KEV match" against a month-old catalogue means
#: something else). Area INTEL, REQ-INTEL-001.
#: 1.5 (S19) adds ``scope.credentials``/``scope.authenticated`` (area CREDS).
#: 1.6 (S21) adds the top-level ``attack_paths`` block: composed chains with per-hop evidence,
#: a verified/candidate marker per hop and the cheapest breaking remediation (REQ-AGENT-003).
#: 1.7 (S22) adds the top-level ``compliance`` block: per-framework control coverage with
#: explicit gaps — fail/pass/gap per control, findings and evidence refs travelling with each
#: row, and the framework's unmapped remainder counted (area TRUST, REQ-TRUST-001).
#: 1.8 (S23) adds the attack-path entries' optional ``criticality``/``business_severity``
#: (the CMDB feed, area POSTURE, REQ-POSTURE-006) — optional fields, so a report without an
#: import is byte-identical to its pre-S23 form.
#: 1.9 (S24) adds the optional top-level ``detection_validation`` block: the purple-team run
#: a scan performed — every emitted action with the ATT&CK technique and tactic it replayed,
#: the run nonce, the coordinated detection window, and the Sigma rule-hit/rule-miss verdict
#: (area VALID, REQ-VALID-003/004). Optional, so an ordinary scan's report is byte-identical.
#: 1.10 (S26) adds the top-level ``locale``: the language this report was rendered in (BCP-47
#: primary subtag, e.g. ``en``/``fr``) so a reader can tell which catalogue produced its
#: labels, and the renderers select it per report (area ECOS, REQ-ECOS-005). The empty string
#: means "the deployment default", which keeps a report built without a locale byte-identical
#: to its pre-S26 form.
#: 1.11 (S28) adds the optional top-level ``simulation`` block: a what-if run's paths, each
#: hop marked ``observed`` or ``hypothetical``, under ``provenance="simulated"`` — rendered in
#: its own section, after the appendix, so nothing about the verified body changes and a
#: simulated path can never read as a finding (area SIM, REQ-SIM-002/004).
REPORT_SCHEMA_VERSION = "1.11"

Severity = Literal["critical", "high", "medium", "low", "info"]

#: Severity order every renderer sorts by .
SEVERITY_ORDER: tuple[str, ...] = ("critical", "high", "medium", "low", "info")

_MODEL = ConfigDict(frozen=True, extra="forbid")


def finding_id(number: int) -> str:
    """``42`` → ``F-000042``."""
    return f"F-{number:06d}"


def evidence_id(number: int) -> str:
    """``1`` → ``E-0001`` (evidence-ref format)."""
    return f"E-{number:04d}"


class AssetRef(BaseModel):
    """The affected asset (``asset``)."""

    model_config = _MODEL

    kind: str
    value: str
    tags: tuple[str, ...] = ()


class Score(BaseModel):
    """The F-05-04 scoring output as the report prints it (``score``)."""

    model_config = _MODEL

    cvss_base: float | None = None
    cvss_vector: str | None = None
    owasp_risk: str | None = None
    epss: float | None = None
    confidence: int = Field(ge=0, le=100)


class Classification(BaseModel):
    """CWE/CVE/CAPEC and the OWASP Top-10 mapping (``classification``)."""

    model_config = _MODEL

    cwe: str | None = None
    cve: str | None = None
    capec: tuple[str, ...] = ()
    owasp_2025: str | None = None


class Provenance(BaseModel):
    """Which engine decided this finding, and on what corpus (F-03-05)."""

    model_config = _MODEL

    engine: str = "heuristic"
    model: str | None = None
    template_version: str | None = None
    analysis_log_id: str | None = None
    rule_ids: tuple[str, ...] = ()
    signatures: tuple[str, ...] = ()


class Timestamps(BaseModel):
    """When the finding was first and last seen, and when it was verified."""

    model_config = _MODEL

    first_seen: datetime | None = None
    last_seen: datetime | None = None
    verified_at: datetime | None = None


class RemediationPlan(BaseModel):
    """A resolved catalog entry: summary, steps, verification, refs."""

    model_config = _MODEL

    id: str
    summary: str
    steps: tuple[str, ...] = ()
    verification: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    source: str = "catalog"


class ReportEvidence(BaseModel):
    """One evidence payload, addressed by its report id (appendix A)."""

    model_config = _MODEL

    id: str
    kind: str
    summary: str
    payload: dict[str, Any] = Field(default_factory=dict)
    sha256: str | None = None
    captured_at: datetime | None = None
    redacted: bool = True


class FindingProof(BaseModel):
    """The per-finding proof artifact (S15, REQ-PROOF-013).

    Carries what the ladder did to prove this finding — the level, the method, the
    token/nonce when the proof was out-of-band or a command echo, and the cleanup
    status in operator-readable form. Rendered as the finding's *Proof* section.
    """

    model_config = _MODEL

    level: str  # "L0".."L4"
    method: str = ""
    cleanup: str = ""
    nonce: str | None = None
    token: str | None = None
    detail: dict[str, Any] = Field(default_factory=dict)


class StateChangeEntry(BaseModel):
    """One L4 state change, for the report-level *state changes* table (REQ-PROOF-013).

    ``restored=False`` is not a rendering detail — it is a repair instruction: the
    target is not in its prior state and an operator must act (REQ-PROOF-010).
    """

    model_config = _MODEL

    change_id: str
    kind: str
    check: str
    where: str
    before: str | None = None
    after: str = ""
    restored: bool = False
    restore_verified: bool = False
    note: str | None = None
    error: str | None = None


class ReportFinding(BaseModel):
    """One finding, exactly the report schema."""

    model_config = _MODEL

    id: str
    scan_id: str
    module: str
    check_id: str
    check_version: str | None = None
    research_ref: str | None = None
    title: str
    asset: AssetRef
    severity: Severity
    score: Score
    classification: Classification = Field(default_factory=Classification)
    description: str = ""
    evidence_refs: tuple[str, ...] = ()
    #: The ladder's proof artifact (S15); ``None`` for a finding proven at L1 or below
    #: with nothing beyond ordinary captured exchanges.
    proof: FindingProof | None = None
    remediation: RemediationPlan
    status: str = "open"
    provenance: Provenance = Field(default_factory=Provenance)
    timestamps: Timestamps = Field(default_factory=Timestamps)
    #: True when the finding is below the confidence threshold . Such a
    #: finding is rendered in its own section and never in a severity table.
    low_confidence: bool = False


class SeverityCounts(BaseModel):
    """The counts table (confirmed findings only)."""

    model_config = _MODEL

    critical: int = Field(default=0, ge=0)
    high: int = Field(default=0, ge=0)
    medium: int = Field(default=0, ge=0)
    low: int = Field(default=0, ge=0)
    info: int = Field(default=0, ge=0)

    @property
    def total(self) -> int:
        return self.critical + self.high + self.medium + self.low + self.info

    def for_severity(self, severity: str) -> int:
        return int(getattr(self, severity, 0))

    def as_rows(self) -> tuple[tuple[str, int], ...]:
        """``(label, count)`` in the report's order — what a Markdown table renders."""
        return (
            ("Critical", self.critical),
            ("High", self.high),
            ("Medium", self.medium),
            ("Low", self.low),
            ("Info", self.info),
        )


class ExecutiveSummary(BaseModel):
    """Section 2: narrative, counts and priority order."""

    model_config = _MODEL

    posture: str = "unknown"
    paragraphs: tuple[str, ...] = ()
    counts: SeverityCounts = Field(default_factory=SeverityCounts)
    low_confidence_count: int = Field(default=0, ge=0)
    headline_finding_ids: tuple[str, ...] = ()
    priority_order: tuple[str, ...] = ()
    provenance: Provenance = Field(default_factory=Provenance)
    #: ``True`` when the narrative was synthesised by the deterministic heuristic writer.
    synthesized: bool = True


class CheckRun(BaseModel):
    """One check that ran (or was deliberately not run) — scope & methodology section."""

    model_config = _MODEL

    module: str
    name: str
    version: str
    title: str
    research_ref: str | None = None
    ran: bool = True
    skip_reason: str | None = None


class ScopeMethodology(BaseModel):
    """Section 3: what was scanned, how, and under which limits."""

    model_config = _MODEL

    target_name: str
    #: The per-user principal that requested the scan (S17, REQ-IDAM-001/004).
    requested_by: str | None = None
    #: The credential **labels** the scan authenticated with (S19, REQ-CREDS-001/002). Labels
    #: only: a label names a vault entry on the executing node, and the material behind it
    #: never reaches a report. Present so a reader knows the scan saw an authenticated surface
    #: rather than an anonymous one.
    credentials: tuple[str, ...] = ()
    #: Whether a credential established a session for this scan.
    authenticated: bool = False
    scope: dict[str, list[str]] = Field(default_factory=dict)
    exclusions: tuple[str, ...] = ()
    modules: tuple[str, ...] = ()
    checks: tuple[CheckRun, ...] = ()
    checks_run: int = Field(default=0, ge=0)
    checks_skipped: int = Field(default=0, ge=0)
    rate_limits: dict[str, float | int] = Field(default_factory=dict)
    started_at: datetime | None = None
    finished_at: datetime | None = None
    duration_seconds: float | None = None
    engine_mode: str = "heuristic"
    research_corpus_version: str | None = None
    report_schema_version: str = REPORT_SCHEMA_VERSION


class AssetEntry(BaseModel):
    """One discovered asset (section 4)."""

    model_config = _MODEL

    kind: str
    value: str
    tags: tuple[str, ...] = ()
    source: str | None = None
    cve_refs: tuple[str, ...] = ()


class AuditHighlights(BaseModel):
    """The audit-log summary and out-of-scope events (appendix B/C)."""

    model_config = _MODEL

    actions: dict[str, int] = Field(default_factory=dict)
    total_events: int = Field(default=0, ge=0)
    blocked_events: int = Field(default=0, ge=0)
    out_of_scope_events: tuple[str, ...] = ()
    first_event_at: datetime | None = None
    last_event_at: datetime | None = None


class FalsePositiveEntry(BaseModel):
    """A finding the analyzer dropped or merged, kept for the appendix (F-05-07)."""

    model_config = _MODEL

    finding_id: str
    title: str
    severity: str | None = None
    reason: str | None = None
    status: str = "fp"


class ReportDiff(BaseModel):
    """The scan-to-scan skeleton of F-06-05.

    Full trend rendering is S11; this is the data the diff section is written from and the
    payload persisted in ``scans_diff``.
    """

    model_config = _MODEL

    scan_a: str
    scan_b: str
    new: tuple[str, ...] = ()
    fixed: tuple[str, ...] = ()
    regressed: tuple[str, ...] = ()
    recurring: tuple[str, ...] = ()
    #: Findings this scan reported that a suppression rule silenced (S21, REQ-QUAL-002). They
    #: are excluded from ``new`` and counted *explicitly* here: a diff that swallowed them
    #: silently would make a suppression look like a fix.
    suppressed: tuple[str, ...] = ()
    #: The suppression rule set version in force, so two diffs are comparable ("v7").
    suppression_version: int = 0
    severity_trend: dict[str, dict[str, int]] = Field(default_factory=dict)

    @property
    def counts(self) -> dict[str, int]:
        return {
            "new": len(self.new),
            "fixed": len(self.fixed),
            "regressed": len(self.regressed),
            "recurring": len(self.recurring),
            "suppressed": len(self.suppressed),
        }


class Appendix(BaseModel):
    """Section 11: payloads, audit, scope events, FP log, glossary."""

    model_config = _MODEL

    evidence: tuple[ReportEvidence, ...] = ()
    audit: AuditHighlights = Field(default_factory=AuditHighlights)
    false_positives: tuple[FalsePositiveEntry, ...] = ()
    glossary: dict[str, str] = Field(default_factory=dict)


class ReportCover(BaseModel):
    """Section 1: the cover and header."""

    model_config = _MODEL

    title: str
    target: str
    scan_id: str
    generated_at: datetime
    scan_started_at: datetime | None = None
    scan_finished_at: datetime | None = None
    engine: str = "heuristic"
    arachne_version: str = ""
    module_versions: dict[str, str] = Field(default_factory=dict)
    authorization: dict[str, Any] | None = None
    schema_version: str = REPORT_SCHEMA_VERSION


class Branding(BaseModel):
    """White-label presentation for a report (S14, MSSP use case).

    The default is the neutral ARACHNE presentation, so a report rendered with no branding
    is byte-identical to the pre-S14 output (the renderers only add a block when
    :meth:`is_customised`). A project stores its branding as YAML/JSON; every value here is
    operator-supplied, so colours and the logo URL are validated at construction rather
    than escaped downstream.

    ``logo_url`` is **HTML/PDF only** and must be ``https``/``http``/``data:image`` — the
    Markdown renderer prints ``logo_text`` (initials) instead, because Markdown has no
    dependable way to carry a remote image into a text report. ``classification`` is the
    handling banner (``CONFIDENTIAL``, ``INTERNAL``); it is printed on every page footer.
    """

    model_config = _MODEL

    company_name: str = ""
    product_name: str = "ARACHNE"
    tagline: str = ""
    primary_color: str = "#1f4e79"
    accent_color: str = "#c00000"
    logo_url: str | None = None
    #: Short initials/mark printed where an image cannot be (Markdown, plain text).
    logo_text: str = ""
    footer_text: str = ""
    contact: str = ""
    classification: str = ""
    show_arachne_branding: bool = True

    @field_validator("primary_color", "accent_color")
    @classmethod
    def _validate_colour(cls, value: str) -> str:
        if not re.fullmatch(r"#[0-9a-fA-F]{6}|#[0-9a-fA-F]{3}", value.strip()):
            msg = f"branding colour {value!r} must be a hex colour such as #1f4e79"
            raise ValueError(msg)
        return value.strip()

    @field_validator("logo_url")
    @classmethod
    def _validate_logo_url(cls, value: str | None) -> str | None:
        if value is None or not value.strip():
            return None
        candidate = value.strip()
        lowered = candidate.lower()
        if lowered.startswith("data:image/"):
            return candidate
        if not lowered.startswith(("https://", "http://")):
            msg = f"branding logo_url {value!r} must be an http(s) URL or a data:image URI"
            raise ValueError(msg)
        return candidate

    def is_customised(self) -> bool:
        """True when any white-label value differs from the neutral default."""
        return bool(
            self.company_name
            or self.tagline
            or self.footer_text
            or self.contact
            or self.classification
            or self.logo_url
            or self.logo_text
            or self.product_name != "ARACHNE"
            or not self.show_arachne_branding
        )

    def display_name(self) -> str:
        """The vendor name a cover line prints (company first, then product)."""
        return self.company_name or self.product_name or "ARACHNE"


class FeedFreshness(BaseModel):
    """One feed kind's freshness, as the report shows it (REQ-INTEL-001).

    ``imported_at=None`` means "this deployment has not ingested this feed", which is a
    different statement from "the feed is stale" and is rendered as such: a report reader
    must be able to tell "we looked and found nothing" from "we never looked".
    """

    model_config = _MODEL

    kind: str
    name: str = ""
    version: str | None = None
    source: str | None = None
    imported_at: str | None = None
    age_hours: float | None = None
    ttl_hours: float = 0.0
    stale: bool = False
    record_count: int = 0
    verified: bool = False
    verification: str | None = None
    digest: str | None = None


class IntelFreshness(BaseModel):
    """The threat-intel block: what data this scan's conclusions rest on (S18).

    ``stale`` means *an ingested feed is older than its configured TTL*; ``missing`` lists the
    kinds nobody ingested. ``providers`` names the third-party indexes the deployment was
    allowed to consult (never a key, never a query) so an absent finding from an opted-out
    provider is not read as a clean result.
    """

    model_config = _MODEL

    generated_at: str = ""
    stale: bool = False
    missing: tuple[str, ...] = ()
    feeds: tuple[FeedFreshness, ...] = ()
    providers: tuple[str, ...] = ()
    opted_in_providers: tuple[str, ...] = ()


class DetectionAction(BaseModel):
    """One purple-team test artifact a scan emitted (S24, area VALID).

    ``nonce`` is the run's visible tag: it appears in every payload the action sent and in
    every artifact the scan recorded, which is what makes "the defender saw *this* test" a
    decidable question rather than a correlation guess (REQ-VALID-003).
    """

    model_config = _MODEL

    action: str
    level: str
    technique: str
    tactic: str
    tactic_label: str = ""
    severity: str = "medium"
    #: ``rule-hit`` when a shipped M6 Sigma rule matches this action's telemetry, else
    #: ``rule-miss`` (REQ-VALID-004).
    sigma_verdict: str = ""
    sigma_rules: tuple[str, ...] = ()
    nonce: str = ""


class DetectionValidation(BaseModel):
    """The purple-team half of a scan report (S24, REQ-VALID-003/004).

    Present only for a purple-team run: an ordinary scan's report carries nothing here and
    is byte-identical to its pre-S24 form. Control *coverage* (what the defender reported
    seeing) is not here: it needs the SIEM's alerts, which arrive after the scan, so it
    lives in the defender report (``arachne purple report``).
    """

    model_config = _MODEL

    campaign: str
    nonce: str
    window: dict[str, Any] | None = None
    window_state: str = ""
    actions: tuple[DetectionAction, ...] = ()
    #: The M6 rules evaluated and how many actions no rule matched — the rule-miss count is
    #: stated so a report cannot read as "all covered" when only some actions were.
    rules_evaluated: int = 0
    rule_misses: tuple[str, ...] = ()
    stopped_at: str | None = None


class AttackPathHop(BaseModel):
    """One hop of a chain as the report renders it (REQ-AGENT-003).

    ``verified`` is the load-bearing field: a hop the analyzer accepted is evidence, and one it
    did not is a *candidate* that names the check which would verify it. A report that showed
    both the same way would be claiming a chain it cannot support.
    """

    model_config = _MODEL

    stage: str
    check_id: str
    title: str
    #: The hop's own asset (a path on the host), so a chain can name each step precisely.
    asset: str = ""
    marker: str = ""
    severity: str
    verified: bool = False
    #: ``None`` for a verified hop; the verifying check id for a candidate hop.
    verifying_check: str | None = None
    finding_id: str | None = None
    evidence_refs: tuple[str, ...] = ()


class AttackPathEntry(BaseModel):
    """A composed path: its hops, what it achieves, and the cheapest way to break it."""

    model_config = _MODEL

    id: str
    asset: str
    #: The terminal hop's severity — what the chain *achieves*, not its worst hop.
    severity: str
    stages: tuple[str, ...] = ()
    fully_verified: bool = False
    hops: tuple[AttackPathHop, ...] = ()
    cheapest_break: str = ""
    cheapest_check_id: str | None = None
    cheapest_finding_id: str | None = None
    #: The CMDB criticality tier of the asset (S23, REQ-POSTURE-006) and the severity the
    #: path ranks at once the tier's business floor applies. Both ``None``/absent when the
    #: deployment imported no criticality — which keeps older reports identical.
    criticality: int | None = None
    business_severity: str | None = None


class ControlCoverage(BaseModel):
    """One framework control as this scan assessed it (S22, REQ-TRUST-001).

    ``status`` is deliberately one of ``pass``/``fail``/``gap`` and nothing else:
    there is no "compliant". A control whose checks found nothing *passed this
    scan's checks*; one whose checks did not run is a ``gap`` naming why — an
    unassessed control must never read as a clean one.
    """

    model_config = _MODEL

    control: str
    title: str
    status: Literal["pass", "fail", "gap"]
    #: The confirmed findings that failed this control (their ids; evidence refs below).
    findings: tuple[str, ...] = ()
    #: The control's mapped checks that ran in this scan.
    checks_run: tuple[str, ...] = ()
    #: The control's mapped checks that did not run (opt-in withheld, module off, …).
    checks_not_run: tuple[str, ...] = ()
    #: The evidence refs of the failing findings, deduplicated.
    evidence_refs: tuple[str, ...] = ()


class FrameworkCoverage(BaseModel):
    """One framework's coverage as this scan assessed it (S22, REQ-TRUST-001).

    ``total_controls`` is the *framework's own* control count (CIS v8.1's 153
    safeguards, PCI DSS v4.0's 12 requirements, ISO 27001:2022's 93 Annex A
    controls, NIST CSF 2.0's 106 subcategories). ``mapped`` is how many of them
    ARACHNE's check catalogue can speak to — of which a scan may still have run
    none, which the per-control ``gap`` states. The difference between ``mapped``
    and ``total_controls`` is the explicit gap: a report that showed only the mapped
    controls would read as coverage it does not have.
    """

    model_config = _MODEL

    framework: str
    name: str
    edition: str = ""
    kind: str = "control"
    total_controls: int = Field(ge=1)
    map_version: str = "0"
    controls: tuple[ControlCoverage, ...] = ()

    @property
    def mapped(self) -> int:
        """Framework controls at least one shipped check can speak to."""
        return len(self.controls)

    def count(self, status: str) -> int:
        return sum(1 for row in self.controls if row.status == status)

    @property
    def unmapped(self) -> int:
        """Framework controls no shipped check can speak to — the explicit gap."""
        return max(0, self.total_controls - self.mapped)


#: The one provenance value a simulated artifact carries (S28, REQ-SIM-004). Exported as a
#: literal type so a renderer or a consumer can switch on it and a typo cannot compile.
SimulatedProvenance = Literal["simulated"]


class SimulatedHop(BaseModel):
    """One hop of a simulated path, with its origin stated rather than implied (S28).

    ``origin`` is the field that keeps a what-if result honest: ``observed`` means a scan
    established the hop, ``hypothetical`` means a hypothesis introduced it and
    ``hypothesis_id`` names which. There is deliberately no ``verified`` field here — the
    simulated block's vocabulary must not borrow the verified report's, because a reader
    skimming for "verified" inside a what-if section would be reading a claim about a target
    that was never touched.
    """

    model_config = _MODEL

    check_id: str
    title: str
    asset: str
    stage: str
    severity: str
    origin: Literal["observed", "hypothetical"]
    hypothesis_id: str | None = None
    #: The observed finding's id, when a scan raised this hop (``None`` for a hypothetical).
    finding_id: str | None = None


class SimulatedPathEntry(BaseModel):
    """One path composed inside a simulation (S28, REQ-SIM-002)."""

    model_config = _MODEL

    id: str
    asset: str
    #: The terminal hop's impact — what the chain achieves, as in the verified section.
    severity: str
    business_severity: str | None = None
    criticality: int | None = None
    stages: tuple[str, ...] = ()
    hops: tuple[SimulatedHop, ...] = ()
    #: The hypotheses that produced at least one hop of this path.
    hypotheses: tuple[str, ...] = ()
    cheapest_break: str = ""
    #: The origin of the cheapest breaking hop (``observed``/``hypothetical``) and, when it is
    #: hypothetical, which hypothesis introduced it — so a reader is never told to fix
    #: something that only exists in the simulation without being told that much.
    cheapest_origin: str | None = None
    cheapest_hypothesis_id: str | None = None
    #: True when at least one hop exists only because of a hypothesis (always true of an
    #: introduced path; a path the scan already had is ``False``).
    hypothetical: bool = False


class SimulationHypothesis(BaseModel):
    """One hypothetical state a run injected, as the report shows it (S28)."""

    model_config = _MODEL

    id: str
    kind: str
    asset: str
    title: str
    severity: str
    cwe: str | None = None
    note: str = ""


class SimulatedChange(BaseModel):
    """The before/after of a proposed change (S28, REQ-SIM-005)."""

    model_config = _MODEL

    name: str
    description: str = ""
    exposure_before: int
    exposure_after: int
    #: After minus before: positive is worse, negative is an improvement.
    exposure_delta: int
    paths_before: int = 0
    paths_after: int = 0
    introduced: tuple[str, ...] = ()
    removed: tuple[str, ...] = ()


class SimulationBlock(BaseModel):
    """A what-if run's result, rendered in its own section (S28, REQ-SIM-002/004).

    The block is **optional** and never populated by a scan: it is attached when an operator
    asks for a simulation of a stored scan (``arachne report --simulate``). That is what keeps
    an ordinary report byte-identical to its pre-S28 form, and what makes the separation
    structural rather than a rendering convention — the paths here live in a field no
    finding-shaped consumer reads.
    """

    model_config = _MODEL

    #: Always ``"simulated"``. The one marker every consumer keys on.
    provenance: SimulatedProvenance = "simulated"
    #: The plain-language statement of what this section is, so a reader cannot mistake it
    #: for a finding even if they read only the heading.
    disclosure: str = (
        "Nothing in this section was observed on a target. It is a computation over the "
        "estate model built from earlier scans, under the hypothetical states listed below."
    )
    estate_key: str
    #: The scans the model was built from (the evidence base of the simulation).
    built_from_scans: tuple[int, ...] = ()
    #: The model's shape: hosts, services, identities, weaknesses, edges, pivots.
    model: dict[str, int] = Field(default_factory=dict)
    hypotheses: tuple[SimulationHypothesis, ...] = ()
    #: Hypotheses that could not be applied, and why — reported, never silently dropped.
    refusals: tuple[str, ...] = ()
    paths: tuple[SimulatedPathEntry, ...] = ()
    change: SimulatedChange | None = None
    exposure_before: int = 0
    exposure_after: int = 0


class ReportData(BaseModel):
    """The immutable report document (ADR-06). Every renderer consumes exactly this."""

    model_config = _MODEL

    #: The schema revision this document conforms to. Declared ``const`` in the generated
    #: JSON Schema as well as defaulted here, so a consumer can validate a document against
    #: the schema *of the revision it claims* rather than only trusting its own default.
    schema_version: str = Field(
        default=REPORT_SCHEMA_VERSION,
        description="Report schema version",
        json_schema_extra={"const": REPORT_SCHEMA_VERSION},
    )
    scan_id: str
    target_name: str
    #: The language this report renders its labels in (S26, REQ-ECOS-005). A BCP-47 primary
    #: subtag (``en``, ``fr``); the empty string means "the deployment default"
    #: (``ARACHNE_REPORT_LOCALE``, else ``en``). The renderers resolve label keys through the
    #: i18n catalogue with this locale, so one report can be delivered in one language while
    #: another of the same scan is delivered in a second.
    locale: str = ""
    cover: ReportCover
    executive_summary: ExecutiveSummary
    scope: ScopeMethodology
    assets: tuple[AssetEntry, ...] = ()
    #: Confirmed findings, sorted by severity (critical first) then id. Low-confidence
    #: findings live in :attr:`low_confidence` and never here .
    findings: tuple[ReportFinding, ...] = ()
    low_confidence: tuple[ReportFinding, ...] = ()
    #: The M6 patch-gap/exposure block; ``None`` when M6 did not run .
    patch_gap: dict[str, Any] | None = None
    #: Every state change an L4 proof made (S15, REQ-PROOF-013): what/where/before/after/
    #: restored. Empty when nothing changed — which is the normal case.
    state_changes: tuple[StateChangeEntry, ...] = ()
    #: Threat-intel freshness (S18, REQ-INTEL-001); ``None`` when the scan recorded none
    #: (an old scan, a deployment with no feed store). The renderers omit the section then.
    intel: IntelFreshness | None = None
    #: Composed attack paths (S21, REQ-AGENT-003): the chains a set of findings adds up to,
    #: each hop marked verified or candidate.
    attack_paths: tuple[AttackPathEntry, ...] = ()
    #: Compliance framework coverage (S22, REQ-TRUST-001): one block per configured
    #: framework, per-control pass/fail/gap with the unmapped remainder counted. Empty
    #: when the deployment names no frameworks — which keeps a pre-S22 report
    #: byte-identical (the renderers omit the section).
    compliance: tuple[FrameworkCoverage, ...] = ()
    #: The purple-team detection test this scan performed (S24, REQ-VALID-003/004);
    #: ``None`` for an ordinary scan, whose report is then byte-identical to its pre-S24
    #: form because the appendix section is omitted.
    detection_validation: DetectionValidation | None = None
    #: A what-if simulation of this scan's estate (S28, area SIM, REQ-SIM-002/004);
    #: ``None`` for every ordinary scan, which is what keeps a report byte-identical to its
    #: pre-S28 form and what keeps a simulated path out of every finding-shaped field above.
    simulation: SimulationBlock | None = None
    appendix: Appendix = Field(default_factory=Appendix)
    diff: ReportDiff | None = None
    #: White-label presentation for MSSP deployments (S14). The default renders exactly
    #: what the spec's skeleton shows; a project's branding replaces the cover and footer.
    branding: Branding = Field(default_factory=Branding)

    @property
    def counts(self) -> SeverityCounts:
        return self.executive_summary.counts

    def findings_by_severity(self, severity: str) -> tuple[ReportFinding, ...]:
        return tuple(item for item in self.findings if item.severity == severity)

    def evidence_by_id(self, ref: str) -> ReportEvidence | None:
        for item in self.appendix.evidence:
            if item.id == ref:
                return item
        return None
