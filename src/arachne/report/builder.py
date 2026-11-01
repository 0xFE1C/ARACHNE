"""Build the immutable :class:`~arachne.report.model.ReportData` from a stored scan.

This is the only report module that reads the evidence store. It joins four persisted
things — the scan record (plan, scope, attestation, timings), the ``findings`` rows (the
candidate and its analysed verdict), the ``analysis_log`` rows (narrative, score, rule
trace, provenance) and the audit trail — into one DTO. Everything downstream is a pure
formatting exercise, which is what makes the Markdown and JSON outputs derivable from the
same source (ADR-06) and keeps the report QA gate meaningful.

Three mapping rules matter:

* **Severity and confidence come from ``findings``** (the analyzer wrote them); the
  narrative, score breakdown and rule trace come from ``analysis_log``. A finding with no
  analysis row is still rendered (a scan can be reported before analysis, and a dropped
  candidate stays visible in the appendix) at ``info`` with the check's own confidence.
* **Low-confidence findings go to their own section** . The threshold is a
  report setting, not a second scoring decision: nothing is dropped, it is only moved.
* **Dropped and merged findings never appear as confirmed findings.** ``fp`` goes to the
  false-positive appendix with its reason; ``merged`` is a dedupe artefact and is counted in
  the appendix too, so the confirmed set is the deduplicated one the correlation step built.

The functions here take plain sequences, not a session, so a unit test (or the API in S12)
can build a report over in-memory stores; :func:`build_report_for_scan` is the SQL-wired
convenience the CLI calls.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from arachne.analyzer.model import severity_rank
from arachne.analyzer.remediation import (
    RemediationCatalog,
    load_remediation_catalog,
)
from arachne.core.config import ReportSettings, Settings
from arachne.core.errors import ConfigurationError
from arachne.data.analysis_store import StoredAnalysis
from arachne.data.finding_store import CandidateRecord, EvidenceRecord
from arachne.purple.attack import TACTIC_LABELS
from arachne.report import model as m
from arachne.report.evidence import DEFAULT_EVIDENCE_BODY_LIMIT, project_evidence
from arachne.report.owasp import OwaspMap, load_owasp_map
from arachne.report.summary import (
    SummaryTemplateSet,
    build_executive_summary,
    load_summary_templates,
)

__all__ = [
    "EXCLUDED_STATUSES",
    "ReportInputs",
    "build_report_data",
    "build_report_for_scan",
    "check_runs_from_plan",
    "module_versions_for",
    "normalize_audit_events",
    "not_run_checks",
    "split_check_key",
]

#: Statuses that are not confirmed findings .
EXCLUDED_STATUSES: frozenset[str] = frozenset({"fp", "merged"})

_GLOSSARY: dict[str, str] = {
    "CVSS": "Common Vulnerability Scoring System v3.1 base score (0-10).",
    "CWE": "Common Weakness Enumeration identifier for the class of weakness.",
    "CVE": "Common Vulnerabilities and Exposures identifier for a known vulnerability.",
    "CAPEC": "Common Attack Pattern Enumerations and Classifications identifier.",
    "EPSS": "Exploit Prediction Scoring System probability (0-1), when a feed is available.",
    "confidence": (
        "0-100 evidence-quality score. Below the report threshold a finding is listed as a "
        "low-confidence observation and is not a confirmed finding."
    ),
    "severity": "critical >= 9.0, high >= 7.0, medium >= 4.0, low >= 2.0, otherwise info.",
    "redacted": (
        "The captured value was redacted at capture time; placeholders such as [REDACTED] "
        "replace any secret."
    ),
    "attestation": "Who authorized the scan, for which scope, and when (F-08-05).",
}


@dataclass(frozen=True, slots=True)
class ReportInputs:
    """Everything the builder reads, as plain values (no session, no ORM)."""

    scan_id: int
    target_name: str
    engine: str
    plan: Mapping[str, Any] = field(default_factory=dict)
    status: str = "completed"
    started_at: datetime | None = None
    finished_at: datetime | None = None
    assets: Sequence[Any] = ()
    candidates: Sequence[CandidateRecord] = ()
    analyses: Sequence[StoredAnalysis] = ()
    audit_events: Sequence[Any] = ()
    module_versions: Mapping[str, str] = field(default_factory=dict)
    rate_limits: Mapping[str, float | int] = field(default_factory=dict)
    arachne_version: str = ""
    generated_at: datetime | None = None
    settings: Settings | None = None
    remediation: RemediationCatalog | None = None
    owasp: OwaspMap | None = None
    summary_templates: SummaryTemplateSet | None = None
    #: check id → "why it did not run" (opt-in checks, withheld by policy).
    not_run_checks: Mapping[str, str] = field(default_factory=dict)
    research_corpus_version: str | None = None
    diff: m.ReportDiff | None = None
    #: The branding to render (S14). ``None`` resolves the deployment default from settings.
    branding: m.Branding | None = None
    #: The report language (S26, REQ-ECOS-005). ``""`` uses the deployment default
    #: (``ARACHNE_REPORT_LOCALE``, else the i18n module's default). It rides on the DTO, so a
    #: renderer reads the locale from the report it was handed rather than from the process
    #: environment — which is what lets one deployment render two languages at once.
    locale: str = ""
    #: The scan's proof journal (S15, ``scans.stats["proof"]``): the state changes and
    #: cleanup status the report's state-changes table renders (REQ-PROOF-013).
    proof_state: Mapping[str, Any] = field(default_factory=dict)
    #: The per-user principal that requested the scan ("user X via key Y", S17).
    requested_by: str | None = None
    #: The credential labels the scan authenticated with (S19, ``scans.stats["credentials"]``).
    credentials: tuple[str, ...] = ()
    authenticated: bool = False
    #: The threat-intel freshness snapshot (S18, ``scans.stats["intel"]``): which feed
    #: artefacts this scan's conclusions rest on, and whether they were verified
    #: (REQ-INTEL-001).
    intel: Mapping[str, Any] = field(default_factory=dict)
    #: The compliance frameworks this report maps its findings onto (S22, REQ-TRUST-001):
    #: canonical names (``cis``, ``pci-dss``, ``iso27001``, ``nist-csf``). ``None`` means
    #: "use the deployment setting" (``report.compliance_frameworks``); an empty tuple
    #: disables the section entirely.
    compliance_frameworks: tuple[str, ...] | None = None
    #: The CMDB criticality index (S23, REQ-POSTURE-006): paths rank (and are labelled)
    #: by business impact. ``None`` keeps the pre-S23 ordering and labels byte-identical.
    criticality: Any | None = None
    #: Directory of managed-data compliance maps (ADR-04) overriding the bundled ones.
    compliance_map_dir: str | None = None
    #: The purple-team run this scan performed (S24, ``scans.stats["purple"]``): the emitted
    #: actions, their ATT&CK techniques and the run nonce. Empty for an ordinary scan, whose
    #: report is then byte-identical to its pre-S24 form (REQ-VALID-003).
    detection_validation: Mapping[str, Any] = field(default_factory=dict)
    #: The M6 Sigma rule-hit/rule-miss alignment for that run (S24, REQ-VALID-004),
    #: recorded by the campaign service: ``{"alignments": [...]}``. Empty when the report is
    #: rendered without it (the scan's own report), in which case the block still shows the
    #: techniques and the nonce.
    detection_sigma: Mapping[str, Any] = field(default_factory=dict)
    #: A what-if simulation of this scan's estate (S28, area SIM). ``None`` — the default for
    #: every scan — leaves the report byte-identical to its pre-S28 form and, more
    #: importantly, keeps a simulated path out of every finding-shaped field (REQ-SIM-004).
    simulation: m.SimulationBlock | None = None


def split_check_key(key: str | None) -> tuple[str, str | None]:
    """``M4/env-file-probe@1.0`` → ``("m4.env-file-probe", "1.0")``."""
    if not key:
        return "unknown", None
    left, _, version = key.partition("@")
    module, _, name = left.partition("/")
    identifier = f"{module.lower()}.{name}" if module and name else left.lower()
    return identifier, (version or None)


def module_versions_for(registry: Any, plan: Mapping[str, Any] | None = None) -> dict[str, str]:
    """Versions of the module groups a scan selected (none selected → every installed one).

    Shared by the CLI's ``arachne report`` and the REST API (S12): the report's cover lists
    the versions of the modules that *actually ran*, which is a subset of the registry when
    the fixture enabled only some modules.
    """
    selected: set[str] = set()
    for raw in (plan or {}).get("checks") or ():
        if isinstance(raw, dict) and raw.get("included"):
            selected.add(str(raw.get("module") or ""))
    groups = getattr(registry, "groups", ())
    return {group.id: group.version for group in groups if not selected or group.id in selected}


def not_run_checks(registry: Any, candidates: Sequence[CandidateRecord]) -> dict[str, str]:
    """Check ids that did not run because they are off by default (S7 gotcha #3).

    A report must not imply an opt-in check was "clean". The registry knows which checks are
    off by default; the candidates know which checks actually produced something. A
    default-off check with no candidate is reported as *not run*, with that reason.
    """
    ran = {split_check_key(candidate.check_key)[0] for candidate in candidates}
    out: dict[str, str] = {}
    for group in getattr(registry, "groups", ()):
        for metadata in group.metadata():
            if metadata.enabled_by_default:
                continue
            if metadata.id not in ran:
                out[metadata.id] = "not run (opt-in; deployment switch may be off)"
    return out


def _as_int_map(value: Any) -> dict[str, int]:
    if not isinstance(value, Mapping):
        return {}
    return {str(key): int(item) for key, item in value.items() if isinstance(item, int)}


def check_runs_from_plan(
    plan: Mapping[str, Any], *, not_run: Mapping[str, str] | None = None
) -> tuple[m.CheckRun, ...]:
    """Turn the persisted plan's check list into the methodology table."""
    checks: list[m.CheckRun] = []
    for raw in plan.get("checks") or ():
        if not isinstance(raw, Mapping):
            continue
        check_id = f"{str(raw.get('module', '')).lower()}.{raw.get('name', '')}"
        included = bool(raw.get("included", False))
        reason = None if included else str(raw.get("skip_reason") or "not selected")
        ran = included
        if check_id in (not_run or {}):
            ran = False
            reason = (not_run or {})[check_id]
        checks.append(
            m.CheckRun(
                module=str(raw.get("module") or ""),
                name=str(raw.get("name") or ""),
                version=str(raw.get("version") or ""),
                title=str(raw.get("title") or raw.get("name") or ""),
                research_ref=(
                    str(raw["research_ref"]) if raw.get("research_ref") is not None else None
                ),
                ran=ran,
                skip_reason=reason,
            )
        )
    return tuple(checks)


def normalize_audit_events(events: Sequence[Any]) -> tuple[dict[str, Any], ...]:
    """Normalise ``AuditEvent`` objects or stored audit rows to plain dicts."""
    out: list[dict[str, Any]] = []
    for event in events:
        if isinstance(event, Mapping):
            meta = dict(event.get("meta") or {})
            action = str(event.get("action") or meta.get("action") or "")
            ts = event.get("ts") or meta.get("ts")
            out.append(
                {
                    "ts": _coerce_dt(ts),
                    "action": action,
                    "outcome": str(event.get("outcome") or meta.get("outcome") or "allowed"),
                    "target": event.get("target") or meta.get("target"),
                    "reason": event.get("reason") or meta.get("reason"),
                }
            )
            continue
        action_value = getattr(event, "action", "")
        action = getattr(action_value, "value", action_value)
        outcome_value = getattr(event, "outcome", "allowed")
        out.append(
            {
                "ts": _coerce_dt(getattr(event, "ts", None)),
                "action": str(action or ""),
                "outcome": str(getattr(outcome_value, "value", outcome_value)),
                "target": getattr(event, "target", None),
                "reason": getattr(event, "reason", None),
            }
        )
    return tuple(out)


def _coerce_dt(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo is not None else value.replace(tzinfo=UTC)
    if isinstance(value, str) and value:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)
    return None


def _audit_highlights(events: Sequence[Mapping[str, Any]]) -> m.AuditHighlights:
    counts = Counter(str(event.get("action") or "unknown") for event in events)
    out_of_scope_actions = {
        "scope.rejected",
        "scope.discarded",
        "safety.blocked",
        "http.request_blocked",
        "net.blocked",
    }
    out_of_scope: list[str] = []
    for event in events:
        action = str(event.get("action") or "")
        if action not in out_of_scope_actions:
            continue
        target = event.get("target") or "(no target)"
        reason = event.get("reason")
        out_of_scope.append(f"{action}: {target}" + (f" — {reason}" if reason else ""))
    timestamps = [event["ts"] for event in events if event.get("ts") is not None]
    return m.AuditHighlights(
        actions=dict(sorted(counts.items())),
        total_events=len(events),
        blocked_events=sum(1 for event in events if event.get("outcome") == "blocked"),
        out_of_scope_events=tuple(out_of_scope[:100]),
        first_event_at=min(timestamps) if timestamps else None,
        last_event_at=max(timestamps) if timestamps else None,
    )


def _asset_tags(meta: Mapping[str, Any]) -> tuple[str, ...]:
    raw = meta.get("tags")
    if isinstance(raw, (list, tuple)):
        return tuple(sorted(str(item) for item in raw))
    if isinstance(raw, str) and raw:
        return tuple(sorted(item.strip() for item in raw.split(",") if item.strip()))
    return ()


def _build_assets(assets: Sequence[Any]) -> tuple[m.AssetEntry, ...]:
    entries = [
        m.AssetEntry(
            kind=str(asset.kind),
            value=str(asset.value),
            tags=_asset_tags(asset.meta or {}),
            source=(
                str((asset.meta or {}).get("source")) if (asset.meta or {}).get("source") else None
            ),
            cve_refs=tuple(sorted(str(item) for item in (asset.meta or {}).get("cve_refs") or ())),
        )
        for asset in assets
    ]
    return tuple(sorted(entries, key=lambda item: (item.kind, item.value)))


def _severity(value: Any) -> str:
    text = str(value or "info").lower()
    return text if text in m.SEVERITY_ORDER else "info"


def _analysis_index(
    analyses: Sequence[StoredAnalysis],
) -> dict[int, StoredAnalysis]:
    """finding id → its latest analysis (a re-analysed finding keeps the last verdict)."""
    index: dict[int, StoredAnalysis] = {}
    for analysis in analyses:
        if analysis.finding_id is not None:
            index[analysis.finding_id] = analysis
    return index


def _note_detail(candidate: CandidateRecord) -> str | None:
    for record in candidate.evidence:
        if record.kind == "note":
            detail = record.payload.get("detail")
            if isinstance(detail, str) and detail.strip():
                return detail.strip()
    return None


def _proof_from_payload(payload: Mapping[str, Any]) -> m.FindingProof:
    """One ``proof`` evidence payload, as the report renders it (S15, REQ-PROOF-013)."""
    token = payload.get("callback_token") or payload.get("token")
    nonce = payload.get("proof_nonce") or payload.get("nonce")
    change = payload.get("change")
    detail = {
        key: value
        for key, value in payload.items()
        if key not in {"level", "method", "cleanup", "callback_token", "proof_nonce"}
    }
    if isinstance(change, Mapping):
        detail["change"] = dict(change)
    hit = payload.get("hit")
    if isinstance(hit, Mapping):
        detail["hit"] = dict(hit)
    return m.FindingProof(
        level=str(payload.get("level") or "L1"),
        method=str(payload.get("method") or ""),
        cleanup=str(payload.get("cleanup") or ""),
        nonce=str(nonce) if nonce else None,
        token=str(token) if token else None,
        detail=detail,
    )


def _finding_proof(
    candidate: CandidateRecord, merged_proofs: Mapping[int, m.FindingProof] | None = None
) -> m.FindingProof | None:
    """The ``proof`` evidence of a candidate — or of a candidate merged into it (S15).

    The dedupe rule folds same-CWE/same-asset findings into one owner and
    keeps the contributors' evidence as merged refs. The proof ladder's artifact must
    survive that fold: "this sink was *proven* with a one-shot echo / a restored marker
    row" is exactly what the report exists to say, so a proof carried by a merged
    contributor is promoted to the finding that reports the root cause.
    """
    own = _own_proof(candidate)
    if own is not None:
        return own
    if merged_proofs and candidate.id is not None:
        return merged_proofs.get(candidate.id)
    return None


def _own_proof(candidate: CandidateRecord) -> m.FindingProof | None:
    for record in candidate.evidence:
        if record.kind != "proof":
            continue
        payload = record.payload if isinstance(record.payload, Mapping) else {}
        return _proof_from_payload(payload)
    return None


def _detection_validation_block(
    payload: Mapping[str, Any], *, sigma: Mapping[str, Any] | None = None
) -> m.DetectionValidation | None:
    """The ``stats["purple"]`` block as the report's detection-validation section (S24).

    ``None`` for an ordinary scan, so its report stays byte-identical and the appendix
    section is omitted rather than printed empty. The Sigma verdicts come from the campaign
    service (which owns the hunt library's alignment); a report rendered without them still
    shows each action's technique, tactic and the run nonce.
    """
    if not payload:
        return None
    verdicts: dict[str, Mapping[str, Any]] = {}
    for item in (sigma or {}).get("alignments") or ():
        if isinstance(item, Mapping):
            verdicts[str(item.get("check_id") or "")] = item
    actions: list[m.DetectionAction] = []
    rule_misses: list[str] = []
    rules_evaluated = 0
    for item in payload.get("emissions") or ():
        if not isinstance(item, Mapping):
            continue
        check_id = str(item.get("check_id") or "")
        alignment = verdicts.get(check_id, {})
        verdict = str(alignment.get("verdict") or "")
        hits = tuple(
            str(entry.get("title") or entry.get("rule_id") or "")
            for entry in (alignment.get("hits") or ())
            if isinstance(entry, Mapping)
        )
        rules_evaluated = max(rules_evaluated, int(alignment.get("rules_evaluated") or 0))
        technique = str(item.get("technique") or "")
        if verdict == "rule-miss":
            rule_misses.append(technique or check_id)
        actions.append(
            m.DetectionAction(
                action=check_id,
                level=str(item.get("level") or ""),
                technique=technique,
                tactic=str(item.get("tactic") or ""),
                tactic_label=TACTIC_LABELS.get(str(item.get("tactic") or ""), ""),
                severity=str(item.get("severity") or "medium"),
                sigma_verdict=verdict,
                sigma_rules=hits,
                nonce=str(item.get("nonce") or payload.get("nonce") or ""),
            )
        )
    raw_window = payload.get("window")
    window = dict(raw_window) if isinstance(raw_window, Mapping) else None
    return m.DetectionValidation(
        campaign=str(payload.get("campaign") or ""),
        nonce=str(payload.get("nonce") or ""),
        window=window,
        window_state=str((window or {}).get("state_at") or ""),
        actions=tuple(actions),
        rules_evaluated=rules_evaluated,
        rule_misses=tuple(dict.fromkeys(rule_misses)),
        stopped_at=str(payload.get("stopped_at")) if payload.get("stopped_at") else None,
    )


def _intel_block(snapshot: Mapping[str, Any]) -> m.IntelFreshness | None:
    """The ``stats["intel"]`` snapshot as the report's freshness block (S18).

    ``None`` when the scan recorded no snapshot at all (an old scan, or a deployment without a
    feed store), so the renderers can omit the section rather than print an empty one.
    """
    if not snapshot:
        return None
    feeds: list[m.FeedFreshness] = []
    for item in snapshot.get("feeds") or ():
        if not isinstance(item, Mapping):
            continue
        feeds.append(
            m.FeedFreshness(
                kind=str(item.get("kind") or ""),
                name=str(item.get("name") or ""),
                version=item.get("version"),
                source=item.get("source"),
                imported_at=item.get("imported_at"),
                age_hours=_opt_float(item.get("age_hours")),
                ttl_hours=_opt_float(item.get("ttl_hours")) or 0.0,
                stale=bool(item.get("stale")),
                record_count=int(item.get("record_count") or 0),
                verified=bool(item.get("verified")),
                verification=item.get("verification"),
                digest=item.get("digest"),
            )
        )
    providers = snapshot.get("providers") or {}
    providers_map = providers if isinstance(providers, Mapping) else {}
    return m.IntelFreshness(
        generated_at=str(snapshot.get("generated_at") or ""),
        stale=bool(snapshot.get("stale")),
        missing=tuple(str(item) for item in snapshot.get("missing") or ()),
        feeds=tuple(feeds),
        providers=tuple(str(item) for item in providers_map.get("enabled") or ()),
        opted_in_providers=tuple(str(item) for item in providers_map.get("opted_in") or ()),
    )


def _opt_float(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _state_change_entries(proof_state: Mapping[str, Any]) -> tuple[m.StateChangeEntry, ...]:
    """The ledger's state changes, as the report-level table renders them (REQ-PROOF-013)."""
    raw = proof_state.get("state_changes")
    if not isinstance(raw, (list, tuple)):
        return ()
    entries: list[m.StateChangeEntry] = []
    for item in raw:
        if not isinstance(item, Mapping):
            continue
        before = item.get("before")
        before_text = (
            "; ".join(f"{key}={value}" for key, value in sorted(before.items()))
            if isinstance(before, Mapping) and before
            else None
        )
        after = item.get("after")
        after_text = (
            "; ".join(f"{key}={value}" for key, value in sorted(after.items()))
            if isinstance(after, Mapping)
            else ""
        )
        entries.append(
            m.StateChangeEntry(
                change_id=str(item.get("change_id") or ""),
                kind=str(item.get("kind") or ""),
                check=str(item.get("check_id") or ""),
                where=str(item.get("locator") or item.get("table") or ""),
                before=before_text,
                after=after_text,
                restored=bool(item.get("restored")),
                restore_verified=bool(item.get("restore_verified")),
                note=str(item["note"]) if item.get("note") else None,
                error=str(item["error"]) if item.get("error") else None,
            )
        )
    return tuple(sorted(entries, key=lambda entry: entry.change_id))


def _remediation_for(
    candidate: CandidateRecord,
    analysis: StoredAnalysis | None,
    check_id: str,
    cwe: str | None,
    catalog: RemediationCatalog,
) -> m.RemediationPlan:
    if analysis is not None:
        payload = analysis.payload.get("remediation")
        if isinstance(payload, Mapping) and payload.get("summary"):
            return m.RemediationPlan(
                id=str(payload.get("id") or analysis.remediation_id or "unknown"),
                summary=str(payload.get("summary")),
                steps=tuple(str(item) for item in payload.get("steps") or ()),
                verification=tuple(str(item) for item in payload.get("verification") or ()),
                references=tuple(str(item) for item in payload.get("references") or ()),
                source=str(payload.get("source") or "catalog"),
            )
    entry = catalog.by_check(check_id) or catalog.by_cwe(cwe)
    resolved = (
        entry.to_remediation()
        if entry is not None
        else catalog.resolve(_placeholder_candidate(candidate, check_id, cwe))
    )
    return m.RemediationPlan(
        id=resolved.id,
        summary=resolved.summary,
        steps=tuple(resolved.steps),
        verification=tuple(resolved.verification),
        references=tuple(resolved.references),
        source=resolved.source,
    )


def _placeholder_candidate(candidate: CandidateRecord, check_id: str, cwe: str | None) -> Any:
    from arachne.analyzer.model import Candidate

    return Candidate(
        scan_id=candidate.scan_id,
        title=candidate.title,
        finding_id=candidate.id,
        check_id=check_id,
        cwe=cwe,
        asset_kind=candidate.asset_kind,
        asset_value=candidate.asset_value,
    )


def _score_from(analysis: StoredAnalysis | None, candidate: CandidateRecord) -> m.Score:
    payload = analysis.payload if analysis is not None else {}
    raw = payload.get("score")
    score = raw if isinstance(raw, Mapping) else {}
    confidence = int(
        score.get("confidence")
        or (analysis.confidence if analysis is not None else 0)
        or round(candidate.confidence or 0)
    )
    epss = score.get("epss")
    return m.Score(
        cvss_base=float(score["cvss_base"]) if score.get("cvss_base") is not None else None,
        cvss_vector=(str(score["cvss_vector"]) if score.get("cvss_vector") is not None else None),
        owasp_risk=str(score["owasp_risk"]) if score.get("owasp_risk") is not None else None,
        epss=float(epss) if isinstance(epss, (int, float)) and not isinstance(epss, bool) else None,
        confidence=max(0, min(100, confidence)),
    )


def _classification(
    analysis: StoredAnalysis | None,
    check_id: str,
    cwe_map: Mapping[str, str | None],
    owasp: OwaspMap,
) -> m.Classification:
    payload = analysis.payload if analysis is not None else {}
    cwe = str(payload.get("cwe") or "") or cwe_map.get(check_id) or None
    cve = str(payload.get("cve") or "") or None
    capec_raw = payload.get("capec")
    capec = tuple(str(item) for item in capec_raw) if isinstance(capec_raw, (list, tuple)) else ()
    return m.Classification(
        cwe=cwe,
        cve=cve,
        capec=capec,
        owasp_2025=owasp.category_for(cwe),
    )


def _provenance(analysis: StoredAnalysis | None, engine: str) -> m.Provenance:
    payload = analysis.payload if analysis is not None else {}
    raw = payload.get("provenance")
    provenance = raw if isinstance(raw, Mapping) else {}
    return m.Provenance(
        engine=str(provenance.get("engine") or (analysis.engine if analysis else engine)),
        model=provenance.get("model"),
        template_version=provenance.get("template_version"),
        analysis_log_id=f"al_{analysis.log_id}" if analysis and analysis.log_id else None,
        rule_ids=tuple(str(item) for item in provenance.get("rule_ids") or ()),
        signatures=tuple(str(item) for item in payload.get("signatures") or ()),
    )


def _patch_gap(findings: Sequence[m.ReportFinding]) -> dict[str, Any]:
    """The M6 patch-gap block : CVE-correlated and EPSS-ranked items."""
    correlated = [item for item in findings if item.classification.cve]
    epss = [item for item in findings if item.score.epss is not None]
    webshell = [item for item in findings if item.check_id == "m6.webshell-yara"]
    return {
        "ran": True,
        "known_vulnerable": [
            {
                "finding_id": item.id,
                "title": item.title,
                "asset": item.asset.value,
                "cve": item.classification.cve,
            }
            for item in correlated
        ],
        "epss_top": [
            {
                "finding_id": item.id,
                "title": item.title,
                "cve": item.classification.cve,
                "epss": item.score.epss,
            }
            for item in sorted(epss, key=lambda entry: -(entry.score.epss or 0.0))[:5]
        ],
        # A dict (rather than None) means the scan actually ran the webshell check; the
        # report can then say "N finding(s)" instead of "not run" (F-06-05 trend honesty).
        "webshell_scan": {"findings": len(webshell)},
    }


def build_report_data(inputs: ReportInputs) -> m.ReportData:
    """Join the stored pieces into the immutable report DTO ."""
    settings = inputs.settings
    report_settings = settings.report if settings is not None else ReportSettings()
    threshold = report_settings.min_confidence
    body_limit = report_settings.evidence_body_limit or DEFAULT_EVIDENCE_BODY_LIMIT
    catalog = inputs.remediation or load_remediation_catalog(
        settings.analysis.remediation_catalog if settings is not None else None
    )
    owasp = inputs.owasp or load_owasp_map(
        settings.report.owasp_map if settings is not None else None
    )
    templates = inputs.summary_templates or (
        load_summary_templates(settings.report.summary_templates)
        if settings is not None and settings.report.summary_templates
        else None
    )
    generated_at = inputs.generated_at or datetime.now(UTC)
    scan_label = f"scan_{inputs.scan_id}"
    checks = check_runs_from_plan(inputs.plan or {}, not_run=inputs.not_run_checks or {})
    cwe_map: dict[str, str | None] = {}
    for raw in (inputs.plan or {}).get("checks") or ():
        if isinstance(raw, Mapping):
            key = f"{str(raw.get('module', '')).lower()}.{raw.get('name', '')}"
            cwe_map[key] = str(raw["cwe"]) if raw.get("cwe") else None
    analyses = _analysis_index(inputs.analyses)

    candidates = sorted(inputs.candidates, key=lambda item: (item.id is None, item.id or 0))
    # 1) project every stored payload once, with stable E-ids
    all_evidence: list[EvidenceRecord] = []
    for candidate in candidates:
        all_evidence.extend(candidate.evidence)
    evidence_entries, ref_map = project_evidence(all_evidence, body_limit=body_limit)
    next_id = len(evidence_entries) + 1
    synthetic: list[m.ReportEvidence] = []

    # The proof ladder's artifacts survive the dedupe fold (S15): a contributor merged
    # into an owner promotes its proof to the finding that reports the root cause.
    own_proofs: dict[int, m.FindingProof] = {}
    for candidate in candidates:
        proof = _own_proof(candidate)
        if proof is not None and candidate.id is not None:
            own_proofs[candidate.id] = proof
    merged_proofs: dict[int, m.FindingProof] = {}
    for stored in inputs.analyses:
        contributors = stored.payload.get("contributors")
        if not isinstance(contributors, (list, tuple)) or stored.finding_id is None:
            continue
        for contributor in contributors:
            try:
                proof = own_proofs.get(int(contributor))
            except (TypeError, ValueError):
                continue
            if proof is not None and stored.finding_id is not None:
                merged_proofs.setdefault(stored.finding_id, proof)

    findings: list[m.ReportFinding] = []
    excluded: list[m.FalsePositiveEntry] = []
    low_confidence: list[m.ReportFinding] = []
    #: ``finding row id → its rendered evidence refs``, so a path hop can cite the same
    #: evidence the finding does rather than a second copy of it (S21).
    finding_refs: dict[int, tuple[str, ...]] = {}
    for candidate in candidates:
        if candidate.id is None:
            continue
        analysis = analyses.get(candidate.id)
        check_id, check_version = split_check_key(candidate.check_key)
        module = candidate.module or check_id.split(".", 1)[0].upper()
        # The analysed verdict is authoritative: the SQL store writes it back to
        # ``findings.status``, while an in-memory store only has it on the analysis.
        status = str(analysis.status if analysis is not None else candidate.status)
        cwe = _classification(analysis, check_id, cwe_map, owasp).cwe
        severity = _severity(
            candidate.severity or (analysis.severity if analysis is not None else None)
        )
        score = _score_from(analysis, candidate)
        description = (
            analysis.narrative
            if analysis is not None and analysis.narrative
            else (_note_detail(candidate) or candidate.title)
        )
        refs = sorted(
            {
                ref_map[record.id]
                for record in candidate.evidence
                if record.id is not None and record.id in ref_map
            }
        )
        merged = analysis.payload.get("merged_evidence_refs") if analysis is not None else None
        if isinstance(merged, (list, tuple)):
            refs.extend(ref_map[int(item)] for item in merged if int(item) in ref_map)
        refs = sorted(set(refs))
        if not refs:
            identifier = m.evidence_id(next_id)
            next_id += 1
            synthetic.append(
                m.ReportEvidence(
                    id=identifier,
                    kind="note",
                    summary=f"candidate provenance for {check_id}",
                    payload={
                        "check": candidate.check_key,
                        "title": candidate.title,
                        "detail": description,
                    },
                    sha256=None,
                    captured_at=candidate.created_at,
                )
            )
            refs = [identifier]

        finding_refs[candidate.id] = tuple(refs)
        finding = m.ReportFinding(
            id=m.finding_id(candidate.id),
            scan_id=scan_label,
            module=module,
            check_id=check_id,
            check_version=check_version,
            research_ref=candidate.research_ref,
            title=candidate.title,
            asset=m.AssetRef(
                kind=candidate.asset_kind or "unknown",
                value=candidate.asset_value or "unknown",
            ),
            severity=severity,  # type: ignore[arg-type]
            score=score,
            classification=_classification(analysis, check_id, cwe_map, owasp),
            description=description,
            evidence_refs=tuple(refs),
            proof=_finding_proof(candidate, merged_proofs),
            remediation=_remediation_for(candidate, analysis, check_id, cwe, catalog),
            status=status,
            provenance=_provenance(analysis, inputs.engine),
            timestamps=m.Timestamps(
                first_seen=candidate.created_at or inputs.started_at,
                last_seen=candidate.created_at or inputs.started_at,
                verified_at=(candidate.created_at if status in {"verified", "fixed"} else None),
            ),
        )
        if status in EXCLUDED_STATUSES:
            excluded.append(
                m.FalsePositiveEntry(
                    finding_id=finding.id,
                    title=finding.title,
                    severity=finding.severity,
                    reason=(
                        str(analysis.payload.get("drop_reason") or "")
                        if analysis is not None and analysis.payload.get("drop_reason")
                        else (
                            "merged into another finding with the same root cause"
                            if status == "merged"
                            else "dropped by a false-positive filter"
                        )
                    ),
                    status=status,
                )
            )
            continue
        if score.confidence < threshold:
            low_confidence.append(finding)
        else:
            findings.append(finding)

    findings.sort(key=lambda item: (-severity_rank(item.severity), item.id))
    low_confidence.sort(key=lambda item: (-severity_rank(item.severity), item.id))

    counts = m.SeverityCounts(
        critical=sum(1 for item in findings if item.severity == "critical"),
        high=sum(1 for item in findings if item.severity == "high"),
        medium=sum(1 for item in findings if item.severity == "medium"),
        low=sum(1 for item in findings if item.severity == "low"),
        info=sum(1 for item in findings if item.severity == "info"),
    )

    assets = _build_assets(inputs.assets)
    urls = sum(1 for asset in assets if asset.kind == "url")
    hosts = sum(1 for asset in assets if asset.kind in {"host", "domain"})
    scope = (inputs.plan or {}).get("scope") or {}
    duration = None
    if inputs.started_at is not None and inputs.finished_at is not None:
        duration = max(0.0, (inputs.finished_at - inputs.started_at).total_seconds())

    modules = tuple(dict.fromkeys(check.module for check in checks if check.ran))
    if not modules:
        modules = tuple(sorted({item.module for item in findings}))

    scope_section = m.ScopeMethodology(
        target_name=inputs.target_name,
        scope={str(key): [str(v) for v in values] for key, values in dict(scope).items()},
        exclusions=_exclusions(scope),
        modules=modules,
        checks=checks,
        checks_run=sum(1 for check in checks if check.ran),
        checks_skipped=sum(1 for check in checks if not check.ran),
        rate_limits=dict(inputs.rate_limits or {}),
        started_at=inputs.started_at,
        finished_at=inputs.finished_at,
        duration_seconds=duration,
        engine_mode=inputs.engine,
        research_corpus_version=inputs.research_corpus_version,
        requested_by=inputs.requested_by,
        credentials=tuple(inputs.credentials),
        authenticated=bool(inputs.authenticated),
    )

    summary = build_executive_summary(
        findings=findings,
        low_confidence=low_confidence,
        counts=counts,
        threshold=threshold,
        asset_count=len(assets),
        host_count=hosts,
        url_count=urls,
        modules=modules,
        duration_seconds=duration,
        engine=inputs.engine,
        templates=templates,
        diff_counts=(inputs.diff.counts if inputs.diff is not None else None),
        compared_scan=(inputs.diff.scan_a if inputs.diff is not None else None),
    )

    audit = normalize_audit_events(inputs.audit_events)
    appendix = m.Appendix(
        evidence=tuple(evidence_entries) + tuple(synthetic),
        audit=_audit_highlights(audit),
        false_positives=tuple(sorted(excluded, key=lambda item: (item.status, item.finding_id))),
        glossary=dict(_GLOSSARY),
    )

    authorization = (inputs.plan or {}).get("attestation")
    cover = m.ReportCover(
        title=f"Security Assessment Report — {inputs.target_name}",
        target=inputs.target_name,
        scan_id=scan_label,
        generated_at=generated_at,
        scan_started_at=inputs.started_at,
        scan_finished_at=inputs.finished_at,
        engine=inputs.engine,
        arachne_version=inputs.arachne_version,
        module_versions=dict(sorted((inputs.module_versions or {}).items())),
        authorization=dict(authorization) if isinstance(authorization, Mapping) else None,
    )

    return m.ReportData(
        scan_id=scan_label,
        target_name=inputs.target_name,
        cover=cover,
        executive_summary=summary,
        scope=scope_section,
        assets=assets,
        findings=tuple(findings),
        low_confidence=tuple(low_confidence),
        patch_gap=_patch_gap(findings) if "M6" in modules else None,
        state_changes=_state_change_entries(inputs.proof_state),
        intel=_intel_block(inputs.intel),
        attack_paths=_attack_paths(
            analyses=list(analyses.values()),
            candidates=candidates,
            finding_refs=finding_refs,
            criticality=inputs.criticality,
        ),
        compliance=_compliance_block(
            inputs, checks=scope_section.checks, findings=findings
        ),
        detection_validation=_detection_validation_block(
            inputs.detection_validation, sigma=inputs.detection_sigma
        ),
        # S28: only ever the block an operator asked for. A scan contributes nothing here,
        # which is what keeps a simulated path out of the verified report (REQ-SIM-004).
        simulation=inputs.simulation,
        appendix=appendix,
        diff=inputs.diff,
        branding=_resolve_branding(inputs),
        locale=_resolve_locale(inputs),
    )


def _compliance_block(
    inputs: ReportInputs, *, checks: Sequence[m.CheckRun], findings: Sequence[m.ReportFinding]
) -> tuple[m.FrameworkCoverage, ...]:
    """The per-framework control-coverage blocks (S22, REQ-TRUST-001).

    Frameworks come from the inputs (which defaults to the deployment's
    ``report.compliance_frameworks``); an empty result keeps a pre-S22 report
    byte-identical. A map that fails to load is a loud :class:`ConfigurationError` — a
    report that silently dropped a named framework would understate both coverage and
    gaps. The loader is called *without* ``known_checks`` so a stale custom map cannot
    fail a report; the shipped maps are pinned by the schema test instead.
    """
    settings = inputs.settings
    frameworks = inputs.compliance_frameworks
    map_dir = inputs.compliance_map_dir or (
        settings.report.compliance_map_dir if settings is not None else None
    )
    if frameworks is None and settings is not None:
        frameworks = settings.report.compliance_frameworks
    if not frameworks:
        return ()
    from arachne.core.errors import ConfigurationError
    from arachne.report.compliance import (
        available_frameworks,
        canonical_framework,
        compute_framework_coverage,
        load_compliance_framework,
    )

    resolved: list[str] = []
    for name in frameworks:
        canonical = canonical_framework(name)
        if canonical is None:
            msg = (
                f"unknown compliance framework {name!r}; this build ships "
                f"{', '.join(available_frameworks())}"
            )
            raise ConfigurationError(msg)
        if canonical not in resolved:
            resolved.append(canonical)

    blocks: list[m.FrameworkCoverage] = []
    for name in resolved:
        map_data = load_compliance_framework(name, maps_dir=map_dir)
        blocks.append(compute_framework_coverage(map_data, checks, findings))
    return tuple(blocks)


def _attack_paths(
    *,
    analyses: Sequence[Any],
    candidates: Sequence[CandidateRecord],
    finding_refs: Mapping[int, tuple[str, ...]],
    criticality: Any | None = None,
) -> tuple[m.AttackPathEntry, ...]:
    """Compose the estate's attack paths for the report (S21, REQ-AGENT-003).

    The *composition* is pure (``arachne.analyzer.paths``); this only adapts it to the report
    DTO — finding ids in the report's ``F-`` form and evidence in its ``E-`` refs, so a hop
    cites exactly what the finding cites.
    """
    from arachne.analyzer.paths import build_attack_paths
    from arachne.data.analysis_store import analysis_from_log

    rebuilt = [item for item in (analysis_from_log(row) for row in analyses) if item is not None]
    paths = build_attack_paths(rebuilt, candidates, criticality=criticality)
    out: list[m.AttackPathEntry] = []
    for path in paths:
        hops = tuple(
            m.AttackPathHop(
                stage=hop.stage.value,
                check_id=hop.check_id,
                title=hop.title,
                asset=hop.asset,
                marker=hop.stage.value,
                severity=hop.severity,
                verified=hop.verified,
                verifying_check=hop.verifying_check,
                finding_id=(m.finding_id(hop.finding_id) if hop.finding_id else None),
                evidence_refs=(
                    tuple(finding_refs.get(hop.finding_id, ()))
                    if hop.finding_id is not None
                    else ()
                ),
            )
            for hop in path.hops
        )
        out.append(
            m.AttackPathEntry(
                id=path.id,
                asset=path.asset,
                severity=path.severity,
                criticality=path.criticality,
                business_severity=(
                    path.business_severity if path.criticality is not None else None
                ),
                stages=tuple(hop.stage for hop in path.hops),
                fully_verified=path.fully_verified,
                hops=hops,
                cheapest_break=path.cheapest_reason,
                cheapest_check_id=(path.cheapest.check_id if path.cheapest else None),
                cheapest_finding_id=(
                    m.finding_id(path.cheapest.finding_id)
                    if path.cheapest is not None and path.cheapest.finding_id
                    else None
                ),
            )
        )
    return tuple(out)


def simulation_block(
    *,
    run: Any = None,
    change: Any = None,
    trend: Any = None,
) -> m.SimulationBlock:
    """Adapt a what-if run (and/or a change delta) to the report's simulated block (S28).

    The one adapter between area SIM and the report, and deliberately a *separate* DTO
    conversion rather than a reuse of :class:`~arachne.report.model.AttackPathEntry`: the
    simulated section must not be able to render through the verified section's types, and a
    hop's origin (``observed``/``hypothetical``) replaces the verified marker entirely
    (REQ-SIM-004).

    ``trend`` is accepted so a caller that re-simulated continuously can attach the series it
    recorded; it is currently reported through the posture view rather than the report, and
    passing it adds nothing to the block.
    """
    _ = trend
    if run is None and change is None:
        msg = "a simulation block needs a run or a change to describe"
        raise ConfigurationError(msg)

    source = run if run is not None else change
    # A run carries its hypotheses itself; a change delta carries them inside its change set.
    declared: Any = getattr(source, "hypotheses", None)
    if declared is None:
        declared = getattr(getattr(source, "change", None), "hypotheses", ())
    hypotheses = tuple(
        m.SimulationHypothesis(
            id=item.id,
            kind=item.kind.value,
            asset=item.asset,
            title=item.title,
            severity=item.severity,
            cwe=item.cwe,
            note=item.note,
        )
        for item in declared
    )
    if run is not None:
        paths = _simulated_paths(run.result)
        refusals = tuple(
            f"{item.hypothesis.id}: {item.reason}" for item in getattr(run, "refusals", ())
        )
        model = dict(getattr(run, "model_after", {}) or {})
        exposure_before = int(getattr(run, "exposure_before", 0))
        exposure_after = int(getattr(run, "exposure_after", 0))
        scans = tuple(int(item) for item in getattr(run, "built_from_scans", ()))
    else:
        paths = _simulated_paths(change.after)
        refusals = tuple(
            f"{item.hypothesis.id}: {item.reason}"
            for item in getattr(change, "refusals", ())
        )
        model = {}
        exposure_before = int(getattr(change, "exposure_before", 0))
        exposure_after = int(getattr(change, "exposure_after", 0))
        scans = tuple(int(item) for item in getattr(change, "built_from_scans", ()))

    return m.SimulationBlock(
        provenance="simulated",
        estate_key=str(getattr(source, "estate_key", "") or ""),
        built_from_scans=scans,
        model=model,
        hypotheses=hypotheses,
        refusals=refusals,
        paths=paths,
        change=(_simulated_change(change) if change is not None else None),
        exposure_before=exposure_before,
        exposure_after=exposure_after,
    )


def _simulated_paths(paths: Any) -> tuple[m.SimulatedPathEntry, ...]:
    out: list[m.SimulatedPathEntry] = []
    for item in paths or ():
        hops = tuple(
            m.SimulatedHop(
                check_id=hop.hop.check_id,
                title=hop.hop.title,
                asset=hop.hop.asset,
                stage=hop.hop.stage.value,
                severity=hop.hop.severity,
                origin=hop.origin,
                hypothesis_id=hop.hypothesis_id,
                finding_id=(m.finding_id(hop.hop.finding_id) if hop.hop.finding_id else None),
            )
            for hop in item.hops
        )
        out.append(
            m.SimulatedPathEntry(
                id=item.path.id,
                asset=item.path.asset,
                severity=item.path.severity,
                business_severity=(
                    item.path.business_severity if item.path.criticality is not None else None
                ),
                criticality=item.path.criticality,
                stages=tuple(hop.hop.stage.value for hop in item.hops),
                hops=hops,
                hypotheses=tuple(item.introduced_by),
                cheapest_break=item.cheapest_label,
                cheapest_origin=item.cheapest_origin,
                cheapest_hypothesis_id=item.cheapest_hypothesis_id,
                hypothetical=item.hypothetical,
            )
        )
    return tuple(out)


def _simulated_change(change: Any) -> m.SimulatedChange:
    return m.SimulatedChange(
        name=str(change.change.name),
        description=str(change.change.description),
        exposure_before=int(change.exposure_before),
        exposure_after=int(change.exposure_after),
        exposure_delta=int(change.exposure_delta),
        paths_before=len(change.before),
        paths_after=len(change.after),
        introduced=tuple(item.path.id for item in change.introduced),
        removed=tuple(item.id for item in change.removed),
    )


def _resolve_branding(inputs: ReportInputs) -> m.Branding:
    """The report's branding: the deployment default, the project's override, MSSP mode.

    ``resolve_branding`` is shared with the CLI and the API so all three resolve a report's
    presentation — and white-label mode — identically (S26, REQ-ECOS-006).
    """
    from arachne.report.branding import resolve_branding

    return resolve_branding(inputs.settings, inputs.branding)


def _resolve_locale(inputs: ReportInputs) -> str:
    """The report's language: the per-report value, else the deployment default (S26).

    An explicit locale (a CLI ``--locale``, an API ``?locale=``, a project default) wins; with
    none, ``ARACHNE_REPORT_LOCALE`` is the deployment's answer and ``""`` leaves the choice to
    the i18n module (``ARACHNE_LOCALE``, else ``en``). Storing the resolved value on the DTO
    is what makes the report self-describing: ``schema_version`` names the shape and ``locale``
    names the language.
    """
    if inputs.locale.strip():
        return inputs.locale.strip()
    if inputs.settings is not None:
        return inputs.settings.report.locale.strip()
    return ""


def _exclusions(scope: Mapping[str, Any]) -> tuple[str, ...]:
    keys = (
        "excluded_hosts",
        "excluded_domains",
        "excluded_networks",
        "excluded_url_prefixes",
        "excluded_refs",
    )
    values: list[str] = []
    for key in keys:
        for item in scope.get(key) or ():
            values.append(str(item))
    return tuple(sorted(values))


def build_report_for_scan(
    *,
    scan_id: int,
    scans: Any,
    findings: Any,
    analyses: Any,
    audit_events: Sequence[Any] = (),
    module_versions: Mapping[str, str] | None = None,
    arachne_version: str = "",
    settings: Settings | None = None,
    generated_at: datetime | None = None,
    diff: m.ReportDiff | None = None,
    not_run_checks: Mapping[str, str] | None = None,
    branding: m.Branding | None = None,
    locale: str | None = None,
    compliance_frameworks: tuple[str, ...] | None = None,
    compliance_map_dir: str | None = None,
    criticality: Any | None = None,
    simulation: m.SimulationBlock | None = None,
) -> m.ReportData:
    """SQL-wired convenience: read the scan, its assets/findings/analyses, then build.

    ``simulation`` is the S28 what-if block an operator asked for; it is the *only* way a
    simulated path reaches a report, and nothing in this function derives one from the scan.
    """
    from arachne.core.errors import ReportError

    record = scans.get_scan(scan_id)
    if record is None:
        msg = f"scan {scan_id} does not exist"
        raise ReportError(msg)
    plan = dict(record.plan or {})
    rate_limits: dict[str, float | int] = {}
    if settings is not None:
        rate_limits = {
            "per_host_per_second": settings.rate_limit.per_host_rate,
            "per_host_burst": settings.rate_limit.per_host_burst,
            "global_per_second": settings.rate_limit.global_rate,
            "global_burst": settings.rate_limit.global_burst,
        }
    corpus_version = _corpus_version(analyses.list_analyses(scan_id))
    return build_report_data(
        ReportInputs(
            scan_id=scan_id,
            target_name=str(plan.get("target_name") or f"scan {scan_id}"),
            engine=str(plan.get("engine") or record.engine),
            plan=plan,
            status=record.status.value,
            started_at=record.started_at,
            finished_at=record.finished_at,
            assets=scans.list_assets(scan_id),
            candidates=findings.list_candidates(scan_id),
            analyses=analyses.list_analyses(scan_id),
            audit_events=audit_events,
            module_versions=module_versions or {},
            rate_limits=rate_limits,
            arachne_version=arachne_version,
            generated_at=generated_at or record.finished_at or record.created_at,
            settings=settings,
            not_run_checks=not_run_checks or {},
            research_corpus_version=corpus_version,
            diff=diff,
            branding=branding,
            locale=locale or "",
            proof_state=dict(record.stats.get("proof") or {}) if record.stats else {},
            requested_by=(record.stats or {}).get("requested_by"),
            credentials=_credential_labels(record),
            authenticated=_authenticated(record),
            intel=dict(record.stats.get("intel") or {}) if record.stats else {},
            compliance_frameworks=compliance_frameworks,
            compliance_map_dir=compliance_map_dir,
            criticality=criticality,
            detection_validation=(
                dict(record.stats.get("purple") or {}) if record.stats else {}
            ),
            simulation=simulation,
        )
    )


def _credential_labels(record: Any) -> tuple[str, ...]:
    """The credential labels the scan recorded (S19), or an empty tuple.

    Read from ``scans.stats["credentials"]``, which the checks step writes — labels only, so a
    report can state *that* it was a credentialed scan without ever carrying a credential.
    """
    block = (getattr(record, "stats", None) or {}).get("credentials") or {}
    labels = block.get("labels") if isinstance(block, dict) else None
    return tuple(str(label) for label in labels or ())


def _authenticated(record: Any) -> bool:
    block = (getattr(record, "stats", None) or {}).get("credentials") or {}
    return bool(block.get("authenticated")) if isinstance(block, dict) else False


def _corpus_version(analyses: Sequence[StoredAnalysis]) -> str | None:
    versions = sorted(
        {analysis.template_version for analysis in analyses if analysis.template_version}
    )
    return ", ".join(versions) if versions else None
