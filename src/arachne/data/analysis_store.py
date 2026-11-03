"""Analysis persistence: ``findings`` gets its severity, ``analysis_log`` gets the analysis.

The analyzer produces :class:`~arachne.analyzer.model.Analysis` objects; this module is the
only place they meet the schema. It writes three things per analysed candidate, and each has
a reason:

``findings.severity`` / ``confidence`` / ``remediation_id`` / ``status``
    The candidate row becomes an *analysed* finding (F-06-01). Severity is the only column
    the module layer deliberately left NULL (ADR-02), so this write is what makes a finding
    reportable.
``analysis_log``
    The whole analysis — score, rule trace, narrative, provenance — as ``output_json``
    (F-03-05), plus the AI provenance record as its own column (WP-15, REQ-AGENT-008). It is
    the report's narrative source and the audit trail of *why* a finding has the severity it
    has; keeping it out of ``findings`` is what lets the schema stay the spec's.
``fp_feedback``
    Operator decisions (F-05-07), read back by the tuner as an aggregate.

A compound finding from the correlation engine has no ``checks`` row to point at, so its
``check_id`` stays NULL and its synthetic identity (``correlation.<rule>``) lives in the
analysis record — where a report already looks for the explanation.

:func:`provenance_of` is the one place that decides whether an analysis row may call itself
AI-authored: the payload's ``ai.provenance`` block is rebuilt as a
:class:`~arachne.ai.provenance.ProvenanceRecord`, and a row that claims ``ai`` without a cited
evidence id is written as ``heuristic`` with ``fallback="provenance_invalid"``. The invariant is
enforced structurally in the record type, and this is the boundary that keeps a payload written
by something else from smuggling an unverifiable claim into the table.

:class:`~arachne.analyzer.fp.FeedbackRecord` is imported under ``TYPE_CHECKING`` only: the
analyzer package re-exports its handlers, and those import *this* module, so a module-level
import here would make ``import arachne.data.analysis_store`` fail depending on which side of
the cycle Python happened to enter first. The annotation is a string, so nothing at runtime
needs the class.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from typing import TYPE_CHECKING, Any, Protocol

from sqlalchemy import func, select
from sqlalchemy.orm import Session, sessionmaker

from arachne.ai.provenance import ProvenanceError, ProvenanceRecord
from arachne.analyzer.model import Analysis, FpStats, Verdict
from arachne.data.models import AnalysisLog, Finding, FpFeedback, Scan
from arachne.data.scan_store import as_utc

if TYPE_CHECKING:  # ``analyzer.fp`` imports back through ``analyzer/__init__`` (see note)
    from arachne.analyzer.fp import FeedbackRecord

__all__ = [
    "AnalysisStore",
    "MemoryAnalysisStore",
    "SqlAnalysisStore",
    "StoredAnalysis",
    "analysis_from_log",
    "provenance_of",
]


@dataclass(frozen=True, slots=True)
class StoredAnalysis:
    """One persisted analysis, with the row it belongs to."""

    finding_id: int | None
    scan_id: int
    severity: str
    confidence: int
    status: str
    engine: str
    remediation_id: str | None = None
    template_version: str | None = None
    #: ``analysis_log.id`` — the report's ``provenance.analysis_log_id`` .
    log_id: int | None = None
    created_at: datetime | None = None
    #: The AI provenance record (WP-15, REQ-AGENT-008): ``origin`` says whether a model
    #: contributed to this row, without reading the trail or joining tables.
    provenance: Mapping[str, Any] = field(default_factory=dict)
    payload: Mapping[str, Any] = field(default_factory=dict)

    @property
    def origin(self) -> str:
        """``ai`` or ``heuristic`` (an unstated record reads as the engine's own label)."""
        value = self.provenance.get("origin")
        return str(value) if isinstance(value, str) and value else self.engine

    @property
    def evidence_ids(self) -> tuple[str, ...]:
        """The evidence ids this row's AI content cited (empty for a heuristic row)."""
        return tuple(str(item) for item in self.provenance.get("evidence_ids") or ())

    @property
    def check_id(self) -> str | None:
        value = self.payload.get("check_id")
        return str(value) if isinstance(value, str) else None

    @property
    def narrative(self) -> str:
        value = self.payload.get("narrative")
        return str(value) if isinstance(value, str) else ""

    @property
    def cwe(self) -> str | None:
        value = self.payload.get("cwe")
        return str(value) if isinstance(value, str) else None

    @property
    def verdict(self) -> str:
        value = self.payload.get("verdict")
        return str(value) if isinstance(value, str) else "analyzed"

    @property
    def correlated(self) -> bool:
        return bool(self.payload.get("correlated"))

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "scan_id": self.scan_id,
            "severity": self.severity,
            "confidence": self.confidence,
            "status": self.status,
            "engine": self.engine,
            "remediation_id": self.remediation_id,
            "check_id": self.check_id,
            "log_id": self.log_id,
            "narrative": self.narrative,
            "cwe": self.cwe,
            "verdict": self.verdict,
            "correlated": self.correlated,
            "analysis": dict(self.payload),
        }


def analysis_from_log(record: StoredAnalysis) -> Analysis | None:
    """Rebuild an :class:`Analysis` from a stored record, for the correlation step.

    Only the fields the correlation engine reads are reconstructed; anything missing from an
    older analysis record degrades to a sensible default rather than raising, because a scan
    must be re-analysable after an upgrade (the same tolerance ``Orchestrator`` shows for
    stored plans).
    """
    payload = record.payload
    if not payload:
        return None
    from arachne.analyzer.model import Analysis as AnalysisModel
    from arachne.analyzer.model import Provenance, Remediation, RuleTraceEntry, ScoreBreakdown

    raw_score = payload.get("score")
    raw_provenance = payload.get("provenance")
    raw_remediation = payload.get("remediation")
    score_payload: Mapping[str, Any] = raw_score if isinstance(raw_score, Mapping) else {}
    provenance_payload: Mapping[str, Any] = (
        raw_provenance if isinstance(raw_provenance, Mapping) else {}
    )
    remediation_payload: Mapping[str, Any] = (
        raw_remediation if isinstance(raw_remediation, Mapping) else {}
    )
    trace_payload = payload.get("rule_trace")
    return AnalysisModel(
        title=str(payload.get("title") or ""),
        severity=str(payload.get("severity") or record.severity or "info"),
        confidence=int(payload.get("confidence") or record.confidence or 0),
        narrative=str(payload.get("narrative") or ""),
        remediation=Remediation(
            id=str(remediation_payload.get("id") or record.remediation_id or "unknown"),
            summary=str(remediation_payload.get("summary") or ""),
            steps=tuple(str(item) for item in remediation_payload.get("steps") or ()),
            verification=tuple(str(item) for item in remediation_payload.get("verification") or ()),
            references=tuple(str(item) for item in remediation_payload.get("references") or ()),
            source=str(remediation_payload.get("source") or "catalog"),
        ),
        finding_id=record.finding_id,
        check_id=record.check_id,
        asset=str(payload.get("asset") or "") or None,
        cwe=record.cwe,
        cve=str(payload["cve"]) if payload.get("cve") else None,
        risk_notes=str(payload.get("risk_notes") or ""),
        verdict=_verdict(payload.get("verdict")),
        drop_reason=str(payload["drop_reason"]) if payload.get("drop_reason") else None,
        verified=bool(payload.get("verified")),
        merged_into=_integer(payload.get("merged_into")),
        score=ScoreBreakdown(
            cvss_vector=_string_or_none(score_payload.get("cvss_vector")),
            cvss_base=float(score_payload.get("cvss_base") or 0.0),
            owasp_likelihood=float(score_payload.get("owasp_likelihood") or 0.0),
            owasp_impact=float(score_payload.get("owasp_impact") or 0.0),
            owasp_risk=str(score_payload.get("owasp_risk") or "low"),
            epss=_float_or_none(score_payload.get("epss")),
            derived_severity=str(score_payload.get("derived_severity") or "info"),
            confidence=int(score_payload.get("confidence") or record.confidence or 0),
            confidence_reasons=tuple(
                str(item) for item in score_payload.get("confidence_reasons") or ()
            ),
        ),
        provenance=Provenance(
            engine=str(provenance_payload.get("engine") or record.engine),
            rule_ids=tuple(str(item) for item in provenance_payload.get("rule_ids") or ()),
            template_version=_string_or_none(provenance_payload.get("template_version")),
            model=_string_or_none(provenance_payload.get("model")),
            prompt_template=_string_or_none(provenance_payload.get("prompt_template")),
            prompt_hash=_string_or_none(provenance_payload.get("prompt_hash")),
            provider=_string_or_none(provenance_payload.get("provider")),
            fallback=_string_or_none(provenance_payload.get("fallback")),
        ),
        rule_trace=tuple(
            RuleTraceEntry(
                rule_id=str(item.get("rule_id") or ""),
                clause=str(item.get("clause") or ""),
                expression=str(item.get("expression") or ""),
                value=item.get("value"),
            )
            for item in trace_payload or ()
            if isinstance(item, Mapping)
        ),
        contributors=tuple(int(item) for item in payload.get("contributors") or ()),
        merged_evidence_refs=tuple(int(item) for item in payload.get("merged_evidence_refs") or ()),
        signatures=tuple(str(item) for item in payload.get("signatures") or ()),
        correlated=bool(payload.get("correlated")),
        ai=dict(payload.get("ai") or {}) if isinstance(payload.get("ai"), Mapping) else {},
    )


def provenance_of(analysis: Analysis) -> ProvenanceRecord:
    """The provenance record to persist for ``analysis`` (REQ-AGENT-008).

    The engine writes the record into the analysis payload (``ai.provenance``); this rebuilds it
    as a typed value, so a malformed or uncited claim cannot reach the column. Three cases:

    * a valid record — returned unchanged, whatever its origin;
    * an analysis with no record at all — a heuristic-origin record derived from
      :class:`~arachne.analyzer.model.Provenance`, which is what a third-party ``Analyzer``
      produces and what every pre-WP-15 payload looks like;
    * a payload that *claims* ``ai`` without a citable evidence id — written as heuristic-origin
      with ``fallback="provenance_invalid"``, because an AI row that cannot name its evidence is
      the one thing the requirement forbids, and a scan must not fail over it.
    """
    raw = analysis.ai.get("provenance") if isinstance(analysis.ai, Mapping) else None
    if isinstance(raw, Mapping):
        try:
            return ProvenanceRecord.from_dict(raw)
        except ProvenanceError:
            return ProvenanceRecord.heuristic(
                fallback="provenance_invalid",
                change={"origin_claimed": str(raw.get("origin") or "")},
            )
    if analysis.provenance.engine == "ai":
        return ProvenanceRecord.heuristic(fallback="provenance_invalid")
    return ProvenanceRecord.heuristic(fallback=analysis.provenance.fallback)


def _verdict(value: Any) -> Verdict:
    """A stored verdict, coerced to the model's vocabulary (tolerating an older row)."""
    text = str(value or "analyzed")
    return "dropped" if text == "dropped" else "merged" if text == "merged" else "analyzed"


def _integer(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _float_or_none(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value)


def _string_or_none(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


class AnalysisStore(Protocol):
    """Where analyses and FP feedback are persisted (F-03-05, F-05-07)."""

    def apply(
        self, scan_id: int, analyses: Sequence[Analysis], *, engine: str
    ) -> tuple[StoredAnalysis, ...]: ...

    def create_compound(
        self,
        scan_id: int,
        analysis: Analysis,
        *,
        engine: str,
        asset_id: int | None = None,
    ) -> StoredAnalysis: ...

    def list_analyses(self, scan_id: int) -> tuple[StoredAnalysis, ...]: ...

    def record_feedback(self, record: FeedbackRecord, *, actor: str | None = None) -> None: ...

    def feedback_stats(self, keys: Iterable[str] | None = None) -> Mapping[str, FpStats]: ...


class MemoryAnalysisStore:
    """In-memory analysis store (dry runs, unit tests, a scan with no database)."""

    def __init__(self) -> None:
        self._analyses: dict[int, list[StoredAnalysis]] = {}
        self._feedback: list[FeedbackRecord] = []
        self._next_finding = 1
        self._next_log = 1

    def apply(
        self, scan_id: int, analyses: Sequence[Analysis], *, engine: str
    ) -> tuple[StoredAnalysis, ...]:
        return tuple(
            self._record(scan_id, analysis, engine=engine, finding_id=analysis.finding_id)
            for analysis in analyses
        )

    def create_compound(
        self,
        scan_id: int,
        analysis: Analysis,
        *,
        engine: str,
        asset_id: int | None = None,
    ) -> StoredAnalysis:
        del asset_id
        finding_id = self._next_finding
        self._next_finding += 1
        return self._record(scan_id, analysis, engine=engine, finding_id=finding_id)

    def list_analyses(self, scan_id: int) -> tuple[StoredAnalysis, ...]:
        return tuple(self._analyses.get(scan_id, ()))

    def record_feedback(self, record: FeedbackRecord, *, actor: str | None = None) -> None:
        del actor
        self._feedback.append(record)

    def feedback_stats(self, keys: Iterable[str] | None = None) -> Mapping[str, FpStats]:
        wanted = set(keys) if keys is not None else None
        totals: dict[str, int] = {}
        fps: dict[str, int] = {}
        for record in self._feedback:
            if wanted is not None and record.key not in wanted:
                continue
            totals[record.key] = totals.get(record.key, 0) + 1
            if record.is_fp:
                fps[record.key] = fps.get(record.key, 0) + 1
        return {
            key: FpStats(total=total, false_positives=fps.get(key, 0))
            for key, total in totals.items()
        }

    def _record(
        self,
        scan_id: int,
        analysis: Analysis,
        *,
        engine: str,
        finding_id: int | None,
    ) -> StoredAnalysis:
        record = provenance_of(analysis)
        stored = StoredAnalysis(
            finding_id=finding_id,
            scan_id=scan_id,
            severity=analysis.severity,
            confidence=analysis.confidence,
            status=analysis.status,
            engine=record.origin,
            remediation_id=analysis.remediation.id,
            template_version=analysis.provenance.template_version,
            log_id=self._next_log,
            provenance=record.to_dict(),
            payload=analysis.to_dict(),
        )
        self._next_log += 1
        self._analyses.setdefault(scan_id, []).append(stored)
        return stored


class SqlAnalysisStore:
    """``AnalysisStore`` over ``findings``/``analysis_log``/``fp_feedback``."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    # ------------------------------------------------------------------ analysis
    def apply(
        self, scan_id: int, analyses: Sequence[Analysis], *, engine: str
    ) -> tuple[StoredAnalysis, ...]:
        stored: list[StoredAnalysis] = []
        with self._session_factory() as session:
            for analysis in analyses:
                if analysis.finding_id is None:
                    # A candidate that was never persisted (a dry analysis): nothing to update,
                    # but the analysis itself is still worth a log row when a scan owns it.
                    stored.append(self._write_log(session, analysis, engine=engine, finding=None))
                    continue
                finding = session.get(Finding, analysis.finding_id)
                if finding is None:
                    continue
                self._update_finding(finding, analysis)
                stored.append(self._write_log(session, analysis, engine=engine, finding=finding))
            session.commit()
        return tuple(stored)

    def create_compound(
        self,
        scan_id: int,
        analysis: Analysis,
        *,
        engine: str,
        asset_id: int | None = None,
    ) -> StoredAnalysis:
        with self._session_factory() as session:
            finding = Finding(
                scan_id=scan_id,
                check_id=None,
                asset_id=asset_id,
                title=analysis.title[:512],
                severity=analysis.severity,
                confidence=float(analysis.confidence),
                status=analysis.status,
                evidence_refs_json=sorted(analysis.merged_evidence_refs),
                remediation_id=analysis.remediation.id,
            )
            session.add(finding)
            session.flush()
            stored = self._write_log(session, analysis, engine=engine, finding=finding)
            session.commit()
            return stored

    def list_analyses(self, scan_id: int) -> tuple[StoredAnalysis, ...]:
        with self._session_factory() as session:
            rows = session.scalars(
                select(AnalysisLog)
                .where(
                    AnalysisLog.finding_id.in_(select(Finding.id).where(Finding.scan_id == scan_id))
                )
                .order_by(AnalysisLog.id)
            ).all()
            out: list[StoredAnalysis] = []
            for row in rows:
                finding = session.get(Finding, row.finding_id) if row.finding_id else None
                out.append(
                    StoredAnalysis(
                        finding_id=row.finding_id,
                        scan_id=scan_id,
                        severity=str(finding.severity) if finding and finding.severity else "info",
                        confidence=int(finding.confidence or 0) if finding else 0,
                        status=str(finding.status) if finding else "open",
                        engine=str(row.engine),
                        remediation_id=finding.remediation_id if finding else None,
                        template_version=row.template_version,
                        log_id=int(row.id),
                        created_at=as_utc(row.created_at),
                        provenance=dict(row.provenance) if row.provenance else {},
                        payload=dict(row.output_json),
                    )
                )
        return tuple(out)

    def provenance_for_scan(self, scan_id: int) -> tuple[Mapping[str, Any], ...]:
        """Every analysis row's provenance record for one scan (REQ-AGENT-008's export).

        Read straight from the column rather than re-derived from ``output_json``: the export is
        a statement about what was *persisted* at the time, and a payload edited afterwards must
        not change it. A pre-WP-15 row contributes nothing (its record was never stated).
        """
        with self._session_factory() as session:
            rows = session.scalars(
                select(AnalysisLog.provenance)
                .join(Finding, Finding.id == AnalysisLog.finding_id)
                .where(Finding.scan_id == scan_id, AnalysisLog.provenance.is_not(None))
                .order_by(AnalysisLog.id)
            ).all()
        return tuple(dict(row) for row in rows if row)

    def provenance_for_project(self, project_id: int | None) -> tuple[Mapping[str, Any], ...]:
        """Every analysis row's provenance record across a project's scans (REQ-AGENT-008).

        ``None`` selects the implicit default project — the rows whose scan carries no
        ``project_id``, which is how a pre-S14 deployment reads (``data/project_store.py``).
        """
        with self._session_factory() as session:
            query = (
                select(AnalysisLog.provenance)
                .join(Finding, Finding.id == AnalysisLog.finding_id)
                .join(Scan, Scan.id == Finding.scan_id)
                .where(AnalysisLog.provenance.is_not(None))
                .order_by(AnalysisLog.id)
            )
            query = (
                query.where(Scan.project_id.is_(None))
                if project_id is None
                else query.where(Scan.project_id == project_id)
            )
            rows = session.scalars(query).all()
        return tuple(dict(row) for row in rows if row)

    def count_analyses(self, scan_id: int) -> int:
        with self._session_factory() as session:
            total = session.scalar(
                select(func.count())
                .select_from(AnalysisLog)
                .join(Finding, Finding.id == AnalysisLog.finding_id)
                .where(Finding.scan_id == scan_id)
            )
        return int(total or 0)

    # ------------------------------------------------------------------ feedback
    def record_feedback(self, record: FeedbackRecord, *, actor: str | None = None) -> None:
        with self._session_factory() as session:
            session.add(
                FpFeedback(
                    key=record.key[:255],
                    finding_id=record.finding_id,
                    is_fp=record.is_fp,
                    note=record.note,
                    actor=actor,
                )
            )
            session.commit()

    def feedback_stats(self, keys: Iterable[str] | None = None) -> Mapping[str, FpStats]:
        query = select(FpFeedback.key, FpFeedback.is_fp)
        wanted = list(keys) if keys is not None else None
        if wanted is not None:
            query = query.where(FpFeedback.key.in_(wanted))
        with self._session_factory() as session:
            rows = session.execute(query).all()
        totals: dict[str, int] = {}
        fps: dict[str, int] = {}
        for key, is_fp in rows:
            name = str(key)
            totals[name] = totals.get(name, 0) + 1
            if is_fp:
                fps[name] = fps.get(name, 0) + 1
        return {
            key: FpStats(total=total, false_positives=fps.get(key, 0))
            for key, total in totals.items()
        }

    # ------------------------------------------------------------------ internals
    @staticmethod
    def _update_finding(finding: Finding, analysis: Analysis) -> None:
        finding.severity = analysis.severity
        finding.confidence = float(analysis.confidence)
        finding.status = analysis.status
        finding.remediation_id = analysis.remediation.id
        refs = list(finding.evidence_refs_json or [])
        for item in sorted(analysis.merged_evidence_refs):
            if item not in refs:
                refs.append(item)
        finding.evidence_refs_json = refs

    @staticmethod
    def _write_log(
        session: Session,
        analysis: Analysis,
        *,
        engine: str,
        finding: Finding | None,
    ) -> StoredAnalysis:
        record = provenance_of(analysis)
        row = AnalysisLog(
            finding_id=finding.id if finding is not None else None,
            engine=record.origin or engine,
            model=analysis.provenance.model,
            template_version=analysis.provenance.template_version,
            prompt_hash=analysis.provenance.prompt_hash,
            output_json=analysis.to_dict(),
            tokens_used=record.total_tokens,
            provenance=record.to_dict(),
        )
        session.add(row)
        session.flush()
        return StoredAnalysis(
            finding_id=finding.id if finding is not None else None,
            scan_id=finding.scan_id if finding is not None else 0,
            severity=analysis.severity,
            confidence=analysis.confidence,
            status=analysis.status,
            engine=str(row.engine),
            remediation_id=analysis.remediation.id,
            template_version=row.template_version,
            log_id=int(row.id),
            created_at=as_utc(row.created_at),
            provenance=record.to_dict(),
            payload=analysis.to_dict(),
        )
