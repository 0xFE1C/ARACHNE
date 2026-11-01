"""Report building for the API and web UI (F-06-02/03, S12).

The CLI builds a report inline in ``cli/report.py``; the API needs the same thing and the
same webhook fan-out, so it lives here as one small service the routers call:

* :meth:`ReportService.build` renders the immutable DTO for a stored scan (reusing
  :func:`~arachne.report.builder.build_report_for_scan`, the same function the CLI uses, so
  the Markdown a UI shows is byte-for-byte the Markdown ``arachne report`` prints).
* :meth:`ReportService.render` picks the renderer.
* :meth:`ReportService.notify` posts the webhooks (F-06-06) — never raising, returning the
  per-integration results.

Keeping it in one place is what lets ``GET /scans/{id}/report`` and the UI's report viewer
share a cacheable, testable path.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from typing import Any

from arachne import __version__
from arachne.core.config import Settings
from arachne.core.errors import ReportError
from arachne.data.analysis_store import SqlAnalysisStore
from arachne.data.report_store import SqlAuditReader, SqlScanDiffStore
from arachne.data.services import ScanServices
from arachne.report import (
    Branding,
    branding_from_dict,
    build_diff,
    build_report_for_scan,
    diff_payload,
    module_versions_for,
    not_run_checks,
    render_report,
    resolve_branding,
)
from arachne.report.model import ReportData

__all__ = ["ReportService"]

_logger = logging.getLogger(__name__)


def _active_suppressions(services: Any) -> Any:
    """The suppression rules in force (S21), or an empty set when none are wired."""
    from arachne.quality.suppressions import SuppressionSet

    quality = getattr(services, "quality", None)
    return SuppressionSet() if quality is None else quality.active_suppressions()


class ReportService:
    """Build, render and push reports for the API."""

    def __init__(
        self,
        services: ScanServices,
        *,
        settings: Settings | None = None,
        notifier: Any = None,
    ) -> None:
        self._services = services
        self._settings = settings or services.settings
        self._notifier = notifier

    # ------------------------------------------------------------------ build
    def build(
        self,
        scan_id: int,
        *,
        diff_with: int | None = None,
        branding: Branding | None = None,
        locale: str | None = None,
    ) -> ReportData:
        """Build the report DTO for ``scan_id`` (optionally attached to an earlier scan).

        ``locale`` selects the report language (S26, REQ-ECOS-005); ``None`` uses the
        deployment default. It rides on the DTO, so ``render`` needs no locale argument.
        """
        services = self._services
        scans = services.store
        findings = services.findings
        analyses = SqlAnalysisStore(services.session_factory)
        record = scans.get_scan(scan_id)
        if record is None:
            raise ReportError(f"scan {scan_id} does not exist")
        effective_branding = branding or self._branding_for(record)
        effective_locale = self._locale_for(record, locale)
        module_versions = module_versions_for(services.registry, record.plan)
        not_run = not_run_checks(services.registry, findings.list_candidates(scan_id))

        diff = None
        if diff_with is not None:
            earlier = scans.get_scan(diff_with)
            if earlier is None:
                raise ReportError(f"scan {diff_with} does not exist")
            earlier_report = self._build_one(
                diff_with,
                earlier,
                module_versions,
                findings,
                analyses,
                branding=effective_branding,
                locale=effective_locale,
            )
            current = self._build_one(
                scan_id,
                record,
                module_versions,
                findings,
                analyses,
                not_run,
                branding=effective_branding,
                locale=effective_locale,
            )
            diff = build_diff(
                earlier_report.findings,
                current.findings,
                scan_a=f"scan_{diff_with}",
                scan_b=f"scan_{scan_id}",
                suppressions=_active_suppressions(services),
            )
            SqlScanDiffStore(services.session_factory).save(diff_with, scan_id, diff_payload(diff))
        return self._build_one(
            scan_id,
            record,
            module_versions,
            findings,
            analyses,
            not_run,
            diff=diff,
            branding=effective_branding,
            locale=effective_locale,
        )

    def _branding_for(self, record: Any) -> Branding:
        """Deployment default ⊕ project branding ⊕ MSSP mode (F-07-06, S14; S26).

        ``resolve_branding`` is shared with the CLI and the builder so all three apply
        white-label mode (REQ-ECOS-006) identically rather than each remembering to.
        """
        project_id = getattr(record, "project_id", None)
        override: Branding | None = None
        if project_id is not None:
            project = self._services.projects.get(int(project_id))
            if project is not None and project.branding:
                override = branding_from_dict(project.branding)
        return resolve_branding(self._settings, override)

    def _locale_for(self, record: Any, explicit: str | None) -> str:
        """The report language: an explicit per-report value, else the tenant's, else ``""``.

        Precedence mirrors branding: a per-report ``?locale=`` wins, then the project's stored
        ``report_locale``, then the deployment default (applied by the builder). That makes a
        tenant able to receive French reports by default while a single scan can still be
        rendered in English for an auditor (S26, REQ-ECOS-005).
        """
        if explicit and explicit.strip():
            return explicit.strip()
        project_id = getattr(record, "project_id", None)
        if project_id is not None:
            project = self._services.projects.get(int(project_id))
            stored = getattr(project, "report_locale", None) if project is not None else None
            if stored and str(stored).strip():
                return str(stored).strip()
        return ""

    def _build_one(
        self,
        scan_id: int,
        record: Any,
        module_versions: dict[str, str],
        findings: Any,
        analyses: Any,
        not_run: dict[str, str] | None = None,
        *,
        diff: Any = None,
        branding: Branding | None = None,
        locale: str = "",
    ) -> ReportData:
        return build_report_for_scan(
            scan_id=scan_id,
            scans=self._services.store,
            findings=findings,
            analyses=analyses,
            audit_events=SqlAuditReader(self._services.session_factory).events_for_scan(
                scan_id, started_at=record.started_at, finished_at=record.finished_at
            ),
            module_versions=module_versions,
            arachne_version=__version__,
            settings=self._settings,
            generated_at=record.finished_at or record.created_at or datetime.now(UTC),
            not_run_checks=not_run,
            diff=diff,
            branding=branding,
            locale=locale,
            criticality=self._criticality_index(),
        )

    def _criticality_index(self) -> Any:
        """The CMDB criticality index (S23, REQ-POSTURE-006), or ``None`` without one."""
        from arachne.posture.cmdb import CriticalityIndex

        store = getattr(self._services, "posture", None)
        if store is None:
            return None
        tiers = store.criticality_index()
        return CriticalityIndex(tiers) if tiers else None

    # ------------------------------------------------------------------ render
    def render(self, scan_id: int, fmt: str = "md", *, locale: str | None = None) -> str:
        report = self.build(scan_id, locale=locale)
        return render_report(report, fmt)

    # ------------------------------------------------------------------ webhooks
    async def notify(self, scan_id: int) -> tuple[Any, ...]:
        """Deliver the configured webhooks for ``scan_id`` (F-06-06). Never raises.

        The scan's audit events are fetched and handed to the notifier (S22,
        REQ-OPS-002) so the SIEM export carries the findings **and** the trail, not
        just the findings; every other destination ignores them. Failure to fetch the
        trail never fails a delivery — the SIEM then receives the findings alone.
        """
        if self._notifier is None or not self._notifier.enabled:
            return ()
        report = self.build(scan_id)
        audit_events: list[dict[str, Any]] = []
        try:
            record = self._services.store.get_scan(scan_id)
            if record is not None:
                events = SqlAuditReader(self._services.session_factory).events_for_scan(
                    scan_id, started_at=record.started_at, finished_at=record.finished_at
                )
                audit_events = [event.to_dict() for event in events]
        except Exception as exc:  # the trail is a bonus here, never a delivery blocker
            _logger.warning(
                "audit events for the siem export could not be read",
                extra={"event": "webhook.audit_read_failed", "scan_id": scan_id, "error": str(exc)},
            )
        results: tuple[Any, ...] = tuple(await self._notifier.notify(report, audit_events))
        return results
