"""Persistence for detection validation (S24, area VALID).

Three views of one dataset — the purple team's memory between runs:

* **campaigns** (REQ-VALID-001/006) — what to replay, against which target, on which
  schedule. A campaign is the identity the coverage *trend* is reported over, so it is a
  stored row rather than a command-line argument.
* **runs** (REQ-VALID-002/004) — one executed run: its nonce, its window, what it emitted,
  the Sigma rule-hit/rule-miss alignment, and the coverage report once alerts have been
  scored against it. Coverage is *updated in place* because a defender's SIEM may report
  after the window closes: re-scoring a run must not need a second scan.
* **alerts** (REQ-VALID-002) — the normalized defender alerts ingested from the SIEM.
  Deduplicated on ``(source, alert_id)`` so a re-delivered webhook does not inflate the
  coverage numbers.

Both implementations live here with the same behaviour, because a workflow that only
works against Postgres is a workflow nobody tests. The store never invents policy: what
counts as "seen" is decided by :mod:`arachne.purple.coverage`, what a window means by
:mod:`arachne.purple.window`.

Every statement is a SQLAlchemy Core expression built from the mapped classes and a bound
literal parameter — no SQL text is ever assembled from a value, and no value from an alert
payload reaches a statement as anything but a bind parameter.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from arachne.core.errors import ScanStateError
from arachne.data import models
from arachne.data.models import utcnow  # noqa: F401  (re-exported for callers' convenience)
from arachne.data.scan_store import as_utc
from arachne.purple.alerts import DefenderAlert

__all__ = [
    "AlertRecord",
    "CampaignRecord",
    "MemoryPurpleStore",
    "PurpleStore",
    "RunRecord",
    "SqlPurpleStore",
]

#: The run status vocabulary. ``window_refused`` is a *recorded refusal*, not an error: a
#: campaign that fired outside its coordinated window is a fact the trend must show.
RUN_STATUSES = ("completed", "window_refused", "failed")


def _now(moment: datetime | None) -> datetime:
    return (moment or datetime.now(UTC)).astimezone(UTC)


def _stored(moment: datetime | None) -> datetime:
    """A *non-nullable* timestamp column read back (``as_utc`` cannot return ``None`` here)."""
    converted = as_utc(moment)
    if converted is None:  # pragma: no cover - the column is NOT NULL by schema
        msg = "a non-nullable timestamp column read back as NULL"
        raise ScanStateError(msg)
    return converted


@dataclass(frozen=True, slots=True)
class CampaignRecord:
    """One stored campaign."""

    id: int
    name: str
    spec: dict[str, Any]
    enabled: bool = True
    last_run_at: datetime | None = None
    created_at: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "spec": dict(self.spec),
            "enabled": self.enabled,
            "last_run_at": self.last_run_at.isoformat() if self.last_run_at else None,
        }


@dataclass(frozen=True, slots=True)
class RunRecord:
    """One stored purple-team run."""

    id: int
    campaign_id: int
    campaign: str
    scan_id: int | None
    nonce: str
    window: dict[str, Any] | None
    started_at: datetime
    finished_at: datetime | None = None
    status: str = "completed"
    emissions: tuple[dict[str, Any], ...] = ()
    sigma: tuple[dict[str, Any], ...] = ()
    coverage: dict[str, Any] | None = None
    gaps: tuple[str, ...] = ()
    note: str | None = None

    @property
    def coverage_pct(self) -> float:
        return float((self.coverage or {}).get("coverage_pct", 0.0))

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.id,
            "campaign": self.campaign,
            "scan_id": self.scan_id,
            "nonce": self.nonce,
            "window": dict(self.window) if self.window else None,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "status": self.status,
            "emissions": [dict(item) for item in self.emissions],
            "sigma": [dict(item) for item in self.sigma],
            "coverage": dict(self.coverage) if self.coverage else None,
            "gaps": list(self.gaps),
            "note": self.note,
        }


@dataclass(frozen=True, slots=True)
class AlertRecord:
    """One stored defender alert."""

    alert_id: str
    source: str
    observed_at: datetime
    title: str = ""
    technique: str | None = None
    tactic: str | None = None
    nonce: str | None = None
    severity: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    def to_alert(self) -> DefenderAlert:
        return DefenderAlert(
            alert_id=self.alert_id,
            source=self.source,
            observed_at=self.observed_at,
            title=self.title,
            technique=self.technique,
            tactic=self.tactic,
            nonce=self.nonce,
            severity=self.severity,
            raw=dict(self.raw),
        )


class PurpleStore(Protocol):
    """The purple-team store both implementations satisfy."""

    def upsert_campaign(
        self,
        name: str,
        spec: dict[str, Any],
        *,
        enabled: bool = True,
        now: datetime | None = None,
    ) -> CampaignRecord: ...

    def campaigns(self) -> tuple[CampaignRecord, ...]: ...

    def campaign(self, name: str) -> CampaignRecord | None: ...

    def set_campaign_enabled(
        self, name: str, enabled: bool, *, now: datetime | None = None
    ) -> CampaignRecord | None: ...

    def delete_campaign(self, name: str) -> bool: ...

    def record_run(
        self,
        *,
        campaign: str,
        nonce: str,
        window: dict[str, Any] | None,
        scan_id: int | None = None,
        status: str = "completed",
        emissions: Sequence[dict[str, Any]] = (),
        sigma: Sequence[dict[str, Any]] = (),
        now: datetime | None = None,
        note: str | None = None,
    ) -> RunRecord | None: ...

    def update_run(
        self,
        run_id: int,
        *,
        coverage: dict[str, Any] | None = None,
        gaps: Sequence[str] | None = None,
        status: str | None = None,
        now: datetime | None = None,
        note: str | None = None,
    ) -> RunRecord | None: ...

    def run(self, run_id: int) -> RunRecord | None: ...

    def runs(self, campaign: str | None = None, *, limit: int = 50) -> tuple[RunRecord, ...]: ...

    def previous_run(self, campaign: str, run_id: int) -> RunRecord | None: ...

    def ingest_alerts(
        self, alerts: Iterable[DefenderAlert], *, now: datetime | None = None
    ) -> int: ...

    def alerts(
        self, *, since: datetime | None = None, until: datetime | None = None, limit: int = 5000
    ) -> tuple[AlertRecord, ...]: ...

    def clear_alerts(self) -> int: ...


def _campaign_record(row: models.PurpleCampaign) -> CampaignRecord:
    return CampaignRecord(
        id=row.id,
        name=row.name,
        spec=dict(row.spec_json or {}),
        enabled=bool(row.enabled),
        last_run_at=as_utc(row.last_run_at) if row.last_run_at else None,
        created_at=_stored(row.created_at),
    )


def _run_from_row(row: models.PurpleRun, campaign: str) -> RunRecord:
    return RunRecord(
        id=row.id,
        campaign_id=row.campaign_id,
        campaign=campaign,
        scan_id=row.scan_id,
        nonce=row.nonce,
        window=dict(row.window_json) if row.window_json else None,
        started_at=_stored(row.started_at),
        finished_at=as_utc(row.finished_at),
        status=row.status,
        emissions=tuple(dict(item) for item in (row.emissions_json or ())),
        sigma=tuple(dict(item) for item in (row.sigma_json or ())),
        coverage=dict(row.coverage_json) if row.coverage_json else None,
        gaps=tuple(str(item) for item in (row.gaps_json or ())),
        note=row.note,
    )


def _alert_from_row(row: models.PurpleAlert) -> AlertRecord:
    return AlertRecord(
        alert_id=row.alert_id,
        source=row.source,
        observed_at=_stored(row.observed_at),
        title=row.title or "",
        technique=row.technique,
        tactic=row.tactic,
        nonce=row.nonce,
        severity=row.severity,
        raw=dict(row.raw_json or {}),
    )


# --------------------------------------------------------------------------- memory


class MemoryPurpleStore:
    """An in-process purple store: the same behaviour without a database (tests)."""

    def __init__(self) -> None:
        self._campaigns: dict[str, CampaignRecord] = {}
        self._runs: list[RunRecord] = []
        self._alerts: list[AlertRecord] = []
        self._next_campaign = 1
        self._next_run = 1

    # ------------------------------------------------------------------ campaigns
    def upsert_campaign(
        self,
        name: str,
        spec: dict[str, Any],
        *,
        enabled: bool = True,
        now: datetime | None = None,
    ) -> CampaignRecord:
        moment = _now(now)
        existing = self._campaigns.get(name)
        record = CampaignRecord(
            id=existing.id if existing else self._next_campaign,
            name=name,
            spec=dict(spec),
            enabled=enabled,
            last_run_at=existing.last_run_at if existing else None,
            created_at=existing.created_at if existing else moment,
        )
        if existing is None:
            self._next_campaign += 1
        self._campaigns[name] = record
        return record

    def campaigns(self) -> tuple[CampaignRecord, ...]:
        return tuple(self._campaigns[name] for name in sorted(self._campaigns))

    def campaign(self, name: str) -> CampaignRecord | None:
        return self._campaigns.get(name)

    def set_campaign_enabled(
        self, name: str, enabled: bool, *, now: datetime | None = None
    ) -> CampaignRecord | None:
        existing = self._campaigns.get(name)
        if existing is None:
            return None
        updated = CampaignRecord(
            id=existing.id,
            name=existing.name,
            spec=dict(existing.spec),
            enabled=enabled,
            last_run_at=existing.last_run_at,
            created_at=existing.created_at,
        )
        self._campaigns[name] = updated
        return updated

    def delete_campaign(self, name: str) -> bool:
        removed = self._campaigns.pop(name, None)
        if removed is None:
            return False
        self._runs = [run for run in self._runs if run.campaign != name]
        return True

    # ------------------------------------------------------------------ runs
    def record_run(
        self,
        *,
        campaign: str,
        nonce: str,
        window: dict[str, Any] | None,
        scan_id: int | None = None,
        status: str = "completed",
        emissions: Sequence[dict[str, Any]] = (),
        sigma: Sequence[dict[str, Any]] = (),
        now: datetime | None = None,
        note: str | None = None,
    ) -> RunRecord | None:
        record_campaign = self._campaigns.get(campaign)
        if record_campaign is None:
            return None
        moment = _now(now)
        record = RunRecord(
            id=self._next_run,
            campaign_id=record_campaign.id,
            campaign=campaign,
            scan_id=scan_id,
            nonce=nonce,
            window=dict(window) if window else None,
            started_at=moment,
            finished_at=moment if status == "completed" else None,
            status=status,
            emissions=tuple(dict(item) for item in emissions),
            sigma=tuple(dict(item) for item in sigma),
            note=note,
        )
        self._next_run += 1
        self._runs.append(record)
        self._campaigns[campaign] = CampaignRecord(
            id=record_campaign.id,
            name=record_campaign.name,
            spec=dict(record_campaign.spec),
            enabled=record_campaign.enabled,
            last_run_at=moment,
            created_at=record_campaign.created_at,
        )
        return record

    def update_run(
        self,
        run_id: int,
        *,
        coverage: dict[str, Any] | None = None,
        gaps: Sequence[str] | None = None,
        status: str | None = None,
        now: datetime | None = None,
        note: str | None = None,
    ) -> RunRecord | None:
        for index, run in enumerate(self._runs):
            if run.id != run_id:
                continue
            updated = RunRecord(
                id=run.id,
                campaign_id=run.campaign_id,
                campaign=run.campaign,
                scan_id=run.scan_id,
                nonce=run.nonce,
                window=run.window,
                started_at=run.started_at,
                finished_at=(
                    _now(now)
                    if (status == "completed" or coverage is not None)
                    else run.finished_at
                ),
                status=status or run.status,
                emissions=run.emissions,
                sigma=run.sigma,
                coverage=dict(coverage) if coverage is not None else run.coverage,
                gaps=tuple(str(item) for item in gaps) if gaps is not None else run.gaps,
                note=note if note is not None else run.note,
            )
            self._runs[index] = updated
            return updated
        return None

    def run(self, run_id: int) -> RunRecord | None:
        for run in self._runs:
            if run.id == run_id:
                return run
        return None

    def runs(self, campaign: str | None = None, *, limit: int = 50) -> tuple[RunRecord, ...]:
        selected = [run for run in self._runs if campaign is None or run.campaign == campaign]
        selected.sort(key=lambda item: (item.started_at, item.id))
        return tuple(selected[-limit:])

    def previous_run(self, campaign: str, run_id: int) -> RunRecord | None:
        previous: RunRecord | None = None
        for run in self.runs(campaign, limit=10_000):
            if run.id == run_id:
                return previous
            previous = run
        return None

    # ------------------------------------------------------------------ alerts
    def ingest_alerts(self, alerts: Iterable[DefenderAlert], *, now: datetime | None = None) -> int:
        existing = {(item.source, item.alert_id) for item in self._alerts}
        added = 0
        for alert in alerts:
            key = (alert.source, alert.alert_id)
            if key in existing:
                continue
            existing.add(key)
            self._alerts.append(
                AlertRecord(
                    alert_id=alert.alert_id,
                    source=alert.source,
                    observed_at=alert.observed_at,
                    title=alert.title,
                    technique=alert.technique,
                    tactic=alert.tactic,
                    nonce=alert.nonce,
                    severity=alert.severity,
                    raw=dict(alert.raw or {}),
                )
            )
            added += 1
        self._alerts.sort(key=lambda item: (item.observed_at, item.alert_id))
        return added

    def alerts(
        self, *, since: datetime | None = None, until: datetime | None = None, limit: int = 5000
    ) -> tuple[AlertRecord, ...]:
        lower = since.astimezone(UTC) if since is not None else None
        upper = until.astimezone(UTC) if until is not None else None
        selected = [
            item
            for item in self._alerts
            if (lower is None or item.observed_at >= lower)
            and (upper is None or item.observed_at <= upper)
        ]
        return tuple(selected[:limit])

    def clear_alerts(self) -> int:
        count = len(self._alerts)
        self._alerts = []
        return count


# --------------------------------------------------------------------------- sql


class SqlPurpleStore:
    """``PurpleStore`` over the three S24 tables (``purple_campaigns`` et al)."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._session_factory = session_factory

    # ------------------------------------------------------------------ campaigns
    def upsert_campaign(
        self,
        name: str,
        spec: dict[str, Any],
        *,
        enabled: bool = True,
        now: datetime | None = None,
    ) -> CampaignRecord:
        moment = _now(now)
        with self._session_factory() as session:
            row = session.scalars(
                select(models.PurpleCampaign).where(models.PurpleCampaign.name == name)
            ).first()
            if row is None:
                row = models.PurpleCampaign(
                    name=name,
                    spec_json=dict(spec),
                    enabled=enabled,
                    created_at=moment,
                    updated_at=moment,
                )
                session.add(row)
            else:
                row.spec_json = dict(spec)
                row.enabled = enabled
                row.updated_at = moment
            session.commit()
            session.refresh(row)
            return _campaign_record(row)

    def campaigns(self) -> tuple[CampaignRecord, ...]:
        with self._session_factory() as session:
            rows = session.scalars(
                select(models.PurpleCampaign).order_by(models.PurpleCampaign.name)
            ).all()
            return tuple(_campaign_record(row) for row in rows)

    def campaign(self, name: str) -> CampaignRecord | None:
        with self._session_factory() as session:
            row = session.scalars(
                select(models.PurpleCampaign).where(models.PurpleCampaign.name == name)
            ).first()
            return _campaign_record(row) if row is not None else None

    def set_campaign_enabled(
        self, name: str, enabled: bool, *, now: datetime | None = None
    ) -> CampaignRecord | None:
        with self._session_factory() as session:
            row = session.scalars(
                select(models.PurpleCampaign).where(models.PurpleCampaign.name == name)
            ).first()
            if row is None:
                return None
            row.enabled = enabled
            row.updated_at = _now(now)
            session.commit()
            return _campaign_record(row)

    def delete_campaign(self, name: str) -> bool:
        with self._session_factory() as session:
            row = session.scalars(
                select(models.PurpleCampaign).where(models.PurpleCampaign.name == name)
            ).first()
            if row is None:
                return False
            children = session.scalars(
                select(models.PurpleRun).where(models.PurpleRun.campaign_id == row.id)
            ).all()
            for child in children:
                session.delete(child)
            session.delete(row)
            session.commit()
            return True

    # ------------------------------------------------------------------ runs
    def record_run(
        self,
        *,
        campaign: str,
        nonce: str,
        window: dict[str, Any] | None,
        scan_id: int | None = None,
        status: str = "completed",
        emissions: Sequence[dict[str, Any]] = (),
        sigma: Sequence[dict[str, Any]] = (),
        now: datetime | None = None,
        note: str | None = None,
    ) -> RunRecord | None:
        moment = _now(now)
        with self._session_factory() as session:
            parent = session.scalars(
                select(models.PurpleCampaign).where(models.PurpleCampaign.name == campaign)
            ).first()
            if parent is None:
                return None
            row = models.PurpleRun(
                campaign_id=parent.id,
                scan_id=scan_id,
                nonce=nonce,
                window_json=dict(window) if window else None,
                started_at=moment,
                finished_at=moment if status == "completed" else None,
                status=status,
                emissions_json=[dict(item) for item in emissions],
                sigma_json=[dict(item) for item in sigma],
                gaps_json=[],
                note=note,
            )
            session.add(row)
            parent.last_run_at = moment
            parent.updated_at = moment
            session.commit()
            session.refresh(row)
            return _run_from_row(row, campaign)

    def update_run(
        self,
        run_id: int,
        *,
        coverage: dict[str, Any] | None = None,
        gaps: Sequence[str] | None = None,
        status: str | None = None,
        now: datetime | None = None,
        note: str | None = None,
    ) -> RunRecord | None:
        moment = _now(now)
        with self._session_factory() as session:
            row = session.get(models.PurpleRun, run_id)
            if row is None:
                return None
            if coverage is not None:
                row.coverage_json = dict(coverage)
                row.finished_at = moment
            if gaps is not None:
                row.gaps_json = [str(item) for item in gaps]
            if status is not None:
                row.status = status
            if note is not None:
                row.note = note
            session.commit()
            session.refresh(row)
            parent = session.get(models.PurpleCampaign, row.campaign_id)
            return _run_from_row(row, parent.name if parent is not None else "")

    def run(self, run_id: int) -> RunRecord | None:
        with self._session_factory() as session:
            row = session.get(models.PurpleRun, run_id)
            if row is None:
                return None
            parent = session.get(models.PurpleCampaign, row.campaign_id)
            return _run_from_row(row, parent.name if parent is not None else "")

    def runs(self, campaign: str | None = None, *, limit: int = 50) -> tuple[RunRecord, ...]:
        with self._session_factory() as session:
            names = {
                row.id: row.name for row in session.scalars(select(models.PurpleCampaign)).all()
            }
            wanted = {key for key, name in names.items() if campaign is None or name == campaign}
            rows = session.scalars(
                select(models.PurpleRun)
                .where(models.PurpleRun.campaign_id.in_(sorted(wanted)))
                .order_by(models.PurpleRun.started_at.desc(), models.PurpleRun.id.desc())
                .limit(limit)
            ).all()
            ordered = list(reversed(rows))
            return tuple(_run_from_row(row, names.get(row.campaign_id, "")) for row in ordered)

    def previous_run(self, campaign: str, run_id: int) -> RunRecord | None:
        previous: RunRecord | None = None
        for run in self.runs(campaign, limit=10_000):
            if run.id == run_id:
                return previous
            previous = run
        return None

    # ------------------------------------------------------------------ alerts
    def ingest_alerts(self, alerts: Iterable[DefenderAlert], *, now: datetime | None = None) -> int:
        moment = _now(now)
        added = 0
        with self._session_factory() as session:
            existing = {
                (item.source, item.alert_id)
                for item in session.scalars(
                    select(models.PurpleAlert).order_by(models.PurpleAlert.id)
                ).all()
            }
            for alert in alerts:
                key = (alert.source, alert.alert_id)
                if key in existing:
                    continue
                existing.add(key)
                session.add(
                    models.PurpleAlert(
                        alert_id=alert.alert_id,
                        source=alert.source,
                        observed_at=alert.observed_at,
                        title=alert.title,
                        technique=alert.technique,
                        tactic=alert.tactic,
                        nonce=alert.nonce,
                        severity=alert.severity,
                        raw_json=dict(alert.raw or {}),
                        created_at=moment,
                    )
                )
                added += 1
            session.commit()
        return added

    def alerts(
        self, *, since: datetime | None = None, until: datetime | None = None, limit: int = 5000
    ) -> tuple[AlertRecord, ...]:
        with self._session_factory() as session:
            statement = select(models.PurpleAlert)
            if since is not None:
                statement = statement.where(models.PurpleAlert.observed_at >= since.astimezone(UTC))
            if until is not None:
                statement = statement.where(models.PurpleAlert.observed_at <= until.astimezone(UTC))
            statement = statement.order_by(
                models.PurpleAlert.observed_at, models.PurpleAlert.id
            ).limit(limit)
            return tuple(_alert_from_row(row) for row in session.scalars(statement).all())

    def clear_alerts(self) -> int:
        with self._session_factory() as session:
            rows = session.scalars(select(models.PurpleAlert)).all()
            count = len(rows)
            for row in rows:
                session.delete(row)
            session.commit()
            return count
