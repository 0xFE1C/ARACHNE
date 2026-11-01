"""Persist scheduler definitions and state in one small JSON document (F-01-05).

The scheduler's state is *operational*, not evidentiary: it answers "when did this schedule
last run, and which scan id did it produce?", and losing it costs a re-run, not a finding. It
therefore lives in a JSON file (``ARACHNE_SCHEDULER_STATE``, defaulting to
``.arachne/schedules.json``) rather than in a database table — which keeps the evidence store
schema to the spec's tables and lets an operator version or copy the schedule file.

Writes are atomic (temp file + ``os.replace``) so a crash mid-write cannot leave a truncated
schedule file, and the loader tolerates an absent file (a fresh deployment has no schedules).
"""

from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Iterable
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from arachne.core.errors import ConfigurationError
from arachne.scheduler.model import ScheduleSpec, ScheduleState

__all__ = ["DEFAULT_STATE_PATH", "ScheduleStore", "StoredSchedule"]

#: Where the scheduler keeps its state when nothing is configured.
DEFAULT_STATE_PATH = Path(".arachne") / "schedules.json"

_FORMAT_VERSION = "1.0"


@dataclass(frozen=True, slots=True)
class StoredSchedule:
    """A definition plus its state, as one row of the store."""

    spec: ScheduleSpec
    state: ScheduleState

    def to_dict(self) -> dict[str, Any]:
        return {"spec": self.spec.to_dict(), "state": self.state.to_dict()}

    @classmethod
    def from_dict(cls, data: Any) -> StoredSchedule:
        if not isinstance(data, dict):
            msg = "a stored schedule must be a mapping"
            raise ConfigurationError(msg)
        return cls(
            spec=ScheduleSpec.from_dict(data.get("spec") or {}),
            state=ScheduleState.from_dict(data.get("state") or {}),
        )


class ScheduleStore:
    """Read/write the scheduler state document."""

    def __init__(self, path: str | Path | None = None) -> None:
        self.path = Path(path).expanduser() if path is not None else DEFAULT_STATE_PATH

    # ------------------------------------------------------------------ loading
    def load(self) -> tuple[StoredSchedule, ...]:
        if not self.path.is_file():
            return ()
        try:
            text = self.path.read_text(encoding="utf-8")
        except OSError as exc:
            msg = f"cannot read scheduler state {self.path}: {exc}"
            raise ConfigurationError(msg) from exc
        if not text.strip():
            return ()
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            msg = f"{self.path}: not valid JSON: {exc}"
            raise ConfigurationError(msg) from exc
        rows = data.get("schedules") if isinstance(data, dict) else data
        if not isinstance(rows, list):
            msg = f"{self.path}: expected a list of schedules"
            raise ConfigurationError(msg)
        return tuple(StoredSchedule.from_dict(row) for row in rows)

    def get(self, schedule_id: str) -> StoredSchedule | None:
        for row in self.load():
            if row.spec.id == schedule_id:
                return row
        return None

    # ------------------------------------------------------------------ writing
    def save(self, rows: Iterable[StoredSchedule]) -> None:
        document = {
            "version": _FORMAT_VERSION,
            "schedules": [row.to_dict() for row in rows],
        }
        _atomic_write(self.path, json.dumps(document, indent=2, sort_keys=True) + "\n")

    def upsert(self, spec: ScheduleSpec, *, state: ScheduleState | None = None) -> StoredSchedule:
        rows = list(self.load())
        for index, row in enumerate(rows):
            if row.spec.id == spec.id:
                merged = StoredSchedule(spec=spec, state=state or row.state)
                rows[index] = merged
                self.save(rows)
                return merged
        merged = StoredSchedule(spec=spec, state=state or ScheduleState())
        rows.append(merged)
        self.save(rows)
        return merged

    def remove(self, schedule_id: str) -> bool:
        rows = [row for row in self.load() if row.spec.id != schedule_id]
        if len(rows) == len(self.load()):
            return False
        self.save(rows)
        return True

    def record(self, schedule_id: str, state: ScheduleState) -> StoredSchedule:
        rows = list(self.load())
        for index, row in enumerate(rows):
            if row.spec.id == schedule_id:
                rows[index] = StoredSchedule(spec=row.spec, state=state)
                self.save(rows)
                return rows[index]
        msg = f"schedule {schedule_id!r} does not exist"
        raise ConfigurationError(msg)


def _atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temp_name = tempfile.mkstemp(prefix=path.name, dir=str(path.parent))
    temp_path = Path(temp_name)
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        temp_path.replace(path)
    except BaseException:
        with suppress(OSError):
            temp_path.unlink()
        raise
