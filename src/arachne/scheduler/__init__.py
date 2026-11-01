"""The recurring-scan scheduler (F-01-05, S11).

The scheduler turns a target fixture plus a cron expression into a *series* of scans and, on
each run, a change-detection diff against the previous run (F-06-05). This package is the
operational half of that requirement; the report engine's trend section is the presentation
half.

``cron``
    A small dependency-free 5-field cron parser.
``model``
    The schedule definition, its persisted state, and one run's result.
``store``
    The JSON state document (definitions + last run / next run per schedule).
``runner``
    The coordinator: due schedules, the real scan, and the persisted diff.
"""

from __future__ import annotations

from arachne.scheduler.cron import CronExpression, parse_cron
from arachne.scheduler.model import ScheduleRun, ScheduleSpec, ScheduleState
from arachne.scheduler.runner import Scheduler, default_diff_writer, default_scan_runner
from arachne.scheduler.store import ScheduleStore, StoredSchedule

__all__ = [
    "CronExpression",
    "ScheduleRun",
    "ScheduleSpec",
    "ScheduleState",
    "ScheduleStore",
    "Scheduler",
    "StoredSchedule",
    "default_diff_writer",
    "default_scan_runner",
    "parse_cron",
]
