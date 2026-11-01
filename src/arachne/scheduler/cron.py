"""Cron-like schedule expressions for the recurring-scan scheduler (F-01-05, S11).

A deliberately small, dependency-free 5-field cron parser:  ``minute hour day-of-month month
day-of-week``. It supports the forms an operator actually writes — ``*``, ``*/n``, ``a-b``,
``a-b/n``, comma lists and a bare number — and the standard cron day rule (when both the
day-of-month and day-of-week fields are restricted, a day matches if *either* does).

Time zones are the caller's: a :class:`~datetime.datetime` is matched field by field, so a
naive expression evaluated in local time and an aware one in UTC both do the obvious thing.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta

from arachne.core.errors import ConfigurationError

__all__ = ["CronExpression", "parse_cron"]

#: ``(min, max)`` per field: minute, hour, day-of-month, month, day-of-week.
_RANGES: tuple[tuple[int, int], ...] = ((0, 59), (0, 23), (1, 31), (1, 12), (0, 7))

#: How far ahead :meth:`CronExpression.next_after` looks before giving up (5 years of
#: minutes). A schedule that never fires in five years is a mistake worth reporting.
_MAX_SEARCH_MINUTES = 5 * 366 * 24 * 60


def _parse_field(text: str, *, low: int, high: int, name: str, expression: str) -> frozenset[int]:
    values: set[int] = set()
    for part in text.split(","):
        part = part.strip()
        if not part:
            msg = f"cron {expression!r}: empty {name} field entry"
            raise ConfigurationError(msg)
        step = 1
        if "/" in part:
            part, _, step_text = part.partition("/")
            try:
                step = int(step_text)
            except ValueError as exc:
                msg = f"cron {expression!r}: {name} step {step_text!r} is not a number"
                raise ConfigurationError(msg) from exc
            if step < 1:
                msg = f"cron {expression!r}: {name} step must be >= 1"
                raise ConfigurationError(msg)
        if part == "*":
            start, end = low, high
        elif "-" in part:
            start_text, _, end_text = part.partition("-")
            try:
                start, end = int(start_text), int(end_text)
            except ValueError as exc:
                msg = f"cron {expression!r}: {name} range {part!r} is not numeric"
                raise ConfigurationError(msg) from exc
        else:
            try:
                start = end = int(part)
            except ValueError as exc:
                msg = f"cron {expression!r}: {name} value {part!r} is not numeric"
                raise ConfigurationError(msg) from exc
        if start < low or end > high or start > end:
            msg = f"cron {expression!r}: {name} value {part!r} is outside {low}-{high}"
            raise ConfigurationError(msg)
        values.update(range(start, end + 1, step))
    if not values:
        msg = f"cron {expression!r}: {name} field matched nothing"
        raise ConfigurationError(msg)
    return frozenset(values)


@dataclass(frozen=True, slots=True)
class CronExpression:
    """A parsed 5-field cron expression."""

    text: str
    minutes: frozenset[int]
    hours: frozenset[int]
    days: frozenset[int]
    months: frozenset[int]
    weekdays: frozenset[int]
    dom_restricted: bool
    dow_restricted: bool

    @classmethod
    def parse(cls, text: str) -> CronExpression:
        fields = text.split()
        if len(fields) != 5:
            msg = f"cron {text!r} must have 5 fields (minute hour day month weekday)"
            raise ConfigurationError(msg)
        minute, hour, day, month, weekday = fields
        weekdays = _parse_field(weekday, low=0, high=7, name="weekday", expression=text)
        # Both 0 and 7 mean Sunday.
        if 7 in weekdays:
            weekdays = frozenset({0} | (weekdays - {7}))
        return cls(
            text=text,
            minutes=_parse_field(
                minute, low=_RANGES[0][0], high=_RANGES[0][1], name="minute", expression=text
            ),
            hours=_parse_field(
                hour, low=_RANGES[1][0], high=_RANGES[1][1], name="hour", expression=text
            ),
            days=_parse_field(
                day, low=_RANGES[2][0], high=_RANGES[2][1], name="day-of-month", expression=text
            ),
            months=_parse_field(
                month, low=_RANGES[3][0], high=_RANGES[3][1], name="month", expression=text
            ),
            weekdays=weekdays,
            dom_restricted=day.strip() != "*",
            dow_restricted=weekday.strip() != "*",
        )

    # ------------------------------------------------------------------ matching
    def matches(self, moment: datetime) -> bool:
        if moment.minute not in self.minutes:
            return False
        if moment.hour not in self.hours:
            return False
        if moment.month not in self.months:
            return False
        return self._day_matches(moment)

    def _day_matches(self, moment: datetime) -> bool:
        dom_ok = moment.day in self.days
        # Python: Monday=0 .. Sunday=6; cron: Sunday=0 .. Saturday=6.
        cron_weekday = (moment.weekday() + 1) % 7
        dow_ok = cron_weekday in self.weekdays
        if self.dom_restricted and self.dow_restricted:
            return dom_ok or dow_ok
        if self.dom_restricted:
            return dom_ok
        if self.dow_restricted:
            return dow_ok
        return True

    def next_after(self, moment: datetime) -> datetime:
        """The first matching minute strictly after ``moment``."""
        candidate = moment.replace(second=0, microsecond=0) + timedelta(minutes=1)
        for _ in range(_MAX_SEARCH_MINUTES):
            if self.matches(candidate):
                return candidate
            candidate += timedelta(minutes=1)
        msg = f"cron {self.text!r} never matches within five years of {moment.isoformat()}"
        raise ConfigurationError(msg)


def parse_cron(text: str) -> CronExpression:
    """Parse a cron expression (a thin, discoverable alias for :meth:`CronExpression.parse`)."""
    return CronExpression.parse(text)
