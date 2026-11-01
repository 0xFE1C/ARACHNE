"""Detection-window enforcement (S24, REQ-VALID-001/003).

The window is the *authorization boundary* of a purple-team test: an action outside it is
refused, and the refusal is audited. This module is the single place that decides what
"inside the window" means, so the gate (plan/execute), the auto-stop (the checks step) and
the coverage scorer cannot disagree about it.

Pure by construction: no clock is read here, ``now`` is always a parameter — which is what
lets ``tests/test_purple_safety.py`` drive the whole boundary with an injected moment
instead of sleeping.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from arachne.core.errors import DetectionWindowError
from arachne.core.target import DetectionWindow

__all__ = ["WindowState", "describe_window", "window_payload", "window_state"]

#: The window's own state at a moment. The vocabulary is deliberately three-valued: a test
#: that cannot be distinguished from "not yet" and "too late" produces a useless report.


class WindowState(StrEnum):
    """Where ``now`` sits relative to a detection window."""

    #: The window has not opened: a purple action is refused (audited).
    PENDING = "pending"
    #: Inside the window: actions may run.
    OPEN = "open"
    #: The window has ended: no further action runs (the auto-stop).
    CLOSED = "closed"


def window_state(window: DetectionWindow | None, now: datetime) -> WindowState:
    """Classify ``now`` against ``window``.

    ``None`` is :attr:`WindowState.CLOSED`, not "open": the absence of a coordinated window
    is the strongest possible refusal, never an implicit grant.
    """
    if window is None:
        return WindowState.CLOSED
    moment = now.astimezone(UTC)
    if moment < window.starts_at:
        return WindowState.PENDING
    if moment > window.ends_at:
        return WindowState.CLOSED
    return WindowState.OPEN


def describe_window(window: DetectionWindow | None, now: datetime | None = None) -> str:
    """A one-line, operator-readable form of the window and its state."""
    if window is None:
        return "no detection window"
    span = f"{window.starts_at.isoformat()}..{window.ends_at.isoformat()}"
    if now is None:
        return f"{span} (coordinated with {window.coordinator})"
    return f"{span} [{window_state(window, now).value}] (coordinated with {window.coordinator})"


def window_payload(window: DetectionWindow | None, now: datetime | None = None) -> dict[str, Any]:
    """The JSON-safe block reports, stats and audit metadata carry."""
    if window is None:
        return {"present": False}
    payload: dict[str, Any] = {"present": True, **window.to_dict()}
    if now is not None:
        payload["state_at"] = window_state(window, now).value
    return payload


def assert_window_open(
    window: DetectionWindow | None,
    now: datetime,
    *,
    what: str = "purple-team action",
) -> None:
    """Refuse ``what`` unless the window is open at ``now``.

    The refusal message names the state *and* the window, because "the window is closed"
    with no timestamps is the kind of message an operator has to reverse-engineer at 3am.
    """
    state = window_state(window, now)
    if state is WindowState.OPEN:
        return
    moment = now.astimezone(UTC).isoformat()
    if window is None:
        msg = (
            f"refusing {what}: no detection window is attached to this scan, and a "
            "purple-team test without a coordinated window is not authorized"
        )
    elif state is WindowState.PENDING:
        msg = (
            f"refusing {what} at {moment}: the coordinated detection window has not opened "
            f"yet (opens {window.starts_at.isoformat()})"
        )
    else:
        msg = (
            f"refusing {what} at {moment}: the coordinated detection window closed at "
            f"{window.ends_at.isoformat()} — a purple-team test stops when the defender "
            "stops watching"
        )
    raise DetectionWindowError(msg, reason=msg)
