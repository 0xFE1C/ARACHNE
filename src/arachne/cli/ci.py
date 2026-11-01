"""CI gate exit-code policy (F-07-05).

A pipeline needs one number: did this scan find anything at or above my threshold? The
policy is deliberately tiny and pure so it can be unit-tested and reused by any caller
(a future ``arachne report --fail-on`` or an API response header):

``0``
    clean — no finding at or above the threshold (and, with the gate enabled, no finding at
    all).
``1``
    findings exist, all below the threshold.
``2``
    at least one finding at or above the threshold.

The threshold vocabulary is the severity ladder plus ``none``, which disables the gate
(exit ``0``) and is the CLI default so an interactive scan keeps its historical exit code.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Final

__all__ = ["SEVERITY_LEVELS", "gate_exit_code", "gate_summary", "parse_threshold"]

#: Least → most severe (same order as :data:`arachne.core.config.SEVERITY_LEVELS`).
SEVERITY_LEVELS: Final[tuple[str, ...]] = ("info", "low", "medium", "high", "critical")

#: ``none`` disables the gate; every other value is a severity the ladder knows.
THRESHOLDS: Final[tuple[str, ...]] = ("none", *SEVERITY_LEVELS)

#: Exit codes .
EXIT_CLEAN: Final = 0
EXIT_BELOW_THRESHOLD: Final = 1
EXIT_AT_OR_ABOVE: Final = 2


def parse_threshold(value: str | None) -> str:
    """Normalize a threshold string; empty/``None`` means ``none`` (gate disabled)."""
    normalized = (value or "none").strip().lower()
    if normalized not in THRESHOLDS:
        msg = f"threshold must be one of {', '.join(THRESHOLDS)}, got {value!r}"
        raise ValueError(msg)
    return normalized


def counts_at_or_above(counts: Mapping[str, int], threshold: str) -> int:
    """How many findings sit at or above ``threshold`` (``none`` → 0)."""
    if threshold == "none":
        return 0
    floor = SEVERITY_LEVELS.index(threshold)
    total = 0
    for severity, count in counts.items():
        if severity in SEVERITY_LEVELS and SEVERITY_LEVELS.index(severity) >= floor:
            total += int(count)
    return total


def gate_exit_code(counts: Mapping[str, int], threshold: str) -> int:
    """The process exit code for ``counts`` under ``threshold`` (F-07-05)."""
    if threshold == "none":
        return EXIT_CLEAN
    total = sum(int(value) for key, value in counts.items() if key != "unanalysed")
    if total == 0:
        return EXIT_CLEAN
    if counts_at_or_above(counts, threshold) > 0:
        return EXIT_AT_OR_ABOVE
    return EXIT_BELOW_THRESHOLD


def gate_summary(counts: Mapping[str, int], threshold: str) -> dict[str, object]:
    """The machine-readable gate block for ``--json`` ."""
    return {
        "threshold": threshold,
        "enabled": threshold != "none",
        "counts": {severity: int(counts.get(severity, 0)) for severity in SEVERITY_LEVELS},
        "at_or_above": counts_at_or_above(counts, threshold),
        "exit_code": gate_exit_code(counts, threshold),
    }
