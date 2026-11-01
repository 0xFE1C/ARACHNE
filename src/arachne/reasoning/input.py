"""The encoders that build :class:`~arachne.reasoning.model.HypothesisInput`'s lines.

A hypothesis engine is a pure function of its input, so the *only* place that can introduce
nondeterminism or hidden state is the code that assembles the input. That code lives here, in
one place, with one shape per line, so the step that builds a real input and the replay that
rebuilds it from a journal cannot disagree about what a line means.

Three line kinds, all plain ids (no free text, so a target-planted string can never reach the
engine's structural fields — hostile content belongs in ``observations``, which is untrusted
by construction, see REQ-AGENT-006):

============================  ==================================================
``finding``                   ``check_id|asset|severity|confidence|verdict|verified``
``group``                     ``rule_id|group_key|check_id,check_id|severity``
``unexplored``                ``rule_id|check_id|asset``
============================  ==================================================
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

__all__ = [
    "FindingLine",
    "GroupLine",
    "UnexploredLine",
    "encode_finding",
    "encode_group",
    "encode_unexplored",
    "parse_finding",
    "parse_group",
    "parse_unexplored",
]

_SEP: Final = "|"
_LIST: Final = ","


@dataclass(frozen=True, slots=True)
class FindingLine:
    """One analysed finding, reduced to what reasoning may depend on."""

    check_id: str
    asset: str
    severity: str
    confidence: int
    verdict: str
    verified: bool

    def encode(self) -> str:
        return _SEP.join(
            [
                self.check_id,
                self.asset,
                self.severity,
                str(self.confidence),
                self.verdict,
                "1" if self.verified else "0",
            ]
        )


@dataclass(frozen=True, slots=True)
class GroupLine:
    """One correlation group and the checks that would confirm its next hop."""

    rule_id: str
    group_key: str
    check_ids: tuple[str, ...] = ()
    severity: str = "info"

    def encode(self) -> str:
        return _SEP.join(
            [self.rule_id, self.group_key, _LIST.join(self.check_ids), self.severity]
        )


@dataclass(frozen=True, slots=True)
class UnexploredLine:
    """A rule whose signals are present but whose check did not run for the asset."""

    rule_id: str
    check_id: str
    asset: str

    def encode(self) -> str:
        return _SEP.join([self.rule_id, self.check_id, self.asset])


def encode_finding(line: FindingLine) -> str:
    return line.encode()


def encode_group(line: GroupLine) -> str:
    return line.encode()


def encode_unexplored(line: UnexploredLine) -> str:
    return line.encode()


def _parts(text: str, expected: int) -> list[str] | None:
    parts = text.split(_SEP)
    if len(parts) != expected:
        return None
    return parts


def parse_finding(text: str) -> FindingLine | None:
    """Decode a finding line; ``None`` for a malformed one (never raises on data)."""
    parts = _parts(text, 6)
    if parts is None:
        return None
    check_id, asset, severity, confidence, verdict, verified = parts
    if not check_id or not asset:
        return None
    try:
        level = int(confidence)
    except ValueError:
        return None
    if not 0 <= level <= 100:
        return None
    return FindingLine(
        check_id=check_id,
        asset=asset,
        severity=severity or "info",
        confidence=level,
        verdict=verdict or "analyzed",
        verified=verified == "1",
    )


def parse_group(text: str) -> GroupLine | None:
    parts = _parts(text, 4)
    if parts is None:
        return None
    rule_id, group_key, checks, severity = parts
    if not rule_id:
        return None
    return GroupLine(
        rule_id=rule_id,
        group_key=group_key,
        check_ids=tuple(item for item in checks.split(_LIST) if item),
        severity=severity or "info",
    )


def parse_unexplored(text: str) -> UnexploredLine | None:
    parts = _parts(text, 3)
    if parts is None:
        return None
    rule_id, check_id, asset = parts
    if not rule_id or not check_id:
        return None
    return UnexploredLine(rule_id=rule_id, check_id=check_id, asset=asset)
