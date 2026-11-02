"""Scan-to-scan diff: the data half of F-06-05 .

Full diff *reporting* is S11; this module is the skeleton S8 must land: compare two scans'
finding sets by ``(check_id, asset)`` and classify each as ``new``, ``fixed``, ``regressed``
or ``recurring``, then persist the result in ``scans_diff``. The table has existed since
``0001`` (it is one of the spec's nine), so this stage adds a writer and the comparison, not
a migration.

Two choices keep the comparison honest:

* **Identity is ``(check_id, asset)``**, exactly as the spec says. Title, severity and
  confidence can all change between scans without the finding becoming a different one.
* **The vocabulary is the spec's four words.** A severity *decrease* is still the same
  finding, so it is ``recurring``; the direction is visible in ``severity_trend``. Calling a
  decrease "regressed" would make the word mean "changed", which is not what an operator
  reading the trend needs.

S21 adds a fifth bucket, **suppressed** (REQ-QUAL-002): a finding a suppression rule covers is
excluded from ``new`` and listed in ``suppressed`` with the rule-set version in force. Surfacing
it is the requirement — an operator must be able to see that a rule, not a fix, made a finding
disappear.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

from arachne.analyzer.model import severity_rank
from arachne.quality.suppressions import SuppressionSet
from arachne.report.model import SEVERITY_ORDER, ReportDiff, ReportFinding

__all__ = [
    "FindingIdentity",
    "build_diff",
    "diff_payload",
    "identity_sort_key",
    "suppression_summary",
]


def suppression_summary(diff: ReportDiff) -> str:
    """The one line a diff section prints about suppressed findings (REQ-QUAL-002)."""
    if not diff.suppressed and not diff.suppression_version:
        return "No suppression rules are in force for this scan."
    return (
        f"Suppressed by rule: {len(diff.suppressed)} of this scan's findings "
        f'(suppressions v{diff.suppression_version}) — excluded from "new", never from '
        "the record."
    )


#: The change kinds persisted in ``scans_diff.changes_json`` .
CHANGE_KINDS: Final[tuple[str, ...]] = ("new", "fixed", "regressed", "recurring")


@dataclass(frozen=True, slots=True)
class FindingIdentity:
    """The part of a finding a diff compares: its check, its asset, its severity."""

    check_id: str
    asset: str
    severity: str
    finding_id: str
    title: str = ""
    module: str = ""

    @property
    def key(self) -> str:
        return f"{self.check_id}|{self.asset}"


def identity_sort_key(identity: FindingIdentity) -> tuple[int, str, str]:
    return (-severity_rank(identity.severity), identity.check_id, identity.asset)


def _identities(findings: Iterable[ReportFinding]) -> dict[str, FindingIdentity]:
    out: dict[str, FindingIdentity] = {}
    for finding in findings:
        identity = FindingIdentity(
            check_id=finding.check_id,
            asset=finding.asset.value,
            severity=finding.severity,
            finding_id=finding.id,
            title=finding.title,
            module=finding.module,
        )
        out.setdefault(identity.key, identity)
    return out


def _counts(findings: Iterable[ReportFinding]) -> dict[str, int]:
    counter: Counter[str] = Counter(item.severity for item in findings)
    return {severity: counter.get(severity, 0) for severity in SEVERITY_ORDER}


def build_diff(
    findings_a: Sequence[ReportFinding],
    findings_b: Sequence[ReportFinding],
    *,
    scan_a: str,
    scan_b: str,
    suppressions: SuppressionSet | None = None,
) -> ReportDiff:
    """Compare two scans' confirmed findings .

    ``suppressions`` is the rule set in force (S21): a *new* finding a rule covers is moved out
    of ``new`` into ``suppressed``. Only the new side is filtered — a finding that was already
    known and is now suppressed is still ``recurring``, because the rule did not fix it, and
    hiding the change would be the silent behaviour the requirement forbids.
    """
    old = _identities(findings_a)
    new = _identities(findings_b)
    rules = suppressions or SuppressionSet()

    suppressed: list[str] = []
    added: list[str] = []
    for key in (key for key in new if key not in old):
        identity = new[key]
        rule = rules.match(
            check_id=identity.check_id,
            asset=identity.asset,
            finding_id=_int_or_none(identity.finding_id),
        )
        if rule is not None:
            suppressed.append(key)
        else:
            added.append(key)
    suppressed.sort(key=lambda key: identity_sort_key(new[key]))
    added.sort(key=lambda key: identity_sort_key(new[key]))
    removed = sorted(
        (key for key in old if key not in new), key=lambda key: identity_sort_key(old[key])
    )
    regressed: list[str] = []
    recurring: list[str] = []
    for key in sorted(set(old) & set(new), key=lambda key: identity_sort_key(new[key])):
        before = severity_rank(old[key].severity)
        after = severity_rank(new[key].severity)
        (regressed if after > before else recurring).append(key)

    return ReportDiff(
        scan_a=scan_a,
        scan_b=scan_b,
        new=tuple(added),
        fixed=tuple(removed),
        regressed=tuple(regressed),
        recurring=tuple(recurring),
        suppressed=tuple(suppressed),
        suppression_version=rules.version,
        severity_trend={
            scan_a: _counts(findings_a),
            scan_b: _counts(findings_b),
        },
    )


def _int_or_none(value: str | None) -> int | None:
    """``F-000042`` → ``42`` (a report id back to the finding id a rule matches on)."""
    if not value:
        return None
    digits = value.rsplit("-", 1)[-1]
    return int(digits) if digits.isdigit() else None


def diff_payload(diff: ReportDiff) -> dict[str, Any]:
    """The ``scans_diff.changes_json`` document for a :class:`ReportDiff`."""
    return {
        "scan_a": diff.scan_a,
        "scan_b": diff.scan_b,
        "new": list(diff.new),
        "fixed": list(diff.fixed),
        "regressed": list(diff.regressed),
        "recurring": list(diff.recurring),
        "suppressed": list(diff.suppressed),
        "suppression_version": diff.suppression_version,
        "counts": diff.counts,
        "severity_trend": diff.severity_trend,
    }


def diff_from_payload(payload: Mapping[str, Any]) -> ReportDiff | None:
    """Rebuild a :class:`ReportDiff` from a stored ``changes_json`` document."""
    if not payload:
        return None
    return ReportDiff(
        scan_a=str(payload.get("scan_a") or ""),
        scan_b=str(payload.get("scan_b") or ""),
        new=tuple(str(item) for item in payload.get("new") or ()),
        fixed=tuple(str(item) for item in payload.get("fixed") or ()),
        regressed=tuple(str(item) for item in payload.get("regressed") or ()),
        recurring=tuple(str(item) for item in payload.get("recurring") or ()),
        suppressed=tuple(str(item) for item in payload.get("suppressed") or ()),
        suppression_version=int(payload.get("suppression_version") or 0),
        severity_trend={
            str(scan): {str(key): int(value) for key, value in dict(trend).items()}
            for scan, trend in dict(payload.get("severity_trend") or {}).items()
        },
    )
