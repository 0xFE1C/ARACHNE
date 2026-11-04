"""The compliance-control vocabulary and its pinned inventories (REQ-TRUST-009).

REQ-DET-002 gave every check a validated *detection* mapping (WSTG, API Top 10, CWE, ATT&CK,
LLM, ASI). REQ-TRUST-009 adds a second, different axis: which **compliance controls** does a
check's evidence bear on? This module is that vocabulary, and the pinned inventories it is
validated against.

The four inventories (``arachne/data/compliance/<framework>.json``) are the *complete* control
lists of CIS Controls v8.1 (153 safeguards), ISO/IEC 27001:2022 Annex A (93 controls), NIST
CSF 2.0 (106 subcategories) and PCI DSS v4.0 (12 requirements). They ship in the package, so
the validation is offline and reproducible, and each one records where it came from, when it
was retrieved, what it was cross-checked against and how confident that check is — the ISO
list in particular is secondary-sourced, because the standard is paywalled, and says so.

Two properties this vocabulary exists to make impossible:

* **A dangling control.** A check claiming ``ISO-A.8.5`` when the pinned Annex A has no such
  control is refused at import, naming the id — the same contract ``framework_map`` gives a
  WSTG id. ``CheckMetadata`` validates it, so it fails when the module is loaded rather than
  when a report is rendered.
* **An omitted control.** Because each inventory is complete, the compliance report can say
  what it does *not* assess: every control without a mapped check is reported as
  ``outside_assessed_set`` with a reason drawn from its group, never silently dropped. The
  denominators are the frameworks' own totals, so the gap is named rather than implied.

The target ratios (REQ-TRUST-009) live here as :data:`TARGET_RATIOS`, so the requirement's
numbers are one declaration that a test asserts and a report prints, rather than two copies
that drift.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from functools import lru_cache
from importlib.resources import files
from typing import Any, Final

from arachne.core.errors import ConfigurationError

__all__ = [
    "COMPLIANCE_FRAMEWORKS",
    "FRAMEWORK_FILES",
    "TARGET_RATIOS",
    "ComplianceControl",
    "ComplianceInventory",
    "control_error",
    "control_ids",
    "framework_of_qualified",
    "inventories",
    "inventory",
    "outside_assessed_set",
    "split_qualified",
    "validate_controls",
]

_FRAMEWORKS_PACKAGE: Final = "arachne.data"
_FRAMEWORKS_DIR: Final = "compliance"

#: The frameworks a check may map its evidence onto, and the pinned inventory for each.
FRAMEWORK_FILES: Final[tuple[tuple[str, str], ...]] = (
    ("cis", "cis.json"),
    ("iso27001", "iso27001.json"),
    ("nist-csf", "nist-csf.json"),
    ("pci-dss", "pci-dss.json"),
)

#: The same names, in the same order — the tuple a caller iterates.
COMPLIANCE_FRAMEWORKS: Final[tuple[str, ...]] = tuple(name for name, _ in FRAMEWORK_FILES)

#: There is no entry in :data:`FRAMEWORK_FILES` that does not parse wholly: the whole list is
#: loaded or the process is misconfigured.
_FILES_BY_NAME: Final[dict[str, str]] = dict(FRAMEWORK_FILES)

#: The id prefixes, longest first so ``ISO-`` is never read as something else.
_PREFIXES: Final[tuple[tuple[str, str], ...]] = (
    ("ISO-", "iso27001"),
    ("CIS-", "cis"),
    ("CSF-", "nist-csf"),
    ("PCI-", "pci-dss"),
)

#: ``(mapped_target, framework_total)`` per framework — REQ-TRUST-009's own numbers, so the
#: requirement is asserted against one declaration. ``pci-dss`` is the requirement's "12 of 12";
#: the generator reports the ratio it actually reaches and names any control it cannot assess,
#: and the test asserts the reached target rather than the aspiration.
TARGET_RATIOS: Final[Mapping[str, tuple[int, int]]] = {
    "cis": (60, 153),
    "iso27001": (45, 93),
    "nist-csf": (40, 106),
    "pci-dss": (12, 12),
}


@dataclass(frozen=True, slots=True)
class ComplianceControl:
    """One control of a framework: its id, its title and the group it belongs to."""

    framework: str
    id: str
    title: str
    group: str
    group_title: str = ""
    #: The top-level grouping a framework nests categories under (CSF's Function: GV, ID, PR,
    #: DE, RS, RC). A :attr:`ComplianceInventory.group_key` of ``function`` selects it, which is
    #: how a CSF subcategory gets its Function's "why this is outside the assessed set" reason
    #: rather than falling back to the generic one.
    function: str = ""

    @property
    def qualified_id(self) -> str:
        """The id as a check's metadata writes it (``ISO-A.8.5``, ``CIS-3.3``)."""
        prefix = {"cis": "CIS", "iso27001": "ISO", "nist-csf": "CSF", "pci-dss": "PCI"}[
            self.framework
        ]
        return f"{prefix}-{self.id}"

    def grouping(self, key: str) -> str:
        """The value of one grouping key, whichever shape the framework uses."""
        if key == "id":
            return self.id
        if key == "function":
            return self.function or self.group.split(".", 1)[0]
        return self.group


@dataclass(frozen=True, slots=True)
class ComplianceInventory:
    """A pinned framework inventory: the complete control list and its provenance."""

    framework: str
    name: str
    edition: str
    kind: str
    total: int
    source: str
    retrieved: str
    notes: str
    cross_check: str
    group_reasons: Mapping[str, str]
    default_reason: str
    group_key: str
    controls: tuple[ComplianceControl, ...]

    @property
    def ids(self) -> frozenset[str]:
        return frozenset(control.qualified_id for control in self.controls)

    def control(self, qualified_id: str) -> ComplianceControl | None:
        for candidate in self.controls:
            if candidate.qualified_id == qualified_id:
                return candidate
        return None

    def reason(self, control: ComplianceControl) -> str:
        """Why this control is outside the assessed set, from its group's reason."""
        key = control.grouping(self.group_key)
        return self.group_reasons.get(key, self.default_reason)


@lru_cache(maxsize=len(FRAMEWORK_FILES))
def _load(framework: str) -> ComplianceInventory:
    node = files(_FRAMEWORKS_PACKAGE).joinpath(_FRAMEWORKS_DIR, _FILES_BY_NAME[framework])
    try:
        data: Any = json.loads(node.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:  # pragma: no cover - a packaging defect
        msg = f"could not read the pinned compliance inventory {framework}: {exc}"
        raise ConfigurationError(msg) from exc
    if not isinstance(data, Mapping):  # pragma: no cover - a packaging defect
        msg = f"the pinned compliance inventory {framework} is not a JSON object"
        raise ConfigurationError(msg)
    controls = tuple(
        ComplianceControl(
            framework=framework,
            id=str(raw["id"]),
            title=str(raw.get("title", "")),
            group=str(raw.get("group", "")),
            group_title=str(raw.get("group_title", "")),
            function=str(raw.get("function", "")),
        )
        for raw in data.get("controls") or ()
    )
    total = int(data.get("total") or 0)
    if total != len(controls):  # pragma: no cover - a data defect, and a loud one
        msg = (
            f"the pinned compliance inventory {framework} declares {total} controls but lists "
            f"{len(controls)} — the denominator and the list must agree, or the gap is a guess"
        )
        raise ConfigurationError(msg)
    return ComplianceInventory(
        framework=framework,
        name=str(data.get("name") or framework),
        edition=str(data.get("edition") or ""),
        kind=str(data.get("kind") or "control"),
        total=total,
        source=str(data.get("source") or ""),
        retrieved=str(data.get("retrieved") or ""),
        notes=str(data.get("notes") or ""),
        cross_check=str(data.get("cross_check") or ""),
        group_reasons={str(k): str(v) for k, v in (data.get("group_reasons") or {}).items()},
        default_reason=str(data.get("default_reason") or "no shipped check assesses this control"),
        group_key=str(data.get("group_key") or "group"),
        controls=controls,
    )


def inventories() -> tuple[ComplianceInventory, ...]:
    """Every pinned inventory, in :data:`COMPLIANCE_FRAMEWORKS` order."""
    return tuple(_load(name) for name in COMPLIANCE_FRAMEWORKS)


def inventory(framework: str) -> ComplianceInventory:
    """The pinned inventory for a canonical framework name."""
    if framework not in _FILES_BY_NAME:
        msg = (
            f"no pinned compliance inventory named {framework!r}; this build ships "
            f"{', '.join(COMPLIANCE_FRAMEWORKS)}"
        )
        raise ConfigurationError(msg)
    return _load(framework)


def _framework_of(item: str) -> str | None:
    for prefix, name in _PREFIXES:
        if item.startswith(prefix):
            return name
    return None


def framework_of_qualified(item: str) -> str | None:
    """The framework a ``CIS-3.3`` / ``ISO-A.8.5``-style id belongs to, or ``None``.

    Public because the generator and a check author both need it: the generator inverts the
    metadata into per-framework maps, and an author reading a refusal wants to know which
    inventory the id was checked against.
    """
    return _framework_of(item)


def split_qualified(item: str) -> tuple[str, str] | None:
    """``ISO-A.8.5`` → ``("iso27001", "A.8.5")``; ``None`` when the id is not qualified."""
    framework = _framework_of(item)
    if framework is None:
        return None
    return framework, item.split("-", 1)[1]


def control_error(item: str) -> str | None:
    """Why ``item`` is not a valid compliance control id, or ``None`` when it is.

    Every message names the offending id, because the refusal is read by a check author who has
    to find the typo — and an id that looks plausible but is not in the pinned inventory is the
    failure mode this function exists for.
    """
    framework = _framework_of(item)
    if framework is None:
        return (
            f"{item!r} is not a compliance control id: the id must start with one of "
            f"{', '.join(prefix for prefix, _ in _PREFIXES)}"
        )
    spec = inventory(framework)
    if spec.control(item) is None:
        return (
            f"{item!r} is not a {spec.name} {spec.edition} control (the pinned inventory has "
            f"{spec.total} {spec.kind}s and no such id)"
        )
    return None


def validate_controls(items: Iterable[str]) -> tuple[str, ...]:
    """Every problem in a compliance mapping, each naming its id (empty when valid)."""
    problems: list[str] = []
    for item in items:
        problem = control_error(item)
        if problem is not None:
            problems.append(problem)
    return tuple(problems)


def control_ids(framework: str) -> frozenset[str]:
    """Every valid id of one framework, for a caller that needs the whole vocabulary."""
    return inventory(framework).ids


def outside_assessed_set(
    inventory: ComplianceInventory, mapped: Iterable[str]
) -> tuple[tuple[ComplianceControl, str], ...]:
    """``(control, reason)`` for every control of ``inventory`` no check maps onto.

    The complement is computed rather than listed, so "an unmapped control is reported, never
    omitted" holds by construction: the only way to be absent is to be mapped.
    """
    mapped_ids = set(mapped)
    return tuple(
        (control, inventory.reason(control))
        for control in inventory.controls
        if control.qualified_id not in mapped_ids
    )
