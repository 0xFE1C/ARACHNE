"""The framework vocabulary and its pinned versions (REQ-DET-002).

Every check declares at least one framework item, and an item is only valid if it belongs to
a **pinned** framework snapshot vendored next to this module
(``arachne/data/frameworks/*.json``). The snapshot ships in the package rather than being
fetched, so mapping validation is offline and reproducible and a scan never acquires a
network dependency for a metadata question (risk ``A-02``).

The controlled vocabulary (``.spec/03-requirements.md`` §4.1):

===============  ==========================================  ==================================
prefix           id form                                     pinned artefact
===============  ==========================================  ==================================
``WSTG-``        ``WSTG-<CAT>-<NN>``                         ``wstg-4.2.json`` (the 97 ids)
``API``          ``API<N>:2023``                             ``api-top10-2023.json``
``CWE-``         ``CWE-<N>``                                 ``cwe-2025.json`` (1..1500)
``ATT&CK-T``     ``ATT&CK-T<NNNN>[.<NNN>]``                  ``attack-enterprise-v20.json``
``LLM``          ``LLM<N>:2025``                             ``llm-top10-2025.json``
``ASI``          ``ASI<N>:2026``                             ``asi-top10-2026.json``
===============  ==========================================  ==================================

Two validation strengths are used, and the difference matters:

* **item lists** (WSTG, API Top 10, LLM, ASI) — the id must be one of the pinned items. A
  WSTG id whose category is real but whose number does not exist (``WSTG-ATHN-11``) is
  refused, so the ledger can never claim a test that is not in the guide.
* **ranges** (CWE, ATT&CK) — the numbering is open-ended, so the pinned artefact is a version
  plus an inclusive numeric bound. ``CWE-99999`` is refused as out of range; ``ATT&CK-T123``
  as malformed.

This module also computes the WSTG coverage states (``mapped`` / ``out_of_scope`` / ``gap``,
REQ-DET-003) from the authored scope of each item plus the ids the registry actually names.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from functools import lru_cache
from importlib.resources import files
from typing import Any, Final

from arachne.core.errors import ConfigurationError

__all__ = [
    "CWE_TOP25_FILE",
    "FRAMEWORK_FILES",
    "FRAMEWORK_ORDER",
    "CweTop25State",
    "Framework",
    "FrameworkItem",
    "WstgState",
    "api_top10_coverage",
    "asi_top10_coverage",
    "cwe_top25_coverage",
    "cwe_top25_framework",
    "framework",
    "framework_for_item",
    "framework_versions",
    "frameworks",
    "item_error",
    "sorted_items",
    "validate_items",
    "wstg_coverage",
]

#: The vendored pinned snapshots: ``(short name, file)``, one file per framework
#: (`REQ-DET-002`). The short name is what ids use and what the ledger's version map keys on.
FRAMEWORK_FILES: tuple[tuple[str, str], ...] = (
    ("WSTG", "wstg-4.2.json"),
    ("API", "api-top10-2023.json"),
    ("CWE", "cwe-2025.json"),
    ("ATT&CK", "attack-enterprise-v20.json"),
    ("LLM", "llm-top10-2025.json"),
    ("ASI", "asi-top10-2026.json"),
)

#: The order items are listed in, everywhere (stable output regardless of declaration order).
FRAMEWORK_ORDER: tuple[str, ...] = ("WSTG", "API", "CWE", "ATT&CK", "LLM", "ASI")

#: The CWE Top 25 (2025) denominator (REQ-DET-004). It is not a mapping vocabulary — a check
#: never names a "CWE Top 25" item — so it is deliberately *not* in :data:`FRAMEWORK_FILES`;
#: it is the list the ledger tallies the emitted CWEs against.
CWE_TOP25_FILE: Final = "cwe-top25-2025.json"

_FRAMEWORKS_PACKAGE = "arachne.data"
_FRAMEWORKS_DIR = "frameworks"

#: Which framework an item id belongs to, by its prefix. Ordered: the first match wins, and
#: ``ATT&CK-T`` is tested before any bare-``T`` form could be.
_PREFIXES: tuple[tuple[str, str], ...] = (
    ("WSTG-", "WSTG"),
    ("API", "API"),
    ("CWE-", "CWE"),
    ("ATT&CK-T", "ATT&CK"),
    ("LLM", "LLM"),
    ("ASI", "ASI"),
)

WSTG_STATES: tuple[str, ...] = ("mapped", "out_of_scope", "gap")


@dataclass(frozen=True, slots=True)
class FrameworkItem:
    """One pinned framework item (a WSTG test, an API Top 10 entry, ...)."""

    id: str
    title: str = ""
    category: str | None = None
    number: int | None = None
    #: ``in_scope`` or ``out_of_scope`` — the counting rule of technique-landscape §2.
    scope: str = "in_scope"
    #: Why an item is out of scope; required when ``scope == "out_of_scope"``.
    reason: str | None = None

    @property
    def in_scope(self) -> bool:
        return self.scope == "in_scope"


@dataclass(frozen=True, slots=True)
class Framework:
    """A pinned framework snapshot: its version, its item list, and its validity rules."""

    name: str
    version: str
    title: str
    source: str
    id_pattern: str
    items: tuple[FrameworkItem, ...]
    minimum: int | None = None
    maximum: int | None = None
    notes: str = ""

    @property
    def label(self) -> str:
        return f"{self.name} {self.version}"

    @property
    def ids(self) -> frozenset[str]:
        return frozenset(item.id for item in self.items)

    def item(self, item_id: str) -> FrameworkItem | None:
        for candidate in self.items:
            if candidate.id == item_id:
                return candidate
        return None


@dataclass(frozen=True, slots=True)
class WstgState:
    """One WSTG test id and its single coverage state (REQ-DET-003)."""

    item: FrameworkItem
    state: str
    checks: tuple[str, ...] = ()

    @property
    def id(self) -> str:
        return self.item.id


@lru_cache(maxsize=1)
def frameworks() -> tuple[Framework, ...]:
    """The pinned snapshots, in :data:`FRAMEWORK_ORDER`."""
    loaded = {name: _load(name, filename) for name, filename in FRAMEWORK_FILES}
    missing = [name for name in FRAMEWORK_ORDER if name not in loaded]
    if missing:  # pragma: no cover - a packaging defect, not a data-entry one
        msg = f"the pinned framework data is missing {missing}"
        raise ConfigurationError(msg)
    return tuple(loaded[name] for name in FRAMEWORK_ORDER)


@lru_cache(maxsize=len(FRAMEWORK_FILES))
def _load(name: str, filename: str) -> Framework:
    node = files(_FRAMEWORKS_PACKAGE).joinpath(_FRAMEWORKS_DIR, filename)
    try:
        data: Any = json.loads(node.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:  # pragma: no cover - a packaging defect
        msg = f"could not read the pinned framework file {filename}: {exc}"
        raise ConfigurationError(msg) from exc
    if not isinstance(data, Mapping):
        msg = f"the pinned framework file {filename} is not a JSON object"
        raise ConfigurationError(msg)
    items: list[FrameworkItem] = []
    for raw in data.get("items") or ():
        item = FrameworkItem(
            id=str(raw["id"]),
            title=str(raw.get("title", "")),
            category=raw.get("category"),
            number=raw.get("number"),
            scope=str(raw.get("scope", "in_scope")),
            reason=raw.get("reason"),
        )
        if not item.in_scope and not item.reason:
            msg = f"framework item {item.id!r} is out of scope with no reason"
            raise ConfigurationError(msg)
        items.append(item)
    bounds = data.get("range") or {}
    return Framework(
        name=name,
        version=str(data["version"]),
        title=str(data.get("title", name)),
        source=str(data.get("source", "")),
        id_pattern=str(data["id_pattern"]),
        items=tuple(items),
        minimum=bounds.get("min"),
        maximum=bounds.get("max"),
        notes=str(data.get("notes", "")),
    )


def framework(name: str) -> Framework:
    """The pinned snapshot for a framework short name (``WSTG``, ``API``, ...)."""
    for spec in frameworks():
        if spec.name == name:
            return spec
    msg = f"no pinned framework named {name!r}"
    raise ConfigurationError(msg)


def framework_versions() -> dict[str, str]:
    """``{framework: pinned version}`` — what the ledger states about itself."""
    return {spec.name: spec.version for spec in frameworks()}


def framework_for_item(item_id: str) -> Framework | None:
    """The framework an item id belongs to, from its prefix (``None`` when unknown)."""
    for prefix, name in _PREFIXES:
        if item_id.startswith(prefix):
            return framework(name)
    return None


def item_error(item_id: str) -> str | None:
    """Why ``item_id`` is not a valid framework item, or ``None`` when it is.

    Every message names the offending id, because the refusal is read by a check author who
    has to find the typo.
    """
    spec = framework_for_item(item_id)
    if spec is None:
        return (
            f"{item_id!r} is not a framework item: the id must start with one of "
            f"{', '.join(prefix for prefix, _ in _PREFIXES)}"
        )
    if not re.match(spec.id_pattern, item_id):
        return (
            f"{item_id!r} is malformed for {spec.label} "
            f"(expected {spec.label} form {spec.id_pattern})"
        )
    if spec.ids and item_id not in spec.ids:
        return f"{item_id!r} is not a {spec.label} item (the pinned snapshot has no such id)"
    if spec.minimum is not None and spec.maximum is not None:
        number = _number_of(item_id)
        if number is None:
            return f"{item_id!r} carries no numeric part for {spec.label}"
        if not spec.minimum <= number <= spec.maximum:
            return f"{item_id!r} is out of range for {spec.label} ({spec.minimum}..{spec.maximum})"
    return None


def validate_items(items: Iterable[str]) -> tuple[str, ...]:
    """Every problem in a framework mapping, each naming its id (empty when valid)."""
    problems: list[str] = []
    for item_id in items:
        problem = item_error(item_id)
        if problem is not None:
            problems.append(problem)
    return tuple(problems)


def _number_of(item_id: str) -> int | None:
    match = re.search(r"(?:T|CWE-)(\d+)", item_id)
    if match is None:
        return None
    return int(match.group(1))


def sorted_items(items: Iterable[str]) -> tuple[str, ...]:
    """A framework mapping in canonical order: framework, then numeric, then text.

    The order is a pure function of the id set, so the ledger's bytes do not depend on the
    order a check happened to list its items in.
    """
    order = {name: index for index, name in enumerate(FRAMEWORK_ORDER)}

    def key(item_id: str) -> tuple[int, int, str]:
        spec = framework_for_item(item_id)
        name = spec.name if spec is not None else ""
        number = _number_of(item_id)
        return (order.get(name, len(order)), number if number is not None else 0, item_id)

    return tuple(sorted(set(items), key=key))


def wstg_coverage(mapped: Mapping[str, Sequence[str]]) -> tuple[WstgState, ...]:
    """The 97 WSTG ids, each in exactly one state (REQ-DET-003).

    ``mapped`` is ``{WSTG id: check ids}`` taken from the registry. An item the registry
    names is ``mapped`` regardless of its authored scope — but an item authored
    ``out_of_scope`` *and* named by a check is a contradiction and raises, because either the
    scope or the mapping is wrong and the ledger must not paper over it.
    """
    spec = framework("WSTG")
    states: list[WstgState] = []
    for item in spec.items:
        checks = tuple(sorted(mapped.get(item.id, ())))
        if checks and not item.in_scope:
            msg = (
                f"WSTG item {item.id!r} is authored out_of_scope but is mapped by "
                f"{', '.join(checks)}; one of the two is wrong"
            )
            raise ConfigurationError(msg)
        if checks:
            state = "mapped"
        elif item.in_scope:
            state = "gap"
        else:
            state = "out_of_scope"
        states.append(WstgState(item=item, state=state, checks=checks))
    return tuple(states)


def api_top10_coverage(mapped: Mapping[str, Sequence[str]]) -> tuple[WstgState, ...]:
    """The ten API Top 10 ids with their mapped checks (REQ-DET-005)."""
    return _item_coverage("API", mapped)


def asi_top10_coverage(mapped: Mapping[str, Sequence[str]]) -> tuple[WstgState, ...]:
    """The ten Agentic Top 10 ids with their mapped checks (REQ-DET-013).

    Every ASI item is authored ``in_scope``, so the state is ``mapped`` when a registered check
    names it and ``gap`` when none does. That is how the ledger reports ``asi.mapped / 10`` with
    the unmapped items named individually rather than only as a shortfall.
    """
    return _item_coverage("ASI", mapped)


def _item_coverage(
    framework_name: str, mapped: Mapping[str, Sequence[str]]
) -> tuple[WstgState, ...]:
    """``(mapped | gap)`` per pinned item of a framework whose whole list is in scope."""
    spec = framework(framework_name)
    return tuple(
        WstgState(
            item=item,
            state="mapped" if mapped.get(item.id) else "gap",
            checks=tuple(sorted(mapped.get(item.id, ()))),
        )
        for item in spec.items
    )


@dataclass(frozen=True, slots=True)
class CweTop25State:
    """One CWE Top 25 (2025) id and the checks that *emit* it (REQ-DET-004)."""

    item: FrameworkItem
    checks: tuple[str, ...] = ()

    @property
    def id(self) -> str:
        return self.item.id

    @property
    def in_scope(self) -> bool:
        return self.item.in_scope

    @property
    def covered(self) -> bool:
        return bool(self.checks)


@lru_cache(maxsize=1)
def cwe_top25_framework() -> Framework:
    """The pinned CWE Top 25 (2025) denominator (``cwe-top25-2025.json``)."""
    return _load("CWE Top 25", CWE_TOP25_FILE)


def cwe_top25_coverage(mapped: Mapping[str, Sequence[str]]) -> tuple[CweTop25State, ...]:
    """The 25 ids with the checks whose findings are classified as each (REQ-DET-004).

    ``mapped`` is ``{CWE id: check ids}`` taken from the registry's **primary** ``cwe`` field,
    so "covered" means at least one registered check emits that weakness, not merely that it
    names the id in a framework tuple. The seven memory-safety classes are in the denominator
    and authored ``out_of_scope`` with a reason, so 18/18 is visible against 25, not hidden
    by a shrunken list.
    """
    return tuple(
        CweTop25State(item=item, checks=tuple(sorted(mapped.get(item.id, ()))))
        for item in cwe_top25_framework().items
    )
