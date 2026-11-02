"""The module registry: discovery, versioning and per-scan selection (F-02-10, F-02-09).

The registry is the executable counterpart of the planning catalogue. It answers three
questions the rest of the scanner asks:

* **What is installed?** :meth:`ModuleRegistry.discover` combines the built-in module groups
  with any installed ``arachne.modules`` entry points (F-09-01: the plugin API is a
  documented contract plus a discovery mechanism, not a fork).
* **What may run for this scan?** :meth:`ModuleRegistry.select` applies
  :class:`~arachne.core.target.ModuleSelection` (F-02-09) and the check's own
  ``enabled_by_default`` / opt-in flags, and returns the checks that will actually execute.
* **What versions did we run?** :meth:`ModuleRegistry.summary` and
  :meth:`ModuleRegistry.check_versions` produce the version metadata a scan report records
  (F-02-10).

Two failures it treats as fatal at load time, because both corrupt a plan silently: a
duplicate check id (two implementations claiming one identity) and a group whose checks do
not all declare that group as their module.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, replace
from importlib.metadata import EntryPoint, entry_points
from typing import Any

from arachne.core.catalog import CheckSpec, PlanningCatalog
from arachne.core.errors import ConfigurationError
from arachne.core.planner import MODULE_STEP, ScanStep
from arachne.core.proof import require_proof_consistency
from arachne.core.target import ModuleSelection
from arachne.modules.base import CheckMetadata, Module
from arachne.modules.framework_map import validate_items

__all__ = [
    "ENTRY_POINT_GROUP",
    "ModuleGroup",
    "ModuleRegistry",
    "require_framework_mapping",
]

#: Entry-point group a third-party plugin registers its module groups under (F-09-01).
ENTRY_POINT_GROUP = "arachne.modules"

_MODULE_ORDER: tuple[str, ...] = ("M1", "M2", "M3", "M4", "M5", "M6")


@dataclass(frozen=True, slots=True)
class ModuleGroup:
    """A module (M1..M6): a titled bundle of checks with its own version .

    ``research_chapter`` is the corpus chapter the module maps 1:1 to, which
    is what makes the coverage matrix a per-chapter question as well as a per-method one.
    """

    id: str
    title: str
    description: str
    version: str
    checks: tuple[type[Module], ...]
    research_chapter: str | None = None
    #: Where the group came from: ``builtin`` or the entry point that supplied it.
    origin: str = "builtin"

    def __post_init__(self) -> None:
        if self.id not in _MODULE_ORDER:
            msg = f"module group id {self.id!r} is not one of {_MODULE_ORDER}"
            raise ConfigurationError(msg)
        for check in self.checks:
            if check.metadata.module != self.id:
                msg = (
                    f"check {check.metadata.id!r} declares module "
                    f"{check.metadata.module!r} but is registered under {self.id!r}"
                )
                raise ConfigurationError(msg)
            # REQ-PROOF-002: the registry re-validates every proof declaration. The metadata
            # constructor already refuses contradictions, so a valid group can only fail here
            # through an instance that bypassed construction (a hand-crafted or mutated
            # metadata object); the belt-and-braces check is what makes a *registration-time*
            # refusal of a broken proof declaration guaranteed, not incidental.
            require_proof_consistency(
                check.metadata.proof,
                enabled_by_default=check.metadata.enabled_by_default,
                requires_state_attestation=check.metadata.requires_state_attestation,
                check_id=check.metadata.id,
            )

    @property
    def step(self) -> ScanStep:
        """The pipeline step this module's checks belong to ."""
        return MODULE_STEP[self.id]

    def metadata(self) -> tuple[CheckMetadata, ...]:
        return tuple(check.metadata for check in self.checks)

    def summary(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "description": self.description,
            "version": self.version,
            "research_chapter": self.research_chapter,
            "origin": self.origin,
            "step": self.step.value,
            "checks": [_as_dict(metadata) for metadata in self.metadata()],
        }


def _as_dict(metadata: CheckMetadata) -> dict[str, Any]:
    return {
        "id": metadata.id,
        "module": metadata.module,
        "name": metadata.name,
        "version": metadata.version,
        "title": metadata.title,
        "description": metadata.description,
        "research_ref": metadata.research_ref,
        "framework": list(metadata.framework),
        "cwe": metadata.cwe,
        "cve": metadata.cve,
        "severity_hint": metadata.severity_hint,
        "type": metadata.type,
        "safe": metadata.safe,
        "verifiable": metadata.verifiable,
        "proof": metadata.proof.value,
        "requires_state_attestation": metadata.requires_state_attestation,
        "enabled_by_default": metadata.enabled_by_default,
        "rate_cost": metadata.rate_cost,
        "estimated_requests": metadata.estimated_requests,
        "requires_active_checks": metadata.requires_active_checks,
        "requires_credentials": list(metadata.requires_credentials),
        "runs_on_discovered": metadata.runs_on_discovered,
        "target_kinds": [kind.value for kind in metadata.target_kinds],
        "key": metadata.key,
    }


class ModuleRegistry:
    """Discovery, lookup and selection over the installed module groups."""

    def __init__(self, groups: Iterable[ModuleGroup] = ()) -> None:
        self._groups: dict[str, ModuleGroup] = {}
        self._by_id: dict[str, type[Module]] = {}
        for group in groups:
            self.add(group)

    # ------------------------------------------------------------------ construction
    def add(self, group: ModuleGroup) -> None:
        """Register a group, refusing duplicate module ids or check ids.

        Both kinds of duplication are checked: an id already registered, and an id repeated
        *within* the group being added — which is what a plugin merging into an existing
        module can produce (``_merge_by_module``), and which would otherwise silently shadow
        one of the two implementations.
        """
        if group.id in self._groups:
            msg = f"module group {group.id!r} is registered twice"
            raise ConfigurationError(msg)
        seen: set[str] = set()
        for check in group.checks:
            check_id = check.metadata.id
            require_framework_mapping(check.metadata)
            if check_id in self._by_id or check_id in seen:
                msg = f"check id {check_id!r} is registered twice"
                raise ConfigurationError(msg)
            seen.add(check_id)
        self._groups[group.id] = group
        for check in group.checks:
            self._by_id[check.metadata.id] = check

    @classmethod
    def builtin(cls) -> ModuleRegistry:
        """The registry of the modules that ship with ARACHNE."""
        return cls(_builtin_groups())

    @classmethod
    def discover(
        cls,
        *,
        include_entry_points: bool = True,
        extra_groups: Sequence[ModuleGroup] = (),
    ) -> ModuleRegistry:
        """Build the registry from the built-in groups plus installed plugins (F-02-10).

        A plugin entry point is an ``arachne.modules`` entry point whose value resolves to a
        :class:`ModuleGroup`, a single :class:`~arachne.modules.base.Module` subclass, or a
        sequence of either. A plugin that fails to load is reported, not fatal: one broken
        third-party package must not make the scanner unusable.
        """
        groups: list[ModuleGroup] = [*_builtin_groups(), *extra_groups]
        if include_entry_points:
            groups.extend(_load_entry_point_groups())
        merged = _merge_by_module(groups)
        # Sort by the module order so listings and reports are stable regardless of the
        # order entry points happen to be reported in.
        merged.sort(key=lambda group: _MODULE_ORDER.index(group.id))
        return cls(merged)

    # ------------------------------------------------------------------ queries
    @property
    def groups(self) -> tuple[ModuleGroup, ...]:
        return tuple(self._groups.values())

    def module_ids(self) -> tuple[str, ...]:
        return tuple(self._groups)

    def group(self, module_id: str) -> ModuleGroup | None:
        return self._groups.get(module_id.upper())

    def checks(self) -> tuple[type[Module], ...]:
        """Every registered check class, in module order."""
        return tuple(check for group in self._groups.values() for check in group.checks)

    def metadata(self) -> tuple[CheckMetadata, ...]:
        return tuple(check.metadata for check in self.checks())

    def check_ids(self) -> tuple[str, ...]:
        return tuple(self._by_id)

    def get(self, check_id: str) -> type[Module] | None:
        return self._by_id.get(check_id)

    def step_has_checks(self, step: ScanStep) -> bool:
        return any(group.step is step and group.checks for group in self._groups.values())

    def check_versions(self) -> dict[str, str]:
        """``{check id: version}`` plus ``{module id: module version}`` (F-02-10)."""
        versions = {metadata.id: metadata.version for metadata in self.metadata()}
        versions.update({group.id: group.version for group in self.groups})
        return versions

    def summary(self) -> list[dict[str, Any]]:
        return [group.summary() for group in self.groups]

    def totals(self) -> dict[str, int]:
        metadata = self.metadata()
        return {
            "modules": len(self._groups),
            "checks": len(metadata),
            "opt_in_checks": sum(1 for item in metadata if item.is_opt_in),
            "active_checks": sum(1 for item in metadata if item.requires_active_checks),
            "proof_l2plus": sum(1 for item in metadata if item.proof.is_opt_in),
            "chapters": len({item.research_ref.split("#", 1)[0] for item in metadata}),
        }

    # ------------------------------------------------------------------ selection
    def select(
        self,
        selection: ModuleSelection,
        *,
        active_checks_allowed: bool = False,
        check_ids: Sequence[str] | None = None,
        enabled_check_ids: Sequence[str] | None = None,
    ) -> tuple[type[Module], ...]:
        """The checks that will run for one scan (F-02-09).

        Three filters, in order:

        1. the scan's module selection (``options.modules``);
        2. the check's own default — an opt-in check (``enabled_by_default=False``) needs an
           explicit ``check_ids`` mention, because "opt-in" is a property of the check, not
           of the module;
        3. the active-checks switch: a check that needs an opt-in per F-01-09 is skipped
           unless the scan opted in *and* the attestation authorized it.
        """
        wanted = set(check_ids) if check_ids is not None else None
        opted_in = set(enabled_check_ids or ())
        selected: list[type[Module]] = []
        for group in self._groups.values():
            if not selection.includes(group.id):
                continue
            for check in group.checks:
                metadata = check.metadata
                if wanted is not None:
                    # An explicit list is an allowlist: it can turn an opt-in check on, and
                    # it excludes everything it does not name.
                    if metadata.id not in wanted:
                        continue
                elif not metadata.enabled_by_default and metadata.id not in opted_in:
                    # An opt-in check is inert until it is named (F-02-09). Naming one
                    # never excludes a default check; it is an addition, not an allowlist.
                    continue
                if metadata.requires_active_checks and not active_checks_allowed:
                    continue
                selected.append(check)
        return tuple(selected)

    # ------------------------------------------------------------------ catalog bridge
    def catalog(self) -> PlanningCatalog:
        """The registry as a planning catalogue (the planner's executable view)."""
        return catalog_from_registry(self)


def catalog_from_registry(registry: ModuleRegistry) -> PlanningCatalog:
    """Convert a registry into the :class:`PlanningCatalog` the planner consumes."""
    specs = [
        CheckSpec(
            module=metadata.module,
            name=metadata.name,
            version=metadata.version,
            title=metadata.title,
            description=metadata.description,
            research_ref=metadata.research_ref,
            cwe=metadata.cwe,
            target_kinds=metadata.target_kinds,
            estimated_requests=metadata.estimated_requests,
            requires_active_checks=metadata.requires_active_checks,
            proof=metadata.proof,
            requires_state_attestation=metadata.requires_state_attestation,
        )
        for metadata in registry.metadata()
    ]
    if not specs:
        msg = "the module registry contains no checks"
        raise ConfigurationError(msg)
    return PlanningCatalog(catalog_version="registry-1.0", checks=tuple(specs))


def _builtin_groups() -> list[ModuleGroup]:
    """The module groups that ship with ARACHNE, in module order.

    Imported lazily (not at module import time) so ``core`` can import the registry without
    pulling in the whole detection layer, which is what keeps ``--dry-run`` able to plan
    without loading a single check.
    """
    from arachne.modules.m1 import M1
    from arachne.modules.m2 import M2
    from arachne.modules.m3 import M3
    from arachne.modules.m4 import M4
    from arachne.modules.m5 import M5
    from arachne.modules.m6 import M6

    return [M1, M2, M3, M4, M5, M6]


def require_framework_mapping(metadata: CheckMetadata) -> None:
    """Refuse a check that declares no framework item, or a malformed one (REQ-DET-002).

    An unmapped check is invisible to every buyer, auditor and coverage report, so the
    registry refuses to register one. The malformed-id half is normally caught earlier, when
    the :class:`~arachne.modules.base.CheckMetadata` is constructed; it is re-checked here so
    a metadata object that bypassed construction (a hand-crafted or mutated one) still cannot
    register a bad id. Both messages name the check and the offending item.
    """
    if not metadata.framework:
        msg = (
            f"check {metadata.id!r} declares no framework mapping: every check must name at "
            "least one WSTG, API Top 10, CWE, ATT&CK, LLM or ASI item (REQ-DET-002)"
        )
        raise ConfigurationError(msg)
    problems = validate_items(metadata.framework)
    if problems:
        msg = f"check {metadata.id!r} has an invalid framework mapping: " + "; ".join(problems)
        raise ConfigurationError(msg)


def _merge_by_module(groups: Sequence[ModuleGroup]) -> list[ModuleGroup]:
    """Fold groups that claim the same module id into one (a plugin *extends* a module).

    Refusing outright would make "add one check to M1" impossible for a plugin, so the
    merge appends the extra checks in the order the groups were supplied (built-ins first)
    and records that the module now has a plugin contributor. Duplicate *check* ids are
    still fatal — :meth:`ModuleRegistry.add` catches that when the merged group is added.
    """
    merged: dict[str, ModuleGroup] = {}
    for group in groups:
        existing = merged.get(group.id)
        if existing is None:
            merged[group.id] = group
            continue
        origin = (
            existing.origin
            if group.origin in existing.origin
            else f"{existing.origin}+{group.origin}"
        )
        merged[group.id] = ModuleGroup(
            id=group.id,
            title=existing.title,
            description=existing.description,
            version=existing.version,
            research_chapter=existing.research_chapter,
            checks=(*existing.checks, *group.checks),
            origin=origin,
        )
    return list(merged.values())


def _load_entry_point_groups() -> list[ModuleGroup]:
    groups: list[ModuleGroup] = []
    for entry_point in _entry_points():
        try:
            loaded = entry_point.load()
            groups.extend(_groups_from_object(loaded, origin=entry_point.name))
        except Exception as exc:  # a broken plugin must not break discovery
            raise ConfigurationError(
                f"module plugin {entry_point.name!r} failed to load: "
                f"{exc.__class__.__name__}: {exc}"
            ) from exc
    return groups


def _entry_points() -> tuple[EntryPoint, ...]:
    """The installed ``arachne.modules`` entry points (empty when none are installed)."""
    return tuple(entry_points(group=ENTRY_POINT_GROUP))


def _groups_from_object(loaded: object, *, origin: str) -> list[ModuleGroup]:
    """Accept a group, a check class, or a sequence of either (plugin ergonomics)."""
    if isinstance(loaded, ModuleGroup):
        # Stamp the group with the entry point that supplied it: which plugin a check came
        # from is the first thing an operator wants to know when one misbehaves.
        return [replace(loaded, origin=origin)]
    if isinstance(loaded, type) and issubclass(loaded, Module):
        return [_group_for(loaded, origin=origin)]
    if isinstance(loaded, (list, tuple)):
        groups: list[ModuleGroup] = []
        for item in loaded:
            groups.extend(_groups_from_object(item, origin=origin))
        return groups
    msg = (
        f"plugin {origin!r} must resolve to a ModuleGroup, a Module subclass, or a sequence "
        f"of those; got {type(loaded).__name__}"
    )
    raise ConfigurationError(msg)


def _group_for(check: type[Module], *, origin: str) -> ModuleGroup:
    """Synthesise a single-check group for a plugin that exports only checks."""
    module_id = check.metadata.module
    return ModuleGroup(
        id=module_id,
        title=f"{module_id} (plugin {origin})",
        description=f"Checks supplied by the {origin!r} plugin.",
        version=check.metadata.version,
        checks=(check,),
        origin=origin,
    )
