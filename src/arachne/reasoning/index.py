"""A read-only index of the checks a hypothesis may name (S21, area AGENT).

A hypothesis engine is handed this and nothing else about the executable surface. It answers
three questions — *does this check id exist*, *what does it cost*, *how far may it go* — and it
is deliberately unable to answer "how do I run it". That split is the first half of
REQ-AGENT-005: a proposed check that is not in the index cannot be executed, because the only
thing that turns a check id into work is the registry, and the registry is reached through
:class:`~arachne.reasoning.executor.HypothesisExecutor`'s gate, never by the engine.

``only_these`` is the executor's allowlist mechanism: the index reports membership, and the
planner/registry enforce it. Nothing here writes anything.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Final

from arachne.core.catalog import CheckSpec, PlanningCatalog

__all__ = ["CheckEntry", "CheckIndex"]

#: Proof levels above L1 need explicit operator approval before the agent may run them
#: (REQ-AGENT-005; the planner's proof gate is the enforcement, this is the classification).
_NEEDS_APPROVAL: Final[frozenset[str]] = frozenset({"L2", "L3", "L4"})


@dataclass(frozen=True, slots=True)
class CheckEntry:
    """One catalogued check, as the reasoning layer needs it."""

    id: str
    key: str
    module: str
    name: str
    version: str
    title: str
    cwe: str | None
    proof: str
    requires_active_checks: bool
    requires_state_attestation: bool
    estimated_requests: int
    target_kinds: tuple[str, ...]

    @property
    def needs_approval(self) -> bool:
        """True for L2+ rows: out-of-band, one-shot command or reversible state change."""
        return self.proof in _NEEDS_APPROVAL

    @property
    def is_state_change(self) -> bool:
        """True for L3/L4 rows: the levels that require a state-change attestation."""
        return self.requires_state_attestation


@dataclass(frozen=True, slots=True)
class CheckIndex:
    """``check id → :class:`CheckEntry```, plus the module view the rule corpus needs."""

    entries: dict[str, CheckEntry] = field(default_factory=dict)

    @classmethod
    def from_catalog(cls, catalog: PlanningCatalog) -> CheckIndex:
        return cls(entries={spec.id: _entry(spec) for spec in catalog.checks})

    @classmethod
    def from_specs(cls, specs: Any) -> CheckIndex:
        """Build from :class:`CheckSpec`-shaped objects (the loader and tests use this)."""
        return cls(entries={spec.id: _entry(spec) for spec in specs})

    def get(self, check_id: str) -> CheckEntry | None:
        return self.entries.get(check_id)

    def __contains__(self, check_id: object) -> bool:
        return check_id in self.entries

    def __len__(self) -> int:
        return len(self.entries)

    def ids(self) -> tuple[str, ...]:
        return tuple(self.entries)

    def of_module(self, module: str) -> tuple[CheckEntry, ...]:
        wanted = module.upper()
        return tuple(entry for entry in self.entries.values() if entry.module == wanted)

    def all(self) -> tuple[CheckEntry, ...]:
        return tuple(self.entries.values())


def _entry(spec: CheckSpec) -> CheckEntry:
    return CheckEntry(
        id=spec.id,
        key=spec.key,
        module=spec.module,
        name=spec.name,
        version=spec.version,
        title=spec.title,
        cwe=spec.cwe,
        proof=spec.proof.value,
        requires_active_checks=spec.requires_active_checks,
        requires_state_attestation=spec.requires_state_attestation,
        estimated_requests=spec.estimated_requests,
        target_kinds=tuple(kind.value for kind in spec.target_kinds),
    )
