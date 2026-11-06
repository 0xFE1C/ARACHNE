"""The planning catalogue: which checks exist, for which targets, at what request cost.

The catalogue is a **data file** (``templates/plan/check_catalog.yaml``, ADR-04), read by
the dry-run planner (F-01-10) so a plan can be printed without loading any detection code.
S3's module registry (F-02-10) becomes the executable counterpart; because the planner
takes the catalogue as a parameter, swapping one for the other is a call-site change.

Loading is strict: unknown fields, a duplicate ``(module, name)`` or an unknown
``target_kind`` fail loudly rather than producing a plan that silently omits checks.
"""

from __future__ import annotations

import functools
import re
from importlib.resources import files
from pathlib import Path
from typing import Any, Final

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from arachne.core.errors import ConfigurationError
from arachne.core.proof import ProofLevel
from arachne.core.target import ModuleSelection, TargetKind

__all__ = [
    "DEFAULT_CATALOG_RESOURCE",
    "CheckSpec",
    "PlanningCatalog",
    "default_catalog_text",
    "load_catalog",
    "load_catalog_from_text",
    "parse_catalog",
]

_MODEL_CONFIG = ConfigDict(frozen=True, extra="forbid")

#: Location of the bundled catalogue, relative to the ``arachne.templates`` package.
DEFAULT_CATALOG_RESOURCE: Final = ("plan", "check_catalog.yaml")

_MODULE_ID = re.compile(r"^M[1-6]$")


class CheckSpec(BaseModel):
    """One planned check: metadata, applicability and estimated request cost."""

    model_config = _MODEL_CONFIG

    module: str
    name: str = Field(min_length=1, max_length=128)
    version: str = Field(min_length=1, max_length=32)
    title: str = Field(min_length=1, max_length=512)
    description: str = Field(min_length=1, max_length=2000)
    research_ref: str = Field(min_length=1, max_length=64)
    cwe: str | None = Field(default=None, max_length=32)
    target_kinds: tuple[TargetKind, ...] = Field(min_length=1)
    estimated_requests: int = Field(ge=0)
    #: True when the check does anything beyond a plain GET (F-01-09).
    requires_active_checks: bool = False
    #: The check's proof-ladder declaration (REQ-PROOF-001). The planner prints it and the
    #: orchestrator's proof gate consumes it; the registry drift test keeps it identical to
    #: the metadata the executing build has.
    proof: ProofLevel = ProofLevel.L1
    #: True only for L3/L4 rows (state-change attestation required).
    requires_state_attestation: bool = False

    @field_validator("module")
    @classmethod
    def _validate_module(cls, value: str) -> str:
        if not _MODULE_ID.match(value):
            msg = f"{value!r} is not a module id (expected M1..M6)"
            raise ValueError(msg)
        return value

    @property
    def key(self) -> str:
        """``module/name@version`` — the stable identity used in plans and reports."""
        return f"{self.module}/{self.name}@{self.version}"

    @property
    def id(self) -> str:
        """``module.name`` — the check id the registry and the report key on (S21).

        The same vocabulary as ``CheckMetadata.id``: a hypothesis names checks by this id, so
        the catalogue and the registry must not disagree about it (which is exactly what the
        catalogue/registry drift gate in ``tests/unit/test_registry.py`` checks).
        """
        return f"{self.module.lower()}.{self.name}"

    def supports(self, kinds: frozenset[TargetKind]) -> bool:
        """True when the check applies to at least one of ``kinds``."""
        return any(kind in kinds for kind in self.target_kinds)


class PlanningCatalog(BaseModel):
    """The whole catalogue, validated as a unit."""

    model_config = _MODEL_CONFIG

    catalog_version: str = Field(min_length=1, max_length=32)
    checks: tuple[CheckSpec, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def _validate_unique(self) -> PlanningCatalog:
        seen: set[tuple[str, str, str]] = set()
        for check in self.checks:
            identity = (check.module, check.name, check.version)
            if identity in seen:
                msg = f"duplicate check in catalogue: {check.module}/{check.name}@{check.version}"
                raise ValueError(msg)
            seen.add(identity)
        return self

    # ------------------------------------------------------------------ queries
    def modules(self) -> tuple[str, ...]:
        """Module ids present in the catalogue, in catalogue order."""
        return tuple(dict.fromkeys(check.module for check in self.checks))

    def for_module(self, module: str) -> tuple[CheckSpec, ...]:
        return tuple(check for check in self.checks if check.module == module)

    def select(self, modules: ModuleSelection) -> tuple[CheckSpec, ...]:
        """Checks whose module the selection includes (F-02-09)."""
        return tuple(check for check in self.checks if modules.includes(check.module))


def parse_catalog(data: Any, *, source: str = "<memory>") -> PlanningCatalog:
    """Validate an already-parsed catalogue document."""
    if not isinstance(data, dict):
        msg = f"{source}: expected a mapping at the top level, got {type(data).__name__}"
        raise ConfigurationError(msg)
    try:
        return PlanningCatalog.model_validate(data)
    except ValidationError as exc:
        parts: list[str] = []
        for error in exc.errors():
            location = ".".join(str(item) for item in error["loc"]) or "<root>"
            parts.append(f"{location}: {error['msg']}")
        raise ConfigurationError(f"{source}: invalid check catalogue: {'; '.join(parts)}") from exc


def load_catalog_from_text(text: str, *, source: str = "<text>") -> PlanningCatalog:
    """Parse YAML/JSON catalogue text."""
    try:
        data = yaml.safe_load(text)  # F-08-06: safe_load only
    except yaml.YAMLError as exc:
        raise ConfigurationError(f"{source}: not valid YAML: {exc}") from exc
    if data is None:
        msg = f"{source}: catalogue document is empty"
        raise ConfigurationError(msg)
    return parse_catalog(data, source=source)


def default_catalog_text() -> str:
    """Read the catalogue bundled with the installed package."""
    resource = files("arachne.templates")
    for part in DEFAULT_CATALOG_RESOURCE:
        resource = resource.joinpath(part)
    try:
        return resource.read_text(encoding="utf-8")
    except (FileNotFoundError, OSError) as exc:  # pragma: no cover - packaging failure
        msg = f"bundled check catalogue is missing ({'/'.join(DEFAULT_CATALOG_RESOURCE)}): {exc}"
        raise ConfigurationError(msg) from exc


def load_catalog(path: str | Path | None = None) -> PlanningCatalog:
    """Load the catalogue from ``path``, or the bundled default when ``path`` is None."""
    if path is None:
        return _bundled_catalog()
    resolved = Path(path).expanduser()
    if not resolved.is_file():
        msg = f"check catalogue {resolved} does not exist or is not a file"
        raise ConfigurationError(msg)
    try:
        text = resolved.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigurationError(f"cannot read check catalogue {resolved}: {exc}") from exc
    return load_catalog_from_text(text, source=str(resolved))


@functools.cache
def _bundled_catalog() -> PlanningCatalog:
    """The catalogue that ships with ARACHNE, parsed once per process.

    A frozen model over a packaged file, and the plan is built more than once per scan, so
    re-parsing it is pure waste — it is the largest of the packaged YAML documents. No
    arguments: the bundled catalogue is a constant of the installation. A caller that passes an
    explicit ``path`` (or its own text) is not cached.
    """
    return load_catalog_from_text(default_catalog_text(), source="bundled catalogue")
