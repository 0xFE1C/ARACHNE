"""The fix-plan catalog: how a remediation becomes a concrete artifact (S27, REQ-FIX-001).

The remediation catalog (:mod:`arachne.analyzer.remediation`) answers *what to do* in prose.
A **fix plan** answers *how to do it as an artifact* for the classes where the change is
unambiguous, deterministic and strictly narrows the exposure: which check the plan is for,
which artifact rule the finding must carry, which files it may touch, and the two
regex-shaped edits it applies.

Two properties make this data rather than code:

* **Selection is mechanical.** A plan names the check key and the *artifact rule id* the
  downstream review puts in the finding's evidence, so "which plan fits this finding" is a
  set intersection — never a similarity score and never a model's opinion. When two plans
  fit equally well the engine refuses (the caller records ``ambiguous``) rather than
  guessing, because a coin-flip fix is not a reviewable artifact.
* **A plan may not widen access, remove a credential literal or bump a dependency.** Those
  prohibitions are enforced twice: this module refuses to load a plan whose edits cannot
  bite at all, and :mod:`arachne.fix.safety` refuses any *diff* — planned or AI-authored —
  that would introduce one of those properties.

The shipped catalog lives in ``templates/fix/fix-plans.yaml``; a deployment points
``ARACHNE_FIX_PLANS`` at its own file (or a directory of per-plan files) to replace it,
exactly like the remediation catalog and the M5 probe corpus.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from functools import lru_cache
from importlib.resources import files
from pathlib import Path
from typing import Any, Final, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from arachne.core.errors import ConfigurationError

__all__ = [
    "DEFAULT_FIX_PLAN_RESOURCE",
    "EditOp",
    "FindingProfile",
    "FixPlan",
    "FixPlanCatalog",
    "PlanSelection",
    "PlanTargeting",
    "load_fix_plan_catalog",
    "parse_fix_plan_catalog",
]

#: Where the shipped catalog lives inside the package.
DEFAULT_FIX_PLAN_RESOURCE: Final = ("fix", "fix-plans.yaml")

#: Bounded patterns: a plan is operator-authored data, but a catastrophic-backtracking
#: regex would hang a proposal run, so the shape is capped before it is compiled.
MAX_PATTERN_CHARS: Final = 400
MAX_EDITS_PER_PLAN: Final = 8

_MODEL_CONFIG = ConfigDict(frozen=True, extra="forbid")

#: The artifact signals a plan may target. ``iac-misconfiguration`` is the M5 review's;
#: anything else has to be named explicitly by an operator's own catalog.
_KNOWN_SIGNALS: Final[frozenset[str]] = frozenset({"iac-misconfiguration", "repo-secret"})


@lru_cache(maxsize=256)
def _compile(pattern: str) -> re.Pattern[str]:
    """Compile a plan pattern once (patterns are data, so they are re-used constantly)."""
    if len(pattern) > MAX_PATTERN_CHARS:
        msg = f"fix-plan pattern is {len(pattern)} characters (max {MAX_PATTERN_CHARS})"
        raise ConfigurationError(msg)
    try:
        return re.compile(pattern)
    except re.error as exc:
        msg = f"fix-plan pattern {pattern!r} is not a valid regular expression: {exc}"
        raise ConfigurationError(msg) from exc


class EditOp(BaseModel):
    """One deterministic text edit inside a matched file.

    ``replace`` rewrites every match of ``pattern`` (``count`` bounds it, ``0`` means all);
    ``insert_after`` adds ``text`` after every matched line. Both are pure text operations:
    no evaluation, no path traversal, no follow-up command.
    """

    model_config = _MODEL_CONFIG

    op: Literal["replace", "insert_after"]
    pattern: str = Field(min_length=1, max_length=MAX_PATTERN_CHARS)
    #: ``replace`` only. Backreferences use the ``\\g<name>`` spelling.
    replacement: str = Field(default="", max_length=MAX_PATTERN_CHARS)
    #: ``insert_after`` only: the line (or block) inserted, verbatim.
    text: str = Field(default="", max_length=2000)
    #: ``0`` means "every match"; a positive value caps the number of edits.
    count: int = Field(default=0, ge=0, le=100)
    #: How many matches the whole plan needs across the file for the edit to have bitten.
    #: ``0`` marks an alternative-syntax edit that may legitimately find nothing.
    min_matches: int = Field(default=1, ge=0, le=100)
    max_matches: int | None = Field(default=None, ge=1, le=1000)

    @model_validator(mode="after")
    def _validate(self) -> EditOp:
        if self.op == "insert_after" and not self.text:
            raise ValueError("an insert_after edit needs the text it inserts")
        if self.op == "replace" and not self.replacement:
            raise ValueError("a replace edit needs a replacement (use insert_after to add)")
        if self.max_matches is not None and self.max_matches < self.min_matches:
            raise ValueError("max_matches cannot be below min_matches")
        _compile(self.pattern)
        return self

    @property
    def required(self) -> bool:
        return self.min_matches > 0


class PlanTargeting(BaseModel):
    """What a plan is for. Every populated field is a precondition (``AND``)."""

    model_config = _MODEL_CONFIG

    #: Check keys (``M5/tfstate-exposure``) or module names (``M5``).
    checks: tuple[str, ...] = ()
    #: Artifact rule ids the finding's evidence must carry (``k8s-privileged``).
    rules: tuple[str, ...] = ()
    #: CWE the finding must carry.
    cwe: str | None = None
    #: Remediation-catalog entry ids this plan implements.
    remediation: tuple[str, ...] = ()
    #: Artifact signal (``iac-misconfiguration``).
    signals: tuple[str, ...] = ()

    @property
    def specificity(self) -> int:
        return sum(
            1
            for group in (self.checks, self.rules, self.cwe, self.remediation, self.signals)
            if group
        )

    def matches(self, profile: FindingProfile) -> bool:
        if self.checks and not _any_check(self.checks, profile.check_key):
            return False
        if self.rules and (profile.rule or "") not in self.rules:
            return False
        if self.cwe and (profile.cwe or "") != self.cwe:
            return False
        if self.remediation and (profile.remediation_id or "") not in self.remediation:
            return False
        return not (self.signals and (profile.signal or "") not in self.signals)


def _any_check(checks: tuple[str, ...], check_key: str | None) -> bool:
    """``M5`` matches ``M5/tfstate-exposure@1.1``; ``M5/tfstate-exposure`` matches too."""
    if not check_key:
        return False
    module, _, remainder = check_key.partition("/")
    name = remainder.split("@", 1)[0]
    base = f"{module}/{name}" if name else module
    return any(item in (base, module, name, check_key) for item in checks)


@dataclass(frozen=True, slots=True)
class FindingProfile:
    """The parts of a finding a plan selects on — nothing else is consulted."""

    check_key: str | None = None
    cwe: str | None = None
    remediation_id: str | None = None
    rule: str | None = None
    signal: str | None = None

    @property
    def check_base(self) -> str | None:
        if not self.check_key:
            return None
        module, _, remainder = self.check_key.partition("/")
        name = remainder.split("@", 1)[0]
        return f"{module}/{name}" if name else module


class FixPlan(BaseModel):
    """One concrete remediation artifact ("this class of finding → these edits")."""

    model_config = _MODEL_CONFIG

    id: str = Field(min_length=3, max_length=128)
    #: ``iac`` artifacts are validated against ARACHNE's own IaC scanner (REQ-FIX-004);
    #: ``code`` artifacts are not IaC and carry no such self-scan.
    kind: Literal["iac", "code"] = "iac"
    summary: str = Field(min_length=10, max_length=2000)
    applies_to: PlanTargeting
    #: Globs (relative to the repo root) the plan may edit. Empty means "any file the
    #: finding's own evidence named", which is still bounded by that evidence.
    globs: tuple[str, ...] = ()
    edits: tuple[EditOp, ...] = Field(min_length=1, max_length=MAX_EDITS_PER_PLAN)
    #: When present in a target file, the fix is already in place: the plan reports
    #: ``already-fixed`` instead of proposing a change it cannot meaningfully make.
    already_fixed: str | None = Field(default=None, max_length=MAX_PATTERN_CHARS)
    #: True when the plan's edits can only be applied by a human (an edit that removes a
    #: credential leaves a diff the tooling cannot reproduce verbatim).
    manual_apply_required: bool = False
    #: True when the plan deliberately removes credential material. The diff-scope analysis
    #: then masks the removed value out of the emitted diff (REQ-FIX-003: "no secrets in
    #: diffs"), which makes the artifact non-byte-applicable and manual by construction —
    #: both flags are set together rather than trusted to agree.
    mask_removals: bool = False
    notes: tuple[str, ...] = ()
    enabled: bool = True

    @model_validator(mode="after")
    def _validate(self) -> FixPlan:
        if not any(edit.required for edit in self.edits):
            raise ValueError(
                f"plan {self.id}: every edit is optional, so the plan could silently do nothing"
            )
        if self.already_fixed is not None:
            _compile(self.already_fixed)
        for glob in self.globs:
            if not glob or glob.startswith("/") or ".." in glob:
                raise ValueError(f"plan {self.id}: glob {glob!r} must be a relative pattern")
        return self

    @property
    def targets_iac(self) -> bool:
        """True when the artifact is IaC/cloud config (self-scanned, REQ-FIX-004)."""
        return self.kind == "iac"

    def fixed_already(self, text: str) -> bool:
        return self.already_fixed is not None and bool(_compile(self.already_fixed).search(text))

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "summary": self.summary,
            "checks": list(self.applies_to.checks),
            "rules": list(self.applies_to.rules),
            "globs": list(self.globs),
            "edits": len(self.edits),
            "manual_apply_required": self.manual_apply_required,
            "enabled": self.enabled,
        }


@dataclass(frozen=True, slots=True)
class PlanSelection:
    """The plan chosen for a finding, plus every plan that fitted equally well."""

    plan: FixPlan | None
    candidates: tuple[FixPlan, ...] = ()

    @property
    def ambiguous(self) -> bool:
        return self.plan is None and len(self.candidates) > 1

    @property
    def unsupported(self) -> bool:
        return self.plan is None and not self.candidates


class FixPlanCatalog(BaseModel):
    """The whole plan catalog."""

    model_config = _MODEL_CONFIG

    version: str = Field(min_length=1, max_length=32)
    plans: tuple[FixPlan, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def _validate_unique(self) -> FixPlanCatalog:
        seen: set[str] = set()
        for plan in self.plans:
            if plan.id in seen:
                raise ValueError(f"duplicate fix-plan id {plan.id!r}")
            seen.add(plan.id)
        return self

    def by_id(self, plan_id: str) -> FixPlan | None:
        for plan in self.plans:
            if plan.id == plan_id:
                return plan
        return None

    def select(self, profile: FindingProfile) -> PlanSelection:
        """The most specific enabled plan for ``profile`` (see the module docstring)."""
        fitting = [plan for plan in self.plans if plan.enabled and plan.applies_to.matches(profile)]
        if not fitting:
            return PlanSelection(plan=None)
        top = max(plan.applies_to.specificity for plan in fitting)
        best = tuple(sorted((p for p in fitting if p.applies_to.specificity == top), key=_plan_key))
        if len(best) == 1:
            return PlanSelection(plan=best[0], candidates=best)
        return PlanSelection(plan=None, candidates=best)

    def covered(self) -> tuple[str, ...]:
        return tuple(plan.id for plan in self.plans)


def _plan_key(plan: FixPlan) -> tuple[int, str]:
    """Prefer the plan that pins an artifact rule, then the lowest id (deterministic)."""
    return (-len(plan.applies_to.rules), plan.id)


def parse_fix_plan_catalog(data: Any, *, source: str = "<memory>") -> FixPlanCatalog:
    if not isinstance(data, dict):
        msg = f"{source}: expected a mapping, got {type(data).__name__}"
        raise ConfigurationError(msg)
    try:
        return FixPlanCatalog.model_validate(data)
    except ValidationError as exc:
        parts = [
            f"{'.'.join(str(item) for item in error['loc']) or '<root>'}: {error['msg']}"
            for error in exc.errors()
        ]
        raise ConfigurationError(f"{source}: invalid fix-plan catalog: {'; '.join(parts)}") from exc


def load_fix_plan_catalog(path: str | None = None) -> FixPlanCatalog:
    """Load the plan catalog from ``path`` (a file or directory), or the shipped default."""
    if path is not None:
        resolved = Path(path).expanduser()
        if resolved.is_dir():
            plans = tuple(_load_plans_from_dir(resolved))
            if not plans:
                msg = f"fix-plan catalog directory {resolved} holds no plans"
                raise ConfigurationError(msg)
            return FixPlanCatalog(version="directory", plans=plans)
        if not resolved.is_file():
            msg = f"fix-plan catalog {resolved} does not exist"
            raise ConfigurationError(msg)
        try:
            text = resolved.read_text(encoding="utf-8")
        except OSError as exc:
            raise ConfigurationError(f"cannot read {resolved}: {exc}") from exc
        return parse_fix_plan_catalog(_safe_yaml(text, source=str(resolved)), source=str(resolved))
    resource = files("arachne.templates")
    for part in DEFAULT_FIX_PLAN_RESOURCE:
        resource = resource.joinpath(part)
    try:
        text = resource.read_text(encoding="utf-8")
    except (FileNotFoundError, OSError) as exc:  # pragma: no cover - packaging failure
        msg = f"bundled fix-plan catalog is missing: {exc}"
        raise ConfigurationError(msg) from exc
    source = "/".join(DEFAULT_FIX_PLAN_RESOURCE)
    return parse_fix_plan_catalog(_safe_yaml(text, source=source), source=source)


def _load_plans_from_dir(directory: Path) -> Iterable[FixPlan]:
    """One plan per ``*.yaml`` file, the id defaulting to the file's stem."""
    for candidate_path in sorted(directory.glob("*.y*ml")):
        data = _safe_yaml(candidate_path.read_text(encoding="utf-8"), source=str(candidate_path))
        if not isinstance(data, Mapping):
            raise ConfigurationError(f"{candidate_path}: expected a mapping")
        payload = dict(data)
        payload.setdefault("id", candidate_path.stem)
        try:
            yield FixPlan.model_validate(payload)
        except ValidationError as exc:
            raise ConfigurationError(f"{candidate_path}: invalid plan: {exc}") from exc


def _safe_yaml(text: str, *, source: str) -> Any:
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigurationError(f"{source}: not valid YAML: {exc}") from exc
