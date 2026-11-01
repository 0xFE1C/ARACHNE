"""The remediation catalog (docs/spec/04- §2.6/§3, docs/spec/06- §6, F-06-04).

A finding without an action is a complaint, so every analysis carries a :class:`Remediation`
resolved from data. Lookup order, most specific first:

1. the rule's ``remediation:`` reference — ``remediation-catalog/env-file-exposure.yaml``
   (docs/spec/04- §2.1's own spelling), a bare entry id, or a path to a catalog file;
2. the catalog entry naming the **check** that fired;
3. the catalog entry for the finding's **CWE**;
4. the catalog's ``default`` block.

The shipped catalog covers the classes this build can already report (M1/M2, plus the
M3/M4 entries the rules reference), and it is *managed data* (F-09-04): a deployment points
``ARACHNE_REMEDIATION_CATALOG`` at its own file to replace it. Stage S8 owns the full
catalog and the QA gate over it; this module owns the lookup the analyzer needs.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from importlib.resources import files
from pathlib import Path
from typing import Any, Final

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from arachne.analyzer.model import Candidate, Remediation
from arachne.core.errors import ConfigurationError

__all__ = [
    "DEFAULT_REMEDIATION_RESOURCE",
    "RemediationCatalog",
    "RemediationEntry",
    "default_remediation",
    "load_remediation_catalog",
    "parse_remediation_catalog",
    "ref_to_entry_id",
]

#: Where the shipped catalog lives inside the package.
DEFAULT_REMEDIATION_RESOURCE: Final = ("remediation", "remediation-catalog.yaml")

_MODEL_CONFIG = ConfigDict(frozen=True, extra="forbid")

_CWE = re.compile(r"^CWE-\d{1,5}$")

#: The fallback every finding gets when the catalog has nothing more specific to say.
_FALLBACK_SUMMARY: Final = (
    "Review the finding, confirm it against the captured evidence, and apply the vendor's "
    "or platform's hardening guidance for the affected component."
)
_FALLBACK_STEPS: Final[tuple[str, ...]] = (
    "1. Reproduce the finding using the captured evidence and confirm the affected component.",
    "2. Apply the least-privilege configuration or patch that removes the exposure.",
    "3. Re-scan the asset to confirm the finding no longer reproduces.",
    "4. Record the change in the system's change log with the scan id for traceability.",
)
_FALLBACK_VERIFICATION: Final[tuple[str, ...]] = (
    "1. Re-run the check that reported the finding against the same asset; it must no longer "
    "produce a candidate.",
    "2. Confirm the fix at the layer that owns it (web-server rule, service configuration, "
    "credential rotation) rather than only in the application.",
    "3. Record the verifying scan id next to the change ticket.",
)


def ref_to_entry_id(reference: str) -> str:
    """``remediation-catalog/env-file-exposure.yaml`` → ``env-file-exposure``.

    The spec writes remediation references as catalog paths; the catalog itself is keyed by
    entry id, so the translation happens in exactly one place.
    """
    text = reference.strip().replace("\\", "/")
    if text.startswith("remediation-catalog/"):
        text = text.split("/", 1)[1]
    if text.endswith((".yaml", ".yml")):
        text = text.rsplit(".", 1)[0]
    return text.rsplit("/", 1)[-1]


class RemediationEntry(BaseModel):
    """One catalog entry."""

    model_config = _MODEL_CONFIG

    id: str = Field(min_length=2, max_length=128)
    summary: str = Field(min_length=10, max_length=2000)
    steps: tuple[str, ...] = ()
    #: "Verification of fix" steps (docs/spec/06- §6). Optional in data so an operator's
    #: older entry still loads; :meth:`to_remediation` supplies the documented fallback.
    verify: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    cwe: str | None = None
    #: Check ids this entry owns (``m4.env-file-probe``); more specific than the CWE match.
    checks: tuple[str, ...] = ()
    #: Optional product substring, so one CWE can have per-product guidance (docs/spec/06- §6).
    product: str | None = None
    title: str | None = None

    @model_validator(mode="after")
    def _validate(self) -> RemediationEntry:
        if self.cwe is not None and not _CWE.match(self.cwe):
            raise ValueError(f"entry {self.id}: cwe {self.cwe!r} is not CWE-NNN")
        return self

    def to_remediation(self, *, source: str = "catalog") -> Remediation:
        return Remediation(
            id=self.id,
            summary=self.summary,
            steps=tuple(self.steps),
            verification=tuple(self.verify) or _FALLBACK_VERIFICATION,
            references=tuple(self.references),
            source=source,
        )


class RemediationCatalog(BaseModel):
    """The whole catalog."""

    model_config = _MODEL_CONFIG

    version: str = Field(min_length=1, max_length=32)
    entries: tuple[RemediationEntry, ...] = Field(min_length=1)
    default: RemediationEntry | None = None

    @model_validator(mode="after")
    def _validate_unique(self) -> RemediationCatalog:
        seen: set[str] = set()
        for entry in self.entries:
            if entry.id in seen:
                raise ValueError(f"duplicate remediation entry id {entry.id!r}")
            seen.add(entry.id)
        return self

    # ------------------------------------------------------------------ lookup
    def by_id(self, entry_id: str) -> RemediationEntry | None:
        for entry in self.entries:
            if entry.id == entry_id:
                return entry
        return None

    def by_check(self, check_id: str | None) -> RemediationEntry | None:
        if not check_id:
            return None
        for entry in self.entries:
            if check_id in entry.checks:
                return entry
        return None

    def by_cwe(self, cwe: str | None, *, product: str | None = None) -> RemediationEntry | None:
        if not cwe:
            return None
        matches = [entry for entry in self.entries if entry.cwe == cwe]
        if not matches:
            return None
        if product:
            lowered = product.lower()
            for entry in matches:
                if entry.product and entry.product.lower() in lowered:
                    return entry
        for entry in matches:
            if not entry.product:
                return entry
        return matches[0]

    def resolve(
        self,
        candidate: Candidate,
        *,
        reference: str | None = None,
        cwe: str | None = None,
        product: str | None = None,
    ) -> Remediation:
        """Resolve the remediation for one candidate (see the module docstring)."""
        effective_cwe = cwe if cwe is not None else candidate.cwe
        if reference:
            entry = self.by_id(ref_to_entry_id(reference))
            if entry is not None:
                return entry.to_remediation()
            fallback = self.by_check(candidate.check_id) or self.by_cwe(
                effective_cwe, product=product
            )
            if fallback is not None:
                return Remediation(
                    id=ref_to_entry_id(reference),
                    summary=fallback.summary,
                    steps=fallback.steps,
                    verification=tuple(fallback.verify) or _FALLBACK_VERIFICATION,
                    references=fallback.references,
                    source="rule-ref+catalog",
                )
            return Remediation(
                id=ref_to_entry_id(reference),
                summary=_FALLBACK_SUMMARY,
                steps=_FALLBACK_STEPS,
                verification=_FALLBACK_VERIFICATION,
                source="rule-ref+default",
            )
        entry = self.by_check(candidate.check_id) or self.by_cwe(effective_cwe, product=product)
        if entry is not None:
            return entry.to_remediation()
        if self.default is not None:
            return self.default.to_remediation(source="catalog-default")
        return default_remediation(cwe=effective_cwe, check_id=candidate.check_id)

    def covered(self) -> tuple[str, ...]:
        """Entry ids, for a coverage check in S8's catalog QA gate."""
        return tuple(entry.id for entry in self.entries)


def default_remediation(*, cwe: str | None = None, check_id: str | None = None) -> Remediation:
    """The generic remediation, named after whatever identified the finding."""
    identifier = cwe or check_id or "generic"
    slug = re.sub(r"[^a-z0-9]+", "-", identifier.lower()).strip("-")
    return Remediation(
        id=f"default-{slug}",
        summary=_FALLBACK_SUMMARY,
        steps=_FALLBACK_STEPS,
        verification=_FALLBACK_VERIFICATION,
        source="builtin-default",
    )


def parse_remediation_catalog(data: Any, *, source: str = "<memory>") -> RemediationCatalog:
    if not isinstance(data, dict):
        msg = f"{source}: expected a mapping, got {type(data).__name__}"
        raise ConfigurationError(msg)
    try:
        return RemediationCatalog.model_validate(data)
    except ValidationError as exc:
        parts = [
            f"{'.'.join(str(item) for item in error['loc']) or '<root>'}: {error['msg']}"
            for error in exc.errors()
        ]
        raise ConfigurationError(
            f"{source}: invalid remediation catalog: {'; '.join(parts)}"
        ) from exc


def load_remediation_catalog(path: str | None = None) -> RemediationCatalog:
    """Load the catalog from ``path`` (a file or directory), or the shipped default."""
    if path is not None:
        resolved = Path(path).expanduser()
        if resolved.is_dir():
            entries = tuple(_load_entries_from_dir(resolved))
            if not entries:
                msg = f"remediation catalog directory {resolved} holds no entries"
                raise ConfigurationError(msg)
            return RemediationCatalog(version="directory", entries=entries)
        if not resolved.is_file():
            msg = f"remediation catalog {resolved} does not exist"
            raise ConfigurationError(msg)
        try:
            text = resolved.read_text(encoding="utf-8")
        except OSError as exc:
            raise ConfigurationError(f"cannot read {resolved}: {exc}") from exc
        return parse_remediation_catalog(
            _safe_yaml(text, source=str(resolved)), source=str(resolved)
        )
    resource = files("arachne.templates")
    for part in DEFAULT_REMEDIATION_RESOURCE:
        resource = resource.joinpath(part)
    try:
        text = resource.read_text(encoding="utf-8")
    except (FileNotFoundError, OSError) as exc:  # pragma: no cover - packaging failure
        msg = f"bundled remediation catalog is missing: {exc}"
        raise ConfigurationError(msg) from exc
    source = "/".join(DEFAULT_REMEDIATION_RESOURCE)
    return parse_remediation_catalog(_safe_yaml(text, source=source), source=source)


def _load_entries_from_dir(directory: Path) -> Iterable[RemediationEntry]:
    """One entry per ``*.yaml`` file — the per-file layout docs/spec/04- §2.1 references."""
    for candidate_path in sorted(directory.glob("*.y*ml")):
        data = _safe_yaml(candidate_path.read_text(encoding="utf-8"), source=str(candidate_path))
        if not isinstance(data, Mapping):
            raise ConfigurationError(f"{candidate_path}: expected a mapping")
        payload = dict(data)
        payload.setdefault("id", candidate_path.stem)
        try:
            yield RemediationEntry.model_validate(payload)
        except ValidationError as exc:
            raise ConfigurationError(f"{candidate_path}: invalid entry: {exc}") from exc


def _safe_yaml(text: str, *, source: str) -> Any:
    try:
        return yaml.safe_load(text)  # F-08-06: safe_load only
    except yaml.YAMLError as exc:
        raise ConfigurationError(f"{source}: not valid YAML: {exc}") from exc
