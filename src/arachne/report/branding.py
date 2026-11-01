"""White-label branding: load, validate and resolve a report's presentation (S14).

An MSSP delivers the same scanner's output under its own name. The values live in
:class:`~arachne.report.model.Branding` on the DTO; this module is how they get there:

* :func:`load_branding` reads a YAML/JSON file (``ARACHNE_REPORT_BRANDING``);
* :func:`branding_from_dict` validates a project's ``branding_json``;
* :func:`branding_from_settings` resolves the deployment default;
* :func:`merge_branding` lets a project override the deployment default field-by-field;
* :func:`resolve_branding` is the one call a renderer-facing path should make: it merges the
  two and then applies the deployment's **white-label/MSSP mode** (S26, REQ-ECOS-006);
* :func:`white_label` is the mode's effect — the vendor's own name only, no ARACHNE
  attribution.

Everything is operator input, so validation happens here (a bad colour or a ``javascript:``
logo fails loudly) and the renderers can treat the result as data.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml
from pydantic import ValidationError

from arachne.core.errors import ReportError
from arachne.report.model import Branding

__all__ = [
    "BrandingError",
    "branding_from_dict",
    "branding_from_settings",
    "load_branding",
    "merge_branding",
    "resolve_branding",
    "white_label",
    "white_label_enabled",
]


class BrandingError(ReportError):
    """A branding document that cannot be loaded or does not validate."""


def branding_from_dict(data: Any) -> Branding:
    """Validate ``data`` into a :class:`Branding`; an empty document is the default."""
    if not data:
        return Branding()
    if not isinstance(data, dict):
        msg = "branding must be a mapping of fields"
        raise BrandingError(msg)
    # A project may nest its presentation under ``report:`` for readability in a file that
    # also carries other settings; accept both spellings.
    payload = data.get("branding", data)
    if not isinstance(payload, dict):
        msg = "branding.branding must be a mapping"
        raise BrandingError(msg)
    try:
        return Branding.model_validate(payload)
    except ValidationError as exc:
        raise BrandingError(f"invalid branding: {exc}") from exc


def load_branding(path: str | Path | None) -> Branding:
    """Load a branding document from a YAML or JSON file (``None`` → the default)."""
    if path is None or (isinstance(path, str) and not path.strip()):
        return Branding()
    resolved = Path(path).expanduser()
    if not resolved.is_file():
        msg = f"branding file {resolved} does not exist"
        raise BrandingError(msg)
    try:
        text = resolved.read_text(encoding="utf-8")
    except OSError as exc:
        msg = f"cannot read branding file {resolved}: {exc}"
        raise BrandingError(msg) from exc
    try:
        parsed = json.loads(text) if resolved.suffix.lower() == ".json" else yaml.safe_load(text)
    except (json.JSONDecodeError, yaml.YAMLError) as exc:
        msg = f"branding file {resolved} is not valid YAML/JSON: {exc}"
        raise BrandingError(msg) from exc
    if parsed is None:
        return Branding()
    if not isinstance(parsed, dict):
        msg = f"branding file {resolved} must contain a mapping at the top level"
        raise BrandingError(msg)
    return branding_from_dict(parsed)


def branding_from_settings(settings: Any) -> Branding:
    """The deployment's default branding (``ARACHNE_REPORT_BRANDING`` when set)."""
    if settings is None:
        return Branding()
    return load_branding(getattr(settings.report, "branding_path", None))


def merge_branding(base: Branding, override: Branding | None) -> Branding:
    """Field-wise merge: ``override``'s non-default fields win over ``base``.

    A project's branding is usually a few fields (company, colours, contact) while the
    deployment supplies the rest (classification banner, footer). Treating the pydantic
    default as "unset" is what makes that composition possible without a sentinel type.
    """
    if override is None or not override.is_customised():
        return base
    default = Branding()
    merged: dict[str, Any] = {}
    for name in Branding.model_fields:
        value = getattr(override, name)
        merged[name] = value if value != getattr(default, name) else getattr(base, name)
    return Branding.model_validate(merged)


def white_label_enabled(settings: Any) -> bool:
    """Whether this deployment runs in white-label/MSSP mode (``ARACHNE_REPORT_WHITE_LABEL``).

    An MSSP delivers one ARACHNE to many customers under its own name; ARACHNE's own
    attribution is then a disclosure the operator may not want in a client deliverable. The
    mode is a *deployment* setting, not a per-tenant one, because it is the operator's
    commercial choice — a tenant cannot switch it back on.
    """
    report = getattr(settings, "report", None)
    return bool(getattr(report, "white_label", False))


def white_label(branding: Branding) -> Branding:
    """The white-label view of ``branding``: ARACHNE attribution removed.

    ``product_name`` falls back to the tenant's ``company_name`` so the product is named after
    whoever delivers it, and ``show_arachne_branding`` is forced off, which is what the
    renderers key on to drop their "produced with ARACHNE" line. A branding that is already
    white-labelled is returned unchanged (idempotent).
    """
    updates: dict[str, Any] = {"show_arachne_branding": False}
    if branding.company_name and branding.product_name == Branding().product_name:
        updates["product_name"] = branding.company_name
    return branding.model_copy(update=updates)


def resolve_branding(settings: Any, override: Branding | None = None) -> Branding:
    """The branding a report renders: deployment default ⊕ project override ⊕ MSSP mode.

    This is the single entry point the CLI, the API and the builder share, so the three cannot
    disagree about which presentation a report gets — or about whether white-label mode is in
    force. ``override`` is usually a project's stored branding; a neutral one inherits the
    deployment default field-by-field (:func:`merge_branding`).
    """
    merged = merge_branding(branding_from_settings(settings), override)
    if white_label_enabled(settings):
        return white_label(merged)
    return merged
