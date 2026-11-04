"""The plugin marketplace: a versioned, signature-verified catalogue of installable packages.

The catalogue is **data** (``templates/marketplace/index.yaml`` by default), so an
air-gapped deployment points ``ARACHNE_MARKETPLACE`` at its own file and the whole
workflow stays offline. Nothing here installs or executes anything: the entry describes a
``source`` and the entry-point group it will register under, and
:mod:`arachne.plugins.installer` does the writing after an explicit operator action.

The ``installed`` flag in :meth:`MarketplaceCatalog.listing` is computed from the live
registries (module groups and report formats whose ``origin`` is not ``builtin``), so the
marketplace answers "what do I already have?" without trusting the catalogue's own claims.

**The index is signed, and an unverifiable one is refused** (REQ-ECOS-008). A marketplace index
is a trust-redirection document: a compromised one points ``verified`` entries at whatever it
likes, so reviewing the packs while trusting an unsigned index protects nothing. The rules are
fail-closed and there are exactly three:

* a signed index must verify against the deployment's content key **set** — and a deployment
  with no key configured therefore refuses it, because "no key" must never mean "accept";
* the bundled index is exempt, because it ships inside the package and is covered by the
  package's own integrity rather than by a runtime signature;
* any other unsigned index (``ARACHNE_MARKETPLACE``, ``--index``) is refused unless the operator
  explicitly set ``ARACHNE_PLUGIN_ALLOW_UNSIGNED_INDEX`` — the one deliberate escape hatch, which
  the operator guide documents.

Refusing the *index* is what makes the second half of the requirement reachable:
:func:`require_verified_entry` refuses an entry pointing at a pack this deployment has no reason
to trust **before anything is downloaded**, which is the only moment at which the refusal is
cheap.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from importlib.resources import files
from pathlib import Path
from typing import Any, Final

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from arachne.core.errors import ConfigurationError
from arachne.core.signing import DeploymentSigner, SigningKeyring, canonical_bytes

__all__ = [
    "CATALOG_RESOURCE",
    "CHECK_ENTRY_POINT_GROUP",
    "FORMAT_ENTRY_POINT_GROUP",
    "INDEX_DOMAIN",
    "INDEX_SIGNATURE_KEY",
    "MarketplaceCatalog",
    "MarketplaceEntry",
    "index_payload",
    "load_marketplace",
    "require_verified_entry",
    "sign_index",
]

#: Bundled catalogue location, relative to ``templates/``.
CATALOG_RESOURCE: Final = ("marketplace", "index.yaml")

#: Signature domain for an index signature: one cannot be replayed as a pack signature, and a
#: pack signature cannot be presented as an index signature.
INDEX_DOMAIN: Final = "arachne.marketplace-index"

#: The key an index document carries its own detached signature under.
INDEX_SIGNATURE_KEY: Final = "signature"

#: The entry-point group a check/module plugin registers under (mirrors the registry).
CHECK_ENTRY_POINT_GROUP: Final = "arachne.modules"
#: The entry-point group a report-format plugin registers under (mirrors the format registry).
FORMAT_ENTRY_POINT_GROUP: Final = "arachne.report_formats"

_KINDS: Final[frozenset[str]] = frozenset({"check", "report-format", "provider", "module"})


class MarketplaceEntry(BaseModel):
    """One catalogue row."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(min_length=1, max_length=128)
    kind: str = "check"
    description: str = ""
    version: str = ""
    source: str = Field(min_length=1, max_length=1024)
    entry_point_group: str | None = None
    homepage: str | None = None
    tags: tuple[str, ...] = ()
    verified: bool = False
    #: The key id the pack at ``source`` is signed by. Required for an entry that claims
    #: ``verified`` once it is used to install: the claim has to be substantiable, and this key
    #: is what the deployment checks it against before anything is downloaded (REQ-ECOS-008).
    pack_key_id: str | None = None

    def model_post_init(self, __context: Any) -> None:
        if self.kind not in _KINDS:
            msg = f"marketplace entry {self.name!r} has unknown kind {self.kind!r}"
            raise ValueError(msg)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "kind": self.kind,
            "description": self.description,
            "version": self.version,
            "source": self.source,
            "entry_point_group": self.entry_point_group,
            "homepage": self.homepage,
            "tags": list(self.tags),
            "verified": self.verified,
            "pack_key_id": self.pack_key_id,
        }

    def matches(self, term: str) -> bool:
        needle = term.strip().lower()
        if not needle:
            return True
        haystack = " ".join([self.name, self.description, self.kind, *self.tags]).lower()
        return needle in haystack


@dataclass(frozen=True, slots=True)
class MarketplaceCatalog:
    """A loaded catalogue: its version, its entries, where it came from — and whether it verified.

    ``verified`` is not decoration: it is the difference between "the maintainers signed this
    list" and "somebody put this file where the deployment reads it". An entry may only be
    installed from a verified index, which :func:`require_verified_entry` enforces.
    """

    version: str = ""
    updated: str = ""
    source: str = "bundled"
    entries: tuple[MarketplaceEntry, ...] = field(default_factory=tuple)
    #: True when the index is signature-verified, or when it is the package's own bundled index.
    verified: bool = False
    #: How that was established: ``signed``, ``bundled`` or ``unsigned``.
    trust: str = "unsigned"
    #: The key id the index was signed by, when it carries a signature.
    signature_key_id: str | None = None

    def search(self, term: str) -> tuple[MarketplaceEntry, ...]:
        return tuple(item for item in self.entries if item.matches(term))

    def get(self, name: str) -> MarketplaceEntry | None:
        wanted = name.strip().lower()
        for item in self.entries:
            if item.name.lower() == wanted:
                return item
        return None

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "updated": self.updated,
            "source": self.source,
            "verified": self.verified,
            "trust": self.trust,
            "signature_key_id": self.signature_key_id,
            "entries": [item.to_dict() for item in self.entries],
        }

    def listing(self, *, term: str | None = None) -> list[dict[str, Any]]:
        """Entries with an ``installed`` flag computed from the live environment."""
        installed = _installed_distributions()
        rows: list[dict[str, Any]] = []
        for item in self.search(term or ""):
            row = item.to_dict()
            row["installed"] = _normalize_distribution_name(item.name) in installed
            rows.append(row)
        return rows


def load_marketplace(
    path: str | Path | None = None,
    *,
    keyring: SigningKeyring | None = None,
    allow_unsigned: bool = False,
) -> MarketplaceCatalog:
    """Load the catalogue from ``path`` (or the bundled index), fail-closed on the signature.

    See the module docstring for the three rules. ``allow_unsigned`` is the operator's explicit
    ``ARACHNE_PLUGIN_ALLOW_UNSIGNED_INDEX``: it admits an unsigned index from a path, and the
    catalog it returns is marked ``trust="unsigned"`` so a caller can still see what it got.
    """
    bundled = path is None or (isinstance(path, str) and not path.strip())
    if bundled:
        node = files("arachne.templates")
        for part in CATALOG_RESOURCE:
            node = node.joinpath(part)
        try:
            text = node.read_text(encoding="utf-8")
        except (FileNotFoundError, OSError) as exc:  # pragma: no cover - packaging failure
            msg = f"bundled marketplace index is missing: {exc}"
            raise ConfigurationError(msg) from exc
        source = "bundled index.yaml"
    else:
        assert path is not None  # the ``bundled`` branch returned above
        resolved = Path(path).expanduser()
        if not resolved.is_file():
            msg = f"marketplace index {resolved} does not exist"
            raise ConfigurationError(msg)
        try:
            text = resolved.read_text(encoding="utf-8")
        except OSError as exc:
            msg = f"cannot read marketplace index {resolved}: {exc}"
            raise ConfigurationError(msg) from exc
        source = str(resolved)

    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        msg = f"{source}: not valid YAML: {exc}"
        raise ConfigurationError(msg) from exc
    if data is None:
        data = {}
    if not isinstance(data, dict):
        msg = f"{source}: expected a mapping at the top level"
        raise ConfigurationError(msg)
    trust, signature_key_id = _verify_index(
        data, source=source, bundled=bundled, keyring=keyring, allow_unsigned=allow_unsigned
    )
    raw_entries = data.get("plugins") or ()
    if not isinstance(raw_entries, (list, tuple)):
        msg = f"{source}: 'plugins' must be a list"
        raise ConfigurationError(msg)
    entries: list[MarketplaceEntry] = []
    seen: set[str] = set()
    for raw in raw_entries:
        try:
            entry = MarketplaceEntry.model_validate(raw)
        except (ValidationError, ValueError) as exc:
            msg = f"{source}: invalid marketplace entry: {exc}"
            raise ConfigurationError(msg) from exc
        if entry.name in seen:
            msg = f"{source}: marketplace entry {entry.name!r} appears twice"
            raise ConfigurationError(msg)
        seen.add(entry.name)
        entries.append(entry)
    return MarketplaceCatalog(
        version=str(data.get("version", "")),
        updated=str(data.get("updated", "")),
        source=source,
        entries=tuple(entries),
        verified=trust != "unsigned",
        trust=trust,
        signature_key_id=signature_key_id,
    )


def index_payload(document: Mapping[str, Any]) -> bytes:
    """The canonical bytes an index signature covers: the document without its signature."""
    return canonical_bytes(
        {key: value for key, value in document.items() if key != INDEX_SIGNATURE_KEY}
    )


def sign_index(document: Mapping[str, Any], signer: DeploymentSigner) -> dict[str, Any]:
    """Return ``document`` with its index signature added — the operator's signing step.

    Exposed because signing an index must not require reverse-engineering the format: hand this
    the parsed catalogue and the deployment's signer, dump the result back to YAML, and the
    deployment (and any peer holding the same key set) can load it. The signature covers the
    document *without* the signature field, so re-signing an already-signed index is idempotent.
    """
    signed = {key: value for key, value in document.items() if key != INDEX_SIGNATURE_KEY}
    signed[INDEX_SIGNATURE_KEY] = signer.sign(INDEX_DOMAIN, index_payload(document))
    return signed


def _verify_index(
    document: dict[str, Any],
    *,
    source: str,
    bundled: bool,
    keyring: SigningKeyring | None,
    allow_unsigned: bool,
) -> tuple[str, str | None]:
    """Establish how the index is trusted, or refuse it (REQ-ECOS-008).

    Returns ``(trust, key_id)``. The signature covers the document *without* its ``signature``
    key, canonicalised, so the signature field itself cannot be part of what it signs.
    """
    signature = document.get(INDEX_SIGNATURE_KEY)
    if signature is None:
        if bundled:
            # Shipped inside the package: its integrity is the package's, and a deployment that
            # installed ARACHNE has already decided to trust what ARACHNE ships. Signing it would
            # mean committing a signing key, which is exactly what must never be in the tree.
            return "bundled", None
        if allow_unsigned:
            return "unsigned", None
        msg = (
            f"{source} carries no signature. A marketplace index redirects trust — a compromised "
            "one points its verified entries anywhere — so an operator-supplied index must carry "
            f"a '{INDEX_SIGNATURE_KEY}' field signed with a key in this deployment's content key "
            "set. Sign it, or set ARACHNE_PLUGIN_ALLOW_UNSIGNED_INDEX=true to accept it anyway "
            "(an explicit, documented exception)"
        )
        raise ConfigurationError(msg)
    if not isinstance(signature, str) or not signature.strip():
        msg = f"{source}: the '{INDEX_SIGNATURE_KEY}' field must be a signature string"
        raise ConfigurationError(msg)
    if keyring is None or not keyring:
        msg = (
            f"{source} is signed, but this deployment has no content key configured: set "
            "ARACHNE_INTEGRITY_KEY (or ARACHNE_CONTENT_KEYS during a rotation) to the key that "
            "signs the index. Nothing is loaded from an index this deployment cannot verify"
        )
        raise ConfigurationError(msg)
    if not keyring.verify(INDEX_DOMAIN, index_payload(document), signature):
        parts = signature.split(":")
        key_id = parts[1] if len(parts) == 3 else "?"
        msg = (
            f"{source}: the index signature by key {key_id} does not verify against any key this "
            f"deployment accepts ({list(keyring.key_ids())}); the index was edited, or it was "
            "signed by a key outside the rotation set"
        )
        raise ConfigurationError(msg)
    return "signed", signature.split(":")[1]


def require_verified_entry(
    catalogue: MarketplaceCatalog,
    entry: MarketplaceEntry,
    *,
    keyring: SigningKeyring | None = None,
) -> None:
    """Refuse an entry that cannot be trusted **before anything is downloaded** (REQ-ECOS-008).

    Four refusals, in the order an operator would ask them:

    1. the index is not verified, so nothing it says about a pack can be relied on;
    2. the entry does not claim maintainer review (``verified: false``);
    3. the entry claims review but names no signing key (``pack_key_id``), so the claim cannot be
       substantiated — it is an assertion, not a fact;
    4. the pack is signed by a key outside the deployment's content key set.

    Steps 1-3 are free and happen first; step 4 is checked against the same keyring the index
    itself was verified with, so one rotation covers packs and index together.
    """
    if not catalogue.verified:
        msg = (
            f"the marketplace index {catalogue.source} is not signature-verified "
            f"(trust={catalogue.trust!r}), so its 'verified' flags cannot be trusted. Sign the "
            "index with a content key (or point ARACHNE_MARKETPLACE at a signed one) before "
            "installing from it; nothing was downloaded"
        )
        raise ConfigurationError(msg)
    if not entry.verified:
        msg = (
            f"marketplace entry {entry.name!r} is not marked as reviewed by the maintainers, so "
            "it cannot be installed from the catalogue. Review the pack "
            "(`arachne plugin review <pack> --publish`) first; nothing was downloaded"
        )
        raise ConfigurationError(msg)
    if not (entry.pack_key_id or "").strip():
        msg = (
            f"marketplace entry {entry.name!r} claims to be verified but names no pack_key_id, "
            "so the claim cannot be substantiated. Add the key id the pack is signed by; nothing "
            "was downloaded"
        )
        raise ConfigurationError(msg)
    trusted = keyring.key_ids() if keyring is not None else ()
    if entry.pack_key_id not in trusted:
        msg = (
            f"marketplace entry {entry.name!r} points at a pack signed by key "
            f"{entry.pack_key_id!r}, which this deployment does not accept ({list(trusted)}). "
            "Refused before download"
        )
        raise ConfigurationError(msg)


def _installed_distributions() -> set[str]:
    """Normalised names of every installed distribution (PEP 503 comparison).

    The catalogue's ``name`` is a **distribution** name, so this is the honest test of
    "installed" — unlike the entry-point names a registry records. A package that is
    importable but has no distribution metadata (a stray directory on ``PYTHONPATH``) is
    still reported by :func:`arachne.plugins.installed_plugins`; the marketplace flag is a
    convenience, not an authorization signal.
    """
    from importlib.metadata import distributions

    names: set[str] = set()
    for distribution in distributions():
        try:
            raw = distribution.metadata["Name"]
        except (KeyError, TypeError):  # pragma: no cover - broken metadata
            continue
        if raw:
            names.add(_normalize_distribution_name(str(raw)))
    return names


def _normalize_distribution_name(name: str) -> str:
    """PEP 503 normalisation: ``Arachne_Example.Report`` → ``arachne-example-report``."""
    return re.sub(r"[-_.]+", "-", name.strip().lower())
