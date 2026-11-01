"""Signed offline content packs (S25, REQ-RESIL-001).

An air-gapped estate cannot fetch checks, rules or feeds. It imports a **content pack**: a
single ``.tar.gz`` an operator builds on a connected machine, signs with the deployment's
content key, carries in by hand (USB, an artefact repository the estate can already reach,
whatever the security policy allows) and imports. This module is the whole format:

* :func:`build_pack` — walk a content tree, hash every file, write a manifest, sign it, and
  return the archive.
* :func:`read_pack` — parse the archive, verify the signature over the manifest's canonical
  form, verify **every** file's digest and size, and refuse anything that does not check
  out. Nothing is returned on a failure; there is no partial success.
* :func:`install_pack` — move a verified pack's files into the deployment's content
  directory. Files are written to a staging directory first and moved into place, so a
  failure halfway cannot leave a half-installed pack.

Fail-closed is the whole point (REQ-RESIL-001's hard rule), so the defaults are strict:
a pack with no signature is refused unless the caller explicitly asks for
``allow_unsigned=True`` — an act the CLI audits and the operator guide documents as a
deliberate exception. The format version is in the manifest and an unknown one is refused
rather than parsed optimistically, because "we did not understand this pack" must not look
like "this pack was fine".

Path safety is enforced on **import**, not only on build: an archive is untrusted input, so
every member is resolved and refused if it is absolute, contains ``..`` or is a symlink or
device. That is what keeps a malicious pack from writing outside the content directory.
"""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
import zlib
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any, Final

from arachne.core.errors import ContentPackError
from arachne.core.signing import DeploymentSigner, canonical_bytes

__all__ = [
    "PACK_FORMAT",
    "PACK_SIGNATURE_NAME",
    "ContentPack",
    "PackFile",
    "PackManifest",
    "build_pack",
    "install_pack",
    "pack_digest",
    "read_pack",
    "write_pack",
]

#: The manifest format tag. Bump it when the manifest's meaning changes; a reader refuses a
#: version it does not know rather than guessing.
PACK_FORMAT: Final = "arachne-content-pack/1"

#: Member name of the detached signature inside the archive.
PACK_SIGNATURE_NAME: Final = "manifest.sig"
MANIFEST_NAME: Final = "manifest.json"
CONTENT_PREFIX: Final = "content/"

#: Signature domain: a pack signature cannot be replayed as a finding or audit signature.
PACK_DOMAIN: Final = "arachne.content-pack"

#: A pack is an operator-carried artifact, not a bulk transfer format; the cap keeps a
#: hostile or accidental archive from exhausting memory before it is even verified.
MAX_PACK_BYTES: Final = 512 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class PackFile:
    """One file in a pack: where it goes and what it must hash to."""

    path: str
    sha256: str
    size: int
    kind: str = "content"

    def to_dict(self) -> dict[str, Any]:
        return {"path": self.path, "sha256": self.sha256, "size": self.size, "kind": self.kind}


@dataclass(frozen=True, slots=True)
class PackManifest:
    """A pack's contents and provenance (the part the signature covers)."""

    name: str
    version: str
    files: tuple[PackFile, ...]
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    format: str = PACK_FORMAT
    generator: str = "arachne"
    notes: str | None = None
    meta: dict[str, Any] = field(default_factory=dict)

    @property
    def digest(self) -> str:
        """SHA-256 of the canonical manifest — what the signature is over."""
        return pack_digest(self)

    def kinds(self) -> dict[str, int]:
        """How many files of each kind the pack carries (the provenance summary)."""
        counts: dict[str, int] = {}
        for item in self.files:
            counts[item.kind] = counts.get(item.kind, 0) + 1
        return counts

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": self.format,
            "name": self.name,
            "version": self.version,
            "created_at": self.created_at,
            "generator": self.generator,
            "notes": self.notes,
            "meta": self.meta,
            "files": [item.to_dict() for item in self.files],
        }

    @classmethod
    def from_dict(cls, data: Any) -> PackManifest:
        if not isinstance(data, Mapping):
            msg = "a content pack manifest must be a JSON object"
            raise ContentPackError(msg)
        if data.get("format") != PACK_FORMAT:
            msg = (
                f"unsupported content pack format {data.get('format')!r} "
                f"(this build understands {PACK_FORMAT})"
            )
            raise ContentPackError(msg)
        name = str(data.get("name") or "").strip()
        version = str(data.get("version") or "").strip()
        if not name or not version:
            msg = "a content pack manifest needs a name and a version"
            raise ContentPackError(msg)
        raw_files = data.get("files")
        if not isinstance(raw_files, list) or not raw_files:
            msg = "a content pack manifest needs a non-empty 'files' list"
            raise ContentPackError(msg)
        files: list[PackFile] = []
        for entry in raw_files:
            if not isinstance(entry, Mapping):
                msg = "every manifest file entry must be an object"
                raise ContentPackError(msg)
            files.append(
                PackFile(
                    path=str(entry.get("path") or ""),
                    sha256=str(entry.get("sha256") or ""),
                    size=int(entry.get("size") or 0),
                    kind=str(entry.get("kind") or "content"),
                )
            )
        meta = data.get("meta")
        return cls(
            name=name,
            version=version,
            files=tuple(files),
            created_at=str(data.get("created_at") or datetime.now(UTC).isoformat()),
            generator=str(data.get("generator") or "arachne"),
            notes=(str(data["notes"]) if data.get("notes") is not None else None),
            meta=dict(meta) if isinstance(meta, Mapping) else {},
        )


@dataclass(frozen=True, slots=True)
class ContentPack:
    """A verified pack: its manifest, its files' bytes and the key that signed it."""

    manifest: PackManifest
    files: Mapping[str, bytes]
    signature: str | None
    key_id: str | None
    source: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "manifest": self.manifest.to_dict(),
            "digest": self.manifest.digest,
            "signature": self.signature,
            "key_id": self.key_id,
            "source": self.source,
        }


def pack_digest(manifest: PackManifest) -> str:
    """SHA-256 of the manifest's canonical form (what a signature is over)."""
    return hashlib.sha256(canonical_bytes(manifest.to_dict())).hexdigest()


# --------------------------------------------------------------------------- building
def build_pack(
    roots: Mapping[str, str | Path],
    *,
    name: str,
    version: str,
    signer: DeploymentSigner | None = None,
    notes: str | None = None,
    meta: Mapping[str, Any] | None = None,
    exclude: Iterable[str] = (),
) -> tuple[bytes, PackManifest, str | None]:
    """Build a pack from ``{kind: directory}`` roots.

    Returns ``(archive bytes, manifest, signature)``. ``signer=None`` produces an unsigned
    pack; ``read_pack`` then refuses it unless the importer opts in, which is the intended
    asymmetry — building is a local act, importing is the one that trusts.
    """
    skip = set(exclude)
    entries: list[tuple[str, str, Path]] = []
    seen: set[str] = set()
    for kind, root in sorted(roots.items()):
        base = Path(root)
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*")):
            if not path.is_file() or path.is_symlink():
                continue
            relative = path.relative_to(base).as_posix()
            if relative in skip:
                continue
            member = f"{kind}/{relative}"
            if member in seen:  # pragma: no cover - two roots with the same relative path
                msg = f"two roots contribute {member!r}; pack members must be unique"
                raise ContentPackError(msg)
            seen.add(member)
            entries.append((member, kind, path))

    files: list[PackFile] = []
    payload: dict[str, bytes] = {}
    for member, kind, path in entries:
        data = path.read_bytes()
        member_path = f"{CONTENT_PREFIX}{member}"
        files.append(
            PackFile(
                path=member_path,
                sha256=hashlib.sha256(data).hexdigest(),
                size=len(data),
                kind=kind,
            )
        )
        payload[member_path] = data

    manifest = PackManifest(
        name=name,
        version=version,
        files=tuple(files),
        notes=notes,
        meta=dict(meta or {}),
    )
    signature = (
        signer.sign(PACK_DOMAIN, manifest.digest.encode("ascii")) if signer is not None else None
    )
    archive = _write_archive(manifest, payload, signature)
    return archive, manifest, signature


def write_pack(
    path: str | Path,
    roots: Mapping[str, str | Path],
    *,
    name: str,
    version: str,
    signer: DeploymentSigner | None = None,
    notes: str | None = None,
    meta: Mapping[str, Any] | None = None,
) -> tuple[Path, PackManifest]:
    """Build a pack and write it to ``path`` (write-then-rename, so a failure leaves none)."""
    archive, manifest, _ = build_pack(
        roots, name=name, version=version, signer=signer, notes=notes, meta=meta
    )
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(target.name + ".tmp")
    temporary.write_bytes(archive)
    temporary.replace(target)
    return target, manifest


def _write_archive(
    manifest: PackManifest, payload: Mapping[str, bytes], signature: str | None
) -> bytes:
    buffer = io.BytesIO()
    manifest_bytes = canonical_bytes(manifest.to_dict())
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        _add_bytes(archive, MANIFEST_NAME, manifest_bytes)
        if signature is not None:
            _add_bytes(archive, PACK_SIGNATURE_NAME, signature.encode("ascii"))
        for member in sorted(payload):
            _add_bytes(archive, member, payload[member])
    return buffer.getvalue()


def _add_bytes(archive: tarfile.TarFile, name: str, data: bytes) -> None:
    info = tarfile.TarInfo(name=name)
    info.size = len(data)
    info.mtime = 0  # deterministic archives: the same content packs to the same bytes
    info.mode = 0o644
    archive.addfile(info, io.BytesIO(data))


# --------------------------------------------------------------------------- reading
def read_pack(
    data: bytes,
    *,
    signer: DeploymentSigner | None = None,
    require_signature: bool = True,
    source: str | None = None,
) -> ContentPack:
    """Verify a pack and return it, or raise :class:`ContentPackError`.

    The order matters: the manifest is parsed and its signature checked **before** any
    member is read, and every member's digest is checked before the pack is returned. A
    failure at any step means the caller receives nothing.
    """
    if len(data) > MAX_PACK_BYTES:
        msg = f"content pack is larger than the {MAX_PACK_BYTES} byte limit"
        raise ContentPackError(msg)
    members = _read_members(data)
    raw_manifest = members.get(MANIFEST_NAME)
    if raw_manifest is None:
        msg = "the archive has no manifest.json: not a content pack"
        raise ContentPackError(msg)
    try:
        manifest = PackManifest.from_dict(json.loads(raw_manifest.decode("utf-8")))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        msg = f"the pack manifest is not valid JSON: {exc}"
        raise ContentPackError(msg) from exc
    signature = None
    if PACK_SIGNATURE_NAME in members:
        signature = members[PACK_SIGNATURE_NAME].decode("ascii", errors="replace").strip()
    if require_signature:
        if signer is None:
            msg = (
                "this pack must be signature-verified but no content key is configured "
                "(ARACHNE_INTEGRITY_KEY); set the key or pass --allow-unsigned to accept it"
            )
            raise ContentPackError(msg)
        if not signer.verify(PACK_DOMAIN, manifest.digest.encode("ascii"), signature):
            msg = (
                "the content pack signature does not verify against the deployment's "
                "content key: the manifest was edited, or the pack was signed elsewhere"
            )
            raise ContentPackError(msg)
    files: dict[str, bytes] = {}
    declared = {item.path: item for item in manifest.files}
    for name, item in declared.items():
        _require_safe_member(name)
        raw = members.get(name)
        if raw is None:
            msg = f"the pack is missing the file its manifest declares: {name}"
            raise ContentPackError(msg)
        digest = hashlib.sha256(raw).hexdigest()
        if digest != item.sha256 or len(raw) != item.size:
            msg = (
                f"the pack's {name} does not match its manifest "
                f"(expected {item.sha256[:16]}…/{item.size} bytes, "
                f"got {digest[:16]}…/{len(raw)} bytes)"
            )
            raise ContentPackError(msg)
        files[name] = raw
    extra = set(members) - {MANIFEST_NAME, PACK_SIGNATURE_NAME} - set(declared)
    if extra:
        msg = f"the pack carries files its manifest does not declare: {sorted(extra)[:5]}"
        raise ContentPackError(msg)
    return ContentPack(
        manifest=manifest,
        files=files,
        signature=signature,
        key_id=_key_id_of(signature),
        source=source,
    )


def read_pack_file(
    path: str | Path,
    *,
    signer: DeploymentSigner | None = None,
    require_signature: bool = True,
) -> ContentPack:
    """Read and verify a pack from disk."""
    resolved = Path(path)
    try:
        data = resolved.read_bytes()
    except OSError as exc:
        msg = f"cannot read content pack {resolved}: {exc}"
        raise ContentPackError(msg) from exc
    return read_pack(
        data, signer=signer, require_signature=require_signature, source=str(resolved)
    )


def _read_members(data: bytes) -> dict[str, bytes]:
    members: dict[str, bytes] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            for info in archive.getmembers():
                if info.isdir():
                    continue
                if not info.isfile():
                    msg = f"the pack member {info.name!r} is not a regular file"
                    raise ContentPackError(msg)
                _require_safe_member(info.name)
                handle = archive.extractfile(info)
                members[info.name] = handle.read() if handle is not None else b""
    except (tarfile.TarError, EOFError, OSError, zlib.error) as exc:
        # ``EOFError``/``zlib.error`` are how a *truncated* gzip surfaces: a pack that lost
        # bytes must be a clean refusal, not an unhandled crash, because "the carrier ate the
        # file" is a normal way for an offline transfer to fail.
        msg = f"the content pack is not a readable gzip tar archive: {exc}"
        raise ContentPackError(msg) from exc
    return members


def _require_safe_member(name: str) -> None:
    """Refuse an archive member that could escape the content directory.

    An archive is untrusted input, so this runs on import even though a pack built by
    :func:`build_pack` could never produce such a name — the pack that matters is the one
    somebody else built.
    """
    candidate = PurePosixPath(name)
    if candidate.is_absolute() or name.startswith("/") or ".." in candidate.parts:
        msg = f"the pack member {name!r} escapes the content directory"
        raise ContentPackError(msg)
    if not name.startswith(CONTENT_PREFIX) and name not in (MANIFEST_NAME, PACK_SIGNATURE_NAME):
        msg = f"the pack member {name!r} is outside {CONTENT_PREFIX}"
        raise ContentPackError(msg)


def _key_id_of(signature: str | None) -> str | None:
    if not signature:
        return None
    parts = signature.split(":")
    return parts[1] if len(parts) == 3 else None


# --------------------------------------------------------------------------- installing
@dataclass(frozen=True, slots=True)
class InstallResult:
    """What one import put on disk."""

    name: str
    version: str
    digest: str
    key_id: str | None
    installed: tuple[str, ...]
    directory: Path
    kinds: dict[str, int]

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "digest": self.digest,
            "key_id": self.key_id,
            "installed": list(self.installed),
            "directory": str(self.directory),
            "kinds": dict(self.kinds),
        }


def install_pack(
    pack: ContentPack,
    *,
    content_dir: str | Path,
    replace: bool = True,
) -> InstallResult:
    """Unpack a *verified* pack into ``content_dir/<name>/<version>``.

    Staged then moved: every file is written into ``<dest>.staging`` first and the directory
    is renamed into place at the end, so an interrupted import leaves either the previous
    version or nothing — never a half-installed tree that a later scan would load.
    """
    base = Path(content_dir).expanduser()
    destination = base / _safe_segment(pack.manifest.name) / _safe_segment(pack.manifest.version)
    if destination.exists() and not replace:
        msg = f"{destination} is already installed; pass replace=True to overwrite it"
        raise ContentPackError(msg)
    staging = destination.with_name(destination.name + ".staging")
    if staging.exists():
        _remove_tree(staging)
    staging.mkdir(parents=True, exist_ok=True)
    installed: list[str] = []
    try:
        for name, data in sorted(pack.files.items()):
            relative = PurePosixPath(name).relative_to(CONTENT_PREFIX)
            target = staging.joinpath(*relative.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            installed.append(str(relative))
        manifest_path = staging / MANIFEST_NAME
        manifest_path.write_bytes(canonical_bytes(pack.manifest.to_dict()))
        if pack.signature is not None:
            (staging / PACK_SIGNATURE_NAME).write_text(pack.signature + "\n", encoding="ascii")
    except OSError as exc:
        _remove_tree(staging)
        msg = f"could not unpack the pack into {staging}: {exc}"
        raise ContentPackError(msg) from exc
    if destination.exists():
        _remove_tree(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    staging.replace(destination)
    return InstallResult(
        name=pack.manifest.name,
        version=pack.manifest.version,
        digest=pack.manifest.digest,
        key_id=pack.key_id,
        installed=tuple(installed),
        directory=destination,
        kinds=pack.manifest.kinds(),
    )


def installed_packs(content_dir: str | Path) -> tuple[dict[str, Any], ...]:
    """Every installed pack, newest directory name last (an operator's inventory)."""
    base = Path(content_dir).expanduser()
    if not base.is_dir():
        return ()
    found: list[dict[str, Any]] = []
    for manifest_path in sorted(base.glob(f"*/*/{MANIFEST_NAME}")):
        if ".staging" in manifest_path.parts:
            continue
        try:
            data = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):  # pragma: no cover - a hand-edited tree
            continue
        signature_path = manifest_path.with_name(PACK_SIGNATURE_NAME)
        signature = (
            signature_path.read_text(encoding="ascii").strip()
            if signature_path.is_file()
            else None
        )
        found.append(
            {
                "name": data.get("name"),
                "version": data.get("version"),
                "created_at": data.get("created_at"),
                "files": len(data.get("files") or []),
                "signature": signature,
                "key_id": _key_id_of(signature),
                "directory": str(manifest_path.parent),
            }
        )
    return tuple(found)


def _safe_segment(value: str) -> str:
    """A pack name/version as a single, safe path segment."""
    cleaned = "".join(char if char.isalnum() or char in "._-" else "-" for char in value.strip())
    if not cleaned or cleaned in {".", ".."}:
        msg = f"unsafe pack name or version: {value!r}"
        raise ContentPackError(msg)
    return cleaned


def _remove_tree(path: Path) -> None:
    import shutil

    shutil.rmtree(path, ignore_errors=True)


def pack_report(pack: ContentPack, *, installed: Sequence[str] = ()) -> dict[str, Any]:
    """A one-object summary an operator (or the audit trail) can record."""
    payload = pack.to_dict()
    payload["verified"] = pack.signature is not None
    payload["installed"] = list(installed)
    return payload
