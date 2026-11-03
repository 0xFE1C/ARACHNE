"""Native container-image scanning (WP-12, REQ-DET-016).

Before this module the product could list an anonymous registry catalog and could review a
lockfile, but it could not read an *image*: an image reference was delegated to an external
converter/scanner that had to be installed and switched on, which an air-gapped deployment
cannot do. ``m5.image-scan`` closes that gap with no external process and no network beyond
the registry already in scope:

1. **Resolve** — ``GET /v2/<repo>/manifests/<ref>`` with the OCI/Docker media types. A
   manifest list/index is followed exactly one level (its first platform manifest); a nested
   index is refused rather than chased.
2. **Fetch** — ``GET /v2/<repo>/blobs/<digest>`` for each layer descriptor, through the
   shared scoped client (scope validation, rate limit, audit — every byte). The blob's
   ``sha256`` digest is verified before it is read, so a tampered layer is refused.
3. **Unpack** — into a private temporary directory, never the workspace, with the blob
   treated as hostile: a header-only validation pass first (types, paths, member count,
   declared size), then an all-or-nothing extraction. Any symlink, hardlink, device node or
   FIFO refuses the whole layer; any absolute path or ``..`` component refuses it; a
   cumulative unpacked size over :attr:`M5Settings.image_max_unpacked_bytes` refuses it. The
   image and its contents are never executed.
4. **Read packages** — the dpkg status file, the apk installed DB, Python ``dist-info``
   metadata and npm ``package.json`` files. A distroless image has none of these and is a
   valid, empty result.
5. **Match advisories** — the offline index in ``templates/m5/probes.yaml``. Each finding
   carries the package name, installed version, fixed version and advisory id.

The external scanner is still available, but it is no longer the default and it is not
allowed to fetch anything: when ``ARACHNE_M5_REGISTRY_SCAN`` is on, ``ARACHNE_M5_SBOM_TOOL``
names a known tool and ``ARACHNE_M5_SBOM_REPORT`` names a report file, the report that tool
produced out of band is merged into these findings
(:mod:`arachne.modules.m5.external_sbom`). The file is read, never executed; a tool launched
here would be a second, unaudited network client, which is precisely the property this work
package must not lose.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import re
import shutil
import tarfile
import tempfile
from collections.abc import AsyncIterator, Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Final, cast

from arachne.core.results import CheckResult
from arachne.core.target import TargetKind
from arachne.modules.base import CheckMetadata, Module
from arachne.modules.context import CheckContext
from arachne.modules.m5.corpus import VulnerableComponent
from arachne.modules.m5.external_sbom import load_external_report
from arachne.modules.m5.support import (
    EndpointCheck,
    corpus_for,
    fetch_page,
    finding_cap,
    m5_candidate,
    skip,
)

__all__ = [
    "ArchiveRefusedError",
    "ImageReference",
    "ImageScan",
    "InstalledPackage",
    "UnpackBudget",
    "UnpackResult",
    "advisory_id",
    "match_advisories",
    "parse_image_reference",
    "read_packages",
    "unpack_layer",
]

#: The image-reference prefixes a target may use. ``registry:`` is shared with the catalog
#: check; an image reference is distinguished by containing a repository path and a tag or
#: digest (``registry:host:5000/app:1.2.3``).
_IMAGE_PROVIDERS: Final[frozenset[str]] = frozenset({"image", "registry", "docker", "containerd"})

#: A registry blob digest the scanner will fetch. Anything else is refused before a request.
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_HOST = re.compile(r"^[A-Za-z0-9._\[\]:-]+$")

#: Advisories are matched on the numeric component of a version. Distro revisions, epochs and
#: ``~`` pre-release markers are not part of the upstream comparison the index records.
_VERSION_PART = re.compile(r"(\d+(?:\.\d+)*)")

#: How much of one metadata file the package reader will read.
_METADATA_LIMIT: Final = 262_144

#: How many metadata files (dist-info / node package.json) one image may contribute.
_MAX_METADATA_FILES: Final = 2_000


# --------------------------------------------------------------------------- reference
@dataclass(frozen=True, slots=True)
class ImageReference:
    """A registry, repository and tag/digest — everything needed to form the two URLs."""

    registry: str
    repository: str
    reference: str

    @property
    def base_url(self) -> str:
        """``http`` for a loopback registry (the lab), ``https`` otherwise."""
        host = self.registry.rsplit(":", 1)[0] if self.registry.count(":") == 1 else self.registry
        scheme = "http" if host in {"127.0.0.1", "::1", "localhost"} else "https"
        return f"{scheme}://{self.registry}"

    def manifest_url(self, reference: str | None = None) -> str:
        target = self.reference if reference is None else reference
        return f"{self.base_url}/v2/{self.repository}/manifests/{target}"

    def blob_url(self, digest: str) -> str:
        return f"{self.base_url}/v2/{self.repository}/blobs/{digest}"

    def label(self) -> str:
        return f"{self.registry}/{self.repository}:{self.reference}"


def parse_image_reference(value: str) -> ImageReference | None:
    """Parse ``image:``/``registry:``/``docker:`` ``host[:port]/repo[:tag|@digest]``.

    ``None`` means the asset names no image. A repository without a tag resolves to
    ``latest``, exactly as a container runtime would. The registry is *not* defaulted: an
    image reference with no registry is refused rather than sent to Docker Hub, because the
    registry has to be in scope like any other host.
    """
    text = value.strip()
    provider, separator, rest = text.partition(":")
    if not separator or provider.lower() not in _IMAGE_PROVIDERS:
        return None
    registry, slash, remainder = rest.partition("/")
    if not slash or not registry or not remainder:
        return None
    if not _HOST.match(registry):
        return None
    repository, reference = _split_reference(remainder)
    if not repository or not reference:
        return None
    return ImageReference(registry=registry, repository=repository, reference=reference)


def _split_reference(remainder: str) -> tuple[str, str]:
    if "@" in remainder:
        repository, _, digest = remainder.partition("@")
        return repository.strip("/"), digest
    if "/" in remainder:
        head, last = remainder.rsplit("/", 1)
        if ":" in last:
            repository, _, tag = last.partition(":")
            return f"{head}/{repository}".strip("/"), tag
        return remainder.strip("/"), "latest"
    if ":" in remainder:
        repository, _, tag = remainder.partition(":")
        return repository.strip("/"), tag
    return remainder.strip("/"), "latest"


# --------------------------------------------------------------------------- unpacking
class ArchiveRefusedError(Exception):
    """A layer that must not be unpacked. Never a crash: the check records the reason."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True, slots=True)
class UnpackResult:
    """What one layer contributed, and why anything in it was refused."""

    files: int = 0
    directories: int = 0
    bytes_written: int = 0
    refused: str | None = None

    @property
    def ok(self) -> bool:
        return self.refused is None


@dataclass
class UnpackBudget:
    """The shared cap across every layer of one image (a bomb can be spread over layers)."""

    max_unpacked_bytes: int
    max_file_bytes: int
    max_members: int
    used_bytes: int = 0
    used_members: int = 0


def unpack_layer(
    blob: bytes,
    media_type: str,
    root: Path,
    *,
    max_unpacked_bytes: int,
    max_file_bytes: int,
    max_members: int,
    budget: UnpackBudget | None = None,
) -> UnpackResult:
    """Unpack one layer into ``root`` (a temporary directory), or refuse it.

    The function is deliberately all-or-nothing: it validates every header first (type, path,
    declared size, member count), so a hostile layer cannot leave half its content behind
    before the offending member is found. Only regular files and directories are written;
    modes, owners, timestamps, extended attributes and links are never applied.
    """
    if not blob:
        return UnpackResult(refused="empty layer")
    data = _decompress(blob, media_type)
    shared = (
        budget
        if budget is not None
        else UnpackBudget(max_unpacked_bytes, max_file_bytes, max_members)
    )

    try:
        # The handle is entered by the ``with`` below; the try only translates a header
        # error into a refusal, so it must be opened before the context is established.
        archive = tarfile.open(  # noqa: SIM115
            fileobj=io.BytesIO(data), mode="r:"
        )
    except (tarfile.TarError, OSError) as exc:
        raise ArchiveRefusedError(f"not a readable tar layer: {exc}") from exc

    members: list[tarfile.TarInfo] = []
    with archive:
        try:
            for member in archive:
                if len(members) >= max_members:
                    raise ArchiveRefusedError(
                        f"layer declares more than {max_members} archive members"
                    )
                members.append(member)
        except (tarfile.TarError, OSError) as exc:
            raise ArchiveRefusedError(f"unreadable tar header: {exc}") from exc

        _validate_members(members, max_file_bytes, shared)
        written = 0
        directories = 0
        total = 0
        for member in members:
            relative = _safe_member_path(member.name)
            target = root.joinpath(*relative.parts) if relative.parts else root
            if not _inside(root, target):
                raise ArchiveRefusedError(f"member {member.name!r} escapes the unpack root")
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                directories += 1
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            total += _write_member(archive, member, target, max_file_bytes)
            written += 1
    shared.used_bytes += total
    shared.used_members += len(members)
    return UnpackResult(files=written, directories=directories, bytes_written=total)


def _decompress(blob: bytes, media_type: str) -> bytes:
    """Gunzip a gzip layer; refuse a compression the standard library cannot read."""
    lowered = media_type.lower()
    if "zstd" in lowered or "zstandard" in lowered:
        raise ArchiveRefusedError("zstd-compressed layer: unsupported format (no external process)")
    if "gzip" in lowered or blob[:2] == b"\x1f\x8b":
        try:
            with gzip.GzipFile(fileobj=io.BytesIO(blob)) as stream:
                return stream.read()
        except (OSError, EOFError) as exc:
            raise ArchiveRefusedError(f"corrupt gzip layer: {exc}") from exc
    return blob


def _validate_members(
    members: Sequence[tarfile.TarInfo], max_file_bytes: int, budget: UnpackBudget
) -> None:
    declared = 0
    if budget.used_members + len(members) > budget.max_members:
        raise ArchiveRefusedError(f"unpacked content exceeds the {budget.max_members}-member cap")
    for member in members:
        if not (member.isreg() or member.isdir()):
            raise ArchiveRefusedError(
                f"layer contains a link or special file ({member.name!r}): refused"
            )
        _safe_member_path(member.name)
        if member.isreg():
            if member.size < 0 or member.size > max_file_bytes:
                raise ArchiveRefusedError(
                    f"member {member.name!r} is {member.size} bytes, above the "
                    f"{max_file_bytes}-byte file cap"
                )
            declared += member.size
            if budget.used_bytes + declared > budget.max_unpacked_bytes:
                raise ArchiveRefusedError(
                    f"unpacked content exceeds the {budget.max_unpacked_bytes}-byte cap"
                )


def _safe_member_path(name: str) -> PurePosixPath:
    """A member name that cannot leave the root, or :class:`ArchiveRefusedError`."""
    if not name or "\x00" in name:
        raise ArchiveRefusedError("layer member has an empty or NUL-containing name")
    path = PurePosixPath(name)
    if path.is_absolute():
        raise ArchiveRefusedError(f"layer member {name!r} uses an absolute path")
    parts = tuple(part for part in path.parts if part not in {"", "."})
    if any(part == ".." for part in parts):
        raise ArchiveRefusedError(f"layer member {name!r} contains a '..' component")
    return PurePosixPath(*parts)


def _inside(root: Path, target: Path) -> bool:
    try:
        root_resolved = root.resolve()
        target_resolved = target.resolve()
    except OSError:  # pragma: no cover - an unresolvable path is not trusted
        return False
    return target_resolved == root_resolved or root_resolved in target_resolved.parents


def _write_member(archive: tarfile.TarFile, member: tarfile.TarInfo, target: Path, cap: int) -> int:
    """Write one regular member without following anything and without its metadata."""
    source = archive.extractfile(member)
    if source is None:
        raise ArchiveRefusedError(f"member {member.name!r} has no readable content")
    written = 0
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(target, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            while True:
                chunk = source.read(65_536)
                if not chunk:
                    break
                written += len(chunk)
                if written > cap:
                    raise ArchiveRefusedError(
                        f"member {member.name!r} exceeds the {cap}-byte file cap"
                    )
                handle.write(chunk)
    finally:
        source.close()
    return written


# --------------------------------------------------------------------------- packages
@dataclass(frozen=True, slots=True)
class InstalledPackage:
    """One package read from the unpacked image."""

    name: str
    version: str
    ecosystem: str
    location: str


def read_packages(root: Path) -> tuple[InstalledPackage, ...]:
    """Read the package databases and language metadata under ``root`` (bounded)."""
    found: dict[tuple[str, str, str], InstalledPackage] = {}
    for package in _dpkg_packages(root) + _apk_packages(root):
        found.setdefault((package.name.lower(), package.version, package.ecosystem), package)
    for package in _python_packages(root) + _npm_packages(root):
        found.setdefault((package.name.lower(), package.version, package.ecosystem), package)
    return tuple(found.values())


def _read_text(path: Path, *, limit: int = _METADATA_LIMIT) -> str | None:
    try:
        data = path.read_bytes()[:limit]
    except OSError:
        return None
    if b"\x00" in data[:1024]:
        return None
    return data.decode("utf-8", "replace")


def _dpkg_packages(root: Path) -> list[InstalledPackage]:
    path = root / "var" / "lib" / "dpkg" / "status"
    text = _read_text(path)
    if text is None:
        return []
    out: list[InstalledPackage] = []
    for block in text.split("\n\n"):
        fields: dict[str, str] = {}
        key: str | None = None
        for line in block.splitlines():
            if line.startswith((" ", "\t")) and key is not None:
                fields[key] += " " + line.strip()
                continue
            name, separator, value = line.partition(":")
            if not separator:
                continue
            key = name.strip()
            fields[key] = value.strip()
        name = fields.get("Package", "")
        version = fields.get("Version", "")
        status = fields.get("Status", "")
        if not name or not version:
            continue
        if status and not status.endswith("installed"):
            continue
        out.append(
            InstalledPackage(
                name=name,
                version=version,
                ecosystem="deb",
                location="var/lib/dpkg/status",
            )
        )
    return out


def _apk_packages(root: Path) -> list[InstalledPackage]:
    path = root / "lib" / "apk" / "db" / "installed"
    text = _read_text(path)
    if text is None:
        return []
    out: list[InstalledPackage] = []
    for block in text.split("\n\n"):
        fields: dict[str, str] = {}
        for line in block.splitlines():
            if len(line) > 2 and line[1] == ":":
                fields[line[0]] = line[2:].strip()
        name = fields.get("P", "")
        version = fields.get("V", "")
        if name and version:
            out.append(
                InstalledPackage(
                    name=name,
                    version=version,
                    ecosystem="apk",
                    location="lib/apk/db/installed",
                )
            )
    return out


def _python_packages(root: Path) -> list[InstalledPackage]:
    out: list[InstalledPackage] = []
    for directory in _bounded_rglob(root, "*.dist-info", _MAX_METADATA_FILES):
        metadata = directory / "METADATA"
        text = _read_text(metadata)
        if text is None:
            continue
        fields: dict[str, str] = {}
        for line in text.splitlines():
            if not line.strip():
                break
            name, separator, value = line.partition(":")
            if separator:
                fields[name.strip().lower()] = value.strip()
        name = fields.get("name", "")
        version = fields.get("version", "")
        if name and version:
            out.append(
                InstalledPackage(
                    name=name,
                    version=version,
                    ecosystem="pypi",
                    location=_relative(directory, root),
                )
            )
    return out


def _npm_packages(root: Path) -> list[InstalledPackage]:
    out: list[InstalledPackage] = []
    for path in _bounded_rglob(root, "package.json", _MAX_METADATA_FILES):
        lowered = path.as_posix().lower()
        if "node_modules" not in lowered:
            continue
        text = _read_text(path)
        if text is None:
            continue
        try:
            document = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            continue
        if not isinstance(document, Mapping):
            continue
        name = str(document.get("name", ""))
        version = str(document.get("version", ""))
        if name and version:
            out.append(
                InstalledPackage(
                    name=name,
                    version=version,
                    ecosystem="npm",
                    location=_relative(path, root),
                )
            )
    return out


def _bounded_rglob(root: Path, pattern: str, limit: int) -> tuple[Path, ...]:
    found: list[Path] = []
    if not root.is_dir():
        return ()
    for path in root.rglob(pattern):
        if len(found) >= limit:
            break
        found.append(path)
    return tuple(found)


def _relative(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:  # pragma: no cover - every walk starts at root
        return path.as_posix()


# --------------------------------------------------------------------------- advisories
def match_advisories(
    packages: Iterable[InstalledPackage], advisories: Iterable[VulnerableComponent]
) -> tuple[tuple[InstalledPackage, VulnerableComponent], ...]:
    """Every ``(package, advisory)`` pair where the installed version is below the fix."""
    by_name: dict[str, list[InstalledPackage]] = {}
    for package in packages:
        by_name.setdefault(package.name.lower(), []).append(package)
    matched: list[tuple[InstalledPackage, VulnerableComponent]] = []
    for advisory in advisories:
        for package in by_name.get(advisory.name.lower(), ()):
            if _version_key(package.version) < _version_key(advisory.below):
                matched.append((package, advisory))
    return tuple(matched)


def _version_key(version: str) -> tuple[int, ...]:
    """A tolerant upstream version key: digits only, epoch-aware, distro suffix dropped."""
    epoch = 0
    text = version.strip()
    if ":" in text:
        head, _, text = text.partition(":")
        if head.isdigit():
            epoch = int(head)
    upstream = text.split("-", 1)[0].split("~", 1)[0]
    match = _VERSION_PART.search(upstream)
    if match is None:
        return (epoch, 0)
    return (epoch, *(int(part) for part in match.group(1).split(".")))


def advisory_id(advisory: VulnerableComponent) -> str:
    """The advisory id a finding carries: the vendor id when present, the CVE otherwise."""
    return advisory.advisory or advisory.cve


# --------------------------------------------------------------------------- manifests
@dataclass(frozen=True, slots=True)
class _Manifest:
    digest: str
    layers: tuple[tuple[str, str, int], ...]  # (media_type, digest, declared size)


async def _fetch_manifest(
    ctx: CheckContext, url: str, accept: str
) -> tuple[dict[str, Any] | None, str, str]:
    """Fetch one manifest; return ``(document, error, digest of the served bytes)``."""
    page = await fetch_page(ctx, url, headers={"Accept": accept}, session=False)
    if page is None:
        return None, "the manifest request was refused or failed", ""
    if page.status != 200:
        return None, f"the registry answered {page.status} for the manifest", ""
    digest = "sha256:" + hashlib.sha256(page.body.encode("utf-8")).hexdigest()
    try:
        document = json.loads(page.body)
    except (json.JSONDecodeError, ValueError):
        return None, "the registry returned a manifest that is not JSON", ""
    if not isinstance(document, Mapping):
        return None, "the registry returned a manifest that is not an object", ""
    return dict(document), "", digest


async def _resolve_manifest(
    ctx: CheckContext, reference: ImageReference, accept: str
) -> tuple[_Manifest | None, str]:
    """Resolve an image to a manifest; follow one index level, never two."""
    document, error, digest = await _fetch_manifest(ctx, reference.manifest_url(), accept)
    if document is None:
        return None, error
    children = document.get("manifests")
    if isinstance(children, list):
        descriptor = _pick_descriptor(children)
        if descriptor is None:
            return None, "the manifest list names no platform manifest"
        child_digest = descriptor.get("digest")
        if not isinstance(child_digest, str) or not _DIGEST.match(child_digest):
            return None, "the manifest list names an invalid child digest"
        document, error, child_served = await _fetch_manifest(
            ctx, reference.manifest_url(child_digest), accept
        )
        if document is None:
            return None, error
        if "manifests" in document:
            return None, "a nested manifest list is refused (one level only)"
        return _manifest_from(document, child_served or child_digest)
    return _manifest_from(document, digest)


def _pick_descriptor(descriptors: Sequence[Any]) -> Mapping[str, Any] | None:
    candidates = [item for item in descriptors if isinstance(item, Mapping)]
    if not candidates:
        return None
    for candidate in candidates:
        platform = candidate.get("platform")
        if isinstance(platform, Mapping) and platform.get("os") not in {None, "unknown"}:
            return candidate
    return candidates[0]


def _manifest_from(document: Mapping[str, Any], digest: str) -> tuple[_Manifest | None, str]:
    layers = document.get("layers")
    if not isinstance(layers, list):
        return None, "the manifest carries no layer list"
    resolved: list[tuple[str, str, int]] = []
    for layer in layers:
        if not isinstance(layer, Mapping):
            return None, "the manifest contains a malformed layer descriptor"
        media_type = str(layer.get("mediaType", ""))
        layer_digest = str(layer.get("digest", ""))
        size = layer.get("size")
        if not _DIGEST.match(layer_digest):
            return None, f"the manifest names an invalid layer digest {layer_digest!r}"
        if not isinstance(size, int) or size < 0:
            return None, f"the manifest names no valid size for {layer_digest}"
        resolved.append((media_type, layer_digest, size))
    return _Manifest(digest=digest, layers=tuple(resolved)), ""


# --------------------------------------------------------------------------- the check
class ImageScan(EndpointCheck, Module):
    """``m5.image-scan`` — native container image package/advisory scan (ch05#15)."""

    metadata = CheckMetadata(
        id="m5.image-scan",
        module="M5",
        name="image-scan",
        version="1.0",
        title="Container image carries known-vulnerable packages",
        description=(
            "Resolves a container image to its manifest, fetches the layers through the scoped "
            "client, unpacks them into a private temporary directory under a documented size "
            "cap, reads the dpkg/apk package databases and the Python/npm metadata, and matches "
            "them against the offline advisory index (research ch05#15; REQ-DET-016). The image "
            "and its contents are never executed. A distroless image is a valid empty result. "
            "The external Trivy/Grype-class scanner remains available as an opt-in over the "
            "already-unpacked root; it is never the default and never fetches the image itself."
        ),
        research_ref="ch05#15",
        framework=("WSTG-CONF-02", "API10:2023", "CWE-1104"),
        cwe="CWE-1104",
        target_kinds=(TargetKind.CLOUD, TargetKind.ARTIFACT),
        severity_hint="high",
        type="hybrid",
        safe=True,
        verifiable=True,
        estimated_requests=8,
        requires_active_checks=True,
        runs_on_discovered=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        reference = parse_image_reference(ctx.asset.value)
        if reference is None:
            yield skip(
                ctx,
                "no container image reference: declare image:<registry>/<repo>[:tag|@digest] "
                "(a bare repository is not sent to a default registry)",
            )
            return
        if not ctx.config.m5.image_scan:
            yield skip(
                ctx,
                "native image scanning is disabled (ARACHNE_M5_IMAGE_SCAN=false); the "
                "external scanner path is not a substitute because it needs the image pulled",
            )
            return
        if ctx.http is None:
            yield skip(
                ctx,
                "no HTTP client in this run: image scanning fetches the manifest and layers "
                "through the scoped client (a dry run sends nothing)",
            )
            return

        accept = ", ".join(corpus_for(ctx).image_media_types())
        manifest, error = await _resolve_manifest(ctx, reference, accept)
        if manifest is None:
            yield ctx.clean(
                f"Container image {reference.label()} could not be resolved",
                detail=error or "the registry returned no usable manifest",
            )
            return
        if len(manifest.layers) > ctx.config.m5.image_max_layers:
            yield skip(
                ctx,
                f"the image declares {len(manifest.layers)} layers, above the "
                f"{ctx.config.m5.image_max_layers}-layer cap",
            )
            return

        temp_root = Path(
            tempfile.mkdtemp(prefix="arachne-image-", dir=ctx.config.m5.image_temp_dir)
        )
        budget = UnpackBudget(
            max_unpacked_bytes=ctx.config.m5.image_max_unpacked_bytes,
            max_file_bytes=ctx.config.m5.image_max_file_bytes,
            max_members=ctx.config.m5.image_max_members,
        )
        layers: list[str] = []
        refused: list[str] = []
        try:
            for index, (media_type, layer_digest, declared) in enumerate(manifest.layers):
                if declared > ctx.config.m5.image_max_layer_bytes:
                    refused.append(
                        f"{layer_digest} declares {declared} bytes, above the "
                        f"{ctx.config.m5.image_max_layer_bytes}-byte layer cap"
                    )
                    continue
                blob = await self._fetch_blob(ctx, reference, layer_digest)
                if blob is None:
                    refused.append(f"{layer_digest} could not be fetched in scope")
                    continue
                layers.append(f"{layer_digest} {media_type} {len(blob)}b")
                try:
                    unpack_layer(
                        blob,
                        media_type,
                        temp_root,
                        max_unpacked_bytes=ctx.config.m5.image_max_unpacked_bytes,
                        max_file_bytes=ctx.config.m5.image_max_file_bytes,
                        max_members=ctx.config.m5.image_max_members,
                        budget=budget,
                    )
                except ArchiveRefusedError as exc:
                    refused.append(f"layer {index} ({layer_digest}): {exc.reason}")
            for reason in refused:
                yield ctx.info(
                    "Image layer refused",
                    detail=reason,
                    evidence=[
                        ctx.evidence(
                            "artifact",
                            {
                                "signal": "image-layer-refused",
                                "family": "image",
                                "image": reference.label(),
                                "reason": reason,
                            },
                            source=reference.label(),
                        )
                    ],
                )
            packages = read_packages(temp_root)
            advisories = corpus_for(ctx).image_vulnerable()
            matches = match_advisories(packages, advisories)
            external_findings: list[dict[str, str]] = []
            note = ""
            if ctx.config.m5.registry_scan and ctx.config.m5.sbom_tool:
                external_findings, note = load_external_report(
                    ctx.config.m5.sbom_tool, ctx.config.m5.sbom_report
                )
            if note:
                yield ctx.info("External image scanner", detail=note)
            yield ctx.info(
                "Container image resolved",
                detail=(
                    f"{reference.label()} -> {len(manifest.layers)} layer(s), "
                    f"{len(packages)} package(s), {budget.used_bytes} byte(s) unpacked"
                ),
                evidence=[
                    ctx.evidence(
                        "artifact",
                        {
                            "signal": "image-inventory",
                            "family": "image",
                            "image": reference.label(),
                            "manifest_digest": manifest.digest,
                            "layers": layers,
                            "package_count": len(packages),
                            "unpacked_bytes": budget.used_bytes,
                            "refused": refused,
                        },
                        source=reference.label(),
                    )
                ],
            )
            findings = 0
            for package, advisory in matches:
                findings += 1
                yield self._package_candidate(ctx, reference, package, advisory)
                if findings >= finding_cap(ctx):
                    return
            for item in external_findings:
                findings += 1
                yield self._external_candidate(ctx, reference, item)
                if findings >= finding_cap(ctx):
                    return
            if not findings:
                yield ctx.clean(
                    f"No known-vulnerable package in {reference.label()}",
                    detail=(
                        f"read {len(packages)} package(s) from {len(manifest.layers)} layer(s)"
                        if packages
                        else "the image declares no package database or language metadata "
                        "(a distroless/static image is a valid empty result)"
                    ),
                )
        finally:
            shutil.rmtree(temp_root, ignore_errors=True)

    async def _fetch_blob(
        self, ctx: CheckContext, reference: ImageReference, digest: str
    ) -> bytes | None:
        """Fetch one layer blob through the scoped client and verify its digest."""
        client = ctx.http
        if client is None:  # pragma: no cover - run() guards this
            return None
        try:
            exchange = await client.request_bytes(
                "GET",
                reference.blob_url(digest),
                max_bytes=ctx.config.m5.image_max_layer_bytes,
            )
        except Exception:  # a refused/failed layer is data, not a check failure
            return None
        payload = cast(bytes, exchange.content)
        if exchange.status_code != 200 or exchange.truncated:
            return None
        actual = "sha256:" + hashlib.sha256(payload).hexdigest()
        if actual != digest:
            return None
        return payload

    def _package_candidate(
        self,
        ctx: CheckContext,
        reference: ImageReference,
        package: InstalledPackage,
        advisory: VulnerableComponent,
    ) -> CheckResult:
        advisory_value = advisory_id(advisory)
        return m5_candidate(
            ctx,
            f"{package.name} {package.version} in {reference.label()} is below the fix",
            artifact={
                "signal": "image-vulnerable-package",
                "family": "image",
                "image": reference.label(),
                "package": package.name,
                "installed": package.version,
                "fixed": advisory.below,
                "advisory": advisory_value,
                "cve": advisory.cve,
                "ecosystem": package.ecosystem,
                "location": package.location,
                "severity_hint": advisory.severity,
            },
            confidence=0.8,
            detail=(
                f"{package.name} {package.version} in {reference.label()} is below "
                f"{advisory.below} ({advisory_value})"
            ),
            source=reference.label(),
        )

    def _external_candidate(
        self, ctx: CheckContext, reference: ImageReference, item: Mapping[str, str]
    ) -> CheckResult:
        return m5_candidate(
            ctx,
            f"{item['package']} {item['installed']} in {reference.label()} is below the fix",
            artifact={
                "signal": "image-vulnerable-package",
                "family": "image",
                "image": reference.label(),
                "package": item["package"],
                "installed": item["installed"],
                "fixed": item["fixed"],
                "advisory": item["advisory"],
                "cve": item["advisory"] if item["advisory"].startswith("CVE-") else "",
                "ecosystem": "external",
                "severity_hint": item.get("severity", "").lower() or "medium",
            },
            confidence=0.8,
            detail=(
                f"the external scanner reported {item['package']} {item['installed']} below "
                f"{item['fixed']} ({item['advisory']})"
            ),
            source=reference.label(),
        )
