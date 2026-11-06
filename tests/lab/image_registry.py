"""An in-process OCI registry fixture for the native image scanner (WP-12, REQ-DET-016).

The fixture serves real manifest and blob responses over loopback: an image is a manifest
with its own digest plus a digest-addressed blob map. That is the whole wire contract the
scanner uses (``GET /v2/<repo>/manifests/<ref>`` and ``GET /v2/<repo>/blobs/<digest>``), so
the acceptance test exercises the same code path a real registry would, offline and with no
container runtime installed.

Images are built with :func:`gzip_layer`, which creates a deterministic tar.gz from a mapping
of paths to content. The hostile image includes a symlink member on purpose: the scanner must
refuse the layer, and the test proves nothing was written through it.
"""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import tarfile
import threading
import urllib.parse
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

__all__ = [
    "ImageRegistry",
    "ImageSpec",
    "gzip_layer",
    "image_from_layers",
    "manifest_list",
    "start_image_registry",
]

MEDIA_TYPE_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
MEDIA_TYPE_INDEX = "application/vnd.oci.image.index.v1+json"
MEDIA_TYPE_LAYER = "application/vnd.oci.image.layer.v1.tar+gzip"


@dataclass(frozen=True, slots=True)
class ImageSpec:
    """One repository's manifests and blobs, addressed by digest."""

    manifests: dict[str, dict[str, Any]] = field(default_factory=dict)
    blobs: dict[str, bytes] = field(default_factory=dict)
    tags: dict[str, str] = field(default_factory=dict)


@dataclass
class ImageRegistry:
    """A running registry: its loopback base URL, the images and every request it answered."""

    port: int = 0
    base_url: str = ""
    repositories: dict[str, ImageSpec] = field(default_factory=dict)
    requests: list[str] = field(default_factory=list)

    def reference(self, repository: str, tag: str = "latest") -> str:
        """An ``image:`` asset value naming this registry/repository/tag."""
        return f"image:127.0.0.1:{self.port}/{repository}:{tag}"


def digest_of(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def gzip_layer(
    files: Mapping[str, bytes | str],
    *,
    symlinks: Mapping[str, str] | None = None,
) -> bytes:
    """A deterministic tar.gz layer from ``path -> content`` (plus optional symlinks)."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w") as archive:
        for path, content in files.items():
            payload = content.encode("utf-8") if isinstance(content, str) else content
            info = tarfile.TarInfo(path)
            info.size = len(payload)
            info.mode = 0o644
            info.mtime = 0
            archive.addfile(info, io.BytesIO(payload))
        for path, target in (symlinks or {}).items():
            info = tarfile.TarInfo(path)
            info.type = tarfile.SYMTYPE
            info.linkname = target
            info.mtime = 0
            archive.addfile(info)
    return gzip.compress(buffer.getvalue(), mtime=0)


def image_from_layers(layers: list[bytes], *, media_type: str = MEDIA_TYPE_LAYER) -> ImageSpec:
    """Build a manifest (and its blobs) from layer bytes."""
    spec = ImageSpec()
    descriptors: list[dict[str, Any]] = []
    for layer in layers:
        digest = digest_of(layer)
        spec.blobs[digest] = layer
        descriptors.append({"mediaType": media_type, "digest": digest, "size": len(layer)})
    document: dict[str, Any] = {
        "schemaVersion": 2,
        "mediaType": MEDIA_TYPE_MANIFEST,
        "config": {
            "mediaType": "application/vnd.oci.image.config.v1+json",
            "digest": digest_of(b"{}"),
            "size": 2,
        },
        "layers": descriptors,
    }
    spec.blobs[document["config"]["digest"]] = b"{}"
    raw = json.dumps(document, sort_keys=True).encode("utf-8")
    digest = digest_of(raw)
    spec.manifests[digest] = document
    spec.tags["latest"] = digest
    return spec


def manifest_list(child: ImageSpec, *, tag: str = "latest") -> dict[str, Any]:
    """An index pointing at ``child``'s manifest, which the scanner follows one level."""
    child_digest = child.tags[tag]
    return {
        "schemaVersion": 2,
        "mediaType": MEDIA_TYPE_INDEX,
        "manifests": [
            {
                "mediaType": MEDIA_TYPE_MANIFEST,
                "digest": child_digest,
                "size": 0,
                "platform": {"architecture": "amd64", "os": "linux"},
            }
        ],
    }


class _Handler(BaseHTTPRequestHandler):
    server_version = "arachne-image-registry/1.0"
    protocol_version = "HTTP/1.1"
    # TCP_NODELAY: the same Nagle/delayed-ACK stall as tests/lab/web_lab.py (42 ms → 0.8 ms per
    # request on loopback).
    disable_nagle_algorithm = True
    lab: ImageRegistry

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - stdlib signature
        return

    def _send(self, status: int, payload: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def do_GET(self) -> None:
        path = urllib.parse.urlsplit(self.path).path
        self.lab.requests.append(f"GET {path}")
        if path in {"/v2", "/v2/"}:
            self._send(200, b"{}", "application/json")
            return
        parts = [part for part in path.strip("/").split("/") if part]
        if len(parts) < 4 or parts[0] != "v2":
            self._send(404, b'{"error":"not found"}', "application/json")
            return
        kind = parts[-2]
        reference = parts[-1]
        repository = "/".join(parts[1:-2])
        spec = self.lab.repositories.get(repository)
        if spec is None:
            self._send(404, b'{"error":"unknown repository"}', "application/json")
            return
        if kind == "manifests":
            document = spec.manifests.get(spec.tags.get(reference, reference))
            if document is None:
                self._send(404, b'{"error":"manifest unknown"}', "application/json")
                return
            media_type = str(document.get("mediaType", MEDIA_TYPE_MANIFEST))
            self._send(
                200,
                json.dumps(document, sort_keys=True).encode("utf-8"),
                media_type,
            )
            return
        if kind == "blobs":
            blob = spec.blobs.get(reference)
            if blob is None:
                self._send(404, b'{"error":"blob unknown"}', "application/json")
                return
            self._send(200, blob, "application/octet-stream")
            return
        self._send(404, b'{"error":"not found"}', "application/json")

    def do_HEAD(self) -> None:
        self.do_GET()


@contextmanager
def start_image_registry(repositories: dict[str, ImageSpec]) -> Iterator[ImageRegistry]:
    """Start the fixture on loopback and yield its handle; tear it down on exit."""
    lab = ImageRegistry(repositories=repositories)
    handler = type("_BoundImageRegistryHandler", (_Handler,), {"lab": lab})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    server.daemon_threads = True
    port = server.server_address[1]
    lab.port = port
    lab.base_url = f"http://127.0.0.1:{port}/"
    thread = threading.Thread(
        target=server.serve_forever, args=(0.05,), name="arachne-image-registry", daemon=True
    )
    thread.start()
    try:
        yield lab
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
