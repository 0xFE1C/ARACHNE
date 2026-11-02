"""Evidence backends: content-addressed storage for payloads too large to sit inline.

REQ-DATA-002 asks for two backends behind one abstraction — the local filesystem (the
default) and any S3-compatible object store — with streaming uploads, presigned UI access,
and an in-memory fake for tests. Three design decisions carry that:

**Content addressing is the dedup mechanism (REQ-DATA-004).** An object's key *is* the
SHA-256 of its logical bytes. Two identical 64 KB response bodies therefore map to one
object: the second write finds the key and skips the write entirely. Dedup and integrity are
the same property, so neither can drift from the other.

**One container format for both backends.** A stored object is ``MAGIC | flag | size |
body``, where the body is the zlib-compressed payload (or the raw payload when compression is
switched off). Both backends write exactly the same bytes, so a payload migrated from one to
the other still verifies, and the digest recorded in the ``evidences`` row is the digest of
the *logical* payload — never of whatever the backend happens to store.

**Async interface, honestly implemented.** Uploads happen on the scan's event loop and an
object-store write is genuine network I/O, so the protocol is async. The local backend's
methods delegate to synchronous helpers: its I/O is one small file write, and a thread hop
would cost more than it saves. The object-store upload is the real thing — SigV4-signed,
multipart above a threshold, and over the shared
:class:`~arachne.core.http.ScopedHttpClient` rather than a second egress path.

Compression is applied while the payload is consumed, but the *container* is assembled before
it is sent, because S3 requires the body digest (``x-amz-content-sha256``) and the length
before the body. The bound that makes that acceptable is the capture policy: an evidence
payload is capped at ``MAX_EVIDENCE_CHARS``, so "the whole container" is at most a few hundred
kilobytes. The filesystem backend streams end to end, because nothing about a local write
needs to know the length first.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import struct
import time
import zlib
from collections.abc import AsyncIterator, Iterable, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Final, Protocol
from urllib.parse import quote, urlparse

from arachne.core.config import EvidenceSettings, Settings
from arachne.core.errors import ConfigurationError, EvidenceNotFoundError, EvidenceStoreError
from arachne.core.logging import get_logger
from arachne.core.safety import Scope

__all__ = [
    "CONTAINER_CONTENT_TYPE",
    "EvidenceBackend",
    "LocalEvidenceBackend",
    "S3EvidenceBackend",
    "StoredObject",
    "build_evidence_backend",
    "decode_container",
    "encode_container",
    "iter_backend_object",
]

_logger = get_logger("data.evidence")

#: The container's magic: the first 8 bytes of every stored object.
CONTAINER_MAGIC: Final = b"ARBLB001"
#: ``flag`` (0 raw, 1 zlib) + the logical length.
_CONTAINER_HEADER: Final = struct.Struct(">BQ")
CONTAINER_CONTENT_TYPE: Final = "application/vnd.arachne.evidence"
_FLAG_RAW: Final = 0
_FLAG_ZLIB: Final = 1
#: A container that declares more than this is refused: no legitimate capture is close, and
#: an unbounded inflate is how a storage bug becomes a memory exhaustion.
_MAX_DECOMPRESSED: Final = 64 * 1024 * 1024
_CHUNK: Final = 64 * 1024
_DEFAULT_MULTIPART_THRESHOLD: Final = 8 * 1024 * 1024
_HEX: Final = frozenset("0123456789abcdef")

#: The S3 initiate-multipart response carries one field; a bounded match keeps a parser out
#: of the trust boundary (no XML entity processing on a peer-supplied document).
_UPLOAD_ID_RE: Final = re.compile(r"<UploadId>([A-Za-z0-9=_\-./]{1,512})</UploadId>")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def encode_container(data: bytes, *, compress: bool = True, level: int = 6) -> bytes:
    """Encode ``data`` into the container format."""
    if compress:
        return (
            CONTAINER_MAGIC
            + _CONTAINER_HEADER.pack(_FLAG_ZLIB, len(data))
            + zlib.compress(data, level)
        )
    return CONTAINER_MAGIC + _CONTAINER_HEADER.pack(_FLAG_RAW, len(data)) + data


def decode_container(raw: bytes) -> bytes:
    """Decode a container, verifying its framing. Raises :class:`EvidenceStoreError`."""
    header_size = len(CONTAINER_MAGIC) + _CONTAINER_HEADER.size
    if len(raw) < header_size or not raw.startswith(CONTAINER_MAGIC):
        msg = "evidence object is not in the ARACHNE container format"
        raise EvidenceStoreError(msg)
    flag, size = _CONTAINER_HEADER.unpack(raw[len(CONTAINER_MAGIC) : header_size])
    body = raw[header_size:]
    if size > _MAX_DECOMPRESSED:
        msg = f"evidence object declares {size} bytes, over the {_MAX_DECOMPRESSED}-byte cap"
        raise EvidenceStoreError(msg)
    if flag == _FLAG_RAW:
        payload = body
    elif flag == _FLAG_ZLIB:
        try:
            payload = zlib.decompress(body)
        except zlib.error as exc:
            msg = f"evidence object failed to decompress: {exc}"
            raise EvidenceStoreError(msg) from exc
    else:
        msg = f"unknown evidence container flag {flag}"
        raise EvidenceStoreError(msg)
    if len(payload) != size:
        msg = f"evidence object length mismatch: declared {size}, decoded {len(payload)}"
        raise EvidenceStoreError(msg)
    return payload


def _is_content_key(key: str) -> bool:
    """True for a 64-character lowercase hex digest — the only key shape accepted.

    Keys reach the filesystem and the object store as path segments, so a key that is not a
    digest is refused rather than sanitised: a row whose ``storage_key`` was tampered with
    must not be able to read or unlink an arbitrary path.
    """
    return len(key) == 64 and all(character in _HEX for character in key)


def _require_content_key(key: str) -> str:
    if not _is_content_key(key):
        msg = f"refusing evidence key {key!r}: not a content digest"
        raise EvidenceStoreError(msg)
    return key


@dataclass(frozen=True, slots=True)
class StoredObject:
    """What a backend reports after writing one payload."""

    key: str
    sha256: str
    size: int
    stored_size: int
    backend: str
    deduplicated: bool = False
    content_type: str = CONTAINER_CONTENT_TYPE

    @property
    def ratio(self) -> float:
        """Logical bytes per physical byte (0 when the object is empty)."""
        return (self.size / self.stored_size) if self.stored_size else 0.0


class EvidenceBackend(Protocol):
    """Where evidence payloads go (REQ-DATA-002)."""

    kind: str

    async def put(self, data: bytes, *, content_type: str = "application/json") -> StoredObject:
        """Store ``data`` under its content hash."""
        ...

    async def put_stream(
        self, chunks: Iterable[bytes], *, content_type: str = "application/json"
    ) -> StoredObject:
        """Store a payload produced in chunks, hashing it as it arrives."""
        ...

    async def get(self, key: str) -> bytes:
        """Read a payload back, verifying the container and its content digest."""
        ...

    async def delete(self, key: str) -> bool:
        """Remove an object; ``False`` when it was already gone."""
        ...

    async def exists(self, key: str) -> bool: ...

    def presign(self, key: str, *, ttl_s: int = 900, filename: str | None = None) -> str | None:
        """A time-limited download URL, or ``None`` when the backend cannot mint one."""
        ...

    def stats(self) -> dict[str, Any]: ...


class LocalEvidenceBackend:
    """The default backend: content-addressed files in a directory (REQ-DATA-002).

    ``<dir>/ab/cd/<sha256>`` — two levels of sharding keep a directory listing manageable on
    the filesystems operators actually use. Writes are atomic (a temp file in the same
    directory, then :func:`os.replace`), so a killed process leaves either the old object or
    the new one, never a half-written file that a later read would report as corrupt. The
    write path streams: each chunk is hashed and compressed as it arrives.
    """

    kind = "local"

    def __init__(
        self,
        directory: Path | str,
        *,
        compress: bool = True,
        compress_level: int = 6,
        dedup: bool = True,
    ) -> None:
        self.directory = Path(directory)
        self.compress = compress
        self.compress_level = compress_level
        self.dedup = dedup
        self.writes = 0
        self.dedup_hits = 0
        self.logical_bytes = 0
        self.stored_bytes = 0

    # ------------------------------------------------------------------ paths
    def path_for(self, key: str) -> Path:
        _require_content_key(key)
        return self.directory / key[:2] / key[2:4] / key

    # ------------------------------------------------------------------ writes
    async def put(self, data: bytes, *, content_type: str = "application/json") -> StoredObject:
        return self._put_stream([data])

    async def put_stream(
        self, chunks: Iterable[bytes], *, content_type: str = "application/json"
    ) -> StoredObject:
        return self._put_stream(chunks)

    def _put_stream(self, chunks: Iterable[bytes]) -> StoredObject:
        self.directory.mkdir(parents=True, exist_ok=True)
        tmp_dir = self.directory / ".tmp"
        tmp_dir.mkdir(exist_ok=True)
        digest = hashlib.sha256()
        size = 0
        compressor = zlib.compressobj(self.compress_level) if self.compress else None
        flag = _FLAG_ZLIB if compressor is not None else _FLAG_RAW
        tmp_path = tmp_dir / f"put-{os.getpid()}-{time.monotonic_ns()}"
        try:
            with tmp_path.open("wb") as handle:
                handle.write(CONTAINER_MAGIC)
                handle.write(_CONTAINER_HEADER.pack(flag, 0))  # length patched below
                for chunk in chunks:
                    if not chunk:
                        continue
                    digest.update(chunk)
                    size += len(chunk)
                    body = compressor.compress(chunk) if compressor is not None else chunk
                    if body:
                        handle.write(body)
                if compressor is not None:
                    handle.write(compressor.flush())
            key = digest.hexdigest()
            target = self.path_for(key)
            if self.dedup and target.exists():
                tmp_path.unlink(missing_ok=True)
                self.dedup_hits += 1
                self.logical_bytes += size
                return StoredObject(
                    key=key,
                    sha256=key,
                    size=size,
                    stored_size=target.stat().st_size,
                    backend=self.kind,
                    deduplicated=True,
                )
            with tmp_path.open("r+b") as handle:
                handle.seek(len(CONTAINER_MAGIC))
                handle.write(_CONTAINER_HEADER.pack(flag, size))
            target.parent.mkdir(parents=True, exist_ok=True)
            tmp_path.replace(target)
            stored = target.stat().st_size
            self.writes += 1
            self.logical_bytes += size
            self.stored_bytes += stored
            return StoredObject(
                key=key, sha256=key, size=size, stored_size=stored, backend=self.kind
            )
        except OSError as exc:
            tmp_path.unlink(missing_ok=True)
            msg = f"could not write evidence to {self.directory}: {exc}"
            raise EvidenceStoreError(msg) from exc

    # ------------------------------------------------------------------ reads
    async def get(self, key: str) -> bytes:
        path = self.path_for(key)
        try:
            raw = path.read_bytes()
        except FileNotFoundError as exc:
            msg = f"evidence object {key} does not exist"
            raise EvidenceNotFoundError(msg) from exc
        except OSError as exc:
            msg = f"could not read evidence object {key}: {exc}"
            raise EvidenceStoreError(msg) from exc
        payload = decode_container(raw)
        if _sha256(payload) != key:
            msg = f"evidence object {key} does not match its content digest"
            raise EvidenceStoreError(msg)
        return payload

    async def delete(self, key: str) -> bool:
        path = self.path_for(key)
        try:
            path.unlink()
        except FileNotFoundError:
            return False
        except OSError as exc:
            msg = f"could not delete evidence object {key}: {exc}"
            raise EvidenceStoreError(msg) from exc
        return True

    async def exists(self, key: str) -> bool:
        return self.path_for(key).is_file()

    def presign(self, key: str, *, ttl_s: int = 900, filename: str | None = None) -> str | None:
        """The local backend mints no URL: the API streams the file itself."""
        return None

    def stats(self) -> dict[str, Any]:
        return {
            "backend": self.kind,
            "directory": str(self.directory),
            "objects_written": self.writes,
            "dedup_hits": self.dedup_hits,
            "logical_bytes": self.logical_bytes,
            "stored_bytes": self.stored_bytes,
            "compression": self.compress,
            "dedup": self.dedup,
        }


# ---------------------------------------------------------------------- S3 helpers
def _sign(key: bytes, message: str) -> bytes:
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).digest()


def _signing_key(secret: str, date_stamp: str, region: str) -> bytes:
    """The AWS SigV4 signing-key derivation for the ``s3`` service."""
    k_date = _sign(f"AWS4{secret}".encode(), date_stamp)
    k_region = _sign(k_date, region)
    k_service = _sign(k_region, "s3")
    return _sign(k_service, "aws4_request")


def _uri_encode(value: str, *, safe: str = "-_.~") -> str:
    return quote(value, safe=safe)


def _query_string(params: Mapping[str, str]) -> str:
    return "&".join(
        f"{_uri_encode(name)}={_uri_encode(value)}" for name, value in sorted(params.items())
    )


class S3EvidenceBackend:
    """Any S3-compatible object store (REQ-DATA-002).

    Signing is stdlib SigV4 — the same deliberate choice S17 made for JWT verification and
    S19 for NTLM: a small, audited implementation beats a dependency in every deployment,
    including the air-gapped one. Only *static* credentials are supported, and the settings
    refuse an S3 backend without them, so there is no half-configured mode in which a write
    silently lands somewhere else.

    Uploads stream: a container above ``multipart_threshold`` is sent as a multipart upload
    (initiate, parts, complete), so the object store never needs the whole body at once, and
    a smaller one is a single signed PUT. Dedup is a signed HEAD on the content key before
    any bytes are sent.
    """

    kind = "s3"

    def __init__(
        self,
        *,
        endpoint: str,
        bucket: str,
        region: str,
        access_key: str,
        secret_key: str,
        session_token: str | None = None,
        prefix: str = "evidence",
        path_style: bool = True,
        client: Any,
        multipart_threshold: int = _DEFAULT_MULTIPART_THRESHOLD,
        dedup: bool = True,
        compress: bool = True,
        compress_level: int = 6,
        max_object_bytes: int = _MAX_DECOMPRESSED,
    ) -> None:
        self.endpoint = endpoint.rstrip("/")
        parsed = urlparse(self.endpoint)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            msg = f"evidence s3 endpoint must be an http(s) URL, got {endpoint!r}"
            raise ConfigurationError(msg)
        self.scheme = parsed.scheme
        self.bucket = bucket
        self.region = region
        self.access_key = access_key
        self._secret_key = secret_key
        self.session_token = session_token
        self.prefix = prefix.strip("/")
        self.path_style = path_style
        self.client = client
        self.multipart_threshold = multipart_threshold
        self.dedup = dedup
        self.compress = compress
        self.compress_level = compress_level
        self.max_object_bytes = max_object_bytes
        self.writes = 0
        self.dedup_hits = 0
        self.parts_uploaded = 0
        self.logical_bytes = 0
        self.stored_bytes = 0

    # ------------------------------------------------------------------ addressing
    def _host(self) -> str:
        """The ``Host`` header value, which is also what gets signed."""
        parsed = urlparse(self.endpoint)
        host = parsed.hostname or ""
        default_port = 443 if self.scheme == "https" else 80
        if parsed.port and parsed.port != default_port:
            return f"{host}:{parsed.port}"
        return host

    def _base_url(self) -> str:
        host = self._host()
        if self.path_style:
            return f"{self.scheme}://{host}"
        return f"{self.scheme}://{self.bucket}.{host}"

    def object_path(self, key: str) -> str:
        """The URL path of one object (the bucket is in the path when path-style)."""
        _require_content_key(key)
        parts = [self.prefix, key] if self.prefix else [key]
        tail = "/".join(_uri_encode(part, safe="") for part in parts)
        if self.path_style:
            return f"/{_uri_encode(self.bucket, safe='')}/{tail}"
        return f"/{tail}"

    def object_url(self, key: str) -> str:
        return f"{self._base_url()}{self.object_path(key)}"

    # ------------------------------------------------------------------ signing
    def _signed_headers(
        self,
        method: str,
        path: str,
        params: Mapping[str, str],
        *,
        payload_hash: str,
        now: datetime | None = None,
    ) -> dict[str, str]:
        """Headers that authenticate one request (SigV4, header-based)."""
        moment = now or datetime.now(UTC)
        amz_date = moment.strftime("%Y%m%dT%H%M%SZ")
        date_stamp = moment.strftime("%Y%m%d")
        headers: dict[str, str] = {
            "host": self._host(),
            "x-amz-content-sha256": payload_hash,
            "x-amz-date": amz_date,
        }
        if self.session_token:
            headers["x-amz-security-token"] = self.session_token
        signed_names = sorted(headers)
        canonical_headers = "".join(f"{name}:{headers[name].strip()}\n" for name in signed_names)
        signed_headers = ";".join(signed_names)
        canonical_request = "\n".join(
            [method, path, _query_string(params), canonical_headers, signed_headers, payload_hash]
        )
        scope = f"{date_stamp}/{self.region}/s3/aws4_request"
        string_to_sign = "\n".join(
            ["AWS4-HMAC-SHA256", amz_date, scope, _sha256(canonical_request.encode())]
        )
        signature = hmac.new(
            _signing_key(self._secret_key, date_stamp, self.region),
            string_to_sign.encode(),
            hashlib.sha256,
        ).hexdigest()
        headers["authorization"] = (
            f"AWS4-HMAC-SHA256 Credential={self.access_key}/{scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}"
        )
        return _header_case(headers)

    def presign(
        self,
        key: str,
        *,
        ttl_s: int = 900,
        filename: str | None = None,
        now: datetime | None = None,
    ) -> str | None:
        """A presigned GET URL — a bearer credential for this object until it expires.

        Computed locally (no request), which is what makes "presigned UI access" cheap: the
        browser fetches straight from the object store and ARACHNE never proxies the bytes.
        ``now`` exists so a test can mint a link at a chosen instant and prove the store's
        expiry check bites.
        """
        path = self.object_path(key)
        moment = now or datetime.now(UTC)
        amz_date = moment.strftime("%Y%m%dT%H%M%SZ")
        date_stamp = moment.strftime("%Y%m%d")
        scope = f"{date_stamp}/{self.region}/s3/aws4_request"
        params = {
            "X-Amz-Algorithm": "AWS4-HMAC-SHA256",
            "X-Amz-Credential": f"{self.access_key}/{scope}",
            "X-Amz-Date": amz_date,
            "X-Amz-Expires": str(int(ttl_s)),
            "X-Amz-SignedHeaders": "host",
        }
        if self.session_token:
            params["X-Amz-Security-Token"] = self.session_token
        if filename:
            safe_name = _uri_encode(filename.replace('"', ""), safe="")
            params["response-content-disposition"] = f'attachment; filename="{safe_name}"'
        canonical_request = "\n".join(
            [
                "GET",
                path,
                _query_string(params),
                f"host:{self._host()}\n",
                "host",
                "UNSIGNED-PAYLOAD",
            ]
        )
        string_to_sign = "\n".join(
            ["AWS4-HMAC-SHA256", amz_date, scope, _sha256(canonical_request.encode())]
        )
        signature = hmac.new(
            _signing_key(self._secret_key, date_stamp, self.region),
            string_to_sign.encode(),
            hashlib.sha256,
        ).hexdigest()
        params["X-Amz-Signature"] = signature
        return f"{self._base_url()}{path}?{_query_string(params)}"

    # ------------------------------------------------------------------ writes
    async def put(self, data: bytes, *, content_type: str = "application/json") -> StoredObject:
        return await self._put_chunks([data])

    async def put_stream(
        self, chunks: Iterable[bytes], *, content_type: str = "application/json"
    ) -> StoredObject:
        return await self._put_chunks(chunks)

    async def _put_chunks(self, chunks: Iterable[bytes]) -> StoredObject:
        digest = hashlib.sha256()
        size = 0
        compressor = zlib.compressobj(self.compress_level) if self.compress else None
        body: list[bytes] = []
        for chunk in chunks:
            if not chunk:
                continue
            digest.update(chunk)
            size += len(chunk)
            body.append(compressor.compress(chunk) if compressor is not None else chunk)
        if compressor is not None:
            body.append(compressor.flush())
        flag = _FLAG_ZLIB if compressor is not None else _FLAG_RAW
        container = CONTAINER_MAGIC + _CONTAINER_HEADER.pack(flag, size) + b"".join(body)
        key = digest.hexdigest()
        deduplicated = False
        if self.dedup and await self.exists(key):
            deduplicated = True
            self.dedup_hits += 1
        elif len(container) >= self.multipart_threshold:
            await self._put_multipart(key, container)
            self.writes += 1
            self.stored_bytes += len(container)
        else:
            headers = self._signed_headers(
                "PUT", self.object_path(key), {}, payload_hash=_sha256(container)
            )
            exchange = await self.client.request(
                "PUT",
                self.object_url(key),
                headers={**headers, "content-type": CONTAINER_CONTENT_TYPE},
                content=container,
            )
            if not exchange.ok:
                msg = f"evidence upload to s3 failed with HTTP {exchange.status_code}"
                raise EvidenceStoreError(msg)
            self.writes += 1
            self.stored_bytes += len(container)
        self.logical_bytes += size
        return StoredObject(
            key=key,
            sha256=key,
            size=size,
            stored_size=len(container),
            backend=self.kind,
            deduplicated=deduplicated,
        )

    async def _put_multipart(self, key: str, container: bytes) -> None:
        """Initiate → upload parts sequentially → complete."""
        path = self.object_path(key)
        initiated = await self.client.request(
            "POST",
            f"{self.object_url(key)}?uploads",
            headers=self._signed_headers("POST", path, {"uploads": ""}, payload_hash=_sha256(b"")),
            content=b"",
        )
        if not initiated.ok:
            msg = f"could not initiate a multipart upload: HTTP {initiated.status_code}"
            raise EvidenceStoreError(msg)
        match = _UPLOAD_ID_RE.search(initiated.body)
        if match is None:
            msg = "the object store returned no upload id"
            raise EvidenceStoreError(msg)
        upload_id = match.group(1)
        part_size = max(self.multipart_threshold, 1)
        etags: list[tuple[int, str]] = []
        try:
            for offset in range(0, len(container), part_size):
                number = len(etags) + 1
                part = container[offset : offset + part_size]
                params = {"partNumber": str(number), "uploadId": upload_id}
                response = await self.client.request(
                    "PUT",
                    f"{self.object_url(key)}?{_query_string(params)}",
                    headers=self._signed_headers("PUT", path, params, payload_hash=_sha256(part)),
                    content=part,
                )
                if not response.ok:
                    msg = f"multipart part {number} failed with HTTP {response.status_code}"
                    raise EvidenceStoreError(msg)
                etag = (response.header("etag") or "").strip('"')
                etags.append((number, etag))
                self.parts_uploaded += 1
        except Exception:
            await self._abort_multipart(key, upload_id)
            raise
        body = (
            "<CompleteMultipartUpload>"
            + "".join(
                f'<Part><PartNumber>{number}</PartNumber><ETag>"{etag}"</ETag></Part>'
                for number, etag in etags
            )
            + "</CompleteMultipartUpload>"
        ).encode()
        completed = await self.client.request(
            "POST",
            f"{self.object_url(key)}?uploadId={_uri_encode(upload_id)}",
            headers=self._signed_headers(
                "POST", path, {"uploadId": upload_id}, payload_hash=_sha256(body)
            ),
            content=body,
        )
        if not completed.ok:
            msg = f"could not complete the multipart upload: HTTP {completed.status_code}"
            raise EvidenceStoreError(msg)

    async def _abort_multipart(self, key: str, upload_id: str) -> None:
        try:
            params = {"uploadId": upload_id}
            await self.client.request(
                "DELETE",
                f"{self.object_url(key)}?{_query_string(params)}",
                headers=self._signed_headers(
                    "DELETE", self.object_path(key), params, payload_hash=_sha256(b"")
                ),
            )
        except Exception as exc:  # an abandoned upload expires on the store's side
            _logger.warning(
                "could not abort a multipart upload",
                extra={"event": "evidence.abort_failed", "error": str(exc)[:200]},
            )

    # ------------------------------------------------------------------ reads
    async def get(self, key: str) -> bytes:
        exchange = await self.client.request_bytes(
            "GET",
            self.object_url(key),
            headers=self._signed_headers(
                "GET", self.object_path(key), {}, payload_hash=_sha256(b"")
            ),
            max_bytes=self.max_object_bytes,
        )
        if exchange.status_code == 404:
            msg = f"evidence object {key} does not exist"
            raise EvidenceNotFoundError(msg)
        if not exchange.ok:
            msg = f"could not read evidence object {key}: HTTP {exchange.status_code}"
            raise EvidenceStoreError(msg)
        if exchange.truncated:
            msg = f"evidence object {key} is larger than the {self.max_object_bytes}-byte cap"
            raise EvidenceStoreError(msg)
        payload = decode_container(exchange.content)
        if _sha256(payload) != key:
            msg = f"evidence object {key} does not match its content digest"
            raise EvidenceStoreError(msg)
        return payload

    async def delete(self, key: str) -> bool:
        exchange = await self.client.request(
            "DELETE",
            self.object_url(key),
            headers=self._signed_headers(
                "DELETE", self.object_path(key), {}, payload_hash=_sha256(b"")
            ),
        )
        return exchange.status_code in {200, 204, 404}

    async def exists(self, key: str) -> bool:
        exchange = await self.client.request(
            "HEAD",
            self.object_url(key),
            headers=self._signed_headers(
                "HEAD", self.object_path(key), {}, payload_hash=_sha256(b"")
            ),
        )
        return bool(exchange.status_code == 200)

    def stats(self) -> dict[str, Any]:
        return {
            "backend": self.kind,
            "endpoint": self.endpoint,
            "bucket": self.bucket,
            "prefix": self.prefix,
            "objects_written": self.writes,
            "dedup_hits": self.dedup_hits,
            "parts_uploaded": self.parts_uploaded,
            "logical_bytes": self.logical_bytes,
            "stored_bytes": self.stored_bytes,
            "compression": self.compress,
            "dedup": self.dedup,
        }


def _header_case(headers: Mapping[str, str]) -> dict[str, str]:
    """Header names from the signer in conventional case (values unchanged).

    SigV4 signs lowercased names; HTTP does not care about case, but a wire log reads better
    with ``Host``/``Authorization`` spelled the usual way.
    """
    renamed = {"host": "Host", "authorization": "Authorization"}
    return {renamed.get(name, name): value for name, value in headers.items()}


def build_evidence_backend(
    settings: Settings | None = None,
    *,
    client: Any = None,
    auditor: Any = None,
) -> EvidenceBackend:
    """Construct the configured backend (the local filesystem by default).

    ``client``/``auditor`` are injected by the composition root so the object-store backend
    uses the deployment's single HTTP egress path and the scan's audit trail. A caller that
    omits them gets a client pinned to exactly the configured endpoint's host — never a
    general-purpose one.
    """
    from arachne.core.config import get_settings

    effective = settings or get_settings()
    config: EvidenceSettings = effective.evidence
    if config.backend == "local":
        return LocalEvidenceBackend(
            effective.evidence_dir,
            compress=config.compress,
            compress_level=config.compress_level,
            dedup=config.dedup,
        )
    # EvidenceSettings guarantees these when backend == "s3" (fail-closed at construction).
    assert config.s3_endpoint is not None
    assert config.s3_bucket is not None
    assert config.s3_access_key is not None
    assert config.s3_secret_key is not None
    if client is None:
        from arachne.core.http import ScopedHttpClient

        host = urlparse(config.s3_endpoint).hostname or ""
        policy = effective.safety.policy
        if config.s3_allow_private_ips:
            policy = replace(policy, allow_private_ips=True)
        client = ScopedHttpClient(
            settings=effective,
            scope=Scope(allowed_hosts=(host,)),
            policy=policy,
            auditor=auditor,
        )
    return S3EvidenceBackend(
        endpoint=config.s3_endpoint,
        bucket=config.s3_bucket,
        region=config.s3_region,
        access_key=config.s3_access_key.get_secret_value(),
        secret_key=config.s3_secret_key.get_secret_value(),
        session_token=(
            config.s3_session_token.get_secret_value() if config.s3_session_token else None
        ),
        prefix=config.s3_prefix,
        path_style=config.s3_path_style,
        client=client,
        dedup=config.dedup,
        compress=config.compress,
        compress_level=config.compress_level,
    )


async def iter_backend_object(backend: EvidenceBackend, key: str) -> AsyncIterator[bytes]:
    """Stream one logical payload in chunks (the download endpoint's read path)."""
    data = await backend.get(key)
    for start in range(0, len(data), _CHUNK):
        yield data[start : start + _CHUNK]
