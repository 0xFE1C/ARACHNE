"""Evidence backends: local filesystem and S3-compatible, with dedup and compression (S20).

REQ-DATA-002's accept criterion is the fake-S3 round trip
(:func:`test_the_fake_s3_round_trip_returns_the_same_bytes`), and REQ-DATA-004's is the dedup
and compression arithmetic asserted here and end-to-end in
``tests/integration/test_data_lifecycle.py``. The rest of the file pins the properties that
make the abstraction safe: content-addressed keys (a tampered key cannot reach an arbitrary
path), container integrity (a corrupted object is refused, not served), and presigned URLs
that a verifying object store accepts — and refuses once tampered with or expired.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from tests.helpers.fake_s3 import FakeS3

from arachne.core.config import EvidenceSettings, Settings
from arachne.core.errors import EvidenceNotFoundError, EvidenceStoreError
from arachne.core.http import ScopedHttpClient
from arachne.core.safety import Scope, StaticResolver
from arachne.data.evidence_backend import (
    LocalEvidenceBackend,
    S3EvidenceBackend,
    build_evidence_backend,
    decode_container,
    encode_container,
)

HOST = "s3.example.com"
PUBLIC_IP = "93.184.216.34"  # the same routable address the other suites resolve to


def payload(size: int = 4096, filler: str = "arachne") -> dict[str, object]:
    """A realistic evidence payload: structured, repetitive, and big enough to offload."""
    return {
        "kind": "http_response",
        "status_code": 200,
        "body": f"<html><body>{filler} " * (size // 20),
        "captured_patterns": ["sqli-error", "stack-trace"],
    }


def _s3_client(handler: object, *, settings: Settings | None = None) -> ScopedHttpClient:
    return ScopedHttpClient(
        settings=settings,
        scope=Scope(allowed_hosts=(HOST,)),
        resolver=StaticResolver((PUBLIC_IP,)),
        transport=httpx.MockTransport(handler),  # type: ignore[arg-type]
    )


def _s3_backend(
    fake: FakeS3,
    *,
    multipart_threshold: int = 8 * 1024 * 1024,
    dedup: bool = True,
    compress: bool = True,
    settings: Settings | None = None,
) -> S3EvidenceBackend:
    return S3EvidenceBackend(
        endpoint=f"https://{HOST}",
        bucket=fake.bucket,
        region=fake.region,
        access_key=fake.access_key,
        secret_key=fake.secret_key,
        prefix="evidence",
        path_style=True,
        client=_s3_client(fake.handler, settings=settings),
        multipart_threshold=multipart_threshold,
        dedup=dedup,
        compress=compress,
    )


# --------------------------------------------------------------------------- container
def test_the_container_round_trips_and_reports_its_flag() -> None:
    data = b"x" * 5000
    container = encode_container(data)
    assert container.startswith(b"ARBLB001")
    assert decode_container(container) == data
    assert len(container) < len(data)  # repetitive input compresses


def test_a_corrupt_container_is_refused_rather_than_served() -> None:
    container = encode_container(b"secret body")
    with pytest.raises(EvidenceStoreError):
        decode_container(b"not-a-container")
    with pytest.raises(EvidenceStoreError):
        decode_container(container[:-4])
    broken = bytearray(container)
    broken[9] = 9  # an unknown flag byte
    with pytest.raises(EvidenceStoreError):
        decode_container(bytes(broken))


def test_a_truncated_or_overlong_container_is_refused() -> None:
    container = encode_container(b"abcdef")
    # Declare a length the body does not have.
    forged = container[:9] + (99).to_bytes(8, "big") + container[17:]
    with pytest.raises(EvidenceStoreError):
        decode_container(forged)


# --------------------------------------------------------------------------- local
async def test_the_local_backend_round_trips_and_verifies_the_digest(tmp_path: object) -> None:
    backend = LocalEvidenceBackend(tmp_path / "evidence")  # type: ignore[operator]
    stored = await backend.put(json.dumps(payload()).encode())
    assert stored.backend == "local"
    assert stored.key == hashlib.sha256(json.dumps(payload()).encode()).hexdigest()
    assert await backend.get(stored.key) == json.dumps(payload()).encode()
    assert await backend.exists(stored.key)
    assert backend.presign(stored.key) is None
    assert await backend.delete(stored.key)
    assert not await backend.exists(stored.key)
    assert await backend.delete(stored.key) is False


async def test_the_local_backend_deduplicates_identical_payloads(tmp_path: object) -> None:
    directory = tmp_path / "evidence"  # type: ignore[operator]
    backend = LocalEvidenceBackend(directory)
    data = json.dumps(payload()).encode()
    first = await backend.put(data)
    second = await backend.put(data)
    assert first.deduplicated is False
    assert second.deduplicated is True
    assert second.key == first.key
    files = [path for path in directory.rglob("*") if path.is_file()]
    assert len(files) == 1, files
    assert backend.stats()["dedup_hits"] == 1


async def test_the_local_backend_compresses_what_it_stores(tmp_path: object) -> None:
    directory = tmp_path / "evidence"  # type: ignore[operator]
    backend = LocalEvidenceBackend(directory, compress=True)
    data = json.dumps(payload(20_000)).encode()
    stored = await backend.put(data)
    assert stored.size == len(data)
    assert stored.stored_size < stored.size
    assert stored.ratio > 2.0
    object_file = next(path for path in directory.rglob("*") if path.is_file())
    assert object_file.stat().st_size == stored.stored_size


async def test_an_offloaded_payload_is_written_atomically(tmp_path: object) -> None:
    directory = tmp_path / "evidence"  # type: ignore[operator]
    backend = LocalEvidenceBackend(directory)
    await backend.put_stream([b"chunk-one", b"chunk-two"])
    joined = b"chunk-onechunk-two"
    key = hashlib.sha256(joined).hexdigest()
    assert (await backend.get(key)) == joined
    # No temporary files are left behind, and nothing sits outside the sharded layout.
    assert list((directory / ".tmp").iterdir()) == []


@pytest.mark.parametrize(
    "key",
    ["../../etc/passwd", "not-a-digest", "A" * 64, "0" * 63, ""],
)
async def test_a_key_that_is_not_a_digest_is_refused(tmp_path: object, key: str) -> None:
    backend = LocalEvidenceBackend(tmp_path / "evidence")  # type: ignore[operator]
    with pytest.raises(EvidenceStoreError):
        backend.path_for(key)
    with pytest.raises(EvidenceStoreError):
        await backend.get(key)


async def test_a_missing_object_is_a_not_found(tmp_path: object) -> None:
    backend = LocalEvidenceBackend(tmp_path / "evidence")  # type: ignore[operator]
    with pytest.raises(EvidenceNotFoundError):
        await backend.get("a" * 64)


async def test_a_tampered_object_is_refused_on_read(tmp_path: object) -> None:
    directory = tmp_path / "evidence"  # type: ignore[operator]
    backend = LocalEvidenceBackend(directory)
    stored = await backend.put(b"the-real-body")
    path = backend.path_for(stored.key)
    # Swap the payload for another valid container whose digest does not match the key.
    path.write_bytes(encode_container(b"a-different-body"))
    with pytest.raises(EvidenceStoreError):
        await backend.get(stored.key)


# --------------------------------------------------------------------------- fake S3
async def test_the_fake_s3_round_trip_returns_the_same_bytes() -> None:
    """REQ-DATA-002's accept criterion: put → get through the object store."""
    fake = FakeS3()
    backend = _s3_backend(fake)
    data = json.dumps(payload()).encode()
    stored = await backend.put(data)
    assert fake.objects, "nothing reached the object store"
    assert await backend.exists(stored.key)
    assert await backend.get(stored.key) == data
    assert fake.signature_failures == 0


async def test_the_fake_s3_verifies_the_signature_on_every_call() -> None:
    fake = FakeS3()
    backend = _s3_backend(fake)
    stored = await backend.put(b"body")
    # A signature that does not recompute is a 403, not a silent accept: the backend refuses
    # the exchange rather than pretending the write landed.
    fake.secret_key = "a-different-secret"
    with pytest.raises(EvidenceStoreError):
        await backend.put(b"another-body")
    assert fake.signature_failures >= 1
    # Reads are refused the same way, and the stored object is untouched.
    with pytest.raises(EvidenceStoreError):
        await backend.get(stored.key)


async def test_the_s3_backend_deduplicates_with_a_head_before_uploading() -> None:
    fake = FakeS3()
    backend = _s3_backend(fake)
    data = json.dumps(payload()).encode()
    first = await backend.put(data)
    writes = len([1 for method, _ in fake.requests if method == "PUT"])
    second = await backend.put(data)
    assert second.deduplicated is True
    assert len([1 for method, _ in fake.requests if method == "PUT"]) == writes
    assert first.key == second.key
    assert backend.stats()["dedup_hits"] == 1


async def test_the_s3_backend_streams_a_large_payload_as_a_multipart_upload() -> None:
    fake = FakeS3()
    # A threshold small enough to exercise multipart without an 8 MiB fixture.
    backend = _s3_backend(fake, multipart_threshold=1024)
    data = os.urandom(40_000)  # incompressible, so the container stays over the threshold
    chunks = [data[index : index + 9000] for index in range(0, len(data), 9000)]
    stored = await backend.put_stream(chunks)
    assert backend.parts_uploaded >= 4
    assert await backend.get(stored.key) == data
    assert any("uploads" in path or "partNumber" in path for _method, path in fake.requests) or (
        len(fake.requests) > 3
    )


async def test_the_s3_backend_deletes_objects() -> None:
    fake = FakeS3()
    backend = _s3_backend(fake)
    stored = await backend.put(b"body")
    assert await backend.delete(stored.key) is True
    assert not await backend.exists(stored.key)
    assert fake.objects == {}


async def test_the_s3_backend_reports_a_missing_object_as_not_found() -> None:
    fake = FakeS3()
    backend = _s3_backend(fake)
    with pytest.raises(EvidenceNotFoundError):
        await backend.get("b" * 64)


async def test_a_tampered_presigned_url_is_refused_by_the_object_store() -> None:
    fake = FakeS3()
    backend = _s3_backend(fake)
    stored = await backend.put(b"the-evidence")
    url = backend.presign(stored.key)
    assert url is not None
    assert "X-Amz-Signature=" in url
    # The signature covers the path: pointing it at another object invalidates it.
    tampered = url.replace(stored.key, "c" * 64)
    assert tampered != url
    assert await _fetch(fake, tampered) == 403
    assert await _fetch(fake, url) == 200


async def test_an_expired_presigned_url_is_refused() -> None:
    issued = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
    fake = FakeS3(now=lambda: issued + timedelta(hours=2))
    backend = _s3_backend(fake)
    stored = await backend.put(b"body")
    url = backend.presign(stored.key, ttl_s=60, now=issued)
    assert url is not None
    assert await _fetch(fake, url) == 403
    # The same link, read while it is still valid, works: the refusal is the clock, not the
    # signature.
    fresh = FakeS3(now=lambda: issued + timedelta(seconds=30))
    fresh.objects = fake.objects
    assert await _fetch(fresh, url) == 200


async def test_the_s3_backend_carries_a_session_token_when_configured() -> None:
    fake = FakeS3(session_token="token-value")
    backend = _s3_backend(fake)
    backend.session_token = "token-value"
    await backend.put(b"body")
    url = backend.presign("a" * 64)
    assert url is not None and "X-Amz-Security-Token=token-value" in url


async def _fetch(fake: FakeS3, url: str) -> int:
    """Perform a plain (unsigned) GET against the fake store and return its status."""
    transport = httpx.MockTransport(fake.handler)
    async with httpx.AsyncClient(transport=transport) as client:
        response = await client.get(url)
    return response.status_code


# --------------------------------------------------------------------------- factory
def test_the_factory_builds_a_local_backend_by_default(tmp_path: object) -> None:
    settings = Settings(
        database_url=f"sqlite:///{tmp_path}/api.db",  # type: ignore[operator]
        evidence=EvidenceSettings(dir=str(tmp_path)),  # type: ignore[operator]
    )
    backend = build_evidence_backend(settings)
    assert backend.kind == "local"


def test_an_s3_backend_without_credentials_is_a_configuration_error() -> None:
    from arachne.core.errors import ConfigurationError

    with pytest.raises(ConfigurationError):
        EvidenceSettings(backend="s3", s3_endpoint="https://s3.example.com", s3_bucket="b")


def test_the_signed_headers_are_pinned_to_the_spec() -> None:
    """The canonical request is what SigV4 is easy to get subtly wrong, so it is pinned.

    The fake object store verifies a signature *as received* (which catches signing or
    canonicalisation drift), but it shares the algorithm with the backend. These assertions
    make the observable parts of the construction explicit — the credential scope, the signed
    header set, the signature shape, and the fact that the object path is covered — so a
    change to any of them has to be deliberate.
    """
    import re

    fake = FakeS3()
    backend = _s3_backend(fake)
    moment = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)
    empty = hashlib.sha256(b"").hexdigest()
    key = "a" * 64
    headers = backend._signed_headers(
        "GET", backend.object_path(key), {}, payload_hash=empty, now=moment
    )
    authorization = headers["Authorization"]
    assert "Credential=AKIAFAKEACCESSKEY000/20260101/us-east-1/s3/aws4_request" in authorization
    assert "SignedHeaders=host;x-amz-content-sha256;x-amz-date" in authorization
    signature = re.search(r"Signature=([0-9a-f]{64})$", authorization)
    assert signature is not None, authorization
    assert headers["x-amz-date"] == "20260101T000000Z"
    assert headers["x-amz-content-sha256"] == empty
    assert headers["Host"] == HOST

    # The same inputs at the same instant give the same signature, and a different object
    # path gives a different one: the path is inside the signature.
    same = backend._signed_headers(
        "GET", backend.object_path(key), {}, payload_hash=empty, now=moment
    )
    assert same["Authorization"] == authorization
    other = backend._signed_headers(
        "GET", backend.object_path("b" * 64), {}, payload_hash=empty, now=moment
    )
    assert other["Authorization"] != authorization

    # The object path is path-style and content-addressed: bucket, prefix, shard-free key.
    assert backend.object_path(key) == f"/{fake.bucket}/evidence/{key}"


def test_a_different_secret_produces_a_different_signature() -> None:
    fake = FakeS3()
    first = _s3_backend(fake)
    second = _s3_backend(fake)
    second._secret_key = "another-secret"
    moment = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)
    empty = hashlib.sha256(b"").hexdigest()
    path = first.object_path("a" * 64)
    one = first._signed_headers("GET", path, {}, payload_hash=empty, now=moment)
    two = second._signed_headers("GET", path, {}, payload_hash=empty, now=moment)
    assert one["Authorization"] != two["Authorization"]
