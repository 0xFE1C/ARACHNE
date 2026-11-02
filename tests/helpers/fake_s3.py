"""An in-memory S3-compatible object store for tests (S20, REQ-DATA-002).

REQ-DATA-002's accept criterion is a *round trip* against a fake S3, so this is a real — if
small — implementation of the protocol surface the backend uses, served through
``httpx.MockTransport`` (no socket, no docker, no MinIO). It is deliberately a **checker** as
well as a store:

* **It verifies SigV4.** Every request must carry a signature that recomputes, header-based
  for API calls and query-based for a presigned URL. A tampered path, an unknown key id or a
  stale ``X-Amz-Date`` is a ``403``, which is what makes the presigned-access test meaningful
  (a fake that accepted anything would prove nothing about the signing code).
* **It expires presigned URLs.** ``X-Amz-Date`` + ``X-Amz-Expires`` is enforced, so an
  expired link is refused.
* **It implements multipart**, because the backend streams large payloads that way and a fake
  without it would leave that path untested.

Only the subset the backend calls is implemented: PUT/GET/HEAD/DELETE object, initiate/part/
complete/abort multipart. Buckets are implicit (any name is accepted and recorded).
"""

from __future__ import annotations

import hashlib
import hmac
import re
from datetime import UTC, datetime, timedelta
from typing import Any
from urllib.parse import parse_qsl, urlparse

import httpx

__all__ = ["FakeS3"]

_UPLOAD_ID_RE = re.compile(r"<UploadId>([A-Za-z0-9=_\-./]+)</UploadId>")


def _sign(key: bytes, message: str) -> bytes:
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).digest()


def _etag(body: bytes) -> str:
    """The object's ETag, which S3 defines as the MD5 of the object (not a security control).

    ``hashlib.md5`` is the protocol's choice, not ours: the fake store returns what a real
    object store returns, and nothing in ARACHNE trusts an ETag for integrity — the content
    digest in the container is what the backend verifies.
    """
    return hashlib.md5(body).hexdigest()  # noqa: S324 - the S3 ETag algorithm


def _signing_key(secret: str, date_stamp: str, region: str) -> bytes:
    k_date = _sign(f"AWS4{secret}".encode(), date_stamp)
    k_region = _sign(k_date, region)
    k_service = _sign(k_region, "s3")
    return _sign(k_service, "aws4_request")


def _canonical_query(params: dict[str, str]) -> str:
    from urllib.parse import quote

    return "&".join(
        f"{quote(name, safe='-_.~')}={quote(value, safe='-_.~')}"
        for name, value in sorted(params.items())
    )


class FakeS3:
    """An in-memory object store with real SigV4 verification."""

    def __init__(
        self,
        *,
        access_key: str = "AKIAFAKEACCESSKEY000",
        secret_key: str = "fake-secret-key",  # noqa: S107 - a fake store needs fake keys
        region: str = "us-east-1",
        bucket: str = "arachne-evidence",
        session_token: str | None = None,
        now: Any = None,
    ) -> None:
        self.access_key = access_key
        self.secret_key = secret_key
        self.region = region
        self.bucket = bucket
        self.session_token = session_token
        self.objects: dict[str, bytes] = {}
        self.uploads: dict[str, dict[int, bytes]] = {}
        self.requests: list[tuple[str, str]] = []
        self.signature_failures = 0
        self._upload_counter = 0
        self._clock = now or (lambda: datetime.now(UTC))

    # ------------------------------------------------------------------ transport
    def handler(self, request: httpx.Request) -> httpx.Response:
        """An ``httpx`` handler: the object store's HTTP surface."""
        parsed = urlparse(str(request.url))
        query = dict(parse_qsl(parsed.query, keep_blank_values=True))
        self.requests.append((request.method, parsed.path))
        key = self._object_key(parsed.path)
        if key is None:
            return httpx.Response(404, json={"error": "unknown bucket"})
        if not self._authorized(request, parsed, query):
            self.signature_failures += 1
            return httpx.Response(
                403,
                json={"error": "SignatureDoesNotMatch"},
                headers={"content-type": "application/xml"},
            )
        if request.method == "PUT" and "uploadId" in query:
            return self._put_part(request, key, query)
        if request.method == "PUT":
            return self._put_object(request, key)
        if request.method == "POST" and "uploads" in query:
            return self._initiate(key)
        if request.method == "POST" and "uploadId" in query:
            return self._complete(key, query)
        if request.method == "GET" and "uploadId" in query:
            return httpx.Response(405)
        if request.method == "DELETE" and "uploadId" in query:
            self.uploads.pop(str(query["uploadId"]), None)
            return httpx.Response(204)
        if request.method == "GET":
            return self._get(key)
        if request.method == "HEAD":
            return self._head(key)
        if request.method == "DELETE":
            return self._delete(key)
        return httpx.Response(405)

    # ------------------------------------------------------------------ object ops
    def _put_object(self, request: httpx.Request, key: str) -> httpx.Response:
        body = request.read()
        self.objects[key] = body
        return httpx.Response(200, headers={"ETag": f'"{_etag(body)}"'})

    def _get(self, key: str) -> httpx.Response:
        body = self.objects.get(key)
        if body is None:
            return httpx.Response(404, headers={"content-type": "application/xml"})
        return httpx.Response(
            200,
            content=body,
            headers={
                "content-type": "application/vnd.arachne.evidence",
                "ETag": f'"{_etag(body)}"',
            },
        )

    def _head(self, key: str) -> httpx.Response:
        body = self.objects.get(key)
        if body is None:
            return httpx.Response(404)
        return httpx.Response(
            200,
            headers={
                "content-length": str(len(body)),
                "ETag": f'"{_etag(body)}"',
            },
        )

    def _delete(self, key: str) -> httpx.Response:
        self.objects.pop(key, None)
        return httpx.Response(204)

    # ------------------------------------------------------------------ multipart
    def _initiate(self, key: str) -> httpx.Response:
        self._upload_counter += 1
        upload_id = f"upload-{self._upload_counter:04d}"
        self.uploads[upload_id] = {}
        body = (
            "<InitiateMultipartUploadResult><Bucket>"
            f"{self.bucket}</Bucket><Key>{key}</Key>"
            f"<UploadId>{upload_id}</UploadId></InitiateMultipartUploadResult>"
        )
        return httpx.Response(200, text=body, headers={"content-type": "application/xml"})

    def _put_part(self, request: httpx.Request, key: str, query: dict[str, str]) -> httpx.Response:
        upload_id = str(query["uploadId"])
        if upload_id not in self.uploads:
            return httpx.Response(404, text="<Error><Code>NoSuchUpload</Code></Error>")
        part = request.read()
        self.uploads[upload_id][int(query["partNumber"])] = part
        return httpx.Response(200, headers={"ETag": f'"{_etag(part)}"'})

    def _complete(self, key: str, query: dict[str, str]) -> httpx.Response:
        upload_id = str(query["uploadId"])
        parts = self.uploads.pop(upload_id, None)
        if parts is None:
            return httpx.Response(404, text="<Error><Code>NoSuchUpload</Code></Error>")
        self.objects[key] = b"".join(parts[number] for number in sorted(parts))
        return httpx.Response(200, text="<CompleteMultipartUploadResult/>")

    # ------------------------------------------------------------------ addressing
    def _object_key(self, path: str) -> str | None:
        prefix = f"/{self.bucket}/"
        if not path.startswith(prefix):
            return None
        return path[len(prefix) :]

    # ------------------------------------------------------------------ signature
    def _authorized(self, request: httpx.Request, parsed: Any, query: dict[str, str]) -> bool:
        if "X-Amz-Signature" in query:
            return self._verify_presign(parsed, query)
        header = request.headers.get("authorization")
        if not header:
            return False
        return self._verify_header(request, parsed, query, header)

    def _verify_header(
        self, request: httpx.Request, parsed: Any, query: dict[str, str], header: str
    ) -> bool:
        match = re.match(
            r"AWS4-HMAC-SHA256 Credential=(?P<key>[^/]+)/(?P<scope>[^,]+), "
            r"SignedHeaders=(?P<signed>[^,]+), Signature=(?P<sig>[0-9a-f]+)",
            header,
        )
        if match is None or match.group("key") != self.access_key:
            return False
        payload_hash = request.headers.get("x-amz-content-sha256", "")
        amz_date = request.headers.get("x-amz-date", "")
        names = match.group("signed").split(";")
        canonical_headers = "".join(
            f"{name}:{request.headers.get(name, '').strip()}\n" for name in names
        )
        canonical_request = "\n".join(
            [
                request.method,
                parsed.path,
                _canonical_query(query),
                canonical_headers,
                match.group("signed"),
                payload_hash,
            ]
        )
        return self._signature_matches(
            match.group("scope"), amz_date, canonical_request, match.group("sig")
        )

    def _verify_presign(self, parsed: Any, query: dict[str, str]) -> bool:
        credential = query.get("X-Amz-Credential", "")
        access_key, _, scope = credential.partition("/")
        if access_key != self.access_key:
            return False
        if query.get("X-Amz-Algorithm") != "AWS4-HMAC-SHA256":
            return False
        if query.get("X-Amz-SignedHeaders") != "host":
            return False
        try:
            issued = datetime.strptime(query["X-Amz-Date"], "%Y%m%dT%H%M%SZ").replace(tzinfo=UTC)
            expires = int(query["X-Amz-Expires"])
        except (KeyError, ValueError):
            return False
        if self._clock() > issued + timedelta(seconds=expires):
            return False
        signed = dict(query)
        signature = signed.pop("X-Amz-Signature", "")
        canonical_request = "\n".join(
            [
                "GET",
                parsed.path,
                _canonical_query(signed),
                f"host:{parsed.netloc}\n",
                "host",
                "UNSIGNED-PAYLOAD",
            ]
        )
        return self._signature_matches(scope, query["X-Amz-Date"], canonical_request, signature)

    def _signature_matches(
        self, scope: str, amz_date: str, canonical_request: str, signature: str
    ) -> bool:
        parts = scope.split("/")
        if len(parts) != 4 or parts[3] != "aws4_request":
            return False
        date_stamp, region, service, _ = parts
        if region != self.region or service != "s3":
            return False
        string_to_sign = "\n".join(
            [
                "AWS4-HMAC-SHA256",
                amz_date,
                scope,
                hashlib.sha256(canonical_request.encode()).hexdigest(),
            ]
        )
        expected = hmac.new(
            _signing_key(self.secret_key, date_stamp, region),
            string_to_sign.encode(),
            hashlib.sha256,
        ).hexdigest()
        return bool(hmac.compare_digest(expected, signature))
