"""The feed sync service: fetch, verify, import, record (REQ-INTEL-001/002).

The flow is deliberately short and fail-closed::

    cursor from the stored feed → fetch (one host per source, scope-checked, audited)
    → parse → verify (integrity before anything is written) → import → audit + freshness

Four invariants make it trustworthy:

1. **Verified before imported.** :func:`~arachne.intel.verify.verify_payload` runs on the
   raw bytes, and a payload whose digest (or signature) does not match what the deployment
   pinned is refused and audited. A rejected sync writes nothing — no rows, no artefact.
2. **Incremental.** Each source resumes from the cursor of the last import: NVD from the
   ``lastModEndDate`` the API reported, EPSS from the score date, KEV by version (an
   unchanged catalogue is a no-op, not a re-import).
3. **Versioned.** The upstream version is stored on the feed row and compared on the next
   run, so "we synced and nothing changed" is reported as such rather than as a new feed.
4. **Offline-capable.** A :class:`FixtureFeedTransport` replays recorded responses, so the
   whole path — including verification, because the fixtures carry their own pins — runs with
   no packet leaving the process. That is the test path *and* the air-gapped demo path.

One host table, one egress path: the live transport is a
:class:`~arachne.core.http.ScopedHttpClient` whose scope is exactly
``IntelSettings.source_hosts()`` (mirrored by ``core.config.INTEL_FEED_HOSTS``), so a feed
mirror that is not named in the configuration is out of scope and the request is refused
before a socket is opened (ADR-05, F-01-02).
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Protocol

from arachne.core.audit import AuditAction, Auditor, AuditOutcome
from arachne.core.config import IntelSettings
from arachne.core.errors import ConfigurationError, FeedIntegrityError
from arachne.core.http import ScopedHttpClient
from arachne.core.logging import get_logger
from arachne.core.safety import Scope
from arachne.data.feed_store import FeedRecord, FeedStore
from arachne.intel.sources import (
    FeedDocument,
    epss_url,
    feed_version_label,
    kev_url,
    nvd_url,
    nvd_window,
    parse_source,
    source_for,
)
from arachne.intel.verify import VerificationPolicy, VerificationResult, digest_of, verify_payload

__all__ = [
    "FeedPayload",
    "FeedSyncService",
    "FixtureFeedTransport",
    "ScopedFeedTransport",
    "SyncOutcome",
    "canonical_payload",
    "feed_sync_policy",
]

_logger = get_logger("intel.sync")

#: How many CVEs are requested per NVD page (the API's documented maximum).
_NVD_PAGE_SIZE = 2000
#: How many EPSS scores are requested per page (the API's documented maximum offset window).
_EPSS_PAGE_SIZE = 5000


@dataclass(frozen=True, slots=True)
class FeedPayload:
    """One fetched document: the bytes, where they came from, and any detached signature."""

    source: str
    url: str
    body: bytes
    status: int = 200
    headers: Mapping[str, str] = field(default_factory=dict)
    signature: bytes | None = None
    fetched_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300

    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


def canonical_payload(payloads: Sequence[FeedPayload]) -> bytes:
    """The bytes verification covers for one source's sync.

    A source fetched in a **single** request (the normal case: KEV is one document, and an
    incremental NVD or EPSS window usually fits one page) is verified over its raw body, so an
    operator's pin is exactly what ``sha256sum`` prints for the file they fetched. A source
    that needed several requests (NVD paginates, EPSS pages by offset) is verified as a *set*:
    each body is length-prefixed and concatenated in fetch order, so the digest covers every
    byte of every page and reordering the pages changes it. ``sync --pin`` records whichever
    form applies, which is why a re-pin is needed when a window outgrows one page.
    """
    if len(payloads) == 1:
        return payloads[0].body
    out = bytearray()
    for payload in payloads:
        out += len(payload.body).to_bytes(8, "big")
        out += payload.body
    return bytes(out)


class FeedTransport(Protocol):
    """How the sync reaches a source. One method, so a fixture set can stand in for the net."""

    async def fetch(self, source: str, url: str) -> FeedPayload:
        """Fetch one document for ``source`` at ``url``."""
        ...

    async def aclose(self) -> None:
        """Release any transport resources."""
        ...


# --------------------------------------------------------------------------- fixture replay
class FixtureFeedTransport:
    """Replay recorded feed responses instead of contacting anything.

    A recording is one JSON file per source::

        {"source": "kev", "url": "https://www.cisa.gov/...", "status": 200,
         "headers": {...}, "body": "<the document text>"}

    An optional sibling ``<source>.sig`` (base64 or PEM signature bytes) carries the detached
    signature for ``verify=signature`` mode. The transport is the *only* thing that changes
    between a live sync and a replayed one, which is why the offline path exercises the same
    verification, parsing, import and audit code.
    """

    def __init__(self, directory: str | Path) -> None:
        self.directory = Path(directory).expanduser()
        if not self.directory.is_dir():
            msg = f"intel fixtures directory {self.directory} does not exist"
            raise ConfigurationError(msg)
        self._responses = self._load()
        self.requests: list[tuple[str, str]] = []

    def _load(self) -> dict[str, FeedPayload]:
        responses: dict[str, FeedPayload] = {}
        for path in sorted(self.directory.glob("*.json")):
            if path.name.startswith("."):
                continue
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                msg = f"cannot read intel fixture {path}: {exc}"
                raise ConfigurationError(msg) from exc
            if not isinstance(data, Mapping) or "body" not in data:
                continue
            source = str(data.get("source") or path.stem)
            if source in responses:  # first file wins; a recording is one document per source
                continue
            signature_path = path.with_suffix(".sig")
            responses[source] = FeedPayload(
                source=source,
                url=str(data.get("url") or f"fixture://{source}"),
                body=str(data["body"]).encode("utf-8"),
                status=int(data.get("status", 200)),
                headers={
                    str(key): str(value) for key, value in (data.get("headers") or {}).items()
                },
                signature=(
                    signature_path.read_bytes() if signature_path.is_file() else None
                ),
            )
        return responses

    def sources(self) -> tuple[str, ...]:
        return tuple(self._responses)

    async def fetch(self, source: str, url: str) -> FeedPayload:
        """Return the recorded payload for ``source`` (the URL is recorded, not followed)."""
        self.requests.append((source, url))
        try:
            recorded = self._responses[source]
        except KeyError as exc:
            msg = f"no recorded response for intel source {source!r} in {self.directory}"
            raise ConfigurationError(msg) from exc
        # The recording keeps its own URL for provenance; the signature is fetched through
        # ``fetch_signature`` below, exactly as the live transport does it.
        return FeedPayload(
            source=source,
            url=recorded.url,
            body=recorded.body,
            status=recorded.status,
            headers=recorded.headers,
        )

    async def fetch_signature(self, source: str, url: str) -> bytes | None:
        """The recorded detached signature (``<source>.sig``), or ``None`` when absent."""
        recorded = self._responses.get(source)
        return recorded.signature if recorded is not None else None

    async def aclose(self) -> None:
        return None


# --------------------------------------------------------------------------- live transport
class ScopedFeedTransport:
    """The live path: a scope-pinned HTTP client, one line of audit per request.

    Two client-level settings are deliberately different from the scanning client's, and both
    are needed for the same reason — a feed must be read **verbatim** to be verified:

    * redaction is off. A feed payload is integrity-checked (a redaction pass would edit it
      and the digest would no longer match what the publisher signed or the deployment
      pinned), it is parsed structurally rather than echoed, and it is never logged, stored as
      evidence, or sent anywhere. It carries nothing about the target or the deployment
      (ADR-230.3; the second and last such exemption, asserted by
      ``tests/unit/test_http_hygiene.py``).
    * the response cap is raised: a page of 2,000 NVD records is megabytes, and the shared
      64 KiB default would truncate it. A body that is *still* truncated is refused rather
      than verified, because a digest over half a feed is worse than no digest at all.

    ``request_delay_s`` is the politeness delay between two requests to the same source (NVD
    publishes a rate limit and asks to be called slowly); the shared client's per-host limiter
    still applies underneath, so the effective rate is the stricter of the two.
    """

    def __init__(
        self,
        *,
        hosts: Sequence[str],
        auditor: Auditor | None = None,
        max_bytes: int = 64 * 1024 * 1024,
        request_delay_s: float = 0.0,
        client: ScopedHttpClient | None = None,
        sleep: Callable[[float], Any] = asyncio.sleep,
    ) -> None:
        if not hosts:
            msg = "the feed sync needs at least one source host; check intel.sources"
            raise ConfigurationError(msg)
        self.hosts = tuple(hosts)
        self.auditor = auditor
        self.max_bytes = max_bytes
        self.request_delay_s = max(0.0, request_delay_s)
        self.client = client or ScopedHttpClient(
            scope=Scope(allowed_hosts=self.hosts),
            auditor=auditor,
            redaction_enabled=False,
            max_body_bytes=max_bytes,
        )
        self._sleep = sleep

    async def fetch(self, source: str, url: str) -> FeedPayload:
        """Fetch one document, rejecting a body that is truncated or over ``max_bytes``."""
        if self.request_delay_s:
            await self._sleep(self.request_delay_s)
        try:
            exchange = await self.client.get(url, headers={"accept": "application/json"})
        except Exception as exc:  # SafetyError, RequestError — both are data, not crashes
            if self.auditor is not None:
                self.auditor.record(
                    AuditAction.INTEL_FEED_FETCHED,
                    outcome=AuditOutcome.ERROR,
                    target=url,
                    reason=f"{exc.__class__.__name__}: {exc}",
                    meta={"source": source},
                )
            raise ConfigurationError(f"{source}: fetch of {url} failed: {exc}") from exc
        body = exchange.body.encode("utf-8")
        problem = None
        if exchange.body_truncated:
            problem = (
                f"the response was truncated at the {self.max_bytes} byte read cap; a partial "
                "feed cannot be verified"
            )
        elif exchange.body_is_binary:
            problem = "the response was not text; a feed document must be JSON"
        elif len(body) > self.max_bytes:
            problem = f"response is {len(body)} bytes, over the {self.max_bytes} byte cap"
        if problem is not None:
            if self.auditor is not None:
                self.auditor.record(
                    AuditAction.INTEL_FEED_FETCHED,
                    outcome=AuditOutcome.BLOCKED,
                    target=url,
                    reason=problem,
                    meta={"source": source, "status": exchange.status_code},
                )
            raise ConfigurationError(f"{source}: {problem}")
        if self.auditor is not None:
            self.auditor.record(
                AuditAction.INTEL_FEED_FETCHED,
                target=url,
                meta={"source": source, "status": exchange.status_code, "bytes": len(body)},
            )
        return FeedPayload(
            source=source,
            url=url,
            body=body,
            status=exchange.status_code,
            headers={key.lower(): value for key, value in exchange.response_headers.items()},
        )

    async def fetch_signature(self, source: str, url: str) -> bytes | None:
        """The detached signature for ``url`` (``<url>.sig``), or ``None`` when absent.

        A missing signature is not an error here: the verification policy decides whether it
        is fatal (``signature`` mode refuses) or irrelevant (``checksum`` mode).
        """
        try:
            exchange = await self.client.get(f"{url}.sig")
        except Exception:
            return None
        if not exchange.ok:
            return None
        text = exchange.body.strip()
        return text.encode("utf-8")

    async def aclose(self) -> None:
        await self.client.aclose()


# --------------------------------------------------------------------------- outcomes
@dataclass(frozen=True, slots=True)
class SyncOutcome:
    """What one source's sync did, and why."""

    source: str
    kind: str
    status: str  # imported | unchanged | rejected | error
    version: str | None = None
    record_count: int = 0
    feed_id: int | None = None
    digest: str | None = None
    verified: bool = False
    verification: VerificationResult | None = None
    url: str | None = None
    reason: str | None = None

    @property
    def imported(self) -> bool:
        return self.status == "imported"

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "kind": self.kind,
            "status": self.status,
            "version": self.version,
            "record_count": self.record_count,
            "feed_id": self.feed_id,
            "digest": self.digest,
            "verified": self.verified,
            "url": self.url,
            "reason": self.reason,
            "verification": self.verification.to_dict() if self.verification else None,
        }


# --------------------------------------------------------------------------- the service
class FeedSyncService:
    """Fetch, verify and import the configured threat-intel feeds."""

    def __init__(
        self,
        *,
        store: FeedStore,
        transport: FeedTransport,
        policy: VerificationPolicy,
        settings: IntelSettings | None = None,
        auditor: Auditor | None = None,
        imported_by: str | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self.store = store
        self.transport = transport
        self.policy = policy
        self.settings = settings or IntelSettings(enabled=True)
        self.auditor = auditor
        self.imported_by = imported_by
        self._now = now or (lambda: datetime.now(UTC))

    # ------------------------------------------------------------------ entry points
    async def sync(
        self, sources: Sequence[str] | None = None, *, force: bool = False
    ) -> tuple[SyncOutcome, ...]:
        """Sync every named source (or the configured set), one at a time.

        Sources are processed in order and a failure in one is recorded as that source's
        outcome rather than aborting the run: a mirror that is down must not stop the other
        two feeds from being brought up to date.
        """
        names = tuple(source_for(name).name for name in (sources or self.settings.sources))
        outcomes: list[SyncOutcome] = []
        for name in names:
            try:
                outcomes.append(await self.sync_source(name, force=force))
            except (ConfigurationError, FeedIntegrityError) as exc:
                outcomes.append(
                    SyncOutcome(
                        source=name,
                        kind=source_for(name).kind,
                        status="error",
                        reason=f"{exc.__class__.__name__}: {exc}",
                    )
                )
        return tuple(outcomes)

    async def sync_source(self, source: str, *, force: bool = False) -> SyncOutcome:
        """Sync one source: fetch, verify, and import unless it is already current."""
        spec = source_for(source)
        previous = self.store.active(spec.kind)
        payloads = await self._fetch(spec.name, previous)
        if not payloads:
            return SyncOutcome(
                source=spec.name, kind=spec.kind, status="error", reason="no payload was fetched"
            )
        if not all(item.ok for item in payloads):
            statuses = ",".join(str(item.status) for item in payloads)
            return SyncOutcome(
                source=spec.name,
                kind=spec.kind,
                status="error",
                url=payloads[0].url,
                reason=f"upstream returned HTTP {statuses}",
            )

        body = canonical_payload(payloads)
        digest = digest_of(body)
        signature = payloads[0].signature
        if signature is None and self.policy.mode == "signature":
            signature = await self._signature_for(spec.name, payloads[0].url)
        verification = verify_payload(
            source=spec.name,
            payload=body,
            policy=self.policy,
            signature=signature,
        )
        self._audit_verification(spec.name, verification, payloads[0].url)
        if not verification.verified:
            return SyncOutcome(
                source=spec.name,
                kind=spec.kind,
                status="rejected",
                digest=digest,
                verified=False,
                verification=verification,
                url=payloads[0].url,
                reason=verification.reason,
            )

        document = _merge_documents(spec.name, payloads)
        version = feed_version_label(document)
        if not force and previous is not None and previous.version == version:
            return SyncOutcome(
                source=spec.name,
                kind=spec.kind,
                status="unchanged",
                version=version,
                record_count=previous.record_count,
                feed_id=previous.id,
                digest=digest,
                verified=True,
                verification=verification,
                url=payloads[0].url,
                reason="the upstream version is the one already stored",
            )

        meta = {
            "source": spec.name,
            "url": payloads[0].url,
            "cursor": document.cursor,
            "published_at": document.published_at,
            "verification": verification.to_dict(),
            "sha256": digest,
            "verified": True,
            "pages": len(payloads),
            "total_results": document.total_results,
        }
        record = self.store.import_entries(
            document.entries,
            kind=spec.kind,
            name=f"{spec.name}-{version}",
            version=version,
            source=payloads[0].url,
            imported_by=self.imported_by,
            meta=meta,
        )
        self._audit_sync(
            spec.name, spec.kind, version, len(document.entries), digest, payloads[0].url
        )
        _logger.info(
            "intel feed synced",
            extra={
                "event": "intel.feed_synced",
                "source": spec.name,
                "kind": spec.kind,
                "version": version,
                "records": len(document.entries),
                "digest": digest,
                "verified": True,
            },
        )
        return SyncOutcome(
            source=spec.name,
            kind=spec.kind,
            status="imported",
            version=version,
            record_count=len(document.entries),
            feed_id=record.id,
            digest=digest,
            verified=True,
            verification=verification,
            url=payloads[0].url,
        )

    async def aclose(self) -> None:
        await self.transport.aclose()

    # ------------------------------------------------------------------ pinning
    async def fetch_and_pin(
        self, sources: Sequence[str] | None = None
    ) -> tuple[dict[str, str], tuple[SyncOutcome, ...]]:
        """Fetch the named sources and return ``{source: sha256}`` without importing.

        This is the *explicit* trust decision behind checksum verification: the operator runs
        it once (after establishing, out of band, that the mirror is the one they mean), and
        the resulting manifest is what every later sync is checked against. It is audited as
        ``intel.checksums_pinned`` — pinning is not a background convenience, it is the moment
        the deployment decides what "the real feed" is.
        """
        names = tuple(source_for(name).name for name in (sources or self.settings.sources))
        pins: dict[str, str] = {}
        outcomes: list[SyncOutcome] = []
        for name in names:
            try:
                payloads = await self._fetch(name, self.store.active(source_for(name).kind))
            except (ConfigurationError, FeedIntegrityError) as exc:
                outcomes.append(
                    SyncOutcome(
                        source=name,
                        kind=source_for(name).kind,
                        status="error",
                        reason=f"{exc.__class__.__name__}: {exc}",
                    )
                )
                continue
            if not payloads or not all(item.ok for item in payloads):
                outcomes.append(
                    SyncOutcome(
                        source=name,
                        kind=source_for(name).kind,
                        status="error",
                        reason="no usable payload was fetched",
                    )
                )
                continue
            digest = digest_of(canonical_payload(payloads))
            pins[name] = digest
            if self.auditor is not None:
                self.auditor.record(
                    AuditAction.INTEL_CHECKSUMS_PINNED,
                    target=payloads[0].url,
                    meta={"source": name, "digest": digest, "pages": len(payloads)},
                )
            outcomes.append(
                SyncOutcome(
                    source=name,
                    kind=source_for(name).kind,
                    status="pinned",
                    digest=digest,
                    url=payloads[0].url,
                )
            )
        return pins, tuple(outcomes)

    async def _signature_for(self, source: str, url: str) -> bytes | None:
        """Ask the transport for a detached signature; ``None`` when it cannot provide one.

        A transport that does not implement ``fetch_signature`` (a test double, a replay
        without a ``.sig``) yields ``None``, and signature mode then refuses the import — the
        same fail-closed answer as a missing key on the provider side.
        """
        getter = getattr(self.transport, "fetch_signature", None)
        if not callable(getter):
            return None
        result: bytes | None = await getter(source, url)
        return result

    # ------------------------------------------------------------------ fetching
    async def _fetch(self, source: str, previous: FeedRecord | None) -> list[FeedPayload]:
        if source == "nvd":
            return await self._fetch_nvd(previous)
        if source == "epss":
            return await self._fetch_epss(previous)
        return [await self.transport.fetch("kev", kev_url())]

    async def _fetch_nvd(self, previous: FeedRecord | None) -> list[FeedPayload]:
        cursor = dict(previous.meta.get("cursor") or {}) if previous is not None else {}
        start, end = nvd_window(cursor=cursor, now=self._now())
        payloads: list[FeedPayload] = []
        start_index = 0
        for _page in range(max(1, self.settings.max_pages)):
            url = nvd_url(
                last_mod_start=start,
                last_mod_end=end,
                start_index=start_index,
                results_per_page=_NVD_PAGE_SIZE,
            )
            payload = await self.transport.fetch("nvd", url)
            payloads.append(payload)
            if not payload.ok:
                break
            total = _nvd_total(payload)
            start_index += _NVD_PAGE_SIZE
            if total is None or start_index >= total:
                break
        return payloads

    async def _fetch_epss(self, previous: FeedRecord | None) -> list[FeedPayload]:
        since = None
        if previous is not None and previous.version:
            # ``version`` is "epss@<score date>"; the API wants the bare date.
            since = previous.version.split("@", 1)[-1]
        payloads: list[FeedPayload] = []
        offset = 0
        for _page in range(max(1, self.settings.max_pages)):
            url = epss_url(
                since=since, offset=offset, limit=_EPSS_PAGE_SIZE
            ) if since else epss_url(offset=offset, limit=_EPSS_PAGE_SIZE)
            payload = await self.transport.fetch("epss", url)
            payloads.append(payload)
            if not payload.ok:
                break
            total = _epss_total(payload)
            offset += _EPSS_PAGE_SIZE
            if total is None or offset >= total:
                break
        return payloads

    # ------------------------------------------------------------------ audit
    def _audit_verification(
        self, source: str, verification: VerificationResult, url: str
    ) -> None:
        if self.auditor is None:
            return
        if verification.verified:
            self.auditor.record(
                AuditAction.INTEL_FEED_VERIFIED,
                target=url,
                meta={
                    "source": source,
                    "mode": verification.mode,
                    "digest": verification.digest,
                    "key_id": verification.key_id,
                },
            )
            return
        self.auditor.record(
            AuditAction.INTEL_FEED_REJECTED,
            outcome=AuditOutcome.BLOCKED,
            target=url,
            reason=verification.reason or "feed verification failed",
            meta={
                "source": source,
                "mode": verification.mode,
                "digest": verification.digest,
                "expected": verification.expected,
            },
        )

    def _audit_sync(
        self, source: str, kind: str, version: str, count: int, digest: str, url: str
    ) -> None:
        if self.auditor is None:
            return
        self.auditor.record(
            AuditAction.INTEL_FEED_SYNCED,
            target=url,
            meta={
                "source": source,
                "kind": kind,
                "version": version,
                "records": count,
                "digest": digest,
            },
        )


def _nvd_total(payload: FeedPayload) -> int | None:
    """``totalResults`` from an NVD page, without a second full parse."""
    try:
        data = json.loads(payload.text())
    except json.JSONDecodeError:
        return None
    if isinstance(data, dict) and isinstance(data.get("totalResults"), int):
        return int(data["totalResults"])
    return None


def _epss_total(payload: FeedPayload) -> int | None:
    """``total`` from an EPSS page (the API pages by offset against it)."""
    try:
        data = json.loads(payload.text())
    except json.JSONDecodeError:
        return None
    if isinstance(data, dict) and isinstance(data.get("total"), int):
        return int(data["total"])
    return None


def _merge_documents(source: str, payloads: Sequence[FeedPayload]) -> FeedDocument:
    """Parse each fetched page and merge them into one document.

    A paginated source delivers several self-contained documents; verification covers the
    concatenation (see :func:`canonical_payload`), while the *import* wants one normalised
    set of entries. Later pages win on a repeated CVE, the first page owns the version
    (upstream reports the same one on every page of a sync), and the last page's cursor is
    the resume point — that is where the pagination actually stopped.
    """
    documents = [parse_source(source, payload.body) for payload in payloads if payload.ok]
    if not documents:
        return FeedDocument(source=source, kind=source_for(source).kind, version=None)
    if len(documents) == 1:
        return documents[0]
    entries: dict[str, dict[str, Any]] = {}
    for document in documents:
        entries.update(document.entries)
    first, last = documents[0], documents[-1]
    return FeedDocument(
        source=first.source,
        kind=first.kind,
        version=first.version,
        entries=entries,
        published_at=first.published_at,
        cursor=dict(last.cursor) or dict(first.cursor),
        total_results=first.total_results,
    )


def feed_sync_policy(
    settings: IntelSettings, *, inline: Mapping[str, str] | None = None
) -> VerificationPolicy:
    """Build the verification policy a deployment's settings describe.

    The digest pins come from ``intel.checksums`` (inline) and ``intel.checksums_file``
    (a manifest), the signature key from ``intel.public_key``. A ``signature`` deployment with
    no readable key is a configuration error rather than a silent downgrade to checksums.
    """
    from arachne.intel.verify import resolve_expectations

    digests = resolve_expectations(
        inline=dict(inline) if inline else dict(settings.checksums),
        manifest=settings.checksums_file,
    )
    pem: str | None = None
    if settings.verify == "signature":
        if not settings.public_key:
            msg = "intel.verify=signature needs intel.public_key"
            raise ConfigurationError(msg)
        path = Path(settings.public_key).expanduser()
        if not path.is_file():
            msg = f"the pinned feed public key {path} does not exist"
            raise ConfigurationError(msg)
        pem = path.read_text(encoding="utf-8")
    return VerificationPolicy(mode=settings.verify, digests=digests, public_key_pem=pem)


def build_feed_transport(
    settings: IntelSettings, *, auditor: Auditor | None = None
) -> FeedTransport:
    """The transport ``settings`` asks for: fixture replay, or the scope-pinned live client."""
    if settings.is_fixture_mode and settings.fixtures_dir:
        return FixtureFeedTransport(settings.fixtures_dir)
    return ScopedFeedTransport(
        hosts=settings.source_hosts(),
        auditor=auditor,
        max_bytes=settings.max_bytes,
        request_delay_s=settings.request_delay_s,
    )


def build_sync_service(
    store: FeedStore,
    settings: IntelSettings,
    *,
    auditor: Auditor | None = None,
    imported_by: str | None = None,
    transport: FeedTransport | None = None,
    inline_checksums: Mapping[str, str] | None = None,
) -> FeedSyncService:
    """Assemble the sync service for ``settings``.

    Raises when intel is switched off: the caller decides what to do about that (the CLI
    reports it, the API never builds one), and a service that silently does nothing would
    make "the feeds are current" unverifiable.
    """
    if not settings.enabled:
        msg = (
            "live threat-intel sync is disabled; set ARACHNE_INTEL_ENABLED=true "
            "(or run with --allow-disabled for an explicit one-off)"
        )
        raise ConfigurationError(msg)
    return FeedSyncService(
        store=store,
        transport=transport or build_feed_transport(settings, auditor=auditor),
        policy=feed_sync_policy(settings, inline=inline_checksums),
        settings=settings,
        auditor=auditor,
        imported_by=imported_by,
    )
