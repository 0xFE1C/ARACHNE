"""The evidence service: offload, quota, preview and download in one seam (S20).

The checks step produces :class:`~arachne.core.results.CheckResult` objects; this service
decides what happens to their payloads before the finding store writes them:

1. **Quota first (REQ-DATA-003).** The logical size of everything the result carries is
   checked against the project's quota *before* a byte is written. Over the hard limit the
   service raises :class:`~arachne.core.errors.StorageQuotaError` and nothing is stored — the
   scan fails in a state ``arachne scan --resume`` can continue. Over the soft threshold it
   records one ``quota.warning`` per scan, which is the notice the requirement asks for.
2. **Offload the big ones (REQ-DATA-002/004).** A payload at or above
   ``offload_threshold_bytes`` is written to the configured backend under its content hash.
   What the row keeps is a **stub**: every scalar field, every string truncated to
   ``preview_chars``, plus the object's key, digest and size. The stub is what a report and
   the UI render, so an offloaded finding still reads correctly; the full object is one
   presigned (or streamed) download away. Two identical payloads share one object.
3. **Count it.** Bytes written, bytes saved by dedup and per-backend totals go to the
   metrics registry, and the offload itself is audited with its key and digest — never its
   content.

Keeping this out of :class:`~arachne.data.finding_store.SqlFindingStore` is deliberate: the
store is synchronous and must stay usable from the report and analyzer paths, while offload
is network I/O. The store's job is to persist the stub and account for its bytes.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping
from dataclasses import replace
from typing import Any, Final

from arachne.core.audit import AuditAction, Auditor, AuditOutcome
from arachne.core.config import EvidenceSettings, Settings
from arachne.core.errors import EvidenceStoreError, ResidencyError
from arachne.core.metrics import REGISTRY
from arachne.core.pii import PIIPolicy, mask_payload
from arachne.core.results import CheckResult, Evidence
from arachne.data.evidence_backend import EvidenceBackend, iter_backend_object
from arachne.data.quota import QuotaState, StorageQuota

__all__ = ["EVIDENCE_STUB_KEY", "EvidenceService", "serialized_size"]

#: The marker that makes a stub self-describing. The finding store reads ``backend``/``key``/
#: ``size`` from it to fill ``evidences.storage``/``storage_key``/``size_bytes``.
EVIDENCE_STUB_KEY: Final = "offloaded"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def serialized_size(payload: Mapping[str, Any]) -> int:
    """Logical bytes of one evidence payload (the number quota and metrics count)."""
    return len(
        json.dumps(payload, default=str, ensure_ascii=False, sort_keys=True).encode("utf-8")
    )


def _truncate(value: Any, limit: int, depth: int = 0) -> Any:
    """Copy a payload with every string bounded — the preview an offloaded stub keeps."""
    if depth > 8:
        return None
    if isinstance(value, str):
        return value[:limit]
    if isinstance(value, Mapping):
        return {str(key): _truncate(item, limit, depth + 1) for key, item in value.items()}
    if isinstance(value, list | tuple):
        return [_truncate(item, limit, depth + 1) for item in value[:64]]
    return value


class EvidenceService:
    """Offloads large payloads, enforces the quota, masks PII and hands out download access.

    ``pii_policy`` resolves the project's PII policy (S25, REQ-TRUST-006); when it returns an
    active policy every staged payload is masked before it can reach the database or an
    object store, and the categories removed are counted for the audit line. ``region`` is
    the deployment's region (S25, REQ-RESIL-004): the residency gate reads it to refuse a
    payload that belongs to another region.
    """

    def __init__(
        self,
        backend: EvidenceBackend,
        *,
        settings: Settings | None = None,
        quota: StorageQuota | None = None,
        auditor: Auditor | None = None,
        pii_policy: Callable[[int | None], PIIPolicy] | None = None,
        region: str | None = None,
    ) -> None:
        from arachne.core.config import get_settings

        self.settings = settings or get_settings()
        self.backend = backend
        self.quota = quota
        self.auditor = auditor
        self._pii_policy = pii_policy
        self.region = region
        self.threshold = self.settings.evidence.offload_threshold_bytes
        self.preview_chars = self.settings.evidence.preview_chars
        #: Projects this process has already warned about, so a scan crossing the soft
        #: threshold logs it once rather than once per candidate.
        self._warned: set[tuple[int | None, int]] = set()

    @property
    def config(self) -> EvidenceSettings:
        return self.settings.evidence

    def policy_for(self, project_id: int | None) -> PIIPolicy:
        """The PII policy in force for ``project_id`` (no resolver means masking off)."""
        if self._pii_policy is None:
            return PIIPolicy()
        return self._pii_policy(project_id)

    # ------------------------------------------------------------------ staging
    async def stage(
        self, result: CheckResult, *, scan_id: int, project_id: int | None
    ) -> CheckResult:
        """Mask PII, check the quota, offload oversized payloads, return the staged result."""
        result = self._mask_pii(result, scan_id=scan_id, project_id=project_id)
        sizes = [serialized_size(item.payload) for item in result.evidence]
        incoming = sum(sizes)
        self._enforce_quota(project_id, incoming, scan_id=scan_id)

        staged: list[Evidence] = []
        for item, size in zip(result.evidence, sizes, strict=True):
            if size < self.threshold or not item.payload:
                staged.append(item)
                continue
            blob = json.dumps(item.payload, default=str, ensure_ascii=False, sort_keys=True).encode(
                "utf-8"
            )
            digest = item.sha256 or _sha256(blob)
            # The stub is built before the upload so its size can be compared with the payload
            # it would replace: a payload barely over the threshold has a stub *larger* than
            # itself (the reference metadata costs ~200 bytes), and offloading it would grow
            # the database to shrink nothing. Such a payload stays inline.
            stub: dict[str, Any] = dict(_truncate(item.payload, self.preview_chars))
            stub.update(
                {
                    EVIDENCE_STUB_KEY: True,
                    "backend": self.backend.kind,
                    "key": digest,
                    "sha256": digest,
                    "size": size,
                    "preview_chars": self.preview_chars,
                }
            )
            if len(json.dumps(stub, default=str, ensure_ascii=False, sort_keys=True)) >= size:
                staged.append(item)
                continue
            stored = await self.backend.put(blob)
            if stored.key != digest:  # pragma: no cover - a backend must be content-addressed
                msg = f"the {stored.backend} backend returned key {stored.key} for digest {digest}"
                raise EvidenceStoreError(msg)
            staged.append(
                Evidence(
                    kind=item.kind,
                    payload=stub,
                    sha256=digest,
                    captured_at=item.captured_at,
                    source=item.source,
                )
            )
            self._count(stored.backend, stored.size, stored.stored_size, stored.deduplicated)
            if self.auditor is not None:
                self.auditor.record(
                    AuditAction.EVIDENCE_STORED,
                    scan_id=scan_id,
                    target=item.kind,
                    meta={
                        "backend": stored.backend,
                        "key": stored.key,
                        "size": stored.size,
                        "stored_size": stored.stored_size,
                        "deduplicated": stored.deduplicated,
                    },
                )
        if len(staged) == len(result.evidence) and all(
            original is new for original, new in zip(result.evidence, staged, strict=True)
        ):
            return result
        return replace(result, evidence=tuple(staged))

    def _mask_pii(
        self, result: CheckResult, *, scan_id: int, project_id: int | None
    ) -> CheckResult:
        """Mask PII in every payload before it can be stored (S25, REQ-TRUST-006).

        Runs *first* in :meth:`stage`, so a masked value can never reach the quota
        accounting, an offloaded object or the finding store — the ordering is the
        guarantee, and it is why this is not a report-time filter. Masking is
        irreversible on purpose: a deployment that could un-mask would have kept the value.
        """
        policy = self.policy_for(project_id)
        if not policy.active:
            return result
        counts: dict[str, int] = {}
        staged: list[Evidence] = []
        for item in result.evidence:
            masked, item_counts = mask_payload(item.payload, policy)
            for category, count in item_counts.items():
                counts[category] = counts.get(category, 0) + count
            if item_counts:
                staged.append(replace(item, payload=masked))
            else:
                staged.append(item)
        if not counts:
            return result
        if self.auditor is not None:
            self.auditor.record(
                AuditAction.PII_MASKED,
                scan_id=scan_id,
                target="evidence",
                meta={
                    "project_id": project_id,
                    "action": policy.action,
                    "categories": counts,
                    "total": sum(counts.values()),
                },
            )
        return replace(result, evidence=tuple(staged))

    # ------------------------------------------------------------------ residency
    def require_region(self, region: str | None, *, scan_id: int | None = None) -> None:
        """Refuse evidence access that crosses a region boundary (S25, REQ-RESIL-004).

        A row with no region, or a deployment with no region declared, is not pinned and so
        cannot be violated. Once both are set, only an exact match is served — that is the
        "residency pinning must refuse cross-region evidence access" hard rule, and it
        composes with the scope gate rather than beside it by raising the same family of
        error (``ResidencyError`` is an ``OutOfScopeError``).
        """
        if self.region is None or region is None or region == self.region:
            return
        reason = (
            f"evidence is pinned to region {region!r}; this deployment serves "
            f"{self.region!r} and will not read across the boundary"
        )
        if self.auditor is not None:
            self.auditor.record(
                AuditAction.RESIDENCY_REJECTED,
                outcome=AuditOutcome.BLOCKED,
                scan_id=scan_id,
                target=f"region:{region}",
                reason=reason,
                meta={"home_region": self.region, "requested_region": region},
            )
        raise ResidencyError(reason, reason="residency")

    def _enforce_quota(
        self, project_id: int | None, incoming: int, *, scan_id: int
    ) -> QuotaState | None:
        """Warn at the soft threshold, then refuse at the limit (REQ-DATA-003).

        The warning is recorded *before* the refusal, and independently of it: a write that
        crosses the soft threshold and the hard limit in one step still gets its warning
        line, so the trail always says "it was getting full" before it says "it stopped".
        """
        if self.quota is None:
            return None
        state = self.quota.state(project_id, incoming)
        key = (project_id, scan_id)
        if state.warning and key not in self._warned:
            self._warned.add(key)
            if self.auditor is not None:
                self.auditor.record(
                    AuditAction.QUOTA_WARNING,
                    scan_id=scan_id,
                    meta={
                        "project_id": project_id,
                        "used_bytes": state.used_bytes,
                        "incoming_bytes": incoming,
                        "limit_bytes": state.limit_bytes,
                        "ratio": round(state.ratio, 4),
                    },
                )
        if state.exceeded:
            self.quota.enforce(project_id, incoming, context=f"scan {scan_id}")
        return state

    def _count(self, backend: str, size: int, stored_size: int, deduplicated: bool) -> None:
        REGISTRY.increment("arachne_evidence_bytes_total", {"backend": backend}, float(size))
        if not deduplicated:
            REGISTRY.increment(
                "arachne_evidence_stored_bytes_total", {"backend": backend}, float(stored_size)
            )
        else:
            REGISTRY.increment("arachne_evidence_dedup_hits_total", {"backend": backend})

    # ------------------------------------------------------------------ access
    async def download(self, key: str, *, region: str | None = None) -> bytes:
        """The full logical payload for one stored object."""
        self.require_region(region)
        return await self.backend.get(key)

    async def iter_download(self, key: str, *, region: str | None = None) -> Any:
        """Stream one payload in chunks."""
        self.require_region(region)
        async for chunk in iter_backend_object(self.backend, key):
            yield chunk

    async def delete(self, key: str) -> bool:
        """Remove one object (the retention job's hook)."""
        return await self.backend.delete(key)

    def presign(
        self, key: str, *, filename: str | None = None, region: str | None = None
    ) -> str | None:
        """A time-limited URL for the backend, or ``None`` when it streams through the API."""
        self.require_region(region)
        return self.backend.presign(
            key, ttl_s=self.config.presign_ttl_s, filename=filename
        )

    def stats(self) -> dict[str, Any]:
        return self.backend.stats()

    def stub_key(self, payload: Mapping[str, Any]) -> str | None:
        """The backend key inside an offloaded stub, if this payload is one."""
        if not payload.get(EVIDENCE_STUB_KEY):
            return None
        key = payload.get("key")
        return str(key) if key else None
