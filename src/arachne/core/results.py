"""Check results and the error model (docs/spec/07- §4, F-02-08 note).

"Errors are data": a check that raises must produce
``CheckResult(status="error")`` with an exception summary, never abort the scan. The
:class:`CheckResult` / :class:`Evidence` pair is the plugin contract from
``docs/spec/02-`` §5; the module base class and registry are stage S3.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal, get_args

from arachne.core.errors import ErrorInfo, error_info
from arachne.core.redaction import redact_value

__all__ = [
    "CheckResult",
    "CheckStatus",
    "Evidence",
    "EvidenceKind",
    "confidence_percent",
    "error_result",
    "guard_check",
    "sha256_of",
]

CheckStatus = Literal["vulnerable", "info", "not_vulnerable", "error"]
_CHECK_STATUSES: frozenset[str] = frozenset(get_args(CheckStatus))

EvidenceKind = Literal[
    "http_request",
    "http_response",
    "banner",
    "file_path",
    "artifact",
    "tls_certificate",
    "note",
    #: S15 (area PROOF): the per-finding proof artifact — level, method, token/hit or
    #: state-change record, cleanup status (REQ-PROOF-012/013). Same capture → redact →
    #: audit path as every other kind.
    "proof",
    #: S24 (area VALID): the purple-team tag on an emitted test artifact — the technique
    #: and tactic it replayed, the campaign, the run nonce and the detection window it
    #: fired inside (REQ-VALID-003: every emitted artifact is visibly distinguishable and
    #: carries the run's nonce).
    "purple",
]

DEFAULT_CONFIDENCE = 0.5

#: Evidence payloads are truncated to this many characters of serialized JSON.
MAX_EVIDENCE_CHARS = 200_000


def sha256_of(payload: str | bytes) -> str:
    """Hex SHA-256 of ``payload`` (integrity reference stored with evidence)."""
    data = payload.encode("utf-8") if isinstance(payload, str) else payload
    return hashlib.sha256(data).hexdigest()


def confidence_percent(value: float) -> int:
    """Convert a check's 0-1 confidence to the report's 0-100 scale (docs/spec/06- §2).

    The store keeps one unit for the column — percent — so a finding's confidence means the
    same thing whether it was just raised by a check or already analysed. The conversion
    lives in :mod:`arachne.core` (not the analyzer) so the candidate layer and the analyzer
    cannot drift apart.
    """
    scaled = float(value) * 100.0 if 0.0 <= float(value) <= 1.0 else float(value)
    return max(0, min(100, round(scaled)))


@dataclass(frozen=True, slots=True)
class Evidence:
    """A reproducible artifact backing a finding.

    ``payload`` is always the **redacted** value: redaction happens at capture time
    (F-08-04), so no consumer of an :class:`Evidence` object can leak a target secret.
    """

    kind: EvidenceKind
    payload: dict[str, Any] = field(default_factory=dict)
    sha256: str | None = None
    captured_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    source: str | None = None

    def __post_init__(self) -> None:
        if self.captured_at.tzinfo is None:
            msg = "evidence timestamps must be timezone-aware (UTC)"
            raise ValueError(msg)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "payload": self.payload,
            "sha256": self.sha256,
            "captured_at": self.captured_at.isoformat(),
            "source": self.source,
        }

    @classmethod
    def of(
        cls,
        kind: EvidenceKind,
        payload: dict[str, Any],
        *,
        source: str | None = None,
    ) -> Evidence:
        """Build evidence from an arbitrary payload, redacting and hashing it."""
        redacted = redact_value(payload)
        safe_payload = redacted if isinstance(redacted, dict) else {"value": redacted}
        serialized = json.dumps(safe_payload, default=str, ensure_ascii=False, sort_keys=True)
        if len(serialized) > MAX_EVIDENCE_CHARS:
            serialized = serialized[:MAX_EVIDENCE_CHARS]
            safe_payload = {"truncated": True, "preview": serialized}
        return cls(
            kind=kind,
            payload=safe_payload,
            sha256=sha256_of(serialized),
            source=source,
        )


@dataclass(frozen=True, slots=True)
class CheckResult:
    """Outcome of a single check.

    ``status="error"`` is a first-class outcome: it carries the redacted exception
    summary in ``detail`` and lets the orchestrator record a failed check without
    losing the rest of the scan.
    """

    status: CheckStatus
    title: str
    detail: str | None = None
    cwe: str | None = None
    evidence: tuple[Evidence, ...] = field(default_factory=tuple)
    confidence: float = DEFAULT_CONFIDENCE
    error: ErrorInfo | None = None
    check: str | None = None
    module: str | None = None

    def __post_init__(self) -> None:
        if self.status not in _CHECK_STATUSES:
            msg = f"invalid check status {self.status!r}; expected one of {sorted(_CHECK_STATUSES)}"
            raise ValueError(msg)
        if not 0.0 <= self.confidence <= 1.0:
            msg = f"confidence must be within [0, 1], got {self.confidence}"
            raise ValueError(msg)
        if self.status == "error" and self.error is None:
            # Keep the invariant that an error result always explains itself.
            object.__setattr__(
                self,
                "error",
                ErrorInfo(error_type="UnknownError", message=self.detail or "check failed"),
            )

    @property
    def is_finding(self) -> bool:
        return self.status == "vulnerable"

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "status": self.status,
            "title": self.title,
            "detail": self.detail,
            "cwe": self.cwe,
            "confidence": self.confidence,
            "check": self.check,
            "module": self.module,
            "evidence": [item.to_dict() for item in self.evidence],
        }
        if self.error is not None:
            payload["error"] = self.error.to_dict()
        return payload

    @classmethod
    def from_error(
        cls,
        title: str,
        exc: BaseException,
        *,
        cwe: str | None = None,
        check: str | None = None,
        module: str | None = None,
        context: dict[str, Any] | None = None,
    ) -> CheckResult:
        """Build a ``status="error"`` result from an exception (F-02-08 note)."""
        info = error_info(exc, context=context)
        return cls(
            status="error",
            title=title,
            detail=info.summary(),
            cwe=cwe,
            confidence=0.0,
            error=info,
            check=check,
            module=module,
        )


def error_result(title: str, exc: BaseException, **kwargs: Any) -> CheckResult:
    """Functional form of :meth:`CheckResult.from_error`."""
    return CheckResult.from_error(title, exc, **kwargs)


async def guard_check(
    title: str,
    results: AsyncIterator[CheckResult],
    *,
    check: str | None = None,
    module: str | None = None,
) -> AsyncIterator[CheckResult]:
    """Wrap a check's result stream so a raise becomes a single error result.

    Usage::

        async for result in guard_check("env-file-probe", raw_results()):
            ...

    The exception is reported, not swallowed silently: callers still see it as an
    ``error`` result, and the orchestrator (S2) records it in the audit log.
    """
    try:
        async for result in results:
            yield result
    except Exception as exc:
        yield CheckResult.from_error(title, exc, check=check, module=module)
