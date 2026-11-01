"""Evidence projection for reports: redaction, truncation, ids and summaries (06- §5).

Evidence is redacted **at capture time** (F-08-04, ``core/redaction.py``), so by the time it
reaches this module it is already safe. This layer still does three things, and each has a
reason:

* **It re-applies redaction.** The functions are idempotent, so a second pass costs a linear
  scan and removes the last path by which a payload written by an older build (or a plugin
  that built an :class:`~arachne.core.results.Evidence` by hand) could reach a report
  unredacted. The report QA gate scans the rendered output for secret patterns; this is the
  layer that makes it pass.
* **It truncates bodies** to the configurable report limit ("truncated at
  configurable size, default 8 KB"). The capture limit (64 KB) is for detection; a report
  carries a readable excerpt and the hash of the whole capture.
* **It maps the internal kinds onto the spec's kind vocabulary** (``tls_certificate`` →
  ``tls_cert``, ``file_path`` → ``file_artifact``) and gives every payload a stable
  ``E-NNNN`` id, so a finding's ``evidence_refs`` point at an appendix entry instead of
  repeating the payload inline.

``artifact`` (a machine-readable fact bundle) and ``note`` (the candidate's provenance) are
deliberate extensions of the §5 table: they are what makes a finding explainable, and the
report renders them as such rather than pretending they are HTTP captures.
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from typing import Any, Final

from arachne.core.redaction import redact_url, redact_value
from arachne.core.results import sha256_of
from arachne.data.finding_store import EvidenceRecord
from arachne.report.model import ReportEvidence, evidence_id

__all__ = [
    "DEFAULT_EVIDENCE_BODY_LIMIT",
    "KIND_MAP",
    "project_evidence",
    "summarize_evidence",
    "truncate_text",
]

#: : response bodies are truncated at 8 KB by default in a report.
DEFAULT_EVIDENCE_BODY_LIMIT: Final = 8192

#: Internal evidence kinds → the report vocabulary.
KIND_MAP: Final[dict[str, str]] = {
    "http_request": "http_request",
    "http_response": "http_response",
    "banner": "banner",
    "file_path": "file_artifact",
    "artifact": "artifact",
    "tls_certificate": "tls_cert",
    "tls_cert": "tls_cert",
    "dns_record": "dns_record",
    "cloud_api": "cloud_api",
    "oob_callback": "oob_callback",
    "log_event": "log_event",
    "note": "note",
}

_BODY_KEYS: Final[tuple[str, ...]] = ("body", "request_body")
_TRUNCATION_MARKER: Final = "\n… (truncated; full capture is hashed above)"


def map_kind(kind: str) -> str:
    """The report kind for an internal evidence kind (unknown kinds pass through)."""
    return KIND_MAP.get(kind, kind)


def truncate_text(text: str, limit: int) -> tuple[str, bool]:
    """Truncate ``text`` to ``limit`` characters, returning ``(text, was_truncated)``."""
    if limit < 0 or len(text) <= limit:
        return text, False
    return text[:limit] + _TRUNCATION_MARKER, True


def _safe_payload(payload: Mapping[str, Any], limit: int) -> dict[str, Any]:
    """Redact, truncate and JSON-normalise one payload."""
    redacted = redact_value(dict(payload))
    safe: dict[str, Any] = redacted if isinstance(redacted, dict) else {"value": redacted}
    for key in _BODY_KEYS:
        value = safe.get(key)
        if isinstance(value, str):
            safe[key], truncated = truncate_text(value, limit)
            if truncated:
                safe[f"{key}_truncated"] = True
    # ``url``/``source`` carry query strings; redact the value itself as well.
    if isinstance(safe.get("url"), str):
        safe["url"] = redact_url(safe["url"])
    return safe


def _canonical(payload: Mapping[str, Any]) -> str:
    return json.dumps(payload, default=str, ensure_ascii=False, sort_keys=True)


def summarize_evidence(kind: str, payload: Mapping[str, Any]) -> str:
    """A one-line, deterministic description of an evidence payload (for the appendix)."""
    if kind == "http_request":
        method = str(payload.get("method") or "GET")
        url = str(payload.get("url") or payload.get("source") or "")
        return f"{method} {url}".strip()
    if kind == "http_response":
        status = payload.get("status_code")
        body = payload.get("body")
        size = len(body) if isinstance(body, str) else None
        parts = [f"HTTP {status}" if status is not None else "HTTP response"]
        if size is not None:
            parts.append(f"{size} bytes")
        patterns = payload.get("captured_patterns")
        if isinstance(patterns, Sequence) and not isinstance(patterns, (str, bytes)):
            named = [str(item) for item in patterns]
            if named:
                parts.append("matched patterns: " + ", ".join(named))
        return " · ".join(parts)
    if kind == "banner":
        text = payload.get("banner") or payload.get("value") or ""
        return f"service banner ({len(str(text))} bytes)"
    if kind == "file_artifact":
        path = payload.get("path") or payload.get("value") or "file"
        size = payload.get("size")
        return f"{path}" + (f" ({size} bytes)" if size is not None else "")
    if kind == "tls_cert":
        subject = payload.get("subject") or payload.get("value") or "certificate"
        issuer = payload.get("issuer")
        return f"{subject}" + (f" issued by {issuer}" if issuer else "")
    if kind == "artifact":
        keys = ", ".join(sorted(str(key) for key in payload))
        return f"machine-readable artifact ({keys})" if keys else "machine-readable artifact"
    if kind == "note":
        detail = str(payload.get("detail") or "").strip()
        return detail or "candidate provenance note"
    return kind


def project_evidence(
    evidence: Iterable[EvidenceRecord],
    *,
    start: int = 1,
    body_limit: int = DEFAULT_EVIDENCE_BODY_LIMIT,
) -> tuple[tuple[ReportEvidence, ...], dict[int, str]]:
    """Project stored evidence rows into report evidence.

    Returns the appendix entries (ids ``E-(start+n)``) and a map from the evidence row id to
    its report id, so the builder can fill each finding's ``evidence_refs`` without a second
    pass over the payloads. Rows are ordered by their stored id, which is the capture order.
    """
    ordered = sorted(evidence, key=lambda item: (item.id is None, item.id or 0))
    entries: list[ReportEvidence] = []
    refs: dict[int, str] = {}
    for offset, record in enumerate(ordered):
        identifier = evidence_id(start + offset)
        payload = _safe_payload(record.payload, body_limit)
        digest = record.sha256 or sha256_of(_canonical(payload))
        entries.append(
            ReportEvidence(
                id=identifier,
                kind=map_kind(record.kind),
                summary=summarize_evidence(map_kind(record.kind), payload),
                payload=payload,
                sha256=digest,
                captured_at=record.created_at,
            )
        )
        if record.id is not None:
            refs[record.id] = identifier
    return tuple(entries), refs
