"""Tamper-evidence: the hash chain, row signatures and seals (S25, REQ-TRUST-005).

REQ-TRUST-005 asks for three things, and this module is the arithmetic that makes all
three checkable:

1. **A hash-chained audit log.** Every audit event carries its position (``seq``), the
   hash of the event before it (``prev_hash``) and its own hash, computed over the event's
   canonical content plus that position. Editing a stored field changes the recomputed
   hash; deleting a row leaves a gap in ``seq`` *and* a dangling ``prev_hash``; reordering
   breaks both. :func:`verify_audit_chain` reports each of those separately, because
   "modified" and "missing" are different answers to an auditor.
2. **Signed findings and evidence.** Each row carries a deployment-key signature over its
   *immutable identity* (its id and provenance) plus, for evidence, the digest of its
   payload — so a rewritten payload no longer matches the signature.
3. **Detected deletion of findings/evidence.** A signature cannot notice an absent row, so
   a completed scan is **sealed**: one signed manifest of every finding and evidence row it
   holds, with their content digests. Verification recomputes the manifest from what is
   there and compares. A deleted row (missing), an added row (extra) and a changed row
   (different digest) are three distinct findings.

The module is pure: it takes plain mappings and returns issues, so the whole chain can be
tested without a database and the data layer only has to project rows into these shapes.
The one import it needs is :mod:`arachne.core.signing` (the deployment key).
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Final

from arachne.core.signing import DeploymentSigner, canonical_bytes, canonical_text

__all__ = [
    "ANCHOR_DOMAIN",
    "AUDIT_DOMAIN",
    "CHAIN_FIELDS",
    "EVIDENCE_DOMAIN",
    "FINDING_DOMAIN",
    "GENESIS_HASH",
    "SEAL_DOMAIN",
    "Anchor",
    "AuditLink",
    "IntegrityIssue",
    "IntegrityReport",
    "audit_payload",
    "chain_digest",
    "evidence_signature_payload",
    "finding_signature_payload",
    "reconstruct_audit_payload",
    "seal_digest",
    "seal_manifest",
    "verify_anchors",
    "verify_audit_chain",
    "verify_row_signature",
    "verify_seal",
]

#: The hash a chain's first row is preceded by when nothing was pruned.
GENESIS_HASH: Final = "0" * 64

#: Signature domains: the purpose a signature was minted for, mixed into every MAC so a
#: signature for one record kind can never be replayed as another.
AUDIT_DOMAIN: Final = "arachne.audit"
ANCHOR_DOMAIN: Final = "arachne.anchor"
FINDING_DOMAIN: Final = "arachne.finding"
EVIDENCE_DOMAIN: Final = "arachne.evidence"
SEAL_DOMAIN: Final = "arachne.seal"

#: The fields that carry the chain itself. They are excluded from the hashed payload so a
#: verification recomputes the same value from the stored *content* — and so writing the
#: chain does not make each row depend on its own hash.
CHAIN_FIELDS: Final = ("seq", "prev_hash", "hash", "signature")


# --------------------------------------------------------------------------- vocabulary
@dataclass(frozen=True, slots=True)
class IntegrityIssue:
    """One reason the trail is not intact.

    ``kind`` is deliberately coarse (``modified`` / ``deleted`` / ``reordered`` /
    ``unsigned``) because those are the four questions an auditor asks; ``detail`` carries
    the specifics (which row, what was expected).
    """

    check: str
    kind: str
    subject: str
    detail: str
    severity: str = "high"

    def to_dict(self) -> dict[str, Any]:
        return {
            "check": self.check,
            "kind": self.kind,
            "subject": self.subject,
            "detail": self.detail,
            "severity": self.severity,
        }


@dataclass(frozen=True, slots=True)
class IntegrityReport:
    """The verdict of one verification pass."""

    checked: dict[str, int] = field(default_factory=dict)
    issues: tuple[IntegrityIssue, ...] = ()
    notes: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return not self.issues

    @property
    def deleted(self) -> tuple[IntegrityIssue, ...]:
        return tuple(issue for issue in self.issues if issue.kind == "deleted")

    @property
    def modified(self) -> tuple[IntegrityIssue, ...]:
        return tuple(issue for issue in self.issues if issue.kind == "modified")

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "checked": dict(self.checked),
            "notes": list(self.notes),
            "issues": [issue.to_dict() for issue in self.issues],
        }

    def summary(self) -> str:
        """One line an operator can read first."""
        if self.ok:
            counts = ", ".join(f"{value} {key}" for key, value in sorted(self.checked.items()))
            return f"intact ({counts or 'nothing to check'})"
        return (
            f"NOT intact: {len(self.issues)} issue(s) — "
            f"{len(self.modified)} modified, {len(self.deleted)} deleted"
        )

    @classmethod
    def combine(cls, *reports: IntegrityReport) -> IntegrityReport:
        """Merge reports (the four verification passes into one verdict)."""
        checked: dict[str, int] = {}
        issues: list[IntegrityIssue] = []
        notes: list[str] = []
        for report in reports:
            for key, value in report.checked.items():
                checked[key] = checked.get(key, 0) + value
            issues.extend(report.issues)
            notes.extend(report.notes)
        return cls(checked=checked, issues=tuple(issues), notes=tuple(notes))


# --------------------------------------------------------------------------- hash chain
def audit_payload(event: Mapping[str, Any]) -> dict[str, Any]:
    """The chained content of an audit event: everything but :data:`CHAIN_FIELDS`."""
    return {str(key): value for key, value in event.items() if key not in CHAIN_FIELDS}


def reconstruct_audit_payload(action: str, meta: Mapping[str, Any]) -> dict[str, Any]:
    """Rebuild the canonical event dict a stored ``audit_log`` row was chained over.

    The row keeps ``action`` in its own column and everything else in ``meta_json``
    (``SqlAuditSink`` writes ``AuditEvent.to_dict()`` minus the action), so the verifier can
    reconstruct exactly the payload the writer hashed — the property that makes the digest
    comparable at all. The key set here must match :meth:`AuditEvent.to_dict`; a test pins
    the two together.
    """
    return {
        "schema_version": meta.get("schema_version"),
        "id": meta.get("id"),
        "ts": meta.get("ts"),
        "actor": meta.get("actor"),
        "action": action,
        "outcome": meta.get("outcome"),
        "target": meta.get("target"),
        "reason": meta.get("reason"),
        "scan_id": meta.get("scan_id"),
        "meta": meta.get("meta") or {},
    }


def chain_digest(seq: int, prev_hash: str, payload: Mapping[str, Any]) -> str:
    """The hash of one chain link.

    Binds position (``seq``), predecessor (``prev_hash``) and content, so a link cannot be
    moved, copied to another position, or edited without the recomputation changing.
    """
    body = canonical_bytes({"seq": seq, "prev_hash": prev_hash, "event": audit_payload(payload)})
    return hashlib.sha256(body).hexdigest()


@dataclass(frozen=True, slots=True)
class AuditLink:
    """One stored audit row, projected for verification."""

    seq: int
    prev_hash: str
    hash: str
    signature: str | None
    payload: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class Anchor:
    """A signed checkpoint of the chain's head, kept so a truncated *tail* is visible.

    A pure hash chain cannot notice that its last rows were deleted — there is simply no
    later row to disagree. An anchor records "at this moment the head was (seq, hash)";
    :func:`verify_anchors` then reports a log that no longer reaches it.
    """

    seq: int
    hash: str
    signature: str | None
    created_at: str | None = None
    reason: str | None = None
    id: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "seq": self.seq,
            "hash": self.hash,
            "signature": self.signature,
            "created_at": self.created_at,
            "reason": self.reason,
        }


def anchor_payload(seq: int, hash_: str) -> dict[str, Any]:
    """What an anchor's signature covers."""
    return {"seq": seq, "hash": hash_}


def sign_anchor(signer: DeploymentSigner, seq: int, hash_: str) -> str:
    return signer.sign(ANCHOR_DOMAIN, canonical_bytes(anchor_payload(seq, hash_)))


def verify_audit_chain(
    links: Sequence[AuditLink],
    *,
    signer: DeploymentSigner | None = None,
    require_signature: bool = False,
    start_prev_hash: str = GENESIS_HASH,
    start_seq: int = 1,
) -> IntegrityReport:
    """Verify a contiguous run of chain links.

    ``start_prev_hash``/``start_seq`` describe what the *oldest retained* row must link
    back to: the genesis constant when nothing was pruned, or the ``(seq, hash)`` an anchor
    recorded when retention has removed older audit rows.
    """
    issues: list[IntegrityIssue] = []
    if not links:
        return IntegrityReport(checked={"audit_rows": 0})

    expected_prev = start_prev_hash
    expected_seq = start_seq
    for link in links:
        subject = f"audit:{link.seq}"
        if link.seq != expected_seq:
            # A gap (or a jump backwards) means rows between are gone or were renumbered.
            issues.append(
                IntegrityIssue(
                    check="audit-chain",
                    kind="deleted",
                    subject=subject,
                    detail=(
                        f"expected sequence {expected_seq}, found {link.seq} — "
                        f"{abs(link.seq - expected_seq)} row(s) missing or reordered"
                    ),
                )
            )
        if link.prev_hash != expected_prev:
            issues.append(
                IntegrityIssue(
                    check="audit-chain",
                    kind="reordered",
                    subject=subject,
                    detail=(
                        f"prev_hash {link.prev_hash[:16]}… does not match the previous row's "
                        f"hash {expected_prev[:16]}…"
                    ),
                )
            )
        recomputed = chain_digest(link.seq, link.prev_hash, link.payload)
        if recomputed != link.hash:
            issues.append(
                IntegrityIssue(
                    check="audit-chain",
                    kind="modified",
                    subject=subject,
                    detail=(
                        f"stored hash {link.hash[:16]}… does not match the recomputed "
                        f"{recomputed[:16]}… — the event content was edited"
                    ),
                )
            )
        if signer is not None:
            if not signer.verify(AUDIT_DOMAIN, link.hash.encode("ascii"), link.signature):
                issues.append(
                    IntegrityIssue(
                        check="audit-signature",
                        kind="unsigned" if not link.signature else "modified",
                        subject=subject,
                        detail=(
                            "no deployment-key signature"
                            if not link.signature
                            else "the signature does not verify against the deployment key"
                        ),
                    )
                )
        elif require_signature:
            issues.append(
                IntegrityIssue(
                    check="audit-signature",
                    kind="unsigned",
                    subject=subject,
                    detail="signatures are required but no deployment key is configured",
                )
            )
        expected_prev = link.hash
        expected_seq = link.seq + 1

    return IntegrityReport(checked={"audit_rows": len(links)}, issues=tuple(issues))


def verify_anchors(
    anchors: Sequence[Anchor],
    *,
    links: Sequence[AuditLink],
    signer: DeploymentSigner | None = None,
) -> IntegrityReport:
    """Check every recorded head against the log that should still reach it."""
    issues: list[IntegrityIssue] = []
    by_seq = {link.seq: link for link in links}
    head_seq = max(by_seq) if by_seq else 0
    for anchor in anchors:
        subject = f"anchor:{anchor.id if anchor.id is not None else anchor.seq}"
        if signer is not None and not signer.verify(
            ANCHOR_DOMAIN,
            canonical_bytes(anchor_payload(anchor.seq, anchor.hash)),
            anchor.signature,
        ):
            issues.append(
                IntegrityIssue(
                    check="anchor",
                    kind="unsigned" if not anchor.signature else "modified",
                    subject=subject,
                    detail="the anchor's own signature does not verify",
                )
            )
        if anchor.seq > head_seq:
            issues.append(
                IntegrityIssue(
                    check="anchor",
                    kind="deleted",
                    subject=subject,
                    detail=(
                        f"the chain is anchored at seq {anchor.seq} but the log ends at "
                        f"{head_seq} — {anchor.seq - head_seq} trailing row(s) were deleted"
                    ),
                )
            )
            continue
        link = by_seq.get(anchor.seq)
        if link is None:
            issues.append(
                IntegrityIssue(
                    check="anchor",
                    kind="deleted",
                    subject=subject,
                    detail=f"no audit row at the anchored seq {anchor.seq}",
                )
            )
        elif link.hash != anchor.hash:
            issues.append(
                IntegrityIssue(
                    check="anchor",
                    kind="modified",
                    subject=subject,
                    detail=(
                        f"the anchored hash {anchor.hash[:16]}… differs from the stored "
                        f"{link.hash[:16]}…"
                    ),
                )
            )
    return IntegrityReport(checked={"anchors": len(anchors)}, issues=tuple(issues))


# --------------------------------------------------------------------------- row signing
def finding_signature_payload(row: Mapping[str, Any]) -> dict[str, Any]:
    """The immutable identity of a finding (what its deployment-key signature covers).

    ``severity``/``confidence``/``status`` are deliberately *not* here: the analyzer fills
    the first two after the row is written and an operator moves the third, so signing
    them would make every finding fail verification the moment it was analysed. Those
    fields are covered by the scan's seal instead, which is written when the scan is done.
    """
    return {
        "id": row.get("id"),
        "scan_id": row.get("scan_id"),
        "check_id": row.get("check_id"),
        "asset_id": row.get("asset_id"),
        "title": row.get("title"),
        "created_at": _as_text(row.get("created_at")),
    }


def evidence_signature_payload(row: Mapping[str, Any]) -> dict[str, Any]:
    """The identity of an evidence row plus the digest of the payload it holds."""
    return {
        "id": row.get("id"),
        "finding_id": row.get("finding_id"),
        "kind": row.get("kind"),
        "payload_digest": payload_digest(row.get("payload_json")),
        "created_at": _as_text(row.get("created_at")),
    }


def payload_digest(payload: Any) -> str:
    """Digest of a stored evidence payload (the value a signature pins)."""
    return hashlib.sha256(canonical_bytes(payload if payload is not None else {})).hexdigest()


def row_signature_payload(domain: str, row: Mapping[str, Any]) -> dict[str, Any]:
    if domain == EVIDENCE_DOMAIN:
        return evidence_signature_payload(row)
    return finding_signature_payload(row)


def sign_row(signer: DeploymentSigner, domain: str, row: Mapping[str, Any]) -> str:
    return signer.sign(domain, canonical_bytes(row_signature_payload(domain, row)))


def verify_row_signature(
    signer: DeploymentSigner | None,
    domain: str,
    row: Mapping[str, Any],
    signature: str | None,
    *,
    subject: str,
    require_signature: bool = False,
) -> IntegrityIssue | None:
    """One issue, or ``None`` when the row's signature is present and valid."""
    if signer is None:
        if require_signature:
            return IntegrityIssue(
                check=f"{domain}-signature",
                kind="unsigned",
                subject=subject,
                detail="signatures are required but no deployment key is configured",
            )
        return None
    if not signer.verify(domain, canonical_bytes(row_signature_payload(domain, row)), signature):
        return IntegrityIssue(
            check=f"{domain}-signature",
            kind="unsigned" if not signature else "modified",
            subject=subject,
            detail=(
                "no deployment-key signature"
                if not signature
                else "the signature does not verify — the row or its payload was edited"
            ),
        )
    return None


# --------------------------------------------------------------------------- scan seals
def finding_seal_entry(row: Mapping[str, Any]) -> str:
    """One line of a scan's seal for a finding: identity **and** the fields that mutate."""
    return canonical_line(
        "finding",
        {
            "id": row.get("id"),
            "scan_id": row.get("scan_id"),
            "check_id": row.get("check_id"),
            "asset_id": row.get("asset_id"),
            "title": row.get("title"),
            "severity": row.get("severity"),
            "confidence": row.get("confidence"),
            "status": row.get("status"),
            "created_at": _as_text(row.get("created_at")),
        },
    )


def evidence_seal_entry(row: Mapping[str, Any]) -> str:
    """One line of a scan's seal for an evidence row."""
    return canonical_line(
        "evidence",
        {
            "id": row.get("id"),
            "finding_id": row.get("finding_id"),
            "kind": row.get("kind"),
            "payload_digest": payload_digest(row.get("payload_json")),
            "created_at": _as_text(row.get("created_at")),
        },
    )


def canonical_line(kind: str, body: Mapping[str, Any]) -> str:
    return f"{kind}:{canonical_bytes(dict(body)).decode('utf-8')}"


def seal_manifest(
    findings: Iterable[Mapping[str, Any]], evidences: Iterable[Mapping[str, Any]]
) -> tuple[str, tuple[str, ...], int]:
    """``(digest, manifest, count)`` for a scan's rows, in a stable order.

    The manifest is the list of per-row lines; the digest is over the manifest. Keeping
    both lets verification *name* a row that vanished instead of only saying "the digest
    changed".
    """
    lines = [finding_seal_entry(row) for row in findings]
    lines.extend(evidence_seal_entry(row) for row in evidences)
    lines.sort()
    digest = hashlib.sha256(canonical_bytes(lines)).hexdigest()
    return digest, tuple(lines), len(lines)


def seal_digest(manifest: Iterable[str]) -> str:
    """Recompute a seal's digest from a manifest (the verifier's half)."""
    return hashlib.sha256(canonical_bytes(list(manifest))).hexdigest()


def sign_seal(signer: DeploymentSigner, scan_id: int, digest: str, count: int) -> str:
    return signer.sign(
        SEAL_DOMAIN, canonical_bytes({"scan_id": scan_id, "digest": digest, "count": count})
    )


def verify_seal(
    seal: Mapping[str, Any],
    *,
    findings: Sequence[Mapping[str, Any]],
    evidences: Sequence[Mapping[str, Any]],
    signer: DeploymentSigner | None = None,
    require_signature: bool = False,
) -> IntegrityReport:
    """Recompute a scan's seal against the rows that are still there.

    Reports the three distinguishable failures: a row **deleted** since sealing (its line
    is gone), a row **added** (a line appeared), and a row **modified** (a line's content
    changed). The digest comparison catches the same three at once; the manifest diff is
    what makes the report actionable.
    """
    issues: list[IntegrityIssue] = []
    scan_id = seal.get("scan_id")
    subject = f"seal:{scan_id}"
    digest, manifest, count = seal_manifest(findings, evidences)
    recorded = seal.get("digest")
    stored_manifest = seal.get("manifest_json") or []
    if not isinstance(stored_manifest, list):
        stored_manifest = []
    if signer is not None and not signer.verify(
        SEAL_DOMAIN,
        canonical_bytes({"scan_id": scan_id, "digest": recorded, "count": seal.get("row_count")}),
        _as_text_or_none(seal.get("signature")),
    ):
        issues.append(
            IntegrityIssue(
                check="seal",
                kind="unsigned" if not seal.get("signature") else "modified",
                subject=subject,
                detail="the seal's signature does not verify against the deployment key",
            )
        )
    elif signer is None and require_signature:
        issues.append(
            IntegrityIssue(
                check="seal",
                kind="unsigned",
                subject=subject,
                detail="signatures are required but no deployment key is configured",
            )
        )
    if recorded != digest:
        missing, extra, changed = _diff_manifest(stored_manifest, list(manifest))
        for line in missing:
            issues.append(
                IntegrityIssue(
                    check="seal",
                    kind="deleted",
                    subject=_subject_of(line, scan_id),
                    detail=f"row sealed at scan completion is gone: {_short(line)}",
                )
            )
        for line in extra:
            issues.append(
                IntegrityIssue(
                    check="seal",
                    kind="modified",
                    subject=_subject_of(line, scan_id),
                    detail=f"row appeared after the scan was sealed: {_short(line)}",
                )
            )
        for line in changed:
            issues.append(
                IntegrityIssue(
                    check="seal",
                    kind="modified",
                    subject=_subject_of(line, scan_id),
                    detail=f"row changed after the scan was sealed: {_short(line)}",
                )
            )
        if not (missing or extra or changed):
            issues.append(
                IntegrityIssue(
                    check="seal",
                    kind="modified",
                    subject=subject,
                    detail=(
                        f"manifest digest {digest[:16]}… does not match the sealed "
                        f"{_as_text(recorded)[:16]}…"
                    ),
                )
            )
    return IntegrityReport(
        checked={"sealed_rows": count},
        issues=tuple(issues),
    )


def _diff_manifest(
    stored: Sequence[str], live: Sequence[str]
) -> tuple[list[str], list[str], list[str]]:
    """``(missing, extra, changed)`` by row identity (the part before the first ``:``)."""
    stored_by_id = {_identity(line): line for line in stored}
    live_by_id = {_identity(line): line for line in live}
    missing = [line for key, line in stored_by_id.items() if key not in live_by_id]
    extra = [line for key, line in live_by_id.items() if key not in stored_by_id]
    changed = [
        live_by_id[key]
        for key, line in stored_by_id.items()
        if key in live_by_id and live_by_id[key] != line
    ]
    return missing, extra, changed


def _identity(line: str) -> str:
    """``kind:id`` — the row's identity inside a manifest line."""
    kind, _, rest = line.partition(":")
    try:
        return f"{kind}:{canonical_text(_json_load(rest).get('id'))}"
    except (ValueError, AttributeError):  # pragma: no cover - a corrupt stored manifest
        return line


def _json_load(text: str) -> dict[str, Any]:
    value = json.loads(text)
    return value if isinstance(value, dict) else {}


def _subject_of(line: str, scan_id: Any) -> str:
    kind = line.split(":", 1)[0]
    return f"{kind}:{_identity(line).split(':', 1)[1]} (scan {scan_id})"


def _short(line: str) -> str:
    return line if len(line) <= 120 else line[:117] + "…"


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    isoformat = getattr(value, "isoformat", None)
    return isoformat() if callable(isoformat) else str(value)


def _as_text_or_none(value: Any) -> str | None:
    if value is None:
        return None
    return _as_text(value)
