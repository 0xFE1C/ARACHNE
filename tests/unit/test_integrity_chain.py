"""The tamper-evidence arithmetic: chain, signatures, anchors and seals (S25, REQ-TRUST-005).

The requirement's accept criterion is "an edited evidence row or audit entry is detected by
the verifier". These tests take the verifier's inputs apart so each detection is pinned to
the mechanism that produces it:

* **modification** — a recomputed hash disagrees (an edit to any chained field), and a
  signature that no longer verifies;
* **deletion** — a gap in ``seq`` (a row removed from the middle) *and* a truncated tail,
  which the chain alone cannot see and an anchor can;
* **reordering** — a ``prev_hash`` that does not match its predecessor;
* **insertion/modification of a finding or its evidence** — a seal whose recomputed manifest
  differs, with the changed row named.
"""

from __future__ import annotations

from datetime import UTC, datetime

from arachne.core.audit import MemoryAuditChain
from arachne.core.integrity import (
    ANCHOR_DOMAIN,
    AUDIT_DOMAIN,
    EVIDENCE_DOMAIN,
    FINDING_DOMAIN,
    GENESIS_HASH,
    SEAL_DOMAIN,
    Anchor,
    AuditLink,
    audit_payload,
    chain_digest,
    evidence_signature_payload,
    payload_digest,
    reconstruct_audit_payload,
    seal_manifest,
    sign_anchor,
    sign_row,
    sign_seal,
    verify_anchors,
    verify_audit_chain,
    verify_row_signature,
    verify_seal,
)
from arachne.core.signing import DeploymentSigner, canonical_bytes

KEY = "s25-unit-test-integrity-key-0001"
OTHER_KEY = "s25-unit-test-integrity-key-0002"


def _signer() -> DeploymentSigner:
    return DeploymentSigner(KEY)


def _links(chain: MemoryAuditChain, count: int = 3) -> list[AuditLink]:
    for index in range(count):
        chain.append({"action": "scan.step_completed", "seq_hint": index})
    return [
        AuditLink(
            seq=int(link["seq"]),
            prev_hash=str(link["prev_hash"]),
            hash=str(link["hash"]),
            signature=link["signature"],
            payload=dict(link["payload"]),
        )
        for link in chain.links
    ]


# --------------------------------------------------------------------------- chain
def test_an_untouched_chain_verifies() -> None:
    signer = _signer()
    chain = MemoryAuditChain(signer=signer)
    report = verify_audit_chain(_links(chain), signer=signer)
    assert report.ok, report.to_dict()
    assert report.checked == {"audit_rows": 3}


def test_the_first_link_links_to_the_genesis_constant() -> None:
    chain = MemoryAuditChain()
    links = _links(chain, count=1)
    assert links[0].prev_hash == GENESIS_HASH
    assert links[0].seq == 1


def test_an_edited_event_is_detected_as_modified() -> None:
    signer = _signer()
    chain = MemoryAuditChain(signer=signer)
    links = _links(chain)
    # Edit the content of the second event, leaving its stored hash alone: exactly what a
    # database-level edit looks like.
    links[1] = AuditLink(
        seq=links[1].seq,
        prev_hash=links[1].prev_hash,
        hash=links[1].hash,
        signature=links[1].signature,
        payload={**links[1].payload, "action": "scan.aborted"},
    )
    report = verify_audit_chain(links, signer=signer)
    assert not report.ok
    assert len(report.modified) == 1
    assert "does not match the recomputed" in report.modified[0].detail


def test_a_deleted_row_leaves_a_gap_and_a_dangling_link() -> None:
    signer = _signer()
    chain = MemoryAuditChain(signer=signer)
    links = _links(chain)
    del links[1]  # the auditor deleted a row it did not like
    report = verify_audit_chain(links, signer=signer)
    assert not report.ok
    kinds = {issue.kind for issue in report.issues}
    assert "deleted" in kinds  # the sequence gap
    assert "reordered" in kinds  # the third link's prev_hash now names the first


def test_a_reordered_pair_is_detected() -> None:
    signer = _signer()
    chain = MemoryAuditChain(signer=signer)
    links = _links(chain)
    links[1], links[2] = links[2], links[1]
    report = verify_audit_chain(links, signer=signer)
    assert not report.ok


def test_a_replayed_signature_from_another_key_is_refused() -> None:
    chain = MemoryAuditChain(signer=DeploymentSigner(OTHER_KEY))
    report = verify_audit_chain(_links(chain), signer=_signer())
    assert not report.ok
    assert all(issue.check == "audit-signature" for issue in report.issues)


def test_requiring_signatures_fails_an_unchained_deployment() -> None:
    chain = MemoryAuditChain()  # no signer
    report = verify_audit_chain(_links(chain), require_signature=True)
    assert not report.ok
    assert {issue.kind for issue in report.issues} == {"unsigned"}


def test_a_pruned_prefix_verifies_when_the_anchor_names_it() -> None:
    """Retention removes old audit rows; the chain restarts from a recorded predecessor."""
    signer = _signer()
    chain = MemoryAuditChain(signer=signer)
    links = _links(chain, count=4)
    retained = links[2:]
    report = verify_audit_chain(
        retained,
        signer=signer,
        start_prev_hash=links[1].hash,
        start_seq=3,
    )
    assert report.ok, report.to_dict()


# --------------------------------------------------------------------------- anchors
def test_a_truncated_tail_is_detected_by_an_anchor() -> None:
    """The failure a hash chain cannot see on its own: the newest rows are gone."""
    signer = _signer()
    chain = MemoryAuditChain(signer=signer)
    links = _links(chain)
    anchor = Anchor(
        id=1,
        seq=links[-1].seq,
        hash=links[-1].hash,
        signature=sign_anchor(signer, links[-1].seq, links[-1].hash),
        reason="manual",
    )
    assert verify_anchors([anchor], links=links, signer=signer).ok

    truncated = links[:-1]  # somebody deleted the last row
    report = verify_anchors([anchor], links=truncated, signer=signer)
    assert not report.ok
    assert report.deleted
    assert "trailing row(s) were deleted" in report.deleted[0].detail


def test_an_anchor_whose_own_signature_is_forged_is_detected() -> None:
    signer = _signer()
    chain = MemoryAuditChain(signer=signer)
    links = _links(chain)
    anchor = Anchor(
        id=1, seq=links[-1].seq, hash=links[-1].hash, signature="v1:deadbeef:00", reason="manual"
    )
    report = verify_anchors([anchor], links=links, signer=signer)
    assert not report.ok
    assert any(
        issue.detail == "the anchor's own signature does not verify" for issue in report.issues
    )


def test_an_anchor_that_no_longer_matches_the_stored_hash_is_detected() -> None:
    signer = _signer()
    chain = MemoryAuditChain(signer=signer)
    links = _links(chain)
    # The log was rewritten and re-chained, so the old anchor points at a hash nobody has.
    anchor = Anchor(id=1, seq=links[-1].seq, hash="f" * 64, signature=None, reason="manual")
    report = verify_anchors([anchor], links=links, signer=signer)
    assert not report.ok
    assert any(issue.kind == "modified" for issue in report.issues)


# --------------------------------------------------------------------------- row signing
def _finding_row(**overrides: object) -> dict[str, object]:
    row: dict[str, object] = {
        "id": 7,
        "scan_id": 3,
        "check_id": 11,
        "asset_id": 22,
        "title": "Exposed admin interface",
        "severity": "high",
        "confidence": 80.0,
        "status": "open",
        "created_at": datetime(2026, 10, 31, tzinfo=UTC),
    }
    row.update(overrides)
    return row


def _evidence_row(**overrides: object) -> dict[str, object]:
    row: dict[str, object] = {
        "id": 4,
        "finding_id": 7,
        "kind": "http_response",
        "payload_json": {"status": 200, "body": "hello"},
        "created_at": datetime(2026, 10, 31, tzinfo=UTC),
    }
    row.update(overrides)
    return row


def test_a_finding_signature_covers_its_identity() -> None:
    signer = _signer()
    row = _finding_row()
    signature = sign_row(signer, FINDING_DOMAIN, row)
    assert verify_row_signature(signer, FINDING_DOMAIN, row, signature, subject="finding:7") is None

    # A different title (the same row id) no longer verifies: the signature binds content.
    edited = _finding_row(title="Something else")
    issue = verify_row_signature(signer, FINDING_DOMAIN, edited, signature, subject="finding:7")
    assert issue is not None and issue.kind == "modified"


def test_a_finding_signature_ignores_the_fields_that_legitimately_change() -> None:
    """The analyzer fills severity later; signing it would fail every analysed finding."""
    signer = _signer()
    row = _finding_row(severity=None, confidence=None, status="open")
    signature = sign_row(signer, FINDING_DOMAIN, row)
    analysed = _finding_row(severity="critical", confidence=95.0, status="verified")
    assert (
        verify_row_signature(signer, FINDING_DOMAIN, analysed, signature, subject="finding:7")
        is None
    )


def test_an_evidence_signature_pins_the_payload_digest() -> None:
    signer = _signer()
    row = _evidence_row()
    signature = sign_row(signer, EVIDENCE_DOMAIN, row)
    assert (
        verify_row_signature(signer, EVIDENCE_DOMAIN, row, signature, subject="evidence:4") is None
    )
    # Rewriting the payload (and even leaving sha256 alone) breaks the signature.
    tampered = _evidence_row(payload_json={"status": 200, "body": "goodbye"})
    issue = verify_row_signature(signer, EVIDENCE_DOMAIN, tampered, signature, subject="evidence:4")
    assert issue is not None and issue.kind == "modified"
    assert payload_digest(row["payload_json"]) != payload_digest(tampered["payload_json"])


def test_a_signature_domain_cannot_be_replayed() -> None:
    """A signature minted in one domain is not a signature in another."""
    signer = _signer()
    row = _evidence_row()
    signature = sign_row(signer, EVIDENCE_DOMAIN, row)
    evidence_bytes = canonical_bytes(evidence_signature_payload(row))
    assert signer.verify(EVIDENCE_DOMAIN, evidence_bytes, signature)
    assert not signer.verify(FINDING_DOMAIN, evidence_bytes, signature)
    assert not signer.verify(AUDIT_DOMAIN, evidence_bytes, signature)


def test_requiring_signatures_flags_an_unsigned_row() -> None:
    row = _finding_row()
    issue = verify_row_signature(
        None, FINDING_DOMAIN, row, None, subject="finding:7", require_signature=True
    )
    assert issue is not None and issue.kind == "unsigned"
    # Without the requirement and without a key there is nothing to report.
    assert verify_row_signature(None, FINDING_DOMAIN, row, None, subject="finding:7") is None


# --------------------------------------------------------------------------- seals
def _seal(
    signer: DeploymentSigner,
    findings: list[dict[str, object]],
    evidences: list[dict[str, object]],
    *,
    scan_id: int = 3,
) -> dict[str, object]:
    digest, manifest, count = seal_manifest(findings, evidences)
    return {
        "scan_id": scan_id,
        "digest": digest,
        "row_count": count,
        "manifest_json": list(manifest),
        "signature": sign_seal(signer, scan_id, digest, count),
    }


def test_a_seal_verifies_against_the_rows_that_are_present() -> None:
    signer = _signer()
    findings = [_finding_row(), _finding_row(id=8, title="Second")]
    evidences = [_evidence_row()]
    seal = _seal(signer, findings, evidences)
    report = verify_seal(seal, findings=findings, evidences=evidences, signer=signer)
    assert report.ok, report.to_dict()
    assert report.checked == {"sealed_rows": 3}


def test_a_deleted_finding_is_detected_by_the_seal() -> None:
    signer = _signer()
    findings = [_finding_row(), _finding_row(id=8, title="Second")]
    evidences = [_evidence_row()]
    seal = _seal(signer, findings, evidences)
    report = verify_seal(seal, findings=findings[:1], evidences=evidences, signer=signer)
    assert not report.ok
    assert len(report.deleted) == 1
    assert "is gone" in report.deleted[0].detail


def test_a_deleted_evidence_row_is_detected_by_the_seal() -> None:
    signer = _signer()
    findings = [_finding_row()]
    evidences = [_evidence_row(), _evidence_row(id=5, kind="note")]
    seal = _seal(signer, findings, evidences)
    report = verify_seal(seal, findings=findings, evidences=evidences[:1], signer=signer)
    assert not report.ok
    assert report.deleted


def test_a_row_inserted_after_the_seal_is_detected() -> None:
    signer = _signer()
    findings = [_finding_row()]
    seal = _seal(signer, findings, [])
    report = verify_seal(
        seal,
        findings=[*findings, _finding_row(id=99, title="Planted")],
        evidences=[],
        signer=signer,
    )
    assert not report.ok
    assert any("appeared after" in issue.detail for issue in report.issues)


def test_a_row_edited_after_the_seal_is_detected() -> None:
    """The seal is what catches a post-seal change to a field the row signature ignores."""
    signer = _signer()
    findings = [_finding_row()]
    seal = _seal(signer, findings, [])
    mutated = [_finding_row(severity="low", status="fp")]  # severity downgraded after sealing
    report = verify_seal(seal, findings=mutated, evidences=[], signer=signer)
    assert not report.ok
    assert any(issue.kind == "modified" for issue in report.issues)


def test_a_forged_seal_signature_is_detected() -> None:
    signer = _signer()
    findings = [_finding_row()]
    seal = _seal(signer, findings, [])
    seal["signature"] = "v1:deadbeef:00"
    report = verify_seal(seal, findings=findings, evidences=[], signer=signer)
    assert not report.ok
    assert any(issue.check == "seal" and issue.kind == "modified" for issue in report.issues)


def test_the_seal_digest_changes_when_anything_changes() -> None:
    first, _, _ = seal_manifest([_finding_row()], [])
    second, _, _ = seal_manifest([_finding_row(title="changed")], [])
    third, _, _ = seal_manifest([_finding_row()], [_evidence_row()])
    assert len({first, second, third}) == 3


# --------------------------------------------------------------------------- canonical form
def test_the_reconstruction_matches_the_hashed_payload() -> None:
    """The verifier rebuilds the event from ``action`` + ``meta_json``; the keys must agree."""
    chain = MemoryAuditChain()
    chain.append(
        {
            "schema_version": "1.2",
            "id": "x",
            "ts": "2026-10-31T00:00:00+00:00",
            "actor": "a",
            "action": "scan.started",
            "outcome": "allowed",
            "target": None,
            "reason": None,
            "scan_id": 1,
            "meta": {"k": "v"},
        }
    )
    stored = dict(chain.links[0]["payload"])
    action = str(stored.pop("action"))
    rebuilt = reconstruct_audit_payload(action, stored)
    assert audit_payload(rebuilt) == audit_payload(chain.links[0]["payload"])
    assert chain_digest(1, GENESIS_HASH, rebuilt) == chain.links[0]["hash"]


def test_signature_domains_are_distinct_constants() -> None:
    assert len({AUDIT_DOMAIN, ANCHOR_DOMAIN, FINDING_DOMAIN, EVIDENCE_DOMAIN, SEAL_DOMAIN}) == 5
