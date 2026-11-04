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

import pytest

from arachne.core.audit import MemoryAuditChain
from arachne.core.errors import ConfigurationError
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


# ------------------------------------------- the asymmetric option (WP-19, REQ-TRUST-008)
def _ed25519_pair() -> tuple[str, str]:
    """A deterministic keypair for these tests: seed and public key, both hex."""
    from arachne.core.signing import generate_keypair

    return generate_keypair()


def _ed25519_chain(seed: str, count: int = 3) -> tuple[list[AuditLink], MemoryAuditChain]:
    from arachne.core.signing import Ed25519Signer

    chain = MemoryAuditChain(signer=Ed25519Signer(private_key=seed))
    return _links(chain, count), chain


def test_a_chain_signed_with_ed25519_verifies_with_the_public_key_alone() -> None:
    """REQ-TRUST-008's first criterion: a verifier that holds no signing material verifies.

    The ring here is built from the *public* key only. It confirms every link and cannot mint
    one — which is the property an HMAC cannot offer, and the whole reason for the option.
    """
    from arachne.core.signing import Ed25519Signer, SigningKeyring

    seed, public = _ed25519_pair()
    links, _ = _ed25519_chain(seed)

    auditor = SigningKeyring([Ed25519Signer(public_key=public)])
    assert auditor.can_sign is False
    assert auditor.schemes() == ("ed25519",)
    report = verify_audit_chain(links, signer=auditor, require_signature=True)
    assert report.ok, report.summary()
    assert report.checked == {"audit_rows": len(links)}
    # The key id travels in every signature and resolves to the key it names.
    assert all(link.signature is not None for link in links)
    assert {str(link.signature).split(":")[1] for link in links} == {auditor.key_ids()[0]}
    assert auditor.admits(auditor.key_ids()[0])


def test_a_verifier_holding_only_the_public_key_cannot_forge() -> None:
    """REQ-TRUST-008's second criterion: the forging attempt fails, twice over.

    Attempt one is the direct one: ask the public-key-only signer for a signature. Attempt two
    is the interesting one — take a *valid* signature, seed a signer with the public key as if it
    were a private key, and try to reproduce it: the two keys derive different public keys, so
    the result verifies under neither. A third attempt edits a real signature in place.
    """
    from arachne.core.errors import ConfigurationError
    from arachne.core.signing import Ed25519Signer

    seed, public = _ed25519_pair()
    real = Ed25519Signer(private_key=seed)
    auditor = Ed25519Signer(public_key=public)
    signature = real.sign(AUDIT_DOMAIN, b"payload")

    with pytest.raises(ConfigurationError, match="holds only the public key"):
        auditor.sign(AUDIT_DOMAIN, b"payload")

    # Seeding a signer with the public key produces a *different* keypair, not a forgery.
    forged = Ed25519Signer(private_key=public)
    assert forged.key_id != real.key_id
    assert auditor.verify(AUDIT_DOMAIN, b"payload", forged.sign(AUDIT_DOMAIN, b"payload")) is False

    # And a real signature cannot be edited into a different one.
    tampered = signature[:-1] + ("0" if signature[-1] != "0" else "1")
    assert auditor.verify(AUDIT_DOMAIN, b"payload", tampered) is False
    assert auditor.verify(AUDIT_DOMAIN, b"other", signature) is False


def test_a_chain_stays_verifiable_across_a_scheme_change() -> None:
    """REQ-TRUST-008's third criterion: the documented dual period, exercised both ways.

    A deployment mid-migration holds an HMAC key *and* an Ed25519 key. A chain signed before the
    cutover (HMAC) and one signed after (Ed25519) are both verified by that one ring, and neither
    scheme's signature verifies against the other's key — so the migration is a retention window
    rather than a flag day.
    """
    from arachne.core.signing import Ed25519Signer, SigningKeyring

    seed, _public = _ed25519_pair()
    before = MemoryAuditChain(signer=_signer())
    during = MemoryAuditChain(signer=Ed25519Signer(private_key=seed))
    dual_ring = SigningKeyring([Ed25519Signer(private_key=seed), _signer()])

    before_links = _links(before, 2)
    during_links = _links(during, 2)
    assert str(before_links[0].signature).startswith("v1:")
    assert str(during_links[0].signature).startswith("ed25519:")

    assert verify_audit_chain(before_links, signer=dual_ring, require_signature=True).ok
    assert verify_audit_chain(during_links, signer=dual_ring, require_signature=True).ok
    assert dual_ring.schemes() == ("ed25519", "hmac-sha256")

    # The two schemes are not interchangeable: each verifier refuses the other's signature.
    hmac_only = SigningKeyring([_signer()])
    assert not verify_audit_chain(during_links, signer=hmac_only, require_signature=True).ok
    assert (
        Ed25519Signer(private_key=seed).verify(
            AUDIT_DOMAIN, b"x", _signer().sign(AUDIT_DOMAIN, b"x")
        )
        is False
    )


def test_an_upgrade_to_ed25519_does_not_invalidate_the_stored_hmac_rows() -> None:
    """The same dual period, through the *configuration* rather than a hand-built ring.

    ``build_verifier`` is what ``arachne verify-chain`` uses, so this is the path an operator
    actually takes: switch ``algorithm`` to ed25519, keep the old HMAC key configured, and the
    pre-switch rows still verify while new ones are signed under the new scheme.
    """
    from pydantic import SecretStr

    from arachne.core.config import IntegritySettings, Settings
    from arachne.core.signing import build_signer, build_verifier, generate_keypair

    seed, public = generate_keypair()
    legacy_key = "s25-unit-test-legacy-hmac-key-01"
    settings = Settings(
        database_url="sqlite:///:memory:",
        integrity=IntegritySettings(
            key=SecretStr(legacy_key),
            algorithm="ed25519",
            ed25519_private_key=SecretStr(seed),
            ed25519_public_key=SecretStr(public),
        ),
    )
    old_rows = _links(MemoryAuditChain(signer=DeploymentSigner(legacy_key)), 2)
    signing = build_signer(settings)
    assert signing is not None and signing.scheme == "ed25519"
    new_rows = _links(MemoryAuditChain(signer=signing), 2)

    verifier = build_verifier(settings)
    assert verifier.schemes() == ("ed25519", "hmac-sha256")
    assert verify_audit_chain(old_rows, signer=verifier, require_signature=True).ok
    assert verify_audit_chain(new_rows, signer=verifier, require_signature=True).ok


def test_the_auditor_shape_cannot_sign_and_reports_itself_as_such() -> None:
    """A public-key-only deployment is a legal, *verifying* state — and must not pretend to sign."""
    from pydantic import SecretStr

    from arachne.core.config import IntegritySettings, Settings
    from arachne.core.signing import build_signer, build_verifier, generate_keypair

    _, public = generate_keypair()
    settings = Settings(
        database_url="sqlite:///:memory:",
        integrity=IntegritySettings(algorithm="ed25519", ed25519_public_key=SecretStr(public)),
    )
    assert build_signer(settings) is None
    verifier = build_verifier(settings)
    assert verifier.can_sign is False
    assert verifier.key_id == ""
    with pytest.raises(ConfigurationError, match="no signing key"):
        verifier.sign(AUDIT_DOMAIN, b"x")


def test_the_scheme_cannot_be_confused_by_a_mismatched_key_id() -> None:
    """The key id is checked before the arithmetic, in both schemes."""
    from arachne.core.signing import Ed25519Signer, SigningKeyring, scheme_of

    seed, public = _ed25519_pair()
    real = Ed25519Signer(private_key=seed)
    signature = real.sign(AUDIT_DOMAIN, b"payload")
    other = SigningKeyring([Ed25519Signer(private_key=bytes(31) + b"\x07")])
    assert other.verify(AUDIT_DOMAIN, b"payload", signature) is False
    assert Ed25519Signer(public_key=public).verify(AUDIT_DOMAIN, b"payload", signature) is True
    # The historical tag spells the same scheme; an unknown tag is refused outright.
    assert scheme_of("v1") == "hmac-sha256" == scheme_of("hmac-sha256")
    assert scheme_of("ed25519") == "ed25519"
    assert scheme_of("rsa") is None


def test_a_key_id_that_does_not_match_the_signature_is_refused() -> None:
    """A signature relabelled with another key's id must not verify under that key."""
    seed, public = _ed25519_pair()
    from arachne.core.signing import Ed25519Signer

    signer = Ed25519Signer(private_key=seed, key_id="auditor-2026")
    signature = signer.sign(AUDIT_DOMAIN, b"payload")
    assert signature.split(":")[1] == "auditor-2026"
    assert (
        Ed25519Signer(public_key=public, key_id="someone-else").verify(
            AUDIT_DOMAIN, b"payload", signature
        )
        is False
    )
