"""The per-scan residue attestation (WP-14, REQ-PROOF-017).

``INV-7`` restores every state change an L4 proof makes and reports a failed restore. That
is a promise about this process's behaviour, made in a report, by the process itself. The
requirement asks for something a third party can check *after the fact*: a signed artefact
that enumerates what the scan changed and states, per change, whether it was put back.

Four properties shape this module:

**One attestation per scan, always.** A scan that authorized no state change still emits
one, stating exactly that ("no state-changing action was authorized for this scan"). The
absence of a state change is not the absence of an attestation — an empty attestation is
what makes "this scan changed nothing" checkable rather than inferred from a missing file.

**Signed when a signer exists, and *marked* unsigned when it does not.** The deployment
signer is :mod:`arachne.core.signing`'s HMAC key; a deployment without one still produces
the attestation, carrying ``signed: false``. It is never silently skipped: a reader can
always tell which of the two artefacts they are holding.

**The before-value is a hash.** Each entry carries
``before_value_hash`` — a digest of the prior value, never the value — plus the asset, the
action, the restore outcome and a timestamp. That is what makes the envelope publishable:
the entries can be handed to an auditor without handing them the target's data.

**The hash is the handle.** ``hash`` is a digest over the attestation body, and the scan
machine links it into the audit chain (``proof.residue_attested``), so the artefact and the
trail cannot disagree about what was attested.

Non-zero residue is a *verdict*, not a detail: ``clean`` is false, the report shows a
warning, and the repair instructions the ledger produced travel inside the attestation.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Any

from arachne.core.integrity import (
    NO_STATE_CHANGE_STATEMENT,
    ZERO_RESIDUE_STATEMENT,
    attestation_digest,
    residue_attestation_payload,
    residue_entry,
    sign_attestation,
    verify_attestation,
)
from arachne.core.signing import Signer
from arachne.proof.ledger import StateChangeRecord

__all__ = [
    "RESIDUE_ATTESTATION_KEY",
    "attestation_is_clean",
    "build_residue_attestation",
    "verify_residue_attestation",
]

#: Where the verdict lives inside the attestation. Also the JSON key a reader of the scan
#: record looks for, so the two cannot drift.
RESIDUE_ATTESTATION_KEY = "residue"


def build_residue_attestation(
    *,
    scan_id: int | str,
    proof_state: Mapping[str, Any] | None,
    generated_at: datetime | None = None,
    signer: Signer | None = None,
) -> dict[str, Any]:
    """Build (and sign) one scan's residue attestation from its proof journal.

    ``proof_state`` is the scan record's ``stats["proof"]`` — the journal
    :class:`~arachne.proof.ledger.ProofLedger` persists — so the attestation is derived from
    the durable record rather than from an in-process object, and a resumed or crashed scan
    attests to what its own record says.
    """
    journal = dict(proof_state or {})
    raw_changes = journal.get("state_changes")
    changes = [dict(item) for item in raw_changes] if isinstance(raw_changes, list) else []
    moment = generated_at or datetime.now(UTC)

    entries = [residue_entry(change) for change in changes]
    unrestored = [change for change in changes if not change.get("restored")]
    residue = len(unrestored)
    restored = len(changes) - residue
    if not changes:
        statement = NO_STATE_CHANGE_STATEMENT
    elif residue == 0:
        statement = ZERO_RESIDUE_STATEMENT
    else:
        statement = (
            f"{residue} state change(s) were not restored — repair required "
            "(see the repair instructions in this attestation)"
        )

    payload = residue_attestation_payload(
        scan_id=scan_id,
        generated_at=moment.isoformat(),
        entries=entries,
        residue=residue,
        restored=restored,
        statement=statement,
        repair_instructions=[_repair_instruction(change) for change in unrestored],
    )
    signature = sign_attestation(signer, payload) if signer is not None else None
    return {
        **payload,
        "hash": attestation_digest(payload),
        "signed": signature is not None,
        "signature": signature,
        # The verdict the report and the scan state key on. Non-zero residue means the scan
        # is *not* clean, whatever else it found.
        "clean": residue == 0,
    }


def attestation_is_clean(attestation: Mapping[str, Any] | None) -> bool:
    """True when the attestation says the scan left nothing behind.

    A missing attestation is **not** clean: a deployment that cannot say what it restored
    has not shown that it restored anything.
    """
    if not attestation:
        return False
    counted = int(attestation.get(RESIDUE_ATTESTATION_KEY) or 0)
    return bool(attestation.get("clean")) and counted == 0


def verify_residue_attestation(
    attestation: Mapping[str, Any], *, signer: Signer | None
) -> tuple[bool, str]:
    """``(ok, detail)`` for a stored attestation — what a third party checks.

    The body is rebuilt from the stored entries and re-hashed, so an edited entry, a
    re-ordered change list or a swapped statement all fail. The signature is verified with
    the deployment key when one is given; without a key the artefact is still hash-checked
    and the detail says so, because "unsigned" must be visible rather than implied.
    """
    stored = dict(attestation)
    digest = stored.pop("hash", None)
    signature = stored.pop("signature", None)
    signed = bool(stored.pop("signed", False))
    clean = stored.pop("clean", None)
    payload = dict(stored)
    recomputed = attestation_digest(payload)
    if digest != recomputed:
        return False, (
            f"the attestation's stored hash {str(digest)[:16]}... does not match the "
            f"recomputed {recomputed[:16]}... — the attestation was edited"
        )
    # Self-consistency before authenticity: a verdict that contradicts the count it is
    # supposed to summarise is not a claim to check a signature against, whatever the
    # signature says — and a forger who knows the format would re-hash this far.
    if clean is not None and bool(clean) != (int(payload.get(RESIDUE_ATTESTATION_KEY) or 0) == 0):
        return False, "the attestation's verdict disagrees with its own residue count"
    if signer is None:
        return True, "hash verified; UNSIGNED (no deployment key configured)"
    if not signed or not verify_attestation(signer, payload, str(signature) if signature else None):
        return False, "the attestation's signature does not verify against the deployment key"
    return True, "signature and hash verified"


def _repair_instruction(change: Mapping[str, Any]) -> str:
    """The ledger's own repair instruction, from the journal entry that produced it."""
    return StateChangeRecord.from_dict(dict(change)).repair_instruction()
