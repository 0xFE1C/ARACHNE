"""The executable proof engine (area ``PROOF``, S15).

``core.proof`` is the pure model (levels, formats, allowlists); this package holds the
services that act:

:mod:`arachne.proof.oob`
    The out-of-band callback service (REQ-PROOF-005): single-use
    ``arachne-<scan>-<check>-<nonce>`` tokens, hits matched to findings, rate-limited
    and audited, and structurally incapable of fetching attacker-controlled URLs.
:mod:`arachne.proof.commands`
    The L3 one-shot helper (REQ-PROOF-007): exactly one allowlisted ``echo`` of a
    unique nonce; no API that accepts an arbitrary command exists.
:mod:`arachne.proof.sql`
    The L4 helpers (REQ-PROOF-008/010): INSERT-first markers, UPDATE with before-value
    capture / auto-restore / re-verification, in-code refusal of destructive SQL, and
    the end-of-scan cleanup pass.
:mod:`arachne.proof.ledger`
    The per-scan proof journal (REQ-PROOF-012): the nonce→probe map, every state
    change and its cleanup status, persisted with the scan record.
:mod:`arachne.proof.access`
    The capability boundary checks see as ``ctx.proof``: grants derived from the
    check's declared proof level, so an L1 check cannot reach an L4 helper
    (REQ-PROOF-011).
:mod:`arachne.proof.server`
    The standalone ``arachne callback-server`` HTTP facade over the service.
"""

from __future__ import annotations

from arachne.proof.commands import CommandProof, CommandProofResult
from arachne.proof.ledger import ProofLedger, StateChangeRecord
from arachne.proof.oob import CallbackService, OobHit, OobProbe

__all__ = [
    "CallbackService",
    "CommandProof",
    "CommandProofResult",
    "OobHit",
    "OobProbe",
    "ProofLedger",
    "StateChangeRecord",
]
