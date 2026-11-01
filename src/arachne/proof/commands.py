"""The L3 one-shot command proof (REQ-PROOF-007).

The ladder's L3 answers one question — "can this sink get a command executed?" — with
one benign action: the server is asked to run ``echo arachne-<nonce>``. The design
makes everything else unrepresentable:

* **No arbitrary command API.** :class:`CommandProof` exposes a payload *getter* and a
  ``prove`` method that hands the payload to a sink callable the *check* supplies.
  There is no parameter anywhere — not on this class, not on
  :func:`arachne.core.proof.command_payload` — that accepts a command string. The only
  command name the code can ever emit is ``echo`` (:data:`ALLOWED_COMMANDS`).
* **One shot.** Each instance proves once; a second :meth:`CommandProof.prove` is
  refused (``service disruption``: a proof is not a repeater).
* **Captured redacted, audited.** The exchange comes back through the check's normal
  evidence path (already redacted at capture, REQ-PROOF-012), and the execution itself
  is audited as ``proof.command_executed`` with the nonce — never the target's full
  output.
"""

from __future__ import annotations

import secrets
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from arachne.core.audit import AuditAction
from arachne.core.proof import ProofRefused, command_payload, poc_marker, validate_nonce
from arachne.core.redaction import redact_text

__all__ = ["CommandProof", "CommandProofResult"]

#: Output text kept as proof. The echo marker is ~50 characters; anything longer is
#: target data, not proof (REQ-PROOF-011: no exfiltration of real secrets/bulk data).
MAX_PROOF_OUTPUT_CHARS = 500


@dataclass(frozen=True, slots=True)
class CommandProofResult:
    """What one L3 proof observed."""

    nonce: str
    payload: str
    reflected: bool
    output_excerpt: str | None
    captured_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def to_dict(self) -> dict[str, Any]:
        return {
            "nonce": self.nonce,
            "payload": self.payload,
            "reflected": self.reflected,
            "output_excerpt": self.output_excerpt,
            "captured_at": self.captured_at.isoformat(),
        }


class CommandProof:
    """One benign, allowlisted, one-shot command execution proof (REQ-PROOF-007)."""

    def __init__(
        self,
        *,
        check_id: str,
        scan_id: str | int,
        auditor: Any = None,
        nonce: str | None = None,
    ) -> None:
        self.check_id = check_id
        self.scan_id = str(scan_id)
        self._auditor = auditor
        #: A caller-supplied nonce pins the payload's visible tag (S24: every artifact a
        #: purple run emits carries the run nonce, REQ-VALID-003). Validated here, so an
        #: operator cannot smuggle a command into the tag.
        self._nonce = nonce or secrets.token_hex(12)
        validate_nonce(self._nonce)
        self._done = False

    # ------------------------------------------------------------------ the payload
    @property
    def nonce(self) -> str:
        return self._nonce

    @property
    def payload(self) -> str:
        """The one allowlisted payload: ``echo arachne-<nonce>``."""
        return command_payload(self._nonce)

    @property
    def marker(self) -> str:
        """The exact text a successful execution produces (the calm marker, REQ-PROOF-009)."""
        return poc_marker(self._nonce, "command execution (one-shot echo)")

    # ------------------------------------------------------------------ the proof
    async def prove(
        self,
        sink: Callable[[str], Awaitable[Any]],
        *,
        find_output: Callable[[Any], str | None] | None = None,
    ) -> CommandProofResult:
        """Inject the payload through ``sink`` — exactly once.

        ``sink`` is the check's own injection callable (it posts the payload through the
        scoped HTTP client, so capture → redact → audit is the normal path). ``output``
        is whatever the sink returned; ``find_output`` optionally extracts the echoed
        marker's surroundings from it. The result is *proof of execution* only when the
        nonce comes back.
        """
        if self._done:
            msg = (
                "this L3 proof already executed its one allowlisted command; a one-shot "
                "proof is never repeated (service disruption is prohibited)"
            )
            raise ProofRefused(msg)
        self._done = True
        output = await sink(self.payload)
        reflected = False
        excerpt: str | None = None
        if output is not None:
            text = output if isinstance(output, str) else str(getattr(output, "body", output))
            # The same guard the L1 oracle uses: a raw reflection echoes the *command
            # text* (nonce included) without executing anything. The proof requires the
            # nonce present while the literal command text is gone — the server's own
            # output, not our injected string.
            reflected = self._nonce in text and self.payload not in text
            if reflected and find_output is not None:
                excerpt = find_output(output)
            elif reflected:
                excerpt = self._excerpt_around(text)
        if self._auditor is not None:
            self._auditor.record(
                AuditAction.PROOF_COMMAND_EXECUTED,
                target=self.check_id,
                meta={
                    "scan_id": self.scan_id,
                    "command": "echo",
                    "allowlist": ["echo"],
                    "nonce": self._nonce,
                    "reflected": reflected,
                    "output_excerpt": redact_text(excerpt) if excerpt else None,
                },
            )
        return CommandProofResult(
            nonce=self._nonce,
            payload=self.payload,
            reflected=reflected,
            output_excerpt=redact_text(excerpt) if excerpt else None,
        )

    def _excerpt_around(self, text: str) -> str:
        """A bounded window of the echoed output — proof, not a transcript."""
        index = text.find(self._nonce)
        if index < 0:
            return ""
        start = max(0, index - 40)
        return text[start : index + len(self._nonce) + 40][:MAX_PROOF_OUTPUT_CHARS]

    def evidence_payload(self, result: CommandProofResult) -> dict[str, Any]:
        """The redacted artifact a check attaches as ``proof`` evidence."""
        return {
            "level": "L3",
            "method": "one-shot allowlisted command (echo)",
            "proof_nonce": result.nonce,
            "payload": result.payload,
            "reflected": result.reflected,
            "output_excerpt": result.output_excerpt,
            "cleanup": "none required (no state was changed)",
        }
