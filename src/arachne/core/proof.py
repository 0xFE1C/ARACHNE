"""The proof ladder model (area ``PROOF``, REQ-PROOF-001…014).

The ladder says how far a check may go to prove a finding. Five levels, lowest
sufficient wins (``01-introduction.md`` §7 principle 2):

``L0``
    passive — never touches the target (third-party indexes only).
``L1``
    active read-only — talks to the target, changes nothing (the default).
``L2``
    out-of-band — the target connects *out* to ARACHNE's callback service, proving a
    blind vulnerability. Single-use tokens (REQ-PROOF-005).
``L3``
    one-shot command — exactly one benign, allowlisted ``echo`` of a unique nonce
    (REQ-PROOF-007). Nothing else is representable.
``L4``
    minimal reversible state change — INSERT-first, before-value capture,
    auto-restore, re-verification (REQ-PROOF-008/009/010).

This module is the *pure* model: enums, formats, allowlists and refusal rules with no
I/O of any kind, so the metadata layer (:mod:`arachne.modules.base`), the planner, the
orchestrator gate and the executable helpers (:mod:`arachne.proof`) all validate
against one definition. Two invariants:

* **Unrepresentable-invalid declarations.** The rules below are enforced by the
  metadata constructor and re-checked by the registry; a contradictory declaration is
  a programming error that fails at import (REQ-PROOF-001/002).
* **The prohibition table is code.** Every prohibited class (persistent shells,
  destructive SQL, deletion without restore, credential/account mutation, secret
  exfiltration, service disruption, evasion tooling) has a named enforcement point a
  helper actually calls, and a named test (REQ-PROOF-011).
"""

from __future__ import annotations

import re
from enum import StrEnum
from typing import Final

from arachne.core.errors import ConfigurationError, SafetyError

__all__ = [
    "ALLOWED_COMMANDS",
    "CREDENTIAL_TABLE_HINTS",
    "FEAR_WORDS",
    "MARKER_TEMPLATE",
    "PROHIBITED_SQL_HEADS",
    "PROOF_LEVELS",
    "CallbackToken",
    "ProofLevel",
    "ProofRefused",
    "command_payload",
    "encode_free",
    "parse_callback_token",
    "poc_marker",
    "validate_nonce",
]

# --------------------------------------------------------------------------- the ladder


class ProofLevel(StrEnum):
    """How far a check may go to prove a finding (REQ-PROOF-001).

    Ordered lowest-first, so ``ProofLevel.L4 > ProofLevel.L2`` is a valid comparison.
    The default for every check is :attr:`L1` — active read-only — and the heuristic
    engine's ceiling is L1 unless an attestation exists (REQ-PROOF-014).
    """

    L0 = "L0"
    L1 = "L1"
    L2 = "L2"
    L3 = "L3"
    L4 = "L4"

    @property
    def rank(self) -> int:
        return PROOF_LEVELS.index(self)

    def at_least(self, other: ProofLevel) -> bool:
        """True when this level may do everything ``other`` may do."""
        return self.rank >= other.rank

    @property
    def is_opt_in(self) -> bool:
        """L2+ is never part of a default scan (REQ-PROOF-001)."""
        return self.rank >= ProofLevel.L2.rank

    @property
    def needs_oob(self) -> bool:
        """L2+ may involve the callback service (its *absence* downgrades, never blocks)."""
        return self.rank >= ProofLevel.L2.rank

    @property
    def needs_state_attestation(self) -> bool:
        """L3/L4 require an explicit state-change attestation (REQ-PROOF-001/003)."""
        return self.rank >= ProofLevel.L3.rank


#: Lowest-first order — the definition ``ProofLevel.rank`` indexes.
PROOF_LEVELS: Final[tuple[ProofLevel, ...]] = (
    ProofLevel.L0,
    ProofLevel.L1,
    ProofLevel.L2,
    ProofLevel.L3,
    ProofLevel.L4,
)


# --------------------------------------------------------------------------- markers (009)

#: The calm, self-identifying marker format (REQ-PROOF-009). Every artifact ARACHNE
#: plants — an OOB token path, an L3 echo payload, an L4 marker row — renders this
#: shape: it says what it is, points at the report, and refuses fear wording.
MARKER_TEMPLATE: Final = "ARACHNE_POC_{nonce} — safe proof of {vuln_class}, see ARACHNE report"

#: Words a marker must never contain: each names a breach that did not happen, and a
#: marker that reads like one can trigger incident response for nothing (REQ-PROOF-009).
FEAR_WORDS: Final[frozenset[str]] = frozenset(
    {
        "penetrated",
        "hacked",
        "pwned",
        "breached",
        "compromised",
        "owned",
        "rooted",
        "backdoor",
        "shelled",
        "infected",
    }
)


def poc_marker(nonce: str, vuln_class: str) -> str:
    """The calm marker an L2/L3/L4 artifact carries (REQ-PROOF-009)."""
    validate_nonce(nonce)
    label = vuln_class.strip().lower()
    if not label or any(word in label for word in FEAR_WORDS):
        msg = f"proof class {vuln_class!r} is not a calm class label"
        raise ProofRefused(msg)
    return MARKER_TEMPLATE.format(nonce=nonce, vuln_class=label)


# --------------------------------------------------------------------------- tokens (005)

_NONCE: Final = re.compile(r"^[a-z0-9]{12,64}$")
_TOKEN_SCAN: Final = re.compile(r"^[A-Za-z0-9]{1,64}$")
_TOKEN_CHECK: Final = re.compile(r"^[a-z0-9][a-z0-9.-]{0,127}$")


def validate_nonce(nonce: str) -> str:
    """Refuse anything that is not a plain opaque identifier.

    The nonce is the only free variable a proof payload may carry; holding it to
    ``[a-z0-9]{12,}`` is what makes shell metacharacters, SQL quote-breaks and
    obfuscation unrepresentable at the format level (REQ-PROOF-011 "evasion tooling").
    """
    if not _NONCE.match(nonce):
        msg = f"nonce {nonce!r} is not a plain [a-z0-9] identifier of 12..64 characters"
        raise ProofRefused(msg)
    return nonce


class CallbackToken:
    """One out-of-band interaction token (REQ-PROOF-005).

    Single-use by service contract: :meth:`arachne.proof.oob.CallbackService.consume`
    returns the hit once, then the token is spent. The string form is the token's URL
    path segment; ``str(token)`` always yields it.
    """

    __slots__ = ("check_id", "nonce", "scan_id")

    def __init__(self, scan_id: str | int, check_id: str, nonce: str) -> None:
        scan = str(scan_id)
        if not _TOKEN_SCAN.match(scan):
            msg = f"scan id {scan!r} is not token-safe (letters/digits only)"
            raise ProofRefused(msg)
        if not _TOKEN_CHECK.match(check_id):
            msg = f"check id {check_id!r} is not token-safe"
            raise ProofRefused(msg)
        validate_nonce(nonce)
        self.scan_id = scan
        self.check_id = check_id
        self.nonce = nonce

    @property
    def value(self) -> str:
        return f"arachne-{self.scan_id}-{self.check_id}-{self.nonce}"

    def __str__(self) -> str:
        return self.value

    def __repr__(self) -> str:
        return f"CallbackToken({self.value!r})"

    def __eq__(self, other: object) -> bool:
        if isinstance(other, CallbackToken):
            return self.value == other.value
        if isinstance(other, str):
            return self.value == other
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self.value)


def parse_callback_token(token: str) -> CallbackToken:
    """Parse ``arachne-<scan-id>-<check-id>-<nonce>``; refuse any other shape.

    Check ids contain dashes themselves (``m3.sqli-oob``), so parsing is anchored from
    both ends: the scan id ends at the *first* dash, the nonce starts after the *last*
    one — the nonce is ``[a-z0-9]{12,}`` and never contains a dash, so the two anchors
    are unambiguous.
    """
    if not token.startswith("arachne-"):
        msg = f"token {token!r} is not an arachne-<scan>-<check>-<nonce> token"
        raise ProofRefused(msg)
    scan, separator, remainder = token[len("arachne-") :].partition("-")
    check, separator, nonce = remainder.rpartition("-")
    if not (scan and separator and check and nonce):
        msg = f"token {token!r} is not an arachne-<scan>-<check>-<nonce> token"
        raise ProofRefused(msg)
    return CallbackToken(scan, check, nonce)


# --------------------------------------------------------------------------- L3 (007)

#: The complete L3 vocabulary: one benign command. An L3 proof echoes a unique nonce
#: through the injection sink; there is no second command and no parameter that could
#: introduce one (REQ-PROOF-007, REQ-PROOF-011 "service disruption"/"evasion tooling").
ALLOWED_COMMANDS: Final[frozenset[str]] = frozenset({"echo"})


def command_payload(nonce: str) -> str:
    """The one allowlisted L3 payload: ``echo arachne-<nonce>`` (REQ-PROOF-007).

    The check injects this string through a command-injection sink; the marker the
    server echoes back (in-band) or the execution monitor records (out-of-band) is the
    proof. There is deliberately no API that accepts a command string.
    """
    return f"echo arachne-{validate_nonce(nonce)}"


def command_payload_for(marker: str) -> str:
    """The allowlisted echo payload carrying ``marker`` — a nonce or a full callback token.

    The L2 blind-command variant echoes the whole token
    (``arachne-<scan>-<check>-<nonce>``) so the execution monitor can phone home to
    exactly that token; the L3 one-shot echoes the bare nonce. The command is ``echo``
    in both cases — the allowlist does not grow.
    """
    if marker.startswith("arachne-"):
        parse_callback_token(marker)
        return f"echo {marker}"
    return command_payload(marker)


# ------------------------------------------------------- L4 SQL policy (008/011)

#: Statement heads an L4 payload may never start with (REQ-PROOF-008). ``UPDATE`` and
#: ``INSERT`` are not in this list because they are only representable through the
#: structured helper paths (:class:`arachne.proof.sql.SqlProof`), which enforce
#: before-value capture, verification and restore.
PROHIBITED_SQL_HEADS: Final[frozenset[str]] = frozenset(
    {"DELETE", "DROP", "TRUNCATE", "ALTER", "GRANT", "REVOKE", "RENAME", "CREATE", "VACUUM"}
)

#: Table names the L4 helpers refuse outright: a proof never touches an identity store
#: (REQ-PROOF-011 "credential/account mutation"). Matched case-insensitively on the
#: table *token* of a statement's target.
CREDENTIAL_TABLE_HINTS: Final[frozenset[str]] = frozenset(
    {
        "users",
        "user",
        "accounts",
        "account",
        "credentials",
        "credential",
        "passwords",
        "password",
        "passwd",
        "sessions",
        "session",
        "tokens",
        "token",
        "api_keys",
        "keys",
        "secrets",
        "otps",
        "mfa",
        "roles",
        "permissions",
        "principals",
        "identities",
    }
)

_SQL_HEAD: Final = re.compile(r"^\s*\(?\s*([A-Za-z]+)")


def _sql_head(statement: str) -> str:
    match = _SQL_HEAD.match(statement)
    return (match.group(1).upper() if match else "").strip()


def sql_refusals(statement: str) -> tuple[str, ...]:
    """Every policy reason the statement may not run as an L4 proof step; empty if none.

    Structural rules (REQ-PROOF-008):
    * prohibited statement heads are refused outright;
    * multi-statement payloads are refused (one statement per proof step);
    * comments and quote-escaping tricks are refused — a proof payload is plain SQL,
      never obfuscated (REQ-PROOF-011 "evasion tooling").
    """
    problems: list[str] = []
    head = _sql_head(statement)
    if not head:
        problems.append("statement does not start with a SQL keyword")
    elif head in PROHIBITED_SQL_HEADS:
        problems.append(f"{head} is a prohibited statement for an L4 proof")
    if head not in {"SELECT", "INSERT", "UPDATE"}:
        problems.append(f"{head or '<empty>'} is not a proof step (expected SELECT/INSERT/UPDATE)")
    stripped = statement.strip().rstrip(";").strip()
    if ";" in stripped:
        problems.append("multi-statement payloads are refused")
    if "--" in statement or "/*" in statement:
        problems.append("SQL comments are refused in a proof payload")
    if re.search(r"[\"'`]", statement):
        problems.append("quoted literals are refused; proof payloads use parameters")
    return tuple(problems)


# --------------------------------------------------------------------------- prohibitions (011)


class ProofRefused(SafetyError):  # noqa: N818 - a refusal is not an error condition
    """A proof action was refused by the proof ladder's own policy (REQ-PROOF-011).

    Raised at code boundaries: the metadata constructor, the registry, the
    orchestrator's proof gate, and the L3/L4 helpers. It is a :class:`SafetyError`, so
    the existing safety plumbing treats it as a refusal, never a crash.
    """


def encode_free(payload: str) -> str:
    """Refuse obfuscated proof payloads (REQ-PROOF-011 "evasion tooling").

    A proof payload is plain, reviewable text: no base64/hex blobs, no ``\\x`` escapes,
    no ``$(...)``/backtick indirection. Noise-reduction in probes is permitted;
    anything that exists to slip past a defender's view is not.
    """
    lowered = payload.lower()
    suspicious = ("base64", "fromhex", "0x", "\\x", "$(", "`", "eval(", "exec(", "decode(")
    if any(token in lowered for token in suspicious):
        msg = "proof payloads must be plain text (evasion/obfuscation is prohibited)"
        raise ProofRefused(msg)
    return payload


def metadata_proof_problems(
    proof: ProofLevel,
    *,
    enabled_by_default: bool,
    requires_state_attestation: bool,
) -> tuple[str, ...]:
    """The declaration contradictions REQ-PROOF-001 makes unrepresentable.

    Shared by :meth:`arachne.modules.base.CheckMetadata.__post_init__` (where they are
    raised) and :meth:`arachne.modules.registry.ModuleGroup.__post_init__` (where a
    hand-crafted instance that bypassed construction is still caught).
    """
    problems: list[str] = []
    if proof.is_opt_in and enabled_by_default:
        problems.append(
            f"proof {proof.value} is opt-in by definition: an L2+ check must set "
            "enabled_by_default=False (an L2+ proof may never run in a default scan)"
        )
    if proof.needs_state_attestation and not requires_state_attestation:
        problems.append(
            f"proof {proof.value} changes target state: requires_state_attestation=True "
            "must be declared"
        )
    if not proof.needs_state_attestation and requires_state_attestation:
        problems.append(
            f"proof {proof.value} does not change state: requires_state_attestation must stay False"
        )
    return tuple(problems)


def require_proof_consistency(
    proof: ProofLevel,
    *,
    enabled_by_default: bool,
    requires_state_attestation: bool,
    check_id: str = "<check>",
) -> None:
    """Raise :class:`ConfigurationError` when the declaration contradicts itself."""
    problems = metadata_proof_problems(
        proof,
        enabled_by_default=enabled_by_default,
        requires_state_attestation=requires_state_attestation,
    )
    if problems:
        raise ConfigurationError(
            f"invalid proof declaration for {check_id!r}: " + "; ".join(problems)
        )
