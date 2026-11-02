"""Personally identifiable information: detect it, mask it, per project policy (S25).

REQ-TRUST-006 wants PII in captured evidence "detectable and maskable under a per-project
policy, with retention hooks integrated into REQ-DATA-001". Three pieces:

* **Detection** (:func:`detect`) — a small set of linear patterns (email, phone, US SSN,
  payment card number, IBAN, IPv4) plus the two *validators* that make a pattern a finding
  rather than a guess: the Luhn check for a card number and mod-97 for an IBAN. A pattern
  that matches a number but fails its checksum is not PII and is left alone, which is what
  keeps a scanner from redacting a version string that happens to be sixteen digits.
* **Masking** (:func:`mask_payload`) — the policy's action applied to every string in an
  evidence payload: ``mask`` (a ``[PII:email]`` placeholder), ``hash`` (a salted
  pseudonym, so two occurrences of the same address are still *correlatable* without being
  readable) or ``drop`` (remove the value entirely). Detection never returns the matched
  value to a caller that only wants to mask, and masking is irreversible.
* **The policy** (:class:`PIIPolicy`) — a project's ``pii_json``, defaulting to the
  deployment's ``ARACHNE_PII_*`` settings. ``enabled=False`` is a legal, explicit choice
  ("this tenant's evidence is not masked") and is different from "no policy", which
  inherits.

Where it runs: :class:`~arachne.data.evidence_service.EvidenceService` masks an evidence
payload before it is written or offloaded, and the retention pruner re-masks a row whose
``pii_days`` window has passed (a minimisation pass, REQ-DATA-001's hook). Both are audited
with **counts by category**, never a value.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, Final, Literal, cast

from arachne.core.config import PII_KNOWN_CATEGORIES, PiiSettings
from arachne.core.errors import ConfigurationError

__all__ = [
    "CATEGORIES",
    "PIICategory",
    "PIIFinding",
    "PIIPolicy",
    "detect",
    "mask_payload",
    "mask_text",
]

#: The categories this build can detect. Owned by ``core.config`` (a policy naming anything
#: else is refused at configuration time) and re-exported here as the runtime vocabulary;
#: extending the set means adding a pattern *and* whatever validator makes it trustworthy
#: (``tests/unit/test_pii.py`` pins the table).
CATEGORIES: Final[tuple[str, ...]] = PII_KNOWN_CATEGORIES

PIICategory = Literal["email", "phone", "ssn", "credit-card", "iban", "ipv4"]
PIIAction = Literal["mask", "hash", "drop"]

#: Placeholder form. The category is kept because "which kind of PII was here" is what a
#: reviewer needs; the value never is.
_PLACEHOLDER: Final = "[PII:{category}]"

_EMAIL_RE: Final = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,63}")
#: US SSN in its grouped forms; validated further by :func:`_valid_ssn`.
_SSN_RE: Final = re.compile(r"(?<!\d)(\d{3})[-\s](\d{2})[-\s](\d{4})(?!\d)")
#: Candidate card numbers: 13-19 digits, optionally grouped by spaces or dashes.
_CARD_RE: Final = re.compile(r"(?<![\d-])(?:\d[ -]?){12,18}\d(?![\d-])")
_IBAN_RE: Final = re.compile(r"(?<![A-Za-z0-9])[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{1,4}){2,8}")
_IPV4_RE: Final = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
#: Phone numbers: a leading ``+`` with 8-15 digits, or a grouped national form. Deliberately
#: conservative — a bare 10-digit run is far more often an id than a phone number.
_PHONE_RE: Final = re.compile(
    r"(?<![\d+])(?:\+\d{1,3}[ .-]?)?(?:\(\d{2,4}\)[ .-]?)?\d{2,4}(?:[ .-]\d{2,4}){1,3}(?!\d)"
)


@dataclass(frozen=True, slots=True)
class PIIFinding:
    """One detected occurrence: where it is and what kind it is (never the value)."""

    category: str
    start: int
    end: int
    masked: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "category": self.category,
            "start": self.start,
            "end": self.end,
            "masked": self.masked,
        }


@dataclass(frozen=True, slots=True)
class PIIPolicy:
    """A project's PII posture (``projects.pii_json``).

    ``categories`` defaults to every category this build knows; an empty tuple with
    ``enabled=True`` is a legal (if odd) policy that masks nothing, and the settings
    validation refuses it so the mistake surfaces at configuration time rather than as
    "we thought we were masking".
    """

    enabled: bool = False
    categories: tuple[str, ...] = CATEGORIES
    action: PIIAction = "mask"
    #: Salt for the ``hash`` action. A policy that hashes without a salt is refused at
    #: validation, because an unsalted digest of a phone number is reversible by
    #: enumeration — the same reason a password hash needs a salt.
    salt: str | None = None

    def __post_init__(self) -> None:
        unknown = [name for name in self.categories if name not in CATEGORIES]
        if unknown:
            msg = f"unknown PII categor(ies): {', '.join(sorted(unknown))}; known: {CATEGORIES}"
            raise ConfigurationError(msg)
        if self.enabled and not self.categories:
            msg = "a PII policy with enabled=true must name at least one category"
            raise ConfigurationError(msg)
        if self.action not in ("mask", "hash", "drop"):
            msg = f"PII action must be mask, hash or drop; got {self.action!r}"
            raise ConfigurationError(msg)
        if self.action == "hash" and not (self.salt or "").strip():
            msg = "PII action 'hash' requires a salt (ARACHNE_PII_SALT)"
            raise ConfigurationError(msg)

    @property
    def active(self) -> bool:
        return self.enabled and bool(self.categories)

    @classmethod
    def from_dict(cls, data: Any) -> PIIPolicy:
        """Validate a project's ``pii_json`` (or a settings mapping)."""
        if not data:
            return cls()
        if not isinstance(data, Mapping):
            msg = "a PII policy must be a mapping"
            raise ConfigurationError(msg)
        raw_categories = data.get("categories")
        categories: tuple[str, ...]
        if raw_categories is None:
            categories = CATEGORIES
        elif isinstance(raw_categories, str):
            categories = tuple(part.strip() for part in raw_categories.split(",") if part.strip())
        else:
            categories = tuple(str(item) for item in raw_categories)
        return cls(
            enabled=bool(data.get("enabled", False)),
            categories=categories,
            action=str(data.get("action", "mask")),  # type: ignore[arg-type]
            salt=(str(data["salt"]) if data.get("salt") else None),
        )

    @classmethod
    def from_settings(cls, settings: PiiSettings) -> PIIPolicy:
        return cls(
            enabled=settings.enabled,
            categories=settings.categories,
            action=cast(PIIAction, settings.action),
            salt=settings.salt.get_secret_value() if settings.salt is not None else None,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "categories": list(self.categories),
            "action": self.action,
            # The salt is deliberately *not* serialised: it is a secret, and a project row
            # that carried it would put it in every report's provenance block.
            "salted": bool(self.salt),
        }


# --------------------------------------------------------------------------- detection
def detect(text: str, *, categories: Iterable[str] = CATEGORIES) -> tuple[PIIFinding, ...]:
    """Every PII occurrence in ``text``, in document order, de-duplicated by span.

    Linear in ``len(text)`` — the same discipline :mod:`arachne.core.redaction` keeps,
    because the text is target-controlled (a huge response body must not be a
    denial-of-service).
    """
    wanted = set(categories)
    found: dict[tuple[int, int], PIIFinding] = {}

    def _add(category: str, start: int, end: int) -> None:
        span = (start, end)
        if span not in found:
            found[span] = PIIFinding(
                category=category,
                start=start,
                end=end,
                masked=_masked(category, text[start:end]),
            )

    if "email" in wanted:
        for match in _EMAIL_RE.finditer(text):
            _add("email", match.start(), match.end())
    if "credit-card" in wanted:
        for match in _CARD_RE.finditer(text):
            digits = re.sub(r"[ -]", "", match.group(0))
            if 13 <= len(digits) <= 19 and _luhn(digits):
                _add("credit-card", match.start(), match.end())
    if "iban" in wanted:
        for match in _IBAN_RE.finditer(text):
            span = _longest_valid_iban(text, match.start(), match.end())
            if span is not None:
                _add("iban", span[0], span[1])
    if "ssn" in wanted:
        for match in _SSN_RE.finditer(text):
            if _valid_ssn(match.group(1), match.group(2), match.group(3)):
                _add("ssn", match.start(), match.end())
    if "ipv4" in wanted:
        for match in _IPV4_RE.finditer(text):
            if _valid_ipv4(match.group(0)):
                _add("ipv4", match.start(), match.end())
    if "phone" in wanted:
        for match in _PHONE_RE.finditer(text):
            digits = re.sub(r"\D", "", match.group(0))
            if _valid_phone(match.group(0), digits):
                _add("phone", match.start(), match.end())

    return _outermost(found.values())


def _outermost(findings: Iterable[PIIFinding]) -> tuple[PIIFinding, ...]:
    """Drop any finding whose span sits inside another one.

    Categories genuinely overlap — a card number's digits are also a plausible phone number,
    and an IBAN contains grouped digit runs — so a naive list would both double-count and make
    masking ambiguous (two replacements competing for one stretch of text). Keeping the
    *outermost* span is the answer the user wants: the card is masked as a card, and the
    substring inside it is not reported twice. Sorted longest-first at each start position, so
    a containing span is always already kept by the time a nested one is considered.
    """
    ordered = sorted(findings, key=lambda item: (item.start, -(item.end - item.start)))
    kept: list[PIIFinding] = []
    for finding in ordered:
        if any(outer.start <= finding.start and finding.end <= outer.end for outer in kept):
            continue
        kept.append(finding)
    return tuple(sorted(kept, key=lambda item: item.start))


def _luhn(digits: str) -> bool:
    total = 0
    for index, char in enumerate(reversed(digits)):
        value = int(char)
        if index % 2 == 1:
            value *= 2
            if value > 9:
                value -= 9
        total += value
    return total % 10 == 0


def _valid_iban(value: str) -> bool:
    compact = value.replace(" ", "").upper()
    if not 15 <= len(compact) <= 34 or not compact[:2].isalpha():
        return False
    rearranged = compact[4:] + compact[:4]
    try:
        digits = "".join(str(int(char, 36)) for char in rearranged)
    except ValueError:  # pragma: no cover - the pattern already restricts the alphabet
        return False
    return int(digits) % 97 == 1


def _longest_valid_iban(text: str, start: int, end: int) -> tuple[int, int] | None:
    """The longest prefix of ``text[start:end]`` that is a checksum-valid IBAN.

    The pattern is deliberately greedy (an IBAN's trailing group is 1-4 characters, so the
    group count alone cannot say where the number ends) and a greedy match that runs into the
    following text fails its mod-97 check. Trimming from the right and taking the first valid
    prefix recovers the true span — and, because every candidate must pass the checksum, a
    shortening can only *add* a finding, never invent one.
    """
    for stop in range(end, start, -1):
        candidate = text[start:stop]
        if len(candidate.replace(" ", "")) < 15:
            return None
        if _valid_iban(candidate):
            return start, stop
    return None


def _valid_ssn(area: str, group: str, serial: str) -> bool:
    if area in {"000", "666"} or area.startswith("9"):
        return False
    return group != "00" and serial != "0000"


def _valid_ipv4(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 4:
        return False
    return all(part.isdigit() and 0 <= int(part) <= 255 for part in parts)


def _valid_phone(raw: str, digits: str) -> bool:
    """A grouped number, or an international one. A bare digit run is not a phone number."""
    if raw.lstrip().startswith("+") or raw.strip().startswith("("):
        return 8 <= len(digits) <= 15
    # The national form must actually be *grouped* — "603 555 0123" yes, "6035550123" no —
    # long enough that a date ("2026-10-31", eight digits) is not mistaken for one, and
    # grouped *consistently*: "123-45-6789 4111" mixes dashes and spaces, which is one number
    # colliding with the next token rather than a phone number.
    separators = {char for char in raw if char in " .-"}
    return 9 <= len(digits) <= 15 and bool(separators) and len(separators) == 1


def _masked(category: str, value: str) -> str:
    """A non-reversible fingerprint of the match, for the operator's manifest."""
    head = value[:2]
    return f"{head}… ({len(value)} chars, {category})"


# --------------------------------------------------------------------------- masking
def mask_text(text: str, policy: PIIPolicy, *, pseudonym_salt: str | None = None) -> str:
    """Apply ``policy`` to one string (a no-op when the policy is inactive)."""
    return _mask_string(text, policy, pseudonym_salt or policy.salt)


def mask_payload(
    payload: Any, policy: PIIPolicy, *, pseudonym_salt: str | None = None
) -> tuple[Any, dict[str, int]]:
    """Mask every string in a JSON-like ``payload``; return ``(masked, counts)``.

    The counts are by category — all a caller may audit or log. Keys are left alone on
    purpose: a key named "email" is a schema detail, and rewriting keys would break the
    consumer that reads the evidence.
    """
    counts: dict[str, int] = {}
    if not policy.active:
        return payload, counts
    return _walk(payload, policy, pseudonym_salt or policy.salt, counts, depth=0), counts


def _walk(
    value: Any,
    policy: PIIPolicy,
    salt: str | None,
    counts: dict[str, int],
    *,
    depth: int,
) -> Any:
    if depth > 12:
        return value
    if isinstance(value, str):
        return _mask_string(value, policy, salt, counts)
    if isinstance(value, Mapping):
        return {
            key: _walk(item, policy, salt, counts, depth=depth + 1) for key, item in value.items()
        }
    if isinstance(value, list):
        return [_walk(item, policy, salt, counts, depth=depth + 1) for item in value]
    if isinstance(value, tuple):
        return tuple(_walk(item, policy, salt, counts, depth=depth + 1) for item in value)
    return value


def _mask_string(
    text: str,
    policy: PIIPolicy,
    salt: str | None,
    counts: dict[str, int] | None = None,
) -> str:
    if not policy.active or not text:
        return text
    findings = detect(text, categories=policy.categories)
    if not findings:
        return text
    out: list[str] = []
    cursor = 0
    for finding in findings:
        out.append(text[cursor : finding.start])
        out.append(_replacement(text[finding.start : finding.end], finding.category, policy, salt))
        cursor = finding.end
        if counts is not None:
            counts[finding.category] = counts.get(finding.category, 0) + 1
    out.append(text[cursor:])
    return "".join(out)


def _replacement(value: str, category: str, policy: PIIPolicy, salt: str | None) -> str:
    if policy.action == "drop":
        return ""
    if policy.action == "hash":
        digest = hashlib.sha256(((salt or "") + value).encode("utf-8")).hexdigest()[:12]
        return f"[PII:{category}:{digest}]"
    return _PLACEHOLDER.format(category=category)


@dataclass(slots=True)
class PIIRun:
    """Accumulates one scan's masking work for the audit line."""

    counts: dict[str, int] = field(default_factory=dict)

    @property
    def total(self) -> int:
        return sum(self.counts.values())

    def merge(self, other: Mapping[str, int]) -> None:
        for key, value in other.items():
            self.counts[key] = self.counts.get(key, 0) + value
