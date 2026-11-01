"""Prompt-injection detection for target-derived content (REQ-AGENT-006).

The defence against a target that plants instructions in its own responses is structural, not
lexical: target content is wrapped, escaped and delimited before a model sees it; the model's
output is validated against the catalogue, the scope and the budget before anything runs; and no
gate reads AI output. This module adds the *detection* half — an auditable record that hostile
content was present — so an operator can see an attempt, and so the adversarial tests have a
signal to assert on that is independent of the outcome.

The patterns are deliberately narrow and label-driven. A false positive here costs one line in
the journal; a missed one costs nothing at all, because the structural defences do not depend
on recognising the text. That asymmetry is why this is a detector and not a filter.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

from arachne.core.redaction import redact_text

__all__ = ["INJECTION_PATTERNS", "InjectionFinding", "scan_text"]

#: ``(label, pattern)`` pairs. Each label names the *capability the text is trying to reach*
#: rather than the wording, because that is what an operator needs to triage the attempt.
INJECTION_PATTERNS: Final[tuple[tuple[str, re.Pattern[str]], ...]] = (
    (
        "override-instructions",
        re.compile(
            r"\b(ignore|disregard|forget)\b[^.\n]{0,40}"
            r"\b(previous|prior|above|all)\b[^.\n]{0,20}\b(instruction|rule|prompt|direction)",
            re.I,
        ),
    ),
    (
        "role-override",
        re.compile(
            r"\b(you are now|act as|new (instructions|system prompt)"
            r"|system prompt:|developer message)\b",
            re.I,
        ),
    ),
    (
        "concealment",
        re.compile(
            r"\b(do not|don'?t|never)\b[^.\n]{0,30}\b(report|mention|tell|log|disclose)\b",
            re.I,
        ),
    ),
    (
        "budget-escalation",
        re.compile(
            r"\b(increase|raise|remove|unlimited|no)\b[^.\n]{0,30}"
            r"\b(budget|limit|quota|rate)\b",
            re.I,
        ),
    ),
    (
        "gate-bypass",
        re.compile(
            r"\b(bypass|skip|disable|ignore|turn off)\b[^.\n]{0,30}"
            r"\b(gate|attestation|scope|approval|safety|authoriz)",
            re.I,
        ),
    ),
    (
        "authorization-mint",
        re.compile(
            r"\b(grant|mint|extend|renew)\b[^.\n]{0,30}"
            r"\b(attestation|authorization|permission)\b",
            re.I,
        ),
    ),
    (
        "proof-escalation",
        re.compile(
            r"\b(approve|authorize|enable|allow)\b[^.\n]{0,30}"
            r"\b(l3|l4|state change|command execution|write access)\b",
            re.I,
        ),
    ),
    (
        "out-of-scope-request",
        re.compile(
            r"\b(scan|fetch|request|visit|crawl|connect to)\b[^.\n]{0,40}"
            r"\b(https?://|[a-z0-9-]+\.(?:com|net|org|io|ru|cn)\b)",
            re.I,
        ),
    ),
    (
        "command-execution",
        re.compile(
            r"\b(run|execute|exec)\b[^.\n]{0,20}"
            r"\b(command|shell|curl|bash|powershell|cmd\.exe)\b",
            re.I,
        ),
    ),
)

#: Matches are reported, not acted on; cap them so a hostile body cannot flood the journal.
_MAX_FINDINGS: Final = 8


@dataclass(frozen=True, slots=True)
class InjectionFinding:
    """One suspected injection attempt: what capability it reached for, and the evidence."""

    label: str
    excerpt: str

    def to_dict(self) -> dict[str, str]:
        return {"label": self.label, "excerpt": self.excerpt}


def scan_text(text: str, *, limit: int = _MAX_FINDINGS) -> tuple[InjectionFinding, ...]:
    """Suspected injection attempts in ``text``, de-duplicated by label, redacted.

    The excerpt is passed through the redactor, because the surrounding capture may carry a
    credential and this record goes to the audit trail and the journal.
    """
    if not text:
        return ()
    seen: set[str] = set()
    out: list[InjectionFinding] = []
    for label, pattern in INJECTION_PATTERNS:
        if label in seen:
            continue
        match = pattern.search(text)
        if match is None:
            continue
        seen.add(label)
        excerpt = redact_text(text[max(0, match.start() - 20) : match.end() + 40])
        out.append(InjectionFinding(label=label, excerpt=" ".join(excerpt.split())[:200]))
        if len(out) >= max(0, limit):
            break
    return tuple(out)
