"""Sigma alignment: would the M6 hunt library have caught the emitted test events?
(S24, REQ-VALID-004)

The honest version of "we validated our Sigma rules" is to feed the *declared telemetry*
of each replayed action through the same evaluator M6 uses on ingested logs
(:func:`arachne.modules.m6.feeds.match_event`) and report which shipped rules matched.
Nothing is inferred: a rule-hit is a rule whose selection the emitted event satisfies, and
a rule-miss is a technique the library has no rule for at all.

A rule-miss is a *finding*, not a failure of the run — the shipped library is small (six
rules) and the whole point of the alignment is to say where it is thin. The
``m3.state-marker`` action (T1565.001, stored data manipulation) is the demonstrated miss:
it is a real, safe, replayable proof action and the library has no rule for its technique.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from arachne.modules.m6.feeds import SigmaRule, load_sigma_rules, match_event
from arachne.purple.attack import ReplayAction, normalize_technique

__all__ = ["RuleAlignment", "align_action", "align_actions", "rule_techniques", "shipped_rules"]


@dataclass(frozen=True, slots=True)
class RuleAlignment:
    """One action's Sigma verdict: which shipped rules matched its emitted event."""

    check_id: str
    techniques: tuple[str, ...]
    event_summary: str
    logsource: dict[str, str]
    fields: dict[str, Any]
    #: ``(rule_id, title, level, technique tags)`` per matching rule, sorted by id.
    hits: tuple[tuple[str, str, str, tuple[str, ...]], ...] = ()
    #: Rules that exist and whose logsource matches but whose selection did not — the
    #: distinction between "no rule covers this" and "a rule looked and did not fire" is
    #: exactly what a rule author needs.
    looked_but_missed: int = 0
    rule_count: int = 0

    @property
    def matched(self) -> bool:
        """True when at least one shipped rule fires on this action's telemetry."""
        return bool(self.hits)

    @property
    def verdict(self) -> str:
        return "rule-hit" if self.matched else "rule-miss"

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "techniques": list(self.techniques),
            "verdict": self.verdict,
            "event": {"summary": self.event_summary, "logsource": dict(self.logsource),
                      "fields": dict(self.fields)},
            "hits": [
                {"rule_id": rid, "title": title, "level": level, "techniques": list(tags)}
                for rid, title, level, tags in self.hits
            ],
            "rules_evaluated": self.rule_count,
        }


def rule_techniques(rule: SigmaRule) -> tuple[str, ...]:
    """The ATT&CK technique ids a Sigma rule tags itself with.

    Sigma convention puts them in ``tags`` as ``attack.t1059``; a tag that is not an
    ATT&CK technique id (a tactic, or a free-form tag) is skipped rather than guessed at.
    """
    found: list[str] = []
    for tag in rule.tags:
        candidate = tag.strip()
        lowered = candidate.lower()
        # Sigma tags are ``attack.t1059`` (technique) or ``attack.credential_access``
        # (tactic) — only the technique form is an id we can score.
        if not lowered.startswith(("attack.t", "t")):
            continue
        try:
            technique = normalize_technique(lowered.removeprefix("attack."))
        except ValueError:
            continue
        if technique not in found:
            found.append(technique)
    return tuple(found)


def shipped_rules(path: str | None = None) -> tuple[SigmaRule, ...]:
    """The M6 hunt library (the bundled set unless an operator override is configured)."""
    return load_sigma_rules(path)


def align_action(action: ReplayAction, rules: tuple[SigmaRule, ...]) -> RuleAlignment:
    """Evaluate one action's declared telemetry against the shipped rules."""
    fields = dict(action.event.fields)
    hits: list[tuple[str, str, str, tuple[str, ...]]] = []
    looked = 0
    for rule in rules:
        if match_event(rule, fields):
            hits.append((rule.id, rule.title, rule.level, rule_techniques(rule)))
        else:
            looked += 1
    hits.sort(key=lambda item: item[0])
    return RuleAlignment(
        check_id=action.check_id,
        techniques=action.techniques,
        event_summary=action.event.summary,
        logsource=dict(action.event.logsource),
        fields=fields,
        hits=tuple(hits),
        looked_but_missed=looked,
        rule_count=len(rules),
    )


def align_actions(
    actions: tuple[ReplayAction, ...], rules: tuple[SigmaRule, ...] | None = None
) -> tuple[RuleAlignment, ...]:
    """Align every action, loading the shipped library once."""
    effective = rules if rules is not None else shipped_rules()
    return tuple(align_action(action, effective) for action in actions)
