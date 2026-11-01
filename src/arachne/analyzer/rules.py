"""The declarative rule engine (F-05-01).

A rule is data: which candidates it applies to (``check_ref``), named conditions over the
candidate's evidence, and the verdict each condition implies (``severity_if``,
``confidence``). Evaluating one is pure — no network, no clock, no database — so a scan can
push millions of candidates through it per hour and two runs over the
same evidence always produce the same verdict .

The YAML shapes, both of which the engine uses, are accepted:

.. code-block:: yaml

    severity_if:
      - "secrets_found and http_status == 200 -> high"   # the spec's inline form
      - {when: "file_exists", then: medium}              # the explicit form
    conditions:
      file_exists: {evidence.http_response.status_code in [200]}   # mapping form: the key
      secrets_found: "evidence.artifact.matched_patterns"          # string form

A *mapping* condition is read by parsing its single key as an expression, which is exactly
how the spec writes ``{evidence.http_status in [200]}``; a plain ``{path: value}`` mapping
whose key is a bare path is read as an equality, so both spellings work.

Rules are ranked by specificity and the most specific one that fires wins, so a general
"anything M4 reports is at least medium" rule never overrides a precise one. Every clause
that fired is kept in the :class:`~arachne.analyzer.model.RuleTraceEntry` trace, which is
what makes the narrative explainable and the report defensible.
"""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from importlib.resources import files
from typing import Any, Final

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from arachne.analyzer.conditions import ConditionError, FactSpace, parse_expression
from arachne.analyzer.model import Candidate, RuleTraceEntry
from arachne.core.errors import ConfigurationError

__all__ = [
    "DEFAULT_RULES_RESOURCE",
    "Rule",
    "RuleClause",
    "RuleEngine",
    "RuleMatch",
    "RuleSelector",
    "RuleSet",
    "load_rule_set",
    "parse_rule_set",
]

#: Where the shipped rule corpus lives inside the package.
DEFAULT_RULES_RESOURCE: Final = ("rules", "heuristic-rules.yaml")

_MODEL_CONFIG = ConfigDict(frozen=True, extra="forbid")

_RESEARCH_REF = re.compile(r"^ch0[1-6]#\d{1,2}(?:-\d{1,2})?$")
_CHECK_ID = re.compile(r"^m[1-6]\.[a-z0-9-]+$")


# --------------------------------------------------------------------------- selectors


@dataclass(frozen=True, slots=True)
class RuleSelector:
    """One entry of ``check_ref``, resolved to a precise matcher.

    Forms: ``m4.env-file-probe`` (check id), ``M4#env-file-probe`` (module#check name),
    ``M4``/``M4#*`` (a whole module), ``ch04#1``/``research:ch04#1`` (a corpus method), and
    ``*`` (any candidate). Globs are allowed in the check-name slot, because a rule family
    legitimately covers ``m4.*-exposure``.
    """

    raw: str
    kind: str  # "any" | "check" | "module" | "research"
    check_pattern: str | None = None
    module: str | None = None

    @property
    def specificity(self) -> int:
        """How narrow this selector is; higher wins when two rules both fire."""
        if self.kind == "check":
            return 4 if "*" not in (self.check_pattern or "") else 3
        if self.kind == "module":
            return 1
        return 3 if self.kind == "research" else 0

    def matches(self, candidate: Candidate) -> bool:
        if self.kind == "any":
            return True
        if self.kind == "module":
            return candidate.check_module == self.module
        if self.kind == "research":
            return candidate.research_ref == self.check_pattern
        if candidate.check_id is None:
            return False
        return fnmatch.fnmatchcase(candidate.check_id, self.check_pattern or "")

    @classmethod
    def parse(cls, raw: str, *, source: str) -> RuleSelector:
        text = raw.strip()
        if not text:
            raise ConfigurationError(f"{source}: an empty check_ref entry is not allowed")
        if text == "*":
            return cls(raw=raw, kind="any")
        if text.startswith("research:"):
            reference = text.split(":", 1)[1]
            if not _RESEARCH_REF.match(reference):
                raise ConfigurationError(
                    f"{source}: {raw!r} is not a corpus reference (expected research:chNN#M)"
                )
            return cls(raw=raw, kind="research", check_pattern=reference)
        if _RESEARCH_REF.match(text):
            return cls(raw=raw, kind="research", check_pattern=text)
        if "#" in text:
            module, _, name = text.partition("#")
            normalized = module.strip().upper()
            if normalized not in {"M1", "M2", "M3", "M4", "M5", "M6"}:
                raise ConfigurationError(f"{source}: {raw!r} does not name a module (M1..M6)")
            name = name.strip()
            if name == "*":
                return cls(raw=raw, kind="module", module=normalized)
            if not name:
                raise ConfigurationError(
                    f"{source}: {raw!r} has a dangling '#'; write 'M2' or 'M2#*' for a whole "
                    "module, or 'M2#<check-name>' for one check"
                )
            return cls(
                raw=raw,
                kind="check",
                module=normalized,
                check_pattern=f"{normalized.lower()}.{name}",
            )
        lowered = text.lower()
        if _CHECK_ID.match(lowered):
            return cls(raw=raw, kind="check", module=lowered[:2].upper(), check_pattern=lowered)
        if "*" in lowered and lowered.startswith("m"):
            return cls(raw=raw, kind="check", check_pattern=lowered)
        if lowered.upper() in {"M1", "M2", "M3", "M4", "M5", "M6"}:
            return cls(raw=raw, kind="module", module=lowered.upper())
        raise ConfigurationError(
            f"{source}: {raw!r} is not a check id, a module reference or a corpus reference"
        )


# --------------------------------------------------------------------------- clauses


@dataclass(frozen=True, slots=True)
class RuleClause:
    """``when → then``: one line of ``severity_if`` or ``confidence``."""

    when: str
    value: Any
    declared: str

    def matches(self, facts: FactSpace, env: Mapping[str, bool]) -> bool:
        return parse_expression(self.when).evaluate(facts, env)


class Rule(BaseModel):
    """One rule ."""

    model_config = _MODEL_CONFIG

    id: str = Field(min_length=3, max_length=128)
    title: str = Field(min_length=3, max_length=512)
    check_ref: tuple[str, ...] = Field(min_length=1)
    conditions: dict[str, Any] = Field(default_factory=dict)
    severity_if: tuple[Any, ...] = ()
    confidence: tuple[Any, ...] = ()
    cwe: str | None = None
    cve: str | None = None
    remediation: str | None = None
    narrative: str | None = None
    tags: tuple[str, ...] = ()
    #: Verdict used when no ``severity_if`` clause matches; without it, the rule only fires
    #: on a matching clause (the safe default — a rule with conditions but no clauses is a
    #: description, not a decision).
    default_severity: str | None = None
    default_confidence: float | None = None
    #: Optional reference to a remediation-catalog entry keyed by CWE when ``remediation``
    #: is absent; ``None`` means "look it up by CWE".
    enabled: bool = True

    @model_validator(mode="after")
    def _validate(self) -> Rule:
        if self.cwe is not None and not re.fullmatch(r"CWE-\d{1,5}", self.cwe):
            raise ValueError(f"rule {self.id}: cwe {self.cwe!r} is not CWE-NNN")
        for severity in (self.default_severity,):
            if severity is not None and severity not in {
                "critical",
                "high",
                "medium",
                "low",
                "info",
            }:
                raise ValueError(f"rule {self.id}: unknown severity {severity!r}")
        if self.default_confidence is not None and not 0.0 <= self.default_confidence <= 100.0:
            raise ValueError(
                f"rule {self.id}: default_confidence must be within [0, 100], "
                f"got {self.default_confidence}"
            )
        return self

    # ------------------------------------------------------------------ built data
    def selectors(self, *, source: str = "rule") -> tuple[RuleSelector, ...]:
        return tuple(
            RuleSelector.parse(item, source=f"{source}:{self.id}") for item in self.check_ref
        )

    @property
    def specificity(self) -> int:
        return max((selector.specificity for selector in self.selectors()), default=0)

    def matches(self, candidate: Candidate) -> bool:
        return any(selector.matches(candidate) for selector in self.selectors())

    def severity_clauses(self) -> tuple[RuleClause, ...]:
        return _parse_clauses(self.severity_if, rule_id=self.id, field_name="severity_if")

    def confidence_clauses(self) -> tuple[RuleClause, ...]:
        return _parse_clauses(self.confidence, rule_id=self.id, field_name="confidence")

    def condition_expressions(self) -> dict[str, str]:
        """The rule's named conditions, normalized to expression text."""
        out: dict[str, str] = {}
        for name, body in self.conditions.items():
            out[name] = _condition_text(name, body, rule_id=self.id)
        return out


def _parse_clauses(
    clauses: Sequence[Any], *, rule_id: str, field_name: str
) -> tuple[RuleClause, ...]:
    parsed: list[RuleClause] = []
    for item in clauses:
        if isinstance(item, str):
            text = item.strip()
            when, separator, then = text.rpartition("->")
            if not separator or not when.strip() or not then.strip():
                raise ConfigurationError(
                    f"rule {rule_id}: {field_name} entry {item!r} is not '<condition> -> <value>'"
                )
            parsed.append(RuleClause(when=when.strip(), value=then.strip(), declared=text))
            continue
        if isinstance(item, Mapping):
            mapping = dict(item)
            if "when" not in mapping or "then" not in mapping:
                raise ConfigurationError(
                    f"rule {rule_id}: {field_name} entry {item!r} must have 'when' and 'then'"
                )
            unknown = sorted(set(mapping) - {"when", "then"})
            if unknown:
                raise ConfigurationError(
                    f"rule {rule_id}: {field_name} entry has unknown key(s) {unknown}"
                )
            when = str(mapping["when"])
            parsed.append(
                RuleClause(
                    when=when, value=mapping["then"], declared=f"{when} -> {mapping['then']}"
                )
            )
            continue
        raise ConfigurationError(
            f"rule {rule_id}: {field_name} entry {item!r} is neither a string nor a mapping"
        )
    return tuple(parsed)


def _condition_text(name: str, body: Any, *, rule_id: str) -> str:
    if isinstance(body, str):
        return body
    if isinstance(body, Mapping):
        mapping = dict(body)
        if len(mapping) == 1:
            key, value = next(iter(mapping.items()))
            key_text = str(key).strip()
            if value is None:
                # ``{evidence.http_status in [200]}``: the key *is* the expression.
                return key_text
            if " " in key_text:
                # ``{evidence.http_status in: [200]}`` — the operator stayed in the key and the
                # operand is the value (how a Python dict literal usually spells it).
                return f"{key_text} {_literal_text(value)}"
            # ``{asset_value: example.com}``: a plain equality.
            return f"{key_text} == {_literal_text(value)}"
        raise ConfigurationError(
            f"rule {rule_id}: condition {name!r} has {len(mapping)} keys; write an expression "
            "string or a single-key mapping"
        )
    raise ConfigurationError(f"rule {rule_id}: condition {name!r} must be a string or a mapping")


def _literal_text(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(_literal_text(item) for item in value) + "]"
    return '"' + str(value).replace('"', '\\"') + '"'


# --------------------------------------------------------------------------- rule set


class RuleSet(BaseModel):
    """The whole rule corpus (``templates/rules/heuristic-rules.yaml``)."""

    model_config = _MODEL_CONFIG

    version: str = Field(min_length=1, max_length=32)
    rules: tuple[Rule, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def _validate_unique(self) -> RuleSet:
        seen: set[str] = set()
        for rule in self.rules:
            if rule.id in seen:
                raise ValueError(f"duplicate rule id {rule.id!r}")
            seen.add(rule.id)
            rule.selectors()  # fail at load time, not at scan time
            for clause in rule.severity_clauses():
                parse_expression(clause.when)
                _as_severity(clause.value, rule_id=rule.id)
            for clause in rule.confidence_clauses():
                parse_expression(clause.when)
                _as_confidence(clause.value, rule_id=rule.id)
            for name, text in rule.condition_expressions().items():
                try:
                    parse_expression(text)
                except ConditionError as exc:
                    raise ValueError(f"rule {rule.id}: condition {name!r}: {exc}") from exc
        return self

    def enabled(self) -> tuple[Rule, ...]:
        return tuple(rule for rule in self.rules if rule.enabled)

    def ranked(self) -> tuple[Rule, ...]:
        """Rules most specific first, then by id — a total order, so results are stable."""
        return tuple(sorted(self.enabled(), key=lambda rule: (-rule.specificity, rule.id)))


def parse_rule_set(data: Any, *, source: str = "<memory>") -> RuleSet:
    if not isinstance(data, dict):
        msg = f"{source}: expected a mapping, got {type(data).__name__}"
        raise ConfigurationError(msg)
    try:
        return RuleSet.model_validate(data)
    except ValidationError as exc:
        parts = [
            f"{'.'.join(str(item) for item in error['loc']) or '<root>'}: {error['msg']}"
            for error in exc.errors()
        ]
        raise ConfigurationError(f"{source}: invalid rule set: {'; '.join(parts)}") from exc


def load_rule_set(path: str | None = None) -> RuleSet:
    """Load the rule corpus from ``path``, or the shipped default (F-09-04)."""
    if path is not None:
        from pathlib import Path

        resolved = Path(path).expanduser()
        if not resolved.is_file():
            msg = f"rule file {resolved} does not exist"
            raise ConfigurationError(msg)
        try:
            text = resolved.read_text(encoding="utf-8")
        except OSError as exc:
            raise ConfigurationError(f"cannot read {resolved}: {exc}") from exc
        return parse_rule_set(_safe_yaml(text, source=str(resolved)), source=str(resolved))
    resource = files("arachne.templates")
    for part in DEFAULT_RULES_RESOURCE:
        resource = resource.joinpath(part)
    try:
        text = resource.read_text(encoding="utf-8")
    except (FileNotFoundError, OSError) as exc:  # pragma: no cover - packaging failure
        msg = f"bundled rule corpus is missing: {exc}"
        raise ConfigurationError(msg) from exc
    source = "/".join(DEFAULT_RULES_RESOURCE)
    return parse_rule_set(_safe_yaml(text, source=source), source=source)


def _safe_yaml(text: str, *, source: str) -> Any:
    try:
        # F-08-06: safe_load only — a rule file is data, never a way to run code.
        return yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ConfigurationError(f"{source}: not valid YAML: {exc}") from exc


# --------------------------------------------------------------------------- evaluation


@dataclass(frozen=True, slots=True)
class RuleMatch:
    """The verdict of the most specific rule that fired for one candidate."""

    rule: Rule
    severity: str
    confidence: float | None
    cwe: str | None
    remediation_ref: str | None
    narrative_id: str | None
    trace: tuple[RuleTraceEntry, ...]
    conditions: Mapping[str, bool]

    @property
    def rule_id(self) -> str:
        return self.rule.id


class _ConditionEnvironment(Mapping[str, bool]):
    """Lazily resolved condition values, so a condition may reference a later one."""

    def __init__(self, expressions: Mapping[str, str], facts: FactSpace) -> None:
        self._expressions = dict(expressions)
        self._facts = facts
        self._values: dict[str, bool] = {}
        self._stack: list[str] = []

    def __getitem__(self, name: str) -> bool:
        if name in self._values:
            return self._values[name]
        if name not in self._expressions:
            raise KeyError(name)
        if name in self._stack:
            cycle = " -> ".join([*self._stack, name])
            raise ConfigurationError(f"cyclic rule condition reference: {cycle}")
        self._stack.append(name)
        try:
            value = parse_expression(self._expressions[name]).evaluate(self._facts, self)
        finally:
            self._stack.pop()
        self._values[name] = value
        return value

    def __iter__(self) -> Iterator[str]:
        return iter(self._expressions)

    def __len__(self) -> int:
        return len(self._expressions)

    def __contains__(self, name: object) -> bool:
        return name in self._expressions


class RuleEngine:
    """Evaluates the rule corpus against candidates (F-05-01)."""

    def __init__(self, rules: RuleSet | None = None) -> None:
        self.rules = rules or load_rule_set()
        self._clauses: dict[str, tuple[tuple[RuleClause, ...], tuple[RuleClause, ...]]] = {
            rule.id: (rule.severity_clauses(), rule.confidence_clauses())
            for rule in self.rules.rules
        }

    @property
    def version(self) -> str:
        return self.rules.version

    def evaluate(self, candidate: Candidate, facts: FactSpace) -> RuleMatch | None:
        """The verdict of the most specific matching rule, or ``None`` when none fires."""
        for rule in self.rules.ranked():
            if not rule.matches(candidate):
                continue
            match = self._evaluate_rule(rule, facts)
            if match is not None:
                return match
        return None

    # ------------------------------------------------------------------ internals
    def _evaluate_rule(self, rule: Rule, facts: FactSpace) -> RuleMatch | None:
        severity_clauses, confidence_clauses = self._clauses[rule.id]
        env = _ConditionEnvironment(rule.condition_expressions(), facts)
        trace: list[RuleTraceEntry] = []

        severity: str | None = None
        for clause in severity_clauses:
            fired = clause.matches(facts, env)
            if fired:
                severity = _as_severity(clause.value, rule_id=rule.id)
                trace.append(
                    RuleTraceEntry(
                        rule_id=rule.id,
                        clause="severity_if",
                        expression=clause.when,
                        value=severity,
                    )
                )
                break
        if severity is None:
            severity = rule.default_severity
            if severity is None:
                return None

        confidence: float | None = None
        for clause in confidence_clauses:
            if clause.matches(facts, env):
                confidence = _as_confidence(clause.value, rule_id=rule.id)
                trace.append(
                    RuleTraceEntry(
                        rule_id=rule.id,
                        clause="confidence",
                        expression=clause.when,
                        value=clause.value,
                    )
                )
                break
        if confidence is None and rule.default_confidence is not None:
            confidence = rule.default_confidence

        for name in rule.condition_expressions():
            value = env[name]
            trace.append(
                RuleTraceEntry(
                    rule_id=rule.id,
                    clause=f"condition {name}",
                    expression=rule.condition_expressions()[name],
                    value=value,
                )
            )

        return RuleMatch(
            rule=rule,
            severity=severity,
            confidence=confidence,
            cwe=rule.cwe,
            remediation_ref=rule.remediation,
            narrative_id=rule.narrative,
            trace=tuple(trace),
            conditions={name: env[name] for name in rule.condition_expressions()},
        )


def _as_severity(value: Any, *, rule_id: str) -> str:
    """The severity a ``severity_if`` clause names, validated at load time."""
    severity = str(value).strip().lower()
    if severity not in {"critical", "high", "medium", "low", "info"}:
        raise ConfigurationError(
            f"rule {rule_id}: severity clause yields {value!r}, which is not one of "
            "critical|high|medium|low|info"
        )
    return severity


def _as_confidence(value: Any, *, rule_id: str) -> float:
    if isinstance(value, str):
        # The inline ``"<condition> -> 0.92"`` form yields text; the explicit mapping form
        # yields a number. Both mean the same thing.
        try:
            value = float(value.strip())
        except ValueError as exc:
            raise ConfigurationError(
                f"rule {rule_id}: a confidence clause must yield a number, got {value!r}"
            ) from exc
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigurationError(
            f"rule {rule_id}: a confidence clause must yield a number, got {value!r}"
        )
    number = float(value)
    if not 0.0 <= number <= 100.0:
        raise ConfigurationError(
            f"rule {rule_id}: confidence {number} is outside [0, 1] / [0, 100]"
        )
    return number
