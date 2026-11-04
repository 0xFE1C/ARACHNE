"""The ATT&CK vocabulary and the replayable proof-action map (S24, REQ-VALID-001/004).

Purple-team mode replays *proof* actions — the same ladder S15 built — but a detection
test is only useful if it is named: which ATT&CK technique does this action exercise, and
would a defender's telemetry and rule set have caught it? That naming lives here.

Two data shapes:

:class:`EmittedEvent`
    the telemetry an action produces, as the flat field mapping the M6 Sigma evaluator
    (:func:`arachne.modules.m6.feeds.match_event`) consumes. Declaring it is what makes
    "rule-hit / rule-miss" a real evaluation against the shipped hunt library rather than
    a claim: the emitted event is fed to the same matcher M6 uses on ingested logs.
:class:`ReplayAction`
    one replayable proof check plus its technique tag(s), its primary tactic and its
    emitted event.

The map ships as data (``templates/purple/attck-map.yaml``), so which actions are
replayable is an operational choice rather than a code change — but it is *cross-checked*
against the registry: an action naming a check that does not exist, or claiming a proof
level the catalogue does not declare, is refused. The map cannot lie about the ladder.

The vocabulary is **ATT&CK Enterprise v20** (REQ-VALID-007): 15 tactics, including the
v20 split of Defense Evasion into **Stealth** and **Defense Impairment**, and each of the
706 technique ids checked against the same pinned snapshot a check's ``framework`` mapping
is checked against (:mod:`arachne.modules.framework_map`). An action's tactic must be one
of the tactics the release assigns its technique, so the catalogue cannot file a credential
technique under discovery. **No action is filed under Stealth**: ARACHNE's tests are
designed to be seen (see :data:`NO_EVASION_POLICY`), and filing one there would describe an
evasion capability the product refuses to have. (ATT&CK v20 assigns T1078 Valid Accounts
*Stealth* among four tactics — the actions use its initial-access/persistence assignment.)
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from arachne.core.errors import ConfigurationError
from arachne.modules.framework_map import attack_tactics, framework, item_error

__all__ = [
    "ATTACK_MAP_VERSION",
    "ATTACK_TACTIC_IDS",
    "ATTACK_VERSION",
    "NO_EVASION_POLICY",
    "TACTICS",
    "TACTIC_LABELS",
    "EmittedEvent",
    "ReplayAction",
    "TechniqueMap",
    "load_technique_map",
    "normalize_technique",
    "technique_matches",
    "technique_parent",
    "technique_tactics",
]

#: Bumped when the shipped map's shape or vocabulary changes.
ATTACK_MAP_VERSION = "2.0"

#: The ATT&CK release the tactic vocabulary and the technique ids are pinned to. Read from the
#: same vendored snapshot ``REQ-DET-002`` validates every check's mapping against, so the
#: catalogue cannot quietly name a release it is not validated against.
ATTACK_VERSION = framework("ATT&CK").version

#: The tactic vocabulary, taken from the pinned release rather than kept here. Coverage is
#: reported per tactic, so the set must be the release's: v20 has **15** Enterprise tactics,
#: because Defense Evasion (TA0005, v18-era) was split into **Stealth** and **Defense
#: Impairment** (TA0112). A v18-era list would refuse a valid v20 tactic and mislabel the rest.
_PINNED_TACTICS = attack_tactics()
TACTICS: tuple[str, ...] = tuple(tactic.shortname for tactic in _PINNED_TACTICS)

TACTIC_LABELS: Mapping[str, str] = {tactic.shortname: tactic.title for tactic in _PINNED_TACTICS}

#: Tactic short name → the release's tactic id (``stealth`` → ``TA0005``), for the report.
ATTACK_TACTIC_IDS: Mapping[str, str] = {tactic.shortname: tactic.id for tactic in _PINNED_TACTICS}

#: The one hard rule of this area, quoted where operators will read it.
#:
#: Purple-team tests are *designed to be seen*. ARACHNE emits the declared payload, in
#: the clear, carrying the run nonce, inside the coordinated window, at the ordinary rate
#: limit. There is no encoding, splitting, obfuscation or timing trick anywhere in this
#: package, and a test asserts that none appears.
NO_EVASION_POLICY = (
    "purple-team tests are designed to be SEEN: payloads are emitted verbatim, tagged with "
    "the run nonce, inside the attested detection window and under the ordinary rate limit. "
    "No encoding, obfuscation, fragmentation or detection-evasion technique is used or "
    "supported by ARACHNE."
)

_SEVERITIES = ("info", "low", "medium", "high", "critical")

#: ``attack.t1059.004`` / ``T1059.004`` / ``t1059`` → ``T1059.004``.
_TECHNIQUE = re.compile(r"^(?:attack\.)?(t\d{4})(?:\.(\d{3}))?$", re.IGNORECASE)

_CHECK_ID = re.compile(r"^m[1-6]\.[a-z0-9]+(?:-[a-z0-9]+)*$")


def normalize_technique(value: str) -> str:
    """Normalise an ATT&CK id to ``T####`` / ``T####.###`` (upper case).

    Accepts the Sigma tag form (``attack.T1059.004``), the bare form (``T1059``) and a
    lower-case variant, because all three appear in the wild — in Sigma ``tags``, in a
    SIEM's alert payload and in an operator's campaign YAML. Anything else is refused: a
    detection report that quietly dropped an id it did not understand would be worse than
    one that refused to score.
    """
    match = _TECHNIQUE.match(value.strip())
    if match is None:
        msg = f"{value!r} is not an ATT&CK technique id (expected T#### or T####.###)"
        raise ValueError(msg)
    parent, sub = match.group(1).upper(), match.group(2)
    return f"{parent}.{sub}" if sub else parent


def technique_parent(value: str) -> str:
    """``T1059.004`` → ``T1059``; a parent id is returned unchanged."""
    return normalize_technique(value).split(".", 1)[0]


def technique_tactics(technique: str) -> tuple[str, ...]:
    """The tactics the pinned release assigns ``technique``, or ``()`` when it is unknown.

    This is the check behind "every action exercises the technique it claims": a catalogue
    entry naming ``T1110.001`` under ``initial-access`` is refused, because the release files
    password guessing under credential access. It is deliberately a lookup into the pinned
    snapshot rather than a list kept beside the map — the two cannot drift apart.
    """
    normalized = normalize_technique(technique)
    spec = framework("ATT&CK")
    item = spec.item(f"ATT&CK-{normalized}") or spec.item(f"ATT&CK-{technique_parent(normalized)}")
    return item.tactics if item is not None else ()


def technique_matches(emitted: str, observed: str) -> bool:
    """True when an alert naming ``observed`` counts as seeing ``emitted``.

    The rule, stated once so scoring and its tests cannot drift apart:

    * the same id always matches;
    * an alert on a **parent** technique sees an emitted **sub-technique** (a defender who
      alerts on "Command and Scripting Interpreter" has seen T1059.004);
    * an alert on a **sub-technique** sees an emitted **parent** (a finer-grained rule is
      not a miss);
    * two different sub-techniques of the same parent do **not** see each other — an alert
      for T1059.001 is not detection of T1059.004, and saying otherwise would flatter the
      coverage number.
    """
    left, right = normalize_technique(emitted), normalize_technique(observed)
    if left == right:
        return True
    return technique_parent(left) == technique_parent(right) and (
        left == technique_parent(left) or right == technique_parent(right)
    )


@dataclass(frozen=True, slots=True)
class EmittedEvent:
    """The telemetry one replay action produces, in the shape the Sigma matcher reads.

    ``fields`` is the flat event mapping (``{"EventID": 1, "Image": "/bin/sh", ...}``).
    ``logsource`` is carried for the report's honesty — it names which log the test
    assumes the defender collects — and is deliberately *not* part of matching, because
    the M6 evaluator matches on fields and a rule whose logsource the deployment does not
    collect would be a collection gap, not a rule gap.
    """

    summary: str
    fields: Mapping[str, Any] = field(default_factory=dict)
    logsource: Mapping[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": self.summary,
            "logsource": dict(self.logsource),
            "fields": dict(self.fields),
        }


@dataclass(frozen=True, slots=True)
class ReplayAction:
    """One replayable proof action: a check, its technique tag(s) and its telemetry."""

    check_id: str
    title: str
    #: The proof level the catalogue declares (``L1``..``L4``). Cross-checked against the
    #: registry, so the map cannot mislabel where on the ladder an action sits.
    level: str
    #: The primary tactic (one of :data:`TACTICS`) — what per-tactic coverage counts.
    tactic: str
    techniques: tuple[str, ...]
    severity: str
    event: EmittedEvent
    notes: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_id": self.check_id,
            "title": self.title,
            "level": self.level,
            "tactic": self.tactic,
            "techniques": list(self.techniques),
            "severity": self.severity,
            "event": self.event.to_dict(),
            "notes": self.notes,
        }


def _parse_action(raw: Mapping[str, Any], *, index: int) -> ReplayAction:
    where = f"actions[{index}]"
    check = str(raw.get("check") or "").strip()
    if not _CHECK_ID.match(check):
        msg = f"purple map {where}: {check!r} is not a check id"
        raise ConfigurationError(msg)
    level = str(raw.get("level") or "").strip().upper()
    if level not in {"L1", "L2", "L3", "L4"}:
        msg = f"purple map {where} ({check}): level {level!r} is not L1..L4"
        raise ConfigurationError(msg)
    tactic = str(raw.get("tactic") or "").strip().lower()
    if tactic not in TACTICS:
        msg = f"purple map {where} ({check}): tactic {tactic!r} is not an ATT&CK tactic"
        raise ConfigurationError(msg)
    raw_techniques = raw.get("techniques") or ()
    if not isinstance(raw_techniques, (list, tuple)) or not raw_techniques:
        msg = f"purple map {where} ({check}): techniques must be a non-empty list"
        raise ConfigurationError(msg)
    techniques: list[str] = []
    for item in raw_techniques:
        try:
            techniques.append(normalize_technique(str(item)))
        except ValueError as exc:
            msg = f"purple map {where} ({check}): {exc}"
            raise ConfigurationError(msg) from exc
    # REQ-VALID-007: an action's technique must exist in the pinned release, and the tactic it
    # files itself under must be one the release assigns that technique. Both are checked here
    # rather than in a test, so an operator's own map (ARACHNE_PURPLE_MAP) is held to the same
    # rule as the shipped one and the catalogue cannot mislabel where an action sits.
    assigned: set[str] = set()
    for technique in techniques:
        problem = item_error(f"ATT&CK-{technique}")
        if problem is not None:
            msg = f"purple map {where} ({check}): {problem}"
            raise ConfigurationError(msg)
        assigned.update(technique_tactics(technique))
    if tactic not in assigned:
        msg = (
            f"purple map {where} ({check}): tactic {tactic!r} is not one ATT&CK "
            f"{ATTACK_VERSION} assigns {', '.join(techniques)} (assigned: "
            f"{', '.join(sorted(assigned)) or 'none'})"
        )
        raise ConfigurationError(msg)
    severity = str(raw.get("severity") or "medium").strip().lower()
    if severity not in _SEVERITIES:
        msg = f"purple map {where} ({check}): severity {severity!r} is not on the ladder"
        raise ConfigurationError(msg)
    telemetry = raw.get("telemetry")
    if not isinstance(telemetry, Mapping):
        msg = f"purple map {where} ({check}): a telemetry block is required"
        raise ConfigurationError(msg)
    fields = telemetry.get("event") or {}
    if not isinstance(fields, Mapping) or not fields:
        msg = f"purple map {where} ({check}): telemetry.event must be a non-empty mapping"
        raise ConfigurationError(msg)
    logsource = telemetry.get("logsource") or {}
    if not isinstance(logsource, Mapping):
        msg = f"purple map {where} ({check}): telemetry.logsource must be a mapping"
        raise ConfigurationError(msg)
    return ReplayAction(
        check_id=check,
        title=str(raw.get("title") or check).strip(),
        level=level,
        tactic=tactic,
        techniques=tuple(dict.fromkeys(techniques)),
        severity=severity,
        event=EmittedEvent(
            summary=str(telemetry.get("summary") or "").strip() or "declared test telemetry",
            fields={str(key): value for key, value in fields.items()},
            logsource={str(key): str(value) for key, value in logsource.items()},
        ),
        notes=str(raw.get("notes") or "").strip(),
    )


@dataclass(frozen=True, slots=True)
class TechniqueMap:
    """The replayable action catalogue, keyed by check id."""

    version: str
    actions: Mapping[str, ReplayAction]

    def get(self, check_id: str) -> ReplayAction | None:
        return self.actions.get(check_id)

    def require(self, check_id: str) -> ReplayAction:
        """The action for ``check_id``, or a loud refusal naming what is replayable."""
        action = self.actions.get(check_id)
        if action is None:
            replayable = ", ".join(sorted(self.actions)) or "none"
            msg = (
                f"{check_id!r} is not a replayable purple-team action; the shipped map "
                f"replays: {replayable}"
            )
            raise ConfigurationError(msg)
        return action

    def action_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self.actions))

    def select(self, check_ids: Iterable[str]) -> tuple[ReplayAction, ...]:
        """The actions for ``check_ids``, in the order given; every id must exist."""
        return tuple(self.require(check_id) for check_id in check_ids)

    def techniques(self, check_ids: Iterable[str]) -> tuple[str, ...]:
        seen: list[str] = []
        for action in self.select(check_ids):
            for technique in action.techniques:
                if technique not in seen:
                    seen.append(technique)
        return tuple(seen)

    def tactics(self, check_ids: Iterable[str]) -> tuple[str, ...]:
        seen: list[str] = []
        for action in self.select(check_ids):
            if action.tactic not in seen:
                seen.append(action.tactic)
        return tuple(seen)

    def check_level(self, check_id: str) -> str:
        return self.require(check_id).level


def _bundled_map_path() -> Path:
    resource = resources.files("arachne.templates").joinpath("purple", "attck-map.yaml")
    return Path(str(resource))


def load_technique_map(path: str | Path | None = None) -> TechniqueMap:
    """Load the shipped technique map, or the operator's override.

    ``path`` unset reads the bundled ``templates/purple/attck-map.yaml``; a path pointing
    at a file (or a directory holding ``attck-map.yaml``) overrides it wholesale. A
    malformed map is a loud :class:`~arachne.core.errors.ConfigurationError`, never a
    silently empty catalogue — "no actions" would make every purple run a no-op that still
    reported a clean result.
    """
    target = Path(path).expanduser() if path else _bundled_map_path()
    if target.is_dir():
        target = target / "attck-map.yaml"
    try:
        raw = target.read_text(encoding="utf-8")
    except OSError as exc:
        msg = f"cannot read the purple technique map at {target}: {exc}"
        raise ConfigurationError(msg) from exc
    try:
        document = yaml.safe_load(raw)
    except yaml.YAMLError as exc:
        msg = f"the purple technique map at {target} is not valid YAML: {exc}"
        raise ConfigurationError(msg) from exc
    if not isinstance(document, Mapping):
        msg = f"the purple technique map at {target} must be a mapping"
        raise ConfigurationError(msg)
    entries = document.get("actions")
    if not isinstance(entries, list) or not entries:
        msg = f"the purple technique map at {target} declares no actions"
        raise ConfigurationError(msg)
    actions: dict[str, ReplayAction] = {}
    for index, entry in enumerate(entries):
        if not isinstance(entry, Mapping):
            msg = f"purple map actions[{index}] must be a mapping"
            raise ConfigurationError(msg)
        action = _parse_action(entry, index=index)
        if action.check_id in actions:
            msg = f"purple map declares {action.check_id!r} twice"
            raise ConfigurationError(msg)
        actions[action.check_id] = action
    return TechniqueMap(version=str(document.get("version") or ATTACK_MAP_VERSION), actions=actions)
