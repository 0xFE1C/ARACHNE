"""Hypothetical states a what-if run injects into the estate model (REQ-SIM-002).

A hypothesis is a *stated* change to the estate, not an observation. Four kinds, which is the
vocabulary the requirement names plus the one change simulation needs to be useful:

``new-exposure``
    a service or application that becomes reachable — a new port opened, a host published, a
    web application put on the internet. It carries the stage ``exposure`` and, when it names
    a port and service, creates the ``SERVICE`` node and ``EXPOSES`` edge the model would
    have recorded had a scan seen it.
``compromised-credential``
    a credential an attacker now holds. It carries the stage ``credentials``, and it is the
    hypothesis an operator reaches for when asking "what does one phished password buy?".
``new-vulnerability``
    a weakness discovered in the estate (an advisory, a newly-published CVE, a finding from
    another tool). Its stage is derived from its CWE exactly as an observed finding's is —
    the model does not get a second staging rule for hypotheticals.
``applied-fix``
    the one *subtractive* hypothesis: a named weakness that a proposed change removes. It is
    what makes REQ-SIM-005's before/after delta answer "is this design change worth it?".

Every hypothesis carries an operator-supplied ``id``. It is what the rendered result cites —
"this hop exists because of ``hyp-2``" — and what an injected weakness's check id is built
from (``sim.new-exposure.hyp-2``), so a composed path can name its own origin without a
side-channel. Ids are therefore required and unique within a run.

A hypothesis is data. It is parsed from an operator's YAML/JSON document, validated here, and
never executed: the only thing that happens to it is that the model grows (or loses) a
weakness and the composer re-runs. That is why this module can be — and is — silent about
networks: there is nothing in a hypothesis that could name a request.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Any, Final

import yaml

from arachne.analyzer.model import SEVERITIES, Analysis, Remediation
from arachne.core.errors import SimulationError

__all__ = [
    "SIM_CHECK_PREFIX",
    "ChangeSet",
    "Hypothesis",
    "HypothesisKind",
    "load_hypotheses",
    "parse_hypotheses",
]

#: Every injected weakness's check id starts with this, so a composed hop's origin is
#: readable without consulting a side table (``sim.new-exposure.hyp-1``).
SIM_CHECK_PREFIX: Final = "sim."

#: The severities a hypothesis may declare (the report's own vocabulary).
_HYPOTHESIS_SEVERITIES: Final[frozenset[str]] = SEVERITIES


class HypothesisKind(StrEnum):
    NEW_EXPOSURE = "new-exposure"
    COMPROMISED_CREDENTIAL = "compromised-credential"
    NEW_VULNERABILITY = "new-vulnerability"
    APPLIED_FIX = "applied-fix"


#: Default CWE per kind: the class that makes the stage deterministic instead of severity
#: driven. A new exposure is missing authorization (CWE-284) → ``impact``? No: the stage
#: table maps CWE-284 to ``impact``, which would overstate an exposure. So an exposure
#: declares CWE-200 (information readable through the new surface) unless the operator says
#: otherwise — the conservative choice, and the operator's ``cwe`` always wins.
_DEFAULT_CWE: Final[dict[HypothesisKind, str]] = {
    HypothesisKind.NEW_EXPOSURE: "CWE-200",
    HypothesisKind.COMPROMISED_CREDENTIAL: "CWE-522",
    HypothesisKind.NEW_VULNERABILITY: "CWE-1035",
}

#: Default severity per kind when the document does not state one.
_DEFAULT_SEVERITY: Final[dict[HypothesisKind, str]] = {
    HypothesisKind.NEW_EXPOSURE: "high",
    HypothesisKind.COMPROMISED_CREDENTIAL: "high",
    HypothesisKind.NEW_VULNERABILITY: "high",
    HypothesisKind.APPLIED_FIX: "info",
}


@dataclass(frozen=True, slots=True)
class Hypothesis:
    """One hypothetical state, fully validated and ready to inject."""

    id: str
    kind: HypothesisKind
    asset: str
    title: str
    severity: str
    cwe: str | None = None
    note: str = ""
    #: ``new-exposure`` only: the port and service name the change publishes.
    port: int | None = None
    service: str | None = None
    #: ``compromised-credential`` only: the identity (vault label) the attacker holds.
    identity: str | None = None
    #: ``applied-fix`` only: the observed weakness's check id the fix removes.
    target_check_id: str | None = None

    @property
    def check_id(self) -> str:
        """The synthetic check id this hypothesis's weakness carries in a composed path."""
        return f"{SIM_CHECK_PREFIX}{self.kind.value}.{self.id}"

    @property
    def simulated(self) -> bool:
        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind.value,
            "asset": self.asset,
            "title": self.title,
            "severity": self.severity,
            "cwe": self.cwe,
            "note": self.note,
            "port": self.port,
            "service": self.service,
            "identity": self.identity,
            "target_check_id": self.target_check_id,
            "check_id": self.check_id,
        }

    # ------------------------------------------------------------------ constructors
    @classmethod
    def new_exposure(
        cls,
        hypothesis_id: str,
        asset: str,
        *,
        title: str = "",
        severity: str | None = None,
        cwe: str | None = None,
        note: str = "",
        port: int | None = None,
        service: str | None = None,
    ) -> Hypothesis:
        return cls(
            id=hypothesis_id,
            kind=HypothesisKind.NEW_EXPOSURE,
            asset=asset,
            title=title or f"Newly exposed surface on {asset}",
            severity=severity or _DEFAULT_SEVERITY[HypothesisKind.NEW_EXPOSURE],
            cwe=cwe or _DEFAULT_CWE[HypothesisKind.NEW_EXPOSURE],
            note=note,
            port=port,
            service=service,
        )

    @classmethod
    def compromised_credential(
        cls,
        hypothesis_id: str,
        asset: str,
        *,
        identity: str | None = None,
        title: str = "",
        severity: str | None = None,
        cwe: str | None = None,
        note: str = "",
    ) -> Hypothesis:
        return cls(
            id=hypothesis_id,
            kind=HypothesisKind.COMPROMISED_CREDENTIAL,
            asset=asset,
            title=title or f"Attacker holds a credential for {asset}",
            severity=severity or _DEFAULT_SEVERITY[HypothesisKind.COMPROMISED_CREDENTIAL],
            cwe=cwe or _DEFAULT_CWE[HypothesisKind.COMPROMISED_CREDENTIAL],
            note=note,
            identity=identity,
        )

    @classmethod
    def new_vulnerability(
        cls,
        hypothesis_id: str,
        asset: str,
        *,
        title: str,
        severity: str,
        cwe: str | None = None,
        note: str = "",
    ) -> Hypothesis:
        return cls(
            id=hypothesis_id,
            kind=HypothesisKind.NEW_VULNERABILITY,
            asset=asset,
            title=title or f"Newly discovered weakness on {asset}",
            severity=severity,
            cwe=cwe or _DEFAULT_CWE[HypothesisKind.NEW_VULNERABILITY],
            note=note,
        )

    @classmethod
    def applied_fix(
        cls,
        hypothesis_id: str,
        asset: str,
        target_check_id: str,
        *,
        note: str = "",
    ) -> Hypothesis:
        return cls(
            id=hypothesis_id,
            kind=HypothesisKind.APPLIED_FIX,
            asset=asset,
            title=f"Fix applied: {target_check_id} on {asset}",
            severity=_DEFAULT_SEVERITY[HypothesisKind.APPLIED_FIX],
            note=note,
            target_check_id=target_check_id,
        )

    def as_analysis(self) -> Analysis:
        """The synthetic analysis this hypothesis injects into the model and the composer.

        ``verified=True`` and a top confidence, deliberately: within the simulated world the
        stipulated state *holds* — the honesty of the run is carried by its ``simulated``
        provenance and by the hop's ``introduced_by`` citation, not by pretending the
        hypothetical is unsupported. The report renders such a hop as ``hypothetical``.

        The remediation is a synthetic entry whose id names the hypothesis, so a simulated
        path can name the cheapest break in its own world without borrowing a real
        catalogued fix for a weakness nobody observed.
        """
        return Analysis(
            title=self.title,
            severity=self.severity,
            confidence=100,
            narrative=(
                self.note
                or f"Hypothetical state ({self.kind.value}) injected by hypothesis {self.id}."
            ),
            remediation=Remediation(
                id=f"{SIM_CHECK_PREFIX}fix.{self.id}",
                summary=f"undo the hypothetical change: {self.title}",
                steps=(),
                source="simulated",
            ),
            check_id=self.check_id,
            asset=self.asset,
            cwe=self.cwe,
            verdict="analyzed",
            verified=True,
        )


@dataclass(frozen=True, slots=True)
class ChangeSet:
    """A named set of hypotheses a design decision is measured against (REQ-SIM-005).

    A change set is what an operator compares: "if we publish this service *and* retire that
    legacy app, how does exposure move?" The name is what the delta is reported under.
    """

    name: str
    hypotheses: tuple[Hypothesis, ...] = ()
    description: str = ""

    def __post_init__(self) -> None:
        if not self.name.strip():
            msg = "a change set needs a name — it is what the delta is reported under"
            raise SimulationError(msg)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "hypotheses": [item.to_dict() for item in self.hypotheses],
        }


def parse_hypotheses(document: Mapping[str, Any] | Sequence[Any]) -> tuple[Hypothesis, ...]:
    """Parse a hypothesis document — a list of mappings, or ``{"hypotheses": [...]}``.

    Fails closed: an unknown kind, a missing id, a duplicate id, an unknown severity or a
    malformed binding raises :class:`~arachne.core.errors.SimulationError` with the entry's
    index, so an operator sees which line of their document was wrong rather than an empty
    result that looks like "no paths".
    """
    entries: Sequence[Any]
    if isinstance(document, Mapping):
        raw = document.get("hypotheses")
        if raw is None:
            msg = "the hypothesis document has no 'hypotheses' list"
            raise SimulationError(msg)
        entries = list(raw) if isinstance(raw, Sequence) and not isinstance(raw, str) else []
    else:
        entries = list(document)

    out: list[Hypothesis] = []
    seen: set[str] = set()
    for index, entry in enumerate(entries):
        hypothesis = _parse_one(entry, index)
        if hypothesis.id in seen:
            msg = f"hypotheses[{index}]: duplicate hypothesis id {hypothesis.id!r}"
            raise SimulationError(msg)
        seen.add(hypothesis.id)
        out.append(hypothesis)
    if not out:
        msg = "the hypothesis document names no hypothesis"
        raise SimulationError(msg)
    return tuple(out)


def parse_change_set(document: Mapping[str, Any] | Sequence[Any], *, name: str = "") -> ChangeSet:
    """Parse a change set: ``{"name": …, "description": …, "hypotheses": [...]}``."""
    if isinstance(document, Mapping):
        resolved = str(document.get("name") or name).strip()
        description = str(document.get("description") or "")
    else:
        resolved = name
        description = ""
    return ChangeSet(
        name=resolved or "change",
        hypotheses=parse_hypotheses(document),
        description=description,
    )


def load_hypotheses(path: Path | str) -> tuple[Hypothesis, ...]:
    """Load a hypothesis document from YAML or JSON (YAML parses JSON too)."""
    target = Path(path)
    if not target.is_file():
        msg = f"hypothesis document not found: {target}"
        raise SimulationError(msg)
    try:
        document = yaml.safe_load(target.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:  # pragma: no cover - malformed operator input
        msg = f"{target}: not valid YAML or JSON ({exc.__class__.__name__})"
        raise SimulationError(msg) from exc
    if not isinstance(document, (Mapping, list)):
        msg = f"{target}: the document must be a mapping or a list"
        raise SimulationError(msg)
    return parse_hypotheses(document)


def load_change_set(path: Path | str, *, name: str = "") -> ChangeSet:
    """Load a named change set from YAML or JSON."""
    target = Path(path)
    if not target.is_file():
        msg = f"change document not found: {target}"
        raise SimulationError(msg)
    try:
        document = yaml.safe_load(target.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:  # pragma: no cover - malformed operator input
        msg = f"{target}: not valid YAML or JSON ({exc.__class__.__name__})"
        raise SimulationError(msg) from exc
    if not isinstance(document, (Mapping, list)):
        msg = f"{target}: the document must be a mapping or a list"
        raise SimulationError(msg)
    return parse_change_set(document, name=name)


def _parse_one(entry: Any, index: int) -> Hypothesis:
    where = f"hypotheses[{index}]"
    if not isinstance(entry, Mapping):
        msg = f"{where}: each hypothesis must be a mapping"
        raise SimulationError(msg)
    raw_kind = str(entry.get("kind") or "").strip()
    try:
        kind = HypothesisKind(raw_kind)
    except ValueError as exc:
        known = ", ".join(item.value for item in HypothesisKind)
        msg = f"{where}: unknown hypothesis kind {raw_kind!r} (known: {known})"
        raise SimulationError(msg) from exc

    identifier = str(entry.get("id") or "").strip()
    if not identifier:
        msg = f"{where}: a hypothesis needs an id (the result cites it)"
        raise SimulationError(msg)
    asset = str(entry.get("asset") or "").strip()
    if not asset:
        msg = f"{where}: a hypothesis needs an 'asset' to apply to"
        raise SimulationError(msg)

    severity = str(entry.get("severity") or _DEFAULT_SEVERITY[kind]).strip().lower()
    if severity not in _HYPOTHESIS_SEVERITIES:
        msg = f"{where}: unknown severity {severity!r}"
        raise SimulationError(msg)
    cwe = _optional_str(entry.get("cwe"))
    if cwe and not cwe.upper().startswith("CWE-"):
        cwe = f"CWE-{cwe}"
    title = str(entry.get("title") or "").strip()
    note = str(entry.get("note") or entry.get("description") or "")

    if kind is HypothesisKind.NEW_EXPOSURE:
        port = entry.get("port")
        if port is not None and not _valid_port(port):
            msg = f"{where}: 'port' must be an integer between 1 and 65535"
            raise SimulationError(msg)
        return Hypothesis(
            id=identifier,
            kind=kind,
            asset=asset,
            title=title or f"Newly exposed surface on {asset}",
            severity=severity,
            cwe=cwe,
            note=note,
            port=int(port) if port is not None else None,
            service=_optional_str(entry.get("service")),
        )
    if kind is HypothesisKind.COMPROMISED_CREDENTIAL:
        return Hypothesis(
            id=identifier,
            kind=kind,
            asset=asset,
            title=title or f"Attacker holds a credential for {asset}",
            severity=severity,
            cwe=cwe,
            note=note,
            identity=_optional_str(entry.get("identity") or entry.get("credential")),
        )
    if kind is HypothesisKind.NEW_VULNERABILITY:
        return Hypothesis(
            id=identifier,
            kind=kind,
            asset=asset,
            title=title or f"Newly discovered weakness on {asset}",
            severity=severity,
            cwe=cwe,
            note=note,
        )
    target = _optional_str(entry.get("target_check_id") or entry.get("check_id"))
    if not target:
        msg = f"{where}: an applied-fix hypothesis needs 'target_check_id'"
        raise SimulationError(msg)
    return Hypothesis(
        id=identifier,
        kind=kind,
        asset=asset,
        title=title or f"Fix applied: {target} on {asset}",
        severity="info",
        cwe=None,
        note=note,
        target_check_id=target,
    )


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _valid_port(value: Any) -> bool:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return False
    return 0 < number < 65536
