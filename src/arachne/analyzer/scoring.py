"""The scoring and confidence model (docs/spec/04- §2.4/§2.6, F-05-04/F-05-06).

Three scores, one severity:

``cvss_base``
    A CVSS v3.1 base score, computed from a vector the engine *derives* rather than asks
    for. The derivation is managed data (``templates/scoring/cvss-vectors.yaml``): defaults,
    then a per-module layer, then a per-CWE layer, then a per-check layer, each overriding
    the last. It is the mapping from "what a check found" to "what an attacker gets", and it
    belongs to whoever runs the scanner — not to a constant in this file (F-09-04).
``owasp``
    OWASP-style risk: likelihood (evidence quality, exposure) x impact (asset criticality),
    each on the 0-9 scale the methodology uses, normalized back to 0-10 so it is comparable
    with the CVSS score.
``epss``
    Optional exploit-likelihood context for CVE-correlated findings (F-09-03). It never
    invents a finding's severity; it moves a borderline score that is *already* high or low.

The final ``severity`` is the rule author's verdict when a rule fired (F-05-01 — the rule
*is* the decision), and the banded score otherwise. Either way the score is reported, so a
report can print both and a reader can see a disagreement.

Confidence (0-100, docs/spec/06- §2) is additive and auditable: a base term plus the
evidence-quality and FP-heuristic terms of docs/spec/04- §2.4/§2.6, each named in
:class:`~arachne.analyzer.model.ConfidenceBreakdown` so a report can explain the number.
"""

from __future__ import annotations

import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from importlib.resources import files
from typing import Any, Final

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from arachne.analyzer.model import (
    Candidate,
    ConfidenceBreakdown,
    ScoreBreakdown,
    clamp_confidence,
    severity_from_rank,
    severity_rank,
)
from arachne.core.errors import ConfigurationError

__all__ = [
    "CVSS_METRICS",
    "DEFAULT_VECTOR_RESOURCE",
    "EPSS_HIGH",
    "EPSS_LOW",
    "CvssVector",
    "ScoringModel",
    "VectorTable",
    "confidence_breakdown",
    "cvss_v31_base",
    "load_vector_table",
    "owasp_risk_band",
    "severity_for_score",
]

#: Where the derived-vector table ships inside the package.
DEFAULT_VECTOR_RESOURCE: Final = ("scoring", "cvss-vectors.yaml")

#: Score → severity boundaries (docs/spec/04- §2.4, docs/spec/06- §2).
_SCORE_BANDS: Final[tuple[tuple[float, str], ...]] = (
    (9.0, "critical"),
    (7.0, "high"),
    (4.0, "medium"),
    (2.0, "low"),
)

#: EPSS thresholds at which the exploit-likelihood signal is allowed to move a score.
EPSS_HIGH: Final = 0.5
EPSS_LOW: Final = 0.01

_MODEL_CONFIG = ConfigDict(frozen=True, extra="forbid")

#: Every CVSS metric and the values this project understands (v3.1 vocabulary).
CVSS_METRICS: Final[dict[str, tuple[str, ...]]] = {
    "AV": ("N", "A", "L", "P"),
    "AC": ("L", "H"),
    "PR": ("N", "L", "H"),
    "UI": ("N", "R"),
    "S": ("U", "C"),
    "C": ("H", "L", "N"),
    "I": ("H", "L", "N"),
    "A": ("H", "L", "N"),
}

_AV: Final[dict[str, float]] = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC: Final[dict[str, float]] = {"L": 0.77, "H": 0.44}
_PR_UNCHANGED: Final[dict[str, float]] = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_CHANGED: Final[dict[str, float]] = {"N": 0.85, "L": 0.68, "H": 0.50}
_UI: Final[dict[str, float]] = {"N": 0.85, "R": 0.62}
_CIA: Final[dict[str, float]] = {"H": 0.56, "L": 0.22, "N": 0.0}

_CWE = re.compile(r"^CWE-\d{1,5}$")


def severity_for_score(score: float) -> str:
    """Band a 0-10 score into the severity vocabulary (``info`` below ``low``)."""
    for threshold, severity in _SCORE_BANDS:
        if score >= threshold:
            return severity
    return "info"


def cvss_v31_base(vector: CvssVector) -> float:
    """The CVSS v3.1 base score for ``vector`` (spec §7.1 of the CVSS v3.1 standard).

    Implemented exactly, including the "round up to one decimal" step, because a report
    that prints "CVSS 7.5" has to mean what CVSS 7.5 means.
    """
    scope_changed = vector.S == "C"
    iss = 1 - ((1 - _CIA[vector.C]) * (1 - _CIA[vector.I]) * (1 - _CIA[vector.A]))
    impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if scope_changed else 6.42 * iss
    if impact <= 0:
        return 0.0
    pr = (_PR_CHANGED if scope_changed else _PR_UNCHANGED)[vector.PR]
    exploitability = 8.22 * _AV[vector.AV] * _AC[vector.AC] * pr * _UI[vector.UI]
    raw = min((impact + exploitability) * (1.08 if scope_changed else 1.0), 10.0)
    return math.ceil(raw * 10) / 10


@dataclass(frozen=True, slots=True)
class CvssVector:
    """One CVSS v3.1 base vector."""

    AV: str = "N"
    AC: str = "L"
    PR: str = "N"
    UI: str = "N"
    S: str = "U"
    C: str = "L"
    I: str = "L"  # noqa: E741 - the CVSS integrity metric
    A: str = "N"

    def __post_init__(self) -> None:
        for metric, value in self.as_dict().items():
            if value not in CVSS_METRICS[metric]:
                msg = (
                    f"invalid CVSS {metric} value {value!r}; expected one of {CVSS_METRICS[metric]}"
                )
                raise ConfigurationError(msg)

    def as_dict(self) -> dict[str, str]:
        # The single-letter attribute names are CVSS's own vocabulary (AV/AC/PR/UI/S/C/I/A);
        # renaming them here would make the vector string harder to check against the standard.
        return {
            "AV": self.AV,
            "AC": self.AC,
            "PR": self.PR,
            "UI": self.UI,
            "S": self.S,
            "C": self.C,
            "I": self.I,
            "A": self.A,
        }

    @property
    def text(self) -> str:
        """The canonical vector string (``CVSS:3.1/AV:N/...``)."""
        body = "/".join(f"{key}:{value}" for key, value in self.as_dict().items())
        return f"CVSS:3.1/{body}"

    @property
    def base_score(self) -> float:
        return cvss_v31_base(self)

    def merged(self, overrides: Mapping[str, str] | None) -> CvssVector:
        """A copy with ``overrides`` applied (unknown metrics are a configuration error)."""
        if not overrides:
            return self
        unknown = sorted(set(overrides) - set(CVSS_METRICS))
        if unknown:
            msg = f"unknown CVSS metric(s) {unknown}; known metrics are {sorted(CVSS_METRICS)}"
            raise ConfigurationError(msg)
        return CvssVector(**{**self.as_dict(), **dict(overrides)})


class VectorTable(BaseModel):
    """The whole derived-vector table (``templates/scoring/cvss-vectors.yaml``)."""

    model_config = _MODEL_CONFIG

    version: str = Field(min_length=1, max_length=32)
    defaults: dict[str, str] = Field(default_factory=dict)
    by_module: dict[str, dict[str, str]] = Field(default_factory=dict)
    by_cwe: dict[str, dict[str, str]] = Field(default_factory=dict)
    by_check: dict[str, dict[str, str]] = Field(default_factory=dict)

    def vector_for(
        self,
        *,
        module: str | None,
        cwe: str | None,
        check_id: str | None,
        evidence_overrides: Mapping[str, str] | None = None,
    ) -> CvssVector:
        """Derive a vector: defaults → module → CWE → check → evidence."""
        vector = CvssVector(**dict(self.defaults))
        for layer in (
            self.by_module.get((module or "").upper()),
            self.by_cwe.get(cwe or ""),
            self.by_check.get(check_id or ""),
            dict(evidence_overrides or {}),
        ):
            vector = vector.merged(layer)
        return vector


def _check_overrides(source: str, table_name: str, key: str, overrides: Mapping[str, str]) -> None:
    try:
        CvssVector().merged(overrides)
    except ConfigurationError as exc:
        raise ConfigurationError(f"{source}: {table_name}[{key}]: {exc}") from exc


def parse_vector_table(data: Any, *, source: str = "<memory>") -> VectorTable:
    if not isinstance(data, dict):
        msg = f"{source}: expected a mapping, got {type(data).__name__}"
        raise ConfigurationError(msg)
    try:
        table = VectorTable.model_validate(data)
    except ValidationError as exc:
        raise ConfigurationError(f"{source}: invalid vector table: {exc}") from exc
    CvssVector(**dict(table.defaults))  # the default vector must itself be valid
    for module, overrides in table.by_module.items():
        if module.upper() not in {"M1", "M2", "M3", "M4", "M5", "M6"}:
            raise ConfigurationError(f"{source}: by_module key {module!r} is not a module id")
        _check_overrides(source, "by_module", module, overrides)
    for cwe, overrides in table.by_cwe.items():
        if not _CWE.match(cwe):
            raise ConfigurationError(f"{source}: by_cwe key {cwe!r} is not CWE-NNN")
        _check_overrides(source, "by_cwe", cwe, overrides)
    for check_id, overrides in table.by_check.items():
        _check_overrides(source, "by_check", check_id, overrides)
    return table


def load_vector_table(path: str | None = None) -> VectorTable:
    """Load the vector table from ``path``, or the shipped default."""
    if path is not None:
        from pathlib import Path

        resolved = Path(path).expanduser()
        if not resolved.is_file():
            msg = f"scoring vector table {resolved} does not exist"
            raise ConfigurationError(msg)
        try:
            data = yaml.safe_load(resolved.read_text(encoding="utf-8"))  # F-08-06: safe_load
        except (OSError, yaml.YAMLError) as exc:
            raise ConfigurationError(f"cannot read {resolved}: {exc}") from exc
        return parse_vector_table(data, source=str(resolved))
    resource = files("arachne.templates")
    for part in DEFAULT_VECTOR_RESOURCE:
        resource = resource.joinpath(part)
    try:
        text = resource.read_text(encoding="utf-8")
    except (FileNotFoundError, OSError) as exc:  # pragma: no cover - packaging failure
        msg = f"bundled scoring table is missing: {exc}"
        raise ConfigurationError(msg) from exc
    return parse_vector_table(yaml.safe_load(text), source="/".join(DEFAULT_VECTOR_RESOURCE))


def owasp_risk_band(likelihood: float, impact: float) -> str:
    """OWASP risk band from a likelihood x impact product on the 0-9 scales."""
    product = max(0.0, min(9.0, likelihood)) * max(0.0, min(9.0, impact)) / 9.0
    if product >= 7.0:
        return "critical"
    if product >= 4.5:
        return "high"
    if product >= 2.0:
        return "medium"
    if product >= 0.5:
        return "low"
    return "note"


#: Asset criticality → the OWASP impact term (0-9).
_CRITICALITY_IMPACT: Final[dict[str, float]] = {
    "critical": 9.0,
    "high": 7.0,
    "normal": 5.0,
    "medium": 5.0,
    "low": 3.0,
    "internal": 2.0,
}


class ScoringModel:
    """Computes the F-05-04 score and the F-05-06 confidence for one candidate."""

    def __init__(self, table: VectorTable | None = None) -> None:
        self.table = table or load_vector_table()

    # ------------------------------------------------------------------ derivation
    def vector_for(
        self,
        candidate: Candidate,
        *,
        cwe: str | None = None,
        verification_reproducible: bool = False,
    ) -> CvssVector:
        """Derive the CVSS vector for a candidate from metadata plus what evidence showed.

        Two evidence-driven overrides are applied on top of the table, because they are
        properties of *this* observation rather than of the check:
        * a network-reachable asset is ``AV:N`` (that is what made it reachable);
        * a finding confirmed by a second, independent request has ``AC:L``; one that could
          only be inferred keeps the table's value (fail towards the higher complexity).
        """
        overrides: dict[str, str] = {}
        if candidate.asset_kind in {"url", "host", "domain", "network"} or candidate.asset_kind in {
            "git",
            "cloud",
            "bucket",
        }:
            overrides["AV"] = "N"
        if verification_reproducible:
            overrides["AC"] = "L"
        return self.table.vector_for(
            module=candidate.check_module,
            cwe=cwe if cwe is not None else candidate.cwe,
            check_id=candidate.check_id,
            evidence_overrides=overrides,
        )

    @staticmethod
    def owasp_likelihood(
        candidate: Candidate,
        *,
        reproducible: bool = False,
        contradicted: bool = False,
        fp_penalty: bool = False,
    ) -> float:
        """Evidence-quality likelihood on the OWASP 0-9 scale (docs/spec/04- §2.4).

        Read as "how likely is this finding to be exploitable as described": a captured
        request *and* response, a second confirming observation, and a definite (rather than
        inferred) probe all raise it; a verification contradiction or an FP heuristic drops
        it hard.
        """
        kinds = {item.kind for item in candidate.evidence}
        likelihood = 3.0
        if {"http_request", "http_response"} <= kinds or candidate.evidence:
            likelihood += 1.0
        if {"http_request", "http_response"} <= kinds:
            likelihood += 1.0
        if len(candidate.evidence) >= 2:
            likelihood += 1.0
        if reproducible:
            likelihood += 1.5
        if candidate.check_confidence is not None:
            likelihood += max(0.0, min(1.0, candidate.check_confidence / 100.0))
        if contradicted:
            likelihood -= 3.0
        if fp_penalty:
            likelihood -= 2.0
        return max(0.0, min(9.0, likelihood))

    @staticmethod
    def owasp_impact(candidate: Candidate, criticality: str, *, confidentiality: bool) -> float:
        """Impact on the OWASP 0-9 scale: asset criticality, lifted by data exposure."""
        impact = _CRITICALITY_IMPACT.get(criticality, 5.0)
        if confidentiality:
            impact = min(9.0, impact + 2.0)
        if candidate.asset_kind in {"network", "cloud"}:
            impact = min(9.0, impact + 1.0)
        return impact

    # ------------------------------------------------------------------ scoring
    def score(
        self,
        candidate: Candidate,
        *,
        criticality: str = "normal",
        cwe: str | None = None,
        verification_reproducible: bool = False,
        contradicted: bool = False,
        fp_penalty: bool = False,
        epss: float | None = None,
        base_confidence: int = 50,
        confidence_adjustments: tuple[tuple[str, int], ...] = (),
    ) -> ScoreBreakdown:
        """The full scoring result for one candidate."""
        effective_cwe = cwe if cwe is not None else candidate.cwe
        vector = self.vector_for(
            candidate, cwe=effective_cwe, verification_reproducible=verification_reproducible
        )
        cvss_base = vector.base_score
        likelihood = self.owasp_likelihood(
            candidate,
            reproducible=verification_reproducible,
            contradicted=contradicted,
            fp_penalty=fp_penalty,
        )
        impact = self.owasp_impact(
            candidate,
            criticality,
            confidentiality=vector.C == "H" or _confidentiality_cwe(effective_cwe),
        )
        owasp_band = owasp_risk_band(likelihood, impact)
        owasp_score = max(0.0, min(9.0, likelihood * impact / 9.0)) * 10.0 / 9.0
        effective = max(cvss_base, owasp_score)
        if epss is not None:
            if epss >= EPSS_HIGH:
                effective = min(10.0, effective + 0.5)
            elif epss < EPSS_LOW and effective >= 7.0:
                effective = max(0.0, effective - 0.5)
        confidence = ConfidenceBreakdown(base=base_confidence, adjustments=confidence_adjustments)
        return ScoreBreakdown(
            cvss_vector=vector.text,
            cvss_base=cvss_base,
            owasp_likelihood=round(likelihood, 2),
            owasp_impact=round(impact, 2),
            owasp_risk=owasp_band,
            epss=epss,
            derived_severity=severity_for_score(effective),
            confidence=confidence.value,
            confidence_reasons=confidence.reasons(),
        )


#: CWEs whose whole point is reading data an attacker should not read.
_CONFIDENTIALITY_CWES: Final[frozenset[str]] = frozenset(
    {
        "CWE-200",
        "CWE-312",
        "CWE-319",
        "CWE-522",
        "CWE-532",
        "CWE-538",
        "CWE-548",
        "CWE-1035",
        "CWE-287",
        "CWE-306",
        "CWE-284",
        "CWE-863",
    }
)


def _confidentiality_cwe(cwe: str | None) -> bool:
    return bool(cwe) and cwe in _CONFIDENTIALITY_CWES


def confidence_breakdown(
    *,
    base: int,
    pair_captured: bool = False,
    reproducible: bool = False,
    multiple_confirmations: bool = False,
    contradicted: bool = False,
    placeholder: bool = False,
    waf: bool = False,
    login_wall: bool = False,
    fp_rate: float = 0.0,
    extra: tuple[tuple[str, int], ...] = (),
) -> tuple[int, tuple[tuple[str, int], ...]]:
    """The F-05-06 confidence terms, as ``(base, adjustments)``.

    Kept separate from :meth:`ScoringModel.score` so the narrative can explain the number
    with the same terms the report prints.
    """
    adjustments: list[tuple[str, int]] = []
    if pair_captured:
        adjustments.append(("request+response captured", 5))
    if reproducible:
        adjustments.append(("reproduced by a second request", 10))
    if multiple_confirmations:
        adjustments.append(("multiple independent evidence items", 5))
    if contradicted:
        adjustments.append(("verification contradicted the finding", -25))
    if placeholder:
        adjustments.append(("placeholder/default page detected", -25))
    if waf:
        adjustments.append(("WAF challenge page detected", -15))
    if login_wall:
        adjustments.append(("login wall detected", -10))
    if fp_rate > 0:
        adjustments.append((f"operator FP rate {fp_rate:.0%}", -round(fp_rate * 20)))
    adjustments.extend(extra)
    return clamp_confidence(base), tuple(adjustments)


def severity_from_hint(hint: str | None, fallback: str = "info") -> str:
    """Read a ``severity_hint`` as a severity, falling back when it is absent or unknown."""
    if not hint:
        return fallback
    lowered = hint.strip().lower()
    return lowered if lowered in {"critical", "high", "medium", "low", "info"} else fallback


def describe_severity_gap(rule_severity: str, derived_severity: str) -> str | None:
    """A note when the rule verdict and the derived score disagree by two bands or more.

    One band of disagreement is normal — a rule author is allowed to rate a class of finding
    higher than the generic CVSS vector for its CWE, and the report prints both numbers. Two
    bands means one of the two is probably wrong, so the analysis says so in ``risk_notes``.
    """
    difference = severity_rank(rule_severity) - severity_rank(derived_severity)
    if abs(difference) < 2:
        return None
    direction = "below" if difference < 0 else "above"
    return (
        f"rule verdict {rule_severity!r} is {direction} the score-derived "
        f"{derived_severity!r} ({severity_from_rank(severity_rank(derived_severity))} band)"
    )
