"""Attack-path composition: from findings to the chain an attacker would take (REQ-AGENT-003).

A scanner reports findings; an attacker follows a *path*. Area AGENT's third requirement is that
ARACHNE says the second thing honestly, and the honesty lives in four rules this module
implements and nothing else:

**Only verified findings are hops.** A hop is verified when the analyzer accepted the finding —
verdict ``analyzed``, confidence at or above the threshold, and evidence attached. Everything
else (a raw candidate, a low-confidence analysis, a finding that could not be re-verified) is a
**candidate edge**, and a candidate edge *names the check that would verify it*. That is the
requirement's exact wording, and it is why the graph never claims a chain it cannot support.

**A hop has a stage, and a path is strictly increasing.** Each hop's weakness class (its CWE,
falling back to its severity) maps to one of five stages — exposure, credentials, access,
execution, impact. A path is a sequence **on one host** whose stages strictly increase: an
attacker who can read a configuration file *and* use what it contains, in that order, has a
path; two unrelated exposures on the same host do not make one. Grouping is by host (the
hostname of a URL asset, else the asset value) because that is the unit an attacker walks —
findings on different paths of the same application are steps of one chain, not separate ones.

**The path's severity is the terminal hop's.** Not the maximum, not a sum: what the chain
achieves is what its last step achieves, which is the difference between "information
disclosure plus a login panel" and "administrative access".

**The cheapest way to break it is named.** For each hop the engine already produced a
remediation; the path reports the cheapest one that breaks the chain, with the policy written
down (see :func:`cheapest_break`): a fix earlier in the chain is preferred when it costs the
same, because it removes every path through that hop rather than one.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Final
from urllib.parse import urlsplit

from arachne.analyzer.model import SEVERITY_ORDER, Analysis, severity_rank

# The CMDB criticality index (S23, REQ-POSTURE-006) is a leaf value object; importing it
# here does not close a cycle (posture.cmdb imports only core.errors).
from arachne.posture.cmdb import CriticalityIndex

__all__ = [
    "AttackHop",
    "AttackPath",
    "AttackStage",
    "build_attack_paths",
    "cheapest_break",
    "criticality_floor",
    "host_of",
    "normalise_check_id",
    "stage_for",
]

#: Confidence at or above which an analysed finding is a *verified* hop.
DEFAULT_MIN_CONFIDENCE: Final = 55

#: How many hops one path may have, and how many paths are reported. Both bounded so a hostile
#: or merely messy estate cannot turn a report section into a combinatorial explosion.
DEFAULT_MAX_DEPTH: Final = 5
DEFAULT_MAX_PATHS: Final = 25


class AttackStage(StrEnum):
    """What a hop gets an attacker. A path is a strictly increasing sequence of these."""

    EXPOSURE = "exposure"
    CREDENTIALS = "credentials"
    ACCESS = "access"
    EXECUTION = "execution"
    IMPACT = "impact"

    @property
    def rank(self) -> int:
        return _STAGE_ORDER.index(self)


_STAGE_ORDER: Final[tuple[AttackStage, ...]] = (
    AttackStage.EXPOSURE,
    AttackStage.CREDENTIALS,
    AttackStage.ACCESS,
    AttackStage.EXECUTION,
    AttackStage.IMPACT,
)

#: CWE → stage. Deliberately small and explicit rather than exhaustive: an unmapped CWE falls
#: back to the severity, and a wrong stage would be worse than a coarse one.
_STAGE_BY_CWE: Final[dict[str, AttackStage]] = {
    # Information an attacker can read (paths, secrets, metadata, source).
    "CWE-200": AttackStage.EXPOSURE,
    "CWE-538": AttackStage.EXPOSURE,
    "CWE-540": AttackStage.EXPOSURE,
    "CWE-548": AttackStage.EXPOSURE,
    "CWE-213": AttackStage.EXPOSURE,
    "CWE-215": AttackStage.EXPOSURE,
    "CWE-312": AttackStage.EXPOSURE,
    "CWE-359": AttackStage.EXPOSURE,
    # Credentials and secrets an attacker can use.
    "CWE-798": AttackStage.CREDENTIALS,
    "CWE-522": AttackStage.CREDENTIALS,
    "CWE-521": AttackStage.CREDENTIALS,
    "CWE-916": AttackStage.CREDENTIALS,
    "CWE-1392": AttackStage.CREDENTIALS,
    "CWE-257": AttackStage.CREDENTIALS,
    "CWE-640": AttackStage.CREDENTIALS,
    # Authentication/authorization weaknesses: the door itself.
    "CWE-287": AttackStage.ACCESS,
    "CWE-288": AttackStage.ACCESS,
    "CWE-290": AttackStage.ACCESS,
    "CWE-306": AttackStage.ACCESS,
    "CWE-352": AttackStage.ACCESS,
    "CWE-384": AttackStage.ACCESS,
    "CWE-613": AttackStage.ACCESS,
    "CWE-620": AttackStage.ACCESS,
    "CWE-639": AttackStage.ACCESS,
    "CWE-862": AttackStage.ACCESS,
    "CWE-863": AttackStage.ACCESS,
    "CWE-566": AttackStage.ACCESS,
    # Code/config execution and deep compromise.
    "CWE-22": AttackStage.EXECUTION,
    "CWE-78": AttackStage.EXECUTION,
    "CWE-89": AttackStage.EXECUTION,
    "CWE-94": AttackStage.EXECUTION,
    "CWE-95": AttackStage.EXECUTION,
    "CWE-98": AttackStage.EXECUTION,
    "CWE-434": AttackStage.EXECUTION,
    "CWE-502": AttackStage.EXECUTION,
    "CWE-611": AttackStage.EXECUTION,
    "CWE-917": AttackStage.EXECUTION,
    "CWE-1336": AttackStage.EXECUTION,
    "CWE-918": AttackStage.EXECUTION,
    # Control of the estate or of its identity.
    "CWE-250": AttackStage.IMPACT,
    "CWE-269": AttackStage.IMPACT,
    "CWE-284": AttackStage.IMPACT,
    "CWE-732": AttackStage.IMPACT,
    "CWE-1188": AttackStage.IMPACT,
}

#: Severity → stage, for a hop whose CWE is unknown or unmapped.
_STAGE_BY_SEVERITY: Final[dict[str, AttackStage]] = {
    "info": AttackStage.EXPOSURE,
    "low": AttackStage.EXPOSURE,
    "medium": AttackStage.ACCESS,
    "high": AttackStage.EXECUTION,
    "critical": AttackStage.IMPACT,
}


def stage_for(cwe: str | None, severity: str) -> AttackStage:
    """The stage a hop reaches: its weakness class if known, else its severity."""
    if cwe and cwe in _STAGE_BY_CWE:
        return _STAGE_BY_CWE[cwe]
    return _STAGE_BY_SEVERITY.get((severity or "").strip().lower(), AttackStage.EXPOSURE)


@dataclass(frozen=True, slots=True)
class AttackHop:
    """One step of a path: a finding, what it gets an attacker, and whether it is proven."""

    finding_id: int | None
    check_id: str
    title: str
    asset: str
    severity: str
    stage: AttackStage
    #: ``True`` when the analyzer accepted the finding (REQ-AGENT-003: verified hops only).
    verified: bool
    #: For an unverified hop: the check that would verify it. ``None`` when verified.
    verifying_check: str | None = None
    evidence_ids: tuple[int, ...] = ()
    remediation_id: str | None = None
    remediation_summary: str = ""
    remediation_steps: int = 0

    @property
    def key(self) -> str:
        return f"{self.check_id}|{self.asset}"


@dataclass(frozen=True, slots=True)
class AttackPath:
    """A chain of hops on one asset, with the cheapest way to break it."""

    id: str
    asset: str
    hops: tuple[AttackHop, ...]
    #: The terminal hop's severity — what the chain *achieves* (REQ-AGENT-003).
    severity: str
    cheapest: AttackHop | None = None
    cheapest_reason: str = ""
    #: The CMDB criticality tier of the asset (S23, REQ-POSTURE-006); ``None`` when the
    #: deployment imported none for it. Context, never a re-score.
    criticality: int | None = None
    #: The severity the path *ranks at* once criticality is factored in: the terminal
    #: impact, floored by the asset's business weight (tier 1 ⇒ at least high). Equal to
    #: :attr:`severity` when no tier applies — the JSON always carries both.
    business_severity: str = ""

    @property
    def verified_hops(self) -> tuple[AttackHop, ...]:
        return tuple(hop for hop in self.hops if hop.verified)

    @property
    def candidate_hops(self) -> tuple[AttackHop, ...]:
        return tuple(hop for hop in self.hops if not hop.verified)

    @property
    def fully_verified(self) -> bool:
        return not self.candidate_hops

    def narrative(self) -> str:
        """One sentence an operator can read: ``exposure → access → impact``."""
        stages = " → ".join(hop.stage.value for hop in self.hops)
        return f"{self.asset}: {stages} (terminal impact: {self.severity})"


#: The business-impact floor per criticality tier (REQ-POSTURE-006): the most critical
#: assets lift a path's *rank* to at least this severity. Tier 3 and below add no floor —
#: a low-value asset never inflates a path, it only ever labels it.
CRITICALITY_FLOORS: Final[dict[int, str]] = {1: "high", 2: "medium", 3: "low"}


def criticality_floor(tier: int | None) -> str | None:
    """The severity floor a criticality tier implies (``None`` when none applies)."""
    if tier is None:
        return None
    return CRITICALITY_FLOORS.get(int(tier))


def build_attack_paths(
    analyses: Sequence[Analysis],
    candidates: Sequence[Any] = (),
    *,
    min_confidence: int = DEFAULT_MIN_CONFIDENCE,
    max_depth: int = DEFAULT_MAX_DEPTH,
    max_paths: int = DEFAULT_MAX_PATHS,
    criticality: CriticalityIndex | Mapping[str, int] | None = None,
) -> tuple[AttackPath, ...]:
    """Compose the estate's paths from the analysed findings (and its unverified candidates).

    ``analyses`` are the analyzer's outputs for this scan; ``candidates`` are the stored rows
    (any object with ``id``, ``check_key``, ``title``, ``asset_value``, ``severity``,
    ``confidence`` and ``evidence``), used only to add candidate edges for findings the
    analyzer did not accept. Deterministic: same inputs, same paths, same order.

    ``criticality`` (S23, REQ-POSTURE-006) is the CMDB import: paths on a tier-1/tier-2
    asset rank (and are labelled) by their *business* severity — the terminal impact,
    floored by the tier — so "medium on the payment host" no longer sorts under "high on
    a build box". Terminal severities themselves are never changed.
    """
    hops = _hops_from_analyses(analyses, min_confidence=min_confidence)
    hops.extend(_candidate_hops(analyses, candidates))
    by_host: dict[str, list[AttackHop]] = {}
    for hop in hops:
        if hop.asset:
            by_host.setdefault(host_of(hop.asset), []).append(hop)

    index: CriticalityIndex | None
    if isinstance(criticality, CriticalityIndex):
        index = criticality
    elif isinstance(criticality, Mapping):
        index = CriticalityIndex(dict(criticality))
    else:
        index = None

    paths: list[AttackPath] = []
    for asset in sorted(by_host):
        chain = _chain(by_host[asset], max_depth=max_depth)
        if len(chain) < 2:
            continue
        terminal = chain[-1]
        cheapest, reason = cheapest_break(chain)
        tier = index.lookup(asset) if index is not None else None
        floor = criticality_floor(tier)
        business = terminal.severity
        if floor is not None and severity_rank(floor) > severity_rank(business):
            business = floor
        paths.append(
            AttackPath(
                id=f"ap-{_digest(asset, chain)}",
                asset=asset,
                hops=chain,
                severity=terminal.severity,
                cheapest=cheapest,
                cheapest_reason=reason,
                criticality=tier,
                business_severity=business,
            )
        )
    paths.sort(
        key=lambda item: (
            -severity_rank(item.business_severity or item.severity),
            -len(item.hops),
            item.asset,
        )
    )
    return tuple(paths[:max_paths])


def cheapest_break(chain: Sequence[AttackHop]) -> tuple[AttackHop | None, str]:
    """The cheapest hop whose remediation breaks the chain, and why it is the cheapest.

    The policy, written down because a report states a recommendation: a fix costs what its
    remediation costs to apply (fewer, documented steps are cheaper than many), and between two
    equally cheap hops the **earlier** one wins, because it removes every path through that
    point rather than only the ones that reached the later step. Verified hops are preferred
    over candidate ones: recommending a fix for a chain whose link is unproven would be advice
    about a maybe.
    """
    if not chain:
        return None, "no hops"
    priced: list[tuple[tuple[int, int, int], AttackHop]] = []
    for hop in chain:
        if not hop.remediation_id:
            continue
        cost = 1 if hop.remediation_steps <= 2 else 2 if hop.remediation_steps <= 4 else 3
        priced.append(((0 if hop.verified else 1, cost, hop.stage.rank), hop))
    if not priced:
        return None, "no hop in this path has a catalogued remediation"
    _, best = min(priced, key=lambda item: item[0])
    verified_note = (
        "verified hop" if best.verified else "unverified hop (fixing the weakness would close it)"
    )
    return best, (
        f"fix {best.check_id} on {best.asset} ({verified_note}): "
        f"{best.remediation_summary or 'see the finding'} — "
        f"{len([hop for hop in chain if hop.stage.rank >= best.stage.rank])} hop(s) depend on it"
    )


# --------------------------------------------------------------------------- derivation


def _hops_from_analyses(analyses: Iterable[Analysis], *, min_confidence: int) -> list[AttackHop]:
    out: list[AttackHop] = []
    for analysis in analyses:
        check_id = analysis.check_id
        if not check_id or not analysis.asset:
            continue
        if analysis.verdict in ("dropped", "merged"):
            # A dropped finding is not evidence of anything (it is the analyzer saying "no"),
            # and a merged one is represented by the finding that absorbed it.
            continue
        verified = bool(analysis.verified) or analysis.confidence >= min_confidence
        canonical = normalise_check_id(check_id)
        out.append(
            AttackHop(
                finding_id=analysis.finding_id,
                check_id=canonical,
                title=analysis.title,
                asset=analysis.asset,
                severity=analysis.severity,
                stage=stage_for(analysis.cwe, analysis.severity),
                verified=verified,
                verifying_check=None if verified else canonical,
                evidence_ids=tuple(
                    int(item) for item in (analysis.merged_evidence_refs or ()) if item is not None
                ),
                remediation_id=analysis.remediation.id,
                remediation_summary=analysis.remediation.summary,
                remediation_steps=len(analysis.remediation.steps),
            )
        )
    return out


def _candidate_hops(analyses: Sequence[Analysis], candidates: Sequence[Any]) -> list[AttackHop]:
    """Candidate edges for stored findings the analyzer never accepted (REQ-AGENT-003).

    Each names the check that would verify it — which for a raw finding is the check that
    raised it, and for a low-confidence analysis is that same check run again with better
    evidence. The report renders these as *candidate* hops and never as a proven chain.
    """
    analysed = {analysis.finding_id for analysis in analyses if analysis.finding_id is not None}
    by_finding = {analysis.finding_id: analysis for analysis in analyses}
    out: list[AttackHop] = []
    for record in candidates:
        finding_id = getattr(record, "id", None)
        if finding_id in analysed:
            continue
        check_id = _check_id_of(record)
        asset = str(getattr(record, "asset_value", "") or "")
        if not check_id or not asset:
            continue
        severity = str(getattr(record, "severity", "") or "info")
        low = by_finding.get(finding_id)
        if low is not None:
            severity = low.severity
        out.append(
            AttackHop(
                finding_id=finding_id,
                check_id=check_id,
                title=str(getattr(record, "title", "") or check_id),
                asset=asset,
                severity=severity,
                stage=stage_for(None, severity),
                verified=False,
                verifying_check=check_id,
                evidence_ids=tuple(
                    int(getattr(item, "id", 0) or 0)
                    for item in (getattr(record, "evidence", ()) or ())
                ),
            )
        )
    return out


def _check_id_of(record: Any) -> str:
    return normalise_check_id(str(getattr(record, "check_key", "") or ""))


def _chain(hops: Sequence[AttackHop], *, max_depth: int) -> tuple[AttackHop, ...]:
    """The longest strictly-increasing-stage subsequence, one hop per stage rise.

    Greedy and deterministic: hops are ordered by (stage, severity desc, check id), then walked
    keeping the first hop of each stage that is higher than the last kept one. A second hop at
    the same or a lower stage does not extend the chain — two things that get an attacker the
    same capability are alternatives, not steps.
    """
    ordered = sorted(
        hops, key=lambda hop: (hop.stage.rank, -severity_rank(hop.severity), hop.check_id)
    )
    chain: list[AttackHop] = []
    for hop in ordered:
        if chain and hop.stage.rank <= chain[-1].stage.rank:
            continue
        chain.append(hop)
        if len(chain) >= max_depth:
            break
    return tuple(chain)


def normalise_check_id(value: str) -> str:
    """``M4/env-file-probe@1.0`` or ``m4.env-file-probe`` → ``m4.env-file-probe``.

    The analyzer sets the canonical form and the report's ``split_check_key`` produces it too,
    but an analysis rebuilt from a stored payload (``analysis_from_log``) can carry either —
    and a path hop that named the same check two ways would be unreadable.
    """
    head, _, _version = value.partition("@")
    module, _, name = head.partition("/")
    if module and name:
        return f"{module.lower()}.{name}"
    return head.lower().strip()


def host_of(asset: str) -> str:
    """The grouping key of an asset: a URL's hostname, else the value itself."""
    split = urlsplit(asset)
    if split.scheme and split.hostname:
        return split.hostname
    return asset


def _digest(asset: str, chain: Sequence[AttackHop]) -> str:
    import hashlib

    payload = "\x1f".join([asset, *(f"{hop.check_id}|{hop.stage.value}" for hop in chain)])
    return hashlib.sha256(payload.encode()).hexdigest()[:12]


def severity_of_chain(chain: Sequence[AttackHop]) -> str:
    """The chain's severity: its terminal hop's (exported for the report builder's tests)."""
    if not chain:
        return "info"
    value = chain[-1].severity
    return value if value in SEVERITY_ORDER else "info"


#: A mapping view the report can print (``{stage: [finding ids]}``), for a compact table.
def stages_to_findings(chain: Sequence[AttackHop]) -> Mapping[str, tuple[int, ...]]:
    out: dict[str, list[int]] = {}
    for hop in chain:
        if hop.finding_id is not None:
            out.setdefault(hop.stage.value, []).append(int(hop.finding_id))
    return {stage: tuple(ids) for stage, ids in out.items()}
