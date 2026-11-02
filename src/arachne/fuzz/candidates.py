"""Fuzzing candidates — leads, explicitly not findings (S30, REQ-FUZZ-003/004).

The distinction is the whole requirement. A fuzzer observes *behaviour*: an error status, a
response shape the target should not have produced, a connection that stopped answering. That
is not a vulnerability — it is a hypothesis about one, and the program's rule is that only the
proof ladder reports (REQ-PROOF-001). So a fuzzing run writes :class:`FuzzCandidate` records and
never a finding: there is no code path in area FUZZ that produces a ``status="vulnerable"``
result, no severity field on a candidate, and no way for one to reach a report on its own.

What a candidate *can* do is enter the hypothesis pipeline (REQ-FUZZ-004). That happens through
:meth:`FuzzCandidate.to_hypothesis`, which builds exactly the object the S21 reasoner consumes —
and the S21 model is itself a cage: a ``Hypothesis`` names a *registered check id* and a *known
asset*, and cannot carry a URL, a payload or a request (REQ-AGENT-005). A fuzzing candidate
therefore has to say which shipped check could prove its claim, and the pipeline then re-runs
that check under the planner, the scope gate and the proof gate it always would. The payload the
fuzzer found is *evidence attached to the candidate*; it is not something the hypothesis can
replay, which is what keeps the proof ladder in charge of what gets proven.

Two kinds of candidate therefore exist, and the difference is recorded rather than glossed over:

* the candidate names a **verifier** — a registered check that can prove this class of signal —
  and ``to_hypothesis()`` returns a proposal the pipeline can execute;
* the candidate names **no verifier**, because this build ships no check that can prove a signal
  from that grammar. It is still recorded, with ``verifier=None`` and
  ``status=needs-manual-triage``, because "we saw something odd on a Modbus device and nothing
  here can prove it" is information an operator needs. Naming a check that cannot prove it would
  manufacture a verification that did not happen.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Final

from pydantic import BaseModel, ConfigDict, Field

from arachne.reasoning.model import Hypothesis, HypothesisKind

__all__ = [
    "CANDIDATE_STATUS",
    "SIGNAL_CONFIDENCE",
    "CandidateSignal",
    "CandidateStatus",
    "FuzzCandidate",
    "candidate_id",
]

#: A candidate was recorded and proposed for verification.
CANDIDATE_STATUS: Final = "candidate"


class CandidateSignal(StrEnum):
    """What was observed. Named for the observation, never for a vulnerability class.

    A signal is deliberately weaker than a finding's claim: ``fault`` says "the service
    answered with its own internal-error status", not "the service is vulnerable to an
    integer overflow". The claim is the proof ladder's to make.
    """

    #: The target answered with its own fault status — a 500, a protocol exception mapped to
    #: "internal error", a parse failure it chose to report. The strongest raw signal.
    FAULT = "fault"
    #: A response whose shape differs from the seed's in a way the grammar did not intend.
    ANOMALY = "anomaly"
    #: No answer at all: a timeout or a connection that was accepted and then dropped.
    NO_RESPONSE = "no-response"
    #: HTTP: the payload was reflected into the response body.
    REFLECTION = "reflection"
    #: HTTP: a database error signature appeared in the response.
    ERROR_LEAK = "error-leak"
    #: HTTP: the response took materially longer than its baseline (a time-based differential).
    TIMING = "timing"
    #: HTTP: a path-traversal marker in the response (a file the target should not have served).
    FILE_READ = "file-read"
    #: HTTP: the response's status or length diverged from a control request's.
    DIVERGENCE = "divergence"

    @property
    def is_fault_like(self) -> bool:
        """True for a signal that says the *target* misbehaved rather than the input landing."""
        return self in (CandidateSignal.FAULT, CandidateSignal.NO_RESPONSE, CandidateSignal.ANOMALY)


#: The prior confidence of each signal, before any verification. Deliberately below the
#: thresholds a *finding* needs to be reported: a candidate starts out as a lead, and the
#: numbers say so. ``m3.sqli-oob``-class proof is what turns a lead into a finding.
SIGNAL_CONFIDENCE: Final[dict[CandidateSignal, int]] = {
    CandidateSignal.FAULT: 70,
    CandidateSignal.ERROR_LEAK: 72,
    CandidateSignal.REFLECTION: 60,
    CandidateSignal.FILE_READ: 68,
    CandidateSignal.TIMING: 55,
    CandidateSignal.DIVERGENCE: 45,
    CandidateSignal.ANOMALY: 45,
    CandidateSignal.NO_RESPONSE: 40,
}

#: How much of a payload a candidate keeps as evidence. The bytes are what makes a candidate
#: replayable and reviewable; the cap is what keeps a report readable.
MAX_PAYLOAD_PREVIEW: Final = 512


class CandidateStatus(StrEnum):
    """Where the candidate stands. Only ever one step ahead of "recorded"."""

    #: Recorded and proposed to the hypothesis pipeline (a verifier exists).
    PROPOSED = "proposed"
    #: Recorded and proposed, but a check could not be run on the asset (unknown asset,
    #: out of scope, refused proof requirement). The capability reason is in ``detail``.
    UNVERIFIABLE = "unverifiable"
    #: Recorded with no shipped verifier for this signal: manual triage.
    NEEDS_MANUAL_TRIAGE = "needs-manual-triage"


def candidate_id(*, grammar: str, target: str, field: str, operator: str) -> str:
    """A stable id for a candidate: same grammar, target, field and operator → same id.

    Stable rather than random so that re-running the same bounded plan produces the same
    candidate ids, and a report diff shows what *changed* rather than a wall of new rows.
    """
    digest = hashlib.sha256("\x00".join((grammar, target, field, operator)).encode()).hexdigest()
    return f"fc-{digest[:12]}"


class FuzzCandidate(BaseModel):
    """One lead a fuzzing run recorded. Not a finding, and shaped so it cannot be mistaken for
    one: no severity, no status field that reads as a verdict, and no evidence kind that the
    report engine renders as a confirmed result.

    Every field is either provenance (which grammar, which field, which operator, which engine,
    which run) or observation (what the target did). The mutation is recorded *as data* — field,
    operator, the payload's digest and a bounded hex preview — so a reviewer can reproduce the
    exact message without the report carrying an arbitrarily large blob.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str
    run_id: str
    engine: str
    grammar: str
    protocol: str
    #: The endpoint the case went to, as ``host:port`` or a URL.
    target: str
    #: The asset the hypothesis pipeline knows this endpoint by. Equal to ``target`` for a
    #: network service; the URL for an HTTP origin.
    asset: str
    field: str
    operator: str
    signal: CandidateSignal
    status: CandidateStatus
    confidence: int = Field(ge=0, le=100)
    #: A one-line reading of the observation, redacted on the way in.
    observation: str = Field(default="", max_length=500)
    #: Structured detail (status code, response bytes, latency ratio, ...).
    evidence: dict[str, Any] = Field(default_factory=dict)
    payload_sha256: str
    payload_bytes: int = Field(ge=0)
    payload_preview_hex: str = Field(default="", max_length=2 * MAX_PAYLOAD_PREVIEW)
    #: The registered check that can prove this signal, or ``None`` when no shipped check can.
    verifier: str | None = None
    #: The hypothesis this candidate became, when it became one.
    hypothesis_id: str | None = None
    #: Why it is not further along, when it is not.
    detail: str = Field(default="", max_length=500)
    recorded_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @property
    def is_finding(self) -> bool:
        """Always ``False``. A candidate is a lead; the proof ladder reports (REQ-FUZZ-003)."""
        return False

    @property
    def is_verified(self) -> bool:
        """Always ``False``. Verification is a check's result, not a candidate's field."""
        return False

    def to_hypothesis(self) -> Hypothesis | None:
        """The candidate as a proposal for the S21 hypothesis pipeline, or ``None``.

        ``None`` when the candidate names no verifier, because the pipeline's cage requires a
        *registered check id*: there is nothing to run, so there is nothing to propose. The
        candidate keeps its record and its ``needs-manual-triage`` status instead.
        """
        if self.verifier is None:
            return None
        return Hypothesis(
            id=hypothesis_id_for(self),
            kind=HypothesisKind.DISCOVERY,
            check_id=self.verifier,
            asset=self.asset,
            rationale=(
                f"fuzzing signal {self.signal.value} on {self.target} via "
                f"{self.grammar}/{self.field}/{self.operator}: {self.observation or 'no detail'}"
            ),
            expected_signal=self.signal.value,
            source="fuzz",
            confidence=self.confidence,
        )

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "id": self.id,
            "run_id": self.run_id,
            "engine": self.engine,
            "grammar": self.grammar,
            "protocol": self.protocol,
            "target": self.target,
            "asset": self.asset,
            "field": self.field,
            "operator": self.operator,
            "signal": self.signal.value,
            "status": self.status.value,
            "confidence": self.confidence,
            "observation": self.observation,
            "evidence": self.evidence,
            "payload_sha256": self.payload_sha256,
            "payload_bytes": self.payload_bytes,
            "payload_preview_hex": self.payload_preview_hex,
            "verifier": self.verifier,
            "hypothesis_id": self.hypothesis_id,
            "detail": self.detail,
            "recorded_at": self.recorded_at.isoformat(),
            # Restated, so a consumer reading only this document cannot mistake it for a finding.
            "is_finding": False,
            "candidate_status": CANDIDATE_STATUS,
        }
        return payload


def hypothesis_id_for(candidate: FuzzCandidate) -> str:
    """The hypothesis id a candidate proposes.

    Derived from the candidate's identity rather than minted, so re-proposing an unchanged
    candidate reuses the same id and the pipeline's journal can tell "the same lead again" from
    "a new lead".
    """
    return f"h-fuzz-{hashlib.sha256(candidate.id.encode()).hexdigest()[:12]}"


def preview_hex(payload: bytes) -> str:
    """A bounded hex preview of a payload for the report."""
    return payload[:MAX_PAYLOAD_PREVIEW].hex()
