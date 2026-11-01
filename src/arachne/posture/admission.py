"""Kubernetes admission mode: AdmissionReview in, decision out (S23, REQ-POSTURE-005).

The policy engine is :mod:`arachne.posture.iac`; this module is the *decision* layer —
and the decision is where "monitor by default" lives:

* **monitor** (the deployment default): every review is evaluated and recorded, every
  request is **allowed**. The findings ride the response's ``status.message`` so the
  operator sees what enforce mode *would* do.
* **enforce** (opt-in, staged): a request is denied only when violations at or above the
  configured threshold occur **and** the object's namespace is in the staged namespace
  list (``*`` is the explicit all-namespaces form). An empty list denies nothing —
  enforce mode cannot become "block the world" by accident (risk R-15).
* **off**: the route refuses; a webhook pointing at a disabled feature fails loudly.

Failure posture: an internal evaluation error is **fail-open** (allow + audit) —
availability of the cluster outranks ARACHNE's opinion, and the audit line carries what
could not be evaluated. A *refusal* of enforce mode's own configuration (mode spelled
wrong) is a configuration error at construction, not a runtime surprise.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Final

from arachne.analyzer.model import severity_rank
from arachne.core.errors import ConfigurationError
from arachne.posture.iac import K8sViolation, evaluate_k8s_manifest

__all__ = [
    "ADMISSION_MODES",
    "AdmissionDecision",
    "AdmissionSettings",
    "evaluate_admission_review",
    "parse_admission_review",
]

#: The admission postures (mirrors ``PostureSettings.ADMISSION_MODES``; kept here so the
#: pure layer owns its vocabulary).
ADMISSION_MODES: Final[tuple[str, ...]] = ("monitor", "enforce", "off")


@dataclass(frozen=True, slots=True)
class AdmissionSettings:
    """The admission posture (projected from ``PostureSettings`` by the route)."""

    mode: str = "monitor"
    enforce_namespaces: tuple[str, ...] = ()
    deny_on: str = "high"

    def __post_init__(self) -> None:
        if self.mode not in ADMISSION_MODES:
            msg = f"admission mode must be one of {ADMISSION_MODES}, got {self.mode!r}"
            raise ConfigurationError(msg)


@dataclass(frozen=True, slots=True)
class AdmissionReview:
    """The parts of a Kubernetes AdmissionReview v1 ARACHNE evaluates."""

    uid: str
    kind: str
    name: str
    namespace: str
    operation: str
    object: dict[str, Any] = field(default_factory=dict)

    @property
    def manifest_kind(self) -> str:
        return str(self.object.get("kind") or self.kind)


@dataclass(frozen=True, slots=True)
class AdmissionDecision:
    """The outcome: allowed or denied, with the violations that drove it."""

    allowed: bool
    mode: str
    uid: str
    namespace: str
    violations: tuple[K8sViolation, ...] = ()
    #: What the response's ``status.message`` carries (monitor: the findings; enforce: the
    #: denial reason; off: the refusal note).
    message: str = ""
    #: True when the decision came from the fail-open path (an evaluation error).
    degraded: bool = False


def parse_admission_review(payload: Any, *, source: str = "<admission>") -> AdmissionReview:
    """Parse and validate an AdmissionReview (v1); refuse anything else loudly."""
    if not isinstance(payload, Mapping):
        msg = f"{source}: an AdmissionReview must be a JSON object"
        raise ConfigurationError(msg)
    request = payload.get("request")
    if not isinstance(request, Mapping):
        msg = f"{source}: AdmissionReview carries no request object"
        raise ConfigurationError(msg)
    uid = str(request.get("uid") or "")
    if not uid:
        msg = f"{source}: AdmissionReview request carries no uid"
        raise ConfigurationError(msg)
    kind = request.get("kind")
    kind_value = kind.get("kind", "") if isinstance(kind, Mapping) else str(kind or "")
    obj = request.get("object")
    return AdmissionReview(
        uid=uid,
        kind=kind_value,
        name=str(request.get("name") or ""),
        namespace=str(request.get("namespace") or "default"),
        operation=str(request.get("operation") or ""),
        object=dict(obj) if isinstance(obj, Mapping) else {},
    )


def _review_response(review: AdmissionReview, decision: AdmissionDecision) -> dict[str, Any]:
    """The AdmissionResponse ARACHNE returns (v1 shape; ``uid`` echoed)."""
    status: dict[str, Any] = {"message": decision.message or None}
    if not decision.allowed:
        status["reason"] = "ARACHNE policy: " + (
            "; ".join(violation.describe() for violation in decision.violations[:5])
            or decision.message
        )
    status = {key: value for key, value in status.items() if value is not None}
    return {
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "response": {
            "uid": review.uid,
            "allowed": decision.allowed,
            "status": status,
        },
    }


def evaluate_admission_review(
    review: AdmissionReview,
    settings: AdmissionSettings,
    rules: tuple[Any, ...],
) -> tuple[AdmissionDecision, dict[str, Any]]:
    """Evaluate one review; return ``(decision, response document)``.

    Pure: no audit, no store — the route records the decision. ``rules`` is the effective
    :data:`~arachne.posture.iac.BUILTIN_K8S_RULES`-shaped tuple (corpus-severities applied).
    """
    if settings.mode == "off":
        decision = AdmissionDecision(
            allowed=False,
            mode="off",
            uid=review.uid,
            namespace=review.namespace,
            message="ARACHNE admission mode is off; this endpoint refuses reviews",
        )
        return decision, _review_response(review, decision)

    violations = evaluate_k8s_manifest(review.object, rules)
    if settings.mode == "monitor":
        message = (
            f"monitor: {len(violations)} policy finding(s) "
            f"({', '.join(sorted({item.rule_id for item in violations})) or 'none'}); "
            "allowed (enforce mode is opt-in)"
        )
        decision = AdmissionDecision(
            allowed=True,
            mode="monitor",
            uid=review.uid,
            namespace=review.namespace,
            violations=violations,
            message=message,
        )
        return decision, _review_response(review, decision)

    # Enforce: staged by namespace, thresholded by severity.
    staged = _namespace_staged(settings.enforce_namespaces, review.namespace)
    blocking = [
        item
        for item in violations
        if severity_rank(item.severity) >= severity_rank(settings.deny_on)
    ]
    if not staged:
        decision = AdmissionDecision(
            allowed=True,
            mode="enforce",
            uid=review.uid,
            namespace=review.namespace,
            violations=violations,
            message=(
                f"enforce mode is staged for {settings.enforce_namespaces or '(no namespaces)'}; "
                f"namespace {review.namespace!r} is not in the rollout, so this is monitor-only: "
                f"{len(blocking)} blocking finding(s)"
            ),
        )
        return decision, _review_response(review, decision)
    if not blocking:
        decision = AdmissionDecision(
            allowed=True,
            mode="enforce",
            uid=review.uid,
            namespace=review.namespace,
            violations=violations,
            message=f"no finding at or above {settings.deny_on}; allowed",
        )
        return decision, _review_response(review, decision)
    decision = AdmissionDecision(
        allowed=False,
        mode="enforce",
        uid=review.uid,
        namespace=review.namespace,
        violations=tuple(blocking),
        message=(
            f"denied: {len(blocking)} finding(s) at or above {settings.deny_on} in namespace "
            f"{review.namespace!r} (staged rollout)"
        ),
    )
    return decision, _review_response(review, decision)


def _namespace_staged(namespaces: tuple[str, ...], namespace: str) -> bool:
    return "*" in namespaces or namespace in namespaces
