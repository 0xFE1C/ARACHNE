"""The Kubernetes admission route (S23, REQ-POSTURE-005).

One route, one decision, one audit line:

``POST /api/v1/admission``
    a Kubernetes API server's ValidatingWebhookConfiguration posts AdmissionReview v1
    documents here. The route parses, evaluates the objects against the same structured
    K8s policy rules the IaC gate runs, decides per the deployment's admission posture —
    **monitor** (the default: record and allow), **enforce** (deny on threshold breaches
    inside the staged namespace list), **off** (refuse, so a mispointed webhook fails
    loudly) — and answers with the AdmissionResponse. Every review is audited
    (``admission.reviewed``); an enforce-mode denial carries ``outcome=blocked``.

Auth: the caller is the cluster's API server, so it authenticates like everything else —
an API key (a dedicated service account is the documented wiring, operator guide §32).
Fail-open on evaluation errors (availability of the cluster outranks ARACHNE's opinion,
risk R-15), with the error audited and the response saying so.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException, status
from fastapi.responses import JSONResponse

from arachne.api.deps import ContextDep, ScannerPrincipal
from arachne.core.audit import AuditAction, AuditOutcome
from arachne.core.errors import ConfigurationError
from arachne.modules.m5.corpus import load_corpus
from arachne.posture.admission import (
    AdmissionSettings,
    evaluate_admission_review,
    parse_admission_review,
)
from arachne.posture.iac import BUILTIN_K8S_RULES, rules_from_corpus

__all__ = ["admission_router"]

admission_router = APIRouter()


def _rules() -> tuple[Any, ...]:
    """The effective K8s rules; a corrupt corpus falls back to the shipped severities
    rather than evaluating nothing (an admission endpoint must never go blind)."""
    try:
        return rules_from_corpus(load_corpus())
    except ConfigurationError:
        return BUILTIN_K8S_RULES


@admission_router.post("/admission", tags=["admission"])
def review_admission(
    payload: dict[str, Any], principal: ScannerPrincipal, context: ContextDep
) -> JSONResponse:
    """Evaluate one AdmissionReview; monitor allows, enforce decides, off refuses."""
    settings = context.settings.posture
    effective = AdmissionSettings(
        mode=settings.admission_mode,
        enforce_namespaces=settings.enforce_namespaces,
        deny_on=settings.admission_deny_on,
    )
    try:
        review = parse_admission_review(payload, source="admission")
    except ConfigurationError as exc:
        context.auditor.record(
            AuditAction.ADMISSION_REVIEWED,
            outcome=AuditOutcome.ERROR,
            target="admission",
            reason=str(exc),
            meta={"mode": effective.mode, "actor": principal.label},
        )
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    try:
        decision, response = evaluate_admission_review(review, effective, _rules())
    except Exception as exc:  # fail-open: availability of the cluster outranks our opinion
        decision_message = f"evaluation failed ({exc.__class__.__name__}); failing open"
        context.auditor.record(
            AuditAction.ADMISSION_REVIEWED,
            outcome=AuditOutcome.ERROR,
            target=review.name or review.uid,
            reason=decision_message,
            scan_id=None,
            meta={
                "mode": effective.mode,
                "namespace": review.namespace,
                "uid": review.uid,
                "actor": principal.label,
            },
        )
        decision_response = {
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "response": {
                "uid": review.uid,
                "allowed": True,
                "status": {"message": decision_message},
            },
        }
        return JSONResponse(decision_response)

    outcome = AuditOutcome.ALLOWED
    if not decision.allowed:
        outcome = AuditOutcome.BLOCKED
    elif decision.violations:
        outcome = AuditOutcome.ALLOWED
    context.auditor.record(
        AuditAction.ADMISSION_REVIEWED,
        outcome=outcome,
        target=f"{review.namespace}/{review.name or review.kind}",
        reason=decision.message,
        meta={
            "mode": decision.mode,
            "uid": review.uid,
            "namespace": review.namespace,
            "operation": review.operation,
            "kind": review.manifest_kind,
            "violations": [item.rule_id for item in decision.violations],
            "allowed": decision.allowed,
            "actor": principal.label,
        },
    )
    return JSONResponse(response)
