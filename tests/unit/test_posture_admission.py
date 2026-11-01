"""Admission mode decisions (S23, REQ-POSTURE-005): monitor by default, enforce opt-in.

The decision layer is pure — parse, evaluate, decide, and the response document — so the
safety-critical properties are unit-testable: monitor *always* allows (and says what
enforce would do), enforce denies only inside the staged namespace list at/above the
threshold, an empty staged list denies nothing, and ``off`` refuses loudly.
"""

from __future__ import annotations

import pytest

from arachne.core.errors import ConfigurationError
from arachne.posture.admission import (
    AdmissionReview,
    AdmissionSettings,
    evaluate_admission_review,
    parse_admission_review,
)
from arachne.posture.iac import BUILTIN_K8S_RULES

_RULES = BUILTIN_K8S_RULES


def _review(
    *,
    namespace: str = "prod",
    privileged: bool = True,
    uid: str = "uid-1",
) -> AdmissionReview:
    doc = {
        "request": {
            "uid": uid,
            "kind": {"kind": "Pod", "version": "v1"},
            "name": "payments",
            "namespace": namespace,
            "operation": "CREATE",
            "object": {
                "apiVersion": "v1",
                "kind": "Pod",
                "metadata": {"name": "payments", "namespace": namespace},
                "spec": {
                    "containers": [
                        {
                            "name": "api",
                            "image": "img:latest",
                            "securityContext": ({"privileged": True} if privileged else {}),
                        }
                    ]
                },
            },
        }
    }
    return parse_admission_review(doc, source="test")


def test_a_review_parses_its_request_fields() -> None:
    review = _review()
    assert review.uid == "uid-1"
    assert review.namespace == "prod"
    assert review.manifest_kind == "Pod"
    assert review.object["spec"]["containers"][0]["name"] == "api"


def test_a_review_without_a_uid_is_refused() -> None:
    with pytest.raises(ConfigurationError):
        parse_admission_review({"request": {"name": "x"}}, source="test")
    with pytest.raises(ConfigurationError):
        parse_admission_review({"not": "a review"}, source="test")
    with pytest.raises(ConfigurationError):
        parse_admission_review("nope", source="test")


def test_monitor_mode_always_allows_and_names_the_findings() -> None:
    decision, response = evaluate_admission_review(_review(), AdmissionSettings(), _RULES)
    assert decision.allowed
    assert decision.mode == "monitor"
    assert {"k8s-privileged", "k8s-latest-image"} <= {item.rule_id for item in decision.violations}
    assert "monitor" in decision.message
    body = response["response"]
    assert body["allowed"] is True
    assert body["uid"] == "uid-1"


def test_enforce_mode_denies_above_the_threshold_in_a_staged_namespace() -> None:
    settings = AdmissionSettings(
        mode="enforce", enforce_namespaces=("prod",), deny_on="high"
    )
    decision, response = evaluate_admission_review(_review(), settings, _RULES)
    assert not decision.allowed
    assert decision.mode == "enforce"
    assert [item.rule_id for item in decision.violations] == ["k8s-privileged"]
    body = response["response"]
    assert body["allowed"] is False
    assert "k8s-privileged" in body["status"]["reason"]


def test_enforce_mode_allows_below_the_threshold() -> None:
    settings = AdmissionSettings(
        mode="enforce", enforce_namespaces=("prod",), deny_on="critical"
    )
    decision, _ = evaluate_admission_review(_review(), settings, _RULES)
    assert decision.allowed
    assert decision.violations  # the findings are still reported


def test_enforce_mode_outside_the_staged_namespaces_is_monitor_only() -> None:
    settings = AdmissionSettings(
        mode="enforce", enforce_namespaces=("staging",), deny_on="high"
    )
    decision, _ = evaluate_admission_review(_review(namespace="prod"), settings, _RULES)
    assert decision.allowed
    assert "not in the rollout" in decision.message


def test_an_empty_staged_list_denies_nothing() -> None:
    settings = AdmissionSettings(mode="enforce", enforce_namespaces=(), deny_on="high")
    decision, _ = evaluate_admission_review(_review(), settings, _RULES)
    assert decision.allowed


def test_the_explicit_wildcard_stages_every_namespace() -> None:
    settings = AdmissionSettings(mode="enforce", enforce_namespaces=("*",), deny_on="high")
    decision, _ = evaluate_admission_review(_review(namespace="anything"), settings, _RULES)
    assert not decision.allowed


def test_off_mode_refuses_the_review() -> None:
    decision, response = evaluate_admission_review(
        _review(), AdmissionSettings(mode="off"), _RULES
    )
    assert not decision.allowed
    assert decision.mode == "off"
    assert response["response"]["status"]["message"]


def test_an_invalid_mode_is_refused_at_construction() -> None:
    with pytest.raises(ConfigurationError):
        AdmissionSettings(mode="yolo")
