"""The structured Kubernetes policy engine (S23, REQ-POSTURE-002/005).

One rule per violation class, plus the data contract: the corpus may re-severity a rule
it can name, and a corpus rule naming an unknown id is refused — a typo must never
silently change what enforce mode denies.
"""

from __future__ import annotations

import pytest

from arachne.core.errors import ConfigurationError
from arachne.posture.iac import (
    BUILTIN_K8S_RULES,
    evaluate_k8s_manifest,
    is_k8s_manifest,
    rules_from_corpus,
)

_PRIVILEGED = {
    "apiVersion": "apps/v1",
    "kind": "Deployment",
    "metadata": {"name": "api", "namespace": "prod"},
    "spec": {
        "template": {
            "spec": {
                "containers": [
                    {
                        "name": "api",
                        "image": "registry.local/api:latest",
                        "securityContext": {"privileged": True},
                    }
                ]
            }
        }
    },
}


def test_a_manifest_is_recognized_and_a_non_manifest_is_not() -> None:
    assert is_k8s_manifest(_PRIVILEGED)
    assert not is_k8s_manifest({"service": "storage"})
    assert not is_k8s_manifest("not-a-mapping")


def test_privileged_container_is_a_high_finding() -> None:
    violations = evaluate_k8s_manifest(_PRIVILEGED)
    ids = {item.rule_id for item in violations}
    assert "k8s-privileged" in ids
    assert "k8s-latest-image" in ids
    privileged = next(item for item in violations if item.rule_id == "k8s-privileged")
    assert privileged.severity == "high"
    assert privileged.path == "spec/template/spec/containers/api"
    assert privileged.name == "api"


def test_each_host_level_rule_fires_once() -> None:
    doc = {
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {"name": "p"},
        "spec": {
            "hostNetwork": True,
            "hostPID": True,
            "volumes": [{"name": "root", "hostPath": {"path": "/"}}],
            "automountServiceAccountToken": True,
            "containers": [
                {
                    "name": "c",
                    "image": "img:1.0",
                    "securityContext": {
                        "allowPrivilegeEscalation": True,
                        "runAsNonRoot": False,
                        "capabilities": {"add": ["NET_ADMIN", "SYS_ADMIN"]},
                    },
                }
            ],
        },
    }
    violations = evaluate_k8s_manifest(doc)
    ids = sorted(item.rule_id for item in violations)
    assert ids == [
        "k8s-automount-token",
        "k8s-dangerous-capability",
        "k8s-host-namespace",
        "k8s-hostpath-volume",
        "k8s-privilege-escalation",
        "k8s-run-as-root",
    ]


def test_a_hardened_manifest_passes_clean() -> None:
    doc = {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {"name": "ok"},
        "spec": {
            "template": {
                "spec": {
                    "automountServiceAccountToken": False,
                    "containers": [
                        {
                            "name": "api",
                            "image": "registry.local/api@sha256:"
                            + "0123456789abcdef" * 4,
                            "securityContext": {
                                "privileged": False,
                                "allowPrivilegeEscalation": False,
                                "runAsNonRoot": True,
                                "capabilities": {"drop": ["ALL"]},
                            },
                        }
                    ],
                }
            }
        },
    }
    assert evaluate_k8s_manifest(doc) == ()


def test_a_cronjob_spec_is_unwrapped() -> None:
    doc = {
        "apiVersion": "batch/v1",
        "kind": "CronJob",
        "metadata": {"name": "nightly"},
        "spec": {
            "jobTemplate": {
                "spec": {
                    "template": {
                        "spec": {
                            "containers": [
                                {"name": "job", "image": "img:latest",
                                 "securityContext": {"privileged": True}}
                            ]
                        }
                    }
                }
            }
        },
    }
    violations = evaluate_k8s_manifest(doc)
    ids = {item.rule_id for item in violations}
    assert {"k8s-privileged", "k8s-latest-image"} <= ids
    assert any(
        item.path.startswith("spec/jobTemplate/spec/template/spec") for item in violations
    )


def test_evaluation_is_deterministic() -> None:
    first = evaluate_k8s_manifest(_PRIVILEGED)
    second = evaluate_k8s_manifest(_PRIVILEGED)
    assert [item.describe() for item in first] == [item.describe() for item in second]
    assert [item.rule_id for item in first] == sorted(item.rule_id for item in first)


# ------------------------------------------------------------------ the data contract
def test_the_builtin_rules_are_the_shipped_severities() -> None:
    by_id = {rule.id: rule.severity for rule in BUILTIN_K8S_RULES}
    assert by_id["k8s-privileged"] == "high"
    assert by_id["k8s-automount-token"] == "medium"


def test_the_corpus_may_reseverity_a_known_rule() -> None:
    class FakeCorpus:
        def section(self, name: str) -> dict[str, object]:
            return {
                "rules": [
                    {"id": "k8s-privileged", "severity": "critical", "hint": "no privileges"},
                    {"id": "k8s-latest-image", "severity": "low"},
                ]
            }

    rules = rules_from_corpus(FakeCorpus())
    by_id = {rule.id: rule for rule in rules}
    assert by_id["k8s-privileged"].severity == "critical"
    assert by_id["k8s-privileged"].hint == "no privileges"
    assert by_id["k8s-latest-image"].severity == "low"
    # Un-overridden rules keep their shipped severity.
    assert by_id["k8s-host-namespace"].severity == "high"
    assert len(rules) == len(BUILTIN_K8S_RULES)


def test_a_corpus_rule_with_an_unknown_id_is_refused() -> None:
    class FakeCorpus:
        def section(self, name: str) -> dict[str, object]:
            return {"rules": [{"id": "k8s-typo"}]}

    with pytest.raises(ConfigurationError):
        rules_from_corpus(FakeCorpus())


def test_a_sectionless_corpus_falls_back_to_the_builtins() -> None:
    class EmptyCorpus:
        def section(self, name: str) -> dict[str, object]:
            return {}

    assert rules_from_corpus(EmptyCorpus()) == BUILTIN_K8S_RULES
