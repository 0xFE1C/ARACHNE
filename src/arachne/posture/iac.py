"""The pre-deploy policy engine for Kubernetes manifests (S23, REQ-POSTURE-002/005).

One engine, two consumers, one vocabulary:

* the **IaC gate** (`arachne iac-gate`) evaluates a directory of manifests before deploy,
* the **admission webhook** (``/api/v1/admission``) evaluates the object Kubernetes is
  about to admit — the same rules, the same severities, so "what the gate blocks" and
  "what the cluster refuses" cannot drift apart.

The rules are structural (a parsed manifest, not a regex over its bytes), because
admission reviews deliver structured objects and a YAML-parsing gate can reuse exactly
that. Severity is managed data (corpus section ``k8s_policy``) so an operator can tune
what enforce mode denies without touching code; a corpus rule naming an unknown rule id
is refused — a typo must not silently change what is enforced.

Monitor mode is *not* decided here: the engine only ever reports violations. Whether they
allow or deny a deploy is the admission layer's decision (``admission.py``), which is what
keeps "evaluate" and "enforce" separable — and enforce opt-in.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any, Final

from arachne.core.errors import ConfigurationError

__all__ = [
    "BUILTIN_K8S_RULES",
    "K8sRule",
    "K8sViolation",
    "evaluate_k8s_manifest",
    "is_k8s_manifest",
    "rules_from_corpus",
]

#: The dangerous Linux capabilities a workload may not add by default. Bounded on purpose:
#: the point is the *class* ( Namespaced capability escalation), not an exhaustive list.
_DANGEROUS_CAPABILITIES: Final[frozenset[str]] = frozenset(
    {
        "SYS_ADMIN",
        "NET_ADMIN",
        "SYS_PTRACE",
        "SYS_BOOT",
        "SYS_TIME",
        "SYS_MODULE",
        "DAC_READ_SEARCH",
        "DAC_OVERRIDE",
    }
)


@dataclass(frozen=True, slots=True)
class K8sRule:
    """One structural Kubernetes policy rule."""

    id: str
    severity: str
    hint: str


#: The shipped rules (the corpus's ``k8s_policy.rules`` may re-severity, never rename).
BUILTIN_K8S_RULES: Final[tuple[K8sRule, ...]] = (
    K8sRule("k8s-privileged", "high", "a container runs with privileged: true"),
    K8sRule("k8s-privilege-escalation", "medium", "allowPrivilegeEscalation is explicitly true"),
    K8sRule("k8s-run-as-root", "medium", "runAsNonRoot is explicitly false"),
    K8sRule("k8s-host-namespace", "high", "hostNetwork/hostPID/hostIPC shares the host namespace"),
    K8sRule("k8s-hostpath-volume", "high", "a hostPath volume mounts host storage into the pod"),
    K8sRule("k8s-latest-image", "medium", "a container image has no pinned tag (or :latest)"),
    K8sRule(
        "k8s-automount-token", "medium",
        "the pod automounts the default service-account token",
    ),
    K8sRule("k8s-dangerous-capability", "high", "a container adds a dangerous Linux capability"),
)


@dataclass(frozen=True, slots=True)
class K8sViolation:
    """One manifest location breaching one rule (deterministic order, stable path)."""

    rule_id: str
    severity: str
    hint: str
    #: Where in the manifest: ``Deployment/spec/containers/api`` (no JSON-pointer noise).
    path: str
    kind: str = ""
    name: str = ""

    def describe(self) -> str:
        return f"{self.rule_id} at {self.path}: {self.hint}"


def rules_from_corpus(corpus: Any) -> tuple[K8sRule, ...]:
    """The effective rules: the builtins with corpus-supplied severities (ids pinned)."""
    section = corpus.section("k8s_policy") if corpus is not None else {}
    overrides = section.get("rules") if isinstance(section, Mapping) else None
    if not overrides:
        return BUILTIN_K8S_RULES
    if not isinstance(overrides, list):
        raise ConfigurationError("k8s_policy.rules must be a list of {id, severity, hint}")
    by_id = {rule.id: rule for rule in BUILTIN_K8S_RULES}
    seen: set[str] = set()
    out: list[K8sRule] = []
    for entry in overrides:
        if not isinstance(entry, Mapping) or "id" not in entry:
            raise ConfigurationError("k8s_policy.rules entries must carry an id")
        rule_id = str(entry["id"])
        if rule_id not in by_id:
            raise ConfigurationError(
                f"k8s_policy.rules names unknown rule {rule_id!r}; known: "
                f"{', '.join(sorted(by_id))}"
            )
        if rule_id in seen:
            raise ConfigurationError(f"k8s_policy.rules names {rule_id!r} twice")
        seen.add(rule_id)
        base = by_id[rule_id]
        out.append(
            K8sRule(
                id=rule_id,
                severity=str(entry.get("severity") or base.severity),
                hint=str(entry.get("hint") or base.hint),
            )
        )
    # Un-overridden rules keep their shipped severity; overridden ones are replaced.
    unoverridden = tuple(rule for rule in BUILTIN_K8S_RULES if rule.id not in seen)
    return tuple(out) + unoverridden


def is_k8s_manifest(doc: Any) -> bool:
    """True when a parsed document is shaped like a Kubernetes object."""
    return isinstance(doc, Mapping) and bool(doc.get("apiVersion")) and bool(doc.get("kind"))


def evaluate_k8s_manifest(
    doc: Mapping[str, Any],
    rules: tuple[K8sRule, ...] = BUILTIN_K8S_RULES,
) -> tuple[K8sViolation, ...]:
    """Evaluate one Kubernetes object against the rules (pure; deterministic order).

    Workload kinds are unwrapped to their pod specs (Pod itself, Deployment/DaemonSet/
    StatefulSet/Job via ``spec.template.spec``, CronJob via the job template). Pods and
    pod templates that declare none of the evaluated fields pass — the gate reports
    misconfiguration, not style.
    """
    kind = str(doc.get("kind") or "")
    metadata = doc.get("metadata")
    name = str(metadata.get("name") or "") if isinstance(metadata, Mapping) else ""
    severity_of = {rule.id: rule for rule in rules}
    violations: list[K8sViolation] = []

    def emit(rule_id: str, path: str) -> None:
        rule = severity_of.get(rule_id)
        if rule is None:  # a rules tuple a caller built by hand may be partial
            return
        violations.append(
            K8sViolation(
                rule_id=rule_id,
                severity=rule.severity,
                hint=rule.hint,
                path=path,
                kind=kind,
                name=name,
            )
        )

    pod_specs: list[tuple[str, Mapping[str, Any]]] = []
    if kind == "Pod":
        spec = doc.get("spec")
        if isinstance(spec, Mapping):
            pod_specs.append(("spec", spec))
    elif kind in {"Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "Job"}:
        outer = doc.get("spec")
        template = outer.get("template", {}) if isinstance(outer, Mapping) else {}
        spec = template.get("spec") if isinstance(template, Mapping) else None
        if isinstance(spec, Mapping):
            pod_specs.append(("spec/template/spec", spec))
    elif kind == "CronJob":
        spec = doc.get("spec", {}) if isinstance(doc.get("spec"), Mapping) else {}
        job = spec.get("jobTemplate", {}) if isinstance(spec, Mapping) else {}
        template = job.get("spec", {}).get("template", {}) if isinstance(job, Mapping) else {}
        pod = template.get("spec") if isinstance(template, Mapping) else None
        if isinstance(pod, Mapping):
            pod_specs.append(("spec/jobTemplate/spec/template/spec", pod))

    for prefix, pod_spec in pod_specs:
        shares_host = any(
            pod_spec.get(field) is True for field in ("hostNetwork", "hostPID", "hostIPC")
        )
        if shares_host:
            emit("k8s-host-namespace", prefix)
        volumes = pod_spec.get("volumes")
        if isinstance(volumes, list):
            for index, volume in enumerate(volumes):
                if isinstance(volume, Mapping) and isinstance(volume.get("hostPath"), Mapping):
                    emit("k8s-hostpath-volume", f"{prefix}/volumes/{volume.get('name') or index}")
        if pod_spec.get("automountServiceAccountToken") is True:
            emit("k8s-automount-token", prefix)
        containers = pod_spec.get("containers")
        if isinstance(containers, list):
            for index, container in enumerate(containers):
                if not isinstance(container, Mapping):
                    continue
                cname = str(container.get("name") or index)
                base = f"{prefix}/containers/{cname}"
                security = container.get("securityContext")
                if isinstance(security, Mapping):
                    if security.get("privileged") is True:
                        emit("k8s-privileged", base)
                    if security.get("allowPrivilegeEscalation") is True:
                        emit("k8s-privilege-escalation", base)
                    if security.get("runAsNonRoot") is False:
                        emit("k8s-run-as-root", base)
                    capabilities = security.get("capabilities")
                    if isinstance(capabilities, Mapping):
                        added = capabilities.get("add") or ()
                        for item in added:
                            if str(item).upper() in _DANGEROUS_CAPABILITIES:
                                emit("k8s-dangerous-capability", f"{base}/capabilities")
                                break
                image = str(container.get("image") or "")
                if image:
                    tag = image.rsplit("/", 1)[-1].partition(":")[2]
                    if not tag or tag == "latest":
                        emit("k8s-latest-image", f"{base}/image")

    # Deterministic: rule id, then manifest path.
    violations.sort(key=lambda item: (item.rule_id, item.path))
    return tuple(violations)


def evaluate_manifests(
    docs: Iterable[Mapping[str, Any]],
    rules: tuple[K8sRule, ...] = BUILTIN_K8S_RULES,
) -> tuple[K8sViolation, ...]:
    """Evaluate a document set (an admission bundle, a manifests directory)."""
    out: list[K8sViolation] = []
    for doc in docs:
        if is_k8s_manifest(doc):
            out.extend(evaluate_k8s_manifest(doc, rules))
    return tuple(out)
