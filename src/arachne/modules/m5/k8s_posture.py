"""WP-32 · Kubernetes read-only posture (REQ-DET-025).

Nine read-only L1 checks over the surfaces the requirement names: the Kubernetes **API server**,
**kubelet**, **dashboard**, **RBAC**, **secrets** and **admission** configuration. Each reads
the cluster's own API with a vault-supplied credential — the operator's service-account or
bearer token — and reports a posture condition the cluster's own objects carry:

============================  ==========================================================
area                            checks
============================  ==========================================================
RBAC (2)                        a custom ClusterRole that grants ``*``, and a
                                ClusterRoleBinding that hands ``cluster-admin`` to a broad
                                group
secrets (1)                     a custom ClusterRole that grants read access to secrets,
                                bound to a broad group — established from RBAC metadata alone
API server (1)                  a ClusterRoleBinding that grants a role to the anonymous
                                group (``system:unauthenticated``)
workloads (2)                   a pod that runs a privileged container, one that mounts a
                                host path
dashboard (1)                   the Kubernetes Dashboard service published on a LoadBalancer
                                or NodePort
kubelet (1)                     a node whose kubelet still allows anonymous requests or
                                serves the read-only port
admission (1)                   a validating admission webhook whose failure policy is
                                ``Ignore`` (fail-open)
============================  ==========================================================

**No secret is ever read — exposure is established from metadata.** The pitfall names the one
behaviour this family must not have: fetching a secret to "prove" it is exposed. The
``m5.k8s-rbac-secrets-exposed`` check therefore never asks the API for a secret; it reads the
*RBAC objects* — a ClusterRole's rules and the ClusterRoleBinding that hands it out — and
establishes that secrets **are listable** by a broad group. There is no operation in
:data:`K8S_READ_OPERATIONS` that returns secret content, so the stronger behaviour is
unrepresentable, not merely unused; ``tests/unit/test_cloud_posture.py`` asserts that no
operation path names a secret and ``tests/integration/test_wp32_scan.py`` asserts it on the
wire, against the fixture's own request log.

**Read-only is the control, and it is a closed allowlist.** Every call this module can make is
one entry of :data:`K8S_READ_OPERATIONS` — a frozen tuple of ``GET`` records. The operation
object is the parameter: the client refuses one that is not a table entry, and
:class:`~arachne.modules.m5.posture_read.CloudReadOperation` refuses a non-``GET`` method or a
mutation verb at construction, so a write to the cluster is unrepresentable.

**The endpoint is declared, not guessed.** The target reference is ``k8s-posture:<base>`` and
``<base>`` is the API server's base URL the operator's read-only credential is scoped to. The
kubelet's own configuration is read *through the API server's node proxy* rather than by
contacting the kubelet, so the family keeps the one authenticated, declared endpoint and never
opens a second connection.

**Credentials come from the vault and never cross the module boundary.** A check declares
``requires_credentials=("cloud-token",)`` and calls the broker, which injects the bearer token
into one request and hands back a redacted exchange; no finding or audit record carries it.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Final

from arachne.modules.base import Module
from arachne.modules.context import CheckContext
from arachne.modules.m5.posture_read import (
    CloudReadClient,
    CloudReadOperation,
    Observation,
    PostureCheck,
    bool_of,
    exchanges_of,
    get,
    items_of,
    limit,
    posture_metadata,
    text_of,
)
from arachne.modules.m5.support import EndpointCheck

__all__ = ["K8S_POSTURE_CHECKS", "K8S_READ_OPERATIONS", "k8s_checks", "service_areas"]

REFERENCES: Final[tuple[str, ...]] = ("k8s-posture", "k8sposture")
FAMILY: Final = "k8s-posture"
PROVIDER: Final = "kubernetes"

#: The ClusterRoles every cluster ships. A wildcard in one of these is by design — the
#: ``cluster-admin`` role *is* a wildcard — so a check that reported them would fire on every
#: cluster and on the hardened decoy alike. A custom role is the thing to report, which is why
#: the built-ins (and everything under the ``system:`` prefix) are excluded.
_BUILTIN_CLUSTER_ROLES: Final[frozenset[str]] = frozenset(
    {"cluster-admin", "admin", "edit", "view"}
)

#: The subject groups that stand for "anything that can reach the API server". A binding that
#: hands a role to one of these has an audience of the whole world (or the whole cluster), not
#: of a named principal.
_BROAD_GROUPS: Final[frozenset[str]] = frozenset(
    {
        "system:authenticated",
        "system:unauthenticated",
        "system:serviceaccounts",
        "system:serviceaccounts:default",
        "*",
    }
)


# --------------------------------------------------------------------------- operations
_PODS = CloudReadOperation(action="listPods", path="/api/v1/pods")
_SERVICES = CloudReadOperation(action="listServices", path="/api/v1/services")
_CLUSTER_ROLES = CloudReadOperation(
    action="listClusterRoles", path="/apis/rbac.authorization.k8s.io/v1/clusterroles"
)
_CLUSTER_ROLE_BINDINGS = CloudReadOperation(
    action="listClusterRoleBindings",
    path="/apis/rbac.authorization.k8s.io/v1/clusterrolebindings",
)
_NODES = CloudReadOperation(action="listNodes", path="/api/v1/nodes")
_NODE_KUBELET_CONFIG = CloudReadOperation(
    action="getNodeProxyConfigz", path="/api/v1/nodes/{node}/proxy/configz"
)
_VALIDATING_WEBHOOKS = CloudReadOperation(
    action="listValidatingWebhookConfigurations",
    path="/apis/admissionregistration.k8s.io/v1/validatingwebhookconfigurations",
)

#: **The operation allowlist.** Every Kubernetes call this module can make is one entry here.
#: There is deliberately no ``getSecret``: exposure is established from RBAC metadata, so
#: reading a secret's content is not something a check in this family can even ask for.
K8S_READ_OPERATIONS: Final[tuple[CloudReadOperation, ...]] = (
    _PODS,
    _SERVICES,
    _CLUSTER_ROLES,
    _CLUSTER_ROLE_BINDINGS,
    _NODES,
    _NODE_KUBELET_CONFIG,
    _VALIDATING_WEBHOOKS,
)


# --------------------------------------------------------------------------- base check
class _K8sCheck(PostureCheck, EndpointCheck):
    """The family's shared shape: the reference prefix and the operation allowlist."""

    references = REFERENCES
    family = FAMILY
    provider = PROVIDER
    operations = K8S_READ_OPERATIONS


def _name(resource: Mapping[str, Any]) -> str:
    metadata = get(resource, "metadata")
    metadata = metadata if isinstance(metadata, Mapping) else {}
    name = text_of(metadata, "name")
    namespace = text_of(metadata, "namespace")
    if not name:
        return "unnamed"
    return f"{namespace}/{name}" if namespace else name


def _rules(role: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    value = get(role, "rules")
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return []
    return [rule for rule in value if isinstance(rule, Mapping)]


def _rule_values(rule: Mapping[str, Any], *names: str) -> set[str]:
    """The declared values of a rule field (``verbs``, ``resources``), lower-cased."""
    for name in names:
        value = get(rule, name)
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
            return {str(item).lower() for item in value}
    return set()


def _is_custom_role(name: str) -> bool:
    return bool(name) and name not in _BUILTIN_CLUSTER_ROLES and not name.startswith("system:")


def _subjects(binding: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    value = get(binding, "subjects")
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return []
    return [subject for subject in value if isinstance(subject, Mapping)]


def _broad_groups(binding: Mapping[str, Any]) -> list[str]:
    """The broad groups a binding's subjects name (``system:authenticated`` and friends)."""
    out: list[str] = []
    for subject in _subjects(binding):
        kind = text_of(subject, "kind").lower()
        if kind != "group":
            continue
        name = text_of(subject, "name").lower()
        if name in _BROAD_GROUPS:
            out.append(text_of(subject, "name"))
    return out


def _role_ref(binding: Mapping[str, Any]) -> tuple[str, str]:
    reference = get(binding, "roleRef")
    reference = reference if isinstance(reference, Mapping) else {}
    return text_of(reference, "kind"), text_of(reference, "name")


# --------------------------------------------------------------------------- RBAC
class K8sRbacWildcardClusterRole(_K8sCheck, Module):
    """``m5.k8s-rbac-wildcard-clusterrole`` — a custom role that grants everything."""

    area = "rbac"
    reads = (_CLUSTER_ROLES,)
    metadata = posture_metadata(
        name="k8s-rbac-wildcard-clusterrole",
        title="Custom ClusterRole grants a wildcard on every resource",
        description=(
            "Lists the cluster's ClusterRoles and reports a custom one (not a built-in and "
            "not under the system: prefix) whose rules grant the verb * or the resource *, "
            "with no resourceNames restriction: the role is unbounded, so every principal "
            "bound to it may act on every object in every namespace. Read-only: "
            "listClusterRoles."
        ),
        research_ref="ch05#14",
        cwe="CWE-269",
        framework=("WSTG-CONF-02", "API8:2023", "CWE-269"),
        compliance=("CIS-5.1", "ISO-A.8.3", "CSF-PR.AA-05", "PCI-7"),
        severity="high",
        estimated_requests=1,
    )

    async def evaluate(self, ctx: CheckContext, client: CloudReadClient) -> list[Observation]:
        reply = await client.get(_CLUSTER_ROLES)
        out: list[Observation] = []
        for role in limit(ctx, items_of(reply.mapping(), "items")):
            name = text_of(get(role, "metadata") or {}, "name") or _name(role)
            if not _is_custom_role(name):
                continue
            wildcards = [
                rule
                for rule in _rules(role)
                if "*" in _rule_values(rule, "verbs")
                or "*" in _rule_values(rule, "resources")
                or "*" in _rule_values(rule, "apiGroups")
            ]
            if not wildcards:
                continue
            out.append(
                Observation(
                    policy="k8s-rbac-wildcard-clusterrole",
                    provider=PROVIDER,
                    resource=name,
                    title=f"Kubernetes ClusterRole grants a wildcard: {name}",
                    detail=(
                        f"custom ClusterRole {name} grants * on one or more rules: every "
                        "principal bound to it is unbounded"
                    ),
                    observed={
                        "rules": [
                            {
                                "apiGroups": sorted(_rule_values(rule, "apiGroups")),
                                "resources": sorted(_rule_values(rule, "resources")),
                                "verbs": sorted(_rule_values(rule, "verbs")),
                            }
                            for rule in wildcards
                        ]
                    },
                    severity="high",
                    exchanges=exchanges_of(reply),
                )
            )
        return out


class K8sRbacClusterAdminBinding(_K8sCheck, Module):
    """``m5.k8s-rbac-cluster-admin-binding`` — cluster-admin handed to a broad group."""

    area = "rbac"
    reads = (_CLUSTER_ROLE_BINDINGS,)
    metadata = posture_metadata(
        name="k8s-rbac-cluster-admin-binding",
        title="ClusterRoleBinding grants cluster-admin to a broad group",
        description=(
            "Lists the cluster's ClusterRoleBindings and reports one whose roleRef is the "
            "built-in cluster-admin and whose subjects name a broad group "
            "(system:authenticated, system:unauthenticated, system:serviceaccounts or *): the "
            "cluster's full authority is handed to everything that can reach the API server "
            "rather than to a named principal. Read-only: listClusterRoleBindings."
        ),
        research_ref="ch05#13",
        cwe="CWE-269",
        framework=("WSTG-CONF-02", "API8:2023", "CWE-269"),
        compliance=("CIS-5.1", "ISO-A.8.3", "CSF-PR.AA-05", "PCI-7"),
        severity="high",
        estimated_requests=1,
    )

    async def evaluate(self, ctx: CheckContext, client: CloudReadClient) -> list[Observation]:
        reply = await client.get(_CLUSTER_ROLE_BINDINGS)
        out: list[Observation] = []
        for binding in limit(ctx, items_of(reply.mapping(), "items")):
            kind, name = _role_ref(binding)
            if kind != "ClusterRole" or name != "cluster-admin":
                continue
            groups = _broad_groups(binding)
            if not groups:
                continue
            out.append(
                Observation(
                    policy="k8s-rbac-cluster-admin-binding",
                    provider=PROVIDER,
                    resource=_name(binding),
                    title=f"cluster-admin is bound to a broad group: {_name(binding)}",
                    detail=(
                        f"ClusterRoleBinding {_name(binding)} grants cluster-admin to "
                        f"{groups}: the cluster's full authority has a group-wide audience"
                    ),
                    observed={"roleRef": "cluster-admin", "groups": groups},
                    severity="high",
                    exchanges=exchanges_of(reply),
                )
            )
        return out


class K8sRbacSecretsExposed(_K8sCheck, Module):
    """``m5.k8s-rbac-secrets-exposed`` — secrets are listable by a broad group.

    Exposure is established from RBAC **metadata**: the check reads a ClusterRole's rules and
    the ClusterRoleBinding that hands it out. It never fetches a secret and never reads a
    secret's contents — it reports that they *are listable*.
    """

    area = "secrets"
    reads = (_CLUSTER_ROLES, _CLUSTER_ROLE_BINDINGS)
    metadata = posture_metadata(
        name="k8s-rbac-secrets-exposed",
        title="Kubernetes secrets are listable by a broad group",
        description=(
            "Lists the cluster's ClusterRoles and ClusterRoleBindings and reports a custom "
            "ClusterRole whose rules grant get/list/watch on the secrets resource (or * on "
            "every resource) and a ClusterRoleBinding that hands it to a broad group "
            "(system:authenticated, system:unauthenticated, system:serviceaccounts or *). "
            "Exposure is established from the RBAC metadata alone: the check never requests a "
            "secret, so it establishes that the secrets are *listable*, not what they "
            "contain. Read-only: listClusterRoles and listClusterRoleBindings."
        ),
        research_ref="ch05#14",
        cwe="CWE-522",
        framework=("WSTG-CONF-02", "API8:2023", "CWE-522"),
        compliance=("CIS-5.1", "ISO-A.5.15", "CSF-PR.AA-05", "PCI-7"),
        severity="high",
        estimated_requests=2,
    )

    async def evaluate(self, ctx: CheckContext, client: CloudReadClient) -> list[Observation]:
        roles_reply = await client.get(_CLUSTER_ROLES)
        bindings_reply = await client.get(_CLUSTER_ROLE_BINDINGS)
        granting = {
            text_of(get(role, "metadata") or {}, "name")
            for role in limit(ctx, items_of(roles_reply.mapping(), "items"))
            if _is_custom_role(text_of(get(role, "metadata") or {}, "name") or "")
            and _grants_secret_read(role)
        }
        granting.discard("")
        out: list[Observation] = []
        for binding in limit(ctx, items_of(bindings_reply.mapping(), "items")):
            kind, name = _role_ref(binding)
            if kind != "ClusterRole" or name not in granting:
                continue
            groups = _broad_groups(binding)
            if not groups:
                continue
            out.append(
                Observation(
                    policy="k8s-rbac-secrets-exposed",
                    provider=PROVIDER,
                    resource=_name(binding),
                    title=f"Kubernetes secrets are listable by a broad group: {_name(binding)}",
                    detail=(
                        f"ClusterRole {name} grants read access to secrets and "
                        f"ClusterRoleBinding {_name(binding)} hands it to {groups}: the "
                        "cluster's secrets are listable by every member of that group "
                        "(established from RBAC metadata; no secret was read)"
                    ),
                    observed={"role": name, "groups": groups, "resource": "secrets"},
                    severity="high",
                    exchanges=exchanges_of(roles_reply, bindings_reply),
                )
            )
        return out


def _grants_secret_read(role: Mapping[str, Any]) -> bool:
    """True when a role's rules grant a read verb on ``secrets`` (or ``*`` resources)."""
    read_verbs = {"get", "list", "watch", "*"}
    for rule in _rules(role):
        resources = _rule_values(rule, "resources")
        if "secrets" not in resources and "*" not in resources:
            continue
        if _rule_values(rule, "verbs") & read_verbs:
            return True
    return False


class K8sApiAnonymousBinding(_K8sCheck, Module):
    """``m5.k8s-api-anonymous-binding`` — the API server grants the anonymous group a role."""

    area = "api-server"
    reads = (_CLUSTER_ROLE_BINDINGS,)
    metadata = posture_metadata(
        name="k8s-api-anonymous-binding",
        title="Kubernetes API server grants a role to the anonymous group",
        description=(
            "Lists the cluster's ClusterRoleBindings and reports one whose subjects name the "
            "group system:unauthenticated: the API server then authorizes requests that carry "
            "no credential at all, so anything that can reach the API server's port is a "
            "principal. Read-only: listClusterRoleBindings."
        ),
        research_ref="ch05#13",
        cwe="CWE-284",
        framework=("WSTG-CONF-02", "API8:2023", "CWE-284"),
        compliance=("CIS-5.1", "ISO-A.8.5", "CSF-PR.AA-05", "PCI-7"),
        severity="high",
        estimated_requests=1,
    )

    async def evaluate(self, ctx: CheckContext, client: CloudReadClient) -> list[Observation]:
        reply = await client.get(_CLUSTER_ROLE_BINDINGS)
        out: list[Observation] = []
        for binding in limit(ctx, items_of(reply.mapping(), "items")):
            groups = [
                group
                for group in _broad_groups(binding)
                if group.lower() == "system:unauthenticated"
            ]
            if not groups:
                continue
            kind, name = _role_ref(binding)
            out.append(
                Observation(
                    policy="k8s-api-anonymous-binding",
                    provider=PROVIDER,
                    resource=_name(binding),
                    title=f"Anonymous requests are authorized: {_name(binding)}",
                    detail=(
                        f"ClusterRoleBinding {_name(binding)} grants {kind}/{name} to "
                        "system:unauthenticated: the API server authorizes requests that carry "
                        "no credential"
                    ),
                    observed={"roleRef": f"{kind}/{name}", "groups": groups},
                    severity="high",
                    exchanges=exchanges_of(reply),
                )
            )
        return out


# --------------------------------------------------------------------------- workloads
class K8sPodPrivileged(_K8sCheck, Module):
    """``m5.k8s-pod-privileged`` — a pod running a privileged container."""

    area = "workloads"
    reads = (_PODS,)
    metadata = posture_metadata(
        name="k8s-pod-privileged",
        title="Kubernetes pod runs a privileged container",
        description=(
            "Lists the cluster's pods and reports one whose container or initContainer "
            "securityContext.privileged is true: the container holds the host's capabilities "
            "and devices, so a workload compromise is a node compromise. Read-only: listPods."
        ),
        research_ref="ch05#14",
        cwe="CWE-250",
        framework=("WSTG-CONF-02", "API8:2023", "CWE-250"),
        compliance=("CIS-5.1", "ISO-A.8.3", "CSF-PR.AA-05", "PCI-7"),
        severity="high",
        estimated_requests=1,
    )

    async def evaluate(self, ctx: CheckContext, client: CloudReadClient) -> list[Observation]:
        reply = await client.get(_PODS)
        out: list[Observation] = []
        for pod in limit(ctx, items_of(reply.mapping(), "items")):
            privileged = [
                container
                for container in _containers(pod)
                if bool_of(get(container, "securityContext") or {}, "privileged") is True
            ]
            if not privileged:
                continue
            out.append(
                Observation(
                    policy="k8s-pod-privileged",
                    provider=PROVIDER,
                    resource=_name(pod),
                    title=f"Kubernetes pod runs a privileged container: {_name(pod)}",
                    detail=(
                        f"pod {_name(pod)} sets securityContext.privileged on "
                        f"{', '.join(_container_name(container) for container in privileged)}"
                    ),
                    observed={
                        "containers": [
                            text_of(container, "name") or "unnamed" for container in privileged
                        ],
                        "privileged": True,
                    },
                    severity="high",
                    exchanges=exchanges_of(reply),
                )
            )
        return out


class K8sPodHostPath(_K8sCheck, Module):
    """``m5.k8s-pod-hostpath`` — a pod mounting a host path."""

    area = "workloads"
    reads = (_PODS,)
    metadata = posture_metadata(
        name="k8s-pod-hostpath",
        title="Kubernetes pod mounts a host path volume",
        description=(
            "Lists the cluster's pods and reports one that declares a hostPath volume: the "
            "pod reads and writes the node's own filesystem, which gives a container access "
            "to the kubelet's credentials, the container runtime's socket and every other "
            "pod's data on that node. Read-only: listPods."
        ),
        research_ref="ch05#14",
        cwe="CWE-250",
        framework=("WSTG-CONF-02", "API8:2023", "CWE-250"),
        compliance=("CIS-5.1", "ISO-A.8.3", "CSF-PR.AA-05", "PCI-7"),
        severity="high",
        estimated_requests=1,
    )

    async def evaluate(self, ctx: CheckContext, client: CloudReadClient) -> list[Observation]:
        reply = await client.get(_PODS)
        out: list[Observation] = []
        for pod in limit(ctx, items_of(reply.mapping(), "items")):
            volumes = get(pod.get("spec") if isinstance(pod, Mapping) else None, "volumes")
            volumes = (
                volumes
                if isinstance(volumes, Sequence) and not isinstance(volumes, (str, bytes))
                else []
            )
            mounts = [
                volume
                for volume in volumes
                if isinstance(volume, Mapping) and get(volume, "hostPath") is not None
            ]
            if not mounts:
                continue
            paths = [text_of(get(volume, "hostPath") or {}, "path") for volume in mounts]
            out.append(
                Observation(
                    policy="k8s-pod-hostpath",
                    provider=PROVIDER,
                    resource=_name(pod),
                    title=f"Kubernetes pod mounts a host path: {_name(pod)}",
                    detail=(
                        f"pod {_name(pod)} declares {len(mounts)} hostPath volume(s): the "
                        "container can read and write the node's filesystem"
                    ),
                    observed={"hostPaths": paths},
                    severity="high",
                    exchanges=exchanges_of(reply),
                )
            )
        return out


def _container_name(container: Mapping[str, Any]) -> str:
    return text_of(container, "name") or "a container"


def _containers(pod: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    """Every container a pod declares, spec containers and initContainers alike."""
    spec = get(pod, "spec")
    spec = spec if isinstance(spec, Mapping) else {}
    out: list[Mapping[str, Any]] = []
    for field_name in ("containers", "initContainers", "ephemeralContainers"):
        value = get(spec, field_name)
        if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
            out.extend(item for item in value if isinstance(item, Mapping))
    return out


# --------------------------------------------------------------------------- dashboard
class K8sDashboardPublicService(_K8sCheck, Module):
    """``m5.k8s-dashboard-public-service`` — the dashboard published to the network."""

    area = "dashboard"
    reads = (_SERVICES,)
    metadata = posture_metadata(
        name="k8s-dashboard-public-service",
        title="Kubernetes Dashboard is published on a public service type",
        description=(
            "Lists the cluster's services and reports one whose name names the Dashboard and "
            "whose type is LoadBalancer or NodePort: the dashboard is then reachable from "
            "outside the cluster, where its skip-login option, an over-broad service account "
            "or a weak credential is the only control in front of it. Read-only: "
            "listServices."
        ),
        research_ref="ch05#13",
        cwe="CWE-284",
        framework=("WSTG-CONF-02", "API8:2023", "CWE-284"),
        compliance=("CIS-5.1", "ISO-A.8.20", "CSF-PR.AA-05", "PCI-1"),
        severity="high",
        estimated_requests=1,
    )

    async def evaluate(self, ctx: CheckContext, client: CloudReadClient) -> list[Observation]:
        reply = await client.get(_SERVICES)
        out: list[Observation] = []
        for service in limit(ctx, items_of(reply.mapping(), "items")):
            metadata = get(service, "metadata")
            metadata = metadata if isinstance(metadata, Mapping) else {}
            name = text_of(metadata, "name")
            if "dashboard" not in name.lower():
                continue
            spec = get(service, "spec")
            spec = spec if isinstance(spec, Mapping) else {}
            service_type = text_of(spec, "type") or "ClusterIP"
            if service_type not in {"LoadBalancer", "NodePort"}:
                continue
            out.append(
                Observation(
                    policy="k8s-dashboard-public-service",
                    provider=PROVIDER,
                    resource=_name(service),
                    title=f"Kubernetes Dashboard service is externally published: {_name(service)}",
                    detail=(
                        f"service {_name(service)} of type {service_type} fronts the "
                        "Kubernetes Dashboard, so it is reachable from outside the cluster"
                    ),
                    observed={"type": service_type, "dashboard": name},
                    severity="high",
                    exchanges=exchanges_of(reply),
                )
            )
        return out


# --------------------------------------------------------------------------- kubelet
class K8sKubeletAnonymousAuth(_K8sCheck, Module):
    """``m5.k8s-kubelet-anonymous-auth`` — a kubelet that answers anonymous requests."""

    area = "kubelet"
    reads = (_NODES, _NODE_KUBELET_CONFIG)
    metadata = posture_metadata(
        name="k8s-kubelet-anonymous-auth",
        title="Kubelet allows anonymous requests or serves the read-only port",
        description=(
            "Lists the cluster's nodes and reads each kubelet's own configuration through the "
            "API server's node proxy; reports a node whose authentication.anonymous.enabled is "
            "true or whose readOnlyPort is set, because the kubelet then answers unauthenticated "
            "requests for its pod list, pod specs and statistics. Read-only: listNodes and "
            "getNodeProxyConfigz."
        ),
        research_ref="ch05#13",
        cwe="CWE-306",
        framework=("WSTG-CONF-02", "API8:2023", "CWE-306"),
        compliance=("CIS-5.1", "ISO-A.8.5", "CSF-PR.AA-05", "PCI-7"),
        severity="high",
        estimated_requests=5,
    )

    async def evaluate(self, ctx: CheckContext, client: CloudReadClient) -> list[Observation]:
        nodes_reply = await client.get(_NODES)
        out: list[Observation] = []
        for node in limit(ctx, items_of(nodes_reply.mapping(), "items")):
            node_name = text_of(get(node, "metadata") or {}, "name")
            if not node_name:
                continue
            config_reply = await client.get(
                _NODE_KUBELET_CONFIG, values={"node": node_name}, required=False
            )
            config = get(config_reply.mapping(), "kubeletconfig")
            config = config if isinstance(config, Mapping) else {}
            anonymous = get(config, "authentication")
            anonymous = anonymous if isinstance(anonymous, Mapping) else {}
            anonymous_setting = get(anonymous, "anonymous")
            anonymous_setting = anonymous_setting if isinstance(anonymous_setting, Mapping) else {}
            enabled = bool_of(anonymous_setting, "enabled") is True
            read_only_port = config.get("readOnlyPort") if isinstance(config, Mapping) else None
            port_set = isinstance(read_only_port, int) and read_only_port != 0
            if not enabled and not port_set:
                continue
            out.append(
                Observation(
                    policy="k8s-kubelet-anonymous-auth",
                    provider=PROVIDER,
                    resource=node_name,
                    title=f"Kubelet accepts anonymous requests: {node_name}",
                    detail=(
                        f"node {node_name}'s kubelet has "
                        f"authentication.anonymous.enabled={enabled} and "
                        f"readOnlyPort={read_only_port if port_set else 0}: unauthenticated "
                        "requests for the pod list and statistics are answered"
                    ),
                    observed={
                        "anonymousEnabled": enabled,
                        "readOnlyPort": read_only_port if port_set else 0,
                    },
                    severity="high",
                    exchanges=exchanges_of(nodes_reply, config_reply),
                )
            )
        return out


# --------------------------------------------------------------------------- admission
class K8sAdmissionWebhookFailOpen(_K8sCheck, Module):
    """``m5.k8s-admission-webhook-fail-open`` — an admission webhook that fails open."""

    area = "admission"
    reads = (_VALIDATING_WEBHOOKS,)
    metadata = posture_metadata(
        name="k8s-admission-webhook-fail-open",
        title="Kubernetes validating admission webhook fails open",
        description=(
            "Lists the cluster's validating admission webhook configurations and reports one "
            "with a webhook whose failurePolicy is Ignore: when the webhook is unreachable — "
            "the very moment it matters — the API server admits the object instead of refusing "
            "it, so the control disappears exactly when it is needed. Read-only: "
            "listValidatingWebhookConfigurations."
        ),
        research_ref="ch05#14",
        cwe="CWE-693",
        framework=("WSTG-CONF-02", "API8:2023", "CWE-693"),
        compliance=("CIS-5.1", "ISO-A.8.16", "CSF-PR.PS-04", "PCI-6"),
        severity="medium",
        estimated_requests=1,
    )

    async def evaluate(self, ctx: CheckContext, client: CloudReadClient) -> list[Observation]:
        reply = await client.get(_VALIDATING_WEBHOOKS)
        out: list[Observation] = []
        for configuration in limit(ctx, items_of(reply.mapping(), "items")):
            webhooks = get(configuration, "webhooks")
            if not isinstance(webhooks, Sequence) or isinstance(webhooks, (str, bytes)):
                continue
            failing = [
                webhook
                for webhook in webhooks
                if isinstance(webhook, Mapping)
                and text_of(webhook, "failurePolicy").lower() == "ignore"
            ]
            if not failing:
                continue
            out.append(
                Observation(
                    policy="k8s-admission-webhook-fail-open",
                    provider=PROVIDER,
                    resource=_name(configuration),
                    title=f"Admission webhook fails open: {_name(configuration)}",
                    detail=(
                        f"webhook configuration {_name(configuration)} declares "
                        f"failurePolicy=Ignore on {len(failing)} webhook(s): an unreachable "
                        "webhook admits the object rather than refusing it"
                    ),
                    observed={
                        "webhooks": [text_of(webhook, "name") or "unnamed" for webhook in failing],
                        "failurePolicy": "Ignore",
                    },
                    severity="medium",
                    exchanges=exchanges_of(reply),
                )
            )
        return out


# --------------------------------------------------------------------------- the family
K8S_POSTURE_CHECKS: tuple[type[Module], ...] = (
    K8sRbacWildcardClusterRole,
    K8sRbacClusterAdminBinding,
    K8sRbacSecretsExposed,
    K8sApiAnonymousBinding,
    K8sPodPrivileged,
    K8sPodHostPath,
    K8sDashboardPublicService,
    K8sKubeletAnonymousAuth,
    K8sAdmissionWebhookFailOpen,
)


def k8s_checks() -> tuple[type[Module], ...]:
    return K8S_POSTURE_CHECKS


def service_areas() -> dict[str, str]:
    """``check name -> scope area`` from the module's own declaration (the test reads this)."""
    return {check.metadata.name: str(getattr(check, "area", "")) for check in K8S_POSTURE_CHECKS}
