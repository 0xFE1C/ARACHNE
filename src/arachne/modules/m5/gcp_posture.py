"""WP-32 · GCP read-only service posture (REQ-DET-025).

Eight read-only L1 checks over the defaults a GCP project's own read APIs disclose. The
requirement's scope names GCP object storage, GKE, IAM, Cloud SQL and functions; this module
covers each:

============================  ==========================================================
area                            checks
============================  ==========================================================
object storage (2)              a bucket whose public-access prevention is not enforced, one
                                without uniform bucket-level access
GKE (2)                         a cluster with no master authorized networks (a public
                                control plane), one with cluster logging disabled
IAM (1)                         a service account that still has user-managed keys
Cloud SQL (2)                   an instance with a public IPv4 address, one that does not
                                require SSL
Cloud Functions (1)             a function whose ingress settings allow every source
============================  ==========================================================

**Read-only is the control, and it is a closed allowlist.** Every call this module can make is
one entry of :data:`GCP_READ_OPERATIONS` — a frozen tuple of ``GET`` records. The read surface
these checks need is entirely ``GET``, so the method is closed too: GCP's ``getIamPolicy`` and
``listServiceAccountKeys`` read verbs that *are* ``POST`` in the real API are deliberately not
in the table, and the checks that would have needed them read RBAC-adjacent metadata through a
``GET`` list instead. The operation object is the parameter: the client refuses one that is not
a table entry, so a call the family did not declare is unrepresentable.

**No key material is ever read.** The IAM check lists **service-account key metadata** — the
key's name, type and validity window, which the API returns without ``privateKeyData`` — and
establishes that a user-managed key *exists and is stale*. It never asks for a key's private
material, and the module contains no operation that could: there is no ``get`` entry for a key
in the table.

**The endpoint is declared, not guessed.** The target reference is ``gcp-posture:<base>`` and
``<base>`` is the read-only API base the operator's least-privilege credential is scoped to.
The project id every path carries comes from ``ARACHNE_M5_GCP_PROJECT_ID``; with none declared
the checks skip rather than guess one.

**Credentials come from the vault and never cross the module boundary.** A check declares
``requires_credentials=("cloud-token",)`` and calls the broker, which injects the bearer token
into one request and hands back a redacted exchange; no finding or audit record carries it.
"""

from __future__ import annotations

from collections.abc import Mapping
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
    str_of,
    text_of,
)
from arachne.modules.m5.support import EndpointCheck

__all__ = ["GCP_POSTURE_CHECKS", "GCP_READ_OPERATIONS", "gcp_checks", "service_areas"]

REFERENCES: Final[tuple[str, ...]] = ("gcp-posture", "gcpposture")
FAMILY: Final = "gcp-posture"
PROVIDER: Final = "gcp"


# --------------------------------------------------------------------------- operations
_BUCKETS = CloudReadOperation(
    action="listBuckets",
    path="/storage/v1/b",
    query=(("project", "{project}"),),
)
_CLUSTERS = CloudReadOperation(
    action="listClusters",
    path="/container/v1/projects/{project}/locations/-/clusters",
)
_SERVICE_ACCOUNTS = CloudReadOperation(
    action="listServiceAccounts",
    path="/v1/projects/{project}/serviceAccounts",
)
_SERVICE_ACCOUNT_KEYS = CloudReadOperation(
    action="listServiceAccountKeys",
    path="/v1/projects/{project}/serviceAccounts/{account}/keys",
)
_SQL_INSTANCES = CloudReadOperation(
    action="listSqlInstances",
    path="/sql/v1beta4/projects/{project}/instances",
)
_FUNCTIONS = CloudReadOperation(
    action="listFunctions",
    path="/v1/projects/{project}/locations/-/functions",
)

#: **The operation allowlist.** Every GCP call this module can make is one entry here.
GCP_READ_OPERATIONS: Final[tuple[CloudReadOperation, ...]] = (
    _BUCKETS,
    _CLUSTERS,
    _SERVICE_ACCOUNTS,
    _SERVICE_ACCOUNT_KEYS,
    _SQL_INSTANCES,
    _FUNCTIONS,
)


# --------------------------------------------------------------------------- base check
class _GcpCheck(PostureCheck, EndpointCheck):
    """The family's shared shape: the reference, the allowlist and the configured project."""

    references = REFERENCES
    family = FAMILY
    provider = PROVIDER
    operations = GCP_READ_OPERATIONS

    def identity(self, ctx: CheckContext) -> tuple[dict[str, str], str | None]:
        project = ctx.config.m5.gcp_project_id.strip()
        if not project:
            return {}, (
                "no GCP project declared: set ARACHNE_M5_GCP_PROJECT_ID (every GCP path is "
                "scoped to it; the checks never guess one)"
            )
        return {"project": project}, None


def _name(resource: Mapping[str, Any]) -> str:
    name = resource.get("name")
    if isinstance(name, str) and name:
        return name
    return "unnamed"


# --------------------------------------------------------------------------- object storage
class GcpGcsPublicPreventionOff(_GcpCheck, Module):
    """``m5.gcp-gcs-public-prevention-off`` — a bucket that may be made public."""

    area = "storage"
    reads = (_BUCKETS,)
    metadata = posture_metadata(
        name="gcp-gcs-public-prevention-off",
        title="GCS bucket does not enforce public access prevention",
        description=(
            "Lists the project's buckets and reports one whose "
            "iamConfiguration.publicAccessPrevention is not enforced: the bucket-level "
            "override that would refuse an allUsers or allAuthenticatedUsers grant is off, so "
            "an IAM change alone can make the objects world-readable. Read-only: listBuckets."
        ),
        research_ref="ch05#2",
        cwe="CWE-732",
        framework=("WSTG-CONF-11", "API8:2023", "CWE-732"),
        compliance=("CIS-3.3", "ISO-A.5.23", "ISO-A.8.3", "CSF-PR.DS-01", "PCI-3"),
        severity="high",
        estimated_requests=1,
    )

    async def evaluate(self, ctx: CheckContext, client: CloudReadClient) -> list[Observation]:
        reply = await client.get(_BUCKETS)
        out: list[Observation] = []
        for bucket in limit(ctx, items_of(reply.mapping(), "items")):
            iam = get(bucket, "iamConfiguration")
            iam = iam if isinstance(iam, Mapping) else {}
            prevention = text_of(iam, "publicAccessPrevention")
            if prevention.lower() == "enforced":
                continue
            name = _name(bucket)
            out.append(
                Observation(
                    policy="gcp-gcs-public-prevention-off",
                    provider=PROVIDER,
                    resource=name,
                    title=f"GCS bucket does not enforce public access prevention: {name}",
                    detail=(
                        f"bucket {name} has publicAccessPrevention="
                        f"{prevention or 'unset'}: a public IAM grant would not be refused"
                    ),
                    observed={"publicAccessPrevention": prevention or None},
                    severity="high",
                    exchanges=exchanges_of(reply),
                )
            )
        return out


class GcpGcsUniformAccessOff(_GcpCheck, Module):
    """``m5.gcp-gcs-uniform-access-off`` — a bucket without uniform access."""

    area = "storage"
    reads = (_BUCKETS,)
    metadata = posture_metadata(
        name="gcp-gcs-uniform-access-off",
        title="GCS bucket does not use uniform bucket-level access",
        description=(
            "Lists the project's buckets and reports one whose "
            "iamConfiguration.uniformBucketLevelAccess.enabled is false: per-object ACLs are "
            "in force, so an object can be shared with the world even when the bucket's IAM "
            "policy says otherwise, and no single policy describes who can read the data. "
            "Read-only: listBuckets."
        ),
        research_ref="ch05#2",
        cwe="CWE-284",
        framework=("WSTG-CONF-02", "API8:2023", "CWE-284"),
        compliance=("CIS-3.3", "ISO-A.5.15", "CSF-PR.AA-05", "PCI-7"),
        severity="medium",
        estimated_requests=1,
    )

    async def evaluate(self, ctx: CheckContext, client: CloudReadClient) -> list[Observation]:
        reply = await client.get(_BUCKETS)
        out: list[Observation] = []
        for bucket in limit(ctx, items_of(reply.mapping(), "items")):
            iam = get(bucket, "iamConfiguration")
            iam = iam if isinstance(iam, Mapping) else {}
            uniform = get(iam, "uniformBucketLevelAccess")
            uniform = uniform if isinstance(uniform, Mapping) else {}
            if bool_of(uniform, "enabled") is not False:
                continue
            name = _name(bucket)
            out.append(
                Observation(
                    policy="gcp-gcs-uniform-access-off",
                    provider=PROVIDER,
                    resource=name,
                    title=f"GCS bucket uses per-object ACLs: {name}",
                    detail=(
                        f"bucket {name} has uniformBucketLevelAccess.enabled=false: object ACLs "
                        "decide access, outside the bucket's IAM policy"
                    ),
                    observed={"uniformBucketLevelAccess": False},
                    severity="medium",
                    exchanges=exchanges_of(reply),
                )
            )
        return out


# --------------------------------------------------------------------------- GKE
class GcpGkePublicControlPlane(_GcpCheck, Module):
    """``m5.gcp-gke-public-control-plane`` — a cluster with a public API server."""

    area = "gke"
    reads = (_CLUSTERS,)
    metadata = posture_metadata(
        name="gcp-gke-public-control-plane",
        title="GKE cluster exposes its control plane to the internet",
        description=(
            "Lists the project's GKE clusters and reports one whose "
            "masterAuthorizedNetworksConfig is not enabled and which is not a private "
            "cluster: the Kubernetes control plane then accepts connections from any source "
            "that can route to its address. Read-only: listClusters."
        ),
        research_ref="ch05#13",
        cwe="CWE-284",
        framework=("WSTG-CONF-02", "API8:2023", "CWE-284"),
        compliance=("CIS-4.1", "ISO-A.8.20", "CSF-PR.AA-05", "PCI-1"),
        severity="high",
        estimated_requests=1,
    )

    async def evaluate(self, ctx: CheckContext, client: CloudReadClient) -> list[Observation]:
        reply = await client.get(_CLUSTERS)
        out: list[Observation] = []
        for cluster in limit(ctx, items_of(reply.mapping(), "clusters")):
            networks = get(cluster, "masterAuthorizedNetworksConfig")
            networks = networks if isinstance(networks, Mapping) else {}
            private = get(cluster, "privateClusterConfig")
            private = private if isinstance(private, Mapping) else {}
            restricted = bool_of(networks, "enabled") is True
            private_nodes = bool_of(private, "enablePrivateNodes") is True
            if restricted or private_nodes:
                continue
            name = _name(cluster)
            out.append(
                Observation(
                    policy="gcp-gke-public-control-plane",
                    provider=PROVIDER,
                    resource=name,
                    title=f"GKE cluster has a public control plane: {name}",
                    detail=(
                        f"cluster {name} has no master authorized networks and no private "
                        "nodes: its API server address is reachable from the internet"
                    ),
                    observed={
                        "masterAuthorizedNetworksConfig": {"enabled": False},
                        "enablePrivateNodes": False,
                    },
                    severity="high",
                    exchanges=exchanges_of(reply),
                )
            )
        return out


class GcpGkeLoggingDisabled(_GcpCheck, Module):
    """``m5.gcp-gke-logging-disabled`` — a cluster with its audit logging switched off."""

    area = "gke"
    reads = (_CLUSTERS,)
    metadata = posture_metadata(
        name="gcp-gke-logging-disabled",
        title="GKE cluster has Cloud Logging disabled",
        description=(
            "Lists the project's GKE clusters and reports one whose loggingService is none: "
            "the control-plane and workload events a GKE cluster normally ships to Cloud "
            "Logging are discarded, so an audit of what the cluster did is impossible. "
            "Read-only: listClusters."
        ),
        research_ref="ch05#10",
        cwe="CWE-778",
        framework=("WSTG-CONF-02", "API8:2023", "CWE-778"),
        compliance=("CIS-8.2", "ISO-A.8.15", "CSF-PR.PS-01", "PCI-10"),
        severity="medium",
        estimated_requests=1,
    )

    async def evaluate(self, ctx: CheckContext, client: CloudReadClient) -> list[Observation]:
        reply = await client.get(_CLUSTERS)
        out: list[Observation] = []
        for cluster in limit(ctx, items_of(reply.mapping(), "clusters")):
            logging = text_of(cluster, "loggingService")
            if logging and logging.lower() != "none":
                continue
            name = _name(cluster)
            out.append(
                Observation(
                    policy="gcp-gke-logging-disabled",
                    provider=PROVIDER,
                    resource=name,
                    title=f"GKE cluster has Cloud Logging disabled: {name}",
                    detail=(
                        f"cluster {name} has loggingService={logging or 'unset'}: no "
                        "control-plane or workload logs are shipped"
                    ),
                    observed={"loggingService": logging or None},
                    severity="medium",
                    exchanges=exchanges_of(reply),
                )
            )
        return out


# --------------------------------------------------------------------------- IAM
class GcpIamSaUserKeys(_GcpCheck, Module):
    """``m5.gcp-iam-sa-user-keys`` — service accounts with long-lived key material."""

    area = "iam"
    reads = (_SERVICE_ACCOUNTS, _SERVICE_ACCOUNT_KEYS)
    metadata = posture_metadata(
        name="gcp-iam-sa-user-keys",
        title="GCP service account has user-managed keys",
        description=(
            "Lists the project's service accounts and, for each, reads the key *metadata* the "
            "API returns without any private material; reports an account with a USER_MANAGED "
            "key — a long-lived credential that survives the principal's deletion and has to "
            "be rotated by hand, unlike a short-lived token. The check never requests a key's "
            "private material. Read-only: listServiceAccounts and listServiceAccountKeys."
        ),
        research_ref="ch05#6",
        cwe="CWE-522",
        framework=("WSTG-CONF-02", "API8:2023", "CWE-522"),
        compliance=("CIS-1.4", "ISO-A.5.17", "CSF-PR.AA-05", "PCI-8"),
        severity="high",
        estimated_requests=5,
    )

    async def evaluate(self, ctx: CheckContext, client: CloudReadClient) -> list[Observation]:
        reply = await client.get(_SERVICE_ACCOUNTS)
        out: list[Observation] = []
        for account in limit(ctx, items_of(reply.mapping(), "accounts")):
            email = text_of(account, "email")
            if not email:
                continue
            keys = await client.get(
                _SERVICE_ACCOUNT_KEYS, values={"account": email}, required=False
            )
            user_keys = [
                key
                for key in items_of(keys.mapping(), "keys")
                if text_of(key, "keyType").upper() == "USER_MANAGED"
            ]
            if not user_keys:
                continue
            out.append(
                Observation(
                    policy="gcp-iam-sa-user-keys",
                    provider=PROVIDER,
                    resource=email,
                    title=f"GCP service account has user-managed keys: {email}",
                    detail=(
                        f"service account {email} has {len(user_keys)} user-managed key(s); "
                        "each is a long-lived credential that must be rotated by hand"
                    ),
                    observed={
                        "keyType": "USER_MANAGED",
                        "keyCount": len(user_keys),
                        "oldestKey": _oldest(user_keys),
                    },
                    severity="high",
                    exchanges=exchanges_of(reply, keys),
                )
            )
        return out


def _oldest(keys: list[Mapping[str, Any]]) -> str | None:
    """The earliest ``validAfterTime`` among a set of key metadata records, as text."""
    times = sorted(str_of(key, "validAfterTime") or "" for key in keys)
    return times[0] if times and times[0] else None


# --------------------------------------------------------------------------- Cloud SQL
class GcpSqlPublicIp(_GcpCheck, Module):
    """``m5.gcp-sql-public-ip`` — a Cloud SQL instance with a public IPv4 address."""

    area = "sql"
    reads = (_SQL_INSTANCES,)
    metadata = posture_metadata(
        name="gcp-sql-public-ip",
        title="Cloud SQL instance has a public IPv4 address",
        description=(
            "Lists the project's Cloud SQL instances and reports one whose "
            "settings.ipConfiguration.ipv4Enabled is true and which declares fewer than two "
            "authorized networks (never the full address space): the instance's address is "
            "reachable from the internet rather than only from the declared networks. "
            "Read-only: listSqlInstances."
        ),
        research_ref="ch05#20",
        cwe="CWE-284",
        framework=("WSTG-CONF-02", "API8:2023", "CWE-284"),
        compliance=("CIS-4.1", "ISO-A.8.20", "CSF-PR.AA-05", "PCI-1"),
        severity="high",
        estimated_requests=1,
    )

    async def evaluate(self, ctx: CheckContext, client: CloudReadClient) -> list[Observation]:
        reply = await client.get(_SQL_INSTANCES)
        out: list[Observation] = []
        for instance in limit(ctx, items_of(reply.mapping(), "items")):
            settings = get(instance, "settings")
            settings = settings if isinstance(settings, Mapping) else {}
            ip_configuration = get(settings, "ipConfiguration")
            ip_configuration = ip_configuration if isinstance(ip_configuration, Mapping) else {}
            if bool_of(ip_configuration, "ipv4Enabled") is not True:
                continue
            authorized = [
                text_of(network, "value")
                for network in items_of(get(ip_configuration, "authorizedNetworks"))
            ]
            if authorized and all(value not in {"0.0.0.0/0", ""} for value in authorized):
                continue
            name = text_of(instance, "name") or _name(instance)
            out.append(
                Observation(
                    policy="gcp-sql-public-ip",
                    provider=PROVIDER,
                    resource=name,
                    title=f"Cloud SQL instance has a public IP address: {name}",
                    detail=(
                        f"instance {name} has ipv4Enabled=true with "
                        f"{len(authorized)} authorized network(s): its address is reachable "
                        "from the internet"
                    ),
                    observed={
                        "ipv4Enabled": True,
                        "authorizedNetworks": authorized,
                    },
                    severity="high",
                    exchanges=exchanges_of(reply),
                )
            )
        return out


class GcpSqlSslNotRequired(_GcpCheck, Module):
    """``m5.gcp-sql-ssl-not-required`` — a Cloud SQL instance that accepts plaintext."""

    area = "sql"
    reads = (_SQL_INSTANCES,)
    metadata = posture_metadata(
        name="gcp-sql-ssl-not-required",
        title="Cloud SQL instance does not require an encrypted connection",
        description=(
            "Lists the project's Cloud SQL instances and reports one whose "
            "settings.ipConfiguration.requireSsl is false: a client may connect without TLS, "
            "so credentials and query results can cross the network in the clear. Read-only: "
            "listSqlInstances."
        ),
        research_ref="ch05#20",
        cwe="CWE-319",
        framework=("WSTG-CONF-01", "API8:2023", "CWE-319"),
        compliance=("ISO-A.8.24", "CSF-PR.DS-01", "PCI-4"),
        severity="medium",
        estimated_requests=1,
    )

    async def evaluate(self, ctx: CheckContext, client: CloudReadClient) -> list[Observation]:
        reply = await client.get(_SQL_INSTANCES)
        out: list[Observation] = []
        for instance in limit(ctx, items_of(reply.mapping(), "items")):
            settings = get(instance, "settings")
            settings = settings if isinstance(settings, Mapping) else {}
            ip_configuration = get(settings, "ipConfiguration")
            ip_configuration = ip_configuration if isinstance(ip_configuration, Mapping) else {}
            if bool_of(ip_configuration, "requireSsl") is not False:
                continue
            name = text_of(instance, "name") or _name(instance)
            out.append(
                Observation(
                    policy="gcp-sql-ssl-not-required",
                    provider=PROVIDER,
                    resource=name,
                    title=f"Cloud SQL instance does not require TLS: {name}",
                    detail=(
                        f"instance {name} has requireSsl=false: an unencrypted connection is "
                        "accepted"
                    ),
                    observed={"requireSsl": False},
                    severity="medium",
                    exchanges=exchanges_of(reply),
                )
            )
        return out


# --------------------------------------------------------------------------- Cloud Functions
class GcpFunctionPublicIngress(_GcpCheck, Module):
    """``m5.gcp-function-public-ingress`` — a function reachable from any source."""

    area = "functions"
    reads = (_FUNCTIONS,)
    metadata = posture_metadata(
        name="gcp-function-public-ingress",
        title="Cloud Function allows ingress from every source",
        description=(
            "Lists the project's Cloud Functions and reports one whose ingressSettings is "
            "ALLOW_ALL: the function's endpoint accepts requests from the internet, not only "
            "from the project's own networks or the load balancer, so its own IAM check is the "
            "only control left in front of it. Read-only: listFunctions."
        ),
        research_ref="ch05#9",
        cwe="CWE-284",
        framework=("WSTG-CONF-02", "API8:2023", "CWE-284"),
        compliance=("CIS-4.1", "ISO-A.8.20", "CSF-PR.AA-05", "PCI-1"),
        severity="high",
        estimated_requests=1,
    )

    async def evaluate(self, ctx: CheckContext, client: CloudReadClient) -> list[Observation]:
        reply = await client.get(_FUNCTIONS)
        out: list[Observation] = []
        for function in limit(ctx, items_of(reply.mapping(), "functions")):
            ingress = text_of(function, "ingressSettings")
            if ingress.upper() != "ALLOW_ALL":
                continue
            name = text_of(function, "name") or _name(function)
            out.append(
                Observation(
                    policy="gcp-function-public-ingress",
                    provider=PROVIDER,
                    resource=name,
                    title=f"Cloud Function allows ingress from every source: {name}",
                    detail=(
                        f"function {name} has ingressSettings=ALLOW_ALL: the endpoint accepts "
                        "requests from the public internet"
                    ),
                    observed={"ingressSettings": ingress},
                    severity="high",
                    exchanges=exchanges_of(reply),
                )
            )
        return out


# --------------------------------------------------------------------------- the family
GCP_POSTURE_CHECKS: tuple[type[Module], ...] = (
    GcpGcsPublicPreventionOff,
    GcpGcsUniformAccessOff,
    GcpGkePublicControlPlane,
    GcpGkeLoggingDisabled,
    GcpIamSaUserKeys,
    GcpSqlPublicIp,
    GcpSqlSslNotRequired,
    GcpFunctionPublicIngress,
)


def gcp_checks() -> tuple[type[Module], ...]:
    return GCP_POSTURE_CHECKS


def service_areas() -> dict[str, str]:
    """``check name -> scope area`` from the module's own declaration (the test reads this)."""
    return {check.metadata.name: str(getattr(check, "area", "")) for check in GCP_POSTURE_CHECKS}
