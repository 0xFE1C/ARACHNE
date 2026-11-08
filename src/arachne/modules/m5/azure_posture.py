"""WP-32 · Azure read-only service posture (REQ-DET-025).

Eleven read-only L1 checks over the defaults an Azure subscription's own read APIs disclose.
The requirement's scope names Azure storage, AKS, Key Vault, App Service, network security
groups and SQL; this module covers each:

============================  ==========================================================
area                            checks
============================  ==========================================================
storage (3)                     a storage account that permits anonymous blob access, one
                                that still accepts TLS 1.0/1.1, one whose network ACL
                                default action is Allow
network security group (2)      an inbound rule that admits SSH, and one that admits RDP,
                                from any source
Key Vault (2)                   a vault reachable from the public internet, one without
                                purge protection (so a deleted vault's secret material can
                                never be recovered or, worse, is purged for good)
SQL (1)                         a SQL server with public network access enabled
AKS (2)                         a cluster whose API server is not private, one with
                                Kubernetes RBAC disabled
App Service (1)                 a web app that does not force HTTPS
============================  ==========================================================

**Read-only is the control, and it is a closed allowlist.** Every call this module can make is
one entry of :data:`AZURE_READ_OPERATIONS` — a frozen tuple of ``GET`` records. The operation
object is the parameter: :meth:`~arachne.modules.m5.posture_read.CloudReadClient.get` refuses
an object that is not a table entry, and
:class:`~arachne.modules.m5.posture_read.CloudReadOperation` refuses a non-``GET`` method, a
relative path or a mutation verb at construction, so an account-changing call is
unrepresentable rather than merely untested.

**The endpoint is declared, not guessed.** The target reference is ``azure-posture:<base>`` and
``<base>`` is the read-only ARM base the operator's least-privilege credential is scoped to
(``https://management.azure.com`` in a real subscription). The subscription id every ARM path
carries comes from ``ARACHNE_M5_AZURE_SUBSCRIPTION_ID``; with none declared the checks skip
rather than guess one. The checks join ``/subscriptions/{subscription}/providers/...`` onto the
base and issue only the ``GET`` operations the table holds.

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

__all__ = ["AZURE_POSTURE_CHECKS", "AZURE_READ_OPERATIONS", "azure_checks", "service_areas"]

#: The reference prefixes this family accepts.
REFERENCES: Final[tuple[str, ...]] = ("azure-posture", "azureposture")
#: The family tag and signal every finding carries.
FAMILY: Final = "azure-posture"
PROVIDER: Final = "azure"
_API: Final = ("api-version",)

#: The open source prefixes an NSG rule that admits the whole internet. ``Internet`` is ARM's
#: own service tag for it; the address forms are the other spellings of the same thing.
_OPEN_SOURCES: Final[frozenset[str]] = frozenset({"*", "0.0.0.0/0", "::/0", "internet", "any"})
_SSH_PORTS: Final[frozenset[str]] = frozenset({"22", "22-22", "*", "0-65535"})
_RDP_PORTS: Final[frozenset[str]] = frozenset({"3389", "3389-3389", "*", "0-65535"})
_WEAK_TLS: Final[frozenset[str]] = frozenset({"tls1_0", "tls1_1", "tls_1_0", "tls_1_1"})


# --------------------------------------------------------------------------- operations
#: Every ARM path is scoped to the operator's subscription; the ``{subscription}`` placeholder
#: is filled from ``ARACHNE_M5_AZURE_SUBSCRIPTION_ID`` (never guessed).
_STORAGE_ACCOUNTS = CloudReadOperation(
    action="listStorageAccounts",
    path="/subscriptions/{subscription}/providers/Microsoft.Storage/storageAccounts",
    query=(("api-version", "2023-05-01"),),
)
_NETWORK_SECURITY_GROUPS = CloudReadOperation(
    action="listNetworkSecurityGroups",
    path="/subscriptions/{subscription}/providers/Microsoft.Network/networkSecurityGroups",
    query=(("api-version", "2023-09-01"),),
)
_KEY_VAULTS = CloudReadOperation(
    action="listKeyVaults",
    path="/subscriptions/{subscription}/providers/Microsoft.KeyVault/vaults",
    query=(("api-version", "2023-07-01"),),
)
_SQL_SERVERS = CloudReadOperation(
    action="listSqlServers",
    path="/subscriptions/{subscription}/providers/Microsoft.Sql/servers",
    query=(("api-version", "2022-05-01-preview"),),
)
_AKS_CLUSTERS = CloudReadOperation(
    action="listManagedClusters",
    path="/subscriptions/{subscription}/providers/Microsoft.ContainerService/managedClusters",
    query=(("api-version", "2023-08-01"),),
)
_WEB_APPS = CloudReadOperation(
    action="listWebApps",
    path="/subscriptions/{subscription}/providers/Microsoft.Web/sites",
    query=(("api-version", "2023-01-01"),),
)

#: **The operation allowlist.** Every Azure call this module can make is one entry here; the
#: client refuses an object that is not equal to one of them, and each entry refused a
#: mutation action name and a non-``GET`` method at construction.
AZURE_READ_OPERATIONS: Final[tuple[CloudReadOperation, ...]] = (
    _STORAGE_ACCOUNTS,
    _NETWORK_SECURITY_GROUPS,
    _KEY_VAULTS,
    _SQL_SERVERS,
    _AKS_CLUSTERS,
    _WEB_APPS,
)


# --------------------------------------------------------------------------- base check
class _AzureCheck(PostureCheck, EndpointCheck):
    """The family's shared shape: the reference, the allowlist and the configured identity."""

    references = REFERENCES
    family = FAMILY
    provider = PROVIDER
    operations = AZURE_READ_OPERATIONS

    def identity(self, ctx: CheckContext) -> tuple[dict[str, str], str | None]:
        subscription = ctx.config.m5.azure_subscription_id.strip()
        if not subscription:
            return {}, (
                "no Azure subscription declared: set ARACHNE_M5_AZURE_SUBSCRIPTION_ID (the "
                "ARM paths are scoped to it; the checks never guess one)"
            )
        return {"subscription": subscription}, None


def _properties(resource: Mapping[str, Any]) -> Mapping[str, Any]:
    """One ARM resource's ``properties`` block (``{}`` when it is absent)."""
    value = resource.get("properties")
    return value if isinstance(value, Mapping) else {}


def _resource_name(resource: Mapping[str, Any]) -> str:
    name = resource.get("name")
    return str(name) if isinstance(name, str) and name else "unnamed"


# --------------------------------------------------------------------------- storage
class AzureStoragePublicBlob(_AzureCheck, Module):
    """``m5.azure-storage-public-blob`` — a storage account that allows anonymous blob access."""

    area = "storage"
    reads = (_STORAGE_ACCOUNTS,)
    metadata = posture_metadata(
        name="azure-storage-public-blob",
        title="Azure storage account permits anonymous blob access",
        description=(
            "Lists the subscription's storage accounts and reports one whose "
            "properties.allowBlobPublicAccess is true: every container in the account may then "
            "be exposed to anonymous read by its own access level, so the account-level "
            "switch that would stop it is off. Read-only: listStorageAccounts."
        ),
        research_ref="ch05#2",
        cwe="CWE-732",
        framework=("WSTG-CONF-11", "API8:2023", "CWE-732"),
        compliance=("CIS-3.3", "ISO-A.5.23", "ISO-A.8.3", "CSF-PR.DS-01", "PCI-3"),
        severity="high",
        estimated_requests=1,
    )

    async def evaluate(self, ctx: CheckContext, client: CloudReadClient) -> list[Observation]:
        reply = await client.get(_STORAGE_ACCOUNTS)
        out: list[Observation] = []
        for account in limit(ctx, items_of(reply.mapping())):
            properties = _properties(account)
            if bool_of(properties, "allowBlobPublicAccess") is not True:
                continue
            name = _resource_name(account)
            out.append(
                Observation(
                    policy="azure-storage-public-blob",
                    provider=PROVIDER,
                    resource=name,
                    title=f"Azure storage account permits anonymous blob access: {name}",
                    detail=(
                        f"storage account {name} has allowBlobPublicAccess=true, so a "
                        "container set to public access is readable by anyone"
                    ),
                    observed={"allowBlobPublicAccess": True},
                    severity="high",
                    exchanges=exchanges_of(reply),
                )
            )
        return out


class AzureStorageMinTls(_AzureCheck, Module):
    """``m5.azure-storage-min-tls`` — a storage account that still accepts TLS 1.0/1.1."""

    area = "storage"
    reads = (_STORAGE_ACCOUNTS,)
    metadata = posture_metadata(
        name="azure-storage-min-tls",
        title="Azure storage account accepts TLS 1.0 or 1.1",
        description=(
            "Lists the subscription's storage accounts and reports one whose "
            "properties.minimumTlsVersion is not TLS1_2: the endpoint still negotiates a "
            "protocol version deprecated for its known weaknesses. Read-only: "
            "listStorageAccounts."
        ),
        research_ref="ch05#2",
        cwe="CWE-326",
        framework=("WSTG-CONF-01", "API8:2023", "CWE-326"),
        compliance=("ISO-A.8.24", "CSF-PR.DS-01", "PCI-4"),
        severity="medium",
        estimated_requests=1,
    )

    async def evaluate(self, ctx: CheckContext, client: CloudReadClient) -> list[Observation]:
        reply = await client.get(_STORAGE_ACCOUNTS)
        out: list[Observation] = []
        for account in limit(ctx, items_of(reply.mapping())):
            version = str_of(_properties(account), "minimumTlsVersion")
            if version is None or version.lower() not in _WEAK_TLS:
                continue
            name = _resource_name(account)
            out.append(
                Observation(
                    policy="azure-storage-min-tls",
                    provider=PROVIDER,
                    resource=name,
                    title=f"Azure storage account accepts a deprecated TLS version: {name}",
                    detail=(
                        f"storage account {name} has minimumTlsVersion={version}; TLS 1.2 is "
                        "the floor a hardened account sets"
                    ),
                    observed={"minimumTlsVersion": version},
                    severity="medium",
                    exchanges=exchanges_of(reply),
                )
            )
        return out


class AzureStoragePublicNetwork(_AzureCheck, Module):
    """``m5.azure-storage-public-network`` — a storage account open to every network."""

    area = "storage"
    reads = (_STORAGE_ACCOUNTS,)
    metadata = posture_metadata(
        name="azure-storage-public-network",
        title="Azure storage account default network action allows all networks",
        description=(
            "Lists the subscription's storage accounts and reports one whose "
            "properties.networkAcls.defaultAction is Allow: the firewall is not restricting "
            "traffic to declared virtual networks or addresses, so the account is reachable "
            "from any source the credential rules permit. Read-only: listStorageAccounts."
        ),
        research_ref="ch05#18",
        cwe="CWE-284",
        framework=("WSTG-CONF-02", "API8:2023", "CWE-284"),
        compliance=("CIS-3.7", "ISO-A.8.20", "CSF-PR.AA-05", "PCI-1"),
        severity="medium",
        estimated_requests=1,
    )

    async def evaluate(self, ctx: CheckContext, client: CloudReadClient) -> list[Observation]:
        reply = await client.get(_STORAGE_ACCOUNTS)
        out: list[Observation] = []
        for account in limit(ctx, items_of(reply.mapping())):
            network_acls = get(_properties(account), "networkAcls")
            default_action = text_of(network_acls, "defaultAction") if network_acls else ""
            if default_action.lower() != "allow":
                continue
            name = _resource_name(account)
            out.append(
                Observation(
                    policy="azure-storage-public-network",
                    provider=PROVIDER,
                    resource=name,
                    title=f"Azure storage account firewall allows all networks: {name}",
                    detail=(
                        f"storage account {name} has networkAcls.defaultAction=Allow: no "
                        "virtual-network or address restriction is in force"
                    ),
                    observed={"defaultAction": default_action},
                    severity="medium",
                    exchanges=exchanges_of(reply),
                )
            )
        return out


# --------------------------------------------------------------------------- network (NSG)
class AzureNsgOpenSsh(_AzureCheck, Module):
    """``m5.azure-nsg-open-ssh`` — a security rule that admits SSH from the internet."""

    area = "nsg"
    reads = (_NETWORK_SECURITY_GROUPS,)
    metadata = posture_metadata(
        name="azure-nsg-open-ssh",
        title="Azure network security group admits SSH from any source",
        description=(
            "Lists the subscription's network security groups and reports an inbound Allow "
            "rule whose destination port range is 22 and whose source is the internet "
            "(*, 0.0.0.0/0, ::/0 or the Internet service tag). Read-only: "
            "listNetworkSecurityGroups."
        ),
        research_ref="ch05#18",
        cwe="CWE-284",
        framework=("WSTG-CONF-02", "API8:2023", "CWE-284"),
        compliance=("CIS-4.1", "ISO-A.8.20", "CSF-PR.AA-05", "PCI-1"),
        severity="high",
        estimated_requests=1,
    )

    async def evaluate(self, ctx: CheckContext, client: CloudReadClient) -> list[Observation]:
        return await _open_port_observations(
            ctx, client, ports=_SSH_PORTS, service="SSH", policy="azure-nsg-open-ssh"
        )


class AzureNsgOpenRdp(_AzureCheck, Module):
    """``m5.azure-nsg-open-rdp`` — a security rule that admits RDP from the internet."""

    area = "nsg"
    reads = (_NETWORK_SECURITY_GROUPS,)
    metadata = posture_metadata(
        name="azure-nsg-open-rdp",
        title="Azure network security group admits RDP from any source",
        description=(
            "Lists the subscription's network security groups and reports an inbound Allow "
            "rule whose destination port range is 3389 and whose source is the internet "
            "(*, 0.0.0.0/0, ::/0 or the Internet service tag). Read-only: "
            "listNetworkSecurityGroups."
        ),
        research_ref="ch05#18",
        cwe="CWE-284",
        framework=("WSTG-CONF-02", "API8:2023", "CWE-284"),
        compliance=("CIS-4.1", "ISO-A.8.20", "CSF-PR.AA-05", "PCI-1"),
        severity="high",
        estimated_requests=1,
    )

    async def evaluate(self, ctx: CheckContext, client: CloudReadClient) -> list[Observation]:
        return await _open_port_observations(
            ctx, client, ports=_RDP_PORTS, service="RDP", policy="azure-nsg-open-rdp"
        )


async def _open_port_observations(
    ctx: CheckContext, client: CloudReadClient, *, ports: frozenset[str], service: str, policy: str
) -> list[Observation]:
    """The inbound Allow rules in this subscription that admit ``service`` from the internet."""
    reply = await client.get(_NETWORK_SECURITY_GROUPS)
    out: list[Observation] = []
    for group in limit(ctx, items_of(reply.mapping())):
        group_name = _resource_name(group)
        rules = items_of(get(_properties(group), "securityRules"))
        for rule in rules:
            properties = _properties(rule)
            if text_of(properties, "direction").lower() != "inbound":
                continue
            if text_of(properties, "access").lower() != "allow":
                continue
            rule_ports = {
                text_of(properties, "destinationPortRange").lower(),
                *(
                    str(port).lower()
                    for port in _as_sequence(get(properties, "destinationPortRanges"))
                ),
            }
            if not (rule_ports & ports):
                continue
            sources = {
                text_of(properties, "sourceAddressPrefix").lower(),
                *(
                    str(source).lower()
                    for source in _as_sequence(get(properties, "sourceAddressPrefixes"))
                ),
            }
            if not (sources & _OPEN_SOURCES):
                continue
            out.append(
                Observation(
                    policy=policy,
                    provider=PROVIDER,
                    resource=f"{group_name}/{text_of(rule, 'name') or 'rule'}",
                    title=f"Azure NSG admits {service} from the internet: {group_name}",
                    detail=(
                        f"security rule {text_of(rule, 'name') or 'rule'} in {group_name} "
                        f"allows inbound {service} from {sorted(sources & _OPEN_SOURCES)}"
                    ),
                    observed={
                        "direction": "Inbound",
                        "access": "Allow",
                        "ports": sorted(rule_ports & ports),
                        "sources": sorted(sources & _OPEN_SOURCES),
                    },
                    severity="high",
                    exchanges=exchanges_of(reply),
                )
            )
    return out


def _as_sequence(value: Any) -> list[Any]:
    return list(value) if isinstance(value, (list, tuple)) else []


# --------------------------------------------------------------------------- Key Vault
class AzureKeyVaultPublicNetwork(_AzureCheck, Module):
    """``m5.azure-keyvault-public-network`` — a vault reachable from the public internet."""

    area = "keyvault"
    reads = (_KEY_VAULTS,)
    metadata = posture_metadata(
        name="azure-keyvault-public-network",
        title="Azure Key Vault is reachable from the public internet",
        description=(
            "Lists the subscription's Key Vaults and reports one whose "
            "properties.publicNetworkAccess is Enabled (or whose network ACL default action "
            "is Allow): the vault's keys, secrets and certificates are reachable from any "
            "source the access policy or RBAC permits, with no private endpoint in front of "
            "it. Read-only: listKeyVaults."
        ),
        research_ref="ch05#19",
        cwe="CWE-284",
        framework=("WSTG-CONF-02", "API8:2023", "CWE-284"),
        compliance=("CIS-3.7", "ISO-A.8.24", "CSF-PR.AA-05", "PCI-3"),
        severity="high",
        estimated_requests=1,
    )

    async def evaluate(self, ctx: CheckContext, client: CloudReadClient) -> list[Observation]:
        reply = await client.get(_KEY_VAULTS)
        out: list[Observation] = []
        for vault in limit(ctx, items_of(reply.mapping())):
            properties = _properties(vault)
            public = str_of(properties, "publicNetworkAccess")
            network_acls = get(properties, "networkAcls")
            default_action = text_of(network_acls, "defaultAction") if network_acls else ""
            exposed = (public is not None and public.lower() == "enabled") or (
                default_action.lower() == "allow"
            )
            if not exposed:
                continue
            name = _resource_name(vault)
            out.append(
                Observation(
                    policy="azure-keyvault-public-network",
                    provider=PROVIDER,
                    resource=name,
                    title=f"Azure Key Vault is publicly reachable: {name}",
                    detail=(
                        f"Key Vault {name} has publicNetworkAccess={public or 'unset'} and "
                        f"networkAcls.defaultAction={default_action or 'unset'}: no private "
                        "endpoint or address restriction is recorded"
                    ),
                    observed={
                        "publicNetworkAccess": public,
                        "defaultAction": default_action or None,
                    },
                    severity="high",
                    exchanges=exchanges_of(reply),
                )
            )
        return out


class AzureKeyVaultPurgeProtectionOff(_AzureCheck, Module):
    """``m5.azure-keyvault-purge-protection-off`` — a vault whose material can be purged."""

    area = "keyvault"
    reads = (_KEY_VAULTS,)
    metadata = posture_metadata(
        name="azure-keyvault-purge-protection-off",
        title="Azure Key Vault does not enable purge protection",
        description=(
            "Lists the subscription's Key Vaults and reports one whose "
            "properties.enablePurgeProtection is not true: a deleted vault and its secret "
            "material can be destroyed immediately instead of surviving the soft-delete "
            "retention window, so neither an accidental delete nor a destructive actor can be "
            "recovered from. Read-only: listKeyVaults."
        ),
        research_ref="ch05#19",
        cwe="CWE-693",
        framework=("WSTG-CONF-02", "API8:2023", "CWE-693"),
        compliance=("ISO-A.5.33", "CSF-PR.DS-11", "PCI-3"),
        severity="medium",
        estimated_requests=1,
    )

    async def evaluate(self, ctx: CheckContext, client: CloudReadClient) -> list[Observation]:
        reply = await client.get(_KEY_VAULTS)
        out: list[Observation] = []
        for vault in limit(ctx, items_of(reply.mapping())):
            properties = _properties(vault)
            if bool_of(properties, "enablePurgeProtection") is True:
                continue
            name = _resource_name(vault)
            out.append(
                Observation(
                    policy="azure-keyvault-purge-protection-off",
                    provider=PROVIDER,
                    resource=name,
                    title=f"Azure Key Vault lacks purge protection: {name}",
                    detail=(
                        f"Key Vault {name} has enablePurgeProtection="
                        f"{bool_of(properties, 'enablePurgeProtection')}: a deleted vault's "
                        "material can be purged before the retention window ends"
                    ),
                    observed={
                        "enablePurgeProtection": bool_of(properties, "enablePurgeProtection"),
                        "enableSoftDelete": bool_of(properties, "enableSoftDelete"),
                    },
                    severity="medium",
                    exchanges=exchanges_of(reply),
                )
            )
        return out


# --------------------------------------------------------------------------- SQL
class AzureSqlPublicNetwork(_AzureCheck, Module):
    """``m5.azure-sql-public-network`` — a SQL server exposed to the public internet."""

    area = "sql"
    reads = (_SQL_SERVERS,)
    metadata = posture_metadata(
        name="azure-sql-public-network",
        title="Azure SQL server allows public network access",
        description=(
            "Lists the subscription's SQL servers and reports one whose "
            "properties.publicNetworkAccess is Enabled: the logical server's endpoint resolves "
            "publicly and admits connections from the firewall rules and the "
            "AllowAzureServices rule rather than from a private endpoint only. Read-only: "
            "listSqlServers."
        ),
        research_ref="ch05#20",
        cwe="CWE-284",
        framework=("WSTG-CONF-02", "API8:2023", "CWE-284"),
        compliance=("CIS-4.1", "ISO-A.8.20", "CSF-PR.AA-05", "PCI-1"),
        severity="high",
        estimated_requests=1,
    )

    async def evaluate(self, ctx: CheckContext, client: CloudReadClient) -> list[Observation]:
        reply = await client.get(_SQL_SERVERS)
        out: list[Observation] = []
        for server in limit(ctx, items_of(reply.mapping())):
            properties = _properties(server)
            if (str_of(properties, "publicNetworkAccess") or "").lower() != "enabled":
                continue
            name = _resource_name(server)
            out.append(
                Observation(
                    policy="azure-sql-public-network",
                    provider=PROVIDER,
                    resource=name,
                    title=f"Azure SQL server is publicly reachable: {name}",
                    detail=(
                        f"SQL server {name} has publicNetworkAccess=Enabled: it is reachable "
                        "from the public internet rather than from a private endpoint alone"
                    ),
                    observed={"publicNetworkAccess": "Enabled"},
                    severity="high",
                    exchanges=exchanges_of(reply),
                )
            )
        return out


# --------------------------------------------------------------------------- AKS
class AzureAksPublicApi(_AzureCheck, Module):
    """``m5.azure-aks-public-api`` — a cluster whose API server is not private."""

    area = "aks"
    reads = (_AKS_CLUSTERS,)
    metadata = posture_metadata(
        name="azure-aks-public-api",
        title="Azure Kubernetes Service cluster exposes a public API server",
        description=(
            "Lists the subscription's AKS managed clusters and reports one whose "
            "properties.apiServerAccessProfile does not enable a private cluster and declares "
            "no authorized IP range: the Kubernetes API server is then reachable from any "
            "source that can route to it. Read-only: listManagedClusters."
        ),
        research_ref="ch05#13",
        cwe="CWE-284",
        framework=("WSTG-CONF-02", "API8:2023", "CWE-284"),
        compliance=("CIS-4.1", "ISO-A.8.20", "CSF-PR.AA-05", "PCI-1"),
        severity="high",
        estimated_requests=1,
    )

    async def evaluate(self, ctx: CheckContext, client: CloudReadClient) -> list[Observation]:
        reply = await client.get(_AKS_CLUSTERS)
        out: list[Observation] = []
        for cluster in limit(ctx, items_of(reply.mapping())):
            properties = _properties(cluster)
            profile = get(properties, "apiServerAccessProfile")
            profile = profile if isinstance(profile, Mapping) else {}
            private = bool_of(profile, "enablePrivateCluster") is True
            ranges = _as_sequence(get(profile, "authorizedIpRanges"))
            if private or ranges:
                continue
            name = _resource_name(cluster)
            out.append(
                Observation(
                    policy="azure-aks-public-api",
                    provider=PROVIDER,
                    resource=name,
                    title=f"AKS cluster has a public API server: {name}",
                    detail=(
                        f"cluster {name} is not a private cluster and declares no "
                        "authorizedIpRanges: the Kubernetes API server accepts traffic from "
                        "the internet"
                    ),
                    observed={
                        "enablePrivateCluster": bool_of(profile, "enablePrivateCluster"),
                        "authorizedIpRanges": [],
                    },
                    severity="high",
                    exchanges=exchanges_of(reply),
                )
            )
        return out


class AzureAksRbacDisabled(_AzureCheck, Module):
    """``m5.azure-aks-rbac-disabled`` — a cluster without Kubernetes RBAC."""

    area = "aks"
    reads = (_AKS_CLUSTERS,)
    metadata = posture_metadata(
        name="azure-aks-rbac-disabled",
        title="Azure Kubernetes Service cluster does not enable Kubernetes RBAC",
        description=(
            "Lists the subscription's AKS managed clusters and reports one whose "
            "properties.enableRBAC is false: every authenticated principal then has the "
            "cluster's full permissions and Kubernetes cannot restrict what a namespace or a "
            "service account may do. Read-only: listManagedClusters."
        ),
        research_ref="ch05#13",
        cwe="CWE-862",
        framework=("WSTG-CONF-02", "API8:2023", "CWE-862"),
        compliance=("CIS-5.1", "ISO-A.8.3", "CSF-PR.AA-03", "PCI-7"),
        severity="high",
        estimated_requests=1,
    )

    async def evaluate(self, ctx: CheckContext, client: CloudReadClient) -> list[Observation]:
        reply = await client.get(_AKS_CLUSTERS)
        out: list[Observation] = []
        for cluster in limit(ctx, items_of(reply.mapping())):
            properties = _properties(cluster)
            if bool_of(properties, "enableRBAC") is not False:
                continue
            name = _resource_name(cluster)
            out.append(
                Observation(
                    policy="azure-aks-rbac-disabled",
                    provider=PROVIDER,
                    resource=name,
                    title=f"AKS cluster has Kubernetes RBAC disabled: {name}",
                    detail=(
                        f"cluster {name} has enableRBAC=false: every authenticated principal "
                        "holds the cluster's full permissions"
                    ),
                    observed={"enableRBAC": False},
                    severity="high",
                    exchanges=exchanges_of(reply),
                )
            )
        return out


# --------------------------------------------------------------------------- App Service
class AzureAppServiceHttpsOnly(_AzureCheck, Module):
    """``m5.azure-appservice-https-only`` — a web app that does not force HTTPS."""

    area = "appservice"
    reads = (_WEB_APPS,)
    metadata = posture_metadata(
        name="azure-appservice-https-only",
        title="Azure App Service web app does not force HTTPS",
        description=(
            "Lists the subscription's App Service web apps and reports one whose "
            "properties.httpsOnly is false: the app answers plain HTTP, so a request — and "
            "the session cookie or credential it carries — can be read or rewritten in "
            "transit. Read-only: listWebApps."
        ),
        research_ref="ch05#9",
        cwe="CWE-319",
        framework=("WSTG-CONF-01", "API8:2023", "CWE-319"),
        compliance=("ISO-A.8.24", "CSF-PR.DS-01", "PCI-4"),
        severity="medium",
        estimated_requests=1,
    )

    async def evaluate(self, ctx: CheckContext, client: CloudReadClient) -> list[Observation]:
        reply = await client.get(_WEB_APPS)
        out: list[Observation] = []
        for site in limit(ctx, items_of(reply.mapping())):
            properties = _properties(site)
            if bool_of(properties, "httpsOnly") is not False:
                continue
            name = _resource_name(site)
            out.append(
                Observation(
                    policy="azure-appservice-https-only",
                    provider=PROVIDER,
                    resource=name,
                    title=f"Azure web app does not force HTTPS: {name}",
                    detail=(
                        f"web app {name} has httpsOnly=false: plain HTTP requests are served "
                        "rather than redirected"
                    ),
                    observed={"httpsOnly": False},
                    severity="medium",
                    exchanges=exchanges_of(reply),
                )
            )
        return out


# --------------------------------------------------------------------------- the family
#: Every check this module registers, in run order, grouped by the requirement's scope areas.
AZURE_POSTURE_CHECKS: tuple[type[Module], ...] = (
    AzureStoragePublicBlob,
    AzureStorageMinTls,
    AzureStoragePublicNetwork,
    AzureNsgOpenSsh,
    AzureNsgOpenRdp,
    AzureKeyVaultPublicNetwork,
    AzureKeyVaultPurgeProtectionOff,
    AzureSqlPublicNetwork,
    AzureAksPublicApi,
    AzureAksRbacDisabled,
    AzureAppServiceHttpsOnly,
)


def azure_checks() -> tuple[type[Module], ...]:
    return AZURE_POSTURE_CHECKS


def service_areas() -> dict[str, str]:
    """``check name -> scope area`` from the module's own declaration (the test reads this)."""
    return {check.metadata.name: str(getattr(check, "area", "")) for check in AZURE_POSTURE_CHECKS}
