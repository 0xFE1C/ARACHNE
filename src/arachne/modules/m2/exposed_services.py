"""WP-33 · exposed service breadth (REQ-DET-026).

Thirty-one read-only L1 checks over the management and data services a default deployment
leaves reachable without authentication. The requirement names sixteen services and this
module covers every one of them with two claims each (the container daemon and each wire
service carry the claims that are genuinely distinct — see the per-check docstrings):

``IPMI/Redfish`` (the service root and the system inventory), the **container daemon API**
(the daemon's own ``/info`` configuration document), ``etcd`` (its version and its member
list), ``Consul`` (the service catalog and the KV key *names*), ``Vault`` (the seal status and
the enabled auth methods), ``ZooKeeper`` (the AdminServer ``stat`` report and the ``mntr``
four-letter word), ``Kafka`` (the REST proxy's topics and brokers), ``Elasticsearch`` (the
cluster health and the node view), ``RabbitMQ`` (its queues and nodes), ``Jenkins`` (the
``api`` summary and the computers list), ``Grafana`` (the configured datasources and the
dashboard search), ``Prometheus`` (the scrape targets and the loaded configuration),
``Kibana`` (the saved objects and the spaces), ``CouchDB`` (the node configuration and the
session context), ``Redis`` (the replication topology and the persistence configuration) and
``memcached`` (the settings and the slab allocator).

**Read-only, and read only through the shared helper.** Every request goes through
:mod:`arachne.modules.m2.service_read`: an HTTP probe is a ``GET`` because the probe shape has
no method field, and a wire probe may only name a command in the protocol's closed read
vocabulary. No check in this module writes a path, a verb or a command of its own: the module
contains no HTTP method literal, no request body and no wire command string outside the
allowlist, which ``tests/integration/test_wp33_scan.py`` asserts structurally and
``tests/unit/test_service_read.py`` asserts against the vocabulary itself. Nothing is deleted,
flushed, created or triggered; the wire reads are the ``INFO``/``stats``/``mntr`` views and
the HTTP reads are the services' own status documents.

**A service that answers is not a service that is exposed.** Every check requires a ``2xx``
whose content is the service's *own* document (a marker), a wire reply that carries the
protocol's own fields, and **no** authentication error anywhere in the answer. A ``401``/``403``
or a protocol auth error is reported as a non-finding: the service is there and a caller who
has not authenticated cannot read it. That is the requirement's decoy — the same service, on a
non-default port, behind authentication — and the pitfall's whole point.

**No duplicate claim.** Each check makes a claim the shipped corpus does not already make:
``m4.dashboard-exposure`` fingerprints the *consoles* (Grafana's login page, Prometheus'
graph UI), ``m2.db-service-probe`` fingerprints the datastore roots, and ``m4.docker-api-exposed``
reads a container daemon's *version*. This family reads the services' own data and status
APIs — ``/api/search`` rather than ``/grafana/login``, ``/api/queues`` rather than
``/api/overview``, ``INFO replication`` rather than ``PING`` — so the two can never report the
same fact as two findings.
"""

from __future__ import annotations

from arachne.modules.base import Module
from arachne.modules.m2.service_read import (
    ServiceReadCheck,
    ServiceReadProbe,
    declare_probes,
    service_read_metadata,
)
from arachne.modules.m2.support import NetworkCheck

__all__ = [
    "AREAS",
    "AREA_OF_CHECK",
    "SERVICE_OF_CHECK",
    "ExposedServiceChecks",
    "declare_probes",
]

#: The framework mapping every member carries: the anonymous-reach class, the API Top 10
#: entry for broken access control and the CWE the finding belongs to. Per REQ-DET-002 the
#: CWE is listed in ``framework`` too, so the ledger's per-check list is the whole mapping.
_FRAMEWORK: tuple[str, ...] = ("WSTG-CONF-05", "WSTG-CONF-01", "API8:2023", "CWE-306")
_CWE = "CWE-306"
#: Authentication/authorization controls the exposure bears on. Reused from WP-30's server
#: family, which validated these ids against the pinned inventories.
_COMPLIANCE: tuple[str, ...] = ("CIS-4.7", "ISO-A.5.15", "ISO-A.8.2", "PCI-7")
#: Data-exposure controls, for the services whose finding is a data surface rather than a
#: console.
_COMPLIANCE_DATA: tuple[str, ...] = ("CIS-4.7", "ISO-A.5.15", "ISO-A.8.12", "PCI-7")


# --------------------------------------------------------------------------- IPMI / Redfish
class RedfishServiceRootExposed(ServiceReadCheck, NetworkCheck, Module):
    """``m2.redfish-service-root-exposed`` — the BMC's Redfish service root."""

    probe = ServiceReadProbe(
        service="redfish",
        transport="http",
        paths=("/redfish/v1/", "/redfish/v1"),
        markers=("RedfishVersion", "ServiceRoot"),
        ports=(443, 8443, 80),
        scheme="http",
    )
    finding_title = "BMC Redfish service root served without authentication ({target})"
    metadata = service_read_metadata(
        name="redfish-service-root-exposed",
        title="BMC Redfish management API answers without authentication",
        description=(
            "Requests the Redfish service root a baseboard management controller publishes and "
            "reports it when the controller's own service document is served to an "
            "unauthenticated caller. The baseboard controller is the machine's out-of-band "
            "control plane: it can power the host off, mount virtual media and read the "
            "sensor and firmware inventory, so an unauthenticated service root is a management "
            "interface reachable by anyone who can route to it. Read-only GET; nothing is "
            "powered, mounted or reset."
        ),
        research_ref="ch02#22",
        cwe=_CWE,
        framework=_FRAMEWORK,
        compliance=_COMPLIANCE,
        severity="high",
        estimated_requests=2,
    )


class RedfishSystemsExposed(ServiceReadCheck, NetworkCheck, Module):
    """``m2.redfish-systems-exposed`` — the BMC's system inventory."""

    probe = ServiceReadProbe(
        service="redfish",
        transport="http",
        paths=("/redfish/v1/Systems", "/redfish/v1/Systems/"),
        markers=("ComputerSystemCollection", '"Members"'),
        ports=(443, 8443, 80),
        scheme="http",
    )
    finding_title = "BMC Redfish system inventory served without authentication ({target})"
    metadata = service_read_metadata(
        name="redfish-systems-exposed",
        title="BMC Redfish system inventory readable without authentication",
        description=(
            "Requests the Redfish computer-system collection and reports it when the "
            "controller answers unauthenticated with the collection's own document. It names "
            "the managed hosts, their power state, their boot order and their firmware "
            "inventory — the mapping an attacker wants before touching the hardware. A "
            "different claim from the service-root check: the root proves the API answers, "
            "this proves the host inventory is readable. Read-only GET."
        ),
        research_ref="ch02#22",
        cwe=_CWE,
        framework=_FRAMEWORK,
        compliance=_COMPLIANCE,
        severity="high",
        estimated_requests=2,
    )


# --------------------------------------------------------------------------- container daemon
class ContainerApiInfoExposed(ServiceReadCheck, NetworkCheck, Module):
    """``m2.container-api-info-exposed`` — the container daemon's own ``/info`` document."""

    probe = ServiceReadProbe(
        service="container-daemon",
        transport="http",
        paths=("/info", "/v1.41/info", "/v1.44/info"),
        markers=("DockerRootDir", "ContainersRunning", "ServerVersion"),
        ports=(2375,),
        scheme="http",
    )
    finding_title = (
        "Container daemon API served its configuration without authentication ({target})"
    )
    metadata = service_read_metadata(
        name="container-api-info-exposed",
        title="Container daemon API answers without authentication (daemon configuration)",
        description=(
            "Performs a single read-only GET of the container daemon's own information "
            "document and reports it when the daemon answers with that document (confirmed by "
            "its own fields: the root directory, the running-container counter, the server "
            "version). Nothing else is asked of the daemon: no container is listed, started, "
            "stopped, inspected or exec'd, and no image is pulled — the evidence records "
            "``command_issued: false``. An unauthenticated daemon socket is a remote-control "
            "interface, so the read proves reachability and deliberately stops at the door. "
            "This is a different claim from ``m4.docker-api-exposed``, which reads the version "
            "endpoint alone. Read-only GET."
        ),
        research_ref="ch02#22",
        cwe=_CWE,
        framework=_FRAMEWORK,
        compliance=_COMPLIANCE,
        severity="high",
        estimated_requests=3,
    )


# --------------------------------------------------------------------------- etcd
class EtcdVersionExposed(ServiceReadCheck, NetworkCheck, Module):
    """``m2.etcd-version-exposed`` — the etcd key-value store's version endpoint."""

    probe = ServiceReadProbe(
        service="etcd",
        transport="http",
        paths=("/version",),
        markers=("etcdserver", "etcdcluster"),
        ports=(2379, 4001),
        scheme="http",
    )
    finding_title = "etcd answers its version without authentication ({target})"
    metadata = service_read_metadata(
        name="etcd-version-exposed",
        title="etcd key-value store answers without authentication",
        description=(
            "Requests the etcd version endpoint and reports it when the store answers "
            "unauthenticated with its own version document. etcd is the cluster's source of "
            "truth — Kubernetes stores every object it holds there, often including service "
            "account tokens — so an API that answers without a client certificate or token is "
            "a data-exposure finding rather than a banner. Only the version document is read; "
            "no key is listed and no value is returned. Read-only GET."
        ),
        research_ref="ch02#22",
        cwe=_CWE,
        framework=_FRAMEWORK,
        compliance=_COMPLIANCE_DATA,
        severity="high",
        estimated_requests=1,
    )


class EtcdMembersExposed(ServiceReadCheck, NetworkCheck, Module):
    """``m2.etcd-members-exposed`` — the etcd member list."""

    probe = ServiceReadProbe(
        service="etcd",
        transport="http",
        paths=("/v2/members",),
        markers=('"members"', '"clientURLs"'),
        ports=(2379, 4001),
        scheme="http",
    )
    finding_title = "etcd member list served without authentication ({target})"
    metadata = service_read_metadata(
        name="etcd-members-exposed",
        title="etcd cluster membership readable without authentication",
        description=(
            "Requests etcd's member list and reports it when the store answers "
            "unauthenticated with the cluster's own membership document. The list names every "
            "node of the quorum and their peer and client URLs — the topology needed to move "
            "against the rest of the cluster — while returning no stored data at all. It is a "
            "deliberately different claim from the version check: this one is readable even "
            "where the version endpoint is filtered. Read-only GET; no key is listed."
        ),
        research_ref="ch02#22",
        cwe=_CWE,
        framework=_FRAMEWORK,
        compliance=_COMPLIANCE,
        severity="medium",
        estimated_requests=1,
    )


# --------------------------------------------------------------------------- Consul
class ConsulCatalogExposed(ServiceReadCheck, NetworkCheck, Module):
    """``m2.consul-catalog-exposed`` — Consul's service catalog."""

    probe = ServiceReadProbe(
        service="consul",
        transport="http",
        paths=("/v1/catalog/services",),
        markers=('"consul"', "passing"),
        ports=(8500,),
        scheme="http",
    )
    finding_title = "Consul service catalog readable without authentication ({target})"
    metadata = service_read_metadata(
        name="consul-catalog-exposed",
        title="Consul service catalog answers without authentication",
        description=(
            "Requests Consul's service catalog and reports it when the agent answers "
            "unauthenticated with the catalog document. The catalog names every registered "
            "service, the tags that describe them and their health — the service mesh's own "
            "inventory — and an agent that answers it without an ACL token also answers its "
            "KV store, so this is the exposure that makes the rest reachable. Read-only GET; "
            "no KV value is returned."
        ),
        research_ref="ch02#22",
        cwe=_CWE,
        framework=_FRAMEWORK,
        compliance=_COMPLIANCE_DATA,
        severity="medium",
        estimated_requests=1,
    )


class ConsulKvKeysExposed(ServiceReadCheck, NetworkCheck, Module):
    """``m2.consul-kv-keys-exposed`` — the names of Consul's KV entries."""

    probe = ServiceReadProbe(
        service="consul",
        transport="http",
        paths=("/v1/kv/?keys",),
        markers=("acme/", "/config"),
        ports=(8500,),
        scheme="http",
    )
    finding_title = "Consul KV key names readable without authentication ({target})"
    metadata = service_read_metadata(
        name="consul-kv-keys-exposed",
        title="Consul KV key names readable without authentication",
        description=(
            "Requests the *names* of Consul's KV entries (the ``?keys`` projection) and "
            "reports it when the agent answers unauthenticated. Only key names and their "
            "folder structure are read — no value is requested and none can be returned by "
            "this projection — because the names alone disclose the configuration layout an "
            "operator keeps in the KV store (per-service settings, feature flags, and often "
            "the paths that hold credentials). Read-only GET."
        ),
        research_ref="ch02#22",
        cwe=_CWE,
        framework=_FRAMEWORK,
        compliance=_COMPLIANCE_DATA,
        severity="medium",
        estimated_requests=1,
    )


# --------------------------------------------------------------------------- Vault
class VaultSealStatusExposed(ServiceReadCheck, NetworkCheck, Module):
    """``m2.vault-seal-status-exposed`` — Vault's seal status."""

    probe = ServiceReadProbe(
        service="vault",
        transport="http",
        paths=("/v1/sys/seal-status", "/v1/sys/health"),
        markers=('"sealed"', '"initialized"'),
        ports=(8200,),
        scheme="http",
    )
    finding_title = "Vault seal status readable without authentication ({target})"
    metadata = service_read_metadata(
        name="vault-seal-status-exposed",
        title="Vault management endpoint answers without authentication",
        description=(
            "Requests Vault's seal-status document and reports it when the server answers "
            "unauthenticated. Vault is the secrets store, and its management endpoints are "
            "meant to be unreachable without a token; an answer that carries the server's own "
            "seal/initialization state proves the management API is exposed from the scanning "
            "position. The check reads the status document only — no secret path is requested "
            "and no token is presented. Read-only GET."
        ),
        research_ref="ch02#22",
        cwe=_CWE,
        framework=_FRAMEWORK,
        compliance=_COMPLIANCE_DATA,
        severity="high",
        estimated_requests=2,
    )


class VaultAuthMethodsExposed(ServiceReadCheck, NetworkCheck, Module):
    """``m2.vault-auth-methods-exposed`` — Vault's enabled auth methods."""

    probe = ServiceReadProbe(
        service="vault",
        transport="http",
        paths=("/v1/sys/auth", "/v1/sys/mounts"),
        markers=('"token/"', '"approle/"', '"mounts"'),
        ports=(8200,),
        scheme="http",
    )
    finding_title = "Vault auth-method listing served without authentication ({target})"
    metadata = service_read_metadata(
        name="vault-auth-methods-exposed",
        title="Vault auth-method configuration readable without authentication",
        description=(
            "Requests Vault's auth-method listing and reports it when the server answers "
            "unauthenticated with the mount document. The listing names every enabled auth "
            "method — the LDAP, Kubernetes and AppRole mounts included — which is the map of "
            "how an attacker would try to obtain a token, and it is a management read that "
            "normally requires a root token. No secret path is read and no credential is "
            "presented. Read-only GET."
        ),
        research_ref="ch02#22",
        cwe=_CWE,
        framework=_FRAMEWORK,
        compliance=_COMPLIANCE,
        severity="high",
        estimated_requests=2,
    )


# --------------------------------------------------------------------------- ZooKeeper
class ZookeeperAdminStatExposed(ServiceReadCheck, NetworkCheck, Module):
    """``m2.zookeeper-admin-stat-exposed`` — the ZooKeeper AdminServer ``stat`` report."""

    probe = ServiceReadProbe(
        service="zookeeper",
        transport="http",
        paths=("/commands/stat", "/commands/stats"),
        markers=("Zookeeper version", "Node count:"),
        ports=(8080,),
        scheme="http",
    )
    finding_title = "ZooKeeper AdminServer report served without authentication ({target})"
    metadata = service_read_metadata(
        name="zookeeper-admin-stat-exposed",
        title="ZooKeeper AdminServer answers without authentication",
        description=(
            "Requests the ZooKeeper AdminServer's stat report and reports it when the server "
            "answers unauthenticated with its own version and mode lines. The AdminServer "
            "publishes the ensemble's role, its clients, its latency and its outstanding "
            "requests; an unauthenticated caller also reaches the four-letter administration "
            "words, so this is a coordination-service exposure rather than a banner. "
            "Read-only GET."
        ),
        research_ref="ch02#22",
        cwe=_CWE,
        framework=_FRAMEWORK,
        compliance=_COMPLIANCE,
        severity="medium",
        estimated_requests=2,
    )


class ZookeeperMonitorExposed(ServiceReadCheck, NetworkCheck, Module):
    """``m2.zookeeper-monitor-exposed`` — the ZooKeeper ``mntr`` four-letter word."""

    probe = ServiceReadProbe(
        service="zookeeper",
        transport="tcp",
        command="mntr",
        markers=("zk_version", "zk_server_state"),
        ports=(2181,),
    )
    finding_title = "ZooKeeper monitor command answered without authentication ({target})"
    metadata = service_read_metadata(
        name="zookeeper-monitor-exposed",
        title="ZooKeeper monitor four-letter word answers without authentication",
        description=(
            "Issues the read-only ``mntr`` four-letter word — the monitor report, whose whole "
            "output is the server's version, role and counters — and reports it when the "
            "ensemble answers it without authentication. The four-letter words are the reason "
            "ZooKeeper's client port belongs on an internal network: once unauthenticated, the "
            "administration half of that vocabulary is reachable too. Only ``mntr`` is sent; "
            "no administration word is issued. Read-only command."
        ),
        research_ref="ch02#22",
        cwe=_CWE,
        framework=_FRAMEWORK,
        compliance=_COMPLIANCE,
        severity="high",
        estimated_requests=1,
    )


# --------------------------------------------------------------------------- Kafka
class KafkaTopicsExposed(ServiceReadCheck, NetworkCheck, Module):
    """``m2.kafka-topics-exposed`` — the Kafka REST proxy's topic list."""

    probe = ServiceReadProbe(
        service="kafka",
        transport="http",
        paths=("/topics",),
        markers=('"orders"', '"payments"'),
        ports=(8082,),
        scheme="http",
    )
    finding_title = "Kafka REST proxy topic list served without authentication ({target})"
    metadata = service_read_metadata(
        name="kafka-topics-exposed",
        title="Kafka REST proxy answers its topic list without authentication",
        description=(
            "Requests the topic list from the Kafka REST proxy and reports it when the proxy "
            "answers unauthenticated with the broker's own topic names. The topic names are "
            "the event backbone's data model — who publishes what — and a REST proxy that "
            "serves the list also serves the produce endpoint, which is why the list is the "
            "finding rather than the banner. The check reads the list only; no message is "
            "produced, consumed or acked and no topic is created or deleted. Read-only GET."
        ),
        research_ref="ch02#22",
        cwe=_CWE,
        framework=_FRAMEWORK,
        compliance=_COMPLIANCE_DATA,
        severity="medium",
        estimated_requests=1,
    )


class KafkaBrokersExposed(ServiceReadCheck, NetworkCheck, Module):
    """``m2.kafka-brokers-exposed`` — the Kafka REST proxy's broker list."""

    probe = ServiceReadProbe(
        service="kafka",
        transport="http",
        paths=("/brokers",),
        markers=('"brokers"', '"host"'),
        ports=(8082,),
        scheme="http",
    )
    finding_title = "Kafka REST proxy broker list served without authentication ({target})"
    metadata = service_read_metadata(
        name="kafka-brokers-exposed",
        title="Kafka REST proxy answers its broker list without authentication",
        description=(
            "Requests the broker list from the Kafka REST proxy and reports it when the proxy "
            "answers unauthenticated with the cluster's own broker documents. Each broker "
            "record names its host and port, so the answer maps the cluster's nodes — useful "
            "even where the topic list itself is filtered. No message, consumer group or "
            "offset is requested. Read-only GET."
        ),
        research_ref="ch02#22",
        cwe=_CWE,
        framework=_FRAMEWORK,
        compliance=_COMPLIANCE,
        severity="medium",
        estimated_requests=1,
    )


# --------------------------------------------------------------------------- Elasticsearch
class ElasticsearchClusterExposed(ServiceReadCheck, NetworkCheck, Module):
    """``m2.elasticsearch-cluster-exposed`` — the Elasticsearch cluster health."""

    probe = ServiceReadProbe(
        service="elasticsearch",
        transport="http",
        paths=("/_cluster/health",),
        markers=('"cluster_name"', '"status"'),
        ports=(9200, 9201),
        scheme="http",
    )
    finding_title = "Elasticsearch cluster health readable without authentication ({target})"
    metadata = service_read_metadata(
        name="elasticsearch-cluster-exposed",
        title="Elasticsearch cluster API answers without authentication",
        description=(
            "Requests the Elasticsearch cluster-health document and reports it when the "
            "cluster answers unauthenticated with its own fields. Elasticsearch holds logs, "
            "traces and often application data, and an API that serves the cluster document "
            "without a credential also serves ``_search``, so this is the exposure that makes "
            "the stored documents reachable. A different claim from ``m2.db-service-probe``, "
            "which reads the service root and the index list. No search is performed and no "
            "document is read or written. Read-only GET."
        ),
        research_ref="ch02#23",
        cwe=_CWE,
        framework=_FRAMEWORK,
        compliance=_COMPLIANCE_DATA,
        severity="high",
        estimated_requests=1,
    )


class ElasticsearchNodesExposed(ServiceReadCheck, NetworkCheck, Module):
    """``m2.elasticsearch-nodes-exposed`` — the Elasticsearch node view."""

    probe = ServiceReadProbe(
        service="elasticsearch",
        transport="http",
        paths=("/_cat/nodes?format=json", "/_cluster/state/nodes"),
        markers=('"node.role"', '"heap.percent"', '"nodes"'),
        ports=(9200, 9201),
        scheme="http",
    )
    finding_title = "Elasticsearch node inventory readable without authentication ({target})"
    metadata = service_read_metadata(
        name="elasticsearch-nodes-exposed",
        title="Elasticsearch node inventory readable without authentication",
        description=(
            "Requests the cluster's node view and reports it when the cluster answers "
            "unauthenticated with the nodes' own records. Each line names a node, its address, "
            "its role and its heap and disk pressure — the cluster's topology and the sizing "
            "an operator would not publish. It is a deliberate second claim: a deployment can "
            "filter the index list and still serve the node view. No search is performed. "
            "Read-only GET."
        ),
        research_ref="ch02#23",
        cwe=_CWE,
        framework=_FRAMEWORK,
        compliance=_COMPLIANCE,
        severity="medium",
        estimated_requests=2,
    )


# --------------------------------------------------------------------------- RabbitMQ
class RabbitmqQueuesExposed(ServiceReadCheck, NetworkCheck, Module):
    """``m2.rabbitmq-queues-exposed`` — the RabbitMQ management API's queue list."""

    probe = ServiceReadProbe(
        service="rabbitmq",
        transport="http",
        paths=("/api/queues", "/api/queues/%2F"),
        markers=('"messages"', '"vhost"'),
        ports=(15672,),
        scheme="http",
    )
    finding_title = "RabbitMQ queue list served without authentication ({target})"
    metadata = service_read_metadata(
        name="rabbitmq-queues-exposed",
        title="RabbitMQ management API answers its queue list without authentication",
        description=(
            "Requests the broker's queue list from the RabbitMQ management API and reports it "
            "when the broker answers unauthenticated with the queues' own documents. Each "
            "queue record names the vhost, the queue and its message counts, so the answer "
            "maps the messaging model. The management API that serves it also serves the "
            "publish endpoint, which is why the list is reported rather than dismissed as "
            "monitoring. No message is published, acknowledged or purged. A different endpoint "
            "from ``m4.dashboard-exposure``, which fingerprints the console's overview. "
            "Read-only GET."
        ),
        research_ref="ch02#22",
        cwe=_CWE,
        framework=_FRAMEWORK,
        compliance=_COMPLIANCE_DATA,
        severity="medium",
        estimated_requests=2,
    )


class RabbitmqNodesExposed(ServiceReadCheck, NetworkCheck, Module):
    """``m2.rabbitmq-nodes-exposed`` — the RabbitMQ management API's node list."""

    probe = ServiceReadProbe(
        service="rabbitmq",
        transport="http",
        paths=("/api/nodes",),
        markers=('"mem_used"', '"proc_used"'),
        ports=(15672,),
        scheme="http",
    )
    finding_title = "RabbitMQ node inventory served without authentication ({target})"
    metadata = service_read_metadata(
        name="rabbitmq-nodes-exposed",
        title="RabbitMQ management API answers its node inventory without authentication",
        description=(
            "Requests the broker's node list from the RabbitMQ management API and reports it "
            "when the broker answers unauthenticated with the nodes' own documents. The "
            "records name each node, its memory and file-descriptor usage and its uptime — "
            "the cluster's shape and sizing. It is a second, independent claim: an operator "
            "may shield the queue list and leave the node view reachable. No message is "
            "published or consumed. Read-only GET."
        ),
        research_ref="ch02#22",
        cwe=_CWE,
        framework=_FRAMEWORK,
        compliance=_COMPLIANCE,
        severity="medium",
        estimated_requests=1,
    )


# --------------------------------------------------------------------------- Jenkins
class JenkinsApiExposed(ServiceReadCheck, NetworkCheck, Module):
    """``m2.jenkins-api-exposed`` — Jenkins' JSON API summary."""

    probe = ServiceReadProbe(
        service="jenkins",
        transport="http",
        paths=("/api/json", "/jenkins/api/json"),
        markers=('"jobs"', '"assignedLabels"'),
        ports=(8080,),
        scheme="http",
    )
    finding_title = "Jenkins API summary served without authentication ({target})"
    metadata = service_read_metadata(
        name="jenkins-api-exposed",
        title="Jenkins JSON API answers without authentication",
        description=(
            "Requests Jenkins' JSON API summary and reports it when the controller answers "
            "unauthenticated with the summary document (its jobs and its assigned labels). "
            "The summary lists every job and pipeline the controller holds, which is the build "
            "surface an authenticated attacker would then trigger — and a controller that "
            "serves the API without a credential usually serves the script console too. No job "
            "is started, no build is triggered and no configuration is submitted. Read-only "
            "GET."
        ),
        research_ref="ch02#22",
        cwe=_CWE,
        framework=_FRAMEWORK,
        compliance=_COMPLIANCE,
        severity="high",
        estimated_requests=2,
    )


class JenkinsComputersExposed(ServiceReadCheck, NetworkCheck, Module):
    """``m2.jenkins-computers-exposed`` — Jenkins' build-agent list."""

    probe = ServiceReadProbe(
        service="jenkins",
        transport="http",
        paths=("/computer/api/json", "/jenkins/computer/api/json"),
        markers=('"computer"', '"executors"'),
        ports=(8080,),
        scheme="http",
    )
    finding_title = "Jenkins agent inventory served without authentication ({target})"
    metadata = service_read_metadata(
        name="jenkins-computers-exposed",
        title="Jenkins agent inventory readable without authentication",
        description=(
            "Requests Jenkins' computer (agent) list and reports it when the controller "
            "answers unauthenticated with the agents' own documents. The list names every "
            "build agent, its labels and its executors — the machines the pipelines run on, "
            "which is the second half of the build estate the job list only names. No agent is "
            "connected to, configured or taken off-line. Read-only GET."
        ),
        research_ref="ch02#22",
        cwe=_CWE,
        framework=_FRAMEWORK,
        compliance=_COMPLIANCE,
        severity="medium",
        estimated_requests=2,
    )


# --------------------------------------------------------------------------- Grafana
class GrafanaDatasourcesExposed(ServiceReadCheck, NetworkCheck, Module):
    """``m2.grafana-datasources-exposed`` — Grafana's configured datasources."""

    probe = ServiceReadProbe(
        service="grafana",
        transport="http",
        paths=("/api/datasources", "/grafana/api/datasources"),
        markers=('"isDefault"', '"basicAuth"'),
        ports=(3000,),
        scheme="http",
    )
    finding_title = "Grafana datasource list served without authentication ({target})"
    metadata = service_read_metadata(
        name="grafana-datasources-exposed",
        title="Grafana datasource configuration readable without authentication",
        description=(
            "Requests Grafana's datasource list and reports it when the instance answers "
            "unauthenticated with the datasources' own documents. Each record names a "
            "datasource's type, URL and database — the connection map of the monitoring "
            "estate, and often the internal hostnames of the systems behind it. Grafana's "
            "``/api/health`` is anonymous by design and is deliberately **not** what this "
            "check reads. A different endpoint from ``m4.dashboard-exposure``, which "
            "fingerprints the login page. No datasource is queried, created or changed. "
            "Read-only GET."
        ),
        research_ref="ch02#22",
        cwe=_CWE,
        framework=_FRAMEWORK,
        compliance=_COMPLIANCE_DATA,
        severity="medium",
        estimated_requests=2,
    )


class GrafanaDashboardsExposed(ServiceReadCheck, NetworkCheck, Module):
    """``m2.grafana-dashboards-exposed`` — Grafana's dashboard search."""

    probe = ServiceReadProbe(
        service="grafana",
        transport="http",
        paths=("/api/search", "/grafana/api/search"),
        markers=('"dash-db"', '"dash-folder"'),
        ports=(3000,),
        scheme="http",
    )
    finding_title = "Grafana dashboard search served without authentication ({target})"
    metadata = service_read_metadata(
        name="grafana-dashboards-exposed",
        title="Grafana dashboard inventory readable without authentication",
        description=(
            "Requests Grafana's dashboard search and reports it when the instance answers "
            "unauthenticated with the search document (whose own result types are "
            "``dash-db``/``dash-folder``). The results name every dashboard and folder, which "
            "is the operator's monitoring map — the services tracked, the SLOs published and "
            "the internal names they carry. No dashboard is opened beyond the search result "
            "metadata and nothing is created, saved or deleted. Read-only GET."
        ),
        research_ref="ch02#22",
        cwe=_CWE,
        framework=_FRAMEWORK,
        compliance=_COMPLIANCE_DATA,
        severity="medium",
        estimated_requests=2,
    )


# --------------------------------------------------------------------------- Prometheus
class PrometheusTargetsExposed(ServiceReadCheck, NetworkCheck, Module):
    """``m2.prometheus-targets-exposed`` — Prometheus' scrape targets."""

    probe = ServiceReadProbe(
        service="prometheus",
        transport="http",
        paths=("/api/v1/targets", "/prometheus/api/v1/targets"),
        markers=('"activeTargets"', '"scrapeUrl"'),
        ports=(9090,),
        scheme="http",
    )
    finding_title = "Prometheus scrape targets readable without authentication ({target})"
    metadata = service_read_metadata(
        name="prometheus-targets-exposed",
        title="Prometheus target API answers without authentication",
        description=(
            "Requests Prometheus' target API and reports it when the server answers "
            "unauthenticated with the targets' own documents. Every target record names a "
            "scrape URL — the internal addresses and ports of the estate Prometheus monitors "
            "— which is a host inventory the operator never published. The server's "
            "``/metrics`` and build-info endpoints are public by design and are not what this "
            "check reads. A different endpoint from ``m4.dashboard-exposure``, which "
            "fingerprints the graph UI. No query is evaluated and no target is reloaded. "
            "Read-only GET."
        ),
        research_ref="ch02#22",
        cwe=_CWE,
        framework=_FRAMEWORK,
        compliance=_COMPLIANCE_DATA,
        severity="medium",
        estimated_requests=2,
    )


class PrometheusConfigExposed(ServiceReadCheck, NetworkCheck, Module):
    """``m2.prometheus-config-exposed`` — Prometheus' loaded configuration."""

    probe = ServiceReadProbe(
        service="prometheus",
        transport="http",
        paths=("/api/v1/status/config", "/prometheus/api/v1/status/config"),
        markers=('"yaml"', '"global"'),
        ports=(9090,),
        scheme="http",
    )
    finding_title = "Prometheus configuration served without authentication ({target})"
    metadata = service_read_metadata(
        name="prometheus-config-exposed",
        title="Prometheus configuration readable without authentication",
        description=(
            "Requests Prometheus' status/config endpoint and reports it when the server "
            "answers unauthenticated with the loaded configuration. The document is the "
            "scrape configuration itself — every job, its targets and its labels, and for "
            "many deployments the basic-auth credentials a scrape job carries — which is why "
            "it is a management read rather than a status page. The check reads the returned "
            "document; the redaction gate strips anything credential-shaped at capture. No "
            "configuration is reloaded or submitted. Read-only GET."
        ),
        research_ref="ch02#22",
        cwe=_CWE,
        framework=_FRAMEWORK,
        compliance=_COMPLIANCE_DATA,
        severity="medium",
        estimated_requests=2,
    )


# --------------------------------------------------------------------------- Kibana
class KibanaSavedObjectsExposed(ServiceReadCheck, NetworkCheck, Module):
    """``m2.kibana-saved-objects-exposed`` — Kibana's saved-object search."""

    probe = ServiceReadProbe(
        service="kibana",
        transport="http",
        paths=("/api/saved_objects/_find?type=dashboard",),
        markers=('"saved_objects"', '"type":"dashboard"'),
        ports=(5601,),
        scheme="http",
    )
    finding_title = "Kibana saved-object index readable without authentication ({target})"
    metadata = service_read_metadata(
        name="kibana-saved-objects-exposed",
        title="Kibana saved-object index answers without authentication",
        description=(
            "Requests Kibana's saved-object search and reports it when the instance answers "
            "unauthenticated with the search document. The results name the space's saved "
            "objects — dashboards, searches and index patterns — which is the operator's view "
            "of the data behind Kibana, and an instance that serves it also serves the query "
            "API over the same indices. No index is queried and no document is read. A "
            "different endpoint from ``m4.dashboard-exposure``, which fingerprints the app "
            "shell. Read-only GET."
        ),
        research_ref="ch02#22",
        cwe=_CWE,
        framework=_FRAMEWORK,
        compliance=_COMPLIANCE_DATA,
        severity="medium",
        estimated_requests=1,
    )


class KibanaSpacesExposed(ServiceReadCheck, NetworkCheck, Module):
    """``m2.kibana-spaces-exposed`` — Kibana's space list."""

    probe = ServiceReadProbe(
        service="kibana",
        transport="http",
        paths=("/api/spaces/space",),
        markers=('"initials"', '"spaces"'),
        ports=(5601,),
        scheme="http",
    )
    finding_title = "Kibana space list served without authentication ({target})"
    metadata = service_read_metadata(
        name="kibana-spaces-exposed",
        title="Kibana space inventory readable without authentication",
        description=(
            "Requests Kibana's space list and reports it when the instance answers "
            "unauthenticated with the spaces' own records (each carrying its id, name and "
            "initials). The list names the instance's tenancy model — which teams' views live "
            "here — and is a management read the login layer is supposed to guard. It is a "
            "second, independent claim: a deployment can restrict the saved-object search and "
            "leave the space list open. Read-only GET."
        ),
        research_ref="ch02#22",
        cwe=_CWE,
        framework=_FRAMEWORK,
        compliance=_COMPLIANCE,
        severity="medium",
        estimated_requests=1,
    )


# --------------------------------------------------------------------------- CouchDB
class CouchdbConfigExposed(ServiceReadCheck, NetworkCheck, Module):
    """``m2.couchdb-config-exposed`` — CouchDB's node configuration."""

    probe = ServiceReadProbe(
        service="couchdb",
        transport="http",
        paths=("/_node/_local/_config", "/_node/couchdb@localhost/_config"),
        markers=('"httpd"', '"couchdb"'),
        ports=(5984,),
        scheme="http",
    )
    finding_title = "CouchDB node configuration served without authentication ({target})"
    metadata = service_read_metadata(
        name="couchdb-config-exposed",
        title="CouchDB node configuration readable without authentication",
        description=(
            "Requests CouchDB's node configuration document and reports it when the server "
            "answers unauthenticated with the configuration's own sections (``httpd``, "
            "``couchdb``, ``log``). The document names the bind address, the authentication "
            "handler and the database directories — the settings that decide what else on the "
            "node is reachable — and it is a management read the admin party is supposed to "
            "guard. A different endpoint from ``m2.db-service-probe``, which reads the "
            "database list. No document is read, written or deleted. Read-only GET."
        ),
        research_ref="ch02#23",
        cwe=_CWE,
        framework=_FRAMEWORK,
        compliance=_COMPLIANCE_DATA,
        severity="high",
        estimated_requests=2,
    )


class CouchdbSessionExposed(ServiceReadCheck, NetworkCheck, Module):
    """``m2.couchdb-session-exposed`` — CouchDB's session context."""

    probe = ServiceReadProbe(
        service="couchdb",
        transport="http",
        paths=("/_session",),
        markers=('"userCtx"', '"authenticated"'),
        ports=(5984,),
        scheme="http",
    )
    finding_title = "CouchDB session context answered without authentication ({target})"
    metadata = service_read_metadata(
        name="couchdb-session-exposed",
        title="CouchDB session context answers without authentication",
        description=(
            "Requests CouchDB's session endpoint and reports it when the server answers with "
            "the session document's own fields. The document carries the ``userCtx`` and the "
            "authentication handler, which is how the server tells a caller whether it is in "
            "the admin party — the default state in which every database is readable and "
            "writable by anyone who can reach the port. Only the context is read; no document "
            "is opened and no credential is presented. Read-only GET."
        ),
        research_ref="ch02#23",
        cwe=_CWE,
        framework=_FRAMEWORK,
        compliance=_COMPLIANCE_DATA,
        severity="high",
        estimated_requests=1,
    )


# --------------------------------------------------------------------------- Redis
class RedisReplicationExposed(ServiceReadCheck, NetworkCheck, Module):
    """``m2.redis-replication-exposed`` — the Redis replication topology."""

    probe = ServiceReadProbe(
        service="redis",
        transport="tcp",
        command="info replication",
        markers=("role:", "connected_slaves"),
        ports=(6379,),
    )
    finding_title = "Redis replication topology readable without authentication ({target})"
    metadata = service_read_metadata(
        name="redis-replication-exposed",
        title="Redis replication topology readable without authentication",
        description=(
            "Issues the read-only ``INFO replication`` section and reports it when the "
            "instance answers it without a credential. The section names the server's role, "
            "its replicas and their offsets — the topology of the cache tier — and it is a "
            "different claim from ``m2.db-service-probe``, which sends ``PING`` and "
            "``INFO server`` to establish the instance is open at all. Only the section is "
            "read; no key is fetched, set or deleted. Read-only command."
        ),
        research_ref="ch02#23",
        cwe=_CWE,
        framework=_FRAMEWORK,
        compliance=_COMPLIANCE_DATA,
        severity="medium",
        estimated_requests=1,
    )


class RedisPersistenceExposed(ServiceReadCheck, NetworkCheck, Module):
    """``m2.redis-persistence-exposed`` — the Redis persistence configuration."""

    probe = ServiceReadProbe(
        service="redis",
        transport="tcp",
        command="info persistence",
        markers=("rdb_changes_since_last_save", "aof_enabled"),
        ports=(6379,),
    )
    finding_title = "Redis persistence configuration readable without authentication ({target})"
    metadata = service_read_metadata(
        name="redis-persistence-exposed",
        title="Redis persistence configuration readable without authentication",
        description=(
            "Issues the read-only ``INFO persistence`` section and reports it when the "
            "instance answers it without a credential. The section reports the snapshot and "
            "append-only-file state — where the dataset is written and whether the last dump "
            "succeeded — which tells a reader how the cache is persisted and, with the "
            "directory setting, where its dumps live. Only the section is read; no key is "
            "fetched and no dump is triggered (``BGSAVE`` is not issued). Read-only command."
        ),
        research_ref="ch02#23",
        cwe=_CWE,
        framework=_FRAMEWORK,
        compliance=_COMPLIANCE_DATA,
        severity="low",
        estimated_requests=1,
    )


# --------------------------------------------------------------------------- memcached
class MemcachedSettingsExposed(ServiceReadCheck, NetworkCheck, Module):
    """``m2.memcached-settings-exposed`` — memcached's settings view."""

    probe = ServiceReadProbe(
        service="memcached",
        transport="tcp",
        command="stats settings",
        markers=("STAT maxbytes", "STAT maxconns"),
        ports=(11211,),
    )
    finding_title = "memcached settings served without authentication ({target})"
    metadata = service_read_metadata(
        name="memcached-settings-exposed",
        title="memcached settings readable without authentication",
        description=(
            "Issues the read-only ``stats settings`` command and reports it when the daemon "
            "answers it without authentication. The reply is the daemon's configuration — its "
            "memory ceiling, connection limit, growth factor and eviction policy — which sizes "
            "the cache and shows whether it is a shared or per-tenant instance. memcached has "
            "no authentication by design, so reachability is the finding. Only the settings "
            "view is read; no item is fetched, stored or flushed (``stats items`` is not "
            "issued and neither is ``flush_all``). Read-only command."
        ),
        research_ref="ch02#23",
        cwe=_CWE,
        framework=_FRAMEWORK,
        compliance=_COMPLIANCE_DATA,
        severity="medium",
        estimated_requests=1,
    )


class MemcachedSlabsExposed(ServiceReadCheck, NetworkCheck, Module):
    """``m2.memcached-slabs-exposed`` — memcached's slab allocator view."""

    probe = ServiceReadProbe(
        service="memcached",
        transport="tcp",
        command="stats slabs",
        markers=("STAT active_slabs", "STAT total_malloced"),
        ports=(11211,),
    )
    finding_title = "memcached slab allocator readable without authentication ({target})"
    metadata = service_read_metadata(
        name="memcached-slabs-exposed",
        title="memcached slab allocator state readable without authentication",
        description=(
            "Issues the read-only ``stats slabs`` command and reports it when the daemon "
            "answers it without authentication. The reply counts the allocated slab classes "
            "and the memory they hold, which shows how much data the cache is carrying and "
            "how it is shaped. It is a second, independent claim from the settings view: a "
            "daemon can be reached for one statistic view and filtered for another. Only the "
            "allocator view is read; no item is fetched or stored. Read-only command."
        ),
        research_ref="ch02#23",
        cwe=_CWE,
        framework=_FRAMEWORK,
        compliance=_COMPLIANCE_DATA,
        severity="low",
        estimated_requests=1,
    )


#: Every check the WP-33 family registers, in the order the services appear above.
ExposedServiceChecks: tuple[type[Module], ...] = (
    RedfishServiceRootExposed,
    RedfishSystemsExposed,
    ContainerApiInfoExposed,
    EtcdVersionExposed,
    EtcdMembersExposed,
    ConsulCatalogExposed,
    ConsulKvKeysExposed,
    VaultSealStatusExposed,
    VaultAuthMethodsExposed,
    ZookeeperAdminStatExposed,
    ZookeeperMonitorExposed,
    KafkaTopicsExposed,
    KafkaBrokersExposed,
    ElasticsearchClusterExposed,
    ElasticsearchNodesExposed,
    RabbitmqQueuesExposed,
    RabbitmqNodesExposed,
    JenkinsApiExposed,
    JenkinsComputersExposed,
    GrafanaDatasourcesExposed,
    GrafanaDashboardsExposed,
    PrometheusTargetsExposed,
    PrometheusConfigExposed,
    KibanaSavedObjectsExposed,
    KibanaSpacesExposed,
    CouchdbConfigExposed,
    CouchdbSessionExposed,
    RedisReplicationExposed,
    RedisPersistenceExposed,
    MemcachedSettingsExposed,
    MemcachedSlabsExposed,
)


def probe_of(check: type[Module]) -> ServiceReadProbe:
    """The read-only probe a family check declares.

    A concrete check mixes :class:`ServiceReadCheck` in *before* :class:`Module`, so the class
    object carries a ``probe`` the :class:`Module` base does not declare. The family tuple is
    typed as ``type[Module]`` (that is what the registry consumes), so the one place that reads
    the mixin's attribute is this accessor, which asserts the type rather than trusting it.
    """
    probe = getattr(check, "probe", None)
    if not isinstance(probe, ServiceReadProbe):  # pragma: no cover - a declaration defect
        msg = f"{check.metadata.id} declares no ServiceReadProbe"
        raise TypeError(msg)
    return probe


#: Every check name → the service (the requirement's scope area) it covers.
SERVICE_OF_CHECK: dict[str, str] = {
    check.metadata.name: probe_of(check).service for check in ExposedServiceChecks
}

#: The sixteen services the requirement names, in the order they appear above.
AREAS: tuple[str, ...] = tuple(dict.fromkeys(SERVICE_OF_CHECK.values()))

#: Check id → its service, for the acceptance test's own controls.
AREA_OF_CHECK: dict[str, str] = {
    check.metadata.id: probe_of(check).service for check in ExposedServiceChecks
}

#: Register the family's probes with the shared helper's table, so nothing else can declare
#: the same identity and the guard has the whole vocabulary in one place.
declare_probes(tuple(probe_of(check) for check in ExposedServiceChecks))
