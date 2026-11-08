"""A loopback Azure/GCP/Kubernetes read-only API fixture for the posture checks (WP-32).

Three provider prefixes live on one server — ``/azure/<account>``, ``/gcp/<account>`` and
``/k8s/<account>`` — each with a ``risky`` account that carries a breach for every policy its
family checks and a ``safe`` account that carries the hardened counterpart (the requirement's
decoy: "each provider ships a hardened fixture"). Every request must carry
``Authorization: Bearer <lab token>``; the fixture answers ``401`` without one and ``403`` with
the wrong one, which is what makes the credential path a test rather than an assertion — a check
that did not authenticate gets no data, so "the posture came from a credentialed read" is
falsifiable.

Two traps make the *read-only* claim falsifiable too:

* any ``PUT``/``POST``/``PATCH``/``DELETE`` is refused with ``405`` and recorded, so a write
  attempt is visible in the request log rather than merely absent by convention;
* any request whose path reaches a Kubernetes **secret** is recorded separately in
  :attr:`CloudLab.secret_reads` and answered with a decoy body. The family establishes that
  secrets are *listable* from RBAC metadata and never reads one, so the assertion
  ``lab.secret_reads == []`` is the wire-level half of that rule.

The ``safe`` accounts are deliberately *plausible* hardened estates rather than empty ones: the
Kubernetes one ships the built-in ``cluster-admin`` ClusterRole (a wildcard by design) and binds
it to a named user, and ships a Dashboard service of type ``ClusterIP``. A check that reported
built-in roles, ignored the binding's subject or ignored the service type would fire on it, so
"silent on the decoy" is a real test of those exclusions rather than of an empty fixture.
"""

from __future__ import annotations

import json
import threading
import urllib.parse
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Final

__all__ = [
    "ACCOUNTS",
    "AZURE_SUBSCRIPTION",
    "CLOUD_LAB_TOKEN",
    "DECOY",
    "GCP_PROJECT",
    "POSITIVE",
    "PROVIDERS",
    "CloudLab",
    "resolve",
    "start_cloud_lab",
]

#: The lab credential. Test constants, never a real credential.
CLOUD_LAB_TOKEN: Final = "arachne-lab-bearer-token-not-a-real-credential"

#: The subscription and project the checks are told to scope their paths to. The fixture
#: ignores the values, so a test can assert the *configured* value reached the request.
AZURE_SUBSCRIPTION: Final = "00000000-0000-0000-0000-000000000000"
GCP_PROJECT: Final = "arachne-lab"

#: The three provider prefixes the fixture serves.
PROVIDERS: Final[frozenset[str]] = frozenset({"azure", "gcp", "k8s"})

#: The accounts the fixture serves: the positive and the requirement's decoy.
POSITIVE: Final = "risky"
DECOY: Final = "safe"


def _arm(*resources: Mapping[str, Any]) -> Mapping[str, Any]:
    """An ARM list answer: the ``value`` envelope every Azure resource list uses."""
    return {"value": list(resources)}


# --------------------------------------------------------------------------- the accounts
ACCOUNTS: Final[dict[str, dict[str, Any]]] = {
    "azure": {
        "risky": {
            "storageAccounts": _arm(
                {
                    "name": "riskyblobs",
                    "properties": {
                        "allowBlobPublicAccess": True,
                        "minimumTlsVersion": "TLS1_0",
                        "networkAcls": {"defaultAction": "Allow"},
                    },
                }
            ),
            "networkSecurityGroups": _arm(
                {
                    "name": "risky-nsg",
                    "properties": {
                        "securityRules": [
                            {
                                "name": "allow-ssh-from-anywhere",
                                "properties": {
                                    "direction": "Inbound",
                                    "access": "Allow",
                                    "destinationPortRange": "22",
                                    "sourceAddressPrefix": "*",
                                },
                            },
                            {
                                "name": "allow-rdp-from-anywhere",
                                "properties": {
                                    "direction": "Inbound",
                                    "access": "Allow",
                                    "destinationPortRange": "3389",
                                    "sourceAddressPrefix": "0.0.0.0/0",
                                },
                            },
                        ]
                    },
                }
            ),
            "vaults": _arm(
                {
                    "name": "risky-vault",
                    "properties": {
                        "publicNetworkAccess": "Enabled",
                        "enablePurgeProtection": False,
                        "networkAcls": {"defaultAction": "Allow"},
                    },
                }
            ),
            "servers": _arm(
                {"name": "risky-sql", "properties": {"publicNetworkAccess": "Enabled"}}
            ),
            "managedClusters": _arm(
                {
                    "name": "risky-aks",
                    "properties": {
                        "apiServerAccessProfile": {
                            "enablePrivateCluster": False,
                            "authorizedIpRanges": [],
                        },
                        "enableRBAC": False,
                    },
                }
            ),
            "sites": _arm({"name": "risky-app", "properties": {"httpsOnly": False}}),
        },
        "safe": {
            "storageAccounts": _arm(
                {
                    "name": "safeblobs",
                    "properties": {
                        "allowBlobPublicAccess": False,
                        "minimumTlsVersion": "TLS1_2",
                        "networkAcls": {"defaultAction": "Deny"},
                    },
                }
            ),
            "networkSecurityGroups": _arm(
                {
                    "name": "safe-nsg",
                    "properties": {
                        "securityRules": [
                            {
                                "name": "allow-ssh-internal",
                                "properties": {
                                    "direction": "Inbound",
                                    "access": "Allow",
                                    "destinationPortRange": "22",
                                    "sourceAddressPrefix": "10.0.0.0/8",
                                },
                            }
                        ]
                    },
                }
            ),
            "vaults": _arm(
                {
                    "name": "safe-vault",
                    "properties": {
                        "publicNetworkAccess": "Disabled",
                        "enablePurgeProtection": True,
                        "networkAcls": {"defaultAction": "Deny"},
                    },
                }
            ),
            "servers": _arm(
                {"name": "safe-sql", "properties": {"publicNetworkAccess": "Disabled"}}
            ),
            "managedClusters": _arm(
                {
                    "name": "safe-aks",
                    "properties": {
                        "apiServerAccessProfile": {
                            "enablePrivateCluster": True,
                            "authorizedIpRanges": [],
                        },
                        "enableRBAC": True,
                    },
                }
            ),
            "sites": _arm({"name": "safe-app", "properties": {"httpsOnly": True}}),
        },
    },
    "gcp": {
        "risky": {
            "buckets": {
                "items": [
                    {
                        "name": "risky-bucket",
                        "iamConfiguration": {
                            "publicAccessPrevention": "inherited",
                            "uniformBucketLevelAccess": {"enabled": False},
                        },
                    }
                ]
            },
            "clusters": {
                "clusters": [
                    {
                        "name": "risky-cluster",
                        "masterAuthorizedNetworksConfig": {"enabled": False},
                        "privateClusterConfig": {"enablePrivateNodes": False},
                        "loggingService": "none",
                    }
                ]
            },
            "serviceAccounts": {
                "accounts": [{"email": "risky-sa@arachne-lab.iam.gserviceaccount.com"}]
            },
            "serviceAccountKeys": {
                "keys": [
                    {
                        "name": "projects/arachne-lab/serviceAccounts/risky-sa/keys/key-1",
                        "keyType": "USER_MANAGED",
                        "validAfterTime": "2024-01-01T00:00:00Z",
                    }
                ]
            },
            "sqlInstances": {
                "items": [
                    {
                        "name": "risky-sql",
                        "settings": {
                            "ipConfiguration": {
                                "ipv4Enabled": True,
                                "requireSsl": False,
                                "authorizedNetworks": [],
                            }
                        },
                    }
                ]
            },
            "functions": {"functions": [{"name": "risky-fn", "ingressSettings": "ALLOW_ALL"}]},
        },
        "safe": {
            "buckets": {
                "items": [
                    {
                        "name": "safe-bucket",
                        "iamConfiguration": {
                            "publicAccessPrevention": "enforced",
                            "uniformBucketLevelAccess": {"enabled": True},
                        },
                    }
                ]
            },
            "clusters": {
                "clusters": [
                    {
                        "name": "safe-cluster",
                        "masterAuthorizedNetworksConfig": {"enabled": True},
                        "privateClusterConfig": {"enablePrivateNodes": True},
                        "loggingService": "logging.googleapis.com",
                    }
                ]
            },
            "serviceAccounts": {
                "accounts": [{"email": "safe-sa@arachne-lab.iam.gserviceaccount.com"}]
            },
            "serviceAccountKeys": {
                "keys": [
                    {
                        "name": "projects/arachne-lab/serviceAccounts/safe-sa/keys/key-1",
                        "keyType": "SYSTEM_MANAGED",
                        "validAfterTime": "2026-01-01T00:00:00Z",
                    }
                ]
            },
            "sqlInstances": {
                "items": [
                    {
                        "name": "safe-sql",
                        "settings": {
                            "ipConfiguration": {
                                "ipv4Enabled": True,
                                "requireSsl": True,
                                "authorizedNetworks": [{"value": "10.0.0.0/8"}],
                            }
                        },
                    }
                ]
            },
            "functions": {
                "functions": [{"name": "safe-fn", "ingressSettings": "ALLOW_INTERNAL_ONLY"}]
            },
        },
    },
    "k8s": {
        "risky": {
            "pods": {
                "items": [
                    {
                        "metadata": {"name": "risky-privileged", "namespace": "default"},
                        "spec": {
                            "containers": [{"name": "app", "securityContext": {"privileged": True}}]
                        },
                    },
                    {
                        "metadata": {"name": "risky-hostpath", "namespace": "default"},
                        "spec": {
                            "containers": [{"name": "app"}],
                            "volumes": [{"name": "host-root", "hostPath": {"path": "/"}}],
                        },
                    },
                ]
            },
            "services": {
                "items": [
                    {
                        "metadata": {"name": "kubernetes-dashboard", "namespace": "kube-system"},
                        "spec": {"type": "LoadBalancer"},
                    }
                ]
            },
            "clusterroles": {
                "items": [
                    {
                        "metadata": {"name": "cluster-admin"},
                        "rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}],
                    },
                    {
                        "metadata": {"name": "custom-wildcard"},
                        "rules": [
                            {"apiGroups": ["*"], "resources": ["*"], "verbs": ["get", "list", "*"]}
                        ],
                    },
                    {
                        "metadata": {"name": "custom-secret-reader"},
                        "rules": [
                            {"apiGroups": [""], "resources": ["secrets"], "verbs": ["get", "list"]}
                        ],
                    },
                ]
            },
            "clusterrolebindings": {
                "items": [
                    {
                        "metadata": {"name": "custom-wildcard-binding"},
                        "roleRef": {"kind": "ClusterRole", "name": "custom-wildcard"},
                        "subjects": [{"kind": "Group", "name": "system:authenticated"}],
                    },
                    {
                        "metadata": {"name": "custom-secret-binding"},
                        "roleRef": {"kind": "ClusterRole", "name": "custom-secret-reader"},
                        "subjects": [{"kind": "Group", "name": "system:authenticated"}],
                    },
                    {
                        "metadata": {"name": "admin-binding"},
                        "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
                        "subjects": [{"kind": "Group", "name": "system:authenticated"}],
                    },
                    {
                        "metadata": {"name": "anonymous-binding"},
                        "roleRef": {"kind": "ClusterRole", "name": "custom-wildcard"},
                        "subjects": [{"kind": "Group", "name": "system:unauthenticated"}],
                    },
                ]
            },
            "nodes": {"items": [{"metadata": {"name": "risky-node"}}]},
            "kubeletConfig": {
                "kubeletconfig": {
                    "readOnlyPort": 10255,
                    "authentication": {"anonymous": {"enabled": True}},
                }
            },
            "validatingWebhooks": {
                "items": [
                    {
                        "metadata": {"name": "risky-webhook"},
                        "webhooks": [{"name": "policy.example.com", "failurePolicy": "Ignore"}],
                    }
                ]
            },
        },
        "safe": {
            "pods": {
                "items": [
                    {
                        "metadata": {"name": "safe-pod", "namespace": "default"},
                        "spec": {
                            "containers": [
                                {"name": "app", "securityContext": {"privileged": False}}
                            ],
                            "volumes": [{"name": "config", "configMap": {"name": "app-config"}}],
                        },
                    }
                ]
            },
            "services": {
                "items": [
                    {
                        "metadata": {"name": "kubernetes-dashboard", "namespace": "kube-system"},
                        "spec": {"type": "ClusterIP"},
                    }
                ]
            },
            "clusterroles": {
                "items": [
                    {
                        "metadata": {"name": "cluster-admin"},
                        "rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}],
                    },
                    {
                        "metadata": {"name": "system:discovery"},
                        "rules": [
                            {
                                "apiGroups": [""],
                                "resources": ["*"],
                                "verbs": ["get"],
                                "nonResourceURLs": ["*"],
                            }
                        ],
                    },
                    {
                        "metadata": {"name": "safe-configmap-reader"},
                        "rules": [
                            {"apiGroups": [""], "resources": ["configmaps"], "verbs": ["get"]}
                        ],
                    },
                ]
            },
            "clusterrolebindings": {
                "items": [
                    {
                        "metadata": {"name": "safe-admin-binding"},
                        "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
                        "subjects": [{"kind": "User", "name": "admin@example.com"}],
                    },
                    {
                        "metadata": {"name": "safe-configmap-binding"},
                        "roleRef": {"kind": "ClusterRole", "name": "safe-configmap-reader"},
                        "subjects": [
                            {"kind": "ServiceAccount", "name": "app", "namespace": "default"}
                        ],
                    },
                ]
            },
            "nodes": {"items": [{"metadata": {"name": "safe-node"}}]},
            "kubeletConfig": {
                "kubeletconfig": {
                    "readOnlyPort": 0,
                    "authentication": {"anonymous": {"enabled": False}},
                }
            },
            "validatingWebhooks": {
                "items": [
                    {
                        "metadata": {"name": "safe-webhook"},
                        "webhooks": [{"name": "policy.example.com", "failurePolicy": "Fail"}],
                    }
                ]
            },
        },
    },
}

#: The decoy body a request for a Kubernetes secret is answered with. Reaching this path is a
#: defect in the family, not a discovery, so the body is obviously synthetic.
_SECRET_DECOY: Final[Mapping[str, Any]] = {
    "items": [{"metadata": {"name": "decoy"}, "data": {"password": "YXJhY2huZS1kZWNveQ=="}}]
}

#: The resources each Azure ARM path addresses, keyed by the last path segment.
_AZURE_RESOURCES: Final[frozenset[str]] = frozenset(
    {"storageAccounts", "networkSecurityGroups", "vaults", "servers", "managedClusters", "sites"}
)


@dataclass
class CloudLab:
    """A running fixture: its loopback base and the requests it answered."""

    port: int = 0
    base_url: str = ""
    #: ``"<method> <provider> <account> <path>"`` per request the fixture saw.
    requests: list[str] = field(default_factory=list)
    #: ``(provider, account, path)`` per request the fixture *answered* (a 2xx).
    answered: list[tuple[str, str, str]] = field(default_factory=list)
    #: Every request whose path reached a Kubernetes secret. Must stay empty.
    secret_reads: list[str] = field(default_factory=list)

    def endpoint(self, provider: str, account: str) -> str:
        """The ``<provider>-posture:<base>`` value for one account (``risky`` or ``safe``)."""
        prefix = "k8s" if provider == "kubernetes" else provider
        return f"{self.base_url.rstrip('/')}/{prefix}/{account}"

    def paths(self, provider: str, account: str) -> list[str]:
        """The paths answered for one provider's account (query strings already stripped)."""
        return [path for name, who, path in self.answered if name == provider and who == account]

    def methods(self) -> set[str]:
        return {entry.split(" ", 1)[0].upper() for entry in self.requests}


# --------------------------------------------------------------------------- dispatch
def _segments(path: str) -> list[str]:
    return [part for part in path.strip("/").split("/") if part]


def resolve(provider: str, rest: list[str]) -> str:
    """The resource kind a request path addresses, or ``""`` when the fixture has none.

    The paths are the documented ones the module allowlists carry, so this mapping is the
    fixture's half of "the checks issued the operation they declared".
    """
    joined = "/".join(rest)
    if rest[-1:] == ["secrets"] or "/secrets/" in f"/{joined}":
        return "secrets"
    if provider == "azure":
        return rest[-1] if rest and rest[-1] in _AZURE_RESOURCES else ""
    if provider == "gcp":
        if joined == "storage/v1/b":
            return "buckets"
        if joined.startswith("container/v1/") and joined.endswith("/clusters"):
            return "clusters"
        if rest[-1:] == ["keys"] and "serviceAccounts" in rest:
            return "serviceAccountKeys"
        if joined.startswith("v1/projects/") and joined.endswith("/serviceAccounts"):
            return "serviceAccounts"
        if joined.startswith("sql/v1beta4/") and joined.endswith("/instances"):
            return "sqlInstances"
        if joined.startswith("v1/projects/") and joined.endswith("/functions"):
            return "functions"
        return ""
    if provider == "k8s":
        if joined == "api/v1/pods":
            return "pods"
        if joined == "api/v1/services":
            return "services"
        if joined == "api/v1/nodes":
            return "nodes"
        if rest[:3] == ["api", "v1", "nodes"] and rest[-1] == "configz":
            return "kubeletConfig"
        if rest[-1:] == ["clusterroles"]:
            return "clusterroles"
        if rest[-1:] == ["clusterrolebindings"]:
            return "clusterrolebindings"
        if rest[-1:] == ["validatingwebhookconfigurations"]:
            return "validatingWebhooks"
        return ""
    return ""  # pragma: no cover - the handler only routes the three providers


def _response(provider: str, account: str, kind: str) -> tuple[int, Mapping[str, Any]]:
    if kind == "secrets":
        return 200, _SECRET_DECOY
    resource = ACCOUNTS.get(provider, {}).get(account, {}).get(kind)
    if resource is None:
        return 404, {"error": {"code": "NotFound", "message": kind}}
    return 200, resource


class _Handler(BaseHTTPRequestHandler):
    server_version = "arachne-cloud-lab/1.0"
    protocol_version = "HTTP/1.1"
    disable_nagle_algorithm = True  # the same Nagle/delayed-ACK stall as the other labs
    lab: CloudLab

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - stdlib signature
        return

    def _respond(self, status: int, body: Mapping[str, Any] | str) -> None:
        text = body if isinstance(body, str) else json.dumps(body)
        payload = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def _handle(self) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        segments = _segments(parsed.path)
        provider = segments[0] if segments else ""
        account = segments[1] if len(segments) > 1 else ""
        self.lab.requests.append(f"{self.command} {provider} {account} {parsed.path}")
        if provider not in PROVIDERS or account not in ACCOUNTS.get(provider, {}):
            self._respond(404, {"error": {"code": "UnknownAccount", "message": account}})
            return
        authorization = self.headers.get("Authorization", "")
        if not authorization:
            self._respond(401, {"error": {"code": "Unauthorized", "message": "no credential"}})
            return
        if authorization != f"Bearer {CLOUD_LAB_TOKEN}":
            self._respond(403, {"error": {"code": "Forbidden", "message": "bad credential"}})
            return
        kind = resolve(provider, segments[2:])
        if kind == "secrets":
            self.lab.secret_reads.append(f"{provider} {parsed.path}")
        if not kind:
            self._respond(404, {"error": {"code": "NotFound", "message": parsed.path}})
            return
        status, document = _response(provider, account, kind)
        self.lab.answered.append((provider, account, parsed.path))
        self._respond(status, document)

    def do_GET(self) -> None:
        self._handle()

    def _refuse_write(self) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        self.lab.requests.append(f"{self.command} write-refused {parsed.path}")
        self._respond(405, {"error": {"code": "MethodNotAllowed", "message": self.command}})

    def do_PUT(self) -> None:
        self._refuse_write()

    def do_POST(self) -> None:
        self._refuse_write()

    def do_PATCH(self) -> None:
        self._refuse_write()

    def do_DELETE(self) -> None:
        self._refuse_write()


@contextmanager
def start_cloud_lab() -> Iterator[CloudLab]:
    """Start the fixture on loopback and yield its handle; tear it down on exit."""
    lab = CloudLab()
    handler = type("_BoundCloudHandler", (_Handler,), {"lab": lab})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    server.daemon_threads = True
    port = server.server_address[1]
    lab.port = port
    lab.base_url = f"http://127.0.0.1:{port}/"
    thread = threading.Thread(
        target=server.serve_forever, args=(0.05,), name="arachne-cloud-lab", daemon=True
    )
    thread.start()
    try:
        yield lab
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
