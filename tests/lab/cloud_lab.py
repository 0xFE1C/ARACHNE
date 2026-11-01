"""A stdlib-only *cloud* lab: real HTTP on loopback, one server, many services.

The S10 acceptance criteria need a deterministic cloud/container surface:
"misconfigured MinIO bucket, kubelet stub, repo fixture with a risky CI workflow". The repo
fixture is a directory (:mod:`tests.fixtures.repo`); this module is the reachable half: an
in-process HTTP server that answers the M5 endpoint checks with the shapes a real (but
misconfigured) S3/MinIO, Firebase, Supabase/PostgREST, Terraform backend, kubelet, Docker daemon
and OCI registry return.

Each service lives under a path prefix on one ephemeral loopback port, so a test declares one
cloud target per family::

    endpoint:http://127.0.0.1:<port>/storage/backup
    endpoint:http://127.0.0.1:<port>/firebase
    endpoint:http://127.0.0.1:<port>/supabase
    endpoint:http://127.0.0.1:<port>/tfstate
    endpoint:http://127.0.0.1:<port>/kubelet
    endpoint:http://127.0.0.1:<port>/registry
    endpoint:http://127.0.0.1:<port>/docker

The hardened counterparts (``/storage/private``, ``/graphql-safe``, ``/kubelet-hardened``)
answer with an authentication challenge, so the acceptance test can score false positives.
"""

from __future__ import annotations

import json
import threading
import urllib.parse
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

__all__ = [
    "CLOUD_FALSE_POSITIVE_TRAPS",
    "CLOUD_GROUND_TRUTH",
    "CloudLab",
    "start_cloud_lab",
]

_BUCKET_LISTING = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    "<ListBucketResult><Name>backup</Name><IsTruncated>false</IsTruncated>"
    "<Contents><Key>db.sql</Key><Size>2048</Size></Contents>"
    "<Contents><Key>users.csv</Key><Size>512</Size></Contents>"
    "</ListBucketResult>"
)
_BUCKET_ACL = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    "<AccessControlPolicy><Owner><ID>lab</ID></Owner><AccessControlList>"
    "<Grant><Grantee><ID>AllUsers</ID></Grantee><Permission>READ</Permission></Grant>"
    "</AccessControlList></AccessControlPolicy>"
)
_FIREBASE_JSON = json.dumps(
    {"users": {"1": {"email": "alice@example.com"}}, "config": {"plan": "pro"}}
)
_TABLES = {
    "users": [{"id": 1, "email": "alice@example.com"}, {"id": 2, "email": "bob@example.com"}],
    "orders": [{"id": 10, "total": 42}],
}
_TFSTATE = json.dumps(
    {
        "version": 4,
        "terraform_version": "1.7.5",
        "serial": 3,
        "outputs": {},
        "resources": [
            {
                "type": "aws_db_instance",
                "name": "main",
                "instances": [
                    {
                        "attributes": {
                            "password": "state-db-password",
                            "endpoint": "db.internal:5432",
                            "publicly_accessible": True,
                        }
                    }
                ],
            }
        ],
    }
)
_PODLIST = json.dumps(
    {
        "kind": "PodList",
        "apiVersion": "v1",
        "items": [
            {
                "metadata": {"name": "api-0", "namespace": "prod"},
                "spec": {
                    "containers": [
                        {
                            "name": "api",
                            "env": [{"name": "AWS_SECRET_ACCESS_KEY", "value": "pod-secret"}],
                        }
                    ]
                },
            }
        ],
    }
)
_DASHBOARD = (
    "<!doctype html><html><head><title>Kubernetes Dashboard</title></head><body>"
    "<h1>Kubernetes Dashboard</h1><p>k8s-app: kubernetes-dashboard</p></body></html>"
)
_DOCKER_VERSION = json.dumps(
    {"ApiVersion": "1.44", "OSType": "linux", "KernelVersion": "6.8.0", "Version": "26.1.0"}
)
_DOCKER_CONTAINERS = json.dumps(
    [
        {
            "Id": "c1",
            "Image": "registry.local/api:latest",
            "State": "running",
            "HostConfig": {"Privileged": True},
        }
    ]
)
_REGISTRY_CATALOG = json.dumps({"repositories": ["api", "worker", "internal/admin"]})
_REGISTRY_TAGS = json.dumps({"name": "api", "tags": ["latest", "1.0.0"]})

#: The continuous cloud-config snapshot (S23, REQ-POSTURE-001): a *mutable* normalized
#: estate. The initial state carries one standing policy breach (an unencrypted archive
#: bucket) and is otherwise clean, so the first continuous run establishes the baseline
#: with exactly one finding and the drift tests mutate ``posture_state`` between runs:
#: making the app bucket public yields a delta finding whose artifact carries before/after.
POSTURE_SNAPSHOT_STATE: dict[str, object] = {
    "provider": "aws",
    "account": "000000000000",
    "resources": [
        {
            "id": "app-assets",
            "service": "storage",
            "type": "storage",
            "region": "us-east-1",
            "name": "app-assets",
            "config": {"public": False, "encrypted": True},
        },
        {
            "id": "logs-archive",
            "service": "storage",
            "type": "storage",
            "region": "us-east-1",
            "name": "logs-archive",
            "config": {"public": False, "encrypted": False},
        },
        {
            "id": "orders-db",
            "service": "database",
            "type": "database",
            "region": "us-east-1",
            "name": "orders-db",
            "config": {"publicly_accessible": False, "encrypted": True},
        },
        {
            "id": "sg-app",
            "service": "network",
            "type": "network",
            "region": "us-east-1",
            "name": "sg-app",
            "config": {"open_to_world": False, "open_cidrs": ["10.0.0.0/8"]},
        },
        {
            "id": "app-runtime",
            "service": "iam",
            "type": "iam",
            "region": "us-east-1",
            "name": "app-runtime",
            "config": {"wildcard_actions": False},
        },
    ],
}
_IMDS_V1 = "ami-id\nami-launch-index\niam/\ninstance-id\n"
_AZURE_INSTANCE = json.dumps(
    {"compute": {"azEnvironment": "AzurePublicCloud", "name": "lab-vm", "subscriptionId": "0000"}}
)
_AZURE_TOKEN = json.dumps(
    {"access_token": "not-a-real-token", "expires_on": "9999999999", "token_type": "Bearer"}
)
_GCP_TOKEN = json.dumps(
    {"access_token": "not-a-real-token", "expires_in": 3599, "token_type": "Bearer"}
)

#: ``(check id, marker)`` pairs the cloud lab plants, in the shape the M3/M4 labs use.
CLOUD_GROUND_TRUTH: tuple[tuple[str, str], ...] = (
    ("m5.bucket-enumerator", "bucket-enumeration"),
    ("m5.firebase-rules", "firebase-open-rules"),
    ("m5.supabase-rls", "supabase-open-rls"),
    ("m5.tfstate-exposure", "tfstate-exposure"),
    ("m5.k8s-exposure", "k8s-kubelet-unauth"),
    ("m5.registry-scan", "registry-catalog"),
    ("m5.docker-socket", "docker-api"),
    ("m5.imds-ssrf", "imds-ssrf"),
    ("m5.azure-mi-audit", "azure-managed-identity"),
)

#: Hardened counterparts: a candidate matching one of these is a false positive.
CLOUD_FALSE_POSITIVE_TRAPS: tuple[tuple[str, str], ...] = (
    ("m5.bucket-enumerator", "/storage/private"),
    ("m5.k8s-exposure", "/kubelet-hardened"),
)


@dataclass
class CloudLab:
    """A running cloud lab: its base URL, its planted set and the requests it answered."""

    base_url: str = ""
    port: int = 0
    requests: list[str] = field(default_factory=list)
    ground_truth: tuple[tuple[str, str], ...] = CLOUD_GROUND_TRUTH
    false_positives: tuple[tuple[str, str], ...] = CLOUD_FALSE_POSITIVE_TRAPS
    #: The mutable cloud-config snapshot the continuous check reads (S23). Tests mutate
    #: this dict between runs to create drift.
    posture_state: dict[str, object] = field(
        default_factory=lambda: json.loads(json.dumps(POSTURE_SNAPSHOT_STATE))
    )
    #: The bucket names the storage half answers publicly. The fix-verification test
    #: removes/re-adds ``backup`` here to simulate fix → regression on the real lab.
    public_buckets: set[str] = field(default_factory=lambda: {"backup"})

    @property
    def host(self) -> str:
        return f"127.0.0.1:{self.port}"

    def endpoint(self, prefix: str = "") -> str:
        return f"{self.base_url.rstrip('/')}/{prefix.lstrip('/')}"


class _Handler(BaseHTTPRequestHandler):
    server_version = "arachne-cloud-lab/1.0"
    protocol_version = "HTTP/1.1"
    lab: CloudLab

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - stdlib signature
        return

    def _respond(
        self,
        status: int,
        body: str,
        *,
        content_type: str = "application/json",
        headers: dict[str, str] | None = None,
    ) -> None:
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def do_GET(self) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        self.lab.requests.append(f"GET {self.path}")
        path = parsed.path
        query = parsed.query

        if path.startswith("/storage/"):
            self._storage(path, query)
            return
        if path.startswith("/firebase"):
            self._respond(200, _FIREBASE_JSON)
            return
        if path.startswith("/supabase/rest/v1"):
            self._supabase(path)
            return
        if path.startswith("/tfstate"):
            if path.endswith(".tfstate"):
                self._respond(200, _TFSTATE, content_type="application/json")
                return
            self._respond(404, "{}")
            return
        if path == "/kubelet/pods" or path == "/kubelet/runningpods":
            self._respond(200, _PODLIST)
            return
        if path == "/kubelet/metrics" or path == "/kubelet/stats/summary":
            self._respond(200, "metrics", content_type="text/plain")
            return
        if path.startswith("/kubelet/api/v1/namespaces/kubernetes-dashboard"):
            self._respond(200, _DASHBOARD, content_type="text/html")
            return
        if path.startswith("/kubelet-hardened"):
            self._respond(401, json.dumps({"error": "unauthorized"}))
            return
        if path == "/docker/version":
            self._respond(200, _DOCKER_VERSION)
            return
        if path == "/docker/info":
            self._respond(200, _DOCKER_VERSION)
            return
        if path == "/docker/containers/json":
            self._respond(200, _DOCKER_CONTAINERS)
            return
        if path == "/docker/images/json":
            self._respond(200, json.dumps([{"Id": "sha256:lab", "RepoTags": ["api:latest"]}]))
            return
        if path == "/registry/v2/_catalog":
            self._respond(200, _REGISTRY_CATALOG)
            return
        if path.startswith("/registry/v2/") and path.endswith("/tags/list"):
            self._respond(200, _REGISTRY_TAGS)
            return
        # The SSRF sink the M5 metadata checks inject into (a query-parameter fetcher).
        if path == "/fetch":
            self._fetch(query)
            return
        # The continuous cloud-config snapshot (S23, REQ-POSTURE-001): the current,
        # mutable estate state; one read-only GET.
        if path in {"/posture/snapshot", "/_arachne/posture"}:
            self._respond(200, json.dumps(self.lab.posture_state))
            return
        self._respond(404, json.dumps({"error": "not found"}))

    def do_HEAD(self) -> None:
        self.do_GET()

    def _storage(self, path: str, query: str) -> None:
        name = path.rstrip("/").rsplit("/", 1)[-1]
        if name == "private":
            self._respond(
                403,
                '<?xml version="1.0"?><Error><Code>AccessDenied</Code></Error>',
                content_type="application/xml",
            )
            return
        if name == "backup":
            if name not in self.lab.public_buckets:
                # "Fixed": the bucket no longer grants anonymous access at all.
                self._respond(
                    404,
                    '<?xml version="1.0"?><Error><Code>NoSuchBucket</Code></Error>',
                    content_type="application/xml",
                )
                return
            if "acl" in query:
                self._respond(200, _BUCKET_ACL, content_type="application/xml")
                return
            if "list-type" in query:
                self._respond(200, _BUCKET_LISTING, content_type="application/xml")
                return
        self._respond(
            404,
            '<?xml version="1.0"?><Error><Code>NoSuchBucket</Code></Error>',
            content_type="application/xml",
        )

    def _supabase(self, path: str) -> None:
        table = path.rstrip("/").rsplit("/", 1)[-1]
        if table in _TABLES:
            self._respond(200, json.dumps(_TABLES[table]))
            return
        if path.rstrip("/").endswith("/rest/v1"):
            self._respond(200, json.dumps({"swagger": "2.0", "definitions": {}, "paths": {}}))
            return
        self._respond(404, json.dumps({"message": "table not found"}))

    def _fetch(self, query: str) -> None:
        params = urllib.parse.parse_qs(query)
        target = (params.get("url") or [""])[0]
        if "metadata/instance" in target:
            self._respond(200, _AZURE_INSTANCE)
            return
        if "metadata/identity" in target:
            self._respond(200, _AZURE_TOKEN)
            return
        if "computeMetadata" in target or "service-accounts" in target:
            self._respond(200, _GCP_TOKEN, headers={"Metadata-Flavor": "Google"})
            return
        if "169.254.169.254" in target or "metadata.google.internal" in target:
            self._respond(200, _IMDS_V1, content_type="text/plain")
            return
        self._respond(400, json.dumps({"error": "unsupported url"}))


@contextmanager
def start_cloud_lab() -> Iterator[CloudLab]:
    """Start the cloud lab on loopback and yield its handle; tear it down on exit."""
    lab = CloudLab()
    handler = type("_BoundCloudHandler", (_Handler,), {"lab": lab})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    server.daemon_threads = True
    port = server.server_address[1]
    lab.port = port
    lab.base_url = f"http://127.0.0.1:{port}/"
    thread = threading.Thread(target=server.serve_forever, name="arachne-cloud-lab", daemon=True)
    thread.start()
    try:
        yield lab
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
