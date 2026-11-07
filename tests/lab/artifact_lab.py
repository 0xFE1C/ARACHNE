"""The source-control, CI and infrastructure-artifact lab (WP-29, REQ-DET-022).

The requirement's acceptance needs a **positive fixture** and a **decoy** per family, and names
the decoy: "servers that answer every artifact path with a generic 404 or an error page that
echoes nothing". This module serves the eight families the requirement's scope names from
their own origins, in four modes:

``vulnerable``
    A deployment whose web root exposes exactly the artifacts its family's three checks
    establish, each with the content that proves it: the ``.git`` reflog and a credential
    store holding a token; a GitHub Actions workflow, another CI system's pipeline and a
    pipeline that carries provider keys; a Terraform state file (with a credentialed
    connection string a resource stored), a plan and the dependency lock; the AWS credential
    file, the cloud CLIs' credential stores and a service-account key; a Compose file, a
    Dockerfile and the Kubernetes manifests; vim swap and tilde backup residue and the
    operating systems' directory metadata; the package-manager and registry credential
    configuration and the authorization files; and the environment-file variants, a secrets
    file and a framework configuration module.
``not-found``
    The hardened deployment: the site is served, and **every artifact path answers the
    installation's own 404** — a stock not-found page that echoes nothing. A check that
    fired on a status code, or on a page that merely mentions the path it was asked for,
    would report the refusal as an exposure.
``error-page``
    The same deployment with a broken backend: every artifact path answers a generic ``500``
    error page that names no artifact and echoes nothing.
``echo-404``
    The archetype the pitfall names — used by one dedicated test rather than the whole matrix,
    because it is the sharpest trap: every artifact path answers ``200 OK`` with a page that
    *echoes the requested path* and says the resource was not found. Only a check that
    requires the artifact's own content (or its own declared binary suffix) stays silent.

**The cross-family decoy.** The eight ``vulnerable`` installations are decoys for one
another's checks: the CI area's origin serves no Terraform state, so a Terraform check that
fired there would be reporting something that installation never published.

**No credential literal in this file, and no usable credential anywhere.** The repository's
credential gate and the pre-commit secret scanner both read test sources, so the planted
values are **assembled at import time** from the fixture's own derived material
(:func:`_derive`) rather than written as literals. Each value has the *shape* the capture path
redacts — a GitHub token in a remote URL, provider access keys, a credentialed connection
string, a JSON web token in a token cache, a PEM private block — and none of them
authenticates anything, anywhere: they are digest outputs over the string
``"arachne-wp29-lab:<label>"`` with no secret input. :data:`PLANTED_SECRETS` exposes the
assembled values so the acceptance test can assert none of them survives into an evidence
payload. No route authenticates, no route accepts a body, and nothing is cloned or
reconstructed.
"""

from __future__ import annotations

import base64
import hashlib
import json
import threading
import urllib.parse
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

__all__ = [
    "AREAS",
    "MODES",
    "OVERSIZED_PLAN_BYTES",
    "PATHS_BY_AREA",
    "PLANTED_SECRETS",
    "ArtifactLab",
    "start_artifact_lab",
]

#: The eight scope areas the requirement names. Each owns three of the family's checks.
AREAS: tuple[str, ...] = (
    "dvcs",
    "ci",
    "terraform",
    "cloud-credentials",
    "containers",
    "editor-residue",
    "credential-files",
    "env-variants",
)

#: The four modes. The first is the positive fixture; the next two are the requirement's own
#: decoys (the matrix runs those three); ``echo-404`` is the pitfall trap, driven by its own
#: test because it is the sharpest one.
MODES: tuple[str, ...] = ("vulnerable", "not-found", "error-page", "echo-404")

#: The PEM header and footer. A format, not a key: the block body below is the fixture's own
#: derived value, and the *shape* is what the redactor's private-key detector recognises.
_PEM_HEADER = "-----BEGIN PRIVATE KEY-----"
_PEM_FOOTER = "-----END PRIVATE KEY-----"


def _derive(label: str, *, length: int) -> str:
    """A deterministic fixture value: digest output, never a credential.

    No randomness, because a fixture must be reproducible — two runs against the same input
    produce the same verdict. No secret input either: the value is a function of the label
    alone, so it cannot authenticate anything and rotating it is meaningless.
    """
    digest = hashlib.sha256(f"arachne-wp29-lab:{label}".encode()).hexdigest()
    return digest[:length]


def _derive_upper(label: str, *, length: int) -> str:
    """The upper-case form, for the shapes that are upper-case by definition (``AKIA…``)."""
    return _derive(label, length=length).upper()


def _b64url(document: object) -> str:
    """Base64url of a JSON document, unpadded — how a JSON web token's segments are built."""
    raw = json.dumps(document, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


#: The values the fixture plants, materialised once. Keys are the template token names used
#: by the artifact bodies below; the values are assembled from :func:`_derive`, so this file
#: contains no credential-shaped literal.
_TOKENS: Mapping[str, str] = {
    # GitHub's token shape: the ``ghp_`` prefix plus 36 alphanumerics.
    "github": "ghp_" + _derive("github", length=36),
    # AWS's access-key-id shape: ``AKIA`` plus 16 upper-case alphanumerics.
    "awsid": "AKIA" + _derive_upper("aws-id", length=16),
    "awssecret": _derive("aws-secret", length=40),
    # Credentialed connection strings carry a user and a passphrase.
    "dbuser": "app",
    "dbpass": _derive("db-passphrase", length=24),
    # A dotenv / parameters-file passphrase and a framework secret key.
    "frameworksecret": _derive("framework-secret", length=50),
    "gcpclientsecret": _derive("gcp-client-secret", length=32),
    # Three base64url segments whose first two begin ``eyJ``: the JWT detector's shape.
    "jwt": ".".join(
        (
            _b64url({"alg": "RS256", "typ": "JWT"}),
            _b64url({"sub": "arachne-lab"}),
            _derive("jwt-signature", length=32),
        )
    ),
    "pem": f"{_PEM_HEADER}\n{_derive('service-account-key', length=48)}\n{_PEM_FOOTER}\n",
}

#: The materialised values a redactor is expected to blank. The acceptance test asserts that
#: none of these appears in any evidence payload of any finding.
PLANTED_SECRETS: tuple[str, ...] = (
    _TOKENS["github"],
    _TOKENS["awsid"],
    _TOKENS["awssecret"],
    _TOKENS["dbpass"],
    _TOKENS["frameworksecret"],
    _TOKENS["gcpclientsecret"],
    _TOKENS["jwt"],
    _derive("service-account-key", length=48),
)


def _materialise(template: str) -> str:
    """Substitute the fixture's ``${token}`` placeholders with the assembled values."""
    for name, value in _TOKENS.items():
        template = template.replace("${" + name + "}", value)
    return template


def _materialise_document(document: Any) -> Any:
    """Substitute the placeholders inside a document's strings, before it is serialised.

    Substituting the *serialised* text would be wrong for the PEM value: it contains real
    newlines, which are legal inside a Python string and illegal inside a JSON string, so the
    escape has to happen in ``json.dumps`` after the substitution.
    """
    if isinstance(document, str):
        return _materialise(document)
    if isinstance(document, Mapping):
        return {key: _materialise_document(value) for key, value in document.items()}
    if isinstance(document, (list, tuple)):
        return [_materialise_document(item) for item in document]
    return document


#: The not-found page every mode's 404 uses. It names the requested resource generically and
#: echoes **nothing**: no path, no nonce, no host.
_NOT_FOUND = (
    "<!DOCTYPE html><html><head><title>404 Not Found</title></head><body>"
    "<h1>Not Found</h1>"
    "<p>The requested resource was not found on this server.</p></body></html>"
)

#: The generic error page the ``error-page`` mode answers with. It names no artifact.
_ERROR_PAGE = (
    "<!DOCTYPE html><html><head><title>500 Internal Server Error</title></head><body>"
    "<h1>Internal Server Error</h1>"
    "<p>The server encountered an internal error and was unable to complete your "
    "request.</p></body></html>"
)

#: The homepage every mode serves: the site itself, linking nothing.
_HOMEPAGE = (
    '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8" />'
    "<title>Arachne infrastructure-artifact lab</title></head><body>"
    "<h1>Arachne Source-control, CI and Infrastructure-artifact Lab</h1>"
    "<p>This deployment serves its own site and nothing else on this path.</p>"
    "</body></html>"
)

#: The echo-404 body: a soft 404 that answers ``200`` and quotes the path it was asked for.
_ECHO_404 = (
    "<!DOCTYPE html><html><head><title>Page not found</title></head><body>"
    "<h1>Page not found</h1><p>No page is published at <code>{path}</code>. "
    "It may have been moved or removed.</p></body></html>"
)


@dataclass
class ArtifactLab:
    """A running fixture: which area, which mode, its origin and what it answered."""

    area: str
    mode: str
    base_url: str = ""
    port: int = 0
    requests: list[str] = field(default_factory=list)

    @property
    def origin(self) -> str:
        return self.base_url.rstrip("/")

    @property
    def host(self) -> str:
        return f"127.0.0.1:{self.port}"


@dataclass(frozen=True, slots=True)
class _Response:
    status: int
    body: bytes
    content_type: str = "text/html; charset=utf-8"
    headers: tuple[tuple[str, str], ...] = ()


def _text(status: int, body: str, content_type: str = "text/html; charset=utf-8") -> _Response:
    return _Response(status, _materialise(body).encode("utf-8"), content_type)


def _binary(status: int, body: bytes, content_type: str) -> _Response:
    return _Response(status, body, content_type)


def _json(document: object, *, status: int = 200) -> _Response:
    body = json.dumps(_materialise_document(document))
    return _Response(status, body.encode("utf-8"), "application/json; charset=utf-8")


# --------------------------------------------------------------------------- the artifacts
_DOTENV_VARIANT = (
    "# staging environment — do not commit\n"
    "APP_ENV=staging\n"
    "DB_HOST=db.staging.internal\n"
    "DB_PASSWORD=${dbpass}\n"
    "DB_USERNAME=${dbuser}\n"
    "SECRET_KEY=${frameworksecret}\n"
    "AWS_ACCESS_KEY_ID=${awsid}\n"
    "AWS_SECRET_ACCESS_KEY=${awssecret}\n"
)

_TFSTATE = {
    "version": 4,
    "terraform_version": "1.7.5",
    "serial": 42,
    "lineage": "5f2c1a7e-0000-4d5e-8f1a-fixture-lab-lineage",
    "outputs": {"db_endpoint": {"value": "db.internal:5432", "type": "string"}},
    "resources": [
        {
            "mode": "managed",
            "type": "aws_db_instance",
            "name": "app",
            "provider": 'provider["registry.terraform.io/hashicorp/aws"]',
            "instances": [
                {
                    "attributes": {
                        "engine": "postgres",
                        "username": "${dbuser}",
                        "password": "${dbpass}",
                        "connection_string": (
                            "postgres://${dbuser}:${dbpass}@db.internal:5432/app"
                        ),
                    }
                }
            ],
        }
    ],
}

_TFPLAN_JSON = {
    "format_version": "1.2",
    "terraform_version": "1.7.5",
    "planned_values": {"root_module": {"resources": []}},
    "resource_changes": [{"address": "aws_db_instance.app", "change": {"actions": ["update"]}}],
}

_TFLOCK = (
    '# This file is maintained automatically by "terraform init".\n'
    "# Manual edits may be lost in future updates.\n\n"
    'provider "registry.terraform.io/hashicorp/aws" {\n'
    '  version     = "5.40.0"\n'
    '  constraints = "~> 5.0"\n'
    "  hashes = [\n"
    '    "h1:fixturehash0000000000000000000000000000000000000000000=",\n'
    "  ]\n}\n"
)

_SERVICE_ACCOUNT = {
    "type": "service_account",
    "project_id": "arachne-lab",
    "private_key_id": "0123456789abcdef0123456789abcdef01234567",
    "private_key": "${pem}",
    "client_email": "deployer@arachne-lab.iam.gserviceaccount.com",
    "client_id": "100000000000000000000",
}

_COMPOSE = (
    "version: '3.9'\n"
    "services:\n"
    "  app:\n"
    "    image: ghcr.io/acme/app:1.4.2\n"
    "    container_name: acme-app\n"
    "    environment:\n"
    "      DATABASE_URL: postgres://${dbuser}:${dbpass}@db:5432/app\n"
    "      APP_ENV: production\n"
)

_DOCKERFILE = (
    "FROM python:3.12-slim AS base\n"
    "WORKDIR /app\n"
    "COPY requirements.txt ./\n"
    "RUN pip install --no-cache-dir -r requirements.txt\n"
    "COPY . .\n"
    'CMD ["python", "-m", "app"]\n'
)

_K8S_DEPLOYMENT = (
    "apiVersion: apps/v1\n"
    "kind: Deployment\n"
    "metadata:\n"
    "  name: acme-app\n"
    "spec:\n"
    "  replicas: 3\n"
    "  template:\n"
    "    spec:\n"
    "      containers:\n"
    "        - name: app\n"
    "          image: ghcr.io/acme/app:1.4.2\n"
    "          env:\n"
    "            - name: DATABASE_URL\n"
    "              value: postgres://${dbuser}:${dbpass}@db:5432/app\n"
)

_GIT_CONFIG = (
    "[core]\n"
    "\trepositoryformatversion = 0\n"
    "\tfilemode = true\n"
    '[remote "origin"]\n'
    "\turl = https://x-access-token:${github}@github.com/acme/app.git\n"
    "\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
)

_AWS_CREDENTIALS = (
    "[default]\n"
    "aws_access_key_id = ${awsid}\n"
    "aws_secret_access_key = ${awssecret}\n"
    "region = eu-central-1\n"
)

_GH_DEPLOY_WORKFLOW = (
    "name: deploy\n"
    "on:\n"
    "  push:\n"
    "    branches: [main]\n"
    "jobs:\n"
    "  deploy:\n"
    "    runs-on: ubuntu-latest\n"
    "    steps:\n"
    "      - uses: actions/checkout@v4\n"
    "      - run: ./scripts/deploy.sh\n"
    "        env:\n"
    "          AWS_ACCESS_KEY_ID: ${awsid}\n"
    "          AWS_SECRET_ACCESS_KEY: ${awssecret}\n"
)

_DJANGO_SETTINGS = (
    "import os\n"
    'SECRET_KEY = "${frameworksecret}"\n'
    "DEBUG = False\n"
    "DATABASES = {\n"
    '    "default": {\n'
    '        "ENGINE": "django.db.backends.postgresql",\n'
    '        "PASSWORD": "${dbpass}",\n'
    "    }\n"
    "}\n"
    "INSTALLED_APPS = []\n"
)

#: How large the Terraform plan fixture is. Deliberately larger than the client's default
#: body limit (64 KiB), so the acceptance test can prove a check reports a binary artifact
#: without reading it: the client stops at its cap, marks the body truncated, and the finding
#: records the bytes it captured. The bytes are a repeated filler, not a plan.
OVERSIZED_PLAN_BYTES: int = 256 * 1024

_VIM_SWAP = b"b0VIM 9.0\x00\x00\x00\x00fixture-swap\x00\x00\x00\x01\x00\x00\x00"
_DS_STORE = b"\x00\x00\x00\x01Bud1\x00\x00\x10\x00\x00\x00\x08\x00\x00\x00\x00"
_TFPLAN_BINARY = (b"\x00\x00\x00\x00terraform-plan-fixture\x01\x02\x03\x00") + (
    b"\x00binary" * (OVERSIZED_PLAN_BYTES // 7)
)


def _area_artifacts() -> dict[str, dict[str, _Response]]:
    """Every area's planted artifacts, keyed by the path a check requests.

    Only the paths a check needs to find are served: an inventory path the fixture does not
    publish answers the installation's own 404, which is what makes the *other* checks of the
    same area (and every other area) silent on it.
    """
    return {
        "dvcs": {
            "/.git/logs/HEAD": _text(
                200,
                "0000000000000000000000000000000000000000 "
                "1111111111111111111111111111111111111111 "
                "Dev <dev@acme.test> 1700000000 +0000\tcommit (initial): project import\n"
                "1111111111111111111111111111111111111111 "
                "2222222222222222222222222222222222222222 "
                "Dev <dev@acme.test> 1700000100 +0000\tcheckout: moving from main to feature\n",
                "text/plain; charset=utf-8",
            ),
            "/.git/config": _text(200, _GIT_CONFIG, "text/plain; charset=utf-8"),
            "/CVS/Root": _text(
                200,
                ":pserver:deploy@cvs.acme.test:/var/lib/cvs/acme\n",
                "text/plain; charset=utf-8",
            ),
        },
        "ci": {
            "/.github/workflows/ci.yml": _text(
                200,
                "name: ci\n"
                "on: [push, pull_request]\n"
                "jobs:\n"
                "  test:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - uses: actions/checkout@v4\n"
                "      - run: make test\n",
                "text/plain; charset=utf-8",
            ),
            "/.github/workflows/deploy.yml": _text(
                200, _GH_DEPLOY_WORKFLOW, "text/plain; charset=utf-8"
            ),
            "/.gitlab-ci.yml": _text(
                200,
                "stages: [build, test]\n"
                "image: alpine:3.19\n"
                "build:\n"
                "  stage: build\n"
                "  script:\n"
                "    - echo building\n",
                "text/plain; charset=utf-8",
            ),
        },
        "terraform": {
            "/terraform.tfstate": _json(_TFSTATE),
            "/terraform.plan.json": _json(_TFPLAN_JSON),
            "/terraform.tfplan": _binary(200, _TFPLAN_BINARY, "application/octet-stream"),
            "/.terraform.lock.hcl": _text(200, _TFLOCK, "text/plain; charset=utf-8"),
        },
        "cloud-credentials": {
            "/.aws/credentials": _text(200, _AWS_CREDENTIALS, "text/plain; charset=utf-8"),
            "/.config/gcloud/application_default_credentials.json": _json(
                {
                    "type": "authorized_user",
                    "client_id": "100000000000-fixture.apps.googleusercontent.com",
                    "client_secret": "${gcpclientsecret}",
                    "refresh_token": "${frameworksecret}",
                }
            ),
            "/.azure/accessTokens.json": _json(
                [
                    {
                        "accessToken": "${jwt}",
                        "expiresOn": "2026-01-01 00:00:00.000000",
                        "subscription": "00000000-0000-0000-0000-000000000000",
                    }
                ]
            ),
            "/service-account.json": _json(_SERVICE_ACCOUNT),
        },
        "containers": {
            "/docker-compose.yml": _text(200, _COMPOSE, "text/plain; charset=utf-8"),
            "/Dockerfile": _text(200, _DOCKERFILE, "text/plain; charset=utf-8"),
            "/k8s/deployment.yaml": _text(200, _K8S_DEPLOYMENT, "text/plain; charset=utf-8"),
        },
        "editor-residue": {
            "/.index.php.swp": _binary(200, _VIM_SWAP, "application/octet-stream"),
            "/.env~": _text(200, _DOTENV_VARIANT, "text/plain; charset=utf-8"),
            "/.DS_Store": _binary(200, _DS_STORE, "application/octet-stream"),
        },
        "credential-files": {
            "/.npmrc": _text(
                200,
                "//registry.npmjs.org/:_authToken=${NPM_TOKEN}\n"
                "always-auth=true\n"
                "registry=https://registry.npmjs.org/\n",
                "text/plain; charset=utf-8",
            ),
            "/.docker/config.json": _json(
                {"auths": {"registry.acme.test": {"identitytoken": "${jwt}"}}}
            ),
            "/.htaccess": _text(
                200,
                "AuthType Basic\n"
                'AuthName "Restricted"\n'
                "AuthUserFile /etc/apache2/.htpasswd\n"
                "Require valid-user\n",
                "text/plain; charset=utf-8",
            ),
        },
        "env-variants": {
            "/.env.staging": _text(200, _DOTENV_VARIANT, "text/plain; charset=utf-8"),
            "/secrets.env": _text(
                200,
                "AWS_ACCESS_KEY_ID=${awsid}\n"
                "AWS_SECRET_ACCESS_KEY=${awssecret}\n"
                "DB_PASSWORD=${dbpass}\n",
                "text/plain; charset=utf-8",
            ),
            "/settings.py": _text(200, _DJANGO_SETTINGS, "text/plain; charset=utf-8"),
        },
    }


#: Every area's published routes, keyed by area.
_AREA_ARTIFACTS: Mapping[str, Mapping[str, _Response]] = _area_artifacts()

#: The published paths per area, for the acceptance test's own controls.
PATHS_BY_AREA: Mapping[str, tuple[str, ...]] = {
    area: tuple(sorted(routes)) for area, routes in _AREA_ARTIFACTS.items()
}


def _normalise(path: str) -> str:
    """The route key for a request path: no trailing slash, ``"/"`` for the root."""
    stripped = path.rstrip("/")
    return stripped or "/"


class _Handler(BaseHTTPRequestHandler):
    """One fixture: one route table per area, differing by the lab's mode."""

    server_version = "arachne-artifact-lab/1.0"
    protocol_version = "HTTP/1.1"
    # Loopback Nagle/delayed-ACK stall removal, as in the shared web lab.
    disable_nagle_algorithm = True
    lab: ArtifactLab

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - stdlib signature
        return  # the fixture is quiet; the scanner's audit log is the record

    def _send(self, response: _Response) -> None:
        self.send_response(response.status)
        self.send_header("Content-Type", response.content_type)
        self.send_header("Content-Length", str(len(response.body)))
        for name, value in response.headers:
            self.send_header(name, value)
        self.end_headers()
        if self.command == "HEAD":
            return
        try:
            self.wfile.write(response.body)
        except (BrokenPipeError, ConnectionResetError):
            # A check that stopped reading at the client's body limit closed the connection
            # early; that is the behaviour under test, not a fixture failure.
            self.close_connection = True

    def _route(self, path: str) -> _Response:
        lab = self.lab
        key = _normalise(path)
        if key == "/":
            return _text(200, _HOMEPAGE)
        if lab.mode == "not-found":
            return _text(404, _NOT_FOUND)
        if lab.mode == "error-page":
            return _text(500, _ERROR_PAGE)
        if lab.mode == "echo-404":
            # The soft 404: a 200 that echoes the requested path and names no artifact.
            return _text(200, _ECHO_404.format(path=self.path))
        published = _AREA_ARTIFACTS.get(lab.area, {})
        if key in published:
            return published[key]
        return _text(404, _NOT_FOUND)

    def _handle(self) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        self.lab.requests.append(f"{self.command} {parsed.path}")
        self._send(self._route(parsed.path))

    def do_GET(self) -> None:
        self._handle()

    def do_HEAD(self) -> None:
        self._handle()

    def do_OPTIONS(self) -> None:
        self.lab.requests.append(f"OPTIONS {self.path}")
        self._send(_Response(405, b"", headers=(("Allow", "GET, HEAD"),)))

    def do_POST(self) -> None:
        self.lab.requests.append(f"POST {self.path}")
        # No route in this fixture accepts a body: nothing can be uploaded, changed or
        # authenticated against it.
        self._send(_Response(405, b"", headers=(("Allow", "GET, HEAD"),)))


@contextmanager
def start_artifact_lab(area: str, mode: str = "vulnerable") -> Iterator[ArtifactLab]:
    """Start one area fixture on loopback in ``mode`` and yield its handle."""
    if area not in AREAS:
        raise ValueError(f"unknown area {area!r}; expected one of {AREAS}")
    if mode not in MODES:
        raise ValueError(f"unknown artifact-lab mode {mode!r}; expected one of {MODES}")
    lab = ArtifactLab(area=area, mode=mode)
    handler: Any = type("_BoundHandler", (_Handler,), {"lab": lab})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    server.daemon_threads = True
    port = server.server_address[1]
    lab.port = port
    lab.base_url = f"http://127.0.0.1:{port}/"
    thread = threading.Thread(
        target=server.serve_forever,
        args=(0.05,),
        name=f"arachne-artifact-lab-{area}-{mode}",
        daemon=True,
    )
    thread.start()
    try:
        yield lab
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
