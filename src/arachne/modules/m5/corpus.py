"""Load the M5 probe corpus (``templates/m5/probes.yaml`` + ``wordlists/``, F-09-04).

M5's checks are a catalogue of well-known *cloud, container and supply-chain mistakes*: an
open bucket, a public Firebase rule set, a committed ``.tfstate``, an unauthenticated kubelet,
a risky GitHub Actions workflow. Almost all of the module is therefore **data** — which paths
to probe, which marker proves a hit, which constructs a workflow review flags — and keeping
that in one reviewable file matters more here than in M3/M4 because the corpus is also the
module's *documentation of what it sends*.

The loader mirrors ``m4.corpus``: typed accessors over the raw mapping, validated lazily so a
corpus without, say, an IAM section still supports every other check, and a malformed regex
fails at load time with the path that holds it.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from importlib.resources import files
from pathlib import Path
from typing import Any, Final

import yaml

from arachne.core.errors import ConfigurationError
from arachne.posture.state import PosturePolicy

__all__ = [
    "BucketProvider",
    "CloudPattern",
    "IacPattern",
    "M5Corpus",
    "NamedSpec",
    "ProviderSpec",
    "VulnerableComponent",
    "WorkflowPattern",
    "load_corpus",
    "load_wordlist",
    "parse_corpus",
]

#: Where the shipped M5 corpus lives inside the package.
DEFAULT_CORPUS_RESOURCE: Final = ("m5", "probes.yaml")

#: Hard cap on a wordlist a check will read (a project-supplied list must not turn a probe
#: into a content-discovery campaign).
MAX_WORDLIST_ENTRIES: Final = 500


# --------------------------------------------------------------------------- typed views
@dataclass(frozen=True, slots=True)
class BucketProvider:
    name: str
    host_template: str
    path_prefix: str
    list_query: str
    acl_query: str
    listing_markers: tuple[str, ...]
    public_acl_markers: tuple[str, ...]
    denied_status: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class IacPattern:
    id: str
    severity: str
    regex: re.Pattern[str]
    hint: str


@dataclass(frozen=True, slots=True)
class WorkflowPattern:
    id: str
    severity: str
    regex: re.Pattern[str]
    hint: str


@dataclass(frozen=True, slots=True)
class VulnerableComponent:
    name: str
    ecosystem: str
    below: str
    cve: str
    severity: str


@dataclass(frozen=True, slots=True)
class CloudPattern:
    """A named credential regex for the local-artifact secret scan (ch05#3/#6)."""

    kind: str
    regex: re.Pattern[str]


@dataclass(frozen=True, slots=True)
class NamedSpec:
    """A generic ``{name, ...}`` entry (metadata endpoints, JWT variants, ...)."""

    name: str
    values: Mapping[str, Any]


@dataclass(frozen=True, slots=True)
class ProviderSpec:
    """A provider entry with a template + markers (firebase/supabase/registry class)."""

    name: str
    values: Mapping[str, Any]


# --------------------------------------------------------------------------- the corpus
@dataclass(frozen=True, slots=True)
class M5Corpus:
    """The parsed M5 corpus with typed accessors for what the checks consume."""

    version: str
    source: str
    raw: Mapping[str, Any] = field(default_factory=dict)

    # ------------------------------------------------------------------ generic
    def section(self, name: str) -> Mapping[str, Any]:
        value = self.raw.get(name)
        if not isinstance(value, Mapping):
            return {}
        return value

    def _get(self, *path: str) -> Any:
        node: Any = self.raw
        for segment in path:
            if not isinstance(node, Mapping) or segment not in node:
                return None
            node = node[segment]
        return node

    def strings(self, *path: str) -> tuple[str, ...]:
        value = self._get(*path)
        if value is None:
            return ()
        if not isinstance(value, (list, tuple)):
            raise ConfigurationError(
                f"{self.source}: {'/'.join(path)} must be a list, got {type(value).__name__}"
            )
        return tuple(str(item) for item in value)

    def string(self, *path: str, default: str = "") -> str:
        value = self._get(*path)
        return default if value is None else str(value)

    def integer(self, *path: str, default: int = 0) -> int:
        value = self._get(*path)
        try:
            return default if value is None else int(value)
        except (TypeError, ValueError) as exc:
            raise ConfigurationError(f"{self.source}: {'/'.join(path)} must be an integer") from exc

    def boolean(self, *path: str, default: bool = False) -> bool:
        value = self._get(*path)
        return default if value is None else bool(value)

    def mapping(self, *path: str) -> Mapping[str, Any]:
        value = self._get(*path)
        if value is None:
            return {}
        if not isinstance(value, Mapping):
            raise ConfigurationError(f"{self.source}: {'/'.join(path)} must be a mapping")
        return value

    def pattern(self, *path: str) -> re.Pattern[str] | None:
        value = self._get(*path)
        if value is None:
            return None
        return _compile(str(value), source=self.source, path="/".join(path))

    def _entries(self, *path: str) -> tuple[Mapping[str, Any], ...]:
        value = self._get(*path)
        if not isinstance(value, (list, tuple)):
            return ()
        return tuple(item for item in value if isinstance(item, Mapping))

    # ------------------------------------------------------------------ buckets
    def bucket_providers(self) -> tuple[BucketProvider, ...]:
        raw = self.mapping("bucket", "providers")
        providers: list[BucketProvider] = []
        for name, entry in raw.items():
            if not isinstance(entry, Mapping):
                continue
            providers.append(
                BucketProvider(
                    name=str(name),
                    host_template=str(entry.get("host_template", "")),
                    path_prefix=str(entry.get("path_prefix", "")),
                    list_query=str(entry.get("list_query", "")),
                    acl_query=str(entry.get("acl_query", "")),
                    listing_markers=tuple(str(i) for i in entry.get("listing_markers") or ()),
                    public_acl_markers=tuple(str(i) for i in entry.get("public_acl_markers") or ()),
                    denied_status=tuple(int(i) for i in entry.get("denied_status") or ()),
                )
            )
        return tuple(providers)

    def bucket_names_wordlist(self) -> str:
        return self.string("bucket", "names_wordlist", default="wordlists/bucket-names.txt")

    def bucket_endpoint_queries(self) -> tuple[str, str]:
        return (
            self.string("bucket", "endpoint_queries", "list", default="?list-type=2"),
            self.string("bucket", "endpoint_queries", "acl", default="?acl"),
        )

    def bucket_access_denied_status(self) -> tuple[int, ...]:
        value = self._get("bucket", "access_denied_status")
        if isinstance(value, (list, tuple)):
            return tuple(int(item) for item in value)
        return (401, 403)

    # ------------------------------------------------------------------ firebase / supabase
    def firebase(self) -> Mapping[str, Any]:
        return self.mapping("firebase")

    def firebase_rtdb_paths(self) -> tuple[str, ...]:
        return self.strings("firebase", "rtdb_paths")

    def firebase_rtdb_host_template(self) -> str:
        return self.string("firebase", "rtdb_host_template")

    def firebase_firestore_template(self) -> str:
        return self.string("firebase", "firestore_path_template")

    def firebase_project_hints(self) -> tuple[str, ...]:
        return self.strings("firebase", "project_ref_hints")

    def firebase_markers(self) -> tuple[str, ...]:
        return self.strings("firebase", "rtdb_markers")

    def supabase(self) -> Mapping[str, Any]:
        return self.mapping("supabase")

    def supabase_rest_path(self) -> str:
        return self.string("supabase", "rest_path", default="/rest/v1/")

    def supabase_host_template(self) -> str:
        return self.string("supabase", "host_template")

    def supabase_tables(self) -> tuple[str, ...]:
        return self.strings("supabase", "probe_tables")

    def supabase_markers(self) -> tuple[str, ...]:
        return self.strings("supabase", "markers")

    # ------------------------------------------------------------------ tfstate / IaC
    def tfstate_paths(self) -> tuple[str, ...]:
        return self.strings("tfstate", "paths")

    def tfstate_secret_keys(self) -> tuple[str, ...]:
        return tuple(k.lower() for k in self.strings("tfstate", "secret_keys"))

    def tfstate_resource_keys(self) -> tuple[str, ...]:
        return self.strings("tfstate", "resource_keys")

    def tfstate_local_names(self) -> tuple[str, ...]:
        return self.strings("tfstate", "local_names")

    def iac_patterns(self) -> tuple[IacPattern, ...]:
        out: list[IacPattern] = []
        for entry in self._entries("tfstate", "iac_patterns"):
            expression = entry.get("regex")
            if expression is None:
                continue
            out.append(
                IacPattern(
                    id=str(entry.get("id", "iac")),
                    severity=str(entry.get("severity", "medium")),
                    regex=_compile(
                        str(expression), source=self.source, path="tfstate/iac_patterns"
                    ),
                    hint=str(entry.get("hint", "")),
                )
            )
        return tuple(out)

    def iac_globs(self) -> tuple[str, ...]:
        return self.strings("tfstate", "iac_globs")

    # ------------------------------------------------------------------ continuous posture (S23)
    def posture_snapshot_paths(self) -> tuple[str, ...]:
        """Where the continuous check looks for a state snapshot on an endpoint asset."""
        return self.strings("posture", "snapshot_paths")

    def posture_policies(self) -> tuple[PosturePolicy, ...]:
        """The estate policies (data): ``{id, severity, key, equals[, service, hint]}``."""
        out: list[PosturePolicy] = []
        for entry in self._entries("posture", "policies"):
            if "id" not in entry or "key" not in entry:
                raise ConfigurationError(
                    f"{self.source}: posture/policies entries need id and key (got {entry!r:.120})"
                )
            out.append(
                PosturePolicy(
                    id=str(entry["id"]),
                    severity=str(entry.get("severity", "medium")),
                    key=str(entry["key"]),
                    equals=entry.get("equals"),
                    service=str(entry.get("service", "") or ""),
                    hint=str(entry.get("hint", "") or ""),
                )
            )
        return tuple(out)

    # ------------------------------------------------------------------ kubernetes / docker
    def k8s_kubelet_paths(self) -> tuple[str, ...]:
        return self.strings("k8s", "kubelet_paths")

    def k8s_dashboard_paths(self) -> tuple[str, ...]:
        return self.strings("k8s", "dashboard_paths")

    def k8s_api_paths(self) -> tuple[str, ...]:
        return self.strings("k8s", "api_paths")

    def k8s_pod_markers(self) -> tuple[str, ...]:
        return self.strings("k8s", "pod_markers")

    def k8s_env_markers(self) -> tuple[str, ...]:
        return self.strings("k8s", "env_markers")

    def k8s_dashboard_markers(self) -> tuple[str, ...]:
        return self.strings("k8s", "dashboard_markers")

    def docker_api_paths(self) -> tuple[str, ...]:
        return self.strings("docker", "api_paths")

    def docker_socket_path(self) -> str:
        return self.string("docker", "socket_path", default="/var/run/docker.sock")

    def docker_markers(self) -> tuple[str, ...]:
        return self.strings("docker", "markers")

    def docker_privileged_markers(self) -> tuple[str, ...]:
        return self.strings("docker", "privileged_markers")

    # ------------------------------------------------------------------ registry
    def registry_catalog_path(self) -> str:
        return self.string("registry", "catalog_path", default="/v2/_catalog")

    def registry_tags_template(self) -> str:
        return self.string("registry", "tags_template", default="/v2/<repo>/tags/list")

    def registry_markers(self) -> tuple[str, ...]:
        return self.strings("registry", "markers")

    def registry_repos_wordlist(self) -> str:
        return self.string("registry", "repos_wordlist", default="wordlists/image-repos.txt")

    def registry_scanner(self) -> str:
        return self.string("registry", "scanner", default="trivy")

    # ------------------------------------------------------------------ image / manifests
    def image_dockerfile_names(self) -> tuple[str, ...]:
        return self.strings("image", "dockerfile_names")

    def image_secret_instruction_hints(self) -> tuple[str, ...]:
        return self.strings("image", "secret_instruction_hints")

    def image_secret_value_markers(self) -> tuple[str, ...]:
        return self.strings("image", "secret_value_markers")

    def image_manifest_globs(self) -> tuple[str, ...]:
        return self.strings("image", "manifest_globs")

    def image_root_user_marker(self) -> str:
        return self.string("image", "root_user_marker", default="USER root")

    # ------------------------------------------------------------------ cloud secrets
    def secret_patterns(self) -> tuple[CloudPattern, ...]:
        raw = self.mapping("secrets", "patterns")
        out: list[CloudPattern] = []
        for kind, expression in raw.items():
            out.append(
                CloudPattern(
                    kind=str(kind),
                    regex=_compile(
                        str(expression), source=self.source, path=f"secrets/patterns/{kind}"
                    ),
                )
            )
        return tuple(out)

    def secret_key_file_names(self) -> tuple[str, ...]:
        return self.strings("secrets", "key_file_names")

    def secret_max_matches(self) -> int:
        return self.integer("secrets", "max_matches", default=40)

    # ------------------------------------------------------------------ cicd
    def cicd_workflow_globs(self) -> tuple[str, ...]:
        return self.strings("cicd", "workflow_globs")

    def cicd_patterns(self) -> tuple[WorkflowPattern, ...]:
        out: list[WorkflowPattern] = []
        for entry in self._entries("cicd", "patterns"):
            expression = entry.get("regex")
            if expression is None:
                continue
            out.append(
                WorkflowPattern(
                    id=str(entry.get("id", "ci")),
                    severity=str(entry.get("severity", "medium")),
                    regex=_compile(str(expression), source=self.source, path="cicd/patterns"),
                    hint=str(entry.get("hint", "")),
                )
            )
        return tuple(out)

    def cicd_secret_context(self) -> str:
        return self.string("cicd", "secret_context", default="secrets.")

    # ------------------------------------------------------------------ dep confusion / sbom
    def dep_manifests(self) -> tuple[str, ...]:
        return self.strings("dep_confusion", "manifests")

    def dep_ecosystems(self) -> Mapping[str, Any]:
        return self.mapping("dep_confusion", "ecosystems")

    def dep_internal_hints(self) -> tuple[str, ...]:
        return tuple(h.lower() for h in self.strings("dep_confusion", "internal_hints"))

    def sbom_lockfiles(self) -> tuple[str, ...]:
        return self.strings("sbom", "lockfiles")

    def sbom_vulnerable(self) -> tuple[VulnerableComponent, ...]:
        out: list[VulnerableComponent] = []
        for entry in self._entries("sbom", "vulnerable"):
            if "name" not in entry or "below" not in entry:
                continue
            out.append(
                VulnerableComponent(
                    name=str(entry["name"]),
                    ecosystem=str(entry.get("ecosystem", "unknown")),
                    below=str(entry["below"]),
                    cve=str(entry.get("cve", "")),
                    severity=str(entry.get("severity", "medium")),
                )
            )
        return tuple(out)

    # ------------------------------------------------------------------ metadata / iam
    def imds_targets(self) -> tuple[NamedSpec, ...]:
        return tuple(
            NamedSpec(name=str(entry.get("provider", "imds")), values=entry)
            for entry in self._entries("imds", "targets")
        )

    def imds_sink_hints(self) -> tuple[str, ...]:
        return tuple(h.lower() for h in self.strings("imds", "sink_param_hints"))

    def imds_v2_status(self) -> int:
        return self.integer("imds", "imds_v2_status", default=401)

    def azure_imds_instance(self) -> str:
        return self.string("azure", "imds_instance")

    def azure_imds_token(self) -> str:
        return self.string("azure", "imds_token")

    def azure_imds_headers(self) -> dict[str, str]:
        return {str(k): str(v) for k, v in self.mapping("azure", "imds_headers").items()}

    def azure_instance_markers(self) -> tuple[str, ...]:
        return self.strings("azure", "instance_markers")

    def azure_token_markers(self) -> tuple[str, ...]:
        return self.strings("azure", "token_markers")

    def gcp_metadata_root(self) -> str:
        return self.string("gcp", "metadata_root")

    def gcp_metadata_paths(self) -> tuple[str, ...]:
        return self.strings("gcp", "metadata_paths")

    def gcp_metadata_headers(self) -> dict[str, str]:
        return {str(k): str(v) for k, v in self.mapping("gcp", "metadata_headers").items()}

    def gcp_token_markers(self) -> tuple[str, ...]:
        return self.strings("gcp", "token_markers")

    def iam_read_only_permissions(self) -> tuple[str, ...]:
        return self.strings("iam", "read_only_permissions")

    def iam_escalation_actions(self) -> tuple[str, ...]:
        return self.strings("iam", "escalation_actions")

    def iam_wildcard_markers(self) -> tuple[str, ...]:
        return self.strings("iam", "wildcard_markers")

    def iam_policy_globs(self) -> tuple[str, ...]:
        return self.strings("iam", "policy_globs")

    def iam_policy_hints(self) -> tuple[str, ...]:
        return tuple(h.lower() for h in self.strings("iam", "policy_hints"))

    # ------------------------------------------------------------------ serverless (ch05#9)
    def serverless_host_suffixes(self) -> tuple[str, ...]:
        return tuple(s.lower() for s in self.strings("serverless", "host_suffixes"))

    def serverless_stage_paths(self) -> tuple[str, ...]:
        return self.strings("serverless", "stage_paths")

    def serverless_response_markers(self) -> tuple[str, ...]:
        return tuple(m.lower() for m in self.strings("serverless", "response_markers"))

    def serverless_auth_status(self) -> tuple[int, ...]:
        value = self._get("serverless", "auth_status")
        if isinstance(value, (list, tuple)) and value:
            return tuple(int(item) for item in value)
        return (401, 403)

    def serverless_auth_markers(self) -> tuple[str, ...]:
        return tuple(m.lower() for m in self.strings("serverless", "auth_markers"))

    def serverless_max_candidates(self) -> int:
        return self.integer("serverless", "max_candidates", default=8)

    # ------------------------------------------------------------------ datastores (ch05#20)
    def managed_datastore_console_paths(self) -> tuple[str, ...]:
        return self.strings("managed_datastores", "console_paths")

    def managed_datastore_console_markers(self) -> tuple[str, ...]:
        return tuple(m.lower() for m in self.strings("managed_datastores", "console_markers"))

    def managed_datastore_auth_status(self) -> tuple[int, ...]:
        value = self._get("managed_datastores", "auth_status")
        if isinstance(value, (list, tuple)) and value:
            return tuple(int(item) for item in value)
        return (401, 403)

    def managed_datastore_db_host_suffixes(self) -> tuple[str, ...]:
        return tuple(s.lower() for s in self.strings("managed_datastores", "db_host_suffixes"))

    def managed_datastore_db_markers(self) -> tuple[str, ...]:
        return tuple(m.lower() for m in self.strings("managed_datastores", "db_markers"))

    # ------------------------------------------------------------------ search (ch05#21)
    def search_platform_paths(self) -> tuple[str, ...]:
        return self.strings("search_platforms", "paths")

    def search_platform_elasticsearch_markers(self) -> tuple[str, ...]:
        return tuple(m.lower() for m in self.strings("search_platforms", "elasticsearch_markers"))

    def search_platform_kibana_markers(self) -> tuple[str, ...]:
        return tuple(m.lower() for m in self.strings("search_platforms", "kibana_markers"))

    def search_platform_opensearch_markers(self) -> tuple[str, ...]:
        return tuple(m.lower() for m in self.strings("search_platforms", "opensearch_markers"))

    def search_platform_auth_status(self) -> tuple[int, ...]:
        value = self._get("search_platforms", "auth_status")
        if isinstance(value, (list, tuple)) and value:
            return tuple(int(item) for item in value)
        return (401, 403)


# --------------------------------------------------------------------------- loading
def parse_corpus(data: Any, *, source: str = "<memory>") -> M5Corpus:
    if not isinstance(data, Mapping):
        msg = f"{source}: expected a mapping, got {type(data).__name__}"
        raise ConfigurationError(msg)
    version = data.get("version")
    if not isinstance(version, str) or not version:
        raise ConfigurationError(f"{source}: 'version' is required")
    corpus = M5Corpus(version=version, source=source, raw=data)
    # Compile the regexes the checks depend on, so a broken corpus fails here, not mid-scan.
    for accessor in (
        corpus.secret_patterns,
        corpus.iac_patterns,
        corpus.cicd_patterns,
    ):
        accessor()
    return corpus


def _compile(expression: str, *, source: str, path: str) -> re.Pattern[str]:
    if len(expression) > 600:
        raise ConfigurationError(f"{source}: {path} pattern is longer than 600 characters")
    try:
        return re.compile(expression)
    except re.error as exc:
        raise ConfigurationError(f"{source}: {path} is not a valid regex: {exc}") from exc


def _safe_yaml(text: str, *, source: str) -> Any:
    try:
        return yaml.safe_load(text)  # F-08-06: safe_load only
    except yaml.YAMLError as exc:
        raise ConfigurationError(f"{source}: not valid YAML: {exc}") from exc


def _resolve(override: str | None) -> tuple[Path | None, str]:
    if override:
        resolved = Path(override).expanduser()
        if resolved.is_dir():
            candidate = resolved / "probes.yaml"
            if candidate.is_file():
                return candidate, str(candidate)
            raise ConfigurationError(f"no probes.yaml under {resolved}")
        if not resolved.is_file():
            raise ConfigurationError(f"M5 probe corpus {resolved} does not exist")
        return resolved, str(resolved)
    return None, "/".join(DEFAULT_CORPUS_RESOURCE)


def load_corpus(path: str | None = None) -> M5Corpus:
    """Load the M5 corpus from ``path`` (a file or a directory), or the shipped one."""
    resolved, source = _resolve(path)
    if resolved is not None:
        try:
            text = resolved.read_text(encoding="utf-8")
        except OSError as exc:  # pragma: no cover - unreadable file
            raise ConfigurationError(f"cannot read {resolved}: {exc}") from exc
        return parse_corpus(_safe_yaml(text, source=source), source=source)
    resource = files("arachne.templates")
    for part in DEFAULT_CORPUS_RESOURCE:
        resource = resource.joinpath(part)
    try:
        text = resource.read_text(encoding="utf-8")
    except (FileNotFoundError, OSError) as exc:  # pragma: no cover - packaging failure
        msg = f"bundled M5 probe corpus is missing: {exc}"
        raise ConfigurationError(msg) from exc
    return parse_corpus(_safe_yaml(text, source=source), source=source)


def load_wordlist(
    name: str,
    *,
    override_dir: str | None = None,
    limit: int = MAX_WORDLIST_ENTRIES,
) -> tuple[str, ...]:
    """Load an M5 wordlist: an operator directory first, then the packaged one."""
    cap = min(limit, MAX_WORDLIST_ENTRIES)
    relative = Path(name)
    text: str | None = None
    if override_dir:
        candidate = Path(override_dir).expanduser()
        if candidate.is_dir():
            candidate = candidate / relative
        if candidate.is_file():
            text = candidate.read_text(encoding="utf-8")
    if text is None:
        resource = files("arachne.templates") / "m5" / relative
        try:
            text = resource.read_text(encoding="utf-8")
        except (FileNotFoundError, OSError):  # pragma: no cover - packaging failure
            return ()
    entries: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            entries.append(stripped)
    return tuple(dict.fromkeys(entries))[:cap]
