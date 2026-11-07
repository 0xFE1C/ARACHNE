"""Load the M4 probe corpus (``templates/m4/probes.yaml`` + ``wordlists/``, F-09-04).

M4's checks are almost entirely *data*: which paths a misconfigured server leaves
reachable, which marker proves the answer is a phpinfo page rather than a 404 page, which
product a dashboard belongs to. Keeping that in one reviewable file matters more here than
in M3, because the whole module is a catalogue of well-known mistakes — an operator must be
able to read, diff and replace it without touching code (``ARACHNE_M4_PROBES``).

The loader mirrors ``m3.payloads``: typed accessors over the raw mapping, validated lazily
so a corpus without, say, an email-auth section still supports every other check, and a
malformed regex fails at load time with the path that holds it.
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

__all__ = [
    "ArtifactProbe",
    "BackupSignature",
    "BucketProvider",
    "CredentialProduct",
    "DashboardPanel",
    "DebugProbe",
    "M4Corpus",
    "MetadataEndpoint",
    "VcsProbe",
    "load_corpus",
    "load_wordlist",
    "parse_corpus",
]

#: Where the shipped M4 corpus lives inside the package.
DEFAULT_CORPUS_RESOURCE: Final = ("m4", "probes.yaml")

#: Hard cap on a wordlist a check will read (a project-supplied list must not turn an
#: exposure probe into a content-discovery campaign).
MAX_WORDLIST_ENTRIES: Final = 500


# --------------------------------------------------------------------------- typed views
@dataclass(frozen=True, slots=True)
class VcsProbe:
    path: str
    markers: tuple[str, ...]
    family: str


@dataclass(frozen=True, slots=True)
class DebugProbe:
    path: str
    family: str
    markers: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class DashboardPanel:
    product: str
    paths: tuple[str, ...]
    markers: tuple[str, ...]
    auth_markers: tuple[str, ...]


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
class MetadataEndpoint:
    provider: str
    url: str
    headers: dict[str, str]
    v1_marker: str | None
    v2_status: int | None


@dataclass(frozen=True, slots=True)
class CredentialProduct:
    product: str
    login_path: str
    method: str
    fields: dict[str, str]
    success_markers: tuple[str, ...]
    failure_markers: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class BackupSignature:
    family: str
    markers: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ArtifactProbe:
    """One infrastructure-artifact path and the content that proves the artifact (WP-29).

    ``markers`` is the artifact's *own* content: a struct key, a manifest keyword, a file
    signature. An empty list is deliberate — it means the artifact has no text marker and the
    answer is decided from the suffix (a declared binary) or from the redactor (a
    credential-bearing artifact), never from a body word.
    """

    path: str
    family: str
    markers: tuple[str, ...]


# --------------------------------------------------------------------------- the corpus
@dataclass(frozen=True, slots=True)
class M4Corpus:
    """The parsed M4 corpus with typed accessors for what the checks consume."""

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
        try:
            return re.compile(str(value), re.IGNORECASE)
        except re.error as exc:
            raise ConfigurationError(
                f"{self.source}: {'/'.join(path)} is not a valid regex: {exc}"
            ) from exc

    # ------------------------------------------------------------------ env files
    def env_paths(self) -> tuple[str, ...]:
        return self.strings("env", "paths")

    def env_markers(self) -> tuple[str, ...]:
        return self.strings("env", "markers")

    def env_assignment_regex(self) -> re.Pattern[str] | None:
        return self.pattern("env", "assignment_regex")

    def env_min_bytes(self) -> int:
        return self.integer("env", "min_bytes", default=40)

    # ------------------------------------------------------------------ vcs
    def vcs_probes(self) -> tuple[VcsProbe, ...]:
        value = self._get("vcs", "probes")
        if not isinstance(value, (list, tuple)) or not value:
            return ()
        probes: list[VcsProbe] = []
        for entry in value:
            if not isinstance(entry, Mapping) or "path" not in entry:
                continue
            probes.append(
                VcsProbe(
                    path=str(entry["path"]),
                    markers=tuple(str(item) for item in entry.get("markers") or ()),
                    family=str(entry.get("family", "vcs")),
                )
            )
        return tuple(probes)

    def vcs_binary_exposed(self) -> bool:
        return self.boolean("vcs", "binary_exposed", default=True)

    # ------------------------------------------------------------------ backups
    def backup_priority(self) -> tuple[str, ...]:
        """High-value relative paths probed before the systematic expansion."""
        return self.strings("backup", "priority")

    def backup_directories(self) -> tuple[str, ...]:
        return self.strings("backup", "directories")

    def backup_names_wordlist(self) -> str:
        return self.string("backup", "names_wordlist", default="wordlists/backup-names.txt")

    def backup_extensions(self) -> tuple[str, ...]:
        return self.strings("backup", "extensions")

    def backup_signatures(self) -> tuple[BackupSignature, ...]:
        raw = self.mapping("backup", "signatures")
        return tuple(
            BackupSignature(family=str(family), markers=tuple(str(item) for item in markers))
            for family, markers in raw.items()
            if isinstance(markers, (list, tuple))
        )

    def backup_binary_extensions(self) -> tuple[str, ...]:
        return self.strings("backup", "binary_extensions")

    def backup_min_bytes(self) -> int:
        return self.integer("backup", "min_bytes", default=32)

    # ------------------------------------------------------------------ source maps
    def sourcemap_reference_regex(self) -> re.Pattern[str] | None:
        return self.pattern("sourcemap", "reference_regex")

    def sourcemap_document_keys(self) -> tuple[str, ...]:
        return self.strings("sourcemap", "document_keys")

    def sourcemap_disclose_keys(self) -> tuple[str, ...]:
        return self.strings("sourcemap", "disclose_keys")

    # ------------------------------------------------------------------ api docs
    def api_doc_paths(self) -> tuple[str, ...]:
        return self.strings("api_doc", "paths")

    def api_doc_document_keys(self) -> tuple[str, ...]:
        return self.strings("api_doc", "document_keys")

    def api_doc_max_endpoints(self) -> int:
        return self.integer("api_doc", "max_endpoints", default=20)

    # ------------------------------------------------------------------ debug
    def debug_probes(self) -> tuple[DebugProbe, ...]:
        value = self._get("debug", "probes")
        if not isinstance(value, (list, tuple)):
            return ()
        probes: list[DebugProbe] = []
        for entry in value:
            if not isinstance(entry, Mapping) or "path" not in entry:
                continue
            probes.append(
                DebugProbe(
                    path=str(entry["path"]),
                    family=str(entry.get("family", "debug")),
                    markers=tuple(str(item) for item in entry.get("markers") or ()),
                )
            )
        return tuple(probes)

    def debug_stack_markers(self) -> tuple[str, ...]:
        return self.strings("debug", "stack_trace_markers")

    # ------------------------------------------------------------------ listings
    def directory_paths(self) -> tuple[str, ...]:
        return self.strings("directory_listing", "paths")

    def directory_markers(self) -> tuple[str, ...]:
        return self.strings("directory_listing", "markers")

    def directory_entry_regex(self) -> re.Pattern[str] | None:
        return self.pattern("directory_listing", "entry_regex")

    def directory_max_entries(self) -> int:
        return self.integer("directory_listing", "max_entries", default=20)

    # ------------------------------------------------------------------ dashboards
    def dashboards(self) -> tuple[DashboardPanel, ...]:
        value = self._get("dashboard", "panels")
        if not isinstance(value, (list, tuple)):
            return ()
        panels: list[DashboardPanel] = []
        for entry in value:
            if not isinstance(entry, Mapping) or "product" not in entry:
                continue
            panels.append(
                DashboardPanel(
                    product=str(entry["product"]),
                    paths=tuple(str(item) for item in entry.get("paths") or ()),
                    markers=tuple(str(item) for item in entry.get("markers") or ()),
                    auth_markers=tuple(str(item) for item in entry.get("auth_markers") or ()),
                )
            )
        return tuple(panels)

    def dashboard_header_markers(self) -> dict[str, tuple[str, ...]]:
        raw = self.mapping("dashboard", "header_markers")
        return {
            str(product): tuple(str(item) for item in headers)
            for product, headers in raw.items()
            if isinstance(headers, (list, tuple))
        }

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
                    acl_query=str(entry.get("acl_query", "?acl")),
                    listing_markers=tuple(str(item) for item in entry.get("listing_markers") or ()),
                    public_acl_markers=tuple(
                        str(item) for item in entry.get("public_acl_markers") or ()
                    ),
                    denied_status=tuple(int(item) for item in entry.get("denied_status") or ()),
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
        return tuple(
            int(item) for item in self.strings_numbered("bucket", "access_denied_status")
        ) or (401, 403)

    def strings_numbered(self, *path: str) -> tuple[int, ...]:
        value = self._get(*path)
        if not isinstance(value, (list, tuple)):
            return ()
        return tuple(int(item) for item in value)

    # ------------------------------------------------------------------ key material
    def key_paths(self) -> tuple[str, ...]:
        return self.strings("key_material", "paths")

    def key_pem_marker(self) -> str:
        return self.string("key_material", "pem_marker", default="-----BEGIN")

    def key_secret_kind(self) -> str:
        return self.string("key_material", "secret_kind", default="private-key")

    def key_extensions(self) -> tuple[str, ...]:
        return self.strings("key_material", "key_extensions")

    # ------------------------------------------------------------------ infrastructure artifacts
    def artifact_groups(self) -> tuple[str, ...]:
        """Every artifact group the corpus defines (one check per group)."""
        groups = self.mapping("artifacts", "groups")
        return tuple(str(name) for name in groups)

    def artifact_probes(self, group: str) -> tuple[ArtifactProbe, ...]:
        """The path inventory of one artifact group, with its proven content markers."""
        value = self._get("artifacts", "groups", group)
        if not isinstance(value, (list, tuple)) or not value:
            return ()
        probes: list[ArtifactProbe] = []
        for entry in value:
            if not isinstance(entry, Mapping) or "path" not in entry:
                continue
            probes.append(
                ArtifactProbe(
                    path=str(entry["path"]),
                    family=str(entry.get("family", group)),
                    markers=tuple(str(item) for item in entry.get("markers") or ()),
                )
            )
        return tuple(probes)

    def artifact_binary_extensions(self) -> tuple[str, ...]:
        """Suffixes whose content is binary by nature: a non-HTML 2xx is the finding."""
        return tuple(
            extension.lower() for extension in self.strings("artifacts", "binary_extensions")
        )

    def artifact_min_bytes(self) -> int:
        return self.integer("artifacts", "min_bytes", default=24)

    # ------------------------------------------------------------------ server platforms
    # WP-30 (REQ-DET-023): the ``servers`` section. Like ``artifacts``, the checks are almost
    # entirely data — one group per check, plus the header-default settings of each family.
    def server_groups(self) -> tuple[str, ...]:
        """Every server-platform group the corpus defines (one check per group)."""
        groups = self.mapping("servers", "groups")
        return tuple(str(name) for name in groups)

    def server_probes(self, group: str) -> tuple[ArtifactProbe, ...]:
        """The path inventory of one server group, with its proven content markers."""
        value = self._get("servers", "groups", group)
        if not isinstance(value, (list, tuple)) or not value:
            return ()
        probes: list[ArtifactProbe] = []
        for entry in value:
            if not isinstance(entry, Mapping) or "path" not in entry:
                continue
            probes.append(
                ArtifactProbe(
                    path=str(entry["path"]),
                    family=str(entry.get("family", group)),
                    markers=tuple(str(item) for item in entry.get("markers") or ()),
                )
            )
        return tuple(probes)

    def server_min_bytes(self) -> int:
        return self.integer("servers", "min_bytes", default=24)

    def server_header_name(self) -> str:
        return self.string("servers", "headers", "server_header", default="server")

    def server_version_regex(self) -> re.Pattern[str] | None:
        return self.pattern("servers", "headers", "server_version_regex")

    def stack_headers(self) -> tuple[str, ...]:
        return tuple(name.lower() for name in self.strings("servers", "headers", "stack_headers"))

    def cache_control_header(self) -> str:
        return self.string("servers", "headers", "cache_control_header", default="cache-control")

    def expires_header(self) -> str:
        return self.string("servers", "headers", "expires_header", default="expires")

    def cache_private_directives(self) -> tuple[str, ...]:
        return tuple(
            directive.lower()
            for directive in self.strings("servers", "headers", "private_directives")
        )

    def server_session_cookie_names(self) -> frozenset[str]:
        return frozenset(
            name.lower() for name in self.strings("servers", "headers", "session_cookie_names")
        )

    def server_shared_cache_directives(self) -> tuple[str, ...]:
        """The ``Cache-Control`` directives that *entitle* a shared cache to store an answer."""
        return tuple(
            directive.lower()
            for directive in self.strings("servers", "headers", "shared_cache_directives")
        )

    def server_session_cookie_tokens(self) -> tuple[str, ...]:
        return tuple(
            token.lower() for token in self.strings("servers", "headers", "session_cookie_tokens")
        )

    # ------------------------------------------------------------------ headers
    def header_baseline(self, *, https: bool) -> tuple[str, ...]:
        return tuple(name.lower() for name in self.strings("headers", "https" if https else "http"))

    def weak_csp_markers(self) -> tuple[str, ...]:
        return self.strings("headers", "weak_csp_markers")

    def session_cookie_names(self) -> frozenset[str]:
        return frozenset(name.lower() for name in self.strings("headers", "session_cookie_names"))

    # ------------------------------------------------------------------ cors
    def cors_origins(self) -> tuple[str, ...]:
        return self.strings("cors", "origins")

    # ------------------------------------------------------------------ email auth
    def email_spf_name(self) -> str:
        return self.string("email_auth", "spf_name", default="")

    def email_dmarc_name(self) -> str:
        return self.string("email_auth", "dmarc_name", default="_dmarc")

    def email_dkim_selectors(self) -> tuple[str, ...]:
        return self.strings("email_auth", "dkim_selectors")

    def email_permissive_spf(self) -> tuple[str, ...]:
        return self.strings("email_auth", "permissive_spf")

    def email_dmarc_policies(self) -> tuple[str, ...]:
        return self.strings("email_auth", "dmarc_policies")

    # ------------------------------------------------------------------ webdav
    def webdav_methods(self) -> tuple[str, ...]:
        return self.strings("webdav", "methods")

    def webdav_paths(self) -> tuple[str, ...]:
        return self.strings("webdav", "paths")

    def webdav_write_verbs(self) -> tuple[str, ...]:
        return self.strings("webdav", "write_verbs")

    def webdav_trace_marker(self) -> str:
        return self.string("webdav", "trace_marker", default="TRACE /")

    # ------------------------------------------------------------------ hidden paths
    def hidden_wordlist(self) -> str:
        return self.string("hidden", "wordlist", default="wordlists/hidden-paths.txt")

    def hidden_interest_regex(self) -> re.Pattern[str] | None:
        return self.pattern("hidden", "interest_regex")

    def hidden_extensions(self) -> tuple[str, ...]:
        return self.strings("hidden", "extension_mutations")

    # ------------------------------------------------------------------ staging
    def staging_labels(self) -> tuple[str, ...]:
        return self.strings("staging", "labels")

    def staging_paths(self) -> tuple[str, ...]:
        return self.strings("staging", "path_labels")

    def staging_markers(self) -> tuple[str, ...]:
        return self.strings("staging", "markers")

    def staging_min_delta(self) -> float:
        value = self._get("staging", "min_similarity_delta")
        try:
            return 0.05 if value is None else float(value)
        except (TypeError, ValueError) as exc:
            raise ConfigurationError(
                f"{self.source}: staging/min_similarity_delta must be a number"
            ) from exc

    # ------------------------------------------------------------------ metadata
    def metadata_endpoints(self) -> tuple[MetadataEndpoint, ...]:
        value = self._get("metadata_ssrf", "endpoints")
        if not isinstance(value, (list, tuple)):
            return ()
        endpoints: list[MetadataEndpoint] = []
        for entry in value:
            if not isinstance(entry, Mapping) or "url" not in entry:
                continue
            headers = entry.get("headers")
            endpoints.append(
                MetadataEndpoint(
                    provider=str(entry.get("provider", "unknown")),
                    url=str(entry["url"]),
                    headers={str(k): str(v) for k, v in (headers or {}).items()},
                    v1_marker=(
                        str(entry["imds_v1_marker"]) if entry.get("imds_v1_marker") else None
                    ),
                    v2_status=(
                        int(entry["imds_v2_status"])
                        if entry.get("imds_v2_status") is not None
                        else None
                    ),
                )
            )
        return tuple(endpoints)

    def metadata_sink_hints(self) -> tuple[str, ...]:
        return tuple(name.lower() for name in self.strings("metadata_ssrf", "sink_param_hints"))

    # ------------------------------------------------------------------ enumeration
    def user_fields(self) -> tuple[str, ...]:
        return self.strings("user_enumeration", "user_fields")

    def password_fields(self) -> tuple[str, ...]:
        return self.strings("user_enumeration", "password_fields")

    def candidate_names(self) -> tuple[str, ...]:
        return self.strings("user_enumeration", "candidate_names")

    def valid_markers(self) -> tuple[str, ...]:
        return self.strings("user_enumeration", "valid_markers")

    def invalid_markers(self) -> tuple[str, ...]:
        return self.strings("user_enumeration", "invalid_markers")

    def dummy_password(self) -> str:
        return self.string("user_enumeration", "dummy_password", default="arachne-not-real-9f3a")

    # ------------------------------------------------------------------ unauth api
    def unauth_path_hints(self) -> tuple[str, ...]:
        return self.strings("unauth_api", "path_hints")

    def unauth_data_content_types(self) -> tuple[str, ...]:
        return self.strings("unauth_api", "data_content_types")

    def unauth_auth_status(self) -> tuple[int, ...]:
        statuses = self.strings_numbered("unauth_api", "auth_challenge_status")
        return tuple(int(item) for item in statuses) or (401, 403)

    # ------------------------------------------------------------------ default creds
    def credential_products(self) -> tuple[CredentialProduct, ...]:
        value = self._get("default_credentials", "products")
        if not isinstance(value, (list, tuple)):
            return ()
        products: list[CredentialProduct] = []
        for entry in value:
            if not isinstance(entry, Mapping) or "product" not in entry:
                continue
            fields = entry.get("fields")
            products.append(
                CredentialProduct(
                    product=str(entry["product"]),
                    login_path=str(entry.get("login_path", "/login")),
                    method=str(entry.get("method", "POST")).upper(),
                    fields={str(k): str(v) for k, v in (fields or {}).items()},
                    success_markers=tuple(str(item) for item in entry.get("success_markers") or ()),
                    failure_markers=tuple(str(item) for item in entry.get("failure_markers") or ()),
                )
            )
        return tuple(products)


# --------------------------------------------------------------------------- loading
def parse_corpus(data: Any, *, source: str = "<memory>") -> M4Corpus:
    if not isinstance(data, Mapping):
        msg = f"{source}: expected a mapping, got {type(data).__name__}"
        raise ConfigurationError(msg)
    version = data.get("version")
    if not isinstance(version, str) or not version:
        raise ConfigurationError(f"{source}: 'version' is required")
    corpus = M4Corpus(version=version, source=source, raw=data)
    # Compile the regexes the checks depend on, so a broken corpus fails here rather than
    # mid-scan. Everything else degrades to "no entries" (a corpus may omit a family).
    for name in (
        "env_assignment_regex",
        "sourcemap_reference_regex",
        "directory_entry_regex",
        "server_version_regex",
    ):
        getattr(corpus, name)()
    return corpus


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
            raise ConfigurationError(f"M4 probe corpus {resolved} does not exist")
        return resolved, str(resolved)
    return None, "/".join(DEFAULT_CORPUS_RESOURCE)


def load_corpus(path: str | None = None) -> M4Corpus:
    """Load the M4 corpus from ``path`` (a file or a directory), or the shipped one."""
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
        msg = f"bundled M4 probe corpus is missing: {exc}"
        raise ConfigurationError(msg) from exc
    return parse_corpus(_safe_yaml(text, source=source), source=source)


def load_wordlist(
    name: str,
    *,
    override_dir: str | None = None,
    limit: int = MAX_WORDLIST_ENTRIES,
) -> tuple[str, ...]:
    """Load an M4 wordlist: an operator directory first, then the packaged one."""
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
        resource = files("arachne.templates") / "m4" / relative
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
