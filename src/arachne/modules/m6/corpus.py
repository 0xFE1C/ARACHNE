"""Load the M6 probe corpus (``templates/m6/probes.yaml`` + ``wordlists/``, F-09-04).

M6 is the module whose evidence is mostly *files and logs* rather than HTTP responses, so the
corpus is larger and more varied than M3/M4's: webshell signatures and behaviour thresholds,
GenAI endpoint/key/agent-config patterns, credential detectors, CI leakage markers, the Sigma
rule directory, the LPE index and the deception trigger fields. Almost all of M6 is therefore
data — which is exactly what the module's *safety documentation* needs to be, because the
corpus states in one reviewable place everything M6 looks at and nothing it does.

The loader mirrors ``m4.corpus``/``m5.corpus``: typed accessors over the raw mapping, validated
lazily so a corpus without, say, a ``deception`` section still supports every other check, and a
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
    "M6Corpus",
    "NamedPattern",
    "Signature",
    "TemplateSpec",
    "load_corpus",
    "load_wordlist",
    "parse_corpus",
]

#: Where the shipped M6 corpus lives inside the package.
DEFAULT_CORPUS_RESOURCE: Final = ("m6", "probes.yaml")

#: Hard cap on a wordlist a check will read (a project-supplied list must not turn a probe
#: into a content-discovery campaign).
MAX_WORDLIST_ENTRIES: Final = 500


@dataclass(frozen=True, slots=True)
class Signature:
    """A named, severity-hinted signature (webshell signatures, secret detectors, ...)."""

    id: str
    severity: str
    regex: re.Pattern[str]
    hint: str = ""
    kind: str = ""


#: ``NamedPattern`` is the read-only alias a caller uses when it only needs kind + regex.
NamedPattern = Signature


@dataclass(frozen=True, slots=True)
class TemplateSpec:
    """One strictly-matcher template (``templates`` of the M6 corpus, ch06#3).

    A template is a path list plus body markers (plain substrings, no templating engine): a
    response flags when its status matches and it carries the markers (``all`` or ``any``).
    """

    id: str
    paths: tuple[str, ...]
    markers: tuple[str, ...]
    status: tuple[int, ...] = (200,)
    severity: str = "medium"
    match: str = "any"
    hint: str = ""
    reference: str = ""


def _compile(expression: str, *, source: str, path: str) -> re.Pattern[str]:
    try:
        return re.compile(expression, re.IGNORECASE)
    except re.error as exc:
        msg = f"{source}: {'/'.join(path.split('/'))} is not a valid regex: {exc}"
        raise ConfigurationError(msg) from exc


@dataclass(frozen=True, slots=True)
class M6Corpus:
    """The parsed M6 corpus with typed accessors for what the checks consume."""

    version: str
    source: str
    raw: Mapping[str, Any] = field(default_factory=dict)

    # ------------------------------------------------------------------ generic
    def section(self, name: str) -> Mapping[str, Any]:
        value = self.raw.get(name)
        return value if isinstance(value, Mapping) else {}

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

    def number(self, *path: str, default: float = 0.0) -> float:
        value = self._get(*path)
        try:
            return default if value is None else float(value)
        except (TypeError, ValueError) as exc:
            raise ConfigurationError(f"{self.source}: {'/'.join(path)} must be a number") from exc

    def mapping(self, *path: str) -> Mapping[str, Any]:
        value = self._get(*path)
        if value is None:
            return {}
        if not isinstance(value, Mapping):
            raise ConfigurationError(f"{self.source}: {'/'.join(path)} must be a mapping")
        return value

    def _entries(self, *path: str) -> tuple[Mapping[str, Any], ...]:
        value = self._get(*path)
        if not isinstance(value, (list, tuple)):
            return ()
        return tuple(item for item in value if isinstance(item, Mapping))

    def _signatures(self, *path: str) -> tuple[Signature, ...]:
        out: list[Signature] = []
        for entry in self._entries(*path):
            expression = entry.get("pattern") or entry.get("regex")
            if expression is None:
                continue
            out.append(
                Signature(
                    id=str(entry.get("id") or entry.get("kind") or "sig"),
                    severity=str(entry.get("severity", "medium")),
                    regex=_compile(str(expression), source=self.source, path="/".join(path)),
                    hint=str(entry.get("hint", "")),
                    kind=str(entry.get("kind", "")),
                )
            )
        return tuple(out)

    # ------------------------------------------------------------------ webshell
    def webshell_script_extensions(self) -> tuple[str, ...]:
        return tuple(item.lower() for item in self.strings("webshell", "script_extensions"))

    def webshell_script_markers(self) -> tuple[str, ...]:
        return tuple(item.lower() for item in self.strings("webshell", "script_markers"))

    def webshell_signatures(self) -> tuple[Signature, ...]:
        return self._signatures("webshell", "signatures")

    def webshell_shell_markers(self) -> tuple[str, ...]:
        return tuple(item.lower() for item in self.strings("webshell", "shell_markers"))

    def webshell_heuristics(self) -> Mapping[str, float]:
        return self.mapping("webshell", "heuristics")

    def webshell_served_wordlist(self) -> str:
        return self.string(
            "webshell", "served_paths_wordlist", default="wordlists/served-shell-paths.txt"
        )

    # ------------------------------------------------------------------ genai
    def genai_endpoint_paths(self) -> tuple[str, ...]:
        return self.strings("genai", "endpoint_paths")

    def genai_provider_hosts(self) -> tuple[str, ...]:
        return self.strings("genai", "provider_hosts")

    def genai_key_patterns(self) -> tuple[Signature, ...]:
        return self._signatures("genai", "key_patterns")

    def genai_client_markers(self) -> tuple[str, ...]:
        return tuple(item.lower() for item in self.strings("genai", "client_markers"))

    def genai_agent_config_globs(self) -> tuple[str, ...]:
        return self.strings("genai", "agent_config_globs")

    def genai_agent_risk_markers(self) -> tuple[str, ...]:
        return tuple(item.lower() for item in self.strings("genai", "agent_risk_markers"))

    def genai_prompt_surface_markers(self) -> tuple[str, ...]:
        return tuple(item.lower() for item in self.strings("genai", "prompt_surface_markers"))

    # ------------------------------------------------------------------ secrets
    def secret_detectors(self) -> tuple[Signature, ...]:
        return self._signatures("secrets", "detectors")

    def secret_history_files(self) -> tuple[str, ...]:
        return self.strings("secrets", "history_files")

    def secret_skip_globs(self) -> tuple[str, ...]:
        return self.strings("secrets", "skip_globs")

    # ------------------------------------------------------------------ ci
    def ci_log_globs(self) -> tuple[str, ...]:
        return self.strings("ci", "log_globs")

    def ci_markers(self) -> tuple[str, ...]:
        return self.strings("ci", "markers")

    # ------------------------------------------------------------------ sigma
    def sigma_rules_dir(self) -> str:
        return self.string("sigma", "rules_dir", default="sigma")

    def sigma_log_globs(self) -> tuple[str, ...]:
        return self.strings("sigma", "log_globs")

    def sigma_time_fields(self) -> tuple[str, ...]:
        return self.strings("sigma", "time_fields")

    # ------------------------------------------------------------------ lpe / ad / deception
    def lpe_index_resource(self) -> str:
        return self.string("lpe", "index", default="lpe-index.yaml")

    def lpe_kernel_products(self) -> tuple[str, ...]:
        return tuple(item.lower() for item in self.strings("lpe", "kernel_products"))

    def ad_escalation_edges(self) -> tuple[str, ...]:
        return self.strings("ad", "escalation_edges")

    def ad_domain_admin_labels(self) -> tuple[str, ...]:
        return tuple(item.lower() for item in self.strings("ad", "domain_admin_labels"))

    def deception_token_fields(self) -> tuple[str, ...]:
        return self.strings("deception", "token_fields")

    def deception_source_fields(self) -> tuple[str, ...]:
        return self.strings("deception", "source_fields")

    def deception_time_fields(self) -> tuple[str, ...]:
        return self.strings("deception", "time_fields")

    # ------------------------------------------------------------------ matcher templates (ch06#3)
    def matcher_templates(self) -> tuple[TemplateSpec, ...]:
        out: list[TemplateSpec] = []
        for entry in self._entries("templates"):
            paths = entry.get("path") or entry.get("paths")
            if not isinstance(paths, (list, tuple)) or not paths:
                continue
            markers = entry.get("markers") or entry.get("words") or ()
            status = entry.get("status") or (200,)
            out.append(
                TemplateSpec(
                    id=str(entry.get("id") or "template"),
                    paths=tuple(str(item) for item in paths),
                    markers=tuple(str(item) for item in markers),
                    status=tuple(int(item) for item in status),
                    severity=str(entry.get("severity", "medium")),
                    match=str(entry.get("match", "any")),
                    hint=str(entry.get("hint", "")),
                    reference=str(entry.get("reference", "")),
                )
            )
        return tuple(out)

    # ------------------------------------------------------------------ config surfaces (ch06#17)
    def credential_surface_paths(self) -> tuple[str, ...]:
        return self.strings("credential_surfaces", "paths")

    def credential_surface_markers(self) -> tuple[str, ...]:
        return tuple(item.lower() for item in self.strings("credential_surfaces", "markers"))

    # ------------------------------------------------------------------ exploit index (ch06#5)
    def exploit_index_resource(self) -> str:
        return self.string("exploit", "index", default="exploit-index.yaml")


def parse_corpus(data: Any, *, source: str = "<memory>") -> M6Corpus:
    """Validate an already-parsed corpus document."""
    if not isinstance(data, Mapping):
        msg = f"{source}: expected a mapping at the top level, got {type(data).__name__}"
        raise ConfigurationError(msg)
    return M6Corpus(
        version=str(data.get("version", "0")),
        source=source,
        raw=dict(data),
    )


def load_corpus(path: str | Path | None = None) -> M6Corpus:
    """Load the M6 corpus from ``path``, or the bundled default when ``path`` is None."""
    if path is None:
        node = files("arachne.templates")
        for part in DEFAULT_CORPUS_RESOURCE:
            node = node.joinpath(part)
        try:
            text = node.read_text(encoding="utf-8")
        except (FileNotFoundError, OSError) as exc:  # pragma: no cover - packaging failure
            msg = f"bundled M6 corpus is missing ({'/'.join(DEFAULT_CORPUS_RESOURCE)}): {exc}"
            raise ConfigurationError(msg) from exc
        source = "bundled M6 corpus"
    else:
        resolved = Path(path).expanduser()
        if resolved.is_dir():
            resolved = resolved / "probes.yaml"
        if not resolved.is_file():
            msg = f"M6 corpus {resolved} does not exist or is not a file"
            raise ConfigurationError(msg)
        source = str(resolved)
        try:
            text = resolved.read_text(encoding="utf-8")
        except OSError as exc:
            msg = f"cannot read M6 corpus {resolved}: {exc}"
            raise ConfigurationError(msg) from exc
    try:
        data = yaml.safe_load(text)  # F-08-06: safe_load only
    except yaml.YAMLError as exc:
        msg = f"{source}: not valid YAML: {exc}"
        raise ConfigurationError(msg) from exc
    return parse_corpus(data, source=source)


def load_wordlist(
    name: str,
    *,
    override_dir: str | Path | None = None,
    limit: int = MAX_WORDLIST_ENTRIES,
) -> tuple[str, ...]:
    """Read a wordlist, preferring the operator's directory over the packaged file (F-09-04)."""
    text = ""
    if override_dir:
        base = Path(override_dir).expanduser()
        if base.is_file():
            base = base.parent
        for candidate in (base / "wordlists" / name, base / name):
            if candidate.is_file():
                try:
                    text = candidate.read_text(encoding="utf-8")
                except OSError:  # pragma: no cover - unreadable
                    text = ""
                if text:
                    break
    if not text:
        node = files("arachne.templates").joinpath("m6", name)
        try:
            text = node.read_text(encoding="utf-8")
        except (FileNotFoundError, OSError):
            text = ""
    entries: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        entries.append(stripped)
        if len(entries) >= limit:
            break
    return tuple(entries)
