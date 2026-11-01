"""The signature system: a Nuclei-compatible template subset (F-05-02).

Templates are the passive half of the engine — they say *what the bytes look like* when a
known exposure is present, where rules say what a combination of signals means. Two formats
are understood:

**Nuclei-compatible** (``templates/nuclei/*.yaml``)
    The community shape: ``id``, ``info``, ``requests``/``http`` with ``method``/``path``,
    ``matchers`` (``status``/``word``/``regex``/``dsl``) and ``extractors``
    (``regex``/``json``/``kval``), plus ``matchers-condition``. A subset, deliberately: the
    corpus is importable, and importing a template cannot execute anything.
**Native ARACHNE signatures** (``templates/signatures/*.yaml``)
    The same matchers and extractors over a non-HTTP subject — a banner, a certificate, a
    DNS response, a file artifact — selected by ``subject: <evidence kind>`` with an
    optional ``field:`` path into its payload.

Both are evaluated by one engine against one :class:`Subject` built from the candidate's own
evidence, and both are restricted to **regex + JSONPath** exactly as F-05-02 requires:

* a ``dsl`` matcher is parsed by :mod:`arachne.analyzer.conditions` — the same hand-written,
  ``eval``-free expression language the rules use, over a fixed fact space
  (``status_code``, ``body``, ``header("name")``-free ``headers.<name>``, ``content_length``);
* a ``json`` extractor walks a JSONPath subset (``$``, ``.key``, ``[n]``, ``[*]``,
  ``["key"]``, ``..key``) with no recursive-descent extensions beyond that.

Nothing here performs I/O: a template *describes* a request, and
``Signature.matches_request(url, method)`` tells the caller whether a request it already
made (or is about to make) is one the template covers. Running requests is the check layer's
job, which is what keeps "no network in the rule engine" true here too.
"""

from __future__ import annotations

import fnmatch
import json
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from importlib.resources import files
from pathlib import Path
from typing import Any, Final
from urllib.parse import urlsplit

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from arachne.analyzer.conditions import FactSpace, parse_expression
from arachne.analyzer.model import Candidate
from arachne.core.errors import ConfigurationError

__all__ = [
    "DEFAULT_NUCLEI_RESOURCE",
    "DEFAULT_SIGNATURE_RESOURCE",
    "EXTRACTOR_TYPES",
    "MATCHER_TYPES",
    "Signature",
    "SignatureLibrary",
    "SignatureMatch",
    "Subject",
    "load_signatures",
    "parse_signature",
    "parse_signatures",
    "select_jsonpath",
]

#: Bundled template directories, relative to the ``arachne.templates`` package.
DEFAULT_NUCLEI_RESOURCE: Final = ("nuclei",)
DEFAULT_SIGNATURE_RESOURCE: Final = ("signatures",)

MATCHER_TYPES: Final[tuple[str, ...]] = ("status", "word", "regex", "dsl", "size")
EXTRACTOR_TYPES: Final[tuple[str, ...]] = ("regex", "json", "kval")

_MODEL_CONFIG = ConfigDict(frozen=True, extra="forbid")

#: Parts of a subject a matcher/extractor may read.
_PARTS: Final[tuple[str, ...]] = ("body", "header", "headers", "status", "all", "raw")


# --------------------------------------------------------------------------- subject


@dataclass(frozen=True, slots=True)
class Subject:
    """What a signature is matched against: one request/response view or one payload.

    ``http`` marks an HTTP view, which is the only kind the ``requests`` block of a nuclei
    template applies to. ``payload`` is the non-HTTP subject of a native signature, and
    ``kind`` is the evidence kind it came from, so a native signature can declare exactly
    which artifact it reads (``subject: banner``) instead of guessing.
    """

    kind: str = ""
    http: bool = False
    url: str = ""
    method: str = "GET"
    status: int | None = None
    headers: Mapping[str, str] = field(default_factory=dict)
    body: str = ""
    payload: Mapping[str, Any] = field(default_factory=dict)

    def part(self, name: str) -> str:
        """The text of ``name`` (``body``, ``header``, ``status``, ``all``/``raw``)."""
        lowered = (name or "body").lower()
        if lowered == "status":
            return "" if self.status is None else str(self.status)
        if lowered in {"header", "headers", "all_headers"}:
            return "\n".join(f"{key}: {value}" for key, value in self.headers.items())
        if lowered == "all" or lowered == "raw":
            headers = "\n".join(f"{key}: {value}" for key, value in self.headers.items())
            status = "" if self.status is None else f"HTTP {self.status}\n"
            return f"{status}{headers}\n{self.body}"
        return self.body

    def header(self, name: str) -> str | None:
        lowered = name.lower()
        for key, value in self.headers.items():
            if key.lower() == lowered:
                return value
        return None

    def facts(self) -> FactSpace:
        """The ``dsl`` matcher's fact space — fixed, so a template cannot invent one."""
        return FactSpace(
            {
                "status_code": self.status,
                "body": self.body,
                "content_length": len(self.body),
                "headers": dict(self.headers),
                "url": self.url,
                "method": self.method,
                "payload": dict(self.payload),
            }
        )


# --------------------------------------------------------------------------- models


class Matcher(BaseModel):
    """One nuclei matcher."""

    model_config = ConfigDict(frozen=True, extra="forbid", populate_by_name=True)

    type: str
    part: str = "body"
    condition: str = "or"
    words: tuple[str, ...] = ()
    regex: tuple[str, ...] = ()
    status: tuple[int, ...] = ()
    dsl: tuple[str, ...] = ()
    size: tuple[int, ...] = ()
    case_insensitive: bool = Field(default=True, alias="case-insensitive")
    negative: bool = False

    @model_validator(mode="after")
    def _validate(self) -> Matcher:
        if self.type not in MATCHER_TYPES:
            raise ValueError(
                f"matcher type {self.type!r} is not supported; supported: {MATCHER_TYPES}"
            )
        if self.condition not in {"and", "or"}:
            raise ValueError(f"matcher condition {self.condition!r} must be 'and' or 'or'")
        if self.part.lower() not in _PARTS:
            raise ValueError(f"matcher part {self.part!r} is not one of {_PARTS}")
        for expression in self.dsl:
            parse_expression(expression)
        required = {
            "status": self.status,
            "word": self.words,
            "regex": self.regex,
            "dsl": self.dsl,
            "size": self.size,
        }[self.type]
        if not required:
            raise ValueError(f"matcher of type {self.type!r} declares no values")
        return self

    def match(self, subject: Subject) -> bool:
        text = subject.part(self.part)
        if self.type == "status":
            result = subject.status in self.status
        elif self.type == "word":
            result = self._match_words(text)
        elif self.type == "regex":
            result = self._match_regexes(text)
        elif self.type == "size":
            result = len(text.encode("utf-8")) in self.size
        else:
            result = self._match_dsl(subject)
        return not result if self.negative else result

    def _match_words(self, text: str) -> bool:
        haystack = text.lower() if self.case_insensitive else text
        matches = []
        for word in self.words:
            needle = word.lower() if self.case_insensitive else word
            matches.append(needle in haystack)
        return all(matches) if self.condition == "and" else any(matches)

    def _match_regexes(self, text: str) -> bool:
        flags = re.IGNORECASE if self.case_insensitive else 0
        matches = []
        for pattern in self.regex:
            compiled = _compile(pattern, flags=flags)
            matches.append(compiled.search(text) is not None)
        return all(matches) if self.condition == "and" else any(matches)

    def _match_dsl(self, subject: Subject) -> bool:
        facts = subject.facts()
        matches = [parse_expression(expression).evaluate(facts, {}) for expression in self.dsl]
        return all(matches) if self.condition == "and" else any(matches)


class Extractor(BaseModel):
    """One nuclei extractor (regex, JSONPath, or key-value).

    ``json_paths`` is spelled ``json:`` in the template (nuclei's own spelling); the field is
    named differently here because ``json`` shadows a method every pydantic model inherits.
    """

    model_config = ConfigDict(frozen=True, extra="forbid", populate_by_name=True)

    type: str
    name: str | None = None
    part: str = "body"
    regex: tuple[str, ...] = ()
    json_paths: tuple[str, ...] = Field(default=(), alias="json")
    kval: tuple[str, ...] = ()
    group: int = 0
    internal: bool = False

    @model_validator(mode="after")
    def _validate(self) -> Extractor:
        if self.type not in EXTRACTOR_TYPES:
            raise ValueError(
                f"extractor type {self.type!r} is not supported; supported: {EXTRACTOR_TYPES}"
            )
        if self.part.lower() not in _PARTS:
            raise ValueError(f"extractor part {self.part!r} is not one of {_PARTS}")
        values = {"regex": self.regex, "json": self.json_paths, "kval": self.kval}[self.type]
        if not values:
            raise ValueError(f"extractor of type {self.type!r} declares no values")
        return self

    def extract(self, subject: Subject) -> tuple[str, ...]:
        text = subject.part(self.part)
        if self.type == "regex":
            return self._extract_regex(text)
        if self.type == "kval":
            return self._extract_kval(text)
        return self._extract_json(text)

    def _extract_regex(self, text: str) -> tuple[str, ...]:
        found: list[str] = []
        for pattern in self.regex:
            compiled = _compile(pattern)
            for match in compiled.finditer(text):
                try:
                    value = match.group(self.group)
                except (IndexError, re.error):
                    # A template asking for a group its own pattern does not have yields
                    # nothing rather than failing the scan.
                    continue
                if value and value not in found:
                    found.append(value)
        return tuple(found)

    def _extract_kval(self, text: str) -> tuple[str, ...]:
        found: list[str] = []
        for key in self.kval:
            for match in re.finditer(rf"^\s*{re.escape(key)}\s*[:=]\s*(.+)$", text, re.MULTILINE):
                value = match.group(1).strip()
                if value and value not in found:
                    found.append(value)
        return tuple(found)

    def _extract_json(self, text: str) -> tuple[str, ...]:
        try:
            document = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            return ()
        found: list[str] = []
        for expression in self.json_paths:
            for value in select_jsonpath(document, expression):
                rendered = _scalar_text(value)
                if rendered is not None and rendered not in found:
                    found.append(rendered)
        return tuple(found)


class TemplateRequest(BaseModel):
    """One entry of a nuclei ``requests``/``http`` block."""

    model_config = ConfigDict(frozen=True, extra="forbid", populate_by_name=True)

    method: str = "GET"
    path: tuple[str, ...] = ()
    headers: dict[str, str] = Field(default_factory=dict)
    matchers_condition: str = Field(default="or", alias="matchers-condition")
    matchers: tuple[Matcher, ...] = ()
    extractors: tuple[Extractor, ...] = ()
    redirects: bool = False

    @model_validator(mode="after")
    def _validate(self) -> TemplateRequest:
        if self.matchers_condition not in {"and", "or"}:
            raise ValueError(
                f"matchers-condition {self.matchers_condition!r} must be 'and' or 'or'"
            )
        if not self.matchers:
            raise ValueError("a template request must declare at least one matcher")
        return self

    def match(self, subject: Subject) -> bool:
        results = [matcher.match(subject) for matcher in self.matchers]
        return all(results) if self.matchers_condition == "and" else any(results)

    def extract(self, subject: Subject) -> dict[str, tuple[str, ...]]:
        out: dict[str, tuple[str, ...]] = {}
        for index, extractor in enumerate(self.extractors):
            if extractor.internal:
                continue
            name = extractor.name or f"extractor{index + 1}"
            values = extractor.extract(subject)
            if values:
                out.setdefault(name, values)
        return out


class Signature(BaseModel):
    """A whole template: metadata plus one or more requests (nuclei) or a subject (native)."""

    model_config = _MODEL_CONFIG

    id: str = Field(min_length=3, max_length=128)
    name: str = Field(min_length=1, max_length=512)
    severity: str = "info"
    description: str = ""
    tags: tuple[str, ...] = ()
    references: tuple[str, ...] = ()
    author: str | None = None
    requests: tuple[TemplateRequest, ...] = ()
    #: Native signatures name the evidence kind to read (``banner``, ``tls_certificate``, ...)
    #: and optionally a dotted ``field`` inside its payload.
    subject: str | None = None
    field: str | None = None
    kind: str = "nuclei"

    @model_validator(mode="after")
    def _validate(self) -> Signature:
        if not self.requests and not self.subject:
            raise ValueError(
                f"signature {self.id}: declare either a 'requests' block or a 'subject'"
            )
        if self.severity not in {"critical", "high", "medium", "low", "info", "unknown"}:
            raise ValueError(f"signature {self.id}: unknown severity {self.severity!r}")
        for request in self.requests:
            for path in request.path:
                if "{{" not in path and not path.startswith("/") and not path.startswith("http"):
                    raise ValueError(f"signature {self.id}: request path {path!r} is not a path")
        return self

    @property
    def request_paths(self) -> tuple[str, ...]:
        return tuple(path for request in self.requests for path in request.path)

    def matches_request(self, url: str, method: str = "GET") -> bool:
        """True when ``url`` is a request this template describes (path + method).

        A nuclei path is usually written as ``{{BaseURL}}/.env``: the placeholder stands for
        scheme and host, and what follows it is a real path. A placeholder *inside* the path
        (``{{BaseURL}}/api/{{id}}``) is a wildcard, which is the only honest reading — the
        template cannot know the concrete value.
        """
        path = urlsplit(url).path or "/"
        for request in self.requests:
            if request.method.upper() != (method or "GET").upper():
                continue
            for declared in request.path:
                if _path_matches(declared, path):
                    return True
        return False

    def match(self, subject: Subject) -> tuple[TemplateRequest, dict[str, tuple[str, ...]]] | None:
        """The first request whose matchers accept ``subject``, with its extractions."""
        for request in self.requests:
            if request.match(subject):
                return request, request.extract(subject)
        return None


@dataclass(frozen=True, slots=True)
class SignatureMatch:
    """A signature that matched a candidate, with what it extracted."""

    signature_id: str
    name: str
    severity: str
    tags: tuple[str, ...] = ()
    extracted: Mapping[str, tuple[str, ...]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "signature_id": self.signature_id,
            "name": self.name,
            "severity": self.severity,
            "tags": list(self.tags),
            "extracted": {key: list(values) for key, values in self.extracted.items()},
        }


# --------------------------------------------------------------------------- parsing


def parse_signature(data: Any, *, source: str = "<memory>") -> Signature:
    """Parse one template, accepting both the nuclei shape and the native shape."""
    if not isinstance(data, Mapping):
        msg = f"{source}: expected a mapping, got {type(data).__name__}"
        raise ConfigurationError(msg)
    document = dict(data)
    info = document.pop("info", None)
    if isinstance(info, Mapping):
        document.setdefault("name", info.get("name") or document.get("id"))
        document.setdefault("severity", str(info.get("severity", "info")).lower())
        document.setdefault("description", info.get("description", ""))
        document.setdefault("tags", info.get("tags", ()))
        references = info.get("reference")
        if isinstance(references, str):
            document.setdefault("references", (references,))
        elif isinstance(references, (list, tuple)):
            document.setdefault("references", tuple(str(item) for item in references))
        document.setdefault("author", info.get("author"))
    # A template without an ``info`` block still needs a display name; its id is one.
    document.setdefault("name", document.get("id"))
    # ``http`` is the current nuclei key; ``requests`` is the historical one.
    for key in ("http", "requests"):
        block = document.pop(key, None)
        if block is None:
            continue
        if not isinstance(block, (list, tuple)):
            raise ConfigurationError(f"{source}: {key!r} must be a list of requests")
        document["requests"] = [_normalize_request(item, source=source) for item in block]
        break
    if "requests" not in document and "subject" in document:
        # A native signature writes its matchers at the top level, because there is exactly one
        # subject (the evidence kind it names) rather than a list of requests.
        top_matchers = document.pop("matchers", None)
        top_extractors = document.pop("extractors", None)
        if top_matchers:
            document["requests"] = [
                {
                    "method": "GET",
                    "matchers": list(top_matchers),
                    "extractors": list(top_extractors or ()),
                    "matchers_condition": document.pop("matchers-condition", "or"),
                }
            ]
        elif top_extractors is not None:
            raise ConfigurationError(
                f"{source}: a native signature declares extractors without any matcher"
            )
    document.setdefault("kind", "native" if document.get("subject") else "nuclei")
    try:
        return Signature.model_validate(document)
    except ValidationError as exc:
        parts = [
            f"{'.'.join(str(item) for item in error['loc']) or '<root>'}: {error['msg']}"
            for error in exc.errors()
        ]
        raise ConfigurationError(f"{source}: invalid template: {'; '.join(parts)}") from exc


def _normalize_request(item: Any, *, source: str) -> dict[str, Any]:
    if not isinstance(item, Mapping):
        raise ConfigurationError(f"{source}: a request entry must be a mapping")
    payload = dict(item)
    payload.setdefault("method", payload.pop("method", "GET"))
    payload["matchers"] = list(payload.get("matchers") or ())
    payload["extractors"] = list(payload.get("extractors") or ())
    # ``path`` is either a list or a single string in the wild.
    path = payload.get("path")
    if isinstance(path, str):
        payload["path"] = [path]
    return payload


def parse_signatures(data: Any, *, source: str = "<memory>") -> tuple[Signature, ...]:
    """Parse a template *file*: either one template or a list of them."""
    if isinstance(data, Mapping) and "signatures" in data:
        items = data["signatures"]
        if not isinstance(items, (list, tuple)):
            raise ConfigurationError(f"{source}: 'signatures' must be a list")
        return tuple(
            parse_signature(item, source=f"{source}[{index}]") for index, item in enumerate(items)
        )
    if isinstance(data, (list, tuple)):
        return tuple(
            parse_signature(item, source=f"{source}[{index}]") for index, item in enumerate(data)
        )
    return (parse_signature(data, source=source),)


def load_signatures(
    directories: Iterable[str | Path] | None = None, *, include_bundled: bool = True
) -> tuple[Signature, ...]:
    """Load every ``*.yaml`` template from ``directories`` plus the bundled corpus.

    Duplicate ids are refused: two templates claiming one identity would make "which
    signature matched" unanswerable, the same reason the module registry refuses them.
    """
    loaded: list[Signature] = []
    seen: set[str] = set()
    if include_bundled:
        for resource_parts in (DEFAULT_NUCLEI_RESOURCE, DEFAULT_SIGNATURE_RESOURCE):
            resource = files("arachne.templates")
            for part in resource_parts:
                resource = resource.joinpath(part)
            try:
                names = sorted(
                    entry.name
                    for entry in resource.iterdir()
                    if entry.name.endswith((".yaml", ".yml"))
                )
            except (FileNotFoundError, NotADirectoryError, OSError):  # pragma: no cover
                continue
            for name in names:
                text = resource.joinpath(name).read_text(encoding="utf-8")
                loaded.extend(_parse_file(text, source=f"{'/'.join(resource_parts)}/{name}"))
    for directory in directories or ():
        resolved = Path(directory).expanduser()
        if not resolved.is_dir():
            raise ConfigurationError(f"signature directory {resolved} does not exist")
        for path in sorted(resolved.glob("*.y*ml")):
            loaded.extend(_parse_file(path.read_text(encoding="utf-8"), source=str(path)))
    for signature in loaded:
        if signature.id in seen:
            raise ConfigurationError(f"duplicate signature id {signature.id!r}")
        seen.add(signature.id)
    return tuple(loaded)


def _parse_file(text: str, *, source: str) -> tuple[Signature, ...]:
    try:
        data = yaml.safe_load(text)  # F-08-06: safe_load only
    except yaml.YAMLError as exc:
        raise ConfigurationError(f"{source}: not valid YAML: {exc}") from exc
    if data is None:
        raise ConfigurationError(f"{source}: template file is empty")
    return parse_signatures(data, source=source)


# --------------------------------------------------------------------------- JSONPath


def select_jsonpath(document: Any, expression: str) -> tuple[Any, ...]:
    """Evaluate the JSONPath subset this project supports over parsed JSON.

    Supported: ``$``, ``.key``, ``["key"]``, ``[n]``, ``[*]``, ``..key``. Anything else
    raises :class:`~arachne.core.errors.ConfigurationError` — a template is data, and an
    unsupported selector must fail loudly rather than silently match nothing.
    """
    text = expression.strip()
    if not text.startswith("$"):
        raise ConfigurationError(f"JSONPath {expression!r} must start with '$'")
    nodes: list[Any] = [document]
    index = 1
    while index < len(text):
        char = text[index]
        if text.startswith("..", index):
            index += 2
            match = re.match(r"[A-Za-z_][A-Za-z0-9_-]*", text[index:])
            if match is None:
                raise ConfigurationError(f"JSONPath {expression!r}: expected a key after '..'")
            key = match.group(0)
            index += len(key)
            collected: list[Any] = []
            for node in nodes:
                collected.extend(_descendant_values(node, key))
            nodes = collected
            continue
        if char == ".":
            index += 1
            match = re.match(r"[A-Za-z_][A-Za-z0-9_-]*", text[index:])
            if match is None:
                raise ConfigurationError(f"JSONPath {expression!r}: expected a key after '.'")
            key = match.group(0)
            index += len(key)
            nodes = [node[key] for node in nodes if isinstance(node, Mapping) and key in node]
            continue
        if char == "[":
            end = text.find("]", index)
            if end == -1:
                raise ConfigurationError(f"JSONPath {expression!r}: unbalanced '['")
            selector = text[index + 1 : end].strip()
            index = end + 1
            if selector == "*":
                expanded: list[Any] = []
                for node in nodes:
                    if isinstance(node, Mapping):
                        expanded.extend(node.values())
                    elif isinstance(node, list):
                        expanded.extend(node)
                nodes = expanded
                continue
            if selector.startswith(("'", '"')) and selector.endswith(("'", '"')):
                key = selector[1:-1]
                nodes = [node[key] for node in nodes if isinstance(node, Mapping) and key in node]
                continue
            try:
                position = int(selector)
            except ValueError as exc:
                raise ConfigurationError(
                    f"JSONPath {expression!r}: unsupported selector [{selector}]"
                ) from exc
            nodes = [
                node[position]
                for node in nodes
                if isinstance(node, list) and -len(node) <= position < len(node)
            ]
            continue
        raise ConfigurationError(f"JSONPath {expression!r}: unexpected character {char!r}")
    return tuple(nodes)


def _descendant_values(node: Any, key: str) -> list[Any]:
    found: list[Any] = []
    if isinstance(node, Mapping):
        for item_key, value in node.items():
            if item_key == key:
                found.append(value)
            found.extend(_descendant_values(value, key))
    elif isinstance(node, list):
        for item in node:
            found.extend(_descendant_values(item, key))
    return found


def _path_matches(declared: str, actual: str) -> bool:
    """Compare a template's declared path with a request's path.

    ``{{BaseURL}}`` (and the other host placeholders nuclei defines) are removed first; a
    placeholder that survives — inside the path itself — becomes a ``*`` wildcard.
    """
    pattern = re.sub(r"\{\{\s*(BaseURL|RootURL|Hostname|Host)\s*\}\}", "", declared)
    if not pattern:
        return True  # the template names only the host, so every path qualifies
    if pattern.startswith(("http://", "https://")):
        pattern = urlsplit(pattern).path or "/"
    if "{{" in pattern:
        wildcard = re.sub(r"\{\{[^}]*\}\}", "*", pattern)
        return fnmatch.fnmatchcase(actual, wildcard)
    return pattern == actual


def _scalar_text(value: Any) -> str | None:
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return None
    if isinstance(value, (int, float, str)):
        return str(value)
    return None


def _compile(pattern: str, *, flags: int = 0) -> re.Pattern[str]:
    try:
        return re.compile(pattern, flags)
    except re.error as exc:
        raise ConfigurationError(f"invalid regex {pattern!r} in a template: {exc}") from exc


# --------------------------------------------------------------------------- library


class SignatureLibrary:
    """Matches the loaded templates against a candidate's captured subjects (F-05-02)."""

    def __init__(self, signatures: Iterable[Signature] | None = None) -> None:
        self.signatures: tuple[Signature, ...] = tuple(signatures or ())

    @classmethod
    def load(
        cls, directories: Iterable[str | Path] | None = None, *, include_bundled: bool = True
    ) -> SignatureLibrary:
        return cls(load_signatures(directories, include_bundled=include_bundled))

    def __bool__(self) -> bool:
        return bool(self.signatures)

    def subjects(self, candidate: Candidate) -> tuple[Subject, ...]:
        """Every subject this candidate offers: its HTTP exchanges and its payloads."""
        views: list[Subject] = []
        requests_by_source = {
            (item.source or ""): str(item.payload.get("method") or "GET")
            for item in candidate.evidence
            if item.kind == "http_request"
        }
        for item in candidate.evidence:
            payload = dict(item.payload)
            if item.kind == "http_response":
                status = payload.get("status_code")
                headers = payload.get("headers")
                body = payload.get("body")
                source = item.source or ""
                views.append(
                    Subject(
                        kind=item.kind,
                        http=True,
                        url=source,
                        method=requests_by_source.get(source, "GET"),
                        status=status if isinstance(status, int) else None,
                        headers=dict(headers) if isinstance(headers, Mapping) else {},
                        body=body if isinstance(body, str) else "",
                        payload=payload,
                    )
                )
                continue
            if item.kind == "http_request":
                continue  # the paired response view carries the exchange
            views.append(Subject(kind=item.kind, body=_payload_text(payload), payload=payload))
        return tuple(views)

    def match(self, candidate: Candidate) -> tuple[SignatureMatch, ...]:
        """Every signature that matched, in id order (deterministic)."""
        if not self.signatures:
            return ()
        subjects = self.subjects(candidate)
        matches: list[SignatureMatch] = []
        for signature in sorted(self.signatures, key=lambda item: item.id):
            result = self._match_signature(signature, subjects)
            if result is not None:
                matches.append(result)
        return tuple(matches)

    def _match_signature(
        self, signature: Signature, subjects: Sequence[Subject]
    ) -> SignatureMatch | None:
        for subject in subjects:
            if signature.subject is not None:
                if signature.subject != subject.kind:
                    continue
                scoped = _field_subject(subject, signature.field)
            else:
                if not subject.http:
                    continue
                # A nuclei template declares the path(s) it applies to, so a template for
                # ``/.env`` cannot be satisfied by the site's home page.
                if signature.request_paths and not signature.matches_request(
                    subject.url, subject.method
                ):
                    continue
                scoped = subject
            result = signature.match(scoped)
            if result is None:
                continue
            _, extracted = result
            return SignatureMatch(
                signature_id=signature.id,
                name=signature.name,
                severity=signature.severity,
                tags=signature.tags,
                extracted=extracted,
            )
        return None


def _payload_text(payload: Mapping[str, Any]) -> str:
    """A stable text view of a non-HTTP payload, so ``word``/``regex`` matchers can read it."""
    try:
        return json.dumps(payload, default=str, sort_keys=True, ensure_ascii=False)
    except (TypeError, ValueError):  # pragma: no cover - payloads are JSON by construction
        return ""


def _field_subject(subject: Subject, field_name: str | None) -> Subject:
    """A native subject narrowed to ``field_name`` (``service.identity.banner``, say)."""
    if not field_name:
        return subject
    node: Any = subject.payload
    for part in field_name.split("."):
        if isinstance(node, Mapping) and part in node:
            node = node[part]
        elif isinstance(node, list) and part.isdigit() and int(part) < len(node):
            node = node[int(part)]
        else:
            return dataclasses_replace(subject, body="")
    text = node if isinstance(node, str) else _payload_text({"value": node})
    return dataclasses_replace(subject, body=text)


def dataclasses_replace(subject: Subject, *, body: str) -> Subject:
    """A copy of ``subject`` with a different matching text (kept typed for mypy)."""
    return Subject(
        kind=subject.kind,
        http=subject.http,
        url=subject.url,
        method=subject.method,
        status=subject.status,
        headers=subject.headers,
        body=body,
        payload=subject.payload,
    )


def signature_ids(signatures: Sequence[Signature]) -> tuple[str, ...]:
    """Ids of ``signatures``, sorted — used by tests and the CLI listing."""
    return tuple(sorted(item.id for item in signatures))
