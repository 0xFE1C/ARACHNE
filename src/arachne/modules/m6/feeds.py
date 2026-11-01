"""M6 managed-data feeds: EPSS/KEV, the LPE index and the Sigma rule set.

Three loaders the M6 checks share, each with the same offline-first contract (F-09-03):

``load_epss``
    The EPSS/KEV snapshot (``templates/m6/epss-snapshot.yaml``) plus, when the deployment
    configured them, a FIRST EPSS CSV (``ARACHNE_M6_EPSS_FEED``) and a CISA KEV JSON
    (``ARACHNE_M6_KEV_FEED``). An operator refresh is a data update, never a code change.
``load_lpe_index``
    The local-privilege-escalation index. It reuses the M2 ``CveIndex`` model verbatim, so the
    two snapshots read the same way and the version-matching logic is shared.
``load_sigma_rules`` / ``match_event``
    The shipped Sigma rules and a bounded evaluator for the subset they are written in. The
    point is that ARACHNE *ships* detection logic an operator can drop into a SIEM (ch06#23);
    the local ingest path is a convenience, not a SIEM replacement.
"""

from __future__ import annotations

import csv
import io
import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from importlib.resources import files
from pathlib import Path
from typing import Any, Final

import yaml

from arachne.core.errors import ConfigurationError
from arachne.modules.m2.catalog import CveIndex

__all__ = [
    "EpssEntry",
    "EpssSnapshot",
    "SigmaRule",
    "load_epss",
    "load_lpe_index",
    "load_sigma_rules",
    "match_event",
]

#: Bundled snapshot resources, relative to ``templates/``.
_EPSS_RESOURCE: Final = ("m6", "epss-snapshot.yaml")
_LPE_RESOURCE: Final = ("m6", "lpe-index.yaml")


# --------------------------------------------------------------------------- EPSS / KEV
@dataclass(frozen=True, slots=True)
class EpssEntry:
    """One CVE's exploit-likelihood signals (research ch06#7)."""

    cve: str
    epss: float | None = None
    percentile: float | None = None
    kev: bool = False
    cvss: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "cve": self.cve,
            "epss": self.epss,
            "percentile": self.percentile,
            "kev": self.kev,
            "cvss": self.cvss,
        }


@dataclass(frozen=True, slots=True)
class EpssSnapshot:
    """The EPSS/KEV table, keyed by CVE."""

    version: str = ""
    generated_at: str = ""
    entries: Mapping[str, EpssEntry] = field(default_factory=dict)

    def get(self, cve: str) -> EpssEntry | None:
        return self.entries.get(cve.upper())

    def rank(self, cve: str) -> float:
        """``epss`` (0..1) for ranking, or 0 when the CVE is unknown."""
        entry = self.get(cve)
        return float(entry.epss) if entry and entry.epss is not None else 0.0


def _read_text(path: str | Path | None, resource: tuple[str, ...]) -> tuple[str, str]:
    if path is None:
        node = files("arachne.templates")
        for part in resource:
            node = node.joinpath(part)
        try:
            return node.read_text(encoding="utf-8"), f"bundled {resource[-1]}"
        except (FileNotFoundError, OSError) as exc:  # pragma: no cover - packaging failure
            msg = f"bundled data file is missing ({'/'.join(resource)}): {exc}"
            raise ConfigurationError(msg) from exc
    resolved = Path(path).expanduser()
    if not resolved.is_file():
        msg = f"data file {resolved} does not exist or is not a file"
        raise ConfigurationError(msg)
    try:
        return resolved.read_text(encoding="utf-8"), str(resolved)
    except OSError as exc:
        msg = f"cannot read data file {resolved}: {exc}"
        raise ConfigurationError(msg) from exc


def _parse_epss_snapshot(data: Any, *, source: str) -> EpssSnapshot:
    if not isinstance(data, Mapping):
        msg = f"{source}: expected a mapping at the top level"
        raise ConfigurationError(msg)
    entries: dict[str, EpssEntry] = {}
    for raw in data.get("entries") or ():
        if not isinstance(raw, Mapping) or not raw.get("cve"):
            continue
        cve = str(raw["cve"]).upper()
        entries[cve] = EpssEntry(
            cve=cve,
            epss=_opt_float(raw.get("epss")),
            percentile=_opt_float(raw.get("percentile")),
            kev=bool(raw.get("kev", False)),
            cvss=_opt_float(raw.get("cvss")),
        )
    return EpssSnapshot(
        version=str(data.get("version", "")),
        generated_at=str(data.get("generated_at", "")),
        entries=entries,
    )


def _parse_epss_csv(text: str, *, source: str) -> dict[str, EpssEntry]:
    """A FIRST EPSS CSV: ``cve,epss,percentile`` (extra columns are ignored)."""
    out: dict[str, EpssEntry] = {}
    reader = csv.DictReader(io.StringIO(text))
    if reader.fieldnames is None:
        return out
    lowered = {name.lower().strip(): name for name in reader.fieldnames}
    cve_col = lowered.get("cve")
    epss_col = lowered.get("epss")
    pct_col = lowered.get("percentile")
    if cve_col is None or epss_col is None:
        msg = f"{source}: an EPSS CSV needs 'cve' and 'epss' columns"
        raise ConfigurationError(msg)
    for row in reader:
        cve = (row.get(cve_col) or "").strip().upper()
        if not cve:
            continue
        out[cve] = EpssEntry(
            cve=cve,
            epss=_opt_float(row.get(epss_col)),
            percentile=_opt_float(row.get(pct_col)) if pct_col else None,
        )
    return out


def _parse_kev_json(text: str, *, source: str) -> set[str]:
    """A CISA KEV JSON: ``{"vulnerabilities": [{"cveID": "CVE-..."}, ...]}``."""
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        msg = f"{source}: not valid JSON: {exc}"
        raise ConfigurationError(msg) from exc
    out: set[str] = set()
    if isinstance(data, Mapping):
        rows = data.get("vulnerabilities") or ()
    elif isinstance(data, list):
        rows = data
    else:
        rows = ()
    for row in rows:
        if isinstance(row, Mapping):
            cve = row.get("cveID") or row.get("cve")
            if cve:
                out.add(str(cve).upper())
        elif isinstance(row, str):
            out.add(row.upper())
    return out


def _opt_float(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def load_epss(
    feed_path: str | Path | None = None,
    *,
    kev_path: str | Path | None = None,
) -> EpssSnapshot:
    """The EPSS/KEV table: the bundled snapshot, overlaid by an operator feed when configured."""
    text, source = _read_text(None, _EPSS_RESOURCE)
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:  # pragma: no cover - the bundled file is valid
        msg = f"{source}: not valid YAML: {exc}"
        raise ConfigurationError(msg) from exc
    snapshot = _parse_epss_snapshot(data, source=source)

    entries: dict[str, EpssEntry] = dict(snapshot.entries)
    version = snapshot.version
    if feed_path is not None:
        feed_text, feed_source = _read_text(feed_path, _EPSS_RESOURCE)
        if str(feed_path).lower().endswith(".csv"):
            entries.update(_parse_epss_csv(feed_text, source=feed_source))
        else:
            overlaid = _parse_epss_snapshot(
                _safe_yaml(feed_text, source=feed_source), source=feed_source
            )
            entries.update(overlaid.entries)
        version = f"{version}+{Path(feed_path).name}"
    if kev_path is not None:
        kev_text, kev_source = _read_text(kev_path, _EPSS_RESOURCE)
        for cve in _parse_kev_json(kev_text, source=kev_source):
            existing = entries.get(cve)
            entries[cve] = EpssEntry(
                cve=cve,
                epss=existing.epss if existing else None,
                percentile=existing.percentile if existing else None,
                kev=True,
                cvss=existing.cvss if existing else None,
            )
    return EpssSnapshot(version=version, generated_at=snapshot.generated_at, entries=entries)


def _safe_yaml(text: str, *, source: str) -> Any:
    try:
        return yaml.safe_load(text)
    except yaml.YAMLError as exc:
        msg = f"{source}: not valid YAML: {exc}"
        raise ConfigurationError(msg) from exc


# --------------------------------------------------------------------------- LPE index
def load_lpe_index(path: str | Path | None = None) -> CveIndex:
    """The local-privilege-escalation index (an M2 ``CveIndex`` document)."""
    text, source = _read_text(path, _LPE_RESOURCE)
    data = _safe_yaml(text, source=source)
    if not isinstance(data, Mapping):
        msg = f"{source}: expected a mapping at the top level"
        raise ConfigurationError(msg)
    try:
        return CveIndex.model_validate(data)
    except Exception as exc:  # pydantic ValidationError
        raise ConfigurationError(f"{source}: invalid LPE index: {exc}") from exc


# --------------------------------------------------------------------------- Sigma
_MODIFIER_RE = re.compile(r"^(?P<field>[^|]+)(?P<mods>(?:\|[a-zA-Z_]+)*)$")


@dataclass(frozen=True, slots=True)
class SigmaRule:
    """One Sigma rule, reduced to what the bounded local evaluator needs (ch06#23)."""

    title: str
    id: str
    level: str
    description: str = ""
    logsource: Mapping[str, Any] = field(default_factory=dict)
    selections: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)
    condition: str = "selection"
    tags: tuple[str, ...] = ()
    source: str = ""
    raw: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "id": self.id,
            "level": self.level,
            "description": self.description,
            "logsource": dict(self.logsource),
            "tags": list(self.tags),
            "condition": self.condition,
        }


def _split_modifiers(key: str) -> tuple[str, tuple[str, ...]]:
    parts = key.split("|")
    field = parts[0].strip()
    return field, tuple(part.strip().lower() for part in parts[1:] if part.strip())


def _parse_rule(data: Any, *, source: str) -> SigmaRule:
    if not isinstance(data, Mapping):
        msg = f"{source}: a Sigma rule must be a mapping"
        raise ConfigurationError(msg)
    detection = data.get("detection") or {}
    if not isinstance(detection, Mapping):
        msg = f"{source}: sigma 'detection' must be a mapping"
        raise ConfigurationError(msg)
    condition = str(detection.get("condition", "selection"))
    selections: dict[str, Mapping[str, Any]] = {}
    for name, value in detection.items():
        if name == "condition" or not isinstance(value, Mapping):
            continue
        selections[str(name)] = value
    logsource = data.get("logsource") or {}
    return SigmaRule(
        title=str(data.get("title", source)),
        id=str(data.get("id", source)),
        level=str(data.get("level", "medium")),
        description=str(data.get("description", "")).strip(),
        logsource=dict(logsource) if isinstance(logsource, Mapping) else {},
        selections=selections,
        condition=condition,
        tags=tuple(str(item) for item in data.get("tags") or ()),
        source=source,
        raw=dict(data),
    )


def load_sigma_rules(directory: str | Path | None = None) -> tuple[SigmaRule, ...]:
    """Load every ``*.yml``/``*.yaml`` Sigma rule from ``directory`` (or the bundled set)."""
    if directory is None:
        node = files("arachne.templates").joinpath("m6", "sigma")
        paths = sorted(
            (node.joinpath(name) for name in _resource_names(node)),
            key=str,
        )
        texts = [(path.read_text(encoding="utf-8"), path.name) for path in paths]
    else:
        resolved = Path(directory).expanduser()
        if resolved.is_file():
            texts = [(resolved.read_text(encoding="utf-8"), str(resolved))]
        elif resolved.is_dir():
            texts = [
                (item.read_text(encoding="utf-8"), str(item))
                for item in sorted(resolved.glob("*.y*ml"))
                if item.is_file()
            ]
        else:
            msg = f"Sigma rule directory {resolved} does not exist"
            raise ConfigurationError(msg)
    rules: list[SigmaRule] = []
    for text, source in texts:
        rules.append(_parse_rule(_safe_yaml(text, source=source), source=source))
    return tuple(rules)


def _resource_names(node: Any) -> list[str]:
    try:
        return [item.name for item in node.iterdir() if str(item.name).endswith((".yml", ".yaml"))]
    except (FileNotFoundError, OSError):  # pragma: no cover - packaging failure
        return []


def _field_value(event: Mapping[str, Any], field_name: str) -> Any:
    if field_name in event:
        return event[field_name]
    lowered = field_name.lower()
    for key, value in event.items():
        if str(key).lower() == lowered:
            return value
    return None


def _match_value(actual: Any, expected: Any, mods: tuple[str, ...]) -> bool:
    if actual is None:
        return False
    text_actual = actual if isinstance(actual, str) else str(actual)
    text_expected = expected if isinstance(expected, str) else str(expected)
    if "re" in mods:
        try:
            return re.search(text_expected, text_actual, re.IGNORECASE) is not None
        except re.error:  # pragma: no cover - a bad rule regex is a corpus bug
            return False
    if "contains" in mods:
        return text_expected.lower() in text_actual.lower()
    if "startswith" in mods:
        return text_actual.lower().startswith(text_expected.lower())
    if "endswith" in mods:
        return text_actual.lower().endswith(text_expected.lower())
    # Exact comparison, case-insensitive for strings, numeric otherwise.
    if isinstance(actual, (int, float)) and not isinstance(actual, bool):
        try:
            return float(actual) == float(text_expected)
        except ValueError:
            return False
    return text_actual.lower() == text_expected.lower()


def _match_selection(selection: Mapping[str, Any], event: Mapping[str, Any]) -> bool:
    for raw_key, expected in selection.items():
        field_name, mods = _split_modifiers(str(raw_key))
        actual = _field_value(event, field_name)
        values = expected if isinstance(expected, (list, tuple)) else [expected]
        want_all = "all" in mods
        results = [_match_value(actual, item, mods) for item in values]
        if want_all:
            if not results or not all(results):
                return False
        elif not any(results):
            return False
    return True


def _eval_condition(condition: str, results: Mapping[str, bool]) -> bool:
    """A bounded evaluator for the Sigma condition subset the shipped rules use.

    Supports: a bare selection name, ``and``/``or``/``not`` between names, ``all of them``
    and ``any of them``. Anything else raises, so a rule the evaluator cannot honour is a
    loud configuration error rather than a silent miss.
    """
    text = condition.strip().lower()
    if not text:
        return False
    if text == "all of them":
        return all(results.values()) if results else False
    if text in {"any of them", "1 of them"}:
        return any(results.values())
    for part in re.split(r"\bor\b", text):
        terms = part.split(" and ")
        if all(_eval_term(term.strip(), results) for term in terms):
            return True
    return False


def _eval_term(term: str, results: Mapping[str, bool]) -> bool:
    negate = False
    if term.startswith("not "):
        negate = True
        term = term[4:].strip()
    if term not in results:
        msg = f"sigma condition names an unknown selection: {term!r}"
        raise ConfigurationError(msg)
    value = bool(results[term])
    return not value if negate else value


def match_event(rule: SigmaRule, event: Mapping[str, Any]) -> bool:
    """True when ``event`` (one log record) matches ``rule`` (bounded Sigma subset)."""
    results = {
        name: _match_selection(selection, event) for name, selection in rule.selections.items()
    }
    try:
        return _eval_condition(rule.condition, results)
    except ConfigurationError:
        # A rule whose condition the evaluator does not support must not abort a whole scan;
        # the loader already validated the shape, and the rule is reported as unusable.
        return False


def iter_json_events(text: str) -> Iterable[Mapping[str, Any]]:
    """Yield the JSON object per (non-blank) line of a JSON-lines log; skip non-objects."""
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if not stripped.startswith("{"):
            continue
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError:
            continue
        if isinstance(parsed, Mapping):
            yield parsed
