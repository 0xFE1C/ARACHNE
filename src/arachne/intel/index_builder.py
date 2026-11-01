"""Generate the CVE-index baseline from the synced corpus (REQ-INTEL-001).

The shipped ``templates/m2/cve-index.yaml`` is an operator's table: ~15 hand-researched
entries with impact and remediation prose that no feed can supply. That does not scale, and
it is why S18 splits the index into two layers:

``baseline``
    **generated** from the synced NVD corpus (plus EPSS/KEV enrichment) for the products this
    build actually fingerprints. It is data, not judgement: a CVE row exists because the
    upstream record says the CPE range covers a version the scanner can recognise.
``overlay``
    the curated file, unchanged in shape and still hand-maintained. It wins on a repeated
    ``(product, cve)`` pair, which is what lets an operator add the prose and the priority that
    matter without fighting the generator.

The generator is deterministic — sorted output, no timestamps inside the entries, versions and
feed provenance in the header — so regenerating from the same corpus produces the same file
and a diff means the corpus changed.

Every generated entry is validated against M2's own model before it is written (the
:class:`~arachne.modules.m2.catalog.CveEntry` schema), because a baseline the loader refuses is
worse than no baseline at all.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib import resources
from pathlib import Path
from typing import Any

import yaml

from arachne.core.errors import ConfigurationError

__all__ = [
    "PRODUCT_MAP_RESOURCE",
    "BaselineIndex",
    "ProductMap",
    "ProductMapEntry",
    "build_baseline",
    "load_product_map",
    "parse_product_map",
    "range_to_affected",
    "write_baseline",
]

#: The packaged product map: which CPE (vendor, product) pairs this build fingerprints.
PRODUCT_MAP_RESOURCE: tuple[str, ...] = ("m2", "cve-index-products.yaml")

#: How many references a generated entry keeps (a CVE page plus its advisory is plenty).
_MAX_REFERENCES = 5


@dataclass(frozen=True, slots=True)
class ProductMapEntry:
    """One ``(vendor, cpe product) → ARACHNE product`` mapping."""

    product: str
    vendor: str
    cpe_product: str
    aliases: tuple[str, ...] = ()

    def matches(self, vendor: str, product: str) -> bool:
        if product != self.cpe_product:
            return False
        return self.vendor == "*" or vendor == self.vendor


@dataclass(frozen=True, slots=True)
class ProductMap:
    """The managed product map (``templates/m2/cve-index-products.yaml``)."""

    version: str = "0"
    entries: tuple[ProductMapEntry, ...] = ()
    description: str = ""

    def match(self, vendor: str, product: str) -> ProductMapEntry | None:
        for entry in self.entries:
            if entry.matches(vendor, product):
                return entry
        return None


@dataclass(frozen=True, slots=True)
class BaselineIndex:
    """A generated baseline, ready to be written as YAML."""

    index_version: str
    generated_at: str
    source: str
    entries: tuple[dict[str, Any], ...] = ()

    @property
    def count(self) -> int:
        return len(self.entries)

    def to_document(self) -> dict[str, Any]:
        return {
            "index_version": self.index_version,
            "generated_at": self.generated_at,
            "source": self.source,
            "entries": [dict(entry) for entry in self.entries],
        }

    def to_yaml(self) -> str:
        header = (
            "# ARACHNE generated CVE-index baseline (S18, REQ-INTEL-001).\n"
            "#\n"
            "# GENERATED FILE — do not edit. `arachne intel build-index` regenerates it from the\n"
            "# synced NVD corpus for the products in templates/m2/cve-index-products.yaml.\n"
            "# The hand-maintained overlay (templates/m2/cve-index.yaml) is merged on top of this\n"
            "# baseline at load time and wins on a repeated (product, cve) pair.\n"
        )
        return header + yaml.safe_dump(self.to_document(), sort_keys=False, allow_unicode=True)


def load_product_map(path: str | Path | None = None) -> ProductMap:
    """Load the product map from ``path`` or the packaged copy."""
    if path is None:
        node = resources.files("arachne.templates")
        for part in PRODUCT_MAP_RESOURCE:
            node = node.joinpath(part)
        try:
            text = node.read_text(encoding="utf-8")
        except (FileNotFoundError, OSError) as exc:  # pragma: no cover - packaging failure
            msg = f"bundled product map is missing: {exc}"
            raise ConfigurationError(msg) from exc
    else:
        resolved = Path(path).expanduser()
        if not resolved.is_file():
            msg = f"product map {resolved} does not exist"
            raise ConfigurationError(msg)
        text = resolved.read_text(encoding="utf-8")
    return parse_product_map(text)


def parse_product_map(text: str) -> ProductMap:
    """Parse a product-map document."""
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        msg = f"product map: not valid YAML: {exc}"
        raise ConfigurationError(msg) from exc
    if not isinstance(data, Mapping):
        msg = "product map: expected a mapping with 'entries'"
        raise ConfigurationError(msg)
    rows = data.get("entries")
    if not isinstance(rows, list) or not rows:
        msg = "product map: 'entries' must be a non-empty list"
        raise ConfigurationError(msg)
    entries: list[ProductMapEntry] = []
    for row in rows:
        if not isinstance(row, Mapping):
            continue
        product = str(row.get("product") or "").strip()
        vendor = str(row.get("vendor") or "").strip().lower()
        cpe_product = str(row.get("cpe_product") or product).strip().lower()
        if not product or not cpe_product:
            continue
        aliases = tuple(str(item) for item in row.get("aliases") or () if str(item).strip())
        entries.append(
            ProductMapEntry(
                product=product, vendor=vendor or "*", cpe_product=cpe_product, aliases=aliases
            )
        )
    if not entries:
        msg = "product map: no usable entries"
        raise ConfigurationError(msg)
    return ProductMap(
        version=str(data.get("product_map_version") or "0"),
        entries=tuple(entries),
        description=str(data.get("description") or ""),
    )


def range_to_affected(item: Mapping[str, Any]) -> tuple[dict[str, str], ...]:
    """Turn one NVD CPE version range into an ``affected`` clause (``[{op, version}]``).

    NVD expresses a range as inclusive/exclusive bounds; M2's index expresses the same thing as
    operator/version pairs. A range with no bounds means "every version" (``[all]``), which is
    how the loader reads an empty or ``all`` clause too.
    """
    constraints: list[dict[str, str]] = []
    start_including = _text(item.get("version_start_including"))
    start_excluding = _text(item.get("version_start_excluding"))
    end_including = _text(item.get("version_end_including"))
    end_excluding = _text(item.get("version_end_excluding"))
    if start_including:
        constraints.append({"op": ">=", "version": start_including})
    if start_excluding:
        constraints.append({"op": ">", "version": start_excluding})
    if end_excluding:
        constraints.append({"op": "<", "version": end_excluding})
    if end_including:
        constraints.append({"op": "<=", "version": end_including})
    if not constraints:
        return ({"op": "all", "version": ""},)
    return tuple(constraints)


def build_baseline(
    records: Iterable[Mapping[str, Any]],
    *,
    products: ProductMap,
    epss: Mapping[str, float] | None = None,
    kev: Iterable[str] | None = None,
    source: str = "nvd",
    max_entries: int = 500,
    min_cvss: float = 0.0,
    now: datetime | None = None,
) -> BaselineIndex:
    """Generate the baseline from normalised NVD records.

    ``records`` are the rows the sync stored (``{"cve": ..., "cpe_ranges": [...]}``), so the
    function is pure and works identically from the store, from an artefact file, or from a
    fixture. ``epss`` and ``kev`` enrich an entry with the current exploitation signals; both
    are optional, because a baseline is still useful without them.
    """
    epss_scores = dict(epss or {})
    kev_cves = {str(item).upper() for item in (kev or ())}
    seen: dict[tuple[str, str, str], dict[str, Any]] = {}
    for record in records:
        cve = str(record.get("cve") or "").strip().upper()
        if not cve:
            continue
        cvss = _number(record.get("cvss"))
        if cvss is not None and cvss < min_cvss:
            continue
        for raw_range in record.get("cpe_ranges") or ():
            if not isinstance(raw_range, Mapping):
                continue
            vendor = _text(raw_range.get("vendor")) or ""
            cpe_product = _text(raw_range.get("product")) or ""
            mapped = products.match(vendor, cpe_product)
            if mapped is None:
                continue
            affected = range_to_affected(raw_range)
            signature = ";".join(f"{item['op']}{item['version']}" for item in affected)
            key = (mapped.product, cve, signature)
            if key in seen:
                continue
            entry: dict[str, Any] = {
                "product": mapped.product,
                "vendor": vendor or None,
                "affected": [dict(item) for item in affected],
                "cve": cve,
                "title": _title(record, cve, mapped.product),
            }
            if mapped.aliases:
                entry["aliases"] = list(mapped.aliases)
            if cvss is not None:
                entry["cvss"] = cvss
            score = epss_scores.get(cve)
            if score is not None:
                entry["epss"] = round(float(score), 4)
            if cve in kev_cves:
                entry["kev"] = True
            if _text(record.get("cwe")):
                entry["cwe"] = _text(record.get("cwe"))
            references = [
                str(item)
                for item in (record.get("references") or ())
                if str(item).startswith(("http://", "https://"))
            ][:_MAX_REFERENCES]
            if references:
                entry["references"] = references
            seen[key] = entry
    ordered = sorted(seen.values(), key=lambda item: (str(item["product"]), str(item["cve"])))
    moment = (now or datetime.now(UTC)).astimezone(UTC)
    return BaselineIndex(
        index_version=f"nvd-{moment.strftime('%Y.%m.%d')}"[:32],
        generated_at=moment.isoformat(),
        source=source,
        entries=tuple(ordered[:max(1, max_entries)]),
    )


def write_baseline(index: BaselineIndex, path: str | Path) -> Path:
    """Write ``index`` to ``path`` (creating parents); returns the resolved path."""
    resolved = Path(path).expanduser()
    resolved.parent.mkdir(parents=True, exist_ok=True)
    resolved.write_text(index.to_yaml(), encoding="utf-8")
    return resolved.resolve()


def _title(record: Mapping[str, Any], cve: str, product: str) -> str:
    candidate = _text(record.get("title")) or f"{cve} affects {product}"
    return candidate[:512]


def _text(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _number(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None
