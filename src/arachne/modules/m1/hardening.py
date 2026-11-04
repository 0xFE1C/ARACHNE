"""M1 hardening checks: mail auth, favicon fingerprints, buckets and document metadata (ch01).

Four checks that read a target's *own* hardening signals rather than enumerate new hosts:

* :class:`DnsTxtMining` — the domain's SPF/DKIM/DMARC TXT records (research ch01 method 25),
  read through the existing ``dns`` OSINT provider (DNS-over-HTTPS), never the target itself.
* :class:`FaviconHash` — the SHA-256/MurmurHash3 fingerprint of ``/favicon.ico``, matched
  against a data table of known default icons (method 23).
* :class:`BucketHunt` — a bounded set of derived cloud-storage names probed for anonymous
  listings (method 30).
* :class:`DocMetadata` — the ``/Info`` and EXIF metadata a published PDF or image carries
  (method 22).

The mail check is passive (a third-party resolver answers about the domain); the other three
are *hybrid*: they read the target's own public content over the target-scoped HTTP client
(``ctx.http``), and every request is bounded and rate limited by that client. They emit
candidates rather than pronouncements — analysis assigns severity (ADR-02).
"""

from __future__ import annotations

import hashlib
import importlib
import re
import struct
from collections.abc import AsyncIterator, Sequence
from typing import TYPE_CHECKING
from urllib.parse import urljoin, urlsplit

from arachne.core.errors import OsintError, RequestError, SafetyError
from arachne.core.results import CheckResult
from arachne.core.safety import normalize_host
from arachne.core.target import TargetKind
from arachne.modules.base import Asset, CheckMetadata, Module
from arachne.modules.context import CheckContext, require_osint
from arachne.modules.extract import internal_hostname_hints
from arachne.modules.providers.sources import dns_txt_url, parse_doh_txt

if TYPE_CHECKING:  # a type-only import: the providers package is built lazily per scan
    from arachne.modules.providers import OsintAccess

__all__ = [
    "KNOWN_DEFAULT_FAVICONS",
    "BucketHunt",
    "DnsTxtMining",
    "DocMetadata",
    "FaviconHash",
]

_DOMAIN_KINDS = (TargetKind.DOMAIN, TargetKind.DOMAIN_PATTERN)

# --------------------------------------------------------------------------- mail auth (25)
#: The DKIM selectors a check tries when a deployment names none of its own. Four common
#: ones keep the request count at a fixed six (apex, ``_dmarc`` and four selectors).
_DKIM_SELECTORS: tuple[str, ...] = ("default", "google", "selector1", "k1")
_SPF_ALL_RE = re.compile(r"(?P<qualifier>[+~?-])all\b", re.IGNORECASE)
_DMARC_POLICY_RE = re.compile(r"\bp\s*=\s*(?P<policy>none|quarantine|reject)\b", re.IGNORECASE)


class DnsTxtMining(Module):
    """``m1.dns-txt-mining`` — SPF/DKIM/DMARC records (research ch01#25)."""

    metadata = CheckMetadata(
        id="m1.dns-txt-mining",
        module="M1",
        name="dns-txt-mining",
        version="1.0",
        title="Mail-authentication TXT mining",
        description=(
            "Reads the domain's SPF, DKIM and DMARC TXT records through a DNS-over-HTTPS "
            "resolver and flags missing or unenforced mail authentication."
        ),
        research_ref="ch01#25",
        framework=("WSTG-INFO-10", "CWE-200"),
        compliance=("CIS-9.5",),
        cwe="CWE-200",
        target_kinds=_DOMAIN_KINDS,
        severity_hint="low",
        type="passive",
        safe=True,
        verifiable=True,
        estimated_requests=6,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        name = ctx.asset.query_name
        if not name:
            yield ctx.skipped(f"asset {ctx.asset.key} has no queryable name")
            return
        osint, skip = require_osint(ctx, "dns")
        if skip is not None:
            yield skip
            return
        assert osint is not None

        spf = _first_record(await _dns_txt(osint, name), "v=spf1")
        dmarc = _first_record(await _dns_txt(osint, f"_dmarc.{name}"), "v=dmarc1")
        selectors: list[str] = []
        for selector in _DKIM_SELECTORS:
            if await _dns_txt(osint, f"{selector}._domainkey.{name}"):
                selectors.append(selector)
        queries = 2 + len(_DKIM_SELECTORS)

        spf_qualifier = _spf_all_qualifier(spf)
        dmarc_policy = _dmarc_policy(dmarc)
        issues: list[str] = []
        if spf is None:
            issues.append("no-spf")
        elif spf_qualifier == "+all":
            issues.append("spf-all-pass")
        if dmarc is None:
            issues.append("no-dmarc")
        elif dmarc_policy in (None, "none"):
            issues.append("dmarc-not-enforced")

        artifact = ctx.evidence(
            "artifact",
            {
                "domain": name,
                "spf_present": spf is not None,
                "spf_qualifier": spf_qualifier,
                "dmarc_present": dmarc is not None,
                "dmarc_policy": dmarc_policy,
                "dkim_selectors": selectors,
                "queries": queries,
                "issues": issues,
            },
            source=name,
        )
        discovered = [
            label
            for label, present in (
                ("SPF", spf is not None),
                ("DMARC", dmarc is not None),
                ("DKIM", bool(selectors)),
            )
            if present
        ]
        yield ctx.info(
            f"mail-authentication DNS records for {name}: "
            f"{', '.join(discovered) if discovered else 'none'}",
            detail=(
                f"{queries} TXT query/queries; SPF "
                f"{'present' if spf else 'absent'}"
                + (f" ({spf_qualifier})" if spf_qualifier else "")
                + f"; DMARC {'present' if dmarc else 'absent'}"
                + (f" (p={dmarc_policy})" if dmarc_policy else "")
                + f"; DKIM selectors answered: {', '.join(selectors) or 'none'}"
            ),
            evidence=[artifact],
            confidence=0.7,
        )
        if issues:
            spf_summary = "SPF absent" if spf is None else f"SPF {spf_qualifier or 'present'}"
            dmarc_summary = (
                "DMARC absent" if dmarc is None else f"DMARC p={dmarc_policy or 'malformed'}"
            )
            yield ctx.candidate(
                f"weak mail authentication for {name} ({', '.join(issues)})",
                detail=(
                    f"{name}: {spf_summary}, {dmarc_summary}; a permissive policy lets anyone "
                    "spoof mail from this domain (research ch01 §25, CWE-290 in M4's active "
                    "review)."
                ),
                evidence=[artifact],
                confidence=0.35,
            )


async def _dns_txt(access: OsintAccess, name: str) -> tuple[str, ...]:
    """One DoH TXT query; a provider error or a non-200 answer reads as "no record"."""
    try:
        response = await access.fetch("dns", dns_txt_url(name))
    except OsintError:
        return ()
    if not response.ok:
        return ()
    return parse_doh_txt(response.json())


def _first_record(records: Sequence[str], marker: str) -> str | None:
    """The first record beginning with ``marker`` (the version tag), else the first record."""
    lowered = marker.lower()
    for record in records:
        if record.lower().startswith(lowered):
            return record
    return records[0] if records else None


def _spf_all_qualifier(record: str | None) -> str | None:
    if not record:
        return None
    match = _SPF_ALL_RE.search(record)
    return None if match is None else f"{match.group('qualifier').lower()}all"


def _dmarc_policy(record: str | None) -> str | None:
    if not record:
        return None
    match = _DMARC_POLICY_RE.search(record)
    return None if match is None else match.group("policy").lower()


# --------------------------------------------------------------------------- favicon (23)
#: Known default/vendor favicon SHA-256 fingerprints. Small and deliberately data: an
#: operator extends it without touching the check. The entry below is the fingerprint of the
#: documented ``VENDOR-DEFAULT-FAVICON`` placeholder the recorded fixture serves.
KNOWN_DEFAULT_FAVICONS: dict[str, str] = {
    "216889cbb2e300a20cecfbae4e0f900ef6dc5ee3d901c8a37d85530ce3a3f099": "vendor-default",
}


class FaviconHash(Module):
    """``m1.favicon-hash`` — favicon fingerprint (research ch01#23)."""

    metadata = CheckMetadata(
        id="m1.favicon-hash",
        module="M1",
        name="favicon-hash",
        version="1.0",
        title="Favicon fingerprint",
        description=(
            "Fetches /favicon.ico, computes its SHA-256 (and MurmurHash3-32 when mmh3 is "
            "importable) and matches it against a table of known default/vendor favicons."
        ),
        research_ref="ch01#23",
        framework=("WSTG-INFO-08", "CWE-200"),
        cwe="CWE-200",
        target_kinds=(*_DOMAIN_KINDS, TargetKind.URL),
        severity_hint="low",
        type="hybrid",
        safe=True,
        verifiable=True,
        estimated_requests=1,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        if ctx.http is None:
            yield ctx.skipped("no HTTP client is available in this mode (dry run)")
            return
        origin = _origin_of(ctx.asset)
        if origin is None:
            yield ctx.skipped(f"asset {ctx.asset.key} has no web origin to fetch a favicon from")
            return
        url = urljoin(f"{origin}/", "favicon.ico")
        try:
            response = await ctx.http.get(url)
        except (SafetyError, RequestError) as exc:
            yield ctx.error(exc)
            return
        if response.status_code != 200 or not response.body:
            yield ctx.clean(
                f"no favicon served at {url}",
                detail=f"the origin answered HTTP {response.status_code}",
                confidence=0.5,
            )
            return
        if response.body_is_binary:
            # The capture pipeline replaces a binary body with a byte-count placeholder before
            # a check sees it (F-08-04), so the icon's own bytes are not available to hash.
            yield ctx.skipped(
                "the favicon is a binary body the capture pipeline does not retain, "
                "so it cannot be fingerprinted"
            )
            return

        data = response.body.encode("latin-1", "replace")
        digest = hashlib.sha256(data).hexdigest()
        murmur = _murmur3_32(data)
        vendor = KNOWN_DEFAULT_FAVICONS.get(digest)
        artifact = ctx.evidence(
            "artifact",
            {
                "url": url,
                "sha256": digest,
                "mmh3_32": murmur,
                "bytes": len(data),
                "vendor": vendor,
            },
            source=url,
        )
        yield ctx.info(
            f"favicon fingerprint for {origin}: sha256 {digest[:16]}...",
            detail=(
                f"{len(data)} byte(s)"
                + (f"; mmh3={murmur}" if murmur is not None else "")
                + (
                    f"; matches the {vendor} default icon — a reconnaissance lead, confirmed by M2"
                    if vendor
                    else ""
                )
            ),
            evidence=[artifact],
            confidence=0.6,
        )


def _origin_of(asset: Asset) -> str | None:
    """The web origin to fetch a favicon from: a URL's scheme://host, else https://name."""
    if asset.kind == "url":
        parts = urlsplit(asset.value)
        if parts.scheme and parts.netloc:
            return f"{parts.scheme}://{parts.netloc}"
        return None
    host = asset.query_name
    return f"https://{host}" if host else None


def _murmur3_32(data: bytes) -> int | None:
    """MurmurHash3-32 of ``data`` when the optional ``mmh3`` package is installed, else None."""
    try:
        module = importlib.import_module("mmh3")
    except ImportError:
        return None
    hasher = getattr(module, "hash", None)
    if hasher is None:  # pragma: no cover - a wrong package named mmh3
        return None
    try:
        return int(hasher(data, signed=False))
    except Exception:  # an optional plugin must never fail the check
        return None


# --------------------------------------------------------------------------- buckets (30)
#: Common name affixes tried after the domain label (S3/GCS/Azure name conventions).
_BUCKET_AFFIXES: tuple[str, ...] = (
    "-backup",
    "-dev",
    "-assets",
    "-media",
    "-static",
    "-data",
    "-public",
)
#: Hard bounds: at most this many derived names, and this many probes in total (three
#: providers each). The check's request estimate is a fraction of this worst case.
_MAX_BUCKET_NAMES = 6
_MAX_BUCKET_PROBES = 16
#: ``(provider, url template)`` — every pattern is HTTPS-only, as the whole check is.
_BUCKET_PROVIDERS: tuple[tuple[str, str], ...] = (
    ("s3", "https://{bucket}.s3.amazonaws.com/"),
    ("gcs", "https://storage.googleapis.com/{bucket}/"),
    ("azure", "https://{bucket}.blob.core.windows.net/?comp=list"),
)


class BucketHunt(Module):
    """``m1.bucket-hunt`` — public cloud-storage listings (research ch01#30)."""

    metadata = CheckMetadata(
        id="m1.bucket-hunt",
        module="M1",
        name="bucket-hunt",
        version="1.0",
        title="Cloud storage bucket hunt",
        description=(
            "Derives candidate bucket names from the domain and probes a bounded set of "
            "S3/GCS/Azure HTTPS endpoints for anonymous bucket listings. Active and opt-in: "
            "because it queries third-party provider hosts it needs --active-checks and an "
            "authorizing attestation, exactly like the cloud module's bucket enumerator "
            "(research ch01#30)."
        ),
        research_ref="ch01#30",
        framework=("WSTG-CONF-11", "CWE-284"),
        compliance=("ISO-A.8.12",),
        cwe="CWE-284",
        target_kinds=_DOMAIN_KINDS,
        severity_hint="medium",
        type="active",
        safe=True,
        verifiable=True,
        enabled_by_default=False,
        estimated_requests=8,
        requires_active_checks=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        if ctx.http is None:
            yield ctx.skipped("no HTTP client is available in this mode (dry run)")
            return
        name = ctx.asset.query_name
        if not name:
            yield ctx.skipped(f"asset {ctx.asset.key} has no queryable name")
            return

        names = _bucket_names(name)
        probes = 0
        findings: list[tuple[str, str, str]] = []
        failures: list[str] = []
        for bucket in names:
            for provider, template in _BUCKET_PROVIDERS:
                if probes >= _MAX_BUCKET_PROBES:
                    break
                url = template.format(bucket=bucket)
                probes += 1
                try:
                    response = await ctx.http.get(url)
                except (SafetyError, RequestError) as exc:
                    failures.append(f"{bucket}/{provider}: {exc.__class__.__name__}")
                    continue
                if _is_listing(provider, response.status_code, response.body):
                    findings.append((bucket, provider, url))
            if probes >= _MAX_BUCKET_PROBES:
                break

        artifact = ctx.evidence(
            "artifact",
            {
                "domain": name,
                "names": list(names),
                "probes": probes,
                "findings": [
                    {"bucket": bucket, "provider": provider, "url": url}
                    for bucket, provider, url in findings
                ],
                "failures": failures,
            },
            source=name,
        )
        if not findings:
            yield ctx.clean(
                f"no public storage bucket for {name} among {len(names)} derived name(s)",
                detail=(
                    f"{probes} probe(s) over HTTPS; none returned a bucket listing"
                    + (f"; failures: {'; '.join(failures[:5])}" if failures else "")
                ),
                evidence=[artifact],
                confidence=0.5,
            )
            return
        yield ctx.info(
            f"{len(findings)} public storage bucket(s) derived from {name}",
            detail="; ".join(f"{provider}:{bucket}" for bucket, provider, _ in findings),
            evidence=[artifact],
            confidence=0.7,
        )
        for bucket, provider, url in findings:
            yield ctx.candidate(
                f"cloud storage bucket {bucket!r} ({provider}) allows anonymous listing",
                detail=(
                    f"{url} returned a bucket listing without credentials (research ch01 §30); "
                    "enumerating it is left to a cloud module, and the exposure is CWE-284."
                ),
                evidence=[
                    ctx.evidence(
                        "artifact",
                        {"bucket": bucket, "provider": provider, "url": url},
                        source=url,
                    )
                ],
                confidence=0.6,
            )


def _bucket_names(domain: str) -> tuple[str, ...]:
    """Candidate bucket names from the domain label, with and without the TLD and affixes."""
    host = normalize_host(domain) or domain
    stem = host.split(".", 1)[0]
    names: dict[str, None] = {}
    for base in (stem, host.replace(".", "-")):
        if base:
            names.setdefault(base, None)
    for affix in _BUCKET_AFFIXES:
        if stem:
            names.setdefault(f"{stem}{affix}", None)
    return tuple(list(names)[:_MAX_BUCKET_NAMES])


def _is_listing(provider: str, status: int, body: str) -> bool:
    """True when a 200 answer is a bucket listing (a 403/404 is a refusal, not a listing)."""
    if status != 200 or not body:
        return False
    if provider == "azure":
        return "<EnumerationResults" in body
    if provider == "gcs":
        return body.lstrip().startswith("[") or "<ListBucketResult" in body
    return "<ListBucketResult" in body


# --------------------------------------------------------------------------- documents (22)
#: A bounded scan: only the first part of a document is searched for its ``/Info`` dictionary.
_PDF_INFO_RE = re.compile(
    rb"/(Author|Creator|Producer|CreationDate|Title|Subject)\s*\(([^)]{0,300})\)"
)
_PDF_SCAN_LIMIT = 200_000
#: ASCII (TIFF type 2) EXIF tags this check decodes, and the GPS pointer tag.
_EXIF_ASCII_TAGS: dict[int, str] = {
    0x010E: "ImageDescription",
    0x0131: "Software",
    0x013B: "Artist",
}
_EXIF_GPS_POINTER_TAG = 0x8825
_EXIF_MAX_ENTRIES = 64
#: A software-version signal: a dotted version (``16.0``) or a product year (``Word 2016``).
_VERSION_RE = re.compile(r"\d+\.\d+|\b(?:19|20)\d{2}\b")

_PDF_UNESCAPE: dict[str, str] = {
    "n": "\n",
    "r": "\r",
    "t": "\t",
    "b": "\b",
    "f": "\f",
    "(": "(",
    ")": ")",
    "\\": "\\",
}


class DocMetadata(Module):
    """``m1.doc-metadata`` — PDF /Info and image EXIF metadata (research ch01#22)."""

    metadata = CheckMetadata(
        id="m1.doc-metadata",
        module="M1",
        name="doc-metadata",
        version="1.0",
        title="Document metadata extraction",
        description=(
            "Fetches a published document or image and extracts its PDF /Info or image EXIF "
            "metadata (author, software, hostnames, GPS) that the publisher left in place."
        ),
        research_ref="ch01#22",
        framework=("WSTG-INFO-05", "CWE-200"),
        cwe="CWE-200",
        target_kinds=(TargetKind.URL,),
        severity_hint="low",
        type="hybrid",
        safe=True,
        verifiable=True,
        estimated_requests=4,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        if ctx.http is None:
            yield ctx.skipped("no HTTP client is available in this mode (dry run)")
            return
        url = ctx.asset.value
        try:
            response = await ctx.http.get(url)
        except (SafetyError, RequestError) as exc:
            yield ctx.error(exc)
            return
        if response.status_code != 200:
            yield ctx.clean(
                f"document metadata probe of {url} returned HTTP {response.status_code}",
                confidence=0.4,
            )
            return

        content_type = (response.header("content-type") or "").lower()
        data = response.body.encode("latin-1", "replace")
        module_kind = ""
        fields: dict[str, str] = {}
        if "pdf" in content_type or data[:5] == b"%PDF-":
            module_kind, fields = "pdf", _pdf_info(data)
        elif content_type.startswith("image/") or data[:3] == b"\xff\xd8\xff":
            module_kind, fields = "image", _image_exif(data)
        else:
            yield ctx.skipped(
                f"{url} is not a document or image ({content_type or 'unknown content type'})"
            )
            return

        if not fields:
            yield ctx.clean(
                f"no document metadata in {url}",
                detail=f"the {module_kind} content carried no /Info or EXIF field this check reads",
                confidence=0.5,
            )
            return

        reasons = _suspicious_metadata(fields)
        artifact = ctx.evidence(
            "artifact",
            {"url": url, "kind": module_kind, "fields": fields, "reasons": reasons},
            source=url,
        )
        yield ctx.info(
            f"{module_kind} metadata in {url}: {', '.join(fields)}",
            detail=f"{len(fields)} field(s) extracted"
            + (f"; signals: {', '.join(reasons)}" if reasons else ""),
            evidence=[artifact],
            confidence=0.6,
        )
        if reasons:
            yield ctx.candidate(
                f"document metadata at {url} leaks {', '.join(reasons)}",
                detail=(
                    "Document metadata is easily overlooked and can name an author, an internal "
                    "host, an authoring-software version or capture GPS coordinates "
                    "(research ch01 §22, CWE-200)."
                ),
                evidence=[artifact],
                confidence=0.5,
            )


def _pdf_info(data: bytes) -> dict[str, str]:
    """The PDF ``/Info`` fields this check reads, first occurrence per key."""
    fields: dict[str, str] = {}
    for match in _PDF_INFO_RE.finditer(data[:_PDF_SCAN_LIMIT]):
        key = match.group(1).decode("ascii", "replace")
        if key in fields:
            continue
        fields[key] = _unescape_pdf(match.group(2).decode("latin-1", "replace"))
    return fields


def _unescape_pdf(value: str) -> str:
    """Resolve PDF string escapes (``\\(``, ``\\n``, ...) and trim whitespace."""
    unescaped = re.sub(
        r"\\(.)",
        lambda match: _PDF_UNESCAPE.get(match.group(1), match.group(1)),
        value,
    )
    return unescaped.strip()


def _image_exif(data: bytes) -> dict[str, str]:
    """ASCII EXIF tags and GPS presence from a JPEG ``APP1`` segment (stdlib only)."""
    marker = data.find(b"Exif\x00\x00")
    if marker < 0:
        return {}
    tiff = data[marker + 6 :]
    if len(tiff) < 8:
        return {}
    if tiff[:2] == b"II":
        endian = "<"
    elif tiff[:2] == b"MM":
        endian = ">"
    else:
        return {}
    try:
        ifd_offset = int(struct.unpack(f"{endian}I", tiff[4:8])[0])
    except struct.error:
        return {}
    return _read_exif_ifd0(tiff, ifd_offset, endian)


def _read_exif_ifd0(tiff: bytes, offset: int, endian: str) -> dict[str, str]:
    """Read the tags this check cares about from IFD0 (bounded to ``_EXIF_MAX_ENTRIES``)."""
    if offset <= 0 or offset + 2 > len(tiff):
        return {}
    try:
        count = int(struct.unpack(f"{endian}H", tiff[offset : offset + 2])[0])
    except struct.error:
        return {}
    fields: dict[str, str] = {}
    entry = offset + 2
    for _ in range(min(count, _EXIF_MAX_ENTRIES)):
        if entry + 12 > len(tiff):
            break
        tag, field_type, number = struct.unpack(f"{endian}HHI", tiff[entry : entry + 8])
        raw_value = tiff[entry + 8 : entry + 12]
        if tag in _EXIF_ASCII_TAGS and field_type == 2:
            text = _exif_ascii(tiff, raw_value, number, endian)
            if text:
                fields[_EXIF_ASCII_TAGS[tag]] = text
        elif tag == _EXIF_GPS_POINTER_TAG:
            fields["GPSInfo"] = "present"
        entry += 12
    return fields


def _exif_ascii(tiff: bytes, raw_value: bytes, number: int, endian: str) -> str:
    """Decode a TIFF ASCII value, which lives inline when short and behind a pointer else."""
    if number <= 0:
        return ""
    if number <= 4:
        raw = raw_value[:number]
    else:
        try:
            pointer = int(struct.unpack(f"{endian}I", raw_value)[0])
        except struct.error:
            return ""
        raw = tiff[pointer : pointer + number]
    return raw.split(b"\x00", 1)[0].decode("latin-1", "replace").strip()


def _suspicious_metadata(fields: dict[str, str]) -> list[str]:
    """The metadata signals worth a candidate: identity, internal hosts, versions, GPS."""
    reasons: list[str] = []
    for key, value in fields.items():
        if not value:
            continue
        if key == "GPSInfo":
            reasons.append("gps-coordinates")
            continue
        if "@" in value or "\\" in value:
            reasons.append(f"identity:{key}")
        if internal_hostname_hints(value):
            reasons.append(f"internal-hostname:{key}")
        if key in {"Producer", "Creator", "Software"} and _VERSION_RE.search(value):
            reasons.append(f"software-version:{key}")
    return list(dict.fromkeys(reasons))
