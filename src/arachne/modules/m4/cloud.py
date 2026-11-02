"""M4 cloud-facing checks: object-storage exposure and metadata-service reachability.

``m4.bucket-exposure``
    Probes a bucket root for a public listing and a public ACL. Two shapes are supported:
    a declared cloud reference (``s3:name``, ``gcs:name``, ``azure:account/container``) is
    translated into the provider's public endpoint, and an ``endpoint:<url>`` reference (or
    a URL asset that already points at a storage host) is treated as an S3-compatible
    endpoint — MinIO, LocalStack, or the lab fixture. Candidate names derived from the
    target's organisation label are probed under a wordlist, which is the
    "`<company>-backup`" pattern of research ch04#13. Probing a third-party provider host
    still goes through the scan's scope: an undeclared bucket host is refused and audited.

``m4.metadata-ssrf``
    **Off by default** (``ARACHNE_M4_METADATA_SSRF``), selected explicitly, and gated by the
    active-checks switch: it injects a provider metadata URL into a parameter the crawl
    identified as a likely server-side fetcher. What it reports is the *posture* — whether
    the sink returned metadata (IMDSv1-style) or a 401 challenge (IMDSv2 enforced) — never
    the credential the metadata service would have returned (the response is redacted at
    capture time like every other body).
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator
from urllib.parse import urlsplit

from arachne.core.results import CheckResult
from arachne.core.target import TargetKind
from arachne.modules.base import Asset, CheckMetadata, Module
from arachne.modules.context import CheckContext
from arachne.modules.m3.inventory import WebInventory, with_params
from arachne.modules.m3.support import web_or_skip
from arachne.modules.m4.corpus import BucketProvider
from arachne.modules.m4.support import (
    BucketCheck,
    UrlCheck,
    artifact_evidence,
    corpus_for,
    exchange_from_page,
    fetch_page,
    finding_cap,
    http_or_skip,
    m4_candidate,
    owns_origin,
    skip,
    text_contains_any,
    wordlist,
)

__all__ = ["BucketExposure", "MetadataSsrf"]

_STORAGE_HOSTS = ("s3.amazonaws.com", "storage.googleapis.com", "blob.core.windows.net")
_OBJECT_KEY_RE = re.compile(r"<(?:Key|Name)>([^<]{1,300})</(?:Key|Name)>")


def _with_query(base: str, query: str) -> str:
    """Append an S3-style query (``?list-type=2``) to ``base`` without doubling separators."""
    if not query:
        return base
    operator = "&" if "?" in base else "?"
    return base.rstrip("?&") + operator + query.lstrip("?&")


def _provider_for_url(value: str) -> str | None:
    host = (urlsplit(value).hostname or "").lower()
    for candidate in _STORAGE_HOSTS:
        if host.endswith(candidate):
            return candidate
    return None


def _strip_scheme(value: str) -> tuple[str, str]:
    provider, _, reference = value.partition(":")
    return provider.lower(), reference


def _object_keys(body: str, limit: int = 10) -> tuple[str, ...]:
    keys: list[str] = []
    for match in _OBJECT_KEY_RE.finditer(body):
        key = match.group(1).strip()
        if key:
            keys.append(key)
        if len(keys) >= limit:
            break
    return tuple(keys)


class BucketExposure(BucketCheck, Module):
    """``m4.bucket-exposure`` — public object-storage listing and ACL (ch04#13)."""

    metadata = CheckMetadata(
        id="m4.bucket-exposure",
        module="M4",
        name="bucket-exposure",
        version="1.0",
        title="Object-storage bucket is publicly readable",
        description=(
            "Probes a bucket root for an anonymous listing (<ListBucketResult>, GCS items, "
            "Azure EnumerationResults) and for a public ACL (AllUsers / allUsers / container-"
            "public-access). Cloud references are translated into the provider's public "
            "endpoint; an endpoint: reference (S3-compatible storage, or the lab fixture) is "
            "probed directly. Candidate names derived from the target's organisation label "
            "are tested with a bounded wordlist. Non-destructive: GET only, no object writes."
        ),
        research_ref="ch04#13",
        framework=("WSTG-CONF-11", "CWE-732"),
        cwe="CWE-732",
        target_kinds=(TargetKind.CLOUD, TargetKind.URL, TargetKind.DOMAIN),
        severity_hint="high",
        type="hybrid",
        safe=True,
        verifiable=True,
        estimated_requests=16,
        runs_on_discovered=True,
    )

    def supports(self, asset: Asset) -> bool:
        if asset.kind in {"bucket", "cloud"}:
            return True
        if asset.kind == "url":
            return _provider_for_url(asset.value) is not None
        return False

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        _client, skipped = http_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        corpus = corpus_for(ctx)
        providers = {provider.name: provider for provider in corpus.bucket_providers()}
        list_query, acl_query = corpus.bucket_endpoint_queries()
        candidates = _bucket_candidates(ctx, providers, list_query)
        if not candidates:
            yield skip(
                ctx,
                "no bucket endpoint could be derived: declare a cloud target "
                "(s3:name, gcs:name, azure:account/container or endpoint:<url>)",
            )
            return
        denied_status = set(corpus.bucket_access_denied_status())
        cap = finding_cap(ctx)
        findings = 0
        for provider_name, label, base in candidates[: ctx.config.m4.max_bucket_names]:
            provider = providers.get(provider_name)
            if provider is None:
                continue
            listing = await fetch_page(ctx, _with_query(base, list_query))
            acl = await fetch_page(ctx, _with_query(base, acl_query))
            if listing is not None and listing.status in denied_status:
                continue
            if (
                acl is not None
                and acl.status in denied_status
                and (listing is None or listing.status >= 400)
            ):
                continue
            public_listing = (
                listing is not None
                and listing.status == 200
                and (text_contains_any(listing.body, provider.listing_markers) is not None)
            )
            public_acl = (
                acl is not None
                and acl.status == 200
                and (text_contains_any(acl.body, provider.public_acl_markers) is not None)
            )
            if not (public_listing or public_acl):
                continue
            findings += 1
            keys = _object_keys(listing.body) if listing is not None and public_listing else ()
            yield m4_candidate(
                ctx,
                (
                    f"Bucket is publicly listable: {label}"
                    if public_listing
                    else f"Bucket grants public access via ACL: {label}"
                ),
                artifact={
                    "signal": "bucket-exposure",
                    "family": "bucket",
                    "provider": provider_name,
                    "bucket": label,
                    "endpoint": base,
                    "public_listing": public_listing,
                    "public_acl": public_acl,
                    "listing_status": None if listing is None else listing.status,
                    "acl_status": None if acl is None else acl.status,
                    "object_count": len(keys),
                    "object_keys": list(keys),
                },
                exchanges=(
                    None if listing is None else exchange_from_page(listing),
                    None if acl is None else exchange_from_page(acl),
                ),
                confidence=0.95 if public_listing else 0.85,
                detail=(
                    f"{base}: anonymous listing {'succeeded' if public_listing else 'refused'}, "
                    f"public ACL {'present' if public_acl else 'not observed'}"
                ),
                source=base,
            )
            if findings >= cap:
                break
        if not findings:
            yield ctx.clean(
                "no public bucket exposure found",
                detail=f"probed {min(len(candidates), ctx.config.m4.max_bucket_names)} bucket "
                "endpoint(s)",
            )


class MetadataSsrf(UrlCheck, Module):
    """``m4.metadata-ssrf`` — cloud metadata reachable through a request sink (ch04#26)."""

    metadata = CheckMetadata(
        id="m4.metadata-ssrf",
        module="M4",
        name="metadata-ssrf",
        version="1.0",
        title="Cloud metadata service reachable through a request sink",
        description=(
            "Injects the provider metadata URLs (AWS 169.254.169.254, GCP computeMetadata, "
            "Azure instance) into parameters the crawl identified as likely server-side "
            "fetchers and reports the posture from the sink's answer: metadata returned "
            "(IMDSv1-style, exploitable) or a 401 challenge (IMDSv2 enforced). Off by "
            "default: it needs ARACHNE_M4_METADATA_SSRF=true, an explicit check selection "
            "and the active-checks opt-in. It sends GET only and never stores a response "
            "body beyond its redacted evidence."
        ),
        research_ref="ch04#26",
        framework=("WSTG-INPV-19", "API7:2023", "CWE-918"),
        cwe="CWE-918",
        target_kinds=(TargetKind.URL,),
        severity_hint="critical",
        type="hybrid",
        safe=True,
        verifiable=False,
        estimated_requests=4,
        enabled_by_default=False,
        requires_active_checks=True,
        runs_on_discovered=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        _client, skipped = http_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        if not owns_origin(ctx):
            yield skip(ctx, "another URL asset on this origin owns the M4 probes for it")
            return
        if not ctx.config.m4.metadata_ssrf_probe:
            yield skip(
                ctx,
                "metadata probing is disabled (set ARACHNE_M4_METADATA_SSRF=true, select "
                "m4.metadata-ssrf explicitly, and authorize active checks)",
            )
            return
        inventory, skipped = web_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        assert isinstance(inventory, WebInventory)
        corpus = corpus_for(ctx)
        sinks = inventory.parameter_targets(names=corpus.metadata_sink_hints(), limit=3)
        if not sinks:
            yield skip(
                ctx,
                "the crawl found no URL-fetching parameter to test for an SSRF sink",
            )
            return
        postures: list[dict[str, object]] = []
        findings = 0
        for endpoint, parameter in sinks:
            for entry in corpus.metadata_endpoints()[:3]:
                injected = with_params(endpoint, {parameter: entry.url})
                page = await fetch_page(ctx, injected, session=False)
                if page is None:
                    postures.append({"provider": entry.provider, "sink": parameter, "status": None})
                    continue
                marker = text_contains_any(page.body, (entry.v1_marker or "",))
                imds_v2 = entry.v2_status is not None and page.status == entry.v2_status
                postures.append(
                    {
                        "provider": entry.provider,
                        "sink": parameter,
                        "endpoint": endpoint,
                        "status": page.status,
                        "marker": marker,
                        "imds_v2": imds_v2,
                    }
                )
                if marker is None and not imds_v2:
                    continue
                findings += 1
                yield m4_candidate(
                    ctx,
                    f"Cloud metadata reachable through '{parameter}' ({entry.provider})",
                    artifact={
                        "signal": "metadata-ssrf",
                        "family": "metadata-ssrf",
                        "provider": entry.provider,
                        "sink": parameter,
                        "endpoint": endpoint,
                        "status": page.status,
                        "marker": marker,
                        "imds_v2": imds_v2,
                        "posture": "imdsv2-enforced" if imds_v2 else "imdsv1-served",
                    },
                    exchanges=(exchange_from_page(page),),
                    confidence=0.9 if marker else 0.6,
                    detail=(
                        f"{endpoint} (parameter {parameter}) answered the {entry.provider} "
                        f"metadata URL with HTTP {page.status}"
                        + (
                            ": the service returned metadata (IMDSv1-style)"
                            if marker
                            else ": the service enforced the IMDSv2 token (posture only)"
                        )
                    ),
                    source=endpoint,
                )
                if findings >= finding_cap(ctx):
                    return
        if not findings:
            yield ctx.info(
                "Cloud metadata SSRF posture",
                detail=(
                    "no sink returned metadata; postures: "
                    + ", ".join(f"{item.get('provider')}={item.get('status')}" for item in postures)
                ),
                evidence=[
                    artifact_evidence(
                        {
                            "signal": "metadata-ssrf-posture",
                            "family": "metadata-ssrf",
                            "postures": postures,
                            "sinks_tested": [f"{url}?{name}=" for url, name in sinks],
                        }
                    )
                ],
            )


# --------------------------------------------------------------------------- candidates
def _bucket_candidates(
    ctx: CheckContext,
    providers: dict[str, BucketProvider],
    list_query: str,
) -> list[tuple[str, str, str]]:
    """``(provider, label, base_url)`` candidates for this asset."""
    candidates: list[tuple[str, str, str]] = []
    names = _bucket_names(ctx)
    value = ctx.asset.value
    if ctx.asset.kind in {"bucket", "cloud"} or "://" in value:
        if value.lower().startswith(("http://", "https://")):
            return [("endpoint", _label_of(value), value), *_endpoint_names(value, names)]
        provider, reference = _strip_scheme(value)
        if provider in {"endpoint", "custom", "minio", "localstack"}:
            reference = reference if "://" in reference else f"https://{reference}"
            return [("endpoint", _label_of(reference), reference)]
        built = _provider_base(provider, reference, providers)
        if built is not None:
            candidates.append(built)
        return candidates
    # A URL asset that already points at a storage provider.
    provider_name = _provider_for_url(value)
    if provider_name is not None:
        return [("endpoint", _label_of(value), value)]
    return candidates


def _provider_base(
    provider: str, reference: str, providers: dict[str, BucketProvider]
) -> tuple[str, str, str] | None:
    if provider in {"s3", "aws"}:
        definition = providers.get("s3")
        bucket = reference.strip("/")
        host = (
            definition.host_template.replace("<bucket>", bucket)
            if definition is not None
            else f"{bucket}.s3.amazonaws.com"
        )
        return "s3", bucket, f"https://{host}/"
    if provider in {"gcs", "gs", "google"}:
        definition = providers.get("gcs")
        bucket = reference.strip("/")
        prefix = (
            definition.path_prefix.replace("<bucket>", bucket)
            if definition is not None
            else f"/{bucket}"
        )
        host = definition.host_template if definition is not None else "storage.googleapis.com"
        return "gcs", bucket, f"https://{host}{prefix}"
    if provider in {"azure", "az", "blob"}:
        account, _, container = reference.partition("/")
        definition = providers.get("azure")
        host = (
            definition.host_template.replace("<account>", account)
            if definition is not None
            else f"{account}.blob.core.windows.net"
        )
        container = container or "public"
        prefix = (
            definition.path_prefix.replace("<container>", container)
            if definition is not None
            else f"/{container}"
        )
        return "azure", f"{account}/{container}", f"https://{host}{prefix}"
    return None


def _bucket_names(ctx: CheckContext) -> tuple[str, ...]:
    """Wordlist stems, plus ``<org>-stem`` variants derived from the target's domains."""
    corpus = corpus_for(ctx)
    stems = wordlist(
        ctx,
        corpus.bucket_names_wordlist(),
        limit=ctx.config.m4.max_bucket_names,
    )
    org = _org_label(ctx)
    names: list[str] = []
    for stem in stems:
        names.append(stem)
        if org:
            names.append(f"{org}-{stem}")
    return tuple(dict.fromkeys(names))


def _org_label(ctx: CheckContext) -> str | None:
    for selector in ctx.definition.targets:
        value = selector.value.strip().lower()
        if selector.kind is TargetKind.DOMAIN:
            labels = [item for item in value.split(".") if item]
            if len(labels) >= 2:
                return labels[-2]
    return None


def _endpoint_names(base: str, names: tuple[str, ...]) -> list[tuple[str, str, str]]:
    """Wordlist probes under an endpoint's parent path (``/storage/<name>``)."""
    parts = urlsplit(base)
    parent = parts.path.rstrip("/").rsplit("/", 1)[0]
    prefix = f"{parts.scheme}://{parts.netloc}{parent}"
    return [("endpoint", name, f"{prefix}/{name}") for name in names]


def _label_of(value: str) -> str:
    parts = urlsplit(value)
    if parts.path.strip("/"):
        return parts.path.rstrip("/").rsplit("/", 1)[-1]
    return (parts.hostname or value).split(".")[0]
