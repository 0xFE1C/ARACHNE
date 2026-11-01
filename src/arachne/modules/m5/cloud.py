"""M5 cloud-facing checks: buckets, leaked credentials, metadata/IMDS, managed identity, GCP SA
keys and the IAM review (research ch05#1-#6).

These are the module's "cloud account" checks. Their safety contract ("Safety") is
*read-only*: bucket probing is GET, the metadata probe reports the IMDSv1-vs-v2
posture (behind ``ARACHNE_M5_IMDS_PROBE``) and never the credential the service would return,
credential *validation* (``sts:GetCallerIdentity``-class) is off by default and only ever uses a
key the deployment configured, and the live IAM review is off unless a read-only credential is
granted (its documented permission list is in the corpus, ``iam/read_only_permissions``).
"""

from __future__ import annotations

import hashlib
import hmac
import re
from collections.abc import AsyncIterator, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from arachne.core.results import CheckResult
from arachne.core.target import TargetKind
from arachne.modules.base import Asset, CheckMetadata, Module
from arachne.modules.context import CheckContext
from arachne.modules.m3.inventory import with_params
from arachne.modules.m5.corpus import M5Corpus
from arachne.modules.m5.support import (
    EndpointCheck,
    RepoCheck,
    UrlCheck,
    corpus_for,
    fetch_page,
    finding_cap,
    http_or_skip,
    iter_repo_files,
    local_root,
    m5_candidate,
    read_text,
    skip,
    text_contains_any,
    wordlist,
)

__all__ = [
    "AzureMiAudit",
    "BucketEnumerator",
    "GcpSaKeys",
    "IamReview",
    "ImdsSsrf",
    "LeakedCloudKeys",
]

_STORAGE_HOSTS = ("s3.amazonaws.com", "storage.googleapis.com", "blob.core.windows.net")
_OBJECT_KEY_RE = re.compile(r"<(?:Key|Name)>([^<]{1,300})</(?:Key|Name)>")


# --------------------------------------------------------------------------- bucket enumerator
class BucketEnumerator(EndpointCheck, Module):
    """``m5.bucket-enumerator`` — public storage bucket detection + wordlist (ch05#2)."""

    metadata = CheckMetadata(
        id="m5.bucket-enumerator",
        module="M5",
        name="bucket-enumerator",
        version="1.0",
        title="Public cloud storage bucket enumerable",
        description=(
            "Probes a bucket root for an anonymous listing and a public ACL, and derives name "
            "candidates from the target's organisation label against a bounded wordlist "
            "(research ch05#2). Cloud references are translated into the provider's public "
            "endpoint (s3:, gcs:, azure:); an endpoint: reference is probed directly. "
            "Non-destructive: GET only, no object writes."
        ),
        research_ref="ch05#2",
        cwe="CWE-732",
        target_kinds=(TargetKind.CLOUD, TargetKind.URL, TargetKind.DOMAIN),
        severity_hint="high",
        type="active",
        safe=True,
        verifiable=True,
        estimated_requests=16,
        requires_active_checks=True,
        runs_on_discovered=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        _client, skipped = http_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        corpus = corpus_for(ctx)
        providers = {provider.name: provider for provider in corpus.bucket_providers()}
        list_query, acl_query = corpus.bucket_endpoint_queries()
        candidates = self._candidates(ctx, corpus, providers, list_query)
        if not candidates:
            yield skip(
                ctx,
                "no bucket endpoint derived: declare s3:/gcs:/azure:name or endpoint:<url>",
            )
            return
        denied = set(corpus.bucket_access_denied_status())
        findings = 0
        for provider_name, label, base in candidates[: ctx.config.m5.max_bucket_names]:
            provider = providers.get(provider_name)
            if provider is None:
                continue
            listing = await fetch_page(ctx, _with_query(base, list_query))
            acl = await fetch_page(ctx, _with_query(base, acl_query)) if acl_query else None
            if listing is not None and listing.status in denied:
                continue
            public_listing = (
                listing is not None
                and listing.status == 200
                and text_contains_any(listing.body, provider.listing_markers) is not None
            )
            public_acl = (
                acl is not None
                and acl.status == 200
                and text_contains_any(acl.body, provider.public_acl_markers) is not None
            )
            if not (public_listing or public_acl):
                continue
            findings += 1
            keys = _object_keys(listing.body) if listing is not None and public_listing else ()
            yield m5_candidate(
                ctx,
                (
                    f"Bucket is publicly listable: {label}"
                    if public_listing
                    else f"Bucket grants public access via ACL: {label}"
                ),
                artifact={
                    "signal": "bucket-enumeration",
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
                confidence=0.95 if public_listing else 0.85,
                detail=(
                    f"{base}: anonymous listing {'succeeded' if public_listing else 'refused'}, "
                    f"public ACL {'present' if public_acl else 'not observed'}"
                ),
                source=base,
            )
            if findings >= finding_cap(ctx):
                break
        if not findings:
            yield ctx.clean(
                "no public bucket exposure found",
                detail=(
                    f"probed {min(len(candidates), ctx.config.m5.max_bucket_names)} bucket name(s)"
                ),
            )

    def _candidates(
        self,
        ctx: CheckContext,
        corpus: M5Corpus,
        providers: Mapping[str, Any],
        list_query: str,
    ) -> list[tuple[str, str, str]]:
        value = ctx.asset.value
        names = self._names(ctx, corpus)
        if value.lower().startswith(("http://", "https://")):
            provider = _provider_for_url(value)
            if provider is not None:
                return [("endpoint", _label_of(value), value)]
            # An endpoint-ish URL: probe it and a few sibling names under its parent path.
            parent = urlsplit(value)
            base = f"{parent.scheme}://{parent.netloc}{parent.path.rstrip('/').rsplit('/', 1)[0]}"
            return [(("endpoint"), _label_of(value), value)] + [
                ("endpoint", name, f"{base}/{name}") for name in names
            ]
        provider, reference = _split(value)
        if provider in {"endpoint", "custom", "minio", "localstack"}:
            reference = reference if "://" in reference else f"https://{reference}"
            return [("endpoint", _label_of(reference), reference)]
        built = _provider_base(provider, reference)
        if built is not None:
            return [built]
        return []

    def _names(self, ctx: CheckContext, corpus: M5Corpus) -> tuple[str, ...]:
        stems = wordlist(ctx, corpus.bucket_names_wordlist(), limit=ctx.config.m5.max_bucket_names)
        org = _org_label(ctx)
        names: list[str] = []
        for stem in stems:
            names.append(stem)
            if org:
                names.append(f"{org}-{stem}")
        return tuple(dict.fromkeys(names))


# --------------------------------------------------------------------------- leaked cloud keys
class LeakedCloudKeys(RepoCheck, Module):
    """``m5.leaked-cloud-keys`` — cloud credential patterns in artifacts (ch05#3)."""

    metadata = CheckMetadata(
        id="m5.leaked-cloud-keys",
        module="M5",
        name="leaked-cloud-keys",
        version="1.0",
        title="Leaked cloud credential material in artifacts",
        description=(
            "Scans a local repository clone and the crawled web assets for cloud credential "
            "patterns (AWS access keys, GCP service-account JSON, Azure client secrets, PEM "
            "keys) and reports the credential *kind* and location — the values are masked and "
            "never stored. Optional read-only validation (sts:GetCallerIdentity-class) is off by "
            "default (ARACHNE_M5_VALIDATE_CLOUD_KEYS) and uses only a configured key."
        ),
        research_ref="ch05#3",
        cwe="CWE-798",
        target_kinds=(TargetKind.GIT, TargetKind.CLOUD, TargetKind.URL),
        severity_hint="high",
        type="hybrid",
        safe=True,
        verifiable=False,
        estimated_requests=0,
        runs_on_discovered=True,
    )

    def supports(self, asset: Asset) -> bool:
        if super().supports(asset):
            return True
        return Module.supports(self, asset) and asset.kind == "url"

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        corpus = corpus_for(ctx)
        patterns = corpus.secret_patterns()
        max_matches = corpus.secret_max_matches()
        findings = 0
        for _path, text, relative in self._sources(ctx, corpus):
            for pattern in patterns:
                match = pattern.regex.search(text)
                if match is None:
                    continue
                validated, validation = await self._validate(ctx, pattern.kind, text)
                findings += 1
                yield m5_candidate(
                    ctx,
                    f"Leaked {pattern.kind} credential in {relative}",
                    artifact={
                        "signal": "leaked-cloud-credentials",
                        "family": "cloud-keys",
                        "kind": pattern.kind,
                        "location": relative,
                        "masked": _mask(match.group(0)),
                        "validated": validated,
                        "validation": validation,
                    },
                    confidence=0.9 if validated else 0.8,
                    detail=(
                        f"{relative} contains {pattern.kind} credential material"
                        + (
                            "; the key authenticated a read-only GetCallerIdentity call"
                            if validated
                            else "; the value is masked and no validation call was made"
                        )
                    ),
                    source=relative,
                )
                if findings >= max_matches:
                    return
        if not findings:
            yield ctx.clean(
                "no cloud credential pattern found",
                detail="scanned the local artifacts and crawled assets",
            )

    async def _validate(self, ctx: CheckContext, kind: str, text: str) -> tuple[bool, str]:
        """Optionally confirm an AWS key with a read-only ``sts:GetCallerIdentity`` call.

        Off by default (ARACHNE_M5_VALIDATE_CLOUD_KEYS). The documented permission list: the
        call needs no IAM permission beyond the caller's own identity, and nothing else is
        enumerated. The request goes through the scan's scoped client, so an STS host that is
        not in scope is refused and audited like any other request.
        """
        if not ctx.config.m5.validate_cloud_keys or kind != "aws-access-key":
            return False, "not-attempted"
        access = re.search(r"(AKIA[0-9A-Z]{16})", text)
        secret = re.search(r"[A-Za-z0-9/+=]{40}", text)
        if access is None or secret is None:
            return False, "incomplete-pair"
        from arachne.core.http import HttpExchange  # noqa: F401  (kept for typing clarity)
        from arachne.modules.m3.support import safe_fetch

        body = "Action=GetCallerIdentity&Version=2011-06-15"
        headers = _aws_sigv4_headers(access.group(1), secret.group(0))
        exchange = await safe_fetch(
            ctx,
            "https://sts.amazonaws.com/",
            method="POST",
            headers=headers,
            content=body,
            follow_redirects=False,
        )
        if exchange is None:
            return False, "call-refused"
        valid = exchange.status_code == 200 and "GetCallerIdentityResponse" in exchange.body
        return valid, "validated" if valid else "rejected"

    def _sources(self, ctx: CheckContext, corpus: M5Corpus) -> list[tuple[Path | None, str, str]]:
        sources: list[tuple[Path | None, str, str]] = []
        root = local_root(ctx)
        if root is not None:
            paths = iter_repo_files(
                root,
                corpus.secret_key_file_names(),
                max_files=ctx.config.m5.max_repo_files,
                max_bytes=ctx.config.m5.max_file_bytes,
            )
            for path in paths:
                text = read_text(path, limit=ctx.config.m5.max_file_bytes)
                if text:
                    relative = path.relative_to(root) if path.is_relative_to(root) else path
                    sources.append((path, text, str(relative)))
        inventory = ctx.web
        if inventory is not None:
            for page in getattr(inventory, "pages", {}).values():
                sources.append((None, page.body, page.url))
        return sources


# --------------------------------------------------------------------------- IMDS SSRF
class ImdsSsrf(UrlCheck, Module):
    """``m5.imds-ssrf`` — metadata service reachable through a request sink (ch05#4)."""

    metadata = CheckMetadata(
        id="m5.imds-ssrf",
        module="M5",
        name="imds-ssrf",
        version="1.0",
        title="Cloud metadata service reachable through a request sink",
        description=(
            "Injects the cloud metadata URLs (AWS 169.254.169.254, GCP computeMetadata, Azure "
            "instance) into parameters the crawl identified as server-side fetchers and reports "
            "the posture: metadata returned (IMDSv1-style, exploitable) or a 401 challenge "
            "(IMDSv2 enforced). Off by default: needs ARACHNE_M5_IMDS_PROBE=true and the "
            "active-checks opt-in. It sends GET only and never stores a body beyond redacted "
            "evidence."
        ),
        research_ref="ch05#4",
        cwe="CWE-918",
        target_kinds=(TargetKind.URL,),
        severity_hint="critical",
        type="hybrid",
        safe=True,
        verifiable=False,
        estimated_requests=6,
        enabled_by_default=False,
        requires_active_checks=True,
        runs_on_discovered=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        _client, skipped = http_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        if not ctx.config.m5.imds_probe:
            yield skip(
                ctx,
                "metadata probing is disabled (set ARACHNE_M5_IMDS_PROBE=true, select "
                "m5.imds-ssrf explicitly, and authorize active checks)",
            )
            return
        inventory = ctx.web
        if inventory is None:
            yield skip(ctx, "no web inventory for this step: the checks step crawls the endpoints")
            return
        corpus = corpus_for(ctx)
        hints = {name.lower() for name in corpus.imds_sink_hints()}
        sinks = inventory.parameter_targets(names=hints, limit=3)
        if not sinks:
            yield skip(ctx, "the crawl found no URL-fetching parameter to test")
            return
        v2_status = corpus.imds_v2_status()
        postures: list[dict[str, object]] = []
        findings = 0
        for endpoint, parameter in sinks:
            for target in corpus.imds_targets()[:3]:
                injected = with_params(endpoint, {parameter: str(target.values.get("url", ""))})
                page = await fetch_page(ctx, injected, session=False)
                if page is None:
                    postures.append({"provider": target.name, "sink": parameter, "status": None})
                    continue
                marker = str(target.values.get("marker", ""))
                served = marker and marker in page.body
                imds_v2 = page.status == v2_status
                postures.append(
                    {
                        "provider": target.name,
                        "sink": parameter,
                        "endpoint": endpoint,
                        "status": page.status,
                        "marker": marker if served else None,
                        "imds_v2": imds_v2,
                    }
                )
                if not served and not imds_v2:
                    continue
                findings += 1
                yield m5_candidate(
                    ctx,
                    f"Cloud metadata reachable through '{parameter}' ({target.name})",
                    artifact={
                        "signal": "imds-ssrf",
                        "family": "imds",
                        "provider": target.name,
                        "sink": parameter,
                        "endpoint": endpoint,
                        "status": page.status,
                        "marker": marker if served else None,
                        "imds_v2": imds_v2,
                        "posture": "imdsv2-enforced" if imds_v2 else "imdsv1-served",
                    },
                    confidence=0.9 if served else 0.6,
                    detail=(
                        f"{endpoint} (parameter {parameter}) answered the {target.name} "
                        f"metadata URL with HTTP {page.status}"
                        + (
                            ": metadata returned (IMDSv1-style)"
                            if served
                            else ": IMDSv2 token enforced"
                        )
                    ),
                    source=endpoint,
                )
                if findings >= finding_cap(ctx):
                    return
        if not findings:
            yield ctx.info(
                "Cloud metadata SSRF posture",
                detail="no sink returned metadata; postures: "
                + ", ".join(f"{item.get('provider')}={item.get('status')}" for item in postures),
            )


# --------------------------------------------------------------------------- Azure managed identity
class AzureMiAudit(UrlCheck, Module):
    """``m5.azure-mi-audit`` — Azure IMDS / managed-identity reachability (ch05#5)."""

    metadata = CheckMetadata(
        id="m5.azure-mi-audit",
        module="M5",
        name="azure-mi-audit",
        version="1.0",
        title="Azure managed-identity metadata reachable",
        description=(
            "Probes a server-side fetch sink for the Azure Instance Metadata Service instance "
            "document and the managed-identity OAuth2 token endpoint, and reports the posture: "
            "instance metadata returned (network egress not restricted) or a token minted "
            "(managed identity reachable). Off by default (ARACHNE_M5_IMDS_PROBE) and behind the "
            "active-checks gate; it reports token *presence*, never the token value."
        ),
        research_ref="ch05#5",
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
        if not ctx.config.m5.imds_probe:
            yield skip(
                ctx,
                "metadata probing is disabled (set ARACHNE_M5_IMDS_PROBE=true and authorize "
                "active checks)",
            )
            return
        inventory = ctx.web
        if inventory is None:
            yield skip(ctx, "no web inventory for this step")
            return
        corpus = corpus_for(ctx)
        hints = {name.lower() for name in corpus.imds_sink_hints()}
        sinks = inventory.parameter_targets(names=hints, limit=3)
        if not sinks:
            yield skip(ctx, "no URL-fetching parameter found to test")
            return
        instance = corpus.azure_imds_instance()
        token_url = corpus.azure_imds_token()
        instance_markers = corpus.azure_instance_markers()
        token_markers = corpus.azure_token_markers()
        findings = 0
        for endpoint, parameter in sinks:
            for label, url, markers in (
                ("instance", instance, instance_markers),
                ("identity-token", token_url, token_markers),
            ):
                page = await fetch_page(ctx, with_params(endpoint, {parameter: url}), session=False)
                if page is None:
                    continue
                marker = text_contains_any(page.body, markers)
                if marker is None:
                    continue
                findings += 1
                yield m5_candidate(
                    ctx,
                    f"Azure {label} metadata reachable through '{parameter}'",
                    artifact={
                        "signal": "azure-managed-identity",
                        "family": "azure-mi",
                        "sink": parameter,
                        "endpoint": endpoint,
                        "document": label,
                        "status": page.status,
                        "marker": marker,
                    },
                    confidence=0.85 if label == "identity-token" else 0.8,
                    detail=(
                        f"{endpoint} returned the Azure {label} document through '{parameter}' "
                        "(managed-identity reachable)"
                    ),
                    source=endpoint,
                )
                if findings >= finding_cap(ctx):
                    return
        if not findings:
            yield ctx.clean(
                "Azure metadata not reachable through the probed sinks",
                detail=f"probed {len(sinks)} sink(s)",
            )


# --------------------------------------------------------------------------- GCP SA keys
_GCP_SA_MARKERS = ('"type": "service_account"', '"type":"service_account"')
_GCP_KEY_MARKERS = ('"private_key"', '"client_email"')


class GcpSaKeys(RepoCheck, Module):
    """``m5.gcp-sa-keys`` — GCP service-account key exposure (ch05#6)."""

    metadata = CheckMetadata(
        id="m5.gcp-sa-keys",
        module="M5",
        name="gcp-sa-keys",
        version="1.0",
        title="GCP service-account key material exposed",
        description=(
            "Scans a local repository clone and crawled assets for GCP service-account key "
            "material (a JSON document with type=service_account and a private_key / client_email "
            "pair) and reports the location. The key body is masked; the check never attempts "
            "token issuance."
        ),
        research_ref="ch05#6",
        cwe="CWE-798",
        target_kinds=(TargetKind.GIT, TargetKind.CLOUD, TargetKind.URL),
        severity_hint="high",
        type="hybrid",
        safe=True,
        verifiable=False,
        estimated_requests=0,
        runs_on_discovered=True,
    )

    def supports(self, asset: Asset) -> bool:
        if super().supports(asset):
            return True
        return Module.supports(self, asset) and asset.kind == "url"

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        corpus_for(ctx)
        findings = 0
        sources: list[tuple[str, str]] = []
        root = local_root(ctx)
        if root is not None:
            for path in iter_repo_files(
                root,
                ("*.json", "*.pem", "*.env", ".env", "*.yaml", "*.yml"),
                max_files=ctx.config.m5.max_repo_files,
                max_bytes=ctx.config.m5.max_file_bytes,
            ):
                text = read_text(path, limit=ctx.config.m5.max_file_bytes)
                if text:
                    sources.append(
                        (str(path.relative_to(root) if path.is_relative_to(root) else path), text)
                    )
        inventory = ctx.web
        if inventory is not None:
            for page in getattr(inventory, "pages", {}).values():
                sources.append((page.url, page.body))
        for location, text in sources:
            if not any(marker in text for marker in _GCP_SA_MARKERS):
                continue
            has_key = any(marker in text for marker in _GCP_KEY_MARKERS)
            findings += 1
            yield m5_candidate(
                ctx,
                f"GCP service-account key material in {location}",
                artifact={
                    "signal": "gcp-service-account-key",
                    "family": "gcp-sa",
                    "location": location,
                    "has_private_key": has_key,
                    "masked": _mask(text[:60]),
                },
                confidence=0.85 if has_key else 0.7,
                detail=f"{location} contains a GCP service-account key document; the key is masked",
                source=location,
            )
        if not findings:
            yield ctx.clean(
                "no GCP service-account key found",
                detail="scanned the local artifacts and crawled assets",
            )


# --------------------------------------------------------------------------- IAM review
class IamReview(RepoCheck, Module):
    """``m5.iam-review`` — IAM over-privilege / escalation review (ch05#1)."""

    metadata = CheckMetadata(
        id="m5.iam-review",
        module="M5",
        name="iam-review",
        version="1.0",
        title="IAM over-privilege and escalation paths",
        description=(
            "Reviews IAM policy documents in a local repository clone for wildcard actions/"
            "resources and privilege-escalation-relevant actions (research ch05#1). The live "
            "review (iam:List*/Get*, sts:GetCallerIdentity) requires a read-only credential and is "
            "documented in the corpus permission list; with none configured the check performs the "
            "static review only."
        ),
        research_ref="ch05#1",
        cwe="CWE-269",
        target_kinds=(TargetKind.GIT, TargetKind.CLOUD),
        severity_hint="high",
        type="hybrid",
        safe=True,
        verifiable=False,
        estimated_requests=0,
        runs_on_discovered=True,
    )

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        corpus = corpus_for(ctx)
        root = local_root(ctx)
        if root is None:
            yield skip(
                ctx,
                "no local policy artifact to review (declare a repo:/path target); the live IAM "
                "review needs a read-only credential",
            )
            return
        hints = corpus.iam_policy_hints()
        escalation = corpus.iam_escalation_actions()
        wildcard_markers = corpus.iam_wildcard_markers()
        findings = 0
        for path in iter_repo_files(
            root,
            corpus.iam_policy_globs(),
            max_files=ctx.config.m5.max_repo_files,
            max_bytes=ctx.config.m5.max_file_bytes,
        ):
            relative = str(path.relative_to(root) if path.is_relative_to(root) else path)
            lowered = relative.lower()
            text = read_text(path, limit=ctx.config.m5.max_file_bytes)
            if text is None:
                continue
            if not any(hint in lowered or hint in text.lower()[:400] for hint in hints):
                continue
            wildcard = text_contains_any(text, wildcard_markers)
            dangerous = [action for action in escalation if action in text]
            if wildcard is None and not dangerous:
                continue
            findings += 1
            yield m5_candidate(
                ctx,
                f"Over-permissive IAM policy in {relative}",
                artifact={
                    "signal": "iam-overprivilege",
                    "family": "iam",
                    "location": relative,
                    "wildcard": wildcard,
                    "escalation_actions": dangerous[:8],
                    "live_review": False,
                },
                confidence=0.75 if wildcard else 0.65,
                detail=(
                    f"{relative} grants a wildcard permission or an escalation-relevant action "
                    f"({'wildcard resource/action' if wildcard else ', '.join(dangerous[:3])})"
                ),
                source=relative,
            )
        if not findings:
            yield ctx.clean(
                "no over-permissive IAM policy found",
                detail="reviewed the local policy artifacts",
            )


# --------------------------------------------------------------------------- helpers (module-level)
def _with_query(base: str, query: str) -> str:
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


def _split(value: str) -> tuple[str, str]:
    provider, _, reference = value.partition(":")
    return provider.lower(), reference


def _provider_base(provider: str, reference: str) -> tuple[str, str, str] | None:
    bucket = reference.strip("/")
    if provider in {"s3", "aws"}:
        return "s3", bucket, f"https://{bucket}.s3.amazonaws.com/"
    if provider in {"gcs", "gs", "google"}:
        return "gcs", bucket, f"https://storage.googleapis.com/{bucket}"
    if provider in {"azure", "az", "blob"}:
        account, _, container = reference.partition("/")
        container = container or "public"
        return (
            "azure",
            f"{account}/{container}",
            f"https://{account}.blob.core.windows.net/{container}",
        )
    return None


def _object_keys(body: str, limit: int = 10) -> tuple[str, ...]:
    keys: list[str] = []
    for match in _OBJECT_KEY_RE.finditer(body):
        key = match.group(1).strip()
        if key:
            keys.append(key)
        if len(keys) >= limit:
            break
    return tuple(keys)


def _label_of(value: str) -> str:
    parts = urlsplit(value)
    if parts.path.strip("/"):
        return parts.path.rstrip("/").rsplit("/", 1)[-1]
    return (parts.hostname or value).split(".")[0]


def _org_label(ctx: CheckContext) -> str | None:
    for selector in ctx.definition.targets:
        value = selector.value.strip().lower()
        if selector.kind is TargetKind.DOMAIN:
            labels = [item for item in value.split(".") if item]
            if len(labels) >= 2:
                return labels[-2]
    return None


def _mask(value: str) -> str:
    """A short, non-reversible fingerprint of a secret-shaped string (never the value)."""
    digest = hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:10]
    return f"<masked:{digest}>"


def _aws_sigv4_headers(
    access_key: str, secret_key: str, *, region: str = "us-east-1"
) -> dict[str, str]:
    """Minimal SigV4 headers for a ``sts:GetCallerIdentity`` POST (read-only, no IAM permission).

    Documented permission list: the call needs no permission beyond the caller's own identity,
    and nothing else is enumerated. Kept here so the optional validation path is self-contained.
    """
    service = "sts"
    host = "sts.amazonaws.com"
    now = datetime.now(UTC)
    amz_date = now.strftime("%Y%m%dT%H%M%SZ")
    date_stamp = now.strftime("%Y%m%d")
    body = "Action=GetCallerIdentity&Version=2011-06-15"
    payload_hash = hashlib.sha256(body.encode()).hexdigest()
    canonical_headers = f"host:{host}\nx-amz-date:{amz_date}\n"
    signed_headers = "host;x-amz-date"
    canonical_request = "\n".join(
        ["POST", "/", "", canonical_headers, signed_headers, payload_hash]
    )
    scope = f"{date_stamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join(
        [
            "AWS4-HMAC-SHA256",
            amz_date,
            scope,
            hashlib.sha256(canonical_request.encode()).hexdigest(),
        ]
    )
    key = _sign(("AWS4" + secret_key).encode(), date_stamp)
    key = _sign(key, region)
    key = _sign(key, service)
    key = _sign(key, "aws4_request")
    signature = hmac.new(key, string_to_sign.encode(), hashlib.sha256).hexdigest()
    authorization = (
        f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )
    return {
        "Host": host,
        "X-Amz-Date": amz_date,
        "Authorization": authorization,
        "Content-Type": "application/x-www-form-urlencoded",
    }


def _sign(key: bytes, message: str) -> bytes:
    return hmac.new(key, message.encode(), hashlib.sha256).digest()
