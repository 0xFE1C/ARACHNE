"""The cloud-provider coverage ledger (WP-12, REQ-DET-017).

A partial multi-cloud story is worse than a stated one. M5's first three provider families
(AWS, Azure, GCP) are covered by the existing read-only checks, but a customer on OCI,
Alibaba Cloud or DigitalOcean had no posture coverage **and no statement that they were
unsupported**. This table is that statement: one row per provider, either

``supported``
    a mapped set of read-only checks exists. :attr:`ProviderEntry.check_ids` names them and
    every id must be in the registry. A provider with a newly added check also declares the
    exact ``(GET, path)`` operations that check may use, which is the allowlist the
    operation test asserts against.
``not_supported``
    the provider is deliberately not covered in this release. The ``reason`` is the recorded
    decision — the honest outcome when the provider's API needs a signing scheme this
    programme will not guess, rather than a token check that misreports posture.

The vocabulary mirrors :mod:`arachne.modules.protocol_matrix`: a *declared* capability must
have an owner or an explicit reason, and :func:`problems` is the cross-reference the test
suite calls. A row added to one surface and not the other fails the build.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any, Literal

__all__ = [
    "CLOUD_PROVIDER_MATRIX",
    "PROVIDER_LEDGER_VERSION",
    "CloudProviderEntry",
    "CloudProviderState",
    "ReadOperation",
    "by_provider",
    "counts",
    "problems",
    "to_dict",
]

#: Bumped when a row changes state or owner: the coverage ledger records it.
PROVIDER_LEDGER_VERSION = "1.0"

CloudProviderState = Literal["supported", "not_supported"]

#: ``(HTTP method, path template)``. Only GET is a read; the constructor refuses anything
#: else, so an operation that mutates a cloud resource is unrepresentable.
ReadOperation = tuple[str, str]


@dataclass(frozen=True, slots=True)
class CloudProviderEntry:
    """One row: what the product claims about one cloud provider."""

    provider: str
    display: str
    state: CloudProviderState
    check_ids: tuple[str, ...]
    reason: str
    operations: tuple[ReadOperation, ...] = ()

    def __post_init__(self) -> None:
        for method, path in self.operations:
            if method != "GET":
                msg = (
                    f"cloud provider {self.provider!r}: operation {method} {path} is not a "
                    "read (only GET is allowed)"
                )
                raise ValueError(msg)
            if not path.startswith("/"):
                msg = (
                    f"cloud provider {self.provider!r}: operation path {path!r} must be "
                    "absolute (start with '/')"
                )
                raise ValueError(msg)

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "display": self.display,
            "state": self.state,
            "checks": list(self.check_ids),
            "operations": [{"method": method, "path": path} for method, path in self.operations],
            "reason": self.reason,
        }


#: The providers the product names, and what it does about each one.
#:
#: AWS/Azure/GCP rows acknowledge the coverage M5 already had. DigitalOcean's row owns the
#: new read-only posture check and its four GET operations. OCI and Alibaba Cloud are the
#: explicit gaps: both need a request-signing scheme (OCI RSA-SHA256 with a tenancy key
#: fingerprint, Alibaba RPC HMAC-SHA1 over canonicalised parameters) whose partial
#: implementation would misreport posture, so this release states the gap instead.
CLOUD_PROVIDER_MATRIX: tuple[CloudProviderEntry, ...] = (
    CloudProviderEntry(
        provider="aws",
        display="Amazon Web Services",
        state="supported",
        check_ids=(
            "m5.bucket-enumerator",
            "m5.iam-review",
            "m5.cloud-posture",
            "m5.leaked-cloud-keys",
            # WP-31 (REQ-DET-024): the read-only service posture family.
            "m5.aws-s3-public-acl",
            "m5.aws-s3-public-policy",
            "m5.aws-s3-public-access-block-missing",
            "m5.aws-s3-unencrypted",
            "m5.aws-s3-versioning-disabled",
            "m5.aws-s3-logging-disabled",
            "m5.aws-iam-root-mfa-disabled",
            "m5.aws-iam-root-access-key",
            "m5.aws-iam-password-policy-weak",
            "m5.aws-iam-user-wildcard-policy",
            "m5.aws-iam-role-public-trust",
            "m5.aws-ec2-imdsv1-allowed",
            "m5.aws-ec2-security-group-open-ssh",
            "m5.aws-ec2-security-group-open-rdp",
            "m5.aws-ec2-ebs-unencrypted",
            "m5.aws-rds-publicly-accessible",
            "m5.aws-rds-unencrypted",
            "m5.aws-eks-public-endpoint",
            "m5.aws-eks-audit-logging-off",
            "m5.aws-lambda-policy-public",
            "m5.aws-lambda-url-auth-none",
            "m5.aws-cloudtrail-not-multiregion",
            "m5.aws-cloudtrail-logging-disabled",
            "m5.aws-kms-key-policy-public",
            "m5.aws-kms-rotation-disabled",
            "m5.aws-sqs-policy-public",
            "m5.aws-sns-topic-public",
            "m5.aws-ecr-repository-public",
            "m5.aws-ecr-scan-on-push-disabled",
            "m5.aws-account-public-access-block-missing",
            "m5.aws-account-ebs-encryption-off",
        ),
        reason=(
            "Public storage, IAM policy, a declared read-only config snapshot and "
            "credential artifacts are covered by the existing read-only checks. WP-31 adds "
            "the read-only service posture family (S3, IAM, EC2 and instance metadata, RDS, "
            "EKS, Lambda, CloudTrail, KMS, SQS/SNS, ECR and the account-level defaults); its "
            "closed operation allowlist is "
            "``arachne.modules.m5.aws_posture.AWS_READ_OPERATIONS``, whose GET half is "
            "declared here and whose other half is the two JSON-RPC ``POST`` reads KMS and "
            "ECR only expose (both read-verb actions, both refused by ``AwsReadOperation`` "
            "if they are not). No create, modify or delete call is representable."
        ),
        operations=(
            ("GET", "/s3/"),
            ("GET", "/s3/{bucket}"),
            ("GET", "/s3control/v20180820/configuration/publicAccessBlock"),
            ("GET", "/iam/"),
            ("GET", "/ec2/"),
            ("GET", "/rds/"),
            ("GET", "/eks/clusters"),
            ("GET", "/eks/clusters/{cluster}"),
            ("GET", "/lambda/2015-03-31/functions/"),
            ("GET", "/lambda/2015-03-31/functions/{function}/policy"),
            ("GET", "/lambda/2021-10-31/functions/{function}/url"),
            ("GET", "/cloudtrail/"),
            ("GET", "/sqs/"),
            ("GET", "/sns/"),
        ),
    ),
    CloudProviderEntry(
        provider="azure",
        display="Microsoft Azure",
        state="supported",
        check_ids=("m5.bucket-enumerator", "m5.azure-mi-audit", "m5.cloud-posture"),
        reason=(
            "Blob exposure, managed-identity metadata and a declared read-only config "
            "snapshot are covered by the existing read-only checks."
        ),
    ),
    CloudProviderEntry(
        provider="gcp",
        display="Google Cloud Platform",
        state="supported",
        check_ids=("m5.bucket-enumerator", "m5.gcp-sa-keys", "m5.cloud-posture"),
        reason=(
            "Storage exposure, service-account key material and a declared read-only config "
            "snapshot are covered by the existing read-only checks."
        ),
    ),
    CloudProviderEntry(
        provider="digitalocean",
        display="DigitalOcean",
        state="supported",
        check_ids=("m5.do-posture",),
        reason=(
            "A read-only posture check reads the account's droplets, managed databases, "
            "load balancers and firewalls with a vault-supplied cloud-token credential. "
            "GET only."
        ),
        operations=(
            ("GET", "/v2/droplets"),
            ("GET", "/v2/databases"),
            ("GET", "/v2/load_balancers"),
            ("GET", "/v2/firewalls"),
        ),
    ),
    CloudProviderEntry(
        provider="oci",
        display="Oracle Cloud Infrastructure",
        state="not_supported",
        check_ids=(),
        reason=(
            "OCI signs every request with RSA-SHA256 over a tenancy-specific key fingerprint "
            "and an HTTP-dated canonical string. A partial signing implementation would "
            "misreport posture, so this release records the gap rather than a token check."
        ),
    ),
    CloudProviderEntry(
        provider="alibaba",
        display="Alibaba Cloud",
        state="not_supported",
        check_ids=(),
        reason=(
            "Alibaba Cloud OpenAPI (RPC style) requires HMAC-SHA1 over a canonicalised, "
            "sorted parameter string and per-API version metadata. A guessed scheme would "
            "produce false clean results, so this release records the gap explicitly."
        ),
    ),
)


def by_provider() -> dict[str, CloudProviderEntry]:
    return {entry.provider: entry for entry in CLOUD_PROVIDER_MATRIX}


def counts() -> dict[str, Any]:
    """The ledger tally: supported and not-supported provider names."""
    supported = [entry.provider for entry in CLOUD_PROVIDER_MATRIX if entry.state == "supported"]
    unsupported = [
        entry.provider for entry in CLOUD_PROVIDER_MATRIX if entry.state == "not_supported"
    ]
    return {
        "supported": supported,
        "not_supported": unsupported,
        "supported_count": len(supported),
        "not_supported_count": len(unsupported),
    }


def to_dict(entries: Sequence[CloudProviderEntry] | None = None) -> dict[str, Any]:
    table = CLOUD_PROVIDER_MATRIX if entries is None else tuple(entries)
    return {
        "version": PROVIDER_LEDGER_VERSION,
        **counts(),
        "items": [entry.to_dict() for entry in table],
    }


def problems(
    registry_check_ids: Iterable[str],
    entries: Sequence[CloudProviderEntry] | None = None,
) -> tuple[str, ...]:
    """Every way the table and the registry disagree, as sentences (empty is the gate)."""
    table = CLOUD_PROVIDER_MATRIX if entries is None else tuple(entries)
    registered = set(registry_check_ids)
    out: list[str] = []
    seen: set[str] = set()
    for entry in table:
        if entry.provider in seen:
            out.append(f"cloud provider {entry.provider!r} has more than one row")
        seen.add(entry.provider)
        if entry.state == "supported":
            if not entry.check_ids:
                out.append(f"cloud provider {entry.provider!r} is supported but names no check")
            for check_id in entry.check_ids:
                if check_id not in registered:
                    out.append(
                        f"cloud provider {entry.provider!r} names unregistered check {check_id!r}"
                    )
        else:
            if not entry.reason.strip():
                out.append(f"cloud provider {entry.provider!r} is not_supported without a reason")
            if entry.check_ids:
                out.append(
                    f"cloud provider {entry.provider!r} is not_supported but names checks "
                    f"{list(entry.check_ids)}"
                )
    return tuple(out)


def operation_offenders(
    entry: CloudProviderEntry, used: Iterable[ReadOperation]
) -> tuple[str, ...]:
    """Operations a check actually issued that are not in the provider's allowlist."""
    allowed = set(entry.operations)
    return tuple(f"{method} {path}" for method, path in used if (method, path) not in allowed)
