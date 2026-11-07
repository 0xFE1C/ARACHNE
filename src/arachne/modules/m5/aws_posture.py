"""WP-31 · AWS read-only service posture (REQ-DET-024).

Thirty-one read-only L1 checks over the defaults an AWS account's own read APIs disclose.
The requirement's scope names S3, IAM, EC2 and instance metadata, RDS, EKS, Lambda,
CloudTrail, KMS, SQS and SNS, ECR, and the account-level defaults that decide whether those
services are reachable from outside the account; this module covers each:

============================  ==========================================================
area                            checks
============================  ==========================================================
S3 (6)                          a public ACL, a public bucket policy, a missing public
                                access block, no default encryption, versioning off, no
                                server access logging
IAM (5)                         root MFA off, a root access key, no custom password
                                policy (or one shorter than 14), a wildcard user/role
                                policy, a role that trusts any principal
EC2 and metadata (4)            IMDSv1 still allowed, a security group open to the world
                                on 22 and on 3389, an unencrypted EBS volume
RDS (2)                         a publicly accessible instance, an unencrypted instance
EKS (2)                         a public cluster endpoint, audit logging off
Lambda (2)                      a resource policy that trusts any principal, a function
                                URL with ``AuthType: NONE``
CloudTrail (2)                  a single-region trail, logging stopped
KMS (2)                         a key policy that trusts any principal, rotation off on a
                                customer-managed key
SQS and SNS (2)                 a queue policy and a topic policy that trust any principal
ECR (2)                         a repository policy that trusts any principal, scan-on-push
                                off
account defaults (2)            no account-level S3 public access block, EBS encryption
                                not enabled by default
============================  ==========================================================

**Read-only is the control, and it is a closed allowlist.** Every call this module can make
is one entry of :data:`AWS_READ_OPERATIONS` — a frozen tuple of ``(action, service, method,
path)`` records whose action names are read verbs and whose methods are ``GET`` and, for the
two JSON-RPC services whose read APIs *are* ``POST`` (KMS and ECR), ``POST``. The operation
object is the parameter: :meth:`AwsReadClient.call` refuses any object that is not in the
tuple, and :class:`AwsReadOperation` refuses a mutation action name or an unknown method at
construction, so "the scanner issued a Create/Modify/Delete call" is unrepresentable rather
than merely untested. ``tests/unit/test_aws_posture.py`` asserts the table and the refusal;
``tests/integration/test_wp31_scan.py`` asserts it on the wire, against the fixture's own
request log.

**Credentials come from the vault and never cross the module boundary.** A check declares
``requires_credentials=("aws-role",)`` and calls the broker
(:meth:`~arachne.creds.broker.CredentialBroker.authorized_aws`), which selects a credential of
that kind scoped to the endpoint URL, signs one request with SigV4 and hands back a redacted
exchange. The access key id, the secret and any session token stay inside ``arachne.creds``;
no finding, evidence payload, detail string or log line in this module ever carries one, which
is what the integration test asserts against the planted lab secret.

**The endpoint is declared, not guessed.** The target reference is ``aws-posture:<base>`` (a
cloud target). ``<base>`` is the read-only API base the operator's least-privilege role is
scoped to; the checks join ``/<service><path>`` onto it and sign for
``ARACHNE_M5_AWS_REGION``. The reader accepts both response envelopes AWS read APIs return —
JSON (the JSON protocols) and XML (the Query and S3 REST protocols) — and normalizes the
documented field names, so a policy is evaluated over the account's own fields rather than
over a status code.

**Nothing is exhaustive.** One finding is established from the first page: each check
enumerates at most ``ARACHNE_M5_AWS_MAX_RESOURCES`` resources (default 5) and stops, because
"this bucket is public" is decided by that bucket, not by the account's full inventory.
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from collections.abc import AsyncIterator, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, ClassVar, Final
from urllib.parse import urlencode

from arachne.core.proof import ProofLevel
from arachne.core.results import CheckResult
from arachne.core.target import TargetKind
from arachne.core.vault import AWS_CREDENTIAL_KINDS
from arachne.modules.base import Asset, CheckMetadata, Module, SeverityHint
from arachne.modules.context import CheckContext
from arachne.modules.m5.support import EndpointCheck, http_or_skip, m5_candidate, skip

__all__ = [
    "AWS_POSTURE_CHECKS",
    "AWS_READ_OPERATIONS",
    "MUTATION_VERBS",
    "READ_VERBS",
    "AwsOperationError",
    "AwsReadClient",
    "AwsReadOperation",
    "AwsRefusedError",
    "AwsReply",
    "aws_checks",
]

#: The family tag and signal every finding carries, so one heuristic rule covers the set.
FAMILY: Final = "aws-posture"
SIGNAL: Final = "aws-posture"

#: The reference prefix the checks accept (a cloud target: ``aws-posture:<base>``).
REFERENCE: Final = "aws-posture"

#: The action-name prefixes a read operation may carry. A mutation verb is refused by
#: :class:`AwsReadOperation` before it can enter the table.
READ_VERBS: Final[tuple[str, ...]] = ("List", "Get", "Describe", "Head", "Query", "Lookup")

#: Mutation verbs this module refuses by name. The list is deliberately broad and matched as a
#: prefix, so a new ``CreateSomething`` cannot slip into the table unnoticed; it is the
#: readable half of the allowlist test, which also asserts the closed tuple.
MUTATION_VERBS: Final[tuple[str, ...]] = (
    "Abort",
    "Accept",
    "Add",
    "Allocate",
    "Apply",
    "Associate",
    "Attach",
    "Authorize",
    "BatchWrite",
    "Cancel",
    "Complete",
    "Copy",
    "Create",
    "Delete",
    "Deregister",
    "Detach",
    "Disable",
    "Disassociate",
    "Enable",
    "Import",
    "Invoke",
    "Modify",
    "Monitor",
    "Move",
    "Publish",
    "Put",
    "Reboot",
    "Register",
    "Release",
    "Remove",
    "Replace",
    "Reset",
    "Restore",
    "Resume",
    "Revoke",
    "Rotate",
    "Run",
    "Schedule",
    "Send",
    "Set",
    "Start",
    "Stop",
    "Tag",
    "Terminate",
    "Unmonitor",
    "Untag",
    "Update",
    "Upload",
    "Withdraw",
)

_METHODS: Final[frozenset[str]] = frozenset({"GET", "POST"})
_JSON_CONTENT_TYPE: Final = "application/x-amz-json-1.1"


class AwsOperationError(ValueError):
    """An operation that is not a read, or not one this build knows, was requested."""


# --------------------------------------------------------------------------- operations
@dataclass(frozen=True, slots=True)
class AwsReadOperation:
    """One read-only AWS API action, as the allowlist represents it.

    ``path`` and a ``query`` value may carry ``{name}`` placeholders the caller fills from a
    resource identifier; the placeholders are data, never a verb. ``target`` is the
    ``X-Amz-Target`` a JSON-RPC read needs (KMS, ECR) and is empty for every other protocol.
    """

    action: str
    service: str
    method: str
    path: str
    version: str = ""
    query: tuple[tuple[str, str], ...] = ()
    target: str = ""

    def __post_init__(self) -> None:
        if self.method not in _METHODS:
            msg = f"{self.action}: {self.method} is not a read method (GET or POST)"
            raise AwsOperationError(msg)
        if not self.action.startswith(READ_VERBS):
            msg = f"{self.action!r} does not name a read action"
            raise AwsOperationError(msg)
        if any(word in self.action for word in MUTATION_VERBS):
            msg = f"{self.action!r} names a mutation and is unrepresentable"
            raise AwsOperationError(msg)
        if not self.path.startswith("/"):
            msg = f"{self.action}: path {self.path!r} must be absolute"
            raise AwsOperationError(msg)
        if self.method == "POST" and not self.target:
            msg = f"{self.action}: a POST read needs its X-Amz-Target"
            raise AwsOperationError(msg)
        if self.method == "POST" and not self.action.startswith(("List", "Describe", "Get")):
            msg = f"{self.action}: only List/Describe/Get may be read over POST"
            raise AwsOperationError(msg)

    @property
    def key(self) -> str:
        return f"{self.service}:{self.action}"


# --------------------------------------------------------------------------- S3
_LIST_BUCKETS = AwsReadOperation(action="ListBuckets", service="s3", method="GET", path="/")
_GET_BUCKET_ACL = AwsReadOperation(
    action="GetBucketAcl", service="s3", method="GET", path="/{bucket}", query=(("acl", ""),)
)
_GET_BUCKET_POLICY = AwsReadOperation(
    action="GetBucketPolicy", service="s3", method="GET", path="/{bucket}", query=(("policy", ""),)
)
_GET_BUCKET_PUBLIC_ACCESS_BLOCK = AwsReadOperation(
    action="GetBucketPublicAccessBlock",
    service="s3",
    method="GET",
    path="/{bucket}",
    query=(("publicAccessBlock", ""),),
)
_GET_BUCKET_ENCRYPTION = AwsReadOperation(
    action="GetBucketEncryption",
    service="s3",
    method="GET",
    path="/{bucket}",
    query=(("encryption", ""),),
)
_GET_BUCKET_VERSIONING = AwsReadOperation(
    action="GetBucketVersioning",
    service="s3",
    method="GET",
    path="/{bucket}",
    query=(("versioning", ""),),
)
_GET_BUCKET_LOGGING = AwsReadOperation(
    action="GetBucketLogging",
    service="s3",
    method="GET",
    path="/{bucket}",
    query=(("logging", ""),),
)
_GET_ACCOUNT_PUBLIC_ACCESS_BLOCK = AwsReadOperation(
    action="GetPublicAccessBlock",
    service="s3control",
    method="GET",
    path="/v20180820/configuration/publicAccessBlock",
)

# --------------------------------------------------------------------------- IAM
_GET_ACCOUNT_SUMMARY = AwsReadOperation(
    action="GetAccountSummary", service="iam", method="GET", path="/", version="2010-05-08"
)
_GET_ACCOUNT_PASSWORD_POLICY = AwsReadOperation(
    action="GetAccountPasswordPolicy",
    service="iam",
    method="GET",
    path="/",
    version="2010-05-08",
)
_GET_ACCOUNT_AUTHORIZATION_DETAILS = AwsReadOperation(
    action="GetAccountAuthorizationDetails",
    service="iam",
    method="GET",
    path="/",
    version="2010-05-08",
)

# --------------------------------------------------------------------------- EC2
_DESCRIBE_INSTANCES = AwsReadOperation(
    action="DescribeInstances", service="ec2", method="GET", path="/", version="2016-11-15"
)
_DESCRIBE_SECURITY_GROUPS = AwsReadOperation(
    action="DescribeSecurityGroups", service="ec2", method="GET", path="/", version="2016-11-15"
)
_DESCRIBE_VOLUMES = AwsReadOperation(
    action="DescribeVolumes", service="ec2", method="GET", path="/", version="2016-11-15"
)
_GET_EBS_ENCRYPTION_BY_DEFAULT = AwsReadOperation(
    action="GetEbsEncryptionByDefault",
    service="ec2",
    method="GET",
    path="/",
    version="2016-11-15",
)

# --------------------------------------------------------------------------- RDS
_DESCRIBE_DB_INSTANCES = AwsReadOperation(
    action="DescribeDBInstances", service="rds", method="GET", path="/", version="2014-10-31"
)

# --------------------------------------------------------------------------- EKS
_LIST_CLUSTERS = AwsReadOperation(
    action="ListClusters", service="eks", method="GET", path="/clusters"
)
_DESCRIBE_CLUSTER = AwsReadOperation(
    action="DescribeCluster", service="eks", method="GET", path="/clusters/{cluster}"
)

# --------------------------------------------------------------------------- Lambda
_LIST_FUNCTIONS = AwsReadOperation(
    action="ListFunctions", service="lambda", method="GET", path="/2015-03-31/functions/"
)
_GET_FUNCTION_POLICY = AwsReadOperation(
    action="GetPolicy",
    service="lambda",
    method="GET",
    path="/2015-03-31/functions/{function}/policy",
)
_GET_FUNCTION_URL_CONFIG = AwsReadOperation(
    action="GetFunctionUrlConfig",
    service="lambda",
    method="GET",
    path="/2021-10-31/functions/{function}/url",
)

# --------------------------------------------------------------------------- CloudTrail
_DESCRIBE_TRAILS = AwsReadOperation(
    action="DescribeTrails", service="cloudtrail", method="GET", path="/", version="2013-11-01"
)
_GET_TRAIL_STATUS = AwsReadOperation(
    action="GetTrailStatus",
    service="cloudtrail",
    method="GET",
    path="/",
    version="2013-11-01",
    query=(("Name", "{trail}"),),
)

# --------------------------------------------------------------------------- KMS (JSON-RPC)
_LIST_KEYS = AwsReadOperation(
    action="ListKeys",
    service="kms",
    method="POST",
    path="/",
    target="TrentService.ListKeys",
)
_DESCRIBE_KEY = AwsReadOperation(
    action="DescribeKey",
    service="kms",
    method="POST",
    path="/",
    target="TrentService.DescribeKey",
)
_GET_KEY_POLICY = AwsReadOperation(
    action="GetKeyPolicy",
    service="kms",
    method="POST",
    path="/",
    target="TrentService.GetKeyPolicy",
)
_GET_KEY_ROTATION_STATUS = AwsReadOperation(
    action="GetKeyRotationStatus",
    service="kms",
    method="POST",
    path="/",
    target="TrentService.GetKeyRotationStatus",
)

# --------------------------------------------------------------------------- SQS
_LIST_QUEUES = AwsReadOperation(
    action="ListQueues", service="sqs", method="GET", path="/", version="2012-11-05"
)
_GET_QUEUE_ATTRIBUTES = AwsReadOperation(
    action="GetQueueAttributes",
    service="sqs",
    method="GET",
    path="/",
    version="2012-11-05",
    query=(("QueueUrl", "{queue}"), ("AttributeName", "Policy")),
)

# --------------------------------------------------------------------------- SNS
_LIST_TOPICS = AwsReadOperation(
    action="ListTopics", service="sns", method="GET", path="/", version="2010-03-31"
)
_GET_TOPIC_ATTRIBUTES = AwsReadOperation(
    action="GetTopicAttributes",
    service="sns",
    method="GET",
    path="/",
    version="2010-03-31",
    query=(("TopicArn", "{topic}"),),
)

# --------------------------------------------------------------------------- ECR (JSON-RPC)
_DESCRIBE_REPOSITORIES = AwsReadOperation(
    action="DescribeRepositories",
    service="ecr",
    method="POST",
    path="/",
    target="AmazonEC2ContainerRegistry_V20150921.DescribeRepositories",
)
_GET_REPOSITORY_POLICY = AwsReadOperation(
    action="GetRepositoryPolicy",
    service="ecr",
    method="POST",
    path="/",
    target="AmazonEC2ContainerRegistry_V20150921.GetRepositoryPolicy",
)

#: **The operation allowlist.** Every AWS call this module can make is one entry here; the
#: client refuses an object that is not equal to one of them, and each entry refused a
#: mutation action name at construction. Adding a capability means adding a read entry.
AWS_READ_OPERATIONS: Final[tuple[AwsReadOperation, ...]] = (
    _LIST_BUCKETS,
    _GET_BUCKET_ACL,
    _GET_BUCKET_POLICY,
    _GET_BUCKET_PUBLIC_ACCESS_BLOCK,
    _GET_BUCKET_ENCRYPTION,
    _GET_BUCKET_VERSIONING,
    _GET_BUCKET_LOGGING,
    _GET_ACCOUNT_PUBLIC_ACCESS_BLOCK,
    _GET_ACCOUNT_SUMMARY,
    _GET_ACCOUNT_PASSWORD_POLICY,
    _GET_ACCOUNT_AUTHORIZATION_DETAILS,
    _DESCRIBE_INSTANCES,
    _DESCRIBE_SECURITY_GROUPS,
    _DESCRIBE_VOLUMES,
    _GET_EBS_ENCRYPTION_BY_DEFAULT,
    _DESCRIBE_DB_INSTANCES,
    _LIST_CLUSTERS,
    _DESCRIBE_CLUSTER,
    _LIST_FUNCTIONS,
    _GET_FUNCTION_POLICY,
    _GET_FUNCTION_URL_CONFIG,
    _DESCRIBE_TRAILS,
    _GET_TRAIL_STATUS,
    _LIST_KEYS,
    _DESCRIBE_KEY,
    _GET_KEY_POLICY,
    _GET_KEY_ROTATION_STATUS,
    _LIST_QUEUES,
    _GET_QUEUE_ATTRIBUTES,
    _LIST_TOPICS,
    _GET_TOPIC_ATTRIBUTES,
    _DESCRIBE_REPOSITORIES,
    _GET_REPOSITORY_POLICY,
)

_OPERATION_SET: Final[frozenset[AwsReadOperation]] = frozenset(AWS_READ_OPERATIONS)


# --------------------------------------------------------------------------- reference
def _base_for(value: str) -> str | None:
    """The read-only API base an ``aws-posture:<base>`` cloud reference names, or ``None``."""
    provider, separator, reference = value.strip().partition(":")
    if not separator or provider.lower() not in {REFERENCE, "awsposture"}:
        return None
    rest = reference.strip()
    if not rest:
        return None
    return rest if "://" in rest else f"https://{rest}"


# --------------------------------------------------------------------------- responses
class AwsRefusedError(RuntimeError):
    """A read could not be made: no credential, a refused credential, or a failed call."""


@dataclass(frozen=True, slots=True)
class AwsReply:
    """One decoded answer: its status, the normalized document (``None`` on 404) and the
    redacted exchange the evidence carries."""

    action: str
    status: int
    data: Any
    exchange: Any = None

    @property
    def missing(self) -> bool:
        """True when the API answered "there is no such thing" (S3/IAM return 404 for one)."""
        return self.status == 404 and self.data is None

    @property
    def failed(self) -> bool:
        """True when the call itself failed (a 5xx, a 4xx other than 404)."""
        return not 200 <= self.status < 300 and self.status != 404

    def mapping(self) -> Mapping[str, Any]:
        return self.data if isinstance(self.data, Mapping) else {}


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _xml_data(element: ET.Element) -> Any:
    """Flatten an XML element into the same dict/list shape a JSON answer has.

    A leaf is its text; a node whose children repeat a tag becomes a list under that tag; a
    node with distinct children becomes a mapping. The documented field names survive, which is
    all a policy reads.
    """
    children = list(element)
    if not children:
        return (element.text or "").strip()
    grouped: dict[str, list[Any]] = {}
    for child in children:
        grouped.setdefault(_local(child.tag), []).append(_xml_data(child))
    return {tag: (values[0] if len(values) == 1 else values) for tag, values in grouped.items()}


def decode_document(body: str) -> Any:
    """Decode an AWS answer: XML for the Query/S3 protocols, JSON for the JSON protocols."""
    stripped = body.lstrip()
    if not stripped:
        return None
    if stripped.startswith("<"):
        try:
            return _xml_data(ET.fromstring(stripped))  # noqa: S314 - a bounded API answer
        except ET.ParseError as exc:
            raise AwsRefusedError(f"the API answer was not valid XML: {exc}") from exc
    try:
        return json.loads(stripped)
    except json.JSONDecodeError as exc:
        raise AwsRefusedError(f"the API answer was not valid JSON: {exc}") from exc


# --- field access (case-insensitive; JSON camelCase and XML PascalCase both read) ----
_ENVELOPE_KEYS: Final[frozenset[str]] = frozenset({"member", "item", "set", "entry"})


def get(document: Any, *names: str, default: Any = None) -> Any:
    """The first value whose key matches one of ``names`` case-insensitively."""
    if not isinstance(document, Mapping):
        return default
    wanted = {name.lower() for name in names}
    for key, value in document.items():
        if str(key).lower() in wanted:
            return value
    return default


def entries(value: Any) -> list[Mapping[str, Any]]:
    """``value`` as a list of mappings, unwrapping the envelopes AWS wraps lists in."""
    if value is None:
        return []
    if isinstance(value, Mapping):
        if len(value) == 1:
            only_key, only_value = next(iter(value.items()))
            if str(only_key).lower() in _ENVELOPE_KEYS:
                return entries(only_value)
        # A single-key mapping whose only value is a list is that list (``{"Buckets": [...]}``)
        inner = [item for item in value.values() if isinstance(item, Sequence)]
        if len(value) == 1 and inner and not isinstance(next(iter(value.values())), str):
            return entries(inner[0])
        return [value]
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        out: list[Mapping[str, Any]] = []
        for item in value:
            out.extend(entries(item))
        return out
    return []


def collect(document: Any, *names: str) -> list[Mapping[str, Any]]:
    """Every mapping found under a key matching one of ``names``, at any depth."""
    found: list[Mapping[str, Any]] = []
    if isinstance(document, Mapping):
        for key, value in document.items():
            if str(key).lower() in {name.lower() for name in names}:
                found.extend(entries(value))
            found.extend(collect(value, *names))
    elif isinstance(document, Sequence) and not isinstance(document, (str, bytes)):
        for item in document:
            found.extend(collect(item, *names))
    return found


def text_of(document: Any, *names: str, default: str = "") -> str:
    value = get(document, *names)
    if value is None:
        return default
    if isinstance(value, (Mapping, list)):
        return default
    return str(value)


def bool_of(document: Any, *names: str, default: bool | None = None) -> bool | None:
    value = get(document, *names)
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"true", "1", "yes", "enabled"}:
            return True
        if lowered in {"false", "0", "no", "disabled", ""}:
            return False
    return default


def int_of(document: Any, *names: str, default: int | None = None) -> int | None:
    value = get(document, *names)
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return default


def document_of(value: Any) -> Any:
    """A nested policy document: already a mapping, or a JSON/URL-encoded string."""
    if isinstance(value, Mapping):
        return value
    if isinstance(value, str) and value.strip():
        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return None
    return None


def public_statements(policy: Any) -> list[Mapping[str, Any]]:
    """The ``Allow`` statements of a policy document whose principal is ``*``.

    A statement scoped by a condition (a source VPC, a source IP range, an organisation id, a
    source ARN/account/owner) is deliberately excluded: that is a policy with an audience, not
    a public one. The check reports those separately from the truly unconditional ones only in
    its detail; the finding is the unconditional principal.
    """
    document = document_of(policy)
    if not isinstance(document, Mapping):
        return []
    statements = entries(get(document, "Statement"))
    out: list[Mapping[str, Any]] = []
    for statement in statements:
        effect = text_of(statement, "Effect")
        if effect and effect.lower() != "allow":
            continue
        principal = get(statement, "Principal")
        if not _is_any_principal(principal):
            continue
        if get(statement, "Condition") is not None:
            continue
        out.append(statement)
    return out


_CONDITIONAL_PRINCIPALS: Final[tuple[str, ...]] = (
    "aws:sourcevpc",
    "aws:sourcevpce",
    "aws:sourceip",
    "aws:sourcearn",
    "aws:sourceaccount",
    "aws:sourceowner",
    "aws:principalorgid",
    "aws:principalarn",
    "aws:principalaccount",
)


def condition_scoped(policy: Any) -> bool:
    """True when a policy's ``*`` principal is constrained by a public-looking condition."""
    document = document_of(policy)
    if not isinstance(document, Mapping):
        return False
    for statement in entries(get(document, "Statement")):
        if not _is_any_principal(get(statement, "Principal")):
            continue
        condition = get(statement, "Condition")
        if isinstance(condition, Mapping):
            for key in condition:
                if str(key).lower() in _CONDITIONAL_PRINCIPALS:
                    return True
    return False


def _is_any_principal(principal: Any) -> bool:
    if principal == "*":
        return True
    if isinstance(principal, str):
        return principal.strip() == "*"
    if isinstance(principal, Mapping):
        return any(_is_any_principal(value) for value in principal.values())
    if isinstance(principal, Sequence) and not isinstance(principal, (str, bytes)):
        return any(_is_any_principal(item) for item in principal)
    return False


# --------------------------------------------------------------------------- the client
class AwsReadClient:
    """Signs and issues read-only AWS calls, bounded by :data:`AWS_READ_OPERATIONS`.

    The client owns no credential: every call goes through the broker's ``authorized_aws``,
    which signs it and returns a redacted exchange. What the client does own is the *guard*:
    the operation must be a member of the allowlist, and the URL is built from that operation
    alone, so a check cannot smuggle a path or a query of its own invention into a call.
    """

    def __init__(self, ctx: CheckContext, base: str, *, region: str) -> None:
        self.ctx = ctx
        self.base = base.rstrip("/")
        self.region = region
        self.issued: list[str] = []

    def url_for(
        self,
        operation: AwsReadOperation,
        *,
        values: Mapping[str, str] | None = None,
        extra_query: Sequence[tuple[str, str]] = (),
    ) -> str:
        if operation not in _OPERATION_SET:
            msg = f"{operation.action!r} is not a declared read operation"
            raise AwsOperationError(msg)
        filled = values or {}
        path = operation.path.format(**filled) if filled else operation.path
        params: list[tuple[str, str]] = []
        if operation.version:
            params.append(("Action", operation.action))
            params.append(("Version", operation.version))
        for name, value in operation.query:
            params.append((name, value.format(**filled) if filled else value))
        params.extend(extra_query)
        url = f"{self.base}/{operation.service}{path}"
        if params:
            url = f"{url}?{urlencode(params)}"
        return url

    async def call(
        self,
        operation: AwsReadOperation,
        *,
        values: Mapping[str, str] | None = None,
        payload: bytes = b"",
        extra_query: Sequence[tuple[str, str]] = (),
        required: bool = True,
    ) -> AwsReply:
        """Issue one read and decode its answer.

        ``required`` is the difference between "this is the call the check is about" (a
        failure is reported as a skip, because the posture cannot be told) and "this is one
        resource's sub-document" (a 404 is a fact about that resource and a mapping is
        returned with ``data=None``).
        """
        http, skipped = http_or_skip(self.ctx)
        if skipped is not None:
            raise AwsRefusedError(skipped.detail or "no HTTP client in this run")
        credentials = self.ctx.credentials
        if credentials is None:
            raise AwsRefusedError("no credential broker is wired for this step")
        url = self.url_for(operation, values=values, extra_query=extra_query)
        headers = {"Accept": "application/json"}
        body = payload
        if operation.target:
            headers["X-Amz-Target"] = operation.target
            headers["Content-Type"] = _JSON_CONTENT_TYPE
            body = payload or b"{}"
        exchange = await credentials.authorized_aws(
            http,
            url=url,
            method=operation.method,
            service=operation.service,
            region=self.region,
            payload=body,
            headers=headers,
        )
        if exchange is None:
            raise AwsRefusedError(
                f"no aws-role credential was released for {operation.service} "
                "(unselected, unscoped or revoked); the refusal is on the audit trail"
            )
        self.issued.append(operation.action)
        status = int(exchange.status_code)
        if status in {401, 403}:
            raise AwsRefusedError(
                f"the {operation.service} API refused the credential (HTTP {status}); no "
                "unsigned fallback is attempted"
            )
        if status == 404:
            return AwsReply(action=operation.action, status=status, data=None, exchange=exchange)
        if not exchange.ok:
            if required:
                raise AwsRefusedError(
                    f"the {operation.service} API answered HTTP {status} for "
                    f"{operation.action}; the posture cannot be established"
                )
            return AwsReply(action=operation.action, status=status, data=None, exchange=exchange)
        try:
            data = decode_document(exchange.body)
        except AwsRefusedError:
            if required:
                raise
            data = None
        return AwsReply(action=operation.action, status=status, data=data, exchange=exchange)


# --------------------------------------------------------------------------- observations
@dataclass(frozen=True, slots=True)
class _Observation:
    """One policy breach on one resource — the unit a check emits."""

    policy: str
    resource: str
    detail: str
    observed: Mapping[str, Any] = field(default_factory=dict)
    severity: str = "medium"
    title: str = ""
    exchanges: tuple[Any, ...] = ()
    service: str = ""


# --------------------------------------------------------------------------- base check
class _AwsPostureCheck:
    """The family's shared shape: resolve the base, get a client, evaluate, report.

    A concrete check declares its metadata, the service tag, the read actions it issues and an
    :meth:`evaluate` that returns observations. Everything else — the credential gate, the
    client construction, the skip wording, the candidate shape — is here, so the thirty-one
    checks read as a catalogue of account mistakes rather than thirty-one copies of a
    preamble.

    A plain mixin rather than a :class:`~arachne.modules.base.Module` subclass, for the same
    reason WP-29's ``_ArtifactCheck`` and WP-30's ``_ServerCheck`` are: the base refuses to be
    created without metadata and a family base has none of its own. A concrete check is
    declared ``class X(_AwsPostureCheck, EndpointCheck, Module)``.
    """

    metadata: ClassVar[CheckMetadata]
    #: The scope area the requirement names (``s3``, ``iam``, ``ec2`` ...) — the check's owner.
    service: ClassVar[str] = ""
    #: The read actions this check may issue, in order (asserted against the allowlist).
    reads: ClassVar[tuple[AwsReadOperation, ...]] = ()

    def supports(self, asset: Asset) -> bool:
        # ``super()`` resolves to ``EndpointCheck`` in a concrete check's MRO; mypy cannot see
        # a mixin's future siblings, hence the same ignore WP-12's check uses.
        return bool(super().supports(asset)) and _base_for(asset.value) is not None  # type: ignore[misc]

    async def evaluate(self, ctx: CheckContext, client: AwsReadClient) -> list[_Observation]:
        raise NotImplementedError

    async def run(self, ctx: CheckContext) -> AsyncIterator[CheckResult]:
        _client, skipped = http_or_skip(ctx)
        if skipped is not None:
            yield skipped
            return
        base = _base_for(ctx.asset.value)
        if base is None:
            yield skip(
                ctx,
                "no AWS read-only API base: declare a cloud target aws-posture:<base> (the "
                "endpoint the least-privilege read-only role is scoped to)",
            )
            return
        credentials = ctx.credentials
        if credentials is None or not credentials.selected_labels(AWS_CREDENTIAL_KINDS):
            yield skip(
                ctx,
                "no aws-role credential selected: declare one with --credential and scope it "
                "to the AWS API base (the checks never run unauthenticated)",
            )
            return
        client = AwsReadClient(ctx, base, region=ctx.config.m5.aws_region)
        try:
            observations = await self.evaluate(ctx, client)
        except AwsRefusedError as exc:
            yield skip(ctx, str(exc))
            return
        if not observations:
            yield ctx.clean(
                self._clean_title(),
                detail=(
                    f"read {len(client.issued)} documented read-only operation(s) against "
                    f"{self.service}; no breach of this policy found (each enumeration is "
                    f"bounded at ARACHNE_M5_AWS_MAX_RESOURCES resources)"
                ),
            )
            return
        for index, observation in enumerate(observations[: _finding_cap(ctx)]):
            yield m5_candidate(
                ctx,
                observation.title or f"AWS posture: {observation.policy} on {observation.resource}",
                artifact={
                    "signal": SIGNAL,
                    "family": FAMILY,
                    "service": observation.service or self.service,
                    "policy": observation.policy,
                    "resource": observation.resource,
                    "region": client.region,
                    "observed": dict(observation.observed),
                    "severity_hint": observation.severity,
                    # The two facts a reviewer needs to accept the finding as a *read*.
                    "operations": list(dict.fromkeys(client.issued)),
                    "read_only": True,
                    "state_changed": False,
                },
                exchanges=observation.exchanges,
                cwe=self.metadata.cwe,
                confidence=0.85,
                detail=observation.detail,
                source=f"{self.service}:{observation.resource}",
            )
            if index + 1 >= _finding_cap(ctx):
                break

    def _clean_title(self) -> str:
        return f"no {self.metadata.name.replace('-', ' ')} found"


def _finding_cap(ctx: CheckContext) -> int:
    return max(1, ctx.config.m5.max_findings_per_check)


def _limit(ctx: CheckContext, items: Sequence[Any]) -> list[Any]:
    """Bound one enumeration: the first ``aws_max_resources`` entries, in order."""
    return list(items[: max(1, ctx.config.m5.aws_max_resources)])


def _exchanges(*replies: AwsReply) -> tuple[Any, ...]:
    return tuple(reply.exchange for reply in replies if reply.exchange is not None)


def _metadata(
    *,
    name: str,
    title: str,
    description: str,
    research_ref: str,
    cwe: str,
    framework: tuple[str, ...],
    compliance: tuple[str, ...],
    severity: SeverityHint,
    estimated_requests: int,
) -> CheckMetadata:
    """One check's metadata: L1, safe, read-only, default-on, credential-gated."""
    return CheckMetadata(
        id=f"m5.{name}",
        module="M5",
        name=name,
        version="1.0",
        title=title,
        description=description,
        research_ref=research_ref,
        cwe=cwe,
        framework=framework,
        compliance=compliance,
        severity_hint=severity,
        type="active",
        safe=True,
        verifiable=True,
        enabled_by_default=True,
        proof=ProofLevel.L1,
        estimated_requests=estimated_requests,
        target_kinds=(TargetKind.CLOUD,),
        requires_active_checks=True,
        requires_credentials=("aws-role",),
    )


# --------------------------------------------------------------------------- S3 checks
class AwsS3PublicAcl(_AwsPostureCheck, EndpointCheck, Module):
    """``m5.aws-s3-public-acl`` — a bucket whose ACL grants the world."""

    service = "s3"
    reads = (_LIST_BUCKETS, _GET_BUCKET_ACL)
    metadata = _metadata(
        name="aws-s3-public-acl",
        title="S3 bucket grants public access through its ACL",
        description="Lists the account's buckets and reads each bucket ACL, then reports one "
        "whose grants name AllUsers or AuthenticatedUsers — the canned ACLs that make the "
        "objects readable (or writable) by anyone. The finding carries the grantee and the "
        "permission it was given. Read-only: ListBuckets and GetBucketAcl.",
        research_ref="ch05#1",
        cwe="CWE-732",
        framework=("WSTG-CONF-11", "API8:2023", "CWE-732"),
        compliance=("CIS-3.3", "ISO-A.5.23", "ISO-A.8.3", "CSF-PR.DS-01", "PCI-3"),
        severity="high",
        estimated_requests=6,
    )

    async def evaluate(self, ctx: CheckContext, client: AwsReadClient) -> list[_Observation]:
        listing = await client.call(_LIST_BUCKETS)
        out: list[_Observation] = []
        for bucket in _limit(ctx, entries(get(listing.mapping(), "Buckets"))):
            name = text_of(bucket, "Name", "BucketName")
            if not name:
                continue
            acl = await client.call(_GET_BUCKET_ACL, values={"bucket": name}, required=False)
            grants = [
                grant
                for grant in entries(get(acl.mapping(), "Grants", "Grant"))
                if _is_public_grantee(grant)
            ]
            if not grants:
                continue
            permissions = sorted({text_of(grant, "Permission") for grant in grants} - {""})
            out.append(
                _Observation(
                    policy="aws-s3-public-acl",
                    service="s3",
                    resource=name,
                    title=f"S3 bucket ACL grants public access: {name}",
                    detail=(
                        f"bucket {name} grants {', '.join(permissions) or 'access'} to a public "
                        "grantee (AllUsers/AuthenticatedUsers)"
                    ),
                    observed={
                        "grantee": "AllUsers/AuthenticatedUsers",
                        "permissions": permissions,
                    },
                    severity="high",
                    exchanges=_exchanges(listing, acl),
                )
            )
        return out


def _is_public_grantee(grant: Mapping[str, Any]) -> bool:
    grantee = get(grant, "Grantee")
    if not isinstance(grantee, Mapping):
        return False
    uri = text_of(grantee, "URI")
    return uri.endswith(("AllUsers", "AuthenticatedUsers"))


class AwsS3PublicPolicy(_AwsPostureCheck, EndpointCheck, Module):
    """``m5.aws-s3-public-policy`` — a bucket policy that trusts any principal."""

    service = "s3"
    reads = (_LIST_BUCKETS, _GET_BUCKET_POLICY)
    metadata = _metadata(
        name="aws-s3-public-policy",
        title="S3 bucket policy allows any principal",
        description="Reads each bucket's policy and reports one whose Allow statement names "
        "Principal '*' with no condition restricting the audience. A policy whose wildcard "
        "principal is constrained by a source VPC, IP range, account or organisation "
        "condition is not reported. Read-only: ListBuckets and GetBucketPolicy.",
        research_ref="ch05#1",
        cwe="CWE-732",
        framework=("WSTG-CONF-11", "API8:2023", "CWE-732"),
        compliance=("CIS-3.3", "ISO-A.5.23", "ISO-A.8.3", "CSF-PR.DS-01", "PCI-3"),
        severity="high",
        estimated_requests=6,
    )

    async def evaluate(self, ctx: CheckContext, client: AwsReadClient) -> list[_Observation]:
        listing = await client.call(_LIST_BUCKETS)
        out: list[_Observation] = []
        for bucket in _limit(ctx, entries(get(listing.mapping(), "Buckets"))):
            name = text_of(bucket, "Name", "BucketName")
            if not name:
                continue
            reply = await client.call(_GET_BUCKET_POLICY, values={"bucket": name}, required=False)
            if reply.missing or reply.data is None:
                continue
            statements = public_statements(_policy_text(reply.data))
            if not statements:
                continue
            out.append(
                _Observation(
                    policy="aws-s3-public-policy",
                    service="s3",
                    resource=name,
                    title=f"S3 bucket policy allows any principal: {name}",
                    detail=(
                        f"bucket {name}'s policy has {len(statements)} Allow statement(s) with "
                        "Principal '*' and no restricting condition"
                    ),
                    observed={
                        "statements": len(statements),
                        "actions": sorted(
                            {
                                action
                                for statement in statements
                                for action in _actions_of(statement)
                            }
                        ),
                    },
                    severity="high",
                    exchanges=_exchanges(listing, reply),
                )
            )
        return out


def _policy_text(data: Any) -> Any:
    """A policy document from a reply body that may be the document or wrap it."""
    document = document_of(data)
    if isinstance(document, Mapping):
        nested = get(document, "Policy", "policyText", "PolicyText")
        if nested is not None:
            return nested
    return data if isinstance(data, (str, Mapping)) else ""


def _actions_of(statement: Mapping[str, Any]) -> list[str]:
    action = get(statement, "Action")
    if isinstance(action, str):
        return [action]
    if isinstance(action, Sequence) and not isinstance(action, (str, bytes)):
        return [str(item) for item in action]
    return []


class AwsS3PublicAccessBlockMissing(_AwsPostureCheck, EndpointCheck, Module):
    """``m5.aws-s3-public-access-block-missing`` — no public access block on a bucket."""

    service = "s3"
    reads = (_LIST_BUCKETS, _GET_BUCKET_PUBLIC_ACCESS_BLOCK)
    metadata = _metadata(
        name="aws-s3-public-access-block-missing",
        title="S3 bucket has no complete public access block",
        description="Reads each bucket's PublicAccessBlockConfiguration and reports one that "
        "is absent or leaves any of the four switches off. The block is the account's own "
        "guard against a future public ACL or policy, so an incomplete one is the finding even "
        "while today's bucket happens to be private. Read-only: ListBuckets and "
        "GetBucketPublicAccessBlock.",
        research_ref="ch05#1",
        cwe="CWE-16",
        framework=("WSTG-CONF-11", "API8:2023", "CWE-16"),
        compliance=("CIS-3.3", "ISO-A.8.3", "CSF-PR.DS-01", "PCI-1"),
        severity="low",
        estimated_requests=6,
    )

    async def evaluate(self, ctx: CheckContext, client: AwsReadClient) -> list[_Observation]:
        listing = await client.call(_LIST_BUCKETS)
        out: list[_Observation] = []
        for bucket in _limit(ctx, entries(get(listing.mapping(), "Buckets"))):
            name = text_of(bucket, "Name", "BucketName")
            if not name:
                continue
            reply = await client.call(
                _GET_BUCKET_PUBLIC_ACCESS_BLOCK, values={"bucket": name}, required=False
            )
            if reply.failed:
                continue
            configuration = get(reply.mapping(), "PublicAccessBlockConfiguration", default={})
            flags = {flag: bool_of(configuration, flag) for flag in _PAB_FLAGS}
            if all(flags.values()):
                continue
            out.append(
                _Observation(
                    policy="aws-s3-public-access-block-missing",
                    service="s3",
                    resource=name,
                    title=f"S3 bucket has no complete public access block: {name}",
                    detail=(
                        f"bucket {name} "
                        + (
                            "has no PublicAccessBlockConfiguration"
                            if reply.missing
                            else "leaves "
                            + ", ".join(flag for flag, on in flags.items() if not on)
                            + " off"
                        )
                    ),
                    observed={"public_access_block": flags, "present": not reply.missing},
                    severity="low",
                    exchanges=_exchanges(listing, reply),
                )
            )
        return out


_PAB_FLAGS: Final[tuple[str, ...]] = (
    "BlockPublicAcls",
    "IgnorePublicAcls",
    "BlockPublicPolicy",
    "RestrictPublicBuckets",
)


class AwsS3Unencrypted(_AwsPostureCheck, EndpointCheck, Module):
    """``m5.aws-s3-unencrypted`` — no default encryption on a bucket."""

    service = "s3"
    reads = (_LIST_BUCKETS, _GET_BUCKET_ENCRYPTION)
    metadata = _metadata(
        name="aws-s3-unencrypted",
        title="S3 bucket has no default server-side encryption",
        description="Reads each bucket's encryption configuration and reports one that "
        "declares no default rule, so objects written without an explicit encryption header "
        "land in the bucket unencrypted. Read-only: ListBuckets and GetBucketEncryption.",
        research_ref="ch05#1",
        cwe="CWE-311",
        framework=("WSTG-CONF-11", "API8:2023", "CWE-311"),
        compliance=("CIS-3.11", "ISO-A.8.24", "CSF-PR.DS-01", "PCI-3"),
        severity="medium",
        estimated_requests=6,
    )

    async def evaluate(self, ctx: CheckContext, client: AwsReadClient) -> list[_Observation]:
        listing = await client.call(_LIST_BUCKETS)
        out: list[_Observation] = []
        for bucket in _limit(ctx, entries(get(listing.mapping(), "Buckets"))):
            name = text_of(bucket, "Name", "BucketName")
            if not name:
                continue
            reply = await client.call(
                _GET_BUCKET_ENCRYPTION, values={"bucket": name}, required=False
            )
            if reply.failed:
                continue
            rules = entries(get(reply.mapping(), "Rules", "Rule"))
            if rules:
                continue
            out.append(
                _Observation(
                    policy="aws-s3-unencrypted",
                    service="s3",
                    resource=name,
                    title=f"S3 bucket has no default encryption: {name}",
                    detail=(
                        f"bucket {name} "
                        + (
                            "declares no ServerSideEncryptionConfiguration"
                            if reply.missing
                            else "declares no default encryption rule"
                        )
                    ),
                    observed={"encryption_present": not reply.missing},
                    severity="medium",
                    exchanges=_exchanges(listing, reply),
                )
            )
        return out


class AwsS3VersioningDisabled(_AwsPostureCheck, EndpointCheck, Module):
    """``m5.aws-s3-versioning-disabled`` — versioning not enabled on a bucket."""

    service = "s3"
    reads = (_LIST_BUCKETS, _GET_BUCKET_VERSIONING)
    metadata = _metadata(
        name="aws-s3-versioning-disabled",
        title="S3 bucket versioning is not enabled",
        description="Reads each bucket's versioning status and reports one whose Status is not "
        "Enabled — either suspended or never configured. Without versioning an overwrite or a "
        "ransomware encryption pass is unrecoverable, and the bucket cannot serve as the "
        "evidence of what was there before. Read-only: ListBuckets and GetBucketVersioning.",
        research_ref="ch05#1",
        cwe="CWE-16",
        framework=("WSTG-CONF-11", "API8:2023", "CWE-16"),
        compliance=("CIS-3.2", "ISO-A.8.13", "CSF-PR.DS-02"),
        severity="low",
        estimated_requests=6,
    )

    async def evaluate(self, ctx: CheckContext, client: AwsReadClient) -> list[_Observation]:
        listing = await client.call(_LIST_BUCKETS)
        out: list[_Observation] = []
        for bucket in _limit(ctx, entries(get(listing.mapping(), "Buckets"))):
            name = text_of(bucket, "Name", "BucketName")
            if not name:
                continue
            reply = await client.call(
                _GET_BUCKET_VERSIONING, values={"bucket": name}, required=False
            )
            if reply.failed:
                continue
            status = text_of(reply.mapping(), "Status")
            if status.lower() == "enabled":
                continue
            out.append(
                _Observation(
                    policy="aws-s3-versioning-disabled",
                    service="s3",
                    resource=name,
                    title=f"S3 bucket versioning is not enabled: {name}",
                    detail=(
                        f"bucket {name} reports versioning status "
                        f"{status or 'absent'} (Expected: Enabled)"
                    ),
                    observed={"status": status or "NeverEnabled"},
                    severity="low",
                    exchanges=_exchanges(listing, reply),
                )
            )
        return out


class AwsS3LoggingDisabled(_AwsPostureCheck, EndpointCheck, Module):
    """``m5.aws-s3-logging-disabled`` — no server access logging on a bucket."""

    service = "s3"
    reads = (_LIST_BUCKETS, _GET_BUCKET_LOGGING)
    metadata = _metadata(
        name="aws-s3-logging-disabled",
        title="S3 bucket has no server access logging",
        description="Reads each bucket's logging configuration and reports one with no "
        "LoggingEnabled block: no record of who read or wrote the objects exists to "
        "investigate. Read-only: ListBuckets and GetBucketLogging.",
        research_ref="ch05#1",
        cwe="CWE-778",
        framework=("WSTG-CONF-11", "API8:2023", "CWE-778"),
        compliance=("CIS-3.10", "ISO-A.8.15", "CSF-DE.AE-02", "PCI-10"),
        severity="low",
        estimated_requests=6,
    )

    async def evaluate(self, ctx: CheckContext, client: AwsReadClient) -> list[_Observation]:
        listing = await client.call(_LIST_BUCKETS)
        out: list[_Observation] = []
        for bucket in _limit(ctx, entries(get(listing.mapping(), "Buckets"))):
            name = text_of(bucket, "Name", "BucketName")
            if not name:
                continue
            reply = await client.call(_GET_BUCKET_LOGGING, values={"bucket": name}, required=False)
            if reply.failed:
                continue
            enabled = get(reply.mapping(), "LoggingEnabled")
            if enabled is not None:
                continue
            out.append(
                _Observation(
                    policy="aws-s3-logging-disabled",
                    service="s3",
                    resource=name,
                    title=f"S3 bucket has no server access logging: {name}",
                    detail=f"bucket {name} declares no LoggingEnabled configuration",
                    observed={"logging_enabled": False},
                    severity="low",
                    exchanges=_exchanges(listing, reply),
                )
            )
        return out


# --------------------------------------------------------------------------- IAM checks
class AwsIamRootMfaDisabled(_AwsPostureCheck, EndpointCheck, Module):
    """``m5.aws-iam-root-mfa-disabled`` — the account root user has no MFA."""

    service = "iam"
    reads = (_GET_ACCOUNT_SUMMARY,)
    metadata = _metadata(
        name="aws-iam-root-mfa-disabled",
        title="AWS account root user has no MFA device",
        description="Reads the account summary and reports AccountMFAEnabled=0: the root "
        "identity, which cannot be scoped by policy, can be used with a password alone. "
        "Read-only: GetAccountSummary.",
        research_ref="ch05#1",
        cwe="CWE-308",
        framework=("WSTG-ATHN-04", "API2:2023", "CWE-308"),
        compliance=("CIS-5.4", "CIS-6.5", "ISO-A.5.17", "ISO-A.8.5", "CSF-PR.AA-05", "PCI-8"),
        severity="high",
        estimated_requests=1,
    )

    async def evaluate(self, ctx: CheckContext, client: AwsReadClient) -> list[_Observation]:
        reply = await client.call(_GET_ACCOUNT_SUMMARY)
        summary = get(reply.mapping(), "SummaryMap", default={})
        enabled = bool_of(summary, "AccountMFAEnabled")
        if enabled is None or enabled:
            return []
        return [
            _Observation(
                policy="aws-iam-root-mfa-disabled",
                service="iam",
                resource="root",
                title="AWS account root user has no MFA device",
                detail="GetAccountSummary reports AccountMFAEnabled=0 for the root user",
                observed={"AccountMFAEnabled": enabled},
                severity="high",
                exchanges=_exchanges(reply),
            )
        ]


class AwsIamRootAccessKey(_AwsPostureCheck, EndpointCheck, Module):
    """``m5.aws-iam-root-access-key`` — the root user has an active access key."""

    service = "iam"
    reads = (_GET_ACCOUNT_SUMMARY,)
    metadata = _metadata(
        name="aws-iam-root-access-key",
        title="AWS account root user has an active access key",
        description="Reads the account summary and reports AccountAccessKeysPresent=1: a "
        "long-lived access key exists on the root identity, which no IAM policy can restrict. "
        "Read-only: GetAccountSummary.",
        research_ref="ch05#1",
        cwe="CWE-798",
        framework=("WSTG-ATHN-04", "API2:2023", "CWE-798"),
        compliance=("CIS-5.4", "ISO-A.5.17", "ISO-A.8.2", "CSF-PR.AA-05", "PCI-7"),
        severity="high",
        estimated_requests=1,
    )

    async def evaluate(self, ctx: CheckContext, client: AwsReadClient) -> list[_Observation]:
        reply = await client.call(_GET_ACCOUNT_SUMMARY)
        summary = get(reply.mapping(), "SummaryMap", default={})
        present = int_of(summary, "AccountAccessKeysPresent")
        if not present:
            return []
        return [
            _Observation(
                policy="aws-iam-root-access-key",
                service="iam",
                resource="root",
                title="AWS account root user has an active access key",
                detail=(
                    "GetAccountSummary reports AccountAccessKeysPresent=1: the root identity "
                    "holds a long-lived access key"
                ),
                observed={"AccountAccessKeysPresent": present},
                severity="high",
                exchanges=_exchanges(reply),
            )
        ]


class AwsIamPasswordPolicyWeak(_AwsPostureCheck, EndpointCheck, Module):
    """``m5.aws-iam-password-policy-weak`` — no custom policy, or a short minimum length."""

    service = "iam"
    reads = (_GET_ACCOUNT_PASSWORD_POLICY,)
    metadata = _metadata(
        name="aws-iam-password-policy-weak",
        title="IAM account password policy is absent or weaker than 14 characters",
        description="Reads the account password policy and reports its absence (the AWS "
        "default of six characters applies) or a MinimumPasswordLength below 14. Read-only: "
        "GetAccountPasswordPolicy.",
        research_ref="ch05#1",
        cwe="CWE-521",
        framework=("WSTG-ATHN-01", "API2:2023", "CWE-521"),
        compliance=("CIS-5.1", "CIS-5.2", "ISO-A.5.17", "CSF-PR.AA-05", "PCI-8"),
        severity="medium",
        estimated_requests=1,
    )

    async def evaluate(self, ctx: CheckContext, client: AwsReadClient) -> list[_Observation]:
        reply = await client.call(_GET_ACCOUNT_PASSWORD_POLICY, required=False)
        if reply.failed:
            return []
        if reply.missing:
            return [
                _Observation(
                    policy="aws-iam-password-policy-weak",
                    service="iam",
                    resource="account",
                    title="IAM account has no custom password policy",
                    detail=(
                        "GetAccountPasswordPolicy answered NoSuchEntity: the account relies on "
                        "the AWS default policy"
                    ),
                    observed={"policy": "absent"},
                    severity="medium",
                    exchanges=_exchanges(reply),
                )
            ]
        policy = get(reply.mapping(), "PasswordPolicy", default=reply.mapping())
        length = int_of(policy, "MinimumPasswordLength")
        if length is None or length >= 14:
            return []
        return [
            _Observation(
                policy="aws-iam-password-policy-weak",
                service="iam",
                resource="account",
                title="IAM account password policy is weaker than 14 characters",
                detail=f"GetAccountPasswordPolicy reports MinimumPasswordLength={length}",
                observed={"MinimumPasswordLength": length},
                severity="medium",
                exchanges=_exchanges(reply),
            )
        ]


class AwsIamUserWildcardPolicy(_AwsPostureCheck, EndpointCheck, Module):
    """``m5.aws-iam-user-wildcard-policy`` — an inline policy granting ``*`` on ``*``."""

    service = "iam"
    reads = (_GET_ACCOUNT_AUTHORIZATION_DETAILS,)
    metadata = _metadata(
        name="aws-iam-user-wildcard-policy",
        title="IAM policy grants every action on every resource",
        description="Reads the account authorization details and reports each user or role "
        "policy whose Allow statement grants Action '*' on Resource '*'. That is the "
        "privilege-escalation ceiling this review exists to find. Read-only: "
        "GetAccountAuthorizationDetails.",
        research_ref="ch05#1",
        cwe="CWE-269",
        framework=("WSTG-ATHZ-03", "API5:2023", "CWE-269"),
        compliance=("CIS-5.1", "ISO-A.5.15", "ISO-A.5.18", "CSF-PR.AA-05", "PCI-7"),
        severity="high",
        estimated_requests=1,
    )

    async def evaluate(self, ctx: CheckContext, client: AwsReadClient) -> list[_Observation]:
        reply = await client.call(_GET_ACCOUNT_AUTHORIZATION_DETAILS)
        out: list[_Observation] = []
        for policy in entries(get(reply.mapping(), "Policies")):
            holder = _policy_holder(policy)
            for statement in public_statements_of(policy):
                if _grants_everything(statement):
                    out.append(
                        _Observation(
                            policy="aws-iam-user-wildcard-policy",
                            service="iam",
                            resource=holder,
                            title=f"IAM policy grants every action on every resource: {holder}",
                            detail=(
                                f"{holder} carries a policy statement with Action '*' and "
                                "Resource '*' under Effect Allow"
                            ),
                            observed={"actions": _actions_of(statement)},
                            severity="high",
                            exchanges=_exchanges(reply),
                        )
                    )
                    break
            if len(out) >= _finding_cap(ctx):
                break
        return out


def _policy_holder(policy: Mapping[str, Any]) -> str:
    name = text_of(policy, "PolicyName", "Name")
    holder = text_of(policy, "UserName", "RoleName", "GroupName")
    if holder and name:
        return f"{holder}:{name}"
    return name or holder or "unnamed-policy"


def public_statements_of(policy: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    """Every Allow statement of a policy (the principal test is applied by the caller)."""
    document = document_of(get(policy, "PolicyDocument"))
    if not isinstance(document, Mapping):
        return []
    out = []
    for statement in entries(get(document, "Statement")):
        effect = text_of(statement, "Effect")
        if effect and effect.lower() != "allow":
            continue
        out.append(statement)
    return out


def _grants_everything(statement: Mapping[str, Any]) -> bool:
    actions = {action.lower() for action in _actions_of(statement) if action}
    resources = _resources_of(statement)
    return "*" in actions and "*" in resources


def _resources_of(statement: Mapping[str, Any]) -> set[str]:
    resource = get(statement, "Resource")
    if isinstance(resource, str):
        return {resource.lower()}
    if isinstance(resource, Sequence) and not isinstance(resource, (str, bytes)):
        return {str(item).lower() for item in resource}
    return set()


class AwsIamRolePublicTrust(_AwsPostureCheck, EndpointCheck, Module):
    """``m5.aws-iam-role-public-trust`` — a role that trusts any principal."""

    service = "iam"
    reads = (_GET_ACCOUNT_AUTHORIZATION_DETAILS,)
    metadata = _metadata(
        name="aws-iam-role-public-trust",
        title="IAM role trust policy allows any principal",
        description="Reads the account authorization details and reports each role whose "
        "AssumeRolePolicyDocument names Principal '*' with no condition: the role can be "
        "assumed from outside the account. Read-only: GetAccountAuthorizationDetails.",
        research_ref="ch05#1",
        cwe="CWE-284",
        framework=("WSTG-ATHZ-03", "API5:2023", "CWE-284"),
        compliance=("CIS-5.1", "ISO-A.5.15", "ISO-A.5.18", "CSF-PR.AA-05", "PCI-7"),
        severity="high",
        estimated_requests=1,
    )

    async def evaluate(self, ctx: CheckContext, client: AwsReadClient) -> list[_Observation]:
        reply = await client.call(_GET_ACCOUNT_AUTHORIZATION_DETAILS)
        out: list[_Observation] = []
        for role in entries(get(reply.mapping(), "Roles")):
            trust = get(role, "AssumeRolePolicyDocument")
            if _is_any_principal_document(trust):
                name = text_of(role, "RoleName") or "unnamed-role"
                out.append(
                    _Observation(
                        policy="aws-iam-role-public-trust",
                        service="iam",
                        resource=name,
                        title=f"IAM role trusts any principal: {name}",
                        detail=(
                            f"role {name}'s trust policy names Principal '*' with no "
                            "restricting condition"
                        ),
                        observed={"trust_policy": "public"},
                        severity="high",
                        exchanges=_exchanges(reply),
                    )
                )
            if len(out) >= _finding_cap(ctx):
                break
        return out


def _is_any_principal_document(document: Any) -> bool:
    parsed = document_of(document)
    if not isinstance(parsed, Mapping):
        return False
    statements = entries(get(parsed, "Statement"))
    for statement in statements:
        effect = text_of(statement, "Effect")
        if effect and effect.lower() != "allow":
            continue
        if not _is_any_principal(get(statement, "Principal")):
            continue
        if get(statement, "Condition") is None:
            return True
    return False


# --------------------------------------------------------------------------- EC2 checks
class AwsEc2ImdsV1Allowed(_AwsPostureCheck, EndpointCheck, Module):
    """``m5.aws-ec2-imdsv1-allowed`` — an instance whose metadata service allows IMDSv1."""

    service = "ec2"
    reads = (_DESCRIBE_INSTANCES,)
    metadata = _metadata(
        name="aws-ec2-imdsv1-allowed",
        title="EC2 instance metadata service allows IMDSv1",
        description="Reads the account's instances and reports each whose MetadataOptions does "
        "not require IMDSv2 tokens. IMDSv1 answers a plain GET, so any server-side request "
        "forgery on the instance can read its role credentials. Read-only: DescribeInstances.",
        research_ref="ch05#4",
        cwe="CWE-918",
        framework=("WSTG-CONF-02", "API7:2023", "CWE-918"),
        compliance=("CIS-16.10", "ISO-A.8.20", "CSF-PR.IR-01", "PCI-1"),
        severity="high",
        estimated_requests=1,
    )

    async def evaluate(self, ctx: CheckContext, client: AwsReadClient) -> list[_Observation]:
        reply = await client.call(_DESCRIBE_INSTANCES)
        out: list[_Observation] = []
        for instance in _limit(ctx, collect(reply.mapping(), "Instance", "Instances")):
            identifier = text_of(instance, "InstanceId")
            if not identifier:
                continue
            options = get(instance, "MetadataOptions", default={})
            tokens = text_of(options, "HttpTokens")
            if tokens.lower() == "required":
                continue
            out.append(
                _Observation(
                    policy="aws-ec2-imdsv1-allowed",
                    service="ec2",
                    resource=identifier,
                    title=f"EC2 instance metadata allows IMDSv1: {identifier}",
                    detail=(
                        f"instance {identifier} reports HttpTokens={tokens or 'optional'} "
                        "(IMDSv2 not required)"
                    ),
                    observed={"HttpTokens": tokens or "optional"},
                    severity="high",
                    exchanges=_exchanges(reply),
                )
            )
            if len(out) >= _finding_cap(ctx):
                break
        return out


class _AwsEc2OpenPort(_AwsPostureCheck):
    """Shared shape for the two "a security group is open to the world" checks."""

    port: ClassVar[int] = 0
    protocol_name: ClassVar[str] = ""

    async def evaluate(self, ctx: CheckContext, client: AwsReadClient) -> list[_Observation]:
        reply = await client.call(_DESCRIBE_SECURITY_GROUPS)
        out: list[_Observation] = []
        for group in _limit(ctx, entries(get(reply.mapping(), "SecurityGroups"))):
            group_id = text_of(group, "GroupId") or text_of(group, "GroupName") or "unnamed-group"
            open_rules = [
                rule
                for rule in entries(get(group, "IpPermissions", "IpPermission"))
                if _rule_opens_port(rule, self.port)
            ]
            if not open_rules:
                continue
            out.append(
                _Observation(
                    policy=self.metadata.name,
                    service="ec2",
                    resource=group_id,
                    title=(
                        f"Security group {group_id} allows {self.protocol_name} from the internet"
                    ),
                    detail=(
                        f"security group {group_id} has an inbound rule admitting "
                        f"{self.protocol_name} (port {self.port}) from 0.0.0.0/0 or ::/0"
                    ),
                    observed={
                        "port": self.port,
                        "sources": ["0.0.0.0/0", "::/0"],
                        "rules": len(open_rules),
                    },
                    severity="high",
                    exchanges=_exchanges(reply),
                )
            )
            if len(out) >= _finding_cap(ctx):
                break
        return out


def _rule_opens_port(rule: Mapping[str, Any], port: int) -> bool:
    ranges = [
        *entries(get(rule, "IpRanges", "IpRange")),
        *entries(get(rule, "Ipv6Ranges", "Ipv6Range")),
    ]
    open_source = any(
        text_of(item, "CidrIp", "CidrIpv6") in {"0.0.0.0/0", "::/0"} for item in ranges
    )
    if not open_source:
        return False
    from_port = int_of(rule, "FromPort")
    to_port = int_of(rule, "ToPort")
    if from_port is None or to_port is None:
        return False
    return from_port <= port <= to_port


class AwsEc2SecurityGroupOpenSsh(_AwsEc2OpenPort, EndpointCheck, Module):
    """``m5.aws-ec2-security-group-open-ssh`` — SSH open to the world."""

    service = "ec2"
    reads = (_DESCRIBE_SECURITY_GROUPS,)
    port = 22
    protocol_name = "SSH"
    metadata = _metadata(
        name="aws-ec2-security-group-open-ssh",
        title="EC2 security group allows SSH from the internet",
        description="Reads the account's security groups and reports each inbound rule that "
        "admits port 22 from 0.0.0.0/0 or ::/0. Read-only: DescribeSecurityGroups.",
        research_ref="ch05#1",
        cwe="CWE-284",
        framework=("WSTG-CONF-02", "API8:2023", "CWE-284"),
        compliance=("CIS-4.1", "CIS-4.2", "ISO-A.8.20", "ISO-A.8.22", "CSF-PR.PS-01", "PCI-1"),
        severity="high",
        estimated_requests=1,
    )


class AwsEc2SecurityGroupOpenRdp(_AwsEc2OpenPort, EndpointCheck, Module):
    """``m5.aws-ec2-security-group-open-rdp`` — RDP open to the world."""

    service = "ec2"
    reads = (_DESCRIBE_SECURITY_GROUPS,)
    port = 3389
    protocol_name = "RDP"
    metadata = _metadata(
        name="aws-ec2-security-group-open-rdp",
        title="EC2 security group allows RDP from the internet",
        description="Reads the account's security groups and reports each inbound rule that "
        "admits port 3389 from 0.0.0.0/0 or ::/0. Read-only: DescribeSecurityGroups.",
        research_ref="ch05#1",
        cwe="CWE-284",
        framework=("WSTG-CONF-02", "API8:2023", "CWE-284"),
        compliance=("CIS-4.1", "CIS-4.2", "ISO-A.8.20", "ISO-A.8.22", "CSF-PR.PS-01", "PCI-1"),
        severity="high",
        estimated_requests=1,
    )


class AwsEc2EbsUnencrypted(_AwsPostureCheck, EndpointCheck, Module):
    """``m5.aws-ec2-ebs-unencrypted`` — an EBS volume with encryption off."""

    service = "ec2"
    reads = (_DESCRIBE_VOLUMES,)
    metadata = _metadata(
        name="aws-ec2-ebs-unencrypted",
        title="EBS volume is not encrypted",
        description="Reads the account's EBS volumes and reports each whose Encrypted flag is "
        "false: the volume's data at rest is readable by anyone who obtains the snapshot. "
        "Read-only: DescribeVolumes.",
        research_ref="ch05#1",
        cwe="CWE-311",
        framework=("WSTG-CONF-02", "API8:2023", "CWE-311"),
        compliance=("CIS-2.1", "ISO-A.8.24", "CSF-PR.DS-01", "PCI-3"),
        severity="medium",
        estimated_requests=1,
    )

    async def evaluate(self, ctx: CheckContext, client: AwsReadClient) -> list[_Observation]:
        reply = await client.call(_DESCRIBE_VOLUMES)
        out: list[_Observation] = []
        for volume in _limit(ctx, entries(get(reply.mapping(), "Volumes"))):
            identifier = text_of(volume, "VolumeId")
            if not identifier or bool_of(volume, "Encrypted") is not False:
                continue
            out.append(
                _Observation(
                    policy="aws-ec2-ebs-unencrypted",
                    service="ec2",
                    resource=identifier,
                    title=f"EBS volume is not encrypted: {identifier}",
                    detail=f"volume {identifier} reports Encrypted=false",
                    observed={"Encrypted": False},
                    severity="medium",
                    exchanges=_exchanges(reply),
                )
            )
            if len(out) >= _finding_cap(ctx):
                break
        return out


# --------------------------------------------------------------------------- RDS checks
class AwsRdsPubliclyAccessible(_AwsPostureCheck, EndpointCheck, Module):
    """``m5.aws-rds-publicly-accessible`` — a database with a public endpoint."""

    service = "rds"
    reads = (_DESCRIBE_DB_INSTANCES,)
    metadata = _metadata(
        name="aws-rds-publicly-accessible",
        title="RDS instance is publicly accessible",
        description="Reads the account's database instances and reports each with "
        "PubliclyAccessible true: the endpoint resolves to a public address, so reachability "
        "is a security-group question rather than a network one. Read-only: "
        "DescribeDBInstances.",
        research_ref="ch05#20",
        cwe="CWE-284",
        framework=("WSTG-CONF-02", "API8:2023", "CWE-284"),
        compliance=("CIS-4.1", "ISO-A.8.20", "CSF-PR.PS-01", "PCI-1"),
        severity="high",
        estimated_requests=1,
    )

    async def evaluate(self, ctx: CheckContext, client: AwsReadClient) -> list[_Observation]:
        reply = await client.call(_DESCRIBE_DB_INSTANCES)
        out: list[_Observation] = []
        for instance in _limit(ctx, entries(get(reply.mapping(), "DBInstances"))):
            identifier = text_of(instance, "DBInstanceIdentifier")
            if not identifier or bool_of(instance, "PubliclyAccessible") is not True:
                continue
            out.append(
                _Observation(
                    policy="aws-rds-publicly-accessible",
                    service="rds",
                    resource=identifier,
                    title=f"RDS instance is publicly accessible: {identifier}",
                    detail=f"database {identifier} reports PubliclyAccessible=true",
                    observed={"PubliclyAccessible": True, "engine": text_of(instance, "Engine")},
                    severity="high",
                    exchanges=_exchanges(reply),
                )
            )
            if len(out) >= _finding_cap(ctx):
                break
        return out


class AwsRdsUnencrypted(_AwsPostureCheck, EndpointCheck, Module):
    """``m5.aws-rds-unencrypted`` — a database with storage encryption off."""

    service = "rds"
    reads = (_DESCRIBE_DB_INSTANCES,)
    metadata = _metadata(
        name="aws-rds-unencrypted",
        title="RDS instance storage is not encrypted",
        description="Reads the account's database instances and reports each with "
        "StorageEncrypted false: the instance's storage and its automated snapshots are "
        "readable wherever the snapshot is copied. Read-only: DescribeDBInstances.",
        research_ref="ch05#20",
        cwe="CWE-311",
        framework=("WSTG-CONF-02", "API8:2023", "CWE-311"),
        compliance=("CIS-2.2", "ISO-A.8.24", "CSF-PR.DS-01", "PCI-3"),
        severity="medium",
        estimated_requests=1,
    )

    async def evaluate(self, ctx: CheckContext, client: AwsReadClient) -> list[_Observation]:
        reply = await client.call(_DESCRIBE_DB_INSTANCES)
        out: list[_Observation] = []
        for instance in _limit(ctx, entries(get(reply.mapping(), "DBInstances"))):
            identifier = text_of(instance, "DBInstanceIdentifier")
            if not identifier or bool_of(instance, "StorageEncrypted") is not False:
                continue
            out.append(
                _Observation(
                    policy="aws-rds-unencrypted",
                    service="rds",
                    resource=identifier,
                    title=f"RDS instance storage is not encrypted: {identifier}",
                    detail=f"database {identifier} reports StorageEncrypted=false",
                    observed={"StorageEncrypted": False},
                    severity="medium",
                    exchanges=_exchanges(reply),
                )
            )
            if len(out) >= _finding_cap(ctx):
                break
        return out


# --------------------------------------------------------------------------- EKS checks
class AwsEksPublicEndpoint(_AwsPostureCheck, EndpointCheck, Module):
    """``m5.aws-eks-public-endpoint`` — a cluster API server reachable from anywhere."""

    service = "eks"
    reads = (_LIST_CLUSTERS, _DESCRIBE_CLUSTER)
    metadata = _metadata(
        name="aws-eks-public-endpoint",
        title="EKS cluster endpoint is public to the internet",
        description="Lists the account's clusters and reads each cluster's VPC configuration, "
        "reporting one whose endpoint is public with 0.0.0.0/0 among its allowed CIDRs: the "
        "Kubernetes API server answers the internet, gated only by authentication. Read-only: "
        "ListClusters and DescribeCluster.",
        research_ref="ch05#13",
        cwe="CWE-284",
        framework=("WSTG-CONF-02", "API8:2023", "CWE-284"),
        compliance=("CIS-4.1", "ISO-A.8.20", "CSF-PR.PS-01", "PCI-1"),
        severity="high",
        estimated_requests=6,
    )

    async def evaluate(self, ctx: CheckContext, client: AwsReadClient) -> list[_Observation]:
        listing = await client.call(_LIST_CLUSTERS)
        names = [str(name) for name in _scalars(get(listing.mapping(), "Clusters"))]
        out: list[_Observation] = []
        for name in _limit(ctx, names):
            reply = await client.call(_DESCRIBE_CLUSTER, values={"cluster": name}, required=False)
            cluster = _cluster_of(reply.mapping())
            configuration = get(cluster, "resourcesVpcConfig", default={})
            public = bool_of(configuration, "endpointPublicAccess")
            cidrs = [str(item) for item in _scalars(get(configuration, "publicAccessCidrs"))]
            if public is not True or not ({"0.0.0.0/0", "::/0"} & set(cidrs)):
                continue
            out.append(
                _Observation(
                    policy="aws-eks-public-endpoint",
                    service="eks",
                    resource=name,
                    title=f"EKS cluster endpoint is public to the internet: {name}",
                    detail=(
                        f"cluster {name} publishes its API server with "
                        f"endpointPublicAccess=true and allowed CIDRs {', '.join(cidrs)}"
                    ),
                    observed={"endpointPublicAccess": True, "publicAccessCidrs": cidrs},
                    severity="high",
                    exchanges=_exchanges(listing, reply),
                )
            )
            if len(out) >= _finding_cap(ctx):
                break
        return out


class AwsEksAuditLoggingOff(_AwsPostureCheck, EndpointCheck, Module):
    """``m5.aws-eks-audit-logging-off`` — a cluster whose control-plane audit log is off."""

    service = "eks"
    reads = (_LIST_CLUSTERS, _DESCRIBE_CLUSTER)
    metadata = _metadata(
        name="aws-eks-audit-logging-off",
        title="EKS cluster control-plane audit logging is disabled",
        description="Lists the account's clusters and reads each cluster's logging "
        "configuration, reporting one that does not enable the audit log type. Without it the "
        "API server's own record of who did what to the cluster does not exist. Read-only: "
        "ListClusters and DescribeCluster.",
        research_ref="ch05#13",
        cwe="CWE-778",
        framework=("WSTG-CONF-02", "API8:2023", "CWE-778"),
        compliance=("CIS-3.10", "ISO-A.8.15", "CSF-DE.AE-02", "PCI-10"),
        severity="medium",
        estimated_requests=6,
    )

    async def evaluate(self, ctx: CheckContext, client: AwsReadClient) -> list[_Observation]:
        listing = await client.call(_LIST_CLUSTERS)
        names = [str(name) for name in _scalars(get(listing.mapping(), "Clusters"))]
        out: list[_Observation] = []
        for name in _limit(ctx, names):
            reply = await client.call(_DESCRIBE_CLUSTER, values={"cluster": name}, required=False)
            logging = get(_cluster_of(reply.mapping()), "logging", default={})
            enabled = {
                text_of(entry, "type"): bool_of(entry, "enabled")
                for entry in entries(get(logging, "clusterLogging"))
            }
            if enabled.get("audit") is True:
                continue
            out.append(
                _Observation(
                    policy="aws-eks-audit-logging-off",
                    service="eks",
                    resource=name,
                    title=f"EKS cluster audit logging is disabled: {name}",
                    detail=(
                        f"cluster {name} does not enable the 'audit' control-plane log type "
                        f"(configured types: {', '.join(sorted(enabled)) or 'none'})"
                    ),
                    observed={"clusterLogging": enabled},
                    severity="medium",
                    exchanges=_exchanges(listing, reply),
                )
            )
            if len(out) >= _finding_cap(ctx):
                break
        return out


def _cluster_of(document: Mapping[str, Any]) -> Mapping[str, Any]:
    """The cluster document inside EKS's ``{"cluster": {...}}`` envelope (or the document)."""
    inner = get(document, "cluster")
    return inner if isinstance(inner, Mapping) else document


def _scalars(value: Any) -> list[Any]:
    """A list of scalars from a value that may be a list, a member envelope or one scalar."""
    if value is None:
        return []
    if isinstance(value, Mapping):
        inner = get(value, "member", "item", "Cluster", "ClusterName")
        return _scalars(inner)
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        out: list[Any] = []
        for item in value:
            out.extend(_scalars(item))
        return out
    return [value]


# --------------------------------------------------------------------------- Lambda checks
class AwsLambdaPolicyPublic(_AwsPostureCheck, EndpointCheck, Module):
    """``m5.aws-lambda-policy-public`` — a function resource policy that trusts any principal."""

    service = "lambda"
    reads = (_LIST_FUNCTIONS, _GET_FUNCTION_POLICY)
    metadata = _metadata(
        name="aws-lambda-policy-public",
        title="Lambda function policy allows any principal",
        description="Lists the account's functions and reads each function's resource policy, "
        "reporting one whose Allow statement names Principal '*' with no source ARN, account "
        "or VPC condition: the function can be invoked from outside the account. Read-only: "
        "ListFunctions and GetPolicy.",
        research_ref="ch05#9",
        cwe="CWE-284",
        framework=("WSTG-ATHZ-03", "API5:2023", "CWE-284"),
        compliance=("CIS-5.1", "ISO-A.5.15", "CSF-PR.AA-05", "PCI-7"),
        severity="high",
        estimated_requests=6,
    )

    async def evaluate(self, ctx: CheckContext, client: AwsReadClient) -> list[_Observation]:
        listing = await client.call(_LIST_FUNCTIONS)
        out: list[_Observation] = []
        for function in _limit(ctx, entries(get(listing.mapping(), "Functions"))):
            name = text_of(function, "FunctionName")
            if not name:
                continue
            reply = await client.call(
                _GET_FUNCTION_POLICY, values={"function": name}, required=False
            )
            if reply.missing or reply.data is None:
                continue
            statements = public_statements(_policy_text(reply.data))
            if not statements:
                continue
            out.append(
                _Observation(
                    policy="aws-lambda-policy-public",
                    service="lambda",
                    resource=name,
                    title=f"Lambda function policy allows any principal: {name}",
                    detail=(
                        f"function {name}'s resource policy allows Principal '*' with no "
                        "restricting condition"
                    ),
                    observed={"statements": len(statements)},
                    severity="high",
                    exchanges=_exchanges(listing, reply),
                )
            )
            if len(out) >= _finding_cap(ctx):
                break
        return out


class AwsLambdaUrlAuthNone(_AwsPostureCheck, EndpointCheck, Module):
    """``m5.aws-lambda-url-auth-none`` — a function URL with authentication disabled."""

    service = "lambda"
    reads = (_LIST_FUNCTIONS, _GET_FUNCTION_URL_CONFIG)
    metadata = _metadata(
        name="aws-lambda-url-auth-none",
        title="Lambda function URL requires no authentication",
        description="Lists the account's functions and reads each function URL configuration, "
        "reporting one whose AuthType is NONE: the function is callable by anyone who knows "
        "the URL. Read-only: ListFunctions and GetFunctionUrlConfig.",
        research_ref="ch05#9",
        cwe="CWE-306",
        framework=("WSTG-ATHN-01", "API2:2023", "CWE-306"),
        compliance=("CIS-5.1", "ISO-A.5.15", "ISO-A.8.3", "CSF-PR.AA-05", "PCI-7"),
        severity="high",
        estimated_requests=6,
    )

    async def evaluate(self, ctx: CheckContext, client: AwsReadClient) -> list[_Observation]:
        listing = await client.call(_LIST_FUNCTIONS)
        out: list[_Observation] = []
        for function in _limit(ctx, entries(get(listing.mapping(), "Functions"))):
            name = text_of(function, "FunctionName")
            if not name:
                continue
            reply = await client.call(
                _GET_FUNCTION_URL_CONFIG, values={"function": name}, required=False
            )
            auth = text_of(reply.mapping(), "AuthType")
            if auth.upper() != "NONE":
                continue
            out.append(
                _Observation(
                    policy="aws-lambda-url-auth-none",
                    service="lambda",
                    resource=name,
                    title=f"Lambda function URL requires no authentication: {name}",
                    detail=f"function {name}'s URL configuration reports AuthType=NONE",
                    observed={"AuthType": auth, "url": text_of(reply.mapping(), "FunctionUrl")},
                    severity="high",
                    exchanges=_exchanges(listing, reply),
                )
            )
            if len(out) >= _finding_cap(ctx):
                break
        return out


# --------------------------------------------------------------------------- CloudTrail
class AwsCloudTrailNotMultiRegion(_AwsPostureCheck, EndpointCheck, Module):
    """``m5.aws-cloudtrail-not-multiregion`` — a trail that covers one region."""

    service = "cloudtrail"
    reads = (_DESCRIBE_TRAILS,)
    metadata = _metadata(
        name="aws-cloudtrail-not-multiregion",
        title="CloudTrail trail is not multi-region",
        description="Reads the account's trails and reports each whose IsMultiRegionTrail is "
        "false: activity in the other regions is not recorded by that trail. Read-only: "
        "DescribeTrails.",
        research_ref="ch05#1",
        cwe="CWE-778",
        framework=("WSTG-CONF-02", "API8:2023", "CWE-778"),
        compliance=("CIS-3.1", "ISO-A.8.15", "CSF-DE.AE-02", "PCI-10"),
        severity="medium",
        estimated_requests=1,
    )

    async def evaluate(self, ctx: CheckContext, client: AwsReadClient) -> list[_Observation]:
        reply = await client.call(_DESCRIBE_TRAILS)
        out: list[_Observation] = []
        for trail in _limit(ctx, entries(get(reply.mapping(), "trailList", "Trails"))):
            name = text_of(trail, "Name", "TrailARN")
            if not name or bool_of(trail, "IsMultiRegionTrail") is not False:
                continue
            out.append(
                _Observation(
                    policy="aws-cloudtrail-not-multiregion",
                    service="cloudtrail",
                    resource=name,
                    title=f"CloudTrail trail is not multi-region: {name}",
                    detail=f"trail {name} reports IsMultiRegionTrail=false",
                    observed={"IsMultiRegionTrail": False},
                    severity="medium",
                    exchanges=_exchanges(reply),
                )
            )
            if len(out) >= _finding_cap(ctx):
                break
        return out


class AwsCloudTrailLoggingDisabled(_AwsPostureCheck, EndpointCheck, Module):
    """``m5.aws-cloudtrail-logging-disabled`` — a trail that has stopped logging."""

    service = "cloudtrail"
    reads = (_DESCRIBE_TRAILS, _GET_TRAIL_STATUS)
    metadata = _metadata(
        name="aws-cloudtrail-logging-disabled",
        title="CloudTrail trail has logging stopped",
        description="Reads the account's trails and each trail's status, reporting one whose "
        "IsLogging is false: the trail exists but records nothing. Read-only: DescribeTrails "
        "and GetTrailStatus.",
        research_ref="ch05#1",
        cwe="CWE-778",
        framework=("WSTG-CONF-02", "API8:2023", "CWE-778"),
        compliance=("CIS-3.1", "ISO-A.8.15", "CSF-DE.AE-02", "PCI-10"),
        severity="high",
        estimated_requests=6,
    )

    async def evaluate(self, ctx: CheckContext, client: AwsReadClient) -> list[_Observation]:
        listing = await client.call(_DESCRIBE_TRAILS)
        out: list[_Observation] = []
        for trail in _limit(ctx, entries(get(listing.mapping(), "trailList", "Trails"))):
            name = text_of(trail, "Name", "TrailARN")
            if not name:
                continue
            reply = await client.call(_GET_TRAIL_STATUS, values={"trail": name}, required=False)
            logging = bool_of(reply.mapping(), "IsLogging")
            if logging is not False:
                continue
            out.append(
                _Observation(
                    policy="aws-cloudtrail-logging-disabled",
                    service="cloudtrail",
                    resource=name,
                    title=f"CloudTrail trail has logging stopped: {name}",
                    detail=f"trail {name} reports IsLogging=false",
                    observed={"IsLogging": False},
                    severity="high",
                    exchanges=_exchanges(listing, reply),
                )
            )
            if len(out) >= _finding_cap(ctx):
                break
        return out


# --------------------------------------------------------------------------- KMS checks
class AwsKmsKeyPolicyPublic(_AwsPostureCheck, EndpointCheck, Module):
    """``m5.aws-kms-key-policy-public`` — a key policy that trusts any principal."""

    service = "kms"
    reads = (_LIST_KEYS, _GET_KEY_POLICY)
    metadata = _metadata(
        name="aws-kms-key-policy-public",
        title="KMS key policy allows any principal",
        description="Lists the account's keys and reads each key policy, reporting one whose "
        "Allow statement names Principal '*' with no condition: the key's data can be "
        "decrypted by an unauthorized principal that is granted kms:Decrypt elsewhere. "
        "Read-only: ListKeys and GetKeyPolicy (JSON-RPC reads).",
        research_ref="ch05#1",
        cwe="CWE-284",
        framework=("WSTG-ATHZ-03", "API5:2023", "CWE-284"),
        compliance=("CIS-3.3", "ISO-A.5.15", "ISO-A.8.24", "CSF-PR.DS-01", "PCI-3"),
        severity="high",
        estimated_requests=11,
    )

    async def evaluate(self, ctx: CheckContext, client: AwsReadClient) -> list[_Observation]:
        listing = await client.call(_LIST_KEYS)
        out: list[_Observation] = []
        for key in _limit(ctx, collect(listing.mapping(), "Key", "Keys")):
            key_id = text_of(key, "KeyId", "KeyArn")
            if not key_id:
                continue
            reply = await client.call(
                _GET_KEY_POLICY,
                payload=_json_payload({"KeyId": key_id, "PolicyName": "default"}),
                required=False,
            )
            if reply.missing or reply.data is None:
                continue
            statements = public_statements(_policy_text(reply.data))
            if not statements:
                continue
            out.append(
                _Observation(
                    policy="aws-kms-key-policy-public",
                    service="kms",
                    resource=key_id,
                    title=f"KMS key policy allows any principal: {key_id}",
                    detail=(
                        f"key {key_id}'s policy allows Principal '*' with no restricting condition"
                    ),
                    observed={"statements": len(statements)},
                    severity="high",
                    exchanges=_exchanges(listing, reply),
                )
            )
            if len(out) >= _finding_cap(ctx):
                break
        return out


class AwsKmsRotationDisabled(_AwsPostureCheck, EndpointCheck, Module):
    """``m5.aws-kms-rotation-disabled`` — a customer-managed key without rotation."""

    service = "kms"
    reads = (_LIST_KEYS, _DESCRIBE_KEY, _GET_KEY_ROTATION_STATUS)
    metadata = _metadata(
        name="aws-kms-rotation-disabled",
        title="Customer-managed KMS key has automatic rotation disabled",
        description="Lists the account's keys, keeps the customer-managed symmetric keys and "
        "reads each one's rotation status, reporting a key with KeyRotationEnabled false: the "
        "same key material protects the data indefinitely. AWS-managed keys are skipped, "
        "because their rotation is the service's decision and not the account's. Read-only: "
        "ListKeys, DescribeKey and GetKeyRotationStatus.",
        research_ref="ch05#1",
        cwe="CWE-320",
        framework=("WSTG-CONF-02", "API8:2023", "CWE-320"),
        compliance=("CIS-3.11", "ISO-A.8.24", "CSF-PR.DS-01", "PCI-3"),
        severity="low",
        estimated_requests=11,
    )

    async def evaluate(self, ctx: CheckContext, client: AwsReadClient) -> list[_Observation]:
        listing = await client.call(_LIST_KEYS)
        out: list[_Observation] = []
        for key in _limit(ctx, collect(listing.mapping(), "Key", "Keys")):
            key_id = text_of(key, "KeyId", "KeyArn")
            if not key_id:
                continue
            described = await client.call(
                _DESCRIBE_KEY, payload=_json_payload({"KeyId": key_id}), required=False
            )
            metadata = get(described.mapping(), "KeyMetadata", default={})
            if text_of(metadata, "KeyManager").upper() != "CUSTOMER":
                continue
            reply = await client.call(
                _GET_KEY_ROTATION_STATUS,
                payload=_json_payload({"KeyId": key_id}),
                required=False,
            )
            if bool_of(reply.mapping(), "KeyRotationEnabled") is not False:
                continue
            out.append(
                _Observation(
                    policy="aws-kms-rotation-disabled",
                    service="kms",
                    resource=key_id,
                    title=f"KMS key has automatic rotation disabled: {key_id}",
                    detail=(f"customer-managed key {key_id} reports KeyRotationEnabled=false"),
                    observed={"KeyRotationEnabled": False},
                    severity="low",
                    exchanges=_exchanges(listing, described, reply),
                )
            )
            if len(out) >= _finding_cap(ctx):
                break
        return out


def _json_payload(values: Mapping[str, Any]) -> bytes:
    return json.dumps(values).encode("utf-8")


# --------------------------------------------------------------------------- SQS and SNS
class AwsSqsPolicyPublic(_AwsPostureCheck, EndpointCheck, Module):
    """``m5.aws-sqs-policy-public`` — a queue policy that trusts any principal."""

    service = "sqs"
    reads = (_LIST_QUEUES, _GET_QUEUE_ATTRIBUTES)
    metadata = _metadata(
        name="aws-sqs-policy-public",
        title="SQS queue policy allows any principal",
        description="Lists the account's queues and reads each queue's policy attribute, "
        "reporting one whose Allow statement names Principal '*' with no condition: any AWS "
        "principal can send to (and, with the matching action, receive from) the queue. "
        "Read-only: ListQueues and GetQueueAttributes.",
        research_ref="ch05#21",
        cwe="CWE-284",
        framework=("WSTG-ATHZ-03", "API5:2023", "CWE-284"),
        compliance=("CIS-5.1", "ISO-A.5.15", "CSF-PR.DS-01", "PCI-3"),
        severity="high",
        estimated_requests=6,
    )

    async def evaluate(self, ctx: CheckContext, client: AwsReadClient) -> list[_Observation]:
        listing = await client.call(_LIST_QUEUES)
        out: list[_Observation] = []
        for queue in _limit(ctx, _scalars(get(listing.mapping(), "QueueUrls", "QueueUrl"))):
            url = str(queue)
            if not url:
                continue
            reply = await client.call(_GET_QUEUE_ATTRIBUTES, values={"queue": url}, required=False)
            policy = get(get(reply.mapping(), "Attributes", default={}), "Policy")
            statements = public_statements(_policy_text(policy))
            if not statements:
                continue
            out.append(
                _Observation(
                    policy="aws-sqs-policy-public",
                    service="sqs",
                    resource=_queue_name(url),
                    title=f"SQS queue policy allows any principal: {_queue_name(url)}",
                    detail=(
                        f"queue {_queue_name(url)}'s policy allows Principal '*' with no "
                        "restricting condition"
                    ),
                    observed={"statements": len(statements)},
                    severity="high",
                    exchanges=_exchanges(listing, reply),
                )
            )
            if len(out) >= _finding_cap(ctx):
                break
        return out


def _queue_name(url: str) -> str:
    return url.rstrip("/").rsplit("/", 1)[-1]


class AwsSnsTopicPublic(_AwsPostureCheck, EndpointCheck, Module):
    """``m5.aws-sns-topic-public`` — a topic policy that trusts any principal."""

    service = "sns"
    reads = (_LIST_TOPICS, _GET_TOPIC_ATTRIBUTES)
    metadata = _metadata(
        name="aws-sns-topic-public",
        title="SNS topic policy allows any principal",
        description="Lists the account's topics and reads each topic's policy attribute, "
        "reporting one whose Allow statement names Principal '*' with no condition: any AWS "
        "principal can publish to the topic and reach every subscriber. Read-only: ListTopics "
        "and GetTopicAttributes.",
        research_ref="ch05#21",
        cwe="CWE-284",
        framework=("WSTG-ATHZ-03", "API5:2023", "CWE-284"),
        compliance=("CIS-5.1", "ISO-A.5.15", "CSF-PR.DS-01", "PCI-3"),
        severity="high",
        estimated_requests=6,
    )

    async def evaluate(self, ctx: CheckContext, client: AwsReadClient) -> list[_Observation]:
        listing = await client.call(_LIST_TOPICS)
        out: list[_Observation] = []
        for topic in _limit(ctx, collect(listing.mapping(), "Topic", "Topics")):
            arn = text_of(topic, "TopicArn")
            if not arn:
                continue
            reply = await client.call(_GET_TOPIC_ATTRIBUTES, values={"topic": arn}, required=False)
            policy = get(get(reply.mapping(), "Attributes", default={}), "Policy")
            statements = public_statements(_policy_text(policy))
            if not statements:
                continue
            out.append(
                _Observation(
                    policy="aws-sns-topic-public",
                    service="sns",
                    resource=arn.rsplit(":", 1)[-1],
                    title=f"SNS topic policy allows any principal: {arn.rsplit(':', 1)[-1]}",
                    detail=(f"topic {arn} allows Principal '*' with no restricting condition"),
                    observed={"statements": len(statements)},
                    severity="high",
                    exchanges=_exchanges(listing, reply),
                )
            )
            if len(out) >= _finding_cap(ctx):
                break
        return out


# --------------------------------------------------------------------------- ECR checks
class AwsEcrRepositoryPublic(_AwsPostureCheck, EndpointCheck, Module):
    """``m5.aws-ecr-repository-public`` — a repository policy that trusts any principal."""

    service = "ecr"
    reads = (_DESCRIBE_REPOSITORIES, _GET_REPOSITORY_POLICY)
    metadata = _metadata(
        name="aws-ecr-repository-public",
        title="ECR repository policy allows any principal",
        description="Lists the account's repositories and reads each repository policy, "
        "reporting one whose Allow statement names Principal '*' with no condition: the images "
        "can be pulled (or pushed) from outside the account. Read-only: DescribeRepositories "
        "and GetRepositoryPolicy (JSON-RPC reads).",
        research_ref="ch05#15",
        cwe="CWE-284",
        framework=("WSTG-ATHZ-03", "API5:2023", "CWE-284"),
        compliance=("CIS-5.1", "ISO-A.8.24", "CSF-PR.DS-01", "PCI-3"),
        severity="high",
        estimated_requests=11,
    )

    async def evaluate(self, ctx: CheckContext, client: AwsReadClient) -> list[_Observation]:
        listing = await client.call(_DESCRIBE_REPOSITORIES)
        out: list[_Observation] = []
        for repository in _limit(ctx, entries(get(listing.mapping(), "repositories"))):
            name = text_of(repository, "repositoryName")
            if not name:
                continue
            reply = await client.call(
                _GET_REPOSITORY_POLICY,
                payload=_json_payload({"repositoryName": name}),
                required=False,
            )
            if reply.missing or reply.data is None:
                continue
            statements = public_statements(_policy_text(reply.data))
            if not statements:
                continue
            out.append(
                _Observation(
                    policy="aws-ecr-repository-public",
                    service="ecr",
                    resource=name,
                    title=f"ECR repository policy allows any principal: {name}",
                    detail=(
                        f"repository {name}'s policy allows Principal '*' with no restricting "
                        "condition"
                    ),
                    observed={"statements": len(statements)},
                    severity="high",
                    exchanges=_exchanges(listing, reply),
                )
            )
            if len(out) >= _finding_cap(ctx):
                break
        return out


class AwsEcrScanOnPushDisabled(_AwsPostureCheck, EndpointCheck, Module):
    """``m5.aws-ecr-scan-on-push-disabled`` — a repository that scans no image on push."""

    service = "ecr"
    reads = (_DESCRIBE_REPOSITORIES,)
    metadata = _metadata(
        name="aws-ecr-scan-on-push-disabled",
        title="ECR repository does not scan images on push",
        description="Reads the account's repositories and reports each whose "
        "imageScanningConfiguration leaves scanOnPush off: a vulnerable base image reaches the "
        "registry without the registry's own advisory check. Read-only: "
        "DescribeRepositories.",
        research_ref="ch05#15",
        cwe="CWE-1104",
        framework=("WSTG-CONF-02", "API8:2023", "CWE-1104"),
        compliance=("CIS-16.11", "ISO-A.8.8", "ISO-A.8.28", "CSF-ID.RA-02", "PCI-6"),
        severity="low",
        estimated_requests=1,
    )

    async def evaluate(self, ctx: CheckContext, client: AwsReadClient) -> list[_Observation]:
        reply = await client.call(_DESCRIBE_REPOSITORIES)
        out: list[_Observation] = []
        for repository in _limit(ctx, entries(get(reply.mapping(), "repositories"))):
            name = text_of(repository, "repositoryName")
            if not name:
                continue
            configuration = get(repository, "imageScanningConfiguration", default={})
            if bool_of(configuration, "scanOnPush") is True:
                continue
            out.append(
                _Observation(
                    policy="aws-ecr-scan-on-push-disabled",
                    service="ecr",
                    resource=name,
                    title=f"ECR repository does not scan images on push: {name}",
                    detail=f"repository {name} reports imageScanningConfiguration.scanOnPush=false",
                    observed={"scanOnPush": False},
                    severity="low",
                    exchanges=_exchanges(reply),
                )
            )
            if len(out) >= _finding_cap(ctx):
                break
        return out


# --------------------------------------------------------------------------- account defaults
class AwsAccountPublicAccessBlockMissing(_AwsPostureCheck, EndpointCheck, Module):
    """``m5.aws-account-public-access-block-missing`` — no account-level S3 block."""

    service = "s3control"
    reads = (_GET_ACCOUNT_PUBLIC_ACCESS_BLOCK,)
    metadata = _metadata(
        name="aws-account-public-access-block-missing",
        title="AWS account has no complete S3 public access block",
        description="Reads the account-level PublicAccessBlockConfiguration and reports it "
        "missing or incomplete. This is the default that decides whether *any* bucket in the "
        "account can be made public, present or future, so an absent one is the finding even "
        "when every current bucket is private. Read-only: GetPublicAccessBlock (S3 Control).",
        research_ref="ch05#1",
        cwe="CWE-16",
        framework=("WSTG-CONF-11", "API8:2023", "CWE-16"),
        compliance=("CIS-3.3", "ISO-A.8.3", "CSF-PR.DS-01", "PCI-1"),
        severity="medium",
        estimated_requests=1,
    )

    async def evaluate(self, ctx: CheckContext, client: AwsReadClient) -> list[_Observation]:
        reply = await client.call(_GET_ACCOUNT_PUBLIC_ACCESS_BLOCK, required=False)
        if reply.failed:
            return []
        configuration = get(reply.mapping(), "PublicAccessBlockConfiguration", default={})
        flags = {flag: bool_of(configuration, flag) for flag in _PAB_FLAGS}
        if all(flags.values()):
            return []
        return [
            _Observation(
                policy="aws-account-public-access-block-missing",
                service="s3control",
                resource="account",
                title="AWS account has no complete S3 public access block",
                detail=(
                    "the account "
                    + (
                        "declares no account-level PublicAccessBlockConfiguration"
                        if reply.missing
                        else "leaves "
                        + ", ".join(flag for flag, on in flags.items() if not on)
                        + " off"
                    )
                ),
                observed={"public_access_block": flags, "present": not reply.missing},
                severity="medium",
                exchanges=_exchanges(reply),
            )
        ]


class AwsAccountEbsEncryptionOff(_AwsPostureCheck, EndpointCheck, Module):
    """``m5.aws-account-ebs-encryption-off`` — EBS encryption is not the account default."""

    service = "ec2"
    reads = (_GET_EBS_ENCRYPTION_BY_DEFAULT,)
    metadata = _metadata(
        name="aws-account-ebs-encryption-off",
        title="AWS account does not enable EBS encryption by default",
        description="Reads the account's EBS encryption default and reports "
        "EbsEncryptionByDefault=false: every new volume created without an explicit encryption "
        "argument — every volume in every launch template, ASG and AMI-based instance — is "
        "unencrypted. This is the account-level default that decides whether the EC2 checks "
        "find anything to report. Read-only: GetEbsEncryptionByDefault.",
        research_ref="ch05#1",
        cwe="CWE-311",
        framework=("WSTG-CONF-02", "API8:2023", "CWE-311"),
        compliance=("CIS-2.1", "ISO-A.8.24", "CSF-PR.DS-01", "PCI-3"),
        severity="medium",
        estimated_requests=1,
    )

    async def evaluate(self, ctx: CheckContext, client: AwsReadClient) -> list[_Observation]:
        reply = await client.call(_GET_EBS_ENCRYPTION_BY_DEFAULT)
        enabled = bool_of(reply.mapping(), "EbsEncryptionByDefault")
        if enabled is not False:
            return []
        return [
            _Observation(
                policy="aws-account-ebs-encryption-off",
                service="ec2",
                resource="account",
                title="AWS account does not enable EBS encryption by default",
                detail="GetEbsEncryptionByDefault reports EbsEncryptionByDefault=false",
                observed={"EbsEncryptionByDefault": False},
                severity="medium",
                exchanges=_exchanges(reply),
            )
        ]


# --------------------------------------------------------------------------- the family
#: Every check this module registers, in run order, grouped by the requirement's scope areas.
AWS_POSTURE_CHECKS: tuple[type[Module], ...] = (
    AwsS3PublicAcl,
    AwsS3PublicPolicy,
    AwsS3PublicAccessBlockMissing,
    AwsS3Unencrypted,
    AwsS3VersioningDisabled,
    AwsS3LoggingDisabled,
    AwsIamRootMfaDisabled,
    AwsIamRootAccessKey,
    AwsIamPasswordPolicyWeak,
    AwsIamUserWildcardPolicy,
    AwsIamRolePublicTrust,
    AwsEc2ImdsV1Allowed,
    AwsEc2SecurityGroupOpenSsh,
    AwsEc2SecurityGroupOpenRdp,
    AwsEc2EbsUnencrypted,
    AwsRdsPubliclyAccessible,
    AwsRdsUnencrypted,
    AwsEksPublicEndpoint,
    AwsEksAuditLoggingOff,
    AwsLambdaPolicyPublic,
    AwsLambdaUrlAuthNone,
    AwsCloudTrailNotMultiRegion,
    AwsCloudTrailLoggingDisabled,
    AwsKmsKeyPolicyPublic,
    AwsKmsRotationDisabled,
    AwsSqsPolicyPublic,
    AwsSnsTopicPublic,
    AwsEcrRepositoryPublic,
    AwsEcrScanOnPushDisabled,
    AwsAccountPublicAccessBlockMissing,
    AwsAccountEbsEncryptionOff,
)


def aws_checks() -> tuple[type[Module], ...]:
    return AWS_POSTURE_CHECKS


def service_areas() -> dict[str, str]:
    """``check name -> scope area`` from the module's own declaration (the test reads this)."""
    return {check.metadata.name: str(getattr(check, "service", "")) for check in AWS_POSTURE_CHECKS}
