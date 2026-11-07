"""A loopback AWS read-only API fixture for the posture checks (WP-31, REQ-DET-024).

Two account prefixes live on one server: ``/risky`` carries a breach for every policy the
family checks, ``/safe`` carries the hardened counterpart (the requirement's decoy: "a hardened
account fixture"). Every request must be **SigV4-signed** with the fixture's own lab
credential, which the fixture verifies with :func:`arachne.creds.aws.verify_request` — the same
canonicalization the signer used. That is what makes the credential path a test rather than an
assertion: a check that did not sign, or signed with the wrong key, gets a ``403`` and no data,
so "the posture came from a credentialed read" is falsifiable.

The fixture speaks the two envelopes the real APIs return: **XML** for the Query and S3 REST
protocols (S3, S3 Control, IAM, EC2, RDS, CloudTrail, SQS, SNS) and **JSON** for the JSON
protocols (EKS, Lambda, KMS, ECR). The documents carry the documented response field names; a
wrapper the reader flattens is the only liberty taken.

Every request is logged as ``"<method> <service> <action> <path>"``, which is what the
operation-allowlist tests assert against: the family may issue a read action and nothing else,
and no mutation verb may appear in the log at all.
"""

from __future__ import annotations

import json
import threading
import urllib.parse
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Final
from xml.sax.saxutils import escape

from arachne.creds.aws import access_key_id, verify_request

__all__ = [
    "ACCOUNTS",
    "AWS_LAB_ACCESS_KEY_ID",
    "AWS_LAB_REGION",
    "AWS_LAB_SECRET",
    "AwsLab",
    "start_aws_lab",
]

#: The lab credential. These are test constants, never a real credential.
AWS_LAB_ACCESS_KEY_ID: Final = "AKIAARACHNELAB0000000"
AWS_LAB_SECRET: Final = "arachne-lab-secret-access-key-not-a-real-credential"
AWS_LAB_REGION: Final = "us-east-1"

#: The services whose answers this fixture writes as XML (the Query and S3 REST protocols).
XML_SERVICES: Final[frozenset[str]] = frozenset(
    {"s3", "s3control", "iam", "ec2", "rds", "cloudtrail", "sqs", "sns"}
)

_PUBLIC_BUCKET_POLICY: Mapping[str, Any] = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "PublicRead",
            "Effect": "Allow",
            "Principal": "*",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::public-logs/*",
        }
    ],
}

_ADMIN_POLICY: Mapping[str, Any] = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Action": "*", "Resource": "*"},
    ],
}

_SAFE_POLICY: Mapping[str, Any] = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "s3:GetObject",
            "Resource": "arn:aws:s3:::safe-data/*",
        }
    ],
}

#: A *resource* policy (KMS, ECR) that trusts any principal. Identity policies have no
#: Principal element; a key or repository policy does, and that is the element this family
#: reads.
_PUBLIC_RESOURCE_POLICY: Mapping[str, Any] = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "PublicAccess",
            "Effect": "Allow",
            "Principal": "*",
            "Action": ["kms:Decrypt", "ecr:GetDownloadUrlForLayer"],
            "Resource": "*",
        }
    ],
}

_SAFE_RESOURCE_POLICY: Mapping[str, Any] = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::111122223333:root"},
            "Action": "kms:Decrypt",
            "Resource": "*",
        }
    ],
}

_PUBLIC_QUEUE_POLICY: Mapping[str, Any] = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sqs:SendMessage"}],
}

_SAFE_QUEUE_POLICY: Mapping[str, Any] = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"AWS": "arn:aws:iam::111122223333:root"},
            "Action": "sqs:SendMessage",
        }
    ],
}

_SAFE_ACCOUNT_PAB: Mapping[str, Any] = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}

_RISKY_ACCOUNT_PAB: Mapping[str, Any] = {
    "BlockPublicAcls": False,
    "IgnorePublicAcls": False,
    "BlockPublicPolicy": False,
    "RestrictPublicBuckets": False,
}

#: The two accounts the fixture serves. Each key is an action the handler answers.
ACCOUNTS: Final[dict[str, dict[str, Any]]] = {
    "risky": {
        "buckets": {
            "public-logs": {
                "acl": [
                    {
                        "Grantee": {
                            "Type": "Group",
                            "URI": "http://acs.amazonaws.com/groups/global/AllUsers",
                        },
                        "Permission": "READ",
                    },
                    {
                        "Grantee": {
                            "Type": "Group",
                            "URI": "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
                        },
                        "Permission": "WRITE",
                    },
                ],
                "policy": _PUBLIC_BUCKET_POLICY,
                "public_access_block": _RISKY_ACCOUNT_PAB,
                "encryption": None,
                "versioning": "Suspended",
                "logging": None,
            }
        },
        "account_summary": {"AccountMFAEnabled": 0, "AccountAccessKeysPresent": 1},
        "password_policy": None,
        "authorization_details": {
            "Policies": [{"PolicyName": "administrator", "PolicyDocument": _ADMIN_POLICY}],
            "Roles": [
                {
                    "RoleName": "open-role",
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": "*",
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                }
            ],
        },
        "instances": [
            {
                "InstanceId": "i-0123456789abcdef0",
                "MetadataOptions": {"HttpTokens": "optional", "HttpEndpoint": "enabled"},
            }
        ],
        "security_groups": [
            {
                "GroupId": "sg-0123456789abcdef0",
                "GroupName": "open-to-the-world",
                "IpPermissions": [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 22,
                        "ToPort": 22,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                        "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
                    },
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 3389,
                        "ToPort": 3389,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                    },
                ],
            }
        ],
        "volumes": [{"VolumeId": "vol-0123456789abcdef0", "Encrypted": False}],
        "ebs_default": False,
        "db_instances": [
            {
                "DBInstanceIdentifier": "orders-risky",
                "Engine": "postgres",
                "PubliclyAccessible": True,
                "StorageEncrypted": False,
            }
        ],
        "clusters": {
            "risky-cluster": {
                "resourcesVpcConfig": {
                    "EndpointPublicAccess": True,
                    "PublicAccessCidrs": ["0.0.0.0/0"],
                },
                "logging": {"ClusterLogging": [{"Type": "audit", "Enabled": False}]},
            }
        },
        "functions": {
            "risky-function": {
                "policy": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": "lambda:InvokeFunction",
                        }
                    ],
                },
                "url_auth": "NONE",
            }
        },
        "trails": [
            {
                "Name": "risky-trail",
                "TrailARN": "arn:aws:cloudtrail:us-east-1:111122223333:trail/risky-trail",
                "IsMultiRegionTrail": False,
                "IsLogging": False,
            }
        ],
        "keys": {
            "key-risky": {
                "KeyManager": "CUSTOMER",
                "KeyRotationEnabled": False,
                "policy": _PUBLIC_RESOURCE_POLICY,
            }
        },
        "queues": {
            "https://sqs.us-east-1.amazonaws.com/111122223333/risky-queue": (_PUBLIC_QUEUE_POLICY)
        },
        "topics": {"arn:aws:sns:us-east-1:111122223333:risky-topic": _PUBLIC_QUEUE_POLICY},
        "repositories": {"risky-repo": {"scan_on_push": False, "policy": _PUBLIC_RESOURCE_POLICY}},
        "account_public_access_block": _RISKY_ACCOUNT_PAB,
    },
    "safe": {
        "buckets": {
            "safe-data": {
                "acl": [
                    {
                        "Grantee": {
                            "Type": "CanonicalUser",
                            "ID": "canonical-user-id",
                        },
                        "Permission": "FULL_CONTROL",
                    }
                ],
                "policy": _SAFE_POLICY,
                "public_access_block": _SAFE_ACCOUNT_PAB,
                "encryption": {
                    "Rules": [
                        {
                            "ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"},
                            "BucketKeyEnabled": True,
                        }
                    ]
                },
                "versioning": "Enabled",
                "logging": {"LoggingEnabled": {"TargetBucket": "safe-logs"}},
            }
        },
        "account_summary": {"AccountMFAEnabled": 1, "AccountAccessKeysPresent": 0},
        "password_policy": {
            "MinimumPasswordLength": 16,
            "RequireSymbols": True,
            "RequireNumbers": True,
            "MaxPasswordAge": 90,
            "PasswordReusePrevention": 24,
        },
        "authorization_details": {
            "Policies": [
                {
                    "PolicyName": "read-only-objects",
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "s3:GetObject",
                                "Resource": "arn:aws:s3:::safe-data/*",
                            }
                        ],
                    },
                }
            ],
            "Roles": [
                {
                    "RoleName": "locked-role",
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"AWS": "arn:aws:iam::111122223333:root"},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                }
            ],
        },
        "instances": [
            {
                "InstanceId": "i-0fedcba9876543210",
                "MetadataOptions": {"HttpTokens": "required", "HttpEndpoint": "enabled"},
            }
        ],
        "security_groups": [
            {
                "GroupId": "sg-0fedcba9876543210",
                "GroupName": "internal-only",
                "IpPermissions": [
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 22,
                        "ToPort": 22,
                        "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
                    },
                    {
                        "IpProtocol": "tcp",
                        "FromPort": 3389,
                        "ToPort": 3389,
                        "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
                    },
                ],
            }
        ],
        "volumes": [{"VolumeId": "vol-0fedcba9876543210", "Encrypted": True}],
        "ebs_default": True,
        "db_instances": [
            {
                "DBInstanceIdentifier": "orders-safe",
                "Engine": "postgres",
                "PubliclyAccessible": False,
                "StorageEncrypted": True,
            }
        ],
        "clusters": {
            "safe-cluster": {
                "resourcesVpcConfig": {
                    "EndpointPublicAccess": False,
                    "PublicAccessCidrs": ["10.0.0.0/8"],
                },
                "logging": {"ClusterLogging": [{"Type": "audit", "Enabled": True}]},
            }
        },
        "functions": {
            "safe-function": {"policy": None, "url_auth": "AWS_IAM"},
        },
        "trails": [
            {
                "Name": "safe-trail",
                "TrailARN": "arn:aws:cloudtrail:us-east-1:111122223333:trail/safe-trail",
                "IsMultiRegionTrail": True,
                "IsLogging": True,
            }
        ],
        "keys": {
            "key-safe": {
                "KeyManager": "CUSTOMER",
                "KeyRotationEnabled": True,
                "policy": _SAFE_RESOURCE_POLICY,
            }
        },
        "queues": {
            "https://sqs.us-east-1.amazonaws.com/111122223333/safe-queue": _SAFE_QUEUE_POLICY
        },
        "topics": {"arn:aws:sns:us-east-1:111122223333:safe-topic": _SAFE_QUEUE_POLICY},
        "repositories": {"safe-repo": {"scan_on_push": True, "policy": None}},
        "account_public_access_block": _SAFE_ACCOUNT_PAB,
    },
}


@dataclass
class AwsLab:
    """A running fixture: its loopback base, its accounts and the requests it answered."""

    port: int = 0
    base_url: str = ""
    #: ``"<method> <service> <action> <path>"`` per answered request.
    requests: list[str] = field(default_factory=list)
    #: ``"<service>:<action>"`` per answered request (the operation the signer asked for).
    operations: list[str] = field(default_factory=list)

    def endpoint(self, account: str) -> str:
        """``aws-posture:<base>`` value for one account prefix (``risky`` or ``safe``)."""
        return f"{self.base_url.rstrip('/')}/{account.lstrip('/')}"

    def actions(self) -> list[str]:
        return [entry.split(":", 1)[1] for entry in self.operations]

    def services(self) -> set[str]:
        return {entry.split(":", 1)[0] for entry in self.operations}


# --------------------------------------------------------------------------- rendering
def _xml(name: str, value: Any) -> str:
    if isinstance(value, Mapping):
        body = "".join(_xml(str(key), item) for key, item in value.items())
        return f"<{name}>{body}</{name}>"
    if isinstance(value, (list, tuple)):
        body = "".join(_xml("member", item) for item in value)
        return f"<{name}>{body}</{name}>"
    if value is None:
        return f"<{name}/>"
    if isinstance(value, bool):
        return f"<{name}>{'true' if value else 'false'}</{name}>"
    return f"<{name}>{escape(str(value))}</{name}>"


def _render(service: str, document: Mapping[str, Any]) -> tuple[str, str]:
    """The answer in the service's own envelope: XML for the Query/S3 protocols, JSON else.

    The XML root holds the documented fields directly (``<Response><Buckets>...``); the reader
    flattens the root away, so both envelopes present the same top-level keys.
    """
    if service in XML_SERVICES:
        body = "".join(_xml(str(key), value) for key, value in document.items())
        return "text/xml", f"<Response>{body}</Response>"
    return "application/json", json.dumps(document)


# --------------------------------------------------------------------------- dispatch
def _segment(parts: list[str], index: int) -> str:
    return parts[index] if index < len(parts) else ""


def _s3_action(query: Mapping[str, list[str]], rest: list[str]) -> str:
    for subresource, action in (
        ("acl", "GetBucketAcl"),
        ("policy", "GetBucketPolicy"),
        ("publicAccessBlock", "GetBucketPublicAccessBlock"),
        ("encryption", "GetBucketEncryption"),
        ("versioning", "GetBucketVersioning"),
        ("logging", "GetBucketLogging"),
    ):
        if subresource in query:
            return action
    if rest:
        return "GetBucketAcl"  # an unknown bucket subresource: answer with a 404 below
    return "ListBuckets"


def _resolve(
    method: str, path: str, query: Mapping[str, list[str]], headers: Mapping[str, str]
) -> tuple[str, str, str]:
    """``(account, service, action)`` for a request path, or ``("", "", "")``.

    The action comes from the request itself the way AWS routes it: the ``X-Amz-Target`` for a
    JSON-RPC service, the ``Action`` query parameter for a Query API, and the path and
    subresource for S3, EKS and Lambda's REST APIs.
    """
    parts = [part for part in path.strip("/").split("/") if part]
    account = _segment(parts, 0)
    service = _segment(parts, 1)
    rest = parts[2:]
    target = headers.get("x-amz-target", "")
    if target:
        return account, service, target.rsplit(".", 1)[-1]
    if service == "s3":
        return account, service, _s3_action(query, rest)
    if service == "s3control" and path.endswith("/publicAccessBlock"):
        return account, service, "GetPublicAccessBlock"
    if service == "eks":
        if len(rest) >= 2 and rest[0] == "clusters":
            return account, service, "DescribeCluster"
        return account, service, "ListClusters"
    if service == "lambda":
        tail = "/".join(rest)
        if tail.endswith("/policy"):
            return account, service, "GetPolicy"
        if tail.endswith("/url"):
            return account, service, "GetFunctionUrlConfig"
        return account, service, "ListFunctions"
    action = _segment(query.get("Action", []), 0)
    return account, service, action


def _bucket_name(path: str) -> str:
    parts = [part for part in path.strip("/").split("/") if part]
    return _segment(parts, 2)


def _lambda_name(path: str) -> str:
    parts = [part for part in path.strip("/").split("/") if part]
    # /<account>/lambda/<date>/functions/<name>/...
    return parts[4] if len(parts) > 4 else ""


def _eks_name(path: str) -> str:
    parts = [part for part in path.strip("/").split("/") if part]
    return parts[3] if len(parts) > 3 else ""


def _response(
    account: str,
    service: str,
    action: str,
    path: str,
    query: Mapping[str, list[str]],
    resource: str = "",
) -> tuple[int, Mapping[str, Any]]:
    """``(status, document)`` for one read against one account."""
    data = ACCOUNTS[account]
    if action == "ListBuckets":
        return 200, {"Buckets": [{"Name": name} for name in data["buckets"]]}
    if action in {
        "GetBucketAcl",
        "GetBucketPolicy",
        "GetBucketPublicAccessBlock",
        "GetBucketEncryption",
        "GetBucketVersioning",
        "GetBucketLogging",
    }:
        bucket = data["buckets"].get(_bucket_name(path))
        if bucket is None:
            return 404, {"Error": {"Code": "NoSuchBucket"}}
        key = {
            "GetBucketAcl": "acl",
            "GetBucketPolicy": "policy",
            "GetBucketPublicAccessBlock": "public_access_block",
            "GetBucketEncryption": "encryption",
            "GetBucketVersioning": "versioning",
            "GetBucketLogging": "logging",
        }[action]
        value = bucket[key]
        if value is None:
            return 404, {"Error": {"Code": "NoSuchConfiguration"}}
        if action == "GetBucketAcl":
            return 200, {"Grants": value}
        if action == "GetBucketPolicy":
            return 200, {"Policy": json.dumps(value)}
        if action == "GetBucketPublicAccessBlock":
            return 200, {"PublicAccessBlockConfiguration": value}
        if action == "GetBucketEncryption":
            return 200, {"Rules": value.get("Rules", [])}
        if action == "GetBucketVersioning":
            return 200, {"Status": value}
        return 200, value if isinstance(value, Mapping) else {}
    if action == "GetPublicAccessBlock":
        pab = data["account_public_access_block"]
        return 200, {"PublicAccessBlockConfiguration": pab}
    if action == "GetAccountSummary":
        return 200, {"SummaryMap": data["account_summary"]}
    if action == "GetAccountPasswordPolicy":
        policy = data["password_policy"]
        if policy is None:
            return 404, {"Error": {"Code": "NoSuchEntity"}}
        return 200, {"PasswordPolicy": policy}
    if action == "GetAccountAuthorizationDetails":
        return 200, data["authorization_details"]
    if action == "DescribeInstances":
        return 200, {"Instances": data["instances"]}
    if action == "DescribeSecurityGroups":
        return 200, {"SecurityGroups": data["security_groups"]}
    if action == "DescribeVolumes":
        return 200, {"Volumes": data["volumes"]}
    if action == "GetEbsEncryptionByDefault":
        return 200, {"EbsEncryptionByDefault": data["ebs_default"]}
    if action == "DescribeDBInstances":
        return 200, {"DBInstances": data["db_instances"]}
    if action == "ListClusters":
        return 200, {"Clusters": list(data["clusters"])}
    if action == "DescribeCluster":
        cluster = data["clusters"].get(_eks_name(path))
        if cluster is None:
            return 404, {"message": "ResourceNotFoundException"}
        return 200, {"cluster": {"name": _eks_name(path), **cluster}}
    if action == "ListFunctions":
        return 200, {"Functions": [{"FunctionName": name} for name in data["functions"]]}
    if action == "GetPolicy":
        function = data["functions"].get(_lambda_name(path))
        if function is None or function["policy"] is None:
            return 404, {"message": "ResourceNotFoundException"}
        return 200, {"Policy": json.dumps(function["policy"])}
    if action == "GetFunctionUrlConfig":
        function = data["functions"].get(_lambda_name(path))
        if function is None:
            return 404, {"message": "ResourceNotFoundException"}
        return 200, {
            "FunctionUrl": "https://example.lambda-url.us-east-1.on.aws/",
            "AuthType": function["url_auth"],
            "FunctionName": _lambda_name(path),
        }
    if action == "DescribeTrails":
        return 200, {"trailList": data["trails"]}
    if action == "GetTrailStatus":
        trail = _named(data["trails"], query.get("Name", [""])[0])
        if trail is None:
            return 404, {"Error": {"Code": "TrailNotFoundException"}}
        return 200, {"IsLogging": trail["IsLogging"]}
    if action == "ListKeys":
        return 200, {"Keys": [{"KeyId": name} for name in data["keys"]], "Truncated": False}
    if action == "DescribeKey":
        key = data["keys"].get(resource)
        if key is None:
            return 404, {"__type": "NotFoundException"}
        return 200, {"KeyMetadata": {"KeyId": resource, "KeyManager": key["KeyManager"]}}
    if action == "GetKeyPolicy":
        key = data["keys"].get(resource)
        if key is None:
            return 404, {"__type": "NotFoundException"}
        return 200, {"Policy": json.dumps(key["policy"])}
    if action == "GetKeyRotationStatus":
        key = data["keys"].get(resource)
        if key is None:
            return 404, {"__type": "NotFoundException"}
        return 200, {"KeyRotationEnabled": key["KeyRotationEnabled"]}
    if action == "ListQueues":
        return 200, {"QueueUrls": list(data["queues"])}
    if action == "GetQueueAttributes":
        queue = _named_mapping(data["queues"], query.get("QueueUrl", [""])[0])
        if queue is None:
            return 404, {"Error": {"Code": "AWS.SimpleQueueService.NonExistentQueue"}}
        return 200, {"Attributes": {"Policy": json.dumps(queue)}}
    if action == "ListTopics":
        return 200, {"Topics": [{"TopicArn": arn} for arn in data["topics"]]}
    if action == "GetTopicAttributes":
        topic = _named_mapping(data["topics"], query.get("TopicArn", [""])[0])
        if topic is None:
            return 404, {"Error": {"Code": "NotFound"}}
        return 200, {"Attributes": {"Policy": json.dumps(topic)}}
    if action == "DescribeRepositories":
        return 200, {
            "repositories": [
                {
                    "repositoryName": name,
                    "imageScanningConfiguration": {"scanOnPush": repository["scan_on_push"]},
                }
                for name, repository in data["repositories"].items()
            ]
        }
    if action == "GetRepositoryPolicy":
        repository = data["repositories"].get(resource)
        if repository is None or repository["policy"] is None:
            return 404, {"__type": "RepositoryPolicyNotFoundException"}
        return 200, {
            "registryId": "111122223333",
            "repositoryName": resource,
            "policyText": json.dumps(repository["policy"]),
        }
    return 404, {"Error": {"Code": "InvalidAction", "Message": action}}


def _named(items: list[Mapping[str, Any]], name: str) -> Mapping[str, Any] | None:
    for item in items:
        if str(item.get("Name", "")) == name or str(item.get("TrailARN", "")).endswith(name):
            return item
    return None


def _named_mapping(items: Mapping[str, Any], name: str) -> Mapping[str, Any] | None:
    value = items.get(name)
    return value if isinstance(value, Mapping) else None


def _body_resource(body: str) -> str:
    """The resource a JSON-RPC read names in its body (KMS ``KeyId``, ECR ``repositoryName``).

    The JSON protocols carry the resource in the body rather than in the path, exactly as AWS
    does, so the fixture reads it from there.
    """
    if not body:
        return ""
    try:
        document = json.loads(body)
    except json.JSONDecodeError:
        return ""
    if not isinstance(document, Mapping):
        return ""
    for key in ("KeyId", "repositoryName"):
        if key in document:
            return str(document[key])
    return ""


class _Handler(BaseHTTPRequestHandler):
    server_version = "arachne-aws-lab/1.0"
    protocol_version = "HTTP/1.1"
    # TCP_NODELAY: the same Nagle/delayed-ACK stall as tests/lab/web_lab.py.
    disable_nagle_algorithm = True
    lab: AwsLab

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - stdlib signature
        return

    def _respond(self, status: int, content_type: str, body: str) -> None:
        payload = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(payload)

    def _handle(self) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        query = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        headers = {name.lower(): value for name, value in self.headers.items()}
        length = int(headers.get("content-length", "0") or "0")
        body = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        account, service, action = _resolve(self.command, parsed.path, query, headers)
        resource = _body_resource(body)
        self.lab.requests.append(f"{self.command} {service} {action} {parsed.path}")
        if account not in ACCOUNTS:
            self._respond(404, "application/json", json.dumps({"message": "no such account"}))
            return
        url = f"http://{headers.get('host', '')}{self.path}"
        signed = access_key_id(headers) == AWS_LAB_ACCESS_KEY_ID and verify_request(
            method=self.command,
            url=url,
            headers=headers,
            service=service,
            region=AWS_LAB_REGION,
            secret_key=AWS_LAB_SECRET,
            payload=body.encode("utf-8"),
        )
        if not signed:
            self._respond(
                403,
                "application/json",
                json.dumps({"message": "the request was not signed with the lab credential"}),
            )
            return
        self.lab.operations.append(f"{service}:{action}")
        status, document = _response(account, service, action, parsed.path, query, resource)
        content_type, text = _render(service, document)
        self._respond(status, content_type, text)

    def do_GET(self) -> None:
        self._handle()

    def do_POST(self) -> None:
        self._handle()

    def _refuse_write(self) -> None:
        parsed = urllib.parse.urlsplit(self.path)
        self.lab.requests.append(f"{self.command} write-refused {parsed.path}")
        self._respond(405, "application/json", json.dumps({"message": "method not allowed"}))

    def do_PUT(self) -> None:
        self._refuse_write()

    def do_PATCH(self) -> None:
        self._refuse_write()

    def do_DELETE(self) -> None:
        self._refuse_write()


@contextmanager
def start_aws_lab() -> Iterator[AwsLab]:
    """Start the fixture on loopback and yield its handle; tear it down on exit."""
    lab = AwsLab()
    handler = type("_BoundAwsHandler", (_Handler,), {"lab": lab})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    server.daemon_threads = True
    port = server.server_address[1]
    lab.port = port
    lab.base_url = f"http://127.0.0.1:{port}/"
    thread = threading.Thread(
        target=server.serve_forever, args=(0.05,), name="arachne-aws-lab", daemon=True
    )
    thread.start()
    try:
        yield lab
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
