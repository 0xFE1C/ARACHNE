"""The AWS operation allowlist and response reader (WP-31, REQ-DET-024).

The acceptance criterion this module exists for is the third deliverable: *"the operation
allowlist updated so only read-only API calls are reachable; a test asserts it."* The test is
deliberately strict rather than permissive, because the pitfall names the most likely defect in
this family — a check that quietly mutates the account:

* every allowlist entry names a read action and a read method;
* the only ``POST`` entries are the two JSON-RPC services whose *read* API is ``POST``, and
  their actions are read verbs;
* a mutation action name is **unrepresentable** — constructing one raises;
* the client refuses an operation object that is not a declared entry, so a check cannot build
  its own call;
* the provider ledger's GET operations are exactly the GET half of the allowlist, so the two
  statements of coverage cannot drift apart;
* every check declares only allowlisted reads.

It also pins the reader, because a policy is only as good as the fields it reads: the same
documented field names must survive both envelopes an AWS read API can return.
"""

from __future__ import annotations

import pytest

from arachne.modules.cloud_providers import CLOUD_PROVIDER_MATRIX, by_provider
from arachne.modules.m5.aws_posture import (
    AWS_POSTURE_CHECKS,
    AWS_READ_OPERATIONS,
    MUTATION_VERBS,
    READ_VERBS,
    AwsOperationError,
    AwsReadClient,
    AwsReadOperation,
    _base_for,
    bool_of,
    collect,
    decode_document,
    entries,
    get,
    public_statements,
    service_areas,
    text_of,
)

POST_SERVICES = {"kms", "ecr"}


# --------------------------------------------------------------------------- the allowlist
def test_every_operation_is_a_read() -> None:
    for operation in AWS_READ_OPERATIONS:
        assert operation.action.startswith(READ_VERBS), operation.action
        assert not any(verb in operation.action for verb in MUTATION_VERBS), operation.action
        assert operation.method == "GET" or (
            operation.method == "POST" and operation.service in POST_SERVICES
        ), operation


def test_post_is_only_the_two_json_rpc_reads() -> None:
    post = [operation for operation in AWS_READ_OPERATIONS if operation.method == "POST"]
    assert post, "this test would be vacuous without the JSON-RPC reads"
    assert {operation.service for operation in post} == POST_SERVICES
    for operation in post:
        assert operation.target, operation
        assert operation.action.startswith(("List", "Describe", "Get")), operation


def test_the_allowlist_is_closed() -> None:
    """No duplicates, and every entry names a service and an absolute path."""
    keys = [operation.key for operation in AWS_READ_OPERATIONS]
    assert len(keys) == len(set(keys)), keys
    for operation in AWS_READ_OPERATIONS:
        assert operation.service
        assert operation.path.startswith("/"), operation


@pytest.mark.parametrize(
    "action",
    ["DeleteBucket", "PutObject", "CreateBucket", "ModifyDBInstance", "SetQueueAttributes"],
)
def test_a_mutation_action_is_unrepresentable(action: str) -> None:
    with pytest.raises(AwsOperationError):
        AwsReadOperation(action=action, service="s3", method="GET", path="/")


def test_a_write_method_is_unrepresentable() -> None:
    with pytest.raises(AwsOperationError, match="not a read method"):
        AwsReadOperation(action="ListBuckets", service="s3", method="DELETE", path="/")


def test_a_post_read_without_a_target_is_unrepresentable() -> None:
    with pytest.raises(AwsOperationError, match="X-Amz-Target"):
        AwsReadOperation(action="ListKeys", service="kms", method="POST", path="/")


def test_a_relative_path_is_unrepresentable() -> None:
    with pytest.raises(AwsOperationError, match="absolute"):
        AwsReadOperation(action="ListKeys", service="kms", method="GET", path="keys")


def test_the_client_refuses_an_operation_outside_the_allowlist() -> None:
    """A check cannot build its own call: the client's guard is the operation's membership."""
    client = AwsReadClient(object(), "https://example.invalid", region="us-east-1")  # type: ignore[arg-type]
    invented = AwsReadOperation(
        action="GetObject", service="s3", method="GET", path="/{bucket}/{key}"
    )
    assert invented not in set(AWS_READ_OPERATIONS)
    with pytest.raises(AwsOperationError, match="not a declared read operation"):
        client.url_for(invented)


def test_every_check_declares_only_allowlisted_reads() -> None:
    allowed = set(AWS_READ_OPERATIONS)
    for check in AWS_POSTURE_CHECKS:
        assert check.reads, check.metadata.id
        for operation in check.reads:
            assert operation in allowed, (check.metadata.id, operation.key)


def test_the_provider_ledger_is_the_get_half_of_the_allowlist() -> None:
    """The two statements of what may be read cannot drift apart."""
    entry = by_provider()["aws"]
    declared = {
        (operation.method, f"/{operation.service}{operation.path}")
        for operation in AWS_READ_OPERATIONS
        if operation.method == "GET"
    }
    assert set(entry.operations) == declared
    assert len(entry.operations) == len(declared), "the ledger repeats an operation"
    assert {method for method, _path in entry.operations} == {"GET"}


def test_the_provider_ledger_names_every_posture_check() -> None:
    entry = by_provider()["aws"]
    for check in AWS_POSTURE_CHECKS:
        assert check.metadata.id in entry.check_ids, check.metadata.id


def test_every_scope_area_the_requirement_names_has_a_check() -> None:
    areas = set(service_areas().values())
    assert {
        "s3",
        "iam",
        "ec2",
        "rds",
        "eks",
        "lambda",
        "cloudtrail",
        "kms",
        "sqs",
        "sns",
        "ecr",
        "s3control",
    } <= areas


def test_the_aws_row_is_the_only_one_that_declares_the_family() -> None:
    declaring = [
        entry.provider
        for entry in CLOUD_PROVIDER_MATRIX
        if any(check.metadata.id in entry.check_ids for check in AWS_POSTURE_CHECKS)
    ]
    assert declaring == ["aws"], declaring


# --------------------------------------------------------------------------- the reference
def test_only_the_aws_posture_reference_resolves() -> None:
    assert _base_for("aws-posture:https://api.example.invalid") == "https://api.example.invalid"
    assert _base_for("aws-posture:api.example.invalid") == "https://api.example.invalid"
    assert _base_for("aws-posture:") is None
    assert _base_for("s3:my-bucket") is None
    assert _base_for("https://example.invalid") is None


# --------------------------------------------------------------------------- the reader
_JSON_DOCUMENT = {
    "Buckets": [{"Name": "public-logs"}, {"Name": "safe-data"}],
    "PublicAccessBlockConfiguration": {"BlockPublicAcls": True},
}
_XML_DOCUMENT = (
    "<Response>"
    "<Buckets><member><Name>public-logs</Name></member><member><Name>safe-data</Name></member></Buckets>"
    "<PublicAccessBlockConfiguration><BlockPublicAcls>true</BlockPublicAcls></PublicAccessBlockConfiguration>"
    "</Response>"
)


def test_both_envelopes_present_the_same_fields() -> None:
    import json

    from_json = decode_document(json.dumps(_JSON_DOCUMENT))
    from_xml = decode_document(_XML_DOCUMENT)
    for document in (from_json, from_xml):
        buckets = entries(get(document, "Buckets"))
        assert [text_of(bucket, "Name") for bucket in buckets] == ["public-logs", "safe-data"]
        configuration = get(document, "PublicAccessBlockConfiguration")
        assert bool_of(configuration, "BlockPublicAcls") is True


def test_the_reader_is_case_insensitive_and_flattens_wrappers() -> None:
    document = decode_document(_XML_DOCUMENT)
    assert get(document, "buckets") is not None
    assert collect(document, "Bucket", "Buckets")
    assert text_of({"Status": "Enabled"}, "status") == "Enabled"


def test_a_malformed_answer_is_refused_not_guessed() -> None:
    from arachne.modules.m5.aws_posture import AwsRefusedError

    with pytest.raises(AwsRefusedError):
        decode_document("{not json")
    with pytest.raises(AwsRefusedError):
        decode_document("<not-xml")


# --------------------------------------------------------------------------- the policy test
def test_a_wildcard_principal_without_a_condition_is_public() -> None:
    policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}],
    }
    assert public_statements(policy)


def test_a_wildcard_principal_scoped_by_a_condition_is_not_public() -> None:
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Condition": {"StringEquals": {"aws:SourceVpc": "vpc-123"}},
            }
        ],
    }
    assert public_statements(policy) == []


def test_a_named_principal_is_not_public() -> None:
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::111122223333:root"},
                "Action": "s3:GetObject",
            }
        ],
    }
    assert public_statements(policy) == []
