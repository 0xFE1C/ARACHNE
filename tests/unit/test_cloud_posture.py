"""The Azure/GCP/Kubernetes operation allowlists and readers (WP-32, REQ-DET-025).

The acceptance criterion this module exists for is the requirement's third deliverable: *"the
operation allowlist updated so only read-only API calls are reachable; a test asserts it."* The
test is deliberately strict rather than permissive, because the pitfall names the most likely
defect in a posture family — a check that quietly mutates the resource it is auditing:

* every allowlist entry names a read action and the ``GET`` method;
* a mutation action name is **unrepresentable** — constructing one raises;
* a non-``GET`` method is unrepresentable;
* the client refuses an operation object that is not a declared entry, so a check cannot build
  its own call;
* the provider ledger's operations are exactly each module's allowlist, so the two statements of
  coverage cannot drift apart;
* every check declares only allowlisted reads;
* **the Kubernetes allowlist contains no operation that names a secret**, because exposure is
  established from RBAC metadata rather than by reading a secret's contents.

It also pins the small reader, because a policy is only as good as the fields it reads: the
envelopes Azure ARM and GCP use must present the same fields a bare list does.
"""

from __future__ import annotations

import pytest

from arachne.modules.cloud_providers import by_provider
from arachne.modules.m5.azure_posture import AZURE_POSTURE_CHECKS, AZURE_READ_OPERATIONS
from arachne.modules.m5.gcp_posture import GCP_POSTURE_CHECKS, GCP_READ_OPERATIONS
from arachne.modules.m5.k8s_posture import (
    K8S_POSTURE_CHECKS,
    K8S_READ_OPERATIONS,
    _grants_secret_read,
    _is_custom_role,
)
from arachne.modules.m5.posture_read import (
    CloudReadClient,
    CloudReadOperation,
    CloudReadOperationError,
    base_for,
    get,
    items_of,
    text_of,
)

FAMILIES = {
    "azure": (AZURE_POSTURE_CHECKS, AZURE_READ_OPERATIONS),
    "gcp": (GCP_POSTURE_CHECKS, GCP_READ_OPERATIONS),
    "k8s": (K8S_POSTURE_CHECKS, K8S_READ_OPERATIONS),
}


# --------------------------------------------------------------------------- the allowlists
@pytest.mark.parametrize("provider", sorted(FAMILIES))
def test_every_operation_is_a_read(provider: str) -> None:
    _checks, operations = FAMILIES[provider]
    assert operations, provider
    for operation in operations:
        assert operation.method == "GET", operation
        assert operation.path.startswith("/"), operation


@pytest.mark.parametrize("provider", sorted(FAMILIES))
def test_the_allowlist_is_closed(provider: str) -> None:
    """No duplicates, and every entry names an action and an absolute path."""
    _checks, operations = FAMILIES[provider]
    times_seen = [operation.path for operation in operations]
    assert len(times_seen) == len(set(times_seen)), times_seen
    for operation in operations:
        assert operation.action
        assert operation.path.startswith("/"), operation


@pytest.mark.parametrize(
    "action",
    [
        "createBucket",
        "deleteInstance",
        "putObject",
        "modifyCluster",
        "setIamPolicy",
        "updateBucket",
        "patchDeployment",
        "runJob",
    ],
)
def test_a_mutation_action_is_unrepresentable(action: str) -> None:
    with pytest.raises(CloudReadOperationError):
        CloudReadOperation(action=action, path="/x")


@pytest.mark.parametrize("action", ["invokeFunction", "authorize", "upload"])
def test_another_class_of_mutation_action_is_unrepresentable(action: str) -> None:
    with pytest.raises(CloudReadOperationError):
        CloudReadOperation(action=action, path="/x")


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE", "HEAD"])
def test_a_non_get_method_is_unrepresentable(method: str) -> None:
    with pytest.raises(CloudReadOperationError, match="not a read method"):
        CloudReadOperation(action="listBuckets", path="/x", method=method)


def test_a_relative_path_is_unrepresentable() -> None:
    with pytest.raises(CloudReadOperationError, match="absolute"):
        CloudReadOperation(action="listBuckets", path="storage/v1/b")


def test_an_action_that_does_not_open_with_a_read_verb_is_unrepresentable() -> None:
    with pytest.raises(CloudReadOperationError, match="read verb"):
        CloudReadOperation(action="inspectBuckets", path="/x")


def test_a_read_name_that_merely_contains_a_mutation_word_is_allowed() -> None:
    """The guard is a prefix test: ``listAddressPools`` contains ``Add`` and is still a read."""
    operation = CloudReadOperation(action="listAddressPools", path="/x")
    assert operation.method == "GET"


@pytest.mark.parametrize("provider", sorted(FAMILIES))
def test_the_client_refuses_an_operation_outside_the_allowlist(provider: str) -> None:
    """A check cannot build its own call: the client's guard is the operation's membership."""
    _checks, operations = FAMILIES[provider]
    client = CloudReadClient(
        object(),
        "https://example.invalid",
        operations=frozenset(operations),  # type: ignore[arg-type]
    )
    invented = CloudReadOperation(action="getObject", path="/x")
    assert invented not in set(operations)
    with pytest.raises(CloudReadOperationError, match="not a declared read operation"):
        client.url_for(invented)


@pytest.mark.parametrize("provider", sorted(FAMILIES))
def test_every_check_declares_only_allowlisted_reads(provider: str) -> None:
    checks, operations = FAMILIES[provider]
    allowed = set(operations)
    for check in checks:
        assert check.reads, check.metadata.id
        for operation in check.reads:
            assert operation in allowed, (check.metadata.id, operation.key)


@pytest.mark.parametrize("provider", sorted(FAMILIES))
def test_the_provider_ledger_matches_the_module_allowlist(provider: str) -> None:
    """The two statements of what may be read cannot drift apart."""
    _checks, operations = FAMILIES[provider]
    if provider == "k8s":
        assert not any(entry.provider == "k8s" for entry in by_provider().values())
        return
    entry = by_provider()[provider]
    declared = {(operation.method, operation.path) for operation in operations}
    assert set(entry.operations) == declared
    assert {method for method, _path in entry.operations} == {"GET"}


@pytest.mark.parametrize("provider", sorted(FAMILIES))
def test_the_provider_ledger_names_every_posture_check(provider: str) -> None:
    checks, _operations = FAMILIES[provider]
    if provider == "k8s":
        return  # Kubernetes is not a cloud provider; its checks are not in that ledger
    entry = by_provider()[provider]
    for check in checks:
        assert check.metadata.id in entry.check_ids, check.metadata.id


# --------------------------------------------------------------------------- secrets
def test_no_kubernetes_operation_names_a_secret() -> None:
    """REQ-DET-025: no operation in the allowlist can return a secret's contents."""
    for operation in K8S_READ_OPERATIONS:
        assert "secret" not in operation.path.lower(), operation.key
        assert "secret" not in operation.action.lower(), operation.action


def test_the_secrets_check_reads_rbac_metadata_only() -> None:
    check = {item.metadata.id: item for item in K8S_POSTURE_CHECKS}["m5.k8s-rbac-secrets-exposed"]
    assert check.reads
    for operation in check.reads:
        assert "rbac.authorization.k8s.io" in operation.path, operation.key
    assert "secret" not in " ".join(operation.path for operation in check.reads).lower()


def test_a_role_that_grants_a_secret_read_is_recognised() -> None:
    role = {
        "metadata": {"name": "reader"},
        "rules": [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get", "list"]}],
    }
    assert _grants_secret_read(role)
    wildcard = {"rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}]}
    assert _grants_secret_read(wildcard)
    harmless = {"rules": [{"apiGroups": [""], "resources": ["configmaps"], "verbs": ["get"]}]}
    assert not _grants_secret_read(harmless)
    write_only = {"rules": [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["create"]}]}
    assert not _grants_secret_read(write_only)


def test_a_builtin_role_is_never_reported() -> None:
    """``cluster-admin`` is a wildcard by design; reporting it would fire on every cluster."""
    assert not _is_custom_role("cluster-admin")
    assert not _is_custom_role("system:discovery")
    assert not _is_custom_role("edit")
    assert _is_custom_role("custom-wildcard")


# --------------------------------------------------------------------------- the reference
@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("azure-posture:https://api.example.invalid", "https://api.example.invalid"),
        ("azure-posture:api.example.invalid", "https://api.example.invalid"),
        ("azureposture:api.example.invalid", "https://api.example.invalid"),
        ("azure-posture:", None),
        ("azure:my-storage-account", None),
        ("gcp-posture:api.example.invalid", None),
        ("https://example.invalid", None),
    ],
)
def test_only_the_family_reference_resolves(value: str, expected: str | None) -> None:
    assert base_for(value, "azure-posture", "azureposture") == expected


def test_a_bucket_reference_is_not_a_posture_base() -> None:
    """``azure:<account>`` is the existing bucket vocabulary and must not be claimed here."""
    for check in AZURE_POSTURE_CHECKS:
        from arachne.modules.base import Asset

        assert not check().supports(Asset.from_meta("bucket", "azure:myaccount", {}))


# --------------------------------------------------------------------------- the reader
def test_items_of_unwraps_every_envelope() -> None:
    bare = [{"name": "a"}, {"name": "b"}]
    assert [text_of(item, "name") for item in items_of(bare)] == ["a", "b"]
    assert [text_of(item, "name") for item in items_of({"value": bare})] == ["a", "b"]
    assert [text_of(item, "name") for item in items_of({"items": bare})] == ["a", "b"]
    assert [text_of(item, "name") for item in items_of({"clusters": bare}, "clusters")] == [
        "a",
        "b",
    ]
    assert items_of(None) == []
    assert items_of("not-a-list") == []


def test_the_reader_is_case_insensitive() -> None:
    assert get({"BucketName": "x"}, "bucketname") == "x"
    assert text_of({"Status": "Enabled"}, "status") == "Enabled"
    assert get({"Value": [1]}, "value") == [1]


def test_the_url_is_built_from_the_operation_alone() -> None:
    operation = CloudReadOperation(
        action="listBuckets", path="/v1/b/{project}", query=(("api-version", "1"),)
    )
    client = CloudReadClient(
        object(),  # type: ignore[arg-type]
        "https://example.invalid",
        operations=frozenset({operation}),
        values={"project": "lab"},
    )
    url = client.url_for(operation)
    assert url == "https://example.invalid/v1/b/lab?api-version=1"
