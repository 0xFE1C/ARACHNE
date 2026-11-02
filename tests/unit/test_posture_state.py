"""The cloud-config state model: snapshot parsing, drift diffing, policies (S23, REQ-POSTURE-001).

The properties under test are the ones the drift detector stands on: stable resource
identity across reordering, change detection by config hash (never by JSON position),
deltas that always carry before/after, and policy evaluation that agrees with the drift
path's "did the new state breach something?" predicate.
"""

from __future__ import annotations

import json

import pytest

from arachne.core.errors import ConfigurationError
from arachne.posture.state import (
    CloudSnapshot,
    PosturePolicy,
    canonical_config,
    config_hash,
    config_violates,
    diff_snapshots,
    evaluate_policies,
    parse_snapshot_document,
    resource_key_of,
)


def _normalized(resources: list[dict[str, object]]) -> dict[str, object]:
    return {"provider": "aws", "account": "000", "resources": resources}


def _resource(
    rid: str = "app-assets",
    service: str = "storage",
    public: bool = False,
    encrypted: bool = True,
) -> dict[str, object]:
    return {
        "id": rid,
        "service": service,
        "type": service,
        "config": {"public": public, "encrypted": encrypted},
    }


# ------------------------------------------------------------------ parsing
def test_the_normalized_export_parses_round_stable() -> None:
    snapshot = parse_snapshot_document(_normalized([_resource()]), source="test")
    assert snapshot.provider == "aws"
    assert len(snapshot.resources) == 1
    resource = snapshot.resources[0]
    assert resource.key == "aws:storage/app-assets"
    assert resource.config == {"encrypted": True, "public": False}


def test_a_resource_without_an_id_is_refused_not_guessed() -> None:
    with pytest.raises(ConfigurationError):
        parse_snapshot_document(_normalized([{"service": "storage"}]), source="test")


def test_an_unrecognised_shape_is_refused() -> None:
    with pytest.raises(ConfigurationError):
        parse_snapshot_document({"anything": []}, source="test")
    with pytest.raises(ConfigurationError):
        parse_snapshot_document(["not", "an", "object"], source="test")


def test_an_aws_describe_security_groups_response_parses() -> None:
    doc = {
        "ownerId": "123456789012",
        "securityGroups": [
            {
                "GroupId": "sg-1",
                "GroupName": "web",
                "VpcId": "vpc-1",
                "IpPermissions": [
                    {"IpRanges": [{"CidrIp": "0.0.0.0/0"}]},
                    {"IpRanges": [{"CidrIp": "10.0.0.0/8"}]},
                ],
            }
        ],
    }
    snapshot = parse_snapshot_document(doc, source="aws")
    assert snapshot.provider == "aws"
    assert snapshot.account == "123456789012"
    resource = snapshot.resources[0]
    assert resource.key == "aws:ec2/sg-1"
    assert resource.config["open_to_world"] is True
    assert resource.config["open_cidrs"] == ["0.0.0.0/0", "10.0.0.0/8"]


def test_an_azure_list_response_parses_publicity_and_encryption() -> None:
    doc = {
        "value": [
            {
                "id": "/subscriptions/x/storageAccounts/a",
                "name": "a",
                "type": "Microsoft.Storage/storageAccounts",
                "properties": {"publicAccess": "Enabled", "encryptionEnabled": False},
            }
        ]
    }
    snapshot = parse_snapshot_document(doc, source="azure")
    resource = snapshot.resources[0]
    assert resource.provider == "azure"
    assert resource.service == "storage"
    assert resource.config["public"] is True
    assert resource.config["encrypted"] is False


def test_a_gcp_aggregated_list_response_parses_buckets() -> None:
    doc = {
        "items": {
            "us-central1": {
                "buckets": [
                    {"name": "images", "iamConfiguration": {"publicAccessPrevention": "inherited"}}
                ]
            }
        }
    }
    snapshot = parse_snapshot_document(doc, source="gcp")
    resource = snapshot.resources[0]
    assert resource.key == "gcp:bucket/images"
    assert resource.config["public"] is True


# ------------------------------------------------------------------ identity & hashing
def test_identity_survives_reordering_and_config_hash_detects_change() -> None:
    a = {"public": False, "encrypted": True}
    b = {"encrypted": True, "public": False}
    assert canonical_config(a) == canonical_config(b)
    assert config_hash(a) == config_hash(b)
    assert config_hash({"public": True, "encrypted": True}) != config_hash(a)
    assert resource_key_of("AWS", "S3", " x ") == "aws:s3/x"


# ------------------------------------------------------------------ drift
def _row(config: dict[str, object]) -> dict[str, object]:
    """A baseline row shape (what the store returns, what the diff reads)."""
    return {"config": config, "provider": "aws", "service": "storage"}


def test_diff_reports_added_removed_and_modified_with_before_and_after() -> None:
    baseline = {
        "aws:storage/kept": _row({"public": False, "encrypted": True}),
        "aws:storage/gone": _row({"public": False}),
    }
    snapshot = CloudSnapshot(
        provider="aws",
        resources=(
            parse_snapshot_document(
                _normalized(
                    [
                        _resource("kept", public=False, encrypted=True),
                        _resource("newcomer", public=True, encrypted=False),
                    ]
                )
            ).resources
        ),
    )
    deltas = diff_snapshots(baseline, snapshot)
    changes = {delta.resource_key: delta for delta in deltas}
    assert set(changes) == {"aws:storage/gone", "aws:storage/newcomer"}
    removed = changes["aws:storage/gone"]
    assert removed.change == "removed"
    assert removed.before == {"public": False}
    assert removed.after is None
    added = changes["aws:storage/newcomer"]
    assert added.change == "added"
    assert added.after == {"public": True, "encrypted": False}
    assert added.before is None


def test_a_modified_resource_names_its_changed_keys() -> None:
    baseline = {
        "aws:storage/app-assets": {
            "config": {"public": False, "encrypted": True},
            "provider": "aws",
            "service": "storage",
        }
    }
    snapshot = parse_snapshot_document(_normalized([_resource("app-assets", public=True)]))
    (delta,) = diff_snapshots(baseline, snapshot)
    assert delta.change == "modified"
    assert delta.before == {"public": False, "encrypted": True}
    assert delta.after == {"public": True, "encrypted": True}
    assert delta.changed_keys == ("public",)


def test_an_identical_resource_is_not_a_delta() -> None:
    baseline = {
        "aws:storage/app-assets": {
            "config": {"public": False, "encrypted": True},
            "provider": "aws",
            "service": "storage",
        }
    }
    snapshot = parse_snapshot_document(_normalized([_resource("app-assets")]))
    assert diff_snapshots(baseline, snapshot) == ()


# ------------------------------------------------------------------ policies
def _policies() -> tuple[PosturePolicy, ...]:
    return (
        PosturePolicy("storage-public", "high", "public", True, service="storage"),
        PosturePolicy("storage-unencrypted", "medium", "encrypted", False, service="storage"),
        PosturePolicy("database-public", "high", "publicly_accessible", True),
    )


def test_policies_fire_on_the_observed_value_and_service() -> None:
    snapshot = parse_snapshot_document(
        _normalized(
            [
                _resource("open", public=True, encrypted=False),
                _resource("db", service="database", encrypted=True),
            ]
        )
    )
    # The database resource carries no publicly_accessible key: the rule cannot fire on it.
    violations = evaluate_policies(snapshot, _policies())
    assert [(item.policy_id, item.resource_key) for item in violations] == [
        ("storage-public", "aws:storage/open"),
        ("storage-unencrypted", "aws:storage/open"),
    ]


def test_a_service_scoped_policy_matches_an_explicit_type() -> None:
    import dataclasses

    snapshot = parse_snapshot_document(_normalized([_resource("weird")]))
    policy = PosturePolicy("storage-public", "high", "public", True, service="storage")
    weird = snapshot.resources[0]
    # A resource whose service label is provider-specific still matches when its
    # normalized config explicitly types it (the export's own vocabulary).
    weird = dataclasses.replace(weird, service="s3", config={"type": "storage", "public": True})
    assert policy.matches(weird)
    assert config_violates(weird.config, policy)
    assert not policy.matches(dataclasses.replace(weird, service="queue", config={"type": "queue"}))


def test_config_violates_agrees_with_evaluate_policies() -> None:
    policy = PosturePolicy("storage-public", "high", "public", True)
    assert config_violates({"public": True}, policy)
    assert not config_violates({"public": False}, policy)
    assert not config_violates({}, policy)  # a missing key is not a breach
    assert config_violates({"nested": {"public": True}}, policy)  # dotted lookup


def test_policy_evaluation_is_deterministic() -> None:
    snapshot = parse_snapshot_document(_normalized([_resource("b"), _resource("a", public=True)]))
    first = evaluate_policies(snapshot, _policies())
    second = evaluate_policies(snapshot, _policies())
    assert json.dumps([v.to_artifact() for v in first]) == json.dumps(
        [v.to_artifact() for v in second]
    )
    assert [v.resource_key for v in first] == sorted(v.resource_key for v in first)
