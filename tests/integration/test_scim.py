"""SCIM 2.0 provisioning: create, read, update, deactivate — and a full JML cycle.

REQ-IDAM-007's acceptance criteria, in order:

* ``/scim/v2/Users`` and ``/scim/v2/Groups`` create, read, update and deactivate;
* deactivation revokes live sessions **and** the service-account keys the subject owns, in one
  request — asserted from the session and key stores, not from the response;
* an identity-provider fixture drives a joiner-mover-leaver cycle;
* SCIM is refused to a viewer key.

The role assertions are the load-bearing ones: a SCIM that provisions people but maps no role
has moved the data and changed nothing about access.
"""

from __future__ import annotations

from typing import Any

import pytest
from tests.helpers.api import ADMIN_KEY, VIEWER_KEY, ApiHarness, auth, make_api_harness
from tests.helpers.scim_client import ScimProvisioner, build_scim_settings

from arachne.core.audit import AuditAction

pytestmark = pytest.mark.integration

#: The groups the fixture maps onto roles; the names are the deployment's vocabulary.
VIEWERS = "g-viewers"
AUDITORS = "g-auditors"
ADMINS = "g-admins"
GROUP_ROLES = (f"{VIEWERS}:viewer", f"{AUDITORS}:scanner", f"{ADMINS}:admin")


@pytest.fixture
def scim(tmp_path: Any) -> Any:
    """A harness with SCIM wired, a provisioner key and an unrelated viewer key."""
    harness = make_api_harness(
        tmp_path,
        settings=_scim_settings(tmp_path),
        sso=build_scim_settings(group_roles=GROUP_ROLES),
    )
    record, secret = harness.services.service_accounts.create(
        "provisioner", "admin", owner="idp@example.com"
    )
    assert record.label == "provisioner"
    harness.provisioner_key = secret  # type: ignore[attr-defined]
    try:
        yield harness
    finally:
        harness.close()


def _scim_settings(tmp_path: Any) -> Any:
    from tests.helpers.api import build_api_settings

    return build_api_settings(tmp_path)


def _provisioner(harness: ApiHarness) -> ScimProvisioner:
    return ScimProvisioner(harness, harness.provisioner_key)  # type: ignore[attr-defined]


def _mint_session(harness: ApiHarness, subject: str, role: str) -> str:
    """The one thing SCIM cannot do: log in. A session stands in for the user's browser."""
    _record, token = harness.services.auth_sessions.create(subject=subject, role=role)
    return token


def _owned_key(harness: ApiHarness, label: str, owner: str) -> str:
    _record, secret = harness.services.service_accounts.create(label, "scanner", owner=owner)
    return secret


# --------------------------------------------------------------------------- auth


def test_a_viewer_key_is_refused_and_the_refusal_is_audited(scim: ApiHarness) -> None:
    """REQ-IDAM-007: a dedicated admin credential authenticates SCIM, not a viewer key."""
    client = scim.client()
    response = client.get("/api/v1/scim/v2/Users", headers=auth(VIEWER_KEY))
    assert response.status_code in {401, 403}, response.text
    assert [event.action for event in scim.sink.events] == [AuditAction.API_DENIED] or (
        AuditAction.API_DENIED in scim.actions()
    )


def test_a_static_admin_key_is_not_a_dedicated_provisioner(scim: ApiHarness) -> None:
    """An ``ARACHNE_API_KEYS`` entry has no owner, so it cannot say who provisioned."""
    response = scim.client().get("/api/v1/scim/v2/Users", headers=auth(ADMIN_KEY))
    assert response.status_code == 403, response.text


def test_a_viewer_service_account_is_refused(scim: ApiHarness) -> None:
    """An admin *role* is required, and the role is checked after the credential type."""
    _record, secret = scim.services.service_accounts.create("weak", "viewer", owner="person@x")
    response = scim.client().get(
        "/api/v1/scim/v2/Users", headers={"Authorization": f"Bearer {secret}"}
    )
    assert response.status_code == 403, response.text


def test_an_unauthenticated_call_is_refused(scim: ApiHarness) -> None:
    response = scim.client().get("/api/v1/scim/v2/Users")
    assert response.status_code == 401, response.text


# --------------------------------------------------------------------------- crud


def test_users_support_create_read_update_and_deactivate(scim: ApiHarness) -> None:
    provisioner = _provisioner(scim)
    created = provisioner.create_user(
        "alice@example.com", email="alice@example.com", display_name="Alice", external_id="idp-1"
    )
    user_id = created.id
    assert user_id

    read = provisioner.get_user(user_id)
    assert read.document["userName"] == "alice@example.com"
    assert read.document["active"] is True
    assert read.document["emails"][0]["value"] == "alice@example.com"

    replaced = provisioner._call(
        "PUT",
        f"/api/v1/scim/v2/Users/{user_id}",
        body={
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": "alice@example.com",
            "displayName": "Alice Cooper",
            "active": True,
        },
    )
    assert replaced.status == 200, replaced.document
    assert replaced.document["displayName"] == "Alice Cooper"

    provisioner.deactivate(user_id)
    assert provisioner.get_user(user_id).document["active"] is False
    # Deactivation is soft: the row is still there to attribute historical scans.
    assert provisioner.get_user(user_id).document["userName"] == "alice@example.com"


def test_groups_support_create_read_update_and_membership(scim: ApiHarness) -> None:
    provisioner = _provisioner(scim)
    user = provisioner.create_user("bob@example.com", email="bob@example.com")
    group = provisioner.create_group(VIEWERS, external_id="grp-1")
    assert provisioner.get_group(group.id).document["displayName"] == VIEWERS

    provisioner.add_member(group.id, user.id)
    members = provisioner.get_group(group.id).document["members"]
    assert [item["value"] for item in members] == [user.id]
    # Membership is projected onto the principal, which is where the role comes from.
    assert (
        provisioner.get_user(user.id).document[
            "urn:arachne:params:scim:schemas:extension:role:2.0"
        ]["role"]
        == "viewer"
    )

    provisioner.delete_group(group.id)
    assert provisioner.get_group(group.id).status == 404
    assert (
        provisioner.get_user(user.id).document[
            "urn:arachne:params:scim:schemas:extension:role:2.0"
        ]["role"]
        is None
    )


def test_an_idp_can_look_at_its_own_resources(scim: ApiHarness) -> None:
    provisioner = _provisioner(scim)
    provisioner.create_user("carol@example.com", email="carol@example.com")
    listed = provisioner.list_users(filter='userName eq "carol@example.com"')
    assert listed.document["totalResults"] == 1
    assert listed.document["Resources"][0]["userName"] == "carol@example.com"
    filtered = provisioner.list_users(filter='userName eq "nobody@example.com"')
    assert filtered.document["totalResults"] == 0


def test_each_supported_filter_matches_on_its_own_attribute(scim: ApiHarness) -> None:
    """``externalId eq`` must search externalId, not externalId *and* userName.

    A filter applied to the wrong attribute returns zero rows, and a provisioner reading zero
    rows concludes the person does not exist — which is how a joiner gets created twice or a
    leaver is skipped. The two attributes carry different values here, so a cross-wired filter
    cannot pass by coincidence.
    """
    provisioner = _provisioner(scim)
    provisioner.create_user("dana@example.com", email="dana@example.com", external_id="idp-4711")
    by_external = provisioner.list_users(filter='externalId eq "idp-4711"')
    assert by_external.document["totalResults"] == 1, by_external.document
    assert by_external.document["Resources"][0]["externalId"] == "idp-4711"
    # ...and it is not an accidental match on the userName.
    assert by_external.document["Resources"][0]["userName"] == "dana@example.com"
    assert provisioner.list_users(filter='externalId eq "nobody"').document["totalResults"] == 0
    # The two filters are independent: the externalId is not reachable as a userName.
    assert provisioner.list_users(filter='userName eq "idp-4711"').document["totalResults"] == 0


def test_an_unsupported_filter_is_refused_not_ignored(scim: ApiHarness) -> None:
    """A filter that silently returns everything is how a job deactivates the wrong person."""
    refused = _provisioner(scim)._call(
        "GET", "/api/v1/scim/v2/Users", params={"filter": 'userName co "example"'}
    )
    assert refused.status == 400
    assert refused.scim_type == "invalidFilter"


def test_the_discovery_documents_describe_this_deployment(scim: ApiHarness) -> None:
    provisioner = _provisioner(scim)
    config = provisioner.service_provider_config().document
    assert config["patch"]["supported"] is True
    assert config["bulk"]["supported"] is False
    assert config["authenticationSchemes"][0]["type"] == "oauthbearertoken"
    types = {item["name"] for item in provisioner.resource_types().resources}
    assert types == {"User", "Group"}
    schemas = {item["name"] for item in provisioner.schemas().resources}
    assert schemas == {"User", "Group"}


# --------------------------------------------------------------------------- deprovisioning


def test_deactivation_revokes_sessions_and_keys_in_one_request(scim: ApiHarness) -> None:
    """REQ-IDAM-007, G7 clause 5: one DELETE ends the sessions *and* the owned keys."""
    provisioner = _provisioner(scim)
    user = provisioner.create_user(
        "dave@example.com", email="dave@example.com", display_name="Dave"
    )
    subject = "dave@example.com"
    session = _mint_session(scim, subject, "viewer")
    key = _owned_key(scim, "dave-cli", "dave@example.com")
    assert scim.services.auth_sessions.resolve(session) is not None
    assert scim.services.service_accounts.verify(key) is not None

    provisioner.deactivate(user.id)

    assert scim.services.auth_sessions.resolve(session) is None, "the live session survived"
    assert scim.services.service_accounts.verify(key) is None, "the owned key survived"
    recorded = [
        event
        for event in scim.events_of(AuditAction.SERVICE_ACCOUNT_CHANGED)
        if (event.meta.get("deprovisioned") or {}).get("subject") == subject
    ]
    assert recorded, "the deprovisioning was not audited with what it revoked"
    assert recorded[0].meta["deprovisioned"]["sessions_revoked"] == 1
    assert "dave-cli" in recorded[0].meta["deprovisioned"]["keys_revoked"]


def test_patching_active_to_false_has_the_same_effect(scim: ApiHarness) -> None:
    """An IdP that PATCHes ``active`` instead of DELETEing gets the same revocation."""
    provisioner = _provisioner(scim)
    user = provisioner.create_user("erin@example.com", email="erin@example.com")
    session = _mint_session(scim, "erin@example.com", "viewer")
    key = _owned_key(scim, "erin-cli", "erin@example.com")

    provisioner.set_active(user.id, False)

    assert scim.services.auth_sessions.resolve(session) is None
    assert scim.services.service_accounts.verify(key) is None


# --------------------------------------------------------------------------- the JML cycle


def test_a_full_joiner_mover_leaver_cycle_against_the_idp_fixture(scim: ApiHarness) -> None:
    """The cycle an enterprise actually runs, end to end, against the SCIM fixture.

    **Joiner** — the IdP creates the person and the group that grants them a role.
    **Mover** — the person changes team; the IdP adds the new group. The effective role is
    *derived*, so the change lands on the next login with no authorisation column rewritten —
    which the fixture proves by minting a session after the move.
    **Leaver** — the IdP deactivates them; the session and the owned key stop working in the
    same request, and the group membership is dropped so a reactivation cannot silently
    restore the old role.
    """
    provisioner = _provisioner(scim)
    subject = "frank@example.com"
    provisioner.create_group(VIEWERS)
    provisioner.create_group(AUDITORS)

    # --- joiner
    user = provisioner.create_user(subject, email=subject, display_name="Frank", groups=(VIEWERS,))
    assert user.role == "viewer", "the joiner did not get the mapped role"
    assert provisioner.get_user(user.id).document["active"] is True

    # --- mover
    moved = provisioner.add_to_group(user.id, AUDITORS)
    assert moved.role == "scanner", "the new group did not raise the derived role"
    session = _mint_session(scim, subject, moved.role or "viewer")
    assert scim.services.auth_sessions.resolve(session) is not None
    key = _owned_key(scim, "frank-cli", subject)

    # --- leaver
    provisioner.deactivate(user.id)
    assert provisioner.get_user(user.id).document["active"] is False
    assert scim.services.auth_sessions.resolve(session) is None
    assert scim.services.service_accounts.verify(key) is None
    recorded = scim.services.provisioned_principals.get_principal(subject)
    assert recorded is not None and recorded.active is False
    assert recorded.groups == (), "the leaver kept a group membership"

    # The history is on the trail: every step of the cycle, with the acting provisioner.
    changes = [
        event.meta.get("change")
        for event in scim.events_of(AuditAction.PROVISIONING_CHANGED)
        if str(event.target).endswith(subject)
    ]
    assert "user.created" in changes
    assert "user.deactivated" in changes
    actors = {
        str(event.meta.get("actor"))
        for event in scim.events_of(AuditAction.PROVISIONING_CHANGED)
        if str(event.target).endswith(subject)
    }
    assert actors, "the cycle left no actor on the trail"
    for actor in actors:
        assert "provisioner" in actor and "idp@example.com" in actor, actor


def test_a_second_create_for_the_same_subject_is_a_reconcile(scim: ApiHarness) -> None:
    """RFC 7644 §3.3 idempotency: a retried create must not fail or duplicate."""
    provisioner = _provisioner(scim)
    first = provisioner.create_user("gina@example.com", email="gina@example.com")
    second = provisioner.create_user(
        "gina@example.com", email="gina@example.com", display_name="Gina"
    )
    assert second.status == 200
    assert second.id == first.id
    assert (
        provisioner.list_users(filter='userName eq "gina@example.com"').document["totalResults"]
        == 1
    )
