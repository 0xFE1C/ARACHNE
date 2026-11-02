"""Integration: enterprise identity & access (S17, area IDAM).

The acceptance criteria of REQ-IDAM-001...004, driven through the real ASGI app:
an OIDC authorization-code login against the canned IdP fixture, group→role binding,
deny-by-default with no IdP, service-account keys with rotation/expiry/last-used, and the
"user X via key Y" actor identity in the audit trail, on the scan and in the report.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from urllib.parse import parse_qs, urlsplit

import pytest
from pydantic import SecretStr
from sqlalchemy import select
from tests.helpers.api import ADMIN_KEY, API_KEYS, auth, make_api_harness, wait_for_scan
from tests.helpers.idp import CLIENT_ID, CLIENT_SECRET, IDP_ISSUER, CannedIdP

from arachne.api.auth import SSO_SESSION_COOKIE, hash_secret
from arachne.core.audit import AuditAction
from arachne.core.config import SsoSettings
from arachne.data.models import ServiceAccount

pytestmark = pytest.mark.integration

TARGET: dict[str, object] = {
    "name": "idam-test-target",
    "targets": [{"kind": "url", "value": "https://example.com/"}],
    "attestation": {
        "attested_by": "idam test",
        "attested_at": "2026-10-01T00:00:00Z",
        "scope_statement": "integration-test authorization covering example.com",
        "allowed_targets": ["example.com"],
    },
}


def sso_settings(**overrides: object) -> SsoSettings:
    base: dict[str, object] = {
        "enabled": True,
        "issuer": IDP_ISSUER,
        "client_id": CLIENT_ID,
        "client_secret": SecretStr(CLIENT_SECRET),
        "group_roles": (
            "arachne-viewers:viewer",
            "arachne-scanners:scanner",
            "arachne-admins:admin",
        ),
        "algorithms": ("RS256",),
    }
    base.update(overrides)
    return SsoSettings(**base)  # type: ignore[arg-type]


@pytest.fixture
def idp_only(tmp_path):  # type: ignore[no-untyped-def]
    """An app with an IdP configured and *no* static API keys (SSO is the only way in)."""
    idp = CannedIdP()
    harness = make_api_harness(tmp_path, keys=(), sso=sso_settings(), oidc_transport=idp.transport)
    try:
        yield harness, idp
    finally:
        harness.close()


def _start_login(client, next_path: str = "/ui/scans") -> tuple[str, str]:  # type: ignore[no-untyped-def]
    """Begin a login and return ``(authorize_url, state)`` (the 302 the app issued)."""
    response = client.get(f"/api/v1/auth/sso/login?next={next_path}", follow_redirects=False)
    assert response.status_code == 303, response.text
    location = response.headers["location"]
    assert location.startswith(f"{IDP_ISSUER}/authorize")
    state = parse_qs(urlsplit(location).query)["state"][0]
    return location, state


def _callback(client, code: str, state: str):  # type: ignore[no-untyped-def]
    return client.get(
        f"/api/v1/auth/sso/callback?code={code}&state={state}", follow_redirects=False
    )


# --------------------------------------------------------------------------- OIDC flow
def test_the_oidc_login_flow_mints_a_session_and_records_the_user(idp_only) -> None:  # type: ignore[no-untyped-def]
    harness, idp = idp_only
    with harness.client() as client:
        location, state = _start_login(client, next_path="/ui/scans")
        code = idp.accept_authorization(location, groups=("arachne-scanners",))
        response = _callback(client, code, state)
        assert response.status_code == 303
        assert response.headers["location"] == "/ui/scans"
        assert SSO_SESSION_COOKIE in response.cookies

        me = client.get("/api/v1/auth/me")
        assert me.status_code == 200
        identity = me.json()
        assert identity["source"] == "sso"
        assert identity["role"] == "scanner"
        assert identity["actor"] == "user alice@corp.example"
        assert identity["email"] == "alice@corp.example"

        # A scanner session can list scans (viewer capability included).
        assert client.get("/api/v1/scans").status_code == 200

    # The exchange really happened, with the client secret and a PKCE verifier.
    token_calls = [item for item in idp.requests if item["path"] == "/token"]
    assert token_calls and token_calls[-1]["form"]["client_secret"] == CLIENT_SECRET
    assert token_calls[-1]["form"].get("code_verifier")

    # Every audit line that request caused names the human, not a key.
    requests = harness.events_of(AuditAction.API_REQUEST)
    assert any(event.actor == "user alice@corp.example" for event in requests)
    logins = harness.events_of(AuditAction.AUTH_SSO_LOGIN)
    assert logins and logins[-1].reason == "granted role scanner"


def test_group_mapping_grants_the_mapped_role(idp_only) -> None:  # type: ignore[no-untyped-def]
    harness, idp = idp_only
    with harness.client() as client:
        location, state = _start_login(client)
        code = idp.accept_authorization(location, groups=("arachne-admins",))
        assert _callback(client, code, state).status_code == 303
        # Admin capability: manage service accounts.
        response = client.post(
            "/api/v1/service-accounts", json={"label": "from-sso", "role": "viewer"}
        )
        assert response.status_code == 201, response.text
        assert response.json()["account"]["role"] == "viewer"


def test_an_sso_user_scan_records_the_user_as_requester(idp_only) -> None:  # type: ignore[no-untyped-def]
    """REQ-IDAM-001: a per-user principal is on the scan *and* in the report."""
    harness, idp = idp_only
    with harness.client() as client:
        location, state = _start_login(client)
        code = idp.accept_authorization(location, groups=("arachne-scanners",))
        assert _callback(client, code, state).status_code == 303
        started = client.post("/api/v1/scans", json={"target": TARGET, "dry_run": False})
        assert started.status_code == 202, started.text
        scan_id = started.json()["scan_id"]
        detail = wait_for_scan(client, {}, scan_id)
        assert detail["stats"]["requested_by"] == "user alice@corp.example"
        document = json.loads(client.get(f"/api/v1/scans/{scan_id}/report?format=json").content)
        assert document["scope"]["requested_by"] == "user alice@corp.example"
    created = harness.events_of(AuditAction.SCAN_CREATED)
    assert created and created[-1].actor == "user alice@corp.example"


def test_a_login_with_no_mapped_role_is_denied(idp_only) -> None:  # type: ignore[no-untyped-def]
    harness, idp = idp_only
    with harness.client() as client:
        location, state = _start_login(client)
        code = idp.accept_authorization(location, groups=("unrelated-group",))
        response = _callback(client, code, state)
        assert response.status_code == 303
        assert response.headers["location"].startswith("/ui/login")
        assert SSO_SESSION_COOKIE not in response.cookies
        assert client.get("/api/v1/auth/me").status_code == 401
    denied = harness.events_of(AuditAction.API_DENIED)
    assert any("no group maps to a role" in (event.reason or "") for event in denied)


def test_an_unconfigured_idp_is_refused_and_the_api_stays_closed(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """REQ-IDAM-002's acceptance test: no IdP ⇒ no SSO login, and no key ⇒ no API."""
    harness = make_api_harness(tmp_path)
    try:
        with harness.client() as client:
            assert client.get("/api/v1/auth/sso/login", follow_redirects=False).status_code == 503
            assert (
                client.get(
                    "/api/v1/auth/sso/callback?code=x&state=y", follow_redirects=False
                ).status_code
                == 503
            )
            assert client.get("/api/v1/scans").status_code == 401
            assert client.get("/api/v1/auth/me").status_code == 401
    finally:
        harness.close()


def test_a_replayed_state_is_refused(idp_only) -> None:  # type: ignore[no-untyped-def]
    harness, idp = idp_only
    with harness.client() as client:
        location, state = _start_login(client)
        code = idp.accept_authorization(location)
        assert _callback(client, code, state).status_code == 303
        # The same state (and code) again must find nothing.
        replay = _callback(client, code, state)
        assert replay.status_code == 303
        assert replay.headers["location"].startswith("/ui/login")
        assert SSO_SESSION_COOKIE not in replay.cookies


def test_an_id_token_with_the_wrong_nonce_is_refused(idp_only) -> None:  # type: ignore[no-untyped-def]
    harness, idp = idp_only
    with harness.client() as client:
        location, state = _start_login(client)
        query = parse_qs(urlsplit(location).query)
        code = "code-wrong-nonce"
        idp.queue_token(
            code,
            idp.id_token(subject="alice", nonce="not-the-flow-nonce"),
            challenge=query["code_challenge"][0],
            redirect_uri=query["redirect_uri"][0],
        )
        response = _callback(client, code, state)
        assert response.status_code == 303
        assert response.headers["location"].startswith("/ui/login")
        assert SSO_SESSION_COOKIE not in response.cookies


def test_an_expired_id_token_is_refused(idp_only) -> None:  # type: ignore[no-untyped-def]
    harness, idp = idp_only
    idp.token_ttl_s = -3600
    with harness.client() as client:
        location, state = _start_login(client)
        code = idp.accept_authorization(location)
        response = _callback(client, code, state)
        assert response.status_code == 303
        assert response.headers["location"].startswith("/ui/login")
        assert SSO_SESSION_COOKIE not in response.cookies


def test_logout_revokes_the_session(idp_only) -> None:  # type: ignore[no-untyped-def]
    harness, idp = idp_only
    with harness.client() as client:
        location, state = _start_login(client)
        code = idp.accept_authorization(location)
        assert _callback(client, code, state).status_code == 303
        assert client.get("/api/v1/auth/me").status_code == 200
        assert client.post("/api/v1/auth/sso/logout", follow_redirects=False).status_code == 303
        assert client.get("/api/v1/auth/me").status_code == 401


# --------------------------------------------------------------------------- service accounts
def test_rotated_service_account_key_is_rejected_and_the_new_key_works(tmp_path) -> None:  # type: ignore[no-untyped-def]
    harness = make_api_harness(tmp_path)
    try:
        with harness.client() as client:
            created = client.post(
                "/api/v1/service-accounts",
                headers=auth(ADMIN_KEY),
                json={"label": "ci-pipeline", "role": "scanner", "owner": "alice@corp"},
            )
            assert created.status_code == 201, created.text
            old_secret = created.json()["secret"]
            assert client.get("/api/v1/scans", headers={"X-API-Key": old_secret}).status_code == 200

            rotated = client.post(
                "/api/v1/service-accounts/ci-pipeline/rotate", headers=auth(ADMIN_KEY)
            )
            assert rotated.status_code == 200, rotated.text
            new_secret = rotated.json()["secret"]
            assert new_secret != old_secret

            assert (
                client.get("/api/v1/scans", headers={"X-API-Key": old_secret}).status_code == 401
            ), "the rotated-away secret must be rejected"
            assert (
                client.get("/api/v1/scans", headers={"X-API-Key": new_secret}).status_code == 200
            ), "the new secret must work"

            # Storage is still hashed, and last-used was tracked.
            with harness.services.session_factory() as session:
                row = session.scalar(select(ServiceAccount))
                assert row is not None
                assert row.digest == hash_secret(new_secret)
                assert row.digest != new_secret and len(row.digest) == 64
                assert row.last_used_at is not None
    finally:
        harness.close()


def test_a_service_account_owner_appears_in_the_audit_actor(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """REQ-IDAM-004: a row reads "user X via key Y"."""
    harness = make_api_harness(tmp_path)
    try:
        with harness.client() as client:
            created = client.post(
                "/api/v1/service-accounts",
                headers=auth(ADMIN_KEY),
                json={"label": "deploy", "role": "viewer", "owner": "bob@corp"},
            )
            secret = created.json()["secret"]
            assert client.get("/api/v1/scans", headers={"X-API-Key": secret}).status_code == 200
        requests = harness.events_of(AuditAction.API_REQUEST)
        assert any(event.actor == "user bob@corp via key deploy" for event in requests)
        assert any(event.meta["identity"] == "user bob@corp via key deploy" for event in requests)
    finally:
        harness.close()


def test_expired_and_revoked_service_accounts_are_refused(tmp_path) -> None:  # type: ignore[no-untyped-def]
    harness = make_api_harness(tmp_path)
    try:
        store = harness.services.service_accounts
        assert store is not None
        _record, expired = store.create(
            "expired", "viewer", expires_at=datetime.now(UTC) - timedelta(seconds=1)
        )
        _record2, revoked = store.create("revoked", "viewer")
        store.revoke("revoked")
        with harness.client() as client:
            assert client.get("/api/v1/scans", headers={"X-API-Key": expired}).status_code == 401
            assert client.get("/api/v1/scans", headers={"X-API-Key": revoked}).status_code == 401
        # A revoked account is still listed (lineage), but a fresh create re-uses no label.
        listed = harness.services.service_accounts.list_accounts()
        assert any(account.label == "revoked" and not account.active for account in listed)
    finally:
        harness.close()


def test_only_admins_manage_service_accounts(tmp_path) -> None:  # type: ignore[no-untyped-def]
    harness = make_api_harness(tmp_path)
    try:
        with harness.client() as client:
            assert client.get("/api/v1/service-accounts").status_code == 401
            assert (
                client.post(
                    "/api/v1/service-accounts",
                    headers=auth("scansecret"),
                    json={"label": "x", "role": "viewer"},
                ).status_code
                == 403
            )
    finally:
        harness.close()


def test_a_scan_records_the_requester_on_the_scan_and_in_the_report(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """REQ-IDAM-001: the per-user principal is recorded on the scan *and* the report."""
    harness = make_api_harness(tmp_path)
    try:
        with harness.client() as client:
            created = client.post(
                "/api/v1/service-accounts",
                headers=auth(ADMIN_KEY),
                json={"label": "runner", "role": "scanner", "owner": "carol@corp"},
            )
            secret = created.json()["secret"]
            headers = {"X-API-Key": secret}
            started = client.post(
                "/api/v1/scans", headers=headers, json={"target": TARGET, "dry_run": False}
            )
            assert started.status_code == 202, started.text
            scan_id = started.json()["scan_id"]
            detail = wait_for_scan(client, headers, scan_id)

            identity = "user carol@corp via key runner"
            assert detail["stats"]["requested_by"] == identity
            created_events = harness.events_of(AuditAction.SCAN_CREATED)
            assert created_events and created_events[-1].actor == identity

            document = json.loads(
                client.get(f"/api/v1/scans/{scan_id}/report?format=json", headers=headers).content
            )
            assert document["scope"]["requested_by"] == identity
    finally:
        harness.close()


def test_an_api_key_scan_still_works_and_records_its_key(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """The S12 path is unchanged: a static key records "key <label>"."""
    harness = make_api_harness(tmp_path)
    try:
        with harness.client() as client:
            started = client.post(
                "/api/v1/scans",
                headers=auth("scansecret"),
                json={"target": TARGET, "dry_run": False},
            )
            assert started.status_code == 202
            detail = wait_for_scan(client, auth("scansecret"), started.json()["scan_id"])
            assert detail["stats"]["requested_by"] == "key scanner"
        assert API_KEYS  # the harness still ships its three keys
    finally:
        harness.close()
