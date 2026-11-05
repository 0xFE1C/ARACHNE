"""A SCIM 2.0 client fixture: an identity provider driving ARACHNE (REQ-IDAM-007).

Real provisioners (Okta, Entra ID, Keycloak) send RFC 7644 documents over HTTPS with a bearer
token and expect RFC 7643 resources back. This fixture is the same conversation in process: it
authenticates the way a provisioner does (``Authorization: Bearer``), keeps the resource ids
the server returns, and refuses to continue when a response is not what the RFC says it should
be — so a test that "passes" cannot be passing because the client swallowed an error.

The fixture owns no assertions about ARACHNE's behaviour; the tests do. It owns only the wire.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from tests.helpers.api import ApiHarness

__all__ = ["ScimProvisioner", "ScimResponse", "build_scim_settings"]

BASE = "/api/v1/scim/v2"


def build_scim_settings(**overrides: Any) -> Any:
    """``SsoSettings`` with the group→role mapping SCIM derives roles through.

    Provisioning is independent of OIDC being switched on: the mapping is what both paths
    read. ``ARACHNE_SSO_GROUP_ROLES`` is the deployment's own vocabulary, so a test asserting
    "this group grants this role" is asserting the mapping, not the fixture.
    """
    from arachne.core.config import SsoSettings

    defaults: dict[str, Any] = {
        "enabled": False,
        "group_roles": (
            "arachne-viewers:viewer",
            "arachne-auditors:scanner",
            "arachne-admins:admin",
        ),
    }
    defaults.update(overrides)
    return SsoSettings(**defaults)


@dataclass(frozen=True, slots=True)
class ScimResponse:
    """One response, with the parts a provisioner reads."""

    status: int
    document: dict[str, Any] = field(default_factory=dict)

    @property
    def id(self) -> str:
        return str(self.document.get("id", ""))

    @property
    def scim_type(self) -> str | None:
        value = self.document.get("scimType")
        return None if value is None else str(value)

    @property
    def role(self) -> str | None:
        extension = self.document.get("urn:arachne:params:scim:schemas:extension:role:2.0") or {}
        value = extension.get("role")
        return None if value is None else str(value)

    @property
    def resources(self) -> list[dict[str, Any]]:
        raw = self.document.get("Resources")
        return list(raw) if isinstance(raw, list) else []


class ScimProvisioner:
    """A provisioner's view of ARACHNE: a bearer token and the two resource collections."""

    def __init__(self, harness: ApiHarness, secret: str) -> None:
        self.harness = harness
        self.secret = secret

    # ------------------------------------------------------------------ transport
    def _call(
        self,
        method: str,
        path: str,
        *,
        body: dict[str, Any] | None = None,
        params: dict[str, Any] | None = None,
    ) -> ScimResponse:
        headers = {"Authorization": f"Bearer {self.secret}"}
        client = self.harness.client()
        if method == "GET":
            response = client.get(path, headers=headers, params=params)
        else:
            response = client.request(method, path, headers=headers, json=body)
        if response.headers.get("content-type", "").startswith("application/json"):
            document: dict[str, Any] = response.json()
        else:  # pragma: no cover - a 204 has no body, and any other type is a defect
            document = {}
        return ScimResponse(status=response.status_code, document=document)

    def _expect(self, response: ScimResponse, *statuses: int) -> ScimResponse:
        assert response.status in statuses, (
            f"SCIM call answered {response.status}, expected {statuses}: {response.document}"
        )
        return response

    # ------------------------------------------------------------------ users
    def create_user(
        self,
        user_name: str,
        *,
        groups: tuple[str, ...] = (),
        external_id: str | None = None,
        email: str | None = None,
        display_name: str | None = None,
        active: bool = True,
    ) -> ScimResponse:
        payload: dict[str, Any] = {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:User"],
            "userName": user_name,
            "active": active,
        }
        if external_id is not None:
            payload["externalId"] = external_id
        if email is not None:
            payload["emails"] = [{"value": email, "primary": True}]
        if display_name is not None:
            payload["displayName"] = display_name
        if groups:
            payload["groups"] = [{"value": group} for group in groups]
        return self._expect(self._call("POST", f"{BASE}/Users", body=payload), 200, 201)

    def get_user(self, user_id: str) -> ScimResponse:
        return self._expect(self._call("GET", f"{BASE}/Users/{user_id}"), 200, 404)

    def list_users(
        self,
        *,
        filter: str | None = None,  # noqa: A002 - the RFC's parameter name
        start_index: int = 1,
        count: int = 100,
    ) -> ScimResponse:
        params: dict[str, Any] = {"startIndex": start_index, "count": count}
        if filter is not None:
            params["filter"] = filter
        return self._expect(self._call("GET", f"{BASE}/Users", params=params), 200)

    def add_to_group(self, user_id: str, group_id: str) -> ScimResponse:
        """The Mover half: an RFC 7644 §3.5.2 ``add`` of one group membership."""
        payload = {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "add", "path": "groups", "value": [{"value": group_id}]}],
        }
        return self._expect(self._call("PATCH", f"{BASE}/Users/{user_id}", body=payload), 200)

    def set_active(self, user_id: str, active: bool) -> ScimResponse:
        payload = {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "replace", "path": "active", "value": active}],
        }
        return self._expect(self._call("PATCH", f"{BASE}/Users/{user_id}", body=payload), 200)

    def deactivate(self, user_id: str) -> ScimResponse:
        """The Leaver half: ``DELETE /Users/{id}``, which is a soft delete by contract."""
        return self._expect(self._call("DELETE", f"{BASE}/Users/{user_id}"), 204)

    def patch_raw(self, user_id: str, payload: dict[str, Any]) -> ScimResponse:
        return self._call("PATCH", f"{BASE}/Users/{user_id}", body=payload)

    def create_raw(self, payload: dict[str, Any]) -> ScimResponse:
        return self._call("POST", f"{BASE}/Users", body=payload)

    # ------------------------------------------------------------------ groups
    def create_group(
        self, display_name: str, *, members: tuple[str, ...] = (), external_id: str | None = None
    ) -> ScimResponse:
        payload: dict[str, Any] = {
            "schemas": ["urn:ietf:params:scim:schemas:core:2.0:Group"],
            "displayName": display_name,
        }
        if external_id is not None:
            payload["externalId"] = external_id
        if members:
            payload["members"] = [{"value": member} for member in members]
        return self._expect(self._call("POST", f"{BASE}/Groups", body=payload), 200, 201)

    def get_group(self, group_id: str) -> ScimResponse:
        return self._expect(self._call("GET", f"{BASE}/Groups/{group_id}"), 200, 404)

    def list_groups(self, *, filter: str | None = None) -> ScimResponse:  # noqa: A002 - the RFC's name
        params = {"filter": filter} if filter is not None else None
        return self._expect(self._call("GET", f"{BASE}/Groups", params=params), 200)

    def delete_group(self, group_id: str) -> ScimResponse:
        return self._expect(self._call("DELETE", f"{BASE}/Groups/{group_id}"), 204)

    def add_member(self, group_id: str, subject: str) -> ScimResponse:
        payload = {
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "add", "path": "members", "value": [{"value": subject}]}],
        }
        return self._expect(self._call("PATCH", f"{BASE}/Groups/{group_id}", body=payload), 200)

    # ------------------------------------------------------------------ discovery
    def service_provider_config(self) -> ScimResponse:
        return self._expect(self._call("GET", f"{BASE}/ServiceProviderConfig"), 200)

    def resource_types(self) -> ScimResponse:
        return self._expect(self._call("GET", f"{BASE}/ResourceTypes"), 200)

    def schemas(self) -> ScimResponse:
        return self._expect(self._call("GET", f"{BASE}/Schemas"), 200)
