"""SCIM 2.0 provisioning: the resources, the filter subset and the provisioning service.

RFC 7643 defines the resources and RFC 7644 the protocol. This module owns both the wire
documents and the one operation that matters most — deprovisioning — so the HTTP layer in
:mod:`arachne.api.scim_routes` stays a translation of JSON into calls.

Three decisions are worth stating, because each is a place a SCIM implementation usually
goes wrong:

**Deletion is deactivation, and deactivation revokes.** ``DELETE /Users/{id}`` sets
``active=false`` and never removes the row (attribution of historical scans depends on it),
*and* in the same request it revokes the subject's live sessions and the service-account keys
they own. A SCIM that only flips a flag is worse than no SCIM: the directory says the person
is gone and the API disagrees.

**Role is derived, never stored.** The effective role is
``SsoSettings.role_for(groups by display name)`` — the exact function the OIDC login calls —
so a group change takes effect on the next login with no authorisation column to keep in step
(docs/scim-ldap-interface.md §2). The derived role is *reported* on each user so an operator
can see what the mapping produces.

**The filter subset is small and strict.** ``GET /Users?filter=userName eq "x"`` and
``externalId eq`` are what provisioners actually send. An unsupported operator or attribute is
refused with a SCIM ``invalidFilter`` error naming it, rather than silently returning every
row — a filter that quietly does nothing is how a deprovisioning job deactivates the wrong
person.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from arachne.core.audit import AuditAction, Auditor, AuditOutcome
from arachne.core.config import Settings
from arachne.core.errors import ConfigurationError
from arachne.data.identity_store import (
    GroupRecord,
    PrincipalRecord,
    ProvisionedPrincipalStore,
    ServiceAccountStore,
    SessionStore,
)

__all__ = [
    "ARACHNE_ROLE_EXTENSION",
    "FILTER_ATTRIBUTES",
    "SCIM_API_MESSAGES",
    "SCIM_SCHEMAS",
    "DeprovisionOutcome",
    "ProvisioningError",
    "ProvisioningService",
    "error_document",
    "group_document",
    "list_document",
    "parse_filter",
    "patch_operations",
    "role_for_groups",
    "service_provider_config",
    "user_document",
]

SCIM_SCHEMAS = {
    "user": "urn:ietf:params:scim:schemas:core:2.0:User",
    "group": "urn:ietf:params:scim:schemas:core:2.0:Group",
    "list": "urn:ietf:params:scim:api:messages:2.0:ListResponse",
    "error": "urn:ietf:params:scim:api:messages:2.0:Error",
    "patch": "urn:ietf:params:scim:api:messages:2.0:PatchOp",
    "service_provider_config": "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig",
    "resource_type": "urn:ietf:params:scim:schemas:core:2.0:ResourceType",
    "schema": "urn:ietf:params:scim:schemas:core:2.0:Schema",
}

#: The RFC 7644 §3.5 URN every PATCH body carries.
SCIM_API_MESSAGES = "urn:ietf:params:scim:api:messages:2.0:PatchOp"

#: The namespaced attribute carrying the *derived* role. SCIM has no role attribute, and a
#: bare ``role`` would collide with a future core schema, so it is namespaced.
ARACHNE_ROLE_EXTENSION = "urn:arachne:params:scim:schemas:extension:role:2.0"

#: The filter attributes this build evaluates. Anything else is refused by name.
FILTER_ATTRIBUTES = frozenset({"username", "externalid", "displayname"})


class ProvisioningError(Exception):
    """A SCIM request this build refuses, carrying the SCIM error fields.

    ``status`` is the HTTP status, ``detail`` the human message and ``scim_type`` the
    RFC 7644 §3.12 error type (``invalidFilter``, ``uniqueness``, ``mutability``, …), so the
    HTTP layer can render a conforming error envelope without guessing.
    """

    def __init__(self, status: int, detail: str, scim_type: str | None = None) -> None:
        super().__init__(detail)
        self.status = status
        self.detail = detail
        self.scim_type = scim_type


# --------------------------------------------------------------------------- documents


def _meta(record: PrincipalRecord | GroupRecord, location: str) -> dict[str, Any]:
    return {
        "resourceType": type(record).__name__.replace("Record", ""),
        "created": record.created_at.isoformat() if record.created_at else None,
        "lastModified": record.updated_at.isoformat() if record.updated_at else None,
        "version": f'W/"{record.version}"',
        "location": location,
    }


def user_document(
    record: PrincipalRecord, *, role: str | None, base: str = "/api/v1/scim/v2"
) -> dict[str, Any]:
    """One SCIM User, with ARACHNE's derived role in a namespaced extension."""
    emails = [{"value": email, "primary": index == 0} for index, email in enumerate(record.emails)]
    return {
        "schemas": [SCIM_SCHEMAS["user"], ARACHNE_ROLE_EXTENSION],
        "id": str(record.id),
        "externalId": record.external_id,
        "userName": record.user_name,
        "name": {"formatted": record.display_name} if record.display_name else {},
        "displayName": record.display_name,
        "emails": emails,
        "active": record.active,
        "meta": _meta(record, f"{base}/Users/{record.id}"),
        ARACHNE_ROLE_EXTENSION: {
            "role": role,
            "subject": record.subject,
            "groups": list(record.groups),
        },
    }


def group_document(
    record: GroupRecord, *, role: str | None, base: str = "/api/v1/scim/v2"
) -> dict[str, Any]:
    """One SCIM Group; ``members`` are subject values, ``role`` is the mapped role or ``None``."""
    return {
        "schemas": [SCIM_SCHEMAS["group"], ARACHNE_ROLE_EXTENSION],
        "id": str(record.id),
        "externalId": record.external_id,
        "displayName": record.display_name,
        "members": [{"value": member} for member in record.members],
        "meta": _meta(record, f"{base}/Groups/{record.id}"),
        ARACHNE_ROLE_EXTENSION: {"role": role},
    }


def list_document(
    resources: list[dict[str, Any]],
    *,
    total: int,
    start_index: int,
    items_per_page: int,
) -> dict[str, Any]:
    """The RFC 7644 §3.4.2 ListResponse envelope."""
    return {
        "schemas": [SCIM_SCHEMAS["list"]],
        "totalResults": total,
        "startIndex": start_index,
        "itemsPerPage": items_per_page,
        "Resources": resources,
    }


def error_document(status: int, detail: str, scim_type: str | None = None) -> dict[str, Any]:
    """The RFC 7644 §3.12 error envelope."""
    document: dict[str, Any] = {
        "schemas": [SCIM_SCHEMAS["error"]],
        "status": str(status),
        "detail": detail,
    }
    if scim_type:
        document["scimType"] = scim_type
    return document


def service_provider_config() -> dict[str, Any]:
    """What this deployment supports: PATCH and filter yes, bulk and sort no."""
    return {
        "schemas": [SCIM_SCHEMAS["service_provider_config"]],
        "documentationUri": "https://github.com/arachne/arachne/blob/main/docs/scim-ldap-interface.md",
        "patch": {"supported": True},
        "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
        "filter": {"supported": True, "maxResults": 1000},
        "changePassword": {"supported": False},
        "sort": {"supported": False},
        "etag": {"supported": True},
        "authenticationSchemes": [
            {
                "type": "oauthbearertoken",
                "name": "Service-account bearer token",
                "description": (
                    "A service account with the admin role, presented as "
                    "`Authorization: Bearer <secret>`. Viewer keys are refused."
                ),
                "primary": True,
            }
        ],
    }


def _resource_type(name: str, endpoint: str, schema: str) -> dict[str, Any]:
    return {
        "schemas": [SCIM_SCHEMAS["resource_type"]],
        "id": name,
        "name": name,
        "endpoint": endpoint,
        "schema": schema,
    }


def resource_types() -> dict[str, Any]:
    return list_document(
        [
            _resource_type("User", "/Users", SCIM_SCHEMAS["user"]),
            _resource_type("Group", "/Groups", SCIM_SCHEMAS["group"]),
        ],
        total=2,
        start_index=1,
        items_per_page=2,
    )


def schemas_document() -> dict[str, Any]:
    """The two core schemas, minimal: the attributes this build actually stores."""
    user_attributes = [
        {"name": "userName", "type": "string", "multiValued": False, "required": True},
        {"name": "displayName", "type": "string", "multiValued": False, "required": False},
        {"name": "emails", "type": "complex", "multiValued": True, "required": False},
        {"name": "active", "type": "boolean", "multiValued": False, "required": False},
        {"name": "externalId", "type": "string", "multiValued": False, "required": False},
        {"name": "groups", "type": "complex", "multiValued": True, "required": False},
    ]
    group_attributes = [
        {"name": "displayName", "type": "string", "multiValued": False, "required": True},
        {"name": "members", "type": "complex", "multiValued": True, "required": False},
        {"name": "externalId", "type": "string", "multiValued": False, "required": False},
    ]
    return list_document(
        [
            {
                "id": SCIM_SCHEMAS["user"],
                "name": "User",
                "description": "ARACHNE provisioned principal (a directory mirror).",
                "attributes": user_attributes,
            },
            {
                "id": SCIM_SCHEMAS["group"],
                "name": "Group",
                "description": "ARACHNE provisioned group; displayName maps to a role.",
                "attributes": group_attributes,
            },
        ],
        total=2,
        start_index=1,
        items_per_page=2,
    )


# --------------------------------------------------------------------------- filters


def parse_filter(text: str | None) -> dict[str, str]:
    """Parse ``attr eq "value"`` (RFC 7644 §3.4.2.2), the subset provisioners use.

    Returns a mapping of *lowercased* attribute name to value. Anything else — another
    operator, another attribute, a compound expression, a malformed literal — raises
    :class:`ProvisioningError` with ``invalidFilter``, because a filter an implementation
    ignores is a filter that returns the wrong rows.
    """
    if not text or not text.strip():
        return {}
    expression = text.strip()
    parts = expression.split()
    if len(parts) != 3 or parts[1].lower() != "eq":
        raise ProvisioningError(
            400,
            f'this build supports only `attribute eq "value"` filters, and received {expression!r}',
            "invalidFilter",
        )
    attribute = parts[0].strip().lower()
    if attribute not in FILTER_ATTRIBUTES:
        raise ProvisioningError(
            400,
            f"cannot filter on {parts[0]!r}; this build filters on "
            f"{', '.join(sorted(FILTER_ATTRIBUTES))}",
            "invalidFilter",
        )
    literal = parts[2].strip()
    if len(literal) < 2 or literal[0] != '"' or literal[-1] != '"':
        raise ProvisioningError(
            400,
            f"the value in {expression!r} must be a double-quoted string",
            "invalidFilter",
        )
    return {attribute: literal[1:-1]}


def patch_operations(payload: dict[str, Any]) -> list[dict[str, Any]]:
    """The ``Operations`` array of a PATCH body, validated minimally and explicitly."""
    if not isinstance(payload, dict):
        raise ProvisioningError(400, "a PATCH body must be a JSON object", "invalidSyntax")
    schemas = payload.get("schemas") or []
    if SCIM_API_MESSAGES not in schemas:
        raise ProvisioningError(
            400,
            f"a PATCH body must declare {SCIM_API_MESSAGES!r} in `schemas`",
            "invalidSyntax",
        )
    operations = payload.get("Operations")
    if not isinstance(operations, list) or not operations:
        raise ProvisioningError(
            400, "a PATCH body needs a non-empty `Operations` array", "invalidValue"
        )
    for index, operation in enumerate(operations):
        if not isinstance(operation, dict) or "op" not in operation:
            raise ProvisioningError(400, f"operation {index} has no `op`", "invalidSyntax")
        if str(operation["op"]).lower() not in {"add", "replace", "remove"}:
            raise ProvisioningError(
                400,
                f"operation {index} uses {operation['op']!r}; this build supports "
                "add, replace, remove",
                "invalidValue",
            )
    return operations


# --------------------------------------------------------------------------- the service


@dataclass(frozen=True, slots=True)
class DeprovisionOutcome:
    """What one deactivation revoked, in one request."""

    subject: str
    user_name: str
    sessions_revoked: int
    keys_revoked: tuple[str, ...]
    groups_left: tuple[str, ...]
    created: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject": self.subject,
            "user_name": self.user_name,
            "sessions_revoked": self.sessions_revoked,
            "keys_revoked": list(self.keys_revoked),
            "groups_left": list(self.groups_left),
        }


def role_for_groups(settings: Settings, group_names: list[str]) -> str | None:
    """The role a set of group *display names* maps to, or ``None`` (deny by default)."""
    role = settings.sso.role_for(tuple(group_names))
    return None if role is None else str(role)


class ProvisioningService:
    """SCIM writes, resolved into the identity stores as one operation each (REQ-IDAM-007).

    The service owns the invariants the HTTP layer must not have to remember: a deleted user
    is deactivated *and* stripped of sessions, keys and group membership; a group's role is
    derived from the same ``group_roles`` mapping the login uses; every write is audited under
    ``provisioning.changed`` with the acting key.
    """

    def __init__(
        self,
        *,
        principals: ProvisionedPrincipalStore,
        sessions: SessionStore | None = None,
        accounts: ServiceAccountStore | None = None,
        settings: Settings | None = None,
        auditor: Auditor | None = None,
    ) -> None:
        self.principals = principals
        self.sessions = sessions
        self.accounts = accounts
        self.settings = settings
        self.auditor = auditor

    # ------------------------------------------------------------------ role derivation
    def _group_names(self, group_ids: tuple[str, ...]) -> list[str]:
        """Group ids → display names, the vocabulary ``group_roles`` is written in."""
        by_id = {group.group_id: group.display_name for group in self.principals.list_groups()}
        names: list[str] = []
        for group_id in group_ids:
            names.append(by_id.get(group_id, group_id))
        return names

    def role_for(self, record: PrincipalRecord) -> str | None:
        if self.settings is None or not record.active:
            return None
        return role_for_groups(self.settings, self._group_names(record.groups))

    def _write_groups(self, record: PrincipalRecord, groups: tuple[str, ...]) -> PrincipalRecord:
        """Persist a principal's membership on both sides (see ``set_groups``)."""
        updated = self.principals.set_groups(record.id, groups)
        return record if updated is None else updated

    def group_role(self, record: GroupRecord) -> str | None:
        if self.settings is None:
            return None
        return role_for_groups(self.settings, [record.display_name])

    # ------------------------------------------------------------------ users
    def create_user(
        self, payload: dict[str, Any], *, actor: str, subject: str | None = None
    ) -> tuple[PrincipalRecord, bool]:
        """``POST /Users``. Idempotent on ``externalId`` (or the supplied subject)."""
        user_name = str(payload.get("userName") or "").strip()
        if not user_name:
            raise ProvisioningError(400, "`userName` is required", "invalidValue")
        external_id = payload.get("externalId")
        key = subject or (str(external_id) if external_id else None) or user_name
        emails = _emails(payload)
        display_name = payload.get("displayName") or _name_formatted(payload)
        groups = _group_values(payload)
        record, created = self.principals.upsert_principal(
            subject=key,
            user_name=user_name,
            display_name=display_name,
            emails=emails,
            groups=groups,
            external_id=str(external_id) if external_id else None,
            active=bool(payload.get("active", True)),
        )
        if groups:
            record = self._write_groups(record, groups)
        self._audit(
            "user.created" if created else "user.reconciled",
            record,
            actor=actor,
        )
        return record, created

    def get_user(self, reference: str) -> PrincipalRecord:
        record = self.principals.get_principal(reference)
        if record is None:
            raise ProvisioningError(404, f"no provisioned user {reference!r}", None)
        return record

    def replace_user(
        self, reference: str, payload: dict[str, Any], *, actor: str
    ) -> PrincipalRecord:
        existing = self.get_user(reference)
        user_name = str(payload.get("userName") or existing.user_name)
        active = bool(payload.get("active", existing.active))
        record = self.principals.update_principal(
            reference,
            user_name=user_name,
            display_name=payload.get("displayName") or _name_formatted(payload),
            emails=_emails(payload),
            external_id=str(payload["externalId"]) if payload.get("externalId") else None,
            active=active,
        )
        if record is None:  # pragma: no cover - replace_user re-reads under the same store
            raise ProvisioningError(404, f"no provisioned user {reference!r}", None)
        record = self._write_groups(record, _group_values(payload))
        self._audit("user.replaced", record, actor=actor)
        if not record.active:
            self._deprovision_side_effects(record, actor=actor)
        return record

    def patch_user(
        self, reference: str, operations: list[dict[str, Any]], *, actor: str
    ) -> PrincipalRecord:
        """RFC 7644 §3.5.2 PATCH, for the operations an IdP actually sends."""
        self.get_user(reference)
        groups = list(self.get_user(reference).groups)
        fields: dict[str, Any] = {}
        deactivated = False
        for operation in operations:
            op = str(operation["op"]).lower()
            path = str(operation.get("path") or "").strip()
            value = operation.get("value")
            if not path:
                if not isinstance(value, dict):
                    raise ProvisioningError(
                        400, "a PATCH without `path` needs an object `value`", "invalidValue"
                    )
                if "active" in value:
                    fields["active"] = bool(value["active"])
                    deactivated = not bool(value["active"])
                if "displayName" in value:
                    fields["displayName"] = value["displayName"]
                if "userName" in value:
                    fields["userName"] = str(value["userName"])
                continue
            attribute = path.split(":")[-1].split("[")[0].strip().lower()
            if attribute == "active" and op in {"add", "replace"}:
                fields["active"] = bool(value)
                deactivated = not bool(value)
            elif attribute == "displayname" and op in {"add", "replace"}:
                fields["displayName"] = value
            elif attribute in {"groups", "members"}:
                groups = _apply_group_patch(groups, op, value)
            elif attribute == "username" and op in {"add", "replace"}:
                fields["userName"] = str(value)
            else:
                raise ProvisioningError(
                    400,
                    f"this build cannot PATCH {path!r} with op {op!r}",
                    "mutability",
                )
        changed_groups = groups != list(self.get_user(reference).groups)
        record = self.principals.update_principal(reference, **fields)
        if record is None:  # pragma: no cover - the get_user above proved it exists
            raise ProvisioningError(404, f"no provisioned user {reference!r}", None)
        if changed_groups:
            record = self._write_groups(record, tuple(groups))
        self._audit("user.patched", record, actor=actor)
        if deactivated:
            self._deprovision_side_effects(record, actor=actor)
        return record

    def deactivate_user(self, reference: str, *, actor: str) -> PrincipalRecord:
        """``DELETE /Users/{id}``: deactivate, revoke sessions and keys, leave the groups.

        Soft by design — the row keeps attributing historical scans — and complete by design:
        the sessions and keys go in the same request, which is the whole reason a
        deprovisioning API exists.
        """
        self.get_user(reference)
        updated = self.principals.update_principal(reference, active=False)
        if updated is None:  # pragma: no cover - get_user proved it exists
            raise ProvisioningError(404, f"no provisioned user {reference!r}", None)
        self._audit("user.deactivated", updated, actor=actor)
        self._deprovision_side_effects(updated, actor=actor)
        return updated

    def _deprovision_side_effects(
        self, record: PrincipalRecord, *, actor: str
    ) -> DeprovisionOutcome:
        """Revoke the subject's sessions and owned keys, and drop their memberships."""
        sessions_revoked = (
            self.sessions.revoke_subject(record.subject) if self.sessions is not None else 0
        )
        keys: list[str] = []
        if self.accounts is not None:
            owners = {record.subject, record.user_name}
            if record.primary_email:
                owners.add(record.primary_email)
            for owner in sorted(owners):
                keys.extend(self.accounts.revoke_owned_by(owner, actor=actor))
        groups_left = self.principals.remove_member(record.subject)
        outcome = DeprovisionOutcome(
            subject=record.subject,
            user_name=record.user_name,
            sessions_revoked=sessions_revoked,
            keys_revoked=tuple(sorted(set(keys))),
            groups_left=groups_left,
        )
        if self.auditor is not None:
            self.auditor.record(
                AuditAction.SERVICE_ACCOUNT_CHANGED if keys else AuditAction.PROVISIONING_CHANGED,
                outcome=AuditOutcome.ALLOWED,
                target=f"principal:{record.subject}",
                reason="deprovisioned: sessions and owned keys revoked in one request",
                meta={"deprovisioned": outcome.to_dict(), "actor": actor},
            )
        return outcome

    def deprovision(self, reference: str, *, actor: str) -> DeprovisionOutcome:
        """Deactivate ``reference`` and revoke everything it held — the public leaver call."""
        self.get_user(reference)
        updated = self.principals.update_principal(reference, active=False)
        if updated is None:  # pragma: no cover - get_user proved it exists
            raise ProvisioningError(404, f"no provisioned user {reference!r}", None)
        self._audit("user.deactivated", updated, actor=actor)
        return self._deprovision_side_effects(updated, actor=actor)

    # ------------------------------------------------------------------ groups
    def create_group(
        self, payload: dict[str, Any], *, actor: str, group_id: str | None = None
    ) -> tuple[GroupRecord, bool]:
        display_name = str(payload.get("displayName") or "").strip()
        if not display_name:
            raise ProvisioningError(400, "`displayName` is required", "invalidValue")
        key = group_id or str(payload.get("externalId") or display_name)
        members = _members(payload)
        record, created = self.principals.upsert_group(
            group_id=key,
            display_name=display_name,
            members=members,
            external_id=str(payload["externalId"]) if payload.get("externalId") else None,
        )
        self._sync_memberships(record, previous=())
        self._audit_group("group.created" if created else "group.reconciled", record, actor=actor)
        return record, created

    def get_group(self, reference: str) -> GroupRecord:
        record = self.principals.get_group(reference)
        if record is None:
            raise ProvisioningError(404, f"no provisioned group {reference!r}", None)
        return record

    def replace_group(self, reference: str, payload: dict[str, Any], *, actor: str) -> GroupRecord:
        existing = self.get_group(reference)
        display_name = str(payload.get("displayName") or existing.display_name)
        members = _members(payload)
        record = self.principals.update_group(reference, display_name=display_name, members=members)
        if record is None:  # pragma: no cover - get_group proved it exists
            raise ProvisioningError(404, f"no provisioned group {reference!r}", None)
        self._sync_memberships(record, previous=existing.members)
        self._audit_group("group.replaced", record, actor=actor)
        return record

    def patch_group(
        self, reference: str, operations: list[dict[str, Any]], *, actor: str
    ) -> GroupRecord:
        existing = self.get_group(reference)
        members = list(existing.members)
        display_name = existing.display_name
        for operation in operations:
            op = str(operation["op"]).lower()
            path = str(operation.get("path") or "").strip()
            value = operation.get("value")
            attribute = path.split(":")[-1].split("[")[0].strip().lower() if path else ""
            if attribute == "displayname" and op in {"add", "replace"}:
                display_name = str(value)
            elif attribute in {"members", ""} and op in {"add", "replace", "remove"}:
                members = list(_apply_group_patch(members, op, value))
            else:
                raise ProvisioningError(
                    400, f"this build cannot PATCH {path!r} with op {op!r}", "mutability"
                )
        record = self.principals.update_group(
            reference, display_name=display_name, members=tuple(members)
        )
        if record is None:  # pragma: no cover - get_group proved it exists
            raise ProvisioningError(404, f"no provisioned group {reference!r}", None)
        self._sync_memberships(record, previous=existing.members)
        self._audit_group("group.patched", record, actor=actor)
        return record

    def delete_group(self, reference: str, *, actor: str) -> GroupRecord:
        """Remove a group and drop it from every member's asserted groups."""
        existing = self.get_group(reference)
        for subject in existing.members:
            principal = self.principals.get_principal(subject)
            if principal is None:
                continue
            kept = tuple(item for item in principal.groups if item != existing.group_id)
            self.principals.update_principal(subject, groups=kept)
        self.principals.delete_group(reference)
        self._audit_group("group.deleted", existing, actor=actor)
        return existing

    def _sync_memberships(self, record: GroupRecord, *, previous: tuple[str, ...]) -> None:
        """Project group membership onto each principal's ``groups_json`` (the role source)."""
        current = set(record.members)
        for subject in sorted(current | set(previous)):
            principal = self.principals.get_principal(subject)
            if principal is None:
                continue
            groups = set(principal.groups)
            if subject in current:
                groups.add(record.group_id)
            else:
                groups.discard(record.group_id)
            if groups != set(principal.groups):
                self.principals.set_groups(principal.id, tuple(sorted(groups)))

    # ------------------------------------------------------------------ audit
    def _audit(self, change: str, record: PrincipalRecord, *, actor: str) -> None:
        if self.auditor is None:
            return
        self.auditor.record(
            AuditAction.PROVISIONING_CHANGED,
            outcome=AuditOutcome.ALLOWED,
            target=f"principal:{record.subject}",
            reason=change,
            meta={
                "change": change,
                "resource": "User",
                "subject": record.subject,
                "user_name": record.user_name,
                "active": record.active,
                "groups": list(record.groups),
                "role": self.role_for(record),
                "actor": actor,
            },
        )

    def _audit_group(self, change: str, record: GroupRecord, *, actor: str) -> None:
        if self.auditor is None:
            return
        self.auditor.record(
            AuditAction.PROVISIONING_CHANGED,
            outcome=AuditOutcome.ALLOWED,
            target=f"group:{record.group_id}",
            reason=change,
            meta={
                "change": change,
                "resource": "Group",
                "group": record.group_id,
                "display_name": record.display_name,
                "members": list(record.members),
                "role": self.group_role(record),
                "actor": actor,
            },
        )


def _emails(payload: dict[str, Any]) -> tuple[str, ...]:
    raw = payload.get("emails")
    if not isinstance(raw, list):
        return ()
    values: list[str] = []
    for entry in raw:
        if isinstance(entry, dict) and entry.get("value"):
            values.append(str(entry["value"]))
        elif isinstance(entry, str) and entry:
            values.append(entry)
    return tuple(values)


def _name_formatted(payload: dict[str, Any]) -> str | None:
    name = payload.get("name")
    if isinstance(name, dict) and name.get("formatted"):
        return str(name["formatted"])
    return None


def _group_values(payload: dict[str, Any]) -> tuple[str, ...]:
    raw = payload.get("groups")
    if not isinstance(raw, list):
        return ()
    values: list[str] = []
    for entry in raw:
        if isinstance(entry, dict) and entry.get("value"):
            values.append(str(entry["value"]))
        elif isinstance(entry, str) and entry:
            values.append(entry)
    return tuple(values)


def _members(payload: dict[str, Any]) -> tuple[str, ...]:
    raw = payload.get("members")
    if not isinstance(raw, list):
        return ()
    values: list[str] = []
    for entry in raw:
        if isinstance(entry, dict) and entry.get("value"):
            values.append(str(entry["value"]))
        elif isinstance(entry, str) and entry:
            values.append(entry)
    return tuple(values)


def _apply_group_patch(groups: list[str], op: str, value: Any) -> list[str]:
    """Apply one ``members``/``groups`` patch operation to a list of subject values."""
    if op == "remove" and value is None:
        return []
    values: list[str] = []
    if isinstance(value, list):
        for entry in value:
            if isinstance(entry, dict) and entry.get("value"):
                values.append(str(entry["value"]))
            elif isinstance(entry, str) and entry:
                values.append(entry)
    elif isinstance(value, dict) and value.get("value"):
        values.append(str(value["value"]))
    elif isinstance(value, str) and value:
        values.append(value)
    if op == "remove":
        return [item for item in groups if item not in set(values)]
    merged = list(groups)
    for item in values:
        if item not in merged:
            merged.append(item)
    return merged


def require_scim_settings(settings: Settings) -> None:
    """SCIM needs a role mapping to be useful; refuse a deployment that has none.

    Without ``ARACHNE_SSO_GROUP_ROLES`` (or a default role) every provisioned principal would
    derive ``None``, and a provisioning API that silently grants nothing is worse than one
    that says why.
    """
    sso = settings.sso
    if not sso.group_roles and sso.default_role is None:
        msg = (
            "SCIM provisioning needs a role mapping: set ARACHNE_SSO_GROUP_ROLES "
            "(group:role entries) or ARACHNE_SSO_DEFAULT_ROLE"
        )
        raise ConfigurationError(msg)
