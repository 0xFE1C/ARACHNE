"""SCIM 2.0 provisioning endpoints (WP-20, area IDAM, REQ-IDAM-007).

Mounted at ``/api/v1/scim/v2`` — the base path ``docs/scim-ldap-interface.md`` fixes — and
authenticated **only** by a dedicated provisioner credential: a service account holding the
``admin`` role. Three things are deliberately excluded:

* a **viewer key**, which the requirement names: provisioning is an access change, not a read;
* a **static API key** (``ARACHNE_API_KEYS``), because it has no owner and no rotation lineage,
  so "which provisioner made this change?" would have no answer;
* an **SSO session**, because a browser cookie must never be able to create accounts. The
  dependency resolves the credential through :meth:`CredentialStore.verify_key` only, so the
  session path is not reachable from here at all.

The wire format is RFC 7643 (resources) and RFC 7644 (protocol), built in
:mod:`arachne.idam.scim`; this module is the HTTP translation and nothing else.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response, status
from fastapi.responses import JSONResponse

from arachne.api.auth import API_KEY_HEADER, Principal, Role, _deny
from arachne.api.deps import ContextDep
from arachne.core.audit import AuditAction, AuditOutcome
from arachne.idam.scim import (
    DeprovisionOutcome,
    ProvisioningError,
    ProvisioningService,
    error_document,
    group_document,
    list_document,
    parse_filter,
    patch_operations,
    resource_types,
    schemas_document,
    service_provider_config,
    user_document,
)

__all__ = ["scim_router"]

scim_router = APIRouter(prefix="/scim/v2", tags=["scim"])

#: How many resources one page returns when the IdP does not say (RFC 7644 §3.4.2.4).
DEFAULT_COUNT = 100
MAX_COUNT = 1000

#: The filter parameter's documentation, shared by the two list endpoints.
FILTER_DESCRIPTION = 'SCIM filter, e.g. `userName eq "alice"`.'


def _bearer(request: Request) -> str | None:
    """The secret from an ``Authorization: Bearer`` header, if that is what it carries."""
    header = request.headers.get("authorization") or ""
    scheme, _, value = header.partition(" ")
    if scheme.lower() != "bearer" or not value.strip():
        return None
    return value.strip()


def scim_principal(request: Request, context: ContextDep) -> Principal:
    """The dedicated provisioner credential, or a refusal audited like every other denial."""
    secret = _bearer(request) or request.headers.get(API_KEY_HEADER)
    principal = context.credentials.verify_key(secret.strip() if secret else None)
    if principal is None:
        _deny(request, context.auditor, "invalid SCIM credential")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="SCIM requires a service-account credential",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if principal.source != "service_account":
        _deny(request, context.auditor, "SCIM requires a dedicated service-account credential")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "SCIM is authenticated by a dedicated admin service account, not by a static "
                "API key or a browser session"
            ),
        )
    if not principal.allows(Role.ADMIN):
        _deny(request, context.auditor, "SCIM requires the admin role")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"role {principal.role.value} may not provision identities",
        )
    return principal


ScimPrincipal = Annotated[Principal, Depends(scim_principal)]


def _service(context: ContextDep) -> ProvisioningService:
    store = context.services.provisioned_principals
    if store is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="this deployment carries no provisioning store",
        )
    return ProvisioningService(
        principals=store,
        sessions=context.services.auth_sessions,
        accounts=context.services.service_accounts,
        settings=context.settings,
        auditor=context.auditor,
    )


def _refused(exc: ProvisioningError) -> JSONResponse:
    return JSONResponse(
        error_document(exc.status, exc.detail, exc.scim_type), status_code=exc.status
    )


def _page(start_index: int, count: int) -> tuple[int, int, int]:
    """Validate the RFC 7644 paging parameters: 1-based ``startIndex``, bounded ``count``."""
    if start_index < 1:
        raise ProvisioningError(400, "`startIndex` is 1-based", "invalidValue")
    size = DEFAULT_COUNT if count <= 0 else min(count, MAX_COUNT)
    return start_index, size, (start_index - 1) * size


def _audit_read(context: ContextDep, principal: Principal, resource: str, count: int) -> None:
    context.auditor.with_actor(principal.actor).record(
        AuditAction.API_REQUEST,
        outcome=AuditOutcome.ALLOWED,
        target=f"/api/v1/scim/v2/{resource}",
        meta={"provisioning_read": resource, "returned": count, "actor": principal.label},
    )


# --------------------------------------------------------------------------- discovery
@scim_router.get("/ServiceProviderConfig")
def get_service_provider_config(principal: ScimPrincipal, context: ContextDep) -> JSONResponse:
    """What this provisioner interface supports (RFC 7643 §5)."""
    del principal
    _service(context)
    return JSONResponse(service_provider_config())


@scim_router.get("/ResourceTypes")
def get_resource_types(principal: ScimPrincipal, context: ContextDep) -> JSONResponse:
    del principal
    _service(context)
    return JSONResponse(resource_types())


@scim_router.get("/Schemas")
def get_schemas(principal: ScimPrincipal, context: ContextDep) -> JSONResponse:
    del principal
    _service(context)
    return JSONResponse(schemas_document())


# --------------------------------------------------------------------------- users
@scim_router.get("/Users")
def list_users(
    principal: ScimPrincipal,
    context: ContextDep,
    filter: Annotated[  # noqa: A002 - the RFC's parameter name
        str | None, Query(description=FILTER_DESCRIPTION)
    ] = None,
    startIndex: Annotated[int, Query(ge=1)] = 1,  # noqa: N803 - the RFC's parameter name
    count: Annotated[int, Query(ge=0)] = DEFAULT_COUNT,
) -> JSONResponse:
    """The provisioned directory, paged and optionally filtered (RFC 7644 §3.4.2)."""
    service = _service(context)
    try:
        criteria = parse_filter(filter)
        start_index, size, offset = _page(startIndex, count)
    except ProvisioningError as exc:
        return _refused(exc)
    # One attribute per filter (``parse_filter`` returns at most one key), and exactly that
    # attribute is passed on. Sending ``externalId eq "x"`` as *both* a userName and an
    # externalId filter matches nothing, and a provisioner reading that concludes the person
    # does not exist — the silent wrong answer this module's docstring exists to prevent.
    records = service.principals.list_principals(
        user_name=criteria.get("username"),
        external_id=criteria.get("externalid"),
    )
    page = records[offset : offset + size]
    resources = [user_document(record, role=service.role_for(record)) for record in page]
    _audit_read(context, principal, "Users", len(resources))
    return JSONResponse(
        list_document(
            resources,
            total=len(records),
            start_index=start_index,
            items_per_page=len(resources),
        )
    )


@scim_router.post("/Users", status_code=status.HTTP_201_CREATED)
def create_user(
    payload: dict[str, Any], principal: ScimPrincipal, context: ContextDep
) -> JSONResponse:
    """Create (or reconcile, on the same subject) one principal (RFC 7644 §3.3)."""
    service = _service(context)
    try:
        record, created = service.create_user(payload, actor=principal.actor)
    except ProvisioningError as exc:
        return _refused(exc)
    document = user_document(record, role=service.role_for(record))
    return JSONResponse(document, status_code=201 if created else 200)


@scim_router.get("/Users/{user_id}")
def get_user(user_id: str, principal: ScimPrincipal, context: ContextDep) -> JSONResponse:
    del principal
    service = _service(context)
    try:
        record = service.get_user(user_id)
    except ProvisioningError as exc:
        return _refused(exc)
    return JSONResponse(user_document(record, role=service.role_for(record)))


@scim_router.put("/Users/{user_id}")
def replace_user(
    user_id: str, payload: dict[str, Any], principal: ScimPrincipal, context: ContextDep
) -> JSONResponse:
    """Replace a principal's attributes (RFC 7644 §3.5.1)."""
    service = _service(context)
    try:
        record = service.replace_user(user_id, payload, actor=principal.actor)
    except ProvisioningError as exc:
        return _refused(exc)
    return JSONResponse(user_document(record, role=service.role_for(record)))


@scim_router.patch("/Users/{user_id}")
def patch_user(
    user_id: str, payload: dict[str, Any], principal: ScimPrincipal, context: ContextDep
) -> JSONResponse:
    """Apply SCIM PATCH operations — the Mover half of a joiner-mover-leaver cycle."""
    service = _service(context)
    try:
        operations = patch_operations(payload)
        record = service.patch_user(user_id, operations, actor=principal.actor)
    except ProvisioningError as exc:
        return _refused(exc)
    return JSONResponse(user_document(record, role=service.role_for(record)))


@scim_router.delete("/Users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(user_id: str, principal: ScimPrincipal, context: ContextDep) -> Response:
    """Deprovision: deactivate, revoke sessions and keys, drop memberships — in one request.

    A 204 with no body, as RFC 7644 §3.6 asks. The removed material is not in the response
    but in the audit trail: ``provisioning.changed`` carries what was revoked, so an operator
    can answer "did the leaver's key stop working?" without reading the database.
    """
    service = _service(context)
    try:
        service.deprovision(user_id, actor=principal.actor)
    except ProvisioningError as exc:
        return _refused(exc)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# --------------------------------------------------------------------------- groups
@scim_router.get("/Groups")
def list_groups(
    principal: ScimPrincipal,
    context: ContextDep,
    filter: Annotated[  # noqa: A002 - the RFC's parameter name
        str | None, Query(description=FILTER_DESCRIPTION)
    ] = None,
    startIndex: Annotated[int, Query(ge=1)] = 1,  # noqa: N803 - the RFC's parameter name
    count: Annotated[int, Query(ge=0)] = DEFAULT_COUNT,
) -> JSONResponse:
    """The provisioned groups, paged and optionally filtered (RFC 7644 §3.4.2)."""
    service = _service(context)
    try:
        criteria = parse_filter(filter)
        start_index, size, offset = _page(startIndex, count)
    except ProvisioningError as exc:
        return _refused(exc)
    records = service.principals.list_groups(display_name=criteria.get("displayname"))
    page = records[offset : offset + size]
    resources = [group_document(record, role=service.group_role(record)) for record in page]
    _audit_read(context, principal, "Groups", len(resources))
    return JSONResponse(
        list_document(resources, total=len(records), start_index=start_index, items_per_page=size)
    )


@scim_router.post("/Groups", status_code=status.HTTP_201_CREATED)
def create_group(
    payload: dict[str, Any], principal: ScimPrincipal, context: ContextDep
) -> JSONResponse:
    """Create (or reconcile) one group; membership is projected onto its members."""
    service = _service(context)
    try:
        record, created = service.create_group(payload, actor=principal.actor)
    except ProvisioningError as exc:
        return _refused(exc)
    document = group_document(record, role=service.group_role(record))
    return JSONResponse(document, status_code=201 if created else 200)


@scim_router.get("/Groups/{group_id}")
def get_group(group_id: str, principal: ScimPrincipal, context: ContextDep) -> JSONResponse:
    del principal
    service = _service(context)
    try:
        record = service.get_group(group_id)
    except ProvisioningError as exc:
        return _refused(exc)
    return JSONResponse(group_document(record, role=service.group_role(record)))


@scim_router.put("/Groups/{group_id}")
def replace_group(
    group_id: str, payload: dict[str, Any], principal: ScimPrincipal, context: ContextDep
) -> JSONResponse:
    service = _service(context)
    try:
        record = service.replace_group(group_id, payload, actor=principal.actor)
    except ProvisioningError as exc:
        return _refused(exc)
    return JSONResponse(group_document(record, role=service.group_role(record)))


@scim_router.patch("/Groups/{group_id}")
def patch_group(
    group_id: str, payload: dict[str, Any], principal: ScimPrincipal, context: ContextDep
) -> JSONResponse:
    service = _service(context)
    try:
        operations = patch_operations(payload)
        record = service.patch_group(group_id, operations, actor=principal.actor)
    except ProvisioningError as exc:
        return _refused(exc)
    return JSONResponse(group_document(record, role=service.group_role(record)))


@scim_router.delete("/Groups/{group_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_group(group_id: str, principal: ScimPrincipal, context: ContextDep) -> Response:
    service = _service(context)
    try:
        outcome: DeprovisionOutcome | Any = service.delete_group(group_id, actor=principal.actor)
    except ProvisioningError as exc:
        return _refused(exc)
    del outcome
    return Response(status_code=status.HTTP_204_NO_CONTENT)
