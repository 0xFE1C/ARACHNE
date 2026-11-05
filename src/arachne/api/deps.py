"""FastAPI dependencies for auth, roles and the application context (S12).

A router depends on ``get_context`` and, when it needs an authenticated caller,
``get_principal``; ``require(minimum_role)`` composes the two. Rate limiting is a
middleware (it must also cover the 401 path), so a route never guards against a flood
itself.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Annotated

from fastapi import Depends, HTTPException, Request, status

from arachne.api.auth import Principal, Role, authenticate, require_role
from arachne.api.context import AppContext
from arachne.core.audit import AuditAction, AuditOutcome
from arachne.core.errors import ConfigurationError
from arachne.data.project_store import ProjectRecord

__all__ = [
    "PROJECT_HEADER",
    "AdminPrincipal",
    "AppContext",
    "Principal",
    "ProjectDep",
    "ScannerPrincipal",
    "ViewerPrincipal",
    "get_context",
    "get_principal",
    "get_project",
    "require",
]

#: Header/query parameter that selects the tenant of a request (F-07-06).
PROJECT_HEADER = "x-project"


def get_context(request: Request) -> AppContext:
    """The application context assembled by :func:`arachne.api.app.create_app`."""
    context: AppContext = request.app.state.context
    return context


def get_principal(
    request: Request,
    context: Annotated[AppContext, Depends(get_context)],
) -> Principal:
    """Authenticate the request or raise 401 (auditing the refusal)."""
    return authenticate(request, context.credentials, auditor=context.auditor)


def require(minimum: Role) -> Callable[..., Principal]:
    """A dependency factory enforcing at least ``minimum`` on the authenticated caller."""

    def dependency(
        request: Request,
        principal: Annotated[Principal, Depends(get_principal)],
        context: Annotated[AppContext, Depends(get_context)],
    ) -> Principal:
        return require_role(principal, minimum, request, auditor=context.auditor)

    return dependency


#: Ready-made dependencies for the three roles of F-07-02.
ViewerPrincipal = Annotated[Principal, Depends(require(Role.VIEWER))]
ScannerPrincipal = Annotated[Principal, Depends(require(Role.SCANNER))]
AdminPrincipal = Annotated[Principal, Depends(require(Role.ADMIN))]
ContextDep = Annotated[AppContext, Depends(get_context)]


def get_project(
    request: Request,
    principal: Annotated[Principal, Depends(get_principal)],
    context: ContextDep,
) -> ProjectRecord:
    """The tenant this request operates in (F-07-06).

    ``X-Project`` (or ``?project=``) selects it. A key bound to a project can only name that
    project; an unbound key may name any project and otherwise gets the ``default``
    workspace. Isolation is enforced by filtering every query on the returned project, not
    by hiding the parameter.
    """
    requested = (
        request.headers.get(PROJECT_HEADER) or request.query_params.get("project") or ""
    ).strip()
    if principal.project:
        if requested and requested.lower() != principal.project.lower():
            reason = (
                f"this API key is bound to project {principal.project!r}; "
                "it cannot operate on another project"
            )
            # Audited as a denial, like every other refusal (REQ-IDAM-006): a key reaching for
            # another tenant is an isolation event whether the route or this dependency caught it.
            context.auditor.with_actor(principal.actor).record(
                AuditAction.API_DENIED,
                outcome=AuditOutcome.BLOCKED,
                target=str(request.url.path),
                reason=reason,
                meta={
                    "resource": "project",
                    "resource_id": requested,
                    "method": request.method,
                    "path": request.url.path,
                    "project": principal.project,
                },
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=reason,
            )
        requested = principal.project
    try:
        return context.services.projects.resolve(requested or None)
    except ConfigurationError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


ProjectDep = Annotated[ProjectRecord, Depends(get_project)]
