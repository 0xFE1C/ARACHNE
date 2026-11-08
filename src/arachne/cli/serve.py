"""``arachne serve`` — run the REST API + web UI (F-07-02/03, F-08-02, S12).

One command starts the ASGI app with uvicorn. TLS is on by default: the command refuses to
bind a non-loopback address without a certificate (``ARACHNE_API_TLS_CERT`` /
``ARACHNE_API_TLS_KEY``) unless ``--insecure`` is given explicitly, which is the F-08-02
"TLS by default" requirement applied where the socket is actually opened.

The API is imported lazily so an ordinary ``arachne scan`` never loads the ASGI stack — the
scanner does not depend on its interface .
"""

from __future__ import annotations

from typing import Annotated, Any

import typer

from arachne import __version__
from arachne.core.config import get_settings
from arachne.core.errors import ConfigurationError

__all__ = ["serve_command"]


def serve_command(
    host: Annotated[
        str | None, typer.Option("--host", help="Bind address (default ARACHNE_API_HOST).")
    ] = None,
    port: Annotated[
        int | None, typer.Option("--port", help="Bind port (default ARACHNE_API_PORT).")
    ] = None,
    insecure: Annotated[
        bool,
        typer.Option(
            "--insecure",
            help="Allow serving plain HTTP (loopback development only).",
        ),
    ] = False,
    log_level: Annotated[str | None, typer.Option("--log-level", help="uvicorn log level.")] = None,
    workers: Annotated[
        int | None,
        typer.Option(
            "--workers",
            help="uvicorn worker processes (default ARACHNE_API_WORKERS). 1 = one process.",
        ),
    ] = None,
) -> None:
    """Serve the REST API and web UI."""
    settings = get_settings()
    api = settings.api
    bind_host = host or api.host
    bind_port = port or api.port

    if api.require_tls and not api.tls_configured and not insecure and not _is_loopback(bind_host):
        msg = (
            f"refusing to serve {bind_host}:{bind_port} without TLS: set "
            "ARACHNE_API_TLS_CERT and ARACHNE_API_TLS_KEY, or pass --insecure for a "
            "loopback-only development deployment (F-08-02 requires TLS by default)"
        )
        raise ConfigurationError(msg)
    if not settings.api.keys:
        typer.echo(
            "warning: no API keys are configured (ARACHNE_API_KEYS / ARACHNE_API_KEYS_FILE); "
            "every request will be refused until keys are set",
            err=True,
        )

    import uvicorn

    worker_count = workers or api.workers
    services = None
    # uvicorn's multi-worker mode spawns subprocesses that import the app
    # themselves, so with more than one worker the factory goes in as an import
    # string and each worker builds its own services from the environment
    # (REQ-OPS-005).
    target: str | Any
    if worker_count > 1:
        target = "arachne.api.app:get_app"
    else:
        from arachne.api.app import create_app
        from arachne.data.services import build_services

        services = build_services(settings)
        target = create_app(services, settings=settings)
    scheme = "https" if api.tls_configured else "http"
    suffix = f" ({worker_count} workers)" if worker_count > 1 else ""
    typer.echo(f"ARACHNE {__version__} serving on {scheme}://{bind_host}:{bind_port}{suffix}")
    try:
        uvicorn.run(
            target,
            host=bind_host,
            port=bind_port,
            log_level=(log_level or settings.log_level or "info").lower(),
            ssl_certfile=api.tls_certfile if api.tls_configured else None,
            ssl_keyfile=api.tls_keyfile if api.tls_configured else None,
            workers=worker_count,
        )
    finally:
        if services is not None:
            services.close()


def _is_loopback(host: str) -> bool:
    import ipaddress

    if host in {"localhost", ""}:
        return True
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return False
