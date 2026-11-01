"""``arachne metrics`` — render the deployment's Prometheus exposition (S20, REQ-OPS-003).

The API serves the same text at ``GET /metrics``; this command exists for the two cases the
endpoint cannot cover: a deployment that does not expose the API at all (an air-gapped cron
job), and a test or operator who wants to see the metric names and labels without a running
server. It collects the deployment-wide gauges first, so the output is the real thing.
"""

from __future__ import annotations

from typing import Annotated

import typer

from arachne.core.config import get_settings
from arachne.core.metrics import render_metrics
from arachne.data.metrics_source import collect_deployment_metrics
from arachne.data.services import build_services

__all__ = ["metrics_command"]


def metrics_command(
    names_only: Annotated[
        bool, typer.Option("--names", help="List the metric family names and stop.")
    ] = False,
    no_collect: Annotated[
        bool,
        typer.Option("--no-collect", help="Skip the database round trip (process counters only)."),
    ] = False,
) -> None:
    """Print the Prometheus exposition for this deployment."""
    if names_only:
        from arachne.core.metrics import METRIC_FAMILIES

        for family in METRIC_FAMILIES:
            labels = ",".join(family.label_names)
            typer.echo(f"{family.name}\t{family.kind}\t{labels}")
        return
    if no_collect:
        typer.echo(render_metrics(), nl=False)
        return
    services = build_services(get_settings())
    try:
        collect_deployment_metrics(services)
    finally:
        services.close()
    typer.echo(render_metrics(), nl=False)
