from __future__ import annotations

from typing import TYPE_CHECKING

import typer

if TYPE_CHECKING:
    from schnee.services.base import ServiceError

SERVICE_ERROR_EXIT_CODE = 1


def exit_for_service_error(exc: ServiceError) -> typer.Exit:
    """Render a service-level error and return a CLI exit exception."""
    typer.echo(exc.msg, err=True)
    return typer.Exit(code=SERVICE_ERROR_EXIT_CODE)
