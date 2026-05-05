from __future__ import annotations

from typing import TYPE_CHECKING, NoReturn

import typer

if TYPE_CHECKING:
    from schnee.services.base import ServiceError

SERVICE_ERROR_EXIT_CODE = 1


def exit_for_service_error(exc: ServiceError) -> NoReturn:
    """Render a service-level error and exit the CLI."""
    typer.echo(exc.msg, err=True)
    raise typer.Exit(code=SERVICE_ERROR_EXIT_CODE)
