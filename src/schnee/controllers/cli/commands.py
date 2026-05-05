from __future__ import annotations

from typing import TYPE_CHECKING

from schnee.controllers.cli.errors import exit_for_service_error
from schnee.controllers.cli.output import echo_text
from schnee.services.backend import ListBackendNamesService
from schnee.services.base import ServiceError

if TYPE_CHECKING:
    import typer


def register_commands(app: typer.Typer) -> None:
    """Register CLI commands."""

    @app.callback(invoke_without_command=True)
    def root() -> None:
        """NFC/RFID tag authentication and encryption tools."""

    @app.command("backends")
    def backends() -> None:
        """List selectable backend names."""
        try:
            names = ListBackendNamesService.call(ListBackendNamesService.Request())
        except ServiceError as exc:
            exit_for_service_error(exc)

        for name in names:
            echo_text(name)
