from __future__ import annotations

from typing import Annotated

import typer

from schnee.controllers.cli.errors import exit_for_service_error
from schnee.controllers.cli.output import echo_json, echo_text
from schnee.services.backend import ListBackendNamesService
from schnee.services.base import ServiceError
from schnee.services.ntag_profile import ReadNtagProfileService


def register_commands(app: typer.Typer) -> None:
    """Register CLI commands."""
    ntag_app = typer.Typer(help="NTAG profile commands.", no_args_is_help=True)
    app.add_typer(ntag_app, name="ntag")

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

    @ntag_app.command("read")
    def read_ntag_profile(
        backend_name: Annotated[
            str,
            typer.Option(
                "--backend",
                help="Backend name, for example pcsc or pcsc:<reader name>.",
            ),
        ] = "pcsc",
    ) -> None:
        """Read an NTAG profile."""
        try:
            profile = ReadNtagProfileService.call(
                ReadNtagProfileService.Request(backend_name=backend_name),
            )
        except ServiceError as exc:
            exit_for_service_error(exc)

        echo_json(profile.model_dump(mode="json"))
