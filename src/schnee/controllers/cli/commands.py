from __future__ import annotations

from typing import Annotated

import typer

from schnee.controllers.cli.errors import exit_for_service_error
from schnee.controllers.cli.output import echo_json, echo_text
from schnee.services.backend import ListBackendNamesService
from schnee.services.base import ServiceError
from schnee.services.ntag_profile import ReadNtagProfileService, WriteNdefUrlService

AES_KEY_SIZE = 16


def _parse_optional_hex(value: str | None, *, option_name: str) -> bytes | None:
    """Convert an optional CLI hex value to bytes."""
    if value is None:
        return None
    try:
        parsed = bytes.fromhex(value)
    except ValueError as exc:
        msg = "must be valid hexadecimal"
        raise typer.BadParameter(msg, param_hint=option_name) from exc
    if len(parsed) != AES_KEY_SIZE:
        msg = "must decode to 16 bytes"
        raise typer.BadParameter(
            msg,
            param_hint=option_name,
        )
    return parsed


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

    @ntag_app.command("write-url")
    def write_ndef_url(
        url: Annotated[
            str,
            typer.Option(
                "--url",
                help="URL to write as a single NDEF URI record.",
            ),
        ],
        backend_name: Annotated[
            str,
            typer.Option(
                "--backend",
                help="Backend name, for example pcsc or pcsc:<reader name>.",
            ),
        ] = "pcsc",
        ntag424_master_key_hex: Annotated[
            str | None,
            typer.Option(
                "--ntag424-master-key-hex",
                help="Current NTAG 424 DNA application master key as hex.",
            ),
        ] = None,
    ) -> None:
        """Write a URL NDEF record."""
        ntag424_master_key = _parse_optional_hex(
            ntag424_master_key_hex,
            option_name="--ntag424-master-key-hex",
        )
        try:
            WriteNdefUrlService.call(
                WriteNdefUrlService.Request(
                    backend_name=backend_name,
                    url=url,
                    ntag424_master_key=ntag424_master_key,
                ),
            )
        except ServiceError as exc:
            exit_for_service_error(exc)
