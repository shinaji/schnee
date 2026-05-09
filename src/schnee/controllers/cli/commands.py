from __future__ import annotations

from typing import Annotated

import typer

from schnee.controllers.cli.errors import exit_for_service_error
from schnee.controllers.cli.output import echo_json, echo_text
from schnee.controllers.cli.parsing import parse_hex
from schnee.ndef import NdefUriPrefix
from schnee.services.backend import ListBackendNamesService
from schnee.services.base import ServiceError
from schnee.services.ntag_profile import (
    ReadNtagProfileService,
    VerifyNtag424SdmMacService,
    WriteNdefUrlService,
)
from schnee.utils.ntag.constants import NtagByteLength


def register_commands(app: typer.Typer) -> None:
    """Register CLI commands."""

    @app.callback(invoke_without_command=True)
    def root() -> None:
        """NFC/RFID tag authentication and encryption tools."""

    _register_root_commands(app)
    _register_ntag_commands(app)


def _register_root_commands(app: typer.Typer) -> None:
    """Register root-level CLI commands."""

    @app.command("backends")
    def backends() -> None:
        """List selectable backend names."""
        try:
            names = ListBackendNamesService.call(ListBackendNamesService.Request())
        except ServiceError as exc:
            exit_for_service_error(exc)

        for name in names:
            echo_text(name)


def _register_ntag_commands(app: typer.Typer) -> None:
    """Register NTAG CLI commands."""
    ntag_app = typer.Typer(help="NTAG profile commands.", no_args_is_help=True)
    app.add_typer(ntag_app, name="ntag")

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
                help=(
                    "Current NTAG 424 DNA application master key as 32 hex characters."
                ),
            ),
        ] = None,
    ) -> None:
        """Write a URL NDEF record."""
        ntag424_master_key = (
            None
            if ntag424_master_key_hex is None
            else parse_hex(
                ntag424_master_key_hex,
                option_name="--ntag424-master-key-hex",
                byte_length=NtagByteLength.AES_KEY,
            )
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

    @ntag_app.command("verify-sdm-mac")
    def verify_sdm_mac(  # noqa: PLR0913
        signed_text: Annotated[
            str,
            typer.Option(
                "--signed-text",
                help="Signed text from the mirrored URL.",
            ),
        ],
        mac_hex: Annotated[
            str,
            typer.Option(
                "--mac",
                help="Observed 8-byte SDM MAC as 16 hex characters.",
            ),
        ],
        sdm_key_hex: Annotated[
            str,
            typer.Option(
                "--sdm-key-hex",
                help="SDM file read key as 32 hex characters.",
            ),
        ],
        ndef_prefix: Annotated[
            NdefUriPrefix,
            typer.Option(
                "--ndef-prefix",
                help="NDEF URI prefix token, for example no_prefix or https.",
            ),
        ] = NdefUriPrefix.NO_PREFIX,
        uid_hex: Annotated[
            str | None,
            typer.Option(
                "--uid",
                help="Optional 7-byte mirrored UID as 14 hex characters.",
            ),
        ] = None,
        counter_hex: Annotated[
            str | None,
            typer.Option(
                "--counter",
                help="Optional 3-byte mirrored read counter as 6 hex characters.",
            ),
        ] = None,
    ) -> None:
        """Verify an NTAG 424 DNA SDM MAC."""
        sdm_key = parse_hex(
            sdm_key_hex,
            option_name="--sdm-key-hex",
            byte_length=NtagByteLength.AES_KEY,
        )
        mac = parse_hex(
            mac_hex,
            option_name="--mac",
            byte_length=NtagByteLength.SDM_MAC,
        )
        uid = (
            None
            if uid_hex is None
            else parse_hex(
                uid_hex,
                option_name="--uid",
                byte_length=NtagByteLength.UID,
            )
        )
        counter = (
            None
            if counter_hex is None
            else parse_hex(
                counter_hex,
                option_name="--counter",
                byte_length=NtagByteLength.SDM_COUNTER,
            )
        )
        try:
            result = VerifyNtag424SdmMacService.call(
                VerifyNtag424SdmMacService.Request(
                    signed_text=signed_text,
                    mac=mac,
                    sdm_key=sdm_key,
                    uid=uid,
                    counter=counter,
                    ndef_prefix=ndef_prefix,
                ),
            )
        except ServiceError as exc:
            exit_for_service_error(exc)

        echo_json(
            {
                "valid": result.valid,
                "calculated_mac": result.calculated_mac.hex(),
                "ndef_prefix": result.ndef_prefix.value,
                "prefix_removed": result.prefix_removed,
            }
        )
