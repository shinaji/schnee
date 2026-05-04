"""APDU preset factories for supported transports and tags."""

from __future__ import annotations

from typing import ClassVar

from .base import Byte, CommandAPDU


class PcscContactlessApduPreset:
    """Factory for common PC/SC contactless reader APDUs."""

    @staticmethod
    def get_uid() -> CommandAPDU:
        """Build a PC/SC GET DATA command for the contactless UID."""
        return CommandAPDU(cla=0xFF, ins=0xCA, p1=0x00, p2=0x00, le=0x00)

    @staticmethod
    def read_binary(*, page: int, length: int) -> CommandAPDU:
        """Build a PC/SC READ BINARY command."""
        return CommandAPDU(cla=0xFF, ins=0xB0, p1=0x00, p2=page, le=length)


class Ntag424ApduPreset:
    """Factory for NTAG 424 DNA native APDUs wrapped for ISO transport."""

    application_df_name: ClassVar[list[Byte]] = [
        0xD2,
        0x76,
        0x00,
        0x00,
        0x85,
        0x01,
        0x01,
    ]
    ndef_file_no: ClassVar[int] = 0x02

    @staticmethod
    def select_application(
        df_name: list[Byte] | None = None,
    ) -> CommandAPDU:
        """Build a SELECT command for the NTAG 424 DNA application DF name."""
        return CommandAPDU(
            cla=0x00,
            ins=0xA4,
            p1=0x04,
            p2=0x00,
            data=df_name or Ntag424ApduPreset.application_df_name,
        )

    @staticmethod
    def authenticate_ev2_first(key_no: int) -> CommandAPDU:
        """Build an NTAG 424 DNA AuthenticateEV2First command."""
        return CommandAPDU(
            cla=0x90,
            ins=0x71,
            p1=0x00,
            p2=0x00,
            data=[key_no, 0x00],
            le=0x00,
        )

    @staticmethod
    def additional_frame(data: list[Byte]) -> CommandAPDU:
        """Build an NTAG 424 DNA AdditionalFrame command."""
        return CommandAPDU(
            cla=0x90,
            ins=0xAF,
            p1=0x00,
            p2=0x00,
            data=data,
            le=0x00,
        )

    @staticmethod
    def change_key(
        *,
        key_no: int,
        encrypted_key_data: list[Byte],
        mac: list[Byte],
    ) -> CommandAPDU:
        """Build an NTAG 424 DNA ChangeKey command."""
        return CommandAPDU(
            cla=0x90,
            ins=0xC4,
            p1=0x00,
            p2=0x00,
            data=[key_no, *encrypted_key_data, *mac],
            le=0x00,
        )

    @staticmethod
    def read_data_file(
        *,
        file_no: int,
        offset: list[Byte],
        length: list[Byte],
    ) -> CommandAPDU:
        """Build an NTAG 424 DNA ReadData command."""
        return CommandAPDU(
            cla=0x90,
            ins=0xAD,
            p1=0x00,
            p2=0x00,
            data=[file_no, *offset, *length],
            le=0x00,
        )

    @staticmethod
    def write_data_file(
        *,
        file_no: int,
        offset: list[Byte],
        data: list[Byte],
    ) -> CommandAPDU:
        """Build an NTAG 424 DNA WriteData command."""
        length = [
            len(data) & 0xFF,
            (len(data) >> 8) & 0xFF,
            (len(data) >> 16) & 0xFF,
        ]
        return CommandAPDU(
            cla=0x90,
            ins=0x8D,
            p1=0x00,
            p2=0x00,
            data=[file_no, *offset, *length, *data],
            le=0x00,
        )

    @staticmethod
    def get_file_settings(file_no: int) -> CommandAPDU:
        """Build an NTAG 424 DNA GetFileSettings command."""
        return CommandAPDU(
            cla=0x90,
            ins=0xF5,
            p1=0x00,
            p2=0x00,
            data=[file_no],
            le=0x00,
        )

    @staticmethod
    def get_key_version(key_no: int) -> CommandAPDU:
        """Build an NTAG 424 DNA GetKeyVersion command."""
        return CommandAPDU(
            cla=0x90,
            ins=0x64,
            p1=0x00,
            p2=0x00,
            data=[key_no],
            le=0x00,
        )
