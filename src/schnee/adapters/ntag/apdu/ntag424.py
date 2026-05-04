"""NTAG 424 DNA APDU response models."""

from __future__ import annotations

from typing import ClassVar

from pydantic import BaseModel, Field

from .base import BYTE_MAX


class Ntag424FileSettings(BaseModel):
    """Parsed NTAG 424 DNA GetFileSettings response for a standard data file."""

    standard_data_file_type: ClassVar[int] = 0x00
    min_length: ClassVar[int] = 7
    sdm_settings_min_length: ClassVar[int] = 10
    sdm_enabled_mask: ClassVar[int] = 0x40
    sdm_uid_mirror_mask: ClassVar[int] = 0x80
    sdm_counter_mirror_mask: ClassVar[int] = 0x40
    sdm_counter_limit_mask: ClassVar[int] = 0x20
    sdm_enc_file_data_mask: ClassVar[int] = 0x10
    access_key_min: ClassVar[int] = 0x00
    access_key_max: ClassVar[int] = 0x04
    access_free: ClassVar[int] = 0x0E
    access_none: ClassVar[int] = 0x0F

    file_type: int = Field(ge=0, le=BYTE_MAX, description="NTAG file type")
    file_option: int = Field(ge=0, le=BYTE_MAX, description="NTAG file option byte")
    read_write_access: int = Field(
        ge=0,
        le=BYTE_MAX,
        description="ReadWrite access nibble",
    )
    change_access: int = Field(ge=0, le=BYTE_MAX, description="Change access nibble")
    read_access: int = Field(ge=0, le=BYTE_MAX, description="Read access nibble")
    write_access: int = Field(ge=0, le=BYTE_MAX, description="Write access nibble")
    file_size: int = Field(ge=0, description="File size in bytes")
    sdm_options: int | None = Field(
        default=None,
        ge=0,
        le=BYTE_MAX,
        description="SDM options byte when SDM is enabled",
    )
    sdm_access_rights: tuple[int, int] | None = Field(
        default=None,
        description="SDM access-right bytes when SDM is enabled",
    )
    uid_offset: int | None = Field(default=None, ge=0)
    read_counter_offset: int | None = Field(default=None, ge=0)
    picc_data_offset: int | None = Field(default=None, ge=0)
    mac_input_offset: int | None = Field(default=None, ge=0)
    enc_offset: int | None = Field(default=None, ge=0)
    enc_length: int | None = Field(default=None, ge=0)
    mac_offset: int | None = Field(default=None, ge=0)
    read_counter_limit: int | None = Field(default=None, ge=0)

    class Ntag424FileSettingsError(Exception):
        """Raised when NTAG 424 file settings cannot be parsed."""

    class TruncatedFileSettingsError(Ntag424FileSettingsError):
        """Raised when a GetFileSettings response is truncated."""

    class UnsupportedFileTypeError(Ntag424FileSettingsError):
        """Raised when the file type is not supported by this parser."""

    class UnsupportedTrailingDataError(Ntag424FileSettingsError):
        """Raised when unsupported trailing data remains after parsing."""

    @classmethod
    def from_response(cls, data: list[int]) -> Ntag424FileSettings:
        """Parse a GetFileSettings response for an NTAG 424 standard data file."""
        if len(data) < cls.min_length:
            msg = "NTAG 424 DNA file settings response is truncated"
            raise cls.TruncatedFileSettingsError(msg)
        if data[0] != cls.standard_data_file_type:
            msg = f"Unsupported NTAG 424 DNA file type: {data[0]:#x}"
            raise cls.UnsupportedFileTypeError(msg)

        access_0 = data[2]
        access_1 = data[3]
        values: dict[str, object] = {
            "file_type": data[0],
            "file_option": data[1],
            "read_write_access": access_0 >> 4,
            "change_access": access_0 & 0x0F,
            "read_access": access_1 >> 4,
            "write_access": access_1 & 0x0F,
            "file_size": int.from_bytes(bytes(data[4:7]), byteorder="little"),
        }
        if not (data[1] & cls.sdm_enabled_mask):
            return cls.model_validate(values)

        values.update(cls._parse_sdm_settings(data))
        return cls.model_validate(values)

    @classmethod
    def _parse_sdm_settings(cls, data: list[int]) -> dict[str, object]:
        """Parse SDM-specific GetFileSettings response bytes."""
        if len(data) < cls.sdm_settings_min_length:
            msg = "NTAG 424 DNA SDM file settings response is truncated"
            raise cls.TruncatedFileSettingsError(msg)

        sdm_options = data[7]
        sdm_access_rights = (data[8], data[9])
        sdm_meta_read = sdm_access_rights[1] >> 4
        sdm_file_read = sdm_access_rights[1] & 0x0F

        values: dict[str, object] = {
            "sdm_options": sdm_options,
            "sdm_access_rights": sdm_access_rights,
        }
        cursor = cls.sdm_settings_min_length

        if sdm_options & cls.sdm_uid_mirror_mask and sdm_meta_read == cls.access_free:
            values["uid_offset"], cursor = cls._read_le3(data, cursor)
        if (
            sdm_options & cls.sdm_counter_mirror_mask
            and sdm_meta_read == cls.access_free
        ):
            values["read_counter_offset"], cursor = cls._read_le3(data, cursor)
        if cls.access_key_min <= sdm_meta_read <= cls.access_key_max:
            values["picc_data_offset"], cursor = cls._read_le3(data, cursor)

        if sdm_file_read != cls.access_none:
            values["mac_input_offset"], cursor = cls._read_le3(data, cursor)
            if sdm_options & cls.sdm_enc_file_data_mask:
                values["enc_offset"], cursor = cls._read_le3(data, cursor)
                values["enc_length"], cursor = cls._read_le3(data, cursor)
            values["mac_offset"], cursor = cls._read_le3(data, cursor)

        if sdm_options & cls.sdm_counter_limit_mask:
            values["read_counter_limit"], cursor = cls._read_le3(data, cursor)

        if cursor != len(data):
            msg = "NTAG 424 DNA SDM file settings contain unsupported trailing data"
            raise cls.UnsupportedTrailingDataError(msg)

        return values

    @classmethod
    def _read_le3(cls, data: list[int], cursor: int) -> tuple[int, int]:
        """Read a three-byte little-endian integer."""
        next_cursor = cursor + 3
        if next_cursor > len(data):
            msg = "NTAG 424 DNA file settings response is truncated"
            raise cls.TruncatedFileSettingsError(msg)
        value = int.from_bytes(bytes(data[cursor:next_cursor]), byteorder="little")
        return value, next_cursor

    @property
    def sdm_enabled(self) -> bool:
        """Return whether Secure Dynamic Messaging is enabled."""
        return bool(self.file_option & self.sdm_enabled_mask)

    @property
    def sdm_uid_mirror(self) -> bool:
        """Return whether UID mirroring is enabled."""
        return bool((self.sdm_options or 0) & self.sdm_uid_mirror_mask)

    @property
    def sdm_counter_mirror(self) -> bool:
        """Return whether SDM read-counter mirroring is enabled."""
        return bool((self.sdm_options or 0) & self.sdm_counter_mirror_mask)

    @property
    def sdm_file_read_access(self) -> int | None:
        """Return the SDMFileRead access nibble."""
        if self.sdm_access_rights is None:
            return None
        return self.sdm_access_rights[1] & 0x0F

    @property
    def sdm_cmac_mirror(self) -> bool:
        """Return whether SDM CMAC mirroring is enabled."""
        return self.sdm_file_read_access not in (None, self.access_none)
