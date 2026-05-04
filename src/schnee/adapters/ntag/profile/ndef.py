"""NDEF payload parsing for tag profiles."""

from __future__ import annotations

from typing import ClassVar

from .models import NdefProfile, NdefRecord


class NdefProfileParser:
    """Parse raw NDEF bytes into editable profile data."""

    type2_null_tlv: ClassVar[int] = 0x00
    type2_ndef_tlv: ClassVar[int] = 0x03
    type2_terminator_tlv: ClassVar[int] = 0xFE
    type2_extended_tlv_length: ClassVar[int] = 0xFF

    class NdefParseError(Exception):
        """Raised when NDEF data cannot be represented as a profile."""

    @classmethod
    def parse_type2_memory(cls, memory: list[int]) -> NdefProfile:
        """Parse the NDEF TLV from Type 2 Tag user memory."""
        cursor = 0
        while cursor < len(memory):
            tlv_type = memory[cursor]
            cursor += 1

            if tlv_type == cls.type2_null_tlv:
                continue
            if tlv_type == cls.type2_terminator_tlv:
                break
            if cursor >= len(memory):
                msg = "Truncated Type 2 Tag TLV length"
                raise cls.NdefParseError(msg)

            tlv_length = memory[cursor]
            cursor += 1
            if tlv_length == cls.type2_extended_tlv_length:
                if cursor + 2 > len(memory):
                    msg = "Truncated extended Type 2 Tag TLV length"
                    raise cls.NdefParseError(msg)
                tlv_length = int.from_bytes(bytes(memory[cursor : cursor + 2]), "big")
                cursor += 2

            value_end = cursor + tlv_length
            if value_end > len(memory):
                msg = "Truncated Type 2 Tag TLV value"
                raise cls.NdefParseError(msg)

            if tlv_type == cls.type2_ndef_tlv:
                if tlv_length == 0:
                    return NdefProfile(present=False)
                return NdefProfile(
                    records=cls.parse_message(memory[cursor:value_end]),
                )

            cursor = value_end

        return NdefProfile(present=False)

    @classmethod
    def parse_message(cls, message: list[int]) -> list[NdefRecord]:
        """Parse supported NDEF records from a raw NDEF message."""
        records: list[NdefRecord] = []
        cursor = 0

        while cursor < len(message):
            header = message[cursor]
            cursor += 1

            short_record = bool(header & 0x10)
            id_length_present = bool(header & 0x08)
            tnf = header & 0x07

            if not short_record:
                msg = "Only short NDEF records are supported"
                raise cls.NdefParseError(msg)

            if cursor + 2 > len(message):
                msg = "Truncated NDEF record header"
                raise cls.NdefParseError(msg)

            type_length = message[cursor]
            payload_length = message[cursor + 1]
            cursor += 2

            id_length = 0
            if id_length_present:
                if cursor >= len(message):
                    msg = "Truncated NDEF record ID length"
                    raise cls.NdefParseError(msg)
                id_length = message[cursor]
                cursor += 1

            record_end = cursor + type_length + id_length + payload_length
            if record_end > len(message):
                msg = "Truncated NDEF record payload"
                raise cls.NdefParseError(msg)

            record_type = bytes(message[cursor : cursor + type_length])
            cursor += type_length + id_length
            payload = bytes(message[cursor : cursor + payload_length])
            cursor += payload_length

            record = cls._parse_record(
                tnf=tnf,
                record_type=record_type,
                payload=payload,
            )
            if record is not None:
                records.append(record)

            if header & 0x40:
                break

        return records

    @classmethod
    def _parse_record(
        cls,
        *,
        tnf: int,
        record_type: bytes,
        payload: bytes,
    ) -> NdefRecord | None:
        """Parse a supported NDEF record payload."""
        if tnf != 0x01:
            return None

        if record_type == b"U":
            return NdefRecord(type="url", value=cls._parse_uri_payload(payload))

        if record_type == b"T":
            return NdefRecord(type="text", value=cls._parse_text_payload(payload))

        return None

    @classmethod
    def _parse_uri_payload(cls, payload: bytes) -> str:
        """Parse a well-known URI NDEF payload."""
        if not payload:
            msg = "URI NDEF payload is empty"
            raise cls.NdefParseError(msg)

        prefixes = {
            0x00: "",
            0x01: "http://www.",
            0x02: "https://www.",
            0x03: "http://",
            0x04: "https://",
        }
        prefix = prefixes.get(payload[0])
        if prefix is None:
            msg = f"Unsupported URI identifier code: {payload[0]:#x}"
            raise cls.NdefParseError(msg)
        return f"{prefix}{payload[1:].decode()}"

    @classmethod
    def _parse_text_payload(cls, payload: bytes) -> str:
        """Parse a well-known text NDEF payload."""
        if not payload:
            msg = "Text NDEF payload is empty"
            raise cls.NdefParseError(msg)

        language_code_length = payload[0] & 0x3F
        text_start = 1 + language_code_length
        if text_start > len(payload):
            msg = "Truncated text NDEF payload"
            raise cls.NdefParseError(msg)

        encoding = "utf-16" if payload[0] & 0x80 else "utf-8"
        return payload[text_start:].decode(encoding)
