"""Tests for NDEF profile parsing."""

import pytest

from schnee.adapters.ntag.profile.ndef import NdefProfileParser


def _uri_record(prefix_code: int, suffix: bytes) -> list[int]:
    payload = [prefix_code, *suffix]
    return [
        0xD1,
        0x01,
        len(payload),
        0x55,
        *payload,
    ]


@pytest.mark.parametrize(
    ("prefix_code", "suffix", "expected"),
    [
        (0x04, b"example.com", "https://example.com"),
        (0x05, b"+81312345678", "tel:+81312345678"),
        (0x1D, b"/tmp/tag.txt", "file:///tmp/tag.txt"),
        (0x23, b"sn:example", "urn:nfc:sn:example"),
    ],
)
def test_parse_uri_record_uses_shared_prefix_table(
    prefix_code: int,
    suffix: bytes,
    expected: str,
) -> None:
    """URI records expand NDEF URI Identifier Code prefixes."""
    records = NdefProfileParser.parse_message(_uri_record(prefix_code, suffix))

    assert len(records) == 1, "URI NDEF message should produce one profile record"
    assert records[0].type == "url", "URI NDEF record should be represented as a URL"
    assert records[0].value == expected, (
        "URI NDEF record should expand the identifier code prefix"
    )


def test_parse_uri_record_rejects_unsupported_prefix_code() -> None:
    """URI records reject undefined NDEF URI Identifier Code prefixes."""
    with pytest.raises(
        NdefProfileParser.NdefParseError,
        match="Unsupported URI identifier code: 0x24",
    ):
        NdefProfileParser.parse_message(_uri_record(0x24, b"example.com"))
