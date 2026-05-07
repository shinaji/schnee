"""Tests for shared NDEF models."""

import pytest

from schnee.ndef import NdefUriPrefix

URN_NFC_PREFIX_CODE = 0x23


def test_ndef_uri_prefix_covers_complete_identifier_code_range() -> None:
    """NDEF URI prefixes expose every defined identifier code."""
    codes = [prefix.code for prefix in NdefUriPrefix]

    assert codes == list(range(0x24)), (
        "NDEF URI prefixes should cover every identifier code from 0x00 to 0x23"
    )


def test_ndef_uri_prefix_exposes_code_and_expanded_text() -> None:
    """NDEF URI prefix members expose numeric and expanded forms."""
    prefix = NdefUriPrefix.URN_NFC

    assert prefix.code == URN_NFC_PREFIX_CODE, (
        "URN_NFC should expose its numeric identifier code"
    )
    assert prefix.expanded_text == "urn:nfc:", (
        "URN_NFC should expose its expanded URI prefix text"
    )


def test_ndef_uri_prefix_from_code_rejects_unsupported_code() -> None:
    """NDEF URI prefix lookup rejects undefined identifier codes."""
    with pytest.raises(ValueError, match="Unsupported URI identifier code: 0x24"):
        NdefUriPrefix.from_code(0x24)
