"""Tests for NTAG cryptographic helpers."""

from Crypto.Cipher import AES
from Crypto.Hash import CMAC

from schnee.adapters.ntag.crypt import SDM_SV2_PREFIX, calculate_sdm_mac

TRUNCATED_SDM_MAC_LENGTH = 8


def test_calculate_sdm_mac_with_uid_and_counter() -> None:
    """SDM MAC includes the UID and counter in SV2 when both are present."""
    assert (
        calculate_sdm_mac(
            sdm_key=bytes.fromhex("00112233445566778899AABBCCDDEEFF"),
            signed_data=bytes.fromhex("DEADBEEF00"),
            uid=bytes.fromhex("04782E21801D80"),
            counter=bytes.fromhex("010203"),
        ).hex()
        == "7db100f509613111"
    )


def test_calculate_sdm_mac_with_uid_only() -> None:
    """SDM MAC includes only the UID when no counter is provided."""
    assert (
        calculate_sdm_mac(
            sdm_key=bytes.fromhex("00112233445566778899AABBCCDDEEFF"),
            signed_data=bytes.fromhex("DEADBEEF00"),
            uid=bytes.fromhex("04782E21801D80"),
        ).hex()
        == "a8e8cc437f54250a"
    )


def test_calculate_sdm_mac_without_uid_or_counter() -> None:
    """SDM MAC can be derived from the fixed SV2 prefix alone."""
    assert (
        calculate_sdm_mac(
            sdm_key=bytes.fromhex("00112233445566778899AABBCCDDEEFF"),
            signed_data=bytes.fromhex("DEADBEEF00"),
        ).hex()
        == "8330e2018ec638ce"
    )


def test_calculate_sdm_mac_truncates_to_odd_indexed_bytes() -> None:
    """SDM MAC returns the 8-byte [1::2] truncation of the full CMAC."""
    sdm_key = bytes.fromhex("00112233445566778899AABBCCDDEEFF")
    signed_data = bytes.fromhex("DEADBEEF00")
    uid = bytes.fromhex("04782E21801D80")
    counter = bytes.fromhex("010203")

    session_key_cmac = CMAC.new(key=sdm_key, ciphermod=AES)
    session_key_cmac.update(SDM_SV2_PREFIX + uid + counter)
    session_mac_key = session_key_cmac.digest()

    full_mac_cmac = CMAC.new(key=session_mac_key, ciphermod=AES)
    full_mac_cmac.update(signed_data)
    full_mac = full_mac_cmac.digest()

    assert (
        calculate_sdm_mac(
            sdm_key=sdm_key,
            signed_data=signed_data,
            uid=uid,
            counter=counter,
        )
        == full_mac[1::2]
    )
    assert len(full_mac[1::2]) == TRUNCATED_SDM_MAC_LENGTH
