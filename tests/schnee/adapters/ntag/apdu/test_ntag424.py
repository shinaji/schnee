"""Tests for NTAG 424 DNA APDU response models."""

import pytest

from schnee.adapters.ntag.apdu import Ntag424FileSettings

NTAG424_TEST_FILE_SIZE = 0x100
NTAG424_TEST_UID_OFFSET = 0x20
NTAG424_TEST_COUNTER_OFFSET = 0x35
NTAG424_TEST_MAC_INPUT_OFFSET = 0x07
NTAG424_TEST_MAC_OFFSET = 0x43


def test_ntag424_file_settings_parses_plain_sdm_response() -> None:
    """NTAG 424 file settings parses plain SDM mirror offsets."""
    settings = Ntag424FileSettings.from_response(
        [
            0x00,
            0x40,
            0x00,
            0xE0,
            0x00,
            0x01,
            0x00,
            0xC1,
            0xF1,
            0xE1,
            0x20,
            0x00,
            0x00,
            0x35,
            0x00,
            0x00,
            0x07,
            0x00,
            0x00,
            0x43,
            0x00,
            0x00,
        ],
    )

    assert settings.file_size == NTAG424_TEST_FILE_SIZE
    assert settings.sdm_enabled is True
    assert settings.sdm_uid_mirror is True
    assert settings.sdm_counter_mirror is True
    assert settings.sdm_cmac_mirror is True
    assert settings.uid_offset == NTAG424_TEST_UID_OFFSET
    assert settings.read_counter_offset == NTAG424_TEST_COUNTER_OFFSET
    assert settings.mac_input_offset == NTAG424_TEST_MAC_INPUT_OFFSET
    assert settings.mac_offset == NTAG424_TEST_MAC_OFFSET


def test_ntag424_file_settings_parses_encrypted_picc_data_sdm_response() -> None:
    """NTAG 424 file settings parses encrypted PICCData SDM offsets."""
    settings = Ntag424FileSettings.from_response(
        [
            0x00,
            0x40,
            0x00,
            0xE0,
            0x00,
            0x01,
            0x00,
            0xC1,
            0xF1,
            0x21,
            0x20,
            0x00,
            0x00,
            0x43,
            0x00,
            0x00,
            0x43,
            0x00,
            0x00,
        ],
    )

    assert settings.uid_offset is None
    assert settings.read_counter_offset is None
    assert settings.picc_data_offset == NTAG424_TEST_UID_OFFSET
    assert settings.mac_input_offset == NTAG424_TEST_MAC_OFFSET
    assert settings.mac_offset == NTAG424_TEST_MAC_OFFSET


def test_ntag424_file_settings_rejects_truncated_response() -> None:
    """NTAG 424 file settings rejects truncated response bytes."""
    with pytest.raises(Ntag424FileSettings.TruncatedFileSettingsError):
        Ntag424FileSettings.from_response([0x00, 0x40])
