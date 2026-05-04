"""Tests for APDU preset factories."""

from schnee.adapters.ntag.apdu import Ntag424ApduPreset, PcscContactlessApduPreset


def test_pcsc_contactless_apdu_presets_serialize_commands() -> None:
    """PC/SC contactless presets serialize common reader commands."""
    assert PcscContactlessApduPreset.get_uid().to_list() == [
        0xFF,
        0xCA,
        0x00,
        0x00,
        0x00,
    ]
    assert PcscContactlessApduPreset.read_binary(page=0x03, length=0x04).to_list() == [
        0xFF,
        0xB0,
        0x00,
        0x03,
        0x04,
    ]


def test_ntag424_apdu_presets_serialize_commands() -> None:
    """NTAG 424 presets serialize native commands for ISO transport."""
    assert Ntag424ApduPreset.get_file_settings(0x02).to_list() == [
        0x90,
        0xF5,
        0x00,
        0x00,
        0x01,
        0x02,
        0x00,
    ]
    assert Ntag424ApduPreset.get_key_version(0x01).to_list() == [
        0x90,
        0x64,
        0x00,
        0x00,
        0x01,
        0x01,
        0x00,
    ]
    assert Ntag424ApduPreset.read_data_file(
        file_no=0x02,
        offset=[0x00, 0x00, 0x00],
        length=[0x02, 0x00, 0x00],
    ).to_list() == [
        0x90,
        0xAD,
        0x00,
        0x00,
        0x07,
        0x02,
        0x00,
        0x00,
        0x00,
        0x02,
        0x00,
        0x00,
        0x00,
    ]
