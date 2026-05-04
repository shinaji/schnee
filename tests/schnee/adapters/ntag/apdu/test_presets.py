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
    assert Ntag424ApduPreset.select_application().to_list() == [
        0x00,
        0xA4,
        0x04,
        0x00,
        0x07,
        0xD2,
        0x76,
        0x00,
        0x00,
        0x85,
        0x01,
        0x01,
    ]
    assert Ntag424ApduPreset.authenticate_ev2_first(0x00).to_list() == [
        0x90,
        0x71,
        0x00,
        0x00,
        0x02,
        0x00,
        0x00,
        0x00,
    ]
    assert Ntag424ApduPreset.additional_frame([0x01, 0x02]).to_list() == [
        0x90,
        0xAF,
        0x00,
        0x00,
        0x02,
        0x01,
        0x02,
        0x00,
    ]
    assert Ntag424ApduPreset.change_key(
        key_no=0x02,
        encrypted_key_data=[0xAA, 0xBB],
        mac=[0xCC, 0xDD],
    ).to_list() == [
        0x90,
        0xC4,
        0x00,
        0x00,
        0x05,
        0x02,
        0xAA,
        0xBB,
        0xCC,
        0xDD,
        0x00,
    ]
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
    assert Ntag424ApduPreset.write_data_file(
        file_no=0x02,
        offset=[0x00, 0x00, 0x00],
        data=[0x00, 0x03, 0xD1],
    ).to_list() == [
        0x90,
        0x8D,
        0x00,
        0x00,
        0x0A,
        0x02,
        0x00,
        0x00,
        0x00,
        0x03,
        0x00,
        0x00,
        0x00,
        0x03,
        0xD1,
        0x00,
    ]
