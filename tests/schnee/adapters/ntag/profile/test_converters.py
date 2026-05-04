"""Tests for profile converters."""

import pytest

from schnee.adapters.ntag.apdu import Ntag424FileSettings
from schnee.adapters.ntag.profile.converters import Ntag424ProfileSections

NTAG424_TEST_KEY_SLOTS = 5


def test_ntag424_profile_sections_from_file_settings_and_key_versions() -> None:
    """NTAG 424 profile sections derive from parsed configuration data."""
    file_settings = Ntag424FileSettings.from_response(
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

    sections = Ntag424ProfileSections.from_parsed_data(
        file_settings=file_settings,
        key_versions=[0x00, 0x00, 0x00, 0x00, 0x00],
    )

    assert sections.sdm.enabled is True
    assert sections.sdm.uid_mirror is True
    assert sections.sdm.counter_mirror is True
    assert sections.sdm.cmac_mirror is True
    assert sections.access.ndef_read == "free"
    assert sections.access.ndef_write == "authenticated"
    assert sections.security.default_keys is True
    assert sections.security.key_slots == NTAG424_TEST_KEY_SLOTS
    assert sections.locks.permanent is False


def test_ntag424_profile_sections_rejects_unrepresentable_no_access() -> None:
    """Profile conversion rejects access states outside the profile model."""
    file_settings = Ntag424FileSettings.from_response(
        [
            0x00,
            0x00,
            0xFF,
            0xFF,
            0x00,
            0x01,
            0x00,
        ],
    )

    with pytest.raises(
        Ntag424ProfileSections.UnsupportedAccessPolicyError,
        match="no-access policy",
    ):
        Ntag424ProfileSections.from_parsed_data(
            file_settings=file_settings,
            key_versions=[0x00],
        )
