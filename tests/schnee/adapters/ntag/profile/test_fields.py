"""Tests for editable profile field descriptors."""

from schnee.adapters.ntag.profile.fields import build_editable_fields
from schnee.adapters.ntag.profile.models import (
    NdefProfile,
    NdefRecord,
    Ntag21xProfile,
    Ntag424DnaProfile,
    TagInfo,
)


def test_build_editable_fields_marks_key_field_dangerous() -> None:
    """Editable fields include UI metadata for risky key changes."""
    profile = Ntag424DnaProfile(
        tag=TagInfo(type="NTAG424DNA", uid="04112233445566"),
        ndef=NdefProfile(
            records=[
                NdefRecord(type="url", value="https://example.com"),
            ],
        ),
    )

    fields = build_editable_fields(profile)

    assert fields[0].path == "ndef.records[0].value"
    assert fields[0].value == "https://example.com"
    assert fields[0].kind == "url"
    assert fields[0].requires_auth is True
    assert fields[-1].path == "security.default_keys"
    assert fields[-1].dangerous is True
    assert fields[-1].requires_auth is True


def test_build_editable_fields_for_ntag21x_omits_sdm_and_key_fields() -> None:
    """NTAG21x editable fields expose only profile sections the tag supports."""
    profile = Ntag21xProfile(
        tag=TagInfo(type="NTAG215", uid="04112233445566"),
        capacity_bytes=496,
        ndef=NdefProfile(
            records=[
                NdefRecord(type="url", value="https://example.com"),
            ],
        ),
    )

    fields = build_editable_fields(profile)

    assert [field.path for field in fields] == ["ndef.records[0].value"]
    assert fields[0].value == "https://example.com"
    assert fields[0].requires_auth is False
