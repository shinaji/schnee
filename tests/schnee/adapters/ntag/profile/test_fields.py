"""Tests for editable profile field descriptors."""

from schnee.adapters.ntag.profile.fields import build_editable_fields
from schnee.adapters.ntag.profile.models import NdefProfile, NdefRecord, TagProfile


def test_build_editable_fields_marks_key_field_dangerous() -> None:
    """Editable fields include UI metadata for risky key changes."""
    profile = TagProfile(
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
    assert fields[-1].path == "security.keys"
    assert fields[-1].dangerous is True
    assert fields[-1].requires_auth is True
