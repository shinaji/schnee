"""Tests for NTAG profile models."""

import pytest

from schnee.adapters.ntag.profile.models import (
    NdefProfile,
    NdefRecord,
    SdmProfile,
    TagProfile,
)


def test_tag_profile_patch_updates_typed_profile_sections() -> None:
    """Profile patch applies typed section replacements."""
    profile = TagProfile(
        ndef=NdefProfile(
            records=[
                NdefRecord(type="url", value="https://example.com"),
            ],
        ),
        sdm=SdmProfile(enabled=False, template_url="https://example.com/tap"),
    )

    updated = profile.patch(
        sdm=SdmProfile(
            enabled=True,
            uid_mirror=True,
            template_url=profile.sdm.template_url,
        ),
    )

    assert updated.sdm.enabled is True
    assert updated.sdm.uid_mirror is True
    assert updated.sdm.template_url == "https://example.com/tap"
    assert updated.ndef.records[0].value == "https://example.com"


def test_sdm_enabled_requires_at_least_one_mirror() -> None:
    """Enabled SDM requires at least one mirrored value."""
    with pytest.raises(SdmProfile.SdmMirrorRequiredError, match="enabled SDM"):
        SdmProfile(enabled=True)


def test_tag_profile_plan_changes_delegates_to_planning() -> None:
    """TagProfile can plan changes from itself to another profile."""
    current = TagProfile(
        ndef=NdefProfile(
            records=[
                NdefRecord(type="url", value="https://example.com"),
            ],
        ),
    )
    requested = current.patch(
        ndef=NdefProfile(
            records=[
                NdefRecord(type="url", value="https://example.com/tap"),
            ],
        ),
    )

    plan = current.plan_changes(requested)

    assert plan.valid is True
    assert [operation.type for operation in plan.operations] == ["writeNdef"]
    assert plan.operations[0].before == current.ndef
    assert plan.operations[0].after == requested.ndef
