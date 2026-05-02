"""Tests for NTAG profile change planning."""

from schnee.adapters.ntag.profile.models import (
    LockProfile,
    NdefProfile,
    NdefRecord,
    SdmProfile,
    TagProfile,
)
from schnee.adapters.ntag.profile.planning import plan_profile_changes


def test_plan_profile_changes_detects_ndef_and_sdm_operations() -> None:
    """Planning returns operations, auth needs, and SDM warnings."""
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
        sdm=SdmProfile(
            enabled=True,
            uid_mirror=True,
            counter_mirror=True,
            cmac_mirror=True,
            template_url="https://example.com/tap?uid={uid}",
        ),
    )

    plan = plan_profile_changes(current, requested)

    assert plan.valid is True
    assert [operation.type for operation in plan.operations] == [
        "writeNdef",
        "updateSdmConfig",
    ]
    assert plan.operations[0].before == current.ndef
    assert plan.operations[0].after == requested.ndef
    assert plan.operations[1].before == current.sdm
    assert plan.operations[1].after == requested.sdm
    assert plan.requires_authentication is True
    assert plan.has_dangerous_operations is False
    assert plan.warnings == ["SDM CMAC requires backend verification support."]


def test_plan_profile_changes_blocks_ndef_updates_on_locked_tag() -> None:
    """Planning rejects NDEF writes when permanent locks are present."""
    current = TagProfile(
        ndef=NdefProfile(
            records=[
                NdefRecord(type="url", value="https://example.com"),
            ],
        ),
        locks=LockProfile(permanent=True),
    )
    requested = current.patch(
        ndef=NdefProfile(
            records=[
                NdefRecord(type="url", value="https://example.com/new"),
            ],
        ),
    )

    plan = plan_profile_changes(current, requested)

    assert plan.valid is False
    assert plan.errors == [
        "NDEF cannot be changed after the tag is permanently locked",
    ]


def test_plan_profile_changes_marks_ndef_write_auth_requirement() -> None:
    """NDEF writes require authentication when access policy requires it."""
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
                NdefRecord(type="url", value="https://example.com/next"),
            ],
        ),
    )

    plan = plan_profile_changes(current, requested)

    assert plan.valid is True
    assert plan.operations[0].type == "writeNdef"
    assert plan.operations[0].requires_authentication is True
    assert plan.requires_authentication is True
