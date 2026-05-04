"""Tests for NTAG profile change planning."""

from schnee.adapters.ntag.profile.models import (
    AccessProfile,
    LockProfile,
    NdefProfile,
    NdefRecord,
    Ntag424DnaProfile,
    SdmProfile,
    SecurityProfile,
    TagInfo,
)
from schnee.adapters.ntag.profile.planning import plan_profile_changes


def make_ntag424_profile(
    *,
    ndef: NdefProfile | None = None,
    sdm: SdmProfile | None = None,
    access: AccessProfile | None = None,
    security: SecurityProfile | None = None,
    locks: LockProfile | None = None,
) -> Ntag424DnaProfile:
    """Build an NTAG 424 DNA profile with explicit tag metadata."""
    return Ntag424DnaProfile(
        tag=TagInfo(type="NTAG424DNA", uid="04112233445566"),
        ndef=ndef or NdefProfile(),
        sdm=sdm or SdmProfile(),
        access=access or AccessProfile(),
        security=security or SecurityProfile(),
        locks=locks or LockProfile(),
    )


def test_plan_profile_changes_detects_ndef_and_sdm_operations() -> None:
    """Planning returns operations, auth needs, and SDM warnings."""
    current = make_ntag424_profile(
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
    current = make_ntag424_profile(
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
    assert plan.operations == []


def test_plan_profile_changes_marks_ndef_write_auth_requirement() -> None:
    """NDEF writes require authentication when access policy requires it."""
    current = make_ntag424_profile(
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


def test_plan_profile_changes_detects_access_updates() -> None:
    """Access updates are dangerous authenticated operations."""
    current = make_ntag424_profile()
    requested = current.patch(
        access=AccessProfile(ndef_write="free"),
    )

    plan = plan_profile_changes(current, requested)

    assert plan.valid is True
    assert [operation.type for operation in plan.operations] == ["updateAccess"]
    assert plan.operations[0].risk == "dangerous"
    assert plan.operations[0].requires_authentication is True
    assert plan.has_dangerous_operations is True


def test_plan_profile_changes_detects_key_rotation() -> None:
    """Key rotation is planned as dangerous and warns callers."""
    current = make_ntag424_profile()
    requested = current.patch(
        security=SecurityProfile(default_keys=False),
    )

    plan = plan_profile_changes(current, requested)

    assert plan.valid is True
    assert [operation.type for operation in plan.operations] == ["rotateKey"]
    assert plan.operations[0].risk == "dangerous"
    assert plan.operations[0].requires_authentication is True
    assert plan.has_dangerous_operations is True
    assert plan.warnings == [
        "Key rotation can make the tag inaccessible if keys are lost.",
    ]


def test_plan_profile_changes_rejects_tag_type_changes() -> None:
    """Tag type changes are rejected."""
    current = make_ntag424_profile()
    requested = current.patch(
        tag=TagInfo.model_construct(type="MIFARE"),
    )

    plan = plan_profile_changes(current, requested)

    assert plan.valid is False
    assert plan.errors == ["tag type cannot be changed"]
