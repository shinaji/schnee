"""Tests for NTAG profile editor orchestration."""

import pytest

from schnee.adapters.ntag.profile.editor import TagProfileEditor
from schnee.adapters.ntag.profile.models import (
    NdefProfile,
    NdefRecord,
    SdmProfile,
    TagProfile,
)
from schnee.adapters.ntag.profile.planning import ChangePlan


class MemoryProfileBackend:
    """In-memory profile backend used by editor tests."""

    def __init__(self, profile: TagProfile) -> None:
        self.profile = profile
        self.applied_plan: ChangePlan | None = None

    def read_profile(self) -> TagProfile:
        """Read the current memory profile."""
        return self.profile

    def apply_plan(self, plan: ChangePlan) -> TagProfile:
        """Apply a plan by returning the requested operation snapshots."""
        self.applied_plan = plan
        for operation in plan.operations:
            if operation.path == "ndef" and isinstance(operation.after, NdefProfile):
                self.profile = self.profile.patch(
                    ndef=operation.after,
                )
            if operation.path == "sdm" and isinstance(operation.after, SdmProfile):
                self.profile = self.profile.patch(
                    sdm=operation.after,
                )
        return self.profile


def test_tag_profile_editor_reads_plans_and_applies() -> None:
    """Editor coordinates backend read, plan, and apply."""
    profile = TagProfile(
        ndef=NdefProfile(
            records=[
                NdefRecord(type="url", value="https://example.com"),
            ],
        ),
    )
    backend = MemoryProfileBackend(profile)
    editor = TagProfileEditor(backend)
    requested = profile.patch(
        ndef=NdefProfile(
            records=[
                NdefRecord(type="url", value="https://example.com/next"),
            ],
        ),
    )

    plan = editor.plan_changes(requested)
    applied = editor.apply(plan)

    assert backend.applied_plan == plan
    assert applied.ndef.records == [
        NdefRecord(type="url", value="https://example.com/next"),
    ]


def test_tag_profile_editor_rejects_invalid_plan() -> None:
    """Editor refuses to apply invalid plans."""
    editor = TagProfileEditor(MemoryProfileBackend(TagProfile()))

    with pytest.raises(TagProfileEditor.InvalidChangePlanError, match="broken"):
        editor.apply(ChangePlan(valid=False, errors=["broken"]))
