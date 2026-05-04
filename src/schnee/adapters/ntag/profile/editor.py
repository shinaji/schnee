"""High-level NTAG profile editor orchestration."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from .fields import EditableField, build_editable_fields
from .models import Ntag424DnaProfile

if TYPE_CHECKING:
    from .models import NtagProfile
    from .planning import ChangePlan


class TagProfileBackend(Protocol):
    """Backend contract used by the profile editor."""

    def read_profile(self) -> NtagProfile:
        """Read the current tag profile."""

    def apply_plan(self, plan: ChangePlan) -> Ntag424DnaProfile:
        """Apply a previously generated change plan."""


class TagProfileEditor:
    """Read, edit, plan, and apply NTAG profile changes."""

    class TagProfileEditorError(Exception):
        """Exception raised when there is a problem with the tag profile editor."""

    class InvalidChangePlanError(TagProfileEditorError):
        """Exception raised when an invalid change plan is applied."""

    class UnsupportedProfilePlanError(TagProfileEditorError):
        """Exception raised when a tag family does not support change planning."""

    def __init__(self, backend: TagProfileBackend) -> None:
        self.backend = backend

    def read_profile(self) -> NtagProfile:
        """Read the current tag profile."""
        return self.backend.read_profile()

    def get_editable_fields(
        self,
        profile: NtagProfile | None = None,
    ) -> list[EditableField]:
        """Return field descriptors suitable for generating UI or CLI forms."""
        current = profile or self.read_profile()
        return build_editable_fields(current)

    def plan_changes(self, next_profile: Ntag424DnaProfile) -> ChangePlan:
        """Compare the current tag with the requested profile."""
        current = self.read_profile()
        if not isinstance(current, Ntag424DnaProfile):
            msg = f"{current.tag.type} change planning is not supported"
            raise self.UnsupportedProfilePlanError(msg)
        return current.plan_changes(next_profile)

    def apply(self, plan: ChangePlan) -> Ntag424DnaProfile:
        """Apply a valid change plan with the configured backend."""
        if not plan.valid:
            errors = ", ".join(plan.errors) or "invalid change plan"
            raise self.InvalidChangePlanError(errors)
        return self.backend.apply_plan(plan)
