"""High-level NTAG profile editor orchestration."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from .fields import EditableField, build_editable_fields

if TYPE_CHECKING:
    from .models import TagProfile
    from .planning import ChangePlan


class TagProfileBackend(Protocol):
    """Backend contract used by the profile editor."""

    def read_profile(self) -> TagProfile:
        """Read the current tag profile."""

    def apply_plan(self, plan: ChangePlan) -> TagProfile:
        """Apply a previously generated change plan."""


class TagProfileEditor:
    """Read, edit, plan, and apply NTAG profile changes."""

    class TagProfileEditorError(Exception):
        """Exception raised when there is a problem with the tag profile editor."""

    class InvalidChangePlanError(TagProfileEditorError):
        """Exception raised when an invalid change plan is applied."""

    def __init__(self, backend: TagProfileBackend) -> None:
        self.backend = backend

    def read_profile(self) -> TagProfile:
        """Read the current tag profile."""
        return self.backend.read_profile()

    def get_editable_fields(
        self,
        profile: TagProfile | None = None,
    ) -> list[EditableField]:
        """Return field descriptors suitable for generating UI or CLI forms."""
        current = profile or self.read_profile()
        return build_editable_fields(current)

    def plan_changes(self, next_profile: TagProfile) -> ChangePlan:
        """Compare the current tag with the requested profile."""
        return self.read_profile().plan_changes(next_profile)

    def apply(self, plan: ChangePlan) -> TagProfile:
        """Apply a valid change plan with the configured backend."""
        if not plan.valid:
            errors = ", ".join(plan.errors) or "invalid change plan"
            raise self.InvalidChangePlanError(errors)
        return self.backend.apply_plan(plan)
