from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from schnee.adapters.ntag.profile import ChangePlan, TagProfile


@runtime_checkable
class ProfileReaderBackend(Protocol):
    """Backend adapter that can read an NTAG profile."""

    def read_profile(self) -> TagProfile:
        """Read the current tag profile."""


@runtime_checkable
class ProfileBackend(ProfileReaderBackend, Protocol):
    """Backend adapter that can read and write an NTAG profile."""

    def apply_plan(self, plan: ChangePlan) -> TagProfile:
        """Apply a profile change plan."""
