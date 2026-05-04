from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from schnee.adapters.ntag.profile import ChangePlan, Ntag424DnaProfile, NtagProfile


@runtime_checkable
class ProfileReaderBackend(Protocol):
    """Backend adapter that can read an NTAG profile."""

    def read_profile(self) -> NtagProfile:
        """Read the current tag profile."""


@runtime_checkable
class ProfileBackend(ProfileReaderBackend, Protocol):
    """Backend adapter that can read and write an NTAG profile."""

    def apply_plan(self, plan: ChangePlan) -> Ntag424DnaProfile:
        """Apply a profile change plan."""
