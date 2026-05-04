from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from schnee.adapters.ntag.apdu import CommandAPDU, ResponseAPDU
    from schnee.adapters.ntag.profile import ChangePlan, Ntag424DnaProfile, NtagProfile


@runtime_checkable
class ProfileReaderBackend(Protocol):
    """Backend adapter that can communicate with and read an NTAG profile."""

    def send_apdu(
        self,
        apdu: CommandAPDU | list[int],
        *,
        check_status: bool = True,
        ok_statuses: tuple[tuple[int, int], ...] | None = None,
    ) -> ResponseAPDU:
        """Transmit an APDU and optionally raise when the status word is not OK."""

    def read_profile(self) -> NtagProfile:
        """Read the current tag profile."""


@runtime_checkable
class ProfileBackend(ProfileReaderBackend, Protocol):
    """Backend adapter that can read and write an NTAG profile."""

    def apply_plan(self, plan: ChangePlan) -> Ntag424DnaProfile:
        """Apply a profile change plan."""
