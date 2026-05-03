from __future__ import annotations

from typing import TYPE_CHECKING

from .pcsc import PcscBackend

if TYPE_CHECKING:
    from .contracts import ProfileBackend


class Backend:
    """Backend adapter selector."""

    class BackendError(Exception):
        """Backend error."""

    class BackendNotFoundError(BackendError):
        """Backend not found."""

    @classmethod
    def backend_names(cls) -> list[str]:
        """Get all backend names."""
        _ = cls
        names = ["pcsc"]
        names.extend(f"pcsc:{name}" for name in PcscBackend.pcsc_backend_names())
        return sorted(names)

    @classmethod
    def get(cls, name: str) -> ProfileBackend:
        """Get a backend adapter by name."""
        _ = cls
        if name == "pcsc":
            return PcscBackend.create_pcsc_backend()
        if name.startswith("pcsc:"):
            return PcscBackend.create_pcsc_backend(name.removeprefix("pcsc:"))
        raise cls.BackendNotFoundError
