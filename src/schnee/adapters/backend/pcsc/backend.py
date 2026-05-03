from __future__ import annotations

from typing import TYPE_CHECKING

from schnee.adapters.ntag.profile import ChangePlan, TagInfo, TagProfile

from .client import PcscApduClient
from .reader import PcscConnection, PcscReader, PcscReaderProvider

if TYPE_CHECKING:
    from schnee.adapters.ntag.apdu import CommandAPDU, ResponseAPDU


class PcscBackend:
    """Backend adapter that wraps a PC/SC reader."""

    class PcscBackendError(Exception):
        """PC/SC backend error."""

    class UnsupportedPlanError(PcscBackendError):
        """Raised when a write plan is not implemented by the PC/SC backend."""

    class UnsupportedProfileReadError(PcscBackendError):
        """Raised when full profile reads are not implemented."""

    def __init__(self, reader: PcscReader) -> None:
        self.reader = reader
        self.client = PcscApduClient(reader)

    @property
    def reader_name(self) -> str:
        """Return the wrapped PC/SC reader name."""
        return self.client.reader_name

    def connect(self) -> PcscConnection:
        """Connect to the wrapped PC/SC reader."""
        return self.client.connect()

    def send_apdu(self, apdu: CommandAPDU | list[int]) -> ResponseAPDU:
        """Transmit an APDU through the wrapped PC/SC reader."""
        return self.client.send_apdu(apdu)

    def read_profile(self) -> TagProfile:
        """Read the currently reachable NTAG profile."""
        msg = "PC/SC full profile reads are not implemented yet"
        raise self.UnsupportedProfileReadError(msg)

    def read_tag_info(self) -> TagInfo:
        """Read the currently reachable NTAG tag identity summary."""
        uid = self._read_uid()
        return TagInfo(
            uid=uid,
            features=["pcsc"],
        )

    def apply_plan(self, plan: ChangePlan) -> TagProfile:
        """Apply a profile change plan through PC/SC."""
        _ = plan
        msg = "PC/SC profile writes are not implemented yet"
        raise self.UnsupportedPlanError(msg)

    def _read_uid(self) -> str | None:
        """Read UID using the common PC/SC contactless reader command."""
        response = self.send_apdu([0xFF, 0xCA, 0x00, 0x00, 0x00])
        if not response.ok:
            return None
        return bytes(response.data).hex().upper()

    @classmethod
    def create_pcsc_backend(cls, reader_name: str | None = None) -> PcscBackend:
        """Create a PC/SC backend adapter."""
        if reader_name is not None:
            return cls(reader=PcscReaderProvider.get(reader_name))

        readers = PcscReaderProvider.readers()
        if not readers:
            raise PcscReaderProvider.ReaderNotFoundError
        return cls(reader=readers[0])

    @staticmethod
    def pcsc_backend_names() -> list[str]:
        """Return available PC/SC reader backend names without the pcsc prefix."""
        return list(PcscReaderProvider.reader_names())
