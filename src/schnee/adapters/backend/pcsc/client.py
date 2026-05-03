from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from schnee.adapters.ntag.apdu import CommandAPDU, ResponseAPDU

if TYPE_CHECKING:
    from .reader import PcscConnection, PcscReader


class PcscApduClient:
    """PC/SC APDU transport client."""

    ok_statuses: ClassVar[tuple[tuple[int, int], ...]] = (
        (0x90, 0x00),
        (0x91, 0x00),
        (0x91, 0xAF),
    )

    class PcscApduClientError(Exception):
        """PC/SC APDU client error."""

    class ApduStatusError(PcscApduClientError):
        """Raised when a response APDU has an unsuccessful status."""

        def __init__(self, sw1: int, sw2: int) -> None:
            self.sw1 = sw1
            self.sw2 = sw2
            super().__init__(f"SW1: {hex(sw1)} SW2: {hex(sw2)}")

    def __init__(self, reader: PcscReader) -> None:
        self.reader = reader
        self.connection: PcscConnection | None = None

    @property
    def reader_name(self) -> str:
        """Return the wrapped PC/SC reader name."""
        return self.reader.name

    def connect(self) -> PcscConnection:
        """Connect to the wrapped PC/SC reader."""
        if self.connection is None:
            self.connection = self.reader.create_connection()
            self.connection.connect()
        return self.connection

    def send_apdu(self, apdu: CommandAPDU | list[int]) -> ResponseAPDU:
        """Transmit an APDU and return the full response."""
        command = apdu.to_list() if isinstance(apdu, CommandAPDU) else apdu
        response, sw1, sw2 = self.connect().transmit(command)
        return ResponseAPDU(data=response, sw1=sw1, sw2=sw2)

    def send_checked(
        self,
        apdu: CommandAPDU | list[int],
        *,
        ok_statuses: tuple[tuple[int, int], ...] | None = None,
    ) -> list[int]:
        """Transmit an APDU and return data for successful status words."""
        response = self.send_apdu(apdu)
        statuses = self.ok_statuses if ok_statuses is None else ok_statuses
        if (response.sw1, response.sw2) in statuses:
            return response.data
        raise self.ApduStatusError(response.sw1, response.sw2)
