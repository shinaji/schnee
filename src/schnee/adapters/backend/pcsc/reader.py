from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

from smartcard.pcsc.PCSCReader import PCSCReader
from smartcard.System import readers as smartcard_readers

if TYPE_CHECKING:
    from smartcard.CardConnection import CardConnection


class PcscConnection(Protocol):
    """PC/SC connection interface used by the backend."""

    def connect(self) -> None:
        """Connect to the card."""

    def transmit(self, command: list[int]) -> tuple[list[int], int, int]:
        """Transmit a command APDU."""


class PcscReader(Protocol):
    """PC/SC reader interface used by the backend."""

    name: str

    def create_connection(self) -> PcscConnection:
        """Create a PC/SC connection."""


class SmartcardPcscConnection:
    """Adapter for pyscard connection objects."""

    def __init__(self, connection: CardConnection) -> None:
        self._connection = connection

    def connect(self) -> None:
        """Connect to the card."""
        self._connection.connect()

    def transmit(self, command: list[int]) -> tuple[list[int], int, int]:
        """Transmit a command APDU."""
        response, sw1, sw2 = self._connection.transmit(command)
        return list(response), sw1, sw2


class SmartcardPcscReader:
    """Adapter for pyscard PC/SC reader objects."""

    def __init__(self, reader: PCSCReader) -> None:
        self._reader = reader

    @property
    def name(self) -> str:
        """Return the PC/SC reader name."""
        return self._reader.name

    def create_connection(self) -> SmartcardPcscConnection:
        """Create a wrapped PC/SC connection."""
        return SmartcardPcscConnection(self._reader.createConnection())


class PcscReaderProvider:
    """Discover and wrap pyscard PC/SC readers."""

    class PcscReaderProviderError(Exception):
        """PC/SC reader provider error."""

    class ReaderNotFoundError(PcscReaderProviderError):
        """Raised when a requested PC/SC reader is not found."""

    @staticmethod
    def readers() -> list[PcscReader]:
        """Return available PC/SC readers."""
        return [
            SmartcardPcscReader(reader)
            for reader in smartcard_readers()
            if isinstance(reader, PCSCReader)
        ]

    @classmethod
    def reader_names(cls) -> list[str]:
        """Return available PC/SC reader names."""
        return [reader.name for reader in cls.readers()]

    @classmethod
    def get(cls, name: str) -> PcscReader:
        """Return a named PC/SC reader."""
        for reader in cls.readers():
            if reader.name == name:
                return reader
        raise cls.ReaderNotFoundError
