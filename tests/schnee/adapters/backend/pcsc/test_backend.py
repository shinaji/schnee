"""Tests for the PC/SC profile backend."""

from __future__ import annotations

from typing import TYPE_CHECKING

from schnee.adapters.backend import PcscBackend
from schnee.adapters.backend.pcsc import PcscReaderProvider
from schnee.adapters.ntag.apdu import CommandAPDU

if TYPE_CHECKING:
    import pytest


class FakeConnection:
    """Fake PC/SC connection."""

    def __init__(self) -> None:
        self.connected = False
        self.commands: list[list[int]] = []
        self.response = [0x04, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66]
        self.sw1 = 0x90
        self.sw2 = 0x00

    def connect(self) -> None:
        """Record connection state."""
        self.connected = True

    def transmit(self, command: list[int]) -> tuple[list[int], int, int]:
        """Return a configurable deterministic response."""
        self.commands.append(command)
        return self.response, self.sw1, self.sw2


class FakeReader:
    """Fake PC/SC reader."""

    def __init__(self, name: str = "Fake PCSC Reader") -> None:
        self.name = name
        self.connection = FakeConnection()

    def create_connection(self) -> FakeConnection:
        """Create a fake PC/SC connection."""
        return self.connection


def test_pcsc_backend_wraps_reader_and_reads_profile_uid() -> None:
    """PC/SC backend reads a profile through the wrapped reader."""
    reader = FakeReader()
    backend = PcscBackend(reader=reader)

    profile = backend.read_profile()

    assert backend.reader_name == "Fake PCSC Reader"
    assert profile.tag.uid == "04112233445566"
    assert profile.tag.features == ["pcsc"]
    assert reader.connection.commands == [[0xFF, 0xCA, 0x00, 0x00, 0x00]]


def test_pcsc_backend_sends_command_apdu() -> None:
    """PC/SC backend accepts CommandAPDU objects."""
    reader = FakeReader()
    backend = PcscBackend(reader=reader)

    response = backend.send_apdu(CommandAPDU(cla=0xFF, ins=0xCA, le=0))

    assert response.ok
    assert reader.connection.commands == [[0xFF, 0xCA, 0x00, 0x00, 0x00]]


def test_pcsc_backend_create_gets_named_reader(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PC/SC backend factory wraps a named reader result."""
    reader = FakeReader("Named Reader")

    def get_reader(_name: str) -> FakeReader:
        return reader

    monkeypatch.setattr(PcscReaderProvider, "get", get_reader)

    backend = PcscBackend.create_pcsc_backend("Named Reader")

    assert backend.reader_name == "Named Reader"


def test_pcsc_backend_create_gets_first_reader(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PC/SC backend factory wraps the first reader by default."""
    reader = FakeReader("First Reader")
    monkeypatch.setattr(PcscReaderProvider, "readers", lambda: [reader])

    backend = PcscBackend.create_pcsc_backend()

    assert backend.reader_name == "First Reader"


def test_pcsc_backend_names_include_reader_names(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PC/SC backend names expose available reader names."""
    monkeypatch.setattr(PcscReaderProvider, "reader_names", lambda: ["Reader A"])

    assert PcscBackend.pcsc_backend_names() == ["Reader A"]
