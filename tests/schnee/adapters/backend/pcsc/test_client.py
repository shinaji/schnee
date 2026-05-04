"""Tests for the PC/SC APDU client."""

from __future__ import annotations

import pytest

from schnee.adapters.backend.pcsc import PcscApduClient


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

    def __init__(self) -> None:
        self.name = "Fake PCSC Reader"
        self.connection = FakeConnection()

    def create_connection(self) -> FakeConnection:
        """Create a fake PC/SC connection."""
        return self.connection


def test_pcsc_apdu_client_checks_accepted_status_words() -> None:
    """PC/SC APDU client returns a response for accepted status words."""
    reader = FakeReader()
    reader.connection.response = [0x01]
    reader.connection.sw1 = 0x91
    reader.connection.sw2 = 0xAF
    client = PcscApduClient(reader)

    response = client.send_apdu([0x90, 0xAF, 0x00, 0x00, 0x00])

    assert response.data == [0x01]


def test_pcsc_apdu_client_raises_for_unexpected_status() -> None:
    """PC/SC APDU client raises for failed status words."""
    reader = FakeReader()
    reader.connection.sw1 = 0x6A
    reader.connection.sw2 = 0x82
    client = PcscApduClient(reader)

    with pytest.raises(PcscApduClient.ApduStatusError):
        client.send_apdu([0x00, 0xA4, 0x00, 0x00])
