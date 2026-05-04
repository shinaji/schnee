"""Tests for the PC/SC profile backend."""

from __future__ import annotations

import pytest
from smartcard.Exceptions import CardConnectionException

from schnee.adapters.backend import PcscBackend
from schnee.adapters.backend.pcsc import PcscReaderProvider
from schnee.adapters.ntag.apdu import CommandAPDU
from schnee.adapters.ntag.profile import Ntag21xProfile, Ntag424DnaProfile

NTAG215_NDEF_CAPACITY_BYTES = 496


class FakeConnection:
    """Fake PC/SC connection."""

    def __init__(self) -> None:
        self.connected = False
        self.commands: list[list[int]] = []
        self.response = [0x04, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66]
        self.responses: dict[tuple[int, ...], list[int]] = {}
        self.exceptions: dict[tuple[int, ...], Exception] = {}
        self.sw1 = 0x90
        self.sw2 = 0x00

    def connect(self) -> None:
        """Record connection state."""
        self.connected = True

    def transmit(self, command: list[int]) -> tuple[list[int], int, int]:
        """Return a configurable deterministic response."""
        self.commands.append(command)
        if tuple(command) in self.exceptions:
            raise self.exceptions[tuple(command)]
        if tuple(command) in self.responses:
            return self.responses[tuple(command)], self.sw1, self.sw2
        return self.response, self.sw1, self.sw2


class FakeReader:
    """Fake PC/SC reader."""

    def __init__(self, name: str = "Fake PCSC Reader") -> None:
        self.name = name
        self.connection = FakeConnection()

    def create_connection(self) -> FakeConnection:
        """Create a fake PC/SC connection."""
        return self.connection


def test_pcsc_backend_reads_tag_info_uid() -> None:
    """PC/SC backend reads tag identity through the wrapped reader."""
    reader = FakeReader()
    backend = PcscBackend(reader=reader)

    tag = backend.read_tag_info()

    assert backend.reader_name == "Fake PCSC Reader"
    assert tag.type == "NTAG424DNA"
    assert tag.uid == "04112233445566"
    assert reader.connection.commands == [
        [0xFF, 0xCA, 0x00, 0x00, 0x00],
        [0x00, 0xA4, 0x04, 0x00, 0x07, 0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01],
    ]


def test_pcsc_backend_reads_ntag424_profile_settings() -> None:
    """PC/SC backend reads NTAG 424 DNA NDEF, SDM, access, and key state."""
    reader = FakeReader()
    backend = PcscBackend(reader=reader)
    ndef_record = [
        0xD1,
        0x01,
        0x0C,
        0x55,
        0x04,
        *list(b"example.com"),
    ]
    reader.connection.responses = {
        (0xFF, 0xCA, 0x00, 0x00, 0x00): [
            0x04,
            0x11,
            0x22,
            0x33,
            0x44,
            0x55,
            0x66,
        ],
        (0x00, 0xA4, 0x04, 0x00, 0x07, 0xD2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01): [],
        (
            0x90,
            0xF5,
            0x00,
            0x00,
            0x01,
            0x02,
            0x00,
        ): [
            0x00,
            0x40,
            0x00,
            0xE0,
            0x00,
            0x01,
            0x00,
            0xC1,
            0xF1,
            0x21,
            0x20,
            0x00,
            0x00,
            0x43,
            0x00,
            0x00,
            0x43,
            0x00,
            0x00,
        ],
        (
            0x90,
            0xAD,
            0x00,
            0x00,
            0x07,
            0x02,
            0x00,
            0x00,
            0x00,
            0x02,
            0x00,
            0x00,
            0x00,
        ): [
            0x00,
            len(ndef_record),
        ],
        (
            0x90,
            0xAD,
            0x00,
            0x00,
            0x07,
            0x02,
            0x02,
            0x00,
            0x00,
            len(ndef_record),
            0x00,
            0x00,
            0x00,
        ): ndef_record,
        (0x90, 0x64, 0x00, 0x00, 0x01, 0x00, 0x00): [0x00],
        (0x90, 0x64, 0x00, 0x00, 0x01, 0x01, 0x00): [0x00],
        (0x90, 0x64, 0x00, 0x00, 0x01, 0x02, 0x00): [0x00],
        (0x90, 0x64, 0x00, 0x00, 0x01, 0x03, 0x00): [0x00],
        (0x90, 0x64, 0x00, 0x00, 0x01, 0x04, 0x00): [0x00],
    }

    profile = backend.read_profile()

    assert isinstance(profile, Ntag424DnaProfile)
    assert profile.tag.uid == "04112233445566"
    assert profile.ndef.records[0].value == "https://example.com"
    assert profile.sdm.enabled is True
    assert profile.sdm.uid_mirror is True
    assert profile.sdm.counter_mirror is True
    assert profile.sdm.cmac_mirror is True
    assert profile.access.ndef_read == "free"
    assert profile.access.ndef_write == "authenticated"
    assert profile.security.default_keys is True
    assert profile.security.key_slots == PcscBackend.ntag424_key_slots
    assert profile.locks.permanent is False


def test_pcsc_backend_falls_back_to_type2_ntag215_reads() -> None:
    """PC/SC backend reads NTAG215 NDEF data when native select is unsupported."""
    reader = FakeReader()
    backend = PcscBackend(reader=reader)
    select_apdu = (
        0x00,
        0xA4,
        0x04,
        0x00,
        0x07,
        0xD2,
        0x76,
        0x00,
        0x00,
        0x85,
        0x01,
        0x01,
    )
    ndef_record = [
        0xD1,
        0x01,
        0x0C,
        0x55,
        0x04,
        *list(b"example.com"),
    ]
    tlv = [
        0x03,
        len(ndef_record),
        *ndef_record,
        0xFE,
    ]
    reader.connection.exceptions = {
        select_apdu: CardConnectionException("unsupported native select"),
    }
    reader.connection.responses = {
        (0xFF, 0xCA, 0x00, 0x00, 0x00): [
            0x04,
            0x11,
            0x22,
            0x33,
            0x44,
            0x55,
            0x66,
        ],
        (0xFF, 0xB0, 0x00, 0x03, 0x04): [0xE1, 0x10, 0x3E, 0x00],
        (0xFF, 0xB0, 0x00, 0x04, 0x04): tlv[0:4],
        (0xFF, 0xB0, 0x00, 0x05, 0x04): tlv[4:8],
        (0xFF, 0xB0, 0x00, 0x06, 0x04): tlv[8:12],
        (0xFF, 0xB0, 0x00, 0x07, 0x04): tlv[12:16],
        (0xFF, 0xB0, 0x00, 0x08, 0x04): [*tlv[16:19], 0x00],
    }

    profile = backend.read_profile()

    assert isinstance(profile, Ntag21xProfile)
    assert profile.tag.type == "NTAG215"
    assert profile.tag.uid == "04112233445566"
    assert profile.capacity_bytes == NTAG215_NDEF_CAPACITY_BYTES
    assert profile.ndef.records[0].value == "https://example.com"
    assert "sdm" not in profile.model_dump()
    assert reader.connection.commands.count([0xFF, 0xB0, 0x00, 0x03, 0x04]) == 1


def test_pcsc_backend_wraps_type2_ndef_parse_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PC/SC backend exposes malformed Type 2 NDEF as a backend error."""
    reader = FakeReader()
    backend = PcscBackend(reader=reader)
    monkeypatch.setattr(PcscBackend, "type2_capacity_types", {8: "NTAG213"})
    select_apdu = (
        0x00,
        0xA4,
        0x04,
        0x00,
        0x07,
        0xD2,
        0x76,
        0x00,
        0x00,
        0x85,
        0x01,
        0x01,
    )
    reader.connection.exceptions = {
        select_apdu: CardConnectionException("unsupported native select"),
    }
    reader.connection.responses = {
        (0xFF, 0xCA, 0x00, 0x00, 0x00): [
            0x04,
            0x11,
            0x22,
            0x33,
            0x44,
            0x55,
            0x66,
        ],
        (0xFF, 0xB0, 0x00, 0x03, 0x04): [0xE1, 0x10, 0x01, 0x00],
        (0xFF, 0xB0, 0x00, 0x04, 0x04): [0x03, 0x10, 0xD1, 0x01],
        (0xFF, 0xB0, 0x00, 0x05, 0x04): [0x00, 0x00, 0x00, 0x00],
    }

    with pytest.raises(PcscBackend.NdefParseError, match="Truncated"):
        backend.read_profile()


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
