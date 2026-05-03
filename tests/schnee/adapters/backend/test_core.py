"""Tests for backend adapter selection."""

from __future__ import annotations

import pytest

from schnee.adapters.backend import Backend, PcscBackend
from schnee.adapters.backend.pcsc import PcscReaderProvider


class FakeConnection:
    """Fake PC/SC connection."""

    def connect(self) -> None:
        """Record connection state."""

    def transmit(self, command: list[int]) -> tuple[list[int], int, int]:
        """Return a deterministic response."""
        _ = command
        return [], 0x90, 0x00


class FakeReader:
    """Fake PC/SC reader."""

    def __init__(self, name: str = "Reader A") -> None:
        self.name = name

    def create_connection(self) -> FakeConnection:
        """Create a fake PC/SC connection."""
        return FakeConnection()


def test_backend_names_returns_pcsc_backend_names(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Backend selector exposes user-selectable PC/SC backend names."""
    monkeypatch.setattr(PcscReaderProvider, "reader_names", lambda: ["Reader A"])

    assert Backend.backend_names() == ["pcsc", "pcsc:Reader A"]


def test_backend_names_hides_pcsc_when_no_readers(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Backend selector does not advertise unavailable PC/SC backends."""
    monkeypatch.setattr(PcscReaderProvider, "reader_names", list)

    assert Backend.backend_names() == []


def test_backend_get_returns_default_pcsc_backend(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Backend selector returns the default PC/SC backend."""
    reader = FakeReader()
    monkeypatch.setattr(PcscReaderProvider, "readers", lambda: [reader])

    backend = Backend.get("pcsc")

    assert isinstance(backend, PcscBackend)
    assert backend.reader_name == "Reader A"


def test_backend_get_accepts_named_pcsc_backend(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Backend selector resolves pcsc-prefixed reader names."""
    reader = FakeReader("Reader B")

    def get_reader(_name: str) -> FakeReader:
        return reader

    monkeypatch.setattr(PcscReaderProvider, "get", get_reader)

    backend = Backend.get("pcsc:Reader B")

    assert isinstance(backend, PcscBackend)
    assert backend.reader_name == "Reader B"


def test_backend_get_rejects_unknown_backend_name() -> None:
    """Backend selector reports unknown backend names."""
    with pytest.raises(Backend.BackendNotFoundError):
        Backend.get("missing")
