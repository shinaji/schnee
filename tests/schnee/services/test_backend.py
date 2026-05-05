"""Tests for backend selection services."""

import pytest

from schnee.adapters.backend.core import Backend
from schnee.adapters.backend.pcsc import PcscReaderProvider
from schnee.services.backend import (
    ListBackendNamesBackendError,
    ListBackendNamesReaderError,
    ListBackendNamesService,
)


def test_list_backend_names_service_returns_selectable_backend_names(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Selectable backend names are available through the service layer."""
    monkeypatch.setattr(
        "schnee.services.backend.Backend.backend_names",
        lambda: ["pcsc", "pcsc:Reader A"],
    )

    names = ListBackendNamesService.call(ListBackendNamesService.Request())

    assert names == ["pcsc", "pcsc:Reader A"]


def test_list_backend_names_service_translates_reader_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reader discovery failures are exposed through service-level errors."""

    def backend_names() -> list[str]:
        raise PcscReaderProvider.PcscReaderProviderError

    monkeypatch.setattr(
        "schnee.services.backend.Backend.backend_names",
        backend_names,
    )

    with pytest.raises(
        ListBackendNamesReaderError,
        match=ListBackendNamesReaderError.msg,
    ) as exc_info:
        ListBackendNamesService.call(ListBackendNamesService.Request())

    assert isinstance(
        exc_info.value.__cause__,
        PcscReaderProvider.PcscReaderProviderError,
    ), "service error should preserve the reader failure as its cause"


def test_list_backend_names_service_translates_backend_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Backend selector failures are exposed through service-level errors."""

    def backend_names() -> list[str]:
        raise Backend.BackendError

    monkeypatch.setattr(
        "schnee.services.backend.Backend.backend_names",
        backend_names,
    )

    with pytest.raises(
        ListBackendNamesBackendError,
        match=ListBackendNamesBackendError.msg,
    ) as exc_info:
        ListBackendNamesService.call(ListBackendNamesService.Request())

    assert isinstance(
        exc_info.value.__cause__,
        Backend.BackendError,
    ), "service error should preserve the backend failure as its cause"
