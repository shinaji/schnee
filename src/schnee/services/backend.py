"""Services for backend selection."""

from __future__ import annotations

from typing import ClassVar

from schnee.adapters.backend.core import Backend
from schnee.adapters.backend.pcsc import PcscReaderProvider
from schnee.services.base import Service, ServiceError


class ListBackendNamesServiceError(ServiceError):
    """Base exception for list backend names service errors."""

    msg: ClassVar[str] = "List backend names service error"


class ListBackendNamesBackendError(ListBackendNamesServiceError):
    """Raised when backend name discovery fails."""

    msg: ClassVar[str] = "List backend names backend operation failed"


class ListBackendNamesReaderError(ListBackendNamesServiceError):
    """Raised when PC/SC reader discovery fails."""

    msg: ClassVar[str] = "List backend names reader discovery failed"


class ListBackendNamesService(Service[list[str]]):
    """List selectable backend names."""

    class Request(Service.Request):
        """Request for listing selectable backend names."""

    def process(self) -> list[str]:
        """Return selectable backend names."""
        try:
            return Backend.backend_names()
        except PcscReaderProvider.PcscReaderProviderError as exc:
            raise ListBackendNamesReaderError from exc
        except Backend.BackendError as exc:
            raise ListBackendNamesBackendError from exc
