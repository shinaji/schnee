"""Tests for the backends CLI command."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, ClassVar

from typer.testing import CliRunner

from schnee.controllers.cli.errors import SERVICE_ERROR_EXIT_CODE
from schnee.controllers.cli.main import app
from schnee.services.base import ServiceError

if TYPE_CHECKING:
    import pytest


class ExampleServiceError(ServiceError):
    """Service error used by backends command tests."""

    msg: ClassVar[str] = "backend names unavailable"


def test_backends_command_prints_service_backend_names(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The backends command delegates backend discovery to the service layer."""
    requests: list[object] = []

    class FakeListBackendNamesService:
        class Request:
            """Request marker used to verify CLI delegation."""

        @classmethod
        def call(cls, req: object) -> list[str]:
            requests.append(req)
            return ["pcsc", "pcsc:Reader A"]

    monkeypatch.setattr(
        "schnee.controllers.cli.commands.ListBackendNamesService",
        FakeListBackendNamesService,
    )

    result = CliRunner().invoke(app, ["backends"], prog_name="schnee")

    assert result.exit_code == 0, "backends command should exit successfully"
    assert result.output == "pcsc\npcsc:Reader A\n", (
        "backends command should print each selectable backend name"
    )
    assert len(requests) == 1, "backends command should call the service once"
    assert isinstance(requests[0], FakeListBackendNamesService.Request), (
        "backends command should pass the service request type"
    )


def test_backends_command_uses_cli_error_handler_for_service_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Service-level failures are rendered through the CLI error handler."""

    class FakeListBackendNamesService:
        class Request:
            """Request marker used by the fake service."""

        @classmethod
        def call(cls, req: object) -> list[str]:
            _ = req
            raise ExampleServiceError

    monkeypatch.setattr(
        "schnee.controllers.cli.commands.ListBackendNamesService",
        FakeListBackendNamesService,
    )

    result = CliRunner().invoke(app, ["backends"], prog_name="schnee")

    assert result.exit_code == SERVICE_ERROR_EXIT_CODE, (
        "service errors should terminate with the configured CLI error code"
    )
    assert ExampleServiceError.msg in result.stderr, (
        "service errors should be rendered by the CLI error handler"
    )


def test_cli_code_does_not_import_adapter_layer() -> None:
    """CLI modules must not import adapter-layer implementation details."""
    cli_dir = Path("src/schnee/controllers/cli")
    imported_adapters = [
        path
        for path in cli_dir.glob("*.py")
        if "schnee.adapters" in path.read_text(encoding="utf-8")
    ]

    assert imported_adapters == [], "CLI code should not import schnee.adapters.*"
