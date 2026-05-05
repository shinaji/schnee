"""Tests for CLI error handling."""

import pytest
import typer

from schnee.controllers.cli.errors import (
    SERVICE_ERROR_EXIT_CODE,
    exit_for_service_error,
)
from schnee.services.base import ServiceError


class ExampleServiceError(ServiceError):
    """Service error used by CLI tests."""

    msg = "example service failure"


def test_exit_for_service_error_writes_error_and_exits(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Service errors are rendered to stderr and terminate the CLI."""
    with pytest.raises(typer.Exit) as exc_info:
        exit_for_service_error(ExampleServiceError())

    captured = capsys.readouterr()

    assert exc_info.value.exit_code == SERVICE_ERROR_EXIT_CODE, (
        "service errors should terminate with the configured CLI error code"
    )
    assert ExampleServiceError.msg in captured.err, (
        "service errors should be rendered to stderr before exiting"
    )
