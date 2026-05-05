"""Tests for NTAG CLI commands."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, ClassVar

from typer.testing import CliRunner

from schnee.controllers.cli.main import app
from schnee.services.ntag_profile import ReadNtagProfileBackendError

if TYPE_CHECKING:
    import pytest


class FakeProfile:
    """Profile object returned by the read service."""

    data: ClassVar[dict[str, Any]] = {
        "tag": {
            "type": "NTAG215",
            "uid": "04112233445566",
        },
        "ndef": {
            "present": True,
            "records": [],
        },
    }

    def model_dump(self, *, mode: str) -> dict[str, Any]:
        """Return a JSON-compatible profile representation."""
        assert mode == "json", "CLI should request JSON-compatible model output"
        return self.data


def test_ntag_read_delegates_to_read_profile_service(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The ntag read command passes the backend option to the read service."""
    calls: list[str] = []

    class FakeReadNtagProfileService:
        """Read service replacement for CLI delegation tests."""

        class Request:
            """Read request replacement."""

            def __init__(self, *, backend_name: str) -> None:
                self.backend_name = backend_name

        @classmethod
        def call(cls, req: Request) -> FakeProfile:
            """Record the requested backend and return a fake profile."""
            calls.append(req.backend_name)
            return FakeProfile()

    monkeypatch.setattr(
        "schnee.controllers.cli.commands.ReadNtagProfileService",
        FakeReadNtagProfileService,
    )

    result = CliRunner().invoke(
        app,
        ["ntag", "read", "--backend", "pcsc:Reader A"],
        prog_name="schnee",
    )

    assert result.exit_code == 0, "successful NTAG reads should exit cleanly"
    assert calls == ["pcsc:Reader A"], (
        "CLI should delegate backend selection to the service"
    )


def test_ntag_read_outputs_stable_json(monkeypatch: pytest.MonkeyPatch) -> None:
    """Successful ntag read output is stable sorted JSON."""

    class FakeReadNtagProfileService:
        """Read service replacement for JSON output tests."""

        class Request:
            """Read request replacement."""

            def __init__(self, *, backend_name: str) -> None:
                self.backend_name = backend_name

        @classmethod
        def call(cls, req: Request) -> FakeProfile:
            """Return a fake profile."""
            _ = req
            return FakeProfile()

    monkeypatch.setattr(
        "schnee.controllers.cli.commands.ReadNtagProfileService",
        FakeReadNtagProfileService,
    )

    result = CliRunner().invoke(app, ["ntag", "read"], prog_name="schnee")

    expected = f"{json.dumps(FakeProfile.data, indent=2, sort_keys=True)}\n"
    assert result.exit_code == 0, "successful NTAG reads should exit cleanly"
    assert result.output == expected, "NTAG profiles should be printed as stable JSON"


def test_ntag_read_renders_service_errors(monkeypatch: pytest.MonkeyPatch) -> None:
    """Service-level read failures are rendered by the CLI error handler."""

    class FakeReadNtagProfileService:
        """Read service replacement for service error tests."""

        class Request:
            """Read request replacement."""

            def __init__(self, *, backend_name: str) -> None:
                self.backend_name = backend_name

        @classmethod
        def call(cls, req: Request) -> FakeProfile:
            """Raise a service-level read error."""
            _ = req
            raise ReadNtagProfileBackendError

    monkeypatch.setattr(
        "schnee.controllers.cli.commands.ReadNtagProfileService",
        FakeReadNtagProfileService,
    )

    result = CliRunner().invoke(app, ["ntag", "read"], prog_name="schnee")

    assert result.exit_code == 1, "service errors should produce a non-zero exit code"
    assert ReadNtagProfileBackendError.msg in result.output, (
        "service errors should be rendered through the CLI error handler"
    )
