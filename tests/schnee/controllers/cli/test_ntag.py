"""Tests for NTAG CLI commands."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, ClassVar

from typer.testing import CliRunner

from schnee.controllers.cli.errors import SERVICE_ERROR_EXIT_CODE
from schnee.controllers.cli.main import app
from schnee.services.ntag_profile import (
    ReadNtagProfileBackendError,
    WriteNdefUrlBackendError,
)

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

    assert result.exit_code == SERVICE_ERROR_EXIT_CODE, (
        "service errors should produce the configured CLI error exit code"
    )
    assert ReadNtagProfileBackendError.msg in result.stderr, (
        "service errors should be rendered to stderr through the CLI error handler"
    )


def test_ntag_write_url_delegates_unauthenticated_write(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The ntag write-url command delegates unauthenticated writes to the service."""
    calls: list[tuple[str, str, bytes | None]] = []

    class FakeWriteNdefUrlService:
        """Write service replacement for unauthenticated CLI delegation tests."""

        class Request:
            """Write request replacement."""

            def __init__(
                self,
                *,
                backend_name: str,
                url: str,
                ntag424_master_key: bytes | None,
            ) -> None:
                self.backend_name = backend_name
                self.url = url
                self.ntag424_master_key = ntag424_master_key

        @classmethod
        def call(cls, req: Request) -> None:
            """Record the service request."""
            calls.append((req.backend_name, req.url, req.ntag424_master_key))

    monkeypatch.setattr(
        "schnee.controllers.cli.commands.WriteNdefUrlService",
        FakeWriteNdefUrlService,
    )

    result = CliRunner().invoke(
        app,
        [
            "ntag",
            "write-url",
            "--backend",
            "pcsc:Reader A",
            "--url",
            "https://example.com",
        ],
        prog_name="schnee",
    )

    assert result.exit_code == 0, "successful URL writes should exit cleanly"
    assert calls == [("pcsc:Reader A", "https://example.com", None)], (
        "CLI should pass backend, URL, and no NTAG 424 key to the service"
    )


def test_ntag_write_url_passes_authenticated_key_bytes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The ntag write-url command converts the NTAG 424 key from hex to bytes."""
    calls: list[bytes | None] = []

    class FakeWriteNdefUrlService:
        """Write service replacement for authenticated CLI delegation tests."""

        class Request:
            """Write request replacement."""

            def __init__(
                self,
                *,
                backend_name: str,
                url: str,
                ntag424_master_key: bytes | None,
            ) -> None:
                self.backend_name = backend_name
                self.url = url
                self.ntag424_master_key = ntag424_master_key

        @classmethod
        def call(cls, req: Request) -> None:
            """Record the converted key."""
            calls.append(req.ntag424_master_key)

    monkeypatch.setattr(
        "schnee.controllers.cli.commands.WriteNdefUrlService",
        FakeWriteNdefUrlService,
    )

    result = CliRunner().invoke(
        app,
        [
            "ntag",
            "write-url",
            "--backend",
            "pcsc",
            "--url",
            "https://example.com",
            "--ntag424-master-key-hex",
            "00112233445566778899aabbccddeeff",
        ],
        prog_name="schnee",
    )

    assert result.exit_code == 0, "authenticated URL writes should exit cleanly"
    assert calls == [bytes.fromhex("00112233445566778899aabbccddeeff")], (
        "CLI should convert the NTAG 424 master key hex to bytes"
    )


def test_ntag_write_url_rejects_invalid_key_hex() -> None:
    """Invalid NTAG 424 key hex input is rejected before service construction."""
    result = CliRunner().invoke(
        app,
        [
            "ntag",
            "write-url",
            "--url",
            "https://example.com",
            "--ntag424-master-key-hex",
            "not-hex",
        ],
        prog_name="schnee",
    )

    assert result.exit_code != 0, "invalid key hex should fail the CLI command"
    assert "valid hexadecimal" in result.stderr, (
        "invalid key hex should explain the accepted input format"
    )


def test_ntag_write_url_renders_service_errors(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Service-level write failures are rendered by the CLI error handler."""

    class FakeWriteNdefUrlService:
        """Write service replacement for service error tests."""

        class Request:
            """Write request replacement."""

            def __init__(
                self,
                *,
                backend_name: str,
                url: str,
                ntag424_master_key: bytes | None,
            ) -> None:
                self.backend_name = backend_name
                self.url = url
                self.ntag424_master_key = ntag424_master_key

        @classmethod
        def call(cls, req: Request) -> None:
            """Raise a service-level write error."""
            _ = req
            raise WriteNdefUrlBackendError

    monkeypatch.setattr(
        "schnee.controllers.cli.commands.WriteNdefUrlService",
        FakeWriteNdefUrlService,
    )

    result = CliRunner().invoke(
        app,
        ["ntag", "write-url", "--url", "https://example.com"],
        prog_name="schnee",
    )

    assert result.exit_code == SERVICE_ERROR_EXIT_CODE, (
        "service errors should produce the configured CLI error exit code"
    )
    assert WriteNdefUrlBackendError.msg in result.stderr, (
        "service errors should be rendered to stderr through the CLI error handler"
    )
