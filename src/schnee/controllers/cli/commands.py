from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import typer


def register_commands(_app: typer.Typer) -> None:
    """Register CLI commands."""

    @_app.callback(invoke_without_command=True)
    def root() -> None:
        """NFC/RFID tag authentication and encryption tools."""
