from __future__ import annotations

import typer

from schnee.controllers.cli.commands import register_commands


def create_app() -> typer.Typer:
    """Create the root Typer application."""
    app = typer.Typer(
        help="NFC/RFID tag authentication and encryption tools.",
        no_args_is_help=True,
    )
    register_commands(app)
    return app


app = create_app()


def main() -> None:
    """Run the schnee CLI."""
    app()


if __name__ == "__main__":
    main()
