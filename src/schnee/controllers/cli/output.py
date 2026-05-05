from __future__ import annotations

import json

import typer


def echo_text(value: str) -> None:
    """Write plain text output."""
    typer.echo(value)


def echo_json(value: object) -> None:
    """Write JSON output."""
    typer.echo(json.dumps(value, indent=2, sort_keys=True))
