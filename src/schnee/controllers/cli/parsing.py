from __future__ import annotations

import typer


def parse_hex(
    value: str,
    *,
    option_name: str,
    byte_length: int,
) -> bytes:
    """Convert CLI hex input to bytes with exact length validation."""
    try:
        parsed = bytes.fromhex(value)
    except ValueError as exc:
        msg = "must be valid hexadecimal"
        raise typer.BadParameter(msg, param_hint=option_name) from exc
    if len(parsed) != byte_length:
        msg = (
            f"must be {byte_length * 2} hex characters that decode to "
            f"{byte_length} bytes"
        )
        raise typer.BadParameter(msg, param_hint=option_name)
    return parsed
