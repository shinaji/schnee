from __future__ import annotations


def normalize_backend_name(value: str) -> str:
    """Normalize a backend name from CLI input."""
    return value.strip()
