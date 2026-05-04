"""Tests for NTAG 424 DNA high-level helpers."""

import pytest

from schnee.adapters.ntag.core import Ntag424, Session


def test_session_requires_explicit_master_key() -> None:
    """Session construction fails unless the caller supplies the master key."""
    with pytest.raises(Session.SessionError, match="master_key"):
        Session(connection=object())  # type: ignore[arg-type]


def test_ntag424_requires_explicit_master_key_before_reader_lookup() -> None:
    """Ntag424 construction fails before any reader I/O without a master key."""
    with pytest.raises(ValueError, match="master_key"):
        Ntag424(name="Reader A")
