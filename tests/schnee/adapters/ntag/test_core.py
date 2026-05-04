"""Tests for NTAG 424 DNA high-level helpers."""

from typing import TYPE_CHECKING, cast

import pytest

from schnee.adapters.ntag.core import Ntag424, Session

if TYPE_CHECKING:
    from schnee.adapters.backend.pcsc import PcscApduClient


def test_session_requires_explicit_master_key() -> None:
    """Session construction fails unless the caller supplies the master key."""
    with pytest.raises(Session.SessionError, match="master_key"):
        Session(connection=cast("PcscApduClient", object()))


def test_ntag424_requires_explicit_master_key_before_reader_lookup() -> None:
    """Ntag424 construction fails before any reader I/O without a master key."""
    with pytest.raises(ValueError, match="master_key"):
        Ntag424(name="Reader A")
