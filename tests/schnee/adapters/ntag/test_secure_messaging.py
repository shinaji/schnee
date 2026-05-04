"""Tests for NTAG 424 DNA secure messaging."""

import pytest

from schnee.adapters.ntag.secure_messaging import (
    EV2SessionContext,
    NTAG424CommandSpec,
    NTAG424SecureMessaging,
)


def make_session_context() -> EV2SessionContext:
    """Create a deterministic EV2 session context."""
    return EV2SessionContext(
        cmd_ctr=1,
        ti=bytes.fromhex("01020304"),
        session_key_mac=bytes.fromhex("00112233445566778899AABBCCDDEEFF"),
        session_key_enc=bytes.fromhex("FFEEDDCCBBAA99887766554433221100"),
    )


def test_build_payload_plain_mode_returns_unprotected_payload() -> None:
    """Plain mode does not require secure messaging context."""
    spec = NTAG424CommandSpec(
        cmd_code=0x5F,
        file_no=0x02,
        header_data=[0x02],
        command_data=[0x40, 0x00, 0xE0],
        mode="plain",
    )

    assert NTAG424SecureMessaging.build_payload(spec) == [0x02, 0x40, 0x00, 0xE0]


def test_build_payload_mac_mode_appends_expected_mac() -> None:
    """MAC mode uses cmd code, counter, TI, file number, and body as MAC input."""
    spec = NTAG424CommandSpec(
        cmd_code=0x5F,
        file_no=0x02,
        header_data=[0x02],
        command_data=[0x40, 0x00, 0xE0],
        mode="mac",
    )

    payload = NTAG424SecureMessaging.build_payload(spec, make_session_context())

    assert bytes(payload).hex() == "024000e088eb9c639c0bd07e"


def test_build_payload_full_mode_encrypts_with_derived_iv_and_appends_mac() -> None:
    """Full mode derives IV, encrypts command data, and MACs the encrypted body."""
    spec = NTAG424CommandSpec(
        cmd_code=0x5F,
        file_no=0x02,
        header_data=[0x02],
        command_data=[0x40, 0x00, 0xE0],
        mode="full",
    )

    payload = NTAG424SecureMessaging.build_payload(spec, make_session_context())

    assert bytes(payload).hex() == "024fc3f081fd0fbdf562e61df50903cbfed058d5cde887aacb"


def test_build_payload_secure_modes_require_session_context() -> None:
    """Secure messaging modes require EV2 session keys and counters."""
    spec = NTAG424CommandSpec(
        cmd_code=0x5F,
        mode="mac",
    )

    with pytest.raises(ValueError, match="EV2SessionContext"):
        NTAG424SecureMessaging.build_payload(spec)
