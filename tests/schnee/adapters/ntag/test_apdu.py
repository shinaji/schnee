"""Tests for APDU models."""

import pytest
from pydantic import ValidationError

from schnee.adapters.ntag.apdu import CommandAPDU, ResponseAPDU


def test_command_apdu_accepts_byte_data() -> None:
    """Command data accepts inclusive byte values."""
    command = CommandAPDU(cla=0x90, ins=0xA4, data=[0x00, 0xFF])

    assert command.to_list() == [0x90, 0xA4, 0x00, 0x00, 0x02, 0x00, 0xFF]


def test_command_apdu_serializes_case1() -> None:
    """Case 1 command APDU serializes only the header."""
    command = CommandAPDU(cla=0x90, ins=0xA4)

    assert command.to_list() == [0x90, 0xA4, 0x00, 0x00]


def test_command_apdu_serializes_short_le_256_as_zero() -> None:
    """Short Le=256 is encoded as 0x00."""
    command = CommandAPDU(cla=0x90, ins=0xA4, le=0x100)

    assert command.to_list() == [0x90, 0xA4, 0x00, 0x00, 0x00]


def test_command_apdu_serializes_case4() -> None:
    """Case 4 command APDU serializes data and Le."""
    command = CommandAPDU(cla=0x90, ins=0xA4, data=[0x01], le=0x02)

    assert command.to_list() == [0x90, 0xA4, 0x00, 0x00, 0x01, 0x01, 0x02]


def test_command_apdu_serializes_extended_case3() -> None:
    """Extended case 3 command APDU uses a 16-bit Lc field."""
    command = CommandAPDU(cla=0x90, ins=0xA4, data=[0x01, 0x02], extended=True)

    assert command.to_list() == [0x90, 0xA4, 0x00, 0x00, 0x00, 0x00, 0x02, 0x01, 0x02]


def test_command_apdu_serializes_extended_le_65536_as_zeroes() -> None:
    """Extended Le=65536 is encoded as 0x0000."""
    command = CommandAPDU(cla=0x90, ins=0xA4, le=0x10000, extended=True)

    assert command.to_list() == [0x90, 0xA4, 0x00, 0x00, 0x00, 0x00, 0x00]


def test_command_apdu_rejects_short_data_length_overflow() -> None:
    """Short command APDU rejects data exceeding one-byte Lc."""
    with pytest.raises(CommandAPDU.ShortDataLengthExceededError):
        CommandAPDU(cla=0x90, ins=0xA4, data=[0x00] * 0x100)


def test_command_apdu_rejects_extended_data_length_overflow() -> None:
    """Extended command APDU rejects data exceeding two-byte Lc."""
    with pytest.raises(CommandAPDU.ExtendedDataLengthExceededError):
        CommandAPDU(cla=0x90, ins=0xA4, data=[0x00] * 0x10001, extended=True)


@pytest.mark.parametrize("byte", [-1, 0x100])
def test_command_apdu_rejects_data_outside_byte_range(byte: int) -> None:
    """Command data rejects integers outside byte range."""
    with pytest.raises(ValidationError):
        CommandAPDU(cla=0x90, ins=0xA4, data=[byte])


def test_response_apdu_accepts_byte_data() -> None:
    """Response data accepts inclusive byte values."""
    response = ResponseAPDU(data=[0x00, 0xFF], sw1=0x90, sw2=0x00)

    assert response.to_list() == [0x00, 0xFF, 0x90, 0x00]


@pytest.mark.parametrize("byte", [-1, 0x100])
def test_response_apdu_rejects_data_outside_byte_range(byte: int) -> None:
    """Response data rejects integers outside byte range."""
    with pytest.raises(ValidationError):
        ResponseAPDU(data=[byte], sw1=0x90, sw2=0x00)
