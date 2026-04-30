"""Tests for APDU models."""

import pytest
from pydantic import ValidationError

from schnee.adapters.ntag.apdu import CommandAPDU, ResponseAPDU


def test_command_apdu_accepts_byte_data() -> None:
    """Command data accepts inclusive byte values."""
    command = CommandAPDU(cla=0x90, ins=0xA4, data=[0x00, 0xFF])

    assert command.to_list() == [0x90, 0xA4, 0x00, 0x00, 0x02, 0x00, 0xFF]


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
