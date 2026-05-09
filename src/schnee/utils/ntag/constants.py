"""Shared NTAG-related constants."""

from enum import IntEnum, unique


@unique
class NtagByteLength(IntEnum):
    """Byte lengths used by NTAG-related APIs."""

    AES_KEY = 16
    SDM_MAC = 8
    UID = 7
    SDM_COUNTER = 3
