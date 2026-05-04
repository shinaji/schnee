from dataclasses import dataclass

NDEF_HEADER_LEN = 7


class PlaceholderNotFoundError(ValueError):
    """Raised when an NDEF URL template placeholder is missing."""


def int_to_3bytes_le(n: int) -> list[int]:
    """Encode an integer as three little-endian bytes."""
    return [n & 0xFF, (n >> 8) & 0xFF, (n >> 16) & 0xFF]


def wrap_ndef_record(url_string: str) -> list[int]:
    """URIをNDEFレコード形式に変換"""
    url_bytes = url_string.encode()
    payload_len = len(url_bytes)

    # NDEF Header (Short Record, URI Type, No ID) = 0xD1
    # Type Length = 1 ('U')
    # Payload Length
    header = [0xD1, 0x01, payload_len + 1, 0x55]  # 0x55 = 'U' (URI)

    # 0x00 (No prefix)
    # URI Identifier Code (0x04 = https://) は今回省略し、URI全体を書く
    no_prefix = [0x00]

    return header + no_prefix + list(url_bytes)


@dataclass
class Offset:
    """Offsets for SDM mirror placeholders inside an NDEF URL file."""

    uid_offset: int
    counter_offset: int
    mac_offset: int
    mac_input_offset: int


def calculate_offsets(url_template: str) -> Offset:
    """Calculate SDM mirror offsets in an NDEF URL template."""
    # UID Data
    uid_placeholder = "U" * 14
    # Counter Data
    counter_placeholder = "C" * 6
    # CMAC(Cipher-based Message Authentication Code)
    mac_placeholder = "M" * 16

    # 文字列検索 (.find は 0 から始まるインデックスを返す)
    # URL文字列内での位置 + ヘッダー7バイト = 実際のオフセット

    # 1. UID Data Offset (暗号化データ開始位置)
    uid_index = url_template.find(uid_placeholder)
    if uid_index == -1:
        msg = "UID placeholder not found!"
        raise PlaceholderNotFoundError(msg)
    uid_offset = NDEF_HEADER_LEN + uid_index

    # 2. COUNTER Offset (署名開始位置)
    counter_index = url_template.find(counter_placeholder)
    if counter_index == -1:
        msg = "counter placeholder not found!"
        raise PlaceholderNotFoundError(msg)
    counter_offset = NDEF_HEADER_LEN + counter_index

    # 3. CMAC Offset (署名開始位置)
    mac_index = url_template.find(mac_placeholder)
    if mac_index == -1:
        msg = "MAC placeholder not found!"
        raise PlaceholderNotFoundError(msg)
    mac_offset = NDEF_HEADER_LEN + mac_index

    # 4. MAC Input Offset (CMAC計算の開始位置)
    mac_input_offset = NDEF_HEADER_LEN

    return Offset(
        uid_offset=uid_offset,
        counter_offset=counter_offset,
        mac_offset=mac_offset,
        mac_input_offset=mac_input_offset,
    )
