from Crypto.Cipher import AES
from Crypto.Hash import CMAC
from Crypto.Util.Padding import pad


def aes_encrypt(key: bytes, data: bytes, iv: bytes | None = None) -> bytes:
    """AES-128 CBC encryption"""
    cipher = AES.new(key=key, mode=AES.MODE_CBC, iv=iv or bytes(16))
    return cipher.encrypt(data)


def aes_decrypt(key: bytes, data: bytes, iv: bytes | None = None) -> bytes:
    """AES-128 CBC decryption"""
    cipher = AES.new(key=key, mode=AES.MODE_CBC, iv=iv or bytes(16))
    return cipher.decrypt(data)


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """AES-128 CBC encryption"""
    return bytes(x ^ y for x, y in zip(a, b, strict=False))


def calculate_ev2_mac(  # noqa: PLR0913
    session_key_mac: bytes,
    cmd_code: int,
    cmd_ctr: int,
    tran_id: bytes,
    file_no: bytes,
    data: bytes,
) -> bytes:
    """Calculate the 8-byte MAC for EV2 commands.

    Args:
        session_key_mac: 16-byte session key for MAC calculation.
        cmd_code: Command code for the EV2 command.
        cmd_ctr: Command counter for the EV2 command.
        tran_id: Transaction ID for the EV2 command.
        file_no: File number for the EV2 command.
        data: Data for the EV2 command.
    """
    # CmdCtr is a 2-byte little-endian value
    cmd_ctr_bytes = cmd_ctr.to_bytes(2, byteorder="little")

    # Concatenate data to be used for MAC calculation
    # CmdCode (0xF5) + Counter + TI + Payload # noqa: ERA001
    mac_input = bytes([cmd_code]) + cmd_ctr_bytes + tran_id + file_no + bytes(data)

    c = CMAC.new(key=session_key_mac, ciphermod=AES)
    c.update(mac_input)
    full_mac = c.digest()

    # For EV2, use the first 8 bytes
    return bytes(list(full_mac)[1::2])


def aes_cbc_encrypt_for_ev2(
    session_key_enc: bytes,
    plain_data: bytes,
    iv: bytes | None,
) -> bytes:
    """Encrypt plain_data for EV2 using AES-128-CBC with ISO 7816-4 padding.

    Args:
        session_key_enc: 16-byte AES encryption key.
        plain_data: Data to encrypt. If its length is not a multiple of 16,
            it will be padded using ISO 7816-4 (0x80 followed by 0x00 bytes).
        iv: Initialization vector. If None, a zero IV is used.
    """
    if len(list(plain_data)) % 16 == 0:
        padded_data = plain_data
    else:
        padded_data = pad(data_to_pad=plain_data, block_size=16, style="iso7816")

    cipher = AES.new(key=session_key_enc, mode=AES.MODE_CBC, iv=iv or bytes(16))

    return cipher.encrypt(padded_data)
