import binascii
from enum import IntEnum

from Crypto.Cipher import AES
from Crypto.Hash import CMAC
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
from pydantic import BaseModel, ConfigDict, Field
from smartcard.util import toHexString

from schnee.adapters.backend.core import Backend
from schnee.adapters.backend.pcsc import PcscApduClient, PcscBackend
from schnee.adapters.ntag.apdu import Ntag424ApduPreset
from schnee.adapters.ntag.crypt import aes_decrypt, aes_encrypt, xor_bytes
from schnee.adapters.ntag.utils import (
    Offset,
    calculate_offsets,
    int_to_3bytes_le,
    wrap_ndef_record,
)
from schnee.utils.logger import get_logger

_logger = get_logger(__name__)

KEY_VERSION_MAX = 0xFF


class Ntag424Key(IntEnum):
    """NTAG 424 DNA application key numbers."""

    APP_MASTER = 0x00
    APP_KEY_1 = 0x01
    APP_KEY_2 = 0x02
    APP_KEY_3 = 0x03
    APP_KEY_4 = 0x04


class Session:
    """Session adapter"""

    class SessionError(Exception):
        """Session error"""

    def __init__(
        self,
        connection: PcscApduClient,
        key_no: int = 0x00,
        master_key: bytes | None = None,
    ) -> None:
        if master_key is None:
            msg = "master_key must be provided explicitly"
            raise self.SessionError(msg)
        self.connection = connection
        self.key_no = key_no
        self.master_key = master_key

    @staticmethod
    def _rotate_left(data: bytes) -> bytes:
        """バイト配列を左に1バイト回転させる (NXP仕様)"""
        return data[1:] + data[0:1]

    def authenticate_ev2_first(self) -> tuple[bytes, bytes, bytes, bytes]:
        """Authenticate with the tag and derive EV2 session keys."""
        return self._authenticate_ev2_first()

    def _authenticate_ev2_first(self) -> tuple[bytes, bytes, bytes, bytes]:
        _logger.debug("AuthEv2First (Get RndB)")
        encrypted_rnd_b = bytes(
            self.connection.send_checked(
                Ntag424ApduPreset.authenticate_ev2_first(self.key_no),
            ),
        )

        # タグから戻ってきた暗号化されたRndB (末尾の90 00ステータスを除く)
        # resp_1 は Enc(RndB)
        _logger.debug("Encrypted RndB: %s", encrypted_rnd_b.hex())

        # 2. RndBを復号する
        rnd_b = aes_decrypt(self.master_key, encrypted_rnd_b)
        _logger.debug("Decrypted RndB: %s", rnd_b.hex())

        # 3. 自分の乱数 (RndA) を生成 (16 bytes)
        rnd_a = get_random_bytes(16)
        _logger.debug("Generated RndA: %s", rnd_a.hex())

        # 4. RndBをローテートする (RndB')
        rnd_b_prime = self._rotate_left(rnd_b)

        # 5. 送信データ作成: Enc(RndA + RndB')
        payload = rnd_a + rnd_b_prime
        encrypted_payload = aes_encrypt(self.master_key, payload)

        # 6. Part 2: コマンド送信 (Send RndA + RndB')
        # 90 AF 00 00 (Len) (EncData) 00
        resp_2 = bytes(
            self.connection.send_checked(
                Ntag424ApduPreset.additional_frame(list(encrypted_payload)),
            ),
        )
        return self._verify_and_derive_keys(
            rnd_a=rnd_a,
            rnd_b=rnd_b,
            response_data=resp_2,
        )

    def _verify_and_derive_keys(
        self,
        rnd_a: bytes,
        rnd_b: bytes,
        response_data: bytes,
    ) -> tuple[bytes, bytes, bytes, bytes]:
        """Part 2のレスポンス検証とセッションキー生成

        response_data: タグから返ってきた暗号化データ (Status Word 91 00 除く)
        """
        _logger.debug("--- Verify & Derive Session Keys ---")

        # 1. レスポンスの復号
        # AuthEV2FirstのレスポンスはIV=0で復号します
        iv = bytes(16)
        cipher = AES.new(self.master_key, AES.MODE_CBC, iv)
        decrypted_data = cipher.decrypt(response_data)

        # 2. RndA' (Rotated RndA) の検証
        # 復号データの構造: [TI(4byte)] [RndA'(16byte)] [PDcap(6byte)] [Padding...]
        # Transaction ID (TI) は先頭4バイト
        ti = decrypted_data[0:4]

        # RndA' は 4バイト目から16バイト分
        rnd_a_prime_received = decrypted_data[4:20]

        # 自分で計算した RndA' (期待値)
        rnd_a_prime_expected = self._rotate_left(rnd_a)

        _logger.debug("Decrypted TI: %s", ti.hex())
        _logger.debug("RndA' (Received): %s", rnd_a_prime_received.hex())
        _logger.debug("RndA' (Calculated): %s", rnd_a_prime_expected.hex())

        if rnd_a_prime_received != rnd_a_prime_expected:
            msg = "Authentication Failed: RndA mismatch! (Tag might be fake)"
            raise RuntimeError(msg)

        # 3. セッションキーの生成 (KDF: Key Derivation Function)
        # NTAG 424 DNA (EV2) 固有の「共有ベクトル(SV)」を作成します
        # Ref: AN12196, 7.2.2 Session key derivation
        sv_input = (
            rnd_a[0:2] + xor_bytes(rnd_a[2:8], rnd_b[0:6]) + rnd_b[6:16] + rnd_a[8:16]
        )

        c_enc = CMAC.new(self.master_key, ciphermod=AES)
        c_enc.update(b"\xa5\x5a\x00\x01\x00\x80" + sv_input)
        session_key_enc = c_enc.digest()

        c_mac = CMAC.new(self.master_key, ciphermod=AES)
        c_mac.update(b"\x5a\xa5\x00\x01\x00\x80" + sv_input)
        session_key_mac = c_mac.digest()

        # 次のコマンドで使うIVは、認証レスポンスの暗号文の最後の16バイト
        iv = response_data[-16:]

        _logger.debug("Session Key (Enc): %s", toHexString(list(session_key_enc)))
        _logger.debug("Session Key (MAC): %s", toHexString(list(session_key_mac)))
        _logger.debug("IV: %s", toHexString(list(iv)))

        return session_key_enc, session_key_mac, ti, iv


class Ntag424:
    """High-level helper for configuring NTAG 424 DNA tags."""

    FACTORY_DEFAULT_KEY = bytes(16)
    key_slots = 5
    aes_key_size = 16
    ti_size = 4
    byte_max = KEY_VERSION_MAX
    change_key_cmd = 0xC4

    class KeyUpdate(BaseModel):
        """One NTAG 424 DNA application-key update."""

        model_config = ConfigDict(frozen=True)

        key_no: Ntag424Key = Field(
            description="Application key number to update.",
        )
        new_key: bytes = Field(
            description="New AES-128 key bytes to write into the selected key slot.",
        )
        key_version: int = Field(
            default=0,
            ge=0,
            le=KEY_VERSION_MAX,
            description="New one-byte key version stored with the key.",
        )
        old_key: bytes | None = Field(
            default=None,
            description=(
                "Current AES-128 key bytes. Required for key 1..4 ChangeKey "
                "cryptograms; use Ntag424.FACTORY_DEFAULT_KEY for factory-default "
                "app keys."
            ),
        )

    class Ntag424Error(Exception):
        """Base exception for NTAG 424 helper errors."""

    class InvalidKeyNumberError(Ntag424Error):
        """Raised when a key number is outside the NTAG 424 key range."""

    class InvalidKeyLengthError(Ntag424Error):
        """Raised when an AES key is not 16 bytes."""

    class InvalidKeyVersionError(Ntag424Error):
        """Raised when a key version is outside one byte."""

    class MissingOldKeyError(Ntag424Error):
        """Raised when a non-master key update does not include the old key."""

    class UnsupportedBackendError(Ntag424Error):
        """Raised when a backend cannot provide raw NTAG 424 APDU access."""

    def __init__(
        self,
        backend_name: str,
        master_key: bytes | None = None,
    ) -> None:
        if master_key is None:
            msg = "master_key must be provided explicitly"
            raise ValueError(msg)
        self.backend = Backend.get(backend_name)
        if not isinstance(self.backend, PcscBackend):
            msg = "Ntag424 requires a PC/SC backend"
            raise self.UnsupportedBackendError(msg)
        self.connection = self.backend.client
        self.session = Session(
            connection=self.connection,
            key_no=0x00,
            master_key=master_key,
        )

    def connect(self) -> None:
        """Select the NTAG 424 DNA application."""
        self._apdu_select()

    def authenticate(self) -> tuple[bytes, bytes, bytes, bytes]:
        """Authenticate and return derived EV2 session values."""
        return self.session.authenticate_ev2_first()

    def update_keys(
        self,
        updates: list[KeyUpdate],
        *,
        cmd_ctr_start: int = 0,
    ) -> None:
        """Authenticate with key 0 and update NTAG 424 DNA application keys.

        Non-master keys are changed before key 0 because changing key 0 invalidates
        the current authenticated session.
        """
        self.connect()
        k_ses_auth_enc, k_ses_auth_mac, ti, _iv = self.authenticate()

        cmd_ctr = cmd_ctr_start
        for update in sorted(
            updates,
            key=lambda item: item.key_no is Ntag424Key.APP_MASTER,
        ):
            apdu = self.build_change_key_apdu(
                update=update,
                session_key_enc=k_ses_auth_enc,
                session_key_mac=k_ses_auth_mac,
                ti=ti,
                cmd_ctr=cmd_ctr,
            )
            _logger.debug(
                "ChangeKey key_no=%s: %s",
                int(update.key_no),
                toHexString(apdu),
            )
            self.connection.send_checked(apdu)
            cmd_ctr += 1

    @classmethod
    def build_change_key_apdu(
        cls,
        *,
        update: KeyUpdate,
        session_key_enc: bytes,
        session_key_mac: bytes,
        ti: bytes,
        cmd_ctr: int,
    ) -> list[int]:
        """Build a protected NTAG 424 DNA ChangeKey APDU."""
        cls._validate_key_update(update)
        cls._validate_key_bytes("session_key_enc", session_key_enc)
        cls._validate_key_bytes("session_key_mac", session_key_mac)
        if len(ti) != cls.ti_size:
            msg = "ti must be 4 bytes"
            raise ValueError(msg)

        plain_key_data = cls._build_change_key_data(update)
        iv = cls._change_key_iv(
            session_key_enc=session_key_enc,
            ti=ti,
            cmd_ctr=cmd_ctr,
        )
        encrypted_key_data = cls.aes_cbc_encrypt_for_ev2(
            session_key_enc=session_key_enc,
            iv=iv,
            plain_data=plain_key_data,
        )
        mac = cls._calculate_ev2_mac(
            session_key_mac=session_key_mac,
            cmd_code=cls.change_key_cmd,
            cmd_ctr=cmd_ctr,
            ti=ti,
            file_no=bytes([int(update.key_no)]),
            data=list(encrypted_key_data),
        )
        return Ntag424ApduPreset.change_key(
            key_no=int(update.key_no),
            encrypted_key_data=list(encrypted_key_data),
            mac=list(mac),
        ).to_list()

    @classmethod
    def _validate_key_update(cls, update: KeyUpdate) -> None:
        cls._validate_key_bytes("new_key", update.new_key)
        if not 0 <= update.key_version <= cls.byte_max:
            msg = "key_version must be between 0 and 255"
            raise cls.InvalidKeyVersionError(msg)
        if update.key_no is not Ntag424Key.APP_MASTER and update.old_key is None:
            msg = (
                "old_key is required when changing key 1..4; "
                "use Ntag424.FACTORY_DEFAULT_KEY for factory-default app keys"
            )
            raise cls.MissingOldKeyError(msg)
        if update.old_key is not None:
            cls._validate_key_bytes("old_key", update.old_key)

    @classmethod
    def _validate_key_bytes(cls, name: str, value: bytes) -> None:
        if len(value) != cls.aes_key_size:
            msg = f"{name} must be 16 bytes"
            raise cls.InvalidKeyLengthError(msg)

    @classmethod
    def _build_change_key_data(cls, update: KeyUpdate) -> bytes:
        """Build plaintext ChangeKey KeyData before EV2 encryption."""
        if update.key_no is Ntag424Key.APP_MASTER:
            return update.new_key + bytes([update.key_version])

        if update.old_key is None:
            msg = (
                "old_key is required when changing key 1..4; "
                "use Ntag424.FACTORY_DEFAULT_KEY for factory-default app keys"
            )
            raise cls.MissingOldKeyError(msg)

        return (
            xor_bytes(update.new_key, update.old_key)
            + bytes([update.key_version])
            + cls.change_key_crc32(update.new_key)
        )

    @staticmethod
    def change_key_crc32(data: bytes) -> bytes:
        """Return IEEE 802.3 FCS CRC32 bytes used by NTAG ChangeKey."""
        return (binascii.crc32(data) ^ 0xFFFFFFFF).to_bytes(4, byteorder="little")

    @classmethod
    def _change_key_iv(
        cls,
        *,
        session_key_enc: bytes,
        ti: bytes,
        cmd_ctr: int,
    ) -> bytes:
        iv_input = b"\xa5\x5a" + ti + cmd_ctr.to_bytes(2, byteorder="little") + bytes(8)
        return cls.aes_cbc_encrypt_for_ev2(
            session_key_enc=session_key_enc,
            iv=None,
            plain_data=iv_input,
        )

    def configure_sdm_url(self, url: str, *, cmd_ctr: int = 1) -> None:
        """Authenticate, write an NDEF URL, and enable SDM explicitly."""
        self.connect()
        k_ses_auth_enc, k_ses_auth_mac, ti, _iv = self.authenticate()
        self.write_ndef_url(
            url_string=url,
        )
        offset = calculate_offsets(url)
        self._enable_sdm(
            session_key_enc=k_ses_auth_enc,
            session_key_mac=k_ses_auth_mac,
            ti=ti,
            cmd_ctr=cmd_ctr,
            offset=offset,
        )

    def _apdu_select(self) -> None:
        """Select Application"""
        _logger.debug("Select Application")
        self.connection.send_checked(Ntag424ApduPreset.select_application())

    def write_ndef_url(
        self,
        url_string: str,
    ) -> None:
        """Write NDEF URL to Tag"""
        _logger.debug("--- Write NDEF Data (URL) ---")

        # 1. URLをNDEFデータに変換
        ndef_record = wrap_ndef_record(url_string)
        # ファイル全体のデータ: [Length(2bytes)] + [NDEF Record]
        file_data = [len(ndef_record) >> 8 & 255, len(ndef_record) & 255, *ndef_record]

        _logger.debug("Writing URL: %s", url_string)
        response = self.connection.send_checked(
            Ntag424ApduPreset.write_data_file(
                file_no=Ntag424ApduPreset.ndef_file_no,
                offset=[0x00, 0x00, 0x00],
                data=file_data,
            ),
        )
        _logger.debug("Response: %s", toHexString(response))

    @staticmethod
    def _calculate_ev2_mac(  # noqa: PLR0913
        session_key_mac: bytes,
        cmd_code: int,
        cmd_ctr: int,
        ti: bytes,
        file_no: bytes,
        data: list[int],
    ) -> bytes:
        """EV2コマンド用のMAC(8バイト)を計算する

        MAC Input = [CmdCode(1)] + [CmdCtr(2)] + [TI(4)] + [Data(N)]
        """
        # CmdCtrはリトルエンディアン2バイト
        cmd_ctr_bytes = cmd_ctr.to_bytes(2, byteorder="little")

        mac_input = bytes([cmd_code]) + cmd_ctr_bytes + ti + file_no + bytes(data)

        # CMAC計算
        c = CMAC.new(session_key_mac, ciphermod=AES)
        c.update(mac_input)
        full_mac = c.digest()

        # EV2では先頭8バイトを使用する
        return bytes(list(full_mac)[1::2])

    @staticmethod
    def aes_cbc_encrypt_for_ev2(
        session_key_enc: bytes,
        plain_data: bytes,
        iv: bytes | None,
    ) -> bytes:
        """NTAG 424 DNA (EV2) 用のAES-CBC暗号化関数

        Args:
            session_key_enc (bytes): 16バイトのセッションキー (SessionKeyEnc)
            iv (bytes): 16バイトの初期化ベクトル。
                        ※通常、セッション開始時はAll-Zero、
                          2回目以降は直前の暗号文の末尾ブロックを使用します。
            plain_data (bytes): 暗号化したい平文データ
                                   (例: FileNo + FileOption + AccessRights)

        Returns:
            bytes: 暗号化されたデータ (パディング済み)

        """
        # 1. パディング (ISO 7816-4 style)
        # データの末尾に 0x80 を付与し、16バイト境界まで 0x00 で埋めます
        if len(list(plain_data)) % 16 == 0:
            padded_data = plain_data
        else:
            padded_data = pad(plain_data, block_size=16, style="iso7816")

        # 2. AES-CBC モードで暗号化器を作成
        if iv is None:
            cipher = AES.new(session_key_enc, AES.MODE_CBC, bytes(16))
        else:
            cipher = AES.new(session_key_enc, AES.MODE_CBC, iv)

        # 3. 暗号化実行
        return cipher.encrypt(padded_data)

    def _enable_sdm(
        self,
        session_key_enc: bytes,
        session_key_mac: bytes,
        ti: bytes,
        cmd_ctr: int,
        offset: Offset,
    ) -> None:
        """Disable SDM (ChangeFileSettings)"""
        _logger.debug("--- Phase 3: ChangeFileSettings (Disable SDM) ---")

        # 設定値
        file_no = 0x02
        file_option = 0x40  # SDM OFF (Plain Communication)
        access_rights = [0x00, 0xE0]  # Read=Free, Write=Key0 (現在の値を維持)
        sdm_options = 0xC1
        sdm_access_rights = [0xF1, 0x21]

        # ペイロード組み立て
        payload = [file_option, *access_rights, sdm_options, *sdm_access_rights]
        payload += int_to_3bytes_le(offset.uid_offset)  # 33. UID
        payload += int_to_3bytes_le(offset.mac_offset)  # 7. MacIn
        payload += int_to_3bytes_le(offset.mac_offset)  # 59. MacOut

        iv = [
            0xA5,
            0x5A,
            *list(ti),
            *list(cmd_ctr.to_bytes(2, byteorder="little")),
            *list(bytes(8)),
        ]
        iv = list(
            self.aes_cbc_encrypt_for_ev2(
                session_key_enc=session_key_enc,
                iv=None,
                plain_data=bytes(iv),
            ),
        )

        encrypted_payload = list(
            self.aes_cbc_encrypt_for_ev2(
                session_key_enc=session_key_enc,
                iv=bytes(iv),
                plain_data=bytes(payload),
            ),
        )

        # 2. MACの計算
        # ChangeFileSettingsのコマンドコードは 0x5F
        cmd_code = 0x5F
        mac_input_data = encrypted_payload

        mac = self._calculate_ev2_mac(
            session_key_mac=session_key_mac,
            cmd_code=cmd_code,
            cmd_ctr=cmd_ctr,
            ti=ti,
            file_no=bytes([file_no]),
            data=mac_input_data,
        )

        _logger.debug("Payload: %s", toHexString(payload))
        _logger.debug("Encrypted payload: %s", toHexString(encrypted_payload))
        _logger.debug("Calculated MAC: %s", toHexString(list(mac)))

        # 3. APDUコマンドの送信
        full_data = [file_no, *encrypted_payload, *list(mac)]
        apdu = [0x90, cmd_code, 0, 0, len(full_data), *full_data, 0]

        _logger.debug("Send: %s", toHexString(apdu))
        response = self.connection.send_checked(apdu)
        _logger.debug("Rex: %s", toHexString(response))


def verify_sdm_mac(
    uid_hex: str,
    ctr_hex: str,
    mac_hex: str,
    master_key_hex: str,
) -> None:
    """NTAG 424 DNAのSDM-MACを検証する関数

    :param uid_hex: URLから取得したUID (例: "04826F823F5B80")
    :param ctr_hex: URLから取得したカウンター (例: "000005")
    :param mac_hex: URLから取得した検証対象のMAC (例: "5A81...")
    :param master_key_hex: タグのSDM用キー (例: "00000000000000000000000000000000")
    """
    # 1. データ形式の変換
    uid_bytes = binascii.unhexlify(uid_hex)
    ctr_bytes = binascii.unhexlify(ctr_hex)
    key_bytes = binascii.unhexlify(master_key_hex)

    # NTAG 424 DNAのカウンターはリトルエンディアンで扱われることが一般的ですが、
    # URLにミラーされる際はASCII Hexなので、そのままの並びでSVに使用される場合と
    # 逆順(Little Endian)にする場合があります。
    # 通常のSDM実装では「Little Endian」として扱う必要があります。
    ctr_bytes_le = ctr_bytes[::-1]

    # 2. セッション鍵生成用のSystem Vector (SV) の作成
    # SV = 3C C3 00 01 00 80 + UID(7bytes) + Counter(3bytes, Little Endian)
    # "3C C3 00 01 00 80" は NXP AN12196 で定義される定数(File 2の場合)
    sv_prefix = binascii.unhexlify("3CC300010080")
    sv_bytes = sv_prefix + uid_bytes + ctr_bytes_le

    c_ses = CMAC.new(key_bytes, ciphermod=AES)
    c_ses.update(sv_bytes)
    session_key = c_ses.digest()

    # 4. SDM-MAC の計算
    # 入力データは「空 (empty)」またはミラーされたデータそのもの。
    # 標準的なSDM設定(File Dataの暗号化なし)では、MACは空入力に対して計算されます。
    c_mac = CMAC.new(session_key, ciphermod=AES)
    c_mac.update(b"")  # 空データ
    full_mac = c_mac.digest()

    # 5. トランケーション (短縮)
    # フルCMAC(16バイト)から、奇数インデックス(1, 3, 5...)のバイトを抽出して8バイトにします。  # noqa: E501
    # (仕様書では "Even bytes" と書かれることがありますが、実装上は [1::2] が正解となるケースが大半です)  # noqa: E501
    calculated_mac = full_mac[1::2]

    print(f"Calculated MAC: {calculated_mac.hex().upper()}")
    print(f"Received MAC:   {mac_hex.upper()}")


if __name__ == "__main__":
    for d in [
        "6E5AC0DB03AF248225BF3A97B2ED5756",
    ]:
        ret = aes_decrypt(
            bytes.fromhex("00000000000000000000000000000000"),
            binascii.unhexlify(d),
        )
        print(toHexString(list(ret)[1:8]))
        print(toHexString(list(ret)[8:11]))

    # https://www.yahoo.co.jp/u=6E5AC0DB03AF248225BF3A97B2ED5756&c=CCCCCC&m=9C9F8040C3E2AD58
    verify_sdm_mac(
        uid_hex="044C2F82322190",
        ctr_hex="250000",
        mac_hex="9C9F8040C3E2AD58",
        master_key_hex="00000000000000000000000000000000",
    )
