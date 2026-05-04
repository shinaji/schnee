"""Tests for NTAG 424 DNA high-level helpers."""

from typing import TYPE_CHECKING, cast

import pytest
from Crypto.Cipher import AES
from Crypto.Hash import CMAC
from Crypto.Util.Padding import pad

from schnee.adapters.backend.pcsc import PcscBackend
from schnee.adapters.ntag.apdu import CommandAPDU, ResponseAPDU
from schnee.adapters.ntag.core import Ntag424, Ntag424Key, Session

if TYPE_CHECKING:
    from schnee.adapters.backend.contracts import ProfileReaderBackend

GET_KEY_VERSION_INS = 0x64
EXPECTED_KEY_VERSION = 0x11
SHORT_CHANGE_KEY_APDU_LENGTH = 47


class FakeApduClient:
    """Fake APDU client for key validation tests."""

    def __init__(self, *, key_versions: dict[int, int] | None = None) -> None:
        self.commands: list[list[int]] = []
        self.key_versions = key_versions or {}

    def send_apdu(
        self,
        command: CommandAPDU | list[int],
        *,
        check_status: bool = True,
        ok_statuses: tuple[tuple[int, int], ...] | None = None,
    ) -> ResponseAPDU:
        """Record commands and return configured GetKeyVersion responses."""
        _ = check_status, ok_statuses
        command = command.to_list() if isinstance(command, CommandAPDU) else command
        self.commands.append(command)
        if command[1] == GET_KEY_VERSION_INS:
            return ResponseAPDU(data=[self.key_versions[command[5]]], sw1=0x90, sw2=0)
        return ResponseAPDU(data=[], sw1=0x90, sw2=0)


def test_session_requires_explicit_master_key() -> None:
    """Session construction fails unless the caller supplies the master key."""
    with pytest.raises(Session.SessionError, match="master_key"):
        Session(connection=cast("ProfileReaderBackend", object()))


def test_ntag424_requires_explicit_master_key_before_reader_lookup() -> None:
    """Ntag424 construction fails before any reader I/O without a master key."""
    with pytest.raises(ValueError, match="master_key"):
        Ntag424(backend_name="pcsc:Reader A")


def test_ntag424_exposes_factory_default_key_constant() -> None:
    """Factory-default key usage is explicit at the call site."""
    assert bytes(16) == Ntag424.FACTORY_DEFAULT_KEY


def test_ntag424_accepts_explicit_factory_default_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ntag424 accepts the explicit factory-default key constant."""

    class FakeClient:
        """Fake APDU client for constructor coverage."""

    backend = object.__new__(PcscBackend)
    backend.client = FakeClient()

    def get_backend(_name: str) -> PcscBackend:
        return backend

    monkeypatch.setattr(
        "schnee.adapters.ntag.core.Backend.get",
        get_backend,
    )

    ntag = Ntag424(
        backend_name="pcsc:Reader A",
        master_key=Ntag424.FACTORY_DEFAULT_KEY,
    )

    assert ntag.backend is backend
    assert ntag.connection is backend
    assert ntag.session.master_key == Ntag424.FACTORY_DEFAULT_KEY


def test_validate_keys_authenticates_expected_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Key validation succeeds when authentication and key version match."""
    client = FakeApduClient(key_versions={2: EXPECTED_KEY_VERSION})
    backend = object.__new__(PcscBackend)
    backend.client = client

    def get_backend(_name: str) -> PcscBackend:
        return backend

    monkeypatch.setattr(
        "schnee.adapters.ntag.core.Backend.get",
        get_backend,
    )

    def authenticate_ev2_first(self: Session) -> tuple[bytes, bytes, bytes, bytes]:
        assert self.key_no == int(Ntag424Key.APP_KEY_2)
        assert self.master_key == bytes.fromhex("11" * 16)
        assert client.commands[-1] == [0x90, 0x64, 0x00, 0x00, 0x01, 0x02, 0x00]
        return bytes(16), bytes(16), bytes(4), bytes(16)

    monkeypatch.setattr(
        "schnee.adapters.ntag.core.Session.authenticate_ev2_first",
        authenticate_ev2_first,
    )

    results = Ntag424.validate_keys(
        backend_name="pcsc:Reader A",
        keys=[
            Ntag424.KeyValidation(
                key_no=Ntag424Key.APP_KEY_2,
                key=bytes.fromhex("11" * 16),
                key_version=EXPECTED_KEY_VERSION,
            ),
        ],
    )

    assert results[0].valid is True
    assert results[0].authenticated is True
    assert results[0].actual_key_version == EXPECTED_KEY_VERSION
    assert results[0].key_version_matches is True


def test_change_key_crc32_fcs_matches_ntag_example() -> None:
    """NTAG 424 ChangeKey CRC32 uses complemented little-endian FCS bytes."""
    assert (
        Ntag424.change_key_crc32(
            bytes.fromhex("F3847D627727ED3BC9C4CC050489B966"),
        ).hex()
        == "789dfadc"
    )


def test_build_change_key_apdu_for_non_master_key() -> None:
    """ChangeKey for key 1..4 encrypts XORed key data and appends EV2 MAC."""
    update = Ntag424.KeyUpdate(
        key_no=Ntag424Key.APP_KEY_2,
        new_key=bytes.fromhex("F3847D627727ED3BC9C4CC050489B966"),
        key_version=0x01,
        old_key=bytes(16),
    )
    session_key_enc = bytes.fromhex("4CF3CB41A22583A61E89B158D252FC53")
    session_key_mac = bytes.fromhex("5529860B2FC5FB6154B7F28361D30BF9")
    ti = bytes.fromhex("7614281A")

    apdu = Ntag424.build_change_key_apdu(
        update=update,
        session_key_enc=session_key_enc,
        session_key_mac=session_key_mac,
        ti=ti,
        cmd_ctr=2,
    )

    plain_key_data = bytes.fromhex(
        "F3847D627727ED3BC9C4CC050489B96601789DFADC",
    )
    iv_input = bytes.fromhex("A55A7614281A02000000000000000000")
    iv = AES.new(session_key_enc, AES.MODE_CBC, bytes(16)).encrypt(iv_input)
    encrypted_key_data = AES.new(session_key_enc, AES.MODE_CBC, iv).encrypt(
        pad(plain_key_data, block_size=16, style="iso7816"),
    )
    mac_input = b"\xc4\x02\x00" + ti + b"\x02" + encrypted_key_data
    mac = CMAC.new(session_key_mac, ciphermod=AES)
    mac.update(mac_input)
    truncated_mac = mac.digest()[1::2]

    assert apdu == [
        0x90,
        0xC4,
        0x00,
        0x00,
        0x29,
        0x02,
        *encrypted_key_data,
        *truncated_mac,
        0x00,
    ]


def test_build_change_key_apdu_for_master_key_uses_short_key_data() -> None:
    """ChangeKey for key 0 uses NewKey || KeyVer before padding."""
    update = Ntag424.KeyUpdate(
        key_no=Ntag424Key.APP_MASTER,
        new_key=bytes.fromhex("00112233445566778899AABBCCDDEEFF"),
        key_version=0x12,
    )

    apdu = Ntag424.build_change_key_apdu(
        update=update,
        session_key_enc=bytes.fromhex("4CF3CB41A22583A61E89B158D252FC53"),
        session_key_mac=bytes.fromhex("5529860B2FC5FB6154B7F28361D30BF9"),
        ti=bytes.fromhex("7614281A"),
        cmd_ctr=0,
    )

    assert apdu[:6] == [0x90, 0xC4, 0x00, 0x00, 0x29, 0x00]
    assert len(apdu) == SHORT_CHANGE_KEY_APDU_LENGTH


def test_build_change_key_apdu_requires_old_key_for_non_master_key() -> None:
    """Changing key 1..4 requires the current key material."""
    with pytest.raises(Ntag424.MissingOldKeyError):
        Ntag424.build_change_key_apdu(
            update=Ntag424.KeyUpdate(
                key_no=Ntag424Key.APP_KEY_1,
                new_key=bytes(16),
            ),
            session_key_enc=bytes(16),
            session_key_mac=bytes(16),
            ti=bytes(4),
            cmd_ctr=0,
        )


def test_key_update_accepts_int_compatible_key_numbers() -> None:
    """The low-level update model normalizes existing numeric key callers."""
    update = Ntag424.KeyUpdate.model_validate(
        {
            "key_no": int(Ntag424Key.APP_KEY_2),
            "new_key": bytes(16),
            "old_key": bytes(16),
        },
    )

    assert update.key_no is Ntag424Key.APP_KEY_2


def test_key_update_fields_have_descriptions() -> None:
    """KeyUpdate exposes descriptions for generated schemas."""
    properties = Ntag424.KeyUpdate.model_json_schema()["properties"]

    assert properties["key_no"]["description"] == "Application key number to update."
    assert properties["new_key"]["description"].startswith("New AES-128 key bytes")
    assert properties["key_version"]["description"].startswith("New one-byte")
    assert properties["old_key"]["description"].startswith("Current AES-128 key bytes")
