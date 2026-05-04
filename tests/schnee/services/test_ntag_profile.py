"""Tests for NTAG profile services."""

import pytest
from pydantic import ValidationError

from schnee.adapters.backend import PcscBackend
from schnee.adapters.ntag.apdu import CommandAPDU, ResponseAPDU
from schnee.adapters.ntag.core import Ntag424Key, Session
from schnee.services.ntag_profile import (
    Ntag424KeyUpdateRequest,
    Ntag424KeyValidationRequest,
    SetNtag424SdmService,
    UpdateNtag424KeysService,
    ValidateNtag424KeysService,
    WriteNdefUrlService,
)

GET_KEY_VERSION_INS = 0x64
EXPECTED_KEY_VERSION = 0x11
MISMATCHED_KEY_VERSION = 0x02


class FakeApduClient:
    """Fake APDU client for service-level validation tests."""

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


def test_ntag424_key_update_request_requires_old_key_for_non_master() -> None:
    """Non-master key updates need the current key for ChangeKey XOR data."""
    with pytest.raises(ValidationError, match="old_key"):
        Ntag424KeyUpdateRequest(key_no=Ntag424Key.APP_KEY_1, new_key=bytes(16))


def test_ntag424_key_update_request_accepts_int_key_number() -> None:
    """Service requests keep accepting serialized numeric key numbers."""
    update = Ntag424KeyUpdateRequest.model_validate(
        {
            "key_no": int(Ntag424Key.APP_KEY_1),
            "new_key": bytes(16),
            "old_key": bytes(16),
        },
    )

    assert update.key_no is Ntag424Key.APP_KEY_1


def test_ntag424_key_update_request_fields_have_descriptions() -> None:
    """Key update requests expose descriptions for generated schemas."""
    properties = Ntag424KeyUpdateRequest.model_json_schema()["properties"]

    assert properties["key_version"]["description"].startswith("New one-byte")


def test_update_ntag424_keys_request_rejects_duplicate_key_slots() -> None:
    """Each key slot can be updated only once per service request."""
    update = Ntag424KeyUpdateRequest(
        key_no=Ntag424Key.APP_MASTER,
        new_key=bytes(16),
        key_version=1,
    )

    with pytest.raises(ValidationError, match="duplicate"):
        UpdateNtag424KeysService.Request(
            backend_name="pcsc:Reader A",
            master_key=bytes(16),
            updates=[update, update],
        )


def test_write_ndef_url_service_delegates_to_pcsc_backend(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """NDEF writing is exposed independently from SDM configuration."""
    backend = object.__new__(PcscBackend)
    written_urls: list[str] = []
    backend.write_ndef_url = written_urls.append

    monkeypatch.setattr(
        "schnee.services.ntag_profile.Backend.get",
        lambda _name: backend,
    )

    WriteNdefUrlService.call(
        WriteNdefUrlService.Request(
            backend_name="pcsc:Reader A",
            url="https://example.com",
        ),
    )

    assert written_urls == ["https://example.com"]


def test_write_ndef_url_service_can_authenticate_ntag424(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """NDEF-only writes can still authenticate for protected NTAG 424 files."""
    calls: list[str] = []

    class FakeNtag424:
        """Fake NTAG 424 helper for authenticated NDEF writes."""

        def __init__(self, *, backend_name: str, master_key: bytes) -> None:
            assert backend_name == "pcsc:Reader A"
            assert master_key == bytes(16)

        def write_ndef_url_with_auth(self, url: str) -> None:
            calls.append(url)

    monkeypatch.setattr("schnee.services.ntag_profile.Ntag424", FakeNtag424)

    WriteNdefUrlService.call(
        WriteNdefUrlService.Request(
            backend_name="pcsc:Reader A",
            url="https://example.com",
            ntag424_master_key=bytes(16),
        ),
    )

    assert calls == ["https://example.com"]


def test_write_ndef_url_service_validates_optional_ntag424_key() -> None:
    """Authenticated NTAG 424 NDEF writes require a full AES-128 key."""
    with pytest.raises(ValidationError, match="ntag424_master_key"):
        WriteNdefUrlService.Request(
            backend_name="pcsc:Reader A",
            url="https://example.com",
            ntag424_master_key=b"short",
        )


def test_set_ntag424_sdm_request_requires_url_template_when_enabling() -> None:
    """Enabling SDM needs the URL template used to calculate mirror offsets."""
    with pytest.raises(ValidationError, match="url_template"):
        SetNtag424SdmService.Request(
            backend_name="pcsc:Reader A",
            master_key=bytes(16),
            enabled=True,
        )


def test_set_ntag424_sdm_service_delegates_to_ntag424(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The SDM service handles enable/disable without writing NDEF content."""
    calls: list[tuple[bool, str | None, int]] = []

    class FakeNtag424:
        """Fake NTAG 424 helper for service delegation."""

        def __init__(self, *, backend_name: str, master_key: bytes) -> None:
            assert backend_name == "pcsc:Reader A"
            assert master_key == bytes(16)

        def set_sdm_enabled(
            self,
            *,
            enabled: bool,
            url_template: str | None,
            cmd_ctr: int,
        ) -> None:
            calls.append((enabled, url_template, cmd_ctr))

    monkeypatch.setattr("schnee.services.ntag_profile.Ntag424", FakeNtag424)

    SetNtag424SdmService.call(
        SetNtag424SdmService.Request(
            backend_name="pcsc:Reader A",
            master_key=bytes(16),
            enabled=False,
            cmd_ctr_start=4,
        ),
    )

    assert calls == [(False, None, 4)]


def test_set_ntag424_sdm_service_defaults_command_counter_to_zero(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """SDM-only changes use command counter 0 after a fresh authentication."""
    calls: list[int] = []

    class FakeNtag424:
        """Fake NTAG 424 helper for command-counter delegation."""

        def __init__(self, *, backend_name: str, master_key: bytes) -> None:
            _ = backend_name, master_key

        def set_sdm_enabled(
            self,
            *,
            enabled: bool,
            url_template: str | None,
            cmd_ctr: int,
        ) -> None:
            _ = enabled, url_template
            calls.append(cmd_ctr)

    monkeypatch.setattr("schnee.services.ntag_profile.Ntag424", FakeNtag424)

    SetNtag424SdmService.call(
        SetNtag424SdmService.Request(
            backend_name="pcsc:Reader A",
            master_key=bytes(16),
            enabled=False,
        ),
    )

    assert calls == [0]


def test_validate_ntag424_keys_service_authenticates_expected_key(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Validation succeeds when AuthenticateEV2First and key version match."""
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
        return bytes(16), bytes(16), bytes(4), bytes(16)

    monkeypatch.setattr(
        "schnee.adapters.ntag.core.Session.authenticate_ev2_first",
        authenticate_ev2_first,
    )

    results = ValidateNtag424KeysService.call(
        ValidateNtag424KeysService.Request(
            backend_name="pcsc:Reader A",
            keys=[
                Ntag424KeyValidationRequest(
                    key_no=Ntag424Key.APP_KEY_2,
                    key=bytes.fromhex("11" * 16),
                    key_version=EXPECTED_KEY_VERSION,
                ),
            ],
        ),
    )

    assert results[0].valid is True
    assert results[0].authenticated is True
    assert results[0].actual_key_version == EXPECTED_KEY_VERSION
    assert results[0].key_version_matches is True


def test_validate_ntag424_keys_service_reports_version_mismatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Validation fails when the requested key version does not match the tag."""
    client = FakeApduClient(key_versions={1: MISMATCHED_KEY_VERSION})
    backend = object.__new__(PcscBackend)
    backend.client = client

    def get_backend(_name: str) -> PcscBackend:
        return backend

    def authenticate_ev2_first(
        _session: Session,
    ) -> tuple[bytes, bytes, bytes, bytes]:
        return bytes(16), bytes(16), bytes(4), bytes(16)

    monkeypatch.setattr(
        "schnee.adapters.ntag.core.Backend.get",
        get_backend,
    )
    monkeypatch.setattr(
        "schnee.adapters.ntag.core.Session.authenticate_ev2_first",
        authenticate_ev2_first,
    )

    results = ValidateNtag424KeysService.call(
        ValidateNtag424KeysService.Request(
            backend_name="pcsc:Reader A",
            keys=[
                Ntag424KeyValidationRequest(
                    key_no=Ntag424Key.APP_KEY_1,
                    key=bytes(16),
                    key_version=0x01,
                ),
            ],
        ),
    )

    assert results[0].valid is False
    assert results[0].authenticated is True
    assert results[0].actual_key_version == MISMATCHED_KEY_VERSION
    assert results[0].key_version_matches is False
