"""Services for NTAG profile operations."""

from __future__ import annotations

import sys
from typing import ClassVar, Self

from pydantic import ConfigDict, Field, model_validator
from smartcard.Exceptions import CardConnectionException

from schnee.adapters.backend import PcscBackend
from schnee.adapters.backend.core import Backend
from schnee.adapters.backend.pcsc import PcscApduClient, PcscReaderProvider
from schnee.adapters.ntag.core import Ntag424, Ntag424Key, Session
from schnee.adapters.ntag.profile import NtagProfile
from schnee.adapters.ntag.utils import PlaceholderNotFoundError
from schnee.services.base import Service, ServiceError

AES_KEY_SIZE = 16


class ReadNtagProfileServiceError(ServiceError):
    """Base exception for read NTAG profile service errors."""

    msg: ClassVar[str] = "Read NTAG profile service error"


class ReadNtagProfileBackendNotFoundError(ReadNtagProfileServiceError):
    """Raised when the configured profile backend is not available."""

    msg: ClassVar[str] = "Read NTAG profile backend is not available"


class ReadNtagProfileReaderError(ReadNtagProfileServiceError):
    """Raised when PC/SC reader discovery fails."""

    msg: ClassVar[str] = "Read NTAG profile reader discovery failed"


class ReadNtagProfileConnectionError(ReadNtagProfileServiceError):
    """Raised when PC/SC card communication fails."""

    msg: ClassVar[str] = "Read NTAG profile card communication failed"


class ReadNtagProfileApduError(ReadNtagProfileServiceError):
    """Raised when PC/SC APDU exchange fails."""

    msg: ClassVar[str] = "Read NTAG profile APDU exchange failed"


class ReadNtagProfileBackendError(ReadNtagProfileServiceError):
    """Raised when the PC/SC backend cannot read the profile."""

    msg: ClassVar[str] = "Read NTAG profile backend operation failed"


class WriteNdefUrlServiceError(ServiceError):
    """Base exception for write NDEF URL service errors."""

    msg: ClassVar[str] = "Write NDEF URL service error"


class WriteNdefUrlBackendNotFoundError(WriteNdefUrlServiceError):
    """Raised when the requested profile backend is not available."""

    msg: ClassVar[str] = "Write NDEF URL backend is not available"


class WriteNdefUrlReaderError(WriteNdefUrlServiceError):
    """Raised when PC/SC reader discovery fails."""

    msg: ClassVar[str] = "Write NDEF URL reader discovery failed"


class WriteNdefUrlConnectionError(WriteNdefUrlServiceError):
    """Raised when PC/SC card communication fails."""

    msg: ClassVar[str] = "Write NDEF URL card communication failed"


class WriteNdefUrlApduError(WriteNdefUrlServiceError):
    """Raised when PC/SC APDU exchange fails."""

    msg: ClassVar[str] = "Write NDEF URL APDU exchange failed"


class WriteNdefUrlBackendError(WriteNdefUrlServiceError):
    """Raised when the backend cannot write the NDEF URL."""

    msg: ClassVar[str] = "Write NDEF URL backend operation failed"


class WriteNdefUrlNtag424Error(WriteNdefUrlServiceError):
    """Raised when the NTAG 424 adapter cannot write the NDEF URL."""

    msg: ClassVar[str] = "Write NDEF URL NTAG 424 operation failed"


class WriteNdefUrlSessionError(WriteNdefUrlServiceError):
    """Raised when NTAG 424 authentication fails."""

    msg: ClassVar[str] = "Write NDEF URL NTAG 424 session failed"


class UpdateNtag424KeysServiceError(ServiceError):
    """Base exception for update NTAG 424 keys service errors."""

    msg: ClassVar[str] = "Update NTAG 424 keys service error"


class UpdateNtag424KeysBackendNotFoundError(UpdateNtag424KeysServiceError):
    """Raised when the requested profile backend is not available."""

    msg: ClassVar[str] = "Update NTAG 424 keys backend is not available"


class UpdateNtag424KeysReaderError(UpdateNtag424KeysServiceError):
    """Raised when PC/SC reader discovery fails."""

    msg: ClassVar[str] = "Update NTAG 424 keys reader discovery failed"


class UpdateNtag424KeysConnectionError(UpdateNtag424KeysServiceError):
    """Raised when PC/SC card communication fails."""

    msg: ClassVar[str] = "Update NTAG 424 keys card communication failed"


class UpdateNtag424KeysApduError(UpdateNtag424KeysServiceError):
    """Raised when PC/SC APDU exchange fails."""

    msg: ClassVar[str] = "Update NTAG 424 keys APDU exchange failed"


class UpdateNtag424KeysBackendError(UpdateNtag424KeysServiceError):
    """Raised when the backend cannot update NTAG 424 keys."""

    msg: ClassVar[str] = "Update NTAG 424 keys backend operation failed"


class UpdateNtag424KeysNtag424Error(UpdateNtag424KeysServiceError):
    """Raised when the NTAG 424 adapter rejects a key update."""

    msg: ClassVar[str] = "Update NTAG 424 keys adapter operation failed"


class UpdateNtag424KeysSessionError(UpdateNtag424KeysServiceError):
    """Raised when NTAG 424 authentication fails during key updates."""

    msg: ClassVar[str] = "Update NTAG 424 keys session failed"


class ValidateNtag424KeysServiceError(ServiceError):
    """Base exception for validate NTAG 424 keys service errors."""

    msg: ClassVar[str] = "Validate NTAG 424 keys service error"


class ValidateNtag424KeysBackendNotFoundError(ValidateNtag424KeysServiceError):
    """Raised when the requested profile backend is not available."""

    msg: ClassVar[str] = "Validate NTAG 424 keys backend is not available"


class ValidateNtag424KeysReaderError(ValidateNtag424KeysServiceError):
    """Raised when PC/SC reader discovery fails."""

    msg: ClassVar[str] = "Validate NTAG 424 keys reader discovery failed"


class ValidateNtag424KeysConnectionError(ValidateNtag424KeysServiceError):
    """Raised when PC/SC card communication fails before validation starts."""

    msg: ClassVar[str] = "Validate NTAG 424 keys card communication failed"


class ValidateNtag424KeysApduError(ValidateNtag424KeysServiceError):
    """Raised when PC/SC APDU exchange fails before validation starts."""

    msg: ClassVar[str] = "Validate NTAG 424 keys APDU exchange failed"


class ValidateNtag424KeysBackendError(ValidateNtag424KeysServiceError):
    """Raised when the backend cannot validate NTAG 424 keys."""

    msg: ClassVar[str] = "Validate NTAG 424 keys backend operation failed"


class ValidateNtag424KeysNtag424Error(ValidateNtag424KeysServiceError):
    """Raised when the NTAG 424 adapter rejects key validation."""

    msg: ClassVar[str] = "Validate NTAG 424 keys adapter operation failed"


class ValidateNtag424KeysSessionError(ValidateNtag424KeysServiceError):
    """Raised when NTAG 424 session setup fails before validation starts."""

    msg: ClassVar[str] = "Validate NTAG 424 keys session failed"


class SetNtag424SdmServiceError(ServiceError):
    """Base exception for set NTAG 424 SDM service errors."""

    msg: ClassVar[str] = "Set NTAG 424 SDM service error"


class SetNtag424SdmBackendNotFoundError(SetNtag424SdmServiceError):
    """Raised when the requested profile backend is not available."""

    msg: ClassVar[str] = "Set NTAG 424 SDM backend is not available"


class SetNtag424SdmReaderError(SetNtag424SdmServiceError):
    """Raised when PC/SC reader discovery fails."""

    msg: ClassVar[str] = "Set NTAG 424 SDM reader discovery failed"


class SetNtag424SdmConnectionError(SetNtag424SdmServiceError):
    """Raised when PC/SC card communication fails."""

    msg: ClassVar[str] = "Set NTAG 424 SDM card communication failed"


class SetNtag424SdmApduError(SetNtag424SdmServiceError):
    """Raised when PC/SC APDU exchange fails."""

    msg: ClassVar[str] = "Set NTAG 424 SDM APDU exchange failed"


class SetNtag424SdmBackendError(SetNtag424SdmServiceError):
    """Raised when the backend cannot change SDM state."""

    msg: ClassVar[str] = "Set NTAG 424 SDM backend operation failed"


class SetNtag424SdmNtag424Error(SetNtag424SdmServiceError):
    """Raised when the NTAG 424 adapter cannot change SDM state."""

    msg: ClassVar[str] = "Set NTAG 424 SDM adapter operation failed"


class SetNtag424SdmSessionError(SetNtag424SdmServiceError):
    """Raised when NTAG 424 authentication fails while changing SDM."""

    msg: ClassVar[str] = "Set NTAG 424 SDM session failed"


class SetNtag424SdmUrlTemplateError(SetNtag424SdmServiceError):
    """Raised when SDM URL template placeholders cannot be resolved."""

    msg: ClassVar[str] = "Set NTAG 424 SDM URL template is invalid"


class ReadNtagProfileService(Service[NtagProfile]):
    """Read the current profile from an NTAG profile backend."""

    class Request(Service.Request):
        """Request for reading an NTAG profile."""

        backend_name: str = Field(
            default="pcsc",
            description="Backend name, for example `pcsc` or `pcsc:<reader name>`.",
        )

        model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    req: Request

    def process(self) -> NtagProfile:
        """Read the current NTAG profile."""
        try:
            backend = Backend.get(self.req.backend_name)
            return backend.read_profile()
        except Backend.BackendNotFoundError as exc:
            raise ReadNtagProfileBackendNotFoundError from exc
        except PcscReaderProvider.PcscReaderProviderError as exc:
            raise ReadNtagProfileReaderError from exc
        except CardConnectionException as exc:
            raise ReadNtagProfileConnectionError from exc
        except PcscApduClient.PcscApduClientError as exc:
            raise ReadNtagProfileApduError from exc
        except PcscBackend.PcscBackendError as exc:
            raise ReadNtagProfileBackendError from exc


class WriteNdefUrlService(Service[None]):
    """Write a URL NDEF record to NTAG 424 DNA or NTAG21x tags."""

    class Request(Service.Request):
        """Request for writing one URL NDEF record."""

        backend_name: str = Field(
            default="pcsc",
            description="Backend name, for example `pcsc` or `pcsc:<reader name>`.",
        )
        url: str = Field(description="URL to write as a single NDEF URI record.")
        ntag424_master_key: bytes | None = Field(
            default=None,
            min_length=AES_KEY_SIZE,
            max_length=AES_KEY_SIZE,
            description=(
                "Current NTAG 424 DNA application master key. Provide this when "
                "the NTAG 424 NDEF file requires authenticated writes."
            ),
        )

    req: Request

    def process(self) -> None:
        """Write the requested NDEF URL."""
        try:
            if self.req.ntag424_master_key is not None:
                Ntag424(
                    backend_name=self.req.backend_name,
                    master_key=self.req.ntag424_master_key,
                ).write_ndef_url_with_auth(self.req.url)
                return

            backend = Backend.get(self.req.backend_name)
            backend.write_ndef_url(self.req.url)
        except Backend.BackendNotFoundError as exc:
            raise WriteNdefUrlBackendNotFoundError from exc
        except PcscReaderProvider.PcscReaderProviderError as exc:
            raise WriteNdefUrlReaderError from exc
        except CardConnectionException as exc:
            raise WriteNdefUrlConnectionError from exc
        except PcscApduClient.PcscApduClientError as exc:
            raise WriteNdefUrlApduError from exc
        except PcscBackend.PcscBackendError as exc:
            raise WriteNdefUrlBackendError from exc
        except Ntag424.Ntag424Error as exc:
            raise WriteNdefUrlNtag424Error from exc
        except Session.SessionError as exc:
            raise WriteNdefUrlSessionError from exc


class Ntag424KeyUpdateRequest(Service.Request):
    """Request item for one NTAG 424 DNA application-key update."""

    key_no: Ntag424Key = Field(description="Application key number to update")
    new_key: bytes = Field(description="New AES-128 key bytes")
    key_version: int = Field(
        default=0,
        ge=0,
        le=0xFF,
        description="New one-byte key version stored with the key.",
    )
    old_key: bytes | None = Field(
        default=None,
        description=(
            "Current key bytes. Required for key 1..4 ChangeKey cryptograms. "
            "Use Ntag424.FACTORY_DEFAULT_KEY for factory-default app keys."
        ),
    )

    class InvalidKeyLengthError(ValueError):
        """Raised when a supplied AES key is not 16 bytes."""

    class MissingOldKeyError(ValueError):
        """Raised when a non-master key update does not include the old key."""

    @model_validator(mode="after")
    def validate_update(self) -> Self:
        """Validate NTAG 424 ChangeKey constraints."""
        if len(self.new_key) != AES_KEY_SIZE:
            msg = "new_key must be 16 bytes"
            raise self.InvalidKeyLengthError(msg)
        if self.old_key is not None and len(self.old_key) != AES_KEY_SIZE:
            msg = "old_key must be 16 bytes"
            raise self.InvalidKeyLengthError(msg)
        if self.key_no is not Ntag424Key.APP_MASTER and self.old_key is None:
            msg = (
                "old_key is required when changing key 1..4; "
                "use Ntag424.FACTORY_DEFAULT_KEY for factory-default app keys"
            )
            raise self.MissingOldKeyError(msg)
        return self


class Ntag424KeyValidationRequest(Service.Request):
    """Request item for validating one NTAG 424 DNA application key."""

    key_no: Ntag424Key = Field(description="Application key number to validate")
    key: bytes = Field(description="Expected AES-128 key bytes")
    key_version: int | None = Field(
        default=None,
        ge=0,
        le=0xFF,
        description="Optional expected one-byte key version stored with the key.",
    )

    class InvalidKeyLengthError(ValueError):
        """Raised when a supplied AES key is not 16 bytes."""

    @model_validator(mode="after")
    def validate_key(self) -> Self:
        """Validate NTAG 424 key validation constraints."""
        if len(self.key) != AES_KEY_SIZE:
            msg = "key must be 16 bytes"
            raise self.InvalidKeyLengthError(msg)
        return self


class UpdateNtag424KeysService(Service[None]):
    """Update NTAG 424 DNA application keys 0 through 4.

    Use `Ntag424.FACTORY_DEFAULT_KEY` explicitly when updating a factory-default tag.
    """

    class Request(Service.Request):
        """Request for updating one or more NTAG 424 DNA keys."""

        backend_name: str = Field(
            default="pcsc",
            description="Backend name, for example `pcsc` or `pcsc:<reader name>`.",
        )
        master_key: bytes = Field(
            min_length=AES_KEY_SIZE,
            max_length=AES_KEY_SIZE,
            description="Current application master key",
        )
        updates: list[Ntag424KeyUpdateRequest] = Field(
            min_length=1,
            max_length=5,
            description="Key updates to apply. Key 0 is applied last.",
        )
        cmd_ctr_start: int = Field(default=0, ge=0, le=0xFFFF)

        class InvalidMasterKeyLengthError(ValueError):
            """Raised when the application master key is not 16 bytes."""

        class DuplicateKeyUpdateError(ValueError):
            """Raised when the same key slot is requested more than once."""

        @model_validator(mode="after")
        def validate_request(self) -> Self:
            """Validate service request constraints."""
            if len(self.master_key) != AES_KEY_SIZE:
                msg = "master_key must be 16 bytes"
                raise self.InvalidMasterKeyLengthError(msg)

            key_numbers = [update.key_no for update in self.updates]
            if len(key_numbers) != len(set(key_numbers)):
                msg = "updates must not contain duplicate key_no values"
                raise self.DuplicateKeyUpdateError(msg)
            return self

    req: Request

    def process(self) -> None:
        """Update requested NTAG 424 DNA application keys."""
        try:
            ntag = Ntag424(
                backend_name=self.req.backend_name,
                master_key=self.req.master_key,
            )
            ntag.update_keys(
                [
                    Ntag424.KeyUpdate(
                        key_no=update.key_no,
                        new_key=update.new_key,
                        key_version=update.key_version,
                        old_key=update.old_key,
                    )
                    for update in self.req.updates
                ],
                cmd_ctr_start=self.req.cmd_ctr_start,
            )
        except Backend.BackendNotFoundError as exc:
            raise UpdateNtag424KeysBackendNotFoundError from exc
        except PcscReaderProvider.PcscReaderProviderError as exc:
            raise UpdateNtag424KeysReaderError from exc
        except CardConnectionException as exc:
            raise UpdateNtag424KeysConnectionError from exc
        except PcscApduClient.PcscApduClientError as exc:
            raise UpdateNtag424KeysApduError from exc
        except PcscBackend.PcscBackendError as exc:
            raise UpdateNtag424KeysBackendError from exc
        except Ntag424.Ntag424Error as exc:
            raise UpdateNtag424KeysNtag424Error from exc
        except Session.SessionError as exc:
            raise UpdateNtag424KeysSessionError from exc


class ValidateNtag424KeysService(Service[list[Ntag424.KeyValidationResult]]):
    """Validate NTAG 424 DNA application keys by authenticating with them."""

    class Request(Service.Request):
        """Request for validating one or more NTAG 424 DNA keys."""

        backend_name: str = Field(
            default="pcsc",
            description="Backend name, for example `pcsc` or `pcsc:<reader name>`.",
        )
        keys: list[Ntag424KeyValidationRequest] = Field(
            min_length=1,
            max_length=5,
            description="Expected keys to validate against the tag.",
        )

        class DuplicateKeyValidationError(ValueError):
            """Raised when the same key slot is requested more than once."""

        @model_validator(mode="after")
        def validate_request(self) -> Self:
            """Validate service request constraints."""
            key_numbers = [key.key_no for key in self.keys]
            if len(key_numbers) != len(set(key_numbers)):
                msg = "keys must not contain duplicate key_no values"
                raise self.DuplicateKeyValidationError(msg)
            return self

    req: Request

    def process(self) -> list[Ntag424.KeyValidationResult]:
        """Validate requested NTAG 424 DNA application keys."""
        try:
            return Ntag424.validate_keys(
                backend_name=self.req.backend_name,
                keys=[
                    Ntag424.KeyValidation(
                        key_no=key.key_no,
                        key=key.key,
                        key_version=key.key_version,
                    )
                    for key in self.req.keys
                ],
            )
        except Backend.BackendNotFoundError as exc:
            raise ValidateNtag424KeysBackendNotFoundError from exc
        except PcscReaderProvider.PcscReaderProviderError as exc:
            raise ValidateNtag424KeysReaderError from exc
        except CardConnectionException as exc:
            raise ValidateNtag424KeysConnectionError from exc
        except PcscApduClient.PcscApduClientError as exc:
            raise ValidateNtag424KeysApduError from exc
        except PcscBackend.PcscBackendError as exc:
            raise ValidateNtag424KeysBackendError from exc
        except Ntag424.Ntag424Error as exc:
            raise ValidateNtag424KeysNtag424Error from exc
        except Session.SessionError as exc:
            raise ValidateNtag424KeysSessionError from exc


class SetNtag424SdmService(Service[None]):
    """Enable or disable NTAG 424 DNA Secure Dynamic Messaging."""

    class Request(Service.Request):
        """Request for changing NTAG 424 DNA SDM state."""

        backend_name: str = Field(
            default="pcsc",
            description="Backend name, for example `pcsc` or `pcsc:<reader name>`.",
        )
        master_key: bytes = Field(
            min_length=AES_KEY_SIZE,
            max_length=AES_KEY_SIZE,
            description="Current application master key",
        )
        enabled: bool = Field(description="Whether SDM should be enabled")
        url_template: str | None = Field(
            default=None,
            description=(
                "URL template used to calculate SDM mirror offsets. Required when "
                "enabling SDM. Include `UUUUUUUUUUUUUU` for the 7-byte UID hex, "
                "`CCCCCC` for the 3-byte read counter hex, and "
                "`MMMMMMMMMMMMMMMM` for the 8-byte CMAC hex; for example "
                "`https://example.com/t?uid=UUUUUUUUUUUUUU&ctr=CCCCCC&mac="
                "MMMMMMMMMMMMMMMM`."
            ),
        )
        cmd_ctr_start: int = Field(
            default=0,
            ge=0,
            le=0xFFFF,
            description=(
                "EV2 command counter for ChangeFileSettings. Use the default 0 "
                "when this service authenticates and immediately changes SDM."
            ),
        )

        class MissingUrlTemplateError(ValueError):
            """Raised when enabling SDM without a URL template."""

        @model_validator(mode="after")
        def validate_request(self) -> Self:
            """Validate service request constraints."""
            if self.enabled and self.url_template is None:
                msg = "url_template is required when enabling SDM"
                raise self.MissingUrlTemplateError(msg)
            return self

    req: Request

    def process(self) -> None:
        """Apply the requested SDM state."""
        try:
            ntag = Ntag424(
                backend_name=self.req.backend_name,
                master_key=self.req.master_key,
            )
            ntag.set_sdm_enabled(
                enabled=self.req.enabled,
                url_template=self.req.url_template,
                cmd_ctr=self.req.cmd_ctr_start,
            )
        except Backend.BackendNotFoundError as exc:
            raise SetNtag424SdmBackendNotFoundError from exc
        except PcscReaderProvider.PcscReaderProviderError as exc:
            raise SetNtag424SdmReaderError from exc
        except CardConnectionException as exc:
            raise SetNtag424SdmConnectionError from exc
        except PcscApduClient.PcscApduClientError as exc:
            raise SetNtag424SdmApduError from exc
        except PcscBackend.PcscBackendError as exc:
            raise SetNtag424SdmBackendError from exc
        except Ntag424.Ntag424Error as exc:
            raise SetNtag424SdmNtag424Error from exc
        except Session.SessionError as exc:
            raise SetNtag424SdmSessionError from exc
        except PlaceholderNotFoundError as exc:
            raise SetNtag424SdmUrlTemplateError from exc


def main() -> int:
    """Run the profile read service from the command line."""
    try:
        print(ReadNtagProfileService.call(ReadNtagProfileService.Request()))
        print(
            UpdateNtag424KeysService.call(
                UpdateNtag424KeysService.Request(
                    backend_name="pcsc",
                    master_key=bytes(16),
                    updates=[
                        Ntag424KeyUpdateRequest(
                            key_no=Ntag424Key.APP_KEY_1,
                            new_key=bytes(16),
                            key_version=0,
                            old_key=bytes(16),
                        ),
                    ],
                )
            )
        )
        print(
            ValidateNtag424KeysService.call(
                ValidateNtag424KeysService.Request(
                    backend_name="pcsc",
                    keys=[
                        Ntag424KeyValidationRequest(
                            key_no=Ntag424Key.APP_MASTER, key=bytes(16), key_version=0
                        ),
                        Ntag424KeyValidationRequest(
                            key_no=Ntag424Key.APP_KEY_1,
                            key=bytes(16),
                            key_version=0,
                        ),
                        Ntag424KeyValidationRequest(
                            key_no=Ntag424Key.APP_KEY_2, key=bytes(16), key_version=0
                        ),
                        Ntag424KeyValidationRequest(
                            key_no=Ntag424Key.APP_KEY_3, key=bytes(16), key_version=0
                        ),
                        Ntag424KeyValidationRequest(
                            key_no=Ntag424Key.APP_KEY_4, key=bytes(16), key_version=0
                        ),
                    ],
                )
            )
        )
        WriteNdefUrlService.call(
            WriteNdefUrlService.Request(
                backend_name="pcsc",
                url="https://example.com/t?uid=UUUUUUUUUUUUUU&ctr=CCCCCC&mac="
                "MMMMMMMMMMMMMMMM",
                ntag424_master_key=bytes(16),
            )
        )
        SetNtag424SdmService.call(
            SetNtag424SdmService.Request(
                backend_name="pcsc",
                master_key=bytes(16),
                enabled=True,
                url_template="https://example.com/t?uid=UUUUUUUUUUUUUU&ctr=CCCCCC&mac="
                "MMMMMMMMMMMMMMMM",
            )
        )
    except ServiceError as exc:
        print(exc, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
