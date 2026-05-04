"""Services for NTAG profile operations."""

import sys
from typing import Self

from pydantic import ConfigDict, Field, model_validator

from schnee.adapters.backend import PcscBackend
from schnee.adapters.backend.core import Backend
from schnee.adapters.ntag.core import Ntag424, Ntag424Key
from schnee.adapters.ntag.profile import NtagProfile
from schnee.services.base import Service

AES_KEY_SIZE = 16


class ReadNtagProfileService(Service[NtagProfile]):
    """Read the current profile from an NTAG profile backend."""

    class Request(Service.Request):
        """Request for reading an NTAG profile."""

        model_config = ConfigDict(frozen=True, arbitrary_types_allowed=True)

    def process(self) -> NtagProfile:
        """Read the current NTAG profile."""
        backend = Backend.get(name="pcsc")
        return backend.read_profile()


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
            description="Backend name, for example `pcsc` or `pcsc:<reader name>`.",
        )
        master_key: bytes = Field(description="Current application master key")
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


class ValidateNtag424KeysService(Service[list[Ntag424.KeyValidationResult]]):
    """Validate NTAG 424 DNA application keys by authenticating with them."""

    class Request(Service.Request):
        """Request for validating one or more NTAG 424 DNA keys."""

        backend_name: str = Field(
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


def main() -> int:
    """Run the profile read service from the command line."""
    try:
        ReadNtagProfileService.call(ReadNtagProfileService.Request())
    except PcscBackend.UnsupportedProfileReadError as exc:
        print(exc, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
