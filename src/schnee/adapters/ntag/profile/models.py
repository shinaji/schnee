"""Pydantic models for NTAG profile state."""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal, Self

from pydantic import BaseModel, Field, HttpUrl, model_validator

if TYPE_CHECKING:
    from .planning import ChangePlan

TagType = Literal["NTAG213", "NTAG215", "NTAG216", "NTAG424DNA"]


class NdefRecord(BaseModel):
    """Editable NDEF record."""

    type: Literal["url", "text"] = Field(description="NDEF record kind")
    value: str = Field(description="Record payload")

    @model_validator(mode="after")
    def validate_record(self) -> Self:
        """Validate record-specific payload constraints."""
        if self.type == "url":
            HttpUrl(self.value)
        return self


class TagInfo(BaseModel):
    """Static tag metadata."""

    type: TagType = Field(description="Detected NTAG product family")
    uid: str = Field(description="Tag UID as uppercase hex")


class NdefProfile(BaseModel):
    """NDEF state exposed as editable profile data."""

    present: bool = Field(
        default=True,
        description="Whether an NDEF message is present on the tag",
    )
    records: list[NdefRecord] = Field(
        default_factory=list,
        description="NDEF records stored in the editable NDEF file",
    )


class SdmProfile(BaseModel):
    """Secure Dynamic Messaging settings."""

    enabled: bool = Field(
        default=False,
        description="Whether Secure Dynamic Messaging is enabled",
    )
    uid_mirror: bool = Field(
        default=False,
        description="Whether the tag UID is mirrored into the NDEF URL",
    )
    counter_mirror: bool = Field(
        default=False,
        description="Whether the read counter is mirrored into the NDEF URL",
    )
    cmac_mirror: bool = Field(
        default=False,
        description="Whether the SDM CMAC is mirrored into the NDEF URL",
    )
    template_url: str | None = Field(
        default=None,
        description="URL template containing SDM mirror placeholders",
    )
    read_counter_limit: int | None = Field(
        default=None,
        ge=0,
        description="Optional SDM read counter limit before access is denied",
    )

    class SdmProfileError(Exception):
        """Exception raised when an SDM error occurs."""

    class SdmMirrorRequiredError(SdmProfileError):
        """Exception raised when enabled SDM has no mirrored values."""

    @model_validator(mode="after")
    def validate_sdm(self) -> Self:
        """Keep SDM settings internally consistent."""
        if not self.enabled:
            return self

        if not any([self.uid_mirror, self.counter_mirror, self.cmac_mirror]):
            msg = "enabled SDM must mirror at least one value"
            raise self.SdmMirrorRequiredError(msg)

        if self.template_url is not None:
            HttpUrl(self.template_url)

        return self


class AccessProfile(BaseModel):
    """High-level access policy."""

    ndef_read: Literal["free", "authenticated"] = Field(
        default="free",
        description="Read access policy for NDEF data",
    )
    ndef_write: Literal["free", "authenticated"] = Field(
        default="authenticated",
        description="Write access policy for NDEF data",
    )
    config_read: Literal["free", "authenticated"] = Field(
        default="authenticated",
        description="Read access policy for tag configuration",
    )
    config_write: Literal["free", "authenticated"] = Field(
        default="authenticated",
        description="Write access policy for tag configuration",
    )


class SecurityProfile(BaseModel):
    """Security and key state summary."""

    keys_configured: bool = Field(
        default=False,
        description="Whether application keys have been configured",
    )
    default_keys: bool = Field(
        default=True,
        description="Whether the tag appears to use factory default keys",
    )
    authenticated: bool = Field(
        default=False,
        description="Whether the current SDK session is authenticated",
    )
    key_slots: int = Field(
        default=5,
        ge=1,
        description="Number of application key slots available on the tag",
    )


class LockProfile(BaseModel):
    """Permanent lock state summary."""

    permanent: bool = Field(
        default=False,
        description="Whether permanent write locks are active",
    )
    irreversible_changes: list[str] = Field(
        default_factory=list,
        description="Irreversible changes already applied to the tag",
    )


class BaseTagProfile(BaseModel):
    """Common profile representation shared by supported NTAG families."""

    tag: TagInfo = Field(description="Static tag identity and capability metadata")
    ndef: NdefProfile = Field(
        default_factory=NdefProfile,
        description="Editable NDEF content profile",
    )


class Ntag21xProfile(BaseTagProfile):
    """Editable profile representation of an NTAG21x Type 2 tag."""

    capacity_bytes: int = Field(
        ge=0,
        description="Usable Type 2 Tag storage capacity in bytes",
    )

    def patch(
        self,
        *,
        tag: TagInfo | None = None,
        ndef: NdefProfile | None = None,
    ) -> Self:
        """Return a validated copy with NTAG21x profile section replacements."""
        return self.model_validate(
            {
                "tag": tag or self.tag,
                "ndef": ndef or self.ndef,
            },
        )


class Ntag424DnaProfile(BaseTagProfile):
    """Editable profile representation of an NTAG 424 DNA tag."""

    sdm: SdmProfile = Field(
        default_factory=SdmProfile,
        description="Secure Dynamic Messaging configuration profile",
    )
    access: AccessProfile = Field(
        default_factory=AccessProfile,
        description="High-level access rights profile",
    )
    security: SecurityProfile = Field(
        default_factory=SecurityProfile,
        description="Authentication and key state profile",
    )
    locks: LockProfile = Field(
        default_factory=LockProfile,
        description="Permanent lock and irreversible change profile",
    )

    def patch(  # noqa: PLR0913
        self,
        *,
        tag: TagInfo | None = None,
        ndef: NdefProfile | None = None,
        sdm: SdmProfile | None = None,
        access: AccessProfile | None = None,
        security: SecurityProfile | None = None,
        locks: LockProfile | None = None,
    ) -> Self:
        """Return a validated copy with typed profile section replacements."""
        return self.model_validate(
            {
                "tag": tag or self.tag,
                "ndef": ndef or self.ndef,
                "sdm": sdm or self.sdm,
                "access": access or self.access,
                "security": security or self.security,
                "locks": locks or self.locks,
            },
        )

    def plan_changes(self, requested: Self) -> ChangePlan:
        """Create a change plan from this profile to the requested profile."""
        from .planning import plan_profile_changes  # noqa: PLC0415

        return plan_profile_changes(self, requested)


NtagProfile = Ntag424DnaProfile | Ntag21xProfile
