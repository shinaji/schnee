"""Converters from parsed NTAG data into profile sections."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

from schnee.adapters.ntag.apdu import Ntag424FileSettings

from .models import AccessProfile, LockProfile, SdmProfile, SecurityProfile

AccessPolicy = Literal["free", "authenticated"]


class Ntag424ProfileSections(BaseModel):
    """Profile sections derived from NTAG 424 DNA configuration data."""

    sdm: SdmProfile = Field(description="Derived SDM profile")
    access: AccessProfile = Field(description="Derived access profile")
    security: SecurityProfile = Field(description="Derived security profile")
    locks: LockProfile = Field(description="Derived lock profile")

    class Ntag424ProfileSectionsError(Exception):
        """Raised when parsed NTAG data cannot be represented as a profile."""

    class UnsupportedAccessPolicyError(Ntag424ProfileSectionsError):
        """Raised when NTAG access rights cannot fit the profile model."""

    @classmethod
    def from_parsed_data(
        cls,
        *,
        file_settings: Ntag424FileSettings,
        key_versions: list[int],
    ) -> Ntag424ProfileSections:
        """Build profile sections from parsed NTAG 424 DNA data."""
        return cls(
            sdm=cls._build_sdm_profile(file_settings),
            access=cls._build_access_profile(file_settings),
            security=cls._build_security_profile(key_versions),
            locks=cls._build_lock_profile(file_settings),
        )

    @staticmethod
    def _build_sdm_profile(file_settings: Ntag424FileSettings) -> SdmProfile:
        """Build an SDM profile from parsed file settings."""
        if not file_settings.sdm_enabled:
            return SdmProfile(enabled=False)

        return SdmProfile(
            enabled=True,
            uid_mirror=file_settings.sdm_uid_mirror,
            counter_mirror=file_settings.sdm_counter_mirror,
            cmac_mirror=file_settings.sdm_cmac_mirror,
            read_counter_limit=file_settings.read_counter_limit,
        )

    @classmethod
    def _build_access_profile(
        cls,
        file_settings: Ntag424FileSettings,
    ) -> AccessProfile:
        """Build high-level access policy from parsed file settings."""
        return AccessProfile(
            ndef_read=cls._access_policy(
                file_settings.read_access,
                file_settings.read_write_access,
            ),
            ndef_write=cls._access_policy(
                file_settings.write_access,
                file_settings.read_write_access,
            ),
            config_read="free",
            config_write=cls._access_policy(file_settings.change_access),
        )

    @staticmethod
    def _build_security_profile(key_versions: list[int]) -> SecurityProfile:
        """Build coarse security state from key version bytes."""
        default_keys = all(version == 0x00 for version in key_versions)
        return SecurityProfile(
            keys_configured=not default_keys,
            default_keys=default_keys,
            authenticated=False,
            key_slots=len(key_versions),
        )

    @classmethod
    def _build_lock_profile(
        cls,
        file_settings: Ntag424FileSettings,
    ) -> LockProfile:
        """Build lock state from parsed file access rights."""
        permanent = (
            file_settings.write_access == Ntag424FileSettings.access_none
            and file_settings.read_write_access == Ntag424FileSettings.access_none
            and file_settings.change_access == Ntag424FileSettings.access_none
        )
        changes = ["NDEF write access is permanently disabled"] if permanent else []
        return LockProfile(permanent=permanent, irreversible_changes=changes)

    @classmethod
    def _access_policy(cls, *access_conditions: int) -> AccessPolicy:
        """Map NTAG 424 access nibbles to profile access policy."""
        if any(
            condition == Ntag424FileSettings.access_free
            for condition in access_conditions
        ):
            return "free"
        if any(
            Ntag424FileSettings.access_key_min
            <= condition
            <= Ntag424FileSettings.access_key_max
            for condition in access_conditions
        ):
            return "authenticated"
        if all(
            condition == Ntag424FileSettings.access_none
            for condition in access_conditions
        ):
            msg = "NTAG 424 DNA no-access policy cannot be represented"
            raise cls.UnsupportedAccessPolicyError(msg)
        msg = f"Unsupported NTAG 424 DNA access condition: {access_conditions}"
        raise cls.UnsupportedAccessPolicyError(msg)
