"""Editable field descriptors for profile-driven UIs."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Literal

from pydantic import BaseModel, Field

from .models import Ntag21xProfile, Ntag424DnaProfile

if TYPE_CHECKING:
    from .models import NtagProfile


FieldKind = Literal["boolean", "choice", "hex", "integer", "secret", "string", "url"]


class EditableField(BaseModel):
    """UI-friendly editable field descriptor."""

    path: str = Field(description="Dotted profile path edited by this field")
    label: str = Field(description="Human-readable field label")
    kind: FieldKind = Field(description="UI control kind suitable for this field")
    value: Any = Field(default=None, description="Current field value")
    writable: bool = Field(
        default=True,
        description="Whether this field can currently be written",
    )
    required: bool = Field(
        default=False,
        description="Whether a value is required for this field",
    )
    choices: list[str] = Field(
        default_factory=list,
        description="Allowed values for choice fields",
    )
    requires_auth: bool = Field(
        default=False,
        description="Whether editing this field requires authentication",
    )
    dangerous: bool = Field(
        default=False,
        description="Whether editing this field can cause irreversible changes",
    )
    description: str | None = Field(
        default=None,
        description="Additional UI help text for the field",
    )


def build_editable_fields(profile: NtagProfile) -> list[EditableField]:
    """Build editable field descriptors from a tag profile."""
    if isinstance(profile, Ntag21xProfile):
        return _build_ntag21x_editable_fields(profile)
    if isinstance(profile, Ntag424DnaProfile):
        return _build_ntag424dna_editable_fields(profile)
    msg = f"Unsupported tag profile type: {type(profile).__name__}"
    raise TypeError(msg)


def _build_ntag21x_editable_fields(profile: Ntag21xProfile) -> list[EditableField]:
    """Build editable field descriptors for NTAG21x profiles."""
    ndef_record = profile.ndef.records[0] if profile.ndef.records else None
    ndef_value = ndef_record.value if ndef_record else ""
    ndef_kind = "url" if ndef_record is None or ndef_record.type == "url" else "string"

    return [
        EditableField(
            path="ndef.records[0].value",
            label="NDEF URL",
            kind=ndef_kind,
            value=ndef_value,
            writable=True,
            required=True,
        ),
    ]


def _build_ntag424dna_editable_fields(
    profile: Ntag424DnaProfile,
) -> list[EditableField]:
    """Build editable field descriptors for NTAG 424 DNA profiles."""
    ndef_record = profile.ndef.records[0] if profile.ndef.records else None
    ndef_value = ndef_record.value if ndef_record else ""
    ndef_kind = "url" if ndef_record is None or ndef_record.type == "url" else "string"

    return [
        EditableField(
            path="ndef.records[0].value",
            label="NDEF URL",
            kind=ndef_kind,
            value=ndef_value,
            writable=not profile.locks.permanent,
            required=True,
            requires_auth=profile.access.ndef_write == "authenticated",
        ),
        EditableField(
            path="sdm.enabled",
            label="SDM",
            kind="boolean",
            value=profile.sdm.enabled,
            requires_auth=True,
        ),
        EditableField(
            path="sdm.uid_mirror",
            label="UID Mirror",
            kind="boolean",
            value=profile.sdm.uid_mirror,
            requires_auth=True,
        ),
        EditableField(
            path="sdm.counter_mirror",
            label="Counter Mirror",
            kind="boolean",
            value=profile.sdm.counter_mirror,
            requires_auth=True,
        ),
        EditableField(
            path="sdm.cmac_mirror",
            label="CMAC Mirror",
            kind="boolean",
            value=profile.sdm.cmac_mirror,
            requires_auth=True,
        ),
        EditableField(
            path="sdm.template_url",
            label="SDM Template URL",
            kind="url",
            value=profile.sdm.template_url,
            requires_auth=True,
        ),
        EditableField(
            path="access.ndef_write",
            label="NDEF Write Access",
            kind="choice",
            value=profile.access.ndef_write,
            choices=["free", "authenticated"],
            requires_auth=True,
        ),
        EditableField(
            path="security.default_keys",
            label="Default Keys",
            kind="boolean",
            value=profile.security.default_keys,
            writable=not profile.locks.permanent,
            requires_auth=True,
            dangerous=True,
            description="Changing keys can lock future write access.",
        ),
    ]
