"""Change planning for NTAG profile edits."""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal

from pydantic import BaseModel, Field

from .models import (
    AccessProfile,
    NdefProfile,
    SdmProfile,
    SecurityProfile,
)

if TYPE_CHECKING:
    from .models import (
        TagProfile,
    )

ProfileSection = NdefProfile | SdmProfile | AccessProfile | SecurityProfile
RiskLevel = Literal["safe", "moderate", "dangerous"]
OperationType = Literal[
    "writeNdef",
    "updateSdmConfig",
    "updateAccess",
    "rotateKey",
]


class ChangeOperation(BaseModel):
    """Single write operation needed to apply a profile change."""

    type: OperationType = Field(description="Operation kind to execute")
    path: str = Field(description="Profile path affected by this operation")
    description: str = Field(description="Human-readable operation summary")
    risk: RiskLevel = Field(
        default="safe",
        description="Risk level associated with this operation",
    )
    requires_authentication: bool = Field(
        default=False,
        description="Whether this operation requires tag authentication",
    )
    before: ProfileSection | None = Field(
        default=None,
        description="Previous profile section snapshot",
    )
    after: ProfileSection | None = Field(
        default=None,
        description="Requested profile section snapshot",
    )


class ChangePlan(BaseModel):
    """Validated profile diff that can be applied by a backend."""

    valid: bool = Field(description="Whether the planned changes can be applied")
    operations: list[ChangeOperation] = Field(
        default_factory=list,
        description="Ordered operations required to apply the requested profile",
    )
    warnings: list[str] = Field(
        default_factory=list,
        description="Non-blocking warnings about the planned changes",
    )
    errors: list[str] = Field(
        default_factory=list,
        description="Blocking validation errors for the planned changes",
    )

    @property
    def requires_authentication(self) -> bool:
        """Return whether any operation requires tag authentication."""
        return any(operation.requires_authentication for operation in self.operations)

    @property
    def has_dangerous_operations(self) -> bool:
        """Return whether the plan includes dangerous changes."""
        return any(operation.risk == "dangerous" for operation in self.operations)


def plan_profile_changes(current: TagProfile, requested: TagProfile) -> ChangePlan:
    """Create a write plan from current and requested tag profiles."""
    errors: list[str] = []
    warnings: list[str] = []
    operations: list[ChangeOperation] = []

    if current.tag.type != requested.tag.type:
        errors.append("tag type cannot be changed")

    if current.locks.permanent and current.ndef != requested.ndef:
        errors.append("NDEF cannot be changed after the tag is permanently locked")

    if current.ndef != requested.ndef:
        operations.append(
            ChangeOperation(
                type="writeNdef",
                path="ndef",
                description="Update NDEF records",
                risk="safe",
                before=current.ndef,
                after=requested.ndef,
            ),
        )

    if current.sdm != requested.sdm:
        operations.append(
            ChangeOperation(
                type="updateSdmConfig",
                path="sdm",
                description="Update Secure Dynamic Messaging settings",
                risk="moderate",
                requires_authentication=True,
                before=current.sdm,
                after=requested.sdm,
            ),
        )
        if requested.sdm.cmac_mirror:
            warnings.append("SDM CMAC requires backend verification support.")

    if current.access != requested.access:
        operations.append(
            ChangeOperation(
                type="updateAccess",
                path="access",
                description="Update access rights",
                risk="dangerous",
                requires_authentication=True,
                before=current.access,
                after=requested.access,
            ),
        )

    if current.security.default_keys and not requested.security.default_keys:
        operations.append(
            ChangeOperation(
                type="rotateKey",
                path="security",
                description="Rotate application keys",
                risk="dangerous",
                requires_authentication=True,
                before=current.security,
                after=requested.security,
            ),
        )
        warnings.append("Key rotation can make the tag inaccessible if keys are lost.")

    return ChangePlan(
        valid=not errors,
        operations=operations,
        warnings=warnings,
        errors=errors,
    )
