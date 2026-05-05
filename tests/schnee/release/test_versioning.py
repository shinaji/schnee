"""Tests for release version automation."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from schnee.release.versioning import (
    INITIAL_RELEASE_VERSION,
    determine_next_version,
    find_latest_release_tag,
    parse_release_tag,
    parse_zerover,
    read_pyproject_version,
    write_pyproject_version,
)

if TYPE_CHECKING:
    from pathlib import Path


def test_determine_next_version_returns_initial_release_without_existing_tags() -> None:
    """The first release should resolve to the documented initial ZeroVer."""
    version = determine_next_version(latest_release_tag=None, release_kind="patch")

    assert version == INITIAL_RELEASE_VERSION, (
        "first automated release should produce the documented initial version"
    )


def test_determine_next_version_returns_initial_release_for_first_minor_release() -> (
    None
):
    """The first release should remain 0.1.0 regardless of release label kind."""
    version = determine_next_version(latest_release_tag=None, release_kind="minor")

    assert version == INITIAL_RELEASE_VERSION, (
        "first automated release should remain 0.1.0 before any release tags exist"
    )


def test_determine_next_version_increments_patch_release() -> None:
    """Patch releases should preserve Y and increment Z."""
    version = determine_next_version(latest_release_tag="v0.4.2", release_kind="patch")

    assert version == "0.4.3", "patch releases should increment Z from the latest tag"


def test_determine_next_version_increments_minor_release() -> None:
    """Minor releases should increment Y and reset Z."""
    version = determine_next_version(latest_release_tag="v0.4.2", release_kind="minor")

    assert version == "0.5.0", "minor releases should increment Y and reset Z"


def test_find_latest_release_tag_selects_highest_zerover_tag() -> None:
    """Release tag discovery should prefer the highest ZeroVer tag."""
    latest_tag = find_latest_release_tag(["v0.3.9", "v0.10.0", "v0.4.8"])

    assert latest_tag == "v0.10.0", (
        "latest release detection should compare ZeroVer values"
    )


def test_parse_zerover_rejects_non_zerover_strings() -> None:
    """Only 0.Y.Z versions should be accepted."""
    with pytest.raises(ValueError, match=r"0\.Y\.Z") as exc_info:
        parse_zerover("1.2.3")

    assert exc_info.value.args, (
        "invalid versions should raise a descriptive parsing error"
    )


def test_parse_release_tag_rejects_missing_prefix() -> None:
    """Release tags should use the v0.Y.Z convention."""
    with pytest.raises(ValueError, match="release tag") as exc_info:
        parse_release_tag("0.3.4")

    assert exc_info.value.args, (
        "invalid release tags should raise a descriptive parsing error"
    )


def test_read_and_write_pyproject_version_updates_project_metadata(
    tmp_path: Path,
) -> None:
    """The release script should update project.version before packaging."""
    pyproject_path = tmp_path / "pyproject.toml"
    pyproject_path.write_text(
        '[project]\nname = "schnee"\nversion = "0.1.0"\n',
        encoding="utf-8",
    )

    write_pyproject_version(pyproject_path, "0.2.0")
    version = read_pyproject_version(pyproject_path)

    assert version == "0.2.0", (
        "release preparation should persist the next package version"
    )
