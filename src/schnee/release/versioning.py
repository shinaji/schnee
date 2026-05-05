"""Helpers for ZeroVer release automation."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from pathlib import Path

INITIAL_RELEASE_VERSION = "0.1.0"
TAG_PREFIX = "v"
ZEROVER_PART_COUNT = 3
RELEASE_KIND_MINOR = "minor"
RELEASE_KIND_PATCH = "patch"
ReleaseKind = Literal["patch", "minor"]

_PYPROJECT_VERSION_PATTERN = re.compile(r'^version = "([^"]+)"$')


@dataclass(frozen=True, order=True)
class ZeroVer:
    """A parsed ZeroVer version."""

    minor: int
    patch: int

    def __str__(self) -> str:
        """Render the version as 0.Y.Z."""
        return f"0.{self.minor}.{self.patch}"


def parse_zerover(value: str) -> ZeroVer:
    """Parse a ZeroVer version string."""
    parts = value.split(".")
    if len(parts) != ZEROVER_PART_COUNT:
        msg = f"expected a 0.Y.Z version, got {value!r}"
        raise ValueError(msg)

    major, minor_text, patch_text = parts
    if major != "0" or not minor_text.isdigit() or not patch_text.isdigit():
        msg = f"expected a 0.Y.Z version, got {value!r}"
        raise ValueError(msg)

    return ZeroVer(minor=int(minor_text), patch=int(patch_text))


def parse_release_tag(tag: str) -> ZeroVer:
    """Parse a release tag of the form v0.Y.Z."""
    if not tag.startswith(TAG_PREFIX):
        msg = f"expected a release tag starting with {TAG_PREFIX!r}, got {tag!r}"
        raise ValueError(msg)

    return parse_zerover(tag.removeprefix(TAG_PREFIX))


def find_latest_release_tag(tags: list[str]) -> str | None:
    """Return the highest ZeroVer release tag from a list of tags."""
    release_tags: list[tuple[ZeroVer, str]] = []
    for tag in tags:
        if not tag.startswith(TAG_PREFIX):
            continue

        try:
            version = parse_release_tag(tag)
        except ValueError:
            continue

        release_tags.append((version, tag))

    if not release_tags:
        return None

    _, latest_tag = max(release_tags, key=lambda item: item[0])
    return latest_tag


def determine_next_version(
    latest_release_tag: str | None,
    release_kind: ReleaseKind,
) -> str:
    """Determine the next release version from the latest release tag."""
    if release_kind not in {RELEASE_KIND_PATCH, RELEASE_KIND_MINOR}:
        msg = f"expected release_kind to be 'patch' or 'minor', got {release_kind!r}"
        raise ValueError(msg)

    if latest_release_tag is None:
        return INITIAL_RELEASE_VERSION

    latest_version = parse_release_tag(latest_release_tag)
    if release_kind == RELEASE_KIND_MINOR:
        return str(ZeroVer(minor=latest_version.minor + 1, patch=0))

    return str(ZeroVer(minor=latest_version.minor, patch=latest_version.patch + 1))


def read_pyproject_version(pyproject_path: Path) -> str:
    """Read project.version from pyproject.toml."""
    project_section_found = False

    for line in pyproject_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped == "[project]":
            project_section_found = True
            continue

        if project_section_found and stripped.startswith("["):
            break

        if project_section_found:
            match = _PYPROJECT_VERSION_PATTERN.match(stripped)
            if match is not None:
                return match.group(1)

    msg = f"could not find [project].version in {pyproject_path}"
    raise ValueError(msg)


def write_pyproject_version(pyproject_path: Path, version: str) -> None:
    """Write project.version in pyproject.toml."""
    parse_zerover(version)
    lines = pyproject_path.read_text(encoding="utf-8").splitlines()
    project_section_found = False

    for index, line in enumerate(lines):
        stripped = line.strip()
        if stripped == "[project]":
            project_section_found = True
            continue

        if project_section_found and stripped.startswith("["):
            break

        if project_section_found and _PYPROJECT_VERSION_PATTERN.match(stripped):
            lines[index] = f'version = "{version}"'
            pyproject_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
            return

    msg = f"could not find [project].version in {pyproject_path}"
    raise ValueError(msg)
