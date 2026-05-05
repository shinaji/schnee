"""Prepare the next ZeroVer release version."""

from __future__ import annotations

import argparse
import subprocess
from pathlib import Path

from schnee.release.versioning import (
    determine_next_version,
    find_latest_release_tag,
    write_pyproject_version,
)


def _list_release_tags() -> list[str]:
    """Return release tags visible from the current repository."""
    completed = subprocess.run(
        ["/usr/bin/git", "tag", "--list", "v0.*"],
        check=True,
        capture_output=True,
        text=True,
    )
    return [line for line in completed.stdout.splitlines() if line]


def _parse_args() -> argparse.Namespace:
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--pyproject",
        type=Path,
        default=Path("pyproject.toml"),
        help="Path to the pyproject.toml file to update.",
    )
    parser.add_argument(
        "--release-kind",
        choices=("patch", "minor"),
        required=True,
        help="Type of ZeroVer release to prepare.",
    )
    return parser.parse_args()


def main() -> int:
    """Prepare and print the next release version."""
    args = _parse_args()
    latest_tag = find_latest_release_tag(_list_release_tags())
    version = determine_next_version(
        latest_release_tag=latest_tag,
        release_kind=args.release_kind,
    )
    write_pyproject_version(args.pyproject, version)
    print(version)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
