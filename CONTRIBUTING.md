# Contributing

## Release Policy

This project uses ZeroVer with the `0.Y.Z` format.

- The first PyPI release is `0.1.0`.
- Increment `Y` for breaking changes to existing public API or CLI behavior, or for large feature changes that require users to update existing integrations or workflows.
- Increment `Z` for backward-compatible features, including new public API or CLI additions, bug fixes, and small improvements that do not require users to change existing integrations.
- Do not cut a release for documentation-only changes, or for internal-only changes that do not affect runtime behavior, public APIs, CLI behavior, packaging, or supported environments, unless those changes need to be published together with another releasable change.

## Release Automation Notes

- Mark releasable pull requests with exactly one of `release:patch` or `release:minor` before merging to `main`.
- Pull requests without either label do not trigger a release.
- When no `v0.Y.Z` tag exists yet, the first labeled release produces `0.1.0`.
- The release workflow updates `project.version` in `pyproject.toml`, commits `chore(release): prepare v0.Y.Z [skip ci]`, and pushes the matching `v0.Y.Z` tag.
- The release workflow assumes GitHub Actions is allowed to push its automated release commit to `main`.
