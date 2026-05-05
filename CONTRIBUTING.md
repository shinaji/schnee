# Contributing

## Release Policy

This project uses ZeroVer with the `0.Y.Z` format.

- The first PyPI release is `0.1.0`.
- Increment `Y` for breaking changes to existing public API or CLI behavior, or for large feature changes that require users to update existing integrations or workflows.
- Increment `Z` for backward-compatible features, including new public API or CLI additions, bug fixes, and small improvements that do not require users to change existing integrations.
- Do not cut a release for documentation-only or internal-only changes unless those changes need to be published together with another releasable change.
