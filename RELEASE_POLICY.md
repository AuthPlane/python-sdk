# Release Policy

This repository follows a common release policy used across all Authplane SDK and adapter repositories.

## Versioning

- Use Semantic Versioning: `MAJOR.MINOR.PATCH`.
- Do not modify or overwrite published versions.
- Every release must be tied to an immutable Git tag.
- Breaking changes require a major version bump.

## Changelog and Documentation

- Keep `CHANGELOG.md` updated using Keep a Changelog format.
- Maintain consumer-facing README installation and usage examples.
- Ensure release notes align with changelog entries.

## Packaging and Metadata

- Keep package metadata complete and consistent for the ecosystem.
- Package only required runtime assets.
- Exclude tests, local configuration, secrets, and temporary build artifacts from release bundles.

## Dependency and Compatibility

- Avoid unnecessary dependencies.
- Do not use local/path-based dependencies in publishable releases.
- Clearly document supported runtime/toolchain versions.

## Release Process

- Releases are performed through CI/CD, not manual local publishing.
- Run build, test, lint/type checks, and package validation before publish.
- Prefer reproducible builds and deterministic release inputs.

## Security

- Never publish credentials, secrets, or internal tokens.
- Use secure registry authentication (trusted publishing or short-lived tokens).
