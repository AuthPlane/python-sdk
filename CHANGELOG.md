# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- Packaging issues discovered after the first release.
- Documentation links and demo references.
- `authplane-fastmcp` dependency range now correctly requires `fastmcp>=3.2,<4` (was `>=2.0`, which could resolve to a version the adapter can't import).

### Changed
- CI and release workflow improvements from first-release learnings.

## [0.1.0] - 2026-05-11

- Initial release.
