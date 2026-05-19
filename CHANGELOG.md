# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security
- `www_authenticate()` now sanitizes CR, LF, double-quote, and backslash from every value it interpolates (`realm`, `error_description`, `scope`, `resource_metadata`), closing a header-injection path through attacker-influenced error messages.

### Fixed
- `DPoPNotSupportedError` now emits `WWW-Authenticate: Bearer` instead of `DPoP`. The resource is bearer-only by configuration, so advertising the DPoP scheme misled clients into retries that would fail the same way.
- `http_status(CircuitOpenError)` now returns `503` (was `500`). The circuit breaker is structurally identical to other temporary-AS-unavailability errors and should be retryable, not surfaced as an internal error.
- Outbound `Host` header now preserves non-default ports and brackets IPv6 hostnames, fixing DPoP `htu` validation against authservers on non-standard ports.
- Packaging issues discovered after the first release.
- Documentation links and demo references.
- `authplane-fastmcp` dependency range now correctly requires `fastmcp>=3.2,<4` (was `>=2.0`, which could resolve to a version the adapter can't import).

### Added
- `www_authenticate()` accepts `resource_metadata_url=` (RFC 9728 §5.1) and `scope=` (RFC 6750 §3) keyword arguments. When the caller does not pass `scope=`, the helper auto-populates it from `InsufficientScopeError.required_scopes`.
- `InsufficientScopeError` now carries a structured `required_scopes` attribute, populated automatically by `VerifiedClaims.require_scope()` so the wire challenge can advertise the missing scope.
- `response_headers_for(error, *, realm, resource_metadata_url, scope)` — bundled helper returning `(status, {"WWW-Authenticate": challenge})` in one call.
- Both adapter verifiers (`authplane-mcp`, `authplane-fastmcp`) now emit a `logging.DEBUG` event `authplane.token_verification_failed` with structured `error_class` and `error` fields before returning `None`. Wire behaviour is unchanged; operators can now distinguish expired tokens from JWKS outages and DPoP replays in logs.

### Changed
- CI and release workflow improvements from first-release learnings.

## [0.1.0] - 2026-05-11

- Initial release.
