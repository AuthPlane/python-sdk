"""Validation for resource and issuer identifiers.

RFC 8414 Section 3.3 and RFC 9728 Section 3.3 require the advertised
issuer/resource to be identical to the configured value — a simple string
comparison, not RFC 3986 equivalence. The SDK therefore never rewrites an
identifier: well-known URLs are formed by inserting the well-known path
segment between the authority and the identifier's path (RFC 8414 Section 3 /
RFC 9728 Section 3), and validation rejects structurally unusable identifiers
instead of repairing them.
"""

from urllib.parse import urlparse


def validate_identifier(value: str, label: str) -> str:
    """Validate that *value* is an absolute http(s) URL identifier.

    The identifier must have an http or https scheme, an authority, and no
    fragment (RFC 8707 Section 2 forbids fragments in resource identifiers).
    Returns *value* unchanged — trailing slashes, host case, and explicit
    ports are all legal identifier variations and are preserved verbatim.

    Raises:
        ValueError: When the identifier is structurally invalid.
    """
    parsed = urlparse(value)
    if parsed.scheme not in ("https", "http"):
        raise ValueError(f"{label} must be an absolute http or https URL: {value!r}")
    if not parsed.netloc:
        raise ValueError(f"{label} must include an authority: {value!r}")
    if "#" in value:
        raise ValueError(f"{label} must not contain a fragment: {value!r}")
    return value
