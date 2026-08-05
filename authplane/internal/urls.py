"""URL utilities for OAuth 2.0 metadata discovery (RFC 8414) and PRM (RFC 9728)."""

from urllib.parse import ParseResult, urlparse, urlunparse


def _redact_authority(parsed: ParseResult) -> str:
    """Return ``scheme://host[:port]/path`` for use in error messages.

    Uses ``hostname`` (never ``netloc``) so any userinfo embedded in the
    authority — e.g. ``svc:s3cr3t@`` — is never echoed into a ``ValueError``
    that may be logged. The path is kept because it is not credential-shaped,
    while any query/fragment is dropped by the caller before this is built.
    """
    host = parsed.hostname or ""
    if parsed.port is not None:
        host = f"{host}:{parsed.port}"
    return f"{parsed.scheme}://{host}{parsed.path}"


def build_prm_url(resource: str) -> str:
    """Build the RFC 9728 well-known Protected Resource Metadata URL.

    The well-known URI is formed by inserting /.well-known/oauth-protected-resource
    between the host and the path and/or query components of the resource URI.

    RFC 9728 Section 3.1:
        https://{host}/.well-known/oauth-protected-resource/{path}

    The resource's query component, if any, is preserved on the derived URL.

    Examples:
        >>> build_prm_url("https://api.example.com")
        'https://api.example.com/.well-known/oauth-protected-resource'

        >>> build_prm_url("https://api.example.com/mcp")
        'https://api.example.com/.well-known/oauth-protected-resource/mcp'

        >>> build_prm_url("https://api.example.com/v2/mcp")
        'https://api.example.com/.well-known/oauth-protected-resource/v2/mcp'

        >>> build_prm_url("https://api.example.com/?x=1")
        'https://api.example.com/.well-known/oauth-protected-resource?x=1'

    Args:
        resource: The resource server URI.

    Returns:
        The fully constructed PRM discovery URL.

    Raises:
        ValueError: If the resource indicator carries a fragment component.
            RFC 8707 §2 forbids a fragment in a resource indicator; it is
            rejected here rather than silently discarded by ``urlunparse``.
    """
    parsed = urlparse(resource)

    # RFC 8707 §2: a resource indicator MUST NOT contain a fragment component.
    # (A query IS preserved below per RFC 9728 §3.1 — the two components are
    # treated asymmetrically.) urlunparse silently drops a fragment, so gate on
    # the raw string and reject it explicitly rather than letting a malformed
    # indicator resolve to a document it does not actually name.
    if "#" in resource:
        safe = _redact_authority(parsed)
        raise ValueError(
            f"resource indicator must not contain a fragment component (RFC 8707 §2): {safe!r}"
        )

    path = parsed.path.strip("/")

    if path:
        well_known_path = f"/.well-known/oauth-protected-resource/{path}"
    else:
        well_known_path = "/.well-known/oauth-protected-resource"

    # RFC 9728 §3.1 inserts the well-known segment between the host and "the path
    # and/or query components" of the resource identifier — so the query survives
    # into the derived PRM URL. (The path strip above is the correct §3.1
    # derivation behavior and is unrelated to identity comparison.)
    return urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            well_known_path,
            "",
            parsed.query,
            "",
        )
    )


def build_metadata_url(issuer: str) -> str:
    """Build the OAuth 2.0 Authorization Server Metadata URL per RFC 8414.

    When the issuer URL contains a path component, the `.well-known` segment
    is inserted immediately after the authority (host), not appended to the end.

    RFC 8414 Section 3:
        https://{host}/.well-known/oauth-authorization-server/{path}

    Examples:
        >>> build_metadata_url("https://auth.example.com")
        'https://auth.example.com/.well-known/oauth-authorization-server'

        >>> build_metadata_url("https://auth.example.com/tenant1")
        'https://auth.example.com/.well-known/oauth-authorization-server/tenant1'

        >>> build_metadata_url("https://auth.example.com/org/tenant1")
        'https://auth.example.com/.well-known/oauth-authorization-server/org/tenant1'

    Args:
        issuer: The OAuth 2.1 authorization server issuer URL.

    Returns:
        The fully constructed metadata discovery URL.

    Raises:
        ValueError: If the issuer carries a query or fragment component. RFC
            8414 §2 requires the issuer identifier to have neither. This raises
            at construction rather than silently discarding the component — that
            reconciliation would let a malformed identifier resolve to a
            document it does not actually name, and would later surface as a
            confusing "issuer mismatch" instead of the real cause. (A fragment
            is not preserved by ``urlunparse`` at all, so without this gate a
            fragment-bearing issuer would be silently dropped.)
    """
    parsed = urlparse(issuer)

    # RFC 8414 §2: the issuer identifier MUST NOT contain a query OR fragment
    # component. Gate on the raw string so a bare `?`/`#` (empty component, which
    # urlparse reports as empty) is rejected too — the delimiter must never
    # survive into the derived `.well-known` URL, and urlunparse silently drops a
    # fragment entirely. Report only scheme://host/path (bare hostname, never
    # netloc) so a credential-shaped query (e.g. `?token=...`) or embedded
    # userinfo does not leak into the message.
    if any(c in issuer for c in ("?", "#")):
        safe = _redact_authority(parsed)
        raise ValueError(
            "issuer identifier must not contain a query or fragment component "
            f"(RFC 8414 §2): {safe!r}"
        )

    # Strip leading/trailing slashes from the path to normalize
    path = parsed.path.strip("/")

    if path:
        well_known_path = f"/.well-known/oauth-authorization-server/{path}"
    else:
        well_known_path = "/.well-known/oauth-authorization-server"

    return urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            well_known_path,
            "",  # params
            "",  # query
            "",  # fragment
        )
    )
