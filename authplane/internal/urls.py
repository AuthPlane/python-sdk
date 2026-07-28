"""URL utilities for OAuth 2.0 metadata discovery (RFC 8414) and PRM (RFC 9728)."""

from urllib.parse import urlparse, urlunparse


def build_prm_url(resource: str) -> str:
    """Build the RFC 9728 well-known Protected Resource Metadata URL.

    The well-known URI is formed by inserting /.well-known/oauth-protected-resource
    between the host and the path component of the resource URI.

    RFC 9728 Section 3:
        https://{host}/.well-known/oauth-protected-resource/{path}

    The insertion is a pure string operation: the resource's path is preserved
    exactly, including any trailing slash.

    Examples:
        >>> build_prm_url("https://api.example.com")
        'https://api.example.com/.well-known/oauth-protected-resource'

        >>> build_prm_url("https://api.example.com/mcp")
        'https://api.example.com/.well-known/oauth-protected-resource/mcp'

        >>> build_prm_url("https://api.example.com/v2/mcp")
        'https://api.example.com/.well-known/oauth-protected-resource/v2/mcp'

        >>> build_prm_url("https://api.example.com/mcp/")
        'https://api.example.com/.well-known/oauth-protected-resource/mcp/'

    Args:
        resource: The resource server URI.

    Returns:
        The fully constructed PRM discovery URL.
    """
    parsed = urlparse(resource)
    well_known_path = "/.well-known/oauth-protected-resource" + parsed.path

    return urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            well_known_path,
            "",
            "",
            "",
        )
    )


def build_metadata_url(issuer: str) -> str:
    """Build the OAuth 2.0 Authorization Server Metadata URL per RFC 8414.

    When the issuer URL contains a path component, the `.well-known` segment
    is inserted immediately after the authority (host), not appended to the end.

    RFC 8414 Section 3:
        https://{host}/.well-known/oauth-authorization-server/{path}

    The insertion is a pure string operation: the issuer's path is preserved
    exactly, including any trailing slash.

    Examples:
        >>> build_metadata_url("https://auth.example.com")
        'https://auth.example.com/.well-known/oauth-authorization-server'

        >>> build_metadata_url("https://auth.example.com/tenant1")
        'https://auth.example.com/.well-known/oauth-authorization-server/tenant1'

        >>> build_metadata_url("https://auth.example.com/org/tenant1")
        'https://auth.example.com/.well-known/oauth-authorization-server/org/tenant1'

        >>> build_metadata_url("https://auth.example.com/tenant1/")
        'https://auth.example.com/.well-known/oauth-authorization-server/tenant1/'

    Args:
        issuer: The OAuth 2.1 authorization server issuer URL.

    Returns:
        The fully constructed metadata discovery URL.
    """
    parsed = urlparse(issuer)
    well_known_path = "/.well-known/oauth-authorization-server" + parsed.path

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
