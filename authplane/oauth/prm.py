"""Protected Resource Metadata (PRM) builder.

Implements RFC 9728: OAuth 2.0 Protected Resource Metadata.
"""

from collections.abc import Sequence


def build_prm(
    issuer: str,
    resource: str,
    scopes: Sequence[str],
    *,
    dpop_algs: Sequence[str] | None = None,
    dpop_required: bool = False,
) -> dict[str, object]:
    """Build an RFC 9728 compliant Protected Resource Metadata document.

    Args:
        issuer: The OAuth 2.1 authorization server issuer URL
        resource: The resource server identifier (audience)
        scopes: Supported scopes for this resource (kept as-is; callers
            pass tuples to preserve immutability)
        dpop_algs: DPoP signing algorithms supported by this resource (RFC 9728 §2).
            When provided, ``dpop_signing_alg_values_supported`` is included.
        dpop_required: Whether DPoP-bound access tokens are always required
            (RFC 9728 §2 ``dpop_bound_access_tokens_required``).

    Returns:
        Dictionary containing RFC 9728 compliant PRM document
    """
    doc: dict[str, object] = {
        "resource": resource,
        "authorization_servers": [issuer],
        "bearer_methods_supported": ["header"],
        "scopes_supported": scopes,
    }
    if dpop_algs is not None:
        doc["dpop_signing_alg_values_supported"] = list(dpop_algs)
        doc["dpop_bound_access_tokens_required"] = dpop_required
    return doc
