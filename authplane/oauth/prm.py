"""Protected Resource Metadata (PRM) builder.

Implements RFC 9728: OAuth 2.0 Protected Resource Metadata.
"""

from collections.abc import Sequence

from ..internal.urls import validate_issuer_identifier, validate_prm_resource_identifier


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

    Raises:
        InvalidIssuerError: If *issuer* carries a query or a fragment component
            (RFC 8414 §2), contains whitespace or a control character
            (RFC 3986 §2), is not an absolute URL with a scheme and a host
            (RFC 8414 §2, §3.1), or carries a userinfo subcomponent
            (RFC 9110 §4.2.4). Subclasses ``ValueError``, so an existing
            ``except ValueError`` still catches it.
        InvalidResourceError: If *resource* is not a usable resource-server
            identifier — see ``validate_prm_resource_identifier`` for the six
            checks (RFC 8707 §2, RFC 3986 §2/§3.2.3, RFC 9728 §3/§3.3,
            RFC 9110 §4.2.4/§5.6.4). Also subclasses ``ValueError``. The issuer
            is checked first, so an argument list with both defects reports the
            issuer — the member served to unauthenticated callers.
    """
    # This builder is exported and its documented use is to serve the returned
    # document directly from a `/.well-known/oauth-protected-resource`
    # endpoint, so it is a publication boundary in its own right — and RFC 9728
    # §3 has that endpoint answer **unauthenticated** callers. The issuer was
    # copied into `authorization_servers` below with no check whatsoever, so
    # `https://svc:s3cr3t@auth.example.com` was handed verbatim to every client
    # that asked. Redacting at this one sink would not be a fix: the same
    # identifier is also the metadata fetch target `build_metadata_url`
    # derives, and a gate applied at one of two sinks is exactly the shape that
    # produced this. Rejecting at the boundary is what makes the guarantee,
    # so both consumers now route through the one predicate.
    #
    # `resource` is gated by the same argument rather than left to the caller.
    # It is the very next member of the same published document, and it is the
    # one RFC 9728 §3.3 makes load-bearing: a client MUST discard a document
    # whose `resource` does not match the identifier it dereferenced. Nothing
    # in this signature guarantees the caller derived the value from a gated
    # `AuthplaneResource` — it is a plain `str` on a public builder — so an
    # identifier carrying a fragment, whitespace, userinfo or an unparseable
    # port could be published here while the well-known URL a client reached it
    # by could never have been derived from it. Every in-SDK path already
    # reaches `validate_prm_resource_identifier` in `AuthplaneResource.__init__`
    # (`verifier/verifier.py` forwards the already-gated `self._resource`), so
    # the new rejection lands exactly on the direct callers of this builder,
    # which is the set that had no gate at all.
    validate_issuer_identifier(issuer)
    validate_prm_resource_identifier(resource)
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
