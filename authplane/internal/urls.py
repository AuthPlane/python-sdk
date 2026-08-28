"""URL utilities for OAuth 2.0 metadata discovery (RFC 8414) and PRM (RFC 9728)."""

from urllib.parse import urlsplit, urlunsplit

from ..errors import InvalidIssuerError, InvalidResourceError


def host_literal(hostname: str) -> str:
    """Re-bracket an IPv6 literal for use in an authority component.

    ``SplitResult.hostname`` strips the brackets RFC 3986 §3.2.2 requires around
    an IPv6 literal, so every place that reassembles an authority from it has to
    put them back — otherwise ``https://[::1]:8080/x`` comes back out as
    ``https://::1:8080/x``, which is not a valid URI and which collides with the
    distinct endpoint ``https://[::1:8080]/x``.

    One definition rather than three: this expression lived inline in
    ``net/ssrf.py``'s ``Host`` header reconstruction, was added to ``dpop.py``
    for the ``htu`` and the nonce origin, and was missing here — three copies
    required to agree with none referencing the others, which is how the two
    halves of one DPoP binding check came to bracket differently in the first
    place.
    """
    return f"[{hostname}]" if ":" in hostname else hostname


def _redact_authority(raw: str) -> str:
    """Return ``scheme://host[:port]/path`` for use in error messages.

    Takes the raw string and parses defensively. Every caller is on an error
    path handling a malformed identifier, and ``urlsplit`` itself raises on some
    of them — it splits the netloc at the first of ``/?#`` and then
    rejects a netloc containing ``[`` without ``]``, so
    ``"https://[::1#frag"`` raises ``ValueError("Invalid IPv6 URL")`` before the
    fragment is ever separated. Parsing outside a guard would surface urllib's
    message in place of the RFC citation the caller wrote.

    Uses ``hostname`` (never ``netloc``) so any userinfo embedded in the
    authority — e.g. ``svc:s3cr3t@`` — is never echoed into a ``ValueError``
    that may be logged. The path is kept because it is not credential-shaped;
    the query and fragment are dropped here, since callers pass the raw
    identifier and it is precisely a query- or fragment-bearing one that reaches
    these guards.
    """
    try:
        parsed = urlsplit(raw)
    except ValueError:
        return "(unparseable identifier)"
    host = parsed.hostname or ""
    # ``ParseResult.port`` parses the port lazily and raises ValueError on a
    # malformed authority — ``https://h:abc/`` is exactly the kind of input that
    # reaches the guards below. Raising while *building* the error message would
    # surface urllib's "Port could not be cast to integer value" instead of the
    # RFC citation the caller wrote, so fall back to the bare hostname.
    try:
        port = parsed.port
    except ValueError:
        port = None
    host = host_literal(host)
    if port is not None:
        host = f"{host}:{port}"
    return f"{parsed.scheme}://{host}{parsed.path}"


def validate_resource_indicator(resource: str) -> None:
    """Raise ``InvalidResourceError`` if *resource* is not a usable indicator.

    RFC 8707 §2 forbids a fragment component. ``urlunsplit`` drops one silently,
    so an indicator carrying a fragment would resolve to a document it does not
    actually name.

    This is the construction-time gate. It has three call sites, and which one is
    authoritative matters:

    * ``AuthplaneResource.__init__`` — the authoritative one. Every construction
      path reaches it, including direct construction of the package-root export.
    * ``AuthplaneClient.resource()`` — redundant for the guarantee, kept for the
      traceback: it raises at the line the operator wrote rather than one frame
      deeper in the constructor.
    * ``build_prm_url`` — a defensive backstop, and it must not be the only one:
      its production caller is ``AuthplaneResource.prm_url()``, which operators
      invoke to build the ``resource_metadata`` parameter of an RFC 9728
      challenge — i.e. inside a 401 response path. Validating only there turns a
      configuration error into a 500 on the failure path, which is the worst
      place to discover it.

    Args:
        resource: The resource indicator, as configured by the operator.

    Raises:
        InvalidResourceError: If the indicator carries a fragment component.
            Subclasses ``ValueError``, so an existing ``except ValueError`` still
            catches it.
    """
    if "#" in resource:
        safe = _redact_authority(resource)
        raise InvalidResourceError(
            f"resource indicator must not contain a fragment component (RFC 8707 §2): {safe!r}"
        )


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
        InvalidResourceError: If the resource indicator carries a fragment
            component. RFC 8707 §2 forbids a fragment in a resource indicator;
            it is rejected here rather than silently discarded by
            ``urlunsplit``. Subclasses ``ValueError``, so an existing
            ``except ValueError`` still catches it.
    """
    # Defensive backstop. The authoritative gate is validate_resource_indicator
    # called from AuthplaneResource.__init__, which every construction path
    # reaches — see its docstring for the full call-site map and for why this
    # must not be the only check. (A query IS preserved below per RFC 9728 §3.1;
    # the two components are treated asymmetrically.)
    #
    # Before parsing, for the same reason build_metadata_url checks first:
    # urlsplit raises on some malformed inputs, so parsing above the guard
    # surfaces urllib's message in place of the RFC citation.
    validate_resource_indicator(resource)

    # urlsplit, not urlparse: urlparse peels an RFC 3986 ";params" segment off the
    # last path segment, and urlunparse's params slot then has to be filled or the
    # segment is dropped. Passing "" dropped it, so "/mcp;v=1" and "/mcp" derived
    # the same document — the collapse this module exists to prevent. urlsplit
    # keeps it in `path`, which is also what the two adapter copies do.
    parsed = urlsplit(resource)

    # Keep the path's own leading slash and remove only terminating ones, then
    # concatenate. ``strip("/")`` removed slashes from both ends, so a doubled
    # leading slash ("//mcp") lost a segment and derived the same URL as "/mcp" —
    # two distinct identifiers collapsing onto one document. §3.1 only speaks of
    # the *terminating* slash.
    #
    # The separator is re-added when the parsed path has none: nothing upstream
    # requires the identifier to be absolute, and for a scheme-less input
    # urlsplit puts the whole authority in ``path`` with no leading slash.
    path = parsed.path.rstrip("/")
    if path and not path.startswith("/"):
        path = "/" + path
    well_known_path = "/.well-known/oauth-protected-resource" + path

    # RFC 9728 §3.1 inserts the well-known segment between the host and "the path
    # and/or query components" of the resource identifier — so the query survives
    # into the derived PRM URL. (The path strip above is the correct §3.1
    # derivation behavior and is unrelated to identity comparison.)
    return urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            well_known_path,
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
        InvalidIssuerError: If the issuer carries a query or fragment component.
            Subclasses ``ValueError``, so existing ``except ValueError``
            handlers are unaffected. RFC
            8414 §2 requires the issuer identifier to have neither. This raises
            at construction rather than silently discarding the component — that
            reconciliation would let a malformed identifier resolve to a
            document it does not actually name, and would later surface as a
            confusing "issuer mismatch" instead of the real cause. (A fragment
            is not preserved by ``urlunsplit`` at all, so without this gate a
            fragment-bearing issuer would be silently dropped.)
    """
    # The raw-string check comes first: urlsplit itself raises on some malformed
    # identifiers (an unclosed IPv6 bracket, for one), and this guard exists to
    # report the RFC violation, not urllib's parse error.
    #
    # RFC 8414 §2: the issuer identifier MUST NOT contain a query OR fragment
    # component. Gate on the raw string so a bare `?`/`#` (empty component, which
    # urlsplit reports as empty) is rejected too — the delimiter must never
    # survive into the derived `.well-known` URL, and urlunsplit silently drops a
    # fragment entirely. Report only scheme://host/path (bare hostname, never
    # netloc) so a credential-shaped query (e.g. `?token=...`) or embedded
    # userinfo does not leak into the message.
    if any(c in issuer for c in ("?", "#")):
        safe = _redact_authority(issuer)
        raise InvalidIssuerError(
            "issuer identifier must not contain a query or fragment component "
            f"(RFC 8414 §2): {safe!r}"
        )

    parsed = urlsplit(issuer)

    # Keep the path's own leading slash and remove only terminating ones, and
    # re-add the separator when there is none — see the note in build_prm_url.
    path = parsed.path.rstrip("/")
    if path and not path.startswith("/"):
        path = "/" + path
    well_known_path = "/.well-known/oauth-authorization-server" + path

    return urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            well_known_path,
            "",  # query
            "",  # fragment
        )
    )
