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
    """Return the identifier's ``scheme:``, ``//host[:port]`` and path — each
    only if present — for use in error messages.

    Takes the raw string and parses defensively. Every caller is on an error
    path handling a malformed identifier, and ``urlsplit`` itself raises on some
    of them — it splits the netloc at the first of ``/?#`` and then
    rejects a netloc containing ``[`` without ``]``, so
    ``"https://[::1#frag"`` raises ``ValueError("Invalid IPv6 URL")`` before the
    fragment is ever separated. Parsing outside a guard would surface urllib's
    message in place of the RFC citation the caller wrote.

    Uses ``hostname`` (never the raw ``netloc``) so any userinfo embedded in
    the authority — e.g. ``svc:s3cr3t@`` — is never echoed into a ``ValueError``
    that may be logged. The path is kept because it is not credential-shaped;
    the query and fragment are dropped here, since callers pass the raw
    identifier and it is precisely a query- or fragment-bearing one that reaches
    these guards.

    Renders only the components the input actually has. The absoluteness gate
    exists precisely for inputs missing the scheme or the authority, and a
    fixed ``scheme://host/path`` template invents the missing half: it rendered
    ``urn:example:api`` as ``'urn://example:api'`` — an opaque identifier shown
    as though it had an authority, against a message saying one is required —
    and made the scheme-less ``api.example.com/mcp`` indistinguishable from the
    scheme-relative ``//api.example.com/mcp``. The operator must see the shape
    they actually configured.

    Two deliberate exceptions to that transcription, both narrower than the
    alternative: the host is rendered from ``hostname``, which case-normalizes
    it (RFC 3986 §3.2.2 defines the host as case-insensitive), so an uppercase
    host echoes lowercased; and a port that does not parse is marked rather
    than quoted — see the port note below.
    """
    try:
        parsed = urlsplit(raw)
    except ValueError:
        return "(unparseable identifier)"
    host = host_literal(parsed.hostname or "")
    # ``SplitResult.port`` parses the port lazily and raises ValueError on a
    # malformed authority — ``https://h:abc/`` is exactly the kind of input the
    # guards below exist for, including the port guard itself. Raising while
    # *building* the error message would surface urllib's "Port could not be
    # cast to integer value" instead of the RFC citation the caller wrote.
    #
    # The unparsed port is still rendered rather than dropped: a message naming
    # the port that echoes an authority *without* one shows the operator a
    # string they did not write, which is the defect this renderer exists to
    # avoid. It is echoed verbatim only when it is all digits — that is the
    # out-of-range case, and digits are not credential-shaped. Anything else
    # gets a marker instead, because ``https://user:pass/x`` — a userinfo whose
    # "@" the operator forgot — has that exact shape and ``urlsplit`` reports no
    # userinfo for it, so quoting it would leak the secret this function is
    # here to redact.
    try:
        port = parsed.port
    except ValueError:
        raw_port = parsed.netloc.rpartition("@")[2].rpartition(":")[2]
        host = f"{host}:{raw_port if raw_port.isdigit() else '(malformed port)'}"
    else:
        if port is not None:
            host = f"{host}:{port}"
    # Gate the "//" on the parse's netloc OR on the raw string spelling one out
    # — "https://" and "file:///x" parse to an *empty* netloc, and gating on
    # the netloc alone echoed them as 'https:' and 'file:/x', dropping a
    # component the operator actually wrote: the same dropped-half defect the
    # fixed template had, running in the other direction. Render the redacted
    # `host` built above (hostname plus the re-rendered port), never the netloc
    # itself — a netloc of only userinfo would otherwise echo the credentials,
    # and one of only a port ("https://:8080/x") still renders faithfully as
    # "https://:8080/x".
    rest = raw[len(parsed.scheme) + 1 :] if parsed.scheme else raw
    scheme_part = f"{parsed.scheme}:" if parsed.scheme else ""
    auth_part = f"//{host}" if parsed.netloc or rest.startswith("//") else ""
    return f"{scheme_part}{auth_part}{parsed.path}"


#: ZERO WIDTH NO-BREAK SPACE, the one member of the class below that
#: ``str.isspace()`` does not report and that no other branch covers. See
#: ``_first_whitespace_or_control``.
_ZERO_WIDTH_NO_BREAK_SPACE = "\ufeff"


def _first_whitespace_or_control(value: str) -> tuple[int, str] | None:
    """Return ``(offset, character)`` for the first character in *value* that is
    whitespace or a control, or ``None`` when there is none.

    RFC 3986 §2 is the grounding for treating the two as one class: it builds
    every URI component out of ``unreserved``, ``reserved`` and
    ``pct-encoded``, all of which are printable ASCII. A string carrying any
    character below is therefore not a URI at all, whatever a permissive parser
    makes of it.

    Four branches, and each one covers something the others miss — measured on
    3.12 rather than assumed:

    * ``ord(ch) <= 0x20`` — the C0 controls and space. These are the characters
      ``urlsplit`` silently removes or lstrips, so they are the ones that make
      the parse disagree with the stored identifier.
    * ``0x7F <= ord(ch) <= 0x9F`` — DEL and the C1 controls. ``urlsplit``
      neither strips nor rejects these, which is exactly why they need naming:
      ``str.isspace()`` reports only U+0085 out of the whole range, so
      ``https://api.example.com/m\\x7fcp`` was accepted, stored and advertised
      with an invisible byte in the middle of the path.
    * ``ch.isspace()`` — the rest of Unicode whitespace: U+00A0, U+1680,
      U+2000-U+200A, U+2028, U+2029, U+202F, U+205F, U+3000 and the C0 members
      the first branch already has.
    * ``_ZERO_WIDTH_NO_BREAK_SPACE`` — U+FEFF, named on its own because nothing
      else reaches it. CPython's ``str.isspace()`` returns **False** for it: the
      Unicode ``White_Space`` property does not include it (it is ``Cf``, not
      ``Zs``), so a class built on ``isspace()`` alone leaves a byte-order mark
      pasted into the middle of a configured identifier accepted. Verified by
      execution; the symmetric difference between the four branches above and
      ``isspace()`` alone is exactly U+007F-U+009F plus this one codepoint, and
      the widening removes nothing.

    Non-ASCII printable characters are deliberately **not** in the class.
    U+00A1 and every other printable codepoint above U+007F stays accepted:
    narrowing the identifier to ASCII is a separate axis with its own migration
    cost, and it is not settled here by accident.

    Returns the offset as well as the character because the offset is most of
    the diagnostic value. Every character this rejects is by definition one
    nothing renders, so a message that merely quotes the identifier back shows
    the operator a string that looks correct. The caller reports the codepoint
    and this offset; neither leaks anything else about the value.
    """
    for index, char in enumerate(value):
        code = ord(char)
        if (
            code <= 0x20
            or 0x7F <= code <= 0x9F
            or char.isspace()
            or char == _ZERO_WIDTH_NO_BREAK_SPACE
        ):
            return index, char
    return None


def validate_prm_resource_identifier(resource: str) -> None:
    """Raise ``InvalidResourceError`` if *resource* is not a usable identifier.

    This is the gate for a **resource-server identifier** — one that publishes
    Protected Resource Metadata and whose well-known URL this module derives.
    It is deliberately *not* the general RFC 8707 resource-indicator predicate,
    and the name says so: RFC 8707 §2 requires only an absolute URI (RFC 3986
    §4.3), which ``urn:example:api`` satisfies. The host requirement below comes
    from RFC 9728 §3, which binds a resource that publishes PRM. A token
    request's ``resource`` parameter (``oauth/token_exchange.py``) carries
    indicators in the general sense and is not gated by this function; if a gate
    for that axis is ever wanted it is a different, weaker predicate and needs a
    name of its own.

    Six checks, in a deterministic order:

    1. RFC 8707 §2 forbids a fragment component. ``urlunsplit`` drops one
       silently, so an identifier carrying a fragment would resolve to a
       document it does not actually name.
    2. No whitespace or control characters, checked on the raw string —
       C0 and space, DEL and the C1 controls, every Unicode whitespace
       character and U+FEFF; see ``_first_whitespace_or_control``. None is a
       URI character (RFC 3986 §2), and ``urlsplit`` silently *cleans* or
       passes through rather than rejects them — so a later check would judge
       a cleaned string while the identifier is stored and advertised
       verbatim, and the served PRM would name a resource differing
       byte-for-byte from the URL it was fetched from (RFC 9728 §3.3 obliges
       a client to discard exactly that). The message names the offending
       codepoint and its offset, because every character in the class is one
       nothing renders.
    3. The identifier must be an absolute URL with a scheme **and** a host.
       The scheme is required by RFC 8707 §2 ("MUST be an absolute URI, as
       specified by Section 4.3 of [RFC3986]", whose grammar is
       ``absolute-URI = scheme ":" hier-part [ "?" query ]``). The host is
       required by RFC 9728 §3: the well-known suffix is inserted after the
       host component, so without one there is no derivable metadata URL —
       and in the MCP adapters no derivable DPoP ``htu`` origin, which is
       reconstructed as ``scheme://netloc`` from this identifier and
       degraded to the literal string ``"://"``.
    4. No userinfo subcomponent. RFC 9110 §4.2.4: "a sender MUST NOT
       generate the userinfo subcomponent" in an http(s) URI. The identifier
       feeds three sinks that reassemble the authority verbatim — the PRM
       URL handed to unauthenticated callers in a 401 ``WWW-Authenticate``
       challenge, the adapters' DPoP ``htu`` origin (which no honest proof
       could then match), and a log record — so credentials embedded in it
       are rejected at construction rather than redacted at each sink.
    5. No literal `"` or `\\` in the host. RFC 9110 §11.2 makes the
       ``resource_metadata`` parameter of the ``WWW-Authenticate`` challenge a
       quoted-string, and §5.6.4 makes those two octets its delimiters — the
       first closes the string at the host, the second opens a quoted-pair a
       conformant client unescapes into a different host. ``urlsplit`` admits
       both and ``urlunsplit`` writes them back out unescaped.
    6. The port, if present, must parse. RFC 3986 §3.2.3 gives it as
       ``*DIGIT``; ``SplitResult.port`` parses lazily, so a non-numeric or
       out-of-range port ("https://api.example.com:80O/mcp", letter O for
       zero) passes checks 3 and 4 — ``hostname`` and ``scheme`` are both
       present — and then yields exactly the "no derivable origin" outcome
       those checks exist to reject.

    The scheme is deliberately **not** narrowed to ``https``: ``http``
    identifiers stay accepted so local development works
    (``http://localhost:8080/mcp``), matching the SDK's dev-mode fetch policy.

    This is the construction-time gate. It has five call sites, and which one is
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
    * ``authplane_mcp_auth(...)`` (authplane-mcp) and ``authplane_auth(...)``
      (authplane-fastmcp) — early gates ahead of ``AuthplaneClient.create()``,
      so a misconfiguration is diagnosed without a reachable AS and without
      stranding a client whose caches the raise path would not close. These
      two are why the name is exported from the package root.

    Args:
        resource: The resource identifier, as configured by the operator.

    Raises:
        InvalidResourceError: If the identifier carries a fragment component,
            contains whitespace or a control character, is not an absolute URL
            with a scheme and a host, carries a userinfo subcomponent, carries
            a literal `"` or `\\` in its host, or carries a port that does not
            parse. Subclasses ``ValueError``, so an existing
            ``except ValueError`` still catches it.
    """
    # Fragment first, absoluteness second — pinned, so "/mcp#frag" reports the
    # fragment. The fragment check stays on the raw string (a bare "#" is an
    # empty component urlsplit reports as empty) and stays ahead of any
    # parsing, so urlsplit's own ValueError on e.g. an unclosed IPv6 bracket
    # cannot mask the RFC citation.
    if "#" in resource:
        safe = _redact_authority(resource)
        raise InvalidResourceError(
            f"resource identifier must not contain a fragment component (RFC 8707 §2): {safe!r}"
        )

    # Whitespace and control characters, also on the RAW string and also ahead
    # of any parsing — because ``urlsplit`` silently cleans them instead of
    # rejecting: it removes tab/CR/LF anywhere in the input, and since CPython
    # 3.11 (the ``requires-python`` floor) additionally lstrips any leading
    # C0-control-or-space, per the WHATWG alignment. Both behaviours verified
    # by execution on 3.11 and 3.12. Gating on the parse result would
    # therefore pass "https://api.exa\tmple.com/mcp" while the identifier is
    # stored (``AuthplaneResource``) and advertised (the adapters'
    # ``verbatim_resource``) byte-for-byte — the served PRM would then name a
    # resource differing from the URL it was fetched from, which RFC 9728
    # §3.3 obliges a conformant client to discard. The class the scan applies
    # is spelled out on ``_first_whitespace_or_control``; the echo is redacted
    # like every other, and parsing for it strips the offending character, so
    # the repr shows what survives and the offence names what does not.
    offence = _first_whitespace_or_control(resource)
    if offence is not None:
        index, char = offence
        safe = _redact_authority(resource)
        raise InvalidResourceError(
            "resource identifier must not contain whitespace or control characters "
            f"(RFC 3986 §2, RFC 9728 §3.3) — invalid character U+{ord(char):04X} "
            f"at offset {index}: {safe!r}"
        )

    # Scheme AND host, both checked explicitly. A guard phrased as "opaque or
    # authority-less" would wrongly admit the scheme-relative form
    # "//api.example.com/mcp", which urlsplit gives a netloc but no scheme.
    # Each of the three rejected shapes is missing a different half:
    #
    #   "/mcp"                  — relative reference: no scheme, no host.
    #   "//api.example.com/mcp" — scheme-relative: host but no scheme.
    #   "urn:example:api"       — opaque: scheme but no host. Without the gate
    #                             this derived the nonsense metadata URL
    #                             "urn:/.well-known/oauth-protected-resource/example:api".
    #
    # ``hostname`` rather than ``netloc``: an authority of only userinfo or a
    # port ("https://:8080/x") names no host either, so it has no RFC 9728 §3
    # insertion point — a `netloc`-based guard would admit both, which is why
    # the port-only rejection is pinned by tests of its own rather than left to
    # read as an accident. An identifier urlsplit itself refuses to parse
    # establishes no host a fortiori, so it falls under the same rejection —
    # with the redacted placeholder, not urllib's message.
    try:
        parsed = urlsplit(resource)
    except ValueError:
        parsed = None
    if parsed is None or not parsed.scheme or not parsed.hostname:
        safe = _redact_authority(resource)
        raise InvalidResourceError(
            "resource identifier must be an absolute URL with a scheme and a host "
            f"(RFC 8707 §2, RFC 9728 §3): {safe!r}"
        )

    # Userinfo next — after absoluteness has established there is an authority
    # to carry one, and ahead of the port so that credentials are the finding
    # the operator is told to act on first. ``is not None`` rather than
    # truthiness: "https://@api.example.com/mcp" parses with ``username == ""``
    # — the subcomponent is *present* (the "@" delimiter sits in the authority
    # the sinks reassemble and the adapters advertise verbatim) even though it
    # is empty, and RFC 9110 §4.2.4 forbids generating the subcomponent, not
    # merely non-empty credentials.
    if parsed.username is not None or parsed.password is not None:
        safe = _redact_authority(resource)
        raise InvalidResourceError(
            f"resource identifier must not contain a userinfo component (RFC 9110 §4.2.4): {safe!r}"
        )

    # Host characters next, once the authority is known to exist and no
    # credentials are left in it to be reported first.
    #
    # RFC 9110 §11.2 gives the auth-param value of a ``WWW-Authenticate``
    # challenge as a quoted-string, and §5.6.4 gives its content:
    # ``qdtext`` is every visible octet EXCEPT the two delimiters `"` and `\`,
    # and ``quoted-pair`` is `\` followed by one more octet. ``errors.py``
    # interpolates the derived PRM URL into that quoted-string as the
    # ``resource_metadata`` parameter, and every derivation in this module
    # carries the authority verbatim, so either delimiter in the host corrupts
    # the challenge — by two different mechanisms, both of which end in the
    # client addressing something other than this resource:
    #
    #   Bearer resource_metadata="https://api"example.com/.well-known/..."
    #
    # closes the quoted-string at the host and re-reads the rest of the URL as
    # garbage auth-params, while
    #
    #   Bearer resource_metadata="https://api\example.com/.well-known/..."
    #
    # is well-formed and therefore worse: `\e` is a quoted-pair, so a
    # conformant client unescapes it and fetches
    # "https://apiexample.com/.well-known/..." — a different host entirely,
    # with nothing in the challenge to suggest anything went wrong.
    #
    # ``urlsplit`` stops neither. It admits both octets into the authority and
    # ``hostname`` returns them unchanged, and ``urlunsplit`` writes them back
    # out unescaped, so they survive every step between this boundary and the
    # header. A sweep of all 256 byte values injected into the host position on
    # 3.12 — checking which construct, which survive verbatim into the derived
    # PRM URL, and which are outside ``qdtext`` — leaves exactly these two plus
    # DEL, and DEL is already rejected by the whitespace/control gate above.
    # `[` and `]` are the only values ``urlsplit`` itself refuses. So the gate
    # is two characters wide because two characters are the whole live gap; a
    # general "invalid host character" sweep would be dead code on the rest.
    #
    # Read off ``parsed.hostname``, and that is a decision rather than a
    # convenience. ``hostname`` in CPython is NOT percent-decoded — measured on
    # 3.12, ``urlsplit("https://api%22example.com/mcp").hostname`` is the
    # literal ``'api%22example.com'`` — so an escaped `%22` is neither decoded
    # into a delimiter here nor anywhere downstream, and the derived URL
    # carries the three characters ``%22``, which are ``qdtext``. It is a
    # useless host, but it is not this defect, and rejecting it would be a
    # rejection this rationale does not support. ``hostname`` also excludes the
    # userinfo and the port, which is what makes this gate disjoint from the
    # two around it: a `"` in the userinfo is caught by the gate above as an
    # `@`, and one in the port by the gate below as a non-digit.
    #
    # ``hostname`` also excludes the path and the query, and nothing else
    # covers them. RFC 9728 §3.1 inserts the well-known segment *between* the
    # host and them, so all three components land inside the one
    # ``resource_metadata`` quoted-string, and ``build_prm_url`` splices the
    # path and the query into the derived URL verbatim — so
    # `https://api.example.com/m"cp` still constructs and still reaches
    # ``errors.py``'s substitution. That is asserted below, so the scope of
    # this gate is pinned rather than left to be inferred. It stops at the host
    # because the consequence differs in kind rather than in degree: a
    # delimiter in the host sends a conformant client to a different origin,
    # while one in the path or the query keeps it on this one and ends in the
    # RFC 9728 §3.3 discard. Closing the rest is also a wider rejection than
    # two characters — the query's own grammar (RFC 3986 §3.4) is the honest
    # boundary there — and that is a decision with its own migration cost.
    #
    # The echo is the redacted authority like every other branch, which renders
    # the host — that is the component at fault, it is what the operator has to
    # change, and ``_redact_authority`` already deems it safe to print. The
    # offending character is named separately because the two have different
    # fixes and a bare echo makes them look like one finding.
    hostname = parsed.hostname or ""
    for delimiter in ('"', "\\"):
        if delimiter in hostname:
            safe = _redact_authority(resource)
            raise InvalidResourceError(
                f"resource identifier host must not contain a literal {delimiter!r} — it "
                "corrupts the WWW-Authenticate quoted-string carrying resource_metadata "
                f"(RFC 9110 §5.6.4, §11.2): {safe!r}"
            )

    # Port last, because it is the only check that needs a host to have been
    # established AND no userinfo to be in the way. ``SplitResult.port`` parses
    # lazily, so nothing above touches it: for "https://h:abc/mcp" the scheme is
    # "https" and the hostname is "h", and both halves of the absoluteness gate
    # pass. RFC 3986 §3.2.3 gives the port as ``*DIGIT``, so such an authority
    # is not one — and the consequence is the same one the gate exists for:
    # build_prm_url would derive
    # "https://h:abc/.well-known/oauth-protected-resource/mcp", and the MCP
    # adapters' "{scheme}://{netloc}" htu origin would be "https://h:abc", a
    # value no honest client proof can match. The realistic spelling is a typo
    # inside a real authority ("https://api.example.com:80O/mcp", letter O for
    # zero), not a hand-written "h:abc". ``from None``: urllib's "Port could not
    # be cast to integer value" is the mechanism, not the diagnosis.
    try:
        _ = parsed.port
    except ValueError:
        safe = _redact_authority(resource)
        raise InvalidResourceError(
            f"resource identifier must not contain a malformed port (RFC 3986 §3.2.3): {safe!r}"
        ) from None


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
        InvalidResourceError: If the resource identifier carries a fragment
            component (RFC 8707 §2 forbids one; it is rejected here rather than
            silently discarded by ``urlunsplit``), contains whitespace or a
            control character (RFC 3986 §2; ``urlsplit`` would strip it and
            derive a URL diverging from the identifier stored verbatim,
            RFC 9728 §3.3), is not an absolute URL with a scheme and a host
            (RFC 8707 §2 requires an absolute URI; RFC 9728 §3 inserts the
            well-known suffix after the host, so without one there is nothing
            to derive), carries a userinfo subcomponent (RFC 9110 §4.2.4),
            carries a literal `"` or `\\` in its host (RFC 9110 §5.6.4/§11.2 —
            both corrupt the quoted-string this URL is interpolated into), or
            carries a port that does not parse (RFC 3986 §3.2.3). Subclasses
            ``ValueError``, so an existing ``except ValueError`` still catches
            it.
    """
    # Defensive backstop. The authoritative gate is the same function called
    # from AuthplaneResource.__init__, which every construction path reaches —
    # see validate_prm_resource_identifier's docstring for the full call-site
    # map and for why this must not be the only check. (A query IS preserved below per RFC 9728 §3.1;
    # the two components are treated asymmetrically.)
    #
    # Before parsing, for the same reason build_metadata_url checks first:
    # urlsplit raises on some malformed inputs, so parsing above the guard
    # surfaces urllib's message in place of the RFC citation.
    validate_prm_resource_identifier(resource)

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
    # No separator re-add: behind the gate above the path is either empty or
    # already starts with "/", because RFC 3986 §3.3 gives a path following an
    # authority as exactly that ("path-abempty"), and the gate guarantees an
    # authority by requiring a host. The branch that used to add one back was
    # unreachable in both builders and is gone rather than kept for textual
    # parallelism — two copies of a branch neither derivation can take, each
    # with a coverage pragma, cost a reader more than the symmetry returns.
    path = parsed.path.rstrip("/")
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


def validate_issuer_identifier(issuer: str) -> None:
    """Raise ``InvalidIssuerError`` if *issuer* is not a usable issuer identifier.

    The issuer has two consumers in this SDK and they had nothing in common.
    ``build_metadata_url`` checked a query and a fragment; ``build_prm``
    (``oauth/prm.py``) checked nothing at all and copied the value straight into
    the ``authorization_servers`` member of the Protected Resource Metadata
    document, which RFC 9728 §3 serves to **unauthenticated** callers. So an
    issuer such as ``https://svc:s3cr3t@auth.example.com`` was published
    verbatim to anyone who fetched the document. One predicate with both
    consumers routed through it is the point of this function: a gate that only
    one of two sinks applies is the shape that produced the disclosure.

    Four checks, in a deterministic order:

    1. No query and no fragment component. RFC 8414 §2 gives the issuer
       identifier as "a URL that uses the https scheme and has no query or
       fragment components". Both are rejected symmetrically and on the raw
       string, so a bare ``?`` or ``#`` — an empty component ``urlsplit``
       reports as empty — is rejected too: the delimiter must never survive
       into the derived ``.well-known`` URL, and ``urlunsplit`` drops a
       fragment silently rather than preserving it. Reconciling instead of
       rejecting would let a malformed identifier resolve to a document it does
       not name, which RFC 8414 §3.3 then has the client reject for an
       ``issuer`` mismatch — the real cause hidden behind a confusing symptom.
    2. No whitespace or control characters, checked on the raw string, with
       the same class the resource gate applies — see
       ``_first_whitespace_or_control``. None is a URI character (RFC 3986 §2),
       so an issuer carrying one is not the URL RFC 8414 §2 requires. The
       consequence is the symptom check 1 exists to prevent, reached by a
       different route: ``urlsplit`` removes tab, CR and LF from anywhere in
       the input (measured on 3.12), so a configured issuer carrying one
       derives a fetch target *without* it, the AS answers with its real
       ``issuer``, and the byte-for-byte comparison in ``internal/metadata.py``
       — seeded from this same configured value — rejects the document as an
       "AS metadata issuer mismatch". The characters ``urlsplit`` does not
       strip (DEL, the C1 controls, U+00A0, U+FEFF) survive instead into the
       derived ``.well-known`` URL, which is no more fetchable for it. The
       message names the offending codepoint and its offset, because every
       character in the class is one nothing renders.
    3. The identifier must be an absolute URL with a scheme **and** a host.
       The scheme is RFC 8414 §2 (the issuer identifier is a URL). The host is
       RFC 8414 **§3.1**, not §2: §3.1 derives the metadata location by
       inserting ``/.well-known/oauth-authorization-server`` between the host
       and the issuer's path, so with no host there is nothing for that
       insertion to anchor to and the derivation yields a string no client can
       fetch. ``build_metadata_url`` demonstrated exactly that — a scheme-less
       ``api.example.com/mcp`` derived the relative, unfetchable
       ``/.well-known/oauth-authorization-server/api.example.com/mcp``.
       Checked on ``hostname`` rather than ``netloc`` for the reason the
       resource gate gives: an authority of only userinfo or only a port
       (``https://:8080``) names no host either.
    4. No userinfo subcomponent. RFC 9110 §4.2.4: "a sender MUST NOT generate
       the userinfo subcomponent" in an http(s) URI, and RFC 3986 §3.2.1 notes
       it routinely carries a credential in clear text. The issuer reaches two
       sinks that reassemble the authority verbatim — the PRM document's
       ``authorization_servers`` member described above, and the metadata fetch
       target ``build_metadata_url`` returns — so credentials embedded in it
       are rejected at construction rather than redacted at each sink. Checked
       last, so an issuer that is also scheme-relative reports the missing
       scheme first: that is the defect an operator fixes first.

    The scheme is deliberately **not** narrowed to ``https`` even though RFC
    8414 §2 would support it, matching the resource gate's identical relaxation
    so local development works (``http://localhost:8080``).

    The whitespace class is shared with the resource gate rather than narrowed
    for this one. An earlier reading of this function held that the divergence
    had no equivalent on the issuer, on the grounds that the issuer's derived
    URL is only ever fetched and never compared against the issuer
    byte-for-byte. The derived URL is not what is compared — the *issuer
    itself* is, in ``internal/metadata.py``, against the configured value — so
    the divergence exists and only the symptom differs. Check 2 above carries
    the mechanism.

    Args:
        issuer: The authorization server issuer identifier, as configured by
            the operator.

    Raises:
        InvalidIssuerError: If the issuer carries a query or a fragment
            component, contains whitespace or a control character, is not an
            absolute URL with a scheme and a host, or carries a userinfo
            subcomponent. Subclasses ``ValueError``, so an existing
            ``except ValueError`` still catches it.
    """
    # The raw-string check comes first: urlsplit itself raises on some
    # malformed identifiers (an unclosed IPv6 bracket, for one), and this guard
    # exists to report the RFC violation, not urllib's parse error. Report only
    # scheme://host/path (bare hostname, never netloc) so a credential-shaped
    # query (`?token=...`) or embedded userinfo does not leak into the message.
    if any(c in issuer for c in ("?", "#")):
        safe = _redact_authority(issuer)
        raise InvalidIssuerError(
            "issuer identifier must not contain a query or fragment component "
            f"(RFC 8414 §2): {safe!r}"
        )

    # Whitespace and controls, on the raw string and before the parse, for the
    # same reason the check above runs there: ``urlsplit`` removes tab, CR and
    # LF from anywhere in the input and lstrips a leading C0-control-or-space,
    # so a gate reading the parse result judges a string the operator never
    # configured. The same class as the resource gate, deliberately — the two
    # identifiers are configured side by side out of the same environment, and
    # a byte-order mark pasted onto the end of one is not a different mistake
    # from one pasted onto the end of the other.
    #
    # The consequence here is not RFC 9728 §3.3 but the confusing symptom
    # check 1 above exists to prevent. ``internal/metadata.py`` compares the
    # AS-advertised ``issuer`` against the configured one byte-for-byte, seeded
    # with this very value, so a configured issuer carrying a tab fetches from
    # a target that has had the tab removed, the AS answers honestly with its
    # own identifier, and the two disagree — surfacing as "AS metadata issuer
    # mismatch", which points the operator at the AS rather than at the
    # invisible character in their own configuration. The members of the class
    # ``urlsplit`` leaves alone fail earlier and more plainly: they ride into
    # the derived ``.well-known`` URL and the fetch simply does not resolve.
    offence = _first_whitespace_or_control(issuer)
    if offence is not None:
        index, char = offence
        safe = _redact_authority(issuer)
        raise InvalidIssuerError(
            "issuer identifier must not contain whitespace or control characters "
            f"(RFC 3986 §2, RFC 8414 §2) — invalid character U+{ord(char):04X} "
            f"at offset {index}: {safe!r}"
        )

    # Scheme AND host, both explicit, for the reasons in the docstring. An
    # identifier urlsplit itself refuses to parse establishes no host a
    # fortiori, so it falls under the same rejection — with the redacted
    # placeholder, not urllib's message. CPython's urlsplit invents no
    # authority for a scheme it recognises: "https:auth.example.com" and
    # "https:/auth.example.com" both parse with an empty netloc and no
    # hostname, so reading `hostname` settles the question and no separate
    # check for the authority's "//" on the raw string is needed. Verified by
    # execution on 3.12. A parser that filled the authority in would need that
    # extra check, because an identifier RFC 3986 §3 gives no authority at all
    # would otherwise be read as carrying the host this gate requires.
    try:
        parsed = urlsplit(issuer)
    except ValueError:
        parsed = None
    if parsed is None or not parsed.scheme or not parsed.hostname:
        safe = _redact_authority(issuer)
        raise InvalidIssuerError(
            "issuer identifier must be an absolute URL with a scheme and a host "
            f"(RFC 8414 §2, §3.1): {safe!r}"
        )

    # ``is not None`` rather than truthiness, for the reason the resource gate
    # spells out: "https://@auth.example.com" parses with ``username == ""`` and
    # the subcomponent is *present* — the "@" delimiter sits in the authority
    # both sinks reassemble — even though it is empty, and RFC 9110 §4.2.4
    # forbids generating the subcomponent, not merely non-empty credentials.
    if parsed.username is not None or parsed.password is not None:
        safe = _redact_authority(issuer)
        raise InvalidIssuerError(
            f"issuer identifier must not contain a userinfo component (RFC 9110 §4.2.4): {safe!r}"
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
        InvalidIssuerError: If the issuer carries a query or a fragment
            component (RFC 8414 §2 forbids both; they are rejected here rather
            than silently reconciled — that reconciliation would let a malformed
            identifier resolve to a document it does not actually name, and
            would later surface as a confusing "issuer mismatch" instead of the
            real cause, and a fragment is not preserved by ``urlunsplit`` at
            all), contains whitespace or a control character (RFC 3986 §2 —
            ``urlsplit`` strips some of the class and passes the rest through,
            so either way the derived URL stops agreeing with the configured
            identifier), is not an absolute URL with a scheme and a host
            (RFC 8414 §2 requires a URL; §3.1 inserts the well-known suffix
            after the host, so without one there is nothing to derive), or
            carries a userinfo subcomponent (RFC 9110 §4.2.4). Subclasses
            ``ValueError``, so existing ``except ValueError`` handlers are
            unaffected.
    """
    # One gate, shared with build_prm. This function used to carry its own
    # inline query/fragment check, which left the other consumer of an issuer —
    # oauth/prm.py's build_prm, which copies it into the PRM document's
    # `authorization_servers` member — with no check at all, and let the two
    # drift. The shared gate is a superset of what was here: it still rejects a
    # query or a fragment, and it additionally rejects an issuer that is not an
    # absolute URL with a scheme and a host, or that carries userinfo. Both
    # additions are reachable from here — the derivation below concatenates the
    # parsed path onto the well-known suffix, so a host-less issuer produced a
    # relative string no client could fetch, and a `svc:s3cr3t@` issuer was
    # carried verbatim into the metadata fetch target.
    validate_issuer_identifier(issuer)

    parsed = urlsplit(issuer)

    # Keep the path's own leading slash and remove only terminating ones — see
    # the note in build_prm_url, including why there is no separator re-add
    # here either. Before the shared gate this builder accepted a scheme-less
    # identifier, which put the whole authority in ``path`` with no leading
    # slash; requiring a host is what made that branch unreachable.
    path = parsed.path.rstrip("/")
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


_RESOURCE_METADATA_URL_SCHEMES = ("http", "https")


def validate_resource_metadata_url(url: str) -> None:
    """Raise ``InvalidResourceError`` if *url* cannot be advertised as ``resource_metadata``.

    This gates the operator-configured override for the RFC 9728 §5.1
    ``resource_metadata`` challenge parameter — the case where the Protected
    Resource Metadata document is hosted by the authorization server rather
    than derived from the resource identifier (``build_prm_url``). The derived
    URL inherits its guarantees from ``validate_prm_resource_identifier``; a
    configured one has to earn the same ones here, because it reaches the same
    sink: the quoted-string of a ``WWW-Authenticate`` challenge served to an
    unauthenticated caller, which then fetches it.

    The checks mirror the issuer gate — absolute URL with a scheme and a host,
    no whitespace or control characters, no userinfo, a parseable port — with
    two differences that follow from this being a URL to *fetch* rather than an
    identifier to *compare*:

    * The scheme is narrowed to ``http`` / ``https``. The identifier gates leave
      the scheme open because their value is compared, not dereferenced; this
      one is dereferenced by every client that honours the challenge, and
      RFC 9728 §5.1 gives the parameter as a URL of the metadata document.
      ``http`` stays accepted for the same reason it does on the issuer:
      local development against a loopback AS.
    * A literal ``"`` or ``\\`` is rejected **anywhere** in the value, not only
      in the host. The whole string lands inside one quoted-string (RFC 9110
      §5.6.4, §11.2), and ``_sanitize_header_value`` would otherwise replace
      the delimiter with a space and advertise a URL that fetches nothing,
      silently. The identifier gate stops at the host because the path and
      query of a derived URL are the operator's identifier and rejecting them
      is a migration; a configured override has no such constraint.

    A query is accepted, as it is on a derived URL. A fragment is rejected:
    it is never sent on the wire, so a value carrying one names a document the
    client does not fetch.

    Args:
        url: The metadata URL, as configured by the operator.

    Raises:
        InvalidResourceError: If the URL carries a fragment, contains
            whitespace or a control character, is not an absolute ``http`` /
            ``https`` URL with a host, carries a userinfo subcomponent, carries
            a literal ``"`` or ``\\``, or carries a port that does not parse.
            Subclasses ``ValueError``, so an existing ``except ValueError``
            still catches it.
    """
    if "#" in url:
        safe = _redact_authority(url)
        raise InvalidResourceError(
            f"resource metadata URL must not contain a fragment component (RFC 9728 §5.1): {safe!r}"
        )

    offence = _first_whitespace_or_control(url)
    if offence is not None:
        index, char = offence
        safe = _redact_authority(url)
        raise InvalidResourceError(
            "resource metadata URL must not contain whitespace or control characters "
            f"(RFC 3986 §2) — invalid character U+{ord(char):04X} at offset {index}: {safe!r}"
        )

    # Both delimiters, over the whole string — see the docstring for why this
    # is wider than the identifier gate's host-only scan.
    for delimiter in ('"', "\\"):
        if delimiter in url:
            safe = _redact_authority(url)
            raise InvalidResourceError(
                f"resource metadata URL must not contain a literal {delimiter!r} — it corrupts "
                "the WWW-Authenticate quoted-string carrying resource_metadata "
                f"(RFC 9110 §5.6.4, §11.2): {safe!r}"
            )

    try:
        parsed = urlsplit(url)
    except ValueError:
        parsed = None
    if parsed is None or not parsed.scheme or not parsed.hostname:
        safe = _redact_authority(url)
        raise InvalidResourceError(
            "resource metadata URL must be an absolute URL with a scheme and a host "
            f"(RFC 9728 §5.1): {safe!r}"
        )

    if parsed.scheme not in _RESOURCE_METADATA_URL_SCHEMES:
        safe = _redact_authority(url)
        raise InvalidResourceError(
            f"resource metadata URL scheme must be http or https (RFC 9728 §5.1): {safe!r}"
        )

    if parsed.username is not None or parsed.password is not None:
        safe = _redact_authority(url)
        raise InvalidResourceError(
            f"resource metadata URL must not contain a userinfo component (RFC 9110 §4.2.4): {safe!r}"
        )

    try:
        _ = parsed.port
    except ValueError:
        safe = _redact_authority(url)
        raise InvalidResourceError(
            f"resource metadata URL must not contain a malformed port (RFC 3986 §3.2.3): {safe!r}"
        ) from None
