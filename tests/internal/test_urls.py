"""Tests for URL utilities (RFC 8414 metadata URL construction)."""

import pytest

from authplane.errors import InvalidIssuerError, InvalidResourceError
from authplane.internal.urls import (
    build_metadata_url,
    build_prm_url,
    validate_issuer_identifier,
    validate_prm_resource_identifier,
    validate_resource_metadata_url,
)


class TestBuildMetadataUrl:
    """Tests for build_metadata_url per RFC 8414 Section 3."""

    def test_issuer_without_path(self) -> None:
        """Issuer with no path appends .well-known suffix directly."""
        result = build_metadata_url("https://auth.example.com")
        assert result == "https://auth.example.com/.well-known/oauth-authorization-server"

    def test_issuer_with_single_path_segment(self) -> None:
        """Issuer with path inserts .well-known after authority."""
        result = build_metadata_url("https://auth.example.com/tenant1")
        assert result == "https://auth.example.com/.well-known/oauth-authorization-server/tenant1"

    def test_issuer_with_multi_segment_path(self) -> None:
        """Issuer with multiple path segments inserts .well-known after authority."""
        result = build_metadata_url("https://auth.example.com/org/tenant1")
        assert (
            result == "https://auth.example.com/.well-known/oauth-authorization-server/org/tenant1"
        )

    def test_issuer_with_trailing_slash(self) -> None:
        """Trailing slash on issuer is normalized away."""
        result = build_metadata_url("https://auth.example.com/")
        assert result == "https://auth.example.com/.well-known/oauth-authorization-server"

    def test_issuer_with_path_and_trailing_slash(self) -> None:
        """Trailing slash on path issuer is normalized."""
        result = build_metadata_url("https://auth.example.com/tenant1/")
        assert result == "https://auth.example.com/.well-known/oauth-authorization-server/tenant1"

    def test_issuer_with_port(self) -> None:
        """Issuer with explicit port is preserved."""
        result = build_metadata_url("https://auth.example.com:8443")
        assert result == "https://auth.example.com:8443/.well-known/oauth-authorization-server"

    def test_issuer_with_port_and_path(self) -> None:
        """Issuer with port and path handles both correctly."""
        result = build_metadata_url("https://auth.example.com:8443/tenant1")
        assert (
            result == "https://auth.example.com:8443/.well-known/oauth-authorization-server/tenant1"
        )

    def test_http_issuer(self) -> None:
        """HTTP scheme is preserved (for dev mode)."""
        result = build_metadata_url("http://localhost:3000")
        assert result == "http://localhost:3000/.well-known/oauth-authorization-server"

    def test_http_issuer_with_path(self) -> None:
        """HTTP issuer with path inserts .well-known correctly."""
        result = build_metadata_url("http://localhost:3000/tenant1")
        assert result == "http://localhost:3000/.well-known/oauth-authorization-server/tenant1"


class TestResourceIdentifierValidation:
    """RFC 8707 §2 — a resource indicator MUST NOT carry a fragment."""

    def test_validate_rejects_fragment(self) -> None:
        with pytest.raises(ValueError, match="must not contain a fragment"):
            validate_prm_resource_identifier("https://api.example.com/mcp#frag")

    def test_validate_accepts_query(self) -> None:
        # A query is legal and is preserved by the derivation (RFC 9728 §3.1);
        # only the fragment is forbidden. The two are treated asymmetrically.
        validate_prm_resource_identifier("https://api.example.com/mcp?tenant=a")

    def test_validate_does_not_echo_credentials(self) -> None:
        with pytest.raises(ValueError) as exc:
            validate_prm_resource_identifier("https://svc:s3cr3t@api.example.com/mcp#frag")
        assert "s3cr3t" not in str(exc.value)
        assert "api.example.com" in str(exc.value)

    def test_malformed_port_does_not_mask_the_rfc_error(self) -> None:
        # ParseResult.port raises ValueError on a non-integer port. Building the
        # redacted authority for the error message must not surface urllib's
        # "Port could not be cast to integer value" in place of the RFC citation.
        with pytest.raises(ValueError) as exc:
            validate_prm_resource_identifier("https://h:abc/mcp#frag")
        assert "must not contain a fragment" in str(exc.value)
        assert "cast to integer" not in str(exc.value)


class TestResourceIdentifierAbsoluteness:
    """The identifier must be an absolute URL with a scheme AND a host.

    The two halves have different sources, which is why the exported gate is
    named for the PRM axis rather than for RFC 8707's. The scheme is RFC 8707
    §2's requirement ("MUST be an absolute URI", RFC 3986 §4.3:
    ``absolute-URI = scheme ":" hier-part [ "?" query ]``, which
    ``urn:example:api`` satisfies); the host is RFC 9728 §3's — the well-known suffix is inserted after the host component,
    so without one there is no derivable metadata URL, and in the MCP adapters
    no derivable DPoP ``htu`` origin. The three rejects below are each missing
    a different half, which is why all three are pinned independently.
    """

    def test_rejects_relative_reference(self) -> None:
        # No scheme, no host. The echo must be the string the operator wrote —
        # the fixed "scheme://host/path" template rendered this as ":///mcp".
        with pytest.raises(
            InvalidResourceError, match="absolute URL with a scheme and a host"
        ) as exc:
            validate_prm_resource_identifier("/mcp")
        assert "'/mcp'" in str(exc.value)

    def test_rejects_scheme_relative_reference(self) -> None:
        # urlsplit gives "//api.example.com/mcp" a netloc but no scheme — a
        # guard phrased as "opaque or authority-less" would wrongly admit it.
        # The scheme is the component missing from both this and the relative
        # form, so it has to be checked explicitly. The echo keeps the "//" and
        # no scheme, so it stays distinguishable from the scheme-less form
        # below — the message has to tell the operator WHICH half is missing.
        with pytest.raises(
            InvalidResourceError, match="absolute URL with a scheme and a host"
        ) as exc:
            validate_prm_resource_identifier("//api.example.com/mcp")
        assert "'//api.example.com/mcp'" in str(exc.value)

    def test_rejects_scheme_less_host_and_echoes_it_faithfully(self) -> None:
        # "api.example.com/mcp" is all path to urlsplit: no scheme, no netloc.
        # It must not render with an invented "//" — that made it identical to
        # the scheme-relative echo above.
        with pytest.raises(
            InvalidResourceError, match="absolute URL with a scheme and a host"
        ) as exc:
            validate_prm_resource_identifier("api.example.com/mcp")
        assert "'api.example.com/mcp'" in str(exc.value)

    def test_rejects_opaque_urn(self) -> None:
        # Scheme but no host. Before the gate this derived the nonsense
        # metadata URL "urn:/.well-known/oauth-protected-resource/example:api",
        # and the MCP adapters' htu origin became the literal "://".
        # The echo must stay opaque: the old template rendered it as
        # "urn://example:api" — an identifier that *appears* to have the host
        # (and port!) the message says is missing.
        with pytest.raises(
            InvalidResourceError, match="absolute URL with a scheme and a host"
        ) as exc:
            validate_prm_resource_identifier("urn:example:api")
        assert "'urn:example:api'" in str(exc.value)

    def test_accepts_http_localhost(self) -> None:
        # Deliberate profile relaxation: the scheme is not narrowed to https,
        # so local development against a plain-http server keeps working.
        validate_prm_resource_identifier("http://localhost:8080/mcp")

    def test_accepts_https_with_path_and_query(self) -> None:
        # Absolute identifiers with paths and queries are untouched by the
        # absoluteness gate — only the fragment axis rejects among them.
        validate_prm_resource_identifier("https://api.example.com/v2/mcp?tenant=a")

    def test_fragment_is_reported_before_absoluteness(self) -> None:
        # Deterministic ordering: an input violating both axes reports the
        # fragment. The fragment check must stay ahead of any parsing anyway
        # (see the unparseable-authority cases), so the order is not free.
        with pytest.raises(InvalidResourceError, match="must not contain a fragment"):
            validate_prm_resource_identifier("/mcp#frag")

    def test_unparseable_authority_is_rejected_with_the_redacted_placeholder(self) -> None:
        # An unclosed IPv6 bracket makes urlsplit itself raise. No host can be
        # established for such an identifier, so it falls under the same
        # rejection — reported with the gate's own message and the redaction
        # placeholder, not urllib's "Invalid IPv6 URL".
        with pytest.raises(InvalidResourceError) as exc:
            validate_prm_resource_identifier("https://[::1")
        assert "absolute URL with a scheme and a host" in str(exc.value)
        assert "(unparseable identifier)" in str(exc.value)
        assert "IPv6" not in str(exc.value)

    def test_rejection_does_not_echo_credentials(self) -> None:
        # Same redaction contract as the fragment gate: userinfo embedded in
        # the authority never reaches the error message.
        with pytest.raises(InvalidResourceError) as exc:
            validate_prm_resource_identifier("//svc:s3cr3t@api.example.com/mcp")
        assert "s3cr3t" not in str(exc.value)
        assert "api.example.com" in str(exc.value)

    def test_build_prm_url_backstop_rejects_too(self) -> None:
        # The defensive backstop in the derivation shares the gate, same as it
        # does for the fragment axis.
        with pytest.raises(InvalidResourceError, match="absolute URL with a scheme and a host"):
            build_prm_url("/mcp")

    def test_userinfo_only_authority_is_rejected_without_echoing_the_secret(self) -> None:
        # netloc present, hostname empty — the load-bearing case for rendering
        # the echo from the redacted `host` rather than `host or parsed.netloc`:
        # that rejected variant would have re-admitted "svc:s3cr3t@" into the
        # very message the renderer exists to redact. Rejected on the
        # absoluteness axis (no host), ahead of the userinfo check.
        with pytest.raises(
            InvalidResourceError, match="absolute URL with a scheme and a host"
        ) as exc:
            validate_prm_resource_identifier("https://svc:s3cr3t@/x")
        assert "s3cr3t" not in str(exc.value)
        assert "svc" not in str(exc.value)
        assert "'https:///x'" in str(exc.value)

    def test_port_only_authority_is_rejected(self) -> None:
        # The gate reads `hostname`, which is empty here, where `netloc` would
        # be ":8080" and would admit the input. An authority of only a port
        # names no host, so there is no RFC 9728 §3 insertion point — the
        # strictness is intentional, not an accident to be "simplified" back
        # to `netloc`.
        with pytest.raises(InvalidResourceError, match="absolute URL with a scheme and a host"):
            validate_prm_resource_identifier("https://:8080/x")

    def test_port_only_authority_renders_faithfully(self) -> None:
        # The redacted echo re-renders the port from `SplitResult.port`, so the
        # operator sees the exact shape they configured.
        with pytest.raises(InvalidResourceError) as exc:
            validate_prm_resource_identifier("https://:8080/x")
        assert "'https://:8080/x'" in str(exc.value)

    def test_empty_authority_echo_keeps_the_slashes(self) -> None:
        # "https://" parses to an EMPTY netloc, so an echo gated on the netloc
        # alone rendered it as 'https:' — indistinguishable from the opaque
        # "https:", the dropped-half defect in the other direction. The "//"
        # is now gated on the raw string spelling it out.
        with pytest.raises(InvalidResourceError) as exc:
            validate_prm_resource_identifier("https://")
        assert "'https://'" in str(exc.value)

    def test_empty_host_file_url_echo_keeps_the_slashes(self) -> None:
        with pytest.raises(InvalidResourceError) as exc:
            validate_prm_resource_identifier("file:///x")
        assert "'file:///x'" in str(exc.value)


class TestResourceIdentifierUserinfo:
    """RFC 9110 §4.2.4 — a sender MUST NOT generate the userinfo subcomponent.

    The identifier feeds three sinks that reassemble the authority from
    ``netloc``, not ``hostname``: the derived PRM URL (handed to
    unauthenticated callers in a 401 ``WWW-Authenticate`` challenge), the MCP
    adapters' DPoP ``htu`` origin (which no honest proof could then match),
    and the ``fail_closed`` warning's log record. Rejecting at construction
    closes all three at once instead of redacting at each.
    """

    def test_rejects_credentials_and_names_the_userinfo_component(self) -> None:
        with pytest.raises(
            InvalidResourceError, match="must not contain a userinfo component"
        ) as exc:
            validate_prm_resource_identifier("https://svc:s3cr3t@api.example.com/mcp")
        assert "RFC 9110" in str(exc.value)

    def test_rejection_does_not_echo_the_secret(self) -> None:
        # Same redaction contract as every other axis: the echo renders the
        # bare hostname, never the netloc the credentials live in.
        with pytest.raises(InvalidResourceError) as exc:
            validate_prm_resource_identifier("https://svc:s3cr3t@api.example.com/mcp")
        assert "s3cr3t" not in str(exc.value)
        assert "svc" not in str(exc.value)
        assert "api.example.com" in str(exc.value)

    def test_rejects_username_only_userinfo(self) -> None:
        # A password-less userinfo ("svc@") is still the subcomponent RFC 9110
        # §4.2.4 forbids generating.
        with pytest.raises(InvalidResourceError, match="userinfo"):
            validate_prm_resource_identifier("https://svc@api.example.com/mcp")

    def test_rejects_empty_userinfo(self) -> None:
        # Decision, pinned: "https://@api.example.com/mcp" parses with
        # username == "" — the subcomponent is PRESENT (the "@" delimiter sits
        # in the authority the sinks reassemble and the adapters advertise
        # verbatim) even though it is empty. The gate checks `is not None`,
        # not truthiness, so the empty form is rejected too.
        with pytest.raises(InvalidResourceError, match="userinfo"):
            validate_prm_resource_identifier("https://@api.example.com/mcp")

    def test_userinfo_is_reported_after_absoluteness(self) -> None:
        # Deterministic order: an input missing a host reports the
        # absoluteness violation even when it also carries userinfo.
        with pytest.raises(InvalidResourceError, match="absolute URL with a scheme and a host"):
            validate_prm_resource_identifier("https://svc:s3cr3t@/x")

    def test_build_prm_url_backstop_rejects_userinfo_too(self) -> None:
        # The PRM-URL sink itself: build_prm_url passes `netloc` to urlunsplit,
        # so without the shared gate this derived a credential-bearing URL for
        # a 401 challenge header.
        with pytest.raises(InvalidResourceError, match="userinfo"):
            build_prm_url("https://svc:s3cr3t@api.example.com/mcp")


class TestResourceIdentifierPort:
    """RFC 3986 §3.2.3 — ``port = *DIGIT``.

    ``SplitResult.port`` parses lazily, so a non-numeric or out-of-range port
    survives the scheme/host checks: ``hostname`` is ``'h'`` and ``scheme`` is
    ``'https'`` for ``https://h:abc/mcp``. Such an authority has the same
    consequence as the relative and opaque shapes — no derivable origin — so it
    is rejected at the same construction-time gate.
    """

    def test_rejects_non_numeric_port(self) -> None:
        with pytest.raises(InvalidResourceError, match="must not contain a malformed port") as exc:
            validate_prm_resource_identifier("https://h:abc/mcp")
        assert "RFC 3986 §3.2.3" in str(exc.value)

    def test_rejects_the_realistic_typo(self) -> None:
        # The shape an operator actually produces: letter O for zero in a real
        # authority. Without the gate this derived the PRM URL
        # "https://api.example.com:80O/.well-known/oauth-protected-resource/mcp"
        # and an htu origin of "https://api.example.com:80O", neither of which
        # any honest client proof can match.
        with pytest.raises(InvalidResourceError, match="must not contain a malformed port"):
            validate_prm_resource_identifier("https://api.example.com:80O/mcp")

    def test_rejects_out_of_range_port(self) -> None:
        # The other way SplitResult.port raises: all digits, but outside
        # 0-65535, which is not an addressable port either.
        with pytest.raises(InvalidResourceError, match="must not contain a malformed port"):
            validate_prm_resource_identifier("https://api.example.com:99999/mcp")

    def test_out_of_range_port_is_echoed_verbatim(self) -> None:
        # An all-digit port is not credential-shaped, so it is echoed as
        # written — a message about the port that renders the identifier
        # WITHOUT one shows the operator a string they did not write.
        with pytest.raises(InvalidResourceError) as exc:
            validate_prm_resource_identifier("https://api.example.com:99999/mcp")
        assert "'https://api.example.com:99999/mcp'" in str(exc.value)

    def test_non_numeric_port_echo_marks_the_port_instead_of_dropping_it(self) -> None:
        # A port carrying non-digits cannot be echoed verbatim: an operator who
        # forgot the "@" writes "https://user:pass/x", which urlsplit reports
        # with NO userinfo and a port of "pass". The redaction contract wins,
        # but the marker still shows the operator which component is at fault
        # rather than silently rendering an authority with no port at all.
        with pytest.raises(InvalidResourceError) as exc:
            validate_prm_resource_identifier("https://h:abc/mcp")
        assert "'https://h:(malformed port)/mcp'" in str(exc.value)

    def test_userinfo_shaped_port_does_not_echo_the_secret(self) -> None:
        # The load-bearing half of the rule above.
        with pytest.raises(InvalidResourceError) as exc:
            validate_prm_resource_identifier("https://user:s3cr3t/x")
        assert "s3cr3t" not in str(exc.value)

    def test_ipv6_authority_with_a_malformed_port_stays_bracketed(self) -> None:
        # host_literal re-brackets the literal SplitResult.hostname strips, and
        # the port marker is appended outside the brackets.
        with pytest.raises(InvalidResourceError) as exc:
            validate_prm_resource_identifier("https://[::1]:abc/x")
        assert "'https://[::1]:(malformed port)/x'" in str(exc.value)

    def test_fragment_is_still_reported_before_the_port(self) -> None:
        # Ordering pin: the fragment check stays first, so the pre-existing
        # test_malformed_port_does_not_mask_the_rfc_error keeps its meaning.
        with pytest.raises(InvalidResourceError, match="must not contain a fragment"):
            validate_prm_resource_identifier("https://h:abc/mcp#frag")

    def test_userinfo_is_reported_before_the_port(self) -> None:
        # Deterministic order: fragment, whitespace, absoluteness, userinfo,
        # port. Credentials are the finding the operator has to act on first.
        with pytest.raises(InvalidResourceError, match="userinfo"):
            validate_prm_resource_identifier("https://svc:s3cr3t@api.example.com:abc/mcp")

    def test_valid_port_still_accepted(self) -> None:
        validate_prm_resource_identifier("http://localhost:8080/mcp")
        validate_prm_resource_identifier("https://api.example.com:8443/mcp")

    def test_build_prm_url_backstop_rejects_a_malformed_port_too(self) -> None:
        # Without the gate this derived a PRM URL from an authority that has no
        # usable origin, and returned it from AuthplaneResource.prm_url() into
        # a 401 challenge header.
        with pytest.raises(InvalidResourceError, match="must not contain a malformed port"):
            build_prm_url("https://h:abc/mcp")


class TestResourceIdentifierHostDelimiters:
    r"""A `"` or a `\` in the host corrupts the challenge that advertises it.

    RFC 9110 §11.2 makes ``resource_metadata`` a quoted-string and §5.6.4 makes
    those two octets its delimiters. ``errors.py`` interpolates the derived PRM
    URL into it, and every derivation here carries the authority verbatim —
    ``urlsplit`` admits both octets into the host, ``hostname`` returns them
    unchanged and ``urlunsplit`` writes them back out unescaped, all measured on
    3.12. A sweep of all 256 byte values in the host position leaves exactly
    these two outside ``qdtext`` once DEL is accounted for by the
    whitespace/control gate, which is why the gate is two characters wide and
    not a general host character-set sweep.
    """

    def test_rejects_literal_quote_in_host(self) -> None:
        # Without the gate the challenge ships as
        #   Bearer resource_metadata="https://api"example.com/.well-known/..."
        # and a conformant client reads the quoted-string as ending at the host.
        with pytest.raises(InvalidResourceError, match="host must not contain a literal") as exc:
            validate_prm_resource_identifier('https://api"example.com/mcp')
        assert "RFC 9110 §5.6.4, §11.2" in str(exc.value)
        assert "'\"'" in str(exc.value)

    def test_rejects_literal_backslash_in_host(self) -> None:
        # The worse of the two: the challenge stays well-formed, so nothing
        # looks wrong, but `\e` is a quoted-pair and a client that unescapes it
        # fetches https://apiexample.com/... — a different host.
        with pytest.raises(InvalidResourceError, match="host must not contain a literal") as exc:
            validate_prm_resource_identifier("https://api\\example.com/mcp")
        assert "'\\\\'" in str(exc.value)

    def test_quote_is_reported_before_backslash(self) -> None:
        # Deterministic when both are present, so the message does not depend
        # on which one urlsplit happens to see first.
        with pytest.raises(InvalidResourceError) as exc:
            validate_prm_resource_identifier('https://a"b\\c.example.com/mcp')
        assert "'\"'" in str(exc.value)

    def test_the_gate_is_reached_through_build_prm_url(self) -> None:
        # build_prm_url is the function that actually derives the advertised
        # URL, and its production caller sits on a 401 response path.
        with pytest.raises(InvalidResourceError, match="host must not contain a literal"):
            build_prm_url('https://api"example.com/mcp')

    def test_rejection_message_shows_the_host_at_fault(self) -> None:
        # The host is the component the operator has to change, and
        # _redact_authority already deems it safe to print.
        with pytest.raises(InvalidResourceError) as exc:
            validate_prm_resource_identifier('https://api"example.com/mcp')
        assert 'api"example.com' in str(exc.value)

    def test_userinfo_is_reported_before_a_host_delimiter(self) -> None:
        # Credentials stay the first finding: they are the more urgent fix, and
        # the userinfo gate runs ahead of this one.
        with pytest.raises(InvalidResourceError) as exc:
            validate_prm_resource_identifier('https://svc:s3cr3t@api"example.com/mcp')
        assert "userinfo component" in str(exc.value)
        assert "s3cr3t" not in str(exc.value)

    def test_host_delimiter_is_reported_before_a_malformed_port(self) -> None:
        # The authority anchors every derived value — the PRM URL's origin and
        # the adapters' htu origin — so a host defect is named before a port one.
        with pytest.raises(InvalidResourceError) as exc:
            validate_prm_resource_identifier('https://a"b:80O/mcp')
        assert "host must not contain a literal" in str(exc.value)

    def test_a_delimiter_in_the_userinfo_is_not_a_host_finding(self) -> None:
        # hostname excludes the userinfo, so this gate is disjoint from the one
        # above rather than shadowing it. Reported as a userinfo defect.
        with pytest.raises(InvalidResourceError) as exc:
            validate_prm_resource_identifier('https://sv"c@api.example.com/mcp')
        assert "userinfo component" in str(exc.value)

    def test_percent_escaped_quote_is_not_rejected(self) -> None:
        # Measured on 3.12: CPython's `hostname` does NOT percent-decode, so
        # urlsplit("https://api%22example.com/mcp").hostname is the literal
        # 'api%22example.com'. Nothing downstream decodes it either, and the
        # three characters "%22" are qdtext, so the challenge stays intact.
        # A useless host, but not this defect — and rejecting it would be a
        # rejection this gate's rationale does not support.
        validate_prm_resource_identifier("https://api%22example.com/mcp")
        assert "%22" in build_prm_url("https://api%22example.com/mcp")

    def test_accepts_the_shapes_an_operator_actually_configures(self) -> None:
        # Acceptance control: the gate must not be rejecting everything, and in
        # particular must not be rejecting the qdtext punctuation that is legal
        # in a host or that this module already handles elsewhere.
        for resource in (
            "https://api.example.com/mcp",
            "https://api.example.com:8443/mcp",
            "http://localhost:8080/mcp",
            "https://[::1]:8443/mcp",
            "https://api-01.example.com/v2/mcp?tenant=a",
            "https://xn--80ak6aa92e.example.com/mcp",
        ):
            validate_prm_resource_identifier(resource)
        # A `"` outside the host is not this gate's business: the path and the
        # query are different components with different consumers, and
        # narrowing them is a separate decision with its own migration cost.
        validate_prm_resource_identifier('https://api.example.com/m"cp')


class TestResourceIdentifierWhitespace:
    """Whitespace splits the gate's view from the stored verbatim identifier.

    ``urlsplit`` removes tab/CR/LF anywhere and, since CPython 3.11 (the
    ``requires-python`` floor), lstrips leading C0-control-or-space — both
    verified by execution on 3.11 and 3.12. A parse-time gate would therefore
    pass a value whose derived PRM URL differs byte-for-byte from the
    ``verbatim_resource`` the adapters advertise, which RFC 9728 §3.3 obliges
    a conformant client to discard. The check runs on the raw string, before
    parsing.
    """

    def test_rejects_internal_tab(self) -> None:
        # urlsplit strips the tab and reports hostname='api.example.com', so
        # without the raw-string check the gate passed this while the stored
        # identifier kept the tab.
        with pytest.raises(InvalidResourceError, match="must not contain whitespace") as exc:
            validate_prm_resource_identifier("https://api.exa\tmple.com/mcp")
        assert "RFC 9728 §3.3" in str(exc.value)

    def test_rejects_leading_space(self) -> None:
        # The 3.11+ WHATWG lstrip: urlsplit(" https://...") parses as though
        # the space were never there.
        with pytest.raises(InvalidResourceError, match="must not contain whitespace"):
            validate_prm_resource_identifier(" https://api.example.com/mcp")

    def test_rejects_trailing_space(self) -> None:
        # A trailing space survives into `path` rather than being stripped,
        # but it is not a URI character (RFC 3986 §2) and would ride into the
        # derived well-known URL — rejected by the same raw-string check.
        with pytest.raises(InvalidResourceError, match="must not contain whitespace"):
            validate_prm_resource_identifier("https://api.example.com/mcp ")

    def test_rejects_leading_c0_control(self) -> None:
        # The 3.11+ lstrip removes C0 controls, not only space — a leading
        # \x01 is invisible to the parse but present in the stored identifier,
        # the identical divergence through a character isspace() misses.
        with pytest.raises(InvalidResourceError, match="whitespace or control characters"):
            validate_prm_resource_identifier("\x01https://api.example.com/mcp")

    def test_fragment_still_reported_first(self) -> None:
        # Order stays deterministic: fragment, then whitespace, then
        # absoluteness, then userinfo.
        with pytest.raises(InvalidResourceError, match="must not contain a fragment"):
            validate_prm_resource_identifier(" /mcp#frag")

    def test_whitespace_reported_before_absoluteness(self) -> None:
        # " /mcp" violates both the whitespace and the absoluteness axes.
        with pytest.raises(InvalidResourceError, match="must not contain whitespace"):
            validate_prm_resource_identifier(" /mcp")

    def test_whitespace_rejection_does_not_echo_credentials(self) -> None:
        # The raw string may carry userinfo too; the echo stays redacted.
        with pytest.raises(InvalidResourceError) as exc:
            validate_prm_resource_identifier(" https://svc:s3cr3t@api.example.com/mcp")
        assert "s3cr3t" not in str(exc.value)


class TestWhitespaceAndControlClass:
    """The rejected class is C0 + space, DEL + C1, Unicode whitespace, U+FEFF.

    RFC 3986 §2 builds every URI component out of ``unreserved``, ``reserved``
    and ``pct-encoded``, all printable ASCII, so none of these is a URI
    character and an identifier carrying one is not a URI at all. The class was
    ``isspace() or ord(ch) <= 0x20``, which left DEL and the C1 controls
    accepted — ``urlsplit`` neither strips nor rejects those — and left U+FEFF
    accepted too, because CPython's ``isspace()`` returns False for it.

    Every codepoint asserted here was checked by execution before being written
    down; the widening adds exactly U+007F-U+009F and U+FEFF and removes
    nothing.
    """

    @pytest.mark.parametrize(
        ("codepoint", "why"),
        [
            (0x007F, "DEL: not stripped by urlsplit and not matched by isspace()"),
            (0x0080, "C1: first of the range isspace() does not report"),
            (0x0085, "NEL: the ONE C1 control CPython's isspace() does report"),
            (0x009F, "C1: last of the range"),
            (0x00A0, "NO-BREAK SPACE: isspace() already reported it"),
            (0x1680, "OGHAM SPACE MARK"),
            (0x2028, "LINE SEPARATOR"),
            (0x2029, "PARAGRAPH SEPARATOR"),
            (0x202F, "NARROW NO-BREAK SPACE"),
            (0x3000, "IDEOGRAPHIC SPACE"),
            (0xFEFF, "ZERO WIDTH NO-BREAK SPACE: isspace() returns False, Cf not Zs"),
        ],
    )
    def test_rejects_codepoint_in_the_path(self, codepoint: int, why: str) -> None:
        resource = f"https://api.example.com/m{chr(codepoint)}cp"
        with pytest.raises(InvalidResourceError, match="whitespace or control characters"):
            validate_prm_resource_identifier(resource)

    @pytest.mark.parametrize(
        ("codepoint", "why"),
        [
            (0x0021, "EXCLAMATION MARK: a sub-delim, legal in a URI"),
            (0x00A1, "INVERTED EXCLAMATION MARK: printable non-ASCII, deliberately kept"),
            (0x200B, "ZERO WIDTH SPACE: not White_Space and not in the class"),
        ],
    )
    def test_accepts_codepoint_in_the_path(self, codepoint: int, why: str) -> None:
        # The acceptance control, and the second entry is the load-bearing one:
        # narrowing the identifier to ASCII is a separate, undecided axis, so
        # this gate must not settle it as a side effect of covering C1.
        validate_prm_resource_identifier(f"https://api.example.com/m{chr(codepoint)}cp")

    def test_del_in_the_path_was_previously_accepted(self) -> None:
        # The concrete regression: urlsplit passes DEL straight through, so the
        # identifier was stored and advertised with an invisible byte in it.
        with pytest.raises(InvalidResourceError, match="whitespace or control characters"):
            validate_prm_resource_identifier("https://api.example.com/m\x7fcp")

    def test_message_names_the_codepoint_and_the_offset(self) -> None:
        # The whole value of this gate is pointing at a byte nothing renders.
        # An echo of the identifier is useless on its own: the repr shows what
        # SURVIVES the parse, and what survives is the string minus the defect.
        with pytest.raises(InvalidResourceError) as exc:
            validate_prm_resource_identifier("https://api.example.com/m\x7fcp")
        assert "U+007F" in str(exc.value)
        assert "at offset 25" in str(exc.value)

    def test_offset_is_a_codepoint_index_not_a_byte_index(self) -> None:
        # Python iterates by codepoint, so a multi-byte character ahead of the
        # offence must not shift the reported offset.
        with pytest.raises(InvalidResourceError) as exc:
            validate_prm_resource_identifier("https://api.example.com/\u00e9\u00a0cp")
        assert "U+00A0" in str(exc.value)
        assert "at offset 25" in str(exc.value)

    def test_reports_the_first_offence_when_several_are_present(self) -> None:
        with pytest.raises(InvalidResourceError) as exc:
            validate_prm_resource_identifier("https://api.example.com/\ufeffm\x7fcp")
        assert "U+FEFF" in str(exc.value)
        assert "at offset 24" in str(exc.value)

    def test_codepoint_is_reported_without_emitting_the_character(self) -> None:
        # Naming it as U+XXXX rather than interpolating it keeps the invisible
        # byte out of a startup log, which is where this message lands.
        with pytest.raises(InvalidResourceError) as exc:
            validate_prm_resource_identifier("https://api.example.com/m\ufeffcp")
        assert "\ufeff" not in str(exc.value)

    def test_control_character_in_the_host_beats_the_delimiter_gate(self) -> None:
        # DEL in the host is in BOTH this class and the set of octets that
        # reach the WWW-Authenticate quoted-string. This gate runs first, on the
        # raw string, so the finding is deterministic and names the codepoint.
        with pytest.raises(InvalidResourceError) as exc:
            validate_prm_resource_identifier("https://api\x7fexample.com/mcp")
        assert "whitespace or control characters" in str(exc.value)
        assert "U+007F" in str(exc.value)

    def test_the_fragment_gate_still_runs_first(self) -> None:
        # Order is unchanged by the widening: fragment, then this class.
        with pytest.raises(InvalidResourceError, match="must not contain a fragment"):
            validate_prm_resource_identifier("https://api.example.com/m\x7fcp#frag")

    def test_accepts_the_shapes_an_operator_actually_configures(self) -> None:
        # Acceptance control for the class as a whole.
        for resource in (
            "https://api.example.com/mcp",
            "https://api.example.com:8443/v2/mcp?tenant=a",
            "http://localhost:8080/mcp",
            "https://api.example.com/mcp%20with%20escapes",
        ):
            validate_prm_resource_identifier(resource)


def test_unparseable_authority_does_not_mask_the_rfc_error() -> None:
    # urlparse raises ValueError("Invalid IPv6 URL") on an unclosed bracket —
    # before the fragment is ever split off. Both guards must still report the
    # RFC violation they were written for, not urllib's parse failure.
    with pytest.raises(ValueError) as exc:
        validate_prm_resource_identifier("https://[::1#frag")
    assert "must not contain a fragment" in str(exc.value)
    assert "IPv6" not in str(exc.value)

    with pytest.raises(ValueError) as exc:
        build_metadata_url("https://[::1?x=1")
    assert "must not contain a query or fragment" in str(exc.value)
    assert "IPv6" not in str(exc.value)


def test_build_prm_url_also_reports_the_rfc_error_not_urllib_s() -> None:
    # The third guard kept the original shape after the first two were fixed:
    # build_prm_url parsed before calling validate_prm_resource_identifier, so an
    # unclosed IPv6 bracket surfaced "Invalid IPv6 URL" instead of the citation.
    with pytest.raises(ValueError) as exc:
        build_prm_url("https://[::1#frag")
    assert "must not contain a fragment" in str(exc.value)
    assert "IPv6" not in str(exc.value)


class TestLeadingSlashPreservation:
    """A doubled leading slash is a distinct identifier, not a normalization."""

    def test_prm_double_leading_slash_does_not_collapse(self) -> None:
        assert build_prm_url("https://api.example.com//mcp") != build_prm_url(
            "https://api.example.com/mcp"
        )

    def test_metadata_double_leading_slash_does_not_collapse(self) -> None:
        assert build_metadata_url("https://auth.example.com//t") != build_metadata_url(
            "https://auth.example.com/t"
        )

    def test_terminating_slash_still_stripped(self) -> None:
        assert build_prm_url("https://api.example.com/mcp/") == build_prm_url(
            "https://api.example.com/mcp"
        )


def test_issuer_error_is_matchable_and_still_a_value_error() -> None:
    # Additive: the guards raised a bare ValueError before, and that is a public
    # contract — but it was indistinguishable from any other ValueError the SDK
    # raises (e.g. "jwks_refresh_seconds must be positive").
    with pytest.raises(InvalidIssuerError):
        build_metadata_url("https://auth.example.com/?x=1")
    with pytest.raises(ValueError):
        build_metadata_url("https://auth.example.com/?x=1")


def test_neither_builder_derives_from_a_scheme_less_identifier() -> None:
    # The asymmetry this test used to pin is gone. A scheme-less issuer was
    # accepted, because build_metadata_url gated only on ?/#; urlsplit then put
    # the whole authority in `path` with no leading slash, and the separator
    # re-add turned it into the RELATIVE, unfetchable
    # "/.well-known/oauth-authorization-server/api.example.com/mcp" — a string
    # named as a derivation success while no client could ever fetch it. The
    # issuer gate now requires a host for the reason RFC 8414 §3.1 gives (the
    # well-known suffix is inserted after the host), so both builders reject
    # the same shape, each with the error class for its own identifier.
    with pytest.raises(InvalidIssuerError) as exc:
        build_metadata_url("api.example.com/mcp")
    assert "absolute URL with a scheme and a host" in str(exc.value)
    assert "RFC 8414 §2, §3.1" in str(exc.value)
    with pytest.raises(InvalidResourceError):
        build_prm_url("api.example.com/mcp")


class TestParamsSegmentIsNotCollapsed:
    """An RFC 3986 ";params" segment is part of the path, not a separate slot.

    ``urlparse`` peels it off the last path segment into ``ParseResult.params``;
    ``urlunparse`` then needs it passed back or the segment is silently dropped.
    Both builders passed "", so "/mcp;v=1" and "/mcp" derived the same document —
    two distinct identifiers collapsing onto one, which is the whole class of bug
    the sibling tests above cover for the leading and terminating slash.
    """

    def test_prm_params_segment_does_not_collapse(self) -> None:
        assert build_prm_url("https://api.example.com/mcp;v=1") != build_prm_url(
            "https://api.example.com/mcp"
        )

    def test_metadata_params_segment_does_not_collapse(self) -> None:
        assert build_metadata_url("https://auth.example.com/t;jsessionid=1") != (
            build_metadata_url("https://auth.example.com/t")
        )

    def test_prm_params_segment_is_kept_verbatim(self) -> None:
        # Not just "different" — the segment has to survive into the derived URL.
        assert build_prm_url("https://api.example.com/mcp;v=1").endswith(
            "/.well-known/oauth-protected-resource/mcp;v=1"
        )


def test_resource_error_is_matchable_and_still_a_value_error() -> None:
    # The counterpart of test_issuer_error_is_matchable_and_still_a_value_error.
    # Both guards raised a bare ValueError before, and that stays a public
    # contract; what the class adds is telling an identifier misconfiguration
    # apart from any other ValueError the SDK raises.
    with pytest.raises(InvalidResourceError):
        validate_prm_resource_identifier("https://api.example.com/mcp#frag")
    with pytest.raises(ValueError):
        validate_prm_resource_identifier("https://api.example.com/mcp#frag")
    with pytest.raises(InvalidResourceError):
        build_prm_url("https://api.example.com/mcp#frag")


def test_identifier_errors_are_exported_from_the_package_root() -> None:
    # Both classes exist to be caught by name, which only works if they are
    # importable from the root. Nothing else in the suite imports them from
    # there — the tests above reach into authplane.errors — so without this the
    # __all__ entries could rot without anything noticing. The gate function
    # is held to the same bar for a stronger reason than either class: both
    # MCP adapters import it by this name through the package root, so a
    # rotted entry breaks an installed adapter/core pair at import time.
    import authplane

    assert "InvalidIssuerError" in authplane.__all__
    assert "InvalidResourceError" in authplane.__all__
    assert "validate_prm_resource_identifier" in authplane.__all__
    # Same rationale, same consumers: both adapters import this one through the
    # package root as well, so a rotted entry breaks an installed pair.
    assert "validate_resource_metadata_url" in authplane.__all__
    assert authplane.InvalidIssuerError is InvalidIssuerError
    assert authplane.InvalidResourceError is InvalidResourceError
    assert authplane.validate_prm_resource_identifier is validate_prm_resource_identifier
    assert authplane.validate_resource_metadata_url is validate_resource_metadata_url
    # The name is the contract, not just the object: it is exported under the
    # PRM-scoped spelling because the gate requires a host, which RFC 8707 §2
    # does not (it requires an absolute URI, RFC 3986 §4.3 — "urn:example:api"
    # is one). A later, weaker gate for the general resource-indicator axis
    # would need its own name, so this one must not drift back to claiming it.
    assert not hasattr(authplane, "validate_resource_indicator")


class TestIssuerIdentifierGate:
    """The issuer had two consumers and only one of them validated anything.

    ``build_metadata_url`` carried an inline query/fragment check;
    ``build_prm`` copied the issuer into the PRM document's
    ``authorization_servers`` member with none. One exported predicate with both
    consumers routed through it is what closes that, and it also lets the
    metadata derivation reject two shapes it previously derived garbage from.
    """

    def test_rejects_userinfo_bearing_issuer(self) -> None:
        # Previously carried verbatim into the metadata fetch target.
        with pytest.raises(InvalidIssuerError, match="must not contain a userinfo component"):
            build_metadata_url("https://svc:s3cr3t@auth.example.com/t")

    def test_userinfo_rejection_does_not_echo_the_credential(self) -> None:
        with pytest.raises(InvalidIssuerError) as exc:
            build_metadata_url("https://svc:s3cr3t@auth.example.com/t")
        assert "s3cr3t" not in str(exc.value)

    def test_rejects_empty_userinfo_issuer(self) -> None:
        # `username == ""` but the "@" delimiter is present in the authority
        # both sinks reassemble — RFC 9110 §4.2.4 forbids the subcomponent.
        with pytest.raises(InvalidIssuerError, match="must not contain a userinfo component"):
            build_metadata_url("https://@auth.example.com/t")

    def test_rejects_opaque_issuer(self) -> None:
        # "urn:example:as" has a scheme but no host, so RFC 8414 §3.1 has
        # nothing to insert the well-known suffix after. It previously derived
        # "urn:/.well-known/oauth-authorization-server/example:as".
        with pytest.raises(InvalidIssuerError, match="absolute URL with a scheme and a host"):
            build_metadata_url("urn:example:as")

    def test_rejects_scheme_relative_issuer(self) -> None:
        # Has a host but no scheme, so a guard phrased as "authority-less"
        # would wrongly admit it. Both halves are checked explicitly.
        with pytest.raises(InvalidIssuerError, match="absolute URL with a scheme and a host"):
            build_metadata_url("//auth.example.com/t")

    def test_rejects_authority_of_only_a_port(self) -> None:
        # "https://:8080/t" has a netloc but names no host, so a netloc-based
        # guard would admit it and derive a URL with no origin to fetch from.
        with pytest.raises(InvalidIssuerError, match="absolute URL with a scheme and a host"):
            build_metadata_url("https://:8080/t")

    def test_cites_section_3_1_for_the_host_requirement(self) -> None:
        # The host requirement is RFC 8414 §3.1 — the clause that derives the
        # metadata location by inserting the well-known string between the host
        # and the issuer's path. §2 gives the scheme and the no-query/fragment
        # rule; it is not where the host comes from, and citing it there would
        # send an operator to a clause that does not say what the message says.
        with pytest.raises(InvalidIssuerError) as exc:
            build_metadata_url("urn:example:as")
        assert "RFC 8414 §2, §3.1" in str(exc.value)

    def test_query_is_reported_before_absoluteness(self) -> None:
        # Deterministic order: query/fragment, then absoluteness, then userinfo.
        with pytest.raises(InvalidIssuerError, match="query or fragment component"):
            build_metadata_url("//auth.example.com/t?x=1")

    def test_absoluteness_is_reported_before_userinfo(self) -> None:
        # A scheme-relative identifier carrying credentials reports the missing
        # scheme — the defect an operator fixes first — and still redacts.
        with pytest.raises(InvalidIssuerError) as exc:
            build_metadata_url("//svc:s3cr3t@auth.example.com/t")
        assert "absolute URL with a scheme and a host" in str(exc.value)
        assert "s3cr3t" not in str(exc.value)

    def test_unparseable_authority_still_reports_the_rfc_error(self) -> None:
        # urlsplit raises ValueError("Invalid IPv6 URL") on an unclosed bracket.
        # An identifier it refuses to parse establishes no host a fortiori, so
        # it falls under the absoluteness rejection — with the redacted
        # placeholder, not urllib's message.
        with pytest.raises(InvalidIssuerError) as exc:
            build_metadata_url("https://[::1/t")
        assert "absolute URL with a scheme and a host" in str(exc.value)
        assert "IPv6" not in str(exc.value)

    def test_accepts_the_shapes_an_operator_actually_configures(self) -> None:
        # Acceptance control: the gate must not be rejecting everything, and
        # every derivation this module documents still produces its URL.
        assert (
            build_metadata_url("https://auth.example.com")
            == "https://auth.example.com/.well-known/oauth-authorization-server"
        )
        assert (
            build_metadata_url("https://auth.example.com/org/tenant1")
            == "https://auth.example.com/.well-known/oauth-authorization-server/org/tenant1"
        )
        assert (
            build_metadata_url("http://localhost:3000/t")
            == "http://localhost:3000/.well-known/oauth-authorization-server/t"
        )
        # An IPv6 literal keeps its brackets through the derivation.
        assert (
            build_metadata_url("https://[::1]:8443/t")
            == "https://[::1]:8443/.well-known/oauth-authorization-server/t"
        )

    def test_both_issuer_consumers_share_one_predicate(self) -> None:
        # The property, not just the two symptoms: the same identifier is
        # rejected on the same axis by both consumers. A check inlined into one
        # of them is what let the two drift, so the test is written against the
        # pair rather than against either one.
        from authplane.oauth.prm import build_prm

        for issuer in ("https://svc:s3cr3t@auth.example.com", "urn:example:as", "//auth.ex.com"):
            with pytest.raises(InvalidIssuerError) as from_metadata:
                build_metadata_url(issuer)
            with pytest.raises(InvalidIssuerError) as from_prm:
                build_prm(issuer=issuer, resource="https://api.example.com", scopes=[])
            assert str(from_metadata.value) == str(from_prm.value)


class TestIssuerIdentifierWhitespace:
    """The issuer's whitespace divergence is real; only its symptom differs.

    The resource identifier is re-advertised verbatim, so a character
    ``urlsplit`` cleans makes it fail RFC 9728 §3.3 against itself. The issuer
    is not re-advertised that way — but it *is* compared byte-for-byte, in
    ``internal/metadata.py``, against the value the client was configured with.
    So a configured issuer carrying a tab derives a fetch target without one,
    the AS answers with its real ``issuer``, and the comparison rejects the
    document as an "AS metadata issuer mismatch" — the confusing symptom the
    query/fragment check of this same gate exists to prevent, reached by a
    different route.
    """

    def test_urlsplit_removes_an_internal_tab_from_the_derivation(self) -> None:
        # The measurement the gate rests on, asserted rather than described:
        # the tab is gone from the parse while the configured string keeps it,
        # so the two stop naming the same authorization server.
        from urllib.parse import urlsplit

        assert urlsplit("https://auth.exa\tmple.com/t").geturl() == "https://auth.example.com/t"
        assert urlsplit("https://auth.example.com/t\renant").geturl() == (
            "https://auth.example.com/tenant"
        )

    def test_the_configured_issuer_is_what_metadata_compares(self) -> None:
        # The other half of the mechanism: the comparison is against the
        # configured issuer, not against the derived URL — which is why the
        # divergence has an equivalent here at all.
        import inspect

        from authplane.internal import metadata

        source = inspect.getsource(metadata)
        assert "issuer != self._expected_issuer" in source

    def test_rejects_internal_tab(self) -> None:
        with pytest.raises(InvalidIssuerError, match="whitespace or control characters") as exc:
            build_metadata_url("https://auth.exa\tmple.com/t")
        assert "U+0009" in str(exc.value)
        assert "RFC 8414 §2" in str(exc.value)

    def test_rejects_leading_space(self) -> None:
        with pytest.raises(InvalidIssuerError, match="whitespace or control characters"):
            build_metadata_url(" https://auth.example.com/t")

    def test_rejects_trailing_space(self) -> None:
        with pytest.raises(InvalidIssuerError, match="whitespace or control characters"):
            build_metadata_url("https://auth.example.com/t ")

    def test_rejects_the_codepoints_isspace_does_not_match(self) -> None:
        # The members of the class that make it wider than `str.isspace()`.
        # Executed, not assumed: each of these returns False from isspace(),
        # and each survives urlsplit rather than being cleaned — so without an
        # explicit branch it rides into the derived .well-known URL intact.
        from urllib.parse import urlsplit

        for char in ("\x7f", "\x9f", "﻿"):
            assert char.isspace() is False
            assert char in urlsplit(f"https://auth.example.com/t{char}x").geturl()
            with pytest.raises(InvalidIssuerError, match="whitespace or control characters") as exc:
                build_metadata_url(f"https://auth.example.com/t{char}x")
            assert f"U+{ord(char):04X}" in str(exc.value)

    def test_message_names_the_codepoint_and_its_offset(self) -> None:
        # The entire value of a gate whose subject is an invisible byte: the
        # echo alone shows the operator a string that looks correct.
        with pytest.raises(InvalidIssuerError) as exc:
            build_metadata_url("https://auth.example.com/﻿t")
        assert "U+FEFF" in str(exc.value)
        assert "at offset 25" in str(exc.value)

    def test_whitespace_rejection_does_not_echo_a_credential(self) -> None:
        with pytest.raises(InvalidIssuerError) as exc:
            build_metadata_url("https://svc:s3cr3t@auth.exa\tmple.com/t")
        assert "s3cr3t" not in str(exc.value)

    def test_query_and_fragment_are_reported_before_whitespace(self) -> None:
        # Deterministic order, pinned: the raw-string checks run in the order
        # the docstring gives, and the query/fragment finding is the one the
        # operator fixes first.
        with pytest.raises(InvalidIssuerError, match="query or fragment component"):
            build_metadata_url("https://auth.example.com/t ?x=1")

    def test_both_issuer_consumers_reject_whitespace_identically(self) -> None:
        from authplane.oauth.prm import build_prm

        issuer = "https://auth.exa\tmple.com/t"
        with pytest.raises(InvalidIssuerError) as from_metadata:
            build_metadata_url(issuer)
        with pytest.raises(InvalidIssuerError) as from_prm:
            build_prm(issuer=issuer, resource="https://api.example.com", scopes=[])
        assert str(from_metadata.value) == str(from_prm.value)

    def test_accepts_the_shapes_an_operator_actually_configures(self) -> None:
        # Acceptance control. Printable non-ASCII stays accepted: narrowing the
        # identifier to ASCII is a separate axis, exactly as on the resource
        # gate, and is not settled here by accident.
        for issuer in (
            "https://auth.example.com",
            "https://auth.example.com/",
            "https://auth.example.com/org/tenant1",
            "https://auth.example.com:8443/tenant1",
            "http://localhost:8080",
            "https://[::1]:8443/t",
            "https://xn--80ak6aa92e.example.com/t",
            "https://auth.example.com/t¡",
        ):
            assert "/.well-known/oauth-authorization-server" in build_metadata_url(issuer)


class TestIdentifierGatesArePubliclyReachable:
    """Both gates are exported from the package root, or neither should be.

    The predicates are the supported way to check configuration before
    constructing anything, and both corresponding error classes are already
    exported. Exporting one and not the other is what leaves a consumer
    reaching into ``authplane.internal`` on a ``0.x`` package — an import that
    breaks an installed application the first time the module moves.
    """

    def test_both_predicates_are_exported_from_the_package_root(self) -> None:
        import authplane

        assert "validate_issuer_identifier" in authplane.__all__
        assert "validate_prm_resource_identifier" in authplane.__all__
        assert authplane.validate_issuer_identifier is validate_issuer_identifier
        assert authplane.validate_prm_resource_identifier is validate_prm_resource_identifier

    def test_the_exported_predicate_is_the_one_the_builders_apply(self) -> None:
        # Not just a name that exists: the same object, so a consumer that
        # pre-validates cannot get a different answer from the builder.
        import authplane

        with pytest.raises(InvalidIssuerError) as pre:
            authplane.validate_issuer_identifier("https://svc:s3cr3t@auth.example.com")
        with pytest.raises(InvalidIssuerError) as built:
            build_metadata_url("https://svc:s3cr3t@auth.example.com")
        assert str(pre.value) == str(built.value)


class TestTheDerivationsNeedNoSeparatorReAdd:
    """The invariant that let a branch be deleted, pinned so it stays true.

    Both builders used to re-add a leading "/" to the parsed path before
    concatenating it onto the well-known suffix. Behind the gates that branch
    cannot be taken: RFC 3986 §3.3 gives a path following an authority as
    ``path-abempty`` — empty or beginning with "/" — and both gates require a
    host, so an authority is always present. A relaxation that ever admits a
    host-less identifier would need the branch back, and this fails if one
    lands.
    """

    def test_an_accepted_identifier_never_has_a_separator_less_path(self) -> None:
        from urllib.parse import urlsplit

        from authplane.errors import AuthplaneError

        alphabet = "".join(chr(c) for c in range(0x20, 0x7F)) + "\x00\t\n\r\x7f\x80﻿ é"
        seeds = (
            "https://api.example.com/mcp",
            "https://api.example.com",
            "https://api.example.com:8443/v2/mcp?t=a",
            "http://localhost:8080/mcp/",
            "https://[::1]:8443/t",
            "//api.example.com/mcp",
            "urn:example:api",
            "api.example.com/mcp",
            "https:/api.example.com/mcp",
            "https:api.example.com/mcp",
        )
        candidates: set[str] = set(seeds) | set(alphabet)
        for seed in seeds:
            for i in range(len(seed) + 1):
                for char in alphabet:
                    candidates.add(seed[:i] + char + seed[i:])
                    candidates.add(seed[:i] + char + seed[i + 1 :])

        accepted = {"resource": 0, "issuer": 0}
        for gate, name in (
            (validate_prm_resource_identifier, "resource"),
            (validate_issuer_identifier, "issuer"),
        ):
            for candidate in candidates:
                try:
                    gate(candidate)
                except (AuthplaneError, ValueError):
                    continue
                accepted[name] += 1
                path = urlsplit(candidate).path
                assert not path or path.startswith("/"), (name, candidate, path)

        # Guard against the sweep passing vacuously if a gate ever rejects
        # everything: it has to be accepting a substantial share of these.
        assert accepted["resource"] > 1000
        assert accepted["issuer"] > 1000


class TestResourceMetadataUrlValidation:
    """RFC 9728 §5.1 — the ``resource_metadata`` override.

    The derived URL earns its guarantees from the identifier gate; a
    configured one has none until ``validate_resource_metadata_url``. It
    reaches the same sink — the quoted-string of a challenge served to an
    unauthenticated caller — so the checks are the identifier's, plus the two
    the docstring gives a reason for: a scheme narrowed to http/https because
    this value is dereferenced rather than compared, and a delimiter scan over
    the whole string rather than the host alone.
    """

    def test_accepts_the_as_hosted_document(self) -> None:
        # The shape authserver >= 0.2.0 serves: the AS origin, the RFC 9728
        # well-known path, and the §3.1 path suffix of the Resource URI.
        validate_resource_metadata_url(
            "https://auth.example.com/.well-known/oauth-protected-resource/mcp"
        )

    def test_accepts_loopback_http_for_development(self) -> None:
        # Same relaxation the issuer and resource gates make, for the same
        # reason: a dev AS on loopback speaks cleartext.
        validate_resource_metadata_url("http://localhost:8080/.well-known/oauth-protected-resource")

    def test_accepts_a_query(self) -> None:
        # A derived URL can carry one (build_prm_url splices the identifier's
        # query in), so rejecting it here would be stricter than the default.
        validate_resource_metadata_url("https://auth.example.com/prm?tenant=acme")

    def test_rejects_a_relative_url(self) -> None:
        with pytest.raises(InvalidResourceError, match="absolute URL with a scheme and a host"):
            validate_resource_metadata_url("/.well-known/oauth-protected-resource/mcp")

    def test_rejects_a_non_http_scheme(self) -> None:
        # The identifier gates accept any scheme because they compare rather
        # than fetch. A client honouring the challenge fetches this one, and
        # RFC 9728 §5.1 names an http(s) metadata document.
        with pytest.raises(InvalidResourceError, match="scheme must be http or https"):
            validate_resource_metadata_url("ftp://auth.example.com/prm")

    def test_rejects_an_opaque_url_as_non_absolute(self) -> None:
        # An opaque form has a scheme but no host, so it is the absoluteness
        # gate that answers, not the scheme gate — pinned so the two checks'
        # ordering is stated rather than inferred.
        with pytest.raises(InvalidResourceError, match="absolute URL with a scheme and a host"):
            validate_resource_metadata_url("urn:example:prm")

    def test_rejects_a_fragment(self) -> None:
        # Never sent on the wire, so the client fetches a document other than
        # the one the value names.
        with pytest.raises(InvalidResourceError, match="fragment component"):
            validate_resource_metadata_url("https://auth.example.com/prm#doc")

    def test_rejects_userinfo(self) -> None:
        with pytest.raises(InvalidResourceError, match="userinfo") as exc:
            validate_resource_metadata_url("https://svc:s3cr3t@auth.example.com/prm")
        assert "s3cr3t" not in str(exc.value)

    def test_rejects_whitespace(self) -> None:
        with pytest.raises(InvalidResourceError, match="whitespace or control characters"):
            validate_resource_metadata_url("https://auth.example.com/p rm")

    def test_rejects_a_malformed_port(self) -> None:
        with pytest.raises(InvalidResourceError, match="malformed port"):
            validate_resource_metadata_url("https://auth.example.com:80O/prm")

    @pytest.mark.parametrize(
        "url",
        [
            'https://auth"example.com/prm',
            "https://auth.example.com/p\\rm",
            'https://auth.example.com/prm?a="b',
        ],
    )
    def test_rejects_a_quoted_string_delimiter_anywhere(self, url: str) -> None:
        # Wider than the identifier gate's host-only scan, and deliberately:
        # the whole value lands inside one quoted-string, and the path and
        # query of a configured override are not an identifier anyone has
        # already deployed, so rejecting them costs no migration.
        with pytest.raises(InvalidResourceError, match="must not contain a literal"):
            validate_resource_metadata_url(url)
