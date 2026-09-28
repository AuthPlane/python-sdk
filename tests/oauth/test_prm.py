"""Tests for Protected Resource Metadata (PRM) builder."""

import pytest

from authplane.errors import InvalidIssuerError, InvalidResourceError
from authplane.oauth.prm import build_prm


def test_build_prm_contains_required_fields() -> None:
    """PRM should contain all required RFC 9728 fields."""
    prm = build_prm(
        issuer="https://auth.example.com",
        resource="https://api.example.com",
        scopes=["read:data", "write:data"],
    )

    assert "resource" in prm
    assert "authorization_servers" in prm
    assert "bearer_methods_supported" in prm
    assert "scopes_supported" in prm


def test_build_prm_resource_field() -> None:
    """PRM resource field should match input."""
    prm = build_prm(
        issuer="https://auth.example.com",
        resource="https://api.example.com",
        scopes=[],
    )

    assert prm["resource"] == "https://api.example.com"


def test_build_prm_authorization_servers_single_element() -> None:
    """authorization_servers should be a single-element list."""
    prm = build_prm(
        issuer="https://auth.example.com",
        resource="https://api.example.com",
        scopes=[],
    )

    authorization_servers = prm["authorization_servers"]
    assert isinstance(authorization_servers, list)
    assert len(authorization_servers) == 1  # pyright: ignore[reportUnknownArgumentType]
    assert authorization_servers[0] == "https://auth.example.com"


def test_build_prm_empty_scopes() -> None:
    """PRM should handle empty scopes list."""
    prm = build_prm(
        issuer="https://auth.example.com",
        resource="https://api.example.com",
        scopes=[],
    )

    assert prm["scopes_supported"] == []


def test_build_prm_multiple_scopes() -> None:
    """PRM should include all provided scopes."""
    scopes = ["read:data", "write:data", "admin"]
    prm = build_prm(
        issuer="https://auth.example.com",
        resource="https://api.example.com",
        scopes=scopes,
    )

    assert prm["scopes_supported"] == scopes


def test_build_prm_hardcoded_bearer_methods() -> None:
    """bearer_methods_supported should be hardcoded to ['header']."""
    prm = build_prm(
        issuer="https://auth.example.com",
        resource="https://api.example.com",
        scopes=[],
    )

    assert prm["bearer_methods_supported"] == ["header"]


class TestBuildPrmGatesTheIssuer:
    """The issuer is published, so it is gated at the boundary that publishes it.

    ``build_prm`` copied *issuer* straight into ``authorization_servers`` with
    no check at all, and RFC 9728 §3 has the endpoint serving this document
    answer **unauthenticated** callers — so a credential-bearing issuer was
    handed verbatim to anyone who asked. The gate is the same predicate
    ``build_metadata_url`` applies, which is the point: the issuer had two
    consumers and only one of them validated anything.
    """

    def test_rejects_userinfo_bearing_issuer(self) -> None:
        with pytest.raises(InvalidIssuerError, match="must not contain a userinfo component"):
            build_prm(
                issuer="https://svc:s3cr3t@auth.example.com",
                resource="https://api.example.com",
                scopes=[],
            )

    def test_userinfo_rejection_does_not_echo_the_credential(self) -> None:
        # The whole point of rejecting here is that the value is disclosed;
        # a message quoting it back would reintroduce the disclosure on the
        # error path, where it lands in a startup log instead.
        with pytest.raises(InvalidIssuerError) as exc:
            build_prm(
                issuer="https://svc:s3cr3t@auth.example.com",
                resource="https://api.example.com",
                scopes=[],
            )
        assert "s3cr3t" not in str(exc.value)
        assert "svc" not in str(exc.value)

    def test_rejects_empty_userinfo_issuer(self) -> None:
        # The "@" delimiter marks the subcomponent present even with nothing in
        # it, and RFC 9110 §4.2.4 forbids generating the subcomponent, not
        # merely non-empty credentials.
        with pytest.raises(InvalidIssuerError, match="must not contain a userinfo component"):
            build_prm(
                issuer="https://@auth.example.com",
                resource="https://api.example.com",
                scopes=[],
            )

    def test_rejects_host_less_issuer(self) -> None:
        # RFC 8414 §3.1 inserts the well-known suffix after the host, so an
        # opaque issuer names no metadata location — and the document would
        # advertise an authorization server no client can discover.
        with pytest.raises(InvalidIssuerError, match="absolute URL with a scheme and a host"):
            build_prm(
                issuer="urn:example:as",
                resource="https://api.example.com",
                scopes=[],
            )

    def test_rejects_scheme_less_issuer(self) -> None:
        with pytest.raises(InvalidIssuerError, match="absolute URL with a scheme and a host"):
            build_prm(
                issuer="//auth.example.com",
                resource="https://api.example.com",
                scopes=[],
            )

    def test_rejects_query_bearing_issuer(self) -> None:
        with pytest.raises(InvalidIssuerError, match="query or fragment component"):
            build_prm(
                issuer="https://auth.example.com?x=1",
                resource="https://api.example.com",
                scopes=[],
            )

    def test_rejects_fragment_bearing_issuer(self) -> None:
        with pytest.raises(InvalidIssuerError, match="query or fragment component"):
            build_prm(
                issuer="https://auth.example.com#frag",
                resource="https://api.example.com",
                scopes=[],
            )

    def test_error_is_still_a_value_error(self) -> None:
        # The gate is new on this function, but the class is not: an existing
        # `except ValueError` around a PRM build still catches it.
        with pytest.raises(ValueError):
            build_prm(
                issuer="https://svc:s3cr3t@auth.example.com",
                resource="https://api.example.com",
                scopes=[],
            )

    def test_accepts_the_shapes_an_operator_actually_configures(self) -> None:
        # Acceptance control: the gate must not be rejecting everything. A
        # tenant path, a port, a trailing slash (which is part of the identity
        # and is NOT normalized away) and plain http for local development all
        # keep building, and the issuer is still copied through byte-for-byte.
        for issuer in (
            "https://auth.example.com",
            "https://auth.example.com/",
            "https://auth.example.com/org/tenant1",
            "https://auth.example.com:8443/tenant1",
            "http://localhost:8080",
            "https://[::1]:8443/t",
        ):
            prm = build_prm(issuer=issuer, resource="https://api.example.com", scopes=["read"])
            assert prm["authorization_servers"] == [issuer]


class TestBuildPrmGatesTheResourceItPublishes:
    """The `resource` member is gated by the same argument as the issuer.

    It sits in the same document, published from the same endpoint, and
    RFC 9728 §3.3 makes it the member a client compares: a document whose
    ``resource`` does not match the identifier the client dereferenced MUST be
    discarded. The parameter is a plain ``str`` on a public builder, so nothing
    obliges a caller to have obtained it from a gated ``AuthplaneResource``.
    """

    def test_rejects_fragment_bearing_resource(self) -> None:
        # The shape that made this concrete: a document is returned, and the
        # well-known URL a client would have reached it by cannot be derived
        # from the identifier it names (RFC 8707 §2 forbids the fragment).
        with pytest.raises(InvalidResourceError, match="must not contain a fragment"):
            build_prm(
                issuer="https://auth.example.com",
                resource="https://api.example.com/mcp#frag",
                scopes=[],
            )

    def test_rejects_userinfo_bearing_resource(self) -> None:
        # Same disclosure as the issuer half, at the same sink: credentials
        # copied verbatim into a document served to unauthenticated callers.
        with pytest.raises(InvalidResourceError, match="must not contain a userinfo component"):
            build_prm(
                issuer="https://auth.example.com",
                resource="https://svc:s3cr3t@api.example.com/mcp",
                scopes=[],
            )

    def test_rejects_whitespace_bearing_resource(self) -> None:
        with pytest.raises(InvalidResourceError, match="whitespace or control characters"):
            build_prm(
                issuer="https://auth.example.com",
                resource="https://api.exa\tmple.com/mcp",
                scopes=[],
            )

    def test_rejects_scheme_less_resource(self) -> None:
        with pytest.raises(InvalidResourceError, match="absolute URL with a scheme and a host"):
            build_prm(
                issuer="https://auth.example.com",
                resource="api.example.com/mcp",
                scopes=[],
            )

    def test_reports_the_issuer_first_when_both_are_defective(self) -> None:
        # Deterministic order, pinned because the two errors are siblings and
        # either could plausibly come first. The issuer wins: it is the member
        # that was published with no check whatsoever, so it is the finding an
        # operator should see before anything else.
        with pytest.raises(InvalidIssuerError):
            build_prm(
                issuer="https://svc:s3cr3t@auth.example.com",
                resource="https://api.example.com/mcp#frag",
                scopes=[],
            )

    def test_accepts_the_resource_shapes_an_operator_actually_configures(self) -> None:
        # Acceptance control. Every shape here is one the resource gate already
        # accepts at `AuthplaneResource.__init__`, so routing the builder
        # through the same predicate cannot reject a document the SDK's own
        # construction path would have built.
        for resource in (
            "https://api.example.com",
            "https://api.example.com/mcp",
            "https://api.example.com:8443/v2/mcp",
            "http://localhost:8080/mcp",
            "https://api.example.com/mcp?tenant=a",
        ):
            prm = build_prm(
                issuer="https://auth.example.com",
                resource=resource,
                scopes=["read"],
            )
            assert prm["resource"] == resource
