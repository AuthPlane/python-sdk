"""Regression tests: issuer identity is preserved byte-for-byte.

Identifiers (the configured issuer and a token's RFC 9068 ``iss``) are STORED
and COMPARED verbatim — a trailing slash is significant. Only .well-known URL
DERIVATION (RFC 8414 / 9728 §3.1) strips the terminating slash. These two
behaviors are distinct and must not be fused.
"""

from collections.abc import AsyncGenerator, Callable
from typing import Any

import pytest
import respx

from authplane import AuthplaneClient, FetchSettings
from authplane.errors import InvalidClaimsError, MetadataFetchError
from authplane.internal.fetch_result import FetchResult
from authplane.internal.metadata import MetadataCache
from authplane.internal.urls import build_metadata_url, build_prm_url

# The issuer under test carries a trailing slash; an AS whose identifier ends in
# ``/`` mints tokens whose ``iss`` keeps the slash (RFC 9068).
ISSUER_WITH_SLASH = "https://auth.example.com/"
RESOURCE = "https://api.example.com"


@pytest.fixture
async def client_slash_issuer(
    jwks_keypair: dict[str, Any],
) -> AsyncGenerator[AuthplaneClient]:
    """Client configured with a trailing-slash issuer, backed by respx mocks.

    The AS metadata document advertises the SAME trailing-slash issuer, so the
    RFC 8414 §3.3 comparison passes; the derived .well-known URL still strips the
    slash (that is derivation, not identity).
    """
    with respx.mock:
        metadata_doc = {
            "issuer": ISSUER_WITH_SLASH,
            "token_endpoint": "https://auth.example.com/oauth/token",
            "jwks_uri": "https://auth.example.com/.well-known/jwks.json",
        }
        respx.get("https://auth.example.com/.well-known/oauth-authorization-server").mock(
            return_value=respx.MockResponse(status_code=200, json=metadata_doc)
        )
        respx.get("https://auth.example.com/.well-known/jwks.json").mock(
            return_value=respx.MockResponse(status_code=200, json=jwks_keypair["jwks"])
        )
        c = await AuthplaneClient.create(
            issuer=ISSUER_WITH_SLASH,
            fetch_settings=FetchSettings(ssrf_protection=False),
        )
        yield c
        await c.aclose()


# (a) A token whose `iss` carries the configured trailing slash verifies OK.
async def test_token_iss_with_trailing_slash_verifies(
    client_slash_issuer: AuthplaneClient,
    token_factory: Callable[..., str],
) -> None:
    # The configured issuer is stored verbatim (with the slash), so a token whose
    # `iss` matches it byte-for-byte must verify. Previously the stored issuer
    # was slash-stripped, so this token's `iss` mismatched and every token was
    # rejected (the outage).
    verifier = client_slash_issuer.resource(resource=RESOURCE)
    token = token_factory(iss=ISSUER_WITH_SLASH)

    claims = await verifier.verify(token)

    assert claims.issuer == ISSUER_WITH_SLASH


# (a1) The advertise leg is verbatim too: the PRM document advertises the
# configured trailing-slash issuer byte-for-byte in `authorization_servers`
# (build_prm passes the stored issuer straight through), symmetric with the
# verify leg above.
def test_prm_response_advertises_issuer_verbatim(
    client_slash_issuer: AuthplaneClient,
) -> None:
    res = client_slash_issuer.resource(resource=RESOURCE)

    assert res.prm_response()["authorization_servers"] == [ISSUER_WITH_SLASH]


# (a2) The configured issuer carries a trailing slash; a token whose `iss` drops
# it is rejected. This proves the `iss` comparison is verbatim rather than merely
# loosened — a slash-insensitive comparison would wrongly accept this token.
async def test_token_iss_without_trailing_slash_is_rejected(
    client_slash_issuer: AuthplaneClient,
    token_factory: Callable[..., str],
) -> None:
    verifier = client_slash_issuer.resource(resource=RESOURCE)
    token = token_factory(iss="https://auth.example.com")  # `iss` WITHOUT the slash

    with pytest.raises(InvalidClaimsError):
        await verifier.verify(token)


# (b) A metadata doc whose issuer differs only by a trailing slash is rejected.
async def test_metadata_issuer_off_by_trailing_slash_is_rejected() -> None:
    metadata = {
        "issuer": "https://auth.example.com/",  # advertised WITH slash
        "jwks_uri": "https://auth.example.com/.well-known/jwks.json",
        "token_endpoint": "https://auth.example.com/oauth/token",
    }

    async def fetcher() -> Any:
        return FetchResult(document=metadata, expires_at=None)

    cache = MetadataCache(
        fetcher,
        expected_issuer="https://auth.example.com",  # configured WITHOUT slash
        document_type="metadata",
    )

    with pytest.raises(MetadataFetchError, match="issuer mismatch"):
        await cache.get()


def _metadata_cache_expecting(expected: str, advertised: str) -> MetadataCache:
    metadata = {
        "issuer": advertised,
        "jwks_uri": "https://auth.example.com/.well-known/jwks.json",
        "token_endpoint": "https://auth.example.com/oauth/token",
    }

    async def fetcher() -> Any:
        return FetchResult(document=metadata, expires_at=None)

    return MetadataCache(fetcher, expected_issuer=expected, document_type="metadata")


# (b2) A trailing-slash-only mismatch gets the "trailing slash is significant"
# hint, since the two identifiers are otherwise identical.
async def test_trailing_slash_mismatch_includes_slash_hint() -> None:
    cache = _metadata_cache_expecting(
        expected="https://auth.example.com",
        advertised="https://auth.example.com/",
    )
    with pytest.raises(MetadataFetchError) as excinfo:
        await cache.get()
    assert "trailing slash is significant" in str(excinfo.value)


# (b3) A genuine wrong-host mismatch does NOT get the slash hint, which would be
# misleading — the values differ by more than a terminating slash.
async def test_wrong_host_mismatch_omits_slash_hint() -> None:
    cache = _metadata_cache_expecting(
        expected="https://auth.example.com",
        advertised="https://evil.example.com",
    )
    with pytest.raises(MetadataFetchError) as excinfo:
        await cache.get()
    assert "issuer mismatch" in str(excinfo.value)
    assert "trailing slash is significant" not in str(excinfo.value)


# (c) A resource with a query component keeps the query in its derived PRM URL.
def test_prm_url_preserves_query_component() -> None:
    assert (
        build_prm_url("https://api.example.com/?x=1")
        == "https://api.example.com/.well-known/oauth-protected-resource?x=1"
    )


def test_prm_url_preserves_query_with_path() -> None:
    assert (
        build_prm_url("https://api.example.com/mcp?tenant=acme")
        == "https://api.example.com/.well-known/oauth-protected-resource/mcp?tenant=acme"
    )


# (d) A query-bearing issuer is rejected at construction (RFC 8414 §2), not
# silently stripped and later surfaced as a confusing "issuer mismatch".
def test_metadata_url_rejects_query_bearing_issuer() -> None:
    with pytest.raises(ValueError, match="must not contain a query or fragment"):
        build_metadata_url("https://auth.example.com/t?x=1")


def test_metadata_url_rejects_bare_empty_query_issuer() -> None:
    # A bare `?` still carries the query delimiter and must not survive into the
    # derived .well-known URL.
    with pytest.raises(ValueError, match="must not contain a query or fragment"):
        build_metadata_url("https://auth.example.com/t?")


# (d2) A fragment-bearing issuer is rejected too. RFC 8414 §2 forbids BOTH a
# query and a fragment; urlunparse silently drops a fragment, so without the
# gate `https://auth.example.com/t#x` would derive a fragment-free .well-known
# URL and later surface as a confusing "issuer mismatch".
def test_metadata_url_rejects_fragment_bearing_issuer() -> None:
    with pytest.raises(ValueError, match="must not contain a query or fragment"):
        build_metadata_url("https://auth.example.com/t#x")


def test_metadata_url_rejects_bare_empty_fragment_issuer() -> None:
    with pytest.raises(ValueError, match="must not contain a query or fragment"):
        build_metadata_url("https://auth.example.com/t#")


def test_metadata_url_query_rejection_does_not_leak_query_value() -> None:
    with pytest.raises(ValueError) as excinfo:
        build_metadata_url("https://auth.example.com/t?token=secret")
    assert "secret" not in str(excinfo.value)


def test_metadata_url_rejection_does_not_leak_userinfo() -> None:
    # `netloc` carries any embedded userinfo; the redacted message must use the
    # bare hostname (plus port when set) so credentials in the authority — here
    # `svc:s3cr3t@` — never reach a log line.
    with pytest.raises(ValueError) as excinfo:
        build_metadata_url("https://svc:s3cr3t@auth.example.com/t?x=1")
    assert "s3cr3t" not in str(excinfo.value)


# (e) A fragment-bearing resource indicator is rejected in PRM derivation too.
# RFC 8707 §2 forbids a fragment in a resource indicator; the query is still
# preserved (that asymmetry is intentional).
def test_prm_url_rejects_fragment_bearing_resource() -> None:
    with pytest.raises(ValueError, match="must not contain a fragment"):
        build_prm_url("https://api.example.com/mcp#frag")


def test_prm_url_rejection_does_not_leak_userinfo() -> None:
    with pytest.raises(ValueError) as excinfo:
        build_prm_url("https://svc:s3cr3t@api.example.com/mcp#frag")
    assert "s3cr3t" not in str(excinfo.value)


async def test_client_create_rejects_query_bearing_issuer() -> None:
    # The guard triggers on the AuthplaneClient.create() path before any network
    # fetch, so a misconfigured issuer fails fast with a clear message.
    with pytest.raises(ValueError, match="must not contain a query or fragment"):
        await AuthplaneClient.create(
            issuer="https://auth.example.com/?x=1",
            fetch_settings=FetchSettings(ssrf_protection=False),
        )


async def test_client_create_rejects_fragment_bearing_issuer() -> None:
    with pytest.raises(ValueError, match="must not contain a query or fragment"):
        await AuthplaneClient.create(
            issuer="https://auth.example.com/t#x",
            fetch_settings=FetchSettings(ssrf_protection=False),
        )
