"""RFC 8414 conformance tests."""

import asyncio
from collections.abc import Callable
from typing import Any

import httpx
import pytest
import respx

from authplane import AuthplaneClient, FetchSettings
from authplane.errors import MetadataFetchError, MissingMetadataEndpointError
from authplane.internal.fetch_result import FetchResult
from authplane.internal.metadata import MetadataCache
from authplane.internal.urls import build_metadata_url

_NO_SSRF = FetchSettings(ssrf_protection=False)


@pytest.mark.conformance("rfc8414-metadata-issuer-must-match-configured-issuer")
async def test_rfc8414_metadata_issuer_must_match_configured_issuer(
    jwks_keypair: dict[str, Any],
) -> None:
    with respx.mock:
        respx.get("https://auth.example.com/.well-known/oauth-authorization-server").mock(
            return_value=respx.MockResponse(
                200,
                json={
                    "issuer": "https://evil.example.com",
                    "jwks_uri": "https://auth.example.com/.well-known/jwks.json",
                },
            )
        )
        respx.get("https://auth.example.com/.well-known/jwks.json").mock(
            return_value=respx.MockResponse(200, json=jwks_keypair["jwks"])
        )

        with pytest.raises(MetadataFetchError, match="issuer mismatch"):
            await AuthplaneClient.create(
                issuer="https://auth.example.com",
                fetch_settings=_NO_SSRF,
            )


@pytest.mark.conformance("rfc8414-jwks-uri-required-for-jwt-validation")
async def test_rfc8414_jwks_uri_required_for_jwt_validation() -> None:
    async def fetcher() -> FetchResult:
        return FetchResult(document={"issuer": "https://auth.example.com"})

    cache = MetadataCache(fetcher, document_type="metadata")
    with pytest.raises(MetadataFetchError, match="jwks_uri"):
        await cache.get_jwks_uri()


@pytest.mark.conformance("rfc8414-metadata-must-contain-issuer")
async def test_rfc8414_metadata_must_contain_issuer() -> None:
    async def fetcher() -> FetchResult:
        return FetchResult(document={"jwks_uri": "https://auth.example.com/.well-known/jwks.json"})

    cache = MetadataCache(fetcher, document_type="metadata")
    with pytest.raises(MetadataFetchError, match="issuer"):
        await cache.get()


@pytest.mark.conformance("rfc8414-jwks-uri-must-be-absolute-https-url")
async def test_rfc8414_jwks_uri_must_be_absolute_https_url() -> None:
    async def fetcher() -> FetchResult:
        return FetchResult(
            document={
                "issuer": "https://auth.example.com",
                "jwks_uri": "/relative-jwks",
            }
        )

    cache = MetadataCache(fetcher, document_type="metadata")
    with pytest.raises(MetadataFetchError, match="jwks_uri"):
        await cache.get_jwks_uri()


@pytest.mark.conformance("rfc8414-introspection-endpoint-required-when-introspection-is-used")
async def test_rfc8414_introspection_endpoint_required_when_introspection_is_used(
    jwks_keypair: dict[str, Any],
) -> None:
    with respx.mock:
        respx.get("https://auth.example.com/.well-known/oauth-authorization-server").mock(
            return_value=respx.MockResponse(
                200,
                json={
                    "issuer": "https://auth.example.com",
                    "jwks_uri": "https://auth.example.com/.well-known/jwks.json",
                },
            )
        )
        respx.get("https://auth.example.com/.well-known/jwks.json").mock(
            return_value=respx.MockResponse(200, json=jwks_keypair["jwks"])
        )

        client = await AuthplaneClient.create(
            issuer="https://auth.example.com",
            fetch_settings=_NO_SSRF,
        )
        try:
            with pytest.raises(MissingMetadataEndpointError, match="introspection_endpoint"):
                await client.introspect("token")
        finally:
            await client.aclose()


@pytest.mark.conformance("rfc8414-token-endpoint-required-when-token-operation-is-used")
async def test_rfc8414_token_endpoint_required_when_token_operation_is_used() -> None:
    async def fetcher() -> FetchResult:
        return FetchResult(
            document={
                "issuer": "https://auth.example.com",
                "jwks_uri": "https://auth.example.com/.well-known/jwks.json",
            }
        )

    cache = MetadataCache(fetcher, document_type="metadata")
    with pytest.raises(MissingMetadataEndpointError, match="token_endpoint"):
        await cache.get_token_endpoint()


@pytest.mark.conformance("rfc8414-revocation-endpoint-required-when-revocation-is-used")
async def test_rfc8414_revocation_endpoint_required_when_revocation_is_used() -> None:
    async def fetcher() -> FetchResult:
        return FetchResult(
            document={
                "issuer": "https://auth.example.com",
                "jwks_uri": "https://auth.example.com/.well-known/jwks.json",
            }
        )

    cache = MetadataCache(fetcher, document_type="metadata")
    with pytest.raises(MissingMetadataEndpointError, match="revocation_endpoint"):
        await cache.get_revocation_endpoint()


@pytest.mark.conformance("rfc8414-token-endpoint-must-be-absolute-https-url")
async def test_rfc8414_token_endpoint_must_be_absolute_https_url() -> None:
    async def fetcher() -> FetchResult:
        return FetchResult(
            document={
                "issuer": "https://auth.example.com",
                "jwks_uri": "https://auth.example.com/.well-known/jwks.json",
                "token_endpoint": "http://auth.example.com/oauth/token",
            }
        )

    cache = MetadataCache(fetcher, document_type="metadata")
    with pytest.raises(MetadataFetchError, match="token_endpoint"):
        await cache.get_token_endpoint()


@pytest.mark.conformance("rfc8414-introspection-endpoint-must-be-absolute-https-url")
async def test_rfc8414_introspection_endpoint_must_be_absolute_https_url() -> None:
    async def fetcher() -> FetchResult:
        return FetchResult(
            document={
                "issuer": "https://auth.example.com",
                "jwks_uri": "https://auth.example.com/.well-known/jwks.json",
                "introspection_endpoint": "http://auth.example.com/oauth/introspect",
            }
        )

    cache = MetadataCache(fetcher, document_type="metadata")
    with pytest.raises(MetadataFetchError, match="introspection_endpoint"):
        await cache.get_introspection_endpoint()


@pytest.mark.conformance("rfc8414-revocation-endpoint-must-be-absolute-https-url")
async def test_rfc8414_revocation_endpoint_must_be_absolute_https_url() -> None:
    async def fetcher() -> FetchResult:
        return FetchResult(
            document={
                "issuer": "https://auth.example.com",
                "jwks_uri": "https://auth.example.com/.well-known/jwks.json",
                "revocation_endpoint": "http://auth.example.com/oauth/revoke",
            }
        )

    cache = MetadataCache(fetcher, document_type="metadata")
    with pytest.raises(MetadataFetchError, match="revocation_endpoint"):
        await cache.get_revocation_endpoint()


@pytest.mark.conformance("rfc8414-discovery-url-must-insert-well-known-before-issuer-path")
async def test_rfc8414_discovery_url_must_insert_well_known_before_issuer_path(
    jwks_keypair: dict[str, Any],
) -> None:
    # RFC 8414 §3: for "https://auth.example.com/tenant-a" the metadata URL must be
    # "https://auth.example.com/.well-known/oauth-authorization-server/tenant-a"
    # — not "https://auth.example.com/tenant-a/.well-known/oauth-authorization-server".
    issuer = "https://auth.example.com/tenant-a"
    expected_url = "https://auth.example.com/.well-known/oauth-authorization-server/tenant-a"
    wrong_url = "https://auth.example.com/tenant-a/.well-known/oauth-authorization-server"

    assert build_metadata_url(issuer) == expected_url
    assert build_metadata_url(issuer) != wrong_url

    # Also verify end-to-end: AuthplaneClient.create must fetch from the RFC-compliant URL
    with respx.mock:
        respx.get(expected_url).mock(
            return_value=respx.MockResponse(
                200,
                json={"issuer": issuer, "jwks_uri": "https://auth.example.com/jwks.json"},
            )
        )
        respx.get("https://auth.example.com/jwks.json").mock(
            return_value=respx.MockResponse(200, json=jwks_keypair["jwks"])
        )
        client = await AuthplaneClient.create(
            issuer=issuer,
            fetch_settings=_NO_SSRF,
        )
        await client.aclose()


@pytest.mark.conformance("rfc8414-jwks-uri-rotation-must-reconfigure-jwks-cache")
async def test_rfc8414_jwks_uri_rotation_must_reconfigure_jwks_cache(
    signing_key_factory: Callable[[str], Any],
) -> None:
    """Follow a ``jwks_uri`` rotation on nothing but ordinary verify() traffic.

    Every mechanism here is one a deployment already has: the refresh interval
    is shortened through the documented constructor argument, real time is
    allowed to elapse, and the rotation is then followed by a second
    ``verify()``. No force-refresh argument, no test-only hook, no reflection
    into cache internals, and no assertion against a locally built metadata
    object — the case rules all four out, and they are the reason it was
    written: a verify-only resource server repeats no discovery of its own, so
    a rotation it cannot follow from the verification path is a rotation it
    never follows in production.

    Both key sets publish the **same** ``kid`` deliberately. Were the rotated
    key introduced under a new ``kid``, the unknown-``kid`` refresh would
    follow the rotation on its own and this would silently become a test of
    that separate requirement instead. Holding the ``kid`` fixed removes that
    explanation: a verifier still bound to the withdrawn URI finds the retired
    key under exactly the id it is looking for, uses it, and fails on the
    signature. Only a genuine rebind to the rotated URI can make this pass.
    """
    # Two seconds rather than one. `DocumentCache.get` spawns a background
    # refresh once 80% of the effective TTL has elapsed, so the
    # inside-the-interval assertion below requires `create()` and the two
    # `verify()` calls that follow it to finish within that window — 0.8s at a
    # one-second interval, which is a non-deterministic failure on a loaded CI
    # runner rather than a clean one. Two seconds buys 1.6s of slack and the
    # rotation is still driven well inside the case's two-interval bound.
    metadata_refresh_seconds = 2
    kid = "rotating-key"
    old_key = signing_key_factory(kid)
    new_key = signing_key_factory(kid)

    rotated = False
    metadata_calls = 0

    def metadata_response(request: httpx.Request) -> httpx.Response:
        nonlocal metadata_calls
        metadata_calls += 1
        uri = (
            "https://auth.example.com/jwks-v2.json"
            if rotated
            else "https://auth.example.com/jwks-v1.json"
        )
        return httpx.Response(
            200,
            json={"issuer": "https://auth.example.com", "jwks_uri": uri},
        )

    with respx.mock:
        respx.get("https://auth.example.com/.well-known/oauth-authorization-server").mock(
            side_effect=metadata_response
        )
        # The withdrawn URI stays reachable and keeps serving the retired key.
        # A 404 there would let the case pass on the fetch failing rather than
        # on the rotation being followed.
        old_route = respx.get("https://auth.example.com/jwks-v1.json").mock(
            return_value=respx.MockResponse(200, json=old_key.jwks)
        )
        new_route = respx.get("https://auth.example.com/jwks-v2.json").mock(
            return_value=respx.MockResponse(200, json=new_key.jwks)
        )

        client = await AuthplaneClient.create(
            issuer="https://auth.example.com",
            fetch_settings=_NO_SSRF,
            metadata_refresh_seconds=metadata_refresh_seconds,
            # Deliberately far longer than the metadata interval. If the key set
            # could fall out of cache on its own, the rotation would be followed
            # by that expiry rather than by the rotation being noticed, and the
            # case would pass without demonstrating the requirement.
            jwks_refresh_seconds=3600,
        )
        verifier = client.resource(resource="https://api.example.com")
        try:
            assert (await verifier.verify(old_key.sign())).kid == kid

            # Ordinary traffic inside the interval must not re-read metadata.
            # The interval is the SDK's side of the contract the case's bound is
            # written against, and following a rotation promptly is worth
            # nothing if the price is a discovery fetch per verification.
            # Exact equality, not a tolerance: the 80%-of-TTL background
            # refresh is the only other thing that could move this counter,
            # and the interval above is sized so it cannot have fired yet.
            metadata_calls_inside_interval = metadata_calls
            assert (await verifier.verify(old_key.sign(jti="inside-interval"))).kid == kid
            assert metadata_calls == metadata_calls_inside_interval

            # The AS begins serving the rotated document.
            rotated = True
            await asyncio.sleep(metadata_refresh_seconds + 0.2)
            old_route_calls_at_rotation = old_route.call_count

            assert (await verifier.verify(new_key.sign())).kid == kid
            # Metadata re-fetched once the interval elapsed, with no explicit
            # refresh call anywhere...
            assert metadata_calls > metadata_calls_inside_interval
            # ...JWKS fetched from the rotated location...
            assert new_route.called
            # ...and the withdrawn one not touched again once the rebind happened.
            assert old_route.call_count == old_route_calls_at_rotation
        finally:
            await client.aclose()
