"""RFC 8414 conformance tests."""

from typing import Any

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
    jwks_keypair: dict[str, Any],
) -> None:
    with respx.mock:
        respx.get("https://auth.example.com/.well-known/oauth-authorization-server").mock(
            return_value=respx.MockResponse(
                200,
                json={
                    "issuer": "https://auth.example.com",
                    "jwks_uri": "https://auth.example.com/jwks-v1.json",
                },
            )
        )
        respx.get("https://auth.example.com/jwks-v1.json").mock(
            return_value=respx.MockResponse(200, json=jwks_keypair["jwks"])
        )
        respx.get("https://auth.example.com/jwks-v2.json").mock(
            return_value=respx.MockResponse(200, json=jwks_keypair["jwks"])
        )

        client = await AuthplaneClient.create(
            issuer="https://auth.example.com",
            fetch_settings=_NO_SSRF,
        )
        try:
            old_metadata: dict[str, object] = {
                "issuer": "https://auth.example.com",
                "jwks_uri": "https://auth.example.com/jwks-v1.json",
            }
            new_metadata: dict[str, object] = {
                "issuer": "https://auth.example.com",
                "jwks_uri": "https://auth.example.com/jwks-v2.json",
            }

            # Drive the rotation directly via the internal hook. A full end-to-
            # end test would simulate a metadata-refresh tick, but the SDK
            # exposes no public seam for that yet; using the private hook here
            # is a deliberate trade-off. Follow-up: lift this to a public
            # test seam when the metadata-cache lifecycle is refactored.
            await client._on_metadata_changed(old_metadata, new_metadata)  # pyright: ignore[reportPrivateUsage]
            assert client._jwks_uri == "https://auth.example.com/jwks-v2.json"  # pyright: ignore[reportPrivateUsage]
        finally:
            await client.aclose()
