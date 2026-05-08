"""Shared test fixtures for Authplane SDK tests."""

import time
from collections.abc import AsyncGenerator, Generator
from typing import Any, Protocol

import pytest
import respx
from authlib.jose import JsonWebKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from respx.models import Route

from authplane import AuthplaneClient, AuthplaneResource, FetchSettings


class TokenFactory(Protocol):
    """Protocol for the token_factory fixture."""

    def __call__(
        self,
        iss: str = ...,
        aud: str = ...,
        sub: str = ...,
        client_id: str = ...,
        scope: str = ...,
        exp: int | None = ...,
        nbf: int | None = ...,
        iat: int | None = ...,
        jti: str = ...,
        typ: str = ...,
        exclude_claims: list[str] | None = ...,
        **extra_claims: Any,
    ) -> str: ...


JWKSKeypair = dict[str, Any]
MockASMetadata = dict[str, Route]


@pytest.fixture
def jwks_keypair() -> JWKSKeypair:
    """Generate an ES256 keypair and export as JWKS.

    Returns:
        dict with 'private_key', 'public_key', and 'jwks' (JWKS JSON dict)
    """
    # Generate ES256 private key
    private_key = ec.generate_private_key(ec.SECP256R1())

    # Get public key
    public_key = private_key.public_key()

    # Export private key as PEM
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Export public key as PEM
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Convert to authlib JsonWebKey
    jwk = JsonWebKey.import_key(public_pem, {"kty": "EC"})  # pyright: ignore[reportArgumentType]
    jwk_dict: dict[str, Any] = jwk.as_dict()  # pyright: ignore[reportUnknownMemberType, reportUnknownVariableType]
    jwk_dict["kid"] = "test-key-1"
    jwk_dict["alg"] = "ES256"
    jwk_dict["use"] = "sig"

    # Build JWKS document
    jwks: dict[str, Any] = {"keys": [jwk_dict]}

    return {
        "private_key": private_pem,
        "public_key": public_pem,
        "jwks": jwks,
    }


@pytest.fixture
def token_factory(jwks_keypair: JWKSKeypair) -> TokenFactory:
    """Factory for creating signed JWTs with customizable claims.

    Returns:
        Callable that creates JWT tokens signed with the test keypair
    """
    from authlib.jose import jwt

    def create_token(
        iss: str = "https://auth.example.com",
        aud: str = "https://api.example.com",
        sub: str = "user123",
        client_id: str = "client456",
        scope: str = "read:data write:data",
        exp: int | None = None,
        nbf: int | None = None,
        iat: int | None = None,
        jti: str = "token-id-123",
        typ: str = "at+jwt",
        exclude_claims: list[str] | None = None,
        **extra_claims: Any,
    ) -> str:
        """Create a signed JWT token.

        Args:
            iss: Issuer
            aud: Audience
            sub: Subject
            client_id: Client ID
            scope: Space-separated scopes
            exp: Expiration (defaults to 1 hour from now)
            nbf: Not before (defaults to now)
            iat: Issued at (defaults to now)
            jti: JWT ID
            typ: Token type header
            exclude_claims: List of claim names to omit from the payload,
                useful for testing validation of missing required claims.
            **extra_claims: Additional claims to include

        Returns:
            Signed JWT token as string
        """
        now = int(time.time())
        if exp is None:
            exp = now + 3600  # 1 hour from now
        if nbf is None:
            nbf = now
        if iat is None:
            iat = now

        header = {"alg": "ES256", "typ": typ, "kid": "test-key-1"}

        payload = {
            "iss": iss,
            "aud": aud,
            "sub": sub,
            "client_id": client_id,
            "scope": scope,
            "exp": exp,
            "nbf": nbf,
            "iat": iat,
            "jti": jti,
            **extra_claims,
        }

        for claim in exclude_claims or []:
            payload.pop(claim, None)

        token: bytes = jwt.encode(header, payload, jwks_keypair["private_key"])  # pyright: ignore[reportUnknownMemberType]
        return token.decode("utf-8")

    return create_token


@pytest.fixture
def mock_jwks(jwks_keypair: JWKSKeypair) -> Generator[Route]:
    """Mock AS metadata and JWKS endpoints using respx.

    Mocks the RFC 8414 AS metadata endpoint (which discovery uses) and the
    JWKS endpoint it points to, so tests do not need a real authorization server.

    Returns:
        respx mock for https://auth.example.com/.well-known/jwks.json
    """
    with respx.mock:
        metadata_doc = {
            "issuer": "https://auth.example.com",
            "jwks_uri": "https://auth.example.com/.well-known/jwks.json",
        }
        respx.get("https://auth.example.com/.well-known/oauth-authorization-server").mock(
            return_value=respx.MockResponse(status_code=200, json=metadata_doc)
        )
        route = respx.get("https://auth.example.com/.well-known/jwks.json").mock(
            return_value=respx.MockResponse(
                status_code=200,
                json=jwks_keypair["jwks"],
            )
        )
        yield route


@pytest.fixture
def mock_as_metadata(jwks_keypair: JWKSKeypair) -> Generator[MockASMetadata]:
    """Mock AS metadata endpoint using respx (RFC 8414).

    Returns:
        respx mock for https://auth.example.com/.well-known/oauth-authorization-server
    """
    with respx.mock:
        metadata_doc = {
            "issuer": "https://auth.example.com",
            "authorization_endpoint": "https://auth.example.com/oauth/authorize",
            "token_endpoint": "https://auth.example.com/oauth/token",
            "jwks_uri": "https://auth.example.com/.well-known/jwks.json",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "scopes_supported": ["read:data", "write:data"],
        }
        metadata_route = respx.get(
            "https://auth.example.com/.well-known/oauth-authorization-server"
        ).mock(return_value=respx.MockResponse(status_code=200, json=metadata_doc))

        # Also mock the JWKS endpoint
        jwks_route = respx.get("https://auth.example.com/.well-known/jwks.json").mock(
            return_value=respx.MockResponse(
                status_code=200,
                json=jwks_keypair["jwks"],
            )
        )

        yield {"metadata": metadata_route, "jwks": jwks_route}


@pytest.fixture
async def client(mock_jwks: Route) -> AsyncGenerator[AuthplaneClient]:
    """Pre-configured AuthplaneClient with cleanup.

    Yields:
        AuthplaneClient instance configured for test issuer
    """
    _no_ssrf = FetchSettings(ssrf_protection=False)
    c = await AuthplaneClient.create(
        issuer="https://auth.example.com",
        fetch_settings=_no_ssrf,
    )
    yield c
    await c.aclose()


@pytest.fixture
async def verifier(client: AuthplaneClient) -> AsyncGenerator[AuthplaneResource]:
    """Pre-configured AuthplaneResource with cleanup (uses RFC 8414 discovery).

    Yields:
        AuthplaneResource instance configured for test issuer/resource
    """
    v = client.resource(
        resource="https://api.example.com",
        scopes=["read:data", "write:data"],
    )
    yield v


@pytest.fixture
async def client_with_discovery(
    mock_as_metadata: MockASMetadata,
) -> AsyncGenerator[AuthplaneClient]:
    """Pre-configured AuthplaneClient with RFC 8414 discovery.

    Yields:
        AuthplaneClient instance that uses metadata discovery
    """
    _no_ssrf = FetchSettings(ssrf_protection=False)
    c = await AuthplaneClient.create(
        issuer="https://auth.example.com",
        fetch_settings=_no_ssrf,
    )
    yield c
    await c.aclose()


@pytest.fixture
async def verifier_with_discovery(
    client_with_discovery: AuthplaneClient,
) -> AsyncGenerator[AuthplaneResource]:
    """Pre-configured AuthplaneResource with RFC 8414 discovery.

    Yields:
        AuthplaneResource instance that uses metadata discovery
    """
    v = client_with_discovery.resource(
        resource="https://api.example.com",
        scopes=["read:data", "write:data"],
    )
    yield v
