"""Shared test fixtures for Authplane SDK tests."""

import time
from collections.abc import AsyncGenerator, Callable, Generator
from dataclasses import dataclass
from typing import Any, Protocol, cast

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


@dataclass(frozen=True)
class SigningKey:
    """An ES256 signing key: its public JWK, its PEMs, and a token signer."""

    kid: str
    jwk: dict[str, Any]
    private_pem: bytes
    public_pem: bytes

    @property
    def jwks(self) -> dict[str, Any]:
        """The single-key JWKS document publishing this key."""
        return {"keys": [self.jwk]}

    def sign(self, **overrides: Any) -> str:
        """Sign an otherwise-valid access token for the default test resource.

        Keyword arguments override individual claims.
        """
        from authlib.jose import jwt

        now = int(time.time())
        claims: dict[str, Any] = {
            "iss": "https://auth.example.com",
            "aud": "https://api.example.com",
            "sub": "user123",
            "client_id": "client456",
            "scope": "read:data write:data",
            "exp": now + 3600,
            "nbf": now,
            "iat": now,
            "jti": f"token-id-{self.kid}",
        }
        claims.update(overrides)
        header = {"alg": "ES256", "typ": "at+jwt", "kid": self.kid}
        token: bytes = jwt.encode(header, claims, self.private_pem)  # pyright: ignore[reportUnknownMemberType]
        return token.decode("utf-8")


def _make_es256_key(kid: str) -> SigningKey:
    """Generate an ES256 keypair and export its public half as a JWK."""
    private_key = ec.generate_private_key(ec.SECP256R1())

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    # Convert to authlib JsonWebKey
    jwk = JsonWebKey.import_key(public_pem, {"kty": "EC"})  # pyright: ignore[reportArgumentType]
    # cast, not just an annotation: `as_dict()` is untyped, and the resulting
    # value now flows into a typed constructor rather than into a dict literal
    # that used to absorb the Unknown.
    jwk_dict = cast("dict[str, Any]", jwk.as_dict())  # pyright: ignore[reportUnknownMemberType]
    jwk_dict["kid"] = kid
    jwk_dict["alg"] = "ES256"
    jwk_dict["use"] = "sig"

    return SigningKey(kid=kid, jwk=jwk_dict, private_pem=private_pem, public_pem=public_pem)


@pytest.fixture
def jwks_keypair() -> JWKSKeypair:
    """Generate an ES256 keypair and export as JWKS.

    Returns:
        dict with 'private_key', 'public_key', and 'jwks' (JWKS JSON dict)
    """
    key = _make_es256_key("test-key-1")
    return {
        "private_key": key.private_pem,
        "public_key": key.public_pem,
        "jwks": key.jwks,
    }


@pytest.fixture
def signing_key_factory() -> Callable[[str], SigningKey]:
    """Mint an independent ES256 signing key under a caller-chosen ``kid``.

    ``jwks_keypair`` and ``token_factory`` cover the single-key case. This is
    for tests that need a *second*, unrelated key set — a rotated ``jwks_uri``
    publishing a key the previous URI never served, say — where the point is
    that a token is unverifiable unless the SDK fetched the right document.
    """
    return _make_es256_key


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


def _expire_metadata_interval(client: AuthplaneClient) -> None:
    """Bring the metadata refresh interval forward instead of sleeping through it.

    Only the cache's notion of when it last fetched is moved; ``verify()`` still
    drives the refresh through the production path, and no caller passes
    ``force_refresh``. Sleeping for a real interval both costs wall clock and
    races the background refresh that opens at 80% of it, which makes exact
    fetch-count assertions unreliable on a loaded runner.
    """
    metadata_cache = client.metadata_cache
    assert metadata_cache is not None
    metadata_cache._cache_time = 0  # pyright: ignore[reportPrivateUsage]


@pytest.fixture
def expire_metadata_interval() -> Callable[[AuthplaneClient], None]:
    """The documented seam for driving a metadata refresh without sleeping.

    Exposed as a fixture rather than a module-level function so the conformance
    suite can re-export it alongside the others: the poke then has one
    definition and one docstring, instead of being repeated inline wherever a
    rotation is driven.
    """
    return _expire_metadata_interval
