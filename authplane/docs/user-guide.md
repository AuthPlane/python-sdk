# Authplane Python SDK User Guide

This guide documents the current `authplane-sdk` API for MCP servers and other resource servers that need to validate JWT access tokens, perform token operations against an authorization server, and support DPoP-bound flows.

The SDK is built around these RFCs:

- RFC 8414: Authorization Server Metadata
- RFC 9068: JWT Profile for OAuth 2.0 Access Tokens
- RFC 7662: Token Introspection
- RFC 8693: Token Exchange
- RFC 7009: Token Revocation
- RFC 9449: DPoP
- RFC 9728: Protected Resource Metadata

## 1. Getting Started

### Requirements

- Python 3.11+

### Installation

```bash
pip install authplane-sdk
```

### Minimal Example

```python
from authplane import ASCredentials, AuthplaneClient

client = await AuthplaneClient.create(
    issuer="https://auth.example.com",
    auth=ASCredentials(client_id="my-resource", client_secret="s3cret"),
)

res = client.resource(
    resource="https://api.example.com",
    scopes=["read", "write"],
)

claims = await res.verify(token)
print(claims.sub, claims.scopes)

await client.aclose()
```

## 2. Creating `AuthplaneClient`

`AuthplaneClient` owns AS metadata discovery, JWKS caching, token caching, DPoP configuration, and the circuit breaker. Always create it with `await AuthplaneClient.create(...)`.

```python
from authplane import ASCredentials, AuthplaneClient, DPoPKeyMaterial, DPoPProvider

client = await AuthplaneClient.create(
    issuer="https://auth.example.com",
    auth=ASCredentials(client_id="my-resource", client_secret="s3cret"),
    dpop=DPoPProvider(DPoPKeyMaterial.from_pem(private_key_pem)),
    dev_mode=False,
    fetch_settings=None,
    jwks_refresh_seconds=300,
    metadata_refresh_seconds=3600,
    cache_ttl_buffer_seconds=30.0,
    default_ttl_seconds=3600.0,
    circuit_breaker_threshold=5,
    circuit_breaker_cooldown_seconds=30.0,
)
```

### What happens during creation

1. Metadata is fetched from the RFC 8414 discovery URL derived from `issuer`.
2. The metadata document must contain an `issuer` that exactly matches the normalized configured issuer.
3. Required discovered endpoints are trusted only from metadata. The SDK does not synthesize fallback token, introspection, or revocation endpoints.
4. The discovered `jwks_uri` is fetched and cached.
5. Background refresh tasks are started for metadata and JWKS.

If initial metadata or JWKS fetch fails and there is no cached value, the SDK raises `MetadataFetchError` or `JWKSFetchError`.

### Authentication to the AS

If you pass `ASCredentials`, the SDK wraps them in `ClientCredentialsProvider` and uses HTTP Basic authentication for AS-facing operations.

```python
from authplane import ASCredentials

creds = ASCredentials(client_id="my-resource", client_secret="s3cret")
```

### Cleanup

Always call `await client.aclose()` during shutdown.

## 3. Verifying Access Tokens

Create a resource from the client:

```python
res = client.resource(
    resource="https://api.example.com",
    scopes=["read", "write"],
    allowed_algorithms=["RS256", "ES256"],
    clock_skew_seconds=30,
    fail_closed=False,  # default; set True to reject tokens when revocation check fails
)
```

### Verification rules

- Only `RS256` and `ES256` (asymmetric) are accepted; `none`, `HS256`, `HS384`, `HS512` are always rejected at construction.
- The JWT header `typ` must be `at+jwt`.
- The JWT `iss` must match the configured issuer.
- The JWT `aud` must match the verifier resource.
- Standard claims required by the SDK include `sub`, `client_id`, `exp`, `iat`, and `jti`.
- JWK selection is filtered by `kid`, and also by `use`, `key_ops`, and `alg` when those fields are present.

### Bearer-style verification

```python
claims = await res.verify(token)
```

`verify()` returns `VerifiedClaims` or raises an `AuthplaneError` subclass.

### DPoP-bound verification

DPoP enforcement is configured per-resource (RFC 9728 § 2 + RFC 9449 § 7.1).
Replay storage, accepted proof algorithms, max proof age, clock skew, and
the `required` policy flag are bundled in `InboundDPoPOptions` and passed
to `client.resource(...)`; only the per-request inputs (proof, HTTP
method, URL — RFC 9449 § 7) flow through `verify()`.

```python
from authplane import InboundDPoPOptions, InMemoryDPoPReplayStore

res = client.resource(
    resource="https://api.example.com",
    scopes=["read"],
    inbound_dpop=InboundDPoPOptions(
        replay_store=InMemoryDPoPReplayStore(),     # process-scoped by default
        max_proof_age_seconds=300,
        clock_skew_seconds=30,
        allowed_proof_algorithms=("RS256", "ES256"),
        required=True,                              # reject bearer-only tokens
    ),
)
```

The presence of `inbound_dpop` on a resource is the on/off switch for
PRM-advertising DPoP support. Set `required=True` to additionally promote
that to a hard requirement and reject bearer-only tokens at verify time;
leave it `False` (the default) when the resource needs to support both
DPoP-bound and bearer tokens during a migration.

For each incoming request that may carry a DPoP-bound token, build a
`DPoPRequestContext` with just the per-request fields and pass it to
`verify()`:

```python
from dataclasses import dataclass

@dataclass
class IncomingRequest:
    """Implements DPoPRequestContext."""
    method: str
    url: str
    proof: str | None

claims = await res.verify(
    token,
    dpop_request=IncomingRequest(
        method="GET",
        url="https://api.example.com/tools/list",
        proof=incoming_dpop_header,
    ),
)

if claims.dpop_proof:
    print(claims.dpop_proof.key_thumbprint)
```

`res.verify()` inspects the token for a `cnf.jkt` binding:

- **Bearer token** (no `cnf.jkt`): verification succeeds normally and
  `claims.dpop_proof` is `None`. If the resource was configured with
  `InboundDPoPOptions(required=True)`, the bearer token is rejected.
- **DPoP-bound token** (has `cnf.jkt`): the request context must carry a
  proof. The verifier enforces:
  - proof `typ` must be `dpop+jwt`
  - proof `alg` must be in the resource's `allowed_proof_algorithms`
  - proof `htm`, `htu`, `iat`, and `jti` must validate
  - replay detection must succeed through the resource's `replay_store`
  - the proof key thumbprint must match the token's `cnf.jkt`

If `dpop_request` is omitted, `verify()` performs bearer-only validation
and callers do not need to manage per-request DPoP inputs.

## 4. Working with `VerifiedClaims`

`VerifiedClaims` is immutable.

Important field types:

- `scopes: tuple[str, ...]`
- `audience: tuple[str, ...]`
- `raw: Mapping[str, Any]`
- `dpop_proof: VerifiedDPoPProof | None` — set when a DPoP-bound token is verified with request context

Example:

```python
claims = await res.verify(token)

if claims.has_scope("tools/query"):
    ...

claims.require_scope("tools/query")

org_id = claims.raw.get("org_id")
actor = claims.act
may_act = claims.may_act
```

Because the object is immutable, post-verification mutations cannot change later authorization decisions.

## 5. Revocation Checking

By default, verification only uses the JWT and JWKS.

### Built-in introspection-based revocation

```python
from authplane import IntrospectionRevocation

res = client.resource(
    resource="https://api.example.com",
    revocation_checker=IntrospectionRevocation(),
)
```

This uses the RFC 7662 introspection endpoint after local JWT verification.

Important behavior:

- by default it is **fail-open**: if introspection fails, the token is accepted
- set `fail_closed=True` to reject tokens when the revocation check fails
- the client must have AS credentials configured
- the AS metadata must expose `introspection_endpoint`

```python
# Fail-closed: reject tokens when introspection is unavailable
res = client.resource(
    resource="https://api.example.com",
    revocation_checker=IntrospectionRevocation(),
    fail_closed=True,
)
```

### Custom revocation checker

```python
from authplane import VerifiedClaims

async def my_revocation_checker(claims: VerifiedClaims, raw_token: str) -> bool:
    return claims.jti in revoked_jtis
```

Return `True` to reject the token.

Important behavior:

- by default it is **fail-open**: if the custom revocation callback fails, the token is accepted and the error is logged
- set `fail_closed=True` on `client.resource()` to reject tokens when the checker raises an exception

## 6. Token Operations

All AS-facing operations use discovered metadata endpoints and the configured circuit breaker.

### `client_credentials(...)`

```python
result = await client.client_credentials(
    scopes=["read", "write"],
    resources=["https://api.example.com"],
)

print(result.access_token)
print(result.token_type)
print(result.expires_in)
print(result.cnf_jkt)
```

Successful token responses are schema-validated. The SDK requires:

- non-empty `access_token`
- `token_type` must be `Bearer` or `DPoP` (case-insensitive)
- valid integer `expires_in` when present

If the response is malformed, the SDK raises `ProtocolError`.

### `introspect(...)`

```python
result = await client.introspect(access_token)
print(result.active, result.sub, result.scope)
```

### `revoke(...)`

```python
await client.revoke(access_token)
```

### `exchange(...)`

`TokenExchangeOptions` supports repeated `resource` and `audience` parameters.

```python
from authplane.oauth.types import TokenExchangeOptions

result = await client.exchange(
    TokenExchangeOptions(
        subject_token=user_token,
        subject_token_type="urn:ietf:params:oauth:token-type:access_token",
        actor_token=agent_token,
        scope="calendar.read",
        resources=(
            "https://calendar.googleapis.com/",
            "https://downstream.example.com/",
        ),
        audiences=("google-calendar",),
    )
)

print(result.access_token)
print(result.issued_token_type)
print(result.cnf_jkt)
```

Token exchange responses only accept access-token-compatible `issued_token_type` values.

### Token caching

Client-credentials responses are cached in memory by `(scope, resource)`. Cached entries are evicted slightly before expiry based on `cache_ttl_buffer_seconds`.

## 7. DPoP for Outbound Calls

Use `DPoPProvider` when your MCP server needs to acquire sender-constrained tokens for its own use against downstream services, or when the AS/downstream service requires DPoP proofs on the request itself. (For accepting DPoP-bound tokens from incoming requests, see `inbound_dpop` in §3.)

```python
from authplane import DPoPKeyMaterial, DPoPProvider

provider = DPoPProvider(DPoPKeyMaterial.from_pem(private_key_pem))

client = await AuthplaneClient.create(
    issuer="https://auth.example.com",
    auth=creds,
    dpop=provider,
)
```

`DPoPProvider` is the outbound proof generator. It owns:

- signing key material
- proof lifetime configuration
- nonce tracking for AS or downstream DPoP challenges

By default:

- proofs include both `iat` and `exp`
- `proof_ttl_seconds` defaults to `300`
- nonce state uses a bounded in-memory store

When configured, the SDK automatically sends DPoP proofs on:

- `client_credentials(...)`
- `exchange(...)`
- `introspect(...)`
- `revoke(...)`

Nonce behavior:

- if the AS returns `error=use_dpop_nonce` and a `DPoP-Nonce` header
- the SDK stores the nonce on the provider
- it rebuilds the proof and retries once automatically

### Configuring proof TTL and nonce storage

For simple single-process deployments, the default provider is usually enough:

```python
from authplane import DPoPKeyMaterial, DPoPProvider

provider = DPoPProvider(
    DPoPKeyMaterial.from_pem(private_key_pem),
    proof_ttl_seconds=300,
)
```

The default nonce store is an in-memory bounded store suitable for local development and single-instance services.

If you want explicit control over that store, use `InMemoryDPoPNonceStore`:

```python
from authplane import DPoPKeyMaterial, DPoPProvider, InMemoryDPoPNonceStore

provider = DPoPProvider(
    DPoPKeyMaterial.from_pem(private_key_pem),
    nonce_store=InMemoryDPoPNonceStore(max_entries=256),
)
```

For multi-instance or shared-state deployments, provide your own `DPoPNonceStore` implementation:

```python
from authplane import DPoPKeyMaterial, DPoPNonceStore, DPoPProvider

class MyNonceStore:
    def get(self, key: str) -> str:
        ...

    def put(self, key: str, nonce: str) -> None:
        ...

provider = DPoPProvider(
    DPoPKeyMaterial.from_pem(private_key_pem),
    nonce_store=MyNonceStore(),
)
```

Use a custom store when nonce state must survive process restarts or be shared across workers.

### Reusing DPoP for downstream APIs

You can reuse the same configured provider for backend calls:

```python
headers = client.dpop_headers(
    "GET",
    "https://calendar.googleapis.com/calendar/v3/users/me/calendarList",
    access_token=downstream_access_token,
)
```

This keeps DPoP key material and nonce tracking in one place.

## 8. Inbound DPoP Summary

A resource has one of three DPoP enforcement modes, selected by how `inbound_dpop` is set on `client.resource(...)`:

| Mode | Configuration | PRM advertises DPoP | Bearer-only token | DPoP-bound token | Proof attached to a bearer-only token |
|------|---------------|---------------------|-------------------|------------------|----------------------------------------|
| **Required** | `InboundDPoPOptions(required=True)` | yes (`dpop_bound_access_tokens_required: true`) | rejected (`DPoPBindingMismatchError`) | validated end-to-end | rejected |
| **Supported** | `InboundDPoPOptions()` (or any `required=False`) | yes (`dpop_bound_access_tokens_required: false`) | accepted | validated end-to-end | rejected (malformed request) |
| **Not configured** | argument omitted | no DPoP fields in PRM | accepted | rejected (`DPoPNotSupportedError`) | rejected (`DPoPNotSupportedError`) |

Mode-3 enforcement reflects RFC 9449 § 6: only resource servers that support DPoP are obliged to validate the binding, and a resource that has not advertised DPoP support cannot be allowed to silently fall back to bearer (which would drop sender-binding) or apply ad-hoc validation policies that were never advertised in PRM.

The single `verify()` entrypoint handles all three modes. Per-resource DPoP policy (replay store, accepted proof algorithms, max proof age, clock skew, `required`) is bundled in `InboundDPoPOptions` per RFC 9728 § 2. Pass a `DPoPRequestContext` carrying just the per-request inputs (proof, method, URL — RFC 9449 § 7) to enable sender-constraint validation:

- the access token is validated first
- if `cnf.jkt` is present (and the resource supports DPoP), the proof must be supplied and valid
- the verifier validates proof signature, `htm`, normalized `htu`, `iat`, and replay state
- proof-to-token binding is enforced via the token thumbprint
- the validated proof is available via `claims.dpop_proof`

Outbound DPoP and inbound DPoP use different state:

- outbound nonce state lives on `DPoPProvider`
- inbound replay detection is supplied through `DPoPReplayStore` (allocated only when the resource is configured for DPoP)

## 9. Auth Providers

Any object that implements `auth_headers() -> dict[str, str]` can be used as the client’s AS auth provider.

```python
class BearerAuthProvider:
    def __init__(self, token: str) -> None:
        self._token = token

    def auth_headers(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self._token}"}
```

## 10. Fetch Settings and SSRF Protection

Metadata discovery, JWKS fetches, and SSRF-protected OAuth form posts all use `FetchSettings`.

```python
from authplane import FetchSettings

settings = FetchSettings(
    ssrf_protection=True,
    allow_http=False,
    allow_localhost=False,
    allow_private_networks=False,
    timeout=10.0,
)
```

### Production defaults

- HTTPS only
- no localhost
- no private networks
- DNS resolution and IP validation
- DNS pinning
- no redirects

### Development mode

```python
client = await AuthplaneClient.create(
    issuer="http://localhost:8080",
    dev_mode=True,
)
```

`dev_mode=True` resolves to `FetchSettings.from_dev_mode(True)`, which keeps SSRF protection enabled while allowing HTTP, localhost, and private-network endpoints. That is intended for local development only.

If you need custom behavior, provide an explicit `fetch_settings`. The single instance applies to both metadata and JWKS fetches.

## 11. Error Handling

The root package exports the main verification, metadata, DPoP, and AS-operation errors.

### Verification-side errors

```python
from authplane import (
    AuthplaneError,
    InsufficientScopeError,
    InvalidClaimsError,
    InvalidSignatureError,
    JWKSFetchError,
    MetadataFetchError,
    MissingMetadataEndpointError,
    ProtocolError,
    TokenExpiredError,
    TokenMissingError,
    TokenRevokedError,
    VerifierRuntimeError,
)
```

Common meanings:

- `TokenMissingError`: empty token input
- `InvalidSignatureError`: bad signature or unknown `kid`
- `InvalidClaimsError`: token/header claims failed validation
- `TokenExpiredError`: expired token
- `TokenRevokedError`: revocation checker rejected the token
- `MetadataFetchError`: AS metadata unavailable or invalid
- `JWKSFetchError`: JWKS unavailable
- `MissingMetadataEndpointError`: required discovered endpoint missing
- `ProtocolError`: malformed successful OAuth response
- `VerifierRuntimeError`: unexpected verifier or DPoP validation runtime failure
- `InsufficientScopeError`: authorization failure, typically HTTP 403

### AS-facing errors

```python
from authplane import AuthError, CircuitOpenError, InvalidClientError, InvalidGrantError
```

The SDK maps OAuth error responses into typed `AuthError` subclasses. The circuit breaker fails fast with `CircuitOpenError` when the AS is considered unavailable.

### HTTP status mapping

Use `http_status()` to map any `AuthplaneError` to an HTTP status code, `www_authenticate()` to build the matching `WWW-Authenticate` challenge, or `response_headers_for()` to get both in one call:

```python
from authplane import AuthplaneError, response_headers_for

try:
    claims = await res.verify(token)
except AuthplaneError as e:
    status, headers = response_headers_for(
        e,
        realm="api.example.com",
        resource_metadata_url=res.prm_url(),
    )
    # status: int, headers: {"WWW-Authenticate": "Bearer error=..."}
```

| Exception | HTTP Status |
|-----------|-------------|
| `InsufficientScopeError` | 403 |
| `JWKSFetchError`, `MetadataFetchError`, `CircuitOpenError` | 503 |
| `TokenMissingError`, `TokenExpiredError`, `InvalidSignatureError`, `InvalidClaimsError`, `TokenRevokedError`, `DPoPError` (and subclasses) | 401 |
| `ProtocolError`, `VerifierRuntimeError`, other | 500 |

`www_authenticate()` selects the scheme (`Bearer` by default, `DPoP` for DPoP-flow errors except `DPoPNotSupportedError`, which stays `Bearer` because the resource is bearer-only). When `scope=` is omitted it auto-populates from `InsufficientScopeError.required_scopes`. Every interpolated value is sanitized against header injection.

## 12. Protected Resource Metadata

Generate an RFC 9728 protected resource metadata document with:

```python
prm = res.prm_response()      # the document body (a dict)
url = res.prm_url()           # the well-known URL where clients can fetch it
```

Example output:

```json
{
  "resource": "https://api.example.com",
  "authorization_servers": ["https://auth.example.com"],
  "bearer_methods_supported": ["header"],
  "scopes_supported": ["read", "write"]
}
```

## 13. Advanced Notes

### Circuit breaker behavior

The circuit breaker protects AS-bound operations from cascading failure.

- transient server-side failures count
- transport failures such as connection and timeout errors count
- SSRF validation failures do not count
- after cooldown expiry, only one half-open probe is allowed at a time

### Unknown `kid`

If a token references an unknown `kid`, the JWKS cache is force-refreshed once before the verifier gives up. This supports normal key rotation without turning every bad token into repeated network traffic.

### Strict discovery behavior

The SDK now fails closed on discovery problems:

- metadata `issuer` mismatch is rejected
- missing discovered endpoints are rejected
- token, introspection, and revocation endpoints are not guessed from the issuer URL
