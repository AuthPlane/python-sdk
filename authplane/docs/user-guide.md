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
- Tested against authserver 0.2.0; introspection-based revocation needs authserver ≥ 0.1.2

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
5. Metadata and JWKS refresh on demand rather than on a timer: a cache re-reads its document when a lookup finds its TTL (`metadata_refresh_seconds`, `jwks_refresh_seconds`) elapsed, and refreshes ahead of expiry in the background when a lookup lands past 80% of it. Verifying a token counts as a lookup for both, so a resource server that never calls an AS endpoint still re-reads metadata and follows a rotated `jwks_uri`. Two bounds are worth knowing about. A token whose `kid` is not in the cached key set forces a metadata re-read, and that is floored at one per `min(metadata_refresh_seconds, 60)` seconds — the `kid` on an unverified token is attacker-controlled, so without a floor invalid tokens would drive discovery traffic at your AS one-for-one. And a *failed* refresh backs off for `max(1, min(30, refresh_seconds))` seconds rather than being retried by the next caller, which keeps an unreachable endpoint from costing a full timeout per verification; for the JWKS cache that means a blip at a newly advertised `jwks_uri` can delay a rotation by up to `min(30, jwks_refresh_seconds)` seconds.
6. `jwks_uri` is read from the metadata document on every key-set fetch rather than captured at creation, so a rotation takes effect on the next fetch with no window in which keys are still being pulled from the withdrawn URI. A token whose `kid` is absent from the cached key set re-reads metadata as well, so a rotation is followed on the request that first needs the new key rather than at the next interval boundary.

If initial metadata or JWKS fetch fails and there is no cached value, the SDK raises `MetadataFetchError` or `JWKSFetchError`.

### Authentication to the AS

If you pass `ASCredentials`, the SDK wraps them in `ClientCredentialsProvider` and uses HTTP Basic authentication for AS-facing operations. Both fields must be non-empty — `ASCredentials` raises `ValueError` otherwise, because an empty secret authenticates as a public client, which cannot introspect at all.

```python
from authplane import ASCredentials

creds = ASCredentials(client_id="my-resource", client_secret="s3cret")
```

For introspection the client behind these credentials must be confidential and either the client the token was issued to or a runtime-client of the resource — see [Revocation Checking](#5-revocation-checking).

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
    fail_closed=False,  # default: a failed revocation check accepts the token; True refuses it
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
        replay_store=InMemoryDPoPReplayStore(),  # process-scoped by default
        max_proof_age_seconds=300,
        clock_skew_seconds=30,
        allowed_proof_algorithms=("RS256", "ES256"),
        required=True,  # reject bearer-only tokens
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
```

`claims.may_act` is deprecated and emits `DeprecationWarning`: authserver 0.2.0 no longer issues `may_act`; the accessor is removed in the next minor.

Because the object is immutable, post-verification mutations cannot change later authorization decisions.

## 5. Revocation Checking

By default, verification only uses the JWT and JWKS.

### Built-in introspection-based revocation

```python
from authplane import IntrospectionRevocation

res = client.resource(
    resource="https://api.example.com",
    revocation_checker=IntrospectionRevocation(),
    fail_closed=True,  # refuse tokens the introspection call could not confirm
)
```

This uses the RFC 7662 introspection endpoint after local JWT verification.

Important behavior:

- the client must have AS credentials configured, and the client behind them must be **confidential** and either the client the token was issued to or a runtime-client of the resource named in the token's `aud`:

  ```bash
  authserver admin resource runtime-client add --client-id <rs-client-id> --slug <resource-slug>
  ```

- a public client cannot introspect at all. Since authserver 0.1.2 an unauthenticated call, or one from a client that is neither the issuer nor a runtime-client, is answered with `{"active": false}` — not an error — so every token is rejected as revoked under both failure policies. The SDK warns at `client.resource(...)` when `IntrospectionRevocation` is configured on a client created without `auth=`, and once per resource the first time `active=false` comes back for a token that passed local verification
- the AS metadata must expose `introspection_endpoint`
- if the check fails, `fail_closed` decides whether the token is accepted or rejected — see below

### Failure policy: fail-open vs fail-closed

**An introspection error lets the token through unless you pass `fail_closed=True`.** The flag defaults to `False`, and that default is a deliberate trade, not an oversight: fail-closed means an introspection outage takes the resource server down with the AS, and local JWT validation exists precisely so the resource server keeps answering while the AS is unreachable.

Which direction is right depends on what an unconfirmed token authorises. Pass `fail_closed=True` when it would authorise something you cannot take back — writes, payments, executing statements on the caller's behalf. Keep the default when serving through an AS outage matters more than closing the window in which an already-revoked token still works.

```python
# Fail-open: the default — an unreachable AS does not take the resource server with it
res = client.resource(
    resource="https://api.example.com",
    revocation_checker=IntrospectionRevocation(),
)
```

- under the default, a failed check accepts the token and logs a warning on every `verify()`
- the SDK logs it at INFO when a resource is built through `client.resource(...)` with a revocation checker configured fail-open, so the posture in effect shows up in startup output rather than only here. INFO rather than a warning: keeping the default is a documented choice, not a misconfiguration — the no-op pairing below is the one that warns
- `fail_closed` has no effect when `revocation_checker` is `None` — there is no check to fail. The SDK logs a warning when a resource is built through `client.resource(...)` with one set and not the other, so the no-op configuration is visible rather than silent.

### Custom revocation checker

```python
from authplane import VerifiedClaims


async def my_revocation_checker(claims: VerifiedClaims, raw_token: str) -> bool:
    return claims.jti in revoked_jtis
```

Return `True` to reject the token.

Important behavior:

- a callback that raises lets the token through and logs the error; pass `fail_closed=True` on `client.resource()` to refuse it instead
- the same trade-off applies as for introspection, and the same construction-time warning fires when a custom checker is configured fail-open

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

**Operator step — allowlist the exchanging client.** authserver 0.2.0 only honours a cross-client exchange when the exchanging client is allowlisted on the target Resource. For each resource server that exchanges for a downstream resource it does not itself act as, add its client id to that Resource's exchange policy:

```http
PATCH /admin/resources/{id}
{"policy": {"exchange": {"allowed_client_ids": ["<exchanging-client-id>"]}}}
```

A client exchanging a token that was issued to itself, a fronted exchange, and a Broker resource need nothing.

Exchange-specific errors:

- `AccessDeniedError` (`access_denied`, HTTP 403) — the exchanging client is not allowlisted on the target Resource. This is an operator-side fix (the `PATCH` above); re-prompting the user will not clear it, which is why it is a distinct class from `ConsentRequiredError`.
- `InvalidTargetError` (`invalid_target`, HTTP 400, RFC 8707 §2.2) — the `resource` string does not match a granted resource byte for byte; a trailing slash is enough.
- `ConsentRequiredError` — the AS requires interactive user consent before issuance (`consent_required` / `interaction_required`).

None of the three trips the circuit breaker — they are the AS answering, not the AS failing.

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
    def get(self, key: str) -> str: ...  # return "" on a miss, never None (DPoPNonceStore contract)

    def put(self, key: str, nonce: str) -> None: ...


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
- `InvalidIssuerError`: the configured issuer carries a query or fragment component (RFC 8414 §2). Raised from `AuthplaneClient.create()`, at construction, before any network fetch. Subclasses `ValueError` as well as `AuthplaneError`, so an existing `except ValueError` still catches it
- `InvalidResourceError`: the configured resource identifier is rejected on one of these axes, checked in that order — it carries a fragment component (RFC 8707 §2); it contains whitespace or a control character (RFC 3986 §2, and RFC 9728 §3.3 obliges a client to discard a PRM document naming a resource that differs from the URL it was fetched from, which is what `urlsplit`'s silent cleaning would produce); it is not an absolute URL with a scheme and a host (RFC 8707 §2 requires an absolute URI; RFC 9728 §3 derives the metadata URL by inserting the well-known suffix after the host); it carries a userinfo subcomponent (RFC 9110 §4.2.4); or its port does not parse (RFC 3986 §3.2.3 — `https://api.example.com:80O/mcp`, letter O for zero). The scheme is not narrowed to `https` — `http://localhost:8080/mcp` stays valid for local development. The rejection message echoes the identifier with any userinfo redacted. The same error type also covers `resource_metadata_url=`, on a slightly different list: the scheme *is* narrowed there, to `http`/`https`, and a `"` or `\` is rejected anywhere in the value rather than only in the host, because that one is spliced into a `WWW-Authenticate` quoted-string (RFC 9110 §11.2). It is raised from `AuthplaneResource.__init__`, `AuthplaneClient.resource()` and both adapter factories. Raised at construction, from these call sites, of which one is authoritative:
  - `AuthplaneResource.__init__` — the authoritative gate. Every construction path reaches it, including direct construction of the package-root export, so `AuthplaneResource(...)` built by hand raises here too.
  - `AuthplaneClient.resource()` — redundant for the guarantee, kept for the traceback: it raises at the line the operator wrote rather than one frame deeper in the constructor.
  - `build_prm_url()` — a defensive backstop only. Its production caller is `AuthplaneResource.prm_url()`, which operators invoke inside a 401 response path, so validating *only* there turned a configuration error into a 500 on the failure path.
  - `authplane_mcp_auth()` (`authplane-mcp`) and `authplane_auth()` (`authplane-fastmcp`) — early gates ahead of `AuthplaneClient.create()`, so a misconfiguration is diagnosed without a reachable authorization server. These call the exported `authplane.validate_prm_resource_identifier`, which is the same gate; the name is scoped to the resource-*server* identifier, since the host requirement is RFC 9728 §3's rather than RFC 8707 §2's.

  Subclasses `ValueError` as well as `AuthplaneError`, on the same terms as `InvalidIssuerError`
- `ProtocolError`: malformed successful OAuth response
- `VerifierRuntimeError`: unexpected verifier or DPoP validation runtime failure
- `InsufficientScopeError`: authorization failure, typically HTTP 403

### AS-facing errors

```python
from authplane import (
    AccessDeniedError,
    AuthError,
    CircuitOpenError,
    InvalidClientError,
    InvalidGrantError,
    InvalidTargetError,
)
```

The SDK maps OAuth error responses into typed `AuthError` subclasses — `access_denied` to `AccessDeniedError`, `invalid_target` to `InvalidTargetError`, `consent_required` / `interaction_required` to `ConsentRequiredError`, and so on. The circuit breaker fails fast with `CircuitOpenError` when the AS is considered unavailable.

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
        resource_metadata_url=res.resource_metadata_url(),
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

`error_description` is a fixed sentence chosen by the error code — never the exception's message. The challenge is served to a caller who has not authenticated, and the SDK's messages name the detail that failed: the unknown `kid`, the claim that did not validate, or, for an `aud` mismatch, the exact audience the resource expects. The message stays on the exception for you to log, and the SDK also logs it at `DEBUG` on the `authplane.errors` logger. `verbose_description=True` puts it back on the wire; it is a development aid, not a production setting.

### Advertising more than one scheme

`www_authenticate()` derives the scheme from the error, so it always names exactly one. A resource running `inbound_dpop` in optional mode accepts both `Bearer` and `DPoP` and should advertise both, so a DPoP-capable client can discover that sender-constrained tokens are taken here (RFC 9449 §7.1; §7.2 covers running the two schemes side by side). Use `www_authenticate_challenges()` for that:

```python
from authplane import AuthplaneError, http_status, www_authenticate_challenges

try:
    claims = await res.verify(token, dpop_request=request)
except AuthplaneError as e:
    challenges = www_authenticate_challenges(
        e,
        schemes=("Bearer", "DPoP"),
        algs=("ES256", "RS256"),  # InboundDPoPOptions.allowed_proof_algorithms
        realm="api.example.com",
        resource_metadata_url=res.resource_metadata_url(),
    )
    for challenge in challenges:
        response.headers.append("WWW-Authenticate", challenge)
    response.status_code = http_status(e)
```

The two challenges cannot be joined into one header value: the comma that would separate them is also the separator *between parameters inside* a challenge, so the result cannot be parsed unambiguously. RFC 7235 §4.1 permits the comma-joined form but warns about parsing it, so separate header values are the interoperable choice and this returns a list — emit one header value per element, using whatever your framework's append-a-header API is (`headers.append`, `add_header`, `MutableHeaders.append`).

`algs=` is the RFC 9449 §7.1 parameter that tells a client which proof algorithms to sign with instead of guessing and retrying; it is emitted on the `DPoP` challenge only. Omitting `schemes=` derives the single scheme from the error, so `www_authenticate_challenges(e)` returns exactly what `www_authenticate(e)` would, in a one-element list. `response_headers_for()` stays single-scheme by construction — a dict holds one value per header name.

## 12. Protected Resource Metadata

Generate an RFC 9728 protected resource metadata document with:

```python
prm = res.prm_response()  # the document body (a dict)
url = res.prm_url()  # the well-known URL where clients can fetch that document
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

### Where the PRM document lives

Two topologies, and the SDK supports both:

**(a) Resource-hosted — the default.** This resource serves the document itself at `/.well-known/oauth-protected-resource[/path]`, derived from the resource identifier per RFC 9728 §3.1. `prm_response()` builds the body, `prm_url()` gives the URL, and the challenge advertises that URL with no configuration.

**(b) AS-hosted.** The authorization server serves the document for every registered Resource — authserver ≥ 0.2.0 serves one at `<issuer>/.well-known/oauth-protected-resource/{ref}`, where `ref` is the RFC 9728 §3.1 path suffix of the Resource URI (or its slug) — and this SDK only points clients at it. Useful when the resource server cannot host well-known paths: a mount behind a path prefix it does not control, or a platform that owns the root of the origin. Pass `resource_metadata_url=` and the resource keeps everything else unchanged:

```python
res = client.resource(
    resource="https://api.example.com/mcp",
    scopes=["read", "write"],
    resource_metadata_url="https://auth.example.com/.well-known/oauth-protected-resource/mcp",
)

res.resource_metadata_url()  # the configured URL — advertise this one
res.prm_url()  # still the §3.1 derivation of the identifier
```

`resource_metadata_url()` returns the override when one is configured and `prm_url()` otherwise, so middleware composing a challenge reads one accessor either way. The option is validated at construction — absolute `http`/`https` URL, no fragment, no userinfo, no whitespace, no quoted-string delimiter — because a bad value would otherwise surface from inside a 401.

**RFC 9728 §3.3 constrains topology (b), and it is worth reading before choosing it.** The rule binds the document's `resource` value to *the URL the document was fetched from*, not to the API URL the client called: "The resource value returned MUST be identical to the protected resource's resource identifier value into which the well-known URI path suffix was inserted to create the URL used to retrieve the metadata. If these values are not identical, the data contained in the response MUST NOT be used."

The two readings coincide only when the metadata URL is the §3.1 derivation of the resource identifier — which is topology (a). In topology (b) they cannot: a client that fetches `https://auth.example.com/.well-known/oauth-protected-resource/mcp` reverse-derives `https://auth.example.com/mcp` and compares it against the document's `resource`, `https://api.example.com/mcp`. Not identical, so a client enforcing §3.3 MUST NOT use the document. That check is load-bearing on the client side — it is what stops a resource server from pointing a client at metadata describing somebody else's resource — so it is not a check to design around.

Concretely: **an AS-hosted document on an origin other than the resource's is usable only against clients that do not enforce §3.3.** Topology (a) is the conformant one, and it is the default for that reason. Both adapters keep serving their own document at the derived path and the upstream middleware's 401 keeps pointing there, so an adapter deployment is unaffected either way; the override reaches only challenges you compose yourself.

Whichever topology you pick, the Resource URI registered at the AS, the identifier passed as `resource=` here, and the public URL of this server have to be one identical string — a trailing slash, a differing case in the host, or a `:443` spelled out on one side and not the other is a mismatch.

## 13. Advanced Notes

### Circuit breaker behavior

The circuit breaker protects AS-bound operations from cascading failure.

- transient server-side failures count
- transport failures such as connection and timeout errors count
- SSRF validation failures do not count
- OAuth policy answers do not count — `access_denied`, `invalid_target`, `consent_required` and the other 4xx error codes are the AS responding, not failing
- after cooldown expiry, only one half-open probe is allowed at a time

### Unknown `kid`

If a token references an unknown `kid`, the JWKS cache is force-refreshed once before the verifier gives up. This supports normal key rotation without turning every bad token into repeated network traffic.

### Strict discovery behavior

The SDK now fails closed on discovery problems:

- metadata `issuer` mismatch is rejected
- missing discovered endpoints are rejected
- token, introspection, and revocation endpoints are not guessed from the issuer URL
