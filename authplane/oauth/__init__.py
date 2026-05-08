"""OAuth protocol primitives — bare implementations without caching or resilience."""

from .client_credentials import client_credentials_grant
from .introspection import introspect_token
from .prm import build_prm
from .revocation import revoke_token
from .token_exchange import exchange_token
from .types import (
    GRANT_TYPE_TOKEN_EXCHANGE,
    TOKEN_TYPE_ACCESS_TOKEN,
    IntrospectionResponse,
    IntrospectionRevocation,
    TokenExchangeOptions,
    TokenResponse,
)

__all__ = [
    "GRANT_TYPE_TOKEN_EXCHANGE",
    "TOKEN_TYPE_ACCESS_TOKEN",
    "IntrospectionResponse",
    "IntrospectionRevocation",
    "TokenExchangeOptions",
    "TokenResponse",
    "build_prm",
    "client_credentials_grant",
    "exchange_token",
    "introspect_token",
    "revoke_token",
]
