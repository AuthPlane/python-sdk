"""AS client credentials shared across AS-facing operations."""

from dataclasses import dataclass


@dataclass(frozen=True)
class ASCredentials:
    """Client credentials for authenticating to the Authorization Server.

    Used for any operation that requires the resource server to authenticate
    itself to the AS — currently introspection (RFC 7662) and token exchange
    (RFC 8693). Configuring them once at the verifier level means both
    features share the same identity without repeating the secret.

    Both fields are required and must be non-empty; omit ``ASCredentials``
    entirely for unauthenticated introspection (an RFC 7662 shape some AS
    implementations accept — authserver >= 0.1.2 answers ``active: false`` to
    it, so every token is rejected as revoked).

    Example::

        client = await AuthplaneClient.create(
            issuer="https://auth.example.com",
            auth=ASCredentials(
                client_id="https://api.example.com",
                client_secret="s3cret",
            ),
        )

    Attributes:
        client_id: OAuth client identifier registered with the AS.
        client_secret: Corresponding client secret.

    Raises:
        ValueError: If either field is empty. An empty secret authenticates
            as a public client, which cannot introspect at all, and the
            failure would otherwise surface per request as a fail-open
            warning or, under ``fail_closed=True``, as every token rejected.
    """

    client_id: str
    client_secret: str

    def __post_init__(self) -> None:
        if not self.client_id:
            raise ValueError("authplane: ASCredentials.client_id must not be empty")
        if not self.client_secret:
            raise ValueError("authplane: ASCredentials.client_secret must not be empty")
