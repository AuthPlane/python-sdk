"""AS client credentials shared across AS-facing operations."""

from dataclasses import dataclass


@dataclass(frozen=True)
class ASCredentials:
    """Client credentials for authenticating to the Authorization Server.

    Used for any operation that requires the resource server to authenticate
    itself to the AS — currently introspection (RFC 7662) and token exchange
    (RFC 8693). Configuring them once at the verifier level means both
    features share the same identity without repeating the secret.

    Both fields are required; omit ``ASCredentials`` entirely for unauthenticated
    introspection (accepted by some AS implementations but not recommended).

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
    """

    client_id: str
    client_secret: str
