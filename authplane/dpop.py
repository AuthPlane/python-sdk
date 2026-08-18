"""DPoP helpers for outbound proof generation and inbound proof validation."""

import asyncio
import base64
import hashlib
import json
import time
import uuid
from collections import OrderedDict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, Protocol, cast
from urllib.parse import SplitResult, urlsplit, urlunsplit

from authlib.jose import JsonWebKey, jwt

from .errors import (
    InvalidDPoPProofError,
)
from .internal.jwt import decode_jwt_header
from .internal.urls import host_literal

SUPPORTED_DPOP_ALGORITHMS = ("ES256", "RS256")


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _decode_jwt_header(token: str) -> dict[str, Any]:  # pyright: ignore[reportUnusedFunction]
    try:
        return decode_jwt_header(token)
    except Exception as exc:
        raise InvalidDPoPProofError(f"DPoP proof header must be a JSON object: {exc}") from exc


def _split_dpop_url(url: str) -> tuple[SplitResult, int | None]:
    """Split *url* and resolve its port, mapping urllib's bare ``ValueError``s.

    Two of them escape on a malformed authority: ``urlsplit`` itself rejects a
    netloc containing ``[`` without ``]`` (``Invalid IPv6 URL``), and
    ``SplitResult.port`` is parsed lazily, so a non-numeric or out-of-range port
    raises at attribute access rather than at split time.

    Both callers below run on attacker-controlled input — ``dpop_verification``
    passes the proof's own ``htu`` claim through ``normalize_dpop_htu`` — and the
    MCP adapters catch only ``AuthplaneError``, so a ``ValueError`` reaching them
    turns a 401 into an unhandled 500. ``internal/urls.py`` guards the same
    urllib trap on the derivation side.
    """
    try:
        parsed = urlsplit(url)
        return parsed, parsed.port
    except ValueError as exc:
        raise InvalidDPoPProofError(f"DPoP URL is not a valid URI, got {url!r}") from exc


def normalize_dpop_htu(url: str) -> str:
    """Normalize a URI for DPoP `htu` generation and comparison.

    urlsplit, not urlparse: urlparse peels an RFC 3986 ``;params`` segment off
    the last path segment into its own slot, and urlunparse then drops it
    unless it is passed back. RFC 9449 §4.3 defines ``htu`` as the request URI
    with query and fragment removed, and RFC 3986 §3.3 puts ``;params`` in the
    path — so it has to survive. ``dpop_verification`` normalizes both the
    request URL and the proof's ``htu`` through here before comparing them,
    which makes this a binding check: collapsing ``/mcp;v=1`` onto ``/mcp``
    would let a proof minted for one endpoint be accepted at the other,
    defeating the cross-endpoint replay protection the comparison exists for.

    ``internal/urls.py`` uses urlsplit for the same reason, on derivation
    rather than binding.
    """
    parsed, port = _split_dpop_url(url)
    if not parsed.scheme or not parsed.hostname:
        raise InvalidDPoPProofError(f"DPoP URL must be absolute, got {url!r}")

    scheme = parsed.scheme.lower()
    host = host_literal(parsed.hostname.lower())
    include_port = port is not None and not (
        (scheme == "https" and port == 443) or (scheme == "http" and port == 80)
    )
    netloc = f"{host}:{port}" if include_port and port is not None else host
    # DPoP binds to the target URI without query/fragment so the same resource
    # remains stable across equivalent requests.
    path = parsed.path or "/"
    return urlunsplit((scheme, netloc, path, "", ""))


def _public_jwk(jwk_dict: Mapping[str, Any]) -> dict[str, Any]:
    # RFC 7638 thumbprints are computed over the public members only.
    return {k: v for k, v in jwk_dict.items() if k not in {"d", "p", "q", "dp", "dq", "qi", "oth"}}


def jwk_thumbprint(jwk_dict: Mapping[str, Any]) -> str:
    """Compute RFC 7638 SHA-256 thumbprint for a public JWK."""
    public = _public_jwk(jwk_dict)
    kty = str(public.get("kty", ""))
    if kty == "EC":
        members = {
            "crv": public["crv"],
            "kty": public["kty"],
            "x": public["x"],
            "y": public["y"],
        }
    elif kty == "RSA":
        members = {
            "e": public["e"],
            "kty": public["kty"],
            "n": public["n"],
        }
    elif kty == "OKP":
        members = {
            "crv": public["crv"],
            "kty": public["kty"],
            "x": public["x"],
        }
    else:
        raise InvalidDPoPProofError(f"Unsupported DPoP JWK type: {kty!r}")

    canonical = json.dumps(members, separators=(",", ":"), sort_keys=True).encode()
    return _b64url(hashlib.sha256(canonical).digest())


@dataclass(frozen=True)
class DPoPKeyMaterial:
    """Signing key material for DPoP proof generation."""

    private_key: str | bytes
    public_jwk: Mapping[str, Any]
    algorithm: str = "ES256"

    def __post_init__(self) -> None:
        if self.algorithm not in SUPPORTED_DPOP_ALGORITHMS:
            raise ValueError(
                f"DPoP algorithm must be one of {SUPPORTED_DPOP_ALGORITHMS}, got {self.algorithm!r}"
            )

    @classmethod
    def from_pem(
        cls,
        private_key: str | bytes,
        *,
        algorithm: str = "ES256",
    ) -> "DPoPKeyMaterial":
        key = JsonWebKey.import_key(private_key)  # pyright: ignore[reportArgumentType]
        public_jwk = cast("dict[str, Any]", key.as_dict(is_private=False))  # pyright: ignore[reportUnknownMemberType]
        return cls(
            private_key=private_key, public_jwk=MappingProxyType(public_jwk), algorithm=algorithm
        )

    @property
    def thumbprint(self) -> str:
        return jwk_thumbprint(self.public_jwk)


class DPoPReplayStore(Protocol):
    """Atomic replay store used by inbound DPoP proof verification."""

    async def check_and_store(self, jti: str, expires_at: int) -> bool:
        """Return True when the `jti` was stored, False if it already existed."""
        ...


class DPoPRequestContext(Protocol):
    """Per-request DPoP inputs for ``AuthplaneResource.verify``.

    Carries only what RFC 9449 § 7 says is per-request: the proof JWT and
    the binding to this HTTP request (``htm``/``htu``). Replay store,
    accepted proof algorithms, max proof age, and clock skew are
    per-resource configuration via :class:`InboundDPoPOptions`.
    """

    @property
    def method(self) -> str:
        """HTTP method (e.g. ``GET``, ``POST``)."""
        ...

    @property
    def url(self) -> str:
        """Absolute target URL of the request."""
        ...

    @property
    def proof(self) -> str | None:
        """DPoP proof JWT from the ``DPoP`` header, or ``None``."""
        ...


@dataclass(frozen=True)
class InboundDPoPOptions:
    """Per-resource inbound DPoP validation configuration (RFC 9449 §7.1
    + RFC 9728 §2).

    Passing any instance of this dataclass (even default-constructed) to
    ``client.resource(..., inbound_dpop=...)`` is the on/off switch for
    PRM advertising of ``dpop_signing_alg_values_supported`` and
    ``dpop_bound_access_tokens_required``. Omitting ``inbound_dpop`` keeps
    DPoP fields out of PRM entirely.

    Attributes:
        replay_store: Replay detector for accepted proof ``jti`` values.
            When ``None`` (the default), the resource allocates a
            per-resource :class:`InMemoryDPoPReplayStore`. Use a shared
            store (Redis, database) for multi-process deployments.
        max_proof_age_seconds: Maximum proof age accepted from ``iat``.
        clock_skew_seconds: Allowable clock skew for proof time validation.
        allowed_proof_algorithms: Accepted JOSE ``alg`` values for DPoP
            proofs. Also advertised as
            ``dpop_signing_alg_values_supported`` in the PRM. Defaults to
            ``("ES256", "RS256")``.
        required: When ``True``, advertises
            ``dpop_bound_access_tokens_required: true`` in the PRM and
            rejects bearer-only access tokens at verify time. When
            ``False`` (the default), the resource advertises DPoP
            capability while still accepting bearer-only tokens.
    """

    replay_store: "DPoPReplayStore | None" = None
    max_proof_age_seconds: int = 300
    clock_skew_seconds: int = 30
    allowed_proof_algorithms: Sequence[str] | None = None
    required: bool = False

    def __post_init__(self) -> None:
        algs = self.allowed_proof_algorithms
        if algs is None:
            return
        algs_tuple = tuple(algs)
        if not algs_tuple:
            raise ValueError(
                "allowed_proof_algorithms must be non-empty; pass None to accept the default "
                f"{list(SUPPORTED_DPOP_ALGORITHMS)}"
            )
        invalid = [alg for alg in algs_tuple if alg not in SUPPORTED_DPOP_ALGORITHMS]
        if invalid:
            raise ValueError(
                f"Unsupported DPoP proof algorithms {invalid!r}; only "
                f"{list(SUPPORTED_DPOP_ALGORITHMS)} are permitted"
            )
        # Normalize to a tuple so the field is immutable in fact, not just by
        # the frozen-dataclass binding — a caller that retains a reference to
        # the list they passed in cannot mutate it under us.
        object.__setattr__(self, "allowed_proof_algorithms", algs_tuple)


@dataclass
class InMemoryDPoPReplayStore:
    """In-memory DPoP replay store with automatic eviction of expired entries.

    Suitable for single-process deployments. For multi-process or distributed
    deployments, implement the ``DPoPReplayStore`` protocol backed by Redis or
    a shared database.
    """

    _entries: dict[str, int] = field(
        default_factory=lambda: dict[str, int](), init=False, repr=False
    )
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock, init=False, repr=False)

    async def check_and_store(self, jti: str, expires_at: int) -> bool:
        """Return True if jti was stored (first seen), False if already present."""
        async with self._lock:
            now = int(time.time())
            # Evict expired entries on every write to bound memory usage
            self._entries = {k: v for k, v in self._entries.items() if v > now}
            if jti in self._entries:
                return False
            self._entries[jti] = expires_at
            return True


class DPoPNonceStore(Protocol):
    """Store used by outbound DPoP providers for nonce challenges."""

    def get(self, key: str) -> str:
        """Return the nonce for the given origin, or an empty string."""
        ...

    def put(self, key: str, nonce: str) -> None:
        """Store or replace the nonce for the given origin."""
        ...


@dataclass
class InMemoryDPoPNonceStore:
    """Bounded in-memory nonce store for outbound DPoP challenges."""

    max_entries: int = 128
    _entries: OrderedDict[str, str] = field(
        default_factory=lambda: OrderedDict[str, str](), init=False, repr=False
    )

    def __post_init__(self) -> None:
        if self.max_entries <= 0:
            raise ValueError(
                f"DPoP nonce store max_entries must be positive, got {self.max_entries!r}"
            )

    def get(self, key: str) -> str:
        nonce = self._entries.get(key, "")
        if nonce:
            self._entries.move_to_end(key)
        return nonce

    def put(self, key: str, nonce: str) -> None:
        if key in self._entries:
            self._entries.move_to_end(key)
        self._entries[key] = nonce
        while len(self._entries) > self.max_entries:
            self._entries.popitem(last=False)


@dataclass
class DPoPProvider:
    """Generates DPoP proof headers and stores AS/backend nonces per origin."""

    key_material: DPoPKeyMaterial
    proof_ttl_seconds: int = 300
    nonce_store: DPoPNonceStore = field(default_factory=InMemoryDPoPNonceStore, repr=False)

    def __post_init__(self) -> None:
        if self.proof_ttl_seconds <= 0:
            raise ValueError(
                f"DPoP proof_ttl_seconds must be positive, got {self.proof_ttl_seconds!r}"
            )

    def _nonce_key(self, url: str) -> str:
        # Only scheme/host/port are read, so ``;params`` cannot reach the key —
        # but urlsplit is used anyway, so the module has one parse idiom rather
        # than a urlparse whose safety has to be argued case by case.
        parsed, port = _split_dpop_url(url)
        if not parsed.scheme or not parsed.hostname:
            raise InvalidDPoPProofError(f"DPoP URL must be absolute, got {url!r}")
        if port is None:
            port = 443 if parsed.scheme.lower() == "https" else 80
        # Bracketed for the same reason as the htu above: this key is an origin
        # string, and an unbracketed IPv6 literal makes two different origins
        # collide as readily as it makes one unparseable.
        return f"{parsed.scheme.lower()}://{host_literal(parsed.hostname.lower())}:{port}"

    def note_nonce(self, url: str, nonce: str) -> None:
        """Store a server-provided DPoP-Nonce for the given URL's origin."""
        # Nonces are tracked per origin because ASes and downstream APIs can
        # challenge independently.
        self.nonce_store.put(self._nonce_key(url), nonce)

    def current_nonce(self, url: str) -> str:
        """Return the last-seen DPoP-Nonce for the given URL's origin."""
        return self.nonce_store.get(self._nonce_key(url))

    def build_proof(
        self,
        method: str,
        url: str,
        *,
        access_token: str = "",
        nonce: str = "",
        issued_at: int | None = None,
        jti: str | None = None,
    ) -> str:
        """Build a signed DPoP proof JWT for the given HTTP method and URL (RFC 9449 Section 4)."""
        iat = issued_at if issued_at is not None else int(time.time())
        # `ath` is only included when the proof accompanies an access token
        # presentation, such as inbound resource requests.
        claims: dict[str, Any] = {
            "jti": jti or str(uuid.uuid4()),
            "htm": method.upper(),
            "htu": normalize_dpop_htu(url),
            "iat": iat,
            "exp": iat + self.proof_ttl_seconds,
        }
        if nonce:
            claims["nonce"] = nonce
        if access_token:
            claims["ath"] = _b64url(hashlib.sha256(access_token.encode()).digest())

        header = {
            "typ": "dpop+jwt",
            "alg": self.key_material.algorithm,
            "jwk": dict(self.key_material.public_jwk),
        }
        token = jwt.encode(header, claims, self.key_material.private_key)  # pyright: ignore[reportUnknownMemberType]
        return token.decode("utf-8")

    def build_headers(
        self,
        method: str,
        url: str,
        *,
        access_token: str = "",
    ) -> dict[str, str]:
        proof = self.build_proof(
            method,
            url,
            access_token=access_token,
            nonce=self.current_nonce(url),
        )
        return {"DPoP": proof}


# Re-export inbound verification from dpop_verification module
