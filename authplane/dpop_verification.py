"""Inbound DPoP proof verification (RFC 9449 Section 4.3).

Separated from dpop.py to keep file sizes manageable. The outbound
proof generation (DPoPProvider) lives in dpop.py.
"""

import hashlib
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, cast

from authlib.jose import JsonWebKey, jwt
from authlib.jose.errors import JoseError

from .dpop import (
    SUPPORTED_DPOP_ALGORITHMS,
    DPoPReplayStore,
    _b64url,  # pyright: ignore[reportPrivateUsage]
    _decode_jwt_header,  # pyright: ignore[reportPrivateUsage]
    jwk_thumbprint,
    normalize_dpop_htu,
)
from .errors import (
    DPoPBindingMismatchError,
    DPoPProofMissingError,
    DPoPReplayDetectedError,
    InvalidDPoPProofError,
)


@dataclass(frozen=True)
class VerifiedDPoPProof:
    """Validated DPoP proof claims."""

    jti: str
    htm: str
    htu: str
    iat: int
    key_thumbprint: str
    raw: Mapping[str, Any]


def _decode_dpop_header_and_key(
    proof: str,
    *,
    allowed_algorithms: Sequence[str],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Decode and validate DPoP proof header; return (claims, public_jwk)."""
    if not proof or not proof.strip():
        raise DPoPProofMissingError("authplane: DPoP proof is required")

    try:
        header = _decode_jwt_header(proof)
    except Exception as exc:  # pragma: no cover - authlib type shape differs
        raise InvalidDPoPProofError(f"Failed to decode DPoP proof header: {exc}") from exc

    alg = str(header.get("alg", ""))
    if alg not in allowed_algorithms:
        raise InvalidDPoPProofError(
            f"Unsupported DPoP algorithm {alg!r}; expected one of {tuple(allowed_algorithms)}"
        )
    if header.get("typ") != "dpop+jwt":
        raise InvalidDPoPProofError("DPoP proof header `typ` must be 'dpop+jwt'")

    header_jwk = header.get("jwk")
    if not isinstance(header_jwk, dict):
        raise InvalidDPoPProofError("DPoP proof header missing public `jwk`")
    # Proof headers must carry the public key only; accepting private members
    # would make malformed or dangerous proofs look valid.
    if "d" in header_jwk:
        raise InvalidDPoPProofError("DPoP proof header JWK must not include private key material")
    public_jwk = cast("dict[str, Any]", header_jwk)

    try:
        key = JsonWebKey.import_key(public_jwk)  # pyright: ignore[reportUnknownArgumentType]
        claims_obj = jwt.decode(proof, key)  # pyright: ignore[reportUnknownMemberType, reportArgumentType]
        claims = dict(claims_obj)
    except JoseError as exc:
        raise InvalidDPoPProofError(f"DPoP proof signature verification failed: {exc}") from exc
    except Exception as exc:
        raise InvalidDPoPProofError(f"Failed to decode DPoP proof: {exc}") from exc

    return claims, public_jwk


def _validate_dpop_temporal(
    claims: dict[str, Any],
    iat: int,
    *,
    max_age_seconds: int,
    clock_skew_seconds: int,
) -> None:
    """Check iat/exp temporal bounds on a DPoP proof."""
    now = int(time.time())
    if iat > now + clock_skew_seconds:
        raise InvalidDPoPProofError("DPoP proof `iat` is in the future")
    if now - iat > max_age_seconds + clock_skew_seconds:
        raise InvalidDPoPProofError("DPoP proof is too old")
    if "exp" in claims:
        try:
            exp = int(claims["exp"])
        except (TypeError, ValueError) as exc:
            raise InvalidDPoPProofError(f"DPoP proof `exp` must be an integer: {exc}") from exc
        if exp < now - clock_skew_seconds:
            raise InvalidDPoPProofError("DPoP proof has expired")


async def verify_dpop_proof(
    proof: str,
    *,
    method: str,
    url: str,
    replay_store: DPoPReplayStore,
    access_token: str = "",
    expected_jkt: str = "",
    expected_nonce: str = "",
    max_age_seconds: int = 300,
    clock_skew_seconds: int = 30,
    allowed_algorithms: Sequence[str] = SUPPORTED_DPOP_ALGORITHMS,
) -> VerifiedDPoPProof:
    """Validate an inbound DPoP proof JWT (RFC 9449 Section 4.3).

    Checks header structure, algorithm, signature, replay, binding, and
    temporal validity. Returns a VerifiedDPoPProof on success.
    """
    claims, public_jwk = _decode_dpop_header_and_key(proof, allowed_algorithms=allowed_algorithms)

    try:
        jti = str(claims["jti"])
        htm = str(claims["htm"])
        htu = str(claims["htu"])
        iat = int(claims["iat"])
    except (KeyError, TypeError, ValueError) as exc:
        raise InvalidDPoPProofError(f"DPoP proof missing required claims: {exc}") from exc

    normalized_url = normalize_dpop_htu(url)
    # RFC 9449 §4.3: normalize BOTH the request URL and the proof htu
    # before comparison (scheme/host case, default port, strip query/fragment).
    normalized_htu = normalize_dpop_htu(htu)
    # Method/URI binding is the core anti-replay guarantee of DPoP: the proof
    # must be specific to the exact HTTP operation being performed.
    if htm != method.upper():
        raise InvalidDPoPProofError(
            f"DPoP proof method mismatch: expected {method.upper()!r}, got {htm!r}"
        )
    if normalized_htu != normalized_url:
        raise InvalidDPoPProofError(
            f"DPoP proof URL mismatch: expected {normalized_url!r}, got {htu!r}"
        )

    if expected_nonce:
        actual_nonce = str(claims.get("nonce", ""))
        if actual_nonce != expected_nonce:
            raise InvalidDPoPProofError(
                f"DPoP proof nonce mismatch: expected {expected_nonce!r}, got {actual_nonce!r}"
            )

    _validate_dpop_temporal(
        claims, iat, max_age_seconds=max_age_seconds, clock_skew_seconds=clock_skew_seconds
    )

    if access_token:
        expected_ath = _b64url(hashlib.sha256(access_token.encode()).digest())
        actual_ath = str(claims.get("ath", ""))
        if actual_ath != expected_ath:
            raise InvalidDPoPProofError("DPoP proof `ath` does not match the access token")
        if not expected_jkt:
            raise DPoPBindingMismatchError(
                "DPoP proof validation requires expected_jkt when an access token is provided"
            )

    thumbprint = jwk_thumbprint(public_jwk)
    if expected_jkt and thumbprint != expected_jkt:
        raise DPoPBindingMismatchError("DPoP proof key does not match the access token `cnf.jkt`")

    # Replay protection is delegated to the caller so MCP servers can plug in
    # Redis, database, or in-memory coordination appropriate to their topology.
    stored = await replay_store.check_and_store(jti, iat + max_age_seconds + clock_skew_seconds)
    if not stored:
        raise DPoPReplayDetectedError(f"DPoP proof replay detected for jti {jti!r}")

    return VerifiedDPoPProof(
        jti=jti,
        htm=htm,
        htu=htu,
        iat=iat,
        key_thumbprint=thumbprint,
        raw=MappingProxyType(claims),
    )
