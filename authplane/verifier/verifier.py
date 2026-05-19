"""AuthplaneResource — JWT validation scoped to a resource."""

import logging
import time
from collections.abc import Awaitable, Callable, Mapping
from typing import TYPE_CHECKING, Any, cast

from authlib.jose import JsonWebKey, JsonWebToken
from authlib.jose.errors import (
    BadSignatureError,
    ExpiredTokenError,
    InvalidClaimError,
    InvalidTokenError,
    MissingClaimError,
)

from ..dpop import (
    SUPPORTED_DPOP_ALGORITHMS,
    DPoPReplayStore,
    DPoPRequestContext,
    InboundDPoPOptions,
    InMemoryDPoPReplayStore,
)
from ..dpop_verification import VerifiedDPoPProof, verify_dpop_proof
from ..errors import (
    AuthplaneError,
    DPoPBindingMismatchError,
    DPoPNotSupportedError,
    DPoPProofMissingError,
    InvalidClaimsError,
    InvalidSignatureError,
    JWKSFetchError,
    TokenExpiredError,
    TokenMissingError,
    TokenRevokedError,
    VerifierRuntimeError,
)
from ..internal.jwt import decode_jwt_header
from ..internal.urls import build_prm_url
from ..oauth.prm import build_prm
from ..oauth.types import IntrospectionRevocation
from .claims import VerifiedClaims, freeze_value

if TYPE_CHECKING:
    from ..client import AuthplaneClient

logger = logging.getLogger(__name__)

RevocationChecker = Callable[[VerifiedClaims, str], Awaitable[bool]]
_ALLOWED_ALGORITHMS = ("RS256", "ES256")


class AuthplaneResource:
    """Verifies RFC 9068-style JWT access tokens."""

    def __init__(
        self,
        client: "AuthplaneClient",
        resource: str,
        scopes: list[str],
        allowed_algorithms: list[str],
        clock_skew_seconds: int = 30,
        revocation_checker: RevocationChecker | IntrospectionRevocation | None = None,
        fail_closed: bool = False,
        inbound_dpop: InboundDPoPOptions | None = None,
    ) -> None:
        invalid = [alg for alg in allowed_algorithms if alg not in _ALLOWED_ALGORITHMS]
        if invalid:
            raise ValueError(
                f"Unsupported algorithms {invalid!r}; only {list(_ALLOWED_ALGORITHMS)} are permitted"
            )

        self._client = client
        self._resource = resource
        self._scopes = tuple(scopes)
        self._allowed_algorithms = allowed_algorithms
        self._clock_skew_seconds = clock_skew_seconds
        self._fail_closed = fail_closed
        self._jwt = JsonWebToken(self._allowed_algorithms)

        # Per-resource DPoP policy (RFC 9728 §2 + RFC 9449 §7.1).  Tuning
        # lives at-rest so a missing per-request context cannot silently
        # bypass sender-binding.  Presence of `inbound_dpop` is the on/off
        # switch for advertising DPoP support in PRM; `required` further
        # promotes that to a hard requirement.
        self._inbound_dpop_configured = inbound_dpop is not None
        opts = inbound_dpop if inbound_dpop is not None else InboundDPoPOptions()
        self._dpop_required = opts.required
        algs = opts.allowed_proof_algorithms
        self._dpop_allowed_proof_algorithms: tuple[str, ...] = tuple(
            algs if algs is not None else SUPPORTED_DPOP_ALGORITHMS
        )
        self._dpop_max_proof_age_seconds = opts.max_proof_age_seconds
        self._dpop_clock_skew_seconds = opts.clock_skew_seconds
        # Allocate a replay store only when the resource has opted into DPoP.
        # In Mode 3 (inbound_dpop is None) the verify path rejects DPoP signals
        # before reaching proof verification, so no replay store is needed.
        self._dpop_replay_store: DPoPReplayStore | None = None
        if inbound_dpop is not None:
            self._dpop_replay_store = opts.replay_store or InMemoryDPoPReplayStore()

        if isinstance(revocation_checker, IntrospectionRevocation):
            self._revocation_checker: RevocationChecker | None = self._introspection_checker
        else:
            self._revocation_checker = revocation_checker

    @property
    def scopes(self) -> tuple[str, ...]:
        """Return the scopes configured for this verifier."""
        return self._scopes

    @property
    def resource(self) -> str:
        """Return the resource URI this verifier is scoped to."""
        return self._resource

    async def verify(
        self,
        token: str,
        *,
        dpop_request: DPoPRequestContext | None = None,
    ) -> VerifiedClaims:
        """Validate a JWT access token for this resource.

        When the access token carries a ``cnf.jkt`` binding the caller must
        pass a *dpop_request* with the proof JWT plus the HTTP method and
        URL of the request, so the verifier can enforce sender-constraint
        per RFC 9449 § 7.  The replay store, accepted proof algorithms,
        max proof age, and clock skew are per-resource configuration set
        on :class:`AuthplaneClient.resource`.
        """
        if not token or not token.strip():
            raise TokenMissingError("authplane: no token provided")

        start_time = time.time()
        try:
            claims = await self._verify_token_core(token)
            dpop_verified = await self._maybe_verify_dpop(claims, token, dpop_request)
        except AuthplaneError:
            raise
        except Exception as exc:
            raise VerifierRuntimeError(f"authplane: verifier runtime failure: {exc}") from exc

        if dpop_verified is not None:
            claims = VerifiedClaims(
                sub=claims.sub,
                client_id=claims.client_id,
                scopes=claims.scopes,
                issuer=claims.issuer,
                audience=claims.audience,
                expires_at=claims.expires_at,
                issued_at=claims.issued_at,
                jti=claims.jti,
                kid=claims.kid,
                raw=claims.raw,
                agent_id=claims.agent_id,
                agent_chain=claims.agent_chain,
                not_before=claims.not_before,
                dpop_proof=dpop_verified,
            )

        if self._revocation_checker is not None:
            try:
                is_revoked = await self._revocation_checker(claims, token)
            except Exception as exc:
                if self._fail_closed:
                    raise TokenRevokedError(
                        f"Token '{claims.jti}' rejected: revocation check failed: {exc}"
                    ) from exc
                logger.warning(
                    "Revocation check failed (fail-open): token accepted despite error",
                    extra={"jti": claims.jti, "error": str(exc)},
                )
                is_revoked = False
            if is_revoked:
                raise TokenRevokedError(f"Token '{claims.jti}' is revoked")

        duration_ms = int((time.time() - start_time) * 1000)
        logger.debug(
            "Token validated successfully",
            extra={
                "sub": claims.sub,
                "client_id": claims.client_id,
                "issuer": claims.issuer,
                "dpop_bound": dpop_verified is not None,
                "duration_ms": duration_ms,
            },
        )
        return claims

    async def _maybe_verify_dpop(
        self,
        claims: VerifiedClaims,
        token: str,
        dpop_request: DPoPRequestContext | None,
    ) -> VerifiedDPoPProof | None:
        """Verify DPoP binding according to the resource's enforcement mode.

        Three modes (set via ``InboundDPoPOptions`` on ``client.resource``):

        * **Required** (``inbound_dpop.required=True``) — every access token
          must be DPoP-bound; bearer-only tokens are rejected.
        * **Supported** (``inbound_dpop`` configured, ``required=False``) —
          DPoP-bound tokens are validated end-to-end; bearer-only tokens
          are accepted; a proof presented with a bearer-only token is a
          malformed request and rejected.
        * **Not configured** (``inbound_dpop=None``) — any DPoP signal in
          the request is rejected (RFC 9449 §6 scopes proof validation to
          DPoP-supporting resources). Plain bearer tokens are accepted.
        """
        cnf_raw = claims.raw.get("cnf")
        token_is_bound = isinstance(cnf_raw, Mapping)
        proof_present = dpop_request is not None and bool(dpop_request.proof)

        # Mode 3 — resource has not opted into DPoP. Reject any DPoP signal
        # upfront rather than fall back to bearer (which would silently drop
        # sender-binding) or apply ad-hoc defaults that were never advertised
        # in PRM.
        if not self._inbound_dpop_configured:
            if token_is_bound or proof_present:
                raise DPoPNotSupportedError(
                    "Resource is not configured for DPoP. Pass "
                    "`inbound_dpop=InboundDPoPOptions(...)` to "
                    "client.resource(...) to enable DPoP validation."
                )
            return None

        # Modes 1 & 2 — resource supports DPoP (and possibly requires it).
        if not token_is_bound:
            if self._dpop_required:
                raise DPoPBindingMismatchError(
                    "Resource requires DPoP-bound access tokens but the "
                    "presented token has no `cnf.jkt`"
                )
            if proof_present:
                # Proof attached to a bearer-only token is structurally
                # malformed: the proof's `ath` claim has nothing to bind to.
                raise DPoPBindingMismatchError(
                    "DPoP proof presented but the access token is not "
                    "DPoP-bound (`cnf.jkt` missing); proof has nothing to "
                    "bind to. Send the request without the DPoP header, or "
                    "use a DPoP-bound access token."
                )
            return None  # plain bearer accepted (Mode 2)

        cnf = cast("Mapping[str, Any]", cnf_raw)
        jkt = cnf.get("jkt")
        if not jkt:
            # cnf present but no jkt — structurally deficient (RFC 9449 §6).
            raise InvalidClaimsError(
                "Access token has 'cnf' claim but missing 'cnf.jkt' — cannot verify DPoP binding"
            )

        if dpop_request is None:
            raise DPoPBindingMismatchError(
                "Access token is DPoP-bound (`cnf.jkt` present) but no DPoP request context was provided"
            )
        if not dpop_request.proof:
            raise DPoPProofMissingError("Access token is DPoP-bound but no DPoP proof was supplied")

        # Replay store is non-None whenever inbound_dpop was configured; the
        # Mode 3 branch above returns before we reach here.
        assert self._dpop_replay_store is not None
        return await verify_dpop_proof(
            dpop_request.proof,
            method=dpop_request.method,
            url=dpop_request.url,
            replay_store=self._dpop_replay_store,
            access_token=token,
            expected_jkt=str(jkt),
            max_age_seconds=self._dpop_max_proof_age_seconds,
            clock_skew_seconds=self._dpop_clock_skew_seconds,
            allowed_algorithms=self._dpop_allowed_proof_algorithms,
        )

    async def _verify_token_core(self, token: str) -> VerifiedClaims:
        jwks_cache = self._client.jwks_cache
        if not jwks_cache:
            raise JWKSFetchError("authplane: no JWKS cache available")

        header = self._decode_header(token)
        kid = str(header.get("kid", "")).strip()
        alg = str(header.get("alg", "")).strip()
        if not kid:
            raise InvalidClaimsError("Token header missing 'kid' field")
        if not alg:
            raise InvalidClaimsError("Token header missing 'alg' field")
        if alg not in self._allowed_algorithms:
            raise InvalidClaimsError(
                f"Token algorithm '{alg}' is not in the allowed list: {self._allowed_algorithms}"
            )
        # RFC 9068 access tokens are explicitly typed. Rejecting other JWT types
        # prevents accidentally accepting ID tokens or generic JWTs here.
        if header.get("typ") != "at+jwt":
            raise InvalidClaimsError(f"Token type must be 'at+jwt', got '{header.get('typ')}'")

        key_dict = await jwks_cache.get_key_by_kid(kid, algorithm=alg)
        if key_dict is None:
            logger.info("Kid not found in JWKS, forcing refresh", extra={"kid": kid})
            # A single forced refresh covers normal key rotation without letting
            # an attacker turn every unknown kid into repeated network churn.
            key_dict = await jwks_cache.get_key_by_kid(kid, force_refresh=True, algorithm=alg)
            if key_dict is None:
                raise InvalidSignatureError(f"Token kid '{kid}' not found in JWKS after refresh")

        claims_options = {
            "iss": {"essential": True, "value": self._client.issuer},
            "aud": {"essential": True, "value": self._resource},
            "sub": {"essential": True},
            "client_id": {"essential": True},
            "exp": {"essential": True},
            "nbf": {"essential": False},
            "iat": {"essential": True},
            "jti": {"essential": True},
        }

        try:
            key = JsonWebKey.import_key(key_dict)
            claims_obj = self._jwt.decode(token, key, claims_options=claims_options)  # pyright: ignore[reportUnknownMemberType, reportArgumentType]
            claims = dict(claims_obj)
            now = time.time()
            iat = int(claims.get("iat", 0))
            # `validate(leeway=...)` handles expiry, but we keep the explicit
            # future-iat guard because "issued in the future" is a clearer
            # operator signal than a generic invalid-claims error.
            if iat > now + self._clock_skew_seconds:
                raise InvalidClaimsError(
                    f"Token 'iat' claim is in the future (iat={iat}, now={int(now)}, leeway={self._clock_skew_seconds}s)"
                )
            claims_obj.validate(leeway=self._clock_skew_seconds)  # pyright: ignore[reportUnknownMemberType]
        except ExpiredTokenError as exc:
            raise TokenExpiredError(f"Token has expired: {exc}") from exc
        except BadSignatureError as exc:
            raise InvalidSignatureError(f"Token signature verification failed: {exc}") from exc
        except (InvalidClaimError, MissingClaimError, InvalidTokenError) as exc:
            claim_name = getattr(exc, "claim_name", "") or ""
            if not claim_name:
                msg = str(exc).lower()
                if "not valid yet" in msg:
                    claim_name = "nbf"
                elif "expired" in msg:
                    claim_name = "exp"
            if claim_name:
                raise InvalidClaimsError(
                    f"Token claims validation failed ({claim_name}): {exc}"
                ) from exc
            raise InvalidClaimsError(f"Token claims validation failed: {exc}") from exc
        except AuthplaneError:
            raise
        except Exception as exc:
            raise VerifierRuntimeError(
                f"authplane: token verification runtime failure: {exc}"
            ) from exc

        scope_str = str(claims.get("scope", ""))
        scopes = tuple(scope_str.split()) if scope_str else ()
        audience = claims["aud"]
        frozen_claims = freeze_value(claims)

        # Agent-specific claims
        agent_id = str(claims["agent_id"]) if "agent_id" in claims else ""
        raw_chain = claims.get("agent_chain")
        agent_chain = (
            tuple(str(x) for x in cast("list[Any]", raw_chain))
            if isinstance(raw_chain, list)
            else ()
        )

        return VerifiedClaims(
            sub=str(claims["sub"]),
            client_id=str(claims["client_id"]),
            scopes=scopes,
            issuer=str(claims["iss"]),
            audience=(audience,) if isinstance(audience, str) else tuple(audience),
            expires_at=int(claims["exp"]),
            issued_at=int(claims["iat"]),
            jti=str(claims["jti"]),
            kid=kid,
            raw=frozen_claims,
            agent_id=agent_id,
            agent_chain=agent_chain,
            not_before=int(claims.get("nbf", 0)),
        )

    def _decode_header(self, token: str) -> dict[str, Any]:
        try:
            raw_header = decode_jwt_header(token)
        except Exception as exc:
            raise InvalidSignatureError(f"Failed to decode token header: {exc}") from exc
        return raw_header

    async def _introspection_checker(self, claims: VerifiedClaims, raw_token: str) -> bool:
        """Return True when introspection marks the token inactive.

        Exceptions propagate to the verifier, which applies the fail-open/closed
        policy configured via the ``fail_closed`` parameter.
        """
        result = await self._client.introspect(raw_token)
        return not result.active

    def prm_response(self) -> dict[str, object]:
        """Build protected resource metadata for this verifier scope."""
        # RFC 9728 §2: advertise DPoP policy when the resource has an
        # InboundDPoPOptions configured. The presence of the bundle is the
        # on/off switch — the algs always carry a meaningful default.
        return build_prm(
            self._client.issuer,
            self._resource,
            self._scopes,
            dpop_algs=self._dpop_allowed_proof_algorithms
            if self._inbound_dpop_configured
            else None,
            dpop_required=self._dpop_required,
        )

    def prm_url(self) -> str:
        """Return the RFC 9728 well-known PRM discovery URL for this resource.

        Symmetric with :meth:`prm_response`: this is the URL clients can fetch
        to retrieve that document, suitable for the ``resource_metadata``
        challenge parameter (:func:`authplane.www_authenticate`,
        :func:`authplane.response_headers_for`).
        """
        return build_prm_url(self._resource)
