"""Verified immutable claims for validated JWT access tokens."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, cast

from ..errors import InsufficientScopeError

if TYPE_CHECKING:
    from ..dpop_verification import VerifiedDPoPProof

_MISSING = object()


def freeze_value(value: Any) -> Any:
    """Recursively freeze nested values into immutable containers."""
    if isinstance(value, dict):
        # Verified claims are returned to application code, so nested structures
        # must be frozen too; otherwise callers could mutate auth-relevant data
        # after signature validation.
        typed = cast("dict[str, Any]", value)
        return MappingProxyType({str(k): freeze_value(v) for k, v in typed.items()})
    if isinstance(value, list):
        typed_list = cast("list[Any]", value)
        return tuple(freeze_value(v) for v in typed_list)
    return value


@dataclass(frozen=True)
class VerifiedClaims:
    """Immutable container for validated JWT claims."""

    sub: str
    client_id: str
    scopes: tuple[str, ...]
    issuer: str
    audience: tuple[str, ...]
    expires_at: int
    issued_at: int
    jti: str
    kid: str
    raw: Mapping[str, Any]
    agent_id: str = ""
    agent_chain: tuple[str, ...] = ()
    not_before: int = 0
    dpop_proof: VerifiedDPoPProof | None = field(default=None, compare=False)

    def has_scope(self, scope: str) -> bool:
        """Return True when the validated token carries the given scope."""
        return scope in self.scopes

    def require_scope(self, scope: str) -> None:
        """Raise InsufficientScopeError when the validated token lacks the scope."""
        if not self.has_scope(scope):
            raise InsufficientScopeError(
                f"Token missing required scope '{scope}'. Token has scopes: {list(self.scopes)}"
            )

    def has_claim(self, key: str, value: Any = _MISSING) -> bool:
        """Check whether a claim exists and optionally matches an expected value."""
        if key not in self.raw:
            return False
        if value is _MISSING:
            return True
        return self.raw[key] == value

    @property
    def act(self) -> Mapping[str, Any] | None:
        """Return the ``act`` (actor) claim, or None if absent (RFC 8693 Section 4.1)."""
        v: object = self.raw.get("act")
        if not isinstance(v, Mapping):
            return None
        return cast("Mapping[str, Any]", v)

    @property
    def may_act(self) -> Mapping[str, Any] | None:
        """Return the ``may_act`` claim, or None if absent (RFC 8693 Section 4.4)."""
        v: object = self.raw.get("may_act")
        if not isinstance(v, Mapping):
            return None
        return cast("Mapping[str, Any]", v)
