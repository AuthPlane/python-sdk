"""Authplane JWT verifier — validates OAuth 2.1 access tokens."""

from .claims import VerifiedClaims
from .verifier import AuthplaneResource

__all__ = ["AuthplaneResource", "VerifiedClaims"]
