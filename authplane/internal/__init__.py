"""Internal caching infrastructure — document cache, metadata, fetcher."""

from .cache_headers import parse_expires_at
from .document_cache import (
    DocumentCache,
    DocumentFetcherCallable,
    DocumentSourceResolver,
    JWKSCache,
)
from .document_fetcher import DocumentFetcher
from .fetch_result import FetchResult
from .metadata import MetadataCache
from .urls import (
    build_metadata_url,
    build_prm_url,
    validate_issuer_identifier,
    validate_prm_resource_identifier,
    validate_resource_metadata_url,
)

__all__ = [
    "DocumentCache",
    "DocumentFetcher",
    "DocumentFetcherCallable",
    "DocumentSourceResolver",
    "FetchResult",
    "JWKSCache",
    "MetadataCache",
    "build_metadata_url",
    "build_prm_url",
    "parse_expires_at",
    "validate_issuer_identifier",
    "validate_prm_resource_identifier",
    "validate_resource_metadata_url",
]
