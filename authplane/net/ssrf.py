"""SSRF-safe HTTP utilities for Authplane SDK.

This module provides SSRF-protected HTTP fetching with:
- DNS resolution and IP validation before requests
- DNS pinning to prevent rebinding TOCTOU attacks
- Configurable opt-in/opt-out for different deployment scenarios
"""

import json
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlencode, urlparse

import httpx

from .ip_validation import SSRFError, format_ip_for_url, is_ip_allowed, resolve_hostname


@dataclass
class ValidatedURL:
    """A URL that has been validated for SSRF with resolved IPs."""

    original_url: str
    hostname: str
    port: int
    path: str
    resolved_ips: list[str]


@dataclass(frozen=True)
class HttpResponse:
    """Raw HTTP response from an SSRF-safe fetch.

    Carries the parsed JSON body and raw response headers so that
    callers (e.g. DocumentFetcher) can extract cache metadata.
    """

    body: dict[str, Any]
    headers: dict[str, str]
    status_code: int


async def validate_url(
    url: str,
    *,
    allow_http: bool = False,
    allow_localhost: bool = False,
    allow_private_networks: bool = False,
) -> ValidatedURL:
    """Validate URL for SSRF and resolve to IPs.

    Args:
        url: URL to validate
        allow_http: If True, allow HTTP in addition to HTTPS (default False)
        allow_localhost: If True, allow localhost addresses (default False)
        allow_private_networks: If True, allow private network addresses (default False)

    Returns:
        ValidatedURL with resolved IPs

    Raises:
        SSRFError: If URL is invalid or resolves to blocked IPs
    """
    try:
        parsed = urlparse(url)
    except (ValueError, AttributeError) as e:
        raise SSRFError(f"Invalid URL: {e}") from e

    # Protocol validation
    if allow_http:
        if parsed.scheme not in ("http", "https"):
            raise SSRFError(f"URL must use HTTP or HTTPS, got: {parsed.scheme}")
    else:
        if parsed.scheme != "https":
            raise SSRFError(f"URL must use HTTPS, got: {parsed.scheme}")

    if not parsed.netloc:
        raise SSRFError("URL must have a host")

    hostname = parsed.hostname or parsed.netloc
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    # Resolve and validate IPs
    resolved_ips = await resolve_hostname(hostname, port)

    blocked = [
        ip
        for ip in resolved_ips
        if not is_ip_allowed(
            ip,
            allow_localhost=allow_localhost,
            allow_private_networks=allow_private_networks,
        )
    ]
    if blocked:
        raise SSRFError(
            f"URL resolves to blocked IP address(es): {blocked}. "
            f"Private, loopback, link-local, and reserved IPs are not allowed."
        )

    return ValidatedURL(
        original_url=url,
        hostname=hostname,
        port=port,
        path=parsed.path + ("?" + parsed.query if parsed.query else ""),
        resolved_ips=resolved_ips,
    )


async def _execute_pinned_request(
    pinned_url: str,
    *,
    method: str,
    hostname: str,
    form_data: dict[str, str] | list[tuple[str, str]] | None = None,
    json_data: dict[str, Any] | None = None,
    extra_headers: dict[str, str] | None = None,
    max_size: int,
    timeout: float,
) -> HttpResponse:
    """Execute a single DNS-pinned HTTP request and return the parsed response."""
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(timeout),
        follow_redirects=False,
        verify=True,
    ) as client:
        headers: dict[str, str] = {}
        if extra_headers:
            headers.update(extra_headers)
        headers["Host"] = hostname
        headers["Accept"] = "application/json"

        stream_kwargs: dict[str, Any] = {
            "headers": headers,
            "extensions": {"sni_hostname": hostname},
        }
        if form_data is not None:
            headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
            stream_kwargs["content"] = urlencode(form_data, doseq=True)
        elif json_data is not None:
            stream_kwargs["json"] = json_data

        async with client.stream(method, pinned_url, **stream_kwargs) as response:
            content_length = response.headers.get("content-length")
            if content_length:
                try:
                    size = int(content_length)
                    if size > max_size:
                        raise SSRFError(f"Response too large: {size} bytes (max {max_size})")
                except ValueError:
                    pass

            content = bytearray()
            async for chunk in response.aiter_bytes():
                content.extend(chunk)
                if len(content) > max_size:
                    raise SSRFError(
                        f"Response too large: streaming exceeded {max_size} bytes limit"
                    )

            # Return the response body for any status code rather than
            # raising on 4xx/5xx. OAuth error responses carry the fields the
            # SDK needs (`error`, `error_description`, `consent_url`,
            # `service_id`, `cause`) in the body — raising here would
            # discard them since the streamed body is not preserved on
            # ``HTTPStatusError.response`` after the stream context exits.
            # Callers that want a hard failure on 4xx/5xx should check
            # ``HttpResponse.status_code`` themselves.
            #
            # On 2xx, malformed JSON is still a hard failure so per-IP
            # retry can try the next address. On 4xx/5xx, malformed JSON
            # falls back to an empty body so the caller can still surface
            # the status code.
            body: dict[str, Any] = {}
            if 200 <= response.status_code < 300:
                if content:
                    body = json.loads(content)
            else:
                if content:
                    try:
                        body = json.loads(content)
                    except json.JSONDecodeError:
                        body = {}
            return HttpResponse(
                body=body,
                headers=dict(response.headers),
                status_code=response.status_code,
            )


async def _ssrf_safe_request(
    url: str,
    *,
    method: str,
    allow_http: bool = False,
    allow_localhost: bool = False,
    allow_private_networks: bool = False,
    form_data: dict[str, str] | list[tuple[str, str]] | None = None,
    json_data: dict[str, Any] | None = None,
    extra_headers: dict[str, str] | None = None,
    max_size: int,
    timeout: float,
) -> HttpResponse:
    """Validate URL for SSRF, then execute a DNS-pinned HTTP request.

    Shared implementation used by both ssrf_safe_get (GET) and ssrf_safe_post (POST).
    Calls validate_url first, then iterates over all resolved IPs so that if one
    fails the next is tried.

    Args:
        url: URL to request.
        method: HTTP method ("GET" or "POST").
        allow_http: If True, allow HTTP in addition to HTTPS (default False).
        allow_localhost: If True, allow loopback addresses (default False).
        allow_private_networks: If True, allow private network addresses (default False).
        form_data: Form-encoded body fields (POST only).
        max_size: Maximum response size in bytes.
        timeout: Request timeout in seconds.

    Returns:
        HttpResponse with parsed JSON body and raw response headers.

    Raises:
        SSRFError: If SSRF validation fails or the response exceeds max_size.
        httpx.HTTPError: If transport fails (timeout, connection error, etc.).
            Non-2xx HTTP responses are returned as ``HttpResponse`` with the
            status code intact, not raised; callers inspect ``status_code``.
    """
    validated = await validate_url(
        url,
        allow_http=allow_http,
        allow_localhost=allow_localhost,
        allow_private_networks=allow_private_networks,
    )

    last_error: Exception | None = None

    for pinned_ip in validated.resolved_ips:
        scheme = "https" if url.startswith("https://") else "http"
        pinned_url = f"{scheme}://{format_ip_for_url(pinned_ip)}:{validated.port}{validated.path}"

        try:
            return await _execute_pinned_request(
                pinned_url,
                method=method,
                hostname=validated.hostname,
                form_data=form_data,
                json_data=json_data,
                extra_headers=extra_headers,
                max_size=max_size,
                timeout=timeout,
            )
        except SSRFError:
            # SSRFError should propagate immediately (size limits, etc.)
            raise
        except (json.JSONDecodeError, httpx.TimeoutException, httpx.RequestError) as e:
            last_error = e
            continue

    if last_error is not None:
        raise last_error

    raise SSRFError(f"No resolved IPs succeeded for {url}")


async def ssrf_safe_get(
    url: str,
    *,
    allow_http: bool = False,
    allow_localhost: bool = False,
    allow_private_networks: bool = False,
    max_size: int = 65536,
    timeout: float = 10.0,
) -> HttpResponse:
    """Fetch JSON from URL with comprehensive SSRF protection and DNS pinning.

    Security measures:
    1. HTTPS-only by default (configurable via allow_http)
    2. DNS resolution with IP validation
    3. Connects to validated IP directly (DNS pinning prevents rebinding)
    4. Response size limit (enforced during streaming)
    5. Redirects disabled
    6. Timeout enforcement
    7. Cloud metadata endpoints (169.254.x) ALWAYS blocked

    Args:
        url: URL to fetch
        allow_http: If True, allow HTTP in addition to HTTPS (default False)
        allow_localhost: If True, allow localhost addresses (default False)
        allow_private_networks: If True, allow private network addresses (default False)
        max_size: Maximum response size in bytes (default 64KB)
        timeout: Timeout in seconds (default 10s)

    Returns:
        HttpResponse with parsed JSON body and raw headers

    Raises:
        SSRFError: If SSRF validation fails or size limit exceeded
        httpx.HTTPError: If transport fails (timeout, connection error, etc.).
            Non-2xx responses are returned with their status code intact.
    """
    return await _ssrf_safe_request(
        url,
        method="GET",
        allow_http=allow_http,
        allow_localhost=allow_localhost,
        allow_private_networks=allow_private_networks,
        max_size=max_size,
        timeout=timeout,
    )


async def ssrf_safe_post(
    url: str,
    *,
    form_data: dict[str, str] | list[tuple[str, str]] | None = None,
    json_data: dict[str, Any] | None = None,
    extra_headers: dict[str, str] | None = None,
    allow_http: bool = False,
    allow_localhost: bool = False,
    allow_private_networks: bool = False,
    max_size: int = 65536,
    timeout: float = 10.0,
) -> HttpResponse:
    """POST form or JSON data to a URL with the same SSRF protections as ssrf_safe_get.

    Applies identical security measures to ssrf_safe_get — HTTPS-only,
    DNS resolution and IP validation, DNS pinning, response size limits,
    no redirects — but sends a POST body instead of a GET request.

    Intended for Authorization Server interactions such as RFC 7662 token
    introspection, where the protocol requires POST.

    Args:
        url: URL to POST to
        form_data: Form-encoded request body (application/x-www-form-urlencoded).
            Mutually exclusive with json_data.
        json_data: JSON request body (application/json).
            Mutually exclusive with form_data.
        extra_headers: Additional request headers (e.g. Authorization).
            Security-critical headers (Host, Accept) always override these.
        allow_http: If True, allow HTTP in addition to HTTPS (default False)
        allow_localhost: If True, allow localhost addresses (default False)
        allow_private_networks: If True, allow private network addresses (default False)
        max_size: Maximum response size in bytes (default 64KB)
        timeout: Timeout in seconds (default 10s)

    Returns:
        HttpResponse with parsed JSON body and raw headers

    Raises:
        SSRFError: If SSRF validation fails or size limit exceeded
        httpx.HTTPError: If transport fails (timeout, connection error, etc.).
            Non-2xx responses are returned with their status code intact.
    """
    return await _ssrf_safe_request(
        url,
        method="POST",
        allow_http=allow_http,
        allow_localhost=allow_localhost,
        allow_private_networks=allow_private_networks,
        form_data=form_data,
        json_data=json_data,
        extra_headers=extra_headers,
        max_size=max_size,
        timeout=timeout,
    )
