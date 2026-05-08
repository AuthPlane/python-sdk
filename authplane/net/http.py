"""Shared HTTP helpers for OAuth protocol operations."""

import base64
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import quote, urlencode

import httpx

from ..dpop import DPoPProvider
from .fetch_settings import FetchSettings
from .ssrf import ssrf_safe_post


@dataclass(frozen=True)
class FormPostResponse:
    """Parsed response from an OAuth form POST."""

    status_code: int
    body: dict[str, Any]
    headers: dict[str, str]


def _normalize_headers(headers: Mapping[str, str]) -> dict[str, str]:
    """Return response headers with lowercase field names."""
    return {str(key).lower(): value for key, value in headers.items()}


def build_basic_auth_header(client_id: str, client_secret: str) -> dict[str, str]:
    """Build HTTP Basic auth header per RFC 6749 §2.3.1.

    Client ID and secret are URL-encoded before base64-encoding.
    """
    encoded_id = quote(client_id, safe="")
    encoded_secret = quote(client_secret, safe="")
    b64 = base64.b64encode(f"{encoded_id}:{encoded_secret}".encode()).decode()
    return {"Authorization": f"Basic {b64}"}


async def form_post(
    url: str,
    form_data: dict[str, str] | list[tuple[str, str]],
    fetch_settings: FetchSettings,
    extra_headers: dict[str, str] | None = None,
    *,
    dpop_provider: DPoPProvider | None = None,
    dpop_access_token: str = "",
) -> FormPostResponse:
    """POST form data to URL with SSRF protection branching.

    Returns status code, parsed JSON body, and response headers.
    """
    base_headers = extra_headers.copy() if extra_headers else {}

    async def _send(req_headers: dict[str, str]) -> FormPostResponse:
        if fetch_settings.ssrf_protection:
            http_response = await ssrf_safe_post(
                url,
                form_data=form_data,
                extra_headers=req_headers or None,
                allow_http=fetch_settings.allow_http,
                allow_localhost=fetch_settings.allow_localhost,
                allow_private_networks=fetch_settings.allow_private_networks,
                timeout=fetch_settings.timeout,
            )
            return FormPostResponse(
                status_code=http_response.status_code,
                body=http_response.body,
                headers=_normalize_headers(http_response.headers),
            )
        else:
            req_headers_direct: dict[str, str] = {"Accept": "application/json"}
            req_headers_direct.update(req_headers)
            req_headers_direct.setdefault("Content-Type", "application/x-www-form-urlencoded")
            async with httpx.AsyncClient(timeout=fetch_settings.timeout) as client:
                encoded = urlencode(form_data, doseq=True)
                response = await client.post(url, content=encoded, headers=req_headers_direct)
                try:
                    data2: dict[str, Any] = response.json() if response.content else {}
                except Exception:
                    data2 = {}
                return FormPostResponse(
                    status_code=response.status_code,
                    body=data2,
                    headers=_normalize_headers(response.headers),
                )

    def _headers_for_attempt() -> dict[str, str]:
        headers = base_headers.copy()
        if dpop_provider is not None:
            headers.update(
                dpop_provider.build_headers(
                    "POST",
                    url,
                    access_token=dpop_access_token,
                )
            )
        return headers

    response = await _send(_headers_for_attempt())

    if dpop_provider is None:
        return response

    nonce = response.headers.get("dpop-nonce")
    if nonce:
        dpop_provider.note_nonce(url, nonce)
    error = str(response.body.get("error", ""))
    if nonce and error == "use_dpop_nonce":
        return await _send(_headers_for_attempt())

    return response
