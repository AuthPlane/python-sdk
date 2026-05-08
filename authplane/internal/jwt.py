"""Internal JWT helpers shared across verifier and DPoP code."""

import base64
import json
from typing import Any, cast


def decode_jwt_header(token: str) -> dict[str, Any]:
    """Decode the JOSE header segment of a compact JWT into a JSON object."""
    header_b64 = token.split(".")[0]
    padding = 4 - (len(header_b64) % 4)
    if padding != 4:
        header_b64 += "=" * padding
    raw_header = json.loads(base64.urlsafe_b64decode(header_b64))
    if not isinstance(raw_header, dict):
        raise ValueError("JWT header must decode to a JSON object")
    return cast("dict[str, Any]", raw_header)
