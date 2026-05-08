"""Tests for client/net/http.py helpers."""

from authplane.net.http import build_basic_auth_header


def test_build_basic_auth_header():
    header = build_basic_auth_header("client_id", "client_secret")
    assert "Authorization" in header
    assert header["Authorization"].startswith("Basic ")


def test_build_basic_auth_header_url_encodes_special_chars():
    header = build_basic_auth_header("client:id", "secret/value")
    assert "Authorization" in header
    # Verify URL encoding happened (: and / should be encoded)
    import base64

    b64_part = header["Authorization"].split(" ", 1)[1]
    decoded = base64.b64decode(b64_part).decode()
    assert "client%3Aid" in decoded
    assert "secret%2Fvalue" in decoded
