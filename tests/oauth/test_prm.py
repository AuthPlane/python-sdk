"""Tests for Protected Resource Metadata (PRM) builder."""

from authplane.oauth.prm import build_prm


def test_build_prm_contains_required_fields() -> None:
    """PRM should contain all required RFC 9728 fields."""
    prm = build_prm(
        issuer="https://auth.example.com",
        resource="https://api.example.com",
        scopes=["read:data", "write:data"],
    )

    assert "resource" in prm
    assert "authorization_servers" in prm
    assert "bearer_methods_supported" in prm
    assert "scopes_supported" in prm


def test_build_prm_resource_field() -> None:
    """PRM resource field should match input."""
    prm = build_prm(
        issuer="https://auth.example.com",
        resource="https://api.example.com",
        scopes=[],
    )

    assert prm["resource"] == "https://api.example.com"


def test_build_prm_authorization_servers_single_element() -> None:
    """authorization_servers should be a single-element list."""
    prm = build_prm(
        issuer="https://auth.example.com",
        resource="https://api.example.com",
        scopes=[],
    )

    authorization_servers = prm["authorization_servers"]
    assert isinstance(authorization_servers, list)
    assert len(authorization_servers) == 1  # pyright: ignore[reportUnknownArgumentType]
    assert authorization_servers[0] == "https://auth.example.com"


def test_build_prm_empty_scopes() -> None:
    """PRM should handle empty scopes list."""
    prm = build_prm(
        issuer="https://auth.example.com",
        resource="https://api.example.com",
        scopes=[],
    )

    assert prm["scopes_supported"] == []


def test_build_prm_multiple_scopes() -> None:
    """PRM should include all provided scopes."""
    scopes = ["read:data", "write:data", "admin"]
    prm = build_prm(
        issuer="https://auth.example.com",
        resource="https://api.example.com",
        scopes=scopes,
    )

    assert prm["scopes_supported"] == scopes


def test_build_prm_hardcoded_bearer_methods() -> None:
    """bearer_methods_supported should be hardcoded to ['header']."""
    prm = build_prm(
        issuer="https://auth.example.com",
        resource="https://api.example.com",
        scopes=[],
    )

    assert prm["bearer_methods_supported"] == ["header"]
