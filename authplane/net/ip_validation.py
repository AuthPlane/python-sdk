"""IP address validation and DNS resolution for SSRF protection.

Validates that resolved IPs are safe to connect to by blocking private,
loopback, link-local, and cloud metadata addresses by default.
"""

import asyncio
import ipaddress
import socket


class SSRFError(Exception):
    """Raised when an SSRF protection check fails."""

    pass


def format_ip_for_url(ip_str: str) -> str:
    """Format IP address for use in URL (bracket IPv6 addresses).

    IPv6 addresses must be bracketed in URLs to distinguish the address from
    the port separator. For example: https://[2001:db8::1]:443/path

    Args:
        ip_str: IP address string

    Returns:
        IP string suitable for URL (IPv6 addresses are bracketed)
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        if isinstance(ip, ipaddress.IPv6Address):
            return f"[{ip_str}]"
        return ip_str
    except ValueError:
        return ip_str


def is_ip_allowed(
    ip_str: str,
    *,
    allow_localhost: bool = False,
    allow_private_networks: bool = False,
) -> bool:
    """Check if an IP address is allowed.

    By default, only globally routable public IPs are allowed.
    Cloud metadata endpoints (169.254.0.0/16) are ALWAYS blocked.

    Default blocking (production):
    - Private (10.x, 172.16-31.x, 192.168.x)
    - Loopback (127.x, ::1)
    - Link-local (169.254.x, fe80::) - includes AWS/GCP metadata!
    - Reserved, unspecified
    - RFC6598 Carrier-Grade NAT (100.64.0.0/10)
    - Multicast

    Args:
        ip_str: IP address string to check
        allow_localhost: If True, allow loopback addresses (127.0.0.0/8, ::1)
            Useful for local development.
        allow_private_networks: If True, allow private network addresses
            (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16).
            Useful for corporate/internal deployments.
            NOTE: Cloud metadata (169.254.0.0/16) is ALWAYS blocked.

    Returns:
        True if the IP is allowed, False if blocked
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False

    # ALWAYS block cloud metadata endpoints (AWS/GCP/Azure)
    # This is the most dangerous SSRF vector
    if ip.is_link_local:  # 169.254.0.0/16 for IPv4, fe80::/10 for IPv6
        return False

    # IPv6-specific: unwrap embedded IPv4 and recurse on the inner address.
    # Must happen before the is_loopback / is_global checks because Python's
    # IPv6Address.is_loopback is only True for ::1, not for ::ffff:127.0.0.1.
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped:
            return is_ip_allowed(
                str(ip.ipv4_mapped),
                allow_localhost=allow_localhost,
                allow_private_networks=allow_private_networks,
            )
        if ip.sixtofour:
            return is_ip_allowed(
                str(ip.sixtofour),
                allow_localhost=allow_localhost,
                allow_private_networks=allow_private_networks,
            )
        if ip.teredo:
            server, client = ip.teredo
            return is_ip_allowed(
                str(server),
                allow_localhost=allow_localhost,
                allow_private_networks=allow_private_networks,
            ) and is_ip_allowed(
                str(client),
                allow_localhost=allow_localhost,
                allow_private_networks=allow_private_networks,
            )

    # Allow localhost if explicitly enabled (development)
    if allow_localhost and ip.is_loopback:
        return True

    # Allow private networks if explicitly enabled (corporate/internal)
    if allow_private_networks and ip.is_private:
        return True

    # For production: only allow globally routable IPs
    if not ip.is_global:
        return False

    # Block multicast (not caught by is_global for some ranges)
    return not ip.is_multicast


async def resolve_hostname(hostname: str, port: int = 443) -> list[str]:
    """Resolve hostname to IP addresses using DNS.

    Args:
        hostname: Hostname to resolve
        port: Port number (used for getaddrinfo)

    Returns:
        List of resolved IP addresses

    Raises:
        SSRFError: If resolution fails
    """
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.run_in_executor(
            None,
            lambda: socket.getaddrinfo(hostname, port, socket.AF_UNSPEC, socket.SOCK_STREAM),
        )
        ips = [str(info[4][0]) for info in infos]
        ips = list(dict.fromkeys(ips))  # deduplicate preserving order
        if not ips:
            raise SSRFError(f"DNS resolution returned no addresses for {hostname}")
        return ips
    except socket.gaierror as e:
        raise SSRFError(f"DNS resolution failed for {hostname}: {e}") from e
