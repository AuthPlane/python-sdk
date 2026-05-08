"""Settings for document fetching with SSRF protection."""

from dataclasses import dataclass


@dataclass(frozen=True)
class FetchSettings:
    """Settings for document fetching with SSRF protection.

    Attributes:
        ssrf_protection: Enable SSRF protection (DNS pinning, IP blocklist, etc.)
        allow_http: Allow HTTP in addition to HTTPS
        allow_localhost: Allow localhost addresses (127.0.0.0/8, ::1)
        allow_private_networks: Allow private network addresses (10.x, 172.16.x, 192.168.x)
        timeout: Timeout in seconds for HTTP requests
    """

    ssrf_protection: bool = True
    allow_http: bool = False
    allow_localhost: bool = False
    allow_private_networks: bool = False
    timeout: float = 10.0

    @classmethod
    def from_dev_mode(cls, dev_mode: bool) -> "FetchSettings":
        """Create fetch settings based on dev_mode flag.

        SSRF protection remains enabled in both modes. When dev_mode is True,
        the allow-lists are relaxed so local development can use HTTP,
        localhost, and private-network endpoints.

        When dev_mode is False (production): SSRF protection is enabled
        with strict rules (HTTPS-only, no localhost, no private networks).

        Args:
            dev_mode: If True, relaxes restrictions for local development

        Returns:
            FetchSettings instance with appropriate values
        """
        if dev_mode:
            return cls(
                ssrf_protection=True,
                allow_http=True,
                allow_localhost=True,
                allow_private_networks=True,
                timeout=10.0,
            )
        else:
            return cls(
                ssrf_protection=True,
                allow_http=False,
                allow_localhost=False,
                allow_private_networks=False,
                timeout=10.0,
            )
