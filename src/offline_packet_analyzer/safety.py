"""Safety constants and lightweight checks for the offline-only lab."""

from __future__ import annotations

from ipaddress import ip_address, ip_network

OFFLINE_ONLY_NOTICE = (
    "Offline-only lab scaffold. No live capture, no raw sockets, no AF_PACKET, "
    "and no real traffic analysis are implemented."
)

ALLOWED_IP_RANGES = (
    ip_network("10.0.0.0/8"),
    ip_network("192.0.2.0/24"),
    ip_network("198.51.100.0/24"),
    ip_network("203.0.113.0/24"),
)

ALLOWED_DOMAIN_SUFFIXES = (
    "example.com",
    "example.org",
    "example.net",
    ".test",
)

ALLOWED_SYNTHETIC_HOSTNAMES = frozenset(
    {
        "analyst-workstation",
        "lab-client",
        "lab-server",
        "synthetic-dns-server",
    }
)

ALLOWED_SYNTHETIC_MARKERS = frozenset(
    {
        "SYNTHETIC_PASSWORD_MARKER",
        "SYNTHETIC_TOKEN_MARKER",
        "SYNTHETIC_SECRET_MARKER",
    }
)

SUPPORTED_SAMPLE_EXTENSIONS = frozenset({".json", ".csv", ".txt", ".md", ".yaml"})
MAX_SAMPLE_FILE_BYTES = 25_000


def is_allowed_ip(value: str) -> bool:
    """Return whether an IP address belongs to an approved synthetic range."""
    try:
        parsed = ip_address(value)
    except ValueError:
        return False

    return any(parsed in network for network in ALLOWED_IP_RANGES)


def is_allowed_domain(value: str) -> bool:
    """Return whether a domain name is approved for synthetic samples."""
    normalized = value.strip().lower().rstrip(".")
    return (
        normalized in ALLOWED_SYNTHETIC_HOSTNAMES
        or normalized in ALLOWED_DOMAIN_SUFFIXES
        or normalized.endswith(".example.com")
        or normalized.endswith(".example.org")
        or normalized.endswith(".example.net")
        or normalized.endswith(".test")
    )
