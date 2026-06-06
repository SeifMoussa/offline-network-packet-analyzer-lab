"""Shared helpers for synthetic byte parsers."""

from __future__ import annotations

PARSED = "parsed"
MALFORMED = "malformed"
UNSUPPORTED = "unsupported"


def format_mac(raw: bytes) -> str:
    """Format six MAC address bytes as lowercase hex octets."""
    return ":".join(f"{octet:02x}" for octet in raw)


def format_ipv4(raw: bytes) -> str:
    """Format four IPv4 address bytes as dotted decimal text."""
    return ".".join(str(octet) for octet in raw)
