"""Event model for synthetic packet and log records."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class PacketEvent:
    """Normalized synthetic event loaded from a local sample file."""

    source_path: str
    record_index: int
    timestamp: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    source_port: int | None = None
    destination_port: int | None = None
    protocol: str | None = None
    byte_count: int | None = None
    status: str | None = None
    hostname: str | None = None
    query_name: str | None = None
    method: str | None = None
    path: str | None = None
    user_agent: str | None = None
    synthetic_marker: bool = False
    raw_record: dict[str, Any] | str = field(default_factory=dict)
    parse_status: str = "valid"

    def to_dict(self) -> dict[str, Any]:
        """Return a stable dictionary representation."""
        return asdict(self)
