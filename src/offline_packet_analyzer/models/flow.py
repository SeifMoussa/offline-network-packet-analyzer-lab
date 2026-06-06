"""Flow and protocol summary models for synthetic events."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class FlowKey:
    """Stable identifier for a synthetic network flow."""

    source_ip: str
    destination_ip: str
    protocol: str
    destination_port: int | None = None
    source_port: int | None = None

    def sort_key(self) -> tuple[str, str, str, int, int]:
        """Return deterministic ordering fields."""
        return (
            self.source_ip,
            self.destination_ip,
            self.protocol,
            self.destination_port if self.destination_port is not None else -1,
            self.source_port if self.source_port is not None else -1,
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a stable dictionary representation."""
        return asdict(self)


@dataclass(slots=True)
class FlowSummary:
    """Aggregated metadata for one synthetic flow."""

    key: FlowKey
    event_count: int = 0
    total_bytes: int = 0
    statuses: set[str] = field(default_factory=set)
    first_seen: str | None = None
    last_seen: str | None = None
    hostnames: set[str] = field(default_factory=set)
    query_names: set[str] = field(default_factory=set)
    user_agents: set[str] = field(default_factory=set)
    malformed_count: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Return a stable dictionary representation."""
        return {
            "key": self.key.to_dict(),
            "event_count": self.event_count,
            "total_bytes": self.total_bytes,
            "statuses": sorted(self.statuses),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "hostnames": sorted(self.hostnames),
            "query_names": sorted(self.query_names),
            "user_agents": sorted(self.user_agents),
            "malformed_count": self.malformed_count,
        }


@dataclass(slots=True)
class ProtocolSummary:
    """Top-level synthetic event summary."""

    total_events: int = 0
    events_by_protocol: dict[str, int] = field(default_factory=dict)
    events_by_destination_port: dict[str, int] = field(default_factory=dict)
    top_sources: list[dict[str, Any]] = field(default_factory=list)
    top_destinations: list[dict[str, Any]] = field(default_factory=list)
    top_talkers: list[dict[str, Any]] = field(default_factory=list)
    malformed_records: int = 0
    skipped_records: int = 0

    def to_dict(self) -> dict[str, Any]:
        """Return a stable dictionary representation."""
        return asdict(self)
