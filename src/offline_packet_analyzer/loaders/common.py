"""Shared helpers for local synthetic sample loaders."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from offline_packet_analyzer.models.event import PacketEvent
from offline_packet_analyzer.validators import validate_packet_event

LOADABLE_EXTENSIONS = frozenset({".json", ".csv", ".txt"})


def coerce_int(value: Any) -> int | None:
    """Coerce a value to int when possible."""
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdecimal():
        return int(value)
    return None


def event_from_mapping(source_path: Path, record_index: int, record: dict[str, Any]) -> PacketEvent:
    """Create a PacketEvent from a mapping and apply schema validation."""
    errors = validate_packet_event(record)
    return PacketEvent(
        source_path=str(source_path),
        record_index=record_index,
        timestamp=record.get("timestamp"),
        source_ip=record.get("source_ip"),
        destination_ip=record.get("destination_ip"),
        source_port=coerce_int(record.get("source_port")),
        destination_port=coerce_int(record.get("destination_port")),
        protocol=record.get("protocol"),
        byte_count=coerce_int(record.get("byte_count")),
        status=record.get("status"),
        hostname=record.get("hostname"),
        query_name=record.get("query_name"),
        method=record.get("method"),
        path=record.get("path"),
        user_agent=record.get("user_agent"),
        synthetic_marker=record.get("synthetic_marker") is True,
        raw_record=record,
        parse_status="valid" if not errors else "malformed",
    )


def event_is_malformed(event: PacketEvent) -> bool:
    """Return whether an event failed validation."""
    return event.parse_status != "valid"
