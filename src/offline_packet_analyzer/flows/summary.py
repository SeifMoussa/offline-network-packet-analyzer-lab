"""Flow and protocol summaries for loaded synthetic events."""

from __future__ import annotations

from collections import Counter
from typing import Any

from offline_packet_analyzer.models.event import PacketEvent
from offline_packet_analyzer.models.flow import FlowKey, FlowSummary, ProtocolSummary
from offline_packet_analyzer.models.load_result import LoadResult

SAFETY_NOTE = "Offline synthetic analysis only. No live capture or real traffic processing."
UNKNOWN = "unknown"


def _valid_events(events: list[PacketEvent]) -> list[PacketEvent]:
    return [event for event in events if event.parse_status == "valid"]


def _protocol(event: PacketEvent) -> str:
    return (event.protocol or UNKNOWN).upper()


def build_flow_key(event: PacketEvent) -> FlowKey | None:
    """Build a deterministic flow key from a loaded synthetic event."""
    if event.parse_status != "valid":
        return None
    if not event.source_ip or not event.destination_ip:
        return None

    return FlowKey(
        source_ip=event.source_ip,
        destination_ip=event.destination_ip,
        protocol=_protocol(event),
        destination_port=event.destination_port,
        source_port=event.source_port,
    )


def summarize_flows(events: list[PacketEvent]) -> list[FlowSummary]:
    """Aggregate valid loaded events into flow summaries."""
    flows: dict[FlowKey, FlowSummary] = {}

    for event in events:
        key = build_flow_key(event)
        if key is None:
            continue

        summary = flows.setdefault(key, FlowSummary(key=key))
        summary.event_count += 1
        summary.total_bytes += event.byte_count or 0

        if event.status:
            summary.statuses.add(event.status)
        if event.hostname:
            summary.hostnames.add(event.hostname)
        if event.query_name:
            summary.query_names.add(event.query_name)
        if event.user_agent:
            summary.user_agents.add(event.user_agent)
        if event.timestamp:
            summary.first_seen = (
                event.timestamp
                if summary.first_seen is None
                else min(summary.first_seen, event.timestamp)
            )
            summary.last_seen = (
                event.timestamp
                if summary.last_seen is None
                else max(summary.last_seen, event.timestamp)
            )

    return sorted(flows.values(), key=lambda flow: flow.key.sort_key())


def _counter_items(counter: Counter[Any], limit: int | None = None) -> list[dict[str, Any]]:
    items = sorted(counter.items(), key=lambda item: (-item[1], str(item[0])))
    if limit is not None:
        items = items[:limit]
    return [{"value": str(value), "count": count} for value, count in items]


def summarize_ports(events: list[PacketEvent]) -> dict[str, int]:
    """Count valid events by destination port."""
    counter: Counter[str] = Counter()
    for event in _valid_events(events):
        if event.destination_port is not None:
            counter[str(event.destination_port)] += 1
    return dict(sorted(counter.items(), key=lambda item: (int(item[0]), item[0])))


def summarize_top_talkers(events: list[PacketEvent], limit: int = 5) -> list[dict[str, Any]]:
    """Return source/destination pairs sorted by total bytes and event count."""
    counter: dict[tuple[str, str], dict[str, Any]] = {}
    for event in _valid_events(events):
        if not event.source_ip or not event.destination_ip:
            continue
        key = (event.source_ip, event.destination_ip)
        entry = counter.setdefault(
            key,
            {
                "source_ip": event.source_ip,
                "destination_ip": event.destination_ip,
                "event_count": 0,
                "total_bytes": 0,
            },
        )
        entry["event_count"] += 1
        entry["total_bytes"] += event.byte_count or 0

    return sorted(
        counter.values(),
        key=lambda item: (
            -int(item["total_bytes"]),
            -int(item["event_count"]),
            str(item["source_ip"]),
            str(item["destination_ip"]),
        ),
    )[:limit]


def summarize_protocols(events: list[PacketEvent]) -> ProtocolSummary:
    """Build a protocol-level summary for loaded synthetic events."""
    valid_events = _valid_events(events)
    protocol_counts = Counter(_protocol(event) for event in valid_events)
    source_counts = Counter(event.source_ip for event in valid_events if event.source_ip)
    destination_counts = Counter(
        event.destination_ip for event in valid_events if event.destination_ip
    )

    return ProtocolSummary(
        total_events=len(events),
        events_by_protocol=dict(sorted(protocol_counts.items())),
        events_by_destination_port=summarize_ports(events),
        top_sources=_counter_items(source_counts, limit=5),
        top_destinations=_counter_items(destination_counts, limit=5),
        top_talkers=summarize_top_talkers(events),
        malformed_records=sum(1 for event in events if event.parse_status != "valid"),
        skipped_records=len(events) - len(valid_events),
    )


def build_analysis_summary(load_result: LoadResult) -> dict[str, Any]:
    """Build a stable JSON-ready summary from a load result."""
    flows = summarize_flows(load_result.events)
    protocol_summary = summarize_protocols(load_result.events)

    return {
        "input_path": load_result.input_path,
        "files_loaded": sorted(load_result.files_loaded),
        "records_seen": load_result.records_seen,
        "events_loaded": len(load_result.events),
        "malformed_records": load_result.malformed_records,
        "total_flows": len(flows),
        "protocol_counts": protocol_summary.events_by_protocol,
        "destination_port_counts": protocol_summary.events_by_destination_port,
        "top_sources": protocol_summary.top_sources,
        "top_destinations": protocol_summary.top_destinations,
        "top_talkers": protocol_summary.top_talkers,
        "flows": [flow.to_dict() for flow in flows],
        "skipped_files": sorted(load_result.skipped_files),
        "errors": load_result.errors,
        "safety_note": SAFETY_NOTE,
    }


def format_analysis_summary_text(summary: dict[str, Any]) -> str:
    """Format an analysis summary as deterministic human-readable text."""
    lines = [
        "Offline Packet Analyzer Summary",
        f"Safety: {summary['safety_note']}",
        f"Input: {summary['input_path']}",
        f"Records seen: {summary['records_seen']}",
        f"Events loaded: {summary['events_loaded']}",
        f"Malformed records: {summary['malformed_records']}",
        f"Total flows: {summary['total_flows']}",
        f"Protocols: {summary['protocol_counts']}",
        f"Destination ports: {summary['destination_port_counts']}",
        "Top talkers:",
    ]
    for talker in summary["top_talkers"]:
        lines.append(
            "- "
            f"{talker['source_ip']} -> {talker['destination_ip']} "
            f"bytes={talker['total_bytes']} events={talker['event_count']}"
        )
    return "\n".join(lines)
