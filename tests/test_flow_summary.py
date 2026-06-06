from offline_packet_analyzer.flows.summary import (
    SAFETY_NOTE,
    build_analysis_summary,
    build_flow_key,
    summarize_flows,
    summarize_ports,
    summarize_protocols,
    summarize_top_talkers,
)
from offline_packet_analyzer.models.event import PacketEvent
from offline_packet_analyzer.models.load_result import LoadResult


def event(
    index: int,
    source_ip: str = "10.0.0.10",
    destination_ip: str = "192.0.2.10",
    source_port: int = 50000,
    destination_port: int = 443,
    protocol: str = "TCP",
    byte_count: int = 100,
    timestamp: str = "2026-06-05T00:00:00Z",
    parse_status: str = "valid",
) -> PacketEvent:
    return PacketEvent(
        source_path="sample.json",
        record_index=index,
        timestamp=timestamp,
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_port=source_port,
        destination_port=destination_port,
        protocol=protocol,
        byte_count=byte_count,
        status="allowed",
        hostname="example.com",
        user_agent="LabClient/1.0",
        synthetic_marker=True,
        parse_status=parse_status,
    )


def test_flow_key_creation() -> None:
    key = build_flow_key(event(0))

    assert key is not None
    assert key.source_ip == "10.0.0.10"
    assert key.destination_ip == "192.0.2.10"
    assert key.protocol == "TCP"
    assert key.destination_port == 443


def test_flow_key_missing_required_fields_returns_none() -> None:
    item = event(0)
    item.destination_ip = None

    assert build_flow_key(item) is None


def test_flow_aggregation_counts_events_and_bytes() -> None:
    events = [
        event(0, byte_count=100, timestamp="2026-06-05T00:00:00Z"),
        event(1, byte_count=250, timestamp="2026-06-05T00:01:00Z"),
    ]

    flows = summarize_flows(events)

    assert len(flows) == 1
    assert flows[0].event_count == 2
    assert flows[0].total_bytes == 350
    assert flows[0].first_seen == "2026-06-05T00:00:00Z"
    assert flows[0].last_seen == "2026-06-05T00:01:00Z"


def test_protocol_counts_and_destination_port_counts() -> None:
    events = [
        event(0, protocol="TCP", destination_port=443),
        event(1, protocol="UDP", destination_port=53),
        event(2, protocol="UDP", destination_port=53),
    ]

    summary = summarize_protocols(events)

    assert summary.events_by_protocol == {"TCP": 1, "UDP": 2}
    assert summary.events_by_destination_port == {"53": 2, "443": 1}


def test_top_sources_destinations_and_talkers() -> None:
    events = [
        event(0, source_ip="10.0.0.1", destination_ip="192.0.2.1", byte_count=100),
        event(1, source_ip="10.0.0.1", destination_ip="192.0.2.1", byte_count=200),
        event(2, source_ip="10.0.0.2", destination_ip="198.51.100.2", byte_count=50),
    ]

    protocol_summary = summarize_protocols(events)
    talkers = summarize_top_talkers(events)

    assert protocol_summary.top_sources[0] == {"value": "10.0.0.1", "count": 2}
    assert protocol_summary.top_destinations[0] == {"value": "192.0.2.1", "count": 2}
    assert talkers[0]["source_ip"] == "10.0.0.1"
    assert talkers[0]["total_bytes"] == 300


def test_deterministic_flow_sorting() -> None:
    events = [
        event(0, source_ip="10.0.0.2", destination_ip="192.0.2.2"),
        event(1, source_ip="10.0.0.1", destination_ip="192.0.2.1"),
    ]

    flows = summarize_flows(events)

    assert [flow.key.source_ip for flow in flows] == ["10.0.0.1", "10.0.0.2"]


def test_malformed_and_missing_fields_handled_safely() -> None:
    malformed = event(0, parse_status="malformed")
    missing_destination = event(1)
    missing_destination.destination_ip = None

    flows = summarize_flows([malformed, missing_destination])
    summary = summarize_protocols([malformed, missing_destination])

    assert flows == []
    assert summary.malformed_records == 1
    assert summary.skipped_records == 1


def test_empty_event_list_behavior() -> None:
    assert summarize_flows([]) == []
    assert summarize_ports([]) == {}

    summary = summarize_protocols([])
    assert summary.total_events == 0
    assert summary.events_by_protocol == {}


def test_build_analysis_summary_shape() -> None:
    result = LoadResult(input_path="samples", events=[event(0)], records_seen=1)
    result.files_loaded.append("sample.json")

    summary = build_analysis_summary(result)

    assert summary["input_path"] == "samples"
    assert summary["total_flows"] == 1
    assert summary["protocol_counts"] == {"TCP": 1}
    assert summary["safety_note"] == SAFETY_NOTE
