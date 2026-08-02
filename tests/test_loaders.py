import json
from pathlib import Path

from offline_packet_analyzer.loaders.inventory import discover_input_files, load_file, load_input
from offline_packet_analyzer.models.event import PacketEvent
from offline_packet_analyzer.models.load_result import LoadResult

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"
LOGS = SAMPLES / "logs"


def test_json_loader_success() -> None:
    result = load_file(LOGS / "normal_traffic.json")

    assert result.records_seen == 7
    assert len(result.events) == 7
    assert result.malformed_records == 0
    assert result.events[0].source_ip == "10.0.0.10"


def test_csv_loader_success() -> None:
    result = load_file(LOGS / "dns_queries.csv")

    assert result.records_seen == 4
    assert len(result.events) == 4
    assert result.events[0].query_name == "example.com"


def test_text_loader_success() -> None:
    result = load_file(LOGS / "http_events.txt")

    assert result.records_seen == 4
    assert len(result.events) == 4
    assert result.events[0].method == "GET"
    assert result.events[0].path == "/index.html"


def test_malformed_json_is_handled_safely(tmp_path: Path) -> None:
    malformed = tmp_path / "broken.json"
    malformed.write_text('[{"timestamp":', encoding="utf-8")

    result = load_file(malformed)

    assert result.events == []
    assert result.malformed_records == 1
    assert result.errors


def test_malformed_records_are_counted_safely() -> None:
    result = load_file(LOGS / "malformed_records.json")

    assert result.records_seen == 3
    assert result.malformed_records == 3
    assert all(event.parse_status == "malformed" for event in result.events)


def test_unsupported_extension_is_skipped_cleanly(tmp_path: Path) -> None:
    unsupported = tmp_path / "notes.unsupported"
    unsupported.write_text("synthetic note", encoding="utf-8")

    result = load_file(unsupported)

    assert result.events == []
    assert result.skipped_files == [str(unsupported)]


def test_directory_inventory_recursive_scan() -> None:
    files, skipped = discover_input_files(SAMPLES)

    names = {path.name for path in files}
    assert "normal_traffic.json" in names
    assert "dns_queries.csv" in names
    assert "http_events.txt" in names
    assert any(path.endswith("README.md") for path in skipped)


def test_single_file_loading() -> None:
    result = load_input(LOGS / "normal_traffic.json")

    assert result.records_seen == 7
    assert len(result.files_loaded) == 1


def test_packet_event_model_shape() -> None:
    event = PacketEvent(
        source_path="samples/logs/example.json",
        record_index=0,
        source_ip="10.0.0.1",
        synthetic_marker=True,
    )

    data = event.to_dict()
    assert data["source_path"] == "samples/logs/example.json"
    assert data["record_index"] == 0
    assert data["parse_status"] == "valid"


def test_load_result_summary_shape() -> None:
    result = LoadResult(input_path="samples")
    result.events.append(PacketEvent(source_path="sample", record_index=0, synthetic_marker=True))
    result.files_loaded.append("b.json")
    result.files_loaded.append("a.json")

    summary = result.to_summary_dict()
    assert summary["input_path"] == "samples"
    assert summary["events_loaded"] == 1
    assert summary["files_loaded"] == ["a.json", "b.json"]


def test_inventory_summary_is_json_serializable() -> None:
    result = load_input(LOGS / "normal_traffic.json")

    encoded = json.dumps(result.to_summary_dict(), sort_keys=True)
    assert "normal_traffic.json" in encoded
