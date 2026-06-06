from pathlib import Path

from offline_packet_analyzer.safety import MAX_SAMPLE_FILE_BYTES, SUPPORTED_SAMPLE_EXTENSIONS

ROOT = Path(__file__).resolve().parents[1]

REQUIRED_SAMPLE_DIRS = (
    ROOT / "samples" / "logs",
    ROOT / "samples" / "raw",
    ROOT / "rules",
)

REQUIRED_SAMPLE_FILES = (
    ROOT / "samples" / "logs" / "normal_traffic.json",
    ROOT / "samples" / "logs" / "suspicious_connections.json",
    ROOT / "samples" / "logs" / "dns_queries.csv",
    ROOT / "samples" / "logs" / "http_events.txt",
    ROOT / "samples" / "logs" / "mixed_packet_events.json",
    ROOT / "samples" / "logs" / "malformed_records.json",
    ROOT / "samples" / "logs" / "sensitive_marker_events.json",
    ROOT / "samples" / "raw" / "README.md",
    ROOT / "rules" / "signatures.yaml",
)


def test_required_sample_directories_exist() -> None:
    for path in REQUIRED_SAMPLE_DIRS:
        assert path.is_dir(), f"Missing required sample directory: {path}"


def test_required_sample_files_exist() -> None:
    for path in REQUIRED_SAMPLE_FILES:
        assert path.is_file(), f"Missing required sample file: {path}"


def test_sample_files_are_text_readable_and_small() -> None:
    for path in REQUIRED_SAMPLE_FILES:
        content = path.read_text(encoding="utf-8")

        assert content.strip(), f"Sample file is empty: {path}"
        assert path.stat().st_size <= MAX_SAMPLE_FILE_BYTES


def test_sample_file_extensions_are_expected() -> None:
    for path in REQUIRED_SAMPLE_FILES:
        assert path.suffix in SUPPORTED_SAMPLE_EXTENSIONS


def test_no_real_pcap_files_exist() -> None:
    forbidden_suffixes = {".pcap", ".pcapng", ".cap"}
    forbidden_files = [
        path
        for path in ROOT.rglob("*")
        if path.is_file() and path.suffix.lower() in forbidden_suffixes
    ]

    assert forbidden_files == []
