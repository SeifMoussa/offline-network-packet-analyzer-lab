from pathlib import Path

from offline_packet_analyzer.safety import ALLOWED_SYNTHETIC_MARKERS
from offline_packet_analyzer.validators import (
    validate_domain_allowed,
    validate_input_path,
    validate_ip_allowed,
    validate_packet_event,
    validate_sample_file,
)

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"


def test_validate_ip_allowed_accepts_reserved_ranges() -> None:
    assert validate_ip_allowed("10.0.0.1") == []
    assert validate_ip_allowed("192.0.2.10") == []


def test_validate_ip_allowed_rejects_unapproved_public_ip() -> None:
    assert validate_ip_allowed("8.8.8.8")


def test_validate_domain_allowed_accepts_safe_domains_and_hostnames() -> None:
    assert validate_domain_allowed("example.com") == []
    assert validate_domain_allowed("updates.example.net") == []
    assert validate_domain_allowed("suspicious-lab.test") == []
    assert validate_domain_allowed("lab-server") == []


def test_validate_domain_allowed_rejects_real_domain() -> None:
    assert validate_domain_allowed("openai.com")


def test_validate_packet_event_accepts_safe_record() -> None:
    errors = validate_packet_event(
        {
            "timestamp": "2026-06-05T00:00:00Z",
            "source_ip": "10.0.0.5",
            "destination_ip": "192.0.2.5",
            "destination_port": 443,
            "hostname": "example.com",
            "synthetic_marker": True,
        }
    )

    assert errors == []


def test_validate_packet_event_rejects_missing_synthetic_marker() -> None:
    assert validate_packet_event({"source_ip": "10.0.0.5"})


def test_validate_sample_file_rejects_credential_looking_values(tmp_path: Path) -> None:
    sample = tmp_path / "sample.txt"
    sample.write_text("password=not_allowed", encoding="utf-8")

    assert validate_sample_file(sample)


def test_validate_sample_file_allows_approved_synthetic_markers(tmp_path: Path) -> None:
    sample = tmp_path / "sample.txt"
    sample.write_text("\n".join(sorted(ALLOWED_SYNTHETIC_MARKERS)), encoding="utf-8")

    assert validate_sample_file(sample) == []


def test_validate_input_path_rejects_path_traversal() -> None:
    assert validate_input_path(Path("samples") / ".." / "samples")


def test_validate_input_path_rejects_nonexistent_input() -> None:
    assert validate_input_path(ROOT / "does-not-exist")


def test_validate_input_path_rejects_packet_capture_suffix(tmp_path: Path) -> None:
    sample = tmp_path / "sample.pcap"
    sample.write_text("not real capture data", encoding="utf-8")

    assert validate_input_path(sample)


def test_sample_tree_validation() -> None:
    for path in (SAMPLES / "logs").iterdir():
        if path.is_file():
            assert validate_sample_file(path) == []
