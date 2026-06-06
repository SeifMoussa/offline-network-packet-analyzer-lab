from pathlib import Path

from offline_packet_analyzer.parsers.ethernet import parse_ethernet_frame
from offline_packet_analyzer.parsers.ipv4 import parse_ipv4_packet
from offline_packet_analyzer.parsers.tcp import parse_tcp_segment
from offline_packet_analyzer.parsers.udp import parse_udp_datagram

ROOT = Path(__file__).resolve().parents[1]


def _read(paths: list[Path]) -> str:
    return "\n".join(path.read_text(encoding="utf-8") for path in paths)


def test_no_capture_module_exists() -> None:
    assert not (ROOT / "src" / "offline_packet_analyzer" / "capture.py").exists()
    assert not any(path.name == "capture.py" for path in (ROOT / "src").rglob("*.py"))


def test_no_packet_capture_files_exist() -> None:
    forbidden_suffixes = {".pcap", ".pcapng", ".cap"}
    assert [
        path
        for path in ROOT.rglob("*")
        if path.is_file() and path.suffix.lower() in forbidden_suffixes
    ] == []


def test_no_capture_libraries_or_raw_capture_code() -> None:
    implementation_files = [
        path
        for path in (ROOT / "src" / "offline_packet_analyzer").rglob("*.py")
        if path.name != "safety.py"
    ]
    source = _read(implementation_files).lower()
    forbidden = (
        "import socket",
        "from socket import",
        "af_packet",
        "sock_raw",
        "scapy",
        "sniff(",
        "pcap_open",
        "promisc",
        "cap_net_raw",
        "arp_spoof",
        "mitm",
        "extract_credential",
        "credential_extraction",
        "dump_payload",
        "--interface",
        "--capture",
    )

    for pattern in forbidden:
        assert pattern not in source


def test_parser_modules_accept_only_bytes_arguments() -> None:
    parser_files = [
        path for path in (ROOT / "src" / "offline_packet_analyzer" / "parsers").rglob("*.py")
    ]
    source = _read(parser_files)

    assert "Path(" not in source
    assert ".open(" not in source
    assert "read_bytes" not in source
    assert "read_text" not in source


def test_no_unhandled_exceptions_on_malformed_synthetic_bytes() -> None:
    malformed_inputs = (b"", b"\x00", b"\xff" * 3, b"\x45" + b"\x00" * 5)

    for data in malformed_inputs:
        assert parse_ethernet_frame(data).parse_status in {"malformed", "unsupported"}
        assert parse_ipv4_packet(data).parse_status == "malformed"
        assert parse_tcp_segment(data).parse_status == "malformed"
        assert parse_udp_datagram(data).parse_status == "malformed"
