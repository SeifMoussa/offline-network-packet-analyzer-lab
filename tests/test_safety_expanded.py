from pathlib import Path

from offline_packet_analyzer.cli import build_parser

ROOT = Path(__file__).resolve().parents[1]
RAW_MARKERS = (
    "SYNTHETIC_PASSWORD_MARKER",
    "SYNTHETIC_TOKEN_MARKER",
    "SYNTHETIC_SECRET_MARKER",
)


def _read(paths: list[Path]) -> str:
    return "\n".join(path.read_text(encoding="utf-8") for path in paths)


def test_no_live_capture_modules_exist() -> None:
    forbidden_names = {
        "capture.py",
        "sniffer.py",
        "pcap.py",
        "pcap_loader.py",
        "live_capture.py",
        "interface.py",
    }
    assert [
        path
        for path in (ROOT / "src" / "offline_packet_analyzer").rglob("*.py")
        if path.name.lower() in forbidden_names
    ] == []


def test_no_live_capture_cli_flags_exist() -> None:
    help_text = build_parser().format_help().lower()
    for action in build_parser()._actions:
        choices = getattr(action, "choices", None)
        if choices:
            for choice in choices:
                subparser = choices[choice]
                help_text += "\n" + subparser.format_help().lower()

    forbidden_flags = (
        "--interface",
        "--iface",
        "--pcap",
        "--sniff",
        "--promiscuous",
        "--capture",
        "--raw-socket",
        "--credentials",
    )

    for flag in forbidden_flags:
        assert flag not in help_text


def test_no_pcap_or_capture_dependency_exists() -> None:
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8").lower()
    forbidden_dependencies = ("scapy", "dpkt", "pyshark", "pcapy", "pcap")

    for dependency in forbidden_dependencies:
        assert dependency not in pyproject


def test_no_raw_socket_or_capture_code_exists() -> None:
    source_files = [path for path in (ROOT / "src" / "offline_packet_analyzer").rglob("*.py")]
    source = _read(source_files).lower()
    forbidden_patterns = (
        "import socket",
        "from socket import",
        "promiscuous",
        "promisc",
        "sniff(",
        "credential_extraction",
        "extract_credentials",
        "dump_payload",
    )

    for pattern in forbidden_patterns:
        assert pattern not in source


def test_generated_reports_contain_redaction_token_and_no_raw_markers() -> None:
    reports = [
        ROOT / "reports" / "examples" / "offline_packet_analysis_report.json",
        ROOT / "reports" / "examples" / "offline_packet_analysis_report.md",
    ]
    content = _read(reports)

    assert "[REDACTED]" in content
    for marker in RAW_MARKERS:
        assert marker not in content


def test_samples_remain_small_text_files() -> None:
    for sample in (ROOT / "samples").rglob("*"):
        if not sample.is_file():
            continue
        assert sample.stat().st_size < 50_000
        sample.read_text(encoding="utf-8")
