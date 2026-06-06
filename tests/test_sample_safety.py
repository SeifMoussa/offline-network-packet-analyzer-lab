import re
from ipaddress import ip_address
from pathlib import Path

from offline_packet_analyzer.safety import (
    ALLOWED_SYNTHETIC_MARKERS,
    is_allowed_domain,
    is_allowed_ip,
)

ROOT = Path(__file__).resolve().parents[1]
SAMPLE_PATHS = [path for path in (ROOT / "samples").rglob("*") if path.is_file()]
RULE_PATH = ROOT / "rules" / "signatures.yaml"

IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_PATTERN = re.compile(r"\b[a-zA-Z0-9][a-zA-Z0-9-]*(?:\.[a-zA-Z0-9-]+)+\b")
MARKER_PATTERN = re.compile(r"\bSYNTHETIC_[A-Z_]+_MARKER\b")
CREDENTIAL_VALUE_PATTERN = re.compile(
    r"(?i)\b(?:password|passwd|pwd|token|secret|api[_-]?key)\s*[:=]\s*[^\s,;}]+"
)


def _read(paths: list[Path]) -> str:
    return "\n".join(path.read_text(encoding="utf-8") for path in paths)


def test_sample_ips_are_reserved_or_private_lab_ranges() -> None:
    content = _read(SAMPLE_PATHS + [RULE_PATH])

    for match in IP_PATTERN.findall(content):
        parsed = ip_address(match)
        assert is_allowed_ip(match), f"Unexpected non-synthetic IP address: {parsed}"


def test_sample_domains_are_example_or_test_domains() -> None:
    content = _read(SAMPLE_PATHS + [RULE_PATH])

    for match in DOMAIN_PATTERN.findall(content):
        candidate = match.lower()
        try:
            ip_address(candidate)
            continue
        except ValueError:
            pass

        if candidate.replace(".", "").isdigit():
            continue

        if candidate.startswith("synthetic_"):
            continue

        if candidate.endswith((".html", ".txt", ".json", ".yaml", ".md")):
            continue

        assert is_allowed_domain(candidate), f"Unexpected non-synthetic domain: {candidate}"


def test_samples_do_not_contain_credential_looking_values() -> None:
    content = _read(SAMPLE_PATHS + [RULE_PATH])
    sanitized = content
    for marker in ALLOWED_SYNTHETIC_MARKERS:
        sanitized = sanitized.replace(marker, "")

    assert CREDENTIAL_VALUE_PATTERN.search(sanitized) is None


def test_sensitive_marker_sample_uses_only_approved_markers() -> None:
    content = (ROOT / "samples" / "logs" / "sensitive_marker_events.json").read_text(
        encoding="utf-8"
    )
    markers = set(MARKER_PATTERN.findall(content))

    assert markers == ALLOWED_SYNTHETIC_MARKERS


def test_rules_file_contains_only_safe_synthetic_placeholders() -> None:
    content = RULE_PATH.read_text(encoding="utf-8")

    assert "rule_id: NET-001" in content
    assert "malware" not in content.lower()
    assert "threat intelligence indicators" in content
    assert "suspicious-lab.test" in content


def test_source_does_not_implement_live_capture_or_raw_socket_behavior() -> None:
    source_files = [path for path in (ROOT / "src").rglob("*.py") if path.is_file()]
    source = _read(source_files).lower()
    forbidden_implementation_patterns = (
        "import socket",
        "from socket import",
        "scapy",
        "import dpkt",
        "import pyshark",
        "sniff(",
        "promisc",
        "packet_inject",
        "arp_spoof",
        "mitm",
        "cap_net_raw",
        "--interface",
        "--capture",
    )

    for pattern in forbidden_implementation_patterns:
        assert pattern not in source
