"""Validation helpers for local synthetic sample files and records."""

from __future__ import annotations

import re
from ipaddress import ip_address
from pathlib import Path
from typing import Any

from offline_packet_analyzer.safety import (
    ALLOWED_SYNTHETIC_MARKERS,
    MAX_SAMPLE_FILE_BYTES,
    SUPPORTED_SAMPLE_EXTENSIONS,
    is_allowed_domain,
    is_allowed_ip,
)

BINARY_CAPTURE_SUFFIXES = frozenset({".pcap", ".pcapng", ".cap"})
FORBIDDEN_FILE_NAMES = frozenset({"capture.py", "sniffer.py"})
CREDENTIAL_VALUE_PATTERN = re.compile(
    r"(?i)\b(?:password|passwd|pwd|token|secret|api[_-]?key)\s*[:=]\s*[^\s,;}]+"
)
SYNTHETIC_MARKER_PATTERN = re.compile(r"\bSYNTHETIC_[A-Z_]+_MARKER\b")


def is_relative_to(path: Path, root: Path) -> bool:
    """Return whether path is contained by root after resolution."""
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def validate_ip_allowed(value: str | None) -> list[str]:
    """Validate that an optional IP address is in an allowed synthetic range."""
    if value in (None, ""):
        return []
    return [] if is_allowed_ip(str(value)) else [f"IP address is not allowed: {value}"]


def validate_domain_allowed(value: str | None) -> list[str]:
    """Validate that an optional domain uses an approved synthetic suffix."""
    if value in (None, ""):
        return []
    return [] if is_allowed_domain(str(value)) else [f"Domain is not allowed: {value}"]


def validate_packet_event(record: dict[str, Any]) -> list[str]:
    """Validate a normalized synthetic event record."""
    errors: list[str] = []

    if record.get("synthetic_marker") is not True:
        errors.append("synthetic_marker must be true")

    errors.extend(validate_ip_allowed(record.get("source_ip")))
    errors.extend(validate_ip_allowed(record.get("destination_ip")))
    errors.extend(validate_domain_allowed(record.get("hostname")))
    errors.extend(validate_domain_allowed(record.get("query_name")))

    protocol = str(record.get("protocol", "")).upper()
    if protocol in {"TCP", "UDP"}:
        if not record.get("destination_ip"):
            errors.append("destination_ip is required for TCP/UDP records")
        if record.get("source_port") is None:
            errors.append("source_port is required for TCP/UDP records")
        if record.get("destination_port") is None:
            errors.append("destination_port is required for TCP/UDP records")

    for field_name in ("source_port", "destination_port", "byte_count"):
        value = record.get(field_name)
        if (
            value is not None
            and not isinstance(value, int)
            and not (isinstance(value, str) and value.isdecimal())
        ):
            errors.append(f"{field_name} must be an integer when present")

    text = str(record)
    sanitized = text
    for marker in ALLOWED_SYNTHETIC_MARKERS:
        sanitized = sanitized.replace(marker, "")

    if CREDENTIAL_VALUE_PATTERN.search(sanitized):
        errors.append("credential-looking value is not allowed")

    markers = set(SYNTHETIC_MARKER_PATTERN.findall(text))
    unexpected_markers = markers - ALLOWED_SYNTHETIC_MARKERS
    if unexpected_markers:
        errors.append(f"unsupported synthetic marker: {sorted(unexpected_markers)}")

    return errors


def validate_loaded_events(events: list[Any]) -> list[str]:
    """Validate loaded event objects at a collection level."""
    errors: list[str] = []
    for index, event in enumerate(events):
        raw_record = getattr(event, "raw_record", {})
        if isinstance(raw_record, dict):
            errors.extend(f"event {index}: {error}" for error in validate_packet_event(raw_record))
        elif getattr(event, "parse_status", "") != "malformed":
            errors.append(f"event {index}: raw_record must be a mapping or malformed text")
    return errors


def validate_sample_file(path: Path) -> list[str]:
    """Validate a local synthetic sample file before loading."""
    errors: list[str] = []
    resolved = path.resolve()

    if not resolved.exists():
        return [f"Input path does not exist: {path}"]
    if not resolved.is_file():
        return [f"Input path is not a file: {path}"]

    suffix = resolved.suffix.lower()
    if suffix in BINARY_CAPTURE_SUFFIXES:
        errors.append(f"Packet capture files are not accepted: {path}")
    if suffix not in SUPPORTED_SAMPLE_EXTENSIONS:
        errors.append(f"Unsupported sample extension: {suffix}")
    if resolved.name.lower() in FORBIDDEN_FILE_NAMES:
        errors.append(f"Live-capture related file name is not allowed: {resolved.name}")
    if resolved.stat().st_size > MAX_SAMPLE_FILE_BYTES:
        errors.append(f"Sample file is too large: {path}")

    try:
        content = resolved.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        errors.append(f"Sample file is not UTF-8 text-readable: {path}")
        return errors

    sanitized = content
    for marker in ALLOWED_SYNTHETIC_MARKERS:
        sanitized = sanitized.replace(marker, "")

    if CREDENTIAL_VALUE_PATTERN.search(sanitized):
        errors.append(f"Sample file contains credential-looking content: {path}")

    return errors


def validate_input_path(path: Path) -> list[str]:
    """Validate an explicit local file or directory input path."""
    if not str(path).strip():
        return ["Input path is required"]

    resolved = path.resolve()
    if ".." in path.parts:
        return [f"Path traversal is not allowed: {path}"]
    if not resolved.exists():
        return [f"Input path does not exist: {path}"]
    if not (resolved.is_file() or resolved.is_dir()):
        return [f"Input path must be a file or directory: {path}"]
    if resolved.is_file() and resolved.suffix.lower() in BINARY_CAPTURE_SUFFIXES:
        return [f"Packet capture files are not accepted: {path}"]

    if resolved.is_file() and not is_relative_to(resolved, resolved.parent):
        return [f"Input path is outside its requested root: {path}"]

    for match in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", str(path)):
        try:
            ip_address(match)
        except ValueError:
            continue

    return []
