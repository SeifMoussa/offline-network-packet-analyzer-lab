"""Redaction helpers for approved synthetic sensitive markers."""

from __future__ import annotations

from dataclasses import is_dataclass
from typing import Any

from offline_packet_analyzer.redaction.markers import APPROVED_SENSITIVE_MARKERS, REDACTION_TOKEN


def contains_sensitive_marker(value: Any) -> bool:
    """Return whether a value contains an approved synthetic marker."""
    if isinstance(value, str):
        return any(marker in value for marker in APPROVED_SENSITIVE_MARKERS)
    if isinstance(value, dict):
        return any(contains_sensitive_marker(item) for item in value.values())
    if isinstance(value, list | tuple | set):
        return any(contains_sensitive_marker(item) for item in value)
    return False


def redact_sensitive_value(value: Any) -> Any:
    """Redact approved synthetic marker values from strings."""
    if not isinstance(value, str):
        return value
    redacted = value
    for marker in APPROVED_SENSITIVE_MARKERS:
        redacted = redacted.replace(marker, REDACTION_TOKEN)
    return redacted


def redact_record(record: Any) -> Any:
    """Return a redacted copy of a nested record-like structure."""
    if isinstance(record, str):
        return redact_sensitive_value(record)
    if isinstance(record, dict):
        return {key: redact_record(value) for key, value in record.items()}
    if isinstance(record, list):
        return [redact_record(value) for value in record]
    if isinstance(record, tuple):
        return tuple(redact_record(value) for value in record)
    if isinstance(record, set):
        return {redact_record(value) for value in record}
    return record


def redact_alert(alert_or_dict: Any) -> dict[str, Any]:
    """Return a redacted alert dictionary."""
    if isinstance(alert_or_dict, dict):
        return redact_record(alert_or_dict)
    if is_dataclass(alert_or_dict) and hasattr(alert_or_dict, "to_dict"):
        return redact_record(alert_or_dict.to_dict())
    raise TypeError("alert_or_dict must be an Alert or dictionary")


def redact_output_structure(data: Any) -> Any:
    """Return a redacted copy of arbitrary output data."""
    return redact_record(data)
