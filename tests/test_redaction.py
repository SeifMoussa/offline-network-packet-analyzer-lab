from copy import deepcopy

from offline_packet_analyzer.models.alert import Alert
from offline_packet_analyzer.redaction.markers import REDACTION_TOKEN
from offline_packet_analyzer.redaction.redact import (
    contains_sensitive_marker,
    redact_alert,
    redact_output_structure,
    redact_record,
    redact_sensitive_value,
)

RAW_MARKERS = (
    "SYNTHETIC_PASSWORD_MARKER",
    "SYNTHETIC_TOKEN_MARKER",
    "SYNTHETIC_SECRET_MARKER",
)


def test_approved_sensitive_markers_are_detected() -> None:
    for marker in RAW_MARKERS:
        assert contains_sensitive_marker(marker)


def test_sensitive_values_are_redacted() -> None:
    assert redact_sensitive_value(f"value {RAW_MARKERS[0]}") == f"value {REDACTION_TOKEN}"


def test_nested_structures_are_redacted_without_mutation() -> None:
    original = {"items": [{"note": RAW_MARKERS[1]}], "safe": "value"}
    snapshot = deepcopy(original)

    redacted = redact_record(original)

    assert original == snapshot
    assert redacted["items"][0]["note"] == REDACTION_TOKEN
    assert RAW_MARKERS[1] not in str(redacted)


def test_redact_alert_redacts_alert_dict() -> None:
    alert = Alert(
        rule_id="SENS-001",
        title="Synthetic marker",
        description="Synthetic marker",
        severity="medium",
        confidence="high",
        category="synthetic-redaction",
        evidence=RAW_MARKERS[2],
        guidance="Review synthetic sample.",
    )

    redacted = redact_alert(alert)

    assert redacted["evidence"] == REDACTION_TOKEN
    assert RAW_MARKERS[2] not in str(redacted)


def test_redact_output_structure_handles_non_strings() -> None:
    data = {"count": 3, "marker": RAW_MARKERS[0], "values": [None, True]}

    redacted = redact_output_structure(data)

    assert redacted["count"] == 3
    assert redacted["marker"] == REDACTION_TOKEN
    assert redacted["values"] == [None, True]
