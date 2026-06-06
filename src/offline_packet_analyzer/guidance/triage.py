"""Defensive triage guidance for synthetic alerts."""

from __future__ import annotations

TRIAGE_GUIDANCE = {
    "NET-001": (
        "Review firewall or endpoint telemetry for the synthetic source and confirm whether "
        "repeated connection attempts are expected."
    ),
    "NET-002": (
        "Validate the synthetic source host inventory and confirm whether the observed "
        "destination ports are approved."
    ),
    "DNS-001": (
        "Review synthetic DNS logs and confirm whether the .test query was intentionally "
        "included in the lab scenario."
    ),
    "FLOW-001": (
        "Compare the synthetic byte volume with expected lab behavior and review proxy or "
        "endpoint telemetry if available."
    ),
    "NET-003": (
        "Confirm whether the unusual destination port is documented for the synthetic service."
    ),
    "NET-004": (
        "Validate whether the protocol and port pairing is expected for the synthetic sample."
    ),
    "NET-005": (
        "Review repeated failed status values and confirm whether they match expected lab activity."
    ),
    "HTTP-001": (
        "Review synthetic HTTP metadata and confirm whether the user-agent marker was expected."
    ),
    "NET-006": (
        "Confirm that documentation-range destinations are expected synthetic lab references."
    ),
    "SENS-001": (
        "Confirm whether the redacted synthetic marker was intentionally placed, then remove "
        "exposed test data from synthetic samples if it is not needed."
    ),
}


def guidance_for_rule(rule_id: str, fallback: str = "") -> str:
    """Return safe defensive guidance for a rule ID."""
    return TRIAGE_GUIDANCE.get(rule_id, fallback)
