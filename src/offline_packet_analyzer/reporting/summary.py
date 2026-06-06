"""Report assembly for offline synthetic analysis results."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from offline_packet_analyzer.detections.engine import build_detection_output
from offline_packet_analyzer.detections.rules import DetectionRule
from offline_packet_analyzer.flows.summary import build_analysis_summary
from offline_packet_analyzer.models.load_result import LoadResult
from offline_packet_analyzer.redaction.markers import REDACTION_TOKEN
from offline_packet_analyzer.redaction.redact import redact_output_structure

SCHEMA_VERSION = "1.0"
TOOL_NAME = "offline-network-packet-analyzer-lab"
SAFETY_SCOPE = {
    "offline_only": True,
    "synthetic_data_only": True,
    "live_sniffing": False,
    "packet_capture": False,
    "real_traffic": False,
    "credential_handling": "not_performed",
}
LIMITATIONS = [
    "This report analyzes local synthetic samples only.",
    "This report is not based on live sniffing or packet capture.",
    "This report does not analyze real traffic.",
    "This report does not perform credential extraction.",
    "Risk scores are deterministic lab scoring values, not production risk ratings.",
]


def _redaction_summary(report: dict[str, Any]) -> dict[str, Any]:
    serialized = str(report)
    redaction_count = serialized.count(REDACTION_TOKEN)
    return {
        "redaction_token": REDACTION_TOKEN,
        "redaction_count": redaction_count,
        "raw_sensitive_markers_present": False,
    }


def build_report_data(
    load_result: LoadResult,
    rules: list[DetectionRule],
    *,
    min_severity: str | None = None,
) -> dict[str, Any]:
    """Build a redacted report-ready dictionary."""
    analysis_summary = build_analysis_summary(load_result)
    detection_output = build_detection_output(load_result, rules, min_severity=min_severity)
    flows = analysis_summary["flows"]

    report = {
        "schema_version": SCHEMA_VERSION,
        "tool_name": TOOL_NAME,
        "generated_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
        "safety_scope": SAFETY_SCOPE,
        "input_path": load_result.input_path,
        "files_loaded": sorted(load_result.files_loaded),
        "records_seen": load_result.records_seen,
        "events_loaded": len(load_result.events),
        "malformed_records": load_result.malformed_records,
        "skipped_files": sorted(load_result.skipped_files),
        "flow_summary": {
            "total_flows": analysis_summary["total_flows"],
            "top_talkers": analysis_summary["top_talkers"],
            "top_flows": sorted(
                flows,
                key=lambda item: (-int(item["total_bytes"]), item["key"]["source_ip"]),
            )[:5],
        },
        "protocol_summary": {
            "protocol_counts": analysis_summary["protocol_counts"],
            "destination_port_counts": analysis_summary["destination_port_counts"],
            "top_sources": analysis_summary["top_sources"],
            "top_destinations": analysis_summary["top_destinations"],
        },
        "detection_summary": {
            "rules_loaded": detection_output["rules_loaded"],
            "min_severity": detection_output["min_severity"],
            "alert_count": detection_output["alert_count"],
            "alerts_by_severity": detection_output["alerts_by_severity"],
            "alerts_by_risk_level": detection_output["alerts_by_risk_level"],
            "highest_risk": detection_output["highest_risk"],
            "max_score": detection_output["max_score"],
            "average_score": detection_output["average_score"],
        },
        "alerts": detection_output["alerts"],
        "redaction_summary": {},
        "limitations": LIMITATIONS,
    }
    report["redaction_summary"] = _redaction_summary(report)
    return redact_output_structure(report)
