"""Markdown report generation."""

from __future__ import annotations

from typing import Any


def _table_row(values: list[Any]) -> str:
    return "| " + " | ".join(str(value) if value is not None else "" for value in values) + " |"


def generate_markdown_report(report_data: dict[str, Any]) -> str:
    """Generate a deterministic Markdown report string."""
    detection = report_data["detection_summary"]
    protocol = report_data["protocol_summary"]
    flow = report_data["flow_summary"]
    redaction = report_data["redaction_summary"]

    lines = [
        "# Offline Packet Analysis Report",
        "",
        f"Generated: `{report_data['generated_at']}`",
        "",
        "## Safety Scope",
        "",
        "Offline synthetic analysis only. This report uses local synthetic samples only.",
        (
            "It does not perform live sniffing, packet capture, real traffic analysis, "
            "or credential extraction."
        ),
        "",
        "## Input Summary",
        "",
        f"- Input path: `{report_data['input_path']}`",
        f"- Files loaded: `{len(report_data['files_loaded'])}`",
        f"- Records seen: `{report_data['records_seen']}`",
        f"- Events loaded: `{report_data['events_loaded']}`",
        f"- Malformed records: `{report_data['malformed_records']}`",
        f"- Skipped files: `{len(report_data['skipped_files'])}`",
        "",
        "## Flow And Protocol Summary",
        "",
        f"- Total flows: `{flow['total_flows']}`",
        f"- Protocol counts: `{protocol['protocol_counts']}`",
        f"- Destination port counts: `{protocol['destination_port_counts']}`",
        "",
        "### Top Talkers",
        "",
        _table_row(["Source", "Destination", "Bytes", "Events"]),
        _table_row(["---", "---", "---:", "---:"]),
    ]

    for talker in flow["top_talkers"]:
        lines.append(
            _table_row(
                [
                    talker["source_ip"],
                    talker["destination_ip"],
                    talker["total_bytes"],
                    talker["event_count"],
                ]
            )
        )

    lines.extend(
        [
            "",
            "## Alert Summary",
            "",
            f"- Alert count: `{detection['alert_count']}`",
            f"- Highest risk: `{detection['highest_risk']}`",
            f"- Max score: `{detection['max_score']}`",
            f"- Average score: `{detection['average_score']}`",
            f"- Alerts by severity: `{detection['alerts_by_severity']}`",
            f"- Alerts by risk level: `{detection['alerts_by_risk_level']}`",
            "",
            "## Detailed Alerts",
            "",
            _table_row(
                [
                    "Rule",
                    "Severity",
                    "Risk",
                    "Score",
                    "Source",
                    "Destination",
                    "Evidence",
                ]
            ),
            _table_row(["---", "---", "---", "---:", "---", "---", "---"]),
        ]
    )

    for alert in report_data["alerts"]:
        lines.append(
            _table_row(
                [
                    alert["rule_id"],
                    alert["severity"],
                    alert["risk_level"],
                    alert["score"],
                    alert.get("source_ip") or "",
                    alert.get("destination_ip") or "",
                    alert["evidence"],
                ]
            )
        )

    lines.extend(["", "## Triage Guidance", ""])
    seen_guidance = set()
    for alert in report_data["alerts"]:
        key = (alert["rule_id"], alert["guidance"])
        if key in seen_guidance:
            continue
        seen_guidance.add(key)
        lines.append(f"- `{alert['rule_id']}`: {alert['guidance']}")

    lines.extend(
        [
            "",
            "## Redaction Summary",
            "",
            f"- Redaction token: `{redaction['redaction_token']}`",
            f"- Redaction count: `{redaction['redaction_count']}`",
            f"- Raw sensitive markers present: `{redaction['raw_sensitive_markers_present']}`",
            "",
            "## Limitations",
            "",
        ]
    )
    lines.extend(f"- {item}" for item in report_data["limitations"])
    return "\n".join(lines) + "\n"
