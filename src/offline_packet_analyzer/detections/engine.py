"""Detection engine for local synthetic events and flow summaries."""

from __future__ import annotations

import statistics
from collections.abc import Iterable
from datetime import datetime
from ipaddress import ip_address, ip_network

from offline_packet_analyzer.flows.summary import summarize_flows
from offline_packet_analyzer.guidance.triage import guidance_for_rule
from offline_packet_analyzer.models.alert import Alert
from offline_packet_analyzer.models.event import PacketEvent
from offline_packet_analyzer.models.flow import FlowSummary
from offline_packet_analyzer.models.load_result import LoadResult
from offline_packet_analyzer.redaction.markers import APPROVED_SENSITIVE_MARKERS, REDACTION_TOKEN
from offline_packet_analyzer.redaction.redact import (
    contains_sensitive_marker,
    redact_output_structure,
)
from offline_packet_analyzer.scoring.risk import apply_scores

from .rules import DetectionRule

PRIVATE_LAB_NETWORK = ip_network("10.0.0.0/8")
DETECTION_SAFETY_NOTE = (
    "Offline synthetic detections only. No live capture or real traffic processing."
)
RISK_ORDER = {"informational": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
SEVERITY_ORDER = RISK_ORDER
DEFAULT_BEACON_MIN_EVENTS = 4
DEFAULT_BEACON_MAX_JITTER_RATIO = 0.15


def _valid_events(events: Iterable[PacketEvent]) -> list[PacketEvent]:
    return [event for event in events if event.parse_status == "valid"]


def _status_matches(event: PacketEvent, keywords: list[str]) -> bool:
    status = (event.status or "").lower()
    return any(keyword.lower() in status for keyword in keywords)


def _alert(
    rule: DetectionRule,
    evidence: str,
    event: PacketEvent | None = None,
    metadata: dict | None = None,
) -> Alert:
    return Alert(
        rule_id=rule.rule_id,
        title=rule.title,
        description=rule.description,
        severity=rule.severity,
        confidence=rule.confidence,
        category=rule.category,
        evidence=evidence,
        guidance=guidance_for_rule(rule.rule_id, rule.guidance),
        source_path=event.source_path if event else None,
        source_ip=event.source_ip if event else None,
        destination_ip=event.destination_ip if event else None,
        destination_port=event.destination_port if event else None,
        protocol=event.protocol if event else None,
        metadata=metadata or {},
    )


def _detect_repeated_connections(rule: DetectionRule, events: list[PacketEvent]) -> list[Alert]:
    grouped: dict[tuple[str, str, int | None], list[PacketEvent]] = {}
    for event in events:
        if not event.source_ip or not event.destination_ip:
            continue
        if rule.status_keywords and not _status_matches(event, rule.status_keywords):
            continue
        key = (event.source_ip, event.destination_ip, event.destination_port)
        grouped.setdefault(key, []).append(event)

    alerts = []
    threshold = rule.threshold or 2
    for key, group in grouped.items():
        if len(group) >= threshold:
            source_ip, destination_ip, destination_port = key
            alerts.append(
                _alert(
                    rule,
                    evidence=(
                        f"{len(group)} synthetic attempts from {source_ip} to "
                        f"{destination_ip}:{destination_port}"
                    ),
                    event=group[0],
                    metadata={"event_count": len(group)},
                )
            )
    return alerts


def _detect_many_destination_ports(rule: DetectionRule, events: list[PacketEvent]) -> list[Alert]:
    ports_by_source: dict[str, set[int]] = {}
    first_event: dict[str, PacketEvent] = {}
    for event in events:
        if not event.source_ip or event.destination_port is None:
            continue
        ports_by_source.setdefault(event.source_ip, set()).add(event.destination_port)
        first_event.setdefault(event.source_ip, event)

    threshold = rule.threshold or 3
    alerts = []
    for source_ip, ports in ports_by_source.items():
        if len(ports) >= threshold:
            alerts.append(
                _alert(
                    rule,
                    evidence=f"{source_ip} contacted {len(ports)} synthetic destination ports",
                    event=first_event[source_ip],
                    metadata={"destination_ports": sorted(ports)},
                )
            )
    return alerts


def _detect_suspicious_test_domain(rule: DetectionRule, events: list[PacketEvent]) -> list[Alert]:
    patterns = {pattern.lower() for pattern in rule.patterns}
    alerts = []
    for event in events:
        query = (event.query_name or event.hostname or "").lower()
        if query in patterns:
            alerts.append(
                _alert(rule, evidence=f"Synthetic query or host matched {query}", event=event)
            )
    return alerts


def _detect_high_volume_flow(rule: DetectionRule, flows: list[FlowSummary]) -> list[Alert]:
    threshold = rule.threshold or 100000
    alerts = []
    for flow in flows:
        if flow.total_bytes >= threshold:
            alerts.append(
                Alert(
                    rule_id=rule.rule_id,
                    title=rule.title,
                    description=rule.description,
                    severity=rule.severity,
                    confidence=rule.confidence,
                    category=rule.category,
                    evidence=(
                        f"Synthetic flow {flow.key.source_ip} -> {flow.key.destination_ip} "
                        f"totaled {flow.total_bytes} bytes"
                    ),
                    guidance=guidance_for_rule(rule.rule_id, rule.guidance),
                    source_ip=flow.key.source_ip,
                    destination_ip=flow.key.destination_ip,
                    destination_port=flow.key.destination_port,
                    protocol=flow.key.protocol,
                    metadata={"event_count": flow.event_count, "total_bytes": flow.total_bytes},
                )
            )
    return alerts


def _detect_unusual_destination_port(rule: DetectionRule, events: list[PacketEvent]) -> list[Alert]:
    ports = set(rule.ports)
    return [
        _alert(
            rule,
            evidence=f"Synthetic destination port {event.destination_port} matched rule list",
            event=event,
        )
        for event in events
        if event.destination_port in ports
    ]


def _detect_protocol_port_mismatch(rule: DetectionRule, events: list[PacketEvent]) -> list[Alert]:
    mismatches = {
        (str(item["protocol"]).upper(), int(item["destination_port"])) for item in rule.mismatches
    }
    alerts = []
    for event in events:
        key = ((event.protocol or "").upper(), event.destination_port)
        if key in mismatches:
            alerts.append(
                _alert(
                    rule,
                    evidence=f"Synthetic {key[0]} traffic used destination port {key[1]}",
                    event=event,
                )
            )
    return alerts


def _detect_repeated_failure_marker(rule: DetectionRule, events: list[PacketEvent]) -> list[Alert]:
    by_source: dict[str, list[PacketEvent]] = {}
    for event in events:
        if event.source_ip and _status_matches(event, rule.status_keywords):
            by_source.setdefault(event.source_ip, []).append(event)

    threshold = rule.threshold or 3
    alerts = []
    for source_ip, group in by_source.items():
        if len(group) >= threshold:
            alerts.append(
                _alert(
                    rule,
                    evidence=f"{source_ip} had {len(group)} synthetic failed status values",
                    event=group[0],
                    metadata={"event_count": len(group)},
                )
            )
    return alerts


def _detect_suspicious_user_agent(rule: DetectionRule, events: list[PacketEvent]) -> list[Alert]:
    patterns = set(rule.patterns)
    return [
        _alert(rule, evidence="Synthetic HTTP user-agent matched configured marker", event=event)
        for event in events
        if event.user_agent in patterns
    ]


def _detect_documentation_range_destination(
    rule: DetectionRule, events: list[PacketEvent]
) -> list[Alert]:
    destination_ranges = [ip_network(value) for value in rule.destination_ranges]
    alerts = []
    for event in events:
        if not event.source_ip or not event.destination_ip:
            continue
        source = ip_address(event.source_ip)
        destination = ip_address(event.destination_ip)
        if source in PRIVATE_LAB_NETWORK and any(
            destination in item for item in destination_ranges
        ):
            alerts.append(
                _alert(
                    rule,
                    evidence=(
                        f"Private lab source {event.source_ip} contacted documentation "
                        f"range destination {event.destination_ip}"
                    ),
                    event=event,
                )
            )
    return alerts


def _detect_synthetic_sensitive_marker(
    rule: DetectionRule, events: list[PacketEvent]
) -> list[Alert]:
    alerts = []
    for event in events:
        if not contains_sensitive_marker(event.raw_record):
            continue
        marker_count = sum(
            str(event.raw_record).count(marker) for marker in APPROVED_SENSITIVE_MARKERS
        )
        alerts.append(
            _alert(
                rule,
                evidence=f"Approved synthetic sensitive marker observed as {REDACTION_TOKEN}",
                event=event,
                metadata={"marker_count": marker_count},
            )
        )
    return alerts


def _parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _detect_beaconing_interval(rule: DetectionRule, events: list[PacketEvent]) -> list[Alert]:
    grouped: dict[tuple[str, str, int | None], list[tuple[datetime, PacketEvent]]] = {}
    for event in events:
        if not event.source_ip or not event.destination_ip:
            continue
        timestamp = _parse_timestamp(event.timestamp)
        if timestamp is None:
            continue
        key = (event.source_ip, event.destination_ip, event.destination_port)
        grouped.setdefault(key, []).append((timestamp, event))

    min_events = rule.min_events or DEFAULT_BEACON_MIN_EVENTS
    max_jitter_ratio = (
        rule.max_jitter_ratio
        if rule.max_jitter_ratio is not None
        else DEFAULT_BEACON_MAX_JITTER_RATIO
    )

    alerts = []
    for key, group in grouped.items():
        if len(group) < min_events:
            continue
        ordered = sorted(group, key=lambda item: item[0])
        intervals = [
            (later - earlier).total_seconds()
            for (earlier, _), (later, _) in zip(ordered, ordered[1:], strict=False)
        ]
        if not intervals or any(interval <= 0 for interval in intervals):
            continue
        mean_interval = statistics.fmean(intervals)
        jitter_ratio = statistics.pstdev(intervals) / mean_interval
        if jitter_ratio > max_jitter_ratio:
            continue

        source_ip, destination_ip, destination_port = key
        alerts.append(
            _alert(
                rule,
                evidence=(
                    f"{source_ip} contacted {destination_ip}:{destination_port} "
                    f"{len(group)} times at roughly {mean_interval:.1f}s intervals "
                    f"with {jitter_ratio:.2%} jitter"
                ),
                event=ordered[0][1],
                metadata={
                    "event_count": len(group),
                    "mean_interval_seconds": round(mean_interval, 2),
                    "jitter_ratio": round(jitter_ratio, 4),
                },
            )
        )
    return alerts


DETECTORS = {
    "repeated_connections": _detect_repeated_connections,
    "many_destination_ports": _detect_many_destination_ports,
    "suspicious_test_domain": _detect_suspicious_test_domain,
    "unusual_destination_port": _detect_unusual_destination_port,
    "protocol_port_mismatch": _detect_protocol_port_mismatch,
    "repeated_failure_marker": _detect_repeated_failure_marker,
    "suspicious_user_agent": _detect_suspicious_user_agent,
    "documentation_range_destination": _detect_documentation_range_destination,
    "synthetic_sensitive_marker": _detect_synthetic_sensitive_marker,
    "beaconing_interval": _detect_beaconing_interval,
}


def run_detections(load_result: LoadResult, rules: list[DetectionRule]) -> list[Alert]:
    """Run enabled synthetic detections over loaded events and flow summaries."""
    events = _valid_events(load_result.events)
    flows = summarize_flows(events)
    alerts: list[Alert] = []

    for rule in rules:
        if not rule.enabled:
            continue
        if rule.detector_type == "high_volume_flow":
            alerts.extend(_detect_high_volume_flow(rule, flows))
            continue
        detector = DETECTORS.get(rule.detector_type)
        if detector is not None:
            alerts.extend(detector(rule, events))

    return sorted(
        alerts,
        key=lambda alert: (
            alert.rule_id,
            alert.source_ip or "",
            alert.destination_ip or "",
            alert.destination_port if alert.destination_port is not None else -1,
            alert.evidence,
        ),
    )


def filter_alerts_by_severity(alerts: list[Alert], minimum: str | None) -> list[Alert]:
    """Return alerts at or above a minimum severity."""
    if minimum is None:
        return alerts
    minimum_rank = SEVERITY_ORDER[minimum]
    return [alert for alert in alerts if SEVERITY_ORDER.get(alert.severity, 0) >= minimum_rank]


def has_alert_at_or_above_severity(alerts: list[dict], minimum: str | None) -> bool:
    """Return whether serialized alerts meet a minimum severity."""
    if minimum is None:
        return False
    minimum_rank = SEVERITY_ORDER[minimum]
    return any(
        SEVERITY_ORDER.get(str(alert.get("severity")), 0) >= minimum_rank for alert in alerts
    )


def build_detection_output(
    load_result: LoadResult, rules: list[DetectionRule], *, min_severity: str | None = None
) -> dict:
    """Return a stable JSON-ready detection result."""
    scored_alerts = apply_scores(run_detections(load_result, rules))
    alerts = filter_alerts_by_severity(scored_alerts, min_severity)
    alert_dicts = [alert.to_dict() for alert in alerts]
    scores = [alert.score or 0 for alert in alerts]
    alerts_by_severity: dict[str, int] = {}
    alerts_by_risk_level: dict[str, int] = {}
    for alert in alerts:
        alerts_by_severity[alert.severity] = alerts_by_severity.get(alert.severity, 0) + 1
        risk_level = alert.risk_level or "informational"
        alerts_by_risk_level[risk_level] = alerts_by_risk_level.get(risk_level, 0) + 1

    highest_risk = max(
        (alert.risk_level or "informational" for alert in alerts),
        key=lambda value: RISK_ORDER.get(value, 0),
        default=None,
    )
    output = {
        "input_path": load_result.input_path,
        "files_loaded": sorted(load_result.files_loaded),
        "records_seen": load_result.records_seen,
        "events_loaded": len(load_result.events),
        "malformed_records": load_result.malformed_records,
        "rules_loaded": len(rules),
        "min_severity": min_severity,
        "alerts": alert_dicts,
        "alert_count": len(alerts),
        "alerts_by_severity": dict(sorted(alerts_by_severity.items())),
        "alerts_by_risk_level": dict(sorted(alerts_by_risk_level.items())),
        "highest_risk": highest_risk,
        "max_score": max(scores) if scores else 0,
        "average_score": round(sum(scores) / len(scores), 2) if scores else 0,
        "errors": load_result.errors,
        "safety_note": DETECTION_SAFETY_NOTE,
    }
    return redact_output_structure(output)


def format_detection_output_text(output: dict) -> str:
    """Format detection output as deterministic human-readable text."""
    lines = [
        "Offline Packet Analyzer Detections",
        f"Safety: {output['safety_note']}",
        f"Input: {output['input_path']}",
        f"Records seen: {output['records_seen']}",
        f"Events loaded: {output['events_loaded']}",
        f"Malformed records: {output['malformed_records']}",
        f"Alerts: {output['alert_count']}",
    ]
    for alert in output["alerts"]:
        lines.append(
            "- "
            f"{alert['rule_id']} {alert['severity']} "
            f"risk={alert.get('risk_level') or 'unknown'} "
            f"score={alert.get('score') if alert.get('score') is not None else 'unknown'} "
            f"{alert.get('source_ip') or 'unknown'} -> "
            f"{alert.get('destination_ip') or 'unknown'} "
            f"{alert['evidence']}"
        )
    return "\n".join(lines)
