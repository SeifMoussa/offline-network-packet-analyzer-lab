from pathlib import Path

from offline_packet_analyzer.detections.engine import build_detection_output, run_detections
from offline_packet_analyzer.detections.rules import DetectionRule, load_default_rules
from offline_packet_analyzer.loaders.inventory import load_input
from offline_packet_analyzer.models.alert import Alert

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"
LOGS = SAMPLES / "logs"


def alerts_for(path: Path) -> list[Alert]:
    return run_detections(load_input(path), load_default_rules())


def rule_ids(alerts: list[Alert]) -> set[str]:
    return {alert.rule_id for alert in alerts}


def test_repeated_connection_detection() -> None:
    alerts = alerts_for(LOGS / "suspicious_connections.json")

    assert "NET-001" in rule_ids(alerts)


def test_many_destination_ports_detection() -> None:
    alerts = alerts_for(LOGS / "suspicious_connections.json")

    assert "NET-002" in rule_ids(alerts)


def test_suspicious_test_dns_detection() -> None:
    alerts = alerts_for(LOGS / "dns_queries.csv")

    assert "DNS-001" in rule_ids(alerts)


def test_high_volume_flow_detection() -> None:
    alerts = alerts_for(LOGS / "mixed_packet_events.json")

    assert "FLOW-001" in rule_ids(alerts)


def test_unusual_destination_port_detection() -> None:
    alerts = alerts_for(LOGS / "suspicious_connections.json")

    assert "NET-003" in rule_ids(alerts)


def test_protocol_port_mismatch_detection() -> None:
    alerts = alerts_for(LOGS / "mixed_packet_events.json")

    assert "NET-004" in rule_ids(alerts)


def test_repeated_failed_status_detection() -> None:
    alerts = alerts_for(LOGS / "suspicious_connections.json")

    assert "NET-005" in rule_ids(alerts)


def test_suspicious_http_user_agent_detection() -> None:
    alerts = alerts_for(LOGS / "http_events.txt")

    assert "HTTP-001" in rule_ids(alerts)


def test_internal_to_documentation_range_destination_detection() -> None:
    alerts = alerts_for(LOGS / "normal_traffic.json")

    assert "NET-006" in rule_ids(alerts)


def test_clean_normal_sample_has_no_high_or_critical_alerts() -> None:
    alerts = alerts_for(LOGS / "normal_traffic.json")

    assert all(alert.severity not in {"high", "critical"} for alert in alerts)


def test_malformed_records_are_skipped_safely() -> None:
    alerts = alerts_for(LOGS / "malformed_records.json")

    assert alerts == []


def test_deterministic_alert_ordering() -> None:
    first = [alert.to_dict() for alert in alerts_for(SAMPLES)]
    second = [alert.to_dict() for alert in alerts_for(SAMPLES)]

    assert first == second
    assert [alert["rule_id"] for alert in first] == sorted(alert["rule_id"] for alert in first)


def test_disabled_rules_are_skipped() -> None:
    rule = DetectionRule(
        rule_id="DNS-DISABLED",
        title="Disabled",
        description="Disabled",
        severity="low",
        confidence="low",
        category="dns",
        enabled=False,
        detector_type="suspicious_test_domain",
        guidance="Disabled",
        patterns=["suspicious-lab.test"],
    )

    assert run_detections(load_input(LOGS / "dns_queries.csv"), [rule]) == []


def test_alert_to_dict_shape() -> None:
    alert = alerts_for(LOGS / "dns_queries.csv")[0]
    data = alert.to_dict()

    assert data["rule_id"]
    assert data["title"]
    assert data["synthetic"] is True
    assert "score" in data


def test_detection_output_shape_has_scores() -> None:
    output = build_detection_output(load_input(SAMPLES), load_default_rules())

    assert output["alert_count"] == len(output["alerts"])
    assert "safety_note" in output
    assert all("score" in alert for alert in output["alerts"])
    assert "alerts_by_risk_level" in output


def test_synthetic_sensitive_marker_detection_is_redacted() -> None:
    alerts = alerts_for(LOGS / "sensitive_marker_events.json")
    sensitive_alerts = [alert for alert in alerts if alert.rule_id == "SENS-001"]

    assert len(sensitive_alerts) == 3
    for alert in sensitive_alerts:
        data = alert.to_dict()
        assert "[REDACTED]" in data["evidence"]
        assert "SYNTHETIC_PASSWORD_MARKER" not in str(data)
        assert "SYNTHETIC_TOKEN_MARKER" not in str(data)
        assert "SYNTHETIC_SECRET_MARKER" not in str(data)
