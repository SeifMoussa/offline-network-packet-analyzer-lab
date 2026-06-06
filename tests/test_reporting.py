import json
from pathlib import Path

from offline_packet_analyzer.detections.rules import load_default_rules
from offline_packet_analyzer.loaders.inventory import load_input
from offline_packet_analyzer.reporting.json_report import generate_json_report
from offline_packet_analyzer.reporting.markdown_report import generate_markdown_report
from offline_packet_analyzer.reporting.summary import build_report_data

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"
RAW_MARKERS = (
    "SYNTHETIC_PASSWORD_MARKER",
    "SYNTHETIC_TOKEN_MARKER",
    "SYNTHETIC_SECRET_MARKER",
)


def report_data() -> dict:
    return build_report_data(load_input(SAMPLES), load_default_rules())


def test_json_report_structure() -> None:
    data = report_data()
    payload = json.loads(generate_json_report(data))

    assert payload["schema_version"] == "1.0"
    assert payload["tool_name"] == "offline-network-packet-analyzer-lab"
    assert payload["safety_scope"]["offline_only"] is True
    assert payload["records_seen"] == 24
    assert "flow_summary" in payload
    assert "protocol_summary" in payload
    assert "detection_summary" in payload
    assert payload["alerts"]


def test_json_report_alert_entries_include_score_and_risk() -> None:
    payload = json.loads(generate_json_report(report_data()))

    alert = payload["alerts"][0]
    assert "score" in alert
    assert "risk_level" in alert
    assert "scoring_reason" in alert
    assert "synthetic" in alert


def test_markdown_report_structure_and_safety_disclaimer() -> None:
    markdown = generate_markdown_report(report_data())

    assert "# Offline Packet Analysis Report" in markdown
    assert "Offline synthetic analysis only" in markdown
    assert "does not perform live sniffing" in markdown
    assert "packet capture" in markdown
    assert "credential extraction" in markdown
    assert "## Detailed Alerts" in markdown
    assert "## Redaction Summary" in markdown


def test_reports_include_redaction_and_no_raw_markers() -> None:
    data = report_data()
    outputs = (generate_json_report(data), generate_markdown_report(data))

    for output in outputs:
        assert "[REDACTED]" in output
        for marker in RAW_MARKERS:
            assert marker not in output


def test_report_does_not_claim_live_capture() -> None:
    markdown = generate_markdown_report(report_data()).lower()

    assert "offline synthetic analysis only" in markdown
    assert "does not perform live sniffing" in markdown
    assert "does not analyze real traffic" in markdown


def test_report_contains_no_realistic_secret_patterns() -> None:
    output = generate_json_report(report_data()).lower()

    assert "password=" not in output
    assert "token=" not in output
    assert "api_key=" not in output
