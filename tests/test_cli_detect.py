import json
from pathlib import Path

from offline_packet_analyzer.cli import build_parser, main

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"


def test_cli_help_includes_detect_without_live_capture_flags() -> None:
    help_text = build_parser().format_help()

    assert "detect" in help_text
    assert "--interface" not in help_text
    assert "--capture" not in help_text


def test_cli_detect_json_output(capsys) -> None:
    exit_code = main(["detect", "--input", str(SAMPLES), "--format", "json"])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert exit_code == 0
    assert payload["input_path"] == str(SAMPLES)
    assert payload["alert_count"] >= 1
    assert {alert["rule_id"] for alert in payload["alerts"]} >= {"NET-001", "DNS-001"}
    assert all("score" in alert for alert in payload["alerts"])


def test_cli_detect_text_output(capsys) -> None:
    exit_code = main(["detect", "--input", str(SAMPLES), "--format", "text"])

    captured = capsys.readouterr()

    assert exit_code == 0
    assert "Offline Packet Analyzer Detections" in captured.out
    assert "Alerts:" in captured.out


def test_cli_detect_invalid_input_failure(capsys) -> None:
    exit_code = main(["detect", "--input", str(ROOT / "missing"), "--format", "json"])

    captured = capsys.readouterr()

    assert exit_code != 0
    assert "does not exist" in captured.err


def test_cli_detect_invalid_rule_file_failure(tmp_path: Path, capsys) -> None:
    rule_file = tmp_path / "rules.yaml"
    rule_file.write_text("rules: [{}]", encoding="utf-8")

    exit_code = main(
        [
            "detect",
            "--input",
            str(SAMPLES),
            "--rules",
            str(rule_file),
            "--format",
            "json",
        ]
    )

    captured = capsys.readouterr()

    assert exit_code != 0
    assert "missing required fields" in captured.err
