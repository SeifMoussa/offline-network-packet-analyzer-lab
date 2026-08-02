import json
from pathlib import Path

import pytest

from offline_packet_analyzer.cli import main

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"
RAW_MARKERS = (
    "SYNTHETIC_PASSWORD_MARKER",
    "SYNTHETIC_TOKEN_MARKER",
    "SYNTHETIC_SECRET_MARKER",
)


def test_help_texts_include_offline_safety_boundaries(capsys) -> None:
    commands = [
        [],
        ["inventory"],
        ["validate-samples"],
        ["summarize"],
        ["detect"],
        ["report"],
    ]

    for command in commands:
        with pytest.raises(SystemExit) as exc_info:
            main([*command, "--help"])
        captured = capsys.readouterr()
        assert exc_info.value.code == 0
        assert "offline" in captured.out.lower()
        assert "synthetic" in captured.out.lower()
        assert "live sniffing" in captured.out.lower()
        assert "packet capture" in captured.out.lower()
        assert "credential extraction" in captured.out.lower()


def test_cli_missing_required_input_fails() -> None:
    with pytest.raises(SystemExit):
        main(["summarize", "--format", "json"])


def test_cli_report_missing_required_output_fails() -> None:
    with pytest.raises(SystemExit):
        main(["report", "--input", str(SAMPLES), "--format", "json"])


def test_cli_traversal_like_input_rejected(capsys) -> None:
    exit_code = main(["summarize", "--input", str(SAMPLES / ".."), "--format", "json"])

    captured = capsys.readouterr()

    assert exit_code == 2
    assert "Path traversal is not allowed" in captured.err


def test_cli_unsupported_single_file_extension_is_controlled(tmp_path: Path, capsys) -> None:
    sample = tmp_path / "unsupported.log"
    sample.write_text("synthetic local placeholder\n", encoding="utf-8")

    exit_code = main(["inventory", "--input", str(sample), "--format", "json"])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert exit_code == 1
    assert payload["events_loaded"] == 0
    assert payload["skipped_files"] == []
    assert str(sample.resolve()) in payload["errors"]


def test_cli_invalid_rules_path_fails(capsys) -> None:
    exit_code = main(
        [
            "detect",
            "--input",
            str(SAMPLES),
            "--rules",
            str(ROOT / "rules" / "missing.yaml"),
        ]
    )

    captured = capsys.readouterr()

    assert exit_code == 2
    assert "does not exist" in captured.err


def test_cli_invalid_rules_yaml_fails_safely(tmp_path: Path, capsys) -> None:
    rules = tmp_path / "rules.yaml"
    rules.write_text("rules:\n  - rule_id: NET-X\n", encoding="utf-8")

    exit_code = main(["detect", "--input", str(SAMPLES), "--rules", str(rules)])

    captured = capsys.readouterr()

    assert exit_code == 2
    assert "missing required field" in captured.err


def test_cli_invalid_min_severity_fails() -> None:
    with pytest.raises(SystemExit):
        main(["detect", "--input", str(SAMPLES), "--min-severity", "severe"])


def test_cli_invalid_fail_on_fails() -> None:
    with pytest.raises(SystemExit):
        main(["detect", "--input", str(SAMPLES), "--fail-on", "severe"])


def test_cli_min_severity_filters_detect_json(capsys) -> None:
    exit_code = main(
        ["detect", "--input", str(SAMPLES), "--format", "json", "--min-severity", "high"]
    )

    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert exit_code == 0
    assert payload["min_severity"] == "high"
    assert payload["alert_count"] == 1
    assert {alert["severity"] for alert in payload["alerts"]} == {"high"}


def test_cli_report_min_severity_filters_alerts(tmp_path: Path) -> None:
    output = tmp_path / "report.json"

    exit_code = main(
        [
            "report",
            "--input",
            str(SAMPLES),
            "--output",
            str(output),
            "--format",
            "json",
            "--min-severity",
            "high",
        ]
    )

    payload = json.loads(output.read_text(encoding="utf-8"))

    assert exit_code == 0
    assert payload["detection_summary"]["min_severity"] == "high"
    assert {alert["severity"] for alert in payload["alerts"]} == {"high"}


def test_cli_fail_on_high_returns_nonzero_when_high_alerts_exist(capsys) -> None:
    exit_code = main(["detect", "--input", str(SAMPLES), "--format", "json", "--fail-on", "high"])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert exit_code == 1
    assert payload["alerts_by_severity"]["high"] >= 1


def test_cli_fail_on_critical_returns_zero_when_no_critical_alerts(capsys) -> None:
    exit_code = main(
        ["detect", "--input", str(SAMPLES), "--format", "json", "--fail-on", "critical"]
    )

    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert exit_code == 0
    assert "critical" not in payload["alerts_by_severity"]


def test_cli_report_output_traversal_rejected(capsys) -> None:
    exit_code = main(
        [
            "report",
            "--input",
            str(SAMPLES),
            "--output",
            str(Path("reports") / ".." / "report.json"),
            "--format",
            "json",
        ]
    )

    captured = capsys.readouterr()

    assert exit_code == 2
    assert "Output path traversal is not allowed" in captured.err


def test_empty_directory_behavior_is_controlled(tmp_path: Path, capsys) -> None:
    exit_code = main(["summarize", "--input", str(tmp_path), "--format", "json"])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert exit_code == 0
    assert payload["events_loaded"] == 0
    assert payload["records_seen"] == 0
    assert payload["total_flows"] == 0


def test_no_recursive_limits_directory_scan(tmp_path: Path, capsys) -> None:
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "event.json").write_text(
        '[{"timestamp":"2026-06-05T00:00:00Z","source_ip":"10.0.0.1",'
        '"destination_ip":"192.0.2.1","source_port":40000,"destination_port":443,'
        '"protocol":"TCP","byte_count":1,"status":"allowed","synthetic_marker":true}]',
        encoding="utf-8",
    )

    exit_code = main(["inventory", "--input", str(tmp_path), "--format", "json", "--no-recursive"])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert exit_code == 0
    assert payload["events_loaded"] == 0
    assert payload["records_seen"] == 0


def test_detect_and_report_outputs_do_not_expose_raw_markers(tmp_path: Path, capsys) -> None:
    report = tmp_path / "report.md"

    assert main(["detect", "--input", str(SAMPLES), "--format", "text"]) == 0
    detect_output = capsys.readouterr().out
    assert (
        main(["report", "--input", str(SAMPLES), "--output", str(report), "--format", "markdown"])
        == 0
    )
    report_output = report.read_text(encoding="utf-8")

    assert "[REDACTED]" in detect_output
    assert "[REDACTED]" in report_output
    for marker in RAW_MARKERS:
        assert marker not in detect_output
        assert marker not in report_output
