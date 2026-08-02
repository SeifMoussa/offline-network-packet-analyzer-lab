import json
from pathlib import Path

from offline_packet_analyzer.cli import build_parser, main

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"


def test_cli_help_includes_summarize_without_live_capture_flags() -> None:
    help_text = build_parser().format_help()

    assert "summarize" in help_text
    assert "--interface" not in help_text
    assert "--capture" not in help_text


def test_summarize_cli_json_output(capsys) -> None:
    exit_code = main(["summarize", "--input", str(SAMPLES), "--format", "json"])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert exit_code == 0
    assert payload["input_path"] == str(SAMPLES)
    assert payload["records_seen"] == 33
    assert payload["events_loaded"] == 33
    assert payload["malformed_records"] == 3
    assert payload["total_flows"] >= 1
    assert payload["protocol_counts"]["TCP"] >= 1
    assert "Offline synthetic analysis only" in payload["safety_note"]


def test_summarize_cli_text_output(capsys) -> None:
    exit_code = main(["summarize", "--input", str(SAMPLES), "--format", "text"])

    captured = capsys.readouterr()

    assert exit_code == 0
    assert "Offline Packet Analyzer Summary" in captured.out
    assert "Total flows:" in captured.out
    assert "Top talkers:" in captured.out


def test_summarize_cli_invalid_input_failure(capsys) -> None:
    exit_code = main(["summarize", "--input", str(ROOT / "missing"), "--format", "json"])

    captured = capsys.readouterr()

    assert exit_code != 0
    assert "does not exist" in captured.err
