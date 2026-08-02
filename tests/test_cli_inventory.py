import json
from pathlib import Path

from offline_packet_analyzer.cli import main

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"


def test_cli_inventory_json_output(capsys) -> None:
    exit_code = main(["inventory", "--input", str(SAMPLES), "--format", "json"])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert exit_code == 0
    assert payload["input_path"] == str(SAMPLES)
    assert payload["records_seen"] >= 1
    assert "errors" in payload


def test_cli_validate_samples_success(capsys) -> None:
    exit_code = main(["validate-samples", "--input", str(SAMPLES)])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)

    assert exit_code == 0
    assert payload["valid"] is True
    assert payload["malformed_records"] >= 1


def test_cli_invalid_input_failure(capsys) -> None:
    exit_code = main(["inventory", "--input", str(ROOT / "missing"), "--format", "json"])

    captured = capsys.readouterr()
    assert exit_code != 0
    assert "does not exist" in captured.err


def test_cli_rejects_packet_capture_file(tmp_path: Path, capsys) -> None:
    capture_file = tmp_path / "sample.pcap"
    capture_file.write_text("synthetic text only", encoding="utf-8")

    exit_code = main(["validate-samples", "--input", str(capture_file)])

    captured = capsys.readouterr()
    assert exit_code != 0
    assert "not accepted" in captured.err
