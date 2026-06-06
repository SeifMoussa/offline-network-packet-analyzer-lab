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


def test_cli_report_json_output_file_creation(tmp_path: Path, capsys) -> None:
    output = tmp_path / "reports" / "report.json"

    exit_code = main(
        ["report", "--input", str(SAMPLES), "--output", str(output), "--format", "json"]
    )

    captured = capsys.readouterr()
    payload = json.loads(output.read_text(encoding="utf-8"))

    assert exit_code == 0
    assert output.exists()
    assert "Wrote json report" in captured.out
    assert payload["detection_summary"]["alert_count"] >= 1


def test_cli_report_markdown_output_file_creation(tmp_path: Path, capsys) -> None:
    output = tmp_path / "nested" / "report.md"

    exit_code = main(
        ["report", "--input", str(SAMPLES), "--output", str(output), "--format", "markdown"]
    )

    captured = capsys.readouterr()
    content = output.read_text(encoding="utf-8")

    assert exit_code == 0
    assert output.exists()
    assert "Wrote markdown report" in captured.out
    assert "# Offline Packet Analysis Report" in content


def test_cli_report_invalid_format_failure(tmp_path: Path) -> None:
    with pytest.raises(SystemExit):
        main(
            [
                "report",
                "--input",
                str(SAMPLES),
                "--output",
                str(tmp_path / "report.txt"),
                "--format",
                "xml",
            ]
        )


def test_cli_report_invalid_input_failure(tmp_path: Path, capsys) -> None:
    exit_code = main(
        [
            "report",
            "--input",
            str(ROOT / "missing"),
            "--output",
            str(tmp_path / "report.json"),
            "--format",
            "json",
        ]
    )

    captured = capsys.readouterr()

    assert exit_code != 0
    assert "does not exist" in captured.err


def test_cli_report_parent_output_directory_creation(tmp_path: Path) -> None:
    output = tmp_path / "a" / "b" / "report.json"

    assert (
        main(["report", "--input", str(SAMPLES), "--output", str(output), "--format", "json"]) == 0
    )
    assert output.exists()


def test_cli_report_outputs_are_redacted(tmp_path: Path) -> None:
    json_output = tmp_path / "report.json"
    markdown_output = tmp_path / "report.md"

    assert (
        main(["report", "--input", str(SAMPLES), "--output", str(json_output), "--format", "json"])
        == 0
    )
    assert (
        main(
            [
                "report",
                "--input",
                str(SAMPLES),
                "--output",
                str(markdown_output),
                "--format",
                "markdown",
            ]
        )
        == 0
    )

    for output in (
        json_output.read_text(encoding="utf-8"),
        markdown_output.read_text(encoding="utf-8"),
    ):
        assert "[REDACTED]" in output
        for marker in RAW_MARKERS:
            assert marker not in output
