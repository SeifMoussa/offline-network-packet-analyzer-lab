import json
from pathlib import Path

from offline_packet_analyzer.cli import main

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"
RAW_MARKERS = (
    "SYNTHETIC_PASSWORD_MARKER",
    "SYNTHETIC_TOKEN_MARKER",
    "SYNTHETIC_SECRET_MARKER",
)


def test_cli_detect_json_output_is_scored_and_redacted(capsys) -> None:
    exit_code = main(["detect", "--input", str(SAMPLES), "--format", "json"])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    output_text = captured.out

    assert exit_code == 0
    assert payload["max_score"] >= 0
    assert payload["highest_risk"] in {"informational", "low", "medium", "high", "critical"}
    assert payload["alerts_by_risk_level"]
    assert any(alert["rule_id"] == "SENS-001" for alert in payload["alerts"])
    assert all("score" in alert and "risk_level" in alert for alert in payload["alerts"])
    assert "[REDACTED]" in output_text
    for marker in RAW_MARKERS:
        assert marker not in output_text


def test_cli_detect_text_output_is_scored_and_redacted(capsys) -> None:
    exit_code = main(["detect", "--input", str(SAMPLES), "--format", "text"])

    captured = capsys.readouterr()

    assert exit_code == 0
    assert "risk=" in captured.out
    assert "score=" in captured.out
    assert "[REDACTED]" in captured.out
    for marker in RAW_MARKERS:
        assert marker not in captured.out
