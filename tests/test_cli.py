from offline_packet_analyzer.cli import build_parser, main
from offline_packet_analyzer.safety import OFFLINE_ONLY_NOTICE


def test_cli_help_includes_offline_safety_scope() -> None:
    help_text = build_parser().format_help()

    assert "Offline packet analysis lab" in help_text
    assert "not a live sniffer" in help_text
    assert "does not capture real traffic" in help_text


def test_cli_placeholder_notice(capsys) -> None:
    exit_code = main([])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert OFFLINE_ONLY_NOTICE in captured.out
