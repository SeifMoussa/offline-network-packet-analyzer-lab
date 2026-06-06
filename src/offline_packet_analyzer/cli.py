"""Command-line interface for safe local synthetic sample operations."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from offline_packet_analyzer.detections.engine import (
    build_detection_output,
    format_detection_output_text,
    has_alert_at_or_above_severity,
)
from offline_packet_analyzer.detections.rules import RuleValidationError, load_detection_rules
from offline_packet_analyzer.flows.summary import (
    build_analysis_summary,
    format_analysis_summary_text,
)
from offline_packet_analyzer.loaders.inventory import load_input
from offline_packet_analyzer.reporting.json_report import generate_json_report
from offline_packet_analyzer.reporting.markdown_report import generate_markdown_report
from offline_packet_analyzer.reporting.summary import build_report_data
from offline_packet_analyzer.safety import OFFLINE_ONLY_NOTICE
from offline_packet_analyzer.validators import validate_input_path

SEVERITY_CHOICES = ("informational", "low", "medium", "high", "critical")
SAFETY_HELP = (
    "Offline-only. Uses explicit local synthetic files only. No live sniffing, "
    "packet capture, raw sockets, interface access, or credential extraction."
)


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line parser."""
    parser = argparse.ArgumentParser(
        prog="offline-packet-analyzer",
        description=(
            "Offline packet analysis lab for local synthetic logs and byte fixtures. "
            "This tool is not a live sniffer; it is offline-only, does not perform "
            "live sniffing, does not capture packets, does not capture real traffic, "
            "and does not extract credentials."
        ),
        epilog=SAFETY_HELP,
    )
    parser.add_argument(
        "--version",
        action="version",
        version="offline-packet-analyzer 0.1.0",
    )

    subparsers = parser.add_subparsers(dest="command")

    inventory = subparsers.add_parser(
        "inventory",
        help="Load local synthetic samples and print a stable inventory summary.",
        description=f"Inventory local synthetic sample files. {SAFETY_HELP}",
    )
    inventory.add_argument("--input", required=True, help="Explicit local file or directory path.")
    inventory.add_argument("--format", choices=("json",), default="json")
    inventory.add_argument(
        "--recursive",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Recursively scan local directories for supported synthetic sample files.",
    )

    validate_samples = subparsers.add_parser(
        "validate-samples",
        help="Validate local synthetic sample files without detection or reporting.",
        description=f"Validate local synthetic sample files. {SAFETY_HELP}",
    )
    validate_samples.add_argument(
        "--input", required=True, help="Explicit local file or directory path."
    )
    validate_samples.add_argument(
        "--recursive",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Recursively scan local directories for supported synthetic sample files.",
    )

    summarize = subparsers.add_parser(
        "summarize",
        help="Summarize loaded synthetic events without detection, scoring, or reporting.",
        description=f"Summarize local synthetic events. {SAFETY_HELP}",
    )
    summarize.add_argument("--input", required=True, help="Explicit local file or directory path.")
    summarize.add_argument("--format", choices=("json", "text"), default="json")
    summarize.add_argument(
        "--recursive",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Recursively scan local directories for supported synthetic sample files.",
    )

    detect = subparsers.add_parser(
        "detect",
        help="Run safe synthetic detections with scoring and redaction, without reporting.",
        description=f"Run local synthetic detections with redacted output. {SAFETY_HELP}",
    )
    detect.add_argument("--input", required=True, help="Explicit local file or directory path.")
    detect.add_argument("--format", choices=("json", "text"), default="json")
    detect.add_argument(
        "--recursive",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Recursively scan local directories for supported synthetic sample files.",
    )
    detect.add_argument(
        "--min-severity",
        choices=SEVERITY_CHOICES,
        help="Only include alerts at or above this severity.",
    )
    detect.add_argument(
        "--fail-on",
        choices=SEVERITY_CHOICES,
        help="Exit non-zero if alerts exist at or above this severity.",
    )
    detect.add_argument(
        "--rules",
        default="rules/signatures.yaml",
        help="Explicit local YAML rule file path.",
    )

    report = subparsers.add_parser(
        "report",
        help="Write a redacted JSON or Markdown report for local synthetic samples.",
        description=f"Write a redacted report from local synthetic samples. {SAFETY_HELP}",
    )
    report.add_argument("--input", required=True, help="Explicit local file or directory path.")
    report.add_argument("--output", required=True, help="Explicit local output file path.")
    report.add_argument("--format", choices=("json", "markdown"), required=True)
    report.add_argument(
        "--recursive",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Recursively scan local directories for supported synthetic sample files.",
    )
    report.add_argument(
        "--min-severity",
        choices=SEVERITY_CHOICES,
        help="Only include alerts at or above this severity in the report.",
    )
    report.add_argument(
        "--rules",
        default="rules/signatures.yaml",
        help="Explicit local YAML rule file path.",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    """Run the CLI."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        print(OFFLINE_ONLY_NOTICE)
        return 0

    input_path = Path(args.input)
    input_errors = validate_input_path(input_path)
    if input_errors:
        for error in input_errors:
            print(error, file=sys.stderr)
        return 2

    result = load_input(input_path, recursive=getattr(args, "recursive", True))
    if args.command == "inventory":
        print(json.dumps(result.to_summary_dict(), indent=2, sort_keys=True))
        return 0 if not result.errors else 1

    if args.command == "validate-samples":
        summary = result.to_summary_dict()
        summary["valid"] = not result.errors
        print(json.dumps(summary, indent=2, sort_keys=True))
        return 0 if summary["valid"] else 1

    if args.command == "summarize":
        summary = build_analysis_summary(result)
        if args.format == "text":
            print(format_analysis_summary_text(summary))
        else:
            print(json.dumps(summary, indent=2, sort_keys=True))
        return 0 if not result.errors else 1

    if args.command == "detect":
        rules = _load_rules_or_print_error(Path(args.rules))
        if rules is None:
            return 2

        output = build_detection_output(result, rules, min_severity=args.min_severity)
        if args.format == "text":
            print(format_detection_output_text(output))
        else:
            print(json.dumps(output, indent=2, sort_keys=True))
        if result.errors:
            return 1
        return 1 if has_alert_at_or_above_severity(output["alerts"], args.fail_on) else 0

    if args.command == "report":
        rules = _load_rules_or_print_error(Path(args.rules))
        if rules is None:
            return 2
        output_path = Path(args.output)
        if ".." in output_path.parts:
            print(f"Output path traversal is not allowed: {output_path}", file=sys.stderr)
            return 2
        if output_path.exists() and output_path.is_dir():
            print(f"Output path must be a file: {output_path}", file=sys.stderr)
            return 2
        report_data = build_report_data(result, rules, min_severity=args.min_severity)
        if args.format == "json":
            content = generate_json_report(report_data)
        else:
            content = generate_markdown_report(report_data)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(content, encoding="utf-8")
        print(f"Wrote {args.format} report to {output_path}")
        return 0 if not result.errors else 1

    return 0


def _load_rules_or_print_error(rule_path: Path):
    rule_errors = validate_input_path(rule_path)
    if rule_errors:
        for error in rule_errors:
            print(error, file=sys.stderr)
        return None
    try:
        return load_detection_rules(rule_path)
    except RuleValidationError as exc:
        print(str(exc), file=sys.stderr)
        return None
