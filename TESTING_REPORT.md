# Testing Report

This report describes how the project is tested locally and what each area
of the test suite covers. All numbers below reflect the latest local run;
CI/CodeQL configured but not yet GitHub-verified.

## Package and CLI basics

Baseline tests confirm the package imports cleanly and the CLI entry point
responds to `--help` and the core subcommands without touching any live
network resources.

## Sample inventory and safety validation

- Required sample folders and files exist
- Text readability and size limits are enforced
- Only expected sample file extensions are accepted
- Reserved IP range and safe domain checks
- Credential-looking value checks
- Synthetic marker allowlist checks
- Source scans confirm no live-capture implementation patterns are present
- No PCAP files exist anywhere in the repo
- Safe rule placeholders exist and load correctly

## Loaders, validation, and models

- JSON, CSV, and text loader success paths
- Malformed JSON is handled without crashing the loader
- Malformed records are counted rather than silently dropped
- Unsupported file extensions are skipped cleanly
- Recursive directory inventory and single-file loading
- Path traversal and nonexistent input are rejected
- Packet-capture file suffixes are rejected outright
- `PacketEvent` and `LoadResult` shape checks
- Sample tree validation and the `inventory`/`validate-samples` CLI commands

## Protocol parsers

Parser tests use handcrafted synthetic byte fixtures only — no binary sample
files, PCAP files, or copied real packet bytes.

- Ethernet: success path, MAC formatting, EtherType parsing, payload
  extraction, truncation handling, unsupported EtherType handling
- IPv4: success path, version/IHL bitmasking, invalid version/IHL handling,
  header length bounds, protocol parsing, source/destination formatting
- TCP: success path, invalid/oversized data offset handling, truncation
  handling
- UDP: success path, invalid/oversized length handling, truncation handling
- Parser safety checks confirm no capture module, no PCAP files, no Scapy,
  no socket-based capture implementation, and no parser file reads exist

## Flow and protocol summaries

- Flow key creation and missing-field handling
- Flow aggregation by source, destination, protocol, and port
- Event and byte totals per flow
- Protocol and destination port counts
- Top source, destination, and talker summaries with deterministic ordering
- Malformed event handling and empty-input behavior
- `summarize` CLI JSON and text output, plus invalid-input failure
- Safety checks confirm no live-capture flags, payload dumping, or
  credential-extraction patterns exist

## Detection engine

- Default detection rule loading and schema validation, including duplicate
  rule ID rejection
- Disabled rules are skipped
- Every detection category ships at least one passing and one non-firing
  test case
- The clean/normal sample produces no high or critical alerts
- Malformed records are skipped rather than raising
- Deterministic alert ordering
- Alert dictionary shape checks
- `detect` CLI JSON and text output, plus invalid-input and invalid-rule-file
  failure paths

## Scoring, guidance, and redaction

- Severity-to-score range mapping and risk-level calculation
- Alert score fields and deterministic scoring factors
- Defensive guidance coverage for every default rule
- Approved synthetic marker detection and recursive redaction without
  mutating the input
- `SENS-001` redacted evidence, and confirmation that raw markers never
  reach `detect` CLI output

## Reporting

- JSON and Markdown report structure
- Safety disclaimer and limitations sections
- Flow/protocol summary, detection summary, and alert-detail sections
- Score and risk fields, and the redaction summary
- Report output redaction
- `report` CLI JSON/Markdown file creation, invalid format/input handling,
  and parent output directory creation

## CLI hardening and negative paths

- Help text includes the offline/synthetic safety boundaries for every
  command
- Missing required input/output arguments fail as expected
- Traversal-like input and output paths are rejected
- Unsupported single-file extensions are handled without crashing
- Invalid rule paths and invalid rule YAML are rejected
- Invalid `--min-severity` and `--fail-on` values are rejected
- `--min-severity` filtering and `--fail-on` exit-code behavior are verified
  for both `detect` and `report`
- Empty directories and `--no-recursive` scans behave as documented
- Expanded safety checks confirm no live-capture modules, forbidden CLI
  flags, PCAP dependencies, raw socket code, or Scapy imports exist anywhere
  in the source tree

## CI, CodeQL, and documentation checks

- CI workflow YAML parses and defines the expected jobs
- CI pins Python 3.12 and enforces the coverage threshold
- CI runs the documentation safety check and a CLI smoke test
- CodeQL workflow runs Python analysis with the `security-and-quality` query
  pack
- Dependabot is configured for weekly pip and GitHub Actions updates, with
  no Docker ecosystem entry
- `scripts/check-docs.py` runs locally and passes
- Documentation is honest about CI/CodeQL verification status and README
  badges point at the correct repository path

## Latest local result

```text
164 passed
coverage: 92.50%
coverage gate: 90%
ruff check: All checks passed
ruff format --check: all files already formatted
docs-check: all documentation safety checks passed
```

## Required checks

```bash
python -m pytest
python -m pytest --cov=offline_packet_analyzer --cov-report=term-missing --cov-fail-under=90
python -m ruff check .
python -m ruff format --check .
python scripts/check-docs.py
python -m py_compile scripts/check-docs.py
python -m offline_packet_analyzer --help
python -m offline_packet_analyzer inventory --input samples --format json
python -m offline_packet_analyzer validate-samples --input samples
python -m offline_packet_analyzer summarize --input samples --format json
python -m offline_packet_analyzer summarize --input samples --format text
python -m offline_packet_analyzer detect --input samples --format json
python -m offline_packet_analyzer detect --input samples --format text
python -m offline_packet_analyzer report --input samples --output reports/examples/offline_packet_analysis_report.json --format json
python -m offline_packet_analyzer report --input samples --output reports/examples/offline_packet_analysis_report.md --format markdown
```
