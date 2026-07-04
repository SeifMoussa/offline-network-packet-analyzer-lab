# Offline Network Packet Analyzer Lab

[![CI](https://github.com/SeifMoussa/offline-network-packet-analyzer-lab/actions/workflows/ci.yml/badge.svg)](https://github.com/SeifMoussa/offline-network-packet-analyzer-lab/actions/workflows/ci.yml)
[![CodeQL](https://github.com/SeifMoussa/offline-network-packet-analyzer-lab/actions/workflows/codeql.yml/badge.svg)](https://github.com/SeifMoussa/offline-network-packet-analyzer-lab/actions/workflows/codeql.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/SeifMoussa/offline-network-packet-analyzer-lab/blob/main/LICENSE)

Offline Network Packet Analyzer Lab is a defensive, offline-only network
security portfolio project. It analyzes local synthetic packet/event logs,
handcrafted synthetic byte fixtures in tests, flow summaries, detection rules,
risk scores, redacted evidence, and Markdown/JSON reports.

This is not a live sniffer. It does not capture packets, does not inspect
interfaces, does not parse PCAP files, does not require sudo/root, does not use
raw sockets or AF_PACKET, does not use Scapy, and does not extract credentials.
It is not a production IDS or NDR replacement.

CI/CodeQL configured but not yet GitHub-verified. The repository has not been
published, and no tags or releases have been created.

## Why This Lab Is Different From My Other Security Labs

This lab starts with network conversations rather than cloud configuration, endpoint state, file signatures, or an existing alert queue. The cloud/IaC lab reviews configuration before deployment, the host lab compares files and host events, the YARA/log lab matches content rules, and the alert-triage lab organizes findings produced elsewhere. Here, local synthetic events are turned into flow/session summaries, protocol counts, YAML-backed detections, scores, redacted evidence, and reports. The byte-level parser tests also make Ethernet, IPv4, TCP, and UDP header boundaries explicit without adding a live capture path.

## Target Roles

This project is designed to be reviewable for:

- SOC Analyst
- Network Security Analyst
- Detection Engineer
- Security Engineer
- Incident Response trainee

## What It Demonstrates

- Defensive packet-analysis thinking without live traffic collection
- Protocol header parsing fundamentals
- Strict local file loading and sample validation
- Flow and protocol summarization from normalized events
- YAML-backed detection rules and alert triage
- Deterministic risk scoring
- Sensitive-marker redaction using safe synthetic markers only
- Markdown and JSON reporting suitable for portfolio review
- Pytest, Ruff, local docs checks, GitHub Actions, CodeQL, and Dependabot setup

## Features

- Local JSON, CSV, and text synthetic sample loaders
- Validation for allowed IP ranges, domains, file types, and sample size
- Ethernet, IPv4, TCP metadata, and UDP metadata parsers
- Controlled handling for malformed records and malformed byte fixtures
- Flow summaries, protocol counts, top sources, top destinations, and top talkers
- YAML-backed synthetic detection rules
- Structured alerts with severity, confidence, score, risk level, evidence, and guidance
- Redacted sensitive-marker evidence using `[REDACTED]`
- JSON and Markdown report generation
- CLI hardening for explicit local input, severity filtering, and fail-on thresholds
- Documentation safety checks and workflow configuration tests

## Tech Stack

- Python 3.12
- `argparse`
- `dataclasses`
- `struct`
- PyYAML
- pytest
- pytest-cov
- Ruff
- GitHub Actions
- CodeQL
- Dependabot

## Supported Synthetic Samples

The project supports only safe local synthetic data:

- Synthetic JSON packet/event logs
- Synthetic CSV DNS-like logs
- Synthetic text HTTP-like logs
- Handcrafted synthetic byte fixtures in tests only

Allowed values are limited to private lab ranges, reserved documentation IP
ranges, `example.com`, `example.org`, `example.net`, `.test` domains, and
synthetic hostnames.

## Safety Boundaries

- Defensive only
- Offline/local files only
- Synthetic samples only
- No live network sniffing
- No live packet capture
- No raw sockets
- No AF_PACKET
- No sudo/root/CAP_NET_RAW requirement
- No promiscuous mode
- No packet injection
- No ARP spoofing
- No MITM logic
- No PCAP parsing
- No Scapy
- No real traffic
- No real packet captures
- No credential extraction
- No payload dumping
- Not a production IDS/NDR replacement

## Parser Overview

Parser modules operate only on `bytes` passed into parser functions.

- Ethernet: destination MAC, source MAC, EtherType, payload extraction
- IPv4: version, IHL, TTL, protocol, source IP, destination IP, payload extraction
- TCP metadata: ports, sequence number, acknowledgment number, data offset, flags
- UDP metadata: ports, length, checksum, payload extraction

Parser tests use handcrafted byte arrays only. No binary sample files, PCAP
files, or copied real packet bytes are included.

## Flow And Protocol Summaries

Flow summaries are built from normalized `PacketEvent` records loaded from local
synthetic samples. Summaries include:

- Flow keys by source, destination, protocol, and port
- Event counts and byte totals
- Protocol counts
- Destination port counts
- Top sources
- Top destinations
- Top talkers
- Malformed record counts

## Detection Categories

Default synthetic detections include:

- Repeated connection attempts
- Many destination ports from one source
- DNS query to suspicious `.test` domain
- High-volume synthetic outbound flow
- Unusual destination port
- Unexpected protocol and port pairing
- Repeated failed connection marker
- Suspicious synthetic HTTP user-agent marker
- Internal-to-documentation-range destination pattern
- Synthetic sensitive-marker detection with redacted evidence

Rules live in [rules/signatures.yaml](rules/signatures.yaml).

## Scoring And Redaction

Alerts receive deterministic lab scores from 0 to 100 and risk levels of
informational, low, medium, high, or critical. Scores are transparent and meant
for lab triage, not production risk rating.

Sensitive-marker handling recognizes only approved synthetic marker constants
and renders them as `[REDACTED]` in CLI output, alert evidence, JSON reports,
and Markdown reports. The project does not parse or extract real secrets.

## Reporting

Reports are generated from local synthetic samples and include:

- Safety scope
- Input and file summary
- Flow and protocol summaries
- Detection summary
- Scored alerts
- Redacted evidence
- Triage guidance
- Limitations

Example reports:

- [JSON report](reports/examples/offline_packet_analysis_report.json)
- [Markdown report](reports/examples/offline_packet_analysis_report.md)

## CLI Examples

Install development dependencies:

```bash
python -m pip install -e ".[dev]"
```

Show help:

```bash
python -m offline_packet_analyzer --help
```

Inventory local synthetic samples:

```bash
python -m offline_packet_analyzer inventory --input samples --format json
```

Validate local synthetic samples:

```bash
python -m offline_packet_analyzer validate-samples --input samples
```

Summarize loaded synthetic events:

```bash
python -m offline_packet_analyzer summarize --input samples --format json
python -m offline_packet_analyzer summarize --input samples --format text
```

Run safe synthetic detections:

```bash
python -m offline_packet_analyzer detect --input samples --format json
python -m offline_packet_analyzer detect --input samples --format text
python -m offline_packet_analyzer detect --input samples --format json --min-severity high
python -m offline_packet_analyzer detect --input samples --format json --fail-on high
```

`--fail-on` returns a non-zero exit code only when alerts exist at or above the
chosen severity.

Generate redacted reports:

```bash
python -m offline_packet_analyzer report --input samples --output reports/examples/offline_packet_analysis_report.json --format json
python -m offline_packet_analyzer report --input samples --output reports/examples/offline_packet_analysis_report.md --format markdown
```

Directory inputs are recursive by default. Use `--no-recursive` on inventory,
validate, summarize, detect, or report commands to inspect only direct child
files of a local directory.

## Test And Quality Status

Latest local validation:

- `164 passed`
- `92.50%` coverage
- `90%` coverage gate
- Ruff check passed
- Ruff format check passed
- Documentation safety check passed
- CLI smoke passed
- Stable example reports generated successfully
- Raw approved sensitive marker constants absent from CLI/report outputs

Run local quality checks:

```bash
python -m pytest
python -m pytest --cov=offline_packet_analyzer --cov-report=term-missing --cov-fail-under=90
python -m ruff check .
python -m ruff format --check .
python scripts/check-docs.py
```

## CI And CodeQL Status

GitHub Actions CI, CodeQL, and Dependabot are configured locally. They are not
yet GitHub-verified because the repository has not been published.

Configured workflows:

- CI: tests, Ruff, coverage gate, docs safety checks, CLI smoke
- CodeQL: Python analysis with security-and-quality queries
- Dependabot: weekly pip and GitHub Actions updates

## Project Structure

```text
.github/                 GitHub templates, CI, CodeQL, Dependabot
docs/                    Safety, schema, detection, testing, release, portfolio docs
reports/examples/         Stable redacted JSON and Markdown example reports
rules/                   Safe synthetic detection rules
samples/logs/             Synthetic JSON, CSV, and text sample logs
samples/raw/              Raw fixture policy documentation
scripts/                 Documentation safety checks
src/offline_packet_analyzer/
  detections/             Rule loading and detection engine
  flows/                  Flow and protocol summaries
  guidance/               Defensive triage guidance
  loaders/                Local JSON, CSV, and text loaders
  models/                 Event, flow, alert, packet, load models
  parsers/                Ethernet, IPv4, TCP, UDP metadata parsers
  redaction/              Synthetic marker redaction
  reporting/              JSON and Markdown report generation
  scoring/                Deterministic risk scoring
tests/                   Unit, CLI, safety, workflow, documentation tests
```

## Known Limitations

- All traffic records and byte fixtures are synthetic and local; no production packet data belongs in this repository.
- There is no live network tap, interface inspection, use of raw sockets, or PCAP ingestion.
- The parsers expose Ethernet, IPv4, TCP, and UDP metadata only. They do not reassemble streams, decode encrypted traffic, or inspect application payloads from real traffic.
- The YAML rules are a small transparent lab set, not production NIDS/NDR coverage or threat intelligence.
- There is no enterprise SIEM integration, sensor fleet management, distributed storage, or continuous monitoring.
- CI/CodeQL have not run on GitHub yet.

## What I Would Improve Next

I would add an offline PCAP adapter behind the existing event model, with strict size limits and fixtures created specifically for the lab. TCP stream reassembly and IPv6 metadata would come before deeper protocol decoders because both affect flow correctness. I would also version the detection-rule schema and add an optional JSON export adapter for SIEM ingestion while keeping collection and network access outside the analyzer.

## How to Verify It Works

Install the development extras, run the repository quality gates, then exercise sample validation, flow summaries, detections, and redacted report generation:

```bash
python -m pip install -e ".[dev]"
python -m ruff check .
python -m ruff format --check .
python -m pytest
python -m pytest --cov=offline_packet_analyzer --cov-report=term-missing --cov-fail-under=90
python scripts/check-docs.py
python -m offline_packet_analyzer validate-samples --input samples
python -m offline_packet_analyzer summarize --input samples --format text
python -m offline_packet_analyzer detect --input samples --format text
python -m offline_packet_analyzer report --input samples --output reports/examples/offline_packet_analysis_report.json --format json
```

These commands verify the offline synthetic workflow. They do not validate live packet capture, encrypted traffic inspection, or production NIDS deployment.

## License

MIT License. See [LICENSE](LICENSE).
