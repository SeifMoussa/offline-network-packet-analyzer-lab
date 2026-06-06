# Testing Guide

Phase 2 adds safety inventory tests for the synthetic sample set.

The tests verify:

- Required sample folders exist
- Required sample files exist
- Sample files are text-readable
- Sample files are small
- Sample file extensions are expected
- Sample IP addresses stay within approved ranges
- Sample domains use only approved values
- Sample files do not contain credential-looking values
- Source code does not implement live capture, raw socket, AF_PACKET, sudo/root, promiscuous mode, injection, ARP spoofing, MITM, or PCAP parsing behavior
- No real PCAP files exist
- `rules/signatures.yaml` exists and remains a safe synthetic placeholder
- Sensitive marker samples use only approved synthetic markers

Phase 3 adds loader, validation, model, and CLI tests.

The Phase 3 tests verify:

- JSON loader success
- CSV loader success
- Text loader success
- Malformed JSON handling
- Malformed record counting
- Unsupported extension skipping
- Recursive directory inventory
- Single-file loading
- Path traversal rejection
- Nonexistent input rejection
- Packet capture suffix rejection
- `PacketEvent` shape
- `LoadResult` summary shape
- CLI inventory JSON output
- CLI sample validation success
- CLI invalid input failure

Phase 4 adds parser and parser safety tests.

The Phase 4 tests verify:

- Ethernet parsing, MAC formatting, EtherType parsing, payload extraction, truncation handling, and unsupported EtherType handling
- IPv4 parsing, version/IHL bitmasking, invalid version handling, invalid IHL handling, out-of-bounds header length handling, protocol parsing, and IP formatting
- TCP metadata parsing, invalid data offset handling, oversized data offset handling, and truncation handling
- UDP metadata parsing, invalid length handling, oversized length handling, and truncation handling
- No unhandled exceptions on malformed synthetic bytes
- No capture module, PCAP files, Scapy imports, socket capture implementation, raw socket constants, or parser file reads

Phase 5 adds flow summary and summarize CLI tests.

The Phase 5 tests verify:

- Flow key creation
- Aggregation by source, destination, protocol, and port
- Total byte counting
- Event count per flow
- Protocol counts
- Destination port counts
- Top sources, destinations, and talkers
- Deterministic sorting
- Malformed and missing fields handled safely
- Empty event list behavior
- `summarize` CLI JSON output
- `summarize` CLI text output
- `summarize` CLI invalid input failure
- No live-capture CLI flags or payload/credential extraction patterns

Phase 6 adds detection rule, alert, detection engine, and detect CLI tests.

The Phase 6 tests verify:

- Default rules load
- Rule IDs are unique
- Severity values are valid
- Disabled rules are skipped
- Invalid rule schemas fail safely
- Repeated connection detection
- Many destination ports detection
- Suspicious `.test` DNS detection
- High-volume flow detection
- Unusual destination port detection
- Protocol/port mismatch detection
- Repeated failed status detection
- Suspicious HTTP user-agent detection
- Internal-to-documentation-range destination detection
- Normal sample avoids high/critical alerts
- Malformed records are skipped safely
- Deterministic alert ordering
- Alert `to_dict()` shape
- Detect CLI JSON and text output
- Detect CLI invalid input and invalid rule failures

Phase 7 adds scoring, guidance, redaction, and sensitive-marker tests.

The Phase 7 tests verify:

- Severity-to-score range mapping
- Deterministic scoring
- Risk level calculation
- Score fields in alert dictionaries
- Guidance exists for every default rule
- Guidance text is defensive only
- Approved synthetic markers are detected
- Approved synthetic markers are redacted
- Nested structures are redacted without mutating input
- `SENS-001` evidence contains `[REDACTED]`
- Raw marker constants do not appear in detect JSON or text CLI output
- No realistic credential extraction patterns are added

Phase 8 adds report generation and report CLI tests.

The Phase 8 tests verify:

- JSON report structure
- Markdown report structure
- Safety disclaimer in reports
- Flow/protocol summary in reports
- Detection summary in reports
- Score and risk fields in reports
- Redaction summary in reports
- `[REDACTED]` appears where expected
- Raw marker constants do not appear
- CLI JSON and Markdown report file creation
- CLI invalid format and invalid input behavior
- Parent output directory creation
- Existing commands continue to pass

Phase 9 adds CLI UX, negative-path, and expanded safety validation tests.

The Phase 9 tests verify:

- Help text for every command includes offline synthetic safety boundaries
- Missing required `--input` and report `--output` fail clearly
- Traversal-like inputs and report outputs are rejected
- Unsupported single-file extensions are controlled
- Invalid rule paths and invalid rule YAML fail safely
- Invalid `--min-severity`, invalid `--fail-on`, and invalid formats fail clearly
- `--min-severity` filters detect and report alerts deterministically
- `--fail-on high` returns non-zero when high alerts exist
- `--fail-on critical` returns zero for the current sample set
- Empty directories and malformed samples remain controlled
- `--no-recursive` limits directory loading to direct child files
- No live-capture modules, CLI flags, raw socket code, Scapy imports, PCAP dependencies, or packet capture files exist
- Detect CLI output and generated reports contain `[REDACTED]` and no raw marker constants

Phase 10 adds workflow, Dependabot, and documentation consistency tests.

The Phase 10 tests verify:

- CI workflow YAML parses locally
- CI has Tests, Docs Safety Checks, and CLI Smoke jobs
- CI uses Python 3.12
- CI includes a 90 percent coverage gate
- CodeQL workflow analyzes Python
- CodeQL uses `security-and-quality` queries
- Dependabot checks pip and GitHub Actions weekly
- Docker updates are not configured
- `scripts/check-docs.py` exists and passes locally
- Documentation says CI/CodeQL configured but not yet GitHub-verified

CI/CodeQL configured but not yet GitHub-verified.

Run:

```bash
python -m pytest
python -m ruff check .
python -m ruff format --check .
python scripts/check-docs.py
python -m offline_packet_analyzer --help
```
