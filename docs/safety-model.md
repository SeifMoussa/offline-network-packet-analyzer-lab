# Safety Model

This project is a defensive, offline-only educational lab.

It is not a live sniffer, does not capture real traffic, does not require sudo/root, and does not use raw sockets, AF_PACKET, promiscuous mode, packet injection, ARP spoofing, or MITM logic.

## Allowed Data

Samples may use only:

- `10.0.0.0/8`
- `192.0.2.0/24`
- `198.51.100.0/24`
- `203.0.113.0/24`
- `example.com`
- `example.org`
- `example.net`
- `.test` domains
- Synthetic hostnames such as `lab-client`, `lab-server`, `analyst-workstation`, and `synthetic-dns-server`

## Prohibited Data

The repository must not include:

- Real packet captures
- PCAP files
- Real credentials, tokens, or secrets
- Real domains or public IP addresses
- Live traffic captures
- Payload dumps from real traffic
- Threat intelligence copied from real incidents

## Synthetic Marker Policy

Synthetic sensitive-marker examples are allowed only for redaction testing:

- `SYNTHETIC_PASSWORD_MARKER`
- `SYNTHETIC_TOKEN_MARKER`
- `SYNTHETIC_SECRET_MARKER`

Phase 7 redaction ensures these markers are reported only as `[REDACTED]` in console output and JSON-ready output structures.

## Offline Loader Safety

Phase 3 loaders operate only on explicit local file or directory paths.

Loader safety controls:

- Reject nonexistent input paths
- Reject path traversal segments
- Reject packet capture file suffixes
- Load only `.json`, `.csv`, and `.txt` samples
- Skip unsupported files with controlled summary output
- Require UTF-8 text-readable files
- Enforce a small file-size limit
- Validate IP ranges and safe domains
- Count malformed records without crashing the whole load

The loader code does not inspect network interfaces, open raw sockets, require elevated privileges, or perform live capture.

## Parser Safety Boundaries

Phase 4 parser functions operate only on `bytes` supplied by the caller.

Parser safety controls:

- No live capture modules
- No `capture.py`
- No packet capture files
- No Scapy dependency
- No socket capture implementation
- No PCAP parsing
- No file reads from parser modules
- Controlled malformed results instead of raw parser tracebacks

The parser modules extract metadata from synthetic bytes only. They do not dump payloads from real traffic, perform credential extraction, or connect to any network resource.

## Offline Flow Analysis Boundaries

Phase 5 flow summaries operate only on `PacketEvent` objects produced by the local synthetic loaders.

Flow summary controls:

- No live capture input
- No interface flags
- No packet capture files
- No network connections
- No credential extraction
- No payload dumping
- Flow summary commands do not perform detection, scoring, redaction, or report generation

Malformed or incomplete records are counted safely and skipped from flow aggregation when required fields are missing.

## Detection Safety Boundaries

Phase 6 detections run only on local synthetic `PacketEvent` objects and synthetic flow summaries.

Detection safety controls:

- Rules load only from an explicit local YAML file
- Default rules use only `.test`, example domains, private lab ranges, and documentation IP ranges
- No network calls
- No interface inspection
- No live capture flags
- No credential extraction
- No payload dumping
- No real threat intelligence indicators
- No report-file generation
- Risk scoring is deterministic and lab-only
- Redaction is applied before detect CLI output is serialized

Malformed records are skipped safely during detection.

## Redaction Boundaries

Phase 7 recognizes only approved synthetic marker constants. It does not parse real passwords, tokens, API keys, or secrets.

Redaction controls:

- Approved synthetic markers are replaced with `[REDACTED]`
- Nested dictionaries and lists are redacted recursively
- Alert evidence and detect CLI output are redacted before serialization
- Input records are not mutated by redaction helpers

## Reporting Guarantees

Phase 8 report generation writes only the explicit output file requested by the user.

Report safety controls:

- JSON and Markdown reports are generated from local synthetic inputs only
- Parent output directories are created only for the requested output path
- Output paths containing traversal segments are rejected
- Reports include the offline-only safety scope and limitations
- Reports include scored alerts and triage guidance
- Reports are redacted before serialization
- Reports do not include raw approved marker constants
- Reports do not claim live sniffing, packet capture, real traffic analysis, or credential extraction

## CLI Safety Boundaries

Phase 9 hardens command-line behavior without adding live capture capability.

CLI safety controls:

- Every analysis command requires an explicit local `--input`
- The report command requires an explicit local `--output`
- Directory scans are recursive by default and can be limited with `--no-recursive`
- Detect and report output can be filtered with `--min-severity`
- Detect can return non-zero with `--fail-on` when matching alerts are present
- Invalid severities, formats, inputs, outputs, and rule files fail clearly
- No command exposes interface, sniffing, PCAP, promiscuous mode, raw-socket, or credential-extraction options
- Detect and report output remains redacted before text, JSON, Markdown, or file serialization

## CI Configuration Boundaries

Phase 10 adds local workflow configuration for GitHub Actions CI, CodeQL, and
Dependabot.

CI/CodeQL configured but not yet GitHub-verified.

CI safety controls:

- CI commands use local synthetic samples only
- CLI smoke commands do not use `--fail-on high` as a passing workflow step
- Docs safety checks reject premature CI/CodeQL pass claims
- CodeQL is configured for Python analysis only
- Dependabot is configured for pip and GitHub Actions only
- Docker updates are not configured because Docker is not used
