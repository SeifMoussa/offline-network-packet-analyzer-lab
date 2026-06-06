# Sample Schema

Phase 3 defines synthetic sample shapes and implements safe local loaders for JSON, CSV, and text samples.

Phase 4 adds parser tests that use handcrafted synthetic byte arrays only. No binary sample files are added.

Phase 5 consumes loaded `PacketEvent` records to build flow and protocol summaries.

Phase 6 detections consume the same loaded event fields plus flow summaries. Rules may refer to safe synthetic fields such as `status`, `query_name`, `hostname`, `user_agent`, `destination_port`, `protocol`, and `byte_count`.

Phase 8 reports consume the loader output, flow/protocol summaries, scored alerts, guidance, and redacted output structures. Reports do not require new sample fields.

## Sample Folders

- `samples/logs/`: JSON, CSV, and text synthetic event logs
- `samples/raw/`: documentation for handcrafted raw byte fixture policy

No PCAP files or real packet captures are allowed.

## Raw Byte Fixture Testing Policy

Raw byte fixtures are created inline in parser tests. They are not stored as binary files under `samples/raw/`.

Phase 4 parser fixtures cover:

- Ethernet header parsing
- IPv4 header parsing
- TCP metadata parsing
- UDP metadata parsing
- Malformed byte-length handling
- Unsupported EtherType behavior

Fixtures must use only reserved documentation/private IP values and must not be copied from real network traffic.

## Loader Behavior

The loader accepts an explicit local file or directory path.

Supported loadable extensions:

- `.json`
- `.csv`
- `.txt`

Directory inputs are scanned recursively by default. Phase 9 CLI commands expose `--no-recursive` to limit loading to direct child files. Unsupported files are skipped and listed in the load summary, or reported as controlled errors when a single unsupported file is the only input. Paths containing traversal segments are rejected.

The loader does not make network calls, inspect network interfaces, open raw sockets, parse binary packet captures, or follow files outside the requested input root.

Detect and report commands can filter alerts with `--min-severity`. The detect command can also use `--fail-on` to return non-zero when matching alerts exist at or above a chosen severity.

## JSON Event Shape

JSON files contain an array of objects. Records may include:

- `timestamp`: ISO-like UTC timestamp string
- `source_ip`: synthetic source IP
- `destination_ip`: synthetic destination IP
- `source_port`: integer source port
- `destination_port`: integer destination port
- `protocol`: `TCP`, `UDP`, or another future synthetic protocol label
- `byte_count`: integer byte count
- `status`: synthetic status string
- `hostname`: optional safe hostname or domain
- `query_name`: optional safe DNS query name
- `user_agent`: optional synthetic HTTP user-agent
- `synthetic_marker`: boolean, expected to be `true`
- `scenario`: short synthetic scenario label
- `notes`: optional notes, including approved synthetic marker names

`samples/logs/malformed_records.json` intentionally contains incomplete and malformed records. Phase 3 counts those records safely instead of crashing the load.

## CSV DNS-Like Shape

`samples/logs/dns_queries.csv` uses:

```text
timestamp,source_ip,query_name,response_code,synthetic_marker
```

The `query_name` column must contain only `example.com`, `example.org`, `example.net`, subdomains of those domains, or `.test` names.

## Text HTTP-Like Shape

`samples/logs/http_events.txt` uses one synthetic event per line:

```text
timestamp source_ip destination_ip method host path user_agent status
```

The text format is intentionally simple and is loaded into normalized event records in Phase 3.

## Normalized Event Model

Loaded records are normalized into a `PacketEvent` shape with fields such as:

- `source_path`
- `record_index`
- `timestamp`
- `source_ip`
- `destination_ip`
- `source_port`
- `destination_port`
- `protocol`
- `byte_count`
- `status`
- `hostname`
- `query_name`
- `method`
- `path`
- `user_agent`
- `synthetic_marker`
- `raw_record`
- `parse_status`

Malformed records are represented with `parse_status: malformed` where possible.

## Flow Summary Inputs

Flow summaries use valid `PacketEvent` fields:

- `source_ip`
- `destination_ip`
- `protocol`
- `destination_port`
- `source_port`
- `byte_count`
- `timestamp`
- `status`
- `hostname`
- `query_name`
- `user_agent`

Malformed records and records missing required flow fields are skipped for flow aggregation but remain counted in overall summary fields.

## Allowed Values

Allowed IP ranges:

- `10.0.0.0/8`
- `192.0.2.0/24`
- `198.51.100.0/24`
- `203.0.113.0/24`

Allowed domain values:

- `example.com`
- `example.org`
- `example.net`
- Subdomains of those example domains
- `.test` domains
- Approved synthetic hostnames such as `lab-server`

## Sensitive Markers

Only these synthetic marker strings are allowed in sample definitions:

- `SYNTHETIC_PASSWORD_MARKER`
- `SYNTHETIC_TOKEN_MARKER`
- `SYNTHETIC_SECRET_MARKER`

They are placeholders for redaction tests, not credentials. CLI output and
reports render them as `[REDACTED]`.
