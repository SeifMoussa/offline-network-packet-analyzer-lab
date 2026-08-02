# Detection Rules

`rules/signatures.yaml` contains safe synthetic detection rules for local
offline analysis. Rules operate on normalized synthetic events and flow
summaries; they do not perform network calls, live capture, PCAP parsing,
Scapy-based analysis, payload dumping, or credential extraction.

CI/CodeQL configured but not yet GitHub-verified.

## Rule Fields

Each rule includes:

- `rule_id`
- `title`
- `description`
- `severity`
- `confidence`
- `category`
- `enabled`
- `detector_type`
- threshold, port, pattern, mismatch, or range fields where needed
- defensive `guidance`

## Implemented Rule IDs

- `NET-001`: repeated connection attempts
- `NET-002`: many destination ports from one source
- `DNS-001`: DNS query to suspicious `.test` domain
- `FLOW-001`: high-volume synthetic outbound flow
- `NET-003`: unusual destination port
- `NET-004`: unexpected protocol and port pairing
- `NET-005`: repeated failed connection marker
- `HTTP-001`: suspicious synthetic HTTP user-agent marker
- `NET-006`: internal-to-documentation-range destination pattern
- `NET-007`: regular-interval beaconing pattern (low-jitter check-in timing)
- `SENS-001`: synthetic sensitive marker detected with redacted evidence

## Safety Rules

Rules may use only:

- `.test` domains
- `example.com`, `example.org`, `example.net`
- `10.0.0.0/8`
- `192.0.2.0/24`
- `198.51.100.0/24`
- `203.0.113.0/24`
- approved synthetic markers for redaction testing

Rules must not include real threat intelligence indicators, real malicious
domains, malware names, real public IP addresses, copied incident data, real
credentials, or token-like values.

`SENS-001` must emit `[REDACTED]` in evidence and output. It does not perform
credential extraction and does not detect realistic secret patterns.
