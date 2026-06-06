# Offline Packet Analysis Report

Generated: `2026-06-06T10:00:01+00:00`

## Safety Scope

Offline synthetic analysis only. This report uses local synthetic samples only.
It does not perform live sniffing, packet capture, real traffic analysis, or credential extraction.

## Input Summary

- Input path: `samples`
- Files loaded: `7`
- Records seen: `24`
- Events loaded: `24`
- Malformed records: `3`
- Skipped files: `1`

## Flow And Protocol Summary

- Total flows: `17`
- Protocol counts: `{'TCP': 12, 'UDP': 1, 'UNKNOWN': 8}`
- Destination port counts: `{'22': 2, '53': 2, '80': 1, '443': 3, '8088': 1, '8443': 2, '9443': 2}`

### Top Talkers

| Source | Destination | Bytes | Events |
| --- | --- | ---: | ---: |
| 10.0.0.42 | 192.0.2.42 | 250000 | 1 |
| 10.0.0.40 | 198.51.100.10 | 4096 | 1 |
| 10.0.0.10 | 10.0.0.20 | 1840 | 1 |
| 10.0.0.12 | 192.0.2.10 | 720 | 1 |
| 10.0.0.60 | 192.0.2.60 | 512 | 1 |

## Alert Summary

- Alert count: `33`
- Highest risk: `high`
- Max score: `85`
- Average score: `27.12`
- Alerts by severity: `{'high': 1, 'informational': 15, 'low': 10, 'medium': 7}`
- Alerts by risk level: `{'high': 4, 'low': 25, 'medium': 4}`

## Detailed Alerts

| Rule | Severity | Risk | Score | Source | Destination | Evidence |
| --- | --- | --- | ---: | --- | --- | --- |
| DNS-001 | low | low | 25 | 10.0.0.16 |  | Synthetic query or host matched suspicious-lab.test |
| DNS-001 | low | low | 25 | 10.0.0.17 |  | Synthetic query or host matched beacon-check.test |
| DNS-001 | low | low | 25 | 10.0.0.23 | 203.0.113.23 | Synthetic query or host matched suspicious-lab.test |
| DNS-001 | low | low | 25 | 10.0.0.41 | 203.0.113.41 | Synthetic query or host matched resolver-check.test |
| FLOW-001 | high | high | 85 | 10.0.0.42 | 192.0.2.42 | Synthetic flow 10.0.0.42 -> 192.0.2.42 totaled 250000 bytes |
| HTTP-001 | low | low | 25 | 10.0.0.23 | 203.0.113.23 | Synthetic HTTP user-agent matched configured marker |
| NET-001 | medium | medium | 60 | 10.0.0.30 | 192.0.2.30 | 2 synthetic attempts from 10.0.0.30 to 192.0.2.30:22 |
| NET-002 | medium | medium | 50 | 10.0.0.30 | 192.0.2.30 | 10.0.0.30 contacted 3 synthetic destination ports |
| NET-003 | low | low | 20 | 10.0.0.30 | 192.0.2.30 | Synthetic destination port 8088 matched rule list |
| NET-003 | low | low | 20 | 10.0.0.30 | 198.51.100.40 | Synthetic destination port 8443 matched rule list |
| NET-003 | low | low | 20 | 10.0.0.42 | 192.0.2.42 | Synthetic destination port 9443 matched rule list |
| NET-003 | low | low | 20 | 10.0.0.61 | 198.51.100.61 | Synthetic destination port 8443 matched rule list |
| NET-003 | low | low | 20 | 10.0.0.62 | 203.0.113.62 | Synthetic destination port 9443 matched rule list |
| NET-004 | medium | medium | 50 | 10.0.0.41 | 203.0.113.41 | Synthetic TCP traffic used destination port 53 |
| NET-005 | medium | medium | 65 | 10.0.0.30 | 192.0.2.30 | 10.0.0.30 had 4 synthetic failed status values |
| NET-006 | informational | low | 10 | 10.0.0.12 | 192.0.2.10 | Private lab source 10.0.0.12 contacted documentation range destination 192.0.2.10 |
| NET-006 | informational | low | 10 | 10.0.0.21 | 203.0.113.21 | Private lab source 10.0.0.21 contacted documentation range destination 203.0.113.21 |
| NET-006 | informational | low | 10 | 10.0.0.22 | 203.0.113.22 | Private lab source 10.0.0.22 contacted documentation range destination 203.0.113.22 |
| NET-006 | informational | low | 10 | 10.0.0.23 | 203.0.113.23 | Private lab source 10.0.0.23 contacted documentation range destination 203.0.113.23 |
| NET-006 | informational | low | 10 | 10.0.0.24 | 203.0.113.24 | Private lab source 10.0.0.24 contacted documentation range destination 203.0.113.24 |
| NET-006 | informational | low | 10 | 10.0.0.30 | 192.0.2.30 | Private lab source 10.0.0.30 contacted documentation range destination 192.0.2.30 |
| NET-006 | informational | low | 10 | 10.0.0.30 | 192.0.2.30 | Private lab source 10.0.0.30 contacted documentation range destination 192.0.2.30 |
| NET-006 | informational | low | 10 | 10.0.0.30 | 192.0.2.30 | Private lab source 10.0.0.30 contacted documentation range destination 192.0.2.30 |
| NET-006 | informational | low | 10 | 10.0.0.30 | 198.51.100.40 | Private lab source 10.0.0.30 contacted documentation range destination 198.51.100.40 |
| NET-006 | informational | low | 10 | 10.0.0.40 | 198.51.100.10 | Private lab source 10.0.0.40 contacted documentation range destination 198.51.100.10 |
| NET-006 | informational | low | 10 | 10.0.0.41 | 203.0.113.41 | Private lab source 10.0.0.41 contacted documentation range destination 203.0.113.41 |
| NET-006 | informational | low | 10 | 10.0.0.42 | 192.0.2.42 | Private lab source 10.0.0.42 contacted documentation range destination 192.0.2.42 |
| NET-006 | informational | low | 10 | 10.0.0.60 | 192.0.2.60 | Private lab source 10.0.0.60 contacted documentation range destination 192.0.2.60 |
| NET-006 | informational | low | 10 | 10.0.0.61 | 198.51.100.61 | Private lab source 10.0.0.61 contacted documentation range destination 198.51.100.61 |
| NET-006 | informational | low | 10 | 10.0.0.62 | 203.0.113.62 | Private lab source 10.0.0.62 contacted documentation range destination 203.0.113.62 |
| SENS-001 | medium | high | 70 | 10.0.0.60 | 192.0.2.60 | Approved synthetic sensitive marker observed as [REDACTED] |
| SENS-001 | medium | high | 70 | 10.0.0.61 | 198.51.100.61 | Approved synthetic sensitive marker observed as [REDACTED] |
| SENS-001 | medium | high | 70 | 10.0.0.62 | 203.0.113.62 | Approved synthetic sensitive marker observed as [REDACTED] |

## Triage Guidance

- `DNS-001`: Review synthetic DNS logs and confirm whether the .test query was intentionally included in the lab scenario.
- `FLOW-001`: Compare the synthetic byte volume with expected lab behavior and review proxy or endpoint telemetry if available.
- `HTTP-001`: Review synthetic HTTP metadata and confirm whether the user-agent marker was expected.
- `NET-001`: Review firewall or endpoint telemetry for the synthetic source and confirm whether repeated connection attempts are expected.
- `NET-002`: Validate the synthetic source host inventory and confirm whether the observed destination ports are approved.
- `NET-003`: Confirm whether the unusual destination port is documented for the synthetic service.
- `NET-004`: Validate whether the protocol and port pairing is expected for the synthetic sample.
- `NET-005`: Review repeated failed status values and confirm whether they match expected lab activity.
- `NET-006`: Confirm that documentation-range destinations are expected synthetic lab references.
- `SENS-001`: Confirm whether the redacted synthetic marker was intentionally placed, then remove exposed test data from synthetic samples if it is not needed.

## Redaction Summary

- Redaction token: `[REDACTED]`
- Redaction count: `3`
- Raw sensitive markers present: `False`

## Limitations

- This report analyzes local synthetic samples only.
- This report is not based on live sniffing or packet capture.
- This report does not analyze real traffic.
- This report does not perform credential extraction.
- Risk scores are deterministic lab scoring values, not production risk ratings.
