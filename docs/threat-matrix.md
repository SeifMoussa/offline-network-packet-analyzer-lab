# Threat Matrix

This document maps project capabilities to defensive learning value and safety controls.

## Parser Boundary Risks

| Area | Defensive value | Risk | Mitigation |
| --- | --- | --- | --- |
| Ethernet metadata parsing | Demonstrates frame structure and EtherType handling | Mistaken for live sniffing | Parser accepts only caller-provided bytes and has no capture module |
| IPv4 header parsing | Demonstrates version/IHL bitmasking, TTL, protocol, and address fields | Malformed bytes could crash naive code | Length checks happen before field access |
| TCP metadata parsing | Demonstrates ports, sequence fields, data offset, and flags | Payload dumping or credential extraction scope creep | Parser returns payload bytes only as test data and does not analyze credentials |
| UDP metadata parsing | Demonstrates length validation and port metadata | Invalid length could cause unsafe slicing assumptions | Length is validated before payload extraction |
| Unsupported EtherTypes | Demonstrates graceful unsupported handling | Parser might over-claim protocol support | Unsupported results are explicit and controlled |

## Flow Analysis Risks

| Area | Defensive value | Risk | Mitigation |
| --- | --- | --- | --- |
| Flow keys | Teaches how SOC tools group source, destination, protocol, and port metadata | Missing fields could crash aggregation | Missing or malformed records are skipped or counted safely |
| Protocol summaries | Shows protocol and port distribution from synthetic logs | Could be mistaken for detection logic | Summaries do not create alerts, scores, or findings |
| Top talkers | Demonstrates high-level traffic accounting | Could imply live monitoring | Summaries use only already-loaded local synthetic events |
| Byte totals | Helps reason about synthetic volume patterns | Could drift into payload inspection | Only `byte_count` metadata is aggregated; payloads are not inspected |

Flow summaries are intentionally limited to local synthetic event metadata.
Detection, scoring, redaction, and reporting are implemented as separate
stages so each behavior remains testable.

## Detection Risks

| Area | Defensive value | Risk | Mitigation |
| --- | --- | --- | --- |
| Repeated connections | Shows basic connection-pattern triage | Could imply active scanning | Uses only loaded synthetic events |
| DNS `.test` matching | Demonstrates domain-focused detection | Could introduce real IOCs | Rules use only `.test` and example domains |
| High-volume flows | Shows synthetic volume anomaly review | Could be confused with scoring | Detection emits alerts only, with scoring handled separately |
| User-agent markers | Demonstrates HTTP metadata detection | Could expose sensitive strings | Uses safe synthetic user-agent markers only |
| Documentation-range destinations | Shows lab-safe public-range patterns | Could be mistaken for real external traffic | Uses RFC documentation ranges only |

Detections produce structured alerts with defensive guidance. Scoring,
redaction, and reporting are implemented separately and covered by tests.

## Scoring And Redaction Risks

| Area | Defensive value | Risk | Mitigation |
| --- | --- | --- | --- |
| Risk scoring | Helps triage synthetic alerts consistently | Scores could be mistaken for production risk | Scoring is deterministic and documented for lab use only |
| Sensitive-marker detection | Demonstrates safe handling of exposed test markers | Raw marker values could leak in output | Detect evidence and CLI output use `[REDACTED]` |
| Triage guidance | Shows SOC-style next steps | Guidance could drift into offensive instructions | Guidance is defensive review, validation, and cleanup only |

Reports generate redacted JSON and Markdown outputs from local synthetic
samples.

## Reporting Risks

| Area | Defensive value | Risk | Mitigation |
| --- | --- | --- | --- |
| JSON report | Machine-readable portfolio artifact | Raw synthetic marker leak | Report data is redacted before serialization |
| Markdown report | Recruiter-readable triage artifact | Could imply live capture | Safety disclaimer states offline synthetic analysis only |
| Example artifacts | Demonstrates project output | Could include real data by mistake | Generated only from local synthetic samples |

Reporting does not publish data or claim live capture capability.

## CLI Misuse Risks

| Area | Defensive value | Risk | Mitigation |
| --- | --- | --- | --- |
| Help text | Makes the tool easy to evaluate | Users may mistake it for a sniffer | Every command states offline synthetic scope and no packet capture |
| Recursive loading | Convenient sample-tree analysis | Users may load unintended files | `--no-recursive` limits directory scans and unsupported files are controlled |
| Severity filtering | Focuses triage output | Users may hide lower-severity context | `--min-severity` is explicit and reflected in output summaries |
| Fail-on thresholds | Supports local quality gates | Could be confused with CI status before CI exists | Exit behavior is limited to local CLI execution |
| Report output paths | Produces portfolio artifacts | Path traversal could write unexpected locations | Traversal segments and directory output paths are rejected |
| Rule loading | Allows local synthetic rule review | Invalid YAML could crash execution | Invalid rules fail with controlled messages |

CLI UX and negative paths are hardened locally. Publishing, tags, releases, and
hosted GitHub verification remain future work.

## CI Configuration Risks

| Area | Defensive value | Risk | Mitigation |
| --- | --- | --- | --- |
| CI workflow | Reproducible local quality gate | Could be described as passing before GitHub runs it | Docs state CI/CodeQL configured but not yet GitHub-verified |
| CLI smoke job | Confirms offline commands work in automation | Could accidentally run an intentionally failing command | `--fail-on high` is excluded from passing workflow steps |
| Docs safety script | Guards portfolio claims and redaction guarantees | Could miss unsafe docs drift | Tests execute the script locally |
| CodeQL workflow | Adds static analysis after publishing | Could imply current hosted verification | Checklist separates configuration from GitHub verification |
| Dependabot | Keeps dependencies and actions visible | Could add irrelevant ecosystems | Docker updates are not configured |

CI, CodeQL, and Dependabot are configured locally. GitHub-hosted verification remains pending until the repository is published.
