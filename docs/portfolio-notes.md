# Portfolio Notes

Offline Network Packet Analyzer Lab is designed as a safe, recruiter-readable
blue-team portfolio project. It demonstrates network security analysis concepts
without live capture, real packet captures, raw sockets, Scapy, credential
extraction, or real traffic.

CI/CodeQL configured but not yet GitHub-verified.

## Role Alignment

SOC Analyst:

- Reviews alerts, severity, confidence, evidence, and triage guidance
- Uses redacted report output suitable for handoff or case notes
- Demonstrates attention to malformed records and false-positive context

Network Security Analyst:

- Shows protocol metadata understanding across Ethernet, IPv4, TCP, and UDP
- Summarizes flows, destination ports, top talkers, and protocol distribution
- Uses only safe reserved networks and synthetic traffic patterns

Detection Engineer:

- Implements YAML-backed rule metadata
- Produces deterministic alert models and stable testable output
- Covers repeated connections, suspicious `.test` domains, protocol/port
  mismatch, high-volume flow behavior, and sensitive-marker redaction

Security Engineer:

- Enforces safety boundaries in validators, tests, docs checks, and CLI UX
- Adds CI, CodeQL, Dependabot, and a coverage gate configured locally
- Keeps functionality offline-only and public-GitHub safe

Incident Response trainee:

- Practices triage language, evidence review, and remediation guidance
- Uses Markdown/JSON reports to communicate findings clearly
- Avoids unsafe collection or real credential handling

## Recruiter-Facing Summary

Built a defensive offline network packet analysis lab in Python that analyzes
local synthetic packet logs and handcrafted parser fixtures. The project
includes safe loaders, protocol metadata parsers, flow summaries, YAML-backed
detections, deterministic risk scoring, redaction, and Markdown/JSON reporting,
with pytest coverage, Ruff, docs safety checks, GitHub Actions, and CodeQL
configuration.

## What To Highlight

- Defensive-only design with explicit safety boundaries
- Offline analysis of local synthetic samples
- Clear protocol parsing and flow-analysis fundamentals
- Detection rules and alert triage workflow
- Redaction proof for synthetic sensitive markers
- 164 local tests, 92.50% coverage, and a 90% coverage gate
- CI/CodeQL configured but pending GitHub-hosted verification after publishing

## What Not To Claim

- Do not claim live packet capture
- Do not claim PCAP parsing
- Do not claim production IDS/NDR capability
- Do not claim credential extraction
- Do not claim hosted GitHub Actions or hosted CodeQL verification until they
  run on GitHub
