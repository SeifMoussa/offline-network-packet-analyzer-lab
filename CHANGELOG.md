# Changelog

## Unreleased

- Local JSON, CSV, and text loaders for synthetic sample logs, with validation
  helpers, normalized event/load models, and `inventory`/`validate-samples`
  CLI commands.
- Ethernet, IPv4, TCP, and UDP metadata parsers, tested against handcrafted
  synthetic byte fixtures only.
- Flow extraction and protocol summaries (top sources, top destinations, top
  talkers) with a `summarize` CLI command.
- YAML-backed synthetic detection rules, an alert model, and a detection
  engine exposed through the `detect` CLI command in JSON and text formats.
- Deterministic risk scoring, defensive triage guidance, and redacted
  synthetic sensitive-marker detection.
- JSON and Markdown report generation through the `report` CLI command, with
  stable example reports checked into the repo.
- CLI hardening: recursive/no-recursive controls, severity filtering,
  fail-on thresholds, and expanded negative-path and safety tests.
- GitHub Actions CI, CodeQL, and Dependabot configuration, plus a local
  documentation safety check script and matching workflow tests.
- README, safety, threat-matrix, schema, detection, testing, release, and
  portfolio docs written for recruiter review.

CI/CodeQL configured but not yet GitHub-verified.
