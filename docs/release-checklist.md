# Release Checklist

The current release-readiness work prepares the project for publishing but does not publish the
repository, create tags, create releases, or claim hosted CI/CodeQL results.

CI/CodeQL configured but not yet GitHub-verified.

## Completed Locally

- [x] README recruiter polish completed
- [x] Safety, schema, detection, testing, release, and portfolio docs polished
- [x] Stable JSON and Markdown example reports generated from synthetic samples
- [x] Local tests pass: 164 passed
- [x] Local coverage result documented: 92.50%
- [x] Local coverage gate set to 90%
- [x] Ruff check passed locally
- [x] Ruff format check passed locally
- [x] Documentation safety check passed locally
- [x] CLI smoke commands passed locally
- [x] Raw approved sensitive marker constants absent from CLI/report output
- [x] CI workflow configured locally
- [x] CodeQL workflow configured locally
- [x] Dependabot configured locally

## Pending After Publishing

- [ ] Repository published to GitHub
- [ ] GitHub Actions run verified on GitHub
- [ ] CodeQL run verified on GitHub
- [ ] Dependabot configuration observed on GitHub
- [ ] Branch protection configured
- [ ] Release tag created
- [ ] GitHub release created

## Pre-Publish Manual Review

- Confirm no `.env`, virtual environment, cache, coverage, or compiled Python
  files are present
- Confirm no PCAP files or real packet captures are present
- Confirm no live capture, raw socket, AF_PACKET, Scapy, or interface-sniffing
  code exists
- Confirm no credential extraction or payload dumping behavior exists
- Confirm samples use only allowed synthetic IP/domain values
- Confirm generated reports contain `[REDACTED]`
- Confirm generated reports do not contain raw approved sensitive marker constants

## Suggested Publish Steps

Manual Git:

```bash
git init
git add .
git commit -m "Initial release candidate for offline packet analyzer lab"
git branch -M main
git remote add origin https://github.com/SeifMoussa/offline-network-packet-analyzer-lab.git
git push -u origin main
```

GitHub CLI:

```bash
gh repo create SeifMoussa/offline-network-packet-analyzer-lab --public --source . --remote origin --push --description "Defensive offline network packet analysis lab using Python, synthetic packet logs, handcrafted protocol parser fixtures, flow summaries, detection rules, risk scoring, redaction, and Markdown/JSON reports with pytest, Ruff, GitHub Actions, and CodeQL."
```

Do not create a tag or release until hosted CI and CodeQL have completed on
GitHub.
