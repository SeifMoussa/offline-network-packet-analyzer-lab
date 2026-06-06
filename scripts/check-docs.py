"""Documentation and safety checks for the offline synthetic lab."""

from __future__ import annotations

import re
import sys
from ipaddress import ip_address
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

REQUIRED_DOCS = [
    ROOT / "README.md",
    ROOT / "docs" / "safety-model.md",
    ROOT / "docs" / "threat-matrix.md",
    ROOT / "docs" / "sample-schema.md",
    ROOT / "docs" / "detection-rules.md",
    ROOT / "docs" / "testing-guide.md",
    ROOT / "docs" / "release-checklist.md",
    ROOT / "docs" / "portfolio-notes.md",
    ROOT / "TESTING_REPORT.md",
    ROOT / "PROJECT_COMPLETION_CHECKLIST.md",
    ROOT / "CHANGELOG.md",
]
REQUIRED_REPORTS = [
    ROOT / "reports" / "examples" / "offline_packet_analysis_report.json",
    ROOT / "reports" / "examples" / "offline_packet_analysis_report.md",
]
RAW_MARKERS = (
    "SYNTHETIC_PASSWORD_MARKER",
    "SYNTHETIC_TOKEN_MARKER",
    "SYNTHETIC_SECRET_MARKER",
)
APPROVED_HOSTS = {
    "example.com",
    "example.org",
    "example.net",
}
APPROVED_DOC_HOSTS = {
    "github.com",
    "seifmoussa.github.io",
    "img.shields.io",
}
COMMANDS = (
    "inventory",
    "validate-samples",
    "summarize",
    "detect",
    "report",
)
LOCAL_LINK_PATTERN = re.compile(r"\[[^\]]+\]\((?!https?://|mailto:|#)([^)]+)\)")
IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_PATTERN = re.compile(r"\b[a-zA-Z0-9][a-zA-Z0-9-]*(?:\.[a-zA-Z0-9-]+)+\b")
SECRET_PATTERN = re.compile(
    r"(?i)\b(?:password|passwd|pwd|token|secret|api[_-]?key)\s*[:=]\s*[^\s,;}`]+"
)


def main() -> int:
    """Run documentation safety checks."""
    errors: list[str] = []
    errors.extend(_check_required_files())
    errors.extend(_check_local_links())
    errors.extend(_check_honest_ci_wording())
    errors.extend(_check_safety_scope())
    errors.extend(_check_indicator_safety())
    errors.extend(_check_report_redaction())
    errors.extend(_check_documented_commands())

    if errors:
        for error in errors:
            print(f"docs-check: {error}", file=sys.stderr)
        return 1

    print("docs-check: all documentation safety checks passed")
    return 0


def _check_required_files() -> list[str]:
    missing = [
        str(path.relative_to(ROOT))
        for path in [*REQUIRED_DOCS, *REQUIRED_REPORTS]
        if not path.exists()
    ]
    return [f"required file is missing: {path}" for path in missing]


def _read(paths: list[Path]) -> str:
    return "\n".join(path.read_text(encoding="utf-8") for path in paths if path.exists())


def _markdown_files() -> list[Path]:
    return [
        path
        for path in [ROOT / "README.md", *sorted((ROOT / "docs").glob("*.md"))]
        if path.exists()
    ]


def _check_local_links() -> list[str]:
    errors: list[str] = []
    for markdown in _markdown_files():
        content = markdown.read_text(encoding="utf-8")
        for match in LOCAL_LINK_PATTERN.findall(content):
            target = match.split("#", 1)[0].strip()
            if not target:
                continue
            candidate = (markdown.parent / target).resolve()
            if ROOT.resolve() not in [candidate, *candidate.parents]:
                errors.append(f"{markdown.relative_to(ROOT)} links outside repository: {match}")
            elif not candidate.exists():
                errors.append(f"{markdown.relative_to(ROOT)} has broken local link: {match}")
    return errors


def _check_honest_ci_wording() -> list[str]:
    content = _read(REQUIRED_DOCS).lower()
    errors: list[str] = []
    forbidden_claims = (
        "github actions passed",
        "codeql passed",
        "ci passed on github",
        "codeql passed on github",
        "repository has been published",
        "release has been created",
    )
    for claim in forbidden_claims:
        if claim in content:
            errors.append(f"documentation makes premature claim: {claim}")

    if "ci/codeql configured but not yet github-verified" not in content:
        errors.append("documentation must state CI/CodeQL configured but not yet GitHub-verified")
    return errors


def _check_safety_scope() -> list[str]:
    content = _read(REQUIRED_DOCS).lower()
    required_phrases = (
        "offline",
        "local",
        "synthetic",
        "no live",
        "no raw socket",
        "no pcap",
        "no scapy",
        "no credential extraction",
    )
    errors = [
        f"documentation missing safety phrase: {phrase}"
        for phrase in required_phrases
        if phrase not in content
    ]

    forbidden_claims = (
        "live sniffing is supported",
        "packet capture is supported",
        "raw-socket capture",
        "pcap analysis",
        "scapy usage",
        "is a production ids",
        "is a production ndr",
    )
    errors.extend(
        f"documentation makes unsupported capability claim: {claim}"
        for claim in forbidden_claims
        if claim in content
    )
    return errors


def _check_indicator_safety() -> list[str]:
    paths = [
        *REQUIRED_DOCS,
        *REQUIRED_REPORTS,
        *sorted((ROOT / "samples").rglob("*")),
        *sorted((ROOT / "rules").rglob("*")),
    ]
    text_paths = [path for path in paths if path.is_file()]
    content = _read(text_paths)
    sanitized = content
    for marker in RAW_MARKERS:
        sanitized = sanitized.replace(marker, "")

    errors: list[str] = []
    if SECRET_PATTERN.search(sanitized):
        errors.append("docs/samples/rules/reports contain credential-looking content")

    for match in IP_PATTERN.findall(content):
        try:
            parsed = ip_address(match)
        except ValueError:
            continue
        if not (parsed.is_private or parsed in _documentation_ip_networks()):
            errors.append(f"unexpected non-reserved IP address: {match}")

    for match in DOMAIN_PATTERN.findall(content):
        domain = match.lower()
        try:
            ip_address(domain)
            continue
        except ValueError:
            pass
        if all(part.isdigit() for part in domain.split(".")):
            continue
        if _domain_is_allowed(domain):
            continue
        if domain.endswith(
            (
                ".md",
                ".py",
                ".json",
                ".yaml",
                ".yml",
                ".txt",
                ".csv",
                ".xml",
                ".svg",
                ".html",
                ".git",
            )
        ):
            continue
        errors.append(f"unexpected non-synthetic domain: {domain}")

    return sorted(set(errors))


def _documentation_ip_networks():
    from ipaddress import ip_network

    return (
        ip_network("192.0.2.0/24"),
        ip_network("198.51.100.0/24"),
        ip_network("203.0.113.0/24"),
    )


def _domain_is_allowed(domain: str) -> bool:
    if domain in APPROVED_HOSTS or domain in APPROVED_DOC_HOSTS:
        return True
    if domain.endswith(".test"):
        return True
    return any(domain.endswith(f".{host}") for host in APPROVED_HOSTS | APPROVED_DOC_HOSTS)


def _check_report_redaction() -> list[str]:
    errors: list[str] = []
    content = _read(REQUIRED_REPORTS)
    if "[REDACTED]" not in content:
        errors.append("generated reports must contain [REDACTED]")
    for marker in RAW_MARKERS:
        if marker in content:
            errors.append(f"generated reports expose raw marker: {marker}")
    return errors


def _check_documented_commands() -> list[str]:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    errors = []
    for command in COMMANDS:
        expected = f"python -m offline_packet_analyzer {command}"
        if expected not in readme:
            errors.append(f"README missing documented CLI command: {expected}")
    return errors


if __name__ == "__main__":
    raise SystemExit(main())
