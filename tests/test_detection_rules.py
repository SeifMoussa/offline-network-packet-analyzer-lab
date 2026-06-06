import re
from pathlib import Path

import pytest

from offline_packet_analyzer.detections.rules import (
    DEFAULT_RULE_PATH,
    VALID_SEVERITIES,
    RuleValidationError,
    load_default_rules,
    load_detection_rules,
    validate_detection_rule,
)
from offline_packet_analyzer.safety import is_allowed_domain, is_allowed_ip

IP_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
DOMAIN_PATTERN = re.compile(r"\b[a-zA-Z0-9][a-zA-Z0-9-]*(?:\.[a-zA-Z0-9-]+)+\b")
CREDENTIAL_VALUE_PATTERN = re.compile(
    r"(?i)\b(?:password|passwd|pwd|token|secret|api[_-]?key)\s*[:=]\s*[^\s,;}]+"
)


def test_default_rules_load() -> None:
    rules = load_default_rules()

    assert rules
    assert {rule.rule_id for rule in rules} >= {"NET-001", "DNS-001", "FLOW-001"}


def test_rule_ids_are_unique() -> None:
    rules = load_default_rules()
    ids = [rule.rule_id for rule in rules]

    assert len(ids) == len(set(ids))


def test_valid_severity_values() -> None:
    rules = load_default_rules()

    assert {rule.severity for rule in rules} <= VALID_SEVERITIES


def test_invalid_rule_schema_fails_safely() -> None:
    with pytest.raises(RuleValidationError):
        validate_detection_rule({"rule_id": "BROKEN"})


def test_duplicate_rule_ids_fail_safely(tmp_path: Path) -> None:
    rules_file = tmp_path / "rules.yaml"
    rules_file.write_text(
        """
rules:
  - rule_id: NET-TEST
    title: A
    description: A
    severity: low
    confidence: low
    category: test
    enabled: true
    detector_type: suspicious_test_domain
    guidance: A
  - rule_id: NET-TEST
    title: B
    description: B
    severity: low
    confidence: low
    category: test
    enabled: true
    detector_type: suspicious_test_domain
    guidance: B
""",
        encoding="utf-8",
    )

    with pytest.raises(RuleValidationError):
        load_detection_rules(rules_file)


def test_default_rule_path_exists() -> None:
    assert DEFAULT_RULE_PATH.exists()


def test_rules_file_uses_only_safe_synthetic_indicators() -> None:
    content = DEFAULT_RULE_PATH.read_text(encoding="utf-8")

    assert CREDENTIAL_VALUE_PATTERN.search(content) is None
    assert "malware" not in content.lower()
    for match in IP_PATTERN.findall(content):
        assert is_allowed_ip(match)
    for match in DOMAIN_PATTERN.findall(content):
        candidate = match.lower()
        if candidate.replace(".", "").isdigit():
            continue
        assert is_allowed_domain(candidate)
