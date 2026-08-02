"""Detection rule loading and validation."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

VALID_SEVERITIES = frozenset({"informational", "low", "medium", "high", "critical"})
VALID_CONFIDENCE = frozenset({"low", "medium", "high"})
DEFAULT_RULE_PATH = Path(__file__).resolve().parents[3] / "rules" / "signatures.yaml"


@dataclass(slots=True)
class DetectionRule:
    """Validated detection rule metadata."""

    rule_id: str
    title: str
    description: str
    severity: str
    confidence: str
    category: str
    enabled: bool
    detector_type: str
    guidance: str
    threshold: int | None = None
    patterns: list[str] = field(default_factory=list)
    ports: list[int] = field(default_factory=list)
    mismatches: list[dict[str, Any]] = field(default_factory=list)
    destination_ranges: list[str] = field(default_factory=list)
    status_keywords: list[str] = field(default_factory=list)
    min_events: int | None = None
    max_jitter_ratio: float | None = None


class RuleValidationError(ValueError):
    """Raised when a detection rule file is invalid."""


def validate_detection_rule(rule: dict[str, Any]) -> None:
    """Validate raw rule data loaded from YAML."""
    required = {
        "rule_id",
        "title",
        "description",
        "severity",
        "confidence",
        "category",
        "enabled",
        "detector_type",
        "guidance",
    }
    missing = sorted(required - set(rule))
    if missing:
        raise RuleValidationError(f"Rule is missing required fields: {missing}")
    if rule["severity"] not in VALID_SEVERITIES:
        raise RuleValidationError(f"Invalid severity for {rule['rule_id']}: {rule['severity']}")
    if rule["confidence"] not in VALID_CONFIDENCE:
        raise RuleValidationError(f"Invalid confidence for {rule['rule_id']}: {rule['confidence']}")
    if not isinstance(rule["enabled"], bool):
        raise RuleValidationError(f"enabled must be boolean for {rule['rule_id']}")


def _to_rule(rule: dict[str, Any]) -> DetectionRule:
    validate_detection_rule(rule)
    return DetectionRule(
        rule_id=rule["rule_id"],
        title=rule["title"],
        description=rule["description"],
        severity=rule["severity"],
        confidence=rule["confidence"],
        category=rule["category"],
        enabled=rule["enabled"],
        detector_type=rule["detector_type"],
        guidance=rule["guidance"],
        threshold=rule.get("threshold"),
        patterns=list(rule.get("patterns", [])),
        ports=[int(port) for port in rule.get("ports", [])],
        mismatches=list(rule.get("mismatches", [])),
        destination_ranges=list(rule.get("destination_ranges", [])),
        status_keywords=list(rule.get("status_keywords", [])),
        min_events=int(rule["min_events"]) if "min_events" in rule else None,
        max_jitter_ratio=float(rule["max_jitter_ratio"]) if "max_jitter_ratio" in rule else None,
    )


def load_detection_rules(path: Path) -> list[DetectionRule]:
    """Load and validate detection rules from a local YAML file."""
    if not path.exists():
        raise RuleValidationError(f"Rule file does not exist: {path}")
    if path.suffix.lower() not in {".yaml", ".yml"}:
        raise RuleValidationError(f"Rule file must be YAML: {path}")

    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("rules"), list):
        raise RuleValidationError("Rule file must contain a top-level rules list")

    rules = [_to_rule(rule) for rule in data["rules"]]
    ids = [rule.rule_id for rule in rules]
    duplicates = sorted({rule_id for rule_id in ids if ids.count(rule_id) > 1})
    if duplicates:
        raise RuleValidationError(f"Duplicate rule IDs: {duplicates}")
    return rules


def load_default_rules() -> list[DetectionRule]:
    """Load the repository default synthetic detection rules."""
    return load_detection_rules(DEFAULT_RULE_PATH)
