"""Alert model for safe synthetic detections."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass(slots=True)
class Alert:
    """Structured alert generated from local synthetic events."""

    rule_id: str
    title: str
    description: str
    severity: str
    confidence: str
    category: str
    evidence: str
    guidance: str
    source_path: str | None = None
    source_ip: str | None = None
    destination_ip: str | None = None
    destination_port: int | None = None
    protocol: str | None = None
    synthetic: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)
    score: int | None = None
    risk_level: str | None = None
    scoring_reason: str | None = None
    scoring_factors: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Return a stable dictionary representation."""
        return asdict(self)
