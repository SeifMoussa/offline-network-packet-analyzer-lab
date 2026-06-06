"""Deterministic risk scoring for synthetic alerts."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from offline_packet_analyzer.models.alert import Alert
from offline_packet_analyzer.scoring.severity import (
    BASE_SEVERITY_SCORES,
    CONFIDENCE_ADJUSTMENTS,
    clamp_score,
    risk_level_for_score,
)


@dataclass(slots=True)
class ScoringResult:
    """Calculated score metadata for one alert."""

    score: int
    risk_level: str
    scoring_reason: str
    scoring_factors: dict[str, Any] = field(default_factory=dict)


def score_alert(alert: Alert) -> ScoringResult:
    """Score one synthetic alert deterministically."""
    base = BASE_SEVERITY_SCORES.get(alert.severity, 0)
    confidence_adjustment = CONFIDENCE_ADJUSTMENTS.get(alert.confidence, 0)
    factors: dict[str, Any] = {
        "severity": alert.severity,
        "confidence": alert.confidence,
        "base": base,
        "confidence_adjustment": confidence_adjustment,
    }

    score = base + confidence_adjustment
    event_count = int(alert.metadata.get("event_count", 0) or 0)
    total_bytes = int(alert.metadata.get("total_bytes", 0) or 0)

    if event_count >= 4:
        score += 10
        factors["repeated_behavior_bonus"] = 10
    elif event_count >= 2:
        score += 5
        factors["repeated_behavior_bonus"] = 5

    if total_bytes >= 100000:
        score += 10
        factors["high_volume_bonus"] = 10

    if alert.rule_id == "SENS-001":
        score += 15
        factors["sensitive_marker_bonus"] = 15

    final_score = clamp_score(score)
    risk_level = risk_level_for_score(final_score)
    reason = (
        f"Severity {alert.severity} with {alert.confidence} confidence produced "
        f"score {final_score}."
    )
    return ScoringResult(
        score=final_score,
        risk_level=risk_level,
        scoring_reason=reason,
        scoring_factors=factors,
    )


def apply_scores(alerts: list[Alert]) -> list[Alert]:
    """Apply scoring fields to alerts in place and return the same list."""
    for alert in alerts:
        result = score_alert(alert)
        alert.score = result.score
        alert.risk_level = result.risk_level
        alert.scoring_reason = result.scoring_reason
        alert.scoring_factors = result.scoring_factors
    return alerts
