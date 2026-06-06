"""Severity and confidence scoring helpers."""

from __future__ import annotations

BASE_SEVERITY_SCORES = {
    "informational": 5,
    "low": 20,
    "medium": 50,
    "high": 75,
    "critical": 95,
}

CONFIDENCE_ADJUSTMENTS = {
    "low": -5,
    "medium": 0,
    "high": 5,
}


def risk_level_for_score(score: int) -> str:
    """Map a numeric score to a deterministic risk level."""
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 10:
        return "low"
    return "informational"


def clamp_score(score: int) -> int:
    """Clamp score to the supported 0-100 range."""
    return max(0, min(100, score))
