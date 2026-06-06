from offline_packet_analyzer.models.alert import Alert
from offline_packet_analyzer.scoring.risk import apply_scores, score_alert
from offline_packet_analyzer.scoring.severity import risk_level_for_score


def alert(severity: str = "medium", confidence: str = "medium", rule_id: str = "NET-001") -> Alert:
    return Alert(
        rule_id=rule_id,
        title="Synthetic alert",
        description="Synthetic alert",
        severity=severity,
        confidence=confidence,
        category="test",
        evidence="Synthetic evidence",
        guidance="Review defensive telemetry.",
    )


def test_severity_to_score_range_mapping() -> None:
    assert risk_level_for_score(0) == "informational"
    assert risk_level_for_score(10) == "low"
    assert risk_level_for_score(40) == "medium"
    assert risk_level_for_score(70) == "high"
    assert risk_level_for_score(90) == "critical"


def test_deterministic_scoring() -> None:
    first = score_alert(alert(severity="high", confidence="high"))
    second = score_alert(alert(severity="high", confidence="high"))

    assert first == second
    assert first.score == 80
    assert first.risk_level == "high"


def test_repeated_behavior_and_high_volume_adjustments() -> None:
    item = alert(severity="high", confidence="medium", rule_id="FLOW-001")
    item.metadata = {"event_count": 4, "total_bytes": 250000}

    result = score_alert(item)

    assert result.score == 95
    assert result.risk_level == "critical"
    assert result.scoring_factors["repeated_behavior_bonus"] == 10
    assert result.scoring_factors["high_volume_bonus"] == 10


def test_sensitive_marker_bonus() -> None:
    result = score_alert(alert(rule_id="SENS-001"))

    assert result.score == 65
    assert result.risk_level == "medium"


def test_apply_scores_updates_alert_fields() -> None:
    items = apply_scores([alert()])

    assert items[0].score == 50
    assert items[0].risk_level == "medium"
    assert items[0].scoring_reason
    assert items[0].scoring_factors
