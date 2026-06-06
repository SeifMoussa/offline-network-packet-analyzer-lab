from offline_packet_analyzer.detections.rules import load_default_rules
from offline_packet_analyzer.guidance.triage import TRIAGE_GUIDANCE, guidance_for_rule


def test_guidance_exists_for_every_default_rule() -> None:
    rule_ids = {rule.rule_id for rule in load_default_rules()}

    assert rule_ids <= set(TRIAGE_GUIDANCE)


def test_guidance_text_is_defensive_only() -> None:
    forbidden = ("exploit", "payload", "exfiltrate", "bypass", "bruteforce")

    for guidance in TRIAGE_GUIDANCE.values():
        lowered = guidance.lower()
        assert any(
            word in lowered for word in ("review", "confirm", "validate", "compare", "remove")
        )
        for word in forbidden:
            assert word not in lowered


def test_guidance_lookup_uses_fallback() -> None:
    assert guidance_for_rule("UNKNOWN", "Review synthetic context.") == "Review synthetic context."
