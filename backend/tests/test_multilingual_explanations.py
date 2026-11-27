"""Automated tests for English, Hindi (Devanagari), and Hinglish explanations."""

from fastapi.testclient import TestClient

from app.main import app
from app.services.explanation_service import generate_multilingual_explanations
from app.services.indicators import RuleFinding

client = TestClient(app)


def test_url_scanner_explanations_in_all_three_languages() -> None:
    """URL scanner returns en, hi (Hindi Unicode), and hinglish explanations in one response."""
    res = client.post("/api/scan/url", json={"url": "https://bit.ly/3xYzAbC"})
    assert res.status_code == 200
    data = res.json()

    multi = data["multilingual_explanations"]
    assert set(multi.keys()) == {"en", "hi", "hinglish"}
    assert "shortened link" in multi["en"]["explanations"][0].lower()
    assert "shortened link" in multi["hi"]["explanations"][0]
    assert "का उपयोग करता है" in multi["hi"]["explanations"][0]
    assert "use karta hai" in multi["hinglish"]["explanations"][0].lower()
    assert len(multi["hi"]["recommendations"]) >= 1
    assert len(multi["hinglish"]["recommendations"]) >= 1


def test_message_scanner_explanations_in_all_three_languages() -> None:
    """Message scanner returns localized explanations for detected URLs and no-URL cases."""
    res = client.post(
        "/api/scan/message",
        json={"message": "Please check http://paypa1-secure-login.com/verify"},
    )
    assert res.status_code == 200
    multi = res.json()["multilingual_explanations"]
    assert set(multi.keys()) == {"en", "hi", "hinglish"}
    assert len(multi["en"]["explanations"]) >= 2
    assert len(multi["hi"]["explanations"]) == len(multi["en"]["explanations"])
    assert len(multi["hinglish"]["explanations"]) == len(multi["en"]["explanations"])

    no_url = client.post(
        "/api/scan/message",
        json={"message": "Hello! Your order is ready."},
    ).json()
    assert "कोई URL नहीं मिला" in no_url["multilingual_explanations"]["hi"]["summary"]
    assert "Koi URL detect nahi hua" in no_url["multilingual_explanations"]["hinglish"]["summary"]


def test_missing_translation_falls_back_to_english() -> None:
    """Unknown rule_id falls back cleanly to English explanation without error."""
    custom_rule = RuleFinding(
        rule_id="untranslated_custom_rule",
        rule_name="Custom Rule",
        category="url_structure",
        severity="low",
        evidence="custom",
        explanation="Fallback English explanation for unknown rule.",
        recommendation="Fallback English recommendation.",
        score_contribution=5,
    )
    bundles = generate_multilingual_explanations(
        risk_score=5,
        risk_level="Inspection unavailable",
        detected_rules=[custom_rule],
        fallback_recommendations=[],
    )
    assert bundles["hi"].explanations == ["Fallback English explanation for unknown rule."]
    assert bundles["hinglish"].explanations == ["Fallback English explanation for unknown rule."]


def test_special_characters_and_hindi_unicode_preserved() -> None:
    """Unicode Hindi input and special characters do not break multilingual explanation generation."""
    res = client.post(
        "/api/scan/message",
        json={"message": "नमस्ते! कृपया इस लिंक को देखें: https://bit.ly/hindi-test?a=1&b=2"},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["multilingual_explanations"]["hi"]["summary"]
    assert data["multilingual_explanations"]["hinglish"]["summary"]
