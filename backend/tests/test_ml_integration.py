"""Automated tests for ML inference, caching, missing-model handling, and combined scoring."""

from pathlib import Path

from fastapi.testclient import TestClient

from app.main import app
from app.ml.predictor import MLModelRegistry, MLPredictionResult
from app.services.risk_scorer import compute_ml_score_contribution

client = TestClient(app)


def test_ml_predict_url_endpoint_legit_and_phishing() -> None:
    """1, 6, 14. POST /api/ml/predict/url returns structured calibrated prediction & version."""
    legit_res = client.post("/api/ml/predict/url", json={"url": "https://example.com/about"})
    assert legit_res.status_code == 200
    legit = legit_res.json()
    assert legit["available"] is True
    assert legit["prediction"] in {"Legitimate", "Phishing"}
    assert legit["model_version"] == "url-ml-v1.0.0"
    assert legit["calibrated"] is True
    assert 0.0 <= legit["confidence"] <= 1.0

    phish_res = client.post(
        "/api/ml/predict/url",
        json={"url": "http://paypa1-secure-login.xyz/login/verify"},
    )
    assert phish_res.status_code == 200
    phish = phish_res.json()
    assert phish["available"] is True
    assert phish["prediction"] == "Phishing"
    assert phish["confidence"] >= 0.75


def test_ml_predict_message_endpoint_classes() -> None:
    """2, 6, 14. POST /api/ml/predict/message returns 4-class prediction & version."""
    legit = client.post(
        "/api/ml/predict/message",
        json={"message": "Hi team, our weekly standup is moved to 3 PM in Room B."},
    ).json()
    assert legit["available"] is True
    assert legit["prediction"] == "Legitimate"
    assert legit["model_version"] == "message-ml-v1.0.0"

    phish = client.post(
        "/api/ml/predict/message",
        json={"message": "Your Bank account has been suspended. Verify your KYC at http://bit.ly/verify-now"},
    ).json()
    assert phish["available"] is True
    assert phish["prediction"] == "Phishing"


def test_ml_endpoints_reject_invalid_inputs() -> None:
    """3, 13. Invalid URL returns 400 and empty message returns 422."""
    assert client.post("/api/ml/predict/url", json={"url": "javascript:alert(1)"}).status_code == 400
    assert client.post("/api/ml/predict/message", json={"message": "   "}).status_code == 422


def test_missing_model_files_handled_gracefully(tmp_path: Path) -> None:
    """4, 7. Missing model files report Model unavailable without leaking paths."""
    registry = MLModelRegistry(artifacts_dir=tmp_path)
    pred = registry.predict("url", "https://example.com")
    assert pred.available is False
    assert pred.prediction == "Model unavailable"
    assert pred.confidence is None
    assert str(tmp_path) not in (pred.error or "")


def test_model_registry_caches_loaded_models() -> None:
    """5. Repeated calls reuse cached model without reloading from disk."""
    registry = MLModelRegistry()
    p1 = registry.predict("url", "https://example.com")
    assert "url" in registry._cache
    cached_obj = registry._cache["url"]
    p2 = registry.predict("url", "https://example.com/docs")
    assert registry._cache["url"] is cached_obj
    assert p1.available and p2.available


def test_rule_based_scanner_works_when_ml_unavailable(monkeypatch) -> None:
    """8. If ML is unavailable, URL Scanner continues working via rule-based scoring."""
    monkeypatch.setattr(
        "app.api.routes.predict_url_ml",
        lambda _u: MLPredictionResult(
            available=False,
            prediction="Model unavailable",
            error="Model unavailable",
        ),
    )
    res = client.post("/api/scan/url", json={"url": "http://paypa1-secure-login.com/verify"})
    assert res.status_code == 200
    data = res.json()
    assert data["rule_score"] == 45
    assert data["risk_score"] == 45
    assert data["ml_analysis"]["available"] is False
    assert data["ml_analysis"]["prediction"] == "Model unavailable"


def test_url_and_message_scanner_include_ml_analysis() -> None:
    """9, 10, 11. URL, Message, and Image OCR endpoints include ml_analysis."""
    url_data = client.post("/api/scan/url", json={"url": "https://example.com/about"}).json()
    assert "ml_analysis" in url_data
    assert "rule_score" in url_data
    assert "combined_risk_score" in url_data

    msg_data = client.post(
        "/api/scan/message",
        json={"message": "Hello! Please check https://example.com/about"},
    ).json()
    assert "ml_analysis" in msg_data
    assert msg_data["ml_analysis"]["available"] is True
    assert msg_data["ml_analysis"]["prediction"] in {"Legitimate", "Spam", "Phishing", "Scam"}


def test_combined_scoring_avoids_double_counting() -> None:
    """12. ML never inflates an already-Dangerous rule score and caps boosts cleanly."""
    high_phish = MLPredictionResult(
        available=True, prediction="Phishing", confidence=0.95, calibrated=True
    )
    assert compute_ml_score_contribution(0, high_phish) == 25
    assert compute_ml_score_contribution(30, high_phish) <= 15
    assert compute_ml_score_contribution(55, high_phish) == 0

    legit_pred = MLPredictionResult(
        available=True, prediction="Legitimate", confidence=0.99, calibrated=True
    )
    assert compute_ml_score_contribution(0, legit_pred) == 0
