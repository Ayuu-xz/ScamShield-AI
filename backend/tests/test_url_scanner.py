"""Tests for the centralized URL Scanner Engine and POST /api/scan/url endpoint."""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_normal_https_url_is_url_only_unavailable() -> None:
    """1. A normal HTTPS URL in URL-only mode returns score 0 and Inspection unavailable (never verified Safe)."""
    response = client.post("/api/scan/url", json={"url": "https://example.com/about"})
    assert response.status_code == 200

    data = response.json()
    assert data["success"] is True
    assert data["scan_type"] == "url"
    assert data["risk_score"] == 0
    assert data["risk_level"] == "Inspection unavailable"
    assert "url-only analysis" in data["inspection_note"].lower()
    assert data["detected_rules"] == []
    assert data["reputation_status"] == "Check unavailable"
    assert "does not guarantee" in data["disclaimer"].lower()


def test_ip_address_url_detected() -> None:
    """3. A URL containing an IP address should flag suspicious_domain_structure (+15)."""
    response = client.post("/api/scan/url", json={"url": "http://192.168.1.50/app"})
    assert response.status_code == 200

    data = response.json()
    assert "Suspicious Domain or URL Structure" in data["detected_indicators"]
    assert data["rule_score"] == 20  # +15 IP structure + +5 missing HTTPS
    assert data["risk_score"] >= 20
    assert data["risk_level"] in {"Inspection unavailable", "Suspicious"}


def test_url_shortener_detected() -> None:
    """2. A known URL shortener domain should be flagged (+10)."""
    response = client.post("/api/scan/url", json={"url": "https://bit.ly/3xYzAbC"})
    assert response.status_code == 200

    data = response.json()
    assert "URL Shortener" in data["detected_indicators"]
    assert data["rule_score"] == 10
    assert data["risk_score"] >= 10
    assert data["risk_level"] in {"Inspection unavailable", "Suspicious"}


def test_excessive_subdomains_detected() -> None:
    """5. A URL with excessive subdomains should be flagged (+15)."""
    response = client.post(
        "/api/scan/url",
        json={"url": "https://a.b.c.example.com/home"},
    )
    assert response.status_code == 200

    data = response.json()
    assert "Suspicious Domain or URL Structure" in data["detected_indicators"]
    assert data["risk_score"] == 15


def test_suspicious_characters_detected() -> None:
    """6. A URL with '@' in authority or heavy percent-encoding should be flagged (+15)."""
    response = client.post(
        "/api/scan/url",
        json={"url": "https://trusted.com@evil.example.com/app%20%2F%2F"},
    )
    assert response.status_code == 200

    data = response.json()
    assert "Suspicious Domain or URL Structure" in data["detected_indicators"]
    assert data["risk_score"] >= 15


def test_malformed_and_unsafe_urls_rejected() -> None:
    """Malformed URLs and unsafe schemes should return HTTP 400 with clear detail."""
    bad_inputs = [
        "not a valid url",
        "javascript:alert(1)",
        "http://[invalid-ipv6",
        "http://",
    ]
    for bad in bad_inputs:
        response = client.post("/api/scan/url", json={"url": bad})
        assert response.status_code == 400, f"Expected 400 for {bad!r}, got {response.status_code}"
        assert "detail" in response.json()


def test_empty_url_rejected_by_pydantic() -> None:
    """Empty/whitespace URLs should return HTTP 422 validation error."""
    response = client.post("/api/scan/url", json={"url": "   "})
    assert response.status_code == 422


def test_missing_https_alone_stays_low_risk() -> None:
    """7. A normal HTTP URL without HTTPS stays low risk (+5)."""
    response = client.post("/api/scan/url", json={"url": "http://example.com/about"})
    assert response.status_code == 200

    data = response.json()
    assert "Missing HTTPS Encryption" in data["detected_indicators"]
    assert data["rule_score"] == 5
    assert data["risk_score"] >= 5
    assert data["risk_level"] in {"Inspection unavailable", "Suspicious"}


def test_lookalike_domain_detected() -> None:
    """4. Look-alike brand impersonation should be flagged (+30)."""
    response = client.post(
        "/api/scan/url",
        json={"url": "http://paypa1-secure-login.com/verify"},
    )
    assert response.status_code == 200

    data = response.json()
    assert "Look-Alike or Brand-Impersonation Domain" in data["detected_indicators"]
    assert data["rule_score"] == 45  # +30 lookalike + +10 credential + +5 missing HTTPS
    assert data["risk_score"] >= 45
    assert data["risk_level"] in {"Suspicious", "Dangerous"}
