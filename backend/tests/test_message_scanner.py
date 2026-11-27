"""Tests for URL-first Message Scanner Engine and POST /api/scan/message endpoint."""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_normal_message_with_low_risk_url() -> None:
    """1. Normal message with a low-risk HTTPS URL should score 0 and Safe."""
    response = client.post(
        "/api/scan/message",
        json={
            "message": "Hello! Dear customer, your order is ready. Please check https://example.com/order"
        },
    )
    assert response.status_code == 200

    data = response.json()
    assert data["success"] is True
    assert data["scan_type"] == "message"
    assert data["status"] == "completed"
    assert data["detected_urls"] == ["https://example.com/order"]
    assert data["overall_risk_score"] == 0
    assert data["overall_risk_level"] == "Inspection unavailable"
    assert len(data["url_results"]) == 1
    assert data["url_results"][0]["risk_score"] == 0


def test_normal_message_with_suspicious_url() -> None:
    """2. Normal message containing a suspicious look-alike URL should reflect URL risk."""
    response = client.post(
        "/api/scan/message",
        json={
            "message": "Thank you for contacting us. Please check http://paypa1-secure-login.com/verify"
        },
    )
    assert response.status_code == 200

    data = response.json()
    assert data["overall_risk_score"] >= 45
    assert data["overall_risk_level"] in {"Suspicious", "Dangerous"}
    assert "Look-Alike or Brand-Impersonation Domain" in data["detected_indicators"]


def test_message_with_ip_address_url() -> None:
    """3. Message containing an IP-address URL should flag the IP indicator."""
    response = client.post(
        "/api/scan/message",
        json={"message": "Please check this link: http://192.168.1.50/login"},
    )
    assert response.status_code == 200

    data = response.json()
    assert data["overall_risk_score"] >= 30  # >= rule_score (30) + optional ML boost
    assert data["overall_risk_level"] in {"Suspicious", "Dangerous"}
    assert "Suspicious Domain or URL Structure" in data["detected_indicators"]


def test_message_with_multiple_urls_uses_highest_risk() -> None:
    """18. Message with both a safe URL and a suspicious URL must not hide the suspicious one."""
    response = client.post(
        "/api/scan/message",
        json={
            "message": (
                "Visit https://example.com/help or check http://paypa1-secure-login.com/verify"
            )
        },
    )
    assert response.status_code == 200

    data = response.json()
    assert len(data["detected_urls"]) == 2
    assert len(data["url_results"]) == 2
    assert data["url_results"][0]["risk_score"] == 0
    assert data["url_results"][1]["risk_score"] >= 45
    assert data["overall_risk_score"] == data["url_results"][1]["risk_score"]
    assert data["overall_risk_level"] in {"Suspicious", "Dangerous"}


def test_message_with_duplicate_urls_deduplicates() -> None:
    """Duplicate URLs in the same message should be deduplicated."""
    response = client.post(
        "/api/scan/message",
        json={
            "message": "Check https://example.com/a and again https://example.com/a please."
        },
    )
    assert response.status_code == 200

    data = response.json()
    assert data["detected_urls"] == ["https://example.com/a"]
    assert len(data["url_results"]) == 1


def test_message_with_no_url_returns_unavailable() -> None:
    """Message with no URL must not be scored or labeled Safe."""
    response = client.post(
        "/api/scan/message",
        json={"message": "Hello! Dear customer, your order is ready. Thank you!"},
    )
    assert response.status_code == 200

    data = response.json()
    assert data["status"] == "no_url_detected"
    assert data["detected_urls"] == []
    assert data["url_results"] == []
    assert data["overall_risk_score"] is None
    assert data["overall_risk_level"] == "Unavailable"
    assert "no url detected" in data["explanation"].lower()


def test_ordinary_scammy_wording_does_not_inflate_url_score() -> None:
    """Ordinary/urgent wording must NOT independently increase the URL-based score."""
    response = client.post(
        "/api/scan/message",
        json={
            "message": (
                "URGENT! Dear customer, your account will be blocked, share your OTP and KYC "
                "immediately to claim your lottery prize: https://example.com/about"
            )
        },
    )
    assert response.status_code == 200

    data = response.json()
    assert data["overall_risk_score"] == 0
    assert data["overall_risk_level"] == "Inspection unavailable"


def test_same_url_consistent_across_url_and_message_scanners() -> None:
    """19. The exact same URL must receive identical score and level in both scanners."""
    target_url = "http://paypa1-secure-login.com/verify"
    url_res = client.post("/api/scan/url", json={"url": target_url}).json()
    msg_res = client.post(
        "/api/scan/message",
        json={"message": f"Hello, please check {target_url} thank you"},
    ).json()

    assert msg_res["overall_risk_score"] == url_res["risk_score"]
    assert msg_res["overall_risk_level"] == url_res["risk_level"]
    assert msg_res["detected_indicators"] == url_res["detected_indicators"]


def test_empty_and_oversized_messages_rejected() -> None:
    """Empty or >5000 char messages should return HTTP 422."""
    assert client.post("/api/scan/message", json={"message": "   "}).status_code == 422
    assert client.post("/api/scan/message", json={"message": "a" * 5001}).status_code == 422
