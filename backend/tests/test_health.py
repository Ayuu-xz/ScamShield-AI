"""Tests for the ScamShield AI health-check endpoint."""

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health_check_returns_ok() -> None:
    """Verify GET /api/health returns 200 and expected metadata fields."""
    response = client.get("/api/health")
    assert response.status_code == 200

    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "ScamShield AI API"
    assert "version" in data
    assert "environment" in data
    assert "timestamp" in data
