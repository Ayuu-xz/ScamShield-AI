"""Tests for Detailed Scan Reports, PDF/JSON Exports, Privacy Sanitization, and Analytics."""

from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from app.db.models import ScanHistory
from app.main import app
from app.schemas.history import ScanReportResponse

client = TestClient(app)


def test_empty_database_analytics_returns_no_fabricated_data() -> None:
    """Empty database must return has_data=False and zero counts."""
    res = client.get("/api/analytics")
    assert res.status_code == 200
    data = res.json()
    assert data["success"] is True
    assert data["has_data"] is False
    assert data["total_scans"] == 0
    assert data["url_scans"] == 0
    assert data["message_scans"] == 0
    assert data["average_risk_score"] is None
    assert data["daily_trends"] == []
    assert data["weekly_trends"] == []
    assert data["top_indicators"] == []


def test_detailed_report_json_and_pdf_export_and_privacy_redaction() -> None:
    """Detailed report, JSON export, and PDF export reflect DB record and redact secrets."""
    scan_res = client.post(
        "/api/scan/url",
        json={"url": "http://paypa1-secure-login.com/verify?token=supersecret123&password=mypass"},
    )
    assert scan_res.status_code == 200
    scan_id = scan_res.json()["scan_id"]
    assert isinstance(scan_id, int)

    report_res = client.get(f"/api/history/{scan_id}/report")
    assert report_res.status_code == 200
    report = ScanReportResponse.model_validate(report_res.json())
    assert report.scan_id == scan_id
    assert report.scan_type == "url"
    assert "supersecret123" not in report.input_preview
    assert "mypass" not in report.input_preview
    assert "REDACTED" in report.input_preview
    assert report.rule_analysis.status == "completed"
    assert report.disclaimer

    json_res = client.get(f"/api/history/{scan_id}/export?format=json")
    assert json_res.status_code == 200
    assert json_res.headers["content-type"].startswith("application/json")
    assert f"scamshield-report-{scan_id}.json" in json_res.headers["content-disposition"]
    exported_report = ScanReportResponse.model_validate_json(json_res.text)
    assert exported_report.scan_id == scan_id
    assert "supersecret123" not in json_res.text
    assert "mypass" not in json_res.text

    pdf_res = client.get(f"/api/history/{scan_id}/export?format=pdf")
    assert pdf_res.status_code == 200
    assert pdf_res.headers["content-type"].startswith("application/pdf")
    assert f"scamshield-report-{scan_id}.pdf" in pdf_res.headers["content-disposition"]
    assert pdf_res.content.startswith(b"%PDF-")
    assert len(pdf_res.content) > 1000


def test_legacy_record_without_report_payload_marks_ml_and_intel_unavailable(
    isolated_test_db,
) -> None:
    """Records created without report_payload clearly report ML and Threat Intel as unavailable."""
    with isolated_test_db() as db:
        legacy = ScanHistory(
            scan_type="url",
            input_text="https://example.org/legacy",
            risk_score=10,
            risk_level="Inspection unavailable",
            detected_indicators=[],
            explanations=[],
            recommendations=["Verify domain manually."],
            report_payload=None,
            created_at=datetime.now(timezone.utc),
        )
        db.add(legacy)
        db.commit()
        db.refresh(legacy)
        legacy_id = legacy.id

    res = client.get(f"/api/history/{legacy_id}/report")
    assert res.status_code == 200
    data = res.json()
    assert data["ml_analysis"]["status"] == "unavailable"
    assert data["ml_analysis"]["available"] is False
    assert data["threat_intelligence"]["status"] == "unavailable"


def test_analytics_calculations_filters_and_deletion_exclusion() -> None:
    """Analytics must match stored records, support filters, and exclude deleted records."""
    r1 = client.post("/api/scan/url", json={"url": "https://example.com/safe-page"}).json()
    r2 = client.post(
        "/api/scan/url", json={"url": "http://192.168.1.50/login"}
    ).json()
    r3 = client.post(
        "/api/scan/message",
        json={"message": "Urgent verify at http://paypa1-secure-login.com/verify"},
    ).json()

    analytics_res = client.get("/api/analytics")
    assert analytics_res.status_code == 200
    analytics = analytics_res.json()
    assert analytics["has_data"] is True
    assert analytics["total_scans"] == 3
    assert analytics["url_scans"] == 2
    assert analytics["message_scans"] == 1
    assert len(analytics["daily_trends"]) >= 1
    assert len(analytics["weekly_trends"]) >= 1
    assert sum(b["count"] for b in analytics["risk_distribution"]) == 3

    # Filter analytics by scan_type=url
    url_analytics = client.get("/api/analytics?scan_type=url").json()
    assert url_analytics["total_scans"] == 2
    assert url_analytics["message_scans"] == 0

    # Delete r2 and verify it is excluded from analytics and report endpoint returns 404
    del_res = client.delete(f"/api/history/{r2['scan_id']}")
    assert del_res.status_code == 200
    assert client.get(f"/api/history/{r2['scan_id']}/report").status_code == 404

    after_delete = client.get("/api/analytics").json()
    assert after_delete["total_scans"] == 2
    assert after_delete["url_scans"] == 1
    assert after_delete["message_scans"] == 1
    assert r1["scan_id"] != r3["scan_id"]


def test_history_search_date_range_and_sorting(isolated_test_db) -> None:
    """History endpoint supports search by ID/text, date range filtering, and sorting."""
    now = datetime.now(timezone.utc)
    yesterday = now - timedelta(days=2)

    with isolated_test_db() as db:
        old_rec = ScanHistory(
            scan_type="url",
            input_text="https://old-example.com/a",
            risk_score=15,
            risk_level="Inspection unavailable",
            detected_indicators=[],
            explanations=[],
            recommendations=[],
            created_at=yesterday,
        )
        high_rec = ScanHistory(
            scan_type="url",
            input_text="http://phish-high-score.com/login",
            risk_score=85,
            risk_level="Dangerous",
            detected_indicators=["Look-alike brand domain"],
            explanations=["Suspicious brand impersonation."],
            recommendations=["Do not click."],
            created_at=now,
        )
        db.add_all([old_rec, high_rec])
        db.commit()
        db.refresh(old_rec)
        db.refresh(high_rec)
        old_id = old_rec.id
        high_id = high_rec.id

    # Search by exact scan ID
    by_id = client.get(f"/api/history?search={high_id}").json()
    assert by_id["total"] == 1
    assert by_id["items"][0]["id"] == high_id

    # Sort by score_asc
    asc_scores = client.get("/api/history?sort_by=score_asc").json()
    assert asc_scores["items"][0]["id"] == old_id

    # Date range filter (only today)
    date_from = (now - timedelta(hours=1)).isoformat()
    recent_only = client.get("/api/history", params={"date_from": date_from}).json()
    assert recent_only["total"] == 1
    assert recent_only["items"][0]["id"] == high_id
