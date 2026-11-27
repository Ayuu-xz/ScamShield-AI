"""Tests for SQLite Scan History persistence, endpoints, and error handling."""

from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import create_engine, inspect
from sqlalchemy.exc import SQLAlchemyError

from app.db.database import get_db, init_db
from app.main import app

client = TestClient(app)


def test_database_initialization_creates_scan_history_table(tmp_path: Path) -> None:
    """1. Database initialization should create the scan_history table and columns."""
    db_path = tmp_path / "init_check.db"
    engine = create_engine(f"sqlite:///{db_path}", future=True)
    init_db(target_engine=engine)

    inspector = inspect(engine)
    assert "scan_history" in inspector.get_table_names()
    column_names = {col["name"] for col in inspector.get_columns("scan_history")}
    assert {
        "id",
        "scan_type",
        "input_text",
        "risk_score",
        "risk_level",
        "detected_indicators",
        "explanations",
        "recommendations",
        "created_at",
    }.issubset(column_names)
    engine.dispose()


def test_saving_url_scan_history_and_retry_dedup() -> None:
    """2. Successful URL scans save to history; immediate identical retries do not duplicate."""
    res1 = client.post("/api/scan/url", json={"url": "https://example.com/login"})
    assert res1.status_code == 200
    scan_id_1 = res1.json()["scan_id"]
    assert isinstance(scan_id_1, int)

    # Immediate identical retry should return the same scan_id (dedup)
    res2 = client.post("/api/scan/url", json={"url": "https://example.com/login"})
    assert res2.status_code == 200
    assert res2.json()["scan_id"] == scan_id_1

    # Invalid URL must NOT be saved
    bad_res = client.post("/api/scan/url", json={"url": "javascript:alert(1)"})
    assert bad_res.status_code == 400

    history = client.get("/api/history").json()
    assert history["total"] == 1
    assert history["items"][0]["scan_type"] == "url"


def test_saving_message_scan_history() -> None:
    """3. Successful Message scans with URLs save to history."""
    res = client.post(
        "/api/scan/message",
        json={
            "message": "Please verify at http://192.168.1.50/login and http://paypa1-secure-login.com/verify"
        },
    )
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data["scan_id"], int)

    history = client.get("/api/history").json()
    assert history["total"] == 1
    item = history["items"][0]
    assert item["scan_type"] == "message"
    assert item["risk_score"] >= 45
    assert item["risk_level"] in {"Suspicious", "Dangerous"}


def test_retrieving_history_newest_first_and_filtered() -> None:
    """4. Retrieving history sorts newest first and supports scan_type/risk_level filters."""
    client.post("/api/scan/url", json={"url": "https://example.com/one"})
    client.post(
        "/api/scan/message",
        json={"message": "Check http://login.verify.account.security.paypa1-secure.com/auth"},
    )

    all_res = client.get("/api/history").json()
    assert all_res["total"] == 2
    assert all_res["items"][0]["scan_type"] == "message"
    assert all_res["items"][1]["scan_type"] == "url"

    url_only = client.get("/api/history?scan_type=url").json()
    assert url_only["total"] == 1
    assert url_only["items"][0]["scan_type"] == "url"

    dangerous_only = client.get("/api/history?risk_level=Dangerous").json()
    assert dangerous_only["total"] == 1
    assert dangerous_only["items"][0]["risk_level"] == "Dangerous"


def test_history_pagination() -> None:
    """5. Pagination with limit and offset returns expected slices."""
    for idx in range(5):
        client.post("/api/scan/url", json={"url": f"https://example.com/page-{idx}"})

    page1 = client.get("/api/history?limit=2&offset=0").json()
    assert page1["total"] == 5
    assert len(page1["items"]) == 2

    page2 = client.get("/api/history?limit=2&offset=2").json()
    assert page2["total"] == 5
    assert len(page2["items"]) == 2
    assert page1["items"][0]["id"] != page2["items"][0]["id"]


def test_retrieving_single_scan_detail() -> None:
    """6. GET /api/history/{scan_id} returns full scan details."""
    created = client.post(
        "/api/scan/url", json={"url": "http://paypa1-secure-login.com/verify"}
    ).json()
    scan_id = created["scan_id"]

    detail_res = client.get(f"/api/history/{scan_id}")
    assert detail_res.status_code == 200
    detail = detail_res.json()
    assert detail["id"] == scan_id
    assert detail["input_text"] == "http://paypa1-secure-login.com/verify"
    assert len(detail["detected_indicators"]) >= 1
    assert len(detail["explanations"]) >= 1
    assert len(detail["recommendations"]) >= 1
    assert "created_at" in detail


def test_deleting_single_scan() -> None:
    """7. DELETE /api/history/{scan_id} removes the targeted record."""
    scan_id = client.post("/api/scan/url", json={"url": "https://example.com/del"}).json()[
        "scan_id"
    ]

    del_res = client.delete(f"/api/history/{scan_id}")
    assert del_res.status_code == 200
    assert del_res.json()["deleted_id"] == scan_id

    get_res = client.get(f"/api/history/{scan_id}")
    assert get_res.status_code == 404


def test_clearing_all_history() -> None:
    """8. DELETE /api/history clears all records and returns deleted_count."""
    client.post("/api/scan/url", json={"url": "https://example.com/a"})
    client.post("/api/scan/url", json={"url": "https://example.com/b"})

    clear_res = client.delete("/api/history")
    assert clear_res.status_code == 200
    assert clear_res.json()["deleted_count"] == 2

    after = client.get("/api/history").json()
    assert after["total"] == 0
    assert after["items"] == []


def test_invalid_and_missing_scan_id() -> None:
    """9. Non-existent scan_id returns 404; invalid <=0 scan_id returns 422."""
    assert client.get("/api/history/999999").status_code == 404
    assert client.delete("/api/history/999999").status_code == 404
    assert client.get("/api/history/0").status_code == 422


def test_database_error_handling_does_not_leak_internals() -> None:
    """10. Database errors return HTTP 500 with a generic message and no stack trace."""

    class BrokenSession:
        def query(self, *args, **kwargs):
            raise SQLAlchemyError("simulated internal sqlite failure at C:\\secret\\path")

        def rollback(self):
            pass

    app.dependency_overrides[get_db] = lambda: BrokenSession()
    try:
        res = client.get("/api/history")
        assert res.status_code == 500
        detail = res.json()["detail"]
        assert "database error" in detail.lower()
        assert "c:\\secret" not in detail.lower()
    finally:
        app.dependency_overrides.clear()
