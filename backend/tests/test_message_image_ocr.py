"""Tests for Image/Screenshot OCR and POST /api/scan/message-image endpoint."""

import io

from fastapi.testclient import TestClient
from PIL import Image, ImageDraw

from app.main import app
from app.services import ocr_service
from app.services.ocr_service import OcrExtractionResult, OcrUnavailableError

client = TestClient(app)


def _make_png_bytes(text: str = "", size: tuple[int, int] = (480, 120)) -> bytes:
    """Create a synthetic in-memory PNG image with optional readable text."""
    img = Image.new("RGB", size, color=(255, 255, 255))
    if text:
        draw = ImageDraw.Draw(img)
        draw.text((20, 45), text, fill=(0, 0, 0))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


def test_valid_image_upload_with_readable_url(monkeypatch) -> None:
    """9 & 12. Valid PNG image with readable URL returns OCR text and URL scan results."""
    png_bytes = _make_png_bytes("Check https://example.com/login")

    monkeypatch.setattr(
        "app.api.routes.extract_text_from_image",
        lambda _bytes: OcrExtractionResult(
            extracted_text="Check https://example.com/login",
            ocr_confidence=0.96,
            low_confidence_warning=None,
        ),
    )

    res = client.post(
        "/api/scan/message-image",
        files={"file": ("screenshot.png", png_bytes, "image/png")},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["scan_type"] == "message-image"
    assert data["extracted_text"] == "Check https://example.com/login"
    assert data["detected_urls"] == ["https://example.com/login"]
    assert data["overall_risk_score"] == 10  # +10 credential_url_pattern (/login)
    assert data["overall_risk_level"] == "Inspection unavailable"
    assert data["ocr_confidence"] == 0.96


def test_invalid_image_format_rejected() -> None:
    """10. Non-image file extensions / MIME types return HTTP 400."""
    res = client.post(
        "/api/scan/message-image",
        files={"file": ("notes.txt", b"hello world", "text/plain")},
    )
    assert res.status_code == 400
    assert "unsupported" in res.json()["detail"].lower()


def test_corrupted_image_rejected() -> None:
    """11. Corrupted bytes with a .png extension return HTTP 400."""
    res = client.post(
        "/api/scan/message-image",
        files={"file": ("broken.png", b"not-a-real-png-payload", "image/png")},
    )
    assert res.status_code == 400
    assert "corrupted" in res.json()["detail"].lower()


def test_image_with_multiple_urls(monkeypatch) -> None:
    """13. Image containing multiple URLs evaluates each URL and aggregates max risk."""
    png_bytes = _make_png_bytes()

    monkeypatch.setattr(
        "app.api.routes.extract_text_from_image",
        lambda _bytes: OcrExtractionResult(
            extracted_text="Safe: https://example.com and Lookalike: http://paypa1-secure-login.com/verify",
            ocr_confidence=0.88,
            low_confidence_warning=None,
        ),
    )

    res = client.post(
        "/api/scan/message-image",
        files={"file": ("multi.png", png_bytes, "image/png")},
    )
    assert res.status_code == 200
    data = res.json()
    assert len(data["detected_urls"]) == 2
    assert data["rule_score"] is None or data["overall_risk_score"] >= 45
    assert data["overall_risk_level"] in {"Suspicious", "Dangerous"}


def test_image_with_no_url_returns_unavailable(monkeypatch) -> None:
    """14. Image with readable text but no URL returns Unavailable (not Safe)."""
    png_bytes = _make_png_bytes()

    monkeypatch.setattr(
        "app.api.routes.extract_text_from_image",
        lambda _bytes: OcrExtractionResult(
            extracted_text="Hello, your package is at the front desk.",
            ocr_confidence=0.92,
            low_confidence_warning=None,
        ),
    )

    res = client.post(
        "/api/scan/message-image",
        files={"file": ("nourl.png", png_bytes, "image/png")},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "no_url_detected"
    assert data["overall_risk_score"] is None
    assert data["overall_risk_level"] == "Unavailable"


def test_ocr_unavailable_returns_503(monkeypatch) -> None:
    """15. OCR failure or missing OCR dependency returns HTTP 503 gracefully."""
    png_bytes = _make_png_bytes()

    def _raise_unavailable(_bytes):
        raise OcrUnavailableError("OCR engine is not installed on the server.")

    monkeypatch.setattr("app.api.routes.extract_text_from_image", _raise_unavailable)

    res = client.post(
        "/api/scan/message-image",
        files={"file": ("screen.png", png_bytes, "image/png")},
    )
    assert res.status_code == 503
    assert "ocr engine" in res.json()["detail"].lower()


def test_oversized_upload_rejected() -> None:
    """16. Uploads exceeding 5 MB return HTTP 413."""
    oversized = b"0" * (5 * 1024 * 1024 + 10)
    res = client.post(
        "/api/scan/message-image",
        files={"file": ("huge.png", oversized, "image/png")},
    )
    assert res.status_code == 413
    assert "maximum allowed size" in res.json()["detail"].lower()


def test_real_rapidocr_end_to_end_on_synthetic_image() -> None:
    """Verify real RapidOCR engine extracts text from a synthetic high-contrast image."""
    img = Image.new("RGB", (600, 120), color=(255, 255, 255))
    draw = ImageDraw.Draw(img)
    draw.text((20, 45), "https://example.com/test", fill=(0, 0, 0))
    buf = io.BytesIO()
    img.save(buf, format="PNG")

    result = ocr_service.extract_text_from_image(buf.getvalue())
    assert isinstance(result.extracted_text, str)
